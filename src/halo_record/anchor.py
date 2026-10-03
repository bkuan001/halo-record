"""Completeness witnessing — the neutral-notary layer.

A per-tenant hash chain is internally tamper-evident: you cannot alter a past
record without breaking every hash after it. But a vendor who *hosts their own*
chain can still drop an embarrassing record and rebuild the chain from scratch.
The rebuilt chain verifies internally — so hash-chaining alone proves
tamper-evidence, **not completeness**. ("Did you show me every record, or a
curated subset?")

The notary closes that gap. A party the vendor does not control (none is
hosted by Halo today; see LIMITS.md section 1) periodically *witnesses* each
chain's head: it records ``(chain_root, count, head, ts)`` in its own append-only
log that the vendor does not control. To later hide record ``k``, the vendor
would have to rewrite history on the witness log too. Completeness
becomes something the buyer checks against a party with no incentive to help the
vendor hide — which is exactly the guarantee the vendor's own logs can never give.

This module is pure-stdlib, consistent with the rest of the package. Its limits
(LIMITS.md §1): checkpoints are unsigned, so a reader trusts whoever operates the
witness log, and that operator can rewrite it; completeness is only as
independent as that operator, and there is no hosted Halo witness today. Offline
*signed* receipts (verifiable without contacting the witness) need asymmetric
signatures and are not implemented here.
"""

import base64
import json
import os

try:
    import fcntl as _fcntl
except ImportError:  # Windows
    _fcntl = None
from datetime import datetime, timezone

from .canon import GENESIS_PREV, canon, compute_hash, sha256_hex
from .verify import parse_record_line, read_log_lines


def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def chain_root(records):
    """Stable identity of a chain: the hash of its first record (which never
    changes as the chain grows). ``None`` for an empty chain."""
    if not records:
        return None
    return (records[0].get("integrity") or {}).get("hash")


def head(records):
    """The current chain head — the last record's hash, or genesis if empty."""
    if not records:
        return GENESIS_PREV
    return (records[-1].get("integrity") or {}).get("hash")


def _subject_id(records):
    for r in records:
        s = r.get("subject")
        if isinstance(s, dict) and s.get("id"):
            return s["id"]
    return None


def checkpoint(records):
    """A witness of the chain's current state."""
    return {
        "chain_root": chain_root(records),
        "subject": _subject_id(records),
        "count": len(records),
        "head": head(records),
        "ts": _now(),
    }


def checkpoint_digest(cp):
    """SHA-256 (hex) of a checkpoint's *state* — chain_root, subject, count, head
    — excluding the self-asserted ``ts`` and any attached ``tsa``. This is what an
    RFC 3161 TSA timestamps: it binds this chain state to a time set by a party
    the operator does not control."""
    state = {k: cp.get(k) for k in ("chain_root", "subject", "count", "head")}
    return sha256_hex(canon(state))


class TimestampError(Exception):
    """The TSA was unreachable, errored, or returned a token that does not cover
    this checkpoint. Raised so the caller can degrade to an un-timestamped
    checkpoint rather than losing it."""


def attach_timestamp(cp, tsa_url=None):
    """Fetch an RFC 3161 time proof over ``checkpoint_digest(cp)`` from a TSA the
    operator doesn't control, and attach it as ``cp['tsa']``. Network call, and
    the only place the witness layer reaches out — done solely on request. The
    raw token is stored base64 so it can be verified in full with
    ``openssl ts -verify`` (see timestamp.py).

    Raises ``TimestampError`` on any TSA failure, or if the returned token does
    not actually cover our digest — a token that doesn't bind this checkpoint is
    worse than none, so it is never stored. The ``gen_time`` recorded here is a
    convenience cache: authoritative time is re-derived from the token on read
    (``checkpoint_verified_time``)."""
    from . import timestamp as _ts
    url = tsa_url or _ts.DEFAULT_TSA_URL
    digest = checkpoint_digest(cp)
    try:
        token = _ts.request_token(digest, url)
    except Exception as e:                       # urllib / HTTP / socket / ...
        raise TimestampError("TSA %s: %s" % (url, e))
    checked = _ts.verify(token, digest)
    if not checked.get("imprint_ok"):
        raise TimestampError(
            "TSA %s returned a token that does not cover this checkpoint" % url)
    out = dict(cp)
    out["tsa"] = {
        "url": url,
        "digest": digest,
        "gen_time": checked.get("gen_time"),     # cache; re-derived on read
        "token_b64": base64.b64encode(token).decode("ascii"),
    }
    return out


def checkpoint_verified_time(cp):
    """Read a checkpoint's CLAIMED time from its stored RFC 3161 token — never
    from the (operator-editable) ``tsa.gen_time`` field. Returns the ISO time
    only if the token is present and its imprint matches this checkpoint's
    recomputed digest; otherwise None. This does NOT validate the TSA's
    signature, so a hand-built token with a matching imprint can claim any time:
    treat the result as unverified until ``openssl ts -verify`` passes."""
    tsa = cp.get("tsa")
    if not isinstance(tsa, dict) or not tsa.get("token_b64"):
        return None
    from . import timestamp as _ts
    try:
        token = base64.b64decode(tsa["token_b64"])
    except (ValueError, TypeError):
        return None
    checked = _ts.verify(token, checkpoint_digest(cp))
    return checked.get("gen_time") if checked.get("imprint_ok") else None


def _chain_intact(records):
    """Recompute the hash chain (mirrors verify.verify_log, record-list form).
    Returns the index (1-based) of the first broken record, or 0 if intact."""
    prev = GENESIS_PREV
    for n, record in enumerate(records, start=1):
        integ = record.get("integrity") or {}
        if integ.get("prev_hash") != prev:
            return n
        recomputed = compute_hash(record, prev)
        if integ.get("hash") != recomputed:
            return n
        prev = integ.get("hash") or recomputed
    return 0


class WitnessFileError(ValueError):
    """A local witness file that is missing or damaged. A completeness verdict
    is refused rather than computed around it: a torn or garbled checkpoint may
    be the very one that would expose a truncation. The CLI exits 2 for it."""


def is_checkpoint(cp):
    """Whether ``cp`` has a checkpoint's shape: an object with a non-negative
    integer ``count`` and a string ``head``."""
    if not isinstance(cp, dict):
        return False
    n = cp.get("count")
    return (isinstance(n, int) and not isinstance(n, bool) and n >= 0
            and isinstance(cp.get("head"), str))


def parse_checkpoint_line(line):
    """The checkpoint on one witness line, or None if the line is damaged."""
    try:
        cp = parse_record_line(line)
    except (ValueError, RecursionError):
        return None
    return cp if is_checkpoint(cp) else None


def damaged_witness(path, line_no):
    return WitnessFileError(
        "witness file %s is damaged at line %d (not a complete checkpoint); a damaged "
        "witness cannot establish completeness, so this is refused — restore the file "
        "from a copy the witness operator holds" % (path, line_no))


class Notary:
    """A neutral witness log. In production this is hosted by Halo; locally it is
    just an append-only JSONL the vendor does not get to rewrite."""

    def __init__(self, witness_log):
        self.path = os.path.expanduser(witness_log)

    def witness(self, records):
        """Record one checkpoint for ``records`` and return it."""
        return self.record_checkpoint(checkpoint(records))

    def record_checkpoint(self, cp):
        """Append a pre-computed checkpoint (e.g. one a vendor anchored over the
        network) to the append-only log. Used by the hosted witness, where the
        vendor computes the checkpoint locally and Halo only stores it."""
        parent = os.path.dirname(self.path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        line = json.dumps(cp, separators=(",", ":")) + "\n"
        with open(self.path, "a+b") as fh:
            # Several witness processes may share one log: append under an
            # exclusive lock and flush to disk before acknowledging.
            if _fcntl is not None:
                _fcntl.flock(fh, _fcntl.LOCK_EX)
            try:
                # After a torn last line, start a new line: the new checkpoint
                # stays readable and the torn one is still reported as damage.
                end = fh.seek(0, os.SEEK_END)
                if end:
                    fh.seek(end - 1)
                    if fh.read(1) != b"\n":
                        line = "\n" + line
                fh.write(line.encode("utf-8"))
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                if _fcntl is not None:
                    _fcntl.flock(fh, _fcntl.LOCK_UN)
        return cp

    def checkpoints(self, subject=None, chain_root=None):
        """All checkpoints, or those for one subject, or (subject None and
        ``chain_root`` given) those for one subjectless chain. Raises
        ``WitnessFileError`` if any line of the file is not a complete
        checkpoint (a torn write, garbage)."""
        if not os.path.exists(self.path):
            return []
        cps = []
        with open(self.path, "rb") as lock:
            # A shared lock waits out an append in progress, so an unfinished
            # line seen here is a torn write, not a writer mid-line.
            if _fcntl is not None:
                _fcntl.flock(lock, _fcntl.LOCK_SH)
            try:
                lines = read_log_lines(self.path)
            except UnicodeDecodeError:
                raise WitnessFileError("witness file %s is damaged (not UTF-8 text); a damaged "
                                       "witness cannot establish completeness" % self.path)
            finally:
                if _fcntl is not None:
                    _fcntl.flock(lock, _fcntl.LOCK_UN)
        for n, ln in enumerate(lines, start=1):
            cp = parse_checkpoint_line(ln)
            if cp is None:
                raise damaged_witness(self.path, n)
            cps.append(cp)
        if subject is not None:
            cps = [c for c in cps if c.get("subject") == subject]
        elif chain_root is not None:
            cps = [c for c in cps if c.get("subject") is None and c.get("chain_root") == chain_root]
        return cps

    def checkpoints_for(self, records):
        """Only the checkpoints that belong to this chain: by subject when it has
        one, else by chain_root. Never the whole log — a page or response built
        for one customer must not carry other customers' checkpoints."""
        subj = _subject_id(records)
        if subj is not None:
            return self.checkpoints(subject=subj)
        if not records:
            return []
        return self.checkpoints(chain_root=chain_root(records))


def _matches(cp, records):
    """Does a checkpoint witness *this* chain? Keyed on the subject (the customer
    identity, asserted by the viewer and outside the vendor's control). Only
    subjectless chains fall back to chain_root — which a vendor *can* change by
    dropping the first record, so it is never the primary key."""
    subj = _subject_id(records)
    if subj is not None:
        return cp.get("subject") == subj
    return cp.get("chain_root") == chain_root(records)


def verify_completeness(records, checkpoints, expected_subject=None):
    """Check a presented chain against what the notary independently witnessed.

    Returns a dict:
      * ``{"ok": None, ...}``  — no witnesses for this chain (unknown, not a
        failure: the chain was simply never anchored).
      * ``{"ok": False, ...}`` — the presented chain is missing or altered a
        record the notary already witnessed (dropped, truncated, or rewritten).
      * ``{"ok": True, ...}``  — every witnessed checkpoint still matches; the
        vendor could not have removed a record the notary saw.
    """
    # Subjectless chains are matched by chain_root, and dropping the first
    # record changes the root (see _matches) — so every verdict on such a chain
    # carries the caveat loudly rather than leaving the weakness implicit.
    def _out(d):
        if records and _subject_id(records) is None:
            d["subjectless_caveat"] = (
                "checkpoints for a subjectless chain are matched by chain_root, "
                "which changes if the first record is dropped — a 'no witnesses' "
                "verdict cannot be distinguished from a re-rooted chain; assign a "
                "subject to records for a stable witness key")
        return d

    if expected_subject is not None:
        # The buyer names the customer it expects. The id inside the records is
        # the vendor's to write, so a re-keyed chain must not pick its own lookup.
        ids = set()
        for r in records:
            s = r.get("subject")
            sid = (s.get("id") or None) if isinstance(s, dict) else None
            ids.add(sid if sid is None or isinstance(sid, (str, int, float, bool))
                    else json.dumps(sid, sort_keys=True, default=str))
        found = _subject_id(records)
        if ids != {expected_subject}:
            return _out({"ok": False, "witnessed": 0,
                         "why": "chain subject id %s differs from the expected %s"
                                % (json.dumps(found), json.dumps(expected_subject))})
    relevant = [c for c in checkpoints if _matches(c, records)]
    if not relevant:
        return _out({"ok": None, "why": "no witnesses for this chain", "witnessed": 0})

    # Checkpoints are keyed by subject, so one subject can carry checkpoints for
    # more than one chain (a restarted or second chain under the same id). Name
    # that plainly when it is the reason a check fails.
    roots = sorted({c.get("chain_root") for c in relevant if c.get("chain_root")})
    mine = chain_root(records)

    def _fail(d):
        foreign = [r for r in roots if r != mine]
        if foreign:
            d["chain_roots"] = roots
            d["why"] += ("; the witness holds checkpoints for %d distinct chains under this "
                         "subject (chain roots %s; this chain's root is %s) — a second or "
                         "restarted chain shares the subject id, or this chain was re-rooted"
                         % (len(roots), ", ".join(r[:12] + "…" for r in roots),
                            (mine or "none")[:12] + "…")) if len(roots) > 1 else (
                         "; the witnessed chain has a different root (%s) than this chain "
                         "(%s) — this is a different or re-rooted chain under the same subject"
                         % (roots[0][:12] + "…", (mine or "none")[:12] + "…"))
        return _out(d)

    broken_at = _chain_intact(records)
    if broken_at:
        return _out({"ok": False, "why": "chain integrity broken", "at": broken_at,
                     "witnessed": len(relevant)})

    latest = max(c["count"] for c in relevant)
    if len(records) < latest:
        return _fail({"ok": False, "why": "chain truncated below witnessed length",
                     "have": len(records), "witnessed_count": latest,
                     "witnessed": len(relevant)})

    for c in relevant:
        n = c["count"]
        if n < 1 or n > len(records):
            return _fail({"ok": False, "why": "witnessed count out of range", "at": n,
                          "witnessed": len(relevant)})
        present_head = (records[n - 1].get("integrity") or {}).get("hash")
        if present_head != c["head"]:
            return _fail({"ok": False, "why": "record altered or dropped before witnessed point",
                          "at": n, "witnessed": len(relevant)})

    result = {"ok": True, "witnessed": len(relevant), "latest_count": latest,
              "head": head(records)}
    # Attested time is re-derived from each token (not the editable JSON field);
    # a checkpoint whose token is missing/forged/imprint-mismatched yields no time.
    tsa_times, tsa_unverified = [], 0
    for c in relevant:
        if isinstance(c.get("tsa"), dict) and c["tsa"].get("token_b64"):
            t = checkpoint_verified_time(c)
            (tsa_times.append(t) if t else None)
            if not t:
                tsa_unverified += 1
    if tsa_times:
        result["tsa_time"] = max(tsa_times)   # claimed upper bound: chain reached
        # this state no later than tsa_time — IF the token is genuine. The TSA
        # signature is not checked here, so the time is an unverified claim.
        result["tsa_time_status"] = ("unverified claim — the TSA signature is not checked here, "
                                     "and a crafted token can state any time; verify with "
                                     "`openssl ts -verify` before relying on it")
    if tsa_unverified:
        result["tsa_unverified"] = tsa_unverified  # a stored token that does not bind this state
    return _out(result)
