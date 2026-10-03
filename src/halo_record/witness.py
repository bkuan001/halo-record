"""The hosted Halo witness — the neutral notary as a network service.

A per-tenant hash chain is internally tamper-evident, but a vendor who hosts
their *own* chain can drop a record and rebuild a chain that still verifies
(see ``anchor`` for the full argument). The answer is an append-only witness the
vendor does not control. ``anchor.Notary`` is that store on disk; this module
puts it behind HTTP so vendors can anchor to a witness operated by someone
other than themselves. "Complete" is a claim the buyer's security team can
rely on only to the extent that whoever runs this service is outside the
vendor's control.

Trust-not-data, by construction:
  The vendor computes the checkpoint LOCALLY and POSTs only
  ``{subject, count, head, chain_root}`` — opaque hashes, a count, and the
  customer id. Record *contents* never leave the vendor. The witness records
  what it was sent (a head at a count at a time) without ever holding the
  underlying runtime data. Any independence comes from the witness operator
  keeping an append-only log the vendor can't rewrite, not from accumulating
  the vendor's data.

Routes:
  POST /anchor                  vendor-authed (Bearer key); append one checkpoint,
                                return a receipt. Append-only — no update/delete.
                                Rate-limited per key.
  GET  /v1/checkpoints?subject= CORS-open so a viewer's browser can fetch the
                                witness log while verifying a report. Public by
                                default, which lets anyone who guesses a subject
                                id see that it is anchored and its record count;
                                set ``$HALO_WITNESS_READ_KEYS`` (``key=subject-
                                glob|…``) to require a scoped read key instead.
  GET  /healthz                 liveness probe.

Pure-stdlib, like the rest of the package.

What this store does not give you (see LIMITS.md §1): checkpoints are not
signed, so a reader trusts whoever operates the store, and an operator with
access to ``witness.jsonl`` can rewrite it. Completeness is only as independent
as the party that runs this service; there is no hosted Halo witness today.
Offline signed receipts (verifiable without contacting the witness) need
asymmetric signatures and are not implemented.
"""

import fnmatch
import hmac
import json
import threading
import os
import re
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode

from ._private import open_private
from . import __version__
from .verify import parse_record_line
from .anchor import Notary, WitnessFileError, checkpoint, damaged_witness, parse_checkpoint_line, _now
from .anchor import _fcntl

WITNESS_FILE = "witness.jsonl"
KEY_FILE = ".halo_witness_key"
MAX_BODY = 8192
MAX_COUNT = 10 ** 12
DEFAULT_PORT = 8730
POST_RATE_LIMIT = 60      # anchors per key per POST_RATE_WINDOW seconds
POST_RATE_WINDOW = 60.0

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# ASCII only, single internal spaces, no leading/trailing space: ids that differ
# only by invisible or lookalike characters cannot be anchored separately.
_SUBJECT_RE = re.compile(r"(?=.{1,200}\Z)[A-Za-z0-9._-]+(?: [A-Za-z0-9._-]+)*\Z")


def load_keys(store):
    """Vendor bearer keys authorized to anchor. ``$HALO_WITNESS_KEYS`` (comma-
    separated) if set, else a single random key persisted in the store so it
    survives restarts. Several vendors can share one witness, each with its own
    key; scope a key with ``<key>=<subject-or-glob>|…`` (for example
    ``k1=vendor-a-*,k2=vendor-b-*``). With more than one key, every key must be
    scoped, so no vendor can write another vendor's subjects. Returns
    ``[(key, scopes), …]``."""
    env = os.environ.get("HALO_WITNESS_KEYS")
    if env:
        return parse_key_spec(env.split(","))
    path = os.path.join(store, KEY_FILE)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return parse_key_spec(fh.read().splitlines())
    key = os.urandom(24).hex()
    with open_private(path, "w") as fh:
        fh.write(key + "\n")
    return parse_key_spec([key])


def parse_key_spec(entries):
    """Parse authorized vendor keys. Each entry is ``<key>`` or
    ``<key>=<scope>|<scope>…``, where a scope is a subject ID or a glob
    (``vendor-a-*``). Returns ``[(key, scopes_or_None), …]``. A scoped key may
    anchor only subjects its scopes match; an unscoped key is accepted only when
    it is the witness's single key."""
    out = []
    for raw in entries:
        if isinstance(raw, tuple):
            out.append(raw)
            continue
        entry = str(raw).strip()
        if not entry:
            continue
        key, _, spec = entry.partition("=")
        scopes = [x.strip() for x in spec.split("|") if x.strip()] if spec else None
        out.append((key.strip(), scopes))
    return out


def _key_match(presented, keys):
    """Constant-time match of a presented bearer key. Returns the matching
    ``(key, scopes)`` entry, or None."""
    if not presented:
        return None
    found = None
    given = presented.encode("utf-8", "replace")
    for entry in parse_key_spec(keys):
        if hmac.compare_digest(given, entry[0].encode("utf-8", "replace")):
            found = entry
    return found


def _key_ok(presented, keys):
    """Constant-time match of a presented bearer key against any authorized key."""
    return _key_match(presented, keys) is not None


def _in_scope(subject, scopes):
    if scopes is None:
        return True
    if subject is None:
        return False
    return any(fnmatch.fnmatchcase(subject, sc) for sc in scopes)




def _clean_checkpoint(payload):
    """Validate and normalize a posted checkpoint. Returns a normalized dict or
    raises ValueError. Only the four attesting fields are accepted; the server
    stamps its own ``ts`` (a vendor cannot backdate a witness)."""
    if not isinstance(payload, dict):
        raise ValueError("checkpoint must be a JSON object")
    subject = payload.get("subject")
    if subject is not None:
        if not isinstance(subject, str) or not _SUBJECT_RE.fullmatch(subject):
            raise ValueError("invalid subject")
    count = payload.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= MAX_COUNT:
        raise ValueError("count must be a positive integer no larger than %d" % MAX_COUNT)
    head = payload.get("head")
    if not isinstance(head, str) or not _HEX64.match(head):
        raise ValueError("head must be a 64-char sha-256 hex digest")
    chain_root = payload.get("chain_root")
    if chain_root is not None and not (
            isinstance(chain_root, str) and _HEX64.match(chain_root)):
        raise ValueError("chain_root must be a 64-char sha-256 hex digest")
    if subject is None and chain_root is None:
        raise ValueError("checkpoint needs a subject or a chain_root")
    return {
        "chain_root": chain_root,
        "subject": subject,
        "count": count,
        "head": head,
        "ts": _now(),
    }


# --- client side: a vendor anchors a chain head to the hosted witness ----------

def anchor_remote(witness_url, key, records, *, timeout=10):
    """Anchor a chain's current head to a hosted Halo witness.

    The checkpoint is computed LOCALLY and only ``{subject, count, head,
    chain_root}`` is sent — record contents never leave the vendor. Returns the
    witness's receipt (the stored checkpoint with Halo's server timestamp)."""
    cp = checkpoint(records)
    body = json.dumps({k: cp[k] for k in ("subject", "count", "head", "chain_root")},
                      separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        witness_url.rstrip("/") + "/anchor", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + key})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        out = parse_record_line(resp.read().decode("utf-8"))
    return out.get("receipt", out)


class WitnessDamagedError(ValueError):
    """The hosted witness answered 503: its own store is damaged, so it serves
    no checkpoints until an operator repairs it."""


def fetch_failure(witness_url, err):
    """How a failed checkpoint read is described: a 401/403 means the witness
    was reached and refused the read (it requires a read key, which report and
    export do not send); anything else means it could not be reached."""
    if isinstance(err, urllib.error.HTTPError) and err.code in (401, 403):
        return ("the witness at %s refused the read (HTTP %d: it requires a read key, "
                "which report and export do not send)" % (witness_url, err.code))
    return "the witness at %s could not be reached (%s)" % (witness_url, err)


def fetch_checkpoints(witness_url, subject=None, *, chain_root=None, timeout=10, key=None):
    """Fetch the witness's checkpoints for a subject. This is what a viewer's
    browser (or a buyer's tooling) calls to check completeness against the
    witness. ``key`` is a read key, needed only when the witness requires one."""
    url = witness_url.rstrip("/") + "/v1/checkpoints"
    if subject is not None:
        url += "?" + urlencode({"subject": subject})
    elif chain_root is not None:
        url += "?" + urlencode({"chain_root": chain_root})
    req = urllib.request.Request(url, headers=({"Authorization": "Bearer " + key}
                                               if key else {}))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # Read as a chain line is read: a repeated key is refused.
            out = parse_record_line(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 503:
            raise WitnessDamagedError(
                "the witness at %s reports its store is damaged (HTTP 503); completeness "
                "cannot be checked against it" % witness_url) from None
        raise
    return out.get("checkpoints", [])


class _CheckpointIndex:
    """In-memory index over the append-only witness log. Each read parses only
    the bytes appended since the previous read, so a GET costs the new lines,
    not the whole log. A log that shrank or was replaced is re-read from the
    start."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._reset()

    def _reset(self):
        self.offset, self.ident = 0, None
        self.by_subject, self.by_root = {}, {}
        self.lines = 0
        self.damage = None
        self.torn = None

    def _refresh(self):
        try:
            st = os.stat(self.path)
        except OSError:
            self._reset()
            return
        ident = (st.st_dev, st.st_ino)
        if ident != self.ident or st.st_size < self.offset:
            self._reset()
            self.ident = ident
        if st.st_size == self.offset:
            self.torn = None
            return
        with open(self.path, "rb") as fh:
            # Appends happen under an exclusive lock; a shared lock here means
            # every line read is complete unless a write was torn.
            if _fcntl is not None:
                _fcntl.flock(fh, _fcntl.LOCK_SH)
            try:
                fh.seek(self.offset)
                data = fh.read()
            finally:
                if _fcntl is not None:
                    _fcntl.flock(fh, _fcntl.LOCK_UN)
        end = data.rfind(b"\n")
        tail = data[end + 1:]
        # An unterminated last line: torn (or, without file locks, still being
        # written). Reads are refused while it is there; it is re-read each time.
        self.torn = (self.lines + data[:end + 1].count(b"\n") + 1) if tail.strip() else None
        if end < 0:
            return
        self.offset += end + 1
        for raw in data[:end].split(b"\n"):
            if not raw.strip():
                continue
            self.lines += 1
            try:
                cp = parse_checkpoint_line(raw.decode("utf-8"))
            except UnicodeDecodeError:
                cp = None
            if cp is None:
                # A damaged line may be the checkpoint that exposes a
                # truncation: refuse reads rather than answer around it.
                self.damage = self.damage or self.lines
                continue
            if cp.get("subject") is not None:
                self.by_subject.setdefault(cp["subject"], []).append(cp)
            elif cp.get("chain_root") is not None:
                self.by_root.setdefault(cp["chain_root"], []).append(cp)

    def lookup(self, subject=None, chain_root=None):
        with self._lock:
            self._refresh()
            at = self.damage or self.torn
            if at is not None:
                raise damaged_witness(os.path.basename(self.path), at)
            if subject is not None:
                return list(self.by_subject.get(subject, []))
            return list(self.by_root.get(chain_root, []))


class _Handler(BaseHTTPRequestHandler):
    server_version = "halo-witness/" + __version__
    config = None  # injected: {"notary","keys"}

    def _send(self, code, body, ctype="application/json; charset=utf-8", cors=False):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, separators=(",", ":"))
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if cors:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        return self._guarded(self._do_get)

    def _do_get(self):
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            return self._send(200, "ok", "text/plain; charset=utf-8")
        if parsed.path == "/v1/checkpoints":
            qs = parse_qs(parsed.query)
            subject = (qs.get("subject") or [None])[0]
            root = (qs.get("chain_root") or [None])[0]
            # A filter is required: listing every subject would disclose each
            # vendor's customers and volumes to any origin.
            if subject is None and not (root and _HEX64.match(root)):
                return self._send(400, {"error": "subject or chain_root required"}, cors=True)
            read_keys = self.config.get("read_keys")
            if read_keys and subject is not None:
                # Subject ids can be guessed; with read keys configured, whether a
                # subject is anchored (and how far) is shown only to a key scoped to it.
                auth = self.headers.get("Authorization", "")
                presented = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
                entry = _key_match(presented, list(read_keys) + list(self.config["keys"]))
                if entry is None:
                    return self._send(401, {"error": "read key required"}, cors=True)
                if not _in_scope(subject, entry[1]) or (
                        entry[1] is None and len(parse_key_spec(self.config["keys"])) > 1):
                    return self._send(403, {"error": "key not authorized for this subject"},
                                      cors=True)
            # subject is only ever a filter, never a path — traversal impossible.
            try:
                cps = self._index().lookup(subject=subject, chain_root=root)
            except WitnessFileError:
                return self._send(503, {"error": "the witness store is damaged; checkpoints are "
                                                 "withheld until the operator restores it"},
                                  cors=True)
            return self._send(200, {"checkpoints": cps, "count": len(cps)}, cors=True)
        return self._send(404, {"error": "not found"})

    do_HEAD = do_GET

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        return self._guarded(self._do_post)

    def _do_post(self):
        if urlparse(self.path).path != "/anchor":
            return self._send(404, {"error": "not found"})

        auth = self.headers.get("Authorization", "")
        presented = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        entry = _key_match(presented, self.config["keys"])
        if entry is None:
            return self._send(401, {"error": "unauthorized"})

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._send(400, {"error": "bad Content-Length"})
        if length < 0:
            return self._send(400, {"error": "bad Content-Length"})
        if length > MAX_BODY:
            return self._send(413, {"error": "payload too large"})
        if not self._rate_ok(entry[0]):
            return self._send(429, {"error": "too many anchors for this key; retry later"})
        raw = self.rfile.read(length) if length else b""
        try:
            payload = parse_record_line(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            # The parser's message quotes the body back; say only what failed.
            return self._send(400, {"error": "body is not valid JSON"})
        try:
            cp = _clean_checkpoint(payload)
        except ValueError as exc:
            return self._send(400, {"error": str(exc)[:200]})  # our own fixed messages

        keys = parse_key_spec(self.config["keys"])
        if len(keys) > 1 and entry[1] is None:
            # On a witness shared by several vendors, an unscoped key could write
            # (or squat) any vendor's subject. Each key must name its subjects.
            return self._send(403, {"error": "shared witness: this key has no subject scope"})
        if not _in_scope(cp["subject"], entry[1]):
            return self._send(403, {"error": "key not authorized for this subject"})
        with self._lock():
            receipt = self.config["notary"].record_checkpoint(cp)
        return self._send(201, {"ok": True, "receipt": receipt})

    def send_response(self, *args, **kwargs):
        self._response_started = True
        return super().send_response(*args, **kwargs)

    def _guarded(self, handler):
        # Malformed requests get a 400, never a traceback or a dropped connection.
        self._response_started = False
        try:
            return handler()
        except Exception:
            if self._response_started:
                self.close_connection = True
                return None
            try:
                self._send(400, {"error": "bad request"})
            except Exception:
                self.close_connection = True
            return None

    _default_lock = threading.Lock()
    _state_lock = threading.Lock()

    def _lock(self):
        return self.config.get("lock") or self._default_lock

    def _index(self):
        with self._state_lock:
            idx = self.config.get("_index")
            if idx is None:
                idx = self.config["_index"] = _CheckpointIndex(self.config["notary"].path)
        return idx

    def _rate_ok(self, key):
        now = time.monotonic()
        limit = self.config.get("post_rate_limit", POST_RATE_LIMIT)
        with self._state_lock:
            hits = self.config.setdefault("_rate", {})
            recent = [t for t in hits.get(key, []) if now - t < POST_RATE_WINDOW]
            if len(recent) >= limit:
                hits[key] = recent
                return False
            recent.append(now)
            hits[key] = recent
        return True

    def log_message(self, fmt, *args):
        pass


def serve(store, *, host="127.0.0.1", port=DEFAULT_PORT):
    """Run the hosted witness over ``<store>/witness.jsonl``."""
    store = os.path.expanduser(store)
    if not os.path.isdir(store):
        os.makedirs(store, exist_ok=True)
    notary = Notary(os.path.join(store, WITNESS_FILE))
    keys = load_keys(store)
    if len(keys) > 1 and any(scopes is None for _k, scopes in keys):
        raise SystemExit("halo witness: several vendor keys are configured, so every key "
                         "needs a subject scope (key=glob|glob); refusing to start")
    read_env = os.environ.get("HALO_WITNESS_READ_KEYS")
    read_keys = parse_key_spec(read_env.split(",")) if read_env else []
    if any(scopes is None for _k, scopes in read_keys):
        raise SystemExit("halo witness: every read key needs a subject scope "
                         "(key=glob|glob); refusing to start")
    handler = type("_BoundWitness", (_Handler,),
                   {"config": {"notary": notary, "keys": keys, "read_keys": read_keys,
                               "lock": threading.Lock()}})
    httpd = ThreadingHTTPServer((host, port), handler)
    print("Halo witness serving from %s" % os.path.join(store, WITNESS_FILE))
    print("  anchor (vendor): POST http://%s:%s/anchor   (Bearer key required)" % (host, port))
    if read_keys:
        print("  checkpoints (scoped read key): GET http://%s:%s/v1/checkpoints?subject=<id>"
              % (host, port))
    else:
        print("  checkpoints (public): GET http://%s:%s/v1/checkpoints?subject=<id>" % (host, port))
        print("  note: reads are public — anyone who guesses a subject id sees that it is "
              "anchored and its record count; set HALO_WITNESS_READ_KEYS to scope reads.")
    if not os.environ.get("HALO_WITNESS_KEYS"):
        print("  vendor key: %s" % keys[0][0])
    print("  Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
    return 0
