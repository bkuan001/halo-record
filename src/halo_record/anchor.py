"""Completeness witnessing — the neutral-notary layer.

A per-tenant hash chain is internally tamper-evident: you cannot alter a past
record without breaking every hash after it. But a vendor who *hosts their own*
chain can still drop an embarrassing record and rebuild the chain from scratch.
The rebuilt chain verifies internally — so hash-chaining alone proves
tamper-evidence, **not completeness**. ("Did you show me every record, or a
curated subset?")

The notary closes that gap. A neutral party (Halo) periodically *witnesses* each
chain's head: it records ``(chain_root, count, head, ts)`` in its own append-only
log that the vendor does not control. To later hide record ``k``, the vendor
would have to rewrite history on Halo's independent witness log too. Completeness
becomes something the buyer checks against a party with no incentive to help the
vendor hide — which is exactly the guarantee the vendor's own logs can never give.

This module is pure-stdlib, consistent with the rest of the package. Offline,
*signed* receipts (so a buyer can verify a witness without contacting Halo) are a
planned extra (asymmetric signatures) and intentionally not implemented here; the
witness store is the complete guarantee on its own.
"""

import json
import os
from datetime import datetime, timezone

from .canon import GENESIS_PREV, compute_hash


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
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(cp, separators=(",", ":")) + "\n")
        return cp

    def checkpoints(self, subject=None):
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8") as fh:
            cps = [json.loads(ln) for ln in fh.read().splitlines() if ln.strip()]
        if subject is not None:
            cps = [c for c in cps if c.get("subject") == subject]
        return cps


def _matches(cp, records):
    """Does a checkpoint witness *this* chain? Keyed on the subject (the customer
    identity, asserted by the viewer and outside the vendor's control). Only
    subjectless chains fall back to chain_root — which a vendor *can* change by
    dropping the first record, so it is never the primary key."""
    subj = _subject_id(records)
    if subj is not None:
        return cp.get("subject") == subj
    return cp.get("chain_root") == chain_root(records)


def verify_completeness(records, checkpoints):
    """Check a presented chain against what the notary independently witnessed.

    Returns a dict:
      * ``{"ok": None, ...}``  — no witnesses for this chain (unknown, not a
        failure: the chain was simply never anchored).
      * ``{"ok": False, ...}`` — the presented chain is missing or altered a
        record the notary already witnessed (dropped, truncated, or rewritten).
      * ``{"ok": True, ...}``  — every witnessed checkpoint still matches; the
        vendor could not have removed a record the notary saw.
    """
    relevant = [c for c in checkpoints if _matches(c, records)]
    if not relevant:
        return {"ok": None, "why": "no witnesses for this chain", "witnessed": 0}

    broken_at = _chain_intact(records)
    if broken_at:
        return {"ok": False, "why": "chain integrity broken", "at": broken_at,
                "witnessed": len(relevant)}

    latest = max(c["count"] for c in relevant)
    if len(records) < latest:
        return {"ok": False, "why": "chain truncated below witnessed length",
                "have": len(records), "witnessed_count": latest,
                "witnessed": len(relevant)}

    for c in relevant:
        n = c["count"]
        if n < 1 or n > len(records):
            return {"ok": False, "why": "witnessed count out of range", "at": n,
                    "witnessed": len(relevant)}
        present_head = (records[n - 1].get("integrity") or {}).get("hash")
        if present_head != c["head"]:
            return {"ok": False, "why": "record altered or dropped before witnessed point",
                    "at": n, "witnessed": len(relevant)}

    return {"ok": True, "witnessed": len(relevant), "latest_count": latest,
            "head": head(records)}
