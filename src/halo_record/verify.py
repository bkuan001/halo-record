"""Conformance verification: schema validation + hash-chain integrity.

Dependency-free. Validates each record against the bundled JSON Schema and
confirms the RFC 8785 + SHA-256 hash chain is intact.
"""

import json
import os
import re
from datetime import datetime, timedelta

from .canon import GENESIS_PREV, canon_issues, compute_hash

_SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "halo-record.schema.json")

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "number": (int, float),
    "integer": int,
    "boolean": bool,
    "null": type(None),
}


def load_schema():
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _validate(node, schema, path, errors):
    if "const" in schema and node != schema["const"]:
        errors.append("%s: expected const %r, got %r" % (path, schema["const"], node))
    if "enum" in schema and node not in schema["enum"]:
        errors.append("%s: %r not in enum %r" % (path, node, schema["enum"]))

    t = schema.get("type")
    if t:
        if t in ("number", "integer") and isinstance(node, bool):
            errors.append("%s: expected %s, got boolean" % (path, t))
        elif not isinstance(node, _TYPES[t]):
            errors.append("%s: expected %s, got %s" % (path, t, type(node).__name__))
            return

    if isinstance(node, dict):
        for req in schema.get("required", []):
            if req not in node:
                errors.append("%s: missing required field %r" % (path, req))
        props = schema.get("properties", {})
        for key, val in node.items():
            if key in props:
                _validate(val, props[key], "%s.%s" % (path, key), errors)

    if isinstance(node, list) and "items" in schema:
        for i, item in enumerate(node):
            _validate(item, schema["items"], "%s[%d]" % (path, i), errors)


def validate_record(record, schema=None):
    schema = schema or load_schema()
    errors = []
    _validate(record, schema, "record", errors)
    return errors


def verify_records(records, schema=None, out=None):
    """verify_log for records already in memory (reports, policy, serving):
    the same schema, canonical-form, duplicate-id, and chain checks."""
    import json as _json
    lines = [_json.dumps(r, separators=(",", ":")) for r in records]
    return _verify_lines(lines, schema, out or (lambda *_a, **_k: None))


def read_log_lines(path):
    """The non-blank lines of a JSONL chain file, split the way every verifier
    splits them. JSON Lines are separated by "\n" only: U+2028/U+2029/U+0085
    are legal inside JSON strings and must not split a record, and a CR is JSON
    whitespace (newline="" keeps it in place rather than splitting on it). A
    leading byte-order mark is skipped, as a UTF-8 decoder does. Raises
    ``UnicodeDecodeError`` / ``OSError`` like ``open``."""
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        return [ln for ln in fh.read().split("\n") if ln.strip()]


def verify_log(path, schema=None, out=print):
    try:
        lines = read_log_lines(path)
    except UnicodeDecodeError as e:
        out("FAIL: log is not valid UTF-8 (%s)" % e)
        return False
    except OSError as e:
        out("FAIL: cannot read %s: %s" % (path, e.strerror or e))
        return False
    return _verify_lines(lines, schema, out)


# Integer literals longer than this are not parsed (Python limits int/str
# conversion to 4300 digits); any integer beyond 2^53-1 already fails the
# canonical-form check, so such a record cannot verify either way.
_MAX_INT_DIGITS = 4000


def _parse_int(text):
    if len(text) > _MAX_INT_DIGITS:
        raise ValueError("integer literal with %d digits is beyond what the record "
                         "format allows" % len(text))
    return int(text)


_TS_PARTS = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?"
    r"(?:([Zz])|([+-])(\d{2}):(\d{2}))$")


def _instant(ts):
    """A sortable instant for an RFC 3339 ``ts`` (nanosecond precision, offsets
    applied), or None when it does not parse."""
    if not isinstance(ts, str):
        return None
    m = _TS_PARTS.match(ts)
    if not m:
        return None
    try:
        dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                      int(m.group(4)), int(m.group(5)), int(m.group(6)))
    except ValueError:
        return None
    if m.group(9):
        off = timedelta(hours=int(m.group(10)), minutes=int(m.group(11)))
        dt = dt - off if m.group(9) == "+" else dt + off
    nanos = int((m.group(7) or "").ljust(9, "0") or 0)
    return (dt, nanos)


def _verify_lines(lines, schema, out):
    schema = schema or load_schema()

    ok = True
    chain_ok = True           # hash-chain/sequence integrity, distinct from schema
    prev_hash = GENESIS_PREV
    chain_broken_at = None    # first record whose break makes everything after it unprovable
    seen_ids = set()          # record_ids seen so far, to resolve parent links
    parent_links = 0          # records that declare a parent_id
    orphan_links = 0          # parent_ids not found earlier in this chain
    unreadable = 0            # lines that are not complete JSON records
    prev_instant = None       # last parseable ts, for the ordering warning
    prev_ts = None
    backdated = 0             # records whose ts is earlier than the one before
    for n, line in enumerate(lines, start=1):
        try:
            record = json.loads(line, parse_int=_parse_int)
        except RecursionError:
            out("record %d: not valid JSON: nested too deeply" % n)
            ok = False
            unreadable += 1
            continue
        except ValueError as e:  # JSONDecodeError, or an over-long integer
            out("record %d: not valid JSON: %s" % (n, e))
            ok = False
            unreadable += 1
            continue
        if not isinstance(record, dict):
            out("record %d: not a JSON object" % n)
            ok = False
            chain_ok = False
            if chain_broken_at is None:
                chain_broken_at = n
            continue
        shape_ok = True
        if not isinstance(record.get("integrity", {}), dict):
            out("record %d: integrity is not an object" % n)
            shape_ok = False
        for key in ("record_id", "parent_id"):
            if key in record and not isinstance(record[key], str):
                out("record %d: %s is not a string" % (n, key))
                shape_ok = False
        if not shape_ok:
            ok = False
            chain_ok = False
            if chain_broken_at is None:
                chain_broken_at = n
            continue

        # Timestamps are declared by the producer; the sealed order is the
        # chain order. A ts earlier than the one before it is surfaced (it can
        # mean a backdated record), not failed: clocks and retries can do it.
        instant = _instant(record.get("ts"))
        if instant is not None:
            if prev_instant is not None and instant < prev_instant:
                backdated += 1
                out("record %d: warning: ts %s is earlier than the previous "
                    "record's ts %s" % (n, record.get("ts"), prev_ts))
            prev_instant, prev_ts = instant, record.get("ts")

        for err in validate_record(record, schema):
            out("record %d: schema: %s" % (n, err))
            ok = False

        for issue in canon_issues(record):
            out("record %d: canonical form: %s" % (n, issue))
            ok = False
        integ = record.get("integrity", {})
        declared_prev = integ.get("prev_hash")
        declared_hash = integ.get("hash")
        try:
            recomputed = compute_hash(record, prev_hash)
        except (ValueError, TypeError) as e:
            out("record %d: chain: cannot be hashed canonically (%s)" % (n, e))
            ok = False
            chain_ok = False
            if chain_broken_at is None:
                chain_broken_at = n
            recomputed = "!unhashable!%d" % n

        # After the first break, a per-record check here is uninformative (see
        # the summary line below) -- LIMITS.md section 9 already covers why.
        if chain_broken_at is None:
            if declared_prev != prev_hash:
                out("record %d: chain: prev_hash %s does not match expected %s"
                    % (n, declared_prev, prev_hash))
                ok = False
                chain_ok = False
                chain_broken_at = n

            if declared_hash != recomputed:
                out("record %d: chain: hash %s does not match recomputed %s"
                    % (n, declared_hash, recomputed))
                ok = False
                chain_ok = False
                chain_broken_at = n
        else:
            ok = False

        # Delegation referential integrity: a parent_id should point at a record
        # that appeared earlier in this chain. An orphan is surfaced but does not
        # fail verification — a windowed export legitimately references parents
        # outside the window (see LIMITS.md).
        parent_id = record.get("parent_id")
        if parent_id:
            parent_links += 1
            if parent_id not in seen_ids:
                orphan_links += 1
                out("record %d: delegation: parent_id %s not found earlier in "
                    "this chain" % (n, parent_id))
        record_id = record.get("record_id")
        if record_id:
            if record_id in seen_ids:
                # Two records sharing an id make every id-keyed view ambiguous
                # (a report could show one record's details for another's row).
                out("record %d: duplicate record_id %s" % (n, record_id))
                ok = False
            seen_ids.add(record_id)

        prev_hash = recomputed  # never the record's own declared_hash

    if chain_broken_at is not None and chain_broken_at < len(lines):
        out("chain: record %d onward is not verifiable relative to the true "
            "chain (the break at record %d means nothing built on it can be "
            "proven intact or shown to be further tampered — see LIMITS.md "
            "section 9: https://github.com/bkuan001/halo-record/blob/main/LIMITS.md)." % (chain_broken_at + 1, chain_broken_at))

    if parent_links:
        if orphan_links:
            out("delegation: %d of %d parent link(s) reference records not in "
                "this chain (expected only for a windowed export)."
                % (orphan_links, parent_links))
        else:
            out("delegation: %d parent link(s) resolve within this chain "
                "(referential integrity only — not a claim the delegation graph "
                "is complete)." % parent_links)

    if backdated:
        out("warning: %d record(s) carry a ts earlier than the record before them; "
            "ts is declared by the producer, and the sealed order is the chain "
            "order (see LIMITS.md)." % backdated)

    if ok and not lines:
        out("OK: 0 records — an empty chain; nothing to attest.")
    elif ok:
        out("OK: %d record(s) valid, hash chain intact — tamper-evident relative to the verified head." % len(lines))
        out("note: this is integrity, not completeness — a self-held chain cannot show records that were removed and the chain re-sealed, anywhere in it; an external witness (halo anchor --check) is what attests nothing was dropped.")
    elif not chain_ok:
        out("FAIL: log did not verify — sequence integrity gap detected (see above).")
    elif unreadable:
        out("FAIL: log did not verify — %d line(s) are not complete records (a torn "
            "write or a truncation; see above); the hash chain of the remaining "
            "records is intact." % unreadable)
    else:
        out("FAIL: log did not verify — records do not match the record format "
            "(schema); the hash chain itself is intact (see above).")
    return ok
