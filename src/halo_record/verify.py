"""Conformance verification: schema validation + hash-chain integrity.

Dependency-free. Validates each record against the bundled JSON Schema and
confirms the RFC 8785 + SHA-256 hash chain is intact.
"""

import json
import os

from .canon import GENESIS_PREV, compute_hash

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


def verify_log(path, schema=None, out=print):
    schema = schema or load_schema()
    with open(path, "r", encoding="utf-8") as fh:
        lines = [ln for ln in fh.read().splitlines() if ln.strip()]

    ok = True
    prev_hash = GENESIS_PREV
    seen_ids = set()          # record_ids seen so far, to resolve parent links
    parent_links = 0          # records that declare a parent_id
    orphan_links = 0          # parent_ids not found earlier in this chain
    for n, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as e:
            out("record %d: not valid JSON: %s" % (n, e))
            ok = False
            continue

        for err in validate_record(record, schema):
            out("record %d: schema: %s" % (n, err))
            ok = False

        integ = record.get("integrity", {})
        declared_prev = integ.get("prev_hash")
        declared_hash = integ.get("hash")

        if declared_prev != prev_hash:
            out("record %d: chain: prev_hash %s does not match expected %s"
                % (n, declared_prev, prev_hash))
            ok = False

        recomputed = compute_hash(record, prev_hash)
        if declared_hash != recomputed:
            out("record %d: chain: hash %s does not match recomputed %s"
                % (n, declared_hash, recomputed))
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
            seen_ids.add(record_id)

        prev_hash = declared_hash if declared_hash else recomputed

    if parent_links:
        if orphan_links:
            out("delegation: %d of %d parent link(s) reference records not in "
                "this chain (expected only for a windowed export)."
                % (orphan_links, parent_links))
        else:
            out("delegation: %d parent link(s) resolve within this chain "
                "(referential integrity only — not a claim the delegation graph "
                "is complete)." % parent_links)

    if ok and not lines:
        out("OK: 0 records — an empty chain; nothing to attest.")
    elif ok:
        out("OK: %d record(s) valid, hash chain intact — tamper-evident relative to the verified head." % len(lines))
        out("note: this is integrity, not completeness — a self-held chain cannot show records dropped from the tail; an external witness (halo anchor --check) is what attests nothing was dropped.")
    else:
        out("FAIL: log did not verify — sequence integrity gap detected (see above).")
    return ok
