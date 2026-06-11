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

        prev_hash = declared_hash if declared_hash else recomputed

    if ok:
        out("OK: %d record(s) valid, hash chain intact." % len(lines))
    else:
        out("FAIL: log did not verify.")
    return ok
