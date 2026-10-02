"""RFC 8785 (JSON Canonicalization Scheme) + SHA-256 hashing.

This is the subset of RFC 8785 the Halo Runtime Record format relies on. It is
the single source of truth for canonicalization across the package; the recorder
and the verifier both call into it so emitted records and verification agree.
"""

import hashlib
import json
import re

GENESIS_PREV = "0" * 64


MAX_SAFE_INT = 2 ** 53 - 1


def canon_issues(value, path="record"):
    """Values no two JSON implementations are guaranteed to hash identically:
    non-integer, exponent-form, or out-of-range numbers. The recorder never
    writes them; a stored record carrying one was not sealed by it."""
    issues = []
    if isinstance(value, bool) or value is None:
        return issues
    if isinstance(value, str):
        # Lone surrogates are not an issue: every implementation hashes them as
        # U+FFFD, and earlier recorders could store one by truncating an emoji.
        return issues
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            issues.append("%s: integer beyond 2^53-1" % path)
        return issues
    if isinstance(value, float):
        issues.append("%s: non-integer or exponent-form number" % path)
        return issues
    if isinstance(value, dict):
        for k, v in value.items():
            issues.extend(canon_issues(k, path + ".<key>"))
            issues.extend(canon_issues(v, "%s.%s" % (path, k)))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            issues.extend(canon_issues(v, "%s[%d]" % (path, i)))
    return issues


def canon(value):
    """Return the RFC 8785 canonical JSON serialization of ``value`` as a str."""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return _canon_string(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise ValueError("integer %d exceeds 2^53-1; JSON readers that parse numbers "
                             "as doubles would hash it differently" % value)
        return str(value)
    if isinstance(value, float):
        return _canon_number(value)
    if isinstance(value, list):
        return "[" + ",".join(canon(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise TypeError("cannot canonicalize a non-string object key %r" % (k,))
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_canon_string(k) + ":" + canon(v) for k, v in items) + "}"
    raise TypeError("cannot canonicalize %r" % type(value))


_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n",
            "\f": "\\f", "\r": "\\r"}
# Characters RFC 8785 escapes, plus lone surrogates: those have no UTF-8
# encoding, so they are hashed as U+FFFD, the bytes every UTF-8 encoder (Node's
# included) produces, and the recorder never raises. Verification rejects
# stored lone surrogates.
_NEEDS_ESCAPE = re.compile('[\x00-\x1f"\\\\\ud800-\udfff]')


def _escape(m):
    ch = m.group(0)
    if ch in _ESCAPES:
        return _ESCAPES[ch]
    if ch >= "\ud800":
        return "\ufffd"
    return "\\u%04x" % ord(ch)


def _canon_string(s):
    return '"' + _NEEDS_ESCAPE.sub(_escape, s) + '"'


def _canon_number(f):
    if f != f or f in (float("inf"), float("-inf")):
        raise ValueError("non-finite number is not valid JSON")
    if f == int(f):
        return str(int(f))
    raise ValueError(
        "non-integer float %r: full RFC 8785 number formatting is out of scope; "
        "the record format uses integer-valued numbers only" % f
    )


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_hash(record, prev_hash):
    """A record's integrity.hash: set integrity.prev_hash, drop integrity.hash,
    canonicalize per RFC 8785, return the lowercase SHA-256 hex digest."""
    clone = json.loads(json.dumps(record))
    integ = clone.setdefault("integrity", {})
    integ["prev_hash"] = prev_hash
    integ.pop("hash", None)
    return sha256_hex(canon(clone))


def input_hash(value):
    """``sha256:`` + SHA-256 of the canonical arguments. Falls back to a stable
    sorted-key serialization if ``value`` isn't strictly canonicalizable, and
    finally to the canonical form of a JSON-safe copy (string keys, cycles and
    excess depth marked), so a recorder embedded in a hook never crashes on an
    odd input."""
    try:
        c = canon(value)
    except Exception:
        try:
            c = json.dumps(value, sort_keys=True, separators=(",", ":"))
        except Exception:
            try:
                c = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
            except Exception:
                c = canon(json_safe(value))
    return "sha256:" + sha256_hex(c)


MAX_DEPTH = 64
CIRCULAR = "[circular]"
TOO_DEEP = "[nested too deeply]"


_HUGE_INT = 10 ** 4300


def int_text(v):
    """``str(v)``, or ``[integer of N bits]`` for an integer of more than 4300
    digits: Python 3.11+ refuses to print one, and every runtime must store
    the same text for it."""
    if -_HUGE_INT < v < _HUGE_INT:
        return str(v)
    return "[integer of %d bits]" % v.bit_length()


def sort_key(v):
    """``repr(v)`` for ordering set members, safe for any integer."""
    return int_text(v) if isinstance(v, int) and not isinstance(v, bool) else repr(v)


def json_key(k):
    """The string a JSON encoder would use for a non-string key (``True`` ->
    ``"true"``, ``None`` -> ``"null"``, ``1`` -> ``"1"``); ``str()`` otherwise."""
    if isinstance(k, str):
        return k
    if k is True:
        return "true"
    if k is False:
        return "false"
    if k is None:
        return "null"
    if isinstance(k, int):
        return int_text(k)
    if isinstance(k, float):
        return json.dumps(k)
    return str(k)


def json_safe(value, _depth=0, _active=None):
    """A canonicalizable copy of ``value``: string keys (a collision keeps both),
    lists for tuples and sets, strings for bytes, non-integer or out-of-range
    numbers and other objects, and markers in place of a cycle or nesting
    beyond ``MAX_DEPTH``."""
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value if abs(value) <= MAX_SAFE_INT else int_text(value)
    if isinstance(value, float):
        if value == value and value not in (float("inf"), float("-inf")) and value.is_integer() \
                and abs(value) <= MAX_SAFE_INT:
            return int(value)
        return str(value)
    if _depth >= MAX_DEPTH:
        return TOO_DEEP
    if isinstance(value, (dict, list, tuple, set, frozenset)):
        _active = _active if _active is not None else set()
        if id(value) in _active:
            return CIRCULAR
        _active.add(id(value))
        try:
            if isinstance(value, dict):
                out = {}
                for k, v in value.items():
                    key = base = json_key(k)
                    n = 2
                    while key in out:
                        key = "%s#%d" % (base, n)
                        n += 1
                    out[key] = json_safe(v, _depth + 1, _active)
                return out
            items = sorted(value, key=sort_key) if isinstance(value, (set, frozenset)) else value
            return [json_safe(v, _depth + 1, _active) for v in items]
        finally:
            _active.discard(id(value))
    return str(value)
