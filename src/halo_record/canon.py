"""RFC 8785 (JSON Canonicalization Scheme) + SHA-256 hashing.

This is the subset of RFC 8785 the Halo Runtime Record format relies on. It is
the single source of truth for canonicalization across the package; the recorder
and the verifier both call into it so emitted records and verification agree.
"""

import hashlib
import json

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
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_canon_string(k) + ":" + canon(v) for k, v in items) + "}"
    raise TypeError("cannot canonicalize %r" % type(value))


def _canon_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif 0xD800 <= o <= 0xDFFF:
            # A lone surrogate has no UTF-8 encoding; hash it as U+FFFD, the
            # same bytes every UTF-8 encoder (Node's included) produces, so the
            # recorder never raises. Verification rejects stored lone surrogates.
            out.append("\ufffd")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


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
    sorted-key serialization if ``value`` isn't strictly canonicalizable, so a
    recorder embedded in a hook never crashes on an odd input."""
    try:
        c = canon(value)
    except (TypeError, ValueError):
        try:
            c = json.dumps(value, sort_keys=True, separators=(",", ":"))
        except TypeError:
            c = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + sha256_hex(c)
