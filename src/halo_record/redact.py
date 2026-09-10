"""Sensitive-data detection and redaction.

``scan`` finds known secret and personal-data patterns in text; ``redact_text``
/ ``redact_sample`` mask them. Detection is two layers, both deterministic and
explainable (never a model judgement):

1. a list of known secret/PII patterns — API keys, tokens, private keys, DB
   connection strings, JWTs, credit cards, SSNs, emails, phone numbers, IBANs,
   internal IPs — and
2. a high-entropy catch-all that flags long random-looking tokens the patterns
   miss (the provider key formats nobody has hardcoded yet).

Coverage is by named pattern, so it is best-effort, not comprehensive: free-form
personal data with no fixed shape — a person's name, a postal address — has no
reliable pattern and is not detected here. Treat redaction as defense-in-depth
for an artifact handed to a third party, not a guarantee that a summary can
carry no personal data (see LIMITS.md). Over-redaction is the safe failure.
Pattern-for-pattern port of the TypeScript ``redact.ts``.
"""

import math
import re
from collections import Counter

PATTERNS = [
    ("api_key",      "CRITICAL", re.compile(r'(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[a-zA-Z0-9\-]{10,})')),
    ("gcp_api_key",  "CRITICAL", re.compile(r'AIza[0-9A-Za-z_\-]{35,}')),
    ("aws_secret_key", "CRITICAL", re.compile(r'(?i)aws_secret_access_key(?:\s*[=:]\s*|\s+)["\']?[A-Za-z0-9/+=]{40}')),
    ("webhook_url",   "CRITICAL", re.compile(r'https://(?:hooks\.slack\.com/services/|discord(?:app)?\.com/api/webhooks/|[a-z0-9.-]+\.webhook\.office\.com/webhookb2/|outlook\.office\.com/webhook/)[^\s"\'<>]+')),
    ("stripe_key",   "CRITICAL", re.compile(r'(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{16,}')),
    ("github_token", "CRITICAL", re.compile(r'(?:gh[opsu]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})')),
    # Matches the whole PEM block when the footer is present (so the key body is
    # masked, not just the header line). When the block is truncated, consumes
    # the base64-shaped body lines that follow the header, so a partial key
    # still cannot leak through the mask.
    ("private_key",  "CRITICAL", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----(?:[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:\n[A-Za-z0-9+/=]+(?![^\n]))*)')),
    ("db_conn",      "CRITICAL", re.compile(r'(?:postgres|mysql|mongodb(?:\+srv)?|redis)://[^\s"\'<>]+')),
    ("jwt",          "HIGH",     re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')),
    ("credit_card",  "HIGH",     re.compile(r'\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))(?:[ -]?[0-9]){9,13}\b')),
    ("ssn",          "HIGH",     re.compile(r'\b\d{3}[- ]\d{2}[- ]\d{4}\b')),
    ("bearer_token", "HIGH",     re.compile(r'Bearer\s+[a-zA-Z0-9\-_\.]{20,}')),
    ("email",        "MEDIUM",   re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')),
    ("ip_internal",  "MEDIUM",   re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b')),
    ("phone",        "MEDIUM",   re.compile(r'\b(?:\+?1[-.\s])?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b')),
    ("iban",         "HIGH",     re.compile(r'\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]){11,30}\b')),
]

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# High-entropy catch-all: long, mixed enough to be machine-generated rather
# than prose, and not a recognizable hash/UUID/id.
HIGH_ENTROPY_TYPE = "high_entropy_secret"
HIGH_ENTROPY_MIN_LEN = 24
HIGH_ENTROPY_BITS = 3.5
TOKEN_RE = re.compile(r'[A-Za-z0-9+/=_-]{24,}')
MAX_PER_TYPE = 25

_HEX_RE = re.compile(r'[0-9a-fA-F]+$')
_UUID_RE = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-')
_DIGITS_RE = re.compile(r'\d+$')


def _shannon_bits(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _looks_like_secret(tok):
    if len(tok) < HIGH_ENTROPY_MIN_LEN:
        return False
    if _HEX_RE.fullmatch(tok):           # hex digest
        return False
    if _UUID_RE.match(tok):              # UUID
        return False
    if _DIGITS_RE.fullmatch(tok):        # long number / id
        return False
    has_digit = any(c.isdigit() for c in tok)
    has_upper = any(c.isupper() for c in tok)
    has_lower = any(c.islower() for c in tok)
    if not (has_digit or (has_upper and has_lower)):  # prose / slugs
        return False
    return _shannon_bits(tok) >= HIGH_ENTROPY_BITS


def redact_sample(ftype, value):
    v = str(value)
    if ftype == "aws_secret_key":
        i = max(v.rfind("="), v.rfind(":"), v.rfind(" "))
        return (v[:i + 1] + "****") if i > 0 else "****"
    if ftype == "webhook_url":
        m = re.match(r'https://[^/]+/[a-z0-9]+/', v)
        return (m.group(0) + "****") if m else "https://****"
    if ftype == "email":
        m = re.match(r'^([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@.+)$', v)
        return (m.group(1) + "****" + m.group(2)) if m else "****"
    if ftype == "db_conn":
        return re.sub(r'://([^:/@]+):[^@]+@', r'://\1:****@', v)
    if ftype == "bearer_token":
        return "Bearer ****"
    if ftype == "private_key":
        # Deliberately header-free: a mask that echoed the PEM header would trip
        # secret scanners on every artifact that contains it, and re-redaction
        # would not be idempotent.
        return "[PRIVATE KEY REDACTED]"
    if ftype == "jwt":
        return "eyJ****"
    if ftype in ("api_key", "gcp_api_key", "stripe_key", "github_token"):
        return (v[:4] + "****") if len(v) > 4 else "****"
    if ftype == HIGH_ENTROPY_TYPE:
        return (v[:3] + "****") if len(v) > 3 else "****"
    if ftype == "credit_card":
        digits = re.sub(r'\D', '', v)
        return ("****" + digits[-4:]) if len(digits) >= 4 else "****"
    if ftype == "ssn":
        return ("***-**-" + v[-4:]) if len(v) >= 4 else "****"
    if ftype == "phone":
        digits = re.sub(r'\D', '', v)
        return ("***-***-" + digits[-4:]) if len(digits) >= 4 else "****"
    if ftype == "iban":
        return (v[:2] + "****") if len(v) > 2 else "****"
    if ftype == "ip_internal":
        parts = v.split(".")
        return ".".join(parts[:2] + ["*", "*"]) if len(parts) == 4 else "****"
    return "****"


def _luhn_ok(value):
    """Luhn check over the digits of ``value`` (13–19 long). Distinguishes a real
    card number from an incidental digit run — e.g. the numeric body of an IBAN,
    whose groups can look card-shaped — so a card finding is only raised for a
    number that actually checksums as one."""
    digits = [int(c) for c in str(value) if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _apply_patterns(text):
    out = text
    for name, _sev, pattern in PATTERNS:
        if name == "credit_card":
            out = pattern.sub(
                lambda m: redact_sample("credit_card", m.group(0))
                if _luhn_ok(m.group(0)) else m.group(0), out)
        else:
            out = pattern.sub(lambda m, n=name: redact_sample(n, m.group(0)), out)
    return out


def mask_known_secrets(text):
    """Mask only the named secret/PII patterns in ``text`` — no high-entropy
    catch-all. For fields whose legitimate values ARE high-entropy (authority
    hashes and refs), where the catch-all would mangle the very thing the field
    exists to carry."""
    return _apply_patterns(str(text))


def redact_text(text, entropy=True):
    # Patterns first, then sweep the residual for high-entropy tokens the
    # patterns did not cover (running on the residual avoids re-masking "****").
    # ``entropy=False`` keeps the named patterns and skips the catch-all: used
    # for path-typed argument fields, whose legitimate values look like secrets.
    after = _apply_patterns(str(text))
    if not entropy:
        return after
    return TOKEN_RE.sub(
        lambda m: redact_sample(HIGH_ENTROPY_TYPE, m.group(0))
        if _looks_like_secret(m.group(0)) else m.group(0),
        after,
    )


def scan(text, entropy=True):
    """Return redacted findings for every sensitive pattern in ``text``.

    Emits one finding per distinct match (deduped on the redacted sample,
    capped per type) so counts reflect reality instead of collapsing to
    one-per-kind.
    """
    s = str(text)
    findings = []
    seen = set()

    for name, severity, pattern in PATTERNS:
        n = 0
        for m in pattern.findall(s):
            raw = m if isinstance(m, str) else next((x for x in m if x), "")
            if name == "credit_card" and not _luhn_ok(raw):
                continue
            sample = redact_sample(name, str(raw)[:120])
            key = name + ":" + sample
            if key in seen:
                continue
            seen.add(key)
            findings.append({"type": name, "severity": severity, "sample": sample})
            n += 1
            if n >= MAX_PER_TYPE:
                break

    # High-entropy catch-all over the pattern-redacted residual, so tokens
    # already flagged above are not double-counted.
    if not entropy:
        return findings
    findings += _entropy_findings(s, seen)

    return findings


def top_severity(findings):
    if not findings:
        return "INFO"
    return max(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 0))["severity"]


# Argument keys whose values are file-system paths, globs, or URLs by
# contract. A path is exactly the shape the entropy catch-all misreads as a
# secret. Under these keys, when the value is anchored as a path (leading
# slash, drive letter, scheme, dot-relative prefix, file extension, or glob
# metacharacter) and carries no query or credential separators, the value is
# left READABLE in the summary — but it is still scanned: an entropy hit there
# is reported as ``high_entropy_path_value`` (LOW) instead of masked, so
# ``findings: []`` keeps meaning "the scanner found nothing anywhere".
PATH_KEYS = frozenset({
    "file_path", "filePath", "notebook_path", "notebookPath", "path", "paths",
    "filenames", "files", "file", "cwd", "pattern", "glob", "directory", "dir",
    "old_path", "new_path", "target_file", "source_file", "workdir",
    "url", "uri", "href", "urls",
})
HIGH_ENTROPY_PATH_TYPE = "high_entropy_path_value"
_NOT_PATH_CHARS = ("=", "?", "&", "%", "@")
_PATH_ANCHOR_RE = re.compile(r'^(?:[/~]|\./|\.\./|[A-Za-z]:[\\/]|[a-z][a-z0-9+.-]*://)')
_PATH_EXT_RE = re.compile(r'\.[A-Za-z0-9]{1,6}$')
_GLOB_CHARS = ("*", "[", "{")


def path_value(key, value):
    """True when ``value`` under ``key`` is treated as a readable path."""
    if key not in PATH_KEYS or not isinstance(value, str) or not value:
        return False
    if any(c in value for c in _NOT_PATH_CHARS):
        return False
    if value[0] in "/~" and "/" not in value[1:] and "." not in value:
        return False  # a lone leading slash on an opaque token is not a path
    return bool(_PATH_ANCHOR_RE.match(value) or _PATH_EXT_RE.search(value)
                or any(c in value for c in _GLOB_CHARS))


def _entropy_findings(text, seen, ftype=HIGH_ENTROPY_TYPE, severity="HIGH"):
    out = []
    residual = _apply_patterns(str(text))
    e = 0
    for tok in TOKEN_RE.findall(residual):
        if not _looks_like_secret(tok):
            continue
        sample = redact_sample(HIGH_ENTROPY_TYPE, tok)
        key = ftype + ":" + sample
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": ftype, "severity": severity, "sample": sample})
        e += 1
        if e >= MAX_PER_TYPE:
            break
    return out


_PATCH_HEADER_RE = re.compile(r'^(\*\*\* (?:Update|Add|Delete|Move to) File: )(.+)$', re.M)


def _split_patch_headers(text):
    """Yield (segment, is_path) pieces so patch file headers can be treated as
    path values while the patch body keeps the full pass."""
    pos = 0
    for m in _PATCH_HEADER_RE.finditer(text):
        yield text[pos:m.start(2)], False
        yield m.group(2), True
        pos = m.end(2)
    yield text[pos:], False


def redact_fields(obj, _entropy=True, _depth=0):
    """Redact a tool-argument structure leaf by leaf, keeping its shape.

    Strings under path-typed keys that pass ``path_value`` keep their text
    (named patterns still masked); every other string gets the full pass.
    Dict keys are redacted too. Nesting is preserved so ``str()`` of the
    result reads like ``str()`` of the original."""
    if _depth > 8:
        return "…"
    if isinstance(obj, str):
        if _entropy and "*** Begin Patch" in obj:
            return "".join(redact_text(seg, entropy=not (is_path and path_value("file_path", seg)))
                           for seg, is_path in _split_patch_headers(obj))
        return redact_text(obj, entropy=_entropy)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            rk = redact_text(k) if isinstance(k, str) else k
            if isinstance(v, (list, tuple)):
                out[rk] = [redact_fields(el, not path_value(k, el), _depth + 1) for el in v]
            else:
                out[rk] = redact_fields(v, not path_value(k, v), _depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact_fields(v, _entropy, _depth + 1) for v in obj]
    return obj


def scan_fields(obj, _entropy=True, _depth=0, _seen=None, _key=None):
    """Findings over a tool-argument structure, leaf by leaf, deduped.

    The scanner looks everywhere. Under a path-typed key an entropy hit is
    reported as ``high_entropy_path_value`` (LOW) rather than as a secret,
    matching what ``redact_fields`` leaves readable."""
    if _seen is None:
        _seen = set()
    out = []
    if _depth > 8:
        return out
    if isinstance(obj, str):
        if _entropy and "*** Begin Patch" in obj:
            for seg, is_path in _split_patch_headers(obj):
                out += scan_fields(seg, _entropy, _depth + 1, _seen, "file_path" if is_path else None)
            return out
        if path_value(_key, obj):
            for f in scan(obj, entropy=False):
                key = f["type"] + ":" + f.get("sample", "")
                if key not in _seen:
                    _seen.add(key)
                    out.append(f)
            out += _entropy_findings(obj, _seen, HIGH_ENTROPY_PATH_TYPE, "LOW")
            return out
        for f in scan(obj, entropy=_entropy):
            key = f["type"] + ":" + f.get("sample", "")
            if key not in _seen:
                _seen.add(key)
                out.append(f)
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                out += scan_fields(k, True, _depth + 1, _seen, None)
            if isinstance(v, (list, tuple)):
                for el in v:
                    out += scan_fields(el, _entropy, _depth + 1, _seen, k)
            else:
                out += scan_fields(v, _entropy, _depth + 1, _seen, k)
        return out
    if isinstance(obj, (list, tuple)):
        for v in obj:
            out += scan_fields(v, _entropy, _depth + 1, _seen, None)
        return out
    return scan_fields(str(obj), _entropy, _depth + 1, _seen, None) if obj is not None else out
