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
    ("gcp_api_key",  "CRITICAL", re.compile(r'AIza[0-9A-Za-z_\-]{35}')),
    ("stripe_key",   "CRITICAL", re.compile(r'(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{16,}')),
    ("github_token", "CRITICAL", re.compile(r'(?:gh[opsu]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})')),
    ("private_key",  "CRITICAL", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ("db_conn",      "CRITICAL", re.compile(r'(?:postgres|mysql|mongodb(?:\+srv)?|redis)://[^\s"\'<>]+')),
    ("jwt",          "HIGH",     re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')),
    ("credit_card",  "HIGH",     re.compile(r'\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))(?:[ -]?[0-9]){9,13}\b')),
    ("ssn",          "HIGH",     re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
    ("bearer_token", "HIGH",     re.compile(r'Bearer\s+[a-zA-Z0-9\-_\.]{20,}')),
    ("email",        "MEDIUM",   re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')),
    ("ip_internal",  "MEDIUM",   re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b')),
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
    if ftype == "email":
        m = re.match(r'^([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@.+)$', v)
        return (m.group(1) + "****" + m.group(2)) if m else "****"
    if ftype == "db_conn":
        return re.sub(r'://([^:/@]+):[^@]+@', r'://\1:****@', v)
    if ftype == "bearer_token":
        return "Bearer ****"
    if ftype == "private_key":
        return "-----BEGIN PRIVATE KEY----- ****"
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


def redact_text(text):
    # Patterns first, then sweep the residual for high-entropy tokens the
    # patterns did not cover (running on the residual avoids re-masking "****").
    after = _apply_patterns(str(text))
    return TOKEN_RE.sub(
        lambda m: redact_sample(HIGH_ENTROPY_TYPE, m.group(0))
        if _looks_like_secret(m.group(0)) else m.group(0),
        after,
    )


def scan(text):
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
    residual = _apply_patterns(s)
    e = 0
    for tok in TOKEN_RE.findall(residual):
        if not _looks_like_secret(tok):
            continue
        sample = redact_sample(HIGH_ENTROPY_TYPE, tok)
        key = HIGH_ENTROPY_TYPE + ":" + sample
        if key in seen:
            continue
        seen.add(key)
        findings.append({"type": HIGH_ENTROPY_TYPE, "severity": "HIGH", "sample": sample})
        e += 1
        if e >= MAX_PER_TYPE:
            break

    return findings


def top_severity(findings):
    if not findings:
        return "INFO"
    return max(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 0))["severity"]
