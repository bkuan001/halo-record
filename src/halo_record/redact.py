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

import hashlib
import math
import re
from collections import Counter

from .canon import int_text, sort_key

# Invisible characters spliced between the characters of a token would
# otherwise split a known key format so no pattern sees it. The set is every
# Unicode format character (category Cf) and every Default_Ignorable_Code_Point
# (both as of Unicode 15.1: soft hyphen, combining grapheme joiner, Hangul
# fillers, Khmer inherent vowels, variation selectors, tags, ...), plus two
# characters that render blank: U+2800 BRAILLE PATTERN BLANK and U+1D159
# MUSICAL SYMBOL NULL NOTEHEAD. They are dropped when they sit between token
# characters, or between a token character and a group separator (see
# _SEP_CLASS); elsewhere (an emoji ZWJ sequence, a bidi mark between two
# spaces) they are kept. The ranges are listed here, not read from ``unicodedata``, so every
# Python version and the TypeScript port strip the same set.
_INVISIBLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x0600, 0x0605), (0x061C, 0x061C),
    (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2),
    (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F),
    (0x202A, 0x202E), (0x2060, 0x206F), (0x2800, 0x2800), (0x3164, 0x3164),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFFB),
    (0x110BD, 0x110BD), (0x110CD, 0x110CD), (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3),
    (0x1D159, 0x1D159), (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)
INVISIBLE_CHARS = frozenset(chr(c) for a, b in _INVISIBLE_RANGES for c in range(a, b + 1))
_INVISIBLE_CLASS = "".join(
    re.escape(chr(a)) if a == b else "%s-%s" % (re.escape(chr(a)), re.escape(chr(b)))
    for a, b in _INVISIBLE_RANGES)

PATTERNS = [
    ("api_key",      "CRITICAL", re.compile(r'(?:sk-[A-Za-z0-9_\-]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[a-zA-Z0-9\-]{10,})')),
    ("gcp_api_key",  "CRITICAL", re.compile(r'AIza[0-9A-Za-z_\-]{35,}')),
    ("aws_secret_key", "CRITICAL", re.compile(r'(?i)aws_secret_access_key(?:\s*[=:]\s*|\s+)["\']?[A-Za-z0-9/+=]{40}')),
    ("webhook_url",   "CRITICAL", re.compile(r'https://(?:hooks\.slack\.com/services/|discord(?:app)?\.com/api/webhooks/|[a-z0-9.-]+\.webhook\.office\.com/webhookb2/|outlook\.office\.com/webhook/)[^\s"\'<>]+')),
    ("stripe_key",   "CRITICAL", re.compile(r'(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{16,}')),
    ("github_token", "CRITICAL", re.compile(r'(?:gh[opsu]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})')),
    # Matches the whole PEM / PGP armor block of any private-key label (RSA, EC,
    # DSA, OPENSSH, ENCRYPTED, PGP ... BLOCK) when the footer is present (so the
    # key body is masked, not just the header line). When the block is truncated, consumes
    # the base64-shaped body lines that follow the header, so a partial key
    # still cannot leak through the mask.
    ("private_key",  "CRITICAL", re.compile(
        r'-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----'
        r'(?:(?:(?!-----BEGIN)[\s\S])*?-----END (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----'
        # Truncated block: optional armor headers ("Version: ...", "Proc-Type:
        # ...") and the blank line after them, then the base64 body lines.
        r'|(?:(?:\n[A-Za-z][A-Za-z0-9-]{0,40}:[^\n]{0,200})*\n(?=\n[A-Za-z0-9+/=]))?'
        r'(?:\n[A-Za-z0-9+/=]+(?![^\n]))*)')),
    ("db_conn",      "CRITICAL", re.compile(r'(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://[^\s"\'<>]+')),
    # A password assigned in text ("password=...", "DB_PASSWORD: ...", a JSON
    # "password": "..." pair). Bounded value length keeps it linear.
    # An invisible run beside the separator or the quote is part of the gap,
    # never the value: the value class leaves invisible characters out, so a
    # zero-width space after "password": cannot be masked in place of it.
    ("password",     "CRITICAL", re.compile(
        r'(?i)(?<![A-Za-z0-9])(?:password|passwd|passphrase|pwd)["\']?[ \t]{0,3}[=:]'
        r'(?:[ \t' + _INVISIBLE_CLASS + r']{0,8})["\']?[' + _INVISIBLE_CLASS + r']{0,8}'
        r'[^\s"\',;<>' + _INVISIBLE_CLASS + r']{1,256}')),
    # A JWT starts a token (the lookbehind), so a run like "eyJeyJeyJ..." is
    # tried once rather than from every "eyJ" in it, and each segment is
    # bounded: matching stays linear on hostile text.
    ("jwt",          "HIGH",     re.compile(r'(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,8192}\.[A-Za-z0-9_-]{10,8192}\.[A-Za-z0-9_-]{10,8192}')),
    # IBAN runs BEFORE credit_card: an IBAN whose digit body happens to Luhn-
    # check would otherwise be card-masked first, leaving country/check digits
    # and the tail exposed. Shape-tolerant (case, space/dot/hyphen groups) and
    # gated on the mod-97 check, so ordinary identifiers are not classified.
    ("iban",         "HIGH",     re.compile(r'(?i)\b[A-Z]{2}[0-9]{2}(?:[ .\-\t\u00a0]{0,2}[A-Z0-9]{4}){2,7}(?:[ .\-\t\u00a0]{0,2}[A-Z0-9]{1,4})?\b')),
    # Digit groups may be separated by a space, hyphen, dot, no-break space,
    # figure space or narrow no-break space; the Luhn check gates the finding.
    ("credit_card",  "HIGH",     re.compile(r'\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))(?:[ .\-\u00a0\u2007\u202f]?[0-9]){9,13}\b')),
    ("ssn",          "HIGH",     re.compile(r'\b\d{3}[- ]\d{2}[- ]\d{4}\b')),
    # Telegram-style bot tokens: a numeric bot id, a colon, a ~35-char secret.
    # Often embedded in a URL path, where path-readable fields keep the rest.
    ("bot_token",    "HIGH",     re.compile(r'(?<![0-9])\d{8,10}:[A-Za-z0-9_-]{30,40}(?![A-Za-z0-9_-])')),
    ("bearer_token", "HIGH",     re.compile(r'Bearer\s+[a-zA-Z0-9\-_\.]{20,}')),
    # Bounded quantifiers (RFC 5321 local part <= 64, label <= 63, at most 16
    # labels) keep this linear on hostile input such as "a." * 40000.
    ("email",        "MEDIUM",   re.compile(r'\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,16}[A-Za-z]{2,24}\b')),
    ("ip_internal",  "MEDIUM",   re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b')),
    ("phone",        "MEDIUM",   re.compile(r'\b(?:\+?1[-.\s])?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b')),
]

# Text each pattern cannot match without (case-folded for the case-insensitive
# patterns). A pattern whose required text is absent is skipped: on long input
# that saves a full pass. Patterns not listed always run.
_REQUIRED = {
    "api_key": (("sk-", "AKIA", "xox"), False),
    "gcp_api_key": (("AIza",), False),
    "aws_secret_key": (("aws_secret_access_key",), True),
    "webhook_url": (("https://",), False),
    "stripe_key": (("_live_", "_test_"), False),
    "github_token": (("ghp_", "gho_", "ghs_", "ghu_", "github_pat_"), False),
    "private_key": (("-----BEGIN ",), False),
    "db_conn": (("://",), False),
    "password": (("pass", "pwd"), True),
    "jwt": (("eyJ",), False),
    "bot_token": ((":",), False),
    "bearer_token": (("Bearer",), False),
    "email": (("@",), False),
}


def _fold(text):
    # str.lower() leaves the long s as is, but the case-insensitive patterns
    # match it as "s" (as they match the Kelvin sign as "k", which lower() folds).
    return text.lower().replace("\u017f", "s")


def _may_match(name, text, folded):
    req = _REQUIRED.get(name)
    if req is None:
        return True
    hay = folded if req[1] else text
    return any(lit in hay for lit in req[0])


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


_PASSWORD_PREFIX_RE = re.compile(r'[^=:]*[=:][ \t]{0,3}["\']?')
_DB_USERINFO_RE = re.compile(r'^([A-Za-z][A-Za-z0-9+.\-]*://)([^:/@\s]*):.*@')


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
        # Anchored at the scheme: one attempt per match, linear in its length.
        # Everything from the user's ":" to the last "@" is masked, so an empty
        # user (redis://:pw@) or an unescaped "@" or "/" in the password is
        # still covered; over-masking the host is the safe failure.
        return _DB_USERINFO_RE.sub(r'\1\2:****@', v, count=1)
    if ftype == "bearer_token":
        return "Bearer ****"
    if ftype == "password":
        m = _PASSWORD_PREFIX_RE.match(v)
        return (m.group(0) + "****") if m else "****"
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
        return (v[:2].upper() + "****") if len(v) > 2 else "****"
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


_IBAN_SEP = re.compile(r'[ .\-\t\u00a0]')


def _iban_ok(value):
    """ISO 13616 mod-97 check over ``value`` with separators removed. Like the
    Luhn check for cards: a match is only a finding if it checksums, so an
    order number or licence key that happens to be IBAN-shaped is neither
    masked nor recorded as ``pii_types: ["iban"]``."""
    v = _IBAN_SEP.sub('', str(value)).upper()
    if not 15 <= len(v) <= 34 or not v[:2].isalpha() or not v[2:4].isdigit():
        return False
    rearranged = v[4:] + v[:4]
    try:
        n = int("".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged))
    except ValueError:
        return False
    return n % 97 == 1


_IBAN_TR = str.maketrans({chr(c): str(c - 55) for c in range(ord("A"), ord("Z") + 1)})


def _iban_prefix(match_text):
    """The longest prefix of ``match_text`` that passes mod-97, or None. A
    regex match can run past the account number into whatever follows it
    ("DE89 … 00 EUR"); the gate must not let that trailing text disarm the
    mask, so shorter candidates are tried too — separator-aligned or not, so a
    compact IBAN glued to a suffix ("…013000EUR") is still found. At most ~20
    candidate lengths, each one integer remainder."""
    t = str(match_text)
    v = _IBAN_SEP.sub('', t).upper()
    if len(v) < 15 or not v[:2].isalpha() or not v[2:4].isdigit():
        return None
    head = v[:4].translate(_IBAN_TR)
    body = v[4:34]
    digits = body.translate(_IBAN_TR)
    if not (head.isdigit() and digits.isdigit() and digits.isascii()):
        return None
    shift = 10 ** len(head)
    head_n = int(head)
    k = len(body)            # body characters in the candidate
    d = len(digits)          # their digit count
    while k + 4 >= 15:
        if (int(digits[:d]) * shift + head_n) % 97 == 1:
            if k + 4 == len(v):
                return t
            # the candidate ends at the (k + 4)-th non-separator character
            seen = 0
            for i, c in enumerate(t):
                if not _IBAN_SEP.match(c):
                    seen += 1
                    if seen == k + 4:
                        return t[:i + 1]
        k -= 1
        d -= 2 if body[k].isalpha() else 1
    return None


def _validated_span(name, match_text):
    """For checksum-gated patterns, the part of ``match_text`` that is a real
    finding (None if none). Cards check as matched; IBANs may shrink to a
    passing prefix."""
    if name == "credit_card":
        return match_text if _luhn_ok(match_text) else None
    if name == "iban":
        return _iban_prefix(match_text)
    return match_text


# Patterns whose shape alone is ambiguous carry a checksum gate.
_VALIDATORS = {"credit_card": _luhn_ok, "iban": _iban_ok}


# Group separators a grouped number or a PEM header may use (every character
# Python's str.isspace() accepts, listed so the TypeScript port uses the same
# set). An invisible run between a separator and a token character, or
# between a token character (or a parenthesis) and a separator, is dropped
# too: "4539\u200b 1488 ..." is the card number it renders as.
_SEP_CLASS = "\t\n\x0b\x0c\r\x1c-\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000"
_ZW_IN_TOKEN_RE = re.compile(
    r'(?<=[A-Za-z0-9_\-+/=.:])[' + _INVISIBLE_CLASS + r']+(?=[A-Za-z0-9_\-+/=.:@])'
    r'|(?<=[A-Za-z0-9_\-+/=.:()])[' + _INVISIBLE_CLASS + r']+(?=[' + _SEP_CLASS + r'])'
    r'|(?<=[' + _SEP_CLASS + r'])[' + _INVISIBLE_CLASS + r']+(?=[A-Za-z0-9_\-+/=.:()])')
_ZW_HINT_RE = re.compile('[' + _INVISIBLE_CLASS + ']')


def normalize_invisible(text):
    """``text`` with invisible characters inside tokens removed."""
    if text.isascii() or not _ZW_HINT_RE.search(text):
        return text
    return _ZW_IN_TOKEN_RE.sub("", text)


# Text from a tool is untrusted and can be huge (an echoed prompt injection, a
# multi-megabyte error), and the recorder runs inside the agent. Masking works
# on at most REDACT_MAX characters and withholds the rest wholesale; findings
# cover the whole text, scanned in SCAN_WINDOW-sized windows that overlap by
# SCAN_OVERLAP so a match straddling a window edge is still seen whole.
REDACT_MAX = 65536
SCAN_WINDOW = 65536
SCAN_OVERLAP = 4096
_WITHHELD = "[\u2026 %d more characters withheld]"
_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")


def _normalized_with_map(text):
    """(normalized text, raw index of each normalized character) — the map is
    None when normalizing removes nothing."""
    if text.isascii() or not _ZW_HINT_RE.search(text):
        return text, None
    keep = []
    pos = 0
    for m in _ZW_IN_TOKEN_RE.finditer(text):
        keep.extend(range(pos, m.start()))
        pos = m.end()
    keep.extend(range(pos, len(text)))
    return "".join(text[i] for i in keep), keep


def _match_spans(window):
    """Sorted, merged (start, end) raw spans of every pattern match and every
    token-character run in ``window``, found on its normalized text exactly as
    the masking pass sees it. Checksum gates are ignored: any match counts."""
    norm, idx = _normalized_with_map(window)
    folded = None
    spans = []
    for name, _sev, pattern in PATTERNS:
        req = _REQUIRED.get(name)
        if req is not None and req[1] and folded is None:
            folded = _fold(norm)
        if not _may_match(name, norm, folded):
            continue
        for m in pattern.finditer(norm):
            if m.end() > m.start():
                spans.append((m.start(), m.end()))
    for m in TOKEN_RE.finditer(norm):
        spans.append((m.start(), m.end()))
    if idx is not None:
        spans = [(idx[a], idx[b - 1] + 1) for a, b in spans]
    spans.sort()
    merged = []
    for a, b in spans:
        if merged and a < merged[-1][1]:
            if b > merged[-1][1]:
                merged[-1] = (merged[-1][0], b)
        else:
            merged.append((a, b))
    return merged


def _capped(text):
    """``text`` cut to at most REDACT_MAX characters, plus the marker naming
    what was withheld.

    The cut never falls inside a pattern match or a token: matches are found
    first over the text up to SCAN_OVERLAP characters past the cap (on the
    normalized text, as masking sees it), and the cut moves back to the start
    of any match it would split. Within that, it lands after whitespace when
    there is some in the second half of the kept text, else after the last
    character that cannot be part of a token; with neither, nothing is kept.
    So a grouped number (card, SSN, IBAN, phone) is either kept whole, and
    masked, or withheld whole. A match longer than SCAN_OVERLAP that runs past
    the window edge is seen only as far as the window reaches."""
    if len(text) <= REDACT_MAX:
        return text, ""
    import bisect
    spans = _match_spans(text[:REDACT_MAX + SCAN_OVERLAP])
    starts = [a for a, _b in spans]
    half = REDACT_MAX // 2
    # Two scan pointers that only move backward, so the retries below cost
    # one pass over the kept text in total: ``w`` for the last whitespace at
    # or after the half mark, ``t`` for the last non-token character.
    c = w = t = REDACT_MAX
    while True:
        w = min(w, c)
        while w > half and text[w - 1] not in " \n\t":
            w -= 1
        if w > half:
            cut = w
        else:
            t = min(t, c)
            while t > 0 and text[t - 1] in _TOKEN_CHARS:
                t -= 1
            cut = t
        k = bisect.bisect_right(starts, cut - 1) - 1
        if k >= 0 and spans[k][0] < cut < spans[k][1]:
            c = spans[k][0]  # inside a match: retry from its start
            continue
        break
    keep = text[:cut]
    return keep, " " + _WITHHELD % (len(text) - len(keep))


def _windows(n):
    """(start, accept_end, scan_end) for each scan window over ``n`` characters.
    A window accepts matches that start before accept_end and may read up to
    scan_end."""
    if n <= SCAN_WINDOW + SCAN_OVERLAP:
        return [(0, n, n)]
    out = []
    start = 0
    while start < n:
        accept = min(start + SCAN_WINDOW, n)
        out.append((start, accept, min(accept + SCAN_OVERLAP, n)))
        start = accept
    return out


def _cached_span(name, text, cache):
    """``_validated_span`` remembered per call, so a repeated match is checked once."""
    if cache is None:
        return _validated_span(name, text)
    key = (name, text)
    if key not in cache:
        cache[key] = _validated_span(name, text)
    return cache[key]


def _apply_patterns(text, cache=None):
    out = normalize_invisible(text)
    for name, _sev, pattern in PATTERNS:
        if not _may_match(name, out, _fold(out) if _REQUIRED.get(name, ((), False))[1] else None):
            continue
        if name in _VALIDATORS:
            def _sub(m, n=name):
                span = _cached_span(n, m.group(0), cache)
                if span is None:
                    return m.group(0)
                return redact_sample(n, span) + m.group(0)[len(span):]
            out = pattern.sub(_sub, out)
        else:
            out = pattern.sub(lambda m, n=name: redact_sample(n, m.group(0)), out)
    return out


def _unless_unmasked(raw, masked):
    """``raw`` itself when masking changed nothing but invisible characters:
    they are dropped only to find secrets, so text with nothing to mask (an
    agent id, a tool name, a session id, prose) is stored exactly as given."""
    if masked != raw and masked == normalize_invisible(raw):
        return raw
    return masked


def mask_known_secrets(text):
    """Mask only the named secret/PII patterns in ``text`` — no high-entropy
    catch-all. For fields whose legitimate values ARE high-entropy (authority
    hashes and refs), where the catch-all would mangle the very thing the field
    exists to carry."""
    keep, rest = _capped(str(text))
    return _unless_unmasked(keep, _apply_patterns(keep)) + rest


# Personal-data patterns that legitimately identify a person in identity
# fields (an approver's email, a principal's phone). Credentials and financial
# identifiers are masked in those fields too; these are not.
_IDENTITY_OK = {"email", "phone", "ip_internal"}


def mask_secrets_only(text):
    """Mask credentials and financial identifiers but keep the personal-data
    patterns an identity field exists to carry (email, phone, internal IP)."""
    keep, rest = _capped(str(text))
    out = normalize_invisible(keep)
    for name, _sev, pattern in PATTERNS:
        if name in _IDENTITY_OK:
            continue
        if not _may_match(name, out, _fold(out) if _REQUIRED.get(name, ((), False))[1] else None):
            continue
        if name in _VALIDATORS:
            def _sub(m, n=name):
                span = _validated_span(n, m.group(0))
                if span is None:
                    return m.group(0)
                return redact_sample(n, span) + m.group(0)[len(span):]
            out = pattern.sub(_sub, out)
        else:
            out = pattern.sub(lambda m, n=name: redact_sample(n, m.group(0)), out)
    return _unless_unmasked(keep, TOKEN_RE.sub(
        lambda m: redact_sample(HIGH_ENTROPY_TYPE, m.group(0))
        if _looks_like_secret(m.group(0)) else m.group(0), out)) + rest


def redact_text(text, entropy=True):
    # Patterns first, then sweep the residual for high-entropy tokens the
    # patterns did not cover (running on the residual avoids re-masking "****").
    # ``entropy=False`` keeps the named patterns and skips the catch-all: used
    # for path-typed argument fields, whose legitimate values look like secrets.
    # Text past REDACT_MAX is withheld, not masked (see ``_capped``).
    keep, rest = _capped(str(text))
    after = _apply_patterns(keep, {})
    if not entropy:
        return _unless_unmasked(keep, after) + rest
    return _unless_unmasked(keep, TOKEN_RE.sub(
        lambda m: redact_sample(HIGH_ENTROPY_TYPE, m.group(0))
        if _looks_like_secret(m.group(0)) else m.group(0),
        after,
    )) + rest


def scan(text, entropy=True):
    """Return redacted findings for every sensitive pattern in ``text``.

    Emits one finding per distinct match (deduped on the redacted sample,
    capped per type) so counts reflect reality instead of collapsing to
    one-per-kind. Long text is scanned whole, window by window (``_windows``),
    so the work stays linear in its length.
    """
    import bisect
    s = normalize_invisible(str(text))
    findings = []
    seen = set()
    windows = _windows(len(s))
    cache = {}
    folded = _fold(s)

    iban_starts, iban_ends = [], []  # accepted IBAN intervals, in order
    for name, severity, pattern in PATTERNS:
        if not _may_match(name, s, folded):
            continue
        n = 0
        last_end = 0
        done = False
        for start, accept, end in windows:
            for m in pattern.finditer(s, max(start, last_end), end):
                if m.start() >= accept:
                    break
                last_end = m.end()
                raw = m.group(0)
                if name in _VALIDATORS:
                    span = _cached_span(name, raw, cache)
                    if span is None:
                        continue
                    if name == "iban":
                        iban_starts.append(m.start())
                        iban_ends.append(m.start() + len(span))
                    elif name == "credit_card":
                        # a card-shaped run inside an accepted IBAN is the IBAN
                        k = bisect.bisect_right(iban_starts, m.start()) - 1
                        if k >= 0 and m.start() < iban_ends[k]:
                            continue
                    raw = span
                # A connection string's password can sit past the excerpt cut, so
                # its sample is masked whole first, then cut.
                sample = (redact_sample(name, str(raw))[:120] if name == "db_conn"
                          else redact_sample(name, str(raw)[:120]))
                key = name + ":" + sample
                if key in seen:
                    continue
                seen.add(key)
                findings.append({"type": name, "severity": severity, "sample": sample})
                n += 1
                if n >= MAX_PER_TYPE:
                    done = True
                    break
            if done:
                break

    # High-entropy catch-all over the pattern-redacted residual, so tokens
    # already flagged above are not double-counted.
    if not entropy:
        return findings
    findings += _entropy_findings(s, seen, cache=cache)

    return findings


def top_severity(findings):
    if not findings:
        return "INFO"
    best = max(findings, key=lambda f: SEVERITY_RANK.get(f.get("severity"), 0))
    return best.get("severity") if best.get("severity") in SEVERITY_RANK else "INFO"


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


def _has_new_candidate(text, start, end, cont, ftype, seen):
    """Whether the raw window holds a secret-looking token whose sample is not
    yet reported. Masking only removes or shortens tokens, so a window
    without one cannot add an entropy finding, and its residual is skipped."""
    checked = set()
    for m in TOKEN_RE.finditer(text, start, end):
        if cont and m.start() == start:
            continue
        tok = m.group(0)
        if ftype + ":" + redact_sample(HIGH_ENTROPY_TYPE, tok) in seen or tok in checked:
            continue
        checked.add(tok)
        if _looks_like_secret(tok):
            return True
    return False


def _entropy_findings(text, seen, ftype=HIGH_ENTROPY_TYPE, severity="HIGH", cache=None):
    out = []
    text = str(text)
    e = 0
    cache = {} if cache is None else cache
    for start, _accept, end in _windows(len(text)):
        # A token cut at the slice start belongs to the previous window and is
        # skipped; tokens in the overlap are seen by two windows and the
        # sample dedupe below counts them once.
        cont = start > 0 and text[start - 1] in _TOKEN_CHARS
        if not _has_new_candidate(text, start, end, cont, ftype, seen):
            continue
        # Each window's residual is computed on its own slice.
        residual = _apply_patterns(text[start:end], cache)
        for m in TOKEN_RE.finditer(residual):
            if cont and m.start() == 0:
                continue
            tok = m.group(0)
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
                return out
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


# Field names that carry a credential by contract. A value under one of these
# keys is masked whole, whatever its shape: "hunter2" matches no pattern and is
# not entropy-shaped, but under "password" it is still a password.
CREDENTIAL_TYPE = "credential_field"
CREDENTIAL_MASK = "****"
_CREDENTIAL_KEY_RE = re.compile(
    r'(?:^|_)(?:pass|pwd|auth|authorization|credentials?)$'
    r'|(?:password|passwd|passphrase|secret|api_?key|token|private_?key|secret_?key)$')
_PASSWORD_KEY_RE = re.compile(r'(?:^|_)(?:pass|pwd)$|(?:password|passwd|passphrase)$')
_KEY_SEP_RE = re.compile(r'[\s.\-]+')


def _norm_key(key):
    return _KEY_SEP_RE.sub("_", key.strip().lower())


def credential_key(key):
    """True when ``key`` names a credential (password, secret, token, API key)."""
    return isinstance(key, str) and bool(_CREDENTIAL_KEY_RE.search(_norm_key(key)))


def credential_value(key, value):
    """True when ``value`` under ``key`` is masked whole: a non-empty string or
    bytes under a credential-named key, or a number under a password-named key."""
    if not credential_key(key):
        return False
    if isinstance(value, (str, bytes)):
        return len(value) > 0 and value != CREDENTIAL_MASK
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return bool(_PASSWORD_KEY_RE.search(_norm_key(key)))
    return False


# Every finding type this scanner can emit, with its severity. The starter
# packs' secret rules are tested against this map (tests/test_pack_secret_coverage.py),
# so a type added here must be classified there too.
FINDING_TYPES = {name: sev for name, sev, _pattern in PATTERNS}
FINDING_TYPES.update({HIGH_ENTROPY_TYPE: "HIGH", HIGH_ENTROPY_PATH_TYPE: "LOW",
                      CREDENTIAL_TYPE: "CRITICAL"})


def _credential_finding(key):
    return {"type": CREDENTIAL_TYPE, "severity": "CRITICAL",
            "sample": redact_text(key)[:60] + "=" + CREDENTIAL_MASK}


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
            if isinstance(k, str):
                rk = redact_text(k)
            elif isinstance(k, int) and not isinstance(k, bool) and int_text(k)[:1] == "[":
                rk = int_text(k)
            else:
                rk = k
            if credential_value(k, v):
                out[rk] = CREDENTIAL_MASK
            elif isinstance(v, (list, tuple)):
                out[rk] = [CREDENTIAL_MASK if credential_value(k, el)
                           else redact_fields(el, not path_value(k, el), _depth + 1) for el in v]
            else:
                out[rk] = redact_fields(v, not path_value(k, v), _depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact_fields(v, _entropy, _depth + 1) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return [redact_fields(v, _entropy, _depth + 1) for v in sorted(obj, key=sort_key)]
    if isinstance(obj, int) and not isinstance(obj, bool):
        text = int_text(obj)
        return obj if text[:1] != "[" else text
    if obj is None or isinstance(obj, (bool, float)):
        return obj
    # Bytes, objects, anything else: redact the text it renders as, so the
    # summary carries no more than the scan found and reported.
    return redact_text(str(obj), entropy=_entropy)


def pseudonymize_secrets(text):
    """Replace each secret-shaped token in ``text`` with ``sha256:`` plus 16 hex
    digits of its digest. Deterministic, so equal ids stay equal (grouping and
    links survive) while the token itself is not stored."""
    def sub(m):
        tok = m.group(0)
        if not _looks_like_secret(tok):
            return tok
        return "sha256:" + hashlib.sha256(tok.encode("utf-8")).hexdigest()[:16]
    text = str(text)
    return _unless_unmasked(text, TOKEN_RE.sub(sub, normalize_invisible(text)))


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
            if credential_value(k, v) or (
                    isinstance(v, (list, tuple)) and any(credential_value(k, el) for el in v)):
                f = _credential_finding(k)
                fkey = f["type"] + ":" + f["sample"]
                if fkey not in _seen:
                    _seen.add(fkey)
                    out.append(f)
            if isinstance(v, (list, tuple)):
                for el in v:
                    out += scan_fields(el, _entropy, _depth + 1, _seen, k)
            else:
                out += scan_fields(v, _entropy, _depth + 1, _seen, k)
        return out
    if isinstance(obj, (list, tuple, set, frozenset)):
        items = sorted(obj, key=sort_key) if isinstance(obj, (set, frozenset)) else obj
        for v in items:
            out += scan_fields(v, _entropy, _depth + 1, _seen, None)
        return out
    if obj is None:
        return out
    text = int_text(obj) if isinstance(obj, int) and not isinstance(obj, bool) else str(obj)
    return scan_fields(text, _entropy, _depth + 1, _seen, None)
