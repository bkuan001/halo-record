"""Sensitive-data detection and redaction.

A conforming record MUST NOT contain raw secrets or personal data. ``scan``
finds them; ``redact_sample`` / ``redact_text`` mask them. Detection is regex —
deterministic and explainable, never a model judgement.
"""

import re

PATTERNS = [
    ("api_key",      "CRITICAL", re.compile(r'(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[a-zA-Z0-9\-]{10,})')),
    ("private_key",  "CRITICAL", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ("db_conn",      "CRITICAL", re.compile(r'(?:postgres|mysql|mongodb(?:\+srv)?|redis)://[^\s"\'<>]+')),
    ("credit_card",  "HIGH",     re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b')),
    ("ssn",          "HIGH",     re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
    ("email",        "MEDIUM",   re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')),
    ("ip_internal",  "MEDIUM",   re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b')),
    ("bearer_token", "HIGH",     re.compile(r'Bearer\s+[a-zA-Z0-9\-_\.]{20,}')),
]

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


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
    if ftype == "api_key":
        return (v[:4] + "****") if len(v) > 4 else "****"
    if ftype == "credit_card":
        digits = re.sub(r'\D', '', v)
        return ("****" + digits[-4:]) if len(digits) >= 4 else "****"
    if ftype == "ssn":
        return ("***-**-" + v[-4:]) if len(v) >= 4 else "****"
    if ftype == "ip_internal":
        parts = v.split(".")
        return ".".join(parts[:2] + ["*", "*"]) if len(parts) == 4 else "****"
    return "****"


def redact_text(text):
    out = str(text)
    for name, _sev, pattern in PATTERNS:
        out = pattern.sub(lambda m: redact_sample(name, m.group(0)), out)
    return out


def scan(text):
    """Return a list of redacted findings for any sensitive patterns in ``text``."""
    findings = []
    for name, severity, pattern in PATTERNS:
        matches = pattern.findall(text)
        if matches:
            findings.append({
                "type": name,
                "severity": severity,
                "sample": redact_sample(name, str(matches[0])[:120]),
            })
    return findings


def top_severity(findings):
    if not findings:
        return "INFO"
    return max(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 0))["severity"]
