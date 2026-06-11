"""Access gating + lead capture for hosted Runtime Reports.

The report's *verification* is trustless: the viewer's browser recomputes the
hash chain and the completeness witness, trusting no server. Gating is a SEPARATE
concern — who may open the link at all. The vendor designates the
recipients of each report; a viewer proves they are one by entering an email that
matches, and only then is the report served. Two guarantees stay distinct:
*who can open it* (the gate) vs *is it real* (in-browser self-verification). The
gate never becomes part of the trust chain.

Emails that pass the gate are captured to a local leads log. That is the demand
signal — every security reviewer who opens a vendor's agent report is, by
definition, someone who cares about independent agent evidence: Halo's buyer.
Forwarding leads to Halo is an explicit opt-in, never automatic; the recorder's
no-phone-home rule extends here.

Pure-stdlib, like the rest of the package.
"""

import base64
import hmac
import json
import os
import re
import secrets
import threading
import time
from hashlib import sha256

ACCESS_FILE = ".halo_access.json"
LEADS_FILE = ".halo_leads.jsonl"
OTP_OUTBOX = ".halo_otp_outbox.jsonl"
SESSION_TTL = 86400  # 24h

OTP_TTL = 600           # codes expire after 10 minutes
OTP_MAX_ATTEMPTS = 5    # wrong guesses before a code is burned
OTP_LEN = 6

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _access_path(directory):
    return os.path.join(directory, ACCESS_FILE)


def load_access(directory):
    path = _access_path(directory)
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_access(directory, data):
    path = _access_path(directory)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.chmod(path, 0o600)


def grant(directory, chain, entry):
    """Designate a recipient for one chain. ``entry`` is an exact email
    (``alice@acme-corp.com``) or a domain (``acme-corp.com``). Returns the updated list."""
    entry = entry.strip().lower().lstrip("@")
    data = load_access(directory)
    allow = data.setdefault(chain, {}).setdefault("allow", [])
    if entry not in allow:
        allow.append(entry)
    save_access(directory, data)
    return allow


def allowed_for(directory, chain):
    return load_access(directory).get(chain, {}).get("allow", [])


def email_ok(email):
    return bool(email) and len(email) <= 254 and bool(_EMAIL_RE.match(email))


def is_allowed(email, allow):
    """Match an email against an allow list of exact addresses and/or domains."""
    if not email_ok(email):
        return False
    email = email.strip().lower()
    domain = email.split("@", 1)[1]
    for entry in allow:
        entry = entry.strip().lower().lstrip("@")
        if "@" in entry:
            if email == entry:
                return True
        elif domain == entry or domain.endswith("." + entry):
            return True
    return False


def capture_lead(directory, email, chain, subject=None, extra=None):
    """Append one captured lead. Best-effort; never raises into the request path."""
    rec = {
        "email": email.strip().lower(),
        "chain": chain,
        "subject": subject,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if extra:
        rec.update(extra)
    try:
        with open(os.path.join(directory, LEADS_FILE), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    except OSError:
        pass
    return rec


def read_leads(directory):
    path = os.path.join(directory, LEADS_FILE)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh.read().splitlines() if ln.strip()]


def make_session(secret, chain, email, ttl=SESSION_TTL):
    exp = str(int(time.time()) + ttl)
    payload = "%s|%s|%s" % (chain, email.strip().lower(), exp)
    sig = hmac.new(secret, payload.encode("utf-8"), sha256).hexdigest()[:32]
    return base64.urlsafe_b64encode((payload + "|" + sig).encode("utf-8")).decode("ascii")


def verify_session(secret, cookie, chain):
    """Return the verified email if the cookie is a valid, unexpired session for
    ``chain``; otherwise None. The chain binding means a cookie for one customer
    cannot unlock another's report."""
    if not cookie:
        return None
    try:
        raw = base64.urlsafe_b64decode(cookie.encode("ascii")).decode("utf-8")
        parts = raw.split("|")
        if len(parts) != 4:
            return None
        c, email, exp, sig = parts
        payload = "%s|%s|%s" % (c, email, exp)
        expected = hmac.new(secret, payload.encode("utf-8"), sha256).hexdigest()[:32]
        if not hmac.compare_digest(expected, sig):
            return None
        if c != chain or int(exp) < int(time.time()):
            return None
        return email
    except (ValueError, UnicodeDecodeError, base64.binascii.Error):
        return None


class OtpStore:
    """In-process, expiring, attempt-limited one-time codes, keyed by
    ``(chain, email)``. Codes live only in memory: they are short-lived, never
    sent to the browser, and a server restart simply asks the viewer to request a
    new one. Keeping the code server-side (not in a client-held token) is what
    makes a 6-digit secret safe — an attacker can't offline-brute-force a hash
    they never receive, and online guesses are capped at OTP_MAX_ATTEMPTS."""

    def __init__(self):
        self._d = {}
        self._lock = threading.Lock()

    def issue(self, chain, email):
        code = "".join(secrets.choice("0123456789") for _ in range(OTP_LEN))
        with self._lock:
            self._d[(chain, email.strip().lower())] = {
                "code": code, "exp": time.time() + OTP_TTL, "tries": 0}
        return code

    def check(self, chain, email, code):
        """True iff ``code`` is the live, unexpired, not-exhausted code for this
        (chain, email). Consumes the code on success and on exhaustion/expiry."""
        key = (chain, email.strip().lower())
        with self._lock:
            rec = self._d.get(key)
            if not rec:
                return False
            if time.time() > rec["exp"]:
                self._d.pop(key, None)
                return False
            rec["tries"] += 1
            if rec["tries"] > OTP_MAX_ATTEMPTS:
                self._d.pop(key, None)
                return False
            if isinstance(code, str) and hmac.compare_digest(code.strip(), rec["code"]):
                self._d.pop(key, None)
                return True
            return False


def send_otp(directory, email, code, chain, subject=None):
    """Deliver a one-time code to ``email``. Real delivery uses SMTP when
    ``$HALO_SMTP_HOST`` is configured; otherwise dev mode writes the code to a
    local outbox (and the caller logs it) so the gate is testable without an
    email account. No-phone-home holds: nothing leaves the box unless the
    operator points it at their own SMTP server."""
    host = os.environ.get("HALO_SMTP_HOST")
    if host:
        _smtp_send(host, email, code, chain, subject)
        delivered = "smtp"
    else:
        delivered = "dev-outbox"
    rec = {
        "email": email.strip().lower(), "chain": chain, "code": code,
        "via": delivered,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        with open(os.path.join(directory, OTP_OUTBOX), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
        os.chmod(os.path.join(directory, OTP_OUTBOX), 0o600)
    except OSError:
        pass
    return delivered


def _smtp_send(host, email, code, chain, subject):
    import smtplib
    from email.message import EmailMessage
    port = int(os.environ.get("HALO_SMTP_PORT") or 587)
    user = os.environ.get("HALO_SMTP_USER")
    pw = os.environ.get("HALO_SMTP_PASS")
    sender = os.environ.get("HALO_SMTP_FROM") or (user or "no-reply@halo.local")
    label = subject or chain
    msg = EmailMessage()
    msg["Subject"] = "Your code to view the %s Runtime Report" % label
    msg["From"] = sender
    msg["To"] = email
    msg.set_content(
        "Your one-time code to view the %s Runtime Report is: %s\n\n"
        "It expires in %d minutes. If you didn't request this, ignore this email."
        % (label, code, OTP_TTL // 60))
    with smtplib.SMTP(host, port, timeout=10) as s:
        s.starttls()
        if user and pw:
            s.login(user, pw)
        s.send_message(msg)
