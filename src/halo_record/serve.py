"""Live serving of Halo Runtime Reports, access-scoped per tenant.

``halo serve <dir>`` exposes the per-tenant chains in ``<dir>`` (one
``<subject>.jsonl`` per customer, as written by ``TenantRecorder``) as live web
pages. Each customer gets an unguessable link to *their* report and no other: the
access token is an HMAC of a server secret over the chain's name, so holding one
link never reveals or grants another, and the server never turns user input into
a filesystem path. It reads only — it renders reports and, if a witness log is
supplied, the independent completeness verdict. It never blocks or writes records.

Routes:
  GET /                  operator console listing every chain + its share link,
                         gated by ``?key=<admin>``; otherwise a minimal landing.
  GET /r/<token>         one customer's runtime report (404 on unknown token).
  GET /healthz           liveness probe.

This is the local form of the hosted Runtime Report — deliberately small: stdlib
``http.server``, no framework, no database.
"""

import hmac
import json
import os
from hashlib import sha256
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import __version__
from . import access as _access
from .anchor import Notary, verify_completeness, _subject_id
from .report import _STYLE, _esc, _load, _subject_label, _summary_stats, render
from .verify import verify_log

TOKEN_LEN = 32
ADMIN_LEN = 24
DEFAULT_PORT = 8721


def _chains(directory):
    """(stem, path) for each chain file in the directory, dotfiles excluded."""
    out = []
    for name in sorted(os.listdir(directory)):
        if name.startswith(".") or not name.endswith(".jsonl"):
            continue
        out.append((name[: -len(".jsonl")], os.path.join(directory, name)))
    return out


def load_secret(directory):
    """A stable server secret: ``$HALO_SERVE_SECRET`` if set, else a random one
    persisted in ``<dir>/.halo_serve_secret`` so share links survive restarts."""
    env = os.environ.get("HALO_SERVE_SECRET")
    if env:
        return env.encode("utf-8")
    path = os.path.join(directory, ".halo_serve_secret")
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return fh.read().strip()
    secret = os.urandom(32).hex().encode("utf-8")
    with open(path, "wb") as fh:
        fh.write(secret)
    os.chmod(path, 0o600)
    return secret


def token_for(secret, stem):
    return hmac.new(secret, stem.encode("utf-8"), sha256).hexdigest()[:TOKEN_LEN]


def admin_key(secret):
    env = os.environ.get("HALO_SERVE_ADMIN")
    if env:
        return env
    return hmac.new(secret, b"__admin__", sha256).hexdigest()[:ADMIN_LEN]


def _verdict(path, checkpoints):
    """Server-side (chain intact?, completeness) for the operator console."""
    intact = verify_log(path, out=lambda *a, **k: None)
    records = _load(path)
    comp = verify_completeness(records, checkpoints) if checkpoints else {"ok": None}
    return intact, comp, records


def _console_payload(directory, secret, witness_log):
    """Live cross-chain summary for the management console (Build b).

    Read-only projection of every per-tenant chain: subject, action volume,
    the independent integrity + completeness verdict, the customer's private
    share token, and the captured recipient list. No raw payloads cross this
    boundary — only the same redacted summaries the report itself exposes.
    """
    notary = Notary(witness_log) if witness_log else None
    leads_by_chain = {}
    for lead in _access.read_leads(directory):
        leads_by_chain.setdefault(lead.get("chain"), []).append(lead)

    chains = []
    totals = {"records": 0, "intact": 0, "complete": 0, "chains": 0}
    for stem, path in _chains(directory):
        records = _load(path)
        subject = _subject_label(records)
        stats = _summary_stats(records)
        cps = notary.checkpoints(subject=_subject_id(records)) if notary else []
        intact, comp, _ = _verdict(path, cps)
        totals["chains"] += 1
        totals["records"] += stats["total"]
        totals["intact"] += 1 if intact else 0
        totals["complete"] += 1 if comp.get("ok") is True else 0
        chains.append({
            "stem": stem,
            "subject": subject,
            "token": token_for(secret, stem),
            "stats": stats,
            "integrity": "intact" if intact else "broken",
            "completeness": ("complete" if comp.get("ok") is True
                             else "incomplete" if comp.get("ok") is False
                             else "unwitnessed"),
            "recipients": [
                {"email": l.get("email"), "ts": l.get("ts")}
                for l in leads_by_chain.get(stem, [])
            ],
        })
    return {
        "version": __version__,
        "source": "halo-record",
        "directory": directory,
        "witnessed": bool(witness_log),
        "totals": totals,
        "chains": chains,
    }


def _index_html(directory, secret, witness_log, authed):
    if not authed:
        return ("""<!doctype html><meta charset="utf-8"><title>Halo Runtime Reports</title>
<style>%s</style><div class="wrap"><div class="eyebrow">Halo Runtime Record</div>
<h1>Runtime Reports</h1><p class="meta">Each customer has a private link to their own
report. Ask the operator for yours.</p></div>""" % _STYLE)

    notary = Notary(witness_log) if witness_log else None
    rows = []
    for stem, path in _chains(directory):
        tok = token_for(secret, stem)
        records = _load(path)
        subject = _subject_label(records)
        stats = _summary_stats(records)
        cps = notary.checkpoints(subject=_subject_id(records)) if notary else []
        intact, comp, _ = _verdict(path, cps)
        ipill = ('<span class="pill ok">intact</span>' if intact
                 else '<span class="pill warn">broken</span>')
        if comp["ok"] is True:
            cpill = '<span class="pill ok">complete</span>'
        elif comp["ok"] is False:
            cpill = '<span class="pill warn">incomplete</span>'
        else:
            cpill = '<span class="pill neutral">unwitnessed</span>'
        rows.append(
            '<tr><td><b>%s</b></td><td class="mono">%s</td><td>%s</td><td>%s</td>'
            '<td>%s</td><td><a class="mono" href="/r/%s">/r/%s&hellip;</a></td></tr>'
            % (_esc(subject), _esc(stem), stats["total"], ipill, cpill,
               _esc(tok), _esc(tok[:10])))
    body = "\n".join(rows) or '<tr><td colspan="6" class="dim">No chains yet.</td></tr>'
    return """<!doctype html><meta charset="utf-8"><title>Operator console</title>
<style>%(style)s</style><div class="wrap">
<div class="eyebrow">Halo Runtime Record &middot; operator console</div>
<h1>Runtime Reports</h1>
<p class="meta">%(n)s chain(s) in <b>%(dir)s</b>. Each row's link is private to that customer.</p>
<table><thead><tr><th>Customer</th><th>Chain</th><th>Actions</th><th>Integrity</th>
<th>Completeness</th><th>Share link</th></tr></thead><tbody>%(rows)s</tbody></table>
</div>""" % {"style": _STYLE, "n": len(_chains(directory)),
             "dir": _esc(directory), "rows": body}


def _gate_html(subject, token, error=None):
    err = ('<div class="verdict fail">%s</div>' % _esc(error)) if error else ""
    return """<!doctype html><meta charset="utf-8"><title>%(subj)s — Runtime Report</title>
<style>%(style)s
.gate{max-width:440px;margin:9vh auto;text-align:center}
.gate input{width:100%%;padding:12px 14px;font-size:15px;border:1px solid var(--line);
border-radius:10px;margin:14px 0;font-family:inherit}
.gate button{width:100%%;padding:12px;font-size:15px;font-weight:600;color:#fff;
background:var(--gold);border:none;border-radius:10px;cursor:pointer}
.gate .verdict{text-align:left;margin:0 0 14px}</style>
<div class="wrap"><div class="gate">
<div class="eyebrow">Halo Runtime Record</div>
<h1>%(subj)s</h1>
<p class="meta">This runtime report was shared with you. Enter your work email to view it.</p>
%(err)s
<form method="POST" action="/r/%(token)s">
<input type="email" name="email" placeholder="you@company.com" required autofocus>
<button type="submit">View report</button>
</form>
<p class="note" style="margin-top:18px">Access is limited to recipients the vendor designated.
Once inside, the report verifies its own integrity in your browser.</p>
</div></div>""" % {"subj": _esc(subject), "style": _STYLE, "err": err, "token": _esc(token)}


def _otp_html(subject, token, email, error=None):
    err = ('<div class="verdict fail">%s</div>' % _esc(error)) if error else ""
    return """<!doctype html><meta charset="utf-8"><title>%(subj)s — Runtime Report</title>
<style>%(style)s
.gate{max-width:440px;margin:9vh auto;text-align:center}
.gate input{width:100%%;padding:12px 14px;font-size:15px;border:1px solid var(--line);
border-radius:10px;margin:14px 0;font-family:inherit}
.gate input.code{letter-spacing:.4em;text-align:center;font-size:20px}
.gate button{width:100%%;padding:12px;font-size:15px;font-weight:600;color:#fff;
background:var(--gold);border:none;border-radius:10px;cursor:pointer}
.gate .verdict{text-align:left;margin:0 0 14px}</style>
<div class="wrap"><div class="gate">
<div class="eyebrow">Halo Runtime Record</div>
<h1>%(subj)s</h1>
<p class="meta">We sent a 6-digit code to <b>%(email)s</b>. Enter it to confirm this is your address.</p>
%(err)s
<form method="POST" action="/r/%(token)s">
<input type="hidden" name="email" value="%(email)s">
<input class="code" type="text" name="code" inputmode="numeric" pattern="[0-9]*"
 maxlength="6" placeholder="000000" required autofocus autocomplete="one-time-code">
<button type="submit">Verify &amp; view report</button>
</form>
<p class="note" style="margin-top:18px">The code expires in 10 minutes. Didn't get it?
<a href="/r/%(token)s">Start over</a>.</p>
</div></div>""" % {"subj": _esc(subject), "style": _STYLE, "err": err,
                   "token": _esc(token), "email": _esc(email)}


class _Handler(BaseHTTPRequestHandler):
    server_version = "halo-record/" + __version__
    config = None  # injected: {"dir","secret","witness"}

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _resolve(self, token):
        """Map an access token to its chain. Returns (stem, path) or (None, None).
        User input is never used as a path — we compare the token against the
        HMAC of each known chain name, so traversal is impossible."""
        if not token:
            return None, None
        for stem, path in _chains(self.config["dir"]):
            if hmac.compare_digest(token_for(self.config["secret"], stem), token):
                return stem, path
        return None, None

    def _render_report(self, path):
        cfg = self.config
        records = _load(path)
        cps = None
        if cfg["witness"]:
            cps = Notary(cfg["witness"]).checkpoints(subject=_subject_id(records))
        return render(records, cps, witness_url=cfg.get("witness_url"))

    def _session_email(self, stem, token):
        cookie = SimpleCookie()
        raw = self.headers.get("Cookie", "")
        try:
            cookie.load(raw)
        except Exception:
            return None
        morsel = cookie.get("halo_" + token[:16])
        if not morsel:
            return None
        return _access.verify_session(self.config["secret"], morsel.value, stem)

    def do_GET(self):
        cfg = self.config
        parsed = urlparse(self.path)
        route = parsed.path
        if route == "/healthz":
            return self._send(200, "ok", "text/plain; charset=utf-8")
        if route == "/api/console":
            key = (parse_qs(parsed.query).get("key") or [""])[0]
            if not hmac.compare_digest(key, admin_key(cfg["secret"])):
                return self._send(401, json.dumps({"error": "unauthorized"}),
                                  "application/json; charset=utf-8")
            payload = _console_payload(cfg["dir"], cfg["secret"], cfg["witness"])
            return self._send(200, json.dumps(payload),
                              "application/json; charset=utf-8")
        if route == "/":
            key = (parse_qs(parsed.query).get("key") or [""])[0]
            authed = hmac.compare_digest(key, admin_key(cfg["secret"]))
            return self._send(200, _index_html(cfg["dir"], cfg["secret"],
                                               cfg["witness"], authed))
        if route.startswith("/r/"):
            token = route[len("/r/"):].strip("/")
            stem, path = self._resolve(token)
            if stem is None:
                return self._send(404, "Not found.", "text/plain; charset=utf-8")
            if cfg["gated"] and not self._session_email(stem, token):
                subject = _subject_label(_load(path))
                return self._send(200, _gate_html(subject, token))
            return self._send(200, self._render_report(path))
        return self._send(404, "Not found.", "text/plain; charset=utf-8")

    def _grant_session(self, stem, token, path, email):
        """Capture the (now ownership-proven) lead, mint a chain-bound session
        cookie, and serve the report in one response."""
        cfg = self.config
        _access.capture_lead(cfg["dir"], email, stem,
                             subject=_subject_label(_load(path)))
        session = _access.make_session(cfg["secret"], stem, email)
        cookie = "halo_%s=%s; Path=/r/%s; HttpOnly; SameSite=Lax; Max-Age=%d" % (
            token[:16], session, token, _access.SESSION_TTL)
        data = self._render_report(path).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_POST(self):
        cfg = self.config
        route = urlparse(self.path).path
        if not route.startswith("/r/"):
            return self._send(404, "Not found.", "text/plain; charset=utf-8")
        token = route[len("/r/"):].strip("/")
        stem, path = self._resolve(token)
        if stem is None:
            return self._send(404, "Not found.", "text/plain; charset=utf-8")

        length = int(self.headers.get("Content-Length") or 0)
        if length < 0 or length > 4096:
            return self._send(400, "Bad request.", "text/plain; charset=utf-8")
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        fields = parse_qs(body)
        email = (fields.get("email") or [""])[0].strip().lower()
        code = (fields.get("code") or [""])[0].strip()
        subject = _subject_label(_load(path))

        # Recipient check first — same for both gate stages. The email is
        # attacker-controlled (hidden field on the code form), so re-check it.
        if not _access.is_allowed(email, _access.allowed_for(cfg["dir"], stem)):
            return self._send(403, _gate_html(
                subject, token,
                error="That address isn't on the recipient list for this report."))

        # Direct-grant mode: allowlist match is sufficient (frictionless demo).
        if not cfg.get("verify"):
            return self._grant_session(stem, token, path, email)

        # Ownership-proof mode: stage 2 if a code was submitted, else stage 1.
        otp = cfg["otp"]
        if code:
            if otp.check(stem, email, code):
                return self._grant_session(stem, token, path, email)
            return self._send(403, _otp_html(
                subject, token, email,
                error="That code is wrong or expired. Try again or start over."))

        issued = otp.issue(stem, email)
        delivered = _access.send_otp(cfg["dir"], email, issued, stem, subject=subject)
        if delivered != "smtp":
            print("[halo otp] %s code for %s: %s" % (stem, email, issued))
        return self._send(200, _otp_html(subject, token, email))

    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        pass  # quiet by default


def serve(directory, *, host="127.0.0.1", port=DEFAULT_PORT, witness=None,
          gated=True, verify=False, witness_url=None):
    directory = os.path.expanduser(directory)
    if not os.path.isdir(directory):
        raise SystemExit("not a directory: %s" % directory)
    secret = load_secret(directory)
    handler = type("_BoundHandler", (_Handler,),
                   {"config": {"dir": directory,
                               "secret": secret,
                               "gated": gated,
                               "verify": verify,
                               "otp": _access.OtpStore(),
                               "witness_url": witness_url,
                               "witness": os.path.expanduser(witness) if witness else None}})
    httpd = ThreadingHTTPServer((host, port), handler)
    key = admin_key(secret)
    mode = "" if gated else "  (OPEN — gating off)"
    if gated and verify:
        mode = "  (email-ownership verification on)"
    print("Halo Runtime Reports serving %s chain(s) from %s%s"
          % (len(_chains(directory)), directory, mode))
    print("  operator console: http://%s:%s/?key=%s" % (host, port, key))
    print("  per-customer link: http://%s:%s/r/<token>  (see console for tokens)" % (host, port))
    print("  Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
    return 0
