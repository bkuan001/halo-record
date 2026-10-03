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

from ._private import open_private
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


def _file_subject(path):
    """The single subject id a chain file holds, or None (subjectless, mixed,
    or not a plain string)."""
    from .record import TenantRecorder
    found = TenantRecorder._file_subjects(path)
    if len(found) == 1:
        (sid,) = found
        if isinstance(sid, str) and sid:
            return sid
    return None


def _stem(path):
    return os.path.basename(path)[: -len(".jsonl")]


def _stem_names_subject(directory, stem, key):
    """True when a file named ``<stem>.jsonl`` is one the recorder would write
    for subject id ``key``: the id itself, its current file name, its digested
    name, or the cleaning used before 0.2.46. A file whose name names another
    tenant (``globex.jsonl`` holding subject id ``initech``) does not."""
    from .record import TenantRecorder
    tr = TenantRecorder(directory)
    names = {key, tr._safe(key), tr._safe_ascii(key), tr._digested(key),
             _stem(tr.path_for(key))}
    return stem in names


def _chain_index(directory):
    """(served, withheld, files).

    ``served``: (key, path) for each servable chain. A file holding exactly one
    subject is keyed by that subject id; any other file by its stem. Share
    links, grants, sessions, and leads all use the key, so they follow a
    customer's chain when its file name changes (for example a subject whose
    records continue in a new file after an upgrade) instead of pinning a
    frozen file. When several files carry one subject, the file the recorder
    appends to now is served.

    ``withheld``: (key, [mislabeled file names]) for each subject whose files
    include one named for a different tenant alongside another file. Which file a grant
    for that subject was meant for cannot be told apart, so none is served.

    ``files``: (key, stem, path, names_key) for every chain file."""
    from .record import TenantRecorder
    groups = {}
    files = []
    for stem, path in _chains(directory):
        sid = _file_subject(path)
        key = sid if sid is not None else stem
        names = sid is None or _stem_names_subject(directory, stem, key)
        groups.setdefault(key, []).append((sid, path, names))
        files.append((key, stem, path, names))
    served, withheld = [], []
    tr = TenantRecorder(directory)
    for key, entries in groups.items():
        if len(entries) > 1 and not all(names for _sid, _p, names in entries):
            withheld.append((key, sorted(os.path.basename(p) for _s, p, n in entries if not n)))
            continue
        single = [p for sid, p, _n in entries if sid is not None]
        if not single:
            served.append((key, entries[0][1]))
            continue
        if len(single) == 1:
            served.append((key, single[0]))
            continue
        import hashlib
        prefer = [tr.path_for(key),
                  os.path.join(directory, tr._safe(key) + ".jsonl"),
                  os.path.join(directory, "%s~%s.jsonl" % (
                      tr._safe_ascii(key), hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]))]
        norm = {os.path.abspath(p): p for p in single}
        chosen = next((norm[os.path.abspath(p)] for p in prefer if os.path.abspath(p) in norm),
                      None)
        if chosen is None:
            chosen = max(single, key=lambda p: os.path.getmtime(p))
        served.append((key, chosen))
    return sorted(served), sorted(withheld), files


def _served_chains(directory):
    """(key, path) for each servable chain; see ``_chain_index``."""
    return _chain_index(directory)[0]


def _legacy_stems(directory):
    """{stem: key} for file names that 0.2.45 keyed links and grants by and that
    still name the subject they serve: the file's name matches its subject id,
    the subject is served, and the name is not itself another chain's key."""
    served, _withheld, files = _chain_index(directory)
    keys = {k for k, _p in served}
    out = {}
    for key, stem, _path, names in files:
        if stem != key and names and key in keys and stem not in keys:
            out[stem] = key
    return out


def chain_key(directory, name):
    """The serving key for a chain named by its subject id (its key) or by its
    file stem. Raises ValueError when the name is ambiguous — one chain's key
    and another chain's file stem (a subject id can be chosen to equal another
    tenant's file name) — so a grant never lands on a chain by accident. Also
    raises when the chain is served from a file named for a different tenant,
    or is withheld because such a file sits beside it: a grant follows the
    subject id, so it would admit the recipient to every file recorded under
    that id, including one that appears later."""
    served, withheld, files = _chain_index(directory)
    by_key = [key for key, _path in served if key == name]
    by_stem = [key for key, path in served if _stem(path) == name]
    found = sorted(set(by_key) | set(by_stem))
    if len(found) > 1:
        raise ValueError(
            "%r is ambiguous: it names the chains for subject ids %s (as a subject id "
            "and as a file name); name the chain by a file name that is unique (%s)"
            % (name, ", ".join(map(repr, found)),
               ", ".join(os.path.basename(p) for k, p in served if k in found)))
    mislabeled = [(key, stem) for key, stem, _p, names in files
                  if not names and (stem == name or key == name)]
    if mislabeled:
        key, stem = mislabeled[0]
        raise ValueError(
            "%s.jsonl carries subject id %r, and its file name does not match that id. "
            "A grant follows the subject id, so it would admit the recipient to every "
            "chain recorded for %r. Rename or move %s.jsonl so its name matches its "
            "records, then grant by subject id." % (stem, key, key, stem))
    for key, names in withheld:
        if key == name:
            raise ValueError("subject %r is withheld: %s holds its records but is named "
                             "for a different tenant; rename or move it, then grant again"
                             % (key, ", ".join(names)))
    return found[0] if found else name


def _file_name_reading(name, keys, files, legacy):
    """How a grant keyed by ``name`` before 0.2.46 (when the key was a file
    name) reads now that grants are keyed by subject id. Returns one of:

    ``("same", name)``: ``<name>.jsonl`` holds subject id ``name``, which is
    served, so both readings name one chain.
    ``("ambiguous", None)``: ``name`` is a served subject id, but
    ``<name>.jsonl`` holds a different subject id or no longer exists, so the
    file-name reading and the subject-id reading name different chains.
    ``("carry", key)``: ``name`` is not a served subject id, and
    ``<name>.jsonl`` names the served subject ``key``.
    ``("orphan", None)``: neither reading names a served chain."""
    stem_keys = [key for key, stem, _p, _n in files if stem == name]
    if name in keys:
        if stem_keys == [name]:
            return "same", name
        return "ambiguous", None
    if name in legacy:
        return "carry", legacy[name]
    return "orphan", None


def honored_recipients(directory, key):
    """The recipients ``halo serve`` admits to the chain served under ``key``.
    A grant issued by subject id (0.2.46 and later) is honored as stored. A
    grant written before 0.2.46 was keyed by a file name; it is honored only
    while that file name and the subject id ``key`` name the same chain, so a
    file-name grant never admits anyone to a different tenant's chain that now
    has that name as its subject id."""
    record = _access.load_access(directory).get(key)
    if not isinstance(record, dict):
        return []
    allow = list(record.get("allow") or [])
    if _access.is_subject_keyed(record) or not allow:
        return allow
    served, _withheld, files = _chain_index(directory)
    keys = {k for k, _p in served}
    reading, _target = _file_name_reading(key, keys, files, {})
    return allow if reading == "same" else []


def _quarantine_line(directory, name, recipients, served, files):
    stem_keys = [key for key, stem, _p, _n in files if stem == name]
    if stem_keys:
        held_by = "%s.jsonl holds subject id %r" % (name, stem_keys[0])
    else:
        held_by = "no file named %s.jsonl remains" % name
    paths = dict(served)
    if name in paths:
        now = "subject id %r is served from %s" % (name, os.path.basename(paths[name]))
    else:
        now = "no chain has subject id %r now" % name
    return ("  quarantined grant %r (recipients: %s): it was keyed by file name before "
            "0.2.46, and that name now also reads as a subject id of a different chain "
            "(%s; %s), so it admits no one. If it was for a customer, re-issue it by "
            "subject id (halo grant %s <subject id> <recipient>) and send the link shown "
            "in the operator console."
            % (name, ", ".join(recipients) or "none", held_by, now, directory))


def reconcile_grants(directory):
    """Read each grant written before 0.2.46 (keyed by file name, with no
    ``"by": "subject"`` marker) under 0.2.46's subject-id keying, and return the
    lines to print at ``halo serve`` startup:

    - both readings name the same chain: the grant is marked as keyed by
      subject id and keeps working;
    - the name is a served subject id and its file is a different chain's (or
      gone): the grant is quarantined, its recipients moved to
      ``quarantined``, admitting no one, and printed with how to re-issue it;
    - the name is only a file name, and that file's name matches the subject id
      it is served under: the grant is carried to that subject id, and the
      earlier share link still opens it (see ``_Handler._resolve``);
    - neither: the grant is left in place, admitting no one while no chain has
      that name, and printed with how to re-issue it.

    ``honored_recipients`` applies the same rule per request, so a grant is
    never read with the wrong meaning before this has run."""
    served, withheld, files = _chain_index(directory)
    keys = {k for k, _p in served}
    legacy = _legacy_stems(directory)
    data = _access.load_access(directory)
    lines = []
    changed = False
    carries = []
    for name in sorted(data):
        record = data.get(name)
        if not isinstance(record, dict) or _access.is_subject_keyed(record):
            continue
        allow = list(record.get("allow") or [])
        held = list(record.get("quarantined") or [])
        reading, target = _file_name_reading(name, keys, files, legacy)
        if held and not allow:
            lines.append(_quarantine_line(directory, name, held, served, files))
            continue
        if reading == "same":
            record["by"] = _access.BY_SUBJECT
            changed = True
            continue
        if reading == "ambiguous":
            record.pop("allow", None)
            record["quarantined"] = held + [e for e in allow if e not in held]
            changed = True
            lines.append(_quarantine_line(directory, name, record["quarantined"],
                                          served, files))
            continue
        if reading == "carry":
            carries.append((name, target, allow))
            continue
        lines.append("  grant %r (recipients: %s) matches no served chain, so it admits no "
                     "one. If it was for a customer, re-issue it by subject id "
                     "(halo grant %s <subject id> <recipient>) and send the link shown in "
                     "the operator console." % (name, ", ".join(allow) or "none", directory))
    for name, target, allow in carries:
        dest = data.setdefault(target, {})
        dest["by"] = _access.BY_SUBJECT
        merged = dest.setdefault("allow", [])
        for entry in allow:
            if entry not in merged:
                merged.append(entry)
        del data[name]
        changed = True
        lines.append("  carried grant %r (recipients: %s) to subject id %r; its earlier "
                     "share link (keyed by %s.jsonl) still opens the report."
                     % (name, ", ".join(allow) or "none", target, name))
    for key, names in withheld:
        lines.append("  withheld: subject id %r also has records in %s, a file named for "
                     "a different tenant; its link opens nothing until that file is "
                     "renamed or moved." % (key, ", ".join(names)))
    if changed:
        _access.save_access(directory, data)
    return lines


def _ambiguous_link_keys(directory):
    """{key: (other subject id, served file)} for each served subject id that is
    also the file name of a different chain. A 0.2.45 share link for that file
    is the same token as the subject id's link, so with gating off (where the
    link is the only check) neither is served by that token."""
    served, _withheld, files = _chain_index(directory)
    out = {}
    for key, path in served:
        for other, stem, _p, _n in files:
            if stem == key and other != key:
                out[key] = (other, os.path.basename(path))
                break
    return out


def ambiguous_link_lines(directory):
    """Startup lines for ``halo serve --open``; see ``_ambiguous_link_keys``."""
    return ["  link withheld: subject id %r (served from %s) is also the file name of "
            "%s.jsonl, which holds subject id %r, so its link was that file's link "
            "before 0.2.46. With gating off the link is the only check, so it opens "
            "nothing; serve with gating on and grant recipients by subject id."
            % (key, served_from, key, other)
            for key, (other, served_from) in sorted(_ambiguous_link_keys(directory).items())]


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
    with open_private(path, "wb") as fh:
        fh.write(secret)
    return secret


def token_for(secret, stem):
    return hmac.new(secret, stem.encode("utf-8"), sha256).hexdigest()[:TOKEN_LEN]


def admin_key(secret):
    env = os.environ.get("HALO_SERVE_ADMIN")
    if env:
        return env
    return hmac.new(secret, b"__admin__", sha256).hexdigest()[:ADMIN_LEN]


def _witness_checkpoints(notary, records):
    """(checkpoints, damaged): a damaged witness file yields no checkpoints and
    damaged=True, which every caller shows as such, never as unwitnessed."""
    if notary is None:
        return [], False
    from .anchor import WitnessFileError
    try:
        return notary.checkpoints_for(records), False
    except WitnessFileError:
        return [], True


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
    for stem, path in _served_chains(directory):
        records = _load(path)
        subject = _subject_label(records)
        stats = _summary_stats(records)
        cps, damaged = _witness_checkpoints(notary, records)
        intact, comp, _ = _verdict(path, cps)
        if damaged:
            comp = {"ok": False, "why": "witness file damaged"}
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
                             else "witness damaged" if damaged
                             else "incomplete" if comp.get("ok") is False
                             else "unwitnessed"),
            "file": os.path.basename(path),
            # Leads are read back from disk; anything a client might render is
            # escaped here so a stored value can never become markup downstream.
            "recipients": [
                {"email": _esc(l.get("email") or ""), "ts": _esc(l.get("ts") or "")}
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
<style>%s</style><div class="wrap"><div class="eyebrow">Halo Runtime Report</div>
<h1>Runtime Reports</h1><p class="meta">Each customer has a private link to their own
report. Ask the operator for yours.</p></div>""" % _STYLE)

    notary = Notary(witness_log) if witness_log else None
    rows = []
    for stem, path in _served_chains(directory):
        tok = token_for(secret, stem)
        records = _load(path)
        subject = _subject_label(records)
        stats = _summary_stats(records)
        cps, damaged = _witness_checkpoints(notary, records)
        intact, comp, _ = _verdict(path, cps)
        if damaged:
            comp = {"ok": False}
        ipill = ('<span class="pill ok">intact</span>' if intact
                 else '<span class="pill warn">broken</span>')
        if comp["ok"] is True:
            cpill = '<span class="pill ok">complete</span>'
        elif damaged:
            cpill = '<span class="pill warn">witness damaged</span>'
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
<div class="eyebrow">Halo &middot; operator console</div>
<h1>Runtime Reports</h1>
<p class="meta">%(n)s chain(s) in <b>%(dir)s</b>. Each row's link is private to that customer.</p>
<table><thead><tr><th>Customer</th><th>Chain</th><th>Actions</th><th>Integrity</th>
<th>Completeness</th><th>Share link</th></tr></thead><tbody>%(rows)s</tbody></table>
</div>""" % {"style": _STYLE, "n": len(_served_chains(directory)),
             "dir": _esc(directory), "rows": body}


def _gate_html(subject, token, error=None, hint=None):
    err = ('<div class="verdict fail">%s</div>' % _esc(error)) if error else ""
    hint_html = ('<div class="verdict neutral" style="text-align:left">%s</div>'
                 % _esc(hint)) if hint else ""
    return """<!doctype html><meta charset="utf-8"><title>%(subj)s — Runtime Report</title>
<style>%(style)s
.gate{max-width:440px;margin:9vh auto;text-align:center}
.gate input{width:100%%;padding:12px 14px;font-size:15px;border:1px solid var(--line);
border-radius:10px;margin:14px 0;font-family:inherit}
.gate button{width:100%%;padding:12px;font-size:15px;font-weight:600;color:#fff;
background:var(--gold);border:none;border-radius:10px;cursor:pointer}
.gate .verdict{text-align:left;margin:0 0 14px}</style>
<div class="wrap"><div class="gate">
<div class="eyebrow">Halo Runtime Report</div>
<h1>%(subj)s</h1>
<p class="meta">This runtime report was shared with you. Enter your work email to view it.</p>
%(hint)s%(err)s
<form method="POST" action="/r/%(token)s">
<input type="email" name="email" placeholder="you@company.com" required autofocus>
<button type="submit">View report</button>
</form>
<p class="note" style="margin-top:18px">Access is limited to recipients the vendor designated.
Once inside, the report verifies its own integrity in your browser.</p>
</div></div>""" % {"subj": _esc(subject), "style": _STYLE, "err": err, "hint": hint_html,
           "token": _esc(token)}


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
<div class="eyebrow">Halo Runtime Report</div>
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
        served = _served_chains(self.config["dir"])
        for key, path in served:
            if hmac.compare_digest(token_for(self.config["secret"], key), token):
                if not self.config.get("gated", True) and key in _ambiguous_link_keys(self.config["dir"]):
                    return None, None
                return key, path
        # A share link issued by 0.2.45 was keyed by file name; it still opens
        # the chain that file name names.
        paths = dict(served)
        for stem, key in _legacy_stems(self.config["dir"]).items():
            if hmac.compare_digest(token_for(self.config["secret"], stem), token):
                return key, paths[key]
        return None, None

    def _render_report(self, path):
        cfg = self.config
        records = _load(path)
        subjects = {(r.get("subject") or {}).get("id") if isinstance(r.get("subject"), dict)
                    else None for r in records}
        from .verify import verify_records
        if records and not verify_records(records):
            return ('<!doctype html><meta charset="utf-8"><title>Report withheld</title>'
                    '<p>This chain does not verify, so the report is withheld. '
                    'Run <code>halo verify</code> on it for details.</p>')
        if len(subjects) > 1:
            # One page, one customer: a file holding several subjects is withheld
            # rather than shown to the holder of any one tenant's link.
            return ('<!doctype html><meta charset="utf-8"><title>Report withheld</title>'
                    '<p>This chain holds records for more than one subject, so the '
                    'report is withheld. Each customer\'s records belong in their own chain.</p>')
        cps = None
        if cfg["witness"]:
            cps, damaged = _witness_checkpoints(Notary(cfg["witness"]), records)
            if damaged:
                return ('<!doctype html><meta charset="utf-8"><title>Report withheld</title>'
                        '<p>The witness file is damaged, so completeness cannot be judged '
                        'and the report is withheld. The operator must restore it.</p>')
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
        return _access.session_email_if_allowed(
            self.config["dir"], self.config["secret"], morsel.value, stem,
            allow=honored_recipients(self.config["dir"], stem))

    def do_GET(self):
        return self._guarded(self._do_get)

    def _do_get(self):
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
                return self._send(200, _gate_html(subject, token, hint=cfg.get("gate_hint")))
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
        return self._guarded(self._do_post)

    def _do_post(self):
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
        if not _access.is_allowed(email, honored_recipients(cfg["dir"], stem)):
            return self._send(403, _gate_html(
                subject, token,
                error="That address isn't on the recipient list for this report.",
                hint=cfg.get("gate_hint")))

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
        if issued is None:
            return self._send(429, _otp_html(
                subject, token, email,
                error="Too many codes requested for this address. Try again later."))
        delivered = _access.send_otp(cfg["dir"], email, issued, stem, subject=subject)
        if delivered != "smtp":
            print("[halo otp] %s code for %s: %s" % (stem, email, issued))
        return self._send(200, _otp_html(subject, token, email))

    do_HEAD = do_GET

    def send_response(self, *args, **kwargs):
        self._response_started = True
        return super().send_response(*args, **kwargs)

    def _guarded(self, handler):
        # A malformed request (odd bytes in the path, a bad form body) gets a
        # plain 400, never a traceback. If a response had already started, the
        # connection is closed instead of writing a second response into it.
        self._response_started = False
        try:
            return handler()
        except Exception:
            if self._response_started:
                self.close_connection = True
                return None
            try:
                self._send(400, "Bad request.", "text/plain; charset=utf-8")
            except Exception:
                self.close_connection = True
            return None

    def log_message(self, fmt, *args):
        pass  # quiet by default


def serve(directory, *, host="127.0.0.1", port=DEFAULT_PORT, witness=None,
          gated=True, verify=False, witness_url=None, gate_hint=None):
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
                               "witness": os.path.expanduser(witness) if witness else None,
                               "gate_hint": gate_hint}})
    httpd = ThreadingHTTPServer((host, port), handler)
    key = admin_key(secret)
    mode = "" if gated else "  (OPEN — gating off)"
    if gated and verify:
        mode = "  (email-ownership verification on)"
    if gated and not verify:
        print("  note: recipients are admitted by link plus an allow-listed address, without "
              "proof they own the mailbox; use --verify for one-time-code ownership proof.")
    print("Halo Runtime Reports serving %s chain(s) from %s%s"
          % (len(_chains(directory)), directory, mode))
    for line in reconcile_grants(directory):
        print(line)
    if not gated:
        for line in ambiguous_link_lines(directory):
            print(line)
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
