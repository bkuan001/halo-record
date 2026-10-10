"""The door: buyer-side records of what an outside agent did, from logs the
buyer already exports.

A vendor's agent acting inside a buyer's systems leaves traces in the buyer's
own logs. This module turns one of those exports into sealed records, isolates
one outside agent, lines its actions up against the agent's own record when one
exists, checks them against a rules file, and renders one page a reviewer can
read without trusting the vendor's account of events.

Every record here is the ``ingested`` tier: the buyer's platform wrote the log,
after the fact, and Halo seals the copy it was given. Sealing proves the copy
was not edited after ingest; it says nothing about whether the export itself
was complete. The page states that, and states what one week cannot show.

Supported export today: a GitHub account security log (JSON array or JSON
lines, as downloaded from Settings > Archives > Security log).

    from halo_record import Recorder, door
    events = door.parse_github_log("export.json")
    recs = door.ingest(events, Recorder("door.jsonl"), subject="acme")
    mine = door.isolate(recs, "app:Example Agent")
    page = door.render_page(mine, door.match(mine, own_records),
                            door.check(mine, door.load_rules(door.bundled_rules("github-default"))),
                            agent="app:Example Agent")

Pure stdlib.
"""

import html
import json
import os
import re
from datetime import datetime, timezone

from . import policy as _policy
from .record import build

SOURCE = {"adapter": "github_audit", "via": "GitHub security log export",
          "capture": "ingested"}

# Kinds of activity an export may or may not carry. A personal security log
# carries none of them; an organization audit log can carry some. The page names
# the ones this export is missing, so a reader does not take absence as proof.
ACTIVITY_KINDS = (
    ("code pushes", ("git.push",)),
    ("clones and fetches", ("git.clone", "git.fetch")),
    ("pull requests", ("pull_request.", "pull_request_review")),
    ("issues", ("issue.", "issues.", "issue_comment")),
)
READS_NOTE = ("Most reads, such as viewing files or calling read-only APIs, are not "
              "recorded in this kind of log.")


def missing_kinds(actions):
    """Labels from ACTIVITY_KINDS with no matching action in the export."""
    actions = [str(a or "").replace("github:", "", 1) for a in actions]
    return [label for label, prefixes in ACTIVITY_KINDS
            if not any(a.startswith(p) for a in actions for p in prefixes)]


def cannot_see(actions):
    """One plain sentence or two on what this export does not show."""
    gone = missing_kinds(actions)
    if not gone:
        return READS_NOTE
    listed = gone[0] if len(gone) == 1 else ", ".join(gone[:-1]) + ", or " + gone[-1]
    return ("This export has no records of %s. That does not mean none happened: the "
            "log did not include them. %s" % (listed, READS_NOTE))


# Automatic, high-volume housekeeping that says nothing about what an agent did.
# Hidden from the page by default (still sealed in the chain, still counted).
ROUTINE_ACTIONS = frozenset({"oauth_access.regenerate"})

MATCHED_WITHIN = 10      # seconds: same action family, near-simultaneous
PROBABLE_WITHIN = 180    # seconds: same action family, plausibly the same act


# ------------------------------------------------------------------ parse ---

def _ts(value):
    """GitHub exports carry @timestamp in epoch milliseconds; some tools write
    created_at as ISO 8601 or epoch seconds. Returns RFC 3339 UTC or None."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        secs = value / 1000.0 if value > 1e11 else float(value)
        return datetime.fromtimestamp(secs, timezone.utc).isoformat()
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return _ts(int(text))
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    return None


def _str(v):
    return v if isinstance(v, str) and v else (str(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None)


def _normalize(row):
    if not isinstance(row, dict):
        return None
    return {
        "ts": _ts(row.get("@timestamp", row.get("created_at"))),
        "action": _str(row.get("action")) or "unknown",
        "actor": _str(row.get("actor") or row.get("user")),
        "repo": _str(row.get("repo") or row.get("repository")),
        "access": _str(row.get("programmatic_access_type")),
        "app": _str(row.get("oauth_application_name") or row.get("integration")
                    or row.get("application_name")),
        "token_id": _str(row.get("token_id")),
        "user_agent": _str(row.get("user_agent")),
    }


def parse_github_log(path):
    """Read a GitHub security-log export (a JSON array, or one JSON object per
    line) into normalized events, oldest first. Every row must be an object
    naming an ``action``; anything else is refused rather than guessed at."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    bad = ValueError("%s is not a GitHub security-log export "
                     "(expected a JSON array or JSON lines of audit events)" % path)
    if not text:
        raise bad
    try:
        if text.startswith("["):
            rows = json.loads(text)
        else:
            rows = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    except ValueError:
        raise bad
    if not isinstance(rows, list) or not all(
            isinstance(r, dict) and isinstance(r.get("action"), str) for r in rows):
        raise bad
    events = [_normalize(r) for r in rows]
    events.sort(key=lambda e: e["ts"] or "")
    return events


_AGENT_UA = re.compile(r"\bAgent/([A-Za-z0-9][A-Za-z0-9._-]*?)(?:_\d[\w.-]*)?(?:\s|$)")


def ua_agent(user_agent):
    """The agent a client declares in its user-agent (GitHub CLI appends
    ``Agent/<name>_<version>_agent`` when an AI agent drives it), or None."""
    if not user_agent:
        return None
    m = _AGENT_UA.search(user_agent)
    return m.group(1) if m else None


def agent_key(event):
    """Who acted, when it was not the person in a browser: the named OAuth or
    GitHub App (plus any agent the client declares in its user-agent), else
    the token. None means no programmatic client is named — the export
    attributes the act to the person."""
    declared = ua_agent(event.get("user_agent"))
    if event.get("app"):
        key = "app:%s" % event["app"]
    elif event.get("access") or event.get("token_id"):
        key = "token:%s" % (event.get("token_id") or event["access"])
    elif declared:
        key = "agent:%s" % declared
        declared = None
    else:
        return None
    return "%s [%s]" % (key, declared) if declared else key


_OS = (("iPhone", "iOS"), ("iPad", "iOS"), ("Android", "Android"), ("Windows", "Windows"),
       ("Macintosh", "macOS"), ("Mac OS X", "macOS"), ("Linux", "Linux"))


def device_family(user_agent):
    for needle, fam in _OS:
        if user_agent and needle in user_agent:
            return fam
    return None


def unusual_devices(events, *, at_most=2):
    """Events from a device family seen at most ``at_most`` times in the whole
    export: a rare operating system acting in the account is worth a look,
    whoever it turns out to be."""
    fams = [device_family(e.get("user_agent")) for e in events]
    counts = {}
    for f in fams:
        if f:
            counts[f] = counts.get(f, 0) + 1
    return [e for e, f in zip(events, fams) if f and counts[f] <= at_most]


# ----------------------------------------------------------------- ingest ---

def ingest(events, recorder, *, subject=None, session_id="door"):
    """Seal each event as an ingested-tier record in ``recorder``'s chain,
    keeping the event's own time. Returns the appended records."""
    out = []
    for e in events:
        key = agent_key(e)
        agent = {"id": key, "name": key.split(":", 1)[1].split(" [")[0]} if key else \
            {"id": "human:%s" % (e.get("actor") or "unknown"), "name": e.get("actor") or "unknown"}
        detail = " · ".join(x for x in (e.get("repo"), e.get("access")) if x)
        rec = build(
            "tool_call", "security",
            tool="github:%s" % e["action"],
            tool_input=detail or e["action"],
            ts=e["ts"],
            agent=agent,
            principal={"human_id": e["actor"]} if e.get("actor") else None,
            source=dict(SOURCE),
            subject=subject,
            session_id=session_id,
        )
        recorder.append(rec)
        out.append(rec)
    return out


def isolate(records, key):
    """Only the records attributed to one outside agent. ``agent:NAME`` gathers
    every client that declared NAME, whichever app or token it came through —
    one agent often acts under several credentials."""
    if key.startswith("agent:"):
        name = key.split(":", 1)[1]
        tag = "[%s]" % name
        return [r for r in records
                if (r.get("agent") or {}).get("id") == key
                or str((r.get("agent") or {}).get("id", "")).endswith(tag)]
    return [r for r in records if (r.get("agent") or {}).get("id") == key]


def is_routine(action):
    """True for automatic housekeeping such as token refreshes."""
    action = str(action or "")
    if action.startswith("github:"):
        action = action[len("github:"):]
    return action in ROUTINE_ACTIONS


def split_routine(records, keep_ids=()):
    """(shown, hidden): routine records are hidden unless their id is in
    ``keep_ids`` (for example, because they broke a rule)."""
    keep = set(keep_ids)
    shown, hidden = [], []
    for r in records:
        tool = (r.get("action") or {}).get("tool")
        (hidden if is_routine(tool) and r.get("record_id") not in keep else shown).append(r)
    return shown, hidden


# ------------------------------------------------------------------ match ---

def _when(rec):
    try:
        return datetime.fromisoformat(str(rec.get("ts")).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


_INGEST_FAMILY = (
    (re.compile(r"^github:git\.push"), "push"),
    (re.compile(r"^github:git\.(clone|fetch)"), "fetch"),
    (re.compile(r"^github:pull_request"), "pr"),
    (re.compile(r"^github:issue"), "issue"),
    (re.compile(r"^github:release"), "release"),
    (re.compile(r"^github:gist\."), "gist"),
    (re.compile(r"^github:workflows?\."), "workflow"),
    (re.compile(r"^github:(repo|protected_branch|repository_ruleset)\."), "repo"),
)

# What each kind of command on the agent's side can account for. ``gh api``
# can drive any repository-level change, so it accounts for every family a
# REST call can produce (not git transport, which the API does not do).
_API_FAMILIES = frozenset({"pr", "issue", "release", "gist", "workflow", "repo"})
_OWN_FAMILY = (
    (re.compile(r"\bgit\s+push\b"), frozenset({"push"})),
    (re.compile(r"\bgit\s+(clone|fetch|pull)\b"), frozenset({"fetch"})),
    (re.compile(r"\bgh\s+api\b"), _API_FAMILIES),
    (re.compile(r"\bgh\s+pr\b"), frozenset({"pr"})),
    (re.compile(r"\bgh\s+issue\b"), frozenset({"issue"})),
    (re.compile(r"\bgh\s+release\b"), frozenset({"release"})),
    (re.compile(r"\bgh\s+gist\b"), frozenset({"gist"})),
    (re.compile(r"\bgh\s+(run|workflow)\b"), frozenset({"workflow"})),
    (re.compile(r"\bgh\s+repo\b"), frozenset({"repo"})),
)


def _ingest_family(rec):
    tool = (rec.get("action") or {}).get("tool") or ""
    for pat, fam in _INGEST_FAMILY:
        if pat.search(tool):
            return fam
    return None


def _own_families(rec):
    act = rec.get("action") or {}
    text = " ".join(str(x) for x in (act.get("tool"), (act.get("input") or {}).get("summary")) if x)
    fams = set()
    for pat, f in _OWN_FAMILY:
        if pat.search(text):
            fams |= f
    return fams


def match(ingested, own):
    """Line each ingested record up against the agent's own record of the same
    act. One command on the agent's side often produces several platform
    events (one ``gh api`` call can set a dozen settings), so an own record
    accounts for every event of a kind it can produce that falls in its
    window: from PROBABLE_WITHIN seconds before it to MATCHED_WITHIN seconds
    after (hook records are written when the command finishes).

    ``matched``: within MATCHED_WITHIN seconds of the command; ``probable``:
    within its window but further off; ``unmatched``: nothing on the agent's
    side accounts for it."""
    pool = []
    for o in own:
        t, fams = _when(o), _own_families(o)
        if t is not None and fams:
            pool.append((t, fams, o))
    pool.sort(key=lambda x: x[0])
    results = []
    for rec in sorted(ingested, key=lambda r: r.get("ts") or ""):
        t, fam = _when(rec), _ingest_family(rec)
        best = None
        if t is not None and fam:
            for ot, fams, o in pool:
                if fam not in fams:
                    continue
                if not (ot - PROBABLE_WITHIN <= t <= ot + MATCHED_WITHIN):
                    continue
                gap = abs(ot - t)
                if best is None or gap < best[0]:
                    best = (gap, o)
        if best:
            tier = "matched" if best[0] <= MATCHED_WITHIN else "probable"
            results.append({"tier": tier, "ingested": rec, "own": best[1],
                            "gap_seconds": round(best[0], 1)})
        else:
            results.append({"tier": "unmatched", "ingested": rec, "own": None,
                            "gap_seconds": None})
    return results


# ------------------------------------------------------- credentials ---

def _credential(rec):
    """The credential part of an agent id: 'app:X [agent]' -> 'app:X'."""
    return str((rec.get("agent") or {}).get("id", "")).split(" [", 1)[0]


def credentials(records):
    """Which credentials the agent acted through, with counts. One agent using
    several keys is itself worth seeing: each key is a separate way in."""
    out = {}
    for r in records:
        c = _credential(r)
        out[c] = out.get(c, 0) + 1
    return out


def unexpected_credentials(records, expected):
    """Records where the agent acted through a credential other than the ones
    the buyer issued it. A vendor agent should act only through its own key."""
    allowed = set(expected)
    return [r for r in records if _credential(r) not in allowed]


# --------------------------------------------------- done as the person ---

# Acts only the person can perform: never re-attributed to an agent.
_PERSON_ONLY = re.compile(r"^github:(user\.|two_factor|passkey|webauthn)")
DONE_AS_PERSON_WITHIN = 300   # seconds


def _agent_on_site(rec, site):
    act = rec.get("action") or {}
    tool = str(act.get("tool") or "")
    if "chrome" not in tool and "browser" not in tool:
        return False
    return site in str((act.get("input") or {}).get("summary") or "")


def done_as_person(ingested, own, *, site, within=DONE_AS_PERSON_WITHIN):
    """Events the platform attributes to the person, made while the agent's own
    record shows it driving the person's browser on the same site. The platform
    cannot tell the two apart; the agent's record can. Acts only a person can
    perform (sign-in, two-factor, passkeys) are never attributed to the agent.
    This is a likelihood from timing, not proof."""
    sessions = sorted(t for t in (_when(o) for o in own if _agent_on_site(o, site))
                      if t is not None)
    hits = []
    for rec in ingested:
        if not str((rec.get("agent") or {}).get("id", "")).startswith("human:"):
            continue
        if _PERSON_ONLY.search(str((rec.get("action") or {}).get("tool") or "")):
            continue
        t = _when(rec)
        if t is None or not sessions:
            continue
        gap = min(abs(s - t) for s in sessions)
        if gap <= within:
            hits.append({"ingested": rec, "gap_seconds": round(gap, 1)})
    return hits


# ------------------------------------------------------------------ rules ---

def bundled_rules(name):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "policies", name + ".json")


def load_rules(path):
    return _policy.load_policy(path)


def check(records, rules):
    return _policy.evaluate(records, rules)


# ------------------------------------------------------------------- page ---

_STYLE = """
:root{--ink:#16202a;--muted:#5b6b7a;--line:#d9e1e8;--bg:#fbfcfd;--card:#ffffff;
--bad:#b42318;--warn:#a15c07;--ok:#1d7a46;--accent:#1f4e79}
@media (prefers-color-scheme: dark){:root{--ink:#e6edf3;--muted:#9aa8b6;--line:#2b3742;
--bg:#0f151b;--card:#161e26;--bad:#f97066;--warn:#f5b84a;--ok:#5fd09a;--accent:#7cb4e8}}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:900px;margin:0 auto;padding:28px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px}
.sub{color:var(--muted);margin:0 0 20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px}
.tile b{display:block;font-size:24px;font-variant-numeric:tabular-nums}
.tile span{color:var(--muted);font-size:13px}
.bad{color:var(--bad)}.warn{color:var(--warn)}.ok{color:var(--ok)}
.note{border-left:3px solid var(--accent);background:var(--card);padding:10px 14px;margin:16px 0;color:var(--muted);font-size:14px}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}td.t{font-variant-numeric:tabular-nums;white-space:nowrap}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
"""


def _e(v):
    return html.escape("" if v is None else str(v), quote=True)


def _creds_section(records, expected):
    used = credentials(records)
    off = {_credential(r) for r in unexpected_credentials(records, expected)} if expected else set()
    rows = "".join(
        "<tr><td><code>%s</code></td><td>%d</td><td class='%s'>%s</td></tr>" % (
            _e(c), n, "bad" if c in off else "",
            "not a credential issued to this agent" if c in off else
            ("issued" if expected else ""))
        for c, n in sorted(used.items(), key=lambda x: -x[1]))
    lead = ("The agent should act only through the credentials issued to it."
            if expected else
            "Each credential is a separate way in. Pass the ones you issued this agent "
            "to flag any others.")
    return ("<h2>Credentials the agent used</h2><p class='sub'>%s</p><div class='wrap'>"
            "<table><tr><th>Credential</th><th>Actions</th><th></th></tr>%s</table></div>"
            % (lead, rows))


def _as_person_section(hits):
    if not hits:
        return ""
    rows = "".join(
        "<tr><td class='t'>%s</td><td><code>%s</code></td><td>%s s</td></tr>" % (
            _e((h["ingested"].get("ts") or "")[:16].replace("T", " ")),
            _e(((h["ingested"].get("action") or {}).get("tool") or "").replace("github:", "", 1)),
            _e(h["gap_seconds"]))
        for h in hits)
    return ("<h2>Likely done by the agent as the person</h2><p class='sub'>The platform "
            "attributes these to the person. The agent's own record shows it was driving the "
            "person's browser on the same site within minutes. A likelihood from timing, not "
            "proof; sign-ins and two-factor prompts are never counted.</p><div class='wrap'>"
            "<table><tr><th>When (UTC)</th><th>Action</th><th>Nearest agent activity</th></tr>"
            "%s</table></div>" % rows)


def render_page(records, matches, verdict, *, agent, title=None, unusual=(),
                as_person=(), expected_credentials=None, routine=(),
                source_actions=None):
    """One self-contained HTML page: what the agent did, what broke a rule,
    and what its own record does not account for. Every value that came from
    the export is escaped."""
    tiers = {"matched": 0, "probable": 0, "unmatched": 0}
    by_id = {}
    for m in matches:
        tiers[m["tier"]] += 1
        by_id[m["ingested"].get("record_id")] = m
    violated = [r for r in verdict.get("rules", []) if r["status"] == "violated"]
    bad_ids = {rid for r in violated for rid in r["violators"]}
    times = sorted(r.get("ts") for r in records if r.get("ts"))
    window = "%s to %s" % (times[0][:10], times[-1][:10]) if times else "no records"
    head = records[-1]["integrity"]["hash"] if records and "integrity" in records[-1] else "none"

    rows = []
    for r in sorted(records, key=lambda x: x.get("ts") or ""):
        act = r.get("action") or {}
        summ = (act.get("input") or {}).get("summary") or ""
        m = by_id.get(r.get("record_id"))
        tier = m["tier"] if m else "not compared"
        cls = "bad" if r.get("record_id") in bad_ids else ("warn" if tier == "unmatched" else "")
        rows.append(
            "<tr class='%s'><td class='t'>%s</td><td><code>%s</code></td><td>%s</td>"
            "<td>%s</td><td>%s</td></tr>" % (
                cls, _e((r.get("ts") or "")[:19].replace("T", " ")),
                _e((act.get("tool") or "").replace("github:", "", 1)), _e(summ),
                _e(tier), "rule broken" if r.get("record_id") in bad_ids else ""))

    rule_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td class='%s'>%s</td><td>%d</td></tr>" % (
            _e(r["id"]), _e(r["description"]),
            "bad" if r["status"] == "violated" else ("ok" if r["status"] == "pass" else ""),
            _e(r["status"]), len(r["violators"]))
        for r in verdict.get("rules", []))

    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%(title)s</title><style>%(style)s</style></head><body><main>
<h1>%(title)s</h1>
<p class="sub">Outside agent <code>%(agent)s</code> &middot; %(window)s &middot; %(n)d actions</p>
<div class="tiles">
<div class="tile"><b>%(n)d</b><span>actions in the export</span></div>
<div class="tile"><b class="%(vcls)s">%(nv)d</b><span>rules broken</span></div>
<div class="tile"><b class="%(ucls)s">%(un)d</b><span>not in the agent's own record</span></div>
<div class="tile"><b>%(mt)d</b><span>matched or probable</span></div>
</div>
<div class="note">These records were <b>ingested</b> from the account's own security-log export
and sealed into a hash chain on ingest (chain head <code>%(head)s</code>). Sealing proves this copy
has not been edited since, not the completeness of the export: the export is only as complete as
what the platform logged. One week of records is a baseline: what changed since the
prior period appears from the second week on. "Not in the agent's own record" means no matching
action was found in the record the agent kept, either because none was kept or because the act
was not recorded there.</div>
<div class="note"><b>What this source cannot show.</b> %(cannot)s%(routine)s</div>
<h2>Rules</h2><div class="wrap"><table><tr><th>Rule</th><th>What it checks</th><th>Result</th><th>Records</th></tr>
%(rules)s</table></div>
%(creds)s
%(asperson)s
%(unusual)s
<h2>What the agent did</h2><div class="wrap"><table>
<tr><th>When (UTC)</th><th>Action</th><th>Detail</th><th>Agent's own record</th><th></th></tr>
%(rows)s</table></div>
</main></body></html>""" % {
        "title": _e(title or "What an outside agent did"),
        "style": _STYLE, "agent": _e(agent), "window": _e(window),
        "n": len(records), "nv": len(violated), "vcls": "bad" if violated else "ok",
        "un": tiers["unmatched"], "ucls": "warn" if tiers["unmatched"] else "ok",
        "mt": tiers["matched"] + tiers["probable"], "head": _e(head[:16] + "..." if len(head) > 16 else head),
        "rules": rule_rows, "rows": "\n".join(rows),
        "creds": _creds_section(list(records) + list(routine), expected_credentials),
        "cannot": _e(cannot_see(source_actions if source_actions is not None else
                                [(r.get("action") or {}).get("tool") for r in list(records) + list(routine)])),
        "routine": (" %d automatic token refreshes by this agent are sealed in the chain "
                    "but not listed below." % len(routine)) if routine else "",
        "asperson": _as_person_section(as_person),
        "unusual": ("<h2>Unusual devices in the account</h2><p class='sub'>A device type seen "
                    "only once or twice in the whole export. Not necessarily the agent; worth a look."
                    "</p><div class='wrap'><table><tr><th>When (UTC)</th><th>Action</th>"
                    "<th>Device</th></tr>%s</table></div>" % "".join(
                        "<tr><td class='t'>%s</td><td><code>%s</code></td><td>%s</td></tr>" % (
                            _e((u.get("ts") or "")[:16].replace("T", " ")), _e(u.get("action")),
                            _e(device_family(u.get("user_agent"))))
                        for u in unusual)) if unusual else "",
    }
