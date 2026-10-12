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

Supported exports: a GitHub account security log (JSON array or JSON lines,
as downloaded from Settings > Archives > Security log), and a Salesforce
Event Monitoring export (EventLogFile CSVs; see ``door_sources``).

    from halo_record import Recorder, door
    events = door.parse_github_log("export.json")
    recs = door.ingest(events, Recorder("door.jsonl"), subject="acme")
    mine = door.isolate(recs, "app:Example Agent")
    page = door.render_page(mine, door.match(mine, own_records),
                            door.check(mine, door.load_rules(door.bundled_rules("github-default"))),
                            agent="app:Example Agent", chain=recs)

The page is the Runtime Report in door mode (see ``report.render``): the whole
sealed chain is embedded and re-verified in the reader's browser, and the
page displays the one agent's rows under a five-line summary.

Pure stdlib.
"""

import html
import json
import os
import re
from datetime import datetime, timezone

from . import policy as _policy
from .door_sources import (DEFAULT_ALLOWLIST, SALESFORCE_SOURCE, ip_allowed,  # noqa: F401
                           parse_salesforce_eventlog, shared_sessions)
from .record import build
from .redact import mask_known_secrets

SOURCE = {"adapter": "github_audit", "via": "GitHub security log export",
          "capture": "ingested"}
_SF = SALESFORCE_SOURCE["adapter"]
_PREFIX = re.compile(r"^(github|salesforce):")

# What a Salesforce Event Monitoring export does not carry, for the page.
SALESFORCE_CANNOT_SHOW = (
    "What an Agentforce agent reasoned, was prompted with, or answered. An Apex Execution "
    "row names the bot that ran (BOT_IDENTIFIER); the agent's prompts, plans and model "
    "output are not in these files.",
    "Which records a query returned. A REST API row shows that a query ran against an "
    "object and how many rows came back, not which rows.",
    "Event types this org does not export. Login and a few other types are available "
    "without an add-on; REST API, Apex Execution, URI, Report Export and Bulk API rows may "
    "require the Event Monitoring (Shield) add-on. A type absent from the input is an "
    "absent file, not an absent event: check which types this org receives on the first "
    "real export.",
    "Who was at the keyboard on a shared session. Rows are attributed to a connected app "
    "by the session it signed in with; a person acting on that same session reads as the "
    "app, and the reverse.",
    "Anything outside Salesforce. What the integration did on its own side is not in this "
    "log; a vendor record, when supplied, is lined up against these rows.",
    "Time between files. EventLogFile files are produced per event type per interval "
    "(daily, or hourly where enabled); a day missing from the input is a gap in the input, "
    "not proof of quiet.",
)

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
    if event.get("adapter") == _SF:
        # Every Salesforce row carries a session key, so a session alone is
        # not a programmatic client: it is one only when the row names an app
        # (or a bot), or the sign-in was an API sign-in.
        if event.get("app"):
            return "app:%s" % event["app"]
        if event.get("access") and event.get("token_id"):
            return "token:%s" % event["token_id"]
        return None
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
    keeping the event's own time. Returns the appended records.

    Salesforce rows seal the event type and the SHA-256 of the whole CSV row
    under ``data`` (never the row itself: session keys, query text and
    addresses stay out of the chain)."""
    out = []
    for e in events:
        key = agent_key(e)
        agent = {"id": key, "name": key.split(":", 1)[1].split(" [")[0]} if key else \
            {"id": "human:%s" % (e.get("actor") or "unknown"), "name": e.get("actor") or "unknown"}
        sf = e.get("adapter") == _SF
        detail = e.get("detail") or " · ".join(x for x in (e.get("repo"), e.get("access")) if x)
        data = None
        if sf:
            data = {"event_type": e.get("event_type"), "source_row": e.get("raw_hash")}
        rec = build(
            "tool_call", "security",
            tool="%s:%s" % ("salesforce" if sf else "github", e["action"]),
            tool_input=detail or e["action"],
            ts=e["ts"],
            agent=agent,
            # The person is sealed as the record's own agent field shows them:
            # an email address keeps its initial and domain, so the buyer's
            # page carries no staff address (a GitHub login is left as is).
            principal={"human_id": mask_known_secrets(e["actor"])} if e.get("actor") else None,
            source=dict(SALESFORCE_SOURCE if sf else SOURCE),
            subject=subject,
            session_id=session_id,
            data=data,
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

def _e(v):
    return html.escape("" if v is None else str(v), quote=True)


def _when_short(rec, n=16):
    return _e((rec.get("ts") or "")[:n].replace("T", " "))


def _tool(rec):
    return _e(_PREFIX.sub("", (rec.get("action") or {}).get("tool") or "", 1))


def _section(title, body, *, open_=False):
    """One folded detail section of the door page."""
    return "<details class='door-sec'%s><summary>%s</summary>%s</details>" % (
        " open" if open_ else "", title, body)


def _table(head, rows):
    return ("<div class='door-scroll'><table><tr>%s</tr>%s</table></div>" % (
        "".join("<th>%s</th>" % h for h in head), rows))


def _rules_section(verdict, allow_note):
    rules = verdict.get("rules", [])
    violated = [r for r in rules if r["status"] == "violated"]
    rows = "".join(
        "<tr><td>%s</td><td>%s</td><td class='%s'>%s</td><td>%d</td></tr>" % (
            _e(r["id"]), _e(r["description"]),
            "bad" if r["status"] == "violated" else ("ok" if r["status"] == "pass" else ""),
            _e(r["status"]), len(r["violators"]))
        for r in rules)
    title = "Rules (%d checked, %d broken)" % (len(rules), len(violated))
    return _section(title, allow_note + _table(("Rule", "What it checks", "Result", "Records"), rows),
                    open_=bool(violated))


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
    return _section("Credentials the agent used (%d)" % len(used),
                    "<p class='sub'>%s</p>%s" % (lead, _table(("Credential", "Actions", ""), rows)),
                    open_=bool(off))


def _as_person_section(hits):
    if not hits:
        return ""
    rows = "".join(
        "<tr><td class='t'>%s</td><td><code>%s</code></td><td>%s s</td></tr>" % (
            _when_short(h["ingested"]), _tool(h["ingested"]), _e(h["gap_seconds"]))
        for h in hits)
    return _section(
        "Likely done by the agent as the person (%d)" % len(hits),
        "<p class='sub'>The platform attributes these to the person. The agent's own record "
        "shows it was driving the person's browser on the same site within minutes. A "
        "likelihood from timing, not proof; sign-ins and two-factor prompts are never counted."
        "</p>" + _table(("When (UTC)", "Action", "Nearest agent activity"), rows))


def _shared_section(hits):
    if not hits:
        return ""
    rows = "".join(
        "<tr><td class='t'>%s</td><td><code>%s</code></td><td><code>%s</code></td>"
        "<td>%s</td><td>%d</td></tr>" % (
            _e((h.get("first_ts") or "")[:16].replace("T", " ")), _e(h["session"]),
            _e(h["agent"]), _e(", ".join(h["ips"])), h["rows"])
        for h in hits)
    return _section(
        "One session, more than one address (%d)" % len(hits),
        "<p class='sub'>A session the platform issued at one sign-in, later used from a "
        "different address. The log cannot tell a proxy change from a copied or shared "
        "session; it shows that one sign-in was used from two places. Worth a look, not a "
        "finding.</p>" + _table(("Signed in (UTC)", "Session", "Client", "Addresses",
                                 "Rows from the other address"), rows))


def _unmatched_section(matches, bad_ids):
    unmatched = [m for m in matches if m["tier"] == "unmatched"]
    if not unmatched:
        return ""
    rows = "".join(
        "<tr class='%s'><td class='t'>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>" % (
            "bad" if m["ingested"].get("record_id") in bad_ids else "",
            _when_short(m["ingested"], 19), _tool(m["ingested"]),
            _e(((m["ingested"].get("action") or {}).get("input") or {}).get("summary") or ""),
            "rule broken" if m["ingested"].get("record_id") in bad_ids else "")
        for m in unmatched)
    return _section(
        "Not in the agent's own record (%d)" % len(unmatched),
        "<p class='sub'>No matching action was found in the record the agent kept, either "
        "because none was kept or because the act was not recorded there. Matched and "
        "probable rows are in the table below.</p>"
        + _table(("When (UTC)", "Action", "Detail", ""), rows), open_=True)


def _unusual_section(unusual):
    if not unusual:
        return ""
    rows = "".join(
        "<tr><td class='t'>%s</td><td><code>%s</code></td><td>%s</td></tr>" % (
            _e((u.get("ts") or "")[:16].replace("T", " ")), _e(u.get("action")),
            _e(device_family(u.get("user_agent"))))
        for u in unusual)
    return _section(
        "Unusual devices in the account (%d)" % len(unusual),
        "<p class='sub'>A device type seen only once or twice in the whole export. Not "
        "necessarily the agent; worth a look.</p>"
        + _table(("When (UTC)", "Action", "Device"), rows))


_VOCAB = {
    "github": {"title": "What an outside agent did", "who": "Outside agent",
               "platform": "GitHub", "tenant": "this account",
               "sample": "SAMPLE — synthetic export; no real account data."},
    "salesforce": {"title": "What an outside integration did in Salesforce", "who": "Connected app",
                   "platform": "Salesforce", "tenant": "this org",
                   "sample": "SAMPLE — synthetic Salesforce export; no real org data."},
}


def _plural(n, one, many=None):
    return "%d %s" % (n, one if n == 1 else (many or one + "s"))


def summary_lines(records, matches, verdict, *, agent, tenant, own_supplied=True,
                  as_person=(), routine=()):
    """The five plain lines at the top of the door page, in order: what the
    agent did and when; rules broken; credentials used; actions that look like
    a person on the agent's session (omitted when none); and what the agent's
    own record does not account for, or that no vendor record was supplied.
    Returns ``(text, css_class)`` pairs."""
    times = sorted(r.get("ts") for r in records if r.get("ts"))
    when = ("between %s and %s" % (times[0][:10], times[-1][:10])) if times else "(no dated records)"
    violated = [r for r in verdict.get("rules", []) if r["status"] == "violated"]
    used = credentials(list(records) + list(routine))
    unmatched = sum(1 for m in matches if m["tier"] == "unmatched")
    lines = [("%s acted in %s %s %s." % (agent, tenant, _plural(len(records), "time"), when), "")]
    if violated:
        lines.append(("%s broken: %s" % (_plural(len(violated), "rule"),
                                         ", ".join(r["id"] for r in violated)), "bad"))
    else:
        lines.append(("No rules broken.", "ok"))
    lines.append(("It used %s: %s." % (_plural(len(used), "credential"),
                                       ", ".join(sorted(used, key=lambda c: -used[c]))), ""))
    if as_person:
        n = len(as_person)
        lines.append(("%d action%s like a person on the agent's session." % (
            n, " looks" if n == 1 else "s look"), "warn"))
    if own_supplied:
        lines.append(("%s not in the agent's own record." % (
            "1 action is" if unmatched == 1 else "%d actions are" % unmatched),
            "warn" if unmatched else "ok"))
    else:
        lines.append(("No vendor record was supplied; this page shows the platform's own log only.", ""))
    return lines


def render_page(records, matches, verdict, *, agent, title=None, unusual=(),
                as_person=(), expected_credentials=None, routine=(),
                source_actions=None, own_supplied=True, sample=False, anchored=None,
                source="github", shared=(), allowlist=None, chain=None, tenant=None):
    """The door page, rendered through the Runtime Report in door mode: the
    buyer's five-line summary on top, the verification badge and in-browser
    re-hash of the whole chain, the door's detail sections folded below, and
    the agent's rows in the records table. Every value that came from the
    export is escaped.

    ``chain`` is the whole sealed chain the export produced; the page embeds
    and verifies all of it and displays ``records`` (the one agent's rows).
    Without it, ``records`` is embedded as the chain, which verifies in the
    browser only when it is the whole chain. ``routine`` rows are sealed in
    the chain but not listed. ``own_supplied=False`` states that no vendor
    record was supplied and drops the comparison counts. ``sample`` adds a
    banner. ``anchored`` is the anchor receipt to cite, or None for none.
    ``tenant`` names the account or org in the first summary line."""
    from . import report as _report
    voc = _VOCAB.get(source, _VOCAB["github"])
    records = list(records)
    routine = list(routine)
    chain = list(chain) if chain is not None else records
    violated = [r for r in verdict.get("rules", []) if r["status"] == "violated"]
    bad_ids = {rid for r in violated for rid in r["violators"]}
    tenant = tenant or next((str((r.get("subject") or {}).get("id")) for r in records
                             if isinstance(r.get("subject"), dict) and (r.get("subject") or {}).get("id")),
                            None) or voc["tenant"]

    lines = summary_lines(records, matches, verdict, agent=agent, tenant=tenant,
                          own_supplied=own_supplied, as_person=as_person, routine=routine)
    # Text content, not attributes: only <, > and & need escaping, so the
    # lines keep their apostrophes.
    summary = ["<li%s>%s</li>" % ((" class='%s'" % cls) if cls else "",
                                  html.escape(text, quote=False))
               for text, cls in lines]

    source_note = ("Source: the buyer's own %s export, sealed on ingest. The export is as complete "
                   "as what the platform logged; sealing proves this copy has not been edited "
                   "since. Sealing proves integrity, not the completeness of the export; one "
                   "week of records is a baseline, and what changed since the prior period "
                   "appears from the second week on." % voc["platform"])

    if source == "salesforce":
        cannot = "<ul>%s</ul>" % "".join("<li>%s</li>" % _e(x) for x in SALESFORCE_CANNOT_SHOW)
        allow_note = ("<p class='sub'>Address allowlist behind <code>login-outside-allowlist</code>: "
                      "<code>%s</code>%s</p>" % (
                          _e(", ".join(allowlist)),
                          " (the sample's range; pass <code>--allow-ip</code> for yours)"
                          if sample else "")
                      if allowlist else
                      "<p class='sub'>No address allowlist was supplied, so "
                      "<code>login-outside-allowlist</code> had nothing to check.</p>")
    else:
        cannot = "<p>%s</p>" % _e(cannot_see(
            source_actions if source_actions is not None else
            [(r.get("action") or {}).get("tool") for r in records + routine]))
        allow_note = ""
    if routine:
        cannot += ("<p class='sub'>%d automatic token refreshes by this agent are sealed in the "
                   "chain but not listed below.</p>" % len(routine))

    sections = "".join(x for x in (
        _rules_section(verdict, allow_note),
        _creds_section(records + routine, expected_credentials),
        _unmatched_section(matches, bad_ids) if own_supplied else "",
        _as_person_section(as_person),
        _shared_section(shared),
        _unusual_section(unusual),
        _section("What this source cannot show", cannot),
    ) if x)

    receipt = (_e(anchored) if anchored else
               "none at the time this page was rendered"
               + (" (a sample is never anchored)" if sample else
                  "; <code>halo anchor</code> records the head with a witness"))
    stands = ("<b>Where this copy stands.</b> The sealed copy's integrity holds relative to a "
              "head someone other than the operator holds; a head only the operator keeps can "
              "be re-sealed without a trace. Anchor receipt: %s. Keep the chain file in storage "
              "you control; the witness keeps the head." % receipt)

    page = _report.render(chain, door={
        "agent": agent, "who": voc["who"], "title": title or voc["title"],
        "hidden": [r.get("record_id") for r in routine if r.get("record_id")],
        "banner": ("<div class=\"banner\">%s</div>\n" % _e(voc["sample"])) if sample else "",
        "summary": summary, "source_note": source_note, "sections": sections, "stands": stands,
    })
    return _report._LONE_SURROGATE_RE.sub("�", page)
