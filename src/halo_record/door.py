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
page displays the one agent's rows under a five-line summary, a chart of its
actions per week, the rules checked, the credentials it signed in through and
the comparison against its own record.

Pure stdlib.
"""

import html
import json
import math
import os
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from . import _view
from . import policy as _policy
from .door_sources import (DEFAULT_ALLOWLIST, PLATFORM_IP, SALESFORCE_SOURCE, ip_allowed,  # noqa: F401
                           parse_salesforce_eventlog, shared_sessions)
from .record import build
from .redact import mask_known_secrets

SOURCE = {"adapter": "github_audit", "via": "GitHub security log export",
          "capture": "ingested"}
_SF = SALESFORCE_SOURCE["adapter"]
_PREFIX = re.compile(r"^(github|salesforce):")

# What the same export does not carry about an Agentforce agent in particular;
# listed first on an Agentforce page. One bullet covers prompts, plans and
# model output: the Apex Execution row names the bot, nothing more.
AGENTFORCE_CANNOT_SHOW = (
    "What an Agentforce agent reasoned, was prompted with, or answered. An Apex Execution "
    "row names the bot that ran (BOT_IDENTIFIER); the agent's prompts, plans, topic choice, "
    "model output and session outcome are Data 360 tables (Agentforce Session Tracing, "
    "Einstein Audit), not EventLogFile.",
    "Which customers an action touched. Rows for a service-agent carry the agent's own user, "
    "not the customer; the customer join lives in Agentforce Session Tracing.",
    "What the system on the other end of a call did. An Apex Callout row shows the host, "
    "method and status; the integration layer and core-system side of the call is in their logs.",
)

# What a Salesforce Event Monitoring export does not carry, for the page.
SALESFORCE_CANNOT_SHOW = (
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

# The three lines in view under "What this export can't show" on a Salesforce
# page; the full list above folds under them.
SALESFORCE_CANNOT_SHOW_SHORT = (
    "What the agent was prompted with, planned, or answered \u2014 that lives in Agentforce "
    "Session Tracing (Data 360).",
    "Which customer an action touched, or what the core system did with a call.",
    "Anything outside Salesforce, or in event types this org does not export.",
)

# A call's query string never enters the chain; listed when the agent called out.
CALLOUT_CANNOT_SHOW = ("The query string of a call. The table under Every action shows each call's "
                       "path with its digit runs masked; the query string is not in the chain.")

def dropped_sentence(dropped):
    """``3 rows in the export were not sealed: unreadable timestamp (2), fewer
    columns than the header (1).`` for the rows the reader set aside."""
    total = sum(dropped.values())
    reasons = ", ".join("%s (%s)" % (reason, _n(n))
                        for reason, n in sorted(dropped.items(), key=lambda kv: (-kv[1], kv[0])) if n)
    return "%s in the export %s not sealed: %s." % (
        _plural(total, "row"), "was" if total == 1 else "were", reasons)


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
READS_SHORT = "Most reads, such as viewing files or calling read-only APIs."


def missing_kinds(actions):
    """Labels from ACTIVITY_KINDS with no matching action in the export."""
    actions = [str(a or "").replace("github:", "", 1) for a in actions]
    return [label for label, prefixes in ACTIVITY_KINDS
            if not any(a.startswith(p) for a in actions for p in prefixes)]


def missing_sentence(actions):
    """The sentence naming what this export has no records of, or "" when it
    carries every kind of activity in ACTIVITY_KINDS."""
    gone = missing_kinds(actions)
    if not gone:
        return ""
    listed = gone[0] if len(gone) == 1 else ", ".join(gone[:-1]) + ", or " + gone[-1]
    return ("This export has no records of %s. That does not mean none happened: the "
            "log did not include them." % listed)


def cannot_see(actions):
    """One plain sentence or two on what this export does not show."""
    gone = missing_sentence(actions)
    return "%s %s" % (gone, READS_NOTE) if gone else READS_NOTE


def missing_short(actions):
    """The one-line form of ``missing_sentence``: "Clones and fetches, or
    issues: not in a personal security log.", or "" when nothing is missing."""
    gone = missing_kinds(actions)
    if not gone:
        return ""
    listed = gone[0] if len(gone) == 1 else ", ".join(gone[:-1]) + ", or " + gone[-1]
    return "%s: not in a personal security log." % (listed[:1].upper() + listed[1:])


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

_URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^\s·]+|(?<![\w/])/[^\s·]+", re.I)
_DIGIT_RUN = re.compile(r"\d{4,}")


def mask_path_digits(url):
    """A URL or path with every run of four or more digits in its path
    replaced by ``****``: an account or record number is never written to the
    chain, while the path itself stays readable (``/core/v2/transfers``
    survives; ``/loans/0000012345/payments`` reads ``/loans/****/payments``).
    The host and any query string are left as given."""
    text = str(url or "")
    parts = urlsplit(text) if "://" in text else None
    if parts is not None:
        path = _DIGIT_RUN.sub("****", parts.path)
        return parts._replace(path=path).geturl()
    head, sep, query = text.partition("?")
    return _DIGIT_RUN.sub("****", head) + sep + query


def _mask_urls(text):
    """``mask_path_digits`` applied to each URL or absolute path in ``text``."""
    return _URL_RE.sub(lambda m: mask_path_digits(m.group(0)), str(text or ""))


def _target(event):
    """What the row acted on, as the chain seals it: a URL as host and path
    (digit runs masked, no scheme, no query), a path with its digit runs
    masked, anything else as the parser read it."""
    sf = event.get("adapter") == _SF
    t = event.get("target") if sf else event.get("repo")
    if not t:
        return None
    t = str(t)
    if "://" in t:
        parts = urlsplit(mask_path_digits(t))
        return (parts.hostname or "") + parts.path
    if t.startswith("/"):
        return mask_path_digits(t.split("?", 1)[0])   # a query string never enters the chain
    return t


def event_index(events, records):
    """``{record_id: event}`` for records ``ingest`` sealed from ``events``, in
    the same order. The page uses it for what the chain deliberately does not
    carry (addresses, session keys): a reading aid, never evidence."""
    events, records = list(events), list(records)
    if len(events) != len(records):
        raise ValueError("halo door: %d events but %d records; the index needs the records "
                         "ingest sealed from these events" % (len(events), len(records)))
    return {r["record_id"]: e for e, r in zip(events, records) if r.get("record_id")}


def ingest(events, recorder, *, subject=None, session_id="door"):
    """Seal each event as an ingested-tier record in ``recorder``'s chain,
    keeping the event's own time. Returns the appended records.

    Salesforce rows seal the event type, the SHA-256 of the whole CSV row,
    what the row acted on (``target``), the row's own status and, for an
    Agentforce row, its bot session under ``data`` (never the row itself:
    session keys, query text and addresses stay out of the chain; a URL's
    digit runs are masked before anything is kept). A GitHub row seals its
    repository as ``data.target``."""
    out = []
    for e in events:
        key = agent_key(e)
        agent = {"id": key, "name": key.split(":", 1)[1].split(" [")[0]} if key else \
            {"id": "human:%s" % (e.get("actor") or "unknown"), "name": e.get("actor") or "unknown"}
        sf = e.get("adapter") == _SF
        detail = e.get("detail") or " · ".join(x for x in (e.get("repo"), e.get("access")) if x)
        detail = _mask_urls(detail)
        data = {}
        target = _target(e)
        if target:
            data["target"] = target
        if sf:
            data.update({"event_type": e.get("event_type"), "source_row": e.get("raw_hash")})
            status = e.get("status")
            if status:
                data["status"] = int(status) if str(status).isdigit() else status
            if e.get("bot_session"):
                data["bot_session"] = e["bot_session"]
            if e.get("event_type") == "ApexCallout":
                # A call outside the org: the host it reached and the status
                # it got, sealed as fields the page can count on.
                data.update(callout_fields(e))
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
            data=data or None,
            # Every field here is an enumerated identifier the platform wrote
            # (an action name, an entry point, a URL with its digit runs
            # already masked, a status): named patterns mask and flag; the
            # high-entropy catch-all, which reads a long class name or path
            # as a secret, does not run over log identifiers.
            entropy=False,
        )
        recorder.append(rec)
        out.append(rec)
    return out


def callout_fields(event):
    """``{"host": ..., "status": ...}`` for an ApexCallout event: the URL's
    host only, and the HTTP status as an integer when the row carried one."""
    out = {}
    try:
        host = urlsplit(str(event.get("repo") or "")).hostname
    except ValueError:
        host = None
    if host:
        out["host"] = host
    m = re.search(r"(?:^| · )([1-5][0-9]{2})(?: · |$)", str(event.get("detail") or ""))
    if m:
        out["status"] = int(m.group(1))
    return out


def callouts(records):
    """The agent's calls outside the org (``salesforce:Callout.*`` rows):
    ``{"count": N, "hosts": {host: {"n": calls, "failed": non-2xx}}}``.
    A row sealed without a host counts under "(host not recorded)"."""
    hosts, count = {}, 0
    for r in records:
        tool = str((r.get("action") or {}).get("tool") or "")
        if not tool.startswith("salesforce:Callout."):
            continue
        count += 1
        data = r.get("data") if isinstance(r.get("data"), dict) else {}
        host = data.get("host")
        host = host if isinstance(host, str) and host else "(host not recorded)"
        status = data.get("status")
        h = hosts.setdefault(host, {"n": 0, "failed": 0})
        h["n"] += 1
        if isinstance(status, int) and not isinstance(status, bool) and not 200 <= status <= 299:
            h["failed"] += 1
    return {"count": count, "hosts": hosts}


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


def _h2(title):
    return "<h2>%s</h2>" % _e(title)


def _note(text, escape=True):
    return '<p class="note">%s</p>' % (_e(text) if escape else text)


def _section(title, body, *, open_=False):
    """One folded detail of the door page."""
    return '<details class="door-sec"%s><summary>%s</summary>%s</details>' % (
        " open" if open_ else "", _e(title), body)


def _table(head, rows):
    return ('<div class="door-scroll"><table><tr>%s</tr>%s</table></div>' % (
        "".join("<th>%s</th>" % h for h in head), rows))


def _n(n):
    """``1,433``: a count with a thousands separator."""
    return "{:,}".format(int(n))


def _plural(n, one, many=None):
    return "%s %s" % (_n(n), one if n == 1 else (many or one + "s"))


# ------------------------------------------------------------ the chart ---

DAY_BUCKETS_UP_TO = 14   # days: a span this short is charted per day, longer per ISO week


def bucket_counts(records, bad_ids=()):
    """Actions per calendar day (UTC) when the dated records span
    DAY_BUCKETS_UP_TO days or fewer, else per ISO week; one entry for every
    bucket from the first dated record to the last: ``{"unit": "day" |
    "week", "buckets": [(start, count, broken)], "first": date, "last":
    date}``, or None when no record carries a readable timestamp. ``broken``
    marks a bucket holding a record in ``bad_ids``."""
    days = []
    for r in records:
        dt = _view.ts_utc(r.get("ts"))
        if dt is None:
            continue
        rid = r.get("record_id")
        days.append((dt.date(), isinstance(rid, str) and rid in bad_ids))
    if not days:
        return None
    first = min(d for d, _ in days)
    last = max(d for d, _ in days)
    if (last - first).days + 1 <= DAY_BUCKETS_UP_TO:
        unit, start, step = "day", first, 1
        n = (last - first).days + 1
    else:
        unit, start, step = "week", first - timedelta(days=first.weekday()), 7
        n = (last - timedelta(days=last.weekday()) - start).days // 7 + 1
    buckets = [[start + timedelta(days=step * i), 0, False] for i in range(n)]
    for d, bad in days:
        b = buckets[(d - start).days // step]
        b[1] += 1
        b[2] = b[2] or bad
    return {"unit": unit, "buckets": [tuple(b) for b in buckets], "first": first, "last": last}


_STEPS = (1, 2, 4, 5, 8)


def axis_top(maxv):
    """``(top, step)``: the lowest round ceiling at or above ``maxv`` that
    divides into two, three or four equal steps of 1, 2, 4, 5 or 8 times a
    power of ten (so 3 reads 0-1-2-3, 24 reads 0-8-16-24, 13 reads 0-5-10-15)."""
    maxv = max(int(maxv), 1)
    best = None
    for k in range(0, 12):
        for s in _STEPS:
            step = s * 10 ** k
            for n in (4, 3, 2):
                top = step * n
                if top >= maxv and (best is None or top < best[0]):
                    best = (top, step)
        if best is not None:
            return best
    return (maxv, maxv)


def _num(v):
    return ("%.1f" % v).rstrip("0").rstrip(".")


def chart_svg(counted):
    """The bar chart as inline SVG (viewBox 800x150): y ticks at round
    numbers, one bar per bucket with the broken-rule buckets in the bad
    colour, an x label on every day (day buckets) or on the first week of
    each month (week buckets; every week when there are eight or fewer),
    thinned to what fits. Readable at one bar and at a hundred."""
    unit, buckets, first, last = counted["unit"], counted["buckets"], counted["first"], counted["last"]
    n = len(buckets)
    top, step = axis_top(max(c for _, c, _ in buckets))
    x0, x1, y0, y1 = 32.0, 796.0, 8.0, 116.0
    pitch = (x1 - x0) / n
    bw = max(min(pitch * 0.8, 120.0), 0.5)
    cross = buckets[0][0].year != buckets[-1][0].year

    def y_of(v):
        return y1 - (v / top) * (y1 - y0)
    ticks = list(range(0, top + 1, step))
    ylab = "".join('<text x="0" y="%s">%d</text>' % (_num(y_of(v) + 4), v) for v in reversed(ticks))
    grid = "".join('<line x1="26" y1="%s" x2="800" y2="%s"/>' % (_num(y_of(v)), _num(y_of(v)))
                   for v in ticks)
    bars = []
    for i, (_, count, broken) in enumerate(buckets):
        h = (count / top) * (y1 - y0)
        bars.append('<rect x="%s" y="%s" width="%s" height="%s"%s/>' % (
            _num(x0 + i * pitch), _num(y1 - h), _num(bw), _num(h),
            ' fill="var(--bad)"' if broken else ""))
    if unit == "day" or n <= 8:
        idx = list(range(n))
    else:
        idx = [0] + [i for i in range(1, n) if buckets[i][0].month != buckets[i - 1][0].month]
        room = max(int((x1 - x0) // (56 if cross else 44)), 1)
        stride = max(1, math.ceil(len(idx) / room))
        idx = idx[::stride]
    labels = []
    year = None
    for i in idx:
        start = buckets[i][0]
        # Across a year boundary the first label of each year carries it.
        text = _view.day_label(start, cross and start.year != year)
        year = start.year
        x = x0 + i * pitch
        anchor = ""
        if x + 6.2 * len(text) > 800:
            x, anchor = x + bw, ' text-anchor="end"'
        labels.append('<text x="%s" y="138"%s>%s</text>' % (_num(x), anchor, _e(text)))
    label = "Actions per %s, %s to %s" % (
        unit, _view.day_label(first, first.year != last.year), _view.day_label(last, True))
    return ('<svg class="weeks" viewBox="0 0 800 150" role="img" aria-label="%s">'
            '<g font-family="var(--mono)" font-size="10" fill="currentColor" opacity=".55">%s</g>'
            '<g stroke="currentColor" stroke-opacity=".12">%s</g>'
            '<g fill="var(--bar-strong)">%s</g>'
            '<g font-family="var(--mono)" font-size="10" fill="currentColor" opacity=".55"><!--x-->%s</g>'
            '</svg>' % (_e(label), ylab, grid, "".join(bars), "".join(labels)))


def _chart_section(records, bad_ids):
    counted = bucket_counts(records, bad_ids)
    if counted is None:
        return ""
    unit = counted["unit"]
    legend = '<span><i style="background:var(--bar-strong)"></i>actions per %s</span>' % unit
    if any(broken for _, _, broken in counted["buckets"]):
        legend += '<span><i style="background:var(--bad)"></i>%s with a broken rule</span>' % unit
    return _h2("When it acted") + chart_svg(counted) + '<div class="legend">%s</div>' % legend


# ------------------------------------------------------------- the rules ---

def rule_label(rule):
    """A short human-readable name for a rule: the pack's ``name`` or
    ``title`` when it carries one, else its id read as words (``no-repo-
    deletion`` reads "Repo deletion")."""
    for key in ("name", "title"):
        if isinstance(rule.get(key), str) and rule[key].strip():
            return rule[key].strip()
    rid = str(rule.get("id") or "")
    words = [w for w in re.split(r"[-_]+", rid) if w]
    if len(words) > 1 and words[0].lower() == "no":
        words = words[1:]
    text = " ".join(words)
    return (text[:1].upper() + text[1:]) if text else rid


def _rules_row(verdict, allow_note):
    spans = []
    for r in verdict.get("rules", []):
        label = _e(rule_label(r))
        desc = _e("%s: %s" % (r.get("id"), r.get("description") or "") if r.get("description")
                  else str(r.get("id") or ""))
        n = len(r.get("violators") or [])
        status = str(r.get("status") or "")
        if status == "violated":
            spans.append('<span class="v" title="%s">%s &middot; broken, %s</span>' % (
                desc, label, _plural(n, "action")))
        elif status == "pass":
            spans.append('<span title="%s">%s</span>' % (desc, label))
        elif status == "no_match":
            spans.append('<span class="u" title="%s">%s &middot; not applicable (no matching events)</span>'
                         % (desc, label))
        else:
            spans.append('<span class="u" title="%s">%s &middot; %s</span>' % (
                desc, label, _e(status.replace("_", " "))))
    return _h2("Rules") + '<div class="rulesrow">%s</div>' % "".join(spans) + allow_note


# ------------------------------------------------------- the credentials ---

def _cred_label(cred, agent=None, label=None):
    """``(html, mono)``: the display name when the credential is the agent's
    own key and one was given, an app's or declared agent's name in the text
    face, a token or anything else as its full key in the mono face."""
    if label and cred == agent:
        return _e(label), False
    kind, _, name = cred.partition(":")
    if kind in ("app", "agent") and name:
        return _e(name), False
    return _e(cred), True


def _reach_bars(records):
    """One bar per host the agent called outside the org, widest first, with
    the calls that got a non-2xx status as a suffix in the bad colour."""
    reach = callouts(records)
    if not reach["count"]:
        return ""
    top = max(h["n"] for h in reach["hosts"].values())
    bars = []
    for host, h in sorted(reach["hosts"].items(), key=lambda x: (-x[1]["n"], x[0])):
        failed = ('<span class="f">&middot; %d failed</span>' % h["failed"]) if h["failed"] else ""
        bars.append('<div class="hbar host"><span class="mono">%s</span><div class="t">'
                    '<i style="width:%d%%"></i></div><span class="n">%d%s</span></div>' % (
                        _e(host), max(1, round(h["n"] * 100 / top)), h["n"], failed))
    return (_h2("Where it reached") + "".join(bars)
            + _note("Hosts the agent called from inside the org; a failed call got a status "
                    "outside 2xx."))


def _creds_bars(records, expected, agent=None, label=None):
    used = credentials(records)
    if not used:
        return ""
    off = {_credential(r) for r in unexpected_credentials(records, expected)} if expected else set()
    top = max(used.values())
    bars = []
    for cred, n in sorted(used.items(), key=lambda x: (-x[1], x[0])):
        text, mono = _cred_label(cred, agent, label)
        classes = (["mono"] if mono else []) + (["v"] if cred in off else [])
        attrs = (' class="%s"' % " ".join(classes)) if classes else ""
        if cred in off:
            attrs += ' title="not a credential issued to this agent"'
        bars.append('<div class="hbar"><span%s>%s</span><div class="t"><i style="width:%d%%"></i></div>'
                    '<span class="n">%d</span></div>' % (attrs, text, max(1, round(n * 100 / top)), n))
    note = ("The agent should act only through the credentials issued to it. One marked in red "
            "is not among those you named." if expected else
            "Each credential is a separate way in. Compare against the ones you issued this agent.")
    return _h2("How it signed in") + "".join(bars) + _note(note)


# ----------------------------------------------- against the own record ---

def _split_bar(matches):
    total = len(matches)
    if not total:
        return ""
    missing = sum(1 for m in matches if m["tier"] == "unmatched")
    found = total - missing
    pct = round(found * 100 / total)
    return (_h2("Against the agent's own record")
            + '<div class="split"><i style="width:%d%%;background:var(--ok)"></i>'
              '<i style="width:%d%%;background:var(--bar)"></i></div>' % (pct, 100 - pct)
            + '<div class="legend"><span><i style="background:var(--ok)"></i>%d matched or probable</span>'
              '<span><i style="background:var(--bar)"></i>%d not found</span></div>' % (found, missing)
            + _note('"Not found" means the agent\'s record has nothing within the matching window, '
                    'whether it skipped the action or never kept one.'))


def _unmatched_fold(matches, bad_ids):
    unmatched = [m for m in matches if m["tier"] == "unmatched"]
    if not unmatched:
        return ""
    rows = "".join(
        '<tr class="%s"><td class="t">%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>' % (
            "bad" if m["ingested"].get("record_id") in bad_ids else "",
            _when_short(m["ingested"], 19), _tool(m["ingested"]),
            _e(((m["ingested"].get("action") or {}).get("input") or {}).get("summary") or ""),
            "rule broken" if m["ingested"].get("record_id") in bad_ids else "")
        for m in unmatched)
    return _section(
        "Not in the agent's own record (%d)" % len(unmatched),
        _note("No matching action was found in the record the agent kept, either because none "
              "was kept or because the act was not recorded there. Matched and probable rows are "
              "in the table below.")
        + _table(("When (UTC)", "Action", "Detail", ""), rows))


# ------------------------------------------------------- smaller tables ---

def _as_person_table(hits):
    if not hits:
        return ""
    rows = "".join(
        '<tr><td class="t">%s</td><td><code>%s</code></td><td>%s s</td></tr>' % (
            _when_short(h["ingested"]), _tool(h["ingested"]), _e(h["gap_seconds"]))
        for h in hits)
    return (_h2("Recorded against the person")
            + _table(("When (UTC)", "Action", "Agent active within"), rows)
            + _note("The platform attributes these to the person. The agent's own record shows "
                    "it was driving the person's browser on the same site within minutes. A "
                    "likelihood from timing, not proof; sign-ins and two-factor prompts are "
                    "never counted."))


def _shared_table(hits, agent=None, label=None, broken_sessions=()):
    """The sessions used from more than one address. The section is left off
    when every one of them is part of a broken rule (the What broke paragraph
    already names the second address); it stays when a shared session is not
    a finding, with the "worth a look" aside dropped if any other one is. The
    Client cell names the agent by its label when the session is the agent's."""
    broken = set(broken_sessions)
    if not hits or all(h["session"] in broken for h in hits):
        return ""
    rows = []
    for h in hits:
        client = ("<td>%s</td>" % _e(label)) if (label and h["agent"] == agent) else \
            "<td><code>%s</code></td>" % _e(h["agent"])
        rows.append('<tr><td class="t">%s</td><td><code>%s</code></td>%s<td>%s</td><td>%d</td></tr>' % (
            _e((h.get("first_ts") or "")[:16].replace("T", " ")), _e(h["session"]),
            client, _e(", ".join(h["ips"])), h["rows"]))
    note = ("A session the platform issued at one sign-in, later used from a different "
            "address. The log cannot tell a proxy change from a copied or shared session; "
            "it shows that one sign-in was used from two places.")
    if not any(h["session"] in broken for h in hits):
        note += " Worth a look, not a finding."
    return (_h2("One session, more than one address")
            + _table(("Signed in (UTC)", "Session", "Client", "Addresses",
                      "Rows from the other address"), "".join(rows))
            + _note(note))


def _unusual_table(unusual):
    if not unusual:
        return ""
    rows = "".join(
        '<tr><td class="t">%s</td><td><code>%s</code></td><td>%s</td></tr>' % (
            _e((u.get("ts") or "")[:16].replace("T", " ")), _e(u.get("action")),
            _e(device_family(u.get("user_agent"))))
        for u in unusual)
    return (_h2("Unusual devices in the account")
            + _table(("When (UTC)", "Action", "Device"), rows)
            + _note("A device type seen only once or twice in the whole export. Not necessarily "
                    "the agent; worth a look."))


def _cannot_section(short, items, routine):
    """Three lines in view, the full list under a fold."""
    body = '<ul class="cannot">%s</ul>' % "".join("<li>%s</li>" % _e(x) for x in short)
    if routine:
        body += _note("%d automatic token refreshes by this agent are sealed in the chain but "
                      "not listed." % len(routine))
    body += _section("All limits of this source",
                     '<ul class="cannot">%s</ul>' % "".join("<li>%s</li>" % _e(x) for x in items))
    return _h2("What this export can't show") + body


# ---------------------------------------------------------- what broke ---

def _stamp(ts):
    """``Oct 8, 2026 23:12 UTC`` for a record timestamp, or "" when unreadable."""
    dt = _view.ts_utc(ts)
    if dt is None:
        return ""
    return "%s %02d:%02d UTC" % (_view.day_label(dt, True), dt.hour, dt.minute)


def _short_entry(entry):
    """``PFFSC.AccountSearchController.search`` reads ``AccountSearchController.search``:
    a namespace prefix is dropped when the entry point has three or more parts."""
    parts = str(entry or "").split(".")
    return ".".join(parts[1:]) if len(parts) >= 3 else str(entry or "")


def _counted(names):
    """``Query Records ×2, Get Record Details ×1`` from an ordered count."""
    return ", ".join("%s ×%d" % (n, c) for n, c in names)


def _ordered_counts(values):
    counts, order = {}, []
    for v in values:
        if not v:
            continue
        if v not in counts:
            order.append(v)
        counts[v] = counts.get(v, 0) + 1
    return [(v, counts[v]) for v in order]


def _is_login(rec):
    return str((rec.get("action") or {}).get("tool") or "").startswith("salesforce:Login.")


def session_activity(key, agent, context):
    """What the agent's rows on session ``key`` did, from the event index:
    ``{"rows": n, "actions": [(name, count)], "entries": [entry point]}``.
    Rows are the agent's non-sign-in events on the session key; the action
    names are the agent actions of the bot sessions those rows belong to
    (an InvocableAction row names the action but carries no session key),
    else the rows' own actions in words; the entry points are the Apex
    entry points the session ran."""
    rows = [e for e in context.values()
            if e.get("token_id") == key and e.get("event_type") != "Login" and agent_key(e) == agent]
    bot_sessions = {e.get("bot_session") for e in rows if e.get("bot_session")}
    names = _ordered_counts(
        e.get("repo") for e in sorted(context.values(), key=lambda e: e.get("ts") or "")
        if e.get("bot_session") in bot_sessions and str(e.get("action") or "").startswith("Agent.")
        and agent_key(e) == agent)
    if not names:
        names = _ordered_counts(_view.action_name("salesforce:%s" % e.get("action"))
                                for e in sorted(rows, key=lambda e: e.get("ts") or ""))
    entries = []
    for e in sorted(rows, key=lambda e: e.get("ts") or ""):
        if e.get("event_type") == "ApexExecution" and e.get("target"):
            short = _short_entry(e["target"])
            if short not in entries:
                entries.append(short)
    return {"rows": len(rows), "actions": names, "entries": entries}


def broken_paragraphs(verdict, records, *, agent, label=None, context=None, shared=()):
    """One paragraph per broken rule, built from the violating records and
    the event index: the rule's name; when (first and last when more than
    one); who (the credential, or the agent's own service user with its
    masked id); from where, when the row carried an address; for a sign-in
    rule, what the session then did and whether the same session appears in
    the shared-session table. Returns ``[(rule_label, text)]`` and the set of
    session keys the broken rules touched."""
    context = context or {}
    by_id = {r.get("record_id"): r for r in records}
    shared_by_key = {h["session"]: h for h in shared}
    out, sessions = [], set()
    for rule in verdict.get("rules", []):
        if rule.get("status") != "violated":
            continue
        vs = sorted((by_id[i] for i in rule.get("violators", []) if i in by_id),
                    key=lambda r: r.get("ts") or "")
        if not vs:
            continue
        parts = []
        first, last = _stamp(vs[0].get("ts")), _stamp(vs[-1].get("ts"))
        if len(vs) == 1:
            parts.append(first + ".")
        else:
            parts.append("%s, first %s, last %s." % (_plural(len(vs), "action"), first, last))
        cred = _credential(vs[0])
        who = label if (label and cred == agent) else cred
        if cred.startswith("app:bot:"):
            ids = sorted({str((r.get("principal") or {}).get("human_id") or "") for r in vs} - {""})
            who = "%s's own service user%s" % (who, (" (%s)" % ", ".join(ids)) if ids else "")
        evs = [context.get(r.get("record_id")) or {} for r in vs]
        ips = []
        for e in evs:
            ip = e.get("ip")
            if ip and ip != PLATFORM_IP and ip not in ips:
                ips.append(ip)
        browsers = sorted({e.get("user_agent") for e in evs if e.get("user_agent")})
        where = ""
        if ips:
            where = " from %s" % ", ".join(ips)
            if browsers:
                where += " (%s)" % ", ".join(browsers)
        login = all(_is_login(r) for r in vs)
        if login:
            parts.append("%s signed in%s." % (who, where))
            keys = []
            for e in evs:
                if e.get("token_id") and e["token_id"] not in keys:
                    keys.append(e["token_id"])
            for key in keys:
                sessions.add(key)
                act = session_activity(key, agent, context)
                if act["rows"]:
                    text = "In that session it ran %s" % _plural(act["rows"], "action")
                    if act["actions"]:
                        text += ": " + _counted(act["actions"])
                    if act["entries"]:
                        text += " — " + ", ".join(act["entries"])
                    parts.append(text + ".")
                else:
                    parts.append("No other row in this export shares that session.")
                h = shared_by_key.get(key)
                if h:
                    others = [ip for ip in h["ips"] if ip != h.get("first_ip")]
                    if others:
                        parts.append("The same session was later used from %s." % ", ".join(others))
        else:
            names = _ordered_counts(_view.action_name((r.get("action") or {}).get("tool")) for r in vs)
            targets = []
            for r in vs:
                t = (r.get("data") or {}).get("target") if isinstance(r.get("data"), dict) else None
                if t and t not in targets:
                    targets.append(str(t))
            text = "%s ran %s" % (who, _counted(names))
            if targets:
                text += " — " + ", ".join(targets)
            parts.append(text + where + ".")
            for e in evs:
                if e.get("token_id"):
                    sessions.add(e["token_id"])
        out.append((rule_label(rule), " ".join(parts)))
    return out, sessions


def _broken_section(paragraphs):
    if not paragraphs:
        return ""
    body = "".join('<p class="broke"><b>%s.</b> %s</p>' % (_e(name), _e(text)) for name, text in paragraphs)
    return (_h2("What broke") + body
            + _note("Rules are the account owner's; edit the list to match what this agent is permitted."))


# ----------------------------------------------------------- the page ---

_VOCAB = {
    "github": {"platform": "GitHub", "tenant": "this account",
               "source": "GitHub security log export",
               "sample": "SAMPLE — synthetic export; no real account data."},
    "salesforce": {"platform": "Salesforce", "tenant": "this org",
                   "source": "Salesforce event log export",
                   "sample": "SAMPLE — synthetic export shaped from public sources; no real org data."},
}


def agent_label(key):
    """How the heading names the agent: an app or declared agent by its name
    (a lowercase declared name such as ``claude-code`` reads "Claude Code"),
    anything else by its full key."""
    kind, _, name = str(key).partition(":")
    if kind == "agent" and name:
        if name.islower():
            return " ".join(w[:1].upper() + w[1:] for w in re.split(r"[-_]+", name) if w)
        return name
    if kind == "app" and name:
        return name
    return str(key)


def bot_sessions(records):
    """The distinct Agentforce sessions the records carry (``data.bot_session``)."""
    return {str(r["data"]["bot_session"]) for r in records
            if isinstance(r.get("data"), dict) and r["data"].get("bot_session")}


def sign_ins(records, context=None):
    """``(platform, browser)``: how many of the agent's sign-in rows came
    through the platform (the literal "Salesforce.com IP" address, or an API
    sign-in type) and how many from a browser or any other address. Without
    an event index the sealed summary decides: an "API" sign-in is the
    platform's, anything else a browser's."""
    context = context or {}
    platform = browser = 0
    for r in records:
        if not _is_login(r):
            continue
        e = context.get(r.get("record_id"))
        if e is not None:
            via_platform = e.get("ip") == PLATFORM_IP or bool(e.get("access"))
        else:
            summary = str(((r.get("action") or {}).get("input") or {}).get("summary") or "")
            via_platform = " · API " in summary or summary.startswith("API ")
        if via_platform:
            platform += 1
        else:
            browser += 1
    return platform, browser


def _count_words(n):
    """``two`` for small counts in running text, the digits above nine."""
    words = ("zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine")
    return words[n] if 0 <= n < len(words) else _n(n)


def summary_lines(records, matches, verdict, *, agent, tenant, own_supplied=True,
                  as_person=(), routine=(), label=None, source="github", context=None,
                  tenant_named=True):
    """The plain lines at the top of the door page, in order, each a short
    sentence: what the agent did (how many actions, over how many days or
    sessions; the period and the org already sit in the header); rules
    broken, by the names the Rules row uses; the credentials or identity it
    acted through; calls outside the org (omitted when none); actions the
    platform recorded against the person (omitted when none); and what the
    agent's own record does not account for, or that no vendor record was
    supplied. ``label`` stands in for the agent's key wherever it would
    print; without one the heading's name is used. Returns ``(text,
    css_class)`` pairs.

    An Agentforce agent acting through one identity has its sign-ins counted
    in the identity line; the reach line names the one host when there is
    one; and without a vendor record the last line names the agent's own
    session trace as the record not yet compared against."""
    violated = [r for r in verdict.get("rules", []) if r["status"] == "violated"]
    used = credentials(list(records) + list(routine))
    unmatched = sum(1 for m in matches if m["tier"] == "unmatched")
    name = label or agent_label(agent)
    sf = source == "salesforce"
    bot = str(agent).startswith("app:bot:")
    if sf:
        first = "%s ran %s" % (name, _plural(len(records), "logged action"))
        sessions = bot_sessions(records)
        if sessions:
            first += " across %s" % _plural(len(sessions), "session")
    else:
        times = sorted(t for t in (_view.ts_utc(r.get("ts")) for r in records) if t is not None)
        days = ((times[-1].date() - times[0].date()).days + 1) if times else 0
        first = "%s acted %s" % (name, _plural(len(records), "time"))
        if days == 1:
            first += " in one day"
        elif days:
            first += " over %s" % _plural(days, "day")
    lines = [(first + ".", "")]
    if violated:
        lines.append(("%s broken: %s." % (_plural(len(violated), "rule"),
                                          ", ".join(rule_label(r) for r in violated)), "bad"))
    else:
        lines.append(("No rules broken.", "ok"))
    if sf and bot and len(used) == 1:
        platform, browser = sign_ins(records, context)
        if platform or browser:
            lines.append(("One identity: its own service user (%s platform sign-in%s, %s browser)." % (
                _n(platform), "" if platform == 1 else "s", _n(browser)), ""))
        else:
            lines.append(("One identity: its own service user (no sign-ins in this export).", ""))
    elif len(used) == 1:
        cred = next(iter(used))
        lines.append(("One credential: %s." % (name if (label and cred == agent) else cred), ""))
    else:
        tokens = sum(1 for c in used if c.startswith("token:"))
        if tokens == 1:
            kinds = ", one of them a personal access token"
        elif tokens:
            kinds = ", %s of them personal access tokens" % _count_words(tokens)
        else:
            kinds = ""
        lines.append(("%s%s." % (_plural(len(used), "credential"), kinds), ""))
    reach = callouts(records)
    if reach["count"]:
        failed = sum(h["failed"] for h in reach["hosts"].values())
        hosts = reach["hosts"]
        where = next(iter(hosts)) if len(hosts) == 1 else _plural(len(hosts), "host")
        lines.append(("%s to %s%s." % (_plural(reach["count"], "call"), where,
                                       (", %s failed" % _n(failed)) if failed else ""), ""))
    if as_person:
        lines.append(("%s recorded against the person." % _plural(len(as_person), "action"), "warn"))
    if own_supplied:
        if unmatched:
            lines.append(("%s of %s not in the agent's own record." % (_n(unmatched), _n(len(records))),
                          "warn"))
        else:
            lines.append(("All %s are in the agent's own record." % _n(len(records)), "ok"))
    elif sf and bot:
        lines.append(("Not yet compared to %s's own session trace." % name, ""))
    else:
        lines.append(("No vendor record supplied; this page shows the platform's log only.", ""))
    return lines


def render_page(records, matches, verdict, *, agent, title=None, unusual=(),
                as_person=(), expected_credentials=None, routine=(),
                source_actions=None, own_supplied=True, sample=False, anchored=None,
                source="github", shared=(), allowlist=None, chain=None, tenant=None,
                prepared=None, chain_file=None, label=None, events=None, sample_note=None,
                dropped=None):
    """The door page, rendered through the Runtime Report in door mode: a
    header naming the agent in the buyer's platform, the five-line summary,
    what broke (one paragraph per broken rule, when any), the agent's actions
    per week, the rules checked, the credentials it signed in through (unless
    the sentence already carries the one identity), the comparison against
    its own record (when one was supplied), the door's smaller tables, three
    lines on what the export cannot show (the full list under a fold), the
    agent's rows in the records table, and the in-browser re-hash of the
    whole chain as the badge near the bottom: one verdict line, one line on
    the witness, and the custody paragraph, the ``halo verify`` command and
    the allowlist aside under "How to check this yourself". The footer
    carries the agent's key. Every value that came from the export is
    escaped.

    ``chain`` is the whole sealed chain the export produced; the page embeds
    and verifies all of it and displays ``records`` (the one agent's rows).
    Without it, ``records`` is embedded as the chain, which verifies in the
    browser only when it is the whole chain. ``routine`` rows are sealed in
    the chain but not listed. ``own_supplied=False`` states that no vendor
    record was supplied and drops the comparison. ``sample`` adds a banner,
    and ``sample_note`` one owner-supplied clause to it. ``anchored`` is the
    anchor receipt to cite, or None for none. ``tenant`` names the account or
    org; ``prepared`` is the date label in the header (today, by the
    preparer's clock, by default); ``chain_file`` is named in the page's
    ``halo verify`` line; ``label`` is a display name for the agent, used in
    the heading, the summary and the credential bar in place of its key
    (the footer then shows the key). ``events`` is the event index
    (``event_index``) the What broke paragraphs and the sign-in count read
    addresses and session keys from; the chain itself carries neither.
    ``dropped`` ({reason: rows}) names the rows of the export the reader
    could not seal, under what the export cannot show."""
    from . import report as _report
    voc = _VOCAB.get(source, _VOCAB["github"])
    records = list(records)
    routine = list(routine)
    chain = list(chain) if chain is not None else records
    context = events or {}
    violated = [r for r in verdict.get("rules", []) if r["status"] == "violated"]
    bad_ids = {rid for r in violated for rid in r["violators"]}
    named = tenant or next((str((r.get("subject") or {}).get("id")) for r in records
                            if isinstance(r.get("subject"), dict) and (r.get("subject") or {}).get("id")),
                           None)
    tenant = named or voc["tenant"]
    if prepared is None:
        prepared = _view.day_label(datetime.now(), True)   # the preparer's own date

    lines = summary_lines(records, matches, verdict, agent=agent, tenant=tenant,
                          own_supplied=own_supplied, as_person=as_person, routine=routine,
                          label=label, source=source, context=context, tenant_named=bool(named))
    # Text content, not attributes: only <, > and & need escaping, so the
    # lines keep their apostrophes.
    summary = ['<li><span class="n">%d</span><span%s>%s</span></li>' % (
        i, (' class="%s"' % cls) if cls else "", html.escape(text, quote=False))
        for i, (text, cls) in enumerate(lines, 1)]

    source_note = ("Source: the buyer's own %s export, sealed on ingest. The export is as complete "
                   "as what the platform logged; sealing proves this copy has not been edited "
                   "since. Sealing proves integrity, not the completeness of the export; one "
                   "week of records is a baseline, and what changed since the prior period "
                   "appears from the second week on." % voc["platform"])
    reached = bool(callouts(records)["count"])

    paragraphs, broken_sessions = broken_paragraphs(verdict, records + routine, agent=agent, label=label,
                                                    context=context, shared=shared)
    # One identity folds the credential bars into the summary sentence, unless
    # the owner named the credentials it issued and this one is not among them.
    one_identity = (source == "salesforce" and len(credentials(records + routine)) == 1
                    and not (expected_credentials
                             and unexpected_credentials(records + routine, expected_credentials)))

    if source == "salesforce":
        short = list(SALESFORCE_CANNOT_SHOW_SHORT)
        cannot = list(AGENTFORCE_CANNOT_SHOW) + list(SALESFORCE_CANNOT_SHOW)
        aside = (_note("Address allowlist behind <code>login-outside-allowlist</code>: "
                       "<code>%s</code>%s" % (
                           _e(", ".join(allowlist)),
                           " (the sample's range; pass <code>--allow-ip</code> for yours)"
                           if sample else ""), escape=False)
                 if allowlist else
                 _note("No address allowlist was supplied, so "
                       "<code>login-outside-allowlist</code> had nothing to check.", escape=False))
    else:
        actions = (source_actions if source_actions is not None else
                   [(r.get("action") or {}).get("tool") for r in records + routine])
        gone, gone_short = missing_sentence(actions), missing_short(actions)
        outside = "Anything outside %s." % voc["platform"]
        short = ([gone_short] if gone_short else []) + [READS_SHORT, outside]
        cannot = ([gone] if gone else []) + [READS_NOTE, outside]
        aside = ""
    if reached:
        cannot.append(CALLOUT_CANNOT_SHOW)
    if dropped and sum(dropped.values()):
        line = dropped_sentence(dropped)
        short.append(line)
        cannot.append(line)

    sections = "".join(x for x in (
        _broken_section(paragraphs),
        _chart_section(records, bad_ids),
        _rules_row(verdict, ""),
        "" if one_identity else _creds_bars(records + routine, expected_credentials, agent, label),
        _reach_bars(records) if source == "salesforce" else "",
        _split_bar(matches) if own_supplied else "",
        _as_person_table(as_person),
        _shared_table(shared, agent, label, broken_sessions),
        _unusual_table(unusual),
        _cannot_section(short, cannot, routine),
    ) if x)

    receipt = (_e(anchored) if anchored else
               "none at the time this page was rendered"
               + (" (a sample is never anchored)" if sample else
                  "; <code>halo anchor</code> records the head with a witness"))
    stands = ("<b>Where this copy stands.</b> The sealed copy's integrity holds relative to a "
              "head someone other than the operator holds; a head only the operator keeps can "
              "be re-sealed without a trace. Anchor receipt: %s. Keep the chain file in storage "
              "you control; the witness keeps the head." % receipt)
    witness = ("An outside witness holds a checkpoint (%s): this proves nothing was edited, not "
               "that nothing was removed." % _e(anchored) if anchored else
               "No outside witness holds a checkpoint yet: this proves nothing was edited, not "
               "that nothing was removed.")

    banner = ""
    if sample:
        text = voc["sample"]
        note = str(sample_note or "").strip().rstrip(".")
        if note:
            text = text.rstrip(".") + "; " + note + "."
        banner = '<div class="banner">%s</div>\n' % _e(text)

    page = _report.render(chain, door={
        "agent": agent,
        "title": title or "%s in %s's %s" % (label or agent_label(agent), tenant, voc["platform"]),
        "label": label or "",
        "prepared": prepared, "source_label": voc["source"], "chain_file": chain_file,
        "hidden": [r.get("record_id") for r in routine if r.get("record_id")],
        "banner": banner,
        "summary": summary, "sections": sections,
        "every": _unmatched_fold(matches, bad_ids) if own_supplied else "",
        "source_note": source_note, "stands": stands, "witness": witness, "aside": aside,
    })
    return _report._LONE_SURROGATE_RE.sub("�", page)
