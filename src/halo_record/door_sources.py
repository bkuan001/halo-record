"""Platform log exports the door can read beyond GitHub.

Salesforce Event Monitoring writes one EventLogFile per event type per
interval; each downloads as a CSV whose first column is ``EVENT_TYPE``. This
module reads Login, RestApi, ApexExecution, URI (and ReportExport when
present), plus the two types an Agentforce agent leaves behind,
InvocableAction (one row per agent action) and ApexCallout (what the org
reached outside itself), into the same normalized event shape
``door.parse_github_log`` produces, so ingest, isolate, rules and the page
work unchanged:

    ts, action, actor, repo (the target), access, app, token_id, user_agent

plus, for this source: ``ip``, ``event_type``, ``user_id``, ``login_type``,
``target`` (what the row acted on: an entry point, a URI, a URL, a report),
``status`` (the row's own status: a login status, an HTTP status code, a
request status), ``bot_session`` (BOT_SESSION_IDENTIFIER, one Agentforce
conversation), ``detail`` (the one-line summary that is sealed) and
``raw_hash`` (SHA-256 of the whole CSV row, sealed in place of the row itself;
session keys, query text and addresses are never written to the chain).

Attribution: ``CLIENT_NAME`` (or ``CONNECTED_APP_ID``) names the connected
app; ``BOT_IDENTIFIER`` (on InvocableAction, ApexExecution and ApexCallout
rows) names an Agentforce bot (``app:bot:<id>``) and outranks the session;
rows that name no client but share a ``LOGIN_KEY`` with rows that do are
attributed to that app, because one sign-in is one session. A bot never
inherits a person's sign-in that way; the one sign-in attributed to a bot is
one whose session did nothing but that bot's work (its own service user).
``USER_ID`` is resolved to ``USER_NAME`` through whichever file carries both.

Pure stdlib.
"""

import csv
import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime, timezone

SALESFORCE_SOURCE = {"adapter": "salesforce_eventlog",
                     "via": "Salesforce Event Monitoring EventLogFile export",
                     "capture": "ingested"}

# The sample fixture's address range (TEST-NET-1). A real org passes its own
# with ``halo door --allow-ip CIDR``.
DEFAULT_ALLOWLIST = ("192.0.2.0/24",)

# The synthetic exports shipped in the package: one connected app's week in
# an org (``salesforce_eventlog``) and an Agentforce agent's (``salesforce_agentforce``).
# Placeholder names, TEST-NET addresses, SAMPLE-marked ids.
SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")

KNOWN_TYPES = {"login": "Login", "restapi": "RestApi", "apexexecution": "ApexExecution",
               "uri": "URI", "reportexport": "ReportExport",
               "invocableaction": "InvocableAction", "apexcallout": "ApexCallout"}

# Event Monitoring writes this literal, not an address, for traffic that
# begins inside Salesforce (an Agentforce runtime sign-in, a scheduled job).
PLATFORM_IP = "Salesforce.com IP"

_LOGIN_AS = re.compile(r"login\s*_?\s*as", re.I)
_BULK = ((re.compile(r"/jobs/query\b", re.I), "BulkApi.query"),
         (re.compile(r"/jobs/ingest\b", re.I), "BulkApi.ingest"),
         (re.compile(r"/services/async/", re.I), "BulkApi.{method}"))
_METADATA_URI = re.compile(r"/tooling/|/services/Soap/m/|/metadata\b", re.I)
_EXPORT_URI = re.compile(r"[?&]export=1\b|[?&]xf=(csv|xls)|PrintableViewDownloadServlet", re.I)
_SETUP_URI = re.compile(r"/setup/|/_ui/common/config|/services/Soap/m/", re.I)


class EventList(list):
    """The parsed events (oldest first) plus what the reader set aside:
    ``skipped`` ({EVENT_TYPE: rows} for types it does not read), ``dropped``
    ({reason: rows} for rows of a known type it could not seal: an
    unreadable timestamp, fewer columns than the header), ``files`` (the
    CSVs read) and ``sample`` (True when the input is one of the bundled
    synthetic exports under ``SAMPLES_DIR``)."""
    skipped = None
    dropped = None
    files = None
    sample = False


UNREADABLE_TIME = "unreadable timestamp"
SHORT_ROW = "fewer columns than the header"


def _iso(value):
    """TIMESTAMP_DERIVED is ISO 8601 with a Z; TIMESTAMP is yyyyMMddHHmmss.SSS.
    Returns RFC 3339 UTC or None."""
    text = (value or "").strip()
    if not text:
        return None
    if re.fullmatch(r"\d{14}(\.\d+)?", text):
        text = "%s-%s-%sT%s:%s:%s+00:00" % (text[0:4], text[4:6], text[6:8], text[8:10],
                                             text[10:12], text[12:14])
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _slug(text):
    return re.sub(r"[^A-Za-z0-9]+", "_", text or "").strip("_")


def _row_hash(row):
    return "sha256:" + hashlib.sha256(
        json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _get(row, *names):
    for n in names:
        v = row.get(n)
        if v is not None and str(v).strip():
            return str(v).strip()
    return None


def _normalize(row, event_type, allowlist=None):
    base = {
        "adapter": SALESFORCE_SOURCE["adapter"],
        "event_type": event_type,
        "ts": _iso(_get(row, "TIMESTAMP_DERIVED", "TIMESTAMP")),
        "user_id": _get(row, "USER_ID"),
        "actor": _get(row, "USER_NAME"),
        "token_id": _get(row, "LOGIN_KEY", "SESSION_KEY"),
        "ip": _get(row, "SOURCE_IP", "CLIENT_IP"),
        "app": None, "access": None, "user_agent": None, "login_type": None,
        "target": None, "status": None, "bot_session": None,
        "raw_hash": _row_hash(row),
    }
    if event_type == "Login":
        login_type = _get(row, "LOGIN_TYPE") or ""
        base["login_type"] = login_type
        # Classified in this order: a Login As names who entered the session
        # (identity before location); then, when an allowlist was given, a
        # sign-in from outside it; else the sign-in type as the platform wrote it.
        outside = (allowlist and base["ip"] and base["ip"] != PLATFORM_IP
                   and ip_allowed(base["ip"], allowlist) is False)
        if _LOGIN_AS.search(login_type):
            base["action"] = "Login.Login_As"
        elif outside:
            base["action"] = "Login.outside_allowlist"
        else:
            base["action"] = "Login.%s" % (_slug(login_type) or "unknown")
        base["repo"] = _get(row, "LOGIN_STATUS")
        base["status"] = base["repo"]
        base["access"] = _get(row, "API_TYPE")
        base["user_agent"] = _get(row, "BROWSER_TYPE")
        base["detail"] = " · ".join(x for x in (
            login_type or None, base["repo"], base["access"] and "API " + base["access"],
            "outside allowlist" if outside else None) if x)
    elif event_type == "RestApi":
        method = (_get(row, "METHOD") or "CALL").upper()
        # The URI classifies the row whole; what is kept is its path alone.
        # A query string (a filter, a key, a record id) never enters the chain.
        full = _get(row, "URI") or ""
        uri = full.split("?", 1)[0]
        action = "RestApi.%s" % method
        for pat, name in _BULK:
            if pat.search(full):
                action = name.format(method=method)
                break
        else:
            if _METADATA_URI.search(full):
                action = "Metadata.%s" % method
        base["action"] = action
        base["app"] = _get(row, "CLIENT_NAME", "CONNECTED_APP_ID")
        base["repo"] = _get(row, "ENTITY_NAME") or uri or None
        base["target"] = uri or base["repo"]
        base["status"] = _get(row, "STATUS_CODE")
        base["access"] = "REST"
        base["user_agent"] = _get(row, "USER_AGENT")
        rows = _get(row, "ROWS_PROCESSED")
        base["detail"] = " · ".join(x for x in (
            "%s %s" % (method, uri) if uri else method, _get(row, "ENTITY_NAME"),
            ("rows %s" % rows) if rows else None, _get(row, "STATUS_CODE")) if x)
    elif event_type == "ApexExecution":
        entry = _get(row, "ENTRY_POINT") or ""
        head = re.split(r"[./]", entry, 1)[0] if entry else ""
        base["action"] = "ApexExecution.Metadata" if "metadata" in entry.lower() else \
            "ApexExecution.%s" % (_slug(head) or "unknown")
        bot = _get(row, "BOT_IDENTIFIER")
        base["app"] = "bot:%s" % bot if bot else None
        base["bot_session"] = _get(row, "BOT_SESSION_IDENTIFIER")
        base["repo"] = entry or None
        base["target"] = entry or None
        base["access"] = None   # a person's click runs Apex too: attribute by bot or session only
        soql = _get(row, "NUMBER_SOQL_QUERIES")
        base["detail"] = " · ".join(x for x in (
            entry or None, ("quiddity %s" % _get(row, "QUIDDITY")) if _get(row, "QUIDDITY") else None,
            ("%s SOQL" % soql) if soql else None, ("bot %s" % bot) if bot else None) if x)
    elif event_type == "URI":
        full = _get(row, "URI") or ""
        uri = full.split("?", 1)[0]   # the query string is dropped before anything is kept
        if _EXPORT_URI.search(full):
            base["action"] = "URI.ReportExport"
        elif _SETUP_URI.search(full):
            base["action"] = "URI.Setup"
        else:
            base["action"] = "URI.page"
        base["repo"] = uri or None
        base["target"] = uri or None
        status = _get(row, "REQUEST_STATUS")
        base["status"] = status
        base["detail"] = " · ".join(x for x in (uri or None, status) if x)
    elif event_type == "ReportExport":
        base["action"] = "ReportExport.export"
        base["repo"] = _get(row, "REPORT_ID")
        base["target"] = base["repo"]
        base["detail"] = " · ".join(x for x in ("report export", base["repo"]) if x)
    elif event_type == "InvocableAction":
        # One row per action call. INVOCATION_SOURCE says who asked: an agent
        # (Agent Action), a prompt template, a flow, Apex, REST. The row names
        # the bot but carries no session key, so attribution is by bot alone.
        name = _get(row, "ACTION_NAME") or _get(row, "AGENT_ACTION") or "unknown"
        source = _get(row, "INVOCATION_SOURCE") or ""
        bot = _get(row, "BOT_IDENTIFIER")
        template = _get(row, "PROMPT_TEMPLATE")
        if source.lower() == "prompt template" or (template and not source):
            base["action"] = "Prompt.%s" % (_slug(template or name) or "unknown")
        elif source.lower() == "agent action" or bot:
            base["action"] = "Agent.%s" % (_slug(name) or "unknown")
        else:
            base["action"] = "InvocableAction.%s" % (_slug(name) or "unknown")
        base["app"] = "bot:%s" % bot if bot else None
        base["bot_session"] = _get(row, "BOT_SESSION_IDENTIFIER")
        base["repo"] = name
        # What the action ran: its Apex class, the prompt template, or the
        # kind of flow when the row names nothing more specific.
        base["target"] = (_get(row, "INVOKING_APEX_CLASS_NAME") or template
                          or _get(row, "FLOW_PROCESS_TYPE"))
        base["detail"] = " · ".join(x for x in (
            source or None, name, template and ("template %s" % template),
            _get(row, "INVOKING_APEX_CLASS_NAME"), _get(row, "FLOW_PROCESS_TYPE"),
            ("bot %s" % bot) if bot else None) if x)
    elif event_type == "ApexCallout":
        # An outbound call from the org: the one place the export shows the
        # agent reaching another system. The query string is dropped before
        # anything is kept; the row itself is sealed only as a hash.
        method = (_get(row, "METHOD") or "CALL").upper()
        url = (_get(row, "URL") or "").split("?", 1)[0]
        bot = _get(row, "BOT_IDENTIFIER")
        status = _get(row, "STATUS_CODE")
        base["action"] = "Callout.%s" % method
        base["app"] = "bot:%s" % bot if bot else None
        base["bot_session"] = _get(row, "BOT_SESSION_IDENTIFIER")
        base["repo"] = url or None
        base["target"] = url or None
        base["status"] = status
        base["detail"] = " · ".join(x for x in (
            "%s %s" % (method, url) if url else method, status,
            ("bot %s" % bot) if bot else None) if x)
    return base


def bundled_sample(name):
    """The path of a bundled sample export: ``salesforce_eventlog`` or
    ``salesforce_agentforce``."""
    return os.path.join(SAMPLES_DIR, name)


def is_bundled_sample(paths_or_dir):
    """True when any of the CSVs ``paths_or_dir`` names lies under the
    package's own samples. A directory of a real export is never a sample,
    whatever it is called; ``halo door --sample`` marks one explicitly."""
    root = os.path.realpath(SAMPLES_DIR) + os.sep
    try:
        files = _csv_paths(paths_or_dir)
    except OSError:
        return False
    return any(os.path.realpath(p).startswith(root) for p in files)


def _rows(path):
    """The rows of one EventLogFile CSV. A CSV without an ``EVENT_TYPE``
    column is refused; a file the csv module or the codec cannot read is
    named with the reader's own reason."""
    try:
        with open(path, encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames or "EVENT_TYPE" not in [f.strip() for f in reader.fieldnames]:
                raise ValueError("%s is not a Salesforce EventLogFile export "
                                 "(expected a CSV with an EVENT_TYPE column)" % path)
            for row in reader:
                yield row
    except (csv.Error, UnicodeDecodeError) as e:
        raise ValueError("%s: %s" % (path, e))


def _csv_paths(paths_or_dir):
    if isinstance(paths_or_dir, (str, os.PathLike)):
        paths_or_dir = [paths_or_dir]
    out = []
    for p in paths_or_dir:
        p = os.fspath(p)
        if os.path.isdir(p):
            out.extend(os.path.join(p, n) for n in sorted(os.listdir(p)) if n.lower().endswith(".csv"))
        else:
            out.append(p)
    return out


def parse_salesforce_eventlog(paths_or_dir, allowlist=None):
    """Read one or more EventLogFile CSVs (or a directory of them) into
    normalized events, oldest first. A CSV without an ``EVENT_TYPE`` column
    is refused rather than guessed at; rows of event types this reader does
    not use are skipped and counted in ``.skipped``. A row of a known type
    whose timestamp cannot be read, or that carries fewer columns than the
    header, is not sealed (never with a guessed time or a bare action): it is
    counted in ``.dropped`` by reason.

    ``allowlist`` (CIDRs the integration may sign in from) classifies each
    sign-in with an address: one from outside it becomes the action
    ``Login.outside_allowlist``, which the ``login-outside-allowlist`` rule
    names. With no allowlist, sign-ins are not classified and that rule is
    reported as not evaluated; ``halo door`` passes one only when given
    ``--allow-ip``, or the fixture's range for the bundled sample."""
    files = _csv_paths(paths_or_dir)
    if not files:
        raise ValueError("%s: no EventLogFile CSVs found" % paths_or_dir)
    rows, skipped, dropped = [], {}, {}
    for path in files:
        for row in _rows(path):
            # DictReader fills a column the row did not reach with None;
            # a column the row left blank is "".
            short = any(v is None for v in row.values())
            row = {(k or "").strip(): (v if v is not None else "") for k, v in row.items()}
            raw_type = (row.get("EVENT_TYPE") or "").strip()
            kind = KNOWN_TYPES.get(raw_type.replace("_", "").replace(" ", "").lower())
            if not kind:
                skipped[raw_type or "(blank)"] = skipped.get(raw_type or "(blank)", 0) + 1
                continue
            if short:
                dropped[SHORT_ROW] = dropped.get(SHORT_ROW, 0) + 1
                continue
            event = _normalize(row, kind, allowlist)
            if not event["ts"]:
                dropped[UNREADABLE_TIME] = dropped.get(UNREADABLE_TIME, 0) + 1
                continue
            rows.append(event)
    # Resolve people and sessions across files: USER_ID -> USER_NAME, and the
    # app a session belongs to from any row on it that names the app.
    users, sessions = {}, {}
    for e in rows:
        if e.get("user_id") and e.get("actor"):
            users.setdefault(e["user_id"], e["actor"])
        if e.get("token_id") and e.get("app") and not e["app"].startswith("bot:"):
            sessions.setdefault(e["token_id"], e["app"])
    for e in rows:
        if not e.get("actor") and e.get("user_id"):
            e["actor"] = users.get(e["user_id"], e["user_id"])
        if not e.get("app") and e.get("token_id") in sessions:
            e["app"] = sessions[e["token_id"]]
    # A bot never owns a person's session: an employee agent runs inside the
    # employee's sign-in, and that sign-in stays the person's. But a sign-in
    # whose session did nothing except one bot's work is the bot's own
    # service user signing in, however it signed in.
    bot_sessions = {}
    for e in rows:
        if e.get("token_id") and e.get("event_type") != "Login":
            seen = bot_sessions.setdefault(e["token_id"], set())
            seen.add(e.get("app") if (e.get("app") or "").startswith("bot:") else None)
    for e in rows:
        if e.get("event_type") == "Login" and not e.get("app"):
            seen = bot_sessions.get(e.get("token_id")) or set()
            if len(seen) == 1 and None not in seen:
                e["app"] = next(iter(seen))
    rows.sort(key=lambda e: e["ts"] or "")
    events = EventList(rows)
    events.skipped = skipped
    events.dropped = dropped
    events.files = files
    events.sample = is_bundled_sample(files)
    return events


def ip_allowed(ip, cidrs):
    """True when ``ip`` falls in one of ``cidrs``; False when it does not or is
    not an address; None when there is no address to check."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs or ():
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def shared_sessions(events):
    """Sessions (by LOGIN_KEY) seen from more than one address. The log
    cannot tell a proxy change from a copied or shared session; it can show
    that one sign-in was used from two places."""
    by_key = {}
    for e in sorted(events, key=lambda e: e.get("ts") or ""):
        if e.get("token_id") and e.get("ip"):
            by_key.setdefault(e["token_id"], []).append(e)
    from .door import agent_key  # local import: door imports this module
    out = []
    for key, evs in by_key.items():
        ips = sorted({e["ip"] for e in evs})
        if len(ips) < 2:
            continue
        first = evs[0]["ip"]
        agent = next((agent_key(e) for e in evs if agent_key(e)), None)
        out.append({"session": key, "ips": ips, "first_ip": first,
                    "agent": agent or "(the person, no programmatic client)",
                    "rows": sum(1 for e in evs if e["ip"] != first),
                    "first_ts": evs[0].get("ts"),
                    "actions": sorted({e["action"] for e in evs if e["ip"] != first})})
    out.sort(key=lambda h: h["first_ts"] or "")
    return out
