"""What the Runtime Report displays, as a function of its records.

Every part of the report page that is derived from the records — the heading,
the period the records span, the summary cards, the scopes, the provenance
panel, the activity table, and the policy verdict — is produced here twice:
once in Python (the page as generated, and what a reader sees without
JavaScript) and once in the page's own JavaScript (``RENDER_JS``), which
re-renders those parts in the browser from the records it has just verified.
The two implementations are kept byte-identical by a differential test
(tests/test_page_binding.py), so editing the generated HTML cannot put a
different table or verdict under the page's verification badge.

Keep the Python and JavaScript halves in step: change both, then run the
differential test.
"""

import html
import json
import re
import unicodedata
from datetime import datetime, timedelta, timezone


def esc(x):
    return html.escape(str(x), quote=True)


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #

_TS_RE = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,9}))?(Z|z|[+-][0-9]{2}:[0-9]{2})?\Z")


def ts_utc(ts):
    """An RFC 3339 timestamp as an aware UTC datetime, or None. A timestamp
    with no offset is read as UTC (as the export does)."""
    if not isinstance(ts, str):
        return None
    m = _TS_RE.match(ts)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    frac = (m.group(7) or "")[:6].ljust(6, "0")
    off = m.group(8)
    try:
        dt = datetime(y, mo, d, h, mi, s, int(frac), tzinfo=timezone.utc)
        if off and off not in ("Z", "z"):
            oh, om = int(off[1:3]), int(off[4:6])
            if oh > 23 or om > 59:
                return None
            delta = timedelta(hours=oh, minutes=om)
            dt = dt - delta if off[0] == "+" else dt + delta
    except (ValueError, OverflowError):
        return None
    return dt


def fmt_ts(ts):
    """Display form of a timestamp, converted to UTC: ``YYYY-MM-DD HH:MM:SS``.
    An unparseable value is shown as written (truncated), never relabeled."""
    dt = ts_utc(ts)
    if dt is None:
        return "".join(list((ts or "") if isinstance(ts, str) else "")[:19])
    return "%04d-%02d-%02d %02d:%02d:%02d" % (dt.year, dt.month, dt.day,
                                              dt.hour, dt.minute, dt.second)


# --------------------------------------------------------------------------- #
# Plain-language summary
# --------------------------------------------------------------------------- #

class _Fail(Exception):
    pass


_NUM_RE = re.compile(r"-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")


_WS = " \t\n\r\f"
_SIMPLE_ESC = {"\\": "\\", "'": "'", '"': '"', "a": "\a", "b": "\b", "f": "\f",
               "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\n": ""}


class _Lit:
    """A deliberately small reader for the Python-literal text the recorder
    writes as an input summary (``str(dict)``). It accepts dicts, lists,
    tuples, single- or double-quoted strings, numbers, True/False/None — and
    nothing else, so the page's JavaScript reader can match it exactly."""

    MAX_DEPTH = 64

    def __init__(self, text):
        self.s, self.i, self.depth = text, 0, 0

    def ws(self):
        while self.i < len(self.s) and self.s[self.i] in _WS:
            self.i += 1

    def value(self):
        self.depth += 1
        try:
            return self._value()
        finally:
            self.depth -= 1

    def _value(self):
        if self.depth > self.MAX_DEPTH:
            raise _Fail()
        self.ws()
        if self.i >= len(self.s):
            raise _Fail()
        c, start = self.s[self.i], self.i
        if c == "{":
            self.i += 1
            entries = []
            self.ws()
            if self.peek("}"):
                self.i += 1
                return ("dict", entries, start, self.i)
            while True:
                k = self.value()
                self.ws()
                self.expect(":")
                v = self.value()
                entries.append((k, v))
                self.ws()
                if self.peek(","):
                    self.i += 1
                    self.ws()
                    if self.peek("}"):
                        self.i += 1
                        break
                    continue
                self.expect("}")
                break
            return ("dict", entries, start, self.i)
        if c in "[(":
            close = "]" if c == "[" else ")"
            self.i += 1
            items, comma = [], False
            self.ws()
            if self.peek(close):
                self.i += 1
                return ("seq", items, start, self.i)
            while True:
                items.append(self.value())
                self.ws()
                if self.peek(","):
                    comma = True
                    self.i += 1
                    self.ws()
                    if self.peek(close):
                        self.i += 1
                        break
                    continue
                self.expect(close)
                break
            if c == "(" and not comma:
                inner = items[0]
                return (inner[0], inner[1], start, self.i)  # a parenthesized value
            return ("seq", items, start, self.i)
        if c in "'\"":
            return ("str", self.string(), start, self.i)
        m = _NUM_RE.match(self.s, self.i)
        if m and m.end() > self.i:
            self.i = m.end()
            if self.i < len(self.s) and (self.s[self.i].isalnum() or self.s[self.i] in "_."):
                raise _Fail()
            return ("num", float(m.group(0)) != 0, start, self.i)
        for word, truthy in (("True", True), ("False", False), ("None", False)):
            if self.s.startswith(word, self.i):
                end = self.i + len(word)
                if end < len(self.s) and (self.s[end].isalnum() or self.s[end] == "_"):
                    raise _Fail()
                self.i = end
                return ("const", truthy, start, end)
        raise _Fail()

    def peek(self, ch):
        return self.i < len(self.s) and self.s[self.i] == ch

    def expect(self, ch):
        if not self.peek(ch):
            raise _Fail()
        self.i += 1

    def string(self):
        q = self.s[self.i]
        self.i += 1
        if self.s.startswith(q * 2, self.i):
            raise _Fail()  # triple-quoted or adjacent: outside this reader
        out = []
        while True:
            if self.i >= len(self.s):
                raise _Fail()
            c = self.s[self.i]
            if c == q:
                self.i += 1
                break
            if c == "\n":
                raise _Fail()
            if c != "\\":
                out.append(c)
                self.i += 1
                continue
            if self.i + 1 >= len(self.s):
                raise _Fail()
            e = self.s[self.i + 1]
            self.i += 2
            if e in _SIMPLE_ESC:
                out.append(_SIMPLE_ESC[e])
            elif e in "01234567":
                j = self.i
                while j < len(self.s) and j < self.i + 2 and self.s[j] in "01234567":
                    j += 1
                out.append(chr(int(e + self.s[self.i:j], 8)))
                self.i = j
            elif e in "xuU":
                n = {"x": 2, "u": 4, "U": 8}[e]
                h = self.s[self.i:self.i + n]
                if len(h) != n or not all(ch in "0123456789abcdefABCDEF" for ch in h):
                    raise _Fail()
                cp = int(h, 16)
                if cp > 0x10FFFF:
                    raise _Fail()
                out.append(chr(cp))
                self.i += n
            elif e == "N":
                raise _Fail()
            else:
                out.append("\\" + e)
        self.ws()
        if self.peek("'") or self.peek('"'):
            raise _Fail()  # implicit concatenation: outside this reader
        return "".join(out)


def _read_dict(text):
    """The top-level dict in ``text`` as {key: node}, or None."""
    try:
        r = _Lit(text)
        node = r.value()
        r.ws()
        if r.i != len(text) or node[0] != "dict":
            return None
    except (_Fail, RecursionError):
        return None
    out = {}
    for k, v in node[1]:
        if k[0] == "str":
            out[k[1]] = v
    return out, text


def _node_text(node, text):
    """(text, truthy) for a value node: a string's value, or the source text of
    anything else."""
    kind, val, start, end = node
    if kind == "str":
        return val, bool(val)
    if kind in ("dict", "seq"):
        return text[start:end], bool(val)
    return text[start:end], bool(val)


PLAIN_VERB = {"tool_call": "Ran", "network": "Fetched", "read": "Read",
              "write": "Wrote", "agent_message": "Messaged"}
PLAIN_KEYS = ("command", "file_path", "url", "query", "description", "path",
              "pattern", "prompt", "to", "summary", "task_id")
_PY_WS = re.compile("[\t\n\x0b\x0c\r\x1c-\x1f \x85\xa0  -   "
                    "  　]+")


def _squash(s):
    return " ".join(p for p in _PY_WS.split(s) if p)


def _gate(r):
    """'Blocked by gate' / 'Denied' when the record says the action was stopped.
    A gate's "blocked" is its own report: when the outcome records the action
    as ok, both are shown and neither is preferred (LIMITS section 11)."""
    action = _dict(r.get("action"))
    auth = _dict(action.get("authorization"))
    ver = _dict(r.get("verification"))
    out = _dict(r.get("outcome"))
    if ver.get("status") == "blocked":
        if out.get("status") == "ok":
            return "Gate reported blocked; outcome recorded: ok"
        return "Blocked by gate"
    if auth.get("decision") == "denied" or out.get("status") == "denied":
        if out.get("status") == "ok":
            return "Decision recorded denied; outcome recorded: ok"
        return "Denied"
    return None


def plain(r):
    """One line a non-engineer can read: what this action was, in words.

    Describes the action (its arguments), not its result; an action the record
    shows as denied or blocked is never described as having run. A view of the
    record, never a replacement: the full summary and its hash stay on it."""
    action = _dict(r.get("action"))
    tool = _str(action.get("tool") or action.get("type") or "action")
    summary = _str(_dict(action.get("input")).get("summary") or "")
    detail = ""
    if summary.startswith("{") and len(summary) <= 4096:
        parsed = _read_dict(summary)
        if parsed is not None:
            d, text = parsed
            for key in PLAIN_KEYS:
                if key in d:
                    t, truthy = _node_text(d[key], text)
                    if truthy:
                        detail = t
                        break
            # No meaningful argument: name the tool rather than echo an
            # arbitrary value (the first value is often the tenant id).
        else:
            detail = summary
    else:
        detail = summary
    detail = _squash(detail)
    gate = _gate(r)
    if gate:
        sep = " \u2014 " if gate.endswith(": ok") else ": "
        return ("%s%s%s \u2014 %s" % (gate, sep, tool, detail)) if detail else ("%s%s%s" % (gate, sep, tool))
    if not detail:
        o = _dict(r.get("outcome")).get("summary")
        o = _squash(o) if isinstance(o, str) and not o.startswith("{") else ""
        return ("Ran %s — result: %s" % (tool, o)) if o else ("Ran %s" % tool)
    verb = PLAIN_VERB.get(action.get("type"), "Ran")
    if action.get("type") == "network" and not tool.lower().startswith(("http", "web", "fetch")):
        verb = "Ran"  # "Fetched" describes fetch-shaped tools only
    if tool in ("Write", "Edit", "NotebookEdit"):
        verb = "Edited" if tool == "Edit" else "Wrote file"
    elif tool in ("WebFetch", "WebSearch"):
        verb = "Searched the web for" if tool == "WebSearch" else "Fetched"
    elif tool == "Bash":
        verb = "Ran the shell command"
    elif tool == "Agent":
        verb = "Started a helper agent to"
    elif tool == "Read":
        verb = "Read the file"
    return ("%s %s" % (verb, detail)).strip()


# --------------------------------------------------------------------------- #
# Regions
# --------------------------------------------------------------------------- #

CAP_TITLE = {
    "captured": "Declared captured at the boundary — per this record's own source tag, "
                "the integration observed the call directly. The tag is set by the "
                "integration, not independently verified.",
    "ingested": "Ingested from telemetry the vendor already emits — the witness "
                "attests \"this is the stream you sent me\", not \"I watched it happen\".",
}


def _cut(s, n):
    return "".join(list(s)[:n])


def _str(x):
    if x is None:
        return ""
    if isinstance(x, bool):
        return "True" if x else "False"
    return x if isinstance(x, str) else json.dumps(x, separators=(",", ":"), ensure_ascii=False)


def _dict(x):
    return x if isinstance(x, dict) else {}


def _list(x):
    return x if isinstance(x, list) else []


def record_subject(r):
    s = r.get("subject")
    sid = (s.get("id") or None) if isinstance(s, dict) else None
    if sid is None or isinstance(sid, str):
        return sid
    return json.dumps(sid, sort_keys=True, separators=(",", ":"))


def subject_label(records):
    ids = {record_subject(r) for r in records} - {None}
    if len(ids) > 1:
        return "%d subjects" % len(ids)  # never label a mixed chain as one customer
    for r in records:
        s = r.get("subject")
        if isinstance(s, dict) and (s.get("name") or s.get("id")):
            return _str(s.get("name") or s.get("id"))
    return "Agent runtime"


def subject_id(records):
    for r in records:
        s = r.get("subject")
        if isinstance(s, dict) and s.get("id"):
            return s["id"]
    return None


def subject_note(records):
    sid = subject_id(records)
    if sid is None:
        return ""
    sid = _str(sid)
    odd = any(ord(c) > 126 or (unicodedata.category(c)[0] in ("C", "Z") and c != " ")
              for c in sid)
    if sid != sid.strip() or "  " in sid:
        odd = True
    if not odd and subject_label(records) == sid:
        return ""
    shown = json.dumps(sid)[1:-1]
    note = "Subject id: <span class=\"mono\">%s</span>" % esc(shown)
    if odd:
        note += " &mdash; contains invisible or non-ASCII characters; compare it to the id the witness holds."
    return '<div class="meta">%s</div>' % note


def agents(records):
    seen = []
    for r in records:
        a = _dict(r.get("agent"))
        label = a.get("name") or a.get("id")
        if label:
            label = _str(label)
            if label not in seen:
                seen.append(label)
    return seen


def agent_meta(names):
    if not names:
        return "Agent <b>unknown</b>"
    if len(names) == 1:
        return "Agent <b>%s</b>" % esc(names[0])
    shown = ", ".join("<b>%s</b>" % esc(a) for a in names[:4])
    more = " (+%d more)" % (len(names) - 4) if len(names) > 4 else ""
    return "%d agents: %s%s" % (len(names), shown, more)


def stats(records):
    tools, scopes, severities = {}, set(), {}
    times = []
    for r in records:
        action = _dict(r.get("action"))
        tool = _str(action.get("tool") or action.get("type") or "—")
        tools[tool] = tools.get(tool, 0) + 1
        scope = _dict(action.get("authorization")).get("scope")
        if scope:
            scopes.add(_str(scope))
        sev = _str(r.get("severity", "INFO"))
        severities[sev] = severities.get(sev, 0) + 1
        dt = ts_utc(r.get("ts"))
        if dt is not None:
            times.append((dt, r.get("ts")))
    times.sort(key=lambda t: t[0])
    return {
        "total": len(records),
        "tools": tools,
        "scopes": sorted(scopes),
        "severities": severities,
        "start": fmt_ts(times[0][1]) if times else "—",
        "end": fmt_ts(times[-1][1]) if times else "—",
    }


def provenance(records):
    buckets, order_seen = {}, []
    for r in records:
        s = r.get("source")
        if not isinstance(s, dict):
            continue
        a = _str(s.get("adapter") or "unknown")
        if a not in buckets:
            order_seen.append(a)
            buckets[a] = {"via": _str(s.get("via") or a),
                          "capture": _str(s.get("capture") or "ingested"), "n": 0}
        buckets[a]["n"] += 1
    if not buckets:
        return ""
    rank = {"captured": 0, "ingested": 1}
    items = sorted(((a, buckets[a]) for a in order_seen),
                   key=lambda kv: (rank.get(kv[1]["capture"], 2), -kv[1]["n"]))
    n_cap = sum(b["n"] for b in buckets.values() if b["capture"] == "captured")
    n_ing = sum(b["n"] for b in buckets.values() if b["capture"] == "ingested")
    cells = []
    for _, b in items:
        tier = "cap" if b["capture"] == "captured" else "ing"
        label = "Captured" if b["capture"] == "captured" else "Ingested"
        cells.append(
            '<div class="prov" title="%s"><span class="pill %s">%s</span>'
            '<span class="prov-via">%s</span><span class="prov-n">%d action%s</span></div>'
            % (esc(CAP_TITLE.get(b["capture"], "")), tier, label, esc(b["via"]), b["n"],
               "" if b["n"] == 1 else "s"))
    if n_ing and n_cap:
        note = ("Each action is tagged with how it was observed. "
                "<b>Captured</b> means the record's source tag declares the integration observed "
                "the call at the boundary as it happened — the tag comes from the integration "
                "that wrote the record. <b>Ingested</b> means the record was built "
                "from telemetry the vendor already emits (a gateway, tracing store, or OTel span) — "
                "real and anchorable, but the witness attests “this is the stream you sent me,” "
                "not “I watched it happen.” The tier is disclosed, never flattened.")
    elif n_ing:
        note = ("These records were <b>ingested</b> from telemetry the vendor already emits — "
                "real and anchorable, but the witness attests “this is the stream you sent me,” "
                "not “I watched it happen.” Source-capture would strengthen them to the "
                "<b>captured</b> tier.")
    else:
        note = ("Every action is <b>declared captured</b> at the boundary: each record's own "
                "source tag says the integration recorded the call as it ran, rather than "
                "rebuilding it later from other telemetry. That is what the tag asserts; it is "
                "set by the integration and not independently verified.")
    return ('<h2>Captured via</h2>\n<div class="provgrid">%s</div>\n'
            '<div class="note prov-note">%s</div>' % ("".join(cells), note))


def flags_count(r):
    return len(_list(r.get("findings"))) + len(_list(r.get("threats")))


def row(r, show_agent=False):
    action = _dict(r.get("action"))
    auth = _dict(action.get("authorization"))
    outcome = _dict(r.get("outcome"))
    findings = _list(r.get("findings"))
    threats = _list(r.get("threats"))
    ver = _dict(r.get("verification"))
    principal = _dict(r.get("principal"))
    status = _str(outcome.get("status", "—"))
    sev = _str(r.get("severity", "INFO"))
    summary = _str((_dict(action.get("input"))).get("summary") or outcome.get("summary") or "")
    short_hash = _cut(_str(_dict(r.get("integrity")).get("hash", "")), 12)
    pills = []
    if sev not in ("INFO", ""):
        pills.append('<span class="pill %s" title="highest redaction-scanner finding">%s</span>'
                     % ("warn" if sev in ("MEDIUM", "HIGH", "CRITICAL") else "neutral", esc(sev)))
    if findings:
        pills.append('<span class="pill warn" title="redaction patterns that matched">%d</span>'
                     % len(findings))
    if threats:
        pills.append('<span class="pill warn" title="threat flags supplied with the record: %s">'
                     '%d threat%s</span>' % (
                         esc(", ".join(_str(_dict(t).get("type")) for t in threats)),
                         len(threats), "" if len(threats) == 1 else "s"))
    if not findings and not threats:
        # "no flags", not "clean": no pattern matched and no threat was supplied,
        # which is not a guarantee no sensitive data is present (see LIMITS.md).
        pills.append('<span class="pill ok" title="no redaction pattern matched and no threat '
                     'flag supplied; not a guarantee no sensitive data is present">no flags</span>')
    finding_cell = " ".join(pills)
    src = _dict(r.get("source"))
    cap = src.get("capture")
    if cap in ("captured", "ingested"):
        tier = "cap" if cap == "captured" else "ing"
        source_cell = '<span class="pill %s" title="%s">%s</span>' % (
            tier, esc(CAP_TITLE.get(cap, "")), esc(_str(src.get("adapter") or cap)))
    else:
        source_cell = '<span class="dim">—</span>'
    agent = _dict(r.get("agent"))
    agent_cell = ('<td class="mono">%s</td>' % esc(_str(agent.get("name") or agent.get("id") or "—"))
                  if show_agent else "")
    text = plain(r)
    haystack = " ".join(_str(x) for x in (
        r.get("ts"), action.get("tool"), action.get("type"), auth.get("scope"),
        auth.get("decision"), status, sev, summary, outcome.get("summary"),
        agent.get("name"), short_hash, r.get("record_id"), r.get("parent_id"),
        ver.get("status"), principal.get("human_id"), principal.get("service_account"),
        " ".join(_str(_dict(t).get("type")) for t in threats),
    ) if x).lower()
    decision = auth.get("decision")
    return (
        '<tr data-ts="%s" data-tool="%s" data-type="%s" data-sev="%s"'
        ' data-status="%s" data-flags="%d" data-rid="%s" data-text="%s"'
        ' tabindex="0" class="rowclick" title="Click for the full record">'
        '<td class="mono dim ts-cell">%s</td>%s<td class="mono">%s</td><td>%s</td>'
        '<td>%s</td><td class="mono">%s</td><td><span class="pill %s">%s</span></td>'
        '<td><span class="pill %s">%s</span></td><td>%s</td>'
        '<td class="trunc dim">%s</td><td class="mono dim">%s</td></tr>'
    ) % (
        esc(_str(r.get("ts") or "")), esc(_str(action.get("tool") or "—")),
        esc(_str(action.get("type") or "—")), esc(sev), esc(status),
        len(findings) + len(threats), esc(_str(r.get("record_id") or "")),
        esc(haystack + " " + text.lower()),
        esc(fmt_ts(r.get("ts"))), agent_cell, esc(_str(action.get("tool") or "—")),
        esc(_str(action.get("type") or "—")), source_cell, esc(_str(auth.get("scope") or "—")),
        # No decision = no gate reported: a statement, not an alarm. Green is
        # reserved for a supplied allow/approval; amber for a supplied denial.
        ("neutral" if not decision else "ok" if decision in ("allowed", "human_approved")
         else "warn"),
        esc(_str(decision or "—")),
        "ok" if status == "ok" else ("warn" if status in ("error", "denied") else "neutral"),
        esc(status), finding_cell, esc(_cut(text, 110)), esc(short_hash),
    )


def cards(records, policy_result=None):
    st = stats(records)
    out = [
        '<div class="card"><div class="n">%d</div><div class="l">Actions</div></div>' % st["total"],
        '<div class="card"><div class="n">%d</div><div class="l">Tools</div></div>' % len(st["tools"]),
        '<div class="card"><div class="n">%d</div><div class="l">Scopes</div></div>' % len(st["scopes"]),
        '<div class="card" title="records whose redaction-scanner severity is MEDIUM or higher">'
        '<div class="n">%d</div><div class="l">Flagged (MEDIUM+)</div></div>'
        % sum(1 for r in records if r.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")),
        '<div class="card"><div class="n">%d</div><div class="l">Low notes</div></div>'
        % sum(1 for r in records if r.get("severity") == "LOW"),
    ]
    if policy_result is not None:
        out.append('<div class="card" title="distinct records that violate at least one policy '
                   'rule"><div class="n">%d</div><div class="l">Out of policy</div></div>'
                   % policy_result.get("violating_records", 0))
    return "".join(out)


def scopes(records):
    return "".join('<span class="pill">%s</span>' % esc(s) for s in stats(records)["scopes"]) \
        or '<span class="dim">none</span>'


def period(records):
    st = stats(records)
    return ('<span class="period-l">Records span</span> <b>%s</b> &ndash; <b>%s</b> '
            '<span class="period-tz">UTC</span>' % (esc(st["start"]), esc(st["end"])))


def rules_digest(rules):
    """SHA-256 of the rules' RFC 8785 canonical JSON: which rule set a verdict
    was computed under, comparable with the policy file a reader holds."""
    from .canon import canon, sha256_hex
    try:
        return sha256_hex(canon(rules))
    except (TypeError, ValueError):
        return None


def policy_result(records, rules, chain_verified=True, policy_digest=None):
    """The policy verdict over ``records``. ``policy_digest`` is the SHA-256 of
    the policy text the rules were read from; without one, the rules' RFC 8785
    canonical JSON stands in for that text."""
    if not rules:
        return None
    from .policy import evaluate
    res = evaluate(records, rules)
    res["policy_sha256"] = policy_digest or rules_digest(rules)
    res["chain_verified"] = bool(chain_verified)
    if not chain_verified:
        res["compliant"] = False
    return res


def regions(records, rules=None, chain_verified=True, policy_digest=None):
    """Every record-derived region of the report page, as HTML strings."""
    from .policy import panel_card
    names = agents(records)
    res = policy_result(records, rules, chain_verified, policy_digest)
    label = subject_label(records)
    return {
        "title": label,
        "h1": esc(label),
        "meta": '%s &middot; <b>%d</b> recorded actions' % (agent_meta(names), len(records)),
        "subject_note": subject_note(records),
        "period": period(records),
        "cards": cards(records, res),
        "scopes": scopes(records),
        "provenance": provenance(records),
        "rows": [row(r, show_agent=len(names) > 1) for r in reversed(records)],
        "policy": panel_card(res, subject=label, in_page=True) if res is not None else "",
    }


# --------------------------------------------------------------------------- #
# The same regions, in the page's JavaScript
# --------------------------------------------------------------------------- #

RENDER_JS = r"""
var HaloView = (function(){
  "use strict";
  var HTML_META = {violated:["FAIL","#B23A48","#F7E4E6"], no_evidence:["GAP","#9A6A00","#F6ECCF"],
                   pass:["PASS","#3E7C5A","#E2EFE5"], no_match:["NONE","#6B6354","#EFEDE7"]};
  var CAP_TITLE = %(cap_title)s;
  var PLAIN_KEYS = %(plain_keys)s;
  var PLAIN_VERB = %(plain_verb)s;
  var FOOT_PAGE = %(foot_page)s;
  var DIGEST_NOTE = %(digest_note)s;
  var SCHEMA = %(schema)s;
  var RULE_KEYS = %(rule_keys)s;
  var SEVERITIES = %(severities)s;
  var PY_WS = /[\t\n\x0b\x0c\r\x1c-\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/;
  var TS_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|z|[+-][0-9]{2}:[0-9]{2})?$/;
  var NUM_RE = /-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?/y;
  var ALNUM = /[\p{L}\p{N}]/u;

  function has(o, k){ return o !== null && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k); }
  function get(o, k, d){ return has(o, k) ? o[k] : d; }
  function isDict(x){ return x !== null && typeof x === "object" && !Array.isArray(x); }
  function dict(x){ return isDict(x) ? x : {}; }
  function list(x){ return Array.isArray(x) ? x : []; }
  function truthy(x){
    if (x === null || x === undefined || x === false || x === 0 || x === "") return false;
    if (Array.isArray(x)) return x.length > 0;
    if (typeof x === "object") return Object.keys(x).length > 0;
    return true;
  }
  function or(){ for (var i = 0; i < arguments.length - 1; i++) if (truthy(arguments[i])) return arguments[i];
                 return arguments[arguments.length - 1]; }
  function str(x){
    if (x === null || x === undefined) return "";
    if (x === true) return "True";
    if (x === false) return "False";
    return typeof x === "string" ? x : JSON.stringify(x);
  }
  function esc(x){
    return String(x).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
                    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
  }
  function cut(s, n){ return Array.from(s).slice(0, n).join(""); }
  function cpLen(s){ return Array.from(s).length; }
  function cmpCp(a, b){
    var A = Array.from(a), B = Array.from(b);
    for (var i = 0; i < Math.min(A.length, B.length); i++){
      var x = A[i].codePointAt(0), y = B[i].codePointAt(0);
      if (x !== y) return x < y ? -1 : 1;
    }
    return A.length - B.length;
  }
  function squash(s){ return s.split(PY_WS).filter(function(p){ return p; }).join(" "); }
  function pyStrip(s){ return s.replace(new RegExp("^" + PY_WS.source), "").replace(new RegExp(PY_WS.source + "$"), ""); }
  function pad(n, w){ n = String(n); while (n.length < w) n = "0" + n; return n; }

  /* --- timestamps (mirror _view.ts_utc / fmt_ts) --- */
  function tsUtc(ts){
    if (typeof ts !== "string") return null;
    var m = TS_RE.exec(ts);
    if (!m) return null;
    var y = +m[1], mo = +m[2], d = +m[3], h = +m[4], mi = +m[5], s = +m[6];
    if (y < 1 || mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || s > 59) return null;
    var leap = (y %% 4 === 0 && (y %% 100 !== 0 || y %% 400 === 0));
    if (d > [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]) return null;
    var t = new Date(0);
    t.setUTCFullYear(y, mo - 1, d);
    t.setUTCHours(h, mi, s, 0);
    var ms = t.getTime();
    var off = m[8];
    if (off && off !== "Z" && off !== "z"){
      var oh = +off.slice(1, 3), om = +off.slice(4, 6);
      if (oh > 23 || om > 59) return null;
      var delta = (oh * 60 + om) * 60000;
      ms = off[0] === "+" ? ms - delta : ms + delta;
    }
    var o = new Date(ms), yy = o.getUTCFullYear();
    if (yy < 1 || yy > 9999) return null;
    return {ms: ms, us: +((m[7] || "").slice(0, 6) + "000000").slice(0, 6), y: yy,
            mo: o.getUTCMonth() + 1, d: o.getUTCDate(), h: o.getUTCHours(),
            mi: o.getUTCMinutes(), s: o.getUTCSeconds()};
  }
  function fmtTs(ts){
    var t = tsUtc(ts);
    if (!t) return cut(typeof ts === "string" ? ts : "", 19);
    return pad(t.y, 4) + "-" + pad(t.mo, 2) + "-" + pad(t.d, 2) + " " +
           pad(t.h, 2) + ":" + pad(t.mi, 2) + ":" + pad(t.s, 2);
  }
  function cmpTs(a, b){ return a.ms !== b.ms ? (a.ms < b.ms ? -1 : 1) : (a.us - b.us); }

  /* --- the summary literal reader (mirror _view._Lit) --- */
  var SIMPLE_ESC = {"\\":"\\", "'":"'", '"':'"', a:"\x07", b:"\b", f:"\f", n:"\n", r:"\r", t:"\t", v:"\x0b", "\n":""};
  function Fail(){}
  function readDict(text){
    var i = 0, s = text;
    function ws(){ while (i < s.length && " \t\n\r\f".indexOf(s[i]) >= 0) i++; }
    function peek(c){ return i < s.length && s[i] === c; }
    function expect(c){ if (!peek(c)) throw new Fail(); i++; }
    function alnumAt(j){ if (j >= s.length) return false; var c = String.fromCodePoint(s.codePointAt(j)); return ALNUM.test(c); }
    function string(){
      var q = s[i]; i++;
      if (s.substr(i, 2) === q + q) throw new Fail();
      var out = "";
      for (;;){
        if (i >= s.length) throw new Fail();
        var c = s[i];
        if (c === q){ i++; break; }
        if (c === "\n") throw new Fail();
        if (c !== "\\"){ out += c; i++; continue; }
        if (i + 1 >= s.length) throw new Fail();
        var e = s[i + 1]; i += 2;
        if (has(SIMPLE_ESC, e)) out += SIMPLE_ESC[e];
        else if ("01234567".indexOf(e) >= 0){
          var j = i;
          while (j < s.length && j < i + 2 && "01234567".indexOf(s[j]) >= 0) j++;
          out += String.fromCodePoint(parseInt(e + s.slice(i, j), 8)); i = j;
        } else if (e === "x" || e === "u" || e === "U"){
          var n = e === "x" ? 2 : (e === "u" ? 4 : 8), h = s.substr(i, n);
          if (h.length !== n || !/^[0-9a-fA-F]+$/.test(h)) throw new Fail();
          var cp = parseInt(h, 16);
          if (cp > 0x10FFFF) throw new Fail();
          out += String.fromCodePoint(cp); i += n;
        } else if (e === "N") throw new Fail();
        else out += "\\" + e;
      }
      ws();
      if (peek("'") || peek('"')) throw new Fail();
      return out;
    }
    var depth = 0;
    function value(){
      depth++;
      try { return value1(); } finally { depth--; }
    }
    function value1(){
      if (depth > 64) throw new Fail();
      ws();
      if (i >= s.length) throw new Fail();
      var c = s[i], start = i;
      if (c === "{"){
        i++; var entries = []; ws();
        if (peek("}")){ i++; return {k: "dict", v: entries, a: start, b: i}; }
        for (;;){
          var k = value(); ws(); expect(":"); var v = value();
          entries.push([k, v]); ws();
          if (peek(",")){ i++; ws(); if (peek("}")){ i++; break; } continue; }
          expect("}"); break;
        }
        return {k: "dict", v: entries, a: start, b: i};
      }
      if (c === "[" || c === "("){
        var close = c === "[" ? "]" : ")", items = [], comma = false;
        i++; ws();
        if (peek(close)){ i++; return {k: "seq", v: items, a: start, b: i}; }
        for (;;){
          items.push(value()); ws();
          if (peek(",")){ comma = true; i++; ws(); if (peek(close)){ i++; break; } continue; }
          expect(close); break;
        }
        if (c === "(" && !comma) return {k: items[0].k, v: items[0].v, a: start, b: i};
        return {k: "seq", v: items, a: start, b: i};
      }
      if (c === "'" || c === '"') return {k: "str", v: string(), a: start, b: i};
      NUM_RE.lastIndex = i;
      var m = NUM_RE.exec(s);
      if (m && m[0].length){
        i += m[0].length;
        if (i < s.length && (alnumAt(i) || s[i] === "_" || s[i] === ".")) throw new Fail();
        return {k: "num", v: parseFloat(m[0]) !== 0, a: start, b: i};
      }
      var words = [["True", true], ["False", false], ["None", false]];
      for (var w = 0; w < words.length; w++){
        if (s.substr(i, words[w][0].length) === words[w][0]){
          var end = i + words[w][0].length;
          if (end < s.length && (alnumAt(end) || s[end] === "_")) throw new Fail();
          i = end;
          return {k: "const", v: words[w][1], a: start, b: end};
        }
      }
      throw new Fail();
    }
    try {
      var node = value(); ws();
      if (i !== s.length || node.k !== "dict") return null;
      var out = new Map();
      for (var e = 0; e < node.v.length; e++)
        if (node.v[e][0].k === "str") out.set(node.v[e][0].v, node.v[e][1]);
      return out;
    } catch (err){
      if (err instanceof Fail || err instanceof RangeError) return null;
      throw err;
    }
  }
  function nodeText(node, text){
    if (node.k === "str") return [node.v, node.v.length > 0];
    if (node.k === "dict" || node.k === "seq") return [text.slice(node.a, node.b), node.v.length > 0];
    return [text.slice(node.a, node.b), !!node.v];
  }

  /* --- plain-language summary (mirror _view.plain) --- */
  function gate(r){
    var action = dict(r.action), auth = dict(action.authorization),
        ver = dict(r.verification), out = dict(r.outcome);
    if (ver.status === "blocked")
      return out.status === "ok" ? "Gate reported blocked; outcome recorded: ok" : "Blocked by gate";
    if (auth.decision === "denied" || out.status === "denied")
      return out.status === "ok" ? "Decision recorded denied; outcome recorded: ok" : "Denied";
    return null;
  }
  function plain(r){
    var action = dict(r.action);
    var tool = str(or(action.tool, action.type, "action"));
    var summary = str(or(dict(action.input).summary, ""));
    var detail = "";
    if (summary.slice(0, 1) === "{" && cpLen(summary) <= 4096){
      var d = readDict(summary);
      if (d !== null){
        for (var i = 0; i < PLAIN_KEYS.length; i++){
          if (d.has(PLAIN_KEYS[i])){
            var t = nodeText(d.get(PLAIN_KEYS[i]), summary);
            if (t[1]){ detail = t[0]; break; }
          }
        }
      } else detail = summary;
    } else detail = summary;
    detail = squash(detail);
    var g = gate(r);
    if (g){
      var sep = g.slice(-4) === ": ok" ? " \u2014 " : ": ";
      return detail ? (g + sep + tool + " \u2014 " + detail) : (g + sep + tool);
    }
    if (!detail){
      var o = dict(r.outcome).summary;
      o = (typeof o === "string" && o.slice(0, 1) !== "{") ? squash(o) : "";
      return o ? ("Ran " + tool + " \u2014 result: " + o) : ("Ran " + tool);
    }
    var verb = has(PLAIN_VERB, action.type) ? PLAIN_VERB[action.type] : "Ran";
    var tl = tool.toLowerCase();
    if (action.type === "network" && !(tl.indexOf("http") === 0 || tl.indexOf("web") === 0 || tl.indexOf("fetch") === 0))
      verb = "Ran";
    if (tool === "Write" || tool === "Edit" || tool === "NotebookEdit") verb = tool === "Edit" ? "Edited" : "Wrote file";
    else if (tool === "WebFetch" || tool === "WebSearch") verb = tool === "WebSearch" ? "Searched the web for" : "Fetched";
    else if (tool === "Bash") verb = "Ran the shell command";
    else if (tool === "Agent") verb = "Started a helper agent to";
    else if (tool === "Read") verb = "Read the file";
    return pyStrip(verb + " " + detail);
  }

  /* --- regions (mirror _view.regions) --- */
  function recordSubject(r){
    var s = r.subject;
    var sid = isDict(s) ? (truthy(s.id) ? s.id : null) : null;
    if (sid === null || typeof sid === "string") return sid;
    return canonJson(sid);
  }
  function canonJson(v){
    if (Array.isArray(v)) return "[" + v.map(canonJson).join(",") + "]";
    if (isDict(v)) return "{" + Object.keys(v).sort().map(function(k){ return JSON.stringify(k) + ":" + canonJson(v[k]); }).join(",") + "}";
    return JSON.stringify(v);
  }
  function subjectLabel(records){
    var ids = new Set();
    records.forEach(function(r){ var x = recordSubject(r); if (x !== null) ids.add(x); });
    if (ids.size > 1) return ids.size + " subjects";
    for (var i = 0; i < records.length; i++){
      var s = records[i].subject;
      if (isDict(s) && (truthy(s.name) || truthy(s.id))) return str(or(s.name, s.id));
    }
    return "Agent runtime";
  }
  function subjectId(records){
    for (var i = 0; i < records.length; i++){
      var s = records[i].subject;
      if (isDict(s) && truthy(s.id)) return s.id;
    }
    return null;
  }
  function pyJsonStr(s){
    var out = '"';
    for (var i = 0; i < s.length; i++){
      var c = s.charCodeAt(i), ch = s[i];
      if (ch === '"') out += '\\"';
      else if (ch === "\\") out += "\\\\";
      else if (ch === "\n") out += "\\n";
      else if (ch === "\r") out += "\\r";
      else if (ch === "\t") out += "\\t";
      else if (ch === "\b") out += "\\b";
      else if (ch === "\f") out += "\\f";
      else if (c < 0x20 || c > 0x7e) out += "\\u" + pad(c.toString(16), 4);
      else out += ch;
    }
    return out + '"';
  }
  function subjectNote(records){
    var sid = subjectId(records);
    if (sid === null) return "";
    sid = str(sid);
    var odd = Array.from(sid).some(function(c){
      return c.codePointAt(0) > 126 || (/[\p{C}\p{Z}]/u.test(c) && c !== " ");
    });
    if (sid !== pyStrip(sid) || sid.indexOf("  ") >= 0) odd = true;
    if (!odd && subjectLabel(records) === sid) return "";
    var note = 'Subject id: <span class="mono">' + esc(pyJsonStr(sid).slice(1, -1)) + "</span>";
    if (odd) note += " &mdash; contains invisible or non-ASCII characters; compare it to the id the witness holds.";
    return '<div class="meta">' + note + "</div>";
  }
  function agents(records){
    var seen = [];
    records.forEach(function(r){
      var a = dict(r.agent), label = or(a.name, a.id);
      if (truthy(label)){ label = str(label); if (seen.indexOf(label) < 0) seen.push(label); }
    });
    return seen;
  }
  function agentMeta(names){
    if (!names.length) return "Agent <b>unknown</b>";
    if (names.length === 1) return "Agent <b>" + esc(names[0]) + "</b>";
    var shown = names.slice(0, 4).map(function(a){ return "<b>" + esc(a) + "</b>"; }).join(", ");
    var more = names.length > 4 ? " (+" + (names.length - 4) + " more)" : "";
    // the label is assembled here so a single-agent page's source never carries it
    return names.length + " agents" + ": " + shown + more;
  }
  function stats(records){
    var tools = new Set(), scopes = new Set(), times = [];
    records.forEach(function(r){
      var action = dict(r.action);
      tools.add(str(or(action.tool, action.type, "\u2014")));
      var scope = dict(action.authorization).scope;
      if (truthy(scope)) scopes.add(str(scope));
      var t = tsUtc(r.ts);
      if (t) times.push([t, r.ts]);
    });
    times.sort(function(a, b){ return cmpTs(a[0], b[0]); });
    return {total: records.length, ntools: tools.size,
            scopes: Array.from(scopes).sort(cmpCp),
            start: times.length ? fmtTs(times[0][1]) : "\u2014",
            end: times.length ? fmtTs(times[times.length - 1][1]) : "\u2014"};
  }
  function provenance(records){
    var buckets = {}, order = [];
    records.forEach(function(r){
      var s = r.source;
      if (!isDict(s)) return;
      var a = str(or(s.adapter, "unknown"));
      if (!has(buckets, a)){
        order.push(a);
        buckets[a] = {via: str(or(s.via, a)), capture: str(or(s.capture, "ingested")), n: 0};
      }
      buckets[a].n++;
    });
    if (!order.length) return "";
    var rank = {captured: 0, ingested: 1};
    var items = order.map(function(a){ return buckets[a]; });
    items.sort(function(x, y){
      var rx = has(rank, x.capture) ? rank[x.capture] : 2, ry = has(rank, y.capture) ? rank[y.capture] : 2;
      return rx !== ry ? rx - ry : y.n - x.n;
    });
    var nCap = 0, nIng = 0;
    items.forEach(function(b){ if (b.capture === "captured") nCap += b.n; if (b.capture === "ingested") nIng += b.n; });
    var cells = items.map(function(b){
      var tier = b.capture === "captured" ? "cap" : "ing", label = b.capture === "captured" ? "Captured" : "Ingested";
      return '<div class="prov" title="' + esc(has(CAP_TITLE, b.capture) ? CAP_TITLE[b.capture] : "") +
        '"><span class="pill ' + tier + '">' + label + '</span><span class="prov-via">' + esc(b.via) +
        '</span><span class="prov-n">' + b.n + " action" + (b.n === 1 ? "" : "s") + "</span></div>";
    }).join("");
    var note = (nIng && nCap) ? %(note_mixed)s : (nIng ? %(note_ing)s : %(note_cap)s);
    return '<h2>Captured via</h2>\n<div class="provgrid">' + cells + '</div>\n<div class="note prov-note">' + note + "</div>";
  }
  function row(r, showAgent){
    var action = dict(r.action), auth = dict(action.authorization), outcome = dict(r.outcome),
        findings = list(r.findings), threats = list(r.threats), ver = dict(r.verification),
        principal = dict(r.principal), agent = dict(r.agent), src = dict(r.source);
    var status = str(get(outcome, "status", "\u2014")), sev = str(get(r, "severity", "INFO"));
    var summary = str(or(dict(action.input).summary, outcome.summary, ""));
    var shortHash = cut(str(get(dict(r.integrity), "hash", "")), 12);
    var pills = [];
    if (sev !== "INFO" && sev !== "")
      pills.push('<span class="pill ' + (["MEDIUM", "HIGH", "CRITICAL"].indexOf(sev) >= 0 ? "warn" : "neutral") +
                 '" title="highest redaction-scanner finding">' + esc(sev) + "</span>");
    if (findings.length) pills.push('<span class="pill warn" title="redaction patterns that matched">' + findings.length + "</span>");
    if (threats.length)
      pills.push('<span class="pill warn" title="threat flags supplied with the record: ' +
        esc(threats.map(function(t){ return str(dict(t).type); }).join(", ")) + '">' +
        threats.length + " threat" + (threats.length === 1 ? "" : "s") + "</span>");
    if (!findings.length && !threats.length)
      pills.push('<span class="pill ok" title="no redaction pattern matched and no threat flag supplied; not a guarantee no sensitive data is present">no flags</span>');
    var sourceCell;
    if (src.capture === "captured" || src.capture === "ingested")
      sourceCell = '<span class="pill ' + (src.capture === "captured" ? "cap" : "ing") + '" title="' +
        esc(CAP_TITLE[src.capture]) + '">' + esc(str(or(src.adapter, src.capture))) + "</span>";
    else sourceCell = '<span class="dim">\u2014</span>';
    var agentCell = showAgent ? '<td class="mono">' + esc(str(or(agent.name, agent.id, "\u2014"))) + "</td>" : "";
    var text = plain(r);
    var hay = [r.ts, action.tool, action.type, auth.scope, auth.decision, status, sev, summary,
               outcome.summary, agent.name, shortHash, r.record_id, r.parent_id, ver.status,
               principal.human_id, principal.service_account,
               threats.map(function(t){ return str(dict(t).type); }).join(" ")]
      .filter(truthy).map(str).join(" ").toLowerCase();
    var decision = auth.decision;
    return '<tr data-ts="' + esc(str(or(r.ts, ""))) + '" data-tool="' + esc(str(or(action.tool, "\u2014"))) +
      '" data-type="' + esc(str(or(action.type, "\u2014"))) + '" data-sev="' + esc(sev) +
      '" data-status="' + esc(status) + '" data-flags="' + (findings.length + threats.length) +
      '" data-rid="' + esc(str(or(r.record_id, ""))) + '" data-text="' + esc(hay + " " + text.toLowerCase()) +
      '" tabindex="0" class="rowclick" title="Click for the full record">' +
      '<td class="mono dim ts-cell">' + esc(fmtTs(r.ts)) + "</td>" + agentCell +
      '<td class="mono">' + esc(str(or(action.tool, "\u2014"))) + "</td><td>" + esc(str(or(action.type, "\u2014"))) +
      "</td><td>" + sourceCell + '</td><td class="mono">' + esc(str(or(auth.scope, "\u2014"))) +
      '</td><td><span class="pill ' + (!truthy(decision) ? "neutral" : (decision === "allowed" || decision === "human_approved") ? "ok" : "warn") +
      '">' + esc(str(or(decision, "\u2014"))) + '</span></td><td><span class="pill ' +
      (status === "ok" ? "ok" : (status === "error" || status === "denied") ? "warn" : "neutral") + '">' + esc(status) +
      "</span></td><td>" + pills.join(" ") + '</td><td class="trunc dim">' + esc(cut(text, 110)) +
      '</td><td class="mono dim">' + esc(shortHash) + "</td></tr>";
  }

  /*POLICY-BEGIN*/
  /* --- policy validation (mirror policy.validate_policy) --- */
  function pyRepr(v){
    if (typeof v === "string"){
      var q = (v.indexOf("'") >= 0 && v.indexOf('"') < 0) ? '"' : "'", out = q;
      for (var i = 0; i < v.length; i++){
        var ch = v[i], c = v.charCodeAt(i);
        if (ch === q || ch === "\\") out += "\\" + ch;
        else if (ch === "\n") out += "\\n";
        else if (ch === "\r") out += "\\r";
        else if (ch === "\t") out += "\\t";
        else if (c < 0x20 || (c >= 0x7f && c < 0xa0)) out += "\\x" + pad(c.toString(16), 2);
        else out += ch;
      }
      return out + q;
    }
    if (v === null || v === undefined) return "None";
    if (v === true) return "True";
    if (v === false) return "False";
    return pyJson(v);
  }
  function pyJson(v){
    if (typeof v === "string") return pyJsonStr(v);
    if (v === null) return "null";
    if (typeof v === "number" && !isFinite(v)) return v > 0 ? "Infinity" : v < 0 ? "-Infinity" : "NaN";
    return JSON.stringify(v);
  }
  function PolicyError(msg){ this.message = msg; }
  function perr(msg){ throw new PolicyError(msg); }
  var MAX_SAFE = 9007199254740991;
  var TYPE_WORD = {string: "a string", number: "a number", integer: "a number", boolean: "true or false"};
  var RANGE_OPS = ["gt", "gte", "lt", "lte"];
  var OPS = ["contains", "eq", "exists", "gt", "gte", "in", "lt", "lte", "ne", "nin"];
  function polField(path, where){
    if (typeof path !== "string" || !path || path.split(".").some(function(p){ return !p; }))
      perr(where + ": field path " + pyRepr(path) + " is not a dotted record path");
    var node = SCHEMA, fanned = false, prev = null, parts = path.split(".");
    for (var i = 0; i < parts.length; i++){
      var part = parts[i], fan = part.slice(-2) === "[]", key = fan ? part.slice(0, -2) : part;
      if (node === null) return [null, fanned];
      if (node.type === "array")
        perr(where + ": " + pyRepr(prev) + ' is a list; use "' + prev + '[]" to match its items (in ' + pyRepr(path) + ")");
      var props = node.properties;
      if (!isDict(props) || !Object.keys(props).length) return [null, fanned];
      if (!has(props, key))
        perr(where + ": " + pyRepr(key) + " is not a Runtime Record field (in " + pyRepr(path) +
             "; known here: " + Object.keys(props).sort().join(", ") + ")");
      node = props[key];
      prev = key;
      if (fan){
        if (node.type !== "array")
          perr(where + ": " + pyRepr(key) + ' is not a list, so "[]" does not apply (in ' + pyRepr(path) + ")");
        node = isDict(node.items) ? node.items : null;
        fanned = true;
      }
    }
    return [node, fanned];
  }
  function polValue(v, node, path, where){
    if (v === null) perr(where + ": null never equals a recorded value of " + pyRepr(path) +
                         '; use {"exists": false} for an absent field');
    if (typeof v === "number" && !isFinite(v)) perr(where + ": " + pyRepr(path) + " needs a finite number");
    if (typeof v === "number" && Number.isInteger(v) && Math.abs(v) > MAX_SAFE)
      perr(where + ": " + pyRepr(path) + ": a number beyond 2^53-1, which a browser cannot compare exactly");
    if (typeof v === "object")
      perr(where + ": " + pyRepr(path) + " needs a single value, not " + (Array.isArray(v) ? "a list" : "an object"));
    if (node === null) return;
    var t = node.type, ok = true;
    if (t === "string") ok = typeof v === "string";
    else if (t === "number") ok = typeof v === "number";
    else if (t === "integer") ok = typeof v === "number" && Number.isInteger(v);
    else if (t === "boolean") ok = typeof v === "boolean";
    if (!ok) perr(where + ": " + pyRepr(path) + " needs " + TYPE_WORD[t] + ", not " + pyJson(v));
    if (Array.isArray(node.enum) && !inList(v, node.enum))
      perr(where + ": " + pyJson(v) + " is not one of the values " + pyRepr(path) + " can hold (" + node.enum.join(", ") + ")");
  }
  function polMatcher(path, spec, node, fanned, where){
    var kind = node !== null ? node.type : null;
    var ops = isDict(spec) ? spec : {eq: spec};
    Object.keys(ops).forEach(function(op){
      var arg = ops[op];
      if (op === "exists") return;
      if (kind === "object") perr(where + ": " + pyRepr(path) + ' is an object; only {"exists": ...} applies to it');
      if (kind === "array"){
        if (op !== "contains")
          perr(where + ": " + pyRepr(path) + ' is a list; match an item with {"contains": ...} or "' + path + '[]"');
        polValue(arg, isDict(node.items) ? node.items : null, path, where);
        return;
      }
      if (op === "contains")
        perr(where + ": 'contains' applies to list fields; " + pyRepr(path) + " is " +
             (kind === null ? "not a list" : (TYPE_WORD[kind] || kind)));
      if (RANGE_OPS.indexOf(op) >= 0){
        if (kind !== null && kind !== "number" && kind !== "integer")
          perr(where + ": " + pyRepr(op) + " applies to numeric fields; " + pyRepr(path) + " is " + (TYPE_WORD[kind] || kind));
        polValue(arg, null, path, where);
        return;
      }
      (op === "in" || op === "nin" ? arg : [arg]).forEach(function(v){ polValue(v, node, path, where); });
    });
    polConsistent(path, ops, fanned, where);
  }
  function polConsistent(path, ops, fanned, where){
    function bad(why){
      perr(where + ": the matchers for " + pyRepr(path) + " contradict each other (" + why + "), so the condition can never hold");
    }
    if (has(ops, "in") && !ops["in"].length)
      perr(where + ": 'in' for " + pyRepr(path) + " has an empty list, so the condition can never hold");
    if (ops.exists === false && Object.keys(ops).some(function(k){ return ["exists", "ne", "nin"].indexOf(k) < 0; }))
      bad("an absent field has no value to compare");
    if (has(ops, "eq") && has(ops, "ne") && pyEq(ops.eq, ops.ne)) bad("eq and ne name the same value");
    if (has(ops, "eq") && has(ops, "nin") && inList(ops.eq, ops.nin)) bad("eq names a value nin excludes");
    if (has(ops, "in") && has(ops, "nin") && ops["in"].every(function(v){ return inList(v, ops.nin); }))
      bad("every value in 'in' is excluded by nin");
    if (fanned) return;
    if (has(ops, "eq") && has(ops, "in") && !inList(ops.eq, ops["in"])) bad("eq names a value outside 'in'");
    var lo = [], hi = [];
    ["gt", "gte"].forEach(function(k){ if (has(ops, k)) lo.push([ops[k], k === "gte"]); });
    ["lt", "lte"].forEach(function(k){ if (has(ops, k)) hi.push([ops[k], k === "lte"]); });
    lo.forEach(function(a){ hi.forEach(function(b){
      if (a[0] > b[0] || (a[0] === b[0] && !(a[1] && b[1]))) bad("the numeric bounds leave no value");
    }); });
  }
  function polCondition(cond, where){
    if (!isDict(cond) || !Object.keys(cond).length) perr(where + ": must be a non-empty object of {field: matcher}");
    Object.keys(cond).forEach(function(path){
      var spec = cond[path], fn = polField(path, where);
      if (isDict(spec)){
        if (!Object.keys(spec).length) perr(where + ": empty matcher for " + pyRepr(path));
        Object.keys(spec).forEach(function(op){
          var arg = spec[op];
          if (OPS.indexOf(op) < 0)
            perr(where + ": unknown matcher " + pyRepr(op) + " for " + pyRepr(path) + " (known: " + OPS.join(", ") + ")");
          if ((op === "in" || op === "nin") && !Array.isArray(arg)) perr(where + ": " + pyRepr(op) + " needs a list for " + pyRepr(path));
          if (op === "exists" && typeof arg !== "boolean") perr(where + ": 'exists' needs true or false for " + pyRepr(path));
          if (RANGE_OPS.indexOf(op) >= 0 && typeof arg !== "number") perr(where + ": " + pyRepr(op) + " needs a number for " + pyRepr(path));
        });
      }
      polMatcher(path, spec, fn[0], fn[1], where);
    });
  }
  function validatePolicy(rules){
    /* null when ``rules`` is a valid policy, else the reason (validate_policy's message). */
    try {
      if (!Array.isArray(rules) || !rules.length) perr("policy: expected a non-empty list of rules");
      var seen = {};
      rules.forEach(function(rule, n){
        var where = "policy rule " + (n + 1);
        if (!isDict(rule)) perr(where + ": must be an object");
        if (typeof rule.id === "string" && rule.id) where = "policy rule " + pyRepr(rule.id);
        else perr(where + ': needs a non-empty string "id"');
        if (has(seen, rule.id)) perr(where + ": duplicate rule id");
        seen[rule.id] = true;
        var unknown = Object.keys(rule).filter(function(k){ return RULE_KEYS.indexOf(k) < 0; }).sort();
        if (unknown.length)
          perr(where + ": unknown key(s) " + unknown.map(pyRepr).join(", ") + " (known: " + RULE_KEYS.join(", ") + ")");
        if (!has(rule, "forbid") && !has(rule, "require") && rule.expect_evidence !== true)
          perr(where + ': has nothing to check — give it forbid, require, or "expect_evidence": true');
        if (has(rule, "expect_evidence") && typeof rule.expect_evidence !== "boolean")
          perr(where + ": expect_evidence must be true or false");
        if (has(rule, "severity") && SEVERITIES.indexOf(rule.severity) < 0)
          perr(where + ": severity " + pyRepr(rule.severity) + " is not one of " + SEVERITIES.join(", "));
        ["description", "source"].forEach(function(k){
          if (has(rule, k) && typeof rule[k] !== "string") perr(where + ": " + k + " must be a string");
        });
        ["when", "forbid", "require"].forEach(function(k){
          if (has(rule, k)) polCondition(rule[k], where + " " + k);
        });
      });
      return null;
    } catch (e){
      if (e instanceof PolicyError) return e.message;
      throw e;
    }
  }
  /* --- policy (mirror policy.evaluate / panel_card) --- */
  function pyEq(a, b){
    var na = typeof a === "number" || typeof a === "boolean", nb = typeof b === "number" || typeof b === "boolean";
    if (na || nb) return na && nb && Number(a) === Number(b);
    if (typeof a === "string" || typeof b === "string") return a === b;
    if (a === null || b === null) return a === b;
    if (Array.isArray(a) || Array.isArray(b)){
      if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
      for (var i = 0; i < a.length; i++) if (!pyEq(a[i], b[i])) return false;
      return true;
    }
    var ka = Object.keys(a), kb = Object.keys(b);
    if (ka.length !== kb.length) return false;
    for (var j = 0; j < ka.length; j++) if (!has(b, ka[j]) || !pyEq(a[ka[j]], b[ka[j]])) return false;
    return true;
  }
  function inList(v, arr){ return arr.some(function(x){ return pyEq(v, x); }); }
  function num(v){ return typeof v === "number" ? v : null; }
  function resolve(node, parts){
    if (!parts.length) return [node];
    var head = parts[0], rest = parts.slice(1), fan = head.slice(-2) === "[]", key = fan ? head.slice(0, -2) : head;
    if (key){ if (isDict(node) && has(node, key)) node = node[key]; else return []; }
    if (fan){
      if (!Array.isArray(node)) return [];
      var out = [];
      node.forEach(function(item){ out = out.concat(resolve(item, rest)); });
      return out;
    }
    return resolve(node, rest);
  }
  function match(values, spec){
    if (isDict(spec)){
      var ops = Object.keys(spec);
      for (var i = 0; i < ops.length; i++){
        var op = ops[i], arg = spec[op], ok;
        if (op === "exists") ok = (values.length > 0) === truthy(arg);
        else if (op === "eq") ok = inList(arg, values);
        else if (op === "ne") ok = !inList(arg, values);
        else if (op === "in") ok = values.some(function(v){ return inList(v, arg); });
        else if (op === "nin") ok = !values.some(function(v){ return inList(v, arg); });
        else if (op === "contains") ok = values.some(function(v){ return Array.isArray(v) && inList(arg, v); });
        else if (op === "gt") ok = values.some(function(v){ return num(v) !== null && num(v) > arg; });
        else if (op === "gte") ok = values.some(function(v){ return num(v) !== null && num(v) >= arg; });
        else if (op === "lt") ok = values.some(function(v){ return num(v) !== null && num(v) < arg; });
        else if (op === "lte") ok = values.some(function(v){ return num(v) !== null && num(v) <= arg; });
        else throw new Error("unknown matcher operator: " + op);
        if (!ok) return false;
      }
      return true;
    }
    return inList(spec, values);
  }
  function holds(rec, cond){
    var paths = Object.keys(cond);
    for (var i = 0; i < paths.length; i++)
      if (!match(resolve(rec, paths[i].split(".")), cond[paths[i]])) return false;
    return true;
  }
  function evaluate(records, rules, chainVerified, digest){
    var results = [], violations = 0, gaps = 0, noMatch = 0, violating = new Set();
    rules.forEach(function(rule){
      var when = get(rule, "when", {}), forbid = get(rule, "forbid", null), require = get(rule, "require", null),
          expect = get(rule, "expect_evidence", false), matched = 0, violators = [];
      records.forEach(function(rec, idx){
        if (truthy(when) && !holds(rec, when)) return;
        matched++;
        var bad = false;
        if (forbid !== null && holds(rec, forbid)) bad = true;
        if (require !== null && !holds(rec, require)) bad = true;
        if (bad){ violators.push(get(rec, "record_id", "?")); violating.add(idx); }
      });
      var status;
      if (violators.length){ status = "violated"; violations++; }
      else if (truthy(expect) && matched === 0){ status = "no_evidence"; gaps++; }
      else if (matched === 0 && (forbid !== null || require !== null)){ status = "no_match"; noMatch++; }
      else status = "pass";
      results.push({id: get(rule, "id", "?"), description: get(rule, "description", ""),
                    severity: get(rule, "severity", "MEDIUM"), source: get(rule, "source", ""),
                    status: status, matched: matched, violators: violators});
    });
    var res = {compliant: violations === 0, checked: records.length, violations: violations,
               violating_records: violating.size, gaps: gaps, unexercised: noMatch, rules: results,
               policy_sha256: digest || null, chain_verified: !!chainVerified};
    if (!chainVerified) res.compliant = false;
    return res;
  }
  function countsLine(res){
    return res.checked + " record(s) checked against " + res.rules.length + " rule(s): " + res.violations +
      " rule(s) violated by " + res.violating_records + " record(s), " + res.gaps + " evidence gap(s), " +
      res.unexercised + " rule(s) not exercised." +
      (res.policy_sha256 ? " " + DIGEST_NOTE.replace("%%s", res.policy_sha256.slice(0, 16)) : "");
  }
  function panelCard(res, subject){
    var order = {violated: 0, no_evidence: 1, no_match: 2, pass: 3};
    var rules = res.rules.slice().sort(function(a, b){ return order[a.status] - order[b.status]; });
    var rows = rules.map(function(r){
      var meta = HTML_META[r.status], detail;
      if (r.status === "violated") detail = r.violators.length + " record(s) out of policy: " + r.violators.join(", ");
      else if (r.status === "no_evidence") detail = "Policy declares this control. The log contains no evidence of it.";
      else if (r.status === "no_match") detail = "Matched no records \u2014 nothing attested.";
      else detail = r.matched + " matching action(s), all within policy.";
      var src = r.source ? '<span class="hp-src">' + esc(r.source) + "</span>" : "";
      return '<div class="hp-row"><div class="hp-badge" style="color:' + meta[1] + ";background:" + meta[2] + '">' +
        meta[0] + '</div><div><div class="hp-rh"><span class="hp-rid">' + esc(r.id) + '</span><span class="hp-sev">' +
        esc(r.severity) + "</span>" + src + '</div><div class="hp-desc">' + esc(r.description) +
        '</div><div class="hp-detail">' + esc(detail) + "</div></div></div>";
    }).join("");
    var v;
    if (res.chain_verified === false) v = ["NON-ATTESTABLE \u2014 LOG DID NOT VERIFY", "#B23A48"];
    else if (res.checked === 0) v = ["NO EVIDENCE \u2014 0 RECORDS IN SCOPE", "#6B6354"];
    else if (res.unexercised === res.rules.length) v = ["NO APPLICABLE EVIDENCE \u2014 NO RULES EXERCISED", "#6B6354"];
    else if (!res.compliant) v = ["NON-COMPLIANT", "#B23A48"];
    else if (res.gaps) v = ["COMPLIANT, WITH GAPS", "#9A6A00"];
    else v = ["COMPLIANT", "#3E7C5A"];
    var subj = subject ? "halo-record &middot; " + esc(subject) : "halo-record";
    return '<div class="hp-card"><div class="hp-top"><div class="hp-eyebrow">Runtime Report &middot; Policy Corroboration</div>' +
      '<div class="hp-h1">Verdict: <span style="color:' + v[1] + '">' + v[0] + '</span></div><div class="hp-sub">' +
      esc(countsLine(res)) + '</div></div><div class="hp-rows">' + rows + '</div><div class="hp-foot"><span>' +
      esc(FOOT_PAGE) + " <b>No model judgment.</b></span><span>" + subj + "</span></div></div>";
  }
  /*POLICY-END*/
  function cards(records, res){
    var st = stats(records), nflag = 0, nlow = 0;
    records.forEach(function(r){
      if (["MEDIUM", "HIGH", "CRITICAL"].indexOf(r.severity) >= 0) nflag++;
      if (r.severity === "LOW") nlow++;
    });
    var out = '<div class="card"><div class="n">' + st.total + '</div><div class="l">Actions</div></div>' +
      '<div class="card"><div class="n">' + st.ntools + '</div><div class="l">Tools</div></div>' +
      '<div class="card"><div class="n">' + st.scopes.length + '</div><div class="l">Scopes</div></div>' +
      '<div class="card" title="records whose redaction-scanner severity is MEDIUM or higher"><div class="n">' + nflag +
      '</div><div class="l">Flagged (MEDIUM+)</div></div>' +
      '<div class="card"><div class="n">' + nlow + '</div><div class="l">Low notes</div></div>';
    if (res) out += '<div class="card" title="distinct records that violate at least one policy rule"><div class="n">' +
      res.violating_records + '</div><div class="l">Out of policy</div></div>';
    return out;
  }
  function regions(records, rules, chainVerified, rulesDigest){
    var names = agents(records), st = stats(records), label = subjectLabel(records);
    var hasRules = rules !== null && rules !== undefined && !(Array.isArray(rules) && !rules.length);
    var invalid = hasRules && typeof validatePolicy === "function" ? validatePolicy(rules) : null;
    var res = (hasRules && !invalid && typeof evaluate === "function")
      ? evaluate(records, rules, chainVerified, rulesDigest) : null;
    var rows = [];
    for (var i = records.length - 1; i >= 0; i--) rows.push(row(records[i], names.length > 1));
    return {
      title: label,
      h1: esc(label),
      meta: agentMeta(names) + " &middot; <b>" + records.length + "</b> recorded actions",
      subject_note: subjectNote(records),
      period: '<span class="period-l">Records span</span> <b>' + esc(st.start) + "</b> &ndash; <b>" + esc(st.end) +
              '</b> <span class="period-tz">UTC</span>',
      cards: cards(records, res),
      scopes: st.scopes.map(function(s){ return '<span class="pill">' + esc(s) + "</span>"; }).join("") ||
              '<span class="dim">none</span>',
      provenance: provenance(records),
      rows: rows,
      policyEvaluated: res !== null,
      policy: invalid ? "<div class='verdict fail'>Policy verdict withheld &mdash; the policy embedded in " +
                        "this page is not a valid policy (" + esc(invalid) + ").</div>"
                      : res ? panelCard(res, label) : ""
    };
  }
  return {regions: regions, tsUtc: tsUtc, fmtTs: fmtTs, plain: plain, esc: esc, subjectId: subjectId,
          validatePolicy: typeof validatePolicy === "function" ? validatePolicy : null};
})();
"""


def _policy_schema():
    """The parts of the record schema the policy validator reads (type, enum,
    items, properties), for the page's copy of it."""
    from .verify import load_schema

    def trim(node):
        out = {}
        for k in ("type", "enum"):
            if k in node:
                out[k] = node[k]
        if isinstance(node.get("items"), dict):
            out["items"] = trim(node["items"])
        if isinstance(node.get("properties"), dict):
            out["properties"] = {k: trim(v) for k, v in node["properties"].items()}
        return out
    return trim(load_schema())


def render_js(with_policy=True):
    """RENDER_JS with its shared constants filled in from this module. Without
    a policy, the policy evaluator and panel are left out of the page."""
    from .policy import _FOOT_PAGE, POLICY_DIGEST_NOTE, RULE_KEYS, SEVERITIES
    st_note = {}
    # The provenance notes come from provenance() itself so the two cannot drift.
    def _note(recs):
        out = provenance(recs)
        return out[out.index('<div class="note prov-note">') + len('<div class="note prov-note">'):-len("</div>")]
    cap = [{"source": {"adapter": "a", "capture": "captured"}}]
    ing = [{"source": {"adapter": "b", "capture": "ingested"}}]
    st_note["mixed"], st_note["ing"], st_note["cap"] = _note(cap + ing), _note(ing), _note(cap)
    js = RENDER_JS
    if not with_policy:
        js = js[:js.index("/*POLICY-BEGIN*/")] + js[js.index("/*POLICY-END*/"):]
    return js % {
        "cap_title": json.dumps(CAP_TITLE),
        "plain_keys": json.dumps(list(PLAIN_KEYS)),
        "plain_verb": json.dumps(PLAIN_VERB),
        "foot_page": json.dumps(_FOOT_PAGE),
        "digest_note": json.dumps(POLICY_DIGEST_NOTE),
        "schema": json.dumps(_policy_schema()),
        "rule_keys": json.dumps(list(RULE_KEYS)),
        "severities": json.dumps(list(SEVERITIES)),
        "note_mixed": json.dumps(st_note["mixed"]),
        "note_ing": json.dumps(st_note["ing"]),
        "note_cap": json.dumps(st_note["cap"]),
    }
