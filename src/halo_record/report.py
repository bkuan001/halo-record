"""Render one tenant's runtime record as a shareable, self-verifying web page.

``halo report customer.jsonl -o customer.html`` produces a single self-contained
HTML file (no build step, no external JS) that:

  * presents what the agent did — every recorded action, its authorization,
    scope, and outcome — as a procurement-facing Runtime Report, and
  * re-verifies the hash chain in the *viewer's own browser* (SHA-256 over
    RFC 8785 canonical JSON, mirroring the Python verifier), so the reader
    confirms tamper-evidence themselves without trusting any server.

It renders exactly one chain — i.e. one ``subject``/customer — so a report is
safe to share with that customer and no other (segmentation by construction).
"""

import ast
import html
import json
import os

from .canon import GENESIS_PREV


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    records = []
    for n, ln in enumerate(lines, start=1):
        try:
            records.append(json.loads(ln))
        except json.JSONDecodeError as e:
            raise ValueError(
                "record %d is not valid JSON (%s) — run `halo verify %s` for "
                "the full picture" % (n, e, path)) from e
    return records


def _subject_label(records):
    for r in records:
        s = r.get("subject")
        if isinstance(s, dict) and (s.get("name") or s.get("id")):
            return s.get("name") or s.get("id")
    return "Agent runtime"


def _subject_id(records):
    for r in records:
        s = r.get("subject")
        if isinstance(s, dict) and s.get("id"):
            return s["id"]
    return None


def _agents(records):
    """Ordered distinct agent labels across the chain (a vendor often runs
    more than one agent against the same tenant)."""
    seen = []
    for r in records:
        a = r.get("agent") or {}
        label = a.get("name") or a.get("id")
        if label and label not in seen:
            seen.append(label)
    return seen


def _agent_meta(agents):
    """The header fragment: one agent keeps the classic label; a fleet is
    counted and named."""
    if not agents:
        return "Agent <b>unknown</b>"
    if len(agents) == 1:
        return "Agent <b>%s</b>" % _esc(agents[0])
    shown = ", ".join("<b>%s</b>" % _esc(a) for a in agents[:4])
    more = " (+%d more)" % (len(agents) - 4) if len(agents) > 4 else ""
    return "%d agents: %s%s" % (len(agents), shown, more)


def _fmt_ts(ts):
    return (ts or "").replace("T", " ").replace("+00:00", "Z")[:19]


def chain_breaks(records):
    """Indices of records whose sealed hash or predecessor link does not hold.

    Operates on a list rather than a file so a *window* can be verified on its
    own terms: each record's hash is recomputed against the predecessor it
    declares, and consecutive records must link. A window legitimately starts
    mid-chain, so the first record's `prev_hash` is taken as its anchor and is
    not compared to genesis — anchoring the window to the wider chain is a
    separate claim, made by the witness, not by this function.
    """
    from .canon import compute_hash
    bad = []
    for i, r in enumerate(records):
        integ = r.get("integrity") or {}
        declared_prev = integ.get("prev_hash")
        if integ.get("hash") != compute_hash(r, declared_prev):
            bad.append(i)
        elif i and declared_prev != ((records[i - 1].get("integrity") or {}).get("hash")):
            bad.append(i)
    return bad


def _summary_stats(records):
    tools, scopes, severities = {}, set(), {}
    times = []
    for r in records:
        action = r.get("action", {})
        tool = action.get("tool") or action.get("type") or "—"
        tools[tool] = tools.get(tool, 0) + 1
        scope = (action.get("authorization") or {}).get("scope")
        if scope:
            scopes.add(scope)
        sev = r.get("severity", "INFO")
        severities[sev] = severities.get(sev, 0) + 1
        if r.get("ts"):
            times.append(r["ts"])
    times.sort()
    return {
        "total": len(records),
        "tools": tools,
        "scopes": sorted(scopes),
        "severities": severities,
        "start": _fmt_ts(times[0]) if times else "—",
        "end": _fmt_ts(times[-1]) if times else "—",
    }


def _esc(x):
    return html.escape(str(x), quote=True)


# How each provenance tier reads to a buyer — kept short for the cell tooltip.
_CAP_TITLE = {
    "captured": "Declared captured at the boundary — per this record's own source tag, "
                "Halo observed the call directly. The tag is set by the integration, "
                "not independently verified.",
    "ingested": "Ingested from telemetry the vendor already emits — the witness "
                "attests \"this is the stream you sent me\", not \"I watched it happen\".",
}


def _provenance(records):
    """Tally records by their on-ramp (``source.adapter``) and evidentiary tier
    (``source.capture``). Returns (panel_html, present, n_captured, n_ingested).
    Records with no ``source`` are skipped, so legacy reports render unchanged."""
    buckets = {}
    for r in records:
        s = r.get("source")
        if not isinstance(s, dict):
            continue
        a = s.get("adapter") or "unknown"
        b = buckets.setdefault(a, {"via": s.get("via") or a,
                                   "capture": s.get("capture") or "ingested", "n": 0})
        b["n"] += 1
    if not buckets:
        return "", False, 0, 0
    order = {"captured": 0, "ingested": 1}
    items = sorted(buckets.items(),
                   key=lambda kv: (order.get(kv[1]["capture"], 2), -kv[1]["n"]))
    n_cap = sum(b["n"] for b in buckets.values() if b["capture"] == "captured")
    n_ing = sum(b["n"] for b in buckets.values() if b["capture"] == "ingested")
    cells = []
    for _, b in items:
        tier = "cap" if b["capture"] == "captured" else "ing"
        label = "Captured" if b["capture"] == "captured" else "Ingested"
        cells.append(
            '<div class="prov" title="%s">'
            '<span class="pill %s">%s</span>'
            '<span class="prov-via">%s</span>'
            '<span class="prov-n">%d action%s</span>'
            "</div>" % (
                _esc(_CAP_TITLE.get(b["capture"], "")), tier, label,
                _esc(b["via"]), b["n"], "" if b["n"] == 1 else "s"))
    panel = '<div class="provgrid">%s</div>' % "".join(cells)
    return panel, True, n_cap, n_ing


_PLAIN_VERB = {
    "tool_call": "Ran", "network": "Fetched", "read": "Read",
    "write": "Wrote", "agent_message": "Messaged",
}

# The field in a tool's arguments that a reader actually wants to see first.
_PLAIN_KEYS = ("command", "file_path", "url", "query", "description", "path",
               "pattern", "prompt", "to", "summary", "task_id")


def _plain(r):
    """One line a non-engineer can read: what this action did, in words.

    The recorded summary is a serialized argument blob — precise, and unreadable
    at a glance. This picks the argument that carries the meaning (the command,
    the file, the URL) and states it as a sentence. It is a *view* of the record,
    never a replacement: the full summary and its hash stay on the record.
    """
    action = r.get("action") or {}
    tool = action.get("tool") or action.get("type") or "action"
    # An outcome summary is already a human sentence — prefer it outright over
    # reconstructing one from the input arguments.
    outcome_summary = (r.get("outcome") or {}).get("summary") or ""
    if outcome_summary and not outcome_summary.startswith("{"):
        return " ".join(outcome_summary.split())
    summary = (action.get("input") or {}).get("summary") or ""
    detail = ""
    if summary.startswith("{"):
        try:
            parsed = ast.literal_eval(summary)
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            for key in _PLAIN_KEYS:
                if parsed.get(key):
                    detail = str(parsed[key])
                    break
            # No meaningful argument found: name the tool rather than echoing
            # an arbitrary value (the first dict value is often the tenant id).
        else:
            detail = summary
    else:
        detail = summary
    detail = " ".join(detail.split())
    if not detail:
        return "Ran %s" % tool
    verb = _PLAIN_VERB.get(action.get("type"), "Ran")
    if action.get("type") == "network" and not str(tool).lower().startswith(("http", "web", "fetch")):
        verb = "Ran"  # "Fetched" is only honest for actual fetch-shaped tools
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


def _row(r, show_agent=False):
    action = r.get("action", {})
    auth = action.get("authorization") or {}
    outcome = r.get("outcome") or {}
    findings = r.get("findings") or []
    status = outcome.get("status", "—")
    sev = r.get("severity", "INFO")
    summary = (action.get("input") or {}).get("summary") or outcome.get("summary") or ""
    short_hash = (r.get("integrity") or {}).get("hash", "")[:12]
    # "no flags" — not "clean": an empty findings list means no redaction
    # pattern matched, which is not a guarantee that no sensitive data is
    # present (unstructured PII has no pattern; see LIMITS.md).
    finding_cell = (
        '<span class="pill warn" title="redaction patterns that matched">%d</span>' % len(findings)
        if findings else
        '<span class="pill ok" title="no redaction pattern matched; not a guarantee no sensitive data is present">no flags</span>'
    )
    src = r.get("source") or {}
    cap = src.get("capture")
    if cap in ("captured", "ingested"):
        tier = "cap" if cap == "captured" else "ing"
        source_cell = '<span class="pill %s" title="%s">%s</span>' % (
            tier, _esc(_CAP_TITLE.get(cap, "")), _esc(src.get("adapter") or cap))
    else:
        source_cell = '<span class="dim">—</span>'
    a = r.get("agent") or {}
    agent_cell = ('<td class="mono">%s</td>' % _esc(a.get("name") or a.get("id") or "—")
                  if show_agent else "")
    # Filter/sort keys ride on the row itself so the table stays searchable
    # without re-parsing the embedded JSON. `data-text` is the haystack for
    # free-text search: everything a reader would plausibly search for.
    haystack = " ".join(str(x) for x in (
        r.get("ts"), action.get("tool"), action.get("type"), auth.get("scope"),
        auth.get("decision"), status, sev, summary, outcome.get("summary"),
        (r.get("agent") or {}).get("name"), short_hash,
    ) if x).lower()
    plain = _plain(r)
    row_attrs = (
        ' data-ts="%s" data-tool="%s" data-type="%s" data-sev="%s"'
        ' data-status="%s" data-flags="%d" data-rid="%s" data-text="%s"'
    ) % (
        _esc(r.get("ts") or ""),
        _esc(action.get("tool") or "—"),
        _esc(action.get("type") or "—"),
        _esc(sev),
        _esc(status),
        len(findings),
        _esc(r.get("record_id") or ""),
        _esc((haystack + " " + plain.lower())),
    )
    return (
        '<tr%s tabindex="0" class="rowclick" title="Click for the full record">'
        '<td class="mono dim ts-cell">%s</td>'
        "%s"
        '<td class="mono">%s</td>'
        '<td>%s</td>'
        '<td>%s</td>'
        '<td class="mono">%s</td>'
        '<td><span class="pill %s">%s</span></td>'
        '<td><span class="pill %s">%s</span></td>'
        '<td>%s</td>'
        '<td class="trunc dim">%s</td>'
        '<td class="mono dim">%s</td>'
        "</tr>"
    ) % (
        row_attrs,
        _esc(_fmt_ts(r.get("ts"))),
        agent_cell,
        _esc(action.get("tool") or "—"),
        _esc(action.get("type") or "—"),
        source_cell,
        _esc(auth.get("scope") or "—"),
        "ok" if auth.get("decision") == "allowed" else "warn",
        _esc(auth.get("decision") or "—"),
        "ok" if status == "ok" else ("warn" if status == "error" else "neutral"),
        _esc(status),
        finding_cell,
        _esc(plain[:110]),
        _esc(short_hash),
    )


_VERIFY_JS = r"""
const GENESIS = "%(genesis)s";
const WINDOW = %(window_json)s;
function canon(v){
  if (v === true) return "true";
  if (v === false) return "false";
  if (v === null) return "null";
  const t = typeof v;
  if (t === "string") return JSON.stringify(v);
  if (t === "number") return String(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(v).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
  }
  throw new Error("cannot canonicalize");
}
function hex(buf){
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function recordHash(rec, prev){
  const clone = JSON.parse(JSON.stringify(rec));
  clone.integrity = clone.integrity || {};
  clone.integrity.prev_hash = prev;
  delete clone.integrity.hash;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canon(clone)));
  return hex(digest);
}
async function verify(records){
  let prev = GENESIS;
  for (let i = 0; i < records.length; i++){
    const r = records[i], integ = r.integrity || {};
    if (integ.prev_hash !== prev) return {ok:false, at:i+1, why:"chain break (prev_hash)"};
    const got = await recordHash(r, prev);
    if (got !== integ.hash) return {ok:false, at:i+1, why:"hash mismatch"};
    prev = integ.hash;
  }
  return {ok:true, head:prev};
}
function completeness(records, cps){
  // Assumes the chain already verified. Mirrors anchor.verify_completeness:
  // every head the notary independently witnessed must still be present here.
  // In a windowed report only the checkpoints that land inside the window can
  // be re-checked in the browser; the ones before/beyond it are disclosed.
  if (!cps.length) return {ok:null};
  const latest = Math.max.apply(null, cps.map(c => c.count));
  if (!WINDOW && records.length < latest)
    return {ok:false, why:"truncated below witnessed length", have:records.length, witnessed:latest};
  let inWin = 0, before = 0, beyond = 0;
  for (const c of cps){
    const n = c.count;
    if (WINDOW){
      if (n < WINDOW.first){ before++; continue; }
      if (n > WINDOW.last){ beyond++; continue; }
      const h = (records[n - WINDOW.first].integrity || {}).hash;
      if (h !== c.head) return {ok:false, why:"record altered or dropped before witnessed point", at:n};
      inWin++;
    } else {
      if (n < 1 || n > records.length) return {ok:false, why:"witnessed count out of range", at:n};
      const h = (records[n-1].integrity || {}).hash;
      if (h !== c.head) return {ok:false, why:"record altered or dropped before witnessed point", at:n};
    }
  }
  if (WINDOW && !inWin)
    return {ok:null, windowed:true, before:before, beyond:beyond};
  return {ok:true, witnessed:cps.length, latest:latest, inWin:inWin, before:before, beyond:beyond};
}
async function liveCheckpoints(cfg, embedded){
  // Completeness must be checked against the notary, not against checkpoints the
  // vendor embedded in (and served with) this page. When a hosted Halo witness
  // is configured, fetch its checkpoints directly (CORS-open) so the verdict
  // rests on a party the vendor doesn't control. Fall back to the embedded
  // snapshot only if the live witness is unreachable.
  if (!cfg.witnessUrl) return {cps: embedded, live: false, error: null};
  try {
    const base = cfg.witnessUrl.replace(/\/+$/, "");
    const u = base + "/v1/checkpoints" + (cfg.subject ? "?subject=" + encodeURIComponent(cfg.subject) : "");
    const resp = await fetch(u, {mode: "cors"});
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();
    return {cps: data.checkpoints || [], live: true, error: null};
  } catch (e){
    return {cps: embedded, live: false, error: e.message};
  }
}
(async function(){
  const el = document.getElementById("verdict");
  const cel = document.getElementById("completeness");
  const records = JSON.parse(document.getElementById("records").textContent);
  const embedded = JSON.parse(document.getElementById("checkpoints").textContent);
  const cfg = JSON.parse(document.getElementById("halo-config").textContent);
  if (!(window.crypto && crypto.subtle)){
    el.className = "verdict neutral";
    el.innerHTML = "Self-verification needs a secure context — serve this page over https or localhost to re-check the chain in your browser.";
    return;
  }
  try {
    if (!records.length){
      el.className = "verdict neutral";
      el.innerHTML = "0 records — an empty chain; nothing to attest.";
      if (cel){ cel.className = "verdict neutral"; cel.innerHTML = "No records to check for completeness."; }
      return;
    }
    const res = await verify(records);
    window.__haloVerify = res;  // the drawer's chain-position note reads this
    if (res.ok && WINDOW){
      el.className = "verdict ok";
      el.innerHTML = "&#10003; Verified in your browser — records " + WINDOW.first +
        "&ndash;" + WINDOW.last + " of " + WINDOW.total +
        ", window chain intact relative to its anchor. <span class='dim'>window head " +
        res.head.slice(0,16) + "&hellip;</span>";
    } else if (res.ok){
      el.className = "verdict ok";
      el.innerHTML = "&#10003; Verified in your browser — " + records.length +
        " records, hash chain intact. <span class='dim'>chain head " +
        res.head.slice(0,16) + "&hellip;</span>";
    } else {
      el.className = "verdict fail";
      el.innerHTML = "&#10007; Verification FAILED at record " + res.at + " (" + res.why + ").";
      return;
    }
  } catch (e){
    el.className = "verdict fail";
    el.textContent = "Verification error: " + e.message;
    return;
  }
  if (!cel) return;
  const src = await liveCheckpoints(cfg, embedded);
  const comp = completeness(records, src.cps);
  const witness = src.live ? "the live witness log" : "the witness log embedded in this report";
  const note = src.error
    ? " <span class='dim'>(couldn't reach the live witness — checked the embedded snapshot instead)</span>"
    : "";
  if (comp.ok === null && comp.windowed){
    cel.className = "verdict neutral";
    cel.innerHTML = "No witness checkpoint falls inside this window — window integrity is " +
      "verified against its anchor above" +
      (comp.beyond ? "; the chain is witnessed beyond this window" : "") +
      (comp.before ? "; " + comp.before + " checkpoint(s) precede the window" : "") +
      "." + note;
  } else if (comp.ok === null){
    cel.className = "verdict open";
    cel.innerHTML = "<b>Not yet anchored.</b> No independent witness exists for this report — " +
      "completeness rests on the vendor alone until the chain is witnessed. " +
      "Integrity is verified above; completeness is not." + note;
  } else if (comp.ok && WINDOW){
    cel.className = "verdict neutral";
    cel.innerHTML = (src.live
        ? "Consistent within window &mdash; "
        : "Self-attested &mdash; the checkpoint was supplied with this report by its operator, so treat completeness as self-attested until a witness outside the operator confirms it. Within the window it is consistent: ") +
      witness + " confirmed " + comp.inWin +
      " checkpoint(s) inside this window" +
      (comp.beyond ? "; chain continues beyond the window (witnessed to record " + comp.latest + ")" : "") +
      (comp.before ? "; " + comp.before + " earlier checkpoint(s) precede it" : "") +
      ". No witnessed record in this window has been dropped or altered." +
      (src.live
        ? " Whether this counts as independent verification depends on who operates the witness at " + String(cfg.witnessUrl || "the configured URL").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") + " &mdash; treat it as self-attested unless that party is outside the operator's control."
        : "") + note;
  } else if (comp.ok){
    cel.className = "verdict neutral";
    cel.innerHTML = (src.live
        ? "Consistent &mdash; "
        : "Self-attested &mdash; the checkpoint was supplied with this report by its operator, so treat completeness as self-attested until a witness outside the operator confirms it. Against that checkpoint the chain is consistent: ") +
      witness + " confirmed " + comp.witnessed +
      " checkpoint(s) up to record " + comp.latest +
      ". No record the notary saw has been dropped or altered." +
      (src.live
        ? " Whether this counts as independent verification depends on who operates the witness at " + String(cfg.witnessUrl || "the configured URL").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") + " &mdash; treat it as self-attested unless that party is outside the operator's control."
        : "") + note;
  } else {
    cel.className = "verdict fail";
    cel.innerHTML = "&#10007; INCOMPLETE &mdash; conflicts with " + witness + " (" +
      comp.why + (comp.at ? " at record " + comp.at : "") + ")." + note;
  }
})();
"""


# Activity rows are rendered newest-first. The first batch sits in the table;
# the rest wait in an inert <template> and stream in as the reader scrolls, so
# the page stays responsive on multi-thousand-record chains while row rendering
# stays entirely in Python (the template holds ready-made rows, not data).
_ROW_BATCH = 100

_PAGINATE_JS = r"""
(function(){
  var tbody = document.getElementById("activity-body");
  var tpl = document.getElementById("more-rows");
  var wrap = document.getElementById("tablewrap");
  var counter = document.getElementById("rowcount");
  var sentinel = document.getElementById("more-sentinel");
  if (!tbody || !tpl || !wrap || !sentinel) return;
  var BATCH = 100;

  /* One array owns every row; the table body is a rendered view of the
     filtered+sorted subset. Rows never go back into the template. */
  var ALL = [];
  Array.prototype.push.apply(ALL, tbody.querySelectorAll("tr"));
  Array.prototype.push.apply(ALL, tpl.content.querySelectorAll("tr"));
  ALL = ALL.filter(function(r){ return r.hasAttribute("data-ts"); });
  if (!ALL.length) return;
  tpl.remove();

  var view = ALL.slice();     // current filtered+sorted set
  var drawn = 0;              // how many of `view` are in the DOM

  /* --- local time -------------------------------------------------------
     Records are sealed in UTC. A reader investigating "what happened at 3pm"
     means their own 3pm, so the displayed time follows the viewer's clock by
     default, with UTC one click away. The underlying record is untouched. */
  var localMode = true;
  var TZ = "";
  try {
    TZ = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  } catch (e) { TZ = ""; }
  function pad(n){ return (n < 10 ? "0" : "") + n; }
  function stamp(iso){
    if (!localMode) return String(iso).replace("T", " ").replace("+00:00", "Z").slice(0, 19);
    var d = new Date(iso);
    if (isNaN(d)) return String(iso).slice(0, 19);
    return d.getFullYear() + "-" + pad(d.getMonth()+1) + "-" + pad(d.getDate()) + " " +
           pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function paintTimes(){
    for (var i = 0; i < ALL.length; i++){
      var cell = ALL[i].querySelector(".ts-cell");
      if (cell) cell.textContent = stamp(ALL[i].getAttribute("data-ts"));
    }
    var th = document.getElementById("th-time");
    if (th) th.firstChild.textContent = localMode
      ? ("Time (" + (TZ || "local") + ")") : "Time (UTC)";
    var btn = document.getElementById("tz-toggle");
    if (btn) btn.textContent = localMode ? "Show UTC" : "Show local time";
  }

  /* --- filtering -------------------------------------------------------- */
  var q = document.getElementById("f-q");
  var fTool = document.getElementById("f-tool");
  var fType = document.getElementById("f-type");
  var fSev = document.getElementById("f-sev");
  var fFrom = document.getElementById("f-from");
  var fTo = document.getElementById("f-to");
  var fFlags = document.getElementById("f-flags");
  var fReset = document.getElementById("f-reset");

  function fillOptions(sel, attr){
    if (!sel) return;
    var seen = {}, vals = [];
    for (var i = 0; i < ALL.length; i++){
      var v = ALL[i].getAttribute(attr);
      if (v && !seen[v]){ seen[v] = 1; vals.push(v); }
    }
    vals.sort();
    for (var j = 0; j < vals.length; j++){
      var o = document.createElement("option");
      o.value = vals[j]; o.textContent = vals[j];
      sel.appendChild(o);
    }
  }
  fillOptions(fTool, "data-tool");
  fillOptions(fType, "data-type");

  /* Datetime-local inputs are read in the same frame as the displayed time,
     so a range typed against local timestamps selects what the reader sees. */
  function bound(input){
    if (!input || !input.value) return null;
    var d = localMode ? new Date(input.value) : new Date(input.value + "Z");
    return isNaN(d) ? null : d.getTime();
  }
  function matches(row){
    if (q && q.value.trim()){
      var terms = q.value.toLowerCase().split(/\s+/);
      var hay = row.getAttribute("data-text") || "";
      for (var i = 0; i < terms.length; i++)
        if (terms[i] && hay.indexOf(terms[i]) === -1) return false;
    }
    if (fTool && fTool.value && row.getAttribute("data-tool") !== fTool.value) return false;
    if (fType && fType.value && row.getAttribute("data-type") !== fType.value) return false;
    if (fSev && fSev.value && row.getAttribute("data-sev") !== fSev.value) return false;
    if (fFlags && fFlags.checked && row.getAttribute("data-flags") === "0") return false;
    var lo = bound(fFrom), hi = bound(fTo);
    if (lo !== null || hi !== null){
      var t = new Date(row.getAttribute("data-ts")).getTime();
      if (isNaN(t)) return false;
      if (lo !== null && t < lo) return false;
      if (hi !== null && t > hi) return false;
    }
    return true;
  }

  /* --- sorting ---------------------------------------------------------- */
  var sortKey = "data-ts", sortDir = -1;   // newest first, as rendered
  function cmp(a, b){
    var av = a.getAttribute(sortKey) || "", bv = b.getAttribute(sortKey) || "";
    if (sortKey === "data-flags"){ av = +av; bv = +bv; }
    if (sortKey === "data-sev"){
      var rank = {INFO:0, LOW:1, MEDIUM:2, HIGH:3, CRITICAL:4};
      av = rank[av] === undefined ? -1 : rank[av];
      bv = rank[bv] === undefined ? -1 : rank[bv];
    }
    if (av < bv) return -sortDir;
    if (av > bv) return sortDir;
    return 0;
  }

  function render(){
    tbody.textContent = "";
    drawn = 0;
    draw();
    if (wrap) wrap.scrollTop = 0;
  }
  function draw(){
    var frag = document.createDocumentFragment();
    var end = Math.min(drawn + BATCH, view.length);
    for (var i = drawn; i < end; i++) frag.appendChild(view[i]);
    tbody.appendChild(frag);
    drawn = end;
    update();
  }
  function update(){
    if (!counter) return;
    var filtered = view.length !== ALL.length;
    counter.textContent = "Showing " + drawn + " of " + view.length + " actions" +
      (filtered ? " (filtered from " + ALL.length + ")" : "") +
      (drawn < view.length ? " — scroll the table for more" : "");
  }
  function apply(){
    view = ALL.filter(matches);
    view.sort(cmp);
    render();
  }

  var heads = document.querySelectorAll("th[data-sort]");
  for (var h = 0; h < heads.length; h++){
    (function(th){
      th.setAttribute("tabindex", "0");
      th.setAttribute("role", "button");
      th.setAttribute("aria-sort", th.getAttribute("data-active") === "desc" ? "descending" : "none");
      var activate = function(){
        var key = th.getAttribute("data-sort");
        if (sortKey === key) sortDir = -sortDir;
        else { sortKey = key; sortDir = (key === "data-ts") ? -1 : 1; }
        for (var k = 0; k < heads.length; k++){
          heads[k].removeAttribute("data-active");
          heads[k].setAttribute("aria-sort", "none");
        }
        th.setAttribute("data-active", sortDir > 0 ? "asc" : "desc");
        th.setAttribute("aria-sort", sortDir > 0 ? "ascending" : "descending");
        apply();
      };
      th.addEventListener("click", activate);
      th.addEventListener("keydown", function(e){
        if (e.key === "Enter" || e.key === " " || e.key === "Spacebar"){
          e.preventDefault();
          activate();
        }
      });
    })(heads[h]);
  }

  var inputs = [q, fTool, fType, fSev, fFrom, fTo, fFlags];
  for (var n = 0; n < inputs.length; n++){
    if (!inputs[n]) continue;
    inputs[n].addEventListener(inputs[n] === q ? "input" : "change", apply);
  }
  if (fReset) fReset.addEventListener("click", function(){
    if (q) q.value = "";
    if (fTool) fTool.value = "";
    if (fType) fType.value = "";
    if (fSev) fSev.value = "";
    if (fFrom) fFrom.value = "";
    if (fTo) fTo.value = "";
    if (fFlags) fFlags.checked = false;
    apply();
  });
  var tz = document.getElementById("tz-toggle");
  if (tz) tz.addEventListener("click", function(){
    localMode = !localMode;
    paintTimes();
    apply();
  });

  if ("IntersectionObserver" in window){
    var io = new IntersectionObserver(function(entries){
      for (var i = 0; i < entries.length; i++)
        if (entries[i].isIntersecting && drawn < view.length){ draw(); break; }
    }, {root: wrap, rootMargin: "600px"});
    io.observe(sentinel);
  } else {
    wrap.addEventListener("scroll", function(){
      if (drawn < view.length &&
          wrap.scrollTop + wrap.clientHeight > wrap.scrollHeight - 600) draw();
    });
  }

  /* --- record detail ----------------------------------------------------
     A row is a summary; the record is the evidence. Clicking a row opens the
     whole sealed record — every field, the findings that matched, and the
     hash linkage a reader can check by hand against the JSONL. */
  var RECORDS = [];
  try {
    RECORDS = JSON.parse(document.getElementById("records").textContent) || [];
  } catch (e) { RECORDS = []; }
  var byId = {};
  for (var ri = 0; ri < RECORDS.length; ri++){
    var rid = RECORDS[ri].record_id;
    if (rid) byId[rid] = ri;
  }
  var panel = document.getElementById("detail");
  var panelBody = document.getElementById("detail-body");
  var panelClose = document.getElementById("detail-close");

  function esc(s){
    return String(s === undefined || s === null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  function field(label, value, mono){
    if (value === undefined || value === null || value === "") return "";
    return '<div class="d-row"><div class="d-k">' + esc(label) + '</div>' +
           '<div class="d-v' + (mono ? " mono" : "") + '">' + esc(value) + '</div></div>';
  }
  function openDetail(rid){
    var idx = byId[rid];
    if (idx === undefined || !panel || !panelBody) return;
    var r = RECORDS[idx];
    var a = r.action || {}, auth = a.authorization || {}, o = r.outcome || {},
        integ = r.integrity || {}, inp = a.input || {}, f = r.findings || [];
    var prev = idx > 0 ? RECORDS[idx - 1] : null;
    var linkOk = prev ? ((prev.integrity || {}).hash === integ.prev_hash) : null;

    var h = "";
    h += '<div class="d-plain">' + esc(document.querySelector('tr[data-rid="' +
         rid.replace(/"/g, "") + '"] td:nth-last-child(2)').textContent) + "</div>";
    h += '<div class="d-sec">When</div>';
    h += field("Recorded at", stamp(r.ts) + (localMode ? " (your time)" : " (UTC)"));
    h += field("Sealed timestamp", r.ts, true);
    h += '<div class="d-sec">What ran</div>';
    h += field("Tool", a.tool);
    h += field("Action type", a.type);
    h += field("Category", a.category);
    h += field("Agent", (r.agent || {}).name || (r.agent || {}).id);
    h += field("Session", r.session_id, true);
    h += '<div class="d-sec">Arguments (as recorded)</div>';
    h += '<pre class="d-pre">' + esc(inp.summary || "(none recorded)") + "</pre>";
    h += field("Argument hash", inp.hash, true);
    h += '<div class="d-sec">Permission</div>';
    h += field("Scope", auth.scope);
    h += field("Decision", auth.decision);
    h += field("Approver", auth.approver);
    h += '<div class="d-sec">Result</div>';
    h += field("Status", o.status);
    if (o.summary){ h += '<pre class="d-pre">' + esc(o.summary) + "</pre>"; }
    h += field("Result hash", o.hash, true);
    h += '<div class="d-sec">Flags (' + f.length + ")</div>";
    if (!f.length){
      h += '<div class="d-note">No redaction pattern matched. That is not a ' +
           "guarantee no sensitive data is present — unstructured personal data " +
           "has no pattern to match.</div>";
    } else {
      for (var i = 0; i < f.length; i++){
        h += '<div class="d-row"><div class="d-k">' + esc(f[i].type || "?") +
             '</div><div class="d-v">' + esc(f[i].severity || "") +
             (f[i].sample ? ' &middot; <span class="mono">' + esc(f[i].sample) + "</span>" : "") +
             "</div></div>";
      }
      h += '<div class="d-note">A flag marks a pattern the redactor matched and ' +
           "masked in the stored summary. The sample above is already masked.</div>";
    }
    h += '<div class="d-sec">Chain position</div>';
    h += field("Record id", r.record_id, true);
    h += field("This record's hash", integ.hash, true);
    h += field("Points back to", integ.prev_hash, true);
    // The declared-linkage check below compares this record's prev_hash to the
    // PREVIOUS record's DECLARED hash — file order only. The cryptographic
    // verdict belongs to the page-level verification; if that failed at or
    // before this record, the declared linkage means nothing and must not
    // render as a green check.
    var pageVerify = window.__haloVerify;
    var brokenHere = pageVerify && pageVerify.ok === false &&
                     typeof pageVerify.at === "number" && (idx + 1) >= pageVerify.at;
    if (brokenHere){
      h += '<div class="d-note bad">✗ Chain verification failed at record ' +
           pageVerify.at + " — this record's position cannot be verified " +
           "(declared links after a break prove nothing; see the banner).</div>";
    } else if (linkOk !== null){
      h += '<div class="d-note' + (linkOk ? " ok" : " bad") + '">' +
           (linkOk
             ? "✓ prev_hash matches the preceding record's declared hash (file order — the cryptographic verdict is the banner above)."
             : "✗ Does not match the previous record's hash in this file.") +
           "</div>";
    } else {
      h += '<div class="d-note">First record in this file — its predecessor is ' +
           "outside the exported window.</div>";
    }
    panelBody.innerHTML = h;
    panel.classList.add("open");
    panel.setAttribute("aria-hidden", "false");
  }
  function closeDetail(){
    if (!panel) return;
    panel.classList.remove("open");
    panel.setAttribute("aria-hidden", "true");
  }
  tbody.addEventListener("click", function(ev){
    var tr = ev.target.closest("tr[data-rid]");
    if (tr) openDetail(tr.getAttribute("data-rid"));
  });
  tbody.addEventListener("keydown", function(ev){
    if (ev.key !== "Enter" && ev.key !== " ") return;
    var tr = ev.target.closest("tr[data-rid]");
    if (tr){ ev.preventDefault(); openDetail(tr.getAttribute("data-rid")); }
  });
  if (panelClose) panelClose.addEventListener("click", closeDetail);
  document.addEventListener("keydown", function(ev){
    if (ev.key === "Escape") closeDetail();
  });

  paintTimes();
  apply();
})();
"""


_STYLE = """
:root{--ink:#1a1714;--dim:#8a7f74;--line:#ece5db;--bg:#fbf8f3;--gold:#b8860b;
--gold-soft:#f3e9cf;--ok:#2f7d4f;--ok-bg:#e6f1ea;--warn:#9a5b00;--warn-bg:#f7ecd9;
--fail:#a3302a;--fail-bg:#f6e3e1;--neutral-bg:#eee8df;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font-family:"Instrument Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
line-height:1.5;-webkit-font-smoothing:antialiased}
.wrap{max-width:1020px;margin:0 auto;padding:56px 28px 80px}
.eyebrow{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--gold);font-weight:600}
h1{font-family:"Instrument Serif",Georgia,serif;font-weight:400;font-size:46px;
line-height:1.05;margin:10px 0 6px;letter-spacing:-.01em}
.meta{color:var(--dim);font-size:14px;margin-bottom:10px}
.meta b{color:var(--ink);font-weight:600}
/* "What period does this cover?" is the first question an assessor asks of an
   evidence artifact, so the span the records actually cover gets its own line
   instead of sitting mid-sentence in the metadata. */
.period{display:inline-flex;align-items:baseline;gap:8px;flex-wrap:wrap;
margin:0 0 26px;padding:8px 14px;border:1px solid var(--line);border-radius:10px;
background:#fff;font-size:15px;color:var(--ink)}
.period b{font-weight:600;font-variant-numeric:tabular-nums}
.period-l{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim);
font-weight:600}
.period-tz{font-size:12px;color:var(--dim)}
.verdict{border-radius:12px;padding:16px 20px;font-size:15px;font-weight:500;margin:0 0 28px;
border:1px solid var(--line);background:#fff}
.verdict.ok{background:var(--ok-bg);border-color:#cfe6d8;color:var(--ok)}
.verdict.fail{background:var(--fail-bg);border-color:#eccdca;color:var(--fail)}
.verdict.neutral{background:var(--neutral-bg);color:var(--dim)}
/* An un-anchored report is integrity-only: nobody outside the operator has
   attested it. That is the single most consequential limit on the page, so it
   is styled as an open question rather than as neutral chrome — it should
   read as unresolved, never as a passing state. */
.verdict.open{background:var(--warn-bg);border-color:#e6d3ae;color:var(--warn)}
.verdict.open b{color:var(--warn)}
.note{font-size:13px;color:var(--dim);margin:-18px 0 30px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:34px}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.card .n{font-family:"Instrument Serif",Georgia,serif;font-size:32px;line-height:1}
.card .l{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-top:6px}
h2{font-family:"Instrument Serif",Georgia,serif;font-weight:400;font-size:24px;margin:0 0 14px}
.tablewrap{max-height:72vh;overflow:auto;background:#fff;border:1px solid var(--line);
border-radius:12px;margin-bottom:8px}
table{width:100%;min-width:960px;border-collapse:separate;border-spacing:0;font-size:13px;background:#fff}
th{text-align:left;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);
font-weight:600;padding:11px 12px;border-bottom:1px solid var(--line);background:#fdfbf7;
position:sticky;top:0;z-index:2}
td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
td:first-child{white-space:nowrap}
tbody tr:last-child td{border-bottom:none}
.rowcount{font-size:12px;color:var(--dim);margin:-6px 0 10px}
/* An assessor's first move on a large record is to narrow it: by time, by tool,
   by what got flagged. The controls sit above the table so the narrowing is
   visible in any screenshot of the result. */
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 12px}
.filters input[type=search],.filters select,.filters input[type=datetime-local]{
font:inherit;font-size:13px;color:var(--ink);background:#fff;
border:1px solid var(--line);border-radius:8px;padding:6px 9px}
.filters .f-grow{flex:1 1 260px;min-width:200px}
.filters input[type=search]:focus,.filters select:focus,
.filters input[type=datetime-local]:focus,.f-btn:focus-visible{
outline:2px solid var(--gold);outline-offset:1px}
.f-lab,.f-check{display:inline-flex;align-items:center;gap:6px;
font-size:12px;color:var(--dim)}
.f-btn{font:inherit;font-size:12px;color:var(--ink);background:#fff;cursor:pointer;
border:1px solid var(--line);border-radius:8px;padding:6px 11px}
.f-btn:hover{background:var(--gold-soft);border-color:var(--gold)}
th[data-sort]{cursor:pointer;user-select:none;white-space:nowrap}
th[data-sort]:hover{color:var(--gold)}
th[data-sort]:focus-visible{outline:2px solid var(--gold);outline-offset:2px;color:var(--gold)}
th[data-sort]::after{content:"\\2195";opacity:.3;margin-left:5px;font-size:11px}
th[data-active=asc]::after{content:"\\2191";opacity:1;color:var(--gold)}
th[data-active=desc]::after{content:"\\2193";opacity:1;color:var(--gold)}
@media print{.filters{display:none}}
tr.rowclick{cursor:pointer}
tr.rowclick:hover td{background:var(--gold-soft)}
tr.rowclick:focus-visible{outline:2px solid var(--gold);outline-offset:-2px}
/* The row answers "what happened"; the drawer answers "show me the record".
   It slides over rather than expanding inline so the reader keeps their place
   in the table. */
.detail{position:fixed;top:0;right:0;width:min(560px,92vw);height:100%;
background:#fff;border-left:1px solid var(--line);box-shadow:-8px 0 28px rgba(26,23,20,.12);
padding:22px 24px 40px;overflow:auto;transform:translateX(101%);
transition:transform .18s ease;z-index:40}
.detail.open{transform:translateX(0)}
.detail-head{display:flex;align-items:center;justify-content:space-between;
gap:12px;margin-bottom:14px}
.detail-title{font-family:"Instrument Serif",Georgia,serif;font-size:24px}
.d-plain{font-size:15px;line-height:1.45;background:var(--gold-soft);
border:1px solid #eadfc0;border-radius:10px;padding:12px 14px;margin-bottom:16px}
.d-sec{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--gold);
font-weight:600;margin:18px 0 8px;padding-bottom:5px;border-bottom:1px solid var(--line)}
.d-row{display:flex;gap:12px;padding:5px 0;font-size:13px;align-items:baseline}
.d-k{flex:0 0 150px;color:var(--dim)}
.d-v{flex:1 1 auto;word-break:break-word}
.d-pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
background:var(--bg);border:1px solid var(--line);border-radius:8px;
padding:10px 12px;white-space:pre-wrap;word-break:break-word;max-height:240px;overflow:auto}
.d-note{font-size:12px;color:var(--dim);margin-top:8px;line-height:1.5}
.d-note.ok{color:var(--ok)}
.d-note.bad{color:var(--fail)}
@media print{.detail{display:none}}
#more-sentinel{height:1px}
.mono{font-family:"SF Mono",ui-monospace,Menlo,monospace;font-size:12px}
.dim{color:var(--dim)}
.trunc{max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:600;
background:var(--neutral-bg);color:var(--ink)}
.pill.ok{background:var(--ok-bg);color:var(--ok)}
.pill.warn{background:var(--warn-bg);color:var(--warn)}
.pill.neutral{background:var(--neutral-bg);color:var(--dim)}
.pill.cap{background:var(--gold-soft);color:#7a5a04}
.pill.ing{background:var(--neutral-bg);color:var(--dim)}
.scopes{margin:2px 0 34px;display:flex;flex-wrap:wrap;gap:8px}
.scopes .pill{background:var(--gold-soft);color:#7a5a04}
@media print{.tablewrap{max-height:none;overflow:visible}}
.provgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin-bottom:14px}
.prov{display:flex;align-items:center;gap:10px;background:#fff;border:1px solid var(--line);
border-radius:10px;padding:11px 14px}
.prov .pill{flex:none}
.prov-via{font-size:13px;font-weight:500;color:var(--ink);flex:1;min-width:0}
.prov-n{font-size:12px;color:var(--dim);white-space:nowrap;margin-left:8px}
.prov-note{margin:0 0 30px}
footer{margin-top:42px;color:var(--dim);font-size:12px;text-align:center}
footer a{color:var(--gold);text-decoration:none}
@media(max-width:720px){.cards{grid-template-columns:repeat(2,1fr)}h1{font-size:36px}}
"""


def _policy_block(records, policy, subject):
    """Render the deterministic policy-corroboration verdict for the report.

    ``policy`` is a list of rule dicts. The verdict panel is computed by
    ``policy.evaluate`` from explicit rules (never a model), so it is safe to sit
    beside the integrity/completeness verdicts, which the page proves with its
    own live checks."""
    if not policy:
        return ""
    from .policy import evaluate, verdict_panel
    result = evaluate(records, policy)
    return ('<h2>Policy corroboration</h2>\n<div style="margin:0 0 30px">%s</div>'
            % verdict_panel(result, subject=subject))


def render(records, checkpoints=None, *, witness_url=None, policy=None, window=None):
    """Return the full HTML for a runtime-record report over ``records``.

    If ``checkpoints`` (a list of notary witnesses for this chain) is given, the
    page re-checks completeness in the browser against those witnesses. If
    ``witness_url`` (a hosted Halo witness) is given, the page instead fetches
    the checkpoints live from that witness — so completeness is verified against
    a party the vendor doesn't control, not the snapshot embedded in the page.
    The embedded checkpoints remain as an offline fallback.

    If ``policy`` (a list of rule dicts) is given, a deterministic
    policy-corroboration verdict is rendered beside the integrity/completeness
    verdicts.

    If ``window`` is given (see ``write_report``), the page carries only the
    windowed records: in-browser verification is seeded with the window's
    anchor (the chain head immediately before the window) instead of genesis,
    and the window's position in the full chain is disclosed on the page."""
    checkpoints = checkpoints or []
    subject = _subject_label(records)
    agents = _agents(records)
    multi_agent = len(agents) > 1
    stats = _summary_stats(records)
    # Display is newest-first; the embedded JSON stays in chain order because
    # in-browser verification walks the chain from its anchor forward.
    row_html = [_row(r, show_agent=multi_agent) for r in reversed(records)]
    if row_html:
        rows = "\n".join(row_html[:_ROW_BATCH])
        more_rows = "\n".join(row_html[_ROW_BATCH:])
        rowcount = (
            '<div class="rowcount" id="rowcount">Showing %d of %d actions, '
            "newest first%s</div>"
            % (min(len(row_html), _ROW_BATCH), len(row_html),
               " — scroll the table for more" if len(row_html) > _ROW_BATCH else ""))
        noscript = (
            '<noscript><div class="note">JavaScript is off — showing the newest '
            "%d recorded actions only; the full list and in-browser verification "
            "need JavaScript.</div></noscript>" % _ROW_BATCH
            if len(row_html) > _ROW_BATCH else "")
    else:
        rows = (
            '<tr><td colspan="%d" class="dim" style="padding:24px;text-align:center">'
            "No actions recorded yet — this report populates as the agent operates."
            "</td></tr>" % (11 if multi_agent else 10))
        more_rows = ""
        rowcount = ""
        noscript = ""
    agent_th = "<th>Agent</th>" if multi_agent else ""
    prov_panel, prov_present, n_cap, n_ing = _provenance(records)
    if prov_present:
        if n_ing and n_cap:
            prov_note = (
                "Each action is tagged with how Halo observed it. "
                "<b>Captured</b> means the record's source tag declares Halo observed the call "
                "at the boundary as it happened — the tag comes from the integration that wrote "
                "the record. <b>Ingested</b> means the record was built "
                "from telemetry the vendor already emits (a gateway, tracing store, or OTel span) — "
                "real and anchorable, but the witness attests “this is the stream you sent me,” "
                "not “I watched it happen.” The tier is disclosed, never flattened.")
        elif n_ing:
            prov_note = (
                "These records were <b>ingested</b> from telemetry the vendor already emits — "
                "real and anchorable, but the witness attests “this is the stream you sent me,” "
                "not “I watched it happen.” Source-capture would strengthen them to the "
                "<b>captured</b> tier.")
        else:
            prov_note = (
                "Every action is <b>declared captured</b> at the boundary — per each record's "
                "own source tag, Halo saw the call as it happened, so nothing could be reshaped "
                "before it was recorded. The strongest tier the source field asserts; the tag is "
                "set by the integration, not independently verified.")
        provenance_block = (
            '<h2>Captured via</h2>\n%s\n<div class="note prov-note">%s</div>'
            % (prov_panel, prov_note))
    else:
        provenance_block = ""
    policy_block = _policy_block(records, policy, subject)
    scope_pills = "".join('<span class="pill">%s</span>' % _esc(s) for s in stats["scopes"]) \
        or '<span class="dim">none</span>'
    # Escape "<" so a record value containing "</script>" can't break out of
    # the embedded JSON block. The in-browser JSON.parse reads these unchanged.
    records_json = json.dumps(records, separators=(",", ":")).replace("<", "\\u003c")
    checkpoints_json = json.dumps(checkpoints, separators=(",", ":")).replace("<", "\\u003c")
    # The completeness half of the banner only holds when the report is actually
    # anchored; an un-anchored report is integrity-only and must say so, not imply
    # a witness it never had.
    anchored = bool(checkpoints) or bool(witness_url)
    if anchored:
        integrity_note = ("This report re-computes its own SHA-256 / RFC 8785 hash chain in your "
                          "browser (integrity) and checks it against the witness checkpoints it "
                          "was anchored to (completeness). Whether completeness counts as independently "
                          "verified depends on who operates the witness — confirm that before "
                          "relying on it.")
    else:
        integrity_note = ("This report re-computes its own SHA-256 / RFC 8785 hash chain in your "
                          "browser (integrity) — you don't take that on trust. Completeness — that "
                          "no records were dropped — is <b>not yet witnessed</b>: this report is "
                          "anchored to no external witness, so completeness rests on the vendor "
                          "until one holds checkpoints for this chain (see below).")
    config_json = json.dumps(
        {"witnessUrl": witness_url, "subject": _subject_id(records)},
        separators=(",", ":")).replace("<", "\\u003c")
    if window:
        window_json = json.dumps(
            {"first": window["first"], "last": window["last"], "total": window["total"]},
            separators=(",", ":"))
        verify_js = _VERIFY_JS % {"genesis": window["anchor"] or GENESIS_PREV,
                                  "window_json": window_json}
        bounds = " to ".join(x for x in [window.get("from"), window.get("to")] if x)
        if window["last"]:
            span = "records <b>%s&ndash;%s</b> of a <b>%s</b>-record chain" % (
                window["first"], window["last"], window["total"])
        else:
            span = "<b>0</b> of the chain's <b>%s</b> records fall in this window" % window["total"]
        n_outside = window.get("outside_breaks") or 0
        if n_outside:
            # Disclosed, not hidden: the window's own integrity is what this
            # report attests, and the reader is told plainly what lies outside it.
            outside_note = (
                ' Outside this window the chain carries <b>%d</b> sequence '
                'break(s)%s; those records are not part of this report and are '
                'not covered by its verdict.'
                % (n_outside,
                   (" (%s to %s)" % (_esc(_fmt_ts(window.get("outside_first_ts"))),
                                     _esc(_fmt_ts(window.get("outside_last_ts")))))
                   if window.get("outside_first_ts") else ""))
        else:
            outside_note = (" The rest of the chain verified at generation "
                            '<span class="mono">(head %s&hellip;)</span>.'
                            % _esc((window["chain_head"] or "")[:16]))
        window_block = (
            '<div class="verdict neutral">Date-windowed report &mdash; showing %s%s. '
            'Window integrity verifies in your browser against its anchor '
            '<span class="mono">%s&hellip;</span>.%s Records outside the window are '
            'not embedded in this page.</div>'
            % (span,
               (" (%s)" % _esc(bounds)) if bounds else "",
               _esc((window["anchor"] or GENESIS_PREV)[:16]),
               outside_note))
    else:
        verify_js = _VERIFY_JS % {"genesis": GENESIS_PREV, "window_json": "null"}
        window_block = ""

    return """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%(subject)s — Runtime Report</title>
<style>%(style)s</style>
</head><body><div class="wrap">
<div class="eyebrow">Halo Runtime Report</div>
<h1>%(subject)s</h1>
<div class="meta">%(agent_meta)s &middot; <b>%(total)s</b> recorded actions</div>
<div class="period"><span class="period-l">Period covered</span>
<b>%(start)s</b> &ndash; <b>%(end)s</b> <span class="period-tz">UTC</span></div>
<div id="verdict" class="verdict neutral">Verifying hash chain&hellip;</div>
<div id="completeness" class="verdict neutral">Checking completeness against the witness checkpoints&hellip;</div>
%(window_block)s
<div class="note">%(integrity_note)s</div>
%(policy_block)s
<div class="cards">
  <div class="card"><div class="n">%(total)s</div><div class="l">Actions</div></div>
  <div class="card"><div class="n">%(ntools)s</div><div class="l">Tools</div></div>
  <div class="card"><div class="n">%(nscopes)s</div><div class="l">Scopes</div></div>
  <div class="card"><div class="n">%(nflagged)s</div><div class="l">Flagged</div></div>
</div>
<h2>Authorized scopes</h2>
<div class="scopes">%(scope_pills)s</div>
%(provenance_block)s
<h2>Activity</h2>
<div class="filters" id="filters">
  <input type="search" id="f-q" class="f-grow" placeholder="Search time, tool, scope, summary, hash&hellip;" aria-label="Search actions">
  <select id="f-tool" aria-label="Filter by tool"><option value="">All tools</option></select>
  <select id="f-type" aria-label="Filter by action type"><option value="">All types</option></select>
  <select id="f-sev" aria-label="Filter by severity">
    <option value="">Any severity</option>
    <option value="INFO">INFO</option><option value="LOW">LOW</option>
    <option value="MEDIUM">MEDIUM</option><option value="HIGH">HIGH</option>
    <option value="CRITICAL">CRITICAL</option>
  </select>
  <label class="f-lab">From <input type="datetime-local" id="f-from" step="1" aria-label="From time"></label>
  <label class="f-lab">To <input type="datetime-local" id="f-to" step="1" aria-label="To time"></label>
  <label class="f-check"><input type="checkbox" id="f-flags"> Flagged only</label>
  <button type="button" id="tz-toggle" class="f-btn">Show UTC</button>
  <button type="button" id="f-reset" class="f-btn">Reset</button>
</div>
%(rowcount)s
%(noscript)s
<div class="tablewrap" id="tablewrap">
<table>
<thead><tr><th id="th-time" data-sort="data-ts" data-active="desc">Time (UTC)</th>%(agent_th)s<th data-sort="data-tool">Tool</th><th data-sort="data-type">Type</th><th>Source</th><th>Scope</th><th>Decision</th><th data-sort="data-status">Outcome</th><th data-sort="data-flags">Findings</th><th>Summary</th><th>Hash</th></tr></thead>
<tbody id="activity-body">
%(rows)s
</tbody></table>
<div id="more-sentinel"></div>
</div>
<template id="more-rows">%(more_rows)s</template>
<aside id="detail" class="detail" aria-hidden="true" aria-label="Record detail">
  <div class="detail-head">
    <div class="detail-title">Record</div>
    <button type="button" id="detail-close" class="f-btn" aria-label="Close record detail">Close</button>
  </div>
  <div id="detail-body"></div>
</aside>
<footer>Generated by <a href="https://github.com/bkuan001/halo-record">halo-record</a> &middot; format <a href="https://github.com/bkuan001/halo-record/blob/main/src/halo_record/halo-record.schema.json">Halo Runtime Record v0.1</a></footer>
</div>
<script id="records" type="application/json">%(records_json)s</script>
<script id="checkpoints" type="application/json">%(checkpoints_json)s</script>
<script id="halo-config" type="application/json">%(config_json)s</script>
<script>%(verify_js)s</script>
<script>%(paginate_js)s</script>
</body></html>""" % {
        "subject": _esc(subject),
        "agent_meta": _agent_meta(agents),
        "agent_th": agent_th,
        "style": _STYLE,
        "start": _esc(stats["start"]),
        "end": _esc(stats["end"]),
        "total": stats["total"],
        "ntools": len(stats["tools"]),
        "nscopes": len(stats["scopes"]),
        "nflagged": sum(1 for r in records if r.get("findings")),
        "scope_pills": scope_pills,
        "integrity_note": integrity_note,
        "provenance_block": provenance_block,
        "policy_block": policy_block,
        "window_block": window_block,
        "rows": rows,
        "more_rows": more_rows,
        "rowcount": rowcount,
        "noscript": noscript,
        "records_json": records_json,
        "checkpoints_json": checkpoints_json,
        "config_json": config_json,
        "verify_js": verify_js,
        "paginate_js": _PAGINATE_JS,
    }


def write_report(log_path, out_path=None, witness_log=None, witness_url=None,
                 policy_path=None, start=None, end=None):
    """Render ``log_path`` to HTML. ``witness_log`` embeds a local notary's
    checkpoints (offline fallback / static report). ``witness_url`` points the
    page at a hosted Halo witness it fetches live, so completeness is checked
    against a party the vendor doesn't control. If both are given, the embedded
    checkpoints seed the offline fallback while the live witness is authoritative.
    ``policy_path`` adds a deterministic policy-corroboration verdict to the report.

    ``start``/``end`` (aware datetimes, inclusive) render a **date-windowed
    report** — the disclosure shape for audit periods and review windows. The
    full chain is verified first (a windowed report is refused on a chain that
    fails verification), then only the records inside the window are embedded:
    the browser re-verifies the window against its anchor (the chain head
    immediately before the window), and records outside the window never enter
    the page."""
    records = _load(log_path)
    checkpoints = None
    if witness_log:
        from .anchor import Notary
        checkpoints = Notary(witness_log).checkpoints(subject=_subject_id(records))
    elif witness_url:
        try:
            from .witness import fetch_checkpoints
            checkpoints = fetch_checkpoints(witness_url, subject=_subject_id(records))
        except Exception:
            checkpoints = None  # live fetch happens in-browser regardless
    policy = None
    if policy_path:
        from .policy import load_policy
        policy = load_policy(policy_path)
    window = None
    if start is not None or end is not None:
        from .export import in_window
        total = len(records)
        chain_head = (records[-1].get("integrity") or {}).get("hash", "") if records else ""
        idx = [i for i, r in enumerate(records) if in_window(r, start=start, end=end)]
        if idx:
            first, last = idx[0], idx[-1]
            win_records = records[first:last + 1]
            anchor = (win_records[0].get("integrity") or {}).get("prev_hash", "")
        else:
            first, last, win_records, anchor = -1, -1, [], ""

        # What the window claims is what the window must prove. A break
        # elsewhere in the chain is disclosed on the report rather than
        # withholding the window: the reader can see both facts and judge.
        # A break *inside* the requested window is still a refusal — that
        # report would assert an integrity it does not have.
        win_breaks = chain_breaks(win_records)
        if win_breaks:
            raise ValueError(
                "%s: the requested window fails verification at record(s) %s; "
                "refusing to render a report that would claim otherwise"
                % (log_path, ", ".join(str(first + 1 + n) for n in win_breaks[:5])))
        outside = [n for n in chain_breaks(records) if not (first <= n <= last)]

        window = {"first": first + 1, "last": last + 1, "total": total,
                  "anchor": anchor, "chain_head": chain_head,
                  "outside_breaks": len(outside),
                  "outside_first_ts": (records[outside[0]].get("ts") if outside else None),
                  "outside_last_ts": (records[outside[-1]].get("ts") if outside else None),
                  "from": start.isoformat() if start else None,
                  "to": end.isoformat() if end else None}
        records = win_records
    html_doc = render(records, checkpoints, witness_url=witness_url, policy=policy,
                      window=window)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(html_doc)
    return html_doc, len(records)
