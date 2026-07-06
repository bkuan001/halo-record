"""Render one tenant's runtime record as a shareable, self-verifying web page.

``halo report customer.jsonl -o customer.html`` produces a single self-contained
HTML file (no build step, no external JS) that:

  * presents what the agent did — every recorded action, its authorization,
    scope, and outcome — as a procurement-facing trust report, and
  * re-verifies the hash chain in the *viewer's own browser* (SHA-256 over
    RFC 8785 canonical JSON, mirroring the Python verifier), so the reader
    confirms tamper-evidence themselves without trusting any server.

It renders exactly one chain — i.e. one ``subject``/customer — so a report is
safe to share with that customer and no other (segmentation by construction).
"""

import html
import json
import os

from .canon import GENESIS_PREV


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh.read().splitlines() if ln.strip()]


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


def _agent_label(records):
    for r in records:
        a = r.get("agent") or {}
        if a.get("name") or a.get("id"):
            return a.get("name") or a.get("id")
    return "unknown"


def _fmt_ts(ts):
    return (ts or "").replace("T", " ").replace("+00:00", "Z")[:19]


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
    "captured": "Captured at the boundary — Halo saw this call as it happened. "
                "Strongest: nothing could be reshaped before it was recorded.",
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


def _row(r):
    action = r.get("action", {})
    auth = action.get("authorization") or {}
    outcome = r.get("outcome") or {}
    findings = r.get("findings") or []
    status = outcome.get("status", "—")
    sev = r.get("severity", "INFO")
    summary = (action.get("input") or {}).get("summary") or outcome.get("summary") or ""
    short_hash = (r.get("integrity") or {}).get("hash", "")[:12]
    finding_cell = (
        '<span class="pill warn">%d</span>' % len(findings) if findings else
        '<span class="pill ok">clean</span>'
    )
    src = r.get("source") or {}
    cap = src.get("capture")
    if cap in ("captured", "ingested"):
        tier = "cap" if cap == "captured" else "ing"
        source_cell = '<span class="pill %s" title="%s">%s</span>' % (
            tier, _esc(_CAP_TITLE.get(cap, "")), _esc(src.get("adapter") or cap))
    else:
        source_cell = '<span class="dim">—</span>'
    return (
        "<tr>"
        '<td class="mono dim">%s</td>'
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
        _esc(_fmt_ts(r.get("ts"))),
        _esc(action.get("tool") or "—"),
        _esc(action.get("type") or "—"),
        source_cell,
        _esc(auth.get("scope") or "—"),
        "ok" if auth.get("decision") == "allowed" else "warn",
        _esc(auth.get("decision") or "—"),
        "ok" if status == "ok" else ("warn" if status == "error" else "neutral"),
        _esc(status),
        finding_cell,
        _esc(summary[:90]),
        _esc(short_hash),
    )


_VERIFY_JS = r"""
const GENESIS = "%(genesis)s";
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
  if (!cps.length) return {ok:null};
  const latest = Math.max.apply(null, cps.map(c => c.count));
  if (records.length < latest)
    return {ok:false, why:"truncated below witnessed length", have:records.length, witnessed:latest};
  for (const c of cps){
    const n = c.count;
    if (n < 1 || n > records.length) return {ok:false, why:"witnessed count out of range", at:n};
    const h = (records[n-1].integrity || {}).hash;
    if (h !== c.head) return {ok:false, why:"record altered or dropped before witnessed point", at:n};
  }
  return {ok:true, witnessed:cps.length, latest:latest};
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
    const res = await verify(records);
    if (res.ok){
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
  const witness = src.live ? "Halo's live witness" : "Halo's independent witness";
  const note = src.error
    ? " <span class='dim'>(couldn't reach the live witness — checked the embedded snapshot instead)</span>"
    : "";
  if (comp.ok === null){
    cel.className = "verdict neutral";
    cel.innerHTML = "Not yet anchored — no independent witness exists for this report. " +
      "Completeness rests on the vendor alone until Halo witnesses the chain." + note;
  } else if (comp.ok){
    cel.className = "verdict ok";
    cel.innerHTML = "&#10003; Complete &mdash; " + witness + " confirmed " + comp.witnessed +
      " checkpoint(s) up to record " + comp.latest +
      ". No record the notary saw has been dropped or altered." + note;
  } else {
    cel.className = "verdict fail";
    cel.innerHTML = "&#10007; INCOMPLETE &mdash; conflicts with " + witness + " (" +
      comp.why + (comp.at ? " at record " + comp.at : "") + ")." + note;
  }
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
.meta{color:var(--dim);font-size:14px;margin-bottom:28px}
.meta b{color:var(--ink);font-weight:600}
.verdict{border-radius:12px;padding:16px 20px;font-size:15px;font-weight:500;margin:0 0 28px;
border:1px solid var(--line);background:#fff}
.verdict.ok{background:var(--ok-bg);border-color:#cfe6d8;color:var(--ok)}
.verdict.fail{background:var(--fail-bg);border-color:#eccdca;color:var(--fail)}
.verdict.neutral{background:var(--neutral-bg);color:var(--dim)}
.note{font-size:13px;color:var(--dim);margin:-18px 0 30px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:34px}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.card .n{font-family:"Instrument Serif",Georgia,serif;font-size:32px;line-height:1}
.card .l{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-top:6px}
h2{font-family:"Instrument Serif",Georgia,serif;font-weight:400;font-size:24px;margin:0 0 14px}
table{width:100%;border-collapse:collapse;font-size:13px;background:#fff;
border:1px solid var(--line);border-radius:12px;overflow:hidden}
th{text-align:left;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);
font-weight:600;padding:11px 12px;border-bottom:1px solid var(--line);background:#fdfbf7}
td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:none}
.mono{font-family:"SF Mono",ui-monospace,Menlo,monospace;font-size:12px}
.dim{color:var(--dim)}
.trunc{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:600;
background:var(--neutral-bg);color:var(--ink)}
.pill.ok{background:var(--ok-bg);color:var(--ok)}
.pill.warn{background:var(--warn-bg);color:var(--warn)}
.pill.neutral{background:var(--neutral-bg);color:var(--dim)}
.pill.cap{background:var(--gold-soft);color:#7a5a04}
.pill.ing{background:var(--neutral-bg);color:var(--dim)}
.scopes{margin:-22px 0 30px;display:flex;flex-wrap:wrap;gap:8px}
.scopes .pill{background:var(--gold-soft);color:#7a5a04}
.provgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin-bottom:14px}
.prov{display:flex;align-items:center;gap:10px;background:#fff;border:1px solid var(--line);
border-radius:10px;padding:11px 14px}
.prov .pill{flex:none}
.prov-via{font-size:13px;font-weight:500;color:var(--ink);flex:1;min-width:0}
.prov-n{font-size:12px;color:var(--dim);white-space:nowrap}
.prov-note{margin:0 0 30px}
footer{margin-top:42px;color:var(--dim);font-size:12px;text-align:center}
footer a{color:var(--gold);text-decoration:none}
@media(max-width:720px){.cards{grid-template-columns:repeat(2,1fr)}h1{font-size:36px}}
"""


def _policy_block(records, policy, subject):
    """Render the deterministic policy-corroboration verdict for the report.

    ``policy`` is a list of rule dicts. The verdict panel is computed by
    ``policy.evaluate`` from explicit rules (never a model), so it is safe to sit
    beside the integrity/completeness verdicts. Integrity + completeness are
    proven by the page's own live checks, so the panel's reassurance pills are
    suppressed here to avoid a static claim competing with the live one."""
    if not policy:
        return ""
    from .policy import evaluate, verdict_panel
    result = evaluate(records, policy)
    return ('<h2>Policy corroboration</h2>\n<div style="margin:0 0 30px">%s</div>'
            % verdict_panel(result, subject=subject, show_pills=False))


def render(records, checkpoints=None, *, witness_url=None, policy=None):
    """Return the full HTML for a runtime-record report over ``records``.

    If ``checkpoints`` (a list of notary witnesses for this chain) is given, the
    page re-checks completeness in the browser against those witnesses. If
    ``witness_url`` (a hosted Halo witness) is given, the page instead fetches
    the checkpoints live from that witness — so completeness is verified against
    a party the vendor doesn't control, not the snapshot embedded in the page.
    The embedded checkpoints remain as an offline fallback.

    If ``policy`` (a list of rule dicts) is given, a deterministic
    policy-corroboration verdict is rendered beside the integrity/completeness
    verdicts."""
    checkpoints = checkpoints or []
    subject = _subject_label(records)
    agent = _agent_label(records)
    stats = _summary_stats(records)
    rows = "\n".join(_row(r) for r in records) or (
        '<tr><td colspan="10" class="dim" style="padding:24px;text-align:center">'
        "No actions recorded yet — this report populates as the agent operates."
        "</td></tr>"
    )
    prov_panel, prov_present, n_cap, n_ing = _provenance(records)
    if prov_present:
        if n_ing and n_cap:
            prov_note = (
                "Each action is tagged with how Halo observed it. "
                "<b>Captured</b> means Halo saw the call at the boundary as it happened — "
                "nothing could be reshaped first. <b>Ingested</b> means the record was built "
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
                "Every action was <b>captured</b> at the boundary — Halo saw each call as it "
                "happened, so nothing could be reshaped before it was recorded. The strongest tier.")
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
    config_json = json.dumps(
        {"witnessUrl": witness_url, "subject": _subject_id(records)},
        separators=(",", ":")).replace("<", "\\u003c")
    verify_js = _VERIFY_JS % {"genesis": GENESIS_PREV}

    return """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%(subject)s — Runtime Record</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Instrument+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>%(style)s</style>
</head><body><div class="wrap">
<div class="eyebrow">Halo Runtime Record</div>
<h1>%(subject)s</h1>
<div class="meta">Agent <b>%(agent)s</b> &middot; %(start)s &ndash; %(end)s &middot; <b>%(total)s</b> recorded actions</div>
<div id="verdict" class="verdict neutral">Verifying hash chain&hellip;</div>
<div id="completeness" class="verdict neutral">Checking completeness against the independent witness&hellip;</div>
<div class="note">This report re-computes its own SHA-256 / RFC 8785 hash chain in your browser (integrity) and checks it against Halo's independent witness (completeness) — neither is something you take on trust.</div>
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
<table>
<thead><tr><th>Time (UTC)</th><th>Tool</th><th>Type</th><th>Source</th><th>Scope</th><th>Decision</th><th>Outcome</th><th>Findings</th><th>Summary</th><th>Hash</th></tr></thead>
<tbody>
%(rows)s
</tbody></table>
<footer>Generated by <a href="https://github.com/bkuan001/halo-record">halo-record</a> &middot; format <a href="https://github.com/bkuan001/halo-record/blob/main/src/halo_record/halo-record.schema.json">Halo Runtime Record v0.1</a></footer>
</div>
<script id="records" type="application/json">%(records_json)s</script>
<script id="checkpoints" type="application/json">%(checkpoints_json)s</script>
<script id="halo-config" type="application/json">%(config_json)s</script>
<script>%(verify_js)s</script>
</body></html>""" % {
        "subject": _esc(subject),
        "agent": _esc(agent),
        "style": _STYLE,
        "start": _esc(stats["start"]),
        "end": _esc(stats["end"]),
        "total": stats["total"],
        "ntools": len(stats["tools"]),
        "nscopes": len(stats["scopes"]),
        "nflagged": sum(1 for r in records if r.get("findings")),
        "scope_pills": scope_pills,
        "provenance_block": provenance_block,
        "policy_block": policy_block,
        "rows": rows,
        "records_json": records_json,
        "checkpoints_json": checkpoints_json,
        "config_json": config_json,
        "verify_js": verify_js,
    }


def write_report(log_path, out_path=None, witness_log=None, witness_url=None,
                 policy_path=None):
    """Render ``log_path`` to HTML. ``witness_log`` embeds a local notary's
    checkpoints (offline fallback / static report). ``witness_url`` points the
    page at a hosted Halo witness it fetches live, so completeness is checked
    against a party the vendor doesn't control. If both are given, the embedded
    checkpoints seed the offline fallback while the live witness is authoritative.
    ``policy_path`` adds a deterministic policy-corroboration verdict to the report."""
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
    html_doc = render(records, checkpoints, witness_url=witness_url, policy=policy)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(html_doc)
    return html_doc, len(records)
