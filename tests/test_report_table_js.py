"""The Runtime Report's activity table, driven the way a browser drives it.

Runs the page's own scripts (HaloView, the verifier, the table) under Node
against a small stand-in DOM, with an IntersectionObserver whose callback the
test fires, as a real browser does once the table's sentinel is on screen.

  * The "Withheld" notice that marks the table as unverified static text stays
    in place after verification fails, whatever the table does next (lazy
    loading, filtering, sorting).
  * Rows sort newest first to the microsecond.

Skipped where Node is not installed.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from halo_record.record import Recorder, build
from halo_record.report import write_report

NODE = shutil.which("node")

_DOM = r"""
const HTML = %(html)s;
const ACTIONS = %(actions)s;
function unesc(s){ return s.replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&#39;/g, "'")
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&"); }
function attrsOf(tag){ const a = {}; tag.replace(/([\w-]+)="([^"]*)"/g, (m, k, v) => { a[k] = unesc(v); }); return a; }
function rowsFrom(html){
  const out = [];
  html.replace(/<tr\b([^>]*)>/g, (m, at) => { const r = new El("tr", attrsOf(at)); out.push(r); });
  return out;
}
class El {
  constructor(tag, attrs){
    this.tag = tag; this.attrs = attrs || {}; this.children = []; this._html = "";
    this.className = ""; this.style = {}; this.listeners = {}; this.options = [{}];
    this.value = ""; this.checked = false; this.firstChild = {textContent: ""};
    this.classList = {add(){}, remove(){}, toggle(){}, contains(){ return false; }};
    this.content = {querySelectorAll: () => []};
  }
  get innerHTML(){ return this._html; }
  set innerHTML(v){
    this._html = String(v);
    if (this.tag === "template"){ const rows = rowsFrom(this._html); this.content = {querySelectorAll: () => rows}; }
    if (this.tag === "tbody") this.children = rowsFrom(this._html);
  }
  get textContent(){ return this._html.replace(/<[^>]*>/g, ""); }
  set textContent(v){ this._html = String(v); this.children = []; }
  hasAttribute(k){ return k in this.attrs; }
  getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; }
  setAttribute(k, v){ this.attrs[k] = String(v); }
  removeAttribute(k){ delete this.attrs[k]; }
  addEventListener(t, f){ (this.listeners[t] = this.listeners[t] || []).push(f); }
  fire(t){ (this.listeners[t] || []).forEach(f => f({preventDefault(){}, key: "", target: this})); }
  querySelectorAll(sel){ return sel === "tr" ? this.children.filter(c => c.tag === "tr") : []; }
  querySelector(){ return null; }
  appendChild(c){
    if (this.tag === "select"){ this.options.push(c); return c; }
    if (c.tag === "#frag") this.children.push(...c.children); else this.children.push(c);
    return c;
  }
  remove(i){ if (typeof i === "number") this.options.splice(i, 1); }
}
const ELS = {};
const IDS = [];   // every element carrying an id, in page order (repeats kept)
const BLOCKS = {};
HTML.replace(/<script id="([^"]+)" type="application\/json">([\s\S]*?)<\/script>/g, (m, id, body) => { BLOCKS[id] = body; });
HTML.replace(/<(\w+)\b([^>]*)\bid="([^"]+)"([^>]*)>/g, (m, tag, a1, id, a2) => {
  if (tag === "script") return;
  const e = new El(tag, attrsOf(a1 + " " + a2));
  e.id = id;
  IDS.push(e);
  if (!(id in ELS)) ELS[id] = e;   // getElementById returns the first, as browsers do
});
for (const id in BLOCKS){ const e = new El("script"); e.id = id; e._html = BLOCKS[id]; ELS[id] = e; IDS.push(e); }
function between(open, close){
  const i = HTML.indexOf(open); if (i < 0) return "";
  const j = HTML.indexOf(close, i + open.length); return HTML.slice(i + open.length, j);
}
ELS["activity-body"].children = rowsFrom(between('<tbody id="activity-body">', "</tbody>"));
{ const rows = rowsFrom(between('<template id="more-rows">', "</template>")); ELS["more-rows"].content = {querySelectorAll: () => rows}; }
ELS["rowcount"]._html = between('<div class="rowcount" id="rowcount">', "</div>");
const OBSERVERS = [];
globalThis.window = globalThis;
globalThis.IntersectionObserver = class { constructor(cb){ OBSERVERS.push(cb); } observe(){} };
globalThis.location = {hash: ""};
globalThis.document = {
  title: "",
  getElementById: id => ELS[id] || null,
  createElement: tag => new El(tag),
  createDocumentFragment: () => new El("#frag"),
  querySelectorAll: sel => {
    if (sel === "[id]") return IDS.slice();
    const m = /^\[id="(.+)"\]$/.exec(sel);
    return m ? IDS.filter(e => e.id === m[1]) : [];
  },
  addEventListener(){},
};
%(prelude)s
const SCRIPTS = %(scripts)s;
const STAGGER = %(stagger)s;
function settle(){ return new Promise(r => setTimeout(r, 300)); }
(async () => {
  // Each page script runs as its own script, in page order. Staggered, each
  // one finishes its async work before the next is parsed, as when a slow
  // connection delivers the table script after verification has completed.
  for (const s of SCRIPTS){ require("vm").runInThisContext(s); if (STAGGER) await settle(); }
  await settle();
  const log = [];
  const snap = () => ({rowcount: ELS["rowcount"].innerHTML,
                       order: ELS["activity-body"].children.map(r => r.getAttribute("data-tool")),
                       toolOptions: ELS["f-tool"].options.slice(1).map(o => ({value: o.value, text: o.textContent})),
                       detail: ELS["detail-body"] ? ELS["detail-body"].innerHTML : null});
  log.push(snap());
  for (const a of ACTIONS){
    if (a === "observe") OBSERVERS.forEach(cb => cb([{isIntersecting: true}]));
    else if (a === "filter"){ ELS["f-tool"].value = ""; ELS["f-tool"].fire("change"); }
    else if (a === "search"){ ELS["f-q"].value = "a"; ELS["f-q"].fire("input"); }
    else if (a.startsWith("search:")){ ELS["f-q"].value = a.slice(7); ELS["f-q"].fire("input"); }
    else if (a.startsWith("open:")){
      const row = ELS["activity-body"].children[+a.slice(5)];
      (ELS["activity-body"].listeners.click || []).forEach(f => f({target: {closest: () => row}, preventDefault(){}}));
    }
    await settle();
    log.push(snap());
  }
  process.stdout.write(JSON.stringify({verdict: ELS["verdict"].className, log,
    verdicts: IDS.filter(e => e.id === "verdict").map(e => ({cls: e.className, html: e.innerHTML}))}));
})();
"""


def _run(html, actions=(), prelude="", stagger=False):
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    code = _DOM % {"html": json.dumps(html), "actions": json.dumps(list(actions)),
                   "prelude": prelude, "scripts": json.dumps(scripts),
                   "stagger": "true" if stagger else "false"}
    js = os.path.join(tempfile.mkdtemp(), "page.js")
    with open(js, "w", encoding="utf-8") as fh:
        fh.write(code)
    p = subprocess.run([NODE, js], capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise AssertionError(p.stderr[-2000:])
    return json.loads(p.stdout)


def _report(entries):
    d = tempfile.mkdtemp()
    log = os.path.join(d, "c.jsonl")
    rec = Recorder(log)
    for tool, ts in entries:
        rec.append(build("tool_call", "security", tool=tool, subject="acme", ts=ts))
    html, _ = write_report(log, os.path.join(d, "r.html"))
    return html


@unittest.skipUnless(NODE, "node not installed")
class WithheldNoticeStaysTest(unittest.TestCase):
    def setUp(self):
        html = _report([("lookup", None), ("issue_refund", None), ("lookup", None)])
        block = re.search(r'<script id="records" type="application/json">(.*?)</script>', html, re.S).group(1)
        self.tampered = html.replace(block, block.replace("issue_refund", "issue_refunX"))

    def test_notice_survives_lazy_loading(self):
        out = _run(self.tampered, ["observe"])
        self.assertIn("fail", out["verdict"])
        self.assertIn("Withheld", out["log"][0]["rowcount"])
        self.assertIn("Withheld", out["log"][-1]["rowcount"])
        self.assertNotIn("Showing", out["log"][-1]["rowcount"])

    def test_notice_set_before_the_table_starts_survives_it(self):
        # Without WebCrypto (an insecure context) the page withholds at once,
        # before the table script has drawn its first batch.
        html = _report([("lookup", None), ("issue_refund", None)])
        out = _run(html, ["observe", "filter"],
                   prelude='Object.defineProperty(globalThis, "crypto", {value: {}, configurable: true});')
        self.assertIn("neutral", out["verdict"])
        for step in out["log"]:
            self.assertIn("Withheld", step["rowcount"])
            self.assertNotIn("Showing", step["rowcount"])

    def test_notice_survives_filtering_and_search(self):
        out = _run(self.tampered, ["filter", "search", "observe"])
        for step in out["log"]:
            self.assertIn("Withheld", step["rowcount"])

    def test_verified_page_still_counts_rows(self):
        html = _report([("lookup", None), ("issue_refund", None)])
        out = _run(html, ["observe", "filter"])
        self.assertIn("ok", out["verdict"])
        self.assertIn("Showing 2 of 2 actions", out["log"][-1]["rowcount"])


_FAKE_ROW = ('<tr data-ts="2030-01-01T00:00:00+00:00" data-tool="EVILTOOL" data-type="tool_call" '
             'data-sev="INFO" data-status="ok" data-flags="0" data-rid="evil" '
             'data-text="2030-01-01t00:00:00+00:00 eviltool tool_call wire $1m approved by cfo">'
             '<td class="mono dim ts-cell">2030-01-01 00:00:00</td><td class="mono">EVILTOOL</td>'
             '<td>tool_call</td><td>wire $1M approved by CFO</td></tr>')


@unittest.skipUnless(NODE, "node not installed")
class VerifiedTableIsTheVerifiedRecordsTest(unittest.TestCase):
    """A report with more rows than the first batch keeps rows past it in a
    static <template>. Once the records verify, the table is the rows
    re-rendered from those records and nothing else, whichever of the
    verifier and the table script finishes first."""

    N = 230

    def setUp(self):
        self.html = _report([("t%d" % (i % 7), None) for i in range(self.N)])
        self.assertIn('<template id="more-rows"><tr', self.html)

    def _check_count(self, stagger):
        out = _run(self.html, ["observe", "filter"], stagger=stagger)
        self.assertIn("ok", out["verdict"])
        for step in out["log"]:
            self.assertIn("of %d actions" % self.N, step["rowcount"])
            self.assertNotIn("filtered", step["rowcount"])

    def test_count_equals_record_count(self):
        self._check_count(stagger=False)

    def test_count_equals_record_count_when_verification_finishes_first(self):
        self._check_count(stagger=True)

    def _check_injected(self, stagger):
        html = self.html.replace('<template id="more-rows">', '<template id="more-rows">' + _FAKE_ROW, 1)
        out = _run(html, ["observe", "filter", "search:eviltool"], stagger=stagger)
        self.assertIn("ok", out["verdict"])
        for step in out["log"]:
            self.assertNotIn("EVILTOOL", [o["value"] for o in step["toolOptions"]])
            self.assertNotIn("EVILTOOL", step["order"])
        self.assertIn("of %d actions" % self.N, out["log"][1]["rowcount"])
        self.assertIn("Showing 0 of 0 actions (filtered from %d)" % self.N, out["log"][-1]["rowcount"])

    def test_template_row_not_shown_after_verification(self):
        self._check_injected(stagger=False)

    def test_template_row_not_shown_when_verification_finishes_first(self):
        self._check_injected(stagger=True)

    def test_failed_verification_keeps_static_rows_withheld(self):
        block = re.search(r'<script id="records" type="application/json">(.*?)</script>', self.html, re.S).group(1)
        html = self.html.replace(block, block.replace('"t3"', '"t9"', 1))
        out = _run(html, ["observe"], stagger=True)
        self.assertIn("fail", out["verdict"])
        for step in out["log"]:
            self.assertIn("Withheld", step["rowcount"])


@unittest.skipUnless(NODE, "node not installed")
class NewestFirstToTheMicrosecondTest(unittest.TestCase):
    def test_rows_in_one_second_sort_by_their_fraction(self):
        html = _report([("approve", "2026-06-01T10:00:00.100999Z"),
                        ("refund", "2026-06-01T10:00:00.200001Z")])
        out = _run(html, ["filter"])
        self.assertIn("ok", out["verdict"])
        self.assertEqual(out["log"][-1]["order"], ["refund", "approve"])

    def test_offsets_and_precision_still_order_by_instant(self):
        html = _report([("first", "2026-06-01T10:00:00.5Z"),
                        ("second", "2026-06-01T12:00:00.500001+02:00"),
                        ("third", "2026-06-01T10:00:01Z")])
        out = _run(html, ["filter"])
        self.assertEqual(out["log"][-1]["order"], ["third", "second", "first"])


@unittest.skipUnless(NODE, "node not installed")
class InvisibleIdentifiersShownTest(unittest.TestCase):
    """An identifier with an invisible character in it is shown with a visible
    marker wherever the page displays it: the Tool filter, and the record
    drawer's approver, principal and scope fields."""

    def setUp(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        Recorder(log).append(build(
            "tool_call", "security", tool="\u202egnp.exe", subject="acme",
            decision="human_approved", approver="alice\u202e", scope="fs.wr\u200bite",
            principal={"human_id": "bob\u200b", "service_account": "svc\u2060-1"}))
        self.html, _ = write_report(log, os.path.join(d, "r.html"))

    def test_tool_filter_marks_the_character_and_keeps_the_value(self):
        out = _run(self.html, ["filter"])
        opts = out["log"][-1]["toolOptions"]
        self.assertEqual([o["value"] for o in opts], ["\u202egnp.exe"])
        self.assertEqual([o["text"] for o in opts], ["\u27e8U+202E\u27e9gnp.exe"])

    def test_drawer_marks_approver_principal_and_scope(self):
        out = _run(self.html, ["open:0"])
        detail = out["log"][-1]["detail"]
        for shown in ("alice\u27e8U+202E\u27e9", "fs.wr\u27e8U+200B\u27e9ite",
                      "bob\u27e8U+200B\u27e9", "svc\u27e8U+2060\u27e9-1"):
            self.assertIn(shown, detail)
        for raw in ("\u202e", "\u200b", "\u2060"):
            self.assertNotIn(raw, detail)


if __name__ == "__main__":
    unittest.main()
