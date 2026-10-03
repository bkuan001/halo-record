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
const BLOCKS = {};
HTML.replace(/<script id="([^"]+)" type="application\/json">([\s\S]*?)<\/script>/g, (m, id, body) => { BLOCKS[id] = body; });
HTML.replace(/<(\w+)\b([^>]*)\bid="([^"]+)"([^>]*)>/g, (m, tag, a1, id, a2) => {
  if (tag === "script") return;
  const e = new El(tag, attrsOf(a1 + " " + a2));
  ELS[id] = e;
});
for (const id in BLOCKS){ const e = new El("script"); e._html = BLOCKS[id]; ELS[id] = e; }
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
  querySelectorAll: () => [],
  addEventListener(){},
};
%(prelude)s
%(scripts)s
function settle(){ return new Promise(r => setTimeout(r, 300)); }
(async () => {
  await settle();
  const log = [];
  const snap = () => ({rowcount: ELS["rowcount"].innerHTML,
                       order: ELS["activity-body"].children.map(r => r.getAttribute("data-tool"))});
  log.push(snap());
  for (const a of ACTIONS){
    if (a === "observe") OBSERVERS.forEach(cb => cb([{isIntersecting: true}]));
    else if (a === "filter"){ ELS["f-tool"].value = ""; ELS["f-tool"].fire("change"); }
    else if (a === "search"){ ELS["f-q"].value = "a"; ELS["f-q"].fire("input"); }
    await settle();
    log.push(snap());
  }
  process.stdout.write(JSON.stringify({verdict: ELS["verdict"].className, log}));
})();
"""


def _run(html, actions=(), prelude=""):
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    code = _DOM % {"html": json.dumps(html), "actions": json.dumps(list(actions)),
                   "prelude": prelude, "scripts": "\n;\n".join(scripts)}
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


if __name__ == "__main__":
    unittest.main()
