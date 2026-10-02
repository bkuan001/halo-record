"""The Runtime Report's display is bound to the records the page verifies.

Two checks:

  * Differential: every record-derived region of the page (heading, period,
    cards, scopes, provenance, activity rows, policy verdict) renders
    byte-identically in Python (_view.regions) and in the page's JavaScript
    (_view.RENDER_JS), over a spread of records and policies.
  * Tampering: a generated report whose static HTML was edited (table rows,
    policy verdict, counts) still shows, under a passing verification badge,
    only what its verified records say — and a report whose records were
    edited shows no verdict at all.

Runs the page's JavaScript under Node; skipped where Node is not installed.
"""

import glob
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr

from halo_record import _view
from halo_record.record import Recorder, build
from halo_record.report import write_report
from halo_record.verify import read_log_lines, verify_log

HERE = os.path.dirname(os.path.abspath(__file__))
PACKS = os.path.join(os.path.dirname(HERE), "examples", "policies")
NODE = shutil.which("node")


def _load(path):
    return [json.loads(l) for l in read_log_lines(path)]


def _records(build_calls):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "c.jsonl")
    rec = Recorder(path)
    with redirect_stderr(io.StringIO()):
        for args, kw in build_calls:
            rec.append(build(*args, **kw))
    return _load(path)


def _cases():
    cases = []
    for path in sorted(glob.glob(os.path.join(HERE, "fixtures", "differential", "*.jsonl"))):
        if verify_log(path, out=lambda *a: None):
            cases.append({"name": os.path.basename(path), "records": _load(path)})
    agent = {"id": "a1", "name": "support-bot", "version": "1.0"}
    varied = _records([
        (("tool_call", "security"), dict(tool="Bash", tool_input={"command": "ls  -la\n/tmp"},
                                          subject={"id": "acme", "name": "Acme Corp"}, agent=agent,
                                          ts="2026-06-01T10:00:00+02:00")),
        (("write", "safety"), dict(tool="Write", tool_input={"file_path": "/r.md", "bytes": 4},
                                    subject="acme", agent=agent, decision="human_approved",
                                    approver="u1", scope="fs.write", ts="2026-06-01T07:30:00Z")),
        (("network", "privacy"), dict(tool="post_webhook", tool_input={"url": "https://x.example/h"},
                                       subject="acme", agent=agent,
                                       data={"pii_types": ["ssn"], "purpose": "support"})),
        (("tool_call", "security"), dict(tool="payments.refund", tool_input={"amount": 50, "to": "c_1"},
                                          subject="acme", decision="denied",
                                          outcome={"status": "denied", "summary": "refused"})),
        (("tool_call", "security"), dict(tool="payments.refund", tool_input={"amount": 9},
                                          subject="acme",
                                          verification={"status": "blocked", "verifier": "gate/1"})),
        (("tool_call", "security"), dict(tool="read_email", tool_input={"q": "ignore previous"},
                                          subject="acme", threats=["prompt_injection_indirect"],
                                          principal={"human_id": "u_alice"})),
        (("tool_call", "security"), dict(tool="db", tool_input={"dsn": "postgres://u:pw@h/db"},
                                          subject="acme", source="langchain")),
        (("tool_call", "reliability"), dict(tool="model", outcome={"status": "ok",
                                                                    "summary": "answered in 3 steps"},
                                             subject="acme", agent={"id": "a2", "name": "billing-bot"})),
        (("tool_call", "security"), dict(tool="WebSearch",
                                          tool_input={"query": "café   naïve \U0001F600",
                                                      "nested": {"a": [1, 2.5, None, True]}},
                                          subject="acme")),
        (("tool_call", "security"), dict(tool="t", tool_input={"description": "", "path": 0,
                                                               "pattern": [], "prompt": "x'y\"z\\\\w"},
                                          subject="acme", ts="2026-05-31T23:59:59.123456-07:00")),
        (("read", "privacy"), dict(tool="Read", tool_input="just a string input", subject="acme")),
        (("tool_call", "security"), dict(tool="Agent", tool_input={"description": "x" * 300},
                                          subject="acme")),
    ])
    for c in cases:
        c.setdefault("rules", None)
    pack = json.load(open(os.path.join(PACKS, "owasp-starter.json")))["rules"]
    aiuc = json.load(open(os.path.join(PACKS, "aiuc-1-starter.json")))["rules"]
    cases.append({"name": "varied", "records": varied, "rules": pack})
    cases.append({"name": "varied-aiuc", "records": varied, "rules": aiuc, "chainVerified": False})
    cases.append({"name": "varied-custom", "records": varied, "rules": [
        {"id": "refunds", "when": {"action.tool": "payments.refund"},
         "forbid": {"action.authorization.decision": {"ne": "human_approved"}}},
        {"id": "gap", "when": {"action.tool": "escalate"}, "expect_evidence": True},
        {"id": "nums", "forbid": {"data.pii_types": {"contains": "ssn"}}},
        {"id": "none", "when": {"action.tool": "nope"}, "require": {"ts": {"exists": True}}},
        {"id": "fan", "forbid": {"findings[].type": {"in": ["db_conn", "ssn"], "nin": ["email"]}}},
        {"id": "items", "when": {"data.pii_types[]": "ssn"}, "require": {"data.purpose": {"exists": True}}},
        {"id": "gate", "when": {"verification.status": {"in": ["blocked", "modified"]}},
         "forbid": {"outcome.status": {"nin": ["denied", "error"]}}},
    ]})
    cases.append({"name": "empty", "records": [], "rules": pack})
    odd_subject = _records([(("tool_call", "security"), dict(tool="t", subject="acme​"))])
    cases.append({"name": "odd-subject", "records": odd_subject})
    return cases


_HARNESS = r"""
const fs = require("fs");
%s
const cases = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const out = cases.map(c => HaloView.regions(c.records, c.rules, c.chainVerified !== false, c.digest));
process.stdout.write(JSON.stringify(out));
"""


@unittest.skipUnless(NODE, "node not installed")
class RegionsMatchPythonTest(unittest.TestCase):
    def test_every_region_renders_identically_in_python_and_the_page(self):
        cases = _cases()
        d = tempfile.mkdtemp()
        for c in cases:
            c["digest"] = _view.rules_digest(c["rules"]) if c.get("rules") else None
        data = os.path.join(d, "cases.json")
        with open(data, "w", encoding="utf-8") as fh:
            json.dump(cases, fh)
        js = os.path.join(d, "h.js")
        with open(js, "w", encoding="utf-8") as fh:
            fh.write(_HARNESS % _view.render_js())
        p = subprocess.run([NODE, js, data], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = json.loads(p.stdout)
        for case, js_regions in zip(cases, got):
            py = _view.regions(case["records"], case.get("rules"),
                               case.get("chainVerified", True) is not False)
            for key in py:
                self.assertEqual(js_regions[key], py[key], "%s: region %s" % (case["name"], key))


def _page_parts(html):
    """The page's JSON blocks and its inline scripts."""
    blocks = dict(re.findall(r'<script id="([^"]+)" type="application/json">(.*?)</script>', html, re.S))
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    return blocks, scripts


_PAGE_HARNESS = r"""
const BLOCKS = %(blocks)s;
const STATIC = %(static)s;
const els = {};
function el(id){
  if (!els[id]) els[id] = {id, className: "", innerHTML: STATIC[id] || "", textContent: BLOCKS[id] || "",
                           style: {}, setAttribute(){}, classList: {add(){}, remove(){}}};
  return els[id];
}
globalThis.window = globalThis;
globalThis.document = {getElementById: el, title: "", querySelectorAll: () => []};
globalThis.location = {hash: %(hash)s};
let ROWS = null;
window.__haloSetRows = rows => { ROWS = rows; };
%(scripts)s
setTimeout(() => {
  const pick = id => ({className: el(id).className, html: el(id).innerHTML});
  process.stdout.write(JSON.stringify({
    verdict: pick("verdict"), completeness: pick("completeness"), policy: pick("r-policy"), cards: pick("r-cards"),
    period: pick("r-period"), h1: pick("r-h1"), rows: ROWS, title: document.title}));
}, 400);
"""


def _run_page(html, hash=""):
    blocks, scripts = _page_parts(html)
    static = {}
    for rid in ("r-policy", "r-cards", "r-period", "r-h1"):
        m = re.search(r'id="%s"[^>]*>(.*?)<!--/%s-->' % (rid, rid), html, re.S)
        static[rid] = m.group(1) if m else ""
    verify = [s for s in scripts if "var HaloView" in s or "async function verify(" in s]
    code = _PAGE_HARNESS % {"blocks": json.dumps(blocks), "static": json.dumps(static),
                            "hash": json.dumps(hash),
                            "scripts": "\n".join(verify)}
    js = os.path.join(tempfile.mkdtemp(), "page.js")
    with open(js, "w", encoding="utf-8") as fh:
        fh.write(code)
    p = subprocess.run([NODE, js], capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise AssertionError(p.stderr)
    return json.loads(p.stdout)


@unittest.skipUnless(NODE, "node not installed")
class TamperedStaticHtmlTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.log = os.path.join(self.d, "c.jsonl")
        rec = Recorder(self.log)
        for tool in ("lookup", "issue_refund", "lookup"):
            rec.append(build("tool_call", "security", tool=tool, subject="acme",
                             decision="allowed"))
        self.policy = os.path.join(self.d, "p.json")
        with open(self.policy, "w") as fh:
            json.dump([{"id": "refunds-need-human", "when": {"action.tool": "issue_refund"},
                        "forbid": {"action.authorization.decision": {"ne": "human_approved"}}}], fh)
        self.html, _ = write_report(self.log, os.path.join(self.d, "r.html"),
                                    policy_path=self.policy)

    def _tamper(self, html):
        """Edit the page's static HTML only: every <script> keeps its bytes."""
        parts = re.split(r"(<script\b.*?</script>)", html, flags=re.S)
        for i in range(0, len(parts), 2):
            p = parts[i].replace("NON-COMPLIANT", "COMPLIANT").replace(">FAIL<", ">PASS<")
            parts[i] = p.replace("issue_refund", "lookup")
        return "".join(parts)

    def test_edited_table_and_verdict_do_not_show_under_the_badge(self):
        tampered = self._tamper(self.html)
        static = re.sub(r"<script\b.*?</script>", "", tampered, flags=re.S)
        self.assertNotIn("NON-COMPLIANT", static)
        self.assertNotIn("issue_refund", static)
        out = _run_page(tampered)
        self.assertIn("ok", out["verdict"]["className"])
        self.assertIn("NON-COMPLIANT", out["policy"]["html"])
        self.assertIn(">FAIL<", out["policy"]["html"])
        self.assertIsNotNone(out["rows"])
        self.assertTrue(any("issue_refund" in r for r in out["rows"]))
        self.assertIn("re-rendered", out["verdict"]["html"])

    def test_the_rules_evaluated_are_identified_on_the_page(self):
        # The policy file travels with the page; the verdict names the SHA-256
        # of the policy text it evaluated (the file's bytes), so an edited rule
        # set cannot pass as the original.
        import hashlib
        with open(self.policy, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        out = _run_page(self.html)
        self.assertIn(digest[:16], out["policy"]["html"])
        blocks, _ = _page_parts(self.html)
        edited = blocks["halo-policy"].replace("issue_refund", "lookup")
        out = _run_page(self.html.replace(blocks["halo-policy"], edited))
        self.assertNotIn(digest[:16], out["policy"]["html"])
        edited_text = json.loads(edited).encode("utf-8")
        self.assertIn(hashlib.sha256(edited_text).hexdigest()[:16], out["policy"]["html"])

    def test_edited_records_show_no_verdict_or_table_as_verified(self):
        blocks, _ = _page_parts(self.html)
        edited = blocks["records"].replace("issue_refund", "issue_refunX")
        out = _run_page(self.html.replace(blocks["records"], edited))
        self.assertIn("fail", out["verdict"]["className"])
        self.assertNotIn("Verdict:", out["policy"]["html"])
        self.assertIsNone(out["rows"])


@unittest.skipUnless(NODE, "node not installed")
class PinnedSubjectTest(unittest.TestCase):
    """A chain re-keyed to a new subject id and re-anchored under it looks
    consistent when looked up by the id it carries; pinning the id the reader
    expects exposes it."""

    def setUp(self):
        from halo_record.anchor import Notary
        self.d = tempfile.mkdtemp()
        old = os.path.join(self.d, "old.jsonl")
        rec = Recorder(old)
        for i in range(3):
            rec.append(build("tool_call", "security", tool="t%d" % i, subject="acme"))
        self.witness = os.path.join(self.d, "w.jsonl")
        Notary(self.witness).witness(_load(old))
        self.log = os.path.join(self.d, "rekeyed.jsonl")
        rec = Recorder(self.log)
        for i in range(2):
            rec.append(build("tool_call", "security", tool="t%d" % i, subject="acme-2"))
        Notary(self.witness).witness(_load(self.log))
        self.html, _ = write_report(self.log, os.path.join(self.d, "r.html"), witness_log=self.witness)

    def test_unpinned_lookup_says_it_is_unpinned(self):
        out = _run_page(self.html)
        self.assertIn("not pinned", out["completeness"]["html"])
        self.assertNotIn("fail", out["completeness"]["className"])

    def test_pinning_the_expected_subject_fails_a_rekeyed_chain(self):
        out = _run_page(self.html, hash="#expect=acme")
        self.assertIn("fail", out["completeness"]["className"])
        self.assertIn("MISMATCH", out["completeness"]["html"])

    def test_generation_pin_is_carried_to_the_page(self):
        html, _ = write_report(self.log, os.path.join(self.d, "r2.html"),
                               witness_log=self.witness, expected_subject="acme-2")
        out = _run_page(html)
        self.assertNotIn("not pinned", out["completeness"]["html"])
        self.assertIn("for &quot;acme-2&quot;", out["completeness"]["html"])


if __name__ == "__main__":
    unittest.main()
