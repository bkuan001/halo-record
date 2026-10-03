"""The report page reads its embedded policy text exactly as ``halo policy``
reads the file: a repeated key, a non-finite number, an unknown top-level key,
a missing rules list or an invalid rule is refused on the page with the CLI's
own reason, so a reviewer whose ``shasum`` matches never sees a green verdict
the CLI would refuse.
"""

import json
import os
import subprocess
import tempfile
import unittest

from halo_record import _view
from halo_record.policy import _rules_from_text
from halo_record.record import Recorder, build
from halo_record.report import write_report
from tests.test_page_binding import NODE, _page_parts, _run_page

DUP_FORBID = ('{"rules":[{"id":"r","forbid":{"action.authorization.decision":"denied"},'
              '"forbid":{"action.authorization.decision":"allowed","outcome.status":"error"}}]}')

CASES = [
    DUP_FORBID,
    '[{"id":"r","id":"s","forbid":{"severity":"HIGH"}}]',
    '[{"id":"r","forbid":{"severity":"HIGH","severity":"LOW"}}]',
    '[{"id":"r","forbid":{"data.cross_region":{"lt":1e400}}}]',
    '[{"id":"r","forbid":{"data.cross_region":{"lt":-1.5e999}}}]',
    '{"rulez":[{"id":"r","forbid":{"severity":"HIGH"}}]}',
    '{"name":"x"}',
    '[]',
    '{"rules":[]}',
    '"x"',
    'null',
    '[{"id":"r","forbid":{"findings[].type":"SSN"}}]',
    '[{"id":"r","when":{"action.type":"network"},"forbid":{"action.type":"read"}}]',
    '[{"id":"r","forbid":{"data.cross_region":{"gte":1e308}}}]',
    '{"a":{"b":1,"b":2},"a":1}',
    '[{"id":"r","forbid":{"severity":"HIGH"}}]',
    '{"name":"ok","rules":[{"id":"r","forbid":{"severity":"HIGH"}}]}',
]

_HARNESS = r"""
const fs = require("fs");
%s
const cases = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
process.stdout.write(JSON.stringify(cases.map(t => HaloView.parsePolicyText(t).error)));
"""


@unittest.skipUnless(NODE, "node not installed")
class ParseParityTest(unittest.TestCase):
    def test_page_refuses_what_the_cli_refuses_with_the_same_reason(self):
        expected = []
        for text in CASES:
            try:
                _rules_from_text(text, "(embedded)")
                expected.append(None)
            except ValueError as e:
                expected.append(str(e))
        d = tempfile.mkdtemp()
        data = os.path.join(d, "cases.json")
        with open(data, "w", encoding="utf-8") as fh:
            json.dump(CASES, fh)
        js = os.path.join(d, "h.js")
        with open(js, "w", encoding="utf-8") as fh:
            fh.write(_HARNESS % _view.render_js())
        p = subprocess.run([NODE, js, data], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = json.loads(p.stdout)
        for text, py, page in zip(CASES, expected, got):
            self.assertEqual(page, py, text)


@unittest.skipUnless(NODE, "node not installed")
class PageVerdictTest(unittest.TestCase):
    def test_duplicate_keys_withhold_the_verdict(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        rec = Recorder(log)
        for dec in ("denied", "denied"):
            rec.append(build("tool_call", "security", tool="t", subject="acme", decision=dec))
        pol = os.path.join(d, "p.json")
        with open(pol, "w", encoding="utf-8") as fh:
            fh.write('[{"id":"r","forbid":{"severity":"CRITICAL"}}]')
        html, _ = write_report(log, os.path.join(d, "r.html"), policy_path=pol)
        blocks, _ = _page_parts(html)
        edited = html.replace(blocks["halo-policy"], json.dumps(DUP_FORBID).replace("<", "\\u003c"))
        out = _run_page(edited)
        self.assertIn("not a valid policy", out["policy"]["html"])
        self.assertIn("duplicate key", out["policy"]["html"])
        self.assertNotIn("COMPLIANT", out["policy"]["html"])
        self.assertNotIn("Verdict:", out["policy"]["html"])


if __name__ == "__main__":
    unittest.main()
