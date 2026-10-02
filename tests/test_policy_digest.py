"""The policy digest is the SHA-256 of the policy file, and the page says where
its rules came from.

* ``halo policy`` and the report show ``sha256`` of the policy file's bytes,
  the value ``shasum -a 256 <file>`` prints;
* the page carries the policy file's text, hashes it in the browser, and
  states that the rules were embedded by whoever generated the page;
* a page whose policy was removed says no policy is embedded and its badge
  claims no policy verdict; an embedded policy that is not valid is withheld
  as such, without blaming the records;
* the page validates an embedded policy exactly as ``validate_policy`` does.
"""

import contextlib
import hashlib
import io
import json
import os
import re
import subprocess
import tempfile
import unittest

from halo_record import _view
from halo_record.cli import main
from halo_record.policy import validate_policy
from halo_record.record import Recorder, build
from halo_record.report import write_report
from tests.test_page_binding import NODE, _page_parts, _run_page
from tests.test_policy_values import REJECTED

POLICY_TEXT = ('{\n  "name": "refunds",\n  "rules": [\n'
               '    {"id": "refunds-need-human", "when": {"action.tool": "issue_refund"},\n'
               '     "forbid": {"action.authorization.decision": {"ne": "human_approved"}}},\n'
               '    {"id": "ts", "require": {"ts": {"exists": true}}}\n  ]\n}\n')


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class _Chain(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.log = os.path.join(self.d, "c.jsonl")
        rec = Recorder(self.log)
        for tool in ("lookup", "issue_refund", "lookup"):
            rec.append(build("tool_call", "security", tool=tool, subject="acme", decision="allowed"))
        self.policy = os.path.join(self.d, "p.json")
        with open(self.policy, "w", encoding="utf-8", newline="") as fh:
            fh.write(POLICY_TEXT)
        self.digest = _sha(self.policy)


class CliDigestTest(_Chain):
    def _run(self, argv):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = main(argv)
        return code, out.getvalue()

    def test_json_and_text_show_the_file_digest(self):
        code, out = self._run(["policy", self.log, self.policy, "--json"])
        self.assertEqual(json.loads(out)["policy_sha256"], self.digest)
        code, out = self._run(["policy", self.log, self.policy])
        self.assertIn(self.digest[:16], out)
        self.assertIn("shasum -a 256", out)

    def test_bundled_pack_digest_is_the_pack_file(self):
        import halo_record
        pack = os.path.join(os.path.dirname(halo_record.__file__), "policies", "owasp-starter.json")
        code, out = self._run(["policy", self.log, "owasp-starter", "--json"])
        self.assertEqual(json.loads(out)["policy_sha256"], _sha(pack))


@unittest.skipUnless(NODE, "node not installed")
class PageDigestTest(_Chain):
    def setUp(self):
        super().setUp()
        self.html, _ = write_report(self.log, os.path.join(self.d, "r.html"), policy_path=self.policy)
        self.blocks, _ = _page_parts(self.html)

    def _with_policy_block(self, text):
        return self.html.replace(self.blocks["halo-policy"], text)

    def test_page_shows_the_file_digest_and_where_the_rules_came_from(self):
        out = _run_page(self.html)
        self.assertIn(self.digest[:16], out["policy"]["html"])
        self.assertIn("embedded", out["policy"]["html"])
        self.assertIn("policy embedded in this page", out["verdict"]["html"])
        self.assertIn(self.digest[:16], out["verdict"]["html"])

    def test_a_removed_rule_changes_the_digest(self):
        edited = json.dumps(POLICY_TEXT.replace(
            '    {"id": "ts", "require": {"ts": {"exists": true}}}\n', "").replace("}},\n", "}}\n"))
        edited = edited.replace("<", "\\u003c")
        out = _run_page(self._with_policy_block(edited))
        self.assertIn("ok", out["verdict"]["className"])
        self.assertNotIn(self.digest[:16], out["policy"]["html"])
        self.assertNotIn(self.digest[:16], out["verdict"]["html"])

    def test_a_removed_policy_claims_no_verdict(self):
        out = _run_page(self._with_policy_block("null"))
        self.assertIn("ok", out["verdict"]["className"])
        self.assertNotIn("verdict", out["verdict"]["html"].lower())
        self.assertIn("No policy is embedded", out["policy"]["html"])

    def test_an_invalid_embedded_policy_is_withheld_as_such(self):
        bad = json.dumps('[{"id":"r","forbid":{"data.cross_region":{"lt":1e400}}}]')
        out = _run_page(self._with_policy_block(bad))
        self.assertIn("ok", out["verdict"]["className"])
        self.assertIn("not a valid policy", out["policy"]["html"])
        self.assertNotIn("could not be verified", out["policy"]["html"])
        self.assertNotIn("Verdict:", out["policy"]["html"])
        bad = json.dumps('[{"id":"r","forbid":{"outcome.status":"deny"}}]')
        out = _run_page(self._with_policy_block(bad))
        self.assertIn("not a valid policy", out["policy"]["html"])


_HARNESS = r"""
const fs = require("fs");
%s
const cases = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
process.stdout.write(JSON.stringify(cases.map(c => HaloView.validatePolicy(c))));
"""


@unittest.skipUnless(NODE, "node not installed")
class ValidationParityTest(unittest.TestCase):
    def test_page_validation_matches_python(self):
        cases = []
        for cond, _why in REJECTED:
            for key in ("forbid", "require", "when"):
                rule = {"id": "r", key: cond}
                if key == "when":
                    rule["expect_evidence"] = True
                cases.append([rule])
        cases += [[{"id": "r", "forbid": {"data.pii_types": {"contains": "ssn"}}}],
                  [{"id": "r", "when": {"action.tool": "x"}, "expect_evidence": True}],
                  [{"id": "r", "forbid": {"nope": 1}}], [{"id": "r"}], [],
                  [{"id": "r", "forbid": {"ts": {"exist": True}}}],
                  [{"id": "a", "forbid": {"severity": "HIGH"}}, {"id": "a", "forbid": {"severity": "LOW"}}],
                  [{"id": "r", "severity": "BAD", "forbid": {"severity": "HIGH"}}],
                  [{"id": "r", "oops": 1, "forbid": {"severity": "HIGH"}}]]
        for name in ("owasp-starter.json", "aiuc-1-starter.json"):
            with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                   "examples", "policies", name), encoding="utf-8") as fh:
                cases.append(json.load(fh)["rules"])
        expected = []
        js_cases = []
        for c in cases:
            try:
                validate_policy(c)
                expected.append(None)
            except ValueError as e:
                expected.append(str(e))
            js_cases.append(c)
        d = tempfile.mkdtemp()
        data = os.path.join(d, "cases.json")
        # NaN and Infinity are not JSON; the page reads 1e400 as Infinity.
        text = json.dumps(js_cases).replace("NaN", "null").replace("Infinity", "1e400")
        with open(data, "w", encoding="utf-8") as fh:
            fh.write(text)
        js = os.path.join(d, "h.js")
        with open(js, "w", encoding="utf-8") as fh:
            fh.write(_HARNESS % _view.render_js())
        p = subprocess.run([NODE, js, data], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = json.loads(p.stdout)
        for c, py, page in zip(cases, expected, got):
            self.assertEqual(page is None, py is None, json.dumps(c, default=str))
            if py is not None and "NaN" not in json.dumps(c) and "Infinity" not in json.dumps(c):
                self.assertEqual(page, py, json.dumps(c))


if __name__ == "__main__":
    unittest.main()
