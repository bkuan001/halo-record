"""Identifiers are stored exactly as given, invisible characters included, but
an invisible character cannot make a lookalike id slip past a policy rule or
read identically in the report.

  * Policy matching compares string values with invisible characters removed,
    in ``halo policy`` and in the page's evaluator alike.
  * The report shows an invisible character in an agent, tool or session id
    as a visible marker (``⟨U+200B⟩``).
  * ``halo policy`` and ``halo report`` print a warning naming each record
    whose identifier carries one.
"""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest

from halo_record import _view
from halo_record.cli import main
from halo_record.policy import evaluate
from halo_record.record import Recorder, build
from halo_record.verify import read_log_lines
from tests.test_page_binding import NODE

RULES = [{"id": "no-email-from-payments", "when": {"agent.id": "payments-bot"},
          "forbid": {"action.tool": "send_email"}}]

LOOKALIKES = [
    ("payments-bot", "send_email"),
    ("payments​-bot", "send⁠_email"),
    ("payments‮-bot", "send_email"),
    ("pay\U000E0041ments-bot", "send_email"),
]


def _chain():
    d = tempfile.mkdtemp()
    log = os.path.join(d, "c.jsonl")
    rec = Recorder(log)
    with contextlib.redirect_stderr(io.StringIO()):
        for aid, tool in LOOKALIKES:
            rec.append(build("tool_call", "security", tool=tool, subject="acme",
                             agent={"id": aid, "name": aid}, session_id="s​1"))
    pol = os.path.join(d, "p.json")
    with open(pol, "w", encoding="utf-8") as fh:
        json.dump(RULES, fh)
    return d, log, pol, [json.loads(l) for l in read_log_lines(log)]


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class StoredAsGivenTest(unittest.TestCase):
    def test_identifiers_keep_their_invisible_characters(self):
        _, _, _, records = _chain()
        self.assertEqual([r["agent"]["id"] for r in records], [a for a, _ in LOOKALIKES])
        self.assertEqual([r["action"]["tool"] for r in records], [t for _, t in LOOKALIKES])


class PolicyMatchingTest(unittest.TestCase):
    def test_lookalike_ids_are_matched_by_the_rule(self):
        _, _, _, records = _chain()
        res = evaluate(records, RULES)
        self.assertEqual(len(res["rules"][0]["violators"]), 4)

    def test_every_matcher_ignores_invisible_characters(self):
        rec = {"record_id": "r", "agent": {"id": "a​b"}, "data": {"pii_types": ["s­sn"]}}
        for spec in ("ab", {"eq": "ab"}, {"in": ["ab"]}):
            self.assertEqual(evaluate([rec], [{"id": "x", "forbid": {"agent.id": spec}}])
                             ["violations"], 1, spec)
        for spec in ({"ne": "ab"}, {"nin": ["ab"]}):
            self.assertEqual(evaluate([rec], [{"id": "x", "forbid": {"agent.id": spec}}])
                             ["violations"], 0, spec)
        self.assertEqual(evaluate([rec], [{"id": "x", "forbid": {"data.pii_types": {
            "contains": "ssn"}}}])["violations"], 1)

    def test_cli_warns_and_reports_the_violations(self):
        _, log, pol, _ = _chain()
        code, out, err = _run(["policy", log, pol])
        self.assertEqual(code, 1, out + err)
        self.assertIn("4 record(s)", out)
        self.assertIn("WARNING", err)
        self.assertIn("agent.id", err)
        self.assertIn("⟨U+200B⟩", err)


@unittest.skipUnless(NODE, "node not installed")
class PageEvaluatorParityTest(unittest.TestCase):
    def test_page_finds_the_same_violators(self):
        _, _, _, records = _chain()
        cases = [{"records": records, "rules": RULES},
                 {"records": [{"record_id": "r", "agent": {"id": "a​b"},
                               "data": {"pii_types": ["s­sn"]}}],
                  "rules": [{"id": "x", "forbid": {"agent.id": {"in": ["ab"]},
                                                   "data.pii_types": {"contains": "ssn"}}}]}]
        d = tempfile.mkdtemp()
        data = os.path.join(d, "cases.json")
        with open(data, "w", encoding="utf-8") as fh:
            json.dump(cases, fh)
        js = os.path.join(d, "h.js")
        with open(js, "w", encoding="utf-8") as fh:
            fh.write(_view.render_js() + r"""
const cases = JSON.parse(require("fs").readFileSync(process.argv[2], "utf8"));
process.stdout.write(JSON.stringify(cases.map(c => HaloView.evaluate(c.records, c.rules, true, null))));
""")
        p = subprocess.run([NODE, js, data], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = json.loads(p.stdout)
        for case, page in zip(cases, got):
            py = evaluate(case["records"], case["rules"])
            self.assertEqual([r["violators"] for r in page["rules"]],
                             [r["violators"] for r in py["rules"]])
        self.assertEqual(len(got[0]["rules"][0]["violators"]), 4)


class ReportDisplayTest(unittest.TestCase):
    def test_invisible_characters_in_ids_are_shown(self):
        _, _, _, records = _chain()
        regions = _view.regions(records)
        self.assertIn("payments⟨U+200B⟩-bot", regions["meta"])
        self.assertIn("pay⟨U+E0041⟩ments-bot", regions["meta"])
        rows = "".join(regions["rows"])
        self.assertIn("send⟨U+2060⟩_email", rows)
        self.assertIn("payments⟨U+202E⟩-bot", rows)
        self.assertNotIn("​", regions["meta"])

    def test_plain_ids_render_unchanged(self):
        self.assertEqual(_view.show_id("payments-bot"), "payments-bot")
        self.assertEqual(_view.show_id("café \U0001F600"), "café \U0001F600")

    def test_report_cli_warns(self):
        d, log, _, _ = _chain()
        code, out, err = _run(["report", log, "-o", os.path.join(d, "r.html")])
        self.assertIn("WARNING", err)
        self.assertIn("session_id", err)
        self.assertIn("action.tool", err)


if __name__ == "__main__":
    unittest.main()
