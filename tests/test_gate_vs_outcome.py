"""A gate's "blocked" report does not outrank the recorded outcome.

When the gate reported blocked but the outcome records the action as ok, the
page says both; the starter packs' egress rules take a record out of scope
only when its outcome is recorded as denied.
"""

import os
import unittest

from halo_record import _view
from halo_record.policy import evaluate, load_policy
from halo_record.record import build

HERE = os.path.dirname(os.path.abspath(__file__))
PACKS = os.path.join(os.path.dirname(HERE), "examples", "policies")


def _egress(rec):
    out = {}
    for name in ("owasp-starter.json", "aiuc-1-starter.json"):
        res = evaluate([rec], load_policy(os.path.join(PACKS, name)))
        out[name] = [r for r in res["rules"] if r["id"] == "pii-egress-controlled"][0]["status"]
    return out


class GateDisplayTest(unittest.TestCase):
    def test_conflicting_gate_and_outcome_are_both_shown(self):
        r = build("tool_call", "security", tool="payments.refund", tool_input={"amount": 9},
                  verification={"status": "blocked", "verifier": "gate/1"},
                  outcome={"status": "ok", "summary": "refund issued"})
        text = _view.plain(r)
        self.assertTrue(text.startswith("Gate reported blocked; outcome recorded: ok"), text)
        self.assertNotIn("Blocked by gate", text)

    def test_only_a_denied_outcome_reads_blocked(self):
        r = build("tool_call", "security", tool="payments.refund",
                  verification={"status": "blocked"}, outcome={"status": "denied"})
        self.assertTrue(_view.plain(r).startswith("Blocked by gate: payments.refund"))

    def test_blocked_with_an_error_or_no_outcome_says_what_was_recorded(self):
        # The egress rules keep these records in scope (the action may have
        # run), so the display does not call them blocked either.
        cases = {"error": "Gate reported blocked; outcome recorded: error",
                 None: "Gate reported blocked; outcome not recorded"}
        for status, expected in cases.items():
            r = build("tool_call", "security", tool="payments.refund",
                      verification={"status": "blocked"},
                      outcome={"status": status, "summary": "timeout after send"} if status else None)
            text = _view.plain(r)
            self.assertTrue(text.startswith(expected + " \u2014 payments.refund"), text)
            self.assertNotIn("Blocked by gate", text)

    def test_denied_decision_follows_the_same_rule(self):
        cases = {"denied": "Denied: payments.refund",
                 "error": "Decision recorded denied; outcome recorded: error \u2014 payments.refund",
                 None: "Decision recorded denied; outcome not recorded \u2014 payments.refund"}
        for status, expected in cases.items():
            r = build("tool_call", "security", tool="payments.refund", decision="denied",
                      outcome={"status": status} if status else None)
            self.assertTrue(_view.plain(r).startswith(expected), (status, _view.plain(r)))
        r = build("tool_call", "security", tool="payments.refund", outcome={"status": "denied"})
        self.assertTrue(_view.plain(r).startswith("Denied: payments.refund"))

    def test_display_matches_the_egress_rule(self):
        for ver, dec, status in [("blocked", None, "error"), ("blocked", None, None),
                                 (None, "denied", "error"), (None, "denied", None),
                                 ("blocked", None, "denied"), ("blocked", "denied", "ok")]:
            kw = {}
            if ver:
                kw["verification"] = {"status": ver}
            if dec:
                kw["decision"] = dec
            rec = build("network", "privacy", tool="post", tool_input={"body": "ssn 123-45-6789"},
                        outcome={"status": status} if status else None, **kw)
            in_scope = "violated" in _egress(rec).values()
            reads_stopped = _view.plain(rec).startswith(("Blocked by gate", "Denied"))
            self.assertEqual(in_scope, not reads_stopped, (ver, dec, status))


class EgressScopeTest(unittest.TestCase):
    def _rec(self, **kw):
        return build("network", "privacy", tool="post", tool_input={"body": "ssn 123-45-6789"}, **kw)

    def test_a_gate_block_with_an_ok_outcome_is_in_scope(self):
        rec = self._rec(verification={"status": "blocked"}, outcome={"status": "ok", "summary": "200 OK sent"})
        self.assertEqual(set(_egress(rec).values()), {"violated"})

    def test_a_denied_decision_with_an_ok_outcome_is_in_scope(self):
        rec = self._rec(decision="denied", outcome={"status": "ok", "summary": "sent"})
        self.assertEqual(set(_egress(rec).values()), {"violated"})

    def test_an_outcome_recorded_as_denied_is_out_of_scope(self):
        rec = self._rec(verification={"status": "blocked"}, decision="denied",
                        outcome={"status": "denied"})
        self.assertNotIn("violated", _egress(rec).values())

    def test_descriptions_do_not_say_blocked_actions_did_not_egress(self):
        for name in ("owasp-starter.json", "aiuc-1-starter.json"):
            with open(os.path.join(PACKS, name), encoding="utf-8") as fh:
                text = fh.read()
            self.assertNotIn("did not egress", text, name)
            self.assertNotIn("verification.status", text, name)


if __name__ == "__main__":
    unittest.main()


class GatePageParityTest(unittest.TestCase):
    def test_page_rows_state_the_gate_as_python_does(self):
        import re
        import tempfile
        from halo_record.record import Recorder
        from halo_record.report import write_report
        from tests.test_page_binding import NODE, _run_page
        if not NODE:
            self.skipTest("node not installed")
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        rec = Recorder(log)
        combos = [("blocked", None, "error"), ("blocked", None, None), ("blocked", None, "denied"),
                  ("blocked", None, "ok"), (None, "denied", "error"), (None, "denied", None),
                  (None, "denied", "ok"), (None, None, "denied")]
        for ver, dec, status in combos:
            kw = {}
            if ver:
                kw["verification"] = {"status": ver}
            if dec:
                kw["decision"] = dec
            rec.append(build("tool_call", "security", tool="payments.refund", subject="acme",
                             outcome={"status": status} if status else None, **kw))
        html, _ = write_report(log, os.path.join(d, "r.html"))
        out = _run_page(html)
        cell = re.compile(r'<td class="trunc dim">(.*?)</td>')
        page = [cell.search(r).group(1) for r in out["rows"]]
        static_body = html[html.index('<tbody id="activity-body">'):html.index("</tbody>")]
        static = cell.findall(static_body)
        self.assertEqual(page, static)
        self.assertEqual(len(page), len(combos))
