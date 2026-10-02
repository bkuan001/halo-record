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

    def test_blocked_without_a_conflicting_outcome_reads_blocked(self):
        for outcome in (None, {"status": "denied"}, {"status": "error"}):
            r = build("tool_call", "security", tool="payments.refund",
                      verification={"status": "blocked"}, outcome=outcome)
            self.assertTrue(_view.plain(r).startswith("Blocked by gate"), outcome)


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
