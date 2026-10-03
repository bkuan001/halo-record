"""A policy whose values could never match what a record holds is rejected.

Each of these used to evaluate to COMPLIANT on a chain of denied actions: a
value outside the field's allowed set, a matcher of the wrong type for the
field, a contradiction, a non-finite number, a duplicate JSON key, or a
null. ``validate_policy`` / ``load_policy`` now refuse them, and the CLI
exits 2 with the reason.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest

from halo_record.cli import main
from halo_record.policy import evaluate, load_policy, render_text, validate_policy

REJECTED = [
    # enum values
    ({"action.authorization.decision": "deny"}, "not one of"),
    ({"action.authorization.decision": "DENIED"}, "not one of"),
    ({"outcome.status": {"in": ["ok", "failed"]}}, "not one of"),
    ({"verification.status": {"ne": "block"}}, "not one of"),
    ({"findings[].severity": {"eq": "critical"}}, "not one of"),
    # operator / value type against the field type
    ({"action.tool": {"contains": "s3"}}, "list fields"),
    ({"subject.id": {"contains": "north"}}, "list fields"),
    ({"data.pii_types": "ssn"}, "is a list"),
    ({"data.pii_types": {"in": ["ssn"]}}, "is a list"),
    ({"action.tool": 5}, "needs a string"),
    ({"ts": {"gt": 0}}, "numeric fields"),
    ({"agent.version": {"gt": 3}}, "numeric fields"),
    ({"data.cross_region": "1"}, "needs a number"),
    ({"data.pii_types": {"contains": 5}}, "needs a string"),
    ({"subject": "acme"}, "is an object"),
    ({"findings.type": "ssn"}, "use \"findings[]\""),
    # contradictions
    ({"outcome.status": {"eq": "denied", "ne": "denied"}}, "contradict"),
    ({"outcome.status": {"eq": "ok", "in": ["denied"]}}, "contradict"),
    ({"outcome.status": {"eq": "ok", "nin": ["ok"]}}, "contradict"),
    ({"outcome.status": {"in": []}}, "empty"),
    ({"data.cross_region": {"gt": 5, "lt": 3}}, "contradict"),
    ({"data.cross_region": {"exists": False, "eq": 1}}, "contradict"),
    ({"threats[].type": {"in": ["tool_misuse"], "nin": ["tool_misuse", "policy_violation"]}},
     "contradict"),
    # null and non-finite values
    ({"action.authorization.approver": {"ne": None}}, "exists"),
    ({"action.authorization.approver": None}, "exists"),
    ({"data.cross_region": {"gte": float("nan")}}, "finite"),
    ({"data.cross_region": {"lt": float("inf")}}, "finite"),
    ({"data.cross_region": {"lt": 2 ** 60}}, "2^53"),
    ({"data.cross_region": {"gte": 1e308}}, "2^53"),
    ({"data.cross_region": {"lt": -1e16}}, "2^53"),
    # free-vocabulary fields: only the scanner's and the documented threat types
    ({"findings[].type": "SSN"}, "not one of"),
    ({"findings[].type": {"in": ["social_security", "ssn"]}}, "not one of"),
    ({"findings[].type": {"ne": "credit-card"}}, "not one of"),
    ({"threats[].type": "PII_EXFILTRATION"}, "not one of"),
    ({"threats[].type": {"nin": ["prompt_injection"]}}, "not one of"),
]


def _rule(cond, key="forbid"):
    return [{"id": "r", key: cond}]


class RejectedValuesTest(unittest.TestCase):
    def test_each_is_rejected_in_every_condition(self):
        for cond, why in REJECTED:
            for key in ("forbid", "require", "when"):
                rule = _rule(cond, key)
                if key == "when":
                    rule[0]["expect_evidence"] = True
                with self.subTest(cond=cond, key=key):
                    with self.assertRaises(ValueError) as cm:
                        validate_policy(rule)
                    self.assertIn(why, str(cm.exception))

    def test_valid_values_still_pass(self):
        for cond in ({"action.authorization.decision": "denied"},
                     {"outcome.status": {"in": ["ok", "error"]}},
                     {"data.pii_types": {"contains": "ssn"}},
                     {"data.pii_types[]": "ssn"},
                     {"data.cross_region": {"gte": 1, "lte": 1}},
                     {"findings[].type": {"in": ["ssn"], "nin": ["email"]}},
                     {"action.authorization.approver": {"exists": True}},
                     {"subject": {"exists": True}},
                     {"agent.version": "3.2.1"},
                     {"data.zdr": True}):
            validate_policy(_rule(cond))


class PolicyFileParsingTest(unittest.TestCase):
    def _file(self, text):
        p = os.path.join(tempfile.mkdtemp(), "p.json")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p

    def test_duplicate_keys_are_rejected(self):
        p = self._file('[{"id":"r","forbid":{"outcome.status":"denied"},'
                       '"forbid":{"outcome.status":"ok"}}]')
        with self.assertRaises(ValueError) as cm:
            load_policy(p)
        self.assertIn("duplicate key", str(cm.exception))

    def test_non_finite_literals_are_rejected(self):
        for lit in ("NaN", "Infinity", "-Infinity", "1e400"):
            p = self._file('[{"id":"r","forbid":{"data.cross_region":{"lt":%s}}}]' % lit)
            with self.assertRaises(ValueError, msg=lit) as cm:
                load_policy(p)
            self.assertIn("finite", str(cm.exception), lit)

    def test_cli_exits_2_with_the_reason(self):
        d = tempfile.mkdtemp()
        from halo_record.record import Recorder, build
        log = os.path.join(d, "c.jsonl")
        Recorder(log).append(build("tool_call", "security", tool="t", decision="denied"))
        p = self._file('[{"id":"r","forbid":{"data.cross_region":{"lt":1e400}}}]')
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(err):
            code = main(["policy", log, p])
        self.assertEqual(code, 2)
        self.assertIn("finite", out.getvalue() + err.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = main(["report", log, "-o", os.path.join(d, "r.html"), "--policy", p])
        self.assertNotEqual(code, 0)
        self.assertFalse(os.path.exists(os.path.join(d, "r.html")))


class NoRecordsMatchedTest(unittest.TestCase):
    def test_a_rule_whose_scope_matches_nothing_says_so(self):
        res = evaluate([{"record_id": "a", "action": {"tool": "x"}}],
                       [{"id": "r", "when": {"action.tool": "y"}, "forbid": {"severity": "HIGH"}}])
        self.assertEqual(res["rules"][0]["status"], "no_match")
        self.assertIn("matched no records", render_text(res))


if __name__ == "__main__":
    unittest.main()
