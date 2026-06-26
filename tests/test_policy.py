"""Tests for the policy-corroboration engine (deterministic, evaluative)."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from halo_record.cli import main
from halo_record.policy import evaluate, render_text, render_html, verdict_panel


def _rec(rid, **fields):
    """Minimal record dict; the policy engine reads fields, doesn't schema-check."""
    base = {"record_id": rid, "schema_version": "0.1"}
    base.update(fields)
    return base


# a small support-agent chain
CHAIN = [
    _rec("r1",
         action={"type": "read", "category": "privacy", "tool": "lookup_order"},
         data={"pii_types": ["email"]}),
    _rec("r2",
         action={"type": "tool_call", "category": "security", "tool": "issue_refund",
                 "authorization": {"decision": "human_approved", "approver": "agent_lead"}}),
    _rec("r3",
         action={"type": "tool_call", "category": "security", "tool": "issue_refund",
                 "authorization": {"decision": "allowed"}}),               # unapproved
    _rec("r4",
         action={"type": "network", "category": "privacy", "tool": "post_webhook"},
         data={"pii_types": ["ssn", "email"]},                            # PII egress
         findings=[{"type": "ssn", "severity": "HIGH", "sample": "***"}]),
]

REFUND_RULE = {
    "id": "refunds-need-human",
    "description": "Any refund must be human-approved.",
    "severity": "HIGH",
    "when": {"action.tool": "issue_refund"},
    "forbid": {"action.authorization.decision": {"ne": "human_approved"}},
}


class TestPolicyEngine(unittest.TestCase):

    def test_pass_when_all_compliant(self):
        result = evaluate([CHAIN[0], CHAIN[1]], [REFUND_RULE])   # only approved refund
        self.assertTrue(result["compliant"])
        self.assertEqual(result["rules"][0]["status"], "pass")
        self.assertEqual(result["rules"][0]["matched"], 1)

    def test_forbid_catches_unapproved_refund(self):
        result = evaluate(CHAIN, [REFUND_RULE])
        self.assertFalse(result["compliant"])
        rule = result["rules"][0]
        self.assertEqual(rule["status"], "violated")
        self.assertEqual(rule["violators"], ["r3"])              # r2 approved, r3 not

    def test_forbid_pii_to_network(self):
        policy = [{
            "id": "no-pii-egress", "severity": "CRITICAL",
            "when": {"action.type": "network"},
            "forbid": {"data.pii_types": {"contains": "ssn"}},
        }]
        result = evaluate(CHAIN, policy)
        self.assertEqual(result["rules"][0]["status"], "violated")
        self.assertEqual(result["rules"][0]["violators"], ["r4"])

    def test_forbid_high_findings_via_array_fanout(self):
        policy = [{
            "id": "no-high-findings", "severity": "HIGH",
            "forbid": {"findings[].severity": {"in": ["CRITICAL", "HIGH"]}},
        }]
        result = evaluate(CHAIN, policy)
        self.assertEqual(result["rules"][0]["violators"], ["r4"])

    def test_require_violation(self):
        # every privacy action must declare a data purpose; none do -> all violate
        policy = [{
            "id": "purpose-required", "severity": "MEDIUM",
            "when": {"action.category": "privacy"},
            "require": {"data.purpose": {"exists": True}},
        }]
        result = evaluate(CHAIN, policy)
        self.assertEqual(set(result["rules"][0]["violators"]), {"r1", "r4"})

    def test_expect_evidence_gap(self):
        policy = [{
            "id": "deletes-recorded", "severity": "MEDIUM",
            "when": {"action.tool": "delete_account"},
            "expect_evidence": True,
        }]
        result = evaluate(CHAIN, policy)
        self.assertEqual(result["rules"][0]["status"], "no_evidence")
        self.assertEqual(result["gaps"], 1)
        self.assertTrue(result["compliant"])    # gaps reported apart from violations

    def test_threats_fanout(self):
        chain = [_rec("t1", threats=[{"type": "prompt_injection_indirect"}])]
        policy = [{
            "id": "no-unmitigated-injection", "severity": "HIGH",
            "forbid": {"threats[].type": {"in": ["prompt_injection_direct",
                                                 "prompt_injection_indirect"]}},
        }]
        self.assertEqual(evaluate(chain, policy)["rules"][0]["status"], "violated")

    def test_render_text(self):
        text = render_text(evaluate(CHAIN, [REFUND_RULE]))
        self.assertIn("NON-COMPLIANT", text)
        self.assertIn("refunds-need-human", text)

    def test_render_html_panel(self):
        rule = dict(REFUND_RULE, source="vendor policy")
        result = evaluate(CHAIN, [rule])
        panel = verdict_panel(result, subject="acme-corp")
        self.assertIn("hp-card", panel)
        self.assertIn("FAIL", panel)
        self.assertIn("vendor policy", panel)          # source surfaced
        self.assertIn("acme-corp", panel)
        self.assertIn("No model judgment", panel)      # the load-bearing footer
        doc = render_html(result)
        self.assertTrue(doc.startswith("<!doctype html>"))


class TestPolicyCLI(unittest.TestCase):
    """Exercise `halo policy` end to end through the real argparse entrypoint."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "chain.jsonl")
        with open(self.log, "w", encoding="utf-8") as fh:
            for rec in CHAIN:
                fh.write(json.dumps(rec) + "\n")
        self.policy = os.path.join(self.dir, "policy.json")
        with open(self.policy, "w", encoding="utf-8") as fh:
            json.dump([REFUND_RULE], fh)

    def test_cli_text_nonzero_exit_on_violation(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["policy", self.log, self.policy])
        self.assertEqual(code, 1)                       # CI-friendly: violation -> non-zero
        self.assertIn("refunds-need-human", buf.getvalue())

    def test_cli_clean_exit_zero(self):
        clean = os.path.join(self.dir, "clean.jsonl")
        with open(clean, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(CHAIN[1]) + "\n")       # the approved refund only
        with redirect_stdout(io.StringIO()):
            code = main(["policy", clean, self.policy])
        self.assertEqual(code, 0)

    def test_cli_html_output(self):
        out = os.path.join(self.dir, "verdict.html")
        with redirect_stdout(io.StringIO()):
            main(["policy", self.log, self.policy, "--html", out, "--subject", "acme-corp"])
        self.assertTrue(os.path.exists(out))
        with open(out, encoding="utf-8") as fh:
            self.assertIn("hp-card", fh.read())

    def test_cli_json_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["policy", self.log, self.policy, "--json"])
        data = json.loads(buf.getvalue())
        self.assertFalse(data["compliant"])
        self.assertEqual(data["violations"], 1)


class TestStarterPack(unittest.TestCase):
    """The shipped starter packs load and evaluate."""

    def _packs_dir(self):
        here = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(here, "..", "examples", "policies")

    def _pack_path(self):
        return os.path.join(self._packs_dir(), "aiuc-1-starter.json")

    def test_pack_loads_and_runs(self):
        from halo_record.policy import load_policy
        rules = load_policy(self._pack_path())            # accepts {"rules":[...]}
        self.assertTrue(len(rules) >= 5)
        result = evaluate(CHAIN, rules)
        # CHAIN has an SSN finding (r4) -> the no-secret-leakage rule must fire
        fired = {r["id"] for r in result["rules"] if r["status"] == "violated"}
        self.assertIn("no-secret-leakage", fired)

    def test_all_shipped_packs_load_and_run(self):
        import glob
        from halo_record.policy import load_policy
        packs = sorted(glob.glob(os.path.join(self._packs_dir(), "*.json")))
        self.assertTrue(packs, "no starter packs found")
        for pack in packs:
            rules = load_policy(pack)                      # must parse
            self.assertTrue(len(rules) >= 3, "%s has too few rules" % pack)
            evaluate(CHAIN, rules)                         # must run without error


class TestReportIntegration(unittest.TestCase):
    """The policy verdict embeds into the actual Runtime Report."""

    def test_render_includes_policy_panel(self):
        from halo_record.report import render
        doc = render(CHAIN, policy=[dict(REFUND_RULE, source="vendor policy")])
        self.assertIn("Policy corroboration", doc)
        self.assertIn("hp-card", doc)
        self.assertIn("NON-COMPLIANT", doc)
        self.assertIn("No model judgment", doc)

    def test_render_omits_panel_without_policy(self):
        from halo_record.report import render
        doc = render(CHAIN)
        self.assertNotIn("hp-card", doc)
        self.assertNotIn("Policy corroboration", doc)

    def test_report_cli_with_policy(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "chain.jsonl")
        with open(log, "w", encoding="utf-8") as fh:
            for rec in CHAIN:
                fh.write(json.dumps(rec) + "\n")
        pol = os.path.join(d, "policy.json")
        with open(pol, "w", encoding="utf-8") as fh:
            json.dump([REFUND_RULE], fh)
        out = os.path.join(d, "report.html")
        with redirect_stdout(io.StringIO()):
            code = main(["report", log, "-o", out, "--policy", pol])
        self.assertEqual(code, 0)
        with open(out, encoding="utf-8") as fh:
            doc = fh.read()
        self.assertIn("Policy corroboration", doc)
        self.assertIn("Runtime Record", doc)          # base report intact


if __name__ == "__main__":
    unittest.main()
