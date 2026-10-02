"""Evidence surfaces — report page, export, policy, witness, serve — say exactly
what they verified, bind what they display to what they verified, and fail
closed when a check they depend on cannot run."""

import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from halo_record.record import Recorder, build
from halo_record.verify import verify_log


def _chain(path, n=4, subject="acme", **kw):
    rec = Recorder(path)
    out = []
    for i in range(n):
        out.append(rec.append(build("tool_call", "security", tool="t%d" % i,
                                    tool_input={"i": i}, subject=subject, **kw)))
    return out


def _drop_line(path, idx):
    with open(path, encoding="utf-8") as fh:
        lines = [ln for ln in fh.read().split("\n") if ln.strip()]
    del lines[idx]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


class DeletionMessageTest(unittest.TestCase):
    def test_a_deleted_record_is_reported_as_a_missing_link_not_a_hash_mismatch(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        _chain(log, 4)
        _drop_line(log, 1)
        lines = []
        self.assertFalse(verify_log(log, out=lines.append))
        text = "\n".join(lines)
        self.assertIn("record 2", text)
        self.assertRegex(text, r"record 2: chain: .*missing|record 2: chain: .*not the record before it")
        self.assertNotIn("does not match recomputed", text)

    def test_an_edited_record_still_reports_its_own_hash_mismatch(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        _chain(log, 3)
        with open(log, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        lines[1] = lines[1].replace('"t1"', '"tX"')
        with open(log, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        out = []
        self.assertFalse(verify_log(log, out=out.append))
        self.assertIn("record 2: chain: hash", "\n".join(out))


if __name__ == "__main__":
    unittest.main()


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKS = os.path.join(ROOT, "examples", "policies")


def _run(argv):
    from halo_record.cli import main
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def _write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    return path


class PolicyValidationTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.log = os.path.join(self.d, "c.jsonl")
        _chain(self.log, 3)

    def _policy(self, rules):
        return _write_json(os.path.join(self.d, "p.json"), {"rules": rules})

    def test_misspelled_rule_key_is_rejected_not_passed(self):
        p = self._policy([{"id": "r", "when": {"action.tool": "t0"},
                           "forbidd": {"severity": "CRITICAL"}}])
        code, out, err = _run(["policy", self.log, p])
        self.assertNotEqual(code, 0)
        self.assertNotIn("PASS", out)
        self.assertIn("forbidd", out + err)

    def test_rule_with_no_check_is_rejected(self):
        p = self._policy([{"id": "r", "when": {"action.tool": "t0"}}])
        code, out, err = _run(["policy", self.log, p])
        self.assertEqual(code, 2)
        self.assertIn("forbid", out + err)

    def test_misspelled_field_path_is_rejected(self):
        p = self._policy([{"id": "r", "forbid": {"acton.tool": "t0"}}])
        code, out, err = _run(["policy", self.log, p])
        self.assertEqual(code, 2)
        self.assertIn("acton", out + err)

    def test_unknown_matcher_is_rejected_before_evaluation(self):
        from halo_record.policy import validate_policy
        with self.assertRaises(ValueError):
            validate_policy([{"id": "r", "require": {"ts": {"exist": True}}}])

    def test_report_refuses_an_invalid_policy(self):
        p = self._policy([{"id": "r", "when": {"action.tool": "t0"}}])
        code, out, _ = _run(["report", self.log, "-o", os.path.join(self.d, "r.html"),
                             "--policy", p])
        self.assertNotEqual(code, 0)
        self.assertFalse(os.path.exists(os.path.join(self.d, "r.html")))

    def test_shipped_packs_validate(self):
        from halo_record.policy import load_policy
        for name in ("owasp-starter.json", "aiuc-1-starter.json"):
            load_policy(os.path.join(PACKS, name))

    def test_policy_help_points_to_the_format(self):
        code, out, _ = _run_help(["policy", "--help"])
        self.assertRegex(out, r"(?s)when.*forbid.*require.*expect_evidence")
        self.assertIn("owasp-starter", out)          # bundled packs are named

    def test_bundled_pack_runs_by_name_from_an_installed_package(self):
        code, out, _ = _run(["policy", self.log, "owasp-starter"])
        self.assertIn(code, (0, 1, 3))
        self.assertIn("Policy verdict", out)

    def test_bundled_packs_match_the_examples(self):
        import halo_record
        pkg = os.path.join(os.path.dirname(halo_record.__file__), "policies")
        for name in ("owasp-starter.json", "aiuc-1-starter.json"):
            with open(os.path.join(pkg, name), "rb") as a, open(os.path.join(PACKS, name), "rb") as b:
                self.assertEqual(a.read(), b.read(), name)


def _run_help(argv):
    out = io.StringIO()
    with redirect_stdout(out):
        try:
            from halo_record.cli import main
            main(argv)
        except SystemExit as e:
            return e.code, out.getvalue(), ""
    return 0, out.getvalue(), ""


class PolicyScopeFlagsTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.log = os.path.join(self.d, "c.jsonl")
        _chain(self.log, 3)
        self.p = _write_json(os.path.join(self.d, "p.json"), [
            {"id": "no-t2", "forbid": {"action.tool": "t2"}}])

    def test_expect_subject_mismatch_is_refused(self):
        code, out, _ = _run(["policy", self.log, self.p, "--expect-subject", "globex"])
        self.assertEqual(code, 2)
        self.assertIn("globex", out)

    def test_window_limits_the_records_evaluated(self):
        recs = [json.loads(l) for l in open(self.log) if l.strip()]
        # Rewrite nothing: pick a window that ends before every record.
        code, out, _ = _run(["policy", self.log, self.p, "--to", "2000-01-01"])
        self.assertEqual(code, 3)          # nothing in scope, not a pass and not a violation
        code, out, _ = _run(["policy", self.log, self.p, "--from", recs[0]["ts"][:10]])
        self.assertEqual(code, 1)


class PolicyVerdictPresentationTest(unittest.TestCase):
    def _result(self):
        from halo_record.policy import evaluate
        recs = [
            {"record_id": "a", "action": {"tool": "x"}, "severity": "HIGH"},
            {"record_id": "b", "action": {"tool": "x"}, "severity": "HIGH"},
            {"record_id": "c", "action": {"tool": "y"}, "severity": "INFO"},
        ]
        return evaluate(recs, [
            {"id": "no-high", "forbid": {"severity": "HIGH"}},
            {"id": "no-x", "forbid": {"action.tool": "x"}},
            {"id": "needs-z", "when": {"action.tool": "z"}, "expect_evidence": True},
        ])

    def test_counts_rules_and_records_consistently(self):
        from halo_record.policy import verdict_panel, render_text
        r = self._result()
        self.assertEqual(r["violating_records"], 2)
        panel = verdict_panel(r)
        self.assertIn("2 rule(s) violated by 2 record(s)", panel)
        self.assertIn("2 rule(s) violated by 2 record(s)", render_text(r))

    def test_compliant_with_gaps_is_not_green(self):
        from halo_record.policy import evaluate, verdict_panel
        r = evaluate([{"record_id": "a", "action": {"tool": "x"}}], [
            {"id": "ok", "forbid": {"action.tool": "q"}},
            {"id": "needs-z", "when": {"action.tool": "z"}, "expect_evidence": True},
        ])
        panel = verdict_panel(r)
        self.assertIn("WITH GAPS", panel)
        m = re.search(r'<span style="color:(#[0-9A-Fa-f]{6})">COMPLIANT, WITH GAPS', panel)
        self.assertTrue(m)
        self.assertNotEqual(m.group(1).upper(), "#3E7C5A")


class StarterPackSemanticsTest(unittest.TestCase):
    def test_denied_network_action_with_ssn_is_not_an_egress_violation(self):
        from halo_record.policy import evaluate, load_policy
        rec = {"record_id": "a", "ts": "2026-01-01T00:00:00Z",
               "action": {"type": "network", "category": "privacy", "tool": "post",
                          "authorization": {"decision": "denied"}},
               "outcome": {"status": "denied"},
               "data": {"pii_types": ["ssn"]}}
        for name in ("owasp-starter.json", "aiuc-1-starter.json"):
            res = evaluate([rec], load_policy(os.path.join(PACKS, name)))
            egress = [r for r in res["rules"] if r["id"] == "pii-egress-controlled"][0]
            self.assertNotEqual(egress["status"], "violated", name)

    def test_secret_rule_does_not_claim_the_value_landed(self):
        for name in ("owasp-starter.json", "aiuc-1-starter.json"):
            with open(os.path.join(PACKS, name), encoding="utf-8") as fh:
                text = fh.read()
            self.assertNotIn("may ever land in a record", text)
            self.assertNotIn("non-repudiable", text)

    def test_write_rule_descriptions_match_their_scope(self):
        with open(os.path.join(PACKS, "aiuc-1-starter.json"), encoding="utf-8") as fh:
            pack = json.load(fh)
        rule = [r for r in pack["rules"] if r["id"] == "high-risk-writes-authorized"][0]
        self.assertNotIn("network", rule["description"])
