import io
import json
import os
import tempfile
import unittest
from unittest import mock

from halo_record.record import Recorder, build, _norm_principal
from halo_record.redact import scan, redact_text
from halo_record import hook


class PathFieldsStayReadableButScanned(unittest.TestCase):
    def _rec(self, tool_input, tool_response=None, tool="Read"):
        kw = {"tool": tool, "tool_input": tool_input}
        if tool_response is not None:
            from halo_record.capture import derive_outcome
            kw["outcome"] = derive_outcome(tool_response)
        return build("read", "privacy", **kw)

    def _types(self, r):
        return [(f["type"], f["severity"]) for f in r["findings"]]

    def test_anchored_paths_are_readable_and_never_high(self):
        for p in ["/Users/dev/src/agent/out/refund.py",
                  "/Users/dev/Projects/Acme-Billing/handlers/Stripe_webhook.ts",
                  "src/generated/AcmeBillingClientV2Generated/index.ts",
                  "C:\\Users\\dev\\AppData\\Local\\Acme2026\\Billing.dll",
                  "./src/Agent/Handlers/File1.ts", "~/Projects/Acme-Billing2026/x.md"]:
            r = self._rec({"file_path": p})
            self.assertIn(repr(p), r["action"]["input"]["summary"], p)
            self.assertNotIn("high_entropy_secret", [t for t, _ in self._types(r)], p)
            self.assertIn(r["severity"], ("INFO", "LOW"), p)

    def test_unanchored_path_key_value_gets_the_full_pass(self):
        # Susie's case: a secret dropped under a path key with no path anchor
        r = self._rec({"file_path": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
        self.assertNotIn("wJalrXUtnFEMI", r["action"]["input"]["summary"])
        self.assertIn(("high_entropy_secret", "HIGH"), self._types(r))
        # and the documented cost: an extension-less relative path is masked
        r2 = self._rec({"file_path": "refs/heads/feature/AcmeBilling2026Rewrite"})
        self.assertNotIn("AcmeBilling2026Rewrite", r2["action"]["input"]["summary"])

    def test_anchored_secret_stays_readable_but_is_reported_low(self):
        r = self._rec({"file_path": "/tmp/wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
        self.assertIn("/tmp/wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", r["action"]["input"]["summary"])
        self.assertIn(("high_entropy_path_value", "LOW"), self._types(r))
        self.assertNotEqual(r["findings"], [])

    def test_list_elements_are_judged_one_by_one(self):
        r = self._rec({"pattern": "**/*.ts", "paths": [
            "/Users/dev/Projects/Acme-Billing/handlers/Stripe_webhook.ts",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]}, tool="Glob")
        s = r["action"]["input"]["summary"]
        self.assertIn("/Users/dev/Projects/Acme-Billing/handlers/Stripe_webhook.ts", s)
        self.assertNotIn("wJalrXUtnFEMI", s)
        self.assertIn(("high_entropy_secret", "HIGH"), self._types(r))

    def test_dict_keys_are_scanned_and_masked(self):
        r = self._rec({"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "v"}, tool="x")
        self.assertNotIn("wJalrXUtnFEMI", r["action"]["input"]["summary"])
        self.assertIn(("high_entropy_secret", "HIGH"), self._types(r))

    def test_url_key_is_readable(self):
        u = "https://github.com/bkuan001/halo-record/blob/main/LIMITS.md"
        r = self._rec({"url": u}, tool="WebFetch")
        self.assertIn(u, r["action"]["input"]["summary"])
        self.assertNotIn("high_entropy_secret", [t for t, _ in self._types(r)])

    def test_query_string_under_a_path_key_is_still_masked(self):
        r = self._rec({"path": "/cb?access_token=A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"})
        self.assertNotIn("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6", r["action"]["input"]["summary"])

    def test_named_patterns_still_run_under_path_keys(self):
        r = self._rec({"file_path": "/tmp/AKIAIOSFODNN7EXAMPLE/x"})
        self.assertIn("AKIA****", r["action"]["input"]["summary"])

    def test_aws_secret_key_in_a_command_is_critical(self):
        r = self._rec({"command": "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, tool="Bash")
        self.assertEqual(r["action"]["input"]["summary"], "{'command': 'export AWS_SECRET_ACCESS_KEY=****'}")
        self.assertIn(("aws_secret_key", "CRITICAL"), self._types(r))
        r2 = self._rec({"command": "aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, tool="Bash")
        self.assertNotIn("wJalrXUtnFEMI", r2["action"]["input"]["summary"])

    def test_slack_webhook_and_slashed_blobs_are_masked_in_free_text(self):
        for s in ["https://hooks.slack.com/services/T7Kq2Zp9L/B4Rt8Vx1N/c3Bd6Fg0Hj5Sw9AbQmXk",
                  "HMAC_KEY=8Kx/2ZpQw9Lm4Rt8Vx1Nc3Bd/6Fg0Hj5Sw9Ab="]:
            self.assertNotEqual(redact_text(s), s, s)

    def test_response_path_keys_are_readable_but_still_scanned(self):
        r = self._rec({"file_path": "/Users/dev/src/agent/out/refund.py"},
                      {"filePath": "/Users/dev/src/agent/out/refund.py", "content": "x = 1"})
        self.assertNotIn("high_entropy_secret", [t for t, _ in self._types(r)])
        # a secret returned under a path-typed response key is still a finding
        r2 = self._rec({"file_path": "/Users/dev/x.py"},
                       {"filePath": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
        self.assertIn(("high_entropy_secret", "HIGH"), self._types(r2))
        self.assertNotIn("_scan", r2["outcome"])
        r3 = self._rec({"file_path": "/Users/dev/x.py"},
                       {"filePath": "https://hooks.slack.com/services/T7Kq2Zp9L/B4Rt8Vx1N/c3Bd6Fg0Hj5Sw9AbQmXk"})
        self.assertNotEqual(r3["findings"], [])

    def test_hash_only_records_drop_scan_material(self):
        from halo_record.capture import derive_outcome
        r = build("read", "privacy", tool="Read", tool_input={"file_path": "/Users/dev/x.py"},
                  outcome=derive_outcome({"filePath": "/Users/dev/x.py", "content": "sk-abcdefghijklmnopqrstuvwxyz1234"}),
                  summaries=False)
        self.assertNotIn("_scan", r["outcome"]); self.assertNotIn("summary", r["outcome"])
        self.assertIn("api_key", [f["type"] for f in r["findings"]])

    def test_exit_codes_mark_errors_including_strings(self):
        from halo_record.capture import derive_outcome
        self.assertEqual(derive_outcome({"stderr": "permission denied", "exit_code": 1})["status"], "error")
        self.assertEqual(derive_outcome({"stdout": "x", "exit_code": "1"})["status"], "error")
        self.assertEqual(derive_outcome({"stdout": "ok", "exit_code": 0})["status"], "ok")
        self.assertEqual(derive_outcome({"returncode": True})["status"], "ok")


class HookEventGuard(unittest.TestCase):
    def _run(self, event):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.jsonl")
            with mock.patch.dict(os.environ, {"HALO_LOG": path}, clear=False), \
                 mock.patch("sys.stdin", io.StringIO(json.dumps(event))):
                rc = hook.main([])
            lines = open(path).read().splitlines() if os.path.exists(path) else []
            return rc, [json.loads(l) for l in lines]

    def test_pre_tool_use_event_is_ignored(self):
        rc, recs = self._run({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                              "tool_input": {"command": "rm -rf /important"},
                              "session_id": "s1"})
        self.assertEqual(rc, 0)
        self.assertEqual(recs, [])

    def test_post_tool_use_event_is_recorded(self):
        rc, recs = self._run({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                              "tool_input": {"command": "ls"}, "tool_response": {"stdout": "ok"},
                              "session_id": "s1"})
        self.assertEqual(rc, 0)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["outcome"]["status"], "ok")

    def test_padded_or_lowercase_event_name_is_still_recorded(self):
        for name in [" PostToolUse ", "PostToolUse", "posttooluse"]:
            rc, recs = self._run({"hook_event_name": name, "tool_name": "Bash",
                                  "tool_input": {"command": "ls"}, "tool_response": {"stdout": "a"},
                                  "session_id": "s1"})
            self.assertEqual(len(recs), 1, name)

    def test_empty_response_seals_no_outcome_claim(self):
        for resp in [{}, "", [], 0, False]:
            rc, recs = self._run({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                                  "tool_input": {"command": "ls"}, "tool_response": resp,
                                  "session_id": "s1"})
            self.assertEqual(len(recs), 1)
            self.assertNotIn("outcome", recs[0], repr(resp))

    def test_missing_response_seals_no_outcome_claim(self):
        rc, recs = self._run({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                              "tool_input": {"command": "ls"}, "session_id": "s1"})
        self.assertEqual(rc, 0)
        self.assertEqual(len(recs), 1)
        self.assertNotIn("outcome", recs[0])


class PrincipalKeysWarn(unittest.TestCase):
    def test_unknown_key_warns_on_stderr(self):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            out = _norm_principal({"user_id": "alice", "human_id": "alice@example.com"})
        self.assertEqual(out, {"human_id": "alice@example.com"})
        self.assertIn("user_id", err.getvalue())

    def test_known_keys_do_not_warn(self):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            _norm_principal({"human_id": "alice@example.com"})
        self.assertEqual(err.getvalue(), "")


if __name__ == "__main__":
    unittest.main()


class CodexHook(unittest.TestCase):
    def _run(self, event, env=None):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.jsonl")
            e = {"HALO_LOG": path}
            e.update(env or {})
            with mock.patch.dict(os.environ, e, clear=False), \
                 mock.patch("sys.stdin", io.StringIO(json.dumps(event))):
                rc = hook.main([])
            lines = open(path).read().splitlines() if os.path.exists(path) else []
            return rc, [json.loads(l) for l in lines]

    CODEX_BASH = {"hook_event_name": "PostToolUse", "session_id": "codex-1", "turn_id": "t-9",
                  "model": "gpt-5.3-codex", "tool_name": "Bash", "tool_use_id": "call_1",
                  "tool_input": {"command": "pytest -q"}, "tool_response": {"output": "12 passed"},
                  "cwd": "/tmp/proj", "permission_mode": "default"}

    def test_codex_event_is_labeled_codex(self):
        rc, recs = self._run(self.CODEX_BASH)
        self.assertEqual(rc, 0)
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r["agent"]["id"], "codex")
        self.assertEqual(r["agent"]["model"], "gpt-5.3-codex")
        self.assertEqual(r["source"]["adapter"], "codex_hook")
        self.assertEqual(r["source"]["via"], "Codex CLI PostToolUse hook")
        self.assertEqual(r["source"]["capture"], "ingested")
        self.assertEqual(r["action"]["authorization"]["scope"], "exec")
        self.assertEqual(r["outcome"]["status"], "ok")

    def test_codex_apply_patch_is_a_write(self):
        ev = dict(self.CODEX_BASH, tool_name="apply_patch",
                  tool_input={"command": "*** Begin Patch\n*** Update File: a.py\n+x=1\n*** End Patch"},
                  tool_response={"output": "Done!"})
        rc, recs = self._run(ev)
        self.assertEqual(recs[0]["action"]["type"], "write")
        self.assertEqual(recs[0]["action"]["authorization"]["scope"], "fs.write")
        self.assertEqual(recs[0]["agent"]["id"], "codex")

    def test_codex_mcp_call_is_a_connector(self):
        ev = dict(self.CODEX_BASH, tool_name="mcp__fs__read", tool_input={"path": "a.py"},
                  tool_response={"content": "x"})
        rc, recs = self._run(ev)
        self.assertEqual(recs[0]["action"]["authorization"]["scope"], "mcp:fs")

    def test_claude_code_event_stays_claude_code(self):
        ev = {"hook_event_name": "PostToolUse", "session_id": "cc-1", "tool_name": "Bash",
              "tool_input": {"command": "ls"}, "tool_response": {"stdout": "a"}}
        rc, recs = self._run(ev)
        self.assertEqual(recs[0]["agent"]["id"], "claude-code")
        self.assertEqual(recs[0]["source"]["adapter"], "hook")

    def test_env_override_wins(self):
        ev = {"hook_event_name": "PostToolUse", "session_id": "x", "tool_name": "Bash",
              "tool_input": {"command": "ls"}, "tool_response": {"stdout": "a"}}
        rc, recs = self._run(ev, env={"HALO_HOOK_AGENT": "codex"})
        self.assertEqual(recs[0]["agent"]["id"], "codex")
        self.assertEqual(recs[0]["source"]["adapter"], "codex_hook")

    def test_codex_shell_aliases_classify_as_exec(self):
        for name in ["shell", "local_shell", "exec_command"]:
            ev = dict(self.CODEX_BASH, tool_name=name)
            rc, recs = self._run(ev)
            self.assertEqual(recs[0]["action"]["authorization"]["scope"], "exec", name)

    def test_codex_pre_tool_use_is_ignored(self):
        ev = dict(self.CODEX_BASH, hook_event_name="PreToolUse"); ev.pop("tool_response")
        rc, recs = self._run(ev)
        self.assertEqual(recs, [])


class LeadingSlashAlone(unittest.TestCase):
    def test_opaque_token_with_leading_slash_is_masked(self):
        r = build("read", "privacy", tool="Read",
                  tool_input={"file_path": "/kY7Qw2Zp9Lm4Rt8Vx1Nc3Bd6Fg0Hj5Sw9AbQmXkLp"})
        self.assertNotIn("kY7Qw2Zp9Lm4Rt8Vx1Nc3Bd6Fg0Hj5Sw9AbQmXkLp", r["action"]["input"]["summary"])


class WebhookAndAwsForms(unittest.TestCase):
    def test_webhook_urls_are_critical_even_under_url_keys(self):
        for u in ["https://hooks.slack.com/services/T7Kq2Zp9L/B4Rt8Vx1N/c3Bd6Fg0Hj5Sw9AbQmXk",
                  "https://discord.com/api/webhooks/1234567890/aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
                  "https://acme.webhook.office.com/webhookb2/aaaa@bbbb/IncomingWebhook/cccc/dddd"]:
            r = build("tool_call", "security", tool="WebFetch", tool_input={"url": u})
            self.assertNotIn(u, r["action"]["input"]["summary"], u)
            self.assertIn(("webhook_url", "CRITICAL"), [(f["type"], f["severity"]) for f in r["findings"]], u)

    def test_aws_cli_space_form_is_critical(self):
        r = build("tool_call", "security", tool="Bash",
                  tool_input={"command": "aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
        self.assertIn(("aws_secret_key", "CRITICAL"), [(f["type"], f["severity"]) for f in r["findings"]])
        self.assertIn("aws_secret_access_key ****", r["action"]["input"]["summary"])


class EmiliaFollowUps(unittest.TestCase):
    def test_response_filenames_list_stays_readable(self):
        from halo_record.capture import derive_outcome
        p = "/Users/dev/acme-billing/src/services/InvoiceReconciliationService.ts"
        r = build("read", "privacy", tool="Glob", tool_input={"pattern": "src/**/*.ts"},
                  outcome=derive_outcome({"filenames": [p], "numFiles": 1}))
        self.assertNotIn("/Us****", r["outcome"].get("summary", ""))
        self.assertNotIn("high_entropy_secret", [f["type"] for f in r["findings"]])

    def test_no_duplicate_findings_across_input_and_response(self):
        from halo_record.capture import derive_outcome
        p = "/Users/dev/acme-billing/src/services/InvoiceReconciliationService.ts"
        r = build("read", "privacy", tool="Read", tool_input={"file_path": p},
                  outcome=derive_outcome({"filePath": p, "content": "x"}))
        keys = [(f["type"], f.get("sample")) for f in r["findings"]]
        self.assertEqual(len(keys), len(set(keys)))

    def test_apply_patch_header_path_is_readable_body_still_scanned(self):
        patch = ("*** Begin Patch\n*** Update File: src/generated/AcmeBillingClientV2Generated/index.ts\n"
                 "@@\n-  key = 'x'\n+  key = 'AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8YzA9bCd0'\n*** End Patch\n")
        r = build("write", "safety", tool="apply_patch", tool_input={"command": patch})
        s = r["action"]["input"]["summary"]
        self.assertIn("src/generated/AcmeBillingClientV2Generated/index.ts", s)
        self.assertNotIn("AbC1dEf2GhI3jKl4MnO5pQr6StU7vWx8YzA9bCd0", s)
        self.assertIn(("high_entropy_secret", "HIGH"), [(f["type"], f["severity"]) for f in r["findings"]])

    def test_report_headline_is_severity_weighted(self):
        from halo_record.report import render
        recs = [build("read", "privacy", tool="Read",
                      tool_input={"file_path": "/Users/dev/acme-billing/src/services/InvoiceReconciliationService.ts"}),
                build("tool_call", "security", tool="Bash",
                      tool_input={"command": "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})]
        html = render(recs)
        self.assertIn(">1</div><div class=\"l\">Flagged (MEDIUM+)</div>", html.replace("\n", ""))
        self.assertIn(">1</div><div class=\"l\">Low notes</div>", html.replace("\n", ""))
