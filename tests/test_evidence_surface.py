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


def _reseal(records):
    from halo_record.canon import GENESIS_PREV, compute_hash
    prev = GENESIS_PREV
    out = []
    for r in records:
        r = json.loads(json.dumps(r))
        r["integrity"]["prev_hash"] = prev
        r["integrity"]["hash"] = compute_hash(r, prev)
        prev = r["integrity"]["hash"]
        out.append(r)
    return out


def _write_records(path, records):
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")


class _WitnessedChain(unittest.TestCase):
    """A 4-record chain witnessed at its head, then a copy with record 2
    deleted and the chain re-sealed (verifies on its own; the witness catches it)."""

    def setUp(self):
        from halo_record.anchor import Notary
        self.d = tempfile.mkdtemp()
        self.log = os.path.join(self.d, "c.jsonl")
        recs = _chain(self.log, 4)
        self.witness = os.path.join(self.d, "w.jsonl")
        Notary(self.witness).witness(recs)
        self.resealed = os.path.join(self.d, "rs.jsonl")
        _write_records(self.resealed, _reseal(recs[:1] + recs[2:]))
        self.assertTrue(verify_log(self.resealed, out=lambda *a: None))


class ReportCompletenessExitTest(_WitnessedChain):
    def test_incomplete_report_exits_nonzero_and_says_so_on_stderr(self):
        code, out, err = _run(["report", self.resealed, "-o", os.path.join(self.d, "r.html"),
                               "-w", self.witness])
        self.assertEqual(code, 1)
        self.assertIn("INCOMPLETE", err)

    def test_complete_report_exits_zero(self):
        code, out, err = _run(["report", self.log, "-o", os.path.join(self.d, "r.html"),
                               "-w", self.witness])
        self.assertEqual(code, 0, out + err)

    def test_unwitnessed_chain_with_a_witness_named_is_not_a_clean_exit(self):
        empty = os.path.join(self.d, "none.jsonl")
        open(empty, "w").close()
        code, out, err = _run(["report", self.log, "-o", os.path.join(self.d, "r.html"),
                               "-w", empty])
        self.assertEqual(code, 3)
        self.assertIn("UNWITNESSED", err)

    def test_empty_chain_report_is_not_a_clean_exit(self):
        empty = os.path.join(self.d, "e.jsonl")
        open(empty, "w").close()
        code, out, err = _run(["report", empty, "-o", os.path.join(self.d, "r.html")])
        self.assertEqual(code, 3)

    def test_unreachable_witness_url_fails_closed(self):
        out_html = os.path.join(self.d, "r.html")
        code, out, err = _run(["report", self.log, "-o", out_html,
                               "--witness-url", "http://127.0.0.1:9/",
                               "--from", "2000-01-01"])
        self.assertNotEqual(code, 0)
        self.assertIn("witness", (out + err).lower())
        self.assertFalse(os.path.exists(out_html))

    def test_window_page_flags_a_witness_longer_than_the_chain(self):
        if not shutil.which("node"):
            self.skipTest("node not installed")
        from halo_record.report import _VERIFY_JS
        from halo_record.canon import GENESIS_PREV
        page = _VERIFY_JS % {"genesis": json.dumps(GENESIS_PREV),
                             "window_json": json.dumps({"first": 1, "last": 2, "total": 3})}
        funcs = page[:page.index("async function liveCheckpoints(")]
        recs = [json.loads(l) for l in open(self.log) if l.strip()][:2]
        cps = [{"count": 9, "head": "a" * 64}]
        script = funcs + "\nconsole.log(JSON.stringify(completeness(%s, %s)));" % (
            json.dumps(recs), json.dumps(cps))
        js = os.path.join(self.d, "w.mjs")
        open(js, "w").write(script)
        res = json.loads(subprocess.run(["node", js], capture_output=True, text=True,
                                        timeout=60).stdout)
        self.assertIs(res["ok"], False)


class ExportCompletenessTest(_WitnessedChain):
    def _export(self, log, *extra):
        out = os.path.join(self.d, "ev.csv")
        code, o, e = _run(["export", log, "-o", out] + list(extra))
        return code, o + e, out

    def test_resealed_chain_is_refused_when_a_witness_is_named(self):
        code, text, out = self._export(self.resealed, "--witness", self.witness)
        self.assertEqual(code, 1)
        self.assertIn("INCOMPLETE", text)
        self.assertFalse(os.path.exists(out))

    def test_manifest_carries_subject_witness_and_completeness(self):
        code, text, out = self._export(self.log, "--witness", self.witness,
                                       "--expect-subject", "acme")
        self.assertEqual(code, 0, text)
        m = json.load(open(out + ".manifest.json"))
        self.assertEqual(m["completeness"]["status"], "COMPLETE")
        self.assertEqual(m["subject"]["expected"], "acme")
        self.assertEqual(m["subject"]["ids"], ["acme"])
        self.assertEqual(m["witness"]["checkpoints"], 1)
        self.assertIn("declared", m["chain"]["ts_source"])

    def test_without_a_witness_the_manifest_says_completeness_was_not_checked(self):
        code, text, out = self._export(self.log)
        self.assertEqual(code, 0, text)
        m = json.load(open(out + ".manifest.json"))
        self.assertEqual(m["completeness"]["status"], "NOT_CHECKED")

    def test_unexpected_subject_is_refused(self):
        code, text, out = self._export(self.log, "--expect-subject", "globex")
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(out))

    def test_unreachable_witness_url_is_refused(self):
        code, text, out = self._export(self.log, "--witness-url", "http://127.0.0.1:9/")
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(out))


class ExportColumnsTest(unittest.TestCase):
    def test_verification_columns_are_exported(self):
        import csv
        from halo_record.export import export
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        Recorder(log).append(build("tool_call", "security", tool="pay",
                                   verification={"status": "blocked", "verifier": "gate/2",
                                                 "policy_ref": "p-7",
                                                 "checked_at": "2026-06-01T00:00:00Z"}))
        export(log, os.path.join(d, "o.csv"), out=lambda *a: None)
        row = list(csv.DictReader(open(os.path.join(d, "o.csv"))))[0]
        self.assertEqual(row["verification_status"], "blocked")
        self.assertEqual(row["verification_verifier"], "gate/2")
        self.assertEqual(row["verification_policy_ref"], "p-7")
        self.assertEqual(row["verification_checked_at"], "2026-06-01T00:00:00Z")

    def test_leading_whitespace_formula_vectors_are_neutralized(self):
        from halo_record.export import _neutralize
        for v in (" =1+1", "\n=cmd|' /C calc'!A0", "  @SUM(A1)", " +1", "\x0b=1"):
            self.assertTrue(_neutralize(v).startswith("'"), repr(v))
        self.assertEqual(_neutralize(" plain text"), " plain text")
        self.assertEqual(_neutralize("ok"), "ok")


class _WitnessServer(unittest.TestCase):
    KEY = "k-surface"
    extra = {}

    def setUp(self):
        import threading
        from http.server import ThreadingHTTPServer
        from halo_record.anchor import Notary
        from halo_record.witness import _Handler
        self.store = tempfile.mkdtemp()
        self.notary = Notary(os.path.join(self.store, "witness.jsonl"))
        cfg = {"notary": self.notary, "keys": [self.KEY]}
        cfg.update(self.extra)
        handler = type("_B", (_Handler,), {"config": cfg})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _raw(self, method, path, body=b"", headers=None):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=5)
        c.putrequest(method, path)
        for k, v in (headers or {}).items():
            c.putheader(k, v)
        c.endheaders()
        if body:
            c.send(body)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data


class WitnessHardeningTest(_WitnessServer):
    def test_negative_content_length_is_a_bad_request(self):
        code, _ = self._raw("POST", "/anchor", headers={
            "Authorization": "Bearer " + self.KEY, "Content-Length": "-5"})
        self.assertEqual(code, 400)

    def test_parser_errors_are_not_echoed(self):
        body = b'{"subject": "acme", "count": 1, "head": <script>}'
        code, data = self._raw("POST", "/anchor", body=body, headers={
            "Authorization": "Bearer " + self.KEY, "Content-Length": str(len(body)),
            "Content-Type": "application/json"})
        self.assertEqual(code, 400)
        self.assertNotIn(b"char", data)          # json's "Expecting value: line 1 column N (char M)"
        self.assertNotIn(b"line 1", data)

    def test_reads_do_not_reparse_the_whole_log(self):
        from halo_record import witness as W
        recs = _chain(os.path.join(self.store, "c.jsonl"), 2)
        from halo_record.witness import anchor_remote, fetch_checkpoints
        anchor_remote(self.url, self.KEY, recs)
        fetch_checkpoints(self.url, subject="acme")
        calls = []
        orig = self.notary.checkpoints
        self.notary.checkpoints = lambda *a, **k: calls.append(1) or orig(*a, **k)
        for _ in range(3):
            self.assertEqual(len(fetch_checkpoints(self.url, subject="acme")), 1)
        self.assertEqual(calls, [])   # served from the incremental index

    def test_anchor_posts_are_rate_limited_per_key(self):
        from halo_record import witness as W
        recs = _chain(os.path.join(self.store, "c.jsonl"), 1)
        body = json.dumps({"subject": "acme", "count": 1,
                           "head": recs[0]["integrity"]["hash"]}).encode()
        codes = []
        for _ in range(W.POST_RATE_LIMIT + 2):
            code, _ = self._raw("POST", "/anchor", body=body, headers={
                "Authorization": "Bearer " + self.KEY, "Content-Length": str(len(body)),
                "Content-Type": "application/json"})
            codes.append(code)
        self.assertIn(429, codes)
        self.assertEqual(codes[0], 201)


class WitnessReadKeysTest(_WitnessServer):
    extra = {"read_keys": [("rk-acme", ["acme"])]}

    def test_subject_reads_need_a_scoped_read_key_when_configured(self):
        from halo_record.witness import fetch_checkpoints
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError) as cm:
            fetch_checkpoints(self.url, subject="acme")
        self.assertEqual(cm.exception.code, 401)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            fetch_checkpoints(self.url, subject="globex", key="rk-acme")
        self.assertEqual(cm.exception.code, 403)
        self.assertEqual(fetch_checkpoints(self.url, subject="acme", key="rk-acme"), [])


class TwoChainsOneSubjectTest(unittest.TestCase):
    def test_a_second_chain_under_the_same_subject_is_named_as_such(self):
        from halo_record.anchor import Notary, verify_completeness
        d = tempfile.mkdtemp()
        a = _chain(os.path.join(d, "a.jsonl"), 3)
        b = _chain(os.path.join(d, "b.jsonl"), 2)
        n = Notary(os.path.join(d, "w.jsonl"))
        n.witness(a)
        n.witness(b)
        res = verify_completeness(a, n.checkpoints_for(a))
        self.assertIs(res["ok"], False)
        self.assertIn("2 distinct chains", res["why"])


class AnchorCheckKeylessTest(unittest.TestCase):
    def test_remote_check_does_not_require_a_vendor_key(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        _chain(log, 1)
        code, out, err = _run(["anchor", log, "--remote", "http://127.0.0.1:9", "--check"])
        self.assertNotIn("requires --key", err)
        self.assertEqual(code, 1)    # unreachable, not a usage error


class StrictEmailTest(unittest.TestCase):
    def test_markup_in_an_address_is_not_admitted(self):
        from halo_record import access
        allow = ["acme.com"]
        for bad in ('<img/src=x>@acme.com', '"><script>@acme.com', "a'b@acme.com",
                    "a&b@acme.com", "x@acme.com<", "a@acme..com"):
            self.assertFalse(access.is_allowed(bad, allow), bad)
        self.assertTrue(access.is_allowed("first.last+tag@acme.com", allow))

    def test_capture_lead_refuses_an_invalid_address(self):
        from halo_record import access
        d = tempfile.mkdtemp()
        access.capture_lead(d, "<svg onload=x>@acme.com", "acme")
        self.assertEqual(access.read_leads(d), [])

    def test_console_payload_escapes_stored_leads(self):
        from halo_record import access
        from halo_record.serve import _console_payload, load_secret
        from halo_record.record import TenantRecorder
        d = tempfile.mkdtemp()
        TenantRecorder(d).append(build("tool_call", "security", tool="t", subject="acme"))
        with open(os.path.join(d, access.LEADS_FILE), "w") as fh:   # written by an older version
            fh.write(json.dumps({"email": "<b>x</b>@acme.com", "chain": "acme"}) + "\n")
        payload = _console_payload(d, load_secret(d), None)
        text = json.dumps(payload)
        self.assertNotIn("<b>", text)


class ServeKeyedByChainTest(unittest.TestCase):
    def test_link_and_grant_follow_a_subject_whose_file_moved(self):
        from halo_record import access
        from halo_record.record import TenantRecorder
        from halo_record.serve import _served_chains, load_secret, token_for
        d = tempfile.mkdtemp()
        merged = os.path.join(d, "acme_eu.jsonl")     # a file an older version shared
        raw = Recorder(merged)
        raw.append(build("tool_call", "security", tool="old", subject="acme_eu"))
        raw.append(build("tool_call", "security", tool="old", subject="acme/eu"))
        access.grant(d, "acme_eu", "cfo@acme.com")
        with redirect_stderr(io.StringIO()):
            live = TenantRecorder(d).chain_path_for("acme_eu")
            TenantRecorder(d).append(build("tool_call", "security", tool="new", subject="acme_eu"))
        self.assertNotEqual(os.path.abspath(live), os.path.abspath(merged))
        chains = dict(_served_chains(d))
        self.assertEqual(os.path.abspath(chains["acme_eu"]), os.path.abspath(live))
        self.assertTrue(access.is_allowed("cfo@acme.com", access.allowed_for(d, "acme_eu")))
        from halo_record.serve import _Handler
        h = _Handler.__new__(_Handler)
        h.config = {"dir": d, "secret": load_secret(d)}
        key, path = h._resolve(token_for(h.config["secret"], "acme_eu"))
        self.assertEqual(key, "acme_eu")
        self.assertEqual(os.path.abspath(path), os.path.abspath(live))
