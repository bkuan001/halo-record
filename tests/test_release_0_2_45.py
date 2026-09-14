"""0.2.45: authorization is never defaulted on the convenience paths either —
record_call, the @record decorator, and the shared adapter funnel — and the
report renders "no gate reported" as neutral, not as an alarm."""
import io
import os
import sys
import tempfile
import unittest

from halo_record import Recorder, build, record, record_call
from halo_record.integrations._common import record_tool_call


class NoDefaultDecisionOnConveniencePaths(unittest.TestCase):
    def setUp(self):
        self.log = os.path.join(tempfile.mkdtemp(), "c.jsonl")
        self.rec = Recorder(self.log)

    def test_record_call_seals_no_authorization_without_a_gate(self):
        with record_call(self.rec, "weather.get", {"city": "LA"}) as call:
            call.result = "sunny"
        import json
        with open(self.log) as fh:
            r = json.loads(fh.read().strip().splitlines()[-1])
        self.assertNotIn("authorization", r["action"])

    def test_record_call_with_decision_seals_it(self):
        with record_call(self.rec, "payments.refund", {"amount": 1}, decision="human_approved",
                         approver="u-2") as call:
            call.result = "ok"
        import json
        with open(self.log) as fh:
            r = json.loads(fh.read().strip().splitlines()[-1])
        self.assertEqual(r["action"]["authorization"]["decision"], "human_approved")

    def test_decorator_seals_no_authorization_without_a_gate(self):
        @record(self.rec, tool="email.send")
        def send(to):
            return "sent"
        send("a@example.com")
        import json
        with open(self.log) as fh:
            r = json.loads(fh.read().strip().splitlines()[-1])
        self.assertNotIn("authorization", r["action"])

    def test_adapter_funnel_seals_no_authorization_without_a_gate(self):
        r = record_tool_call(self.rec, "mcp__stripe__refund", {"id": "x"}, response="ok")
        self.assertNotIn("decision", r["action"].get("authorization", {}))


class ReportRendersMissingDecisionAsNeutral(unittest.TestCase):
    def test_pill_classes(self):
        from halo_record.report import render
        log = os.path.join(tempfile.mkdtemp(), "c.jsonl")
        rec = Recorder(log)
        rec.append(build("tool_call", "security", tool="ungated"))
        rec.append(build("tool_call", "security", tool="gated", decision="allowed"))
        rec.append(build("tool_call", "security", tool="denied", decision="denied"))
        import json
        with open(log) as fh:
            records = [json.loads(l) for l in fh if l.strip()]
        html = render(records)
        self.assertIn('class="pill neutral">—<', html)
        self.assertIn('class="pill ok">allowed<', html)
        self.assertIn('class="pill warn">denied<', html)


class IbanMidSentence(unittest.TestCase):
    CASES = [
        ("Wire 500 EUR to DE89370400440532013000 today please", "Wire 500 EUR to DE**** today please"),
        ("Wire 500 EUR to DE89 3704 0044 0532 0130 00 today please", "Wire 500 EUR to DE**** today please"),
        ("DE89370400440532013000 EUR", "DE**** EUR"),
        ("from DE89 3704 0044 0532 0130 00 to GB82 WEST 1234 5698 7654 32", "from DE**** to GB****"),
        ("DE89  3704  0044  0532  0130  00 double", "DE**** double"),
        ("DE89\t3704\t0044\t0532\t0130\t00 tabbed", "DE**** tabbed"),
        ("pay DE67 0792 4402 6859 9528 90 now", "pay DE**** now"),
    ]

    def test_trailing_words_never_disarm_the_mask(self):
        from halo_record.redact import redact_text, scan
        for text, expected in self.CASES:
            self.assertEqual(redact_text(text), expected, text)
            types = [f["type"] for f in scan(text)]
            self.assertIn("iban", types, text)
            self.assertNotIn("credit_card", types, "card must not co-classify an IBAN: " + text)

    def test_outcome_summary_is_covered_too(self):
        rec = build("tool_call", "privacy", tool="pay",
                    outcome={"status": "ok", "summary": "refund sent to DE89 3704 0044 0532 0130 00 today"})
        self.assertNotIn("3704", rec["outcome"]["summary"])
        self.assertIn("iban", rec["data"]["pii_types"])

    def test_anthropic_style_key_masks_as_api_key(self):
        from halo_record.redact import redact_text, scan
        v = "sk-ant-api03-ABCDEFGHIJKLMNOPQRST_uvwx-yz12"
        self.assertIn("api_key", [f["type"] for f in scan(v, entropy=False)])
        self.assertNotIn("uvwx", redact_text(v))


class JunkNeverCrashesOrPoisons(unittest.TestCase):
    def test_coerced_or_dropped_and_record_validates(self):
        from halo_record import validate_record
        err = io.StringIO(); old = sys.stderr; sys.stderr = err
        try:
            r = build("tool_call", "security", tool=123, scope=["gmail.read"], approver={"id": "a"},
                      session_id=None, agent="bot", subject={"id": 5}, source=123,
                      findings=[{"type": "x"}, "junk", {"severity": "HIGH"}])
            r2 = build("tool_call", "security", tool="x", source=["x"], findings="x")
        finally:
            sys.stderr = old
        self.assertEqual(r["action"]["tool"], "123")
        self.assertNotIn("authorization", r["action"])          # list scope + dict approver both dropped
        self.assertEqual(r["session_id"], "local")
        self.assertEqual(r["agent"], {"id": "bot", "name": "bot"})
        self.assertEqual(r["subject"]["id"], "5")
        self.assertNotIn("source", r)
        self.assertEqual([f["type"] for f in r["findings"]], ["x"])
        self.assertEqual(r["findings"][0]["severity"], "INFO")
        self.assertEqual(validate_record(r), [])
        self.assertNotIn("source", r2)
        self.assertEqual(validate_record(r2), [])
        self.assertIn("dropped", err.getvalue())


class ExportMissingPath(unittest.TestCase):
    def test_missing_chain_file_is_a_clean_refusal(self):
        from halo_record.export import export
        d = tempfile.mkdtemp()
        code = export(os.path.join(d, "nope.jsonl"), os.path.join(d, "x.csv"), out=lambda *a, **k: None)
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(os.path.join(d, "x.csv")))


class CodeRabbitRoundTwo(unittest.TestCase):
    def test_compact_iban_glued_to_suffix_still_masks(self):
        from halo_record.redact import redact_text, scan
        self.assertEqual(redact_text("DE89370400440532013000EUR"), "DE****EUR")
        self.assertIn("iban", [f["type"] for f in scan("DE89370400440532013000EUR")])

    def test_caller_finding_sample_is_redacted_and_shape_restricted(self):
        r = build("tool_call", "security", tool="x",
                  findings=[{"type": "custom", "severity": ["HIGH"],
                             "sample": "key sk-live-AAAAAAAAAAAAAAAAAAAAAAAA", "extra": "dropped"}])
        f = r["findings"][0]
        self.assertEqual(set(f), {"type", "severity", "sample"})
        self.assertEqual(f["severity"], "INFO")
        self.assertNotIn("AAAAAAAA", f["sample"])

    def test_non_scalar_identity_fields_drop_the_block(self):
        from halo_record import validate_record
        err = io.StringIO(); old = sys.stderr; sys.stderr = err
        try:
            r = build("tool_call", "security", tool="x", subject={"id": {"x": 1}},
                      agent={"id": ["a"], "name": "n"}, source={"adapter": None, "capture": "captured"})
        finally:
            sys.stderr = old
        self.assertNotIn("subject", r)
        self.assertEqual(r["agent"]["id"], "unknown")
        self.assertNotIn("source", r)
        self.assertEqual(validate_record(r), [])


if __name__ == "__main__":
    unittest.main()
