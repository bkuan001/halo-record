"""Regression tests for the 0.2.44 batch: hyphenated IBANs, the auditor
export columns, OpenTelemetry loss reporting, and the schema's source block."""
import csv
import io
import json
import os
import sys
import tempfile
import unittest

from halo_record import Recorder, build, load_schema
from halo_record.export import CSV_COLUMNS, export
from halo_record.redact import redact_text, scan


class HyphenatedIban(unittest.TestCase):
    def test_hyphen_separated_iban_is_masked(self):
        # Spaces were already tolerated; hyphens passed through untouched.
        for v in ("GB29-NWBK-6016-1331-9268-19", "GB29 NWBK 6016 1331 9268 19",
                  "GB29NWBK60161331926819"):
            self.assertIn("iban", [f["type"] for f in scan(v)], v)
            self.assertNotIn("6016", redact_text("account " + v), v)


class AuditorExportColumns(unittest.TestCase):
    def test_approver_data_and_input_hash_columns_populate(self):
        log = os.path.join(tempfile.mkdtemp(), "chain.jsonl")
        out = log + ".csv"
        Recorder(log).append(build(
            "tool_call", "privacy", tool="crm.export",
            tool_input={"customer": "C-1"},
            subject={"id": "acme"}, decision="human_approved",
            approver="reviewer@example.com", scope="crm.read",
            data={"region": "eu-west-1", "cross_region": True,
                  "purpose": "support", "pii_types": ["email"]},
            outcome={"status": "ok", "summary": "1 row"}))
        export(log, out, out=lambda *a, **k: None)
        with open(out, newline="") as fh:
            row = list(csv.DictReader(fh))[0]
        for col in ("approver", "region", "cross_region", "purpose", "input_hash"):
            self.assertIn(col, CSV_COLUMNS)
        self.assertEqual(row["approver"], "reviewer@example.com")
        self.assertEqual(row["region"], "eu-west-1")
        self.assertEqual(row["cross_region"], "true")
        self.assertEqual(row["purpose"], "support")
        self.assertTrue(row["input_hash"].startswith("sha256:"))
        self.assertEqual(len(row["input_hash"]), len("sha256:") + 64)

    def test_cross_region_blank_when_undeclared(self):
        log = os.path.join(tempfile.mkdtemp(), "chain.jsonl")
        out = log + ".csv"
        Recorder(log).append(build("tool_call", "privacy", tool="t"))
        export(log, out, out=lambda *a, **k: None)
        with open(out, newline="") as fh:
            row = list(csv.DictReader(fh))[0]
        self.assertEqual(row["cross_region"], "")


class OtelLossReporting(unittest.TestCase):
    def test_failed_span_is_counted_and_reported(self):
        # Stand in for opentelemetry-sdk so the exporter class builds without
        # the optional dependency installed.
        import types
        fake = types.ModuleType("opentelemetry.sdk.trace.export")

        class SpanExporter:
            pass

        class SpanExportResult:
            SUCCESS = "SUCCESS"

        fake.SpanExporter = SpanExporter
        fake.SpanExportResult = SpanExportResult
        saved = {k: sys.modules.get(k) for k in
                 ("opentelemetry", "opentelemetry.sdk", "opentelemetry.sdk.trace",
                  "opentelemetry.sdk.trace.export")}
        sys.modules["opentelemetry"] = types.ModuleType("opentelemetry")
        sys.modules["opentelemetry.sdk"] = types.ModuleType("opentelemetry.sdk")
        sys.modules["opentelemetry.sdk.trace"] = types.ModuleType("opentelemetry.sdk.trace")
        sys.modules["opentelemetry.sdk.trace.export"] = fake
        self.addCleanup(lambda: [sys.modules.pop(k) if v is None else sys.modules.__setitem__(k, v)
                                 for k, v in saved.items()])
        from halo_record.integrations import otel
        exporter_cls = otel._build_exporter_class()

        class BrokenRecorder:
            def append(self, *a, **k):
                raise IOError("disk full")

        class FakeSpan:
            name = "gen_ai.tool"
            attributes = {"gen_ai.operation.name": "execute_tool",
                          "gen_ai.tool.name": "lookup"}
            def __init__(self):
                self.status = None
                self.start_time = 0
                self.end_time = 0

        orig = otel.record_span
        otel.record_span = lambda *a, **k: (_ for _ in ()).throw(IOError("disk full"))
        try:
            exp = exporter_cls(BrokenRecorder())
            err = io.StringIO()
            old = sys.stderr
            sys.stderr = err
            try:
                exp.export([FakeSpan(), FakeSpan()])
            finally:
                sys.stderr = old
        finally:
            otel.record_span = orig
        self.assertEqual(exp.lost_records, 2)
        self.assertIn("NOT in the evidence log", err.getvalue())
        self.assertIn("lost so far: 2", err.getvalue())


class SchemaDeclaresSource(unittest.TestCase):
    def test_source_block_declared_and_sealed_records_validate(self):
        schema = load_schema()
        src = schema["properties"]["source"]
        self.assertEqual(set(src["properties"]), {"adapter", "via", "capture"})
        self.assertEqual(src["properties"]["capture"]["enum"], ["captured", "ingested"])
        from halo_record import validate_record
        from halo_record.record import SOURCES
        for key in SOURCES:
            rec = build("tool_call", "privacy", tool="t", source=key)
            self.assertIn(rec["source"]["capture"], ("captured", "ingested"), key)
            validate_record(rec)



class ExportRefusesEmptyChain(unittest.TestCase):
    def test_zero_record_chain_refused_and_nothing_written(self):
        log = os.path.join(tempfile.mkdtemp(), "empty.jsonl")
        open(log, "w").close()
        out = log + ".csv"
        code = export(log, out, out=lambda *a, **k: None)
        self.assertEqual(code, 3)
        self.assertFalse(os.path.exists(out))
        self.assertFalse(os.path.exists(out + ".manifest.json"))


class ManifestProvenance(unittest.TestCase):
    def test_manifest_carries_producer_source_hash_and_column_notes(self):
        from halo_record import __version__
        from halo_record.export import COLUMN_NOTES
        log = os.path.join(tempfile.mkdtemp(), "chain.jsonl")
        out = log + ".csv"
        Recorder(log).append(build("tool_call", "privacy", tool="t"))
        export(log, out, out=lambda *a, **k: None)
        with open(out + ".manifest.json") as fh:
            m = json.load(fh)
        self.assertEqual(m["producer_version"], __version__)
        import hashlib
        with open(log, "rb") as fh:
            self.assertEqual(m["source_log_sha256"], hashlib.sha256(fh.read()).hexdigest())
        self.assertEqual(set(m["columns"]), set(CSV_COLUMNS))
        self.assertEqual(m["columns"]["cross_region"]["blank"], "not declared (not 'false')")

    def test_manifest_column_notes_cover_every_column(self):
        from halo_record.export import COLUMN_NOTES
        self.assertEqual(set(COLUMN_NOTES), set(CSV_COLUMNS))
        for col, note in COLUMN_NOTES.items():
            self.assertIn(note["source"], ("recorder", "declared"), col)
            self.assertTrue(note["blank"], col)


class DataBlockNormalization(unittest.TestCase):
    def _stderr(self, fn):
        err = io.StringIO()
        old = sys.stderr
        sys.stderr = err
        try:
            result = fn()
        finally:
            sys.stderr = old
        return result, err.getvalue()

    def test_purpose_none_is_absent_not_the_string_none(self):
        rec = build("read", "privacy", tool="t", data={"purpose": None, "region": None})
        self.assertNotIn("purpose", rec.get("data", {}))
        self.assertNotIn("region", rec.get("data", {}))

    def test_cross_region_accepts_bool_and_0_1_only(self):
        for v, expect in ((True, 1), (False, 0), (1, 1), (0, 0), (1.0, 1)):
            rec, err = self._stderr(lambda: build("read", "privacy", tool="t",
                                                  data={"cross_region": v}))
            self.assertEqual(rec["data"]["cross_region"], expect, v)
            self.assertEqual(err, "", v)
        for v in ("yes", 2, -1, 2.5, [1]):
            rec, err = self._stderr(lambda: build("read", "privacy", tool="t",
                                                  data={"cross_region": v}))
            self.assertNotIn("cross_region", rec.get("data", {}), v)
            self.assertIn("cross_region", err, v)
            self.assertIn("dropped", err, v)

    def test_human_approved_without_approver_warns(self):
        _, err = self._stderr(lambda: build("tool_call", "privacy", tool="t",
                                            decision="human_approved"))
        self.assertIn("no approver", err)
        _, err = self._stderr(lambda: build("tool_call", "privacy", tool="t",
                                            decision="human_approved", approver="u-2"))
        self.assertEqual(err, "")

class AuthorizationIsNeverDefaulted(unittest.TestCase):
    def _stderr(self, fn):
        err = io.StringIO(); old = sys.stderr; sys.stderr = err
        try:
            r = fn()
        finally:
            sys.stderr = old
        return r, err.getvalue()

    def test_no_authorization_block_unless_supplied(self):
        rec = build("tool_call", "security", tool="x")
        self.assertNotIn("authorization", rec["action"])
        rec = build("tool_call", "security", tool="x", decision="denied")
        self.assertEqual(rec["action"]["authorization"], {"decision": "denied"})
        rec = build("tool_call", "security", tool="x", approver="u-2")
        self.assertEqual(rec["action"]["authorization"], {"approver": "u-2"})

    def test_out_of_enum_decision_dropped_loudly_and_record_verifies(self):
        from halo_record import validate_record
        rec, err = self._stderr(lambda: build("tool_call", "security", tool="x",
                                              decision="approved", scope="s"))
        self.assertIn("approved", err)
        self.assertEqual(rec["action"]["authorization"], {"scope": "s"})
        self.assertEqual(validate_record(rec), [])

    def test_out_of_enum_capture_drops_source_loudly(self):
        from halo_record import validate_record
        rec, err = self._stderr(lambda: build("tool_call", "security", tool="x",
                                              source={"adapter": "csv", "capture": "bogus"}))
        self.assertNotIn("source", rec)
        self.assertIn("bogus", err)
        self.assertEqual(validate_record(rec), [])

    def test_export_decision_blank_when_no_gate(self):
        log = os.path.join(tempfile.mkdtemp(), "c.jsonl"); out = log + ".csv"
        Recorder(log).append(build("tool_call", "security", tool="x"))
        export(log, out, out=lambda *a, **k: None)
        with open(out, newline="") as fh:
            self.assertEqual(list(csv.DictReader(fh))[0]["decision"], "")


class IbanChecksumGate(unittest.TestCase):
    VALID = ["GB82 WEST 1234 5698 7654 32", "gb82 west 1234 5698 7654 32",
             "GB82.WEST.1234.5698.7654.32", "GB82-WEST-1234-5698-7654-32",
             "DE89 3704 0044 0532 0130 00", "FR14 2004 1010 0505 0001 3M02 606"]
    LOOKALIKE = ["PO12 3456 7890 1234", "SK10-ABCD-1234-5678-9012",
                 "AB12-CDEF-3456-7890-1234-56", "US20 2026 REPORT FINAL",
                 "XX99-AAAA-BBBB-CCCC-DDDD", "OK42 WE ARE GOOD TO GO NOW",
                 "AA11 BB22 CC33 DD44 EE55"]

    def test_valid_ibans_masked_whole_and_classified(self):
        for v in self.VALID:
            masked = redact_text("account " + v)
            self.assertNotIn("1234", masked, v)
            self.assertNotIn("0044", masked, v)
            self.assertIn("iban", [f["type"] for f in scan(v)], v)

    def test_lookalikes_neither_masked_nor_classified(self):
        for v in self.LOOKALIKE:
            self.assertNotIn("iban", [f["type"] for f in scan(v, entropy=False)], v)
            if v.startswith("AB12"):
                continue  # its digit run is a Luhn-valid Amex shape; card masking is the safe failure
            self.assertEqual(redact_text(v, entropy=False), v, v)

    def test_iban_wins_over_card_pattern(self):
        # Digit body that a card regex could claim: the IBAN gate runs first,
        # so the whole value masks as an IBAN and never leaks a card-style tail.
        v = "DE89 3704 0044 0532 0130 00"
        masked = redact_text("send to " + v)
        self.assertEqual(masked, "send to DE****")


class HyphenatedApiKeys(unittest.TestCase):
    def test_vendor_segmented_keys_masked_even_when_low_entropy(self):
        for v in ("sk-live-AAAAAAAAAAAAAAAAAAAAAAAA", "sk-proj-abcdefghijklmnop1234",
                  "sk-ant-api03-ABCDEFGHIJKLMNOPQRST"):
            self.assertIn("api_key", [f["type"] for f in scan(v, entropy=False)], v)
            self.assertNotIn("AAAAAAAA", redact_text(v, entropy=False), v)
            self.assertNotIn("abcdefgh", redact_text(v, entropy=False), v)


class ExportWindowSemantics(unittest.TestCase):
    def test_unparseable_ts_included_in_unbounded_export(self):
        from halo_record.export import in_window
        rec = build("tool_call", "security", tool="x", ts="yesterday-ish")
        self.assertTrue(in_window(rec))
        import datetime
        self.assertFalse(in_window(rec, start=datetime.datetime(2026, 1, 1,
                                                                tzinfo=datetime.timezone.utc)))


class ModelCallPurposeLandsInData(unittest.TestCase):
    def test_record_model_call_seals_purpose_in_data(self):
        from halo_record import record_model_call
        log = os.path.join(tempfile.mkdtemp(), "m.jsonl")
        rec = record_model_call(Recorder(log), provider="anthropic", model="m",
                                purpose="draft reply", response="ok")
        self.assertEqual(rec["data"]["purpose"], "draft reply")
        # scope is declared (model:<provider>); no decision is ever defaulted
        self.assertNotIn("decision", rec["action"]["authorization"])

    def test_demo_exports_region_and_purpose(self):
        from halo_record.demo import scaffold
        d = tempfile.mkdtemp()
        scaffold(d)
        log = os.path.join(d, "acme-corp.jsonl"); out = log + ".csv"
        export(log, out, out=lambda *a, **k: None)
        with open(out, newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertTrue(any(r["region"] == "us-east-1" for r in rows))
        self.assertTrue(any(r["purpose"].startswith("draft reply") for r in rows))


class NonStringDeclarationsNeverRaise(unittest.TestCase):
    def test_unhashable_decision_and_capture_are_dropped_not_raised(self):
        err = io.StringIO(); old = sys.stderr; sys.stderr = err
        try:
            rec = build("tool_call", "security", tool="x", decision=["allowed"],
                        source={"adapter": "csv", "capture": {"tier": "captured"}})
        finally:
            sys.stderr = old
        self.assertNotIn("authorization", rec["action"])
        self.assertNotIn("source", rec)
        self.assertIn("dropped", err.getvalue())


if __name__ == "__main__":
    unittest.main()
