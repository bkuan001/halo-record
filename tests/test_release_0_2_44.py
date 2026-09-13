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


if __name__ == "__main__":
    unittest.main()
