import csv
import json
import os
import tempfile
import unittest

from halo_record import Recorder, build
from halo_record.export import export, parse_bound


def _silent(*args, **kwargs):
    pass


def _chain(path, days, agent=None):
    rec = Recorder(path)
    for i, day in enumerate(days):
        rec.append(
            build(
                "tool_call",
                "security",
                tool="Bash",
                tool_input={"n": i},
                subject="acme-corp",
                agent=agent,
                ts=f"2026-06-{day:02d}T12:00:00+00:00",
                outcome={"status": "ok"},
            )
        )


class ExportTest(unittest.TestCase):
    def _paths(self):
        d = tempfile.mkdtemp()
        return (
            os.path.join(d, "audit.jsonl"),
            os.path.join(d, "evidence.csv"),
        )

    def test_window_is_inclusive_and_dated(self):
        log, out = self._paths()
        _chain(log, [1, 10, 20, 30])
        code = export(
            log,
            out,
            start=parse_bound("2026-06-10"),
            end=parse_bound("2026-06-20", end=True),
            out=_silent,
        )
        self.assertEqual(code, 0)
        with open(out, newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 2)  # the 10th and the 20th, both inclusive
        self.assertTrue(rows[0]["ts"].startswith("2026-06-10"))
        self.assertTrue(rows[1]["ts"].startswith("2026-06-20"))
        self.assertEqual(rows[0]["subject"], "acme-corp")
        self.assertEqual(rows[0]["outcome"], "ok")
        self.assertTrue(rows[0]["hash"])

    def test_manifest_ties_export_to_chain_head(self):
        log, out = self._paths()
        _chain(log, [1, 10, 20, 30])
        export(log, out, start=parse_bound("2026-06-10"),
               end=parse_bound("2026-06-20", end=True), out=_silent)
        with open(out + ".manifest.json") as fh:
            manifest = json.load(fh)
        with open(log) as fh:
            last = json.loads([l for l in fh if l.strip()][-1])
        self.assertEqual(manifest["chain"]["head_hash"], last["integrity"]["hash"])
        self.assertEqual(manifest["chain"]["total_records"], 4)
        self.assertEqual(manifest["window_records"], 2)
        self.assertTrue(manifest["chain"]["verified"])

    def test_manifest_csv_hash_matches_file_and_detects_edits(self):
        import hashlib
        log, out = self._paths()
        _chain(log, [1, 10, 20])
        export(log, out, out=_silent)
        with open(out + ".manifest.json") as fh:
            manifest = json.load(fh)
        with open(out, "rb") as fh:
            self.assertEqual(manifest["csv_sha256"],
                             hashlib.sha256(fh.read()).hexdigest())
        # an edited CSV no longer matches its manifest
        with open(out, "a", encoding="utf-8") as fh:
            fh.write("2026-06-30T00:00:00Z,forged-row\n")
        with open(out, "rb") as fh:
            self.assertNotEqual(manifest["csv_sha256"],
                                hashlib.sha256(fh.read()).hexdigest())

    def test_formula_cells_are_neutralized(self):
        # An evidence CSV gets opened in Excel/Sheets — cells must never
        # execute as formulas there.
        log, out = self._paths()
        rec = Recorder(log)
        rec.append(build("tool_call", "security",
                         tool='=HYPERLINK("http://evil.example","x")',
                         tool_input={"q": 1}, session_id="=cmd|calc",
                         ts="2026-06-15T00:00:00+00:00"))
        export(log, out, out=_silent)
        with open(out, newline="") as fh:
            row = list(csv.DictReader(fh))[0]
        self.assertTrue(row["tool"].startswith("'="))
        self.assertTrue(row["session_id"].startswith("'="))

    def test_tool_filter_scopes_the_export(self):
        # An assessor pulling "just the actions this control covers" shouldn't
        # have to hand-filter the sheet afterward.
        log, out = self._paths()
        rec = Recorder(log)
        for tool in ("email.send", "db.query", "email.send", "http.get"):
            rec.append(build("tool_call", "security", tool=tool, subject="acme",
                             ts="2026-06-15T00:00:00+00:00",
                             outcome={"status": "ok"}))
        export(log, out, tools=["email.send"], out=_silent)
        with open(out, newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["tool"] for r in rows}, {"email.send"})

    def test_tool_filter_is_case_insensitive_and_disclosed_in_manifest(self):
        # A filtered export is a SUBSET — the manifest must say so, or the CSV
        # reads as the whole population.
        log, out = self._paths()
        rec = Recorder(log)
        for tool in ("Email.Send", "db.query"):
            rec.append(build("tool_call", "security", tool=tool, subject="acme",
                             ts="2026-06-15T00:00:00+00:00",
                             outcome={"status": "ok"}))
        export(log, out, tools=["EMAIL.SEND"], out=_silent)
        with open(out + ".manifest.json") as fh:
            manifest = json.load(fh)
        self.assertEqual(manifest["tool_filter"], ["EMAIL.SEND"])
        self.assertEqual(manifest["window_records"], 1)
        self.assertEqual(manifest["chain"]["total_records"], 2)

    def test_unfiltered_export_records_no_tool_filter(self):
        log, out = self._paths()
        _chain(log, [15])
        export(log, out, out=_silent)
        with open(out + ".manifest.json") as fh:
            self.assertIsNone(json.load(fh)["tool_filter"])

    def test_summary_columns_read_as_prose_not_dict_syntax(self):
        # The recorder stores structured inputs as the string form of a
        # mapping; a review sheet should show "k=v; k=v", not Python syntax.
        log, out = self._paths()
        rec = Recorder(log)
        rec.append(build("tool_call", "security", tool="email.send",
                         tool_input={"to": "alice@acme.com", "subject": "Q3"},
                         subject="acme", ts="2026-06-15T00:00:00+00:00",
                         outcome={"status": "ok", "summary": "sent to 1 recipient"}))
        export(log, out, out=_silent)
        with open(out, newline="") as fh:
            row = list(csv.DictReader(fh))[0]
        self.assertNotIn("{", row["action_summary"])
        self.assertNotIn("'", row["action_summary"])
        self.assertIn("subject=Q3", row["action_summary"])
        self.assertIn("to=", row["action_summary"])
        self.assertEqual(row["outcome_summary"], "sent to 1 recipient")
        # reformatting must not undo redaction — the address stays masked
        self.assertNotIn("alice@acme.com", row["action_summary"])

    def test_reformatting_still_neutralizes_formula_injection(self):
        # _readable runs before _neutralize; a payload smuggled inside a
        # structured summary must still not execute in a spreadsheet.
        log, out = self._paths()
        rec = Recorder(log)
        rec.append(build("tool_call", "security", tool="http.get",
                         tool_input={"=cmd|calc": "x"}, subject="acme",
                         ts="2026-06-15T00:00:00+00:00",
                         outcome={"status": "ok"}))
        export(log, out, out=_silent)
        with open(out, newline="") as fh:
            row = list(csv.DictReader(fh))[0]
        self.assertFalse(row["action_summary"].startswith("="))

    def test_auditor_columns_populate(self):
        # The fields an assessor maps controls against: authorization scope,
        # framework tags, chain linkage, and the friendly subject name.
        log, out = self._paths()
        rec = Recorder(log)
        rec.append(build("tool_call", "privacy", tool="db.query",
                         subject={"id": "acme", "name": "Acme Corp"},
                         scope="tenant:acme", decision="human_approved",
                         ts="2026-06-15T00:00:00+00:00",
                         outcome={"status": "ok"}))
        export(log, out, out=_silent)
        with open(out, newline="") as fh:
            row = list(csv.DictReader(fh))[0]
        self.assertEqual(row["subject_name"], "Acme Corp")
        self.assertEqual(row["scope"], "tenant:acme")
        self.assertEqual(row["decision"], "human_approved")
        # prev_hash gives a reviewer the chain linkage without opening the JSONL
        self.assertTrue(row["prev_hash"])
        self.assertTrue(row["hash"])

    def test_no_always_empty_columns(self):
        # Every column must be able to carry data from a record the shipped
        # builder can produce — an always-blank column reads as a broken
        # feature in a review sheet.
        from halo_record.export import CSV_COLUMNS
        log, out = self._paths()
        rec = Recorder(log)
        rec.append(build("tool_call", "privacy", tool="db.query",
                         tool_input={"q": "select 1"},
                         subject={"id": "acme", "name": "Acme Corp"},
                         scope="tenant:acme", decision="human_approved",
                         principal={"human_id": "u-1"}, parent_id="r-0",
                         agent={"id": "a1", "name": "Support", "version": "1.2.0",
                                "model": "claude", "model_version": "4"},
                         data={"pii_types": ["email"]},
                         ts="2026-06-15T00:00:00+00:00",
                         outcome={"status": "ok", "summary": "1 row"}))
        export(log, out, out=_silent)
        with open(out, newline="") as fh:
            row = list(csv.DictReader(fh))[0]
        # 'threats' and 'authority_snapshot' are legitimately optional here
        optional = {"threats", "authority_snapshot", "findings", "severity",
                    "session_id", "source"}
        blank = [c for c in CSV_COLUMNS if c not in optional and not row.get(c)]
        self.assertEqual(blank, [], f"columns never populate: {blank}")

    def test_refuses_tampered_chain(self):
        log, out = self._paths()
        _chain(log, [1, 10])
        with open(log) as fh:
            rows = [json.loads(l) for l in fh if l.strip()]
        rows[0]["action"]["tool"] = "Tampered"
        with open(log, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, separators=(",", ":")) + "\n")
        code = export(log, out, out=_silent)
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(out))  # no evidence file from a broken chain

    def test_empty_window_still_writes_valid_files(self):
        log, out = self._paths()
        _chain(log, [1, 2])
        code = export(log, out, start=parse_bound("2026-07-01"), out=_silent)
        self.assertEqual(code, 0)
        with open(out, newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(rows, [])
        with open(out + ".manifest.json") as fh:
            manifest = json.load(fh)
        self.assertEqual(manifest["window_records"], 0)
        self.assertEqual(manifest["chain"]["total_records"], 2)

    def test_version_binding_surfaces_in_csv(self):
        log, out = self._paths()
        _chain(
            log,
            [1, 2],
            agent={
                "id": "support-bot",
                "name": "support-bot",
                "version": "1.4.2",
                "model": "claude-sonnet-4-6",
                "model_version": "20251001",
            },
        )
        export(log, out, out=_silent)
        with open(out, newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(rows[0]["agent_version"], "1.4.2")
        self.assertEqual(rows[0]["model"], "claude-sonnet-4-6")
        self.assertEqual(rows[0]["model_version"], "20251001")

    def test_unversioned_records_export_empty_binding(self):
        log, out = self._paths()
        _chain(log, [1])
        export(log, out, out=_silent)
        with open(out, newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertIn("agent_version", rows[0])
        self.assertEqual(rows[0]["agent_version"], "")

    def test_no_bounds_exports_everything(self):
        log, out = self._paths()
        _chain(log, [1, 10, 20])
        export(log, out, out=_silent)
        with open(out, newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 3)

    def test_bad_bound_raises(self):
        with self.assertRaises(ValueError):
            parse_bound("junk")


if __name__ == "__main__":
    unittest.main()
