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
