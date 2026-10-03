"""`halo export` keeps identifier cells exactly as recorded (so the CSV ties
out to the records byte for byte) and says when one carries an invisible
character: a warning on stderr naming the record and field, and the same list
in the manifest."""

import csv
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from halo_record.cli import main
from halo_record.record import Recorder, build


def _chain(tool, approver=None):
    d = tempfile.mkdtemp()
    log = os.path.join(d, "c.jsonl")
    rec = Recorder(log)
    rec.append(build("tool_call", "security", tool="lookup", subject="acme"))
    r = rec.append(build("tool_call", "security", tool=tool, subject="acme",
                         decision="human_approved" if approver else None, approver=approver))
    return d, log, r["record_id"]


def _export(d, log):
    out, err = io.StringIO(), io.StringIO()
    csv_path = os.path.join(d, "e.csv")
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(["export", log, "-o", csv_path])
    with open(csv_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    with open(csv_path + ".manifest.json", encoding="utf-8") as fh:
        manifest = json.load(fh)
    return rc, err.getvalue(), rows, manifest


class ExportInvisibleIdentifiersTest(unittest.TestCase):
    def test_warns_and_keeps_raw_values(self):
        d, log, rid = _chain("payments​.refund", approver="alice‮")
        rc, err, rows, manifest = _export(d, log)
        self.assertEqual(rc, 0)
        self.assertIn("WARNING", err)
        self.assertIn(rid, err)
        self.assertIn("action.tool = payments⟨U+200B⟩.refund", err)
        self.assertIn("action.authorization.approver = alice⟨U+202E⟩", err)
        self.assertIn("payments​.refund", [r["tool"] for r in rows])  # as recorded
        note = manifest["invisible_identifiers"]
        self.assertEqual(note["count"], 2)
        self.assertEqual({f["field"] for f in note["fields"]},
                         {"action.tool", "action.authorization.approver"})
        self.assertTrue(all(f["record_id"] == rid for f in note["fields"]))

    def test_plain_ids_add_nothing(self):
        d, log, _ = _chain("payments.refund")
        rc, err, _, manifest = _export(d, log)
        self.assertEqual(rc, 0)
        self.assertNotIn("invisible", err)
        self.assertNotIn("invisible_identifiers", manifest)


if __name__ == "__main__":
    unittest.main()
