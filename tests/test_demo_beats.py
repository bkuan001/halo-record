"""The demo's printed beats describe what the page and the CLI actually show:
a local witness file reads as grey "Self-attested" completeness; dropping the
LAST line of a chain keeps integrity green and turns completeness red; dropping
a middle line fails integrity and the report is withheld."""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from halo_record import demo
from halo_record.anchor import Notary, verify_completeness
from halo_record.report import _load
from halo_record.verify import read_log_lines, verify_log


def _beats():
    d = tempfile.mkdtemp()
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        demo.main(d, serve=False, open_browser=False)
    return d, " ".join(out.getvalue().split())


def _drop(path, index):
    lines = read_log_lines(path)
    del lines[index]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


class DemoBeatsTest(unittest.TestCase):
    def test_beats_name_what_the_page_shows(self):
        _, text = _beats()
        self.assertNotIn("both green", text)
        self.assertIn("Self-attested", text)
        self.assertIn("LAST line", text)
        self.assertIn("middle line", text)
        self.assertIn("withheld", text)

    def test_dropping_the_last_line_keeps_integrity_and_fails_completeness(self):
        d, _ = _beats()
        log = os.path.join(d, "acme-corp.jsonl")
        _drop(log, -1)
        self.assertTrue(verify_log(log, out=lambda *_: None))
        cps = Notary(os.path.join(d, ".witness.jsonl")).checkpoints()
        self.assertIs(verify_completeness(_load(log), cps)["ok"], False)

    def test_dropping_a_middle_line_fails_integrity(self):
        d, _ = _beats()
        log = os.path.join(d, "acme-corp.jsonl")
        _drop(log, 1)
        self.assertFalse(verify_log(log, out=lambda *_: None))


if __name__ == "__main__":
    unittest.main()
