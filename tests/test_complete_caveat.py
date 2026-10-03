"""A COMPLETE verdict printed by the CLI carries the same caveat the report
page and the export manifest carry: completeness is only as independent as
whoever operates the witness. A local witness file is the operator's own copy
unless someone outside the operator holds it."""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from halo_record.anchor import Notary
from halo_record.cli import main
from halo_record.record import Recorder, build

CAVEAT = "only as independent as whoever holds this witness file"


def _anchored():
    d = tempfile.mkdtemp()
    log = os.path.join(d, "c.jsonl")
    rec = Recorder(log)
    recs = [rec.append(build("tool_call", "security", tool="t%d" % i, subject="acme")) for i in range(3)]
    witness = os.path.join(d, "w.jsonl")
    Notary(witness).witness(recs)
    return d, log, witness


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue() + err.getvalue()


class CompleteCaveatTest(unittest.TestCase):
    def test_anchor_check_against_a_local_file(self):
        _, log, witness = _anchored()
        rc, text = _run(["anchor", log, witness, "--check"])
        self.assertEqual(rc, 0, text)
        self.assertIn("COMPLETE", text)
        self.assertIn(CAVEAT, text)
        self.assertIn("self-attested", text)

    def test_export_against_a_local_file(self):
        d, log, witness = _anchored()
        rc, text = _run(["export", log, "-o", os.path.join(d, "e.csv"), "-w", witness])
        self.assertEqual(rc, 0, text)
        self.assertIn("COMPLETE", text)
        self.assertIn(CAVEAT, text)

    def test_no_caveat_without_a_complete_verdict(self):
        d, log, witness = _anchored()
        Recorder(log).append(build("tool_call", "security", tool="later", subject="acme"))
        os.remove(witness)
        rc, text = _run(["export", log, "-o", os.path.join(d, "e.csv")])
        self.assertEqual(rc, 0, text)
        self.assertNotIn(CAVEAT, text)


if __name__ == "__main__":
    unittest.main()
