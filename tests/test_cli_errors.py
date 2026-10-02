"""CLI commands report unreadable input in one line, and still fail closed.

``halo anchor`` (witness and ``--check``) on a torn line, an integer too long
to read, or a missing file exits 1 with a message, not a traceback;
``halo witness-serve`` on a port already in use does the same.
``halo export -w`` naming a witness file that does not exist is refused (exit
2), distinct from an existing witness that holds no checkpoint (exit 3);
``halo report -w`` refuses it (exit 1) and ``halo anchor --check`` exits 2.
"""

import contextlib
import io
import json
import os
import socket
import tempfile
import unittest

from halo_record.cli import main
from halo_record.record import Recorder, build


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class _Chain(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.log = os.path.join(self.d, "c.jsonl")
        rec = Recorder(self.log)
        with contextlib.redirect_stderr(io.StringIO()):
            for i in range(3):
                rec.append(build("tool_call", "security", tool="t%d" % i, subject="acme"))
        self.witness = os.path.join(self.d, "w.jsonl")

    def _variant(self, name, text):
        p = os.path.join(self.d, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p


class AnchorErrorsTest(_Chain):
    def _bad_logs(self):
        with open(self.log, encoding="utf-8") as fh:
            good = fh.read()
        torn = self._variant("torn.jsonl", good + '{"schema_version": "0.1", "rec')
        rec = json.loads(good.splitlines()[0])
        rec["outcome"] = {"status": "ok"}
        huge = self._variant("huge.jsonl", good + json.dumps(rec)[:-1] + ', "n": ' + "9" * 5000 + "}\n")
        return {"torn": torn, "huge": huge, "missing": os.path.join(self.d, "nope.jsonl")}

    def test_anchor_reports_unreadable_logs_cleanly(self):
        for name, path in self._bad_logs().items():
            for extra in ([], ["--check"]):
                with self.subTest(case=name, extra=extra):
                    code, out, err = _run(["anchor", path, self.witness] + extra)
                    self.assertEqual(code, 1)
                    self.assertIn("halo anchor:", err)
                    self.assertIn(os.path.basename(path), err)
                    self.assertNotIn("COMPLETE", out)

    def test_anchor_skips_an_unreadable_witness_line(self):
        bad = self._variant("w-bad.jsonl", '{"subject": "acme", "count": ' + "9" * 5000 + "}\n")
        # A damaged witness line is skipped (it never hides the rest), so the
        # chain reads as not witnessed, the same in every Python version.
        code, out, err = _run(["anchor", self.log, bad, "--check"])
        self.assertEqual(code, 3)
        self.assertIn("UNWITNESSED", out)


class WitnessServePortTest(unittest.TestCase):
    def test_port_in_use_is_reported(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        try:
            code, out, err = _run(["witness-serve", tempfile.mkdtemp(), "--port", str(port)])
        finally:
            s.close()
        self.assertEqual(code, 1)
        self.assertIn("halo witness-serve:", err)


class ExportMissingWitnessTest(_Chain):
    def test_missing_witness_file_is_refused(self):
        out = os.path.join(self.d, "e.csv")
        code, so, err = _run(["export", self.log, "-o", out, "-w",
                              os.path.join(self.d, "typo.jsonl")])
        self.assertEqual(code, 2)
        self.assertIn("typo.jsonl", so + err)
        self.assertFalse(os.path.exists(out))

    def test_report_and_anchor_check_refuse_a_missing_witness_file(self):
        typo = os.path.join(self.d, "typo.jsonl")
        out = os.path.join(self.d, "r.html")
        code, so, err = _run(["report", self.log, "-o", out, "-w", typo])
        self.assertEqual(code, 1)
        self.assertIn("REFUSED", so)
        self.assertFalse(os.path.exists(out))
        code, so, err = _run(["anchor", self.log, typo, "--check"])
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)

    def test_existing_empty_witness_is_unwitnessed(self):
        open(self.witness, "w").close()
        code, so, err = _run(["export", self.log, "-o", os.path.join(self.d, "e2.csv"),
                              "-w", self.witness])
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
