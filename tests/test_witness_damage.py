"""A damaged witness is refused, never read around.

A checkpoint line that does not parse (a torn last write, garbage) or does not
have a checkpoint's shape makes the whole witness unusable for a completeness
verdict: the torn checkpoint may be the one that exposes a truncation. So:

* ``Notary.checkpoints`` raises ``WitnessFileError``;
* ``halo anchor --check``, ``halo report -w`` and ``halo export -w`` refuse
  with exit 2, the same code as for a missing witness file;
* the hosted witness answers 503 for reads while its store is damaged, and a
  new checkpoint appended after a torn line still lands on its own line;
* ``halo export -o`` into a missing directory is a one-line refusal (exit 2).
"""

import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from halo_record.anchor import Notary, checkpoint
try:
    from halo_record.anchor import WitnessFileError
except ImportError:  # red run
    WitnessFileError = ValueError
from halo_record.cli import main
from halo_record.record import Recorder, build
from halo_record.witness import _Handler

KEY = "k-123"


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue() + err.getvalue()


class _Chain(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.log = os.path.join(self.d, "c.jsonl")
        rec = Recorder(self.log)
        self.records = [rec.append(build("tool_call", "security", tool="t%d" % i, subject="acme"))
                        for i in range(3)]
        self.wit = os.path.join(self.d, "w.jsonl")
        n = Notary(self.wit)
        n.witness(self.records[:2])
        n.witness(self.records)

    def _tear(self):
        with open(self.wit, "rb") as fh:
            data = fh.read()
        with open(self.wit, "wb") as fh:
            fh.write(data[:-25])  # the last checkpoint loses its tail

    def _garbage(self):
        with open(self.wit, "w", encoding="utf-8") as fh:
            fh.write("this is not a witness\nnor is this\n")


class NotaryDamageTest(_Chain):
    def test_intact_file_reads(self):
        self.assertEqual(len(Notary(self.wit).checkpoints()), 2)

    def test_torn_tail_is_refused(self):
        self._tear()
        with self.assertRaises(WitnessFileError) as cm:
            Notary(self.wit).checkpoints()
        self.assertIn("line 2", str(cm.exception))

    def test_garbage_is_refused(self):
        self._garbage()
        with self.assertRaises(WitnessFileError):
            Notary(self.wit).checkpoints_for(self.records)

    def test_wrong_shape_is_refused(self):
        for line in ('{"count": "3", "head": "x"}', '{"count": 2}', '[1, 2]', '{"count": true, "head": "x"}'):
            with open(self.wit, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            with self.assertRaises(WitnessFileError, msg=line):
                Notary(self.wit).checkpoints()
            self.setUp()

    def test_a_new_checkpoint_after_a_torn_line_keeps_its_own_line(self):
        self._tear()
        Notary(self.wit).record_checkpoint(checkpoint(self.records))
        with open(self.wit, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        self.assertEqual(json.loads(lines[-2])["count"], 3)


class CliDamageTest(_Chain):
    def test_anchor_check(self):
        for damage in (self._tear, self._garbage):
            self.setUp()
            damage()
            rc, out = _run(["anchor", self.log, self.wit, "--check"])
            self.assertEqual(rc, 2, out)
            self.assertIn("damaged", out)
            self.assertNotIn("COMPLETE", out)
            self.assertNotIn("UNWITNESSED", out)
            self.assertNotIn("Traceback", out)

    def test_report(self):
        for damage in (self._tear, self._garbage):
            self.setUp()
            damage()
            rc, out = _run(["report", self.log, "-w", self.wit, "-o", os.path.join(self.d, "r.html")])
            self.assertEqual(rc, 2, out)
            self.assertIn("damaged", out)

    def test_export(self):
        for damage in (self._tear, self._garbage):
            self.setUp()
            damage()
            rc, out = _run(["export", self.log, "-w", self.wit, "-o", os.path.join(self.d, "x.csv")])
            self.assertEqual(rc, 2, out)
            self.assertIn("damaged", out)
            self.assertFalse(os.path.exists(os.path.join(self.d, "x.csv")))

    def test_missing_witness_file_is_exit_2_everywhere(self):
        missing = os.path.join(self.d, "nope.jsonl")
        for argv in (["anchor", self.log, missing, "--check"],
                     ["report", self.log, "-w", missing, "-o", os.path.join(self.d, "r.html")],
                     ["export", self.log, "-w", missing, "-o", os.path.join(self.d, "x.csv")]):
            rc, out = _run(argv)
            self.assertEqual(rc, 2, (argv[0], out))
            self.assertIn("does not exist", out)

    def test_export_into_a_missing_directory(self):
        target = os.path.join(self.d, "no", "such", "x.csv")
        rc, out = _run(["export", self.log, "-o", target])
        self.assertEqual(rc, 2, out)
        self.assertIn("REFUSED", out)
        self.assertNotIn("Traceback", out)
        rc, out = _run(["export", self.log, "-o", os.path.join(self.d, "ok.csv"),
                        "--manifest", os.path.join(self.d, "no", "m.json")])
        self.assertEqual(rc, 2, out)
        self.assertFalse(os.path.exists(os.path.join(self.d, "ok.csv")))


class HostedWitnessDamageTest(unittest.TestCase):
    def setUp(self):
        self.store = tempfile.mkdtemp()
        self.notary = Notary(os.path.join(self.store, "witness.jsonl"))
        handler = type("_BoundWitness", (_Handler,),
                       {"config": {"notary": self.notary, "keys": [KEY]}})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def _get(self):
        try:
            with urllib.request.urlopen(self.url + "/v1/checkpoints?subject=acme", timeout=5) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_damaged_store_answers_503(self):
        recs = [build("tool_call", "security", tool="t", subject="acme")]
        self.notary.witness(recs)
        self.assertEqual(self._get()[0], 200)
        with open(self.notary.path, "a", encoding="utf-8") as fh:
            fh.write('{"subject": "acme", "count": 9, "he')  # torn
        status, body = self._get()
        self.assertEqual(status, 503)
        self.assertIn("damaged", body["error"])


if __name__ == "__main__":
    unittest.main()


class ServeDamageTest(_Chain):
    def test_console_and_index_show_a_damaged_witness(self):
        from halo_record import serve
        d = tempfile.mkdtemp()
        rec = Recorder(os.path.join(d, "acme.jsonl"))
        recs = [rec.append(build("tool_call", "security", tool="t", subject="acme"))]
        Notary(self.wit).witness(recs)
        self._tear()
        payload = serve._console_payload(d, b"s" * 32, self.wit)
        self.assertEqual(payload["chains"][0]["completeness"], "witness damaged")
        self.assertIn("witness damaged", serve._index_html(d, b"s" * 32, self.wit, True))
