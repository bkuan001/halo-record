"""An incomplete last line (a torn write, or a truncated file) never restarts
the chain and is never glued to the next record: its bytes stay in place, the
next record links to the last complete record, and verification reports the
incomplete line."""

import contextlib
import io
import json
import os
import tempfile
import unittest

from halo_record.canon import GENESIS_PREV
from halo_record.record import Recorder, TenantRecorder, build
from halo_record.verify import verify_log


def _rec(tool="t", **kw):
    return build("tool_call", "security", tool=tool, **kw)


def _lines(path):
    with open(path, "rb") as fh:
        return fh.read().split(b"\n")


class TornTailTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.path = os.path.join(self.d, "c.jsonl")
        r = Recorder(self.path)
        self.sealed = [r.append(_rec("t%d" % i)) for i in range(3)]

    def _truncate(self, n):
        size = os.path.getsize(self.path)
        with open(self.path, "r+b") as fh:
            fh.truncate(size - n)
        with open(self.path, "rb") as fh:
            return fh.read()

    def test_append_after_torn_tail_links_to_last_complete_record(self):
        before = self._truncate(40)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            new = Recorder(self.path).append(_rec("after"))
        with open(self.path, "rb") as fh:
            after = fh.read()
        # Nothing lost: the torn bytes are kept exactly, then a line break.
        self.assertTrue(after.startswith(before + b"\n"))
        self.assertEqual(new["integrity"]["prev_hash"], self.sealed[1]["integrity"]["hash"])
        self.assertNotEqual(new["integrity"]["prev_hash"], GENESIS_PREV)
        self.assertEqual(json.loads(_lines(self.path)[3])["record_id"], new["record_id"])
        self.assertIn("not a complete record", err.getvalue())
        out = []
        self.assertFalse(verify_log(self.path, out=out.append))
        text = "\n".join(out)
        self.assertIn("record 3: not valid JSON", text)
        self.assertNotIn("prev_hash", text)
        self.assertIn("1 line(s) are not complete records", text)

    def test_cached_recorder_also_links_past_torn_tail(self):
        r = Recorder(self.path)
        r.last_hash()  # cache the head
        self._truncate(40)
        with contextlib.redirect_stderr(io.StringIO()):
            new = r.append(_rec("after"))
        self.assertEqual(new["integrity"]["prev_hash"], self.sealed[1]["integrity"]["hash"])

    def test_complete_last_line_without_newline_is_not_glued(self):
        self._truncate(1)  # drop only the trailing newline
        Recorder(self.path).append(_rec("after"))
        self.assertTrue(verify_log(self.path, out=lambda *_: None))

    def test_file_with_no_complete_record_keeps_its_bytes(self):
        with open(self.path, "wb") as fh:
            fh.write(b'{"schema_version":"0.1","record_id":"x","integ')
        with open(self.path, "rb") as fh:
            before = fh.read()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            new = Recorder(self.path).append(_rec("after"))
        with open(self.path, "rb") as fh:
            self.assertTrue(fh.read().startswith(before + b"\n"))
        self.assertEqual(new["integrity"]["prev_hash"], GENESIS_PREV)
        self.assertIn("not a complete record", err.getvalue())

    def test_tenant_tail_check_reads_last_complete_record(self):
        d = tempfile.mkdtemp()
        t = TenantRecorder(d)
        t.append(_rec(subject="acme"))
        t.append(_rec(subject="acme"))
        p = t.chain_path_for("acme")
        with open(p, "r+b") as fh:
            fh.truncate(os.path.getsize(p) - 40)
        with contextlib.redirect_stderr(io.StringIO()):
            new = TenantRecorder(d).append(_rec(subject="acme"))
        self.assertNotEqual(new["integrity"]["prev_hash"], GENESIS_PREV)


if __name__ == "__main__":
    unittest.main()
