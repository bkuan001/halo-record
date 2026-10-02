"""Evidence surfaces — report page, export, policy, witness, serve — say exactly
what they verified, bind what they display to what they verified, and fail
closed when a check they depend on cannot run."""

import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from halo_record.record import Recorder, build
from halo_record.verify import verify_log


def _chain(path, n=4, subject="acme", **kw):
    rec = Recorder(path)
    out = []
    for i in range(n):
        out.append(rec.append(build("tool_call", "security", tool="t%d" % i,
                                    tool_input={"i": i}, subject=subject, **kw)))
    return out


def _drop_line(path, idx):
    with open(path, encoding="utf-8") as fh:
        lines = [ln for ln in fh.read().split("\n") if ln.strip()]
    del lines[idx]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


class DeletionMessageTest(unittest.TestCase):
    def test_a_deleted_record_is_reported_as_a_missing_link_not_a_hash_mismatch(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        _chain(log, 4)
        _drop_line(log, 1)
        lines = []
        self.assertFalse(verify_log(log, out=lines.append))
        text = "\n".join(lines)
        self.assertIn("record 2", text)
        self.assertRegex(text, r"record 2: chain: .*missing|record 2: chain: .*not the record before it")
        self.assertNotIn("does not match recomputed", text)

    def test_an_edited_record_still_reports_its_own_hash_mismatch(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        _chain(log, 3)
        with open(log, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        lines[1] = lines[1].replace('"t1"', '"tX"')
        with open(log, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        out = []
        self.assertFalse(verify_log(log, out=out.append))
        self.assertIn("record 2: chain: hash", "\n".join(out))


if __name__ == "__main__":
    unittest.main()
