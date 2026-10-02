"""Tenant routing reads chain files the way the verifier splits them."""

import json
import os
import tempfile
import unittest

from halo_record.record import TenantRecorder, build


class FileSubjectsSplitTest(unittest.TestCase):
    def test_a_carriage_return_inside_a_record_does_not_split_it(self):
        rec = build("tool_call", "security", tool="t", subject="acme")
        text = json.dumps(rec).replace(', "subject"', ',\r"subject"', 1)
        self.assertIn("\r", text)
        p = os.path.join(tempfile.mkdtemp(), "c.jsonl")
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write("﻿" + text + "\r\n")
        self.assertEqual(TenantRecorder._file_subjects(p), {"acme"})


if __name__ == "__main__":
    unittest.main()
