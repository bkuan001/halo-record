"""Subjectless chains are witness-matched by chain_root, which a drop-first
attack changes. verify_completeness must say so loudly on every verdict for
such a chain — and stay quiet for chains with a subject."""

import os
import tempfile
import unittest

from halo_record.anchor import checkpoint, verify_completeness
from halo_record.record import Recorder, build


def _chain(directory, n, subject=None):
    rec = Recorder(os.path.join(directory, "c.jsonl"))
    out = []
    for i in range(n):
        out.append(rec.append(build("tool_call", "security", tool="t%d" % i,
                                    subject=subject)))
    return out


class SubjectlessCaveatTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_subjectless_ok_verdict_carries_caveat(self):
        recs = _chain(self.dir, 3)
        result = verify_completeness(recs, [checkpoint(recs)])
        self.assertIs(result["ok"], True)
        self.assertIn("subjectless_caveat", result)
        self.assertIn("chain_root", result["subjectless_caveat"])

    def test_drop_first_reads_unwitnessed_with_caveat(self):
        recs = _chain(self.dir, 3)
        cp = checkpoint(recs)
        rerooted = recs[1:]  # drop-first: chain_root changes, checkpoint no longer matches
        result = verify_completeness(rerooted, [cp])
        self.assertIsNone(result["ok"])
        self.assertIn("subjectless_caveat", result)

    def test_out_of_range_witnessed_counts_fail_with_caveat(self):
        recs = _chain(self.dir, 3)
        for bad_count in (0, -1, 4):
            cp = checkpoint(recs)
            cp["count"] = bad_count
            result = verify_completeness(recs, [cp])
            self.assertIs(result["ok"], False)
            self.assertIn("subjectless_caveat", result)

    def test_subjectful_chain_has_no_caveat(self):
        recs = _chain(self.dir, 3, subject="acme-corp")
        ok = verify_completeness(recs, [checkpoint(recs)])
        self.assertIs(ok["ok"], True)
        self.assertNotIn("subjectless_caveat", ok)
        none = verify_completeness(recs, [])
        self.assertIsNone(none["ok"])
        self.assertNotIn("subjectless_caveat", none)


if __name__ == "__main__":
    unittest.main()
