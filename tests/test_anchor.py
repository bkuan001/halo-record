"""Completeness witnessing — the notary closes the drop-a-record gap that
hash-chaining alone can't."""

import os
import tempfile
import unittest

from halo_record.anchor import (
    Notary, chain_root, checkpoint, head, verify_completeness,
)
from halo_record.record import Recorder, build


def _chain(directory, n, subject=None):
    rec = Recorder(os.path.join(directory, "c.jsonl"))
    out = []
    for i in range(n):
        out.append(rec.append(build("tool_call", "security", tool="t%d" % i,
                                     subject=subject)))
    return out


class CheckpointTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_checkpoint_shape(self):
        recs = _chain(self.dir, 2, subject="acme-corp")
        cp = checkpoint(recs)
        self.assertEqual(cp["count"], 2)
        self.assertEqual(cp["subject"], "acme-corp")
        self.assertEqual(cp["head"], head(recs))
        self.assertEqual(cp["chain_root"], chain_root(recs))

    def test_chain_root_is_first_record_hash(self):
        recs = _chain(self.dir, 3)
        self.assertEqual(chain_root(recs), recs[0]["integrity"]["hash"])

    def test_empty_chain(self):
        self.assertIsNone(chain_root([]))
        self.assertEqual(head([]), "0" * 64)


class CompletenessTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_unwitnessed_is_none(self):
        recs = _chain(self.dir, 2, subject="acme-corp")
        self.assertIsNone(verify_completeness(recs, [])["ok"])

    def test_complete(self):
        recs = _chain(self.dir, 2, subject="acme-corp")
        cps = [checkpoint(recs)]
        self.assertTrue(verify_completeness(recs, cps)["ok"])

    def test_truncated_below_witnessed(self):
        recs = _chain(self.dir, 3, subject="acme-corp")
        cps = [checkpoint(recs)]  # witnesses count=3
        res = verify_completeness(recs[:2], cps)
        self.assertFalse(res["ok"])
        self.assertIn("truncated", res["why"])

    def test_altered_head_at_witnessed_point(self):
        recs = _chain(self.dir, 2, subject="acme-corp")
        cps = [checkpoint(recs)]
        # rebuild a *different* chain of the same length for the same subject
        other = _chain(self.dir + "_b" if False else tempfile.mkdtemp(), 2,
                       subject="acme-corp")
        res = verify_completeness(other, cps)
        self.assertFalse(res["ok"])

    def test_subject_keys_matching_not_chain_root(self):
        # A checkpoint for a *different* subject must not be treated as a witness
        # of this chain, even at the same count.
        recs = _chain(self.dir, 2, subject="acme-corp")
        foreign = checkpoint(recs)
        foreign["subject"] = "initech"
        self.assertIsNone(verify_completeness(recs, [foreign])["ok"])

    def test_subjectless_falls_back_to_chain_root(self):
        recs = _chain(self.dir, 2)  # no subject
        cps = [checkpoint(recs)]
        self.assertTrue(verify_completeness(recs, cps)["ok"])


class NotaryTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.wit = os.path.join(self.dir, "nested", "witness.jsonl")

    def test_witness_persists_and_filters_by_subject(self):
        notary = Notary(self.wit)
        acme = _chain(tempfile.mkdtemp(), 1, subject="acme-corp")
        initech = _chain(tempfile.mkdtemp(), 1, subject="initech")
        notary.witness(acme)
        notary.witness(initech)
        self.assertEqual(len(notary.checkpoints()), 2)
        self.assertEqual(len(notary.checkpoints(subject="acme-corp")), 1)
        self.assertEqual(notary.checkpoints(subject="acme-corp")[0]["subject"], "acme-corp")

    def test_record_checkpoint_creates_parent_dir(self):
        notary = Notary(self.wit)
        notary.record_checkpoint({"subject": "x", "count": 1, "head": "a" * 64,
                                  "chain_root": "b" * 64, "ts": "now"})
        self.assertTrue(os.path.exists(self.wit))


if __name__ == "__main__":
    unittest.main()
