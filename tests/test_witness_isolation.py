"""A shared witness keeps vendors apart: no vendor can write, squat, or list
another vendor's subjects, and a report only ever embeds its own checkpoints."""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from halo_record.anchor import Notary, chain_root
from halo_record.record import Recorder, build
from halo_record.report import render, write_report
from halo_record.witness import _Handler, parse_key_spec


class SharedWitnessTest(unittest.TestCase):
    def _serve(self, specs, notary=None):
        store = tempfile.mkdtemp()
        notary = notary or Notary(os.path.join(store, "witness.jsonl"))
        handler = type("_W", (_Handler,), {"config": {"notary": notary, "keys": parse_key_spec(specs)}})
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return "http://127.0.0.1:%d" % httpd.server_address[1], notary

    def _post(self, url, key, subject):
        req = urllib.request.Request(
            url + "/anchor", method="POST",
            data=json.dumps({"subject": subject, "count": 1, "head": "a" * 64}).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def _get(self, url, query=""):
        try:
            with urllib.request.urlopen(url + "/v1/checkpoints" + query, timeout=5) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, None

    def test_single_unscoped_key_still_works(self):
        url, _ = self._serve(["only-key"])
        self.assertEqual(self._post(url, "only-key", "acme"), 201)

    def test_unscoped_keys_cannot_write_on_a_shared_witness(self):
        url, _ = self._serve(["keyA", "keyB"])
        self.assertEqual(self._post(url, "keyA", "acme"), 403)
        self.assertEqual(self._post(url, "keyB", "acme"), 403)

    def test_no_squatting_across_scopes(self):
        url, _ = self._serve(["keyA=vendor-a-*", "keyB=vendor-b-*"])
        self.assertEqual(self._post(url, "keyB", "vendor-a-acme"), 403)
        self.assertEqual(self._post(url, "keyA", "vendor-a-acme"), 201)

    def test_checkpoint_list_requires_a_filter(self):
        url, notary = self._serve(["only-key"])
        self._post(url, "only-key", "bigbank-prod")
        status, _ = self._get(url)
        self.assertEqual(status, 400)
        status, body = self._get(url, "?subject=bigbank-prod")
        self.assertEqual((status, body["count"]), (200, 1))


class ReportEmbedsOnlyItsOwnCheckpointsTest(unittest.TestCase):
    def test_subjectless_report_does_not_embed_other_subjects(self):
        d = tempfile.mkdtemp()
        wlog = os.path.join(d, "witness.jsonl")
        notary = Notary(wlog)
        notary.record_checkpoint({"subject": "globex-secret-customer", "count": 3,
                                  "head": "b" * 64, "chain_root": "c" * 64, "ts": "x"})
        log = os.path.join(d, "c.jsonl")
        rec = Recorder(log)
        rec.append(build("tool_call", "security", tool="t"))
        html, _ = write_report(log, os.path.join(d, "r.html"), witness_log=wlog)
        self.assertNotIn("globex-secret-customer", html)

    def test_subjectless_live_lookup_uses_the_chain_root(self):
        d = tempfile.mkdtemp()
        rec = Recorder(os.path.join(d, "c.jsonl"))
        records = [rec.append(build("tool_call", "security", tool="t"))]
        html = render(records, witness_url="https://witness.example")
        self.assertIn('"chainRoot":"%s"' % chain_root(records), html)


class SubjectIdentityTest(unittest.TestCase):
    def test_invisible_characters_in_subject_id_are_flagged(self):
        d = tempfile.mkdtemp()
        rec = Recorder(os.path.join(d, "c.jsonl"))
        records = [rec.append(build("tool_call", "security", tool="t",
                                    subject={"id": "acme​", "name": "Acme Corp"}))]
        html = render(records)
        self.assertIn("invisible", html)
        self.assertIn("acme\\u200b", html)


if __name__ == "__main__":
    unittest.main()


class BuyerPinsTheSubjectTest(unittest.TestCase):
    def _witnessed_then_rekeyed(self):
        from halo_record.anchor import checkpoint
        from halo_record.canon import GENESIS_PREV, compute_hash
        d = tempfile.mkdtemp()
        rec = Recorder(os.path.join(d, "c.jsonl"))
        recs = [rec.append(build("tool_call", "security", tool="t%d" % i, subject="acme-corp"))
                for i in range(4)]
        cps = [checkpoint(recs)]
        kept = [r for i, r in enumerate(recs) if i != 2]
        prev = GENESIS_PREV
        for r in kept:  # drop a record, re-key the subject, re-seal
            r["subject"] = {"id": "acme-corp "}
            r["integrity"]["prev_hash"] = prev
            r["integrity"]["hash"] = compute_hash(r, prev)
            prev = r["integrity"]["hash"]
        return kept, cps

    def test_pinned_subject_mismatch_is_a_failure(self):
        from halo_record.anchor import verify_completeness
        kept, cps = self._witnessed_then_rekeyed()
        result = verify_completeness(kept, cps, expected_subject="acme-corp")
        self.assertIs(result["ok"], False)

    def test_witness_rejects_edge_and_double_spaces(self):
        from halo_record.witness import _SUBJECT_RE
        for bad in ("acme-corp ", " acme", "acme  corp", "acme\n", "acmе"):
            self.assertIsNone(_SUBJECT_RE.fullmatch(bad), repr(bad))
        self.assertIsNotNone(_SUBJECT_RE.fullmatch("acme corp"))

    def test_report_refuses_a_chain_whose_subject_is_not_the_pinned_one(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        Recorder(log).append(build("tool_call", "security", tool="t", subject="acrne-corp"))
        with self.assertRaises(ValueError):
            write_report(log, os.path.join(d, "r.html"), expected_subject="acme-corp")
