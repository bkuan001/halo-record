"""The hosted Halo witness over HTTP — completeness checked against a
store the vendor does not control. Boots a real server on an ephemeral port."""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from halo_record.anchor import Notary, verify_completeness
from halo_record.record import Recorder, build
from halo_record.witness import _Handler, anchor_remote, fetch_checkpoints

KEY = "testkey-123"


def _chain(directory, n, subject="acme-corp"):
    rec = Recorder(os.path.join(directory, "c.jsonl"))
    return [rec.append(build("tool_call", "security", tool="t%d" % i, subject=subject))
            for i in range(n)]


class WitnessHTTPTest(unittest.TestCase):
    def setUp(self):
        self.store = tempfile.mkdtemp()
        self.notary = Notary(os.path.join(self.store, "witness.jsonl"))
        handler = type("_BoundWitness", (_Handler,),
                       {"config": {"notary": self.notary, "keys": [KEY]}})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.url = "http://127.0.0.1:%d" % self.port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _get(self, path):
        with urllib.request.urlopen(self.url + path, timeout=5) as r:
            return r.status, json.loads(r.read().decode())

    def _post(self, body, key=KEY):
        req = urllib.request.Request(
            self.url + "/anchor", data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + key})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())

    def test_healthz(self):
        with urllib.request.urlopen(self.url + "/healthz", timeout=5) as r:
            self.assertEqual(r.read().decode(), "ok")

    def test_anchor_and_fetch_roundtrip(self):
        recs = _chain(tempfile.mkdtemp(), 2)
        receipt = anchor_remote(self.url, KEY, recs)
        self.assertEqual(receipt["count"], 2)
        self.assertEqual(receipt["head"], recs[-1]["integrity"]["hash"])
        self.assertIn("ts", receipt)  # server-stamped
        cps = fetch_checkpoints(self.url, subject="acme-corp")
        self.assertEqual(len(cps), 1)
        self.assertTrue(verify_completeness(recs, cps)["ok"])

    def test_only_attesting_fields_persisted(self):
        recs = _chain(tempfile.mkdtemp(), 1)
        anchor_remote(self.url, KEY, recs)
        cp = fetch_checkpoints(self.url, subject="acme-corp")[0]
        self.assertEqual(set(cp), {"chain_root", "subject", "count", "head", "ts"})

    def test_dropped_record_is_incomplete_against_remote(self):
        recs = _chain(tempfile.mkdtemp(), 3)
        anchor_remote(self.url, KEY, recs)  # witnesses count=3
        cps = fetch_checkpoints(self.url, subject="acme-corp")
        # vendor presents a truncated chain — fails against the remote witness
        res = verify_completeness(recs[:2], cps)
        self.assertFalse(res["ok"])

    def test_subject_isolation(self):
        anchor_remote(self.url, KEY, _chain(tempfile.mkdtemp(), 1, subject="acme-corp"))
        anchor_remote(self.url, KEY, _chain(tempfile.mkdtemp(), 1, subject="initech"))
        self.assertEqual(len(fetch_checkpoints(self.url, subject="acme-corp")), 1)
        self.assertEqual(len(fetch_checkpoints(self.url, subject="initech")), 1)
        self.assertEqual(len(fetch_checkpoints(self.url)), 2)

    def test_bad_key_401(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post({"subject": "p", "count": 1, "head": "a" * 64}, key="wrong")
        self.assertEqual(cm.exception.code, 401)

    def test_bad_payload_400(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post({"subject": "p", "count": 0, "head": "a" * 64})
        self.assertEqual(cm.exception.code, 400)

    def test_non_hex_head_400(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post({"subject": "p", "count": 1, "head": "nothex"})
        self.assertEqual(cm.exception.code, 400)

    def test_oversize_413(self):
        big = {"subject": "p", "count": 1, "head": "a" * 64, "pad": "x" * 9000}
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post(big)
        self.assertEqual(cm.exception.code, 413)

    def test_checkpoints_cors_open(self):
        with urllib.request.urlopen(self.url + "/v1/checkpoints", timeout=5) as r:
            self.assertEqual(r.headers.get("Access-Control-Allow-Origin"), "*")

    def test_unknown_route_404(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get("/nope")
        self.assertEqual(cm.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
