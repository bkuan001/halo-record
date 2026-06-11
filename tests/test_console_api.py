"""/api/console — admin-gated live cross-chain feed the management plane consumes."""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from halo_record.record import TenantRecorder, build
from halo_record.serve import _Handler, admin_key, load_secret, token_for


class ConsoleApiTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        tr = TenantRecorder(self.dir)
        for i in range(3):
            tr.append(build("tool_call", "security", tool="t%d" % i, subject="acme-corp"))
        tr.append(build("tool_call", "security", tool="x", subject="initech"))
        self.secret = load_secret(self.dir)
        self.key = admin_key(self.secret)
        handler = type("_BoundConsole", (_Handler,), {"config": {
            "dir": self.dir, "secret": self.secret, "gated": True,
            "verify": False, "otp": None, "witness_url": None, "witness": None}})
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

    def test_requires_admin_key(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get("/api/console")
        self.assertEqual(cm.exception.code, 401)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._get("/api/console?key=wrong")
        self.assertEqual(cm.exception.code, 401)

    def test_returns_live_cross_chain_summary(self):
        status, body = self._get("/api/console?key=" + self.key)
        self.assertEqual(status, 200)
        self.assertEqual(body["source"], "halo-record")
        self.assertEqual(body["totals"]["chains"], 2)
        self.assertEqual(body["totals"]["records"], 4)
        self.assertEqual(body["totals"]["intact"], 2)
        subjects = {c["subject"]: c for c in body["chains"]}
        self.assertIn("acme-corp", subjects)
        self.assertEqual(subjects["acme-corp"]["stats"]["total"], 3)
        self.assertEqual(subjects["acme-corp"]["integrity"], "intact")
        # unwitnessed server → completeness not asserted, never silently "complete"
        self.assertEqual(subjects["acme-corp"]["completeness"], "unwitnessed")

    def test_token_matches_share_link(self):
        _, body = self._get("/api/console?key=" + self.key)
        for c in body["chains"]:
            self.assertEqual(c["token"], token_for(self.secret, c["stem"]))

    def test_tamper_surfaces_as_broken(self):
        path = os.path.join(self.dir, "acme-corp.jsonl")
        with open(path) as fh:
            lines = fh.readlines()
        lines[1] = lines[1].replace("t1", "tampered")
        with open(path, "w") as fh:
            fh.writelines(lines)
        _, body = self._get("/api/console?key=" + self.key)
        acme = next(c for c in body["chains"] if c["subject"] == "acme-corp")
        self.assertEqual(acme["integrity"], "broken")
        self.assertEqual(body["totals"]["intact"], 1)


if __name__ == "__main__":
    unittest.main()
