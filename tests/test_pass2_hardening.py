"""Regression tests for the second adversarial pass: malformed input is refused
cleanly, shared stores tolerate damage, and budgets hold across addresses."""

import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from halo_record.anchor import Notary
from halo_record.record import build
from halo_record.witness import _Handler, parse_key_spec


class WitnessInputTest(unittest.TestCase):
    def setUp(self):
        store = tempfile.mkdtemp()
        self.notary = Notary(os.path.join(store, "witness.jsonl"))
        handler = type("_W", (_Handler,), {"config": {"notary": self.notary,
                                                      "keys": parse_key_spec(["k1"])}})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def _raw(self, request_bytes):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(request_bytes)
        data = s.recv(200)
        s.close()
        return data

    def test_malformed_requests_get_400_not_a_dropped_connection(self):
        body = b"[" * 8000
        cases = [
            b"POST /anchor HTTP/1.0\r\nAuthorization: Bearer \xc3\xa9\r\nContent-Length: 2\r\n\r\n{}",
            b"POST /anchor HTTP/1.0\r\nAuthorization: Bearer k1\r\nContent-Length: abc\r\n\r\n",
            b"POST /anchor HTTP/1.0\r\nAuthorization: Bearer k1\r\nContent-Length: %d\r\n\r\n" % len(body) + body,
        ]
        for req in cases:
            resp = self._raw(req)
            self.assertTrue(resp.startswith(b"HTTP/1.0 4"), resp[:60])

    def test_count_is_bounded(self):
        req = urllib.request.Request(
            "http://127.0.0.1:%d/anchor" % self.port, method="POST",
            data=json.dumps({"subject": "acme", "count": 10 ** 40, "head": "a" * 64}).encode(),
            headers={"Authorization": "Bearer k1", "Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(cm.exception.code, 400)

    def test_one_damaged_line_does_not_break_reads(self):
        self.notary.record_checkpoint({"subject": "acme", "count": 1, "head": "a" * 64,
                                       "chain_root": None, "ts": "x"})
        with open(self.notary.path, "a") as fh:
            fh.write('{"subject": "trunc')
        self.assertEqual(len(self.notary.checkpoints(subject="acme")), 1)


class AccessBudgetTest(unittest.TestCase):
    def test_codes_are_budgeted_per_report_across_addresses(self):
        from halo_record.access import OtpStore
        store = OtpStore()
        issued = [store.issue("chain", "user%d@corp.com" % i) for i in range(200)]
        self.assertIn(None, issued)



class RedactionTimeTest(unittest.TestCase):
    def test_private_key_pattern_is_bounded(self):
        from halo_record.redact import redact_text
        t0 = time.perf_counter()
        redact_text("-----BEGIN PRIVATE KEY-----" * 4000)
        self.assertLess(time.perf_counter() - t0, 1.0)


class LargePrivateKeyTest(unittest.TestCase):
    def test_oversized_private_key_block_is_masked_through_its_footer(self):
        from halo_record.redact import redact_text
        body = ("MIIE" + "A" * 60 + "\n") * 400  # ~26 KB
        out = redact_text("key: -----BEGIN PRIVATE KEY-----\n" + body + "-----END PRIVATE KEY----- tail")
        self.assertNotIn("MIIE", out)
        self.assertIn("tail", out)


class PrivateFileSymlinkTest(unittest.TestCase):
    def test_private_open_does_not_follow_symlinks(self):
        from halo_record._private import open_private
        d = tempfile.mkdtemp()
        target = os.path.join(d, "target")
        open(target, "w").close()
        link = os.path.join(d, "link")
        os.symlink(target, link)
        with self.assertRaises(OSError):
            open_private(link, "w")


class VerifierTypeConfusionTest(unittest.TestCase):
    def test_odd_shapes_fail_cleanly(self):
        from halo_record.verify import verify_log
        good = json.dumps(build("tool_call", "security", tool="t"))
        for bad in ('"just a string"', '{"integrity": "x"}', '{"record_id": ["a"]}',
                    '{"parent_id": {"a": 1}}'):
            with self.subTest(line=bad):
                p = os.path.join(tempfile.mkdtemp(), "c.jsonl")
                with open(p, "w") as fh:
                    fh.write(good + "\n" + bad + "\n")
                self.assertFalse(verify_log(p, out=lambda *_: None))

    def test_invalid_utf8_fails_cleanly(self):
        from halo_record.verify import verify_log
        p = os.path.join(tempfile.mkdtemp(), "c.jsonl")
        with open(p, "wb") as fh:
            fh.write(b'{"a": "\xff\xfe"}\n')
        self.assertFalse(verify_log(p, out=lambda *_: None))


class TraceProfileOwnershipTest(unittest.TestCase):
    def test_uppercase_profile_gets_its_own_log(self):
        import importlib
        trace_mod = importlib.import_module("halo_record.trace")
        self.assertNotEqual(trace_mod._profile_log_name("ACME_A").lower(),
                            trace_mod._profile_log_name("acme_a").lower())


class DrawerLookupTest(unittest.TestCase):
    def test_drawer_does_not_build_selectors_from_record_ids(self):
        from halo_record.report import _PAGINATE_JS
        self.assertNotIn("querySelector('tr[data-rid=\"'", _PAGINATE_JS)


if __name__ == "__main__":
    unittest.main()
