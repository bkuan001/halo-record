"""RFC 3161 timestamping (stdlib request + light verify). No network: the TSA
round-trip is mocked; only the DER encoding and the imprint/time check run live.
"""

import unittest
from unittest import mock

from halo_record import timestamp as ts
from halo_record import anchor


def _fake_token(digest_hex, gen="20260723145959Z"):
    """A minimal TSTInfo-shaped blob: <prefix> messageImprint serialNumber genTime.
    Mirrors what verify() walks after locating the imprint."""
    imprint = ts._message_imprint(bytes.fromhex(digest_hex))
    return (b"\x30\x82\x01\x00cms-prefix" + imprint
            + ts._der_int(4242)            # serialNumber INTEGER
            + ts._tlv(0x18, gen.encode())  # genTime GeneralizedTime
            + b"signature-tail")


class TestTimestamp(unittest.TestCase):
    def test_build_request_is_der_with_imprint(self):
        digest = bytes.fromhex("ab" * 32)
        req = ts.build_request(digest)
        self.assertEqual(req[0], 0x30)                       # SEQUENCE
        self.assertIn(ts._message_imprint(digest), req)      # carries our imprint
        self.assertIn(b"\x01\x01\xff", req)                  # certReq BOOLEAN TRUE

    def test_verify_matches_our_digest_and_reads_time(self):
        digest = "cd" * 32
        res = ts.verify(_fake_token(digest), digest)
        self.assertTrue(res["imprint_ok"])
        self.assertEqual(res["gen_time"], "2026-07-23T14:59:59Z")

    def test_verify_rejects_a_different_digest(self):
        token = _fake_token("cd" * 32)
        res = ts.verify(token, "ef" * 32)          # a token for someone else's chain
        self.assertFalse(res["imprint_ok"])
        self.assertIsNone(res["gen_time"])

    def test_checkpoint_digest_excludes_self_asserted_ts(self):
        cp = {"chain_root": "r", "subject": "s", "count": 2, "head": "h",
              "ts": "2026-01-01T00:00:00Z"}
        cp_backdated = dict(cp, ts="2099-01-01T00:00:00Z", tsa={"noise": 1})
        # the timestamped digest is the chain STATE, not the operator's clock
        self.assertEqual(anchor.checkpoint_digest(cp),
                         anchor.checkpoint_digest(cp_backdated))

    def test_attach_timestamp_binds_the_checkpoint(self):
        from halo_record import Recorder, build
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.jsonl")
            rec = Recorder(path)
            rec.append(build("tool_call", "security", tool="a", subject="acme"))
            from halo_record.report import _load
            cp = anchor.checkpoint(_load(path))

            def fake_request(digest_hex, url=None, **kw):
                self.assertEqual(digest_hex, anchor.checkpoint_digest(cp))  # over the state
                return _fake_token(digest_hex, gen="20260101000000Z")

            with mock.patch.object(ts, "request_token", fake_request):
                out = anchor.attach_timestamp(cp)
            self.assertEqual(out["tsa"]["gen_time"], "2026-01-01T00:00:00Z")
            self.assertEqual(out["tsa"]["digest"], anchor.checkpoint_digest(cp))
            self.assertTrue(out["tsa"]["token_b64"])


if __name__ == "__main__":
    unittest.main()
