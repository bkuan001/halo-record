"""Redaction + detection: known patterns, the high-entropy catch-all, and the
over-redaction guardrails. Mirrors the TypeScript suite so both recorders flag
and mask the same content the same way."""

import unittest

from halo_record.redact import redact_text, scan, top_severity


class RedactTest(unittest.TestCase):
    def test_basics(self):
        self.assertEqual(redact_text("call me at bob@acme.com"), "call me at b****@acme.com")
        f = scan("Bearer abcdefghijklmnopqrstuvwx and 10.0.0.5")
        types = {x["type"] for x in f}
        self.assertIn("bearer_token", types)
        self.assertIn("ip_internal", types)
        self.assertEqual(top_severity(f), "HIGH")

    def test_expanded_provider_patterns(self):
        # Keys assembled at runtime so no secret-shaped literal sits in source.
        secrets = {
            "gcp_api_key": "AIza" + "x" * 35,
            "stripe_key": "sk_" + "live_" + "x" * 20,
            "github_token": "ghp_" + "a" * 36,
            "jwt": "eyJ" + "x" * 12 + "." + "y" * 12 + "." + "z" * 12,
        }
        text = " ".join(f"{k}={v}" for k, v in secrets.items())
        red = redact_text(text)
        for v in secrets.values():
            self.assertNotIn(v, red)
        found = {x["type"] for x in scan(text)}
        for t in secrets:
            self.assertIn(t, found)

    def test_high_entropy_catch_all(self):
        rand = "Zx9Qw7Lp2Rt5Vn8Mb3Kc6Hd1Gf4Js0Ay"
        self.assertNotIn(rand, redact_text(f"token {rand}"))
        self.assertTrue(any(x["type"] == "high_entropy_secret" for x in scan(f"token {rand}")))

    def test_does_not_over_redact_uuid(self):
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        self.assertEqual(redact_text(f"id {uuid}"), f"id {uuid}")
        self.assertFalse(any(x["type"] == "high_entropy_secret" for x in scan(f"id {uuid}")))

    def test_all_matches_counted_not_collapsed(self):
        # Two distinct emails -> two findings, not one.
        f = [x for x in scan("a@x.com and b@y.com") if x["type"] == "email"]
        self.assertEqual(len(f), 2)


if __name__ == "__main__":
    unittest.main()
