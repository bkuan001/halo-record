"""Credentials in connection strings, credential-named fields, assignment text,
and private-key blocks never reach a sealed record — not in a summary, not in a
finding sample. Secret-shaped values are assembled at runtime so no literal
credential sits in source."""

import json
import os
import tempfile
import unittest

from halo_record import Recorder, record_call
from halo_record.record import build
from halo_record.redact import redact_text, scan

PW = "Hunter" + "2pass" + "word9"           # a password that is not entropy-shaped
STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"


def _sealed(**kw):
    rec = build("tool_call", "security", tool="t", **kw)
    return rec, json.dumps(rec)


class ConnectionStringPasswordTest(unittest.TestCase):
    URLS = [
        "redis://:%s@cache.internal:6379/0" % PW,       # empty user
        "rediss://default:%s@cache.internal:6380" % PW,
        "amqp://app:%s@mq.internal:5672/vhost" % PW,
        "amqps://app:%s@mq.internal:5671" % PW,
        "postgresql://app:%s@db.internal:5432/prod" % PW,
        "postgres://app:%s@db.internal/prod" % PW,
        "mysql://root:%s@db.internal/x" % PW,
        "mongodb+srv://u:%s@cluster.example.net/db" % PW,
    ]

    def test_password_absent_from_input_summary_and_findings(self):
        for url in self.URLS:
            rec, blob = _sealed(tool_input={"dsn": url})
            self.assertNotIn(PW, blob, url)
            self.assertIn("db_conn", [f["type"] for f in rec["findings"]], url)

    def test_password_absent_from_outcome_summary_and_findings(self):
        for url in self.URLS:
            rec, blob = _sealed(outcome={"status": "error", "summary": "connect failed: " + url})
            self.assertNotIn(PW, blob, url)
            self.assertIn("db_conn", [f["type"] for f in rec["findings"]], url)

    def test_long_password_is_masked_in_sample(self):
        long_pw = "q" * 150
        f = [x for x in scan("redis://:%s@h:6379" % long_pw) if x["type"] == "db_conn"]
        self.assertTrue(f)
        self.assertNotIn("q" * 20, f[0]["sample"])

    def test_user_is_kept_password_masked(self):
        self.assertEqual(redact_text("amqp://app:%s@mq/v" % PW), "amqp://app:****@mq/v")
        self.assertEqual(redact_text("redis://:%s@h:1" % PW), "redis://:****@h:1")


class CredentialFieldTest(unittest.TestCase):
    KEYS = ["password", "Password", "db_password", "passwd", "pwd", "passphrase",
            "secret", "client_secret", "api_key", "apiKey", "x-api-key",
            "token", "access_token", "auth_token", "private_key"]

    def test_credential_named_input_fields_are_masked_and_flagged(self):
        for key in self.KEYS:
            rec, blob = _sealed(tool_input={key: PW, "user": "admin"})
            self.assertNotIn(PW, blob, key)
            self.assertIn("admin", rec["action"]["input"]["summary"], key)
            self.assertTrue(rec["findings"], key)

    def test_numeric_password_is_masked(self):
        rec, blob = _sealed(tool_input={"password": 739184265})
        self.assertNotIn("739184265", rec["action"]["input"]["summary"])

    def test_credential_named_data_and_outcome_fields_are_masked(self):
        rec, blob = _sealed(data={"password": PW},
                            outcome={"status": "ok", "api_key": PW})
        self.assertNotIn(PW, blob)

    def test_ordinary_fields_are_untouched(self):
        rec, _ = _sealed(tool_input={"max_tokens": 512, "query": "pass the salt"})
        self.assertIn("512", rec["action"]["input"]["summary"])
        self.assertIn("pass the salt", rec["action"]["input"]["summary"])

    def test_tool_result_with_credential_field(self):
        d = tempfile.mkdtemp()
        rec = Recorder(os.path.join(d, "c.jsonl"))
        with record_call(rec, "lookup", {"a": 1}) as c:
            c.result = {"api_key": PW, "note": "ok"}
        self.assertNotIn(PW, json.dumps(c.record))


class PasswordAssignmentTextTest(unittest.TestCase):
    def test_password_assignment_in_text_is_masked(self):
        for text in ("login failed password=%s for admin" % PW,
                     "password: %s" % PW,
                     '{"password": "%s"}' % PW,
                     "DB_PASSWORD=%s" % PW,
                     "pwd=%s&user=x" % PW):
            out = redact_text(text)
            self.assertNotIn(PW, out, text)
            self.assertIn("password", [f["type"] for f in scan(text)], text)

    def test_password_in_exception_text_is_masked(self):
        d = tempfile.mkdtemp()
        rec = Recorder(os.path.join(d, "e.jsonl"))
        try:
            with record_call(rec, "db.connect", {"a": 1}) as c:
                raise RuntimeError("auth failed password=%s" % PW)
        except RuntimeError:
            pass
        self.assertNotIn(PW, json.dumps(c.record))

    def test_prose_is_untouched(self):
        self.assertEqual(redact_text("reset your password via the portal"),
                         "reset your password via the portal")


class InvisibleCharacterInKeyTest(unittest.TestCase):
    """An invisible character in a field name, or between a password's name and
    its separator, does not stop the value from being masked."""

    KEYS = ["password\u200b", "pass\u200bword", "password\u2060", "PASSWORD\ufeff",
            "\u200bpassword", "pass\U000e0041word", "db_pass\u00adword", "api\u200b_key",
            "to\u200dken", "client_secret\u180e"]

    def test_credential_key_ignores_invisible_characters(self):
        from halo_record.redact import credential_key, credential_value
        for key in self.KEYS:
            self.assertTrue(credential_key(key), ascii(key))
        self.assertTrue(credential_value("pass\u200bword", 739184265))
        self.assertFalse(credential_key("max\u200b_tokens"))

    def test_value_under_such_a_key_is_masked_and_flagged(self):
        for key in self.KEYS:
            rec, blob = _sealed(tool_input={key: PW, "user": "admin"})
            self.assertNotIn(PW, blob, ascii(key))
            self.assertIn("credential_field", [f["type"] for f in rec["findings"]], ascii(key))

    TEXTS = ['"password"\u200b: "%s"', '"password\u200b": "%s"', '{"password\u2060": "%s"}',
             'password\u200b"\u200b:\u200b"\u200b%s"', "password\u200b=%s", "pwd\ufeff = %s",
             "password    =    %s", "password\t\t\t\t\t: %s", "PASSWORD          = %s",
             '{"db_password"\U000e0041\u200b : "%s"}']

    def test_password_text_with_a_gap_before_the_separator_is_masked(self):
        for form in self.TEXTS:
            text = form % PW
            self.assertNotIn(PW, redact_text(text), ascii(text))
            self.assertIn("password", [f["type"] for f in scan(text)], ascii(text))
            rec, blob = _sealed(tool_input={"q": text})
            self.assertNotIn(PW, blob, ascii(text))

    def test_prose_is_still_untouched(self):
        for text in ("reset your password    via the portal", "password\u200b reset"):
            self.assertEqual(redact_text(text), text)


class ZeroWidthSplitTest(unittest.TestCase):
    def test_zero_width_inside_known_key_is_still_masked(self):
        for zw in ("​", "‌", "‍", "⁠", "﻿", "­"):
            k = STRIPE[:15] + zw + STRIPE[15:]
            rec, blob = _sealed(tool_input={"k": k})
            self.assertNotIn(STRIPE[15:], json.dumps(rec["findings"]), repr(zw))
            self.assertNotIn(STRIPE[15:], rec["action"]["input"]["summary"], repr(zw))
            self.assertIn("stripe_key", [f["type"] for f in rec["findings"]], repr(zw))

    def test_emoji_joiner_sequences_survive(self):
        family = "\U0001F468‍\U0001F469‍\U0001F467"
        self.assertEqual(redact_text("hi " + family), "hi " + family)


class PrivateKeyBlockTest(unittest.TestCase):
    BODY = "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI"

    def blocks(self):
        b = self.BODY
        return [
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n%s\n-----END ENCRYPTED PRIVATE KEY-----" % b,
            "-----BEGIN DSA PRIVATE KEY-----\n%s\n-----END DSA PRIVATE KEY-----" % b,
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n%s\n=abcd\n-----END PGP PRIVATE KEY BLOCK-----" % b,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n%s\n%s" % (b, b),            # truncated
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n%s\n%s" % (b, b),  # truncated
        ]

    def test_blocks_are_masked_everywhere(self):
        for block in self.blocks():
            rec, blob = _sealed(
                tool_input={"k": block},
                authority={"note": block},
                agent={"id": "a", "name": block},
                threats=[{"type": "x", "ref": block}],
                verification={"status": "allowed", "verifier": block},
            )
            self.assertNotIn(self.BODY, blob, block[:40])
            self.assertIn("private_key", [f["type"] for f in rec["findings"]], block[:40])

    def test_mask_is_bounded(self):
        import time
        hostile = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" * 20000
        t = time.perf_counter()
        redact_text(hostile)
        self.assertLess(time.perf_counter() - t, 0.5)


if __name__ == "__main__":
    unittest.main()
