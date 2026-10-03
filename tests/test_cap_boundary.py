"""The masking cap never cuts inside a pattern match.

Text past ``redact.REDACT_MAX`` characters is withheld. The cut is chosen
outside every pattern match in the text around it, so a grouped number (a
card, an SSN, an IBAN, a phone number) is never split into a stored prefix
plus a finding that keeps its last digits. Each pattern shape is placed so the
65,536-character boundary falls at every position inside it.
"""

import re
import unittest

from halo_record import redact
from halo_record.record import build

FILL = "zz "  # no character any sample below contains

SAMPLES = {
    "credit_card spaced": "4539 1488 0343 6467",
    "credit_card dotted": "4539.1488.0343.6467",
    "credit_card hyphen": "4539-1488-0343-6467",
    "credit_card nbsp": "4539 1488 0343 6467",
    "credit_card thin": "4539 1488 0343 6467",
    "credit_card compact": "4539148803436467",
    "ssn spaced": "123 45 6789",
    "ssn hyphen": "123-45-6789",
    "iban spaced": "DE89 3704 0044 0532 0130 00",
    "iban dotted": "DE89.3704.0044.0532.0130.00",
    "iban compact": "DE89370400440532013000",
    "phone spaced": "+1 555 123 4567",
    "phone parens": "(555) 123-4567",
    "phone dotted": "555.123.4567",
    "ip_internal": "10.12.34.56",
    "email": "jane.doe@example.com",
    "api_key": "sk-ABCDEFGHIJKLMNOPQRSTUVWX0123",
    "aws key id": "AKIAIOSFODNN7EXAMPLE",
    "gcp_api_key": "AIzaSyA1234567890abcdefghijklmnopqrstuv",
    "aws_secret_key": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "webhook_url": "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX",
    "stripe_key": "sk_live_" + "4eC39HqLyjWDarjtT1" + "dp7dc",
    "github_token": "ghp_" + "A" * 18 + "b" * 18,
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0123456789\n"
                   "abcdefghijklmnop\n-----END RSA PRIVATE KEY-----",
    "db_conn": "postgres://admin:hunter2@db.internal:5432/app",
    "password": "password: hunter2pass",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
    "bot_token": "123456789:AAH" + "x" * 32,
    "bearer_token": "Bearer abcdefghijklmnopqrstuvwxy0123",
}

_MARK = re.compile(r" \[… \d+ more characters withheld\]$")


def _kept(out):
    m = _MARK.search(out)
    return out[:m.start()] if m else out


class CapBoundaryTest(unittest.TestCase):
    def _assert_no_fragment(self, label, sample, fn, ks=None):
        for k in (ks or range(1, len(sample))):
            # the boundary falls after the k-th character of the sample
            head = redact.REDACT_MAX - k
            fill = (FILL * (head // len(FILL) + 1))[:head - 1] + " "
            text = fill + sample + " tail " + "y" * 200
            out = fn(text)
            kept = _kept(out)
            self.assertNotEqual(kept, out, (label, k))
            stray = kept.replace("z", "").replace(" ", "")
            self.assertEqual(stray, "", "%s: cut at %d stored %r" % (label, k, kept[-40:]))

    def test_no_pattern_is_split_by_the_cap(self):
        for label, sample in SAMPLES.items():
            self.assertTrue(redact.scan(sample, entropy=False) or redact.scan(sample),
                            "sample %s is not detected on its own" % label)
            # every boundary position through the cut itself ...
            self._assert_no_fragment(label, sample, lambda t: "".join(redact._capped(t)))
            # ... and a few through each masking entry point
            ks = sorted({1, len(sample) // 2, len(sample) - 1})
            for fn in (redact.redact_text, redact.mask_known_secrets, redact.mask_secrets_only):
                self._assert_no_fragment(label, sample, fn, ks)

    def test_the_cold_pass_repro_stores_no_card_prefix(self):
        detail = "x" * (65536 - 16) + " 4539 1488 0343 6467 tail"
        rec = build("tool_call", "security", tool="t",
                    outcome={"status": "ok", "summary": detail})
        stored = rec["outcome"]["summary"]
        self.assertNotIn("4539", stored)
        for label, sample in (("ssn", "123 45 6789"), ("iban", "DE89 3704 0044 0532 0130 00"),
                              ("dotted", "4539.1488.0343.6467")):
            text = "x" * (65536 - 6) + " " + sample + " tail"
            out = redact.redact_text(text)
            self.assertNotIn(sample[:4], out, label)

    def test_repeated_rows_keep_no_partial_card(self):
        text = "row,4539 1488 0343 6467\n" * 4000
        out = redact.redact_text(text)
        kept = _kept(out)
        for line in kept.split("\n"):
            self.assertIn(line, ("row,****6467", ""), repr(line))

    def test_short_text_is_unchanged(self):
        self.assertEqual(redact._capped("abc 4539 1488"), ("abc 4539 1488", ""))

    def test_invisible_characters_inside_a_match_do_not_shift_the_cut(self):
        sample = "4539 14\u200b88 0343 6467"
        for k in range(1, len(sample)):
            head = redact.REDACT_MAX - k
            fill = (FILL * (head // len(FILL) + 1))[:head - 1] + " "
            kept = _kept(redact.redact_text(fill + sample + " tail"))
            self.assertEqual(kept.replace("z", "").replace(" ", ""), "", k)


if __name__ == "__main__":
    unittest.main()
