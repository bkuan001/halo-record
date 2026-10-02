"""Invisible format characters spliced into a token do not hide it from the scanner.

Every Unicode format character (category Cf), plus the invisible combining and
variation marks and Hangul fillers, is dropped when it sits between token
characters, so the token is scanned and masked as if it were not there.
"""

import sys
import unicodedata
import unittest

from halo_record import redact
from halo_record.record import build

KEY = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0"
LISTED = ["‎", "‏", "͏", "⁡", "⁢", "⁣", "⁤", "᠎",
          "﻿", "­", "⁠", "​", "‌", "‍", "‮", "⁦",
          "\U000e0041", "️", "ㅤ"]


def _spliced(ch):
    return KEY[:10] + ch + KEY[10:14] + ch + ch + KEY[14:]


class InvisibleCharactersTest(unittest.TestCase):
    def test_each_listed_character_is_dropped_inside_a_key(self):
        for ch in LISTED:
            text = _spliced(ch)
            types = [f["type"] for f in redact.scan(text)]
            self.assertIn("stripe_key", types, "U+%04X" % ord(ch))
            self.assertNotIn(KEY[8:], redact.redact_text(text), "U+%04X" % ord(ch))
            rec = build("tool_call", "security", tool="t", tool_input={"q": text},
                        outcome={"status": "error", "summary": text})
            self.assertIn("stripe_key", [f["type"] for f in rec["findings"]], "U+%04X" % ord(ch))
            self.assertNotIn(KEY[8:], rec["action"]["input"]["summary"])
            self.assertNotIn(KEY[8:], rec["outcome"]["summary"])

    def test_every_format_character_of_this_python_is_covered(self):
        missing = [c for c in range(sys.maxunicode + 1)
                   if unicodedata.category(chr(c)) == "Cf" and chr(c) not in redact.INVISIBLE_CHARS]
        self.assertEqual(missing, [])

    def test_outside_a_token_the_characters_are_kept(self):
        family = "\U0001F468‍\U0001F469"
        self.assertEqual(redact.normalize_invisible(family), family)
        self.assertEqual(redact.normalize_invisible("a ‎ b"), "a ‎ b")


if __name__ == "__main__":
    unittest.main()
