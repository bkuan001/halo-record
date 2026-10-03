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


class BlankAndIgnorableCharactersTest(unittest.TestCase):
    """Characters that render blank without being format characters: the Khmer
    inherent vowels, the braille blank, the musical null notehead, and every
    Default_Ignorable_Code_Point of Unicode 15.1."""

    # DerivedCoreProperties.txt (Unicode 15.1), Default_Ignorable_Code_Point
    DEFAULT_IGNORABLE = [
        (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
        (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
        (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
        (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
        (0xE0000, 0xE0FFF),
    ]

    def test_blank_characters_are_dropped_inside_a_key(self):
        for ch in ("\u17b4", "\u17b5", "\u2800", "\U0001d159"):
            text = _spliced(ch)
            self.assertIn("stripe_key", [f["type"] for f in redact.scan(text)], "U+%04X" % ord(ch))
            self.assertNotIn(KEY[8:], redact.redact_text(text), "U+%04X" % ord(ch))

    def test_every_default_ignorable_code_point_is_covered(self):
        missing = ["U+%04X" % c for a, b in self.DEFAULT_IGNORABLE for c in range(a, b + 1)
                   if chr(c) not in redact.INVISIBLE_CHARS]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()


class IdentifiersKeepTheirTextTest(unittest.TestCase):
    """Invisible characters are dropped only to find secrets. An identifier
    (agent id, tool name, session id) with nothing to mask is stored exactly
    as given; one that hides a secret is still masked."""

    def test_identifiers_without_a_secret_are_stored_as_given(self):
        zw = "​"
        rec = build("tool_call", "security", tool="look" + zw + "up",
                    session_id="sess" + zw + "1", parent_id="p" + zw + "1",
                    agent={"id": "bot" + zw + "1", "name": "support" + zw + "bot",
                           "version": "1" + zw + ".2"})
        self.assertEqual(rec["action"]["tool"], "look" + zw + "up")
        self.assertEqual(rec["session_id"], "sess" + zw + "1")
        self.assertEqual(rec["parent_id"], "p" + zw + "1")
        self.assertEqual(rec["agent"]["id"], "bot" + zw + "1")
        self.assertEqual(rec["agent"]["name"], "support" + zw + "bot")
        self.assertEqual(rec["agent"]["version"], "1" + zw + ".2")

    def test_an_identifier_hiding_a_secret_is_still_masked(self):
        text = _spliced("​")
        rec = build("tool_call", "security", tool=text, session_id=text,
                    agent={"id": text, "name": "n"})
        for value in (rec["action"]["tool"], rec["session_id"], rec["agent"]["id"]):
            self.assertNotIn(KEY[8:], value)
            self.assertNotIn(KEY[14:], value)


ZW = "​"
PAN = "4539 1488 0343 6467"


class BesideASeparatorTest(unittest.TestCase):
    """An invisible character next to a group separator (a space, NBSP, tab,
    hyphen or dot) inside a grouped number or a PEM header is dropped for
    matching, so the number is masked whole and reported."""

    CASES = [
        ("4539" + ZW + " 1488" + ZW + " 0343" + ZW + " 6467", "credit_card"),
        ("4539 " + ZW + "1488 " + ZW + "0343 " + ZW + "6467", "credit_card"),
        ("cc 4539 " + ZW + "1488 " + ZW + "0343 " + ZW + "6467", "credit_card"),
        ("4539­ 1488 0343 6467", "credit_card"),
        ("4539" + ZW + " 1488 0343 6467", "credit_card"),
        ("4539⁠-1488-0343-6467", "credit_card"),
        ("123" + ZW + " 45" + ZW + " 6789", "ssn"),
        ("ssn 123 ⁠" + "45 ﻿6789", "ssn"),
        ("DE89" + ZW + " 3704 0044 0532 0130 00", "iban"),
        ("DE89 3704‍ 0044 ⁠" + "0532 0130 00", "iban"),
        ("call (555)" + ZW + " 123-4567", "phone"),
        ("call +1" + ZW + " 555 123 4567", "phone"),
    ]

    def test_grouped_numbers_are_found_and_masked(self):
        for text, ftype in self.CASES:
            with self.subTest(text=text):
                self.assertIn(ftype, [f["type"] for f in redact.scan(text)])
                out = redact.redact_text(text)
                self.assertNotIn("1488", out)
                self.assertNotIn("0532", out)
                self.assertNotIn("45" + ZW, out)
                rec = build("tool_call", "security", tool="t",
                            outcome={"status": "ok", "summary": "s", "detail": text})
                self.assertIn(ftype, [f["type"] for f in rec["findings"]])
                self.assertNotEqual(rec["outcome"]["detail"], text)

    def test_pem_header_with_an_invisible_character_is_masked(self):
        pem = ("-----BEGIN" + ZW + " RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1b2c3d4e5f6g7h8i9j0\n"
               "-----END RSA PRIVATE KEY-----")
        self.assertIn("private_key", [f["type"] for f in redact.scan(pem)])
        self.assertNotIn("MIIEowIBAAKCAQEA", redact.mask_known_secrets(pem))
        pem2 = pem.replace("RSA" + " PRIVATE", "RSA ⁠PRIVATE")
        self.assertNotIn("MIIEowIBAAKCAQEA", redact.mask_known_secrets(pem2))

    def test_prose_without_a_secret_is_stored_as_given(self):
        for text in ("hello" + ZW + " world", "a ‎ b", "id 12" + ZW + " 34",
                     "family \U0001F468‍\U0001F469 trip", "ok" + ZW + " -" + ZW + " done"):
            with self.subTest(text=text):
                self.assertEqual(redact.redact_text(text, entropy=False), text)
                self.assertEqual(redact.mask_known_secrets(text), text)

    def test_the_invisible_character_cannot_carry_the_number_through_unmasked(self):
        # The stored text keeps no run of the number's digits, however the
        # invisible characters were placed.
        for sep in (" ", " ", "-", "."):
            for zw in (ZW, "­", "⁠", "﻿", "\U000e0041"):
                for left in (True, False):
                    groups = ["4539", "1488", "0343", "6467"]
                    joint = (zw + sep) if left else (sep + zw)
                    text = "pay " + joint.join(groups) + " now"
                    with self.subTest(sep=sep, zw=hex(ord(zw)), left=left):
                        out = redact.redact_text(text)
                        self.assertNotIn("1488", out)
                        self.assertIn("credit_card", [f["type"] for f in redact.scan(text)])
