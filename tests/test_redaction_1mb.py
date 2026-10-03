"""Every scanner pattern stays fast on 1 MB of hostile text.

Tool output and errors are attacker-influenced (an echoed prompt injection) and
the recorder runs inside the agent, so neither scanning nor masking may stall
on input shaped against a pattern. Masking works on at most
``redact.REDACT_MAX`` characters and withholds the rest; findings still cover
the whole text, scanned in overlapping windows.
"""

import random
import re
import time
import unittest

from halo_record import redact
from halo_record.record import build

N = 1 << 20
LIMIT = 0.5

# One or more hostile shapes per pattern, each repeated to 1 MB.
HOSTILE = {
    "api_key": ["sk-", "AKIA", "xoxb-"],
    "gcp_api_key": ["AIza"],
    "aws_secret_key": ["aws_secret_access_key ", "aws_secret_access_key="],
    "webhook_url": ["https://hooks.slack.com/services/"],
    "stripe_key": ["sk_live_"],
    "github_token": ["ghp_", "github_pat_"],
    "private_key": ["-----BEGIN PRIVATE KEY-----", "-----BEGIN A B C ",
                    "-----BEGIN PRIVATE KEY-----\nA"],
    "db_conn": ["postgres://", "redis://a:"],
    "password": ["password=", "password: "],
    "jwt": ["eyJ", "eyJaaaaaaaaaaa.", "_eyJ", "eyJaaaaaaaaaaaa.bbbbbbbbbbbb."],
    "iban": ["DE89 ", "DE89", "de89.", "DE89 3704 0044 0532 0130 00 "],
    "credit_card": ["4111 ", "4", "4111.", "4111 "],
    "ssn": ["123-45-"],
    "bot_token": ["12345678:"],
    "bearer_token": ["Bearer "],
    "email": ["a.", "a@", "a@b."],
    "ip_internal": ["10.", "192.168."],
    "phone": ["+1 ", "(555) "],
    "high_entropy_secret": ["aB3", "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9 "],
    "invisible": ["​a", "a​", "4\u200b ", " \u200b1", "4539\u200b 1488\u200b 0343\u200b 6467 "],
}


def _mb(unit):
    return (unit * (N // len(unit) + 1))[:N]


def _took(fn):
    """Seconds ``fn`` takes; a slow first run is retried (best of three) so a
    busy machine does not read as a regression."""
    best = None
    for _ in range(3):
        t = time.perf_counter()
        fn()
        took = time.perf_counter() - t
        best = took if best is None else min(best, took)
        if best < LIMIT:
            break
    return best


class EveryPatternIsFastAt1MBTest(unittest.TestCase):
    def test_scan_and_redact(self):
        self.assertEqual(set(HOSTILE) - {"invisible"}, set(redact.FINDING_TYPES) - {
            "credential_field", "high_entropy_path_value"})
        for name, units in HOSTILE.items():
            for unit in units:
                text = _mb(unit)
                with self.subTest(pattern=name, unit=unit):
                    self.assertLess(_took(lambda: redact.scan(text)), LIMIT)
                    self.assertLess(_took(lambda: redact.redact_text(text)), LIMIT)

    def test_build_with_1mb_input_and_outcome(self):
        for name, units in HOSTILE.items():
            for unit in units:
                text = _mb(unit)
                with self.subTest(pattern=name, unit=unit):
                    self.assertLess(_took(lambda: build(
                        "tool_call", "security", tool="t", tool_input={"q": text})), LIMIT)
                    self.assertLess(_took(lambda: build(
                        "tool_call", "security", tool="t",
                        outcome={"status": "error", "summary": text})), LIMIT)

    def test_path_values_are_bounded(self):
        text = "/" + _mb("aB3dE5fG7hJ9kL1mN3pQ5rS7tU9/")
        self.assertLess(_took(lambda: redact.scan_fields({"path": text})), LIMIT)
        self.assertLess(_took(lambda: redact.redact_fields({"path": text})), LIMIT)


KEY = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0"


class WindowedScanTest(unittest.TestCase):
    def test_a_secret_at_the_end_of_1mb_is_found(self):
        text = _mb("lorem ipsum ") + " " + KEY
        self.assertIn("stripe_key", [f["type"] for f in redact.scan(text)])
        rec = build("tool_call", "security", tool="t", tool_input={"q": text},
                    outcome={"status": "ok", "summary": text})
        self.assertIn("stripe_key", [f["type"] for f in rec["findings"]])

    def test_a_secret_across_a_window_edge_is_found_once(self):
        for off in range(-30, 5, 3):
            pos = redact.SCAN_WINDOW + off
            text = "x " * (pos // 2) + ("" if pos % 2 == 0 else "x") + KEY + " " + "y " * 50000
            stripe = [f for f in redact.scan(text) if f["type"] == "stripe_key"]
            self.assertEqual(len(stripe), 1, off)

    def test_long_text_is_masked_up_to_the_cap_and_the_rest_withheld(self):
        text = "word " * (redact.REDACT_MAX // 5 - 2) + KEY + KEY + " tail " * 1000
        out = redact.redact_text(text)
        self.assertNotIn(KEY[8:16], out)
        self.assertLess(len(out), redact.REDACT_MAX + 100)
        self.assertRegex(out, r"\[… \d+ more characters withheld\]$")
        short = "word " * 10
        self.assertEqual(redact.redact_text(short), short)

    def test_cut_without_whitespace_keeps_no_partial_token(self):
        text = "a" * (redact.REDACT_MAX - 10) + "." + KEY * 5
        out = redact.redact_text(text, entropy=False)
        self.assertNotIn("sk_live", out)
        blob = "Q" * (redact.REDACT_MAX * 2)
        self.assertNotIn("Q", redact.redact_text(blob, entropy=False))


class JwtShapeTest(unittest.TestCase):
    JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"

    def test_jwts_in_context_are_still_found(self):
        for text in (self.JWT, "token=" + self.JWT, "Authorization: " + self.JWT,
                     '{"t":"%s"}' % self.JWT, "a " + self.JWT + " b", "x." + self.JWT):
            self.assertIn("jwt", [f["type"] for f in redact.scan(text)], text)
            self.assertNotIn(self.JWT[20:], redact.redact_text(text, entropy=False), text)


def _old_iban_prefix(match_text):
    t = str(match_text)
    if redact._iban_ok(t):
        return t
    for end in range(len(t) - 1, 0, -1):
        cand = t[:end].rstrip(" .-\t ")
        if len(redact._IBAN_SEP.sub('', cand)) < 15:
            break
        if redact._iban_ok(cand):
            return cand
    return None


class IbanPrefixTest(unittest.TestCase):
    def test_same_answer_as_trying_every_prefix(self):
        rnd = random.Random(7)
        cases = ["DE89 3704 0044 0532 0130 00", "DE89370400440532013000EUR",
                 "GB82 WEST 1234 5698 7654 32 00 EUR", "DE89 DE89 DE89 DE89 DE89 DE89"]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .-"
        for _ in range(3000):
            body = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(10, 40)))
            cases.append(rnd.choice(["DE", "GB", "FR", "NL"]) + "%02d" % rnd.randint(0, 99) + body)
        for c in cases:
            self.assertEqual(redact._iban_prefix(c), _old_iban_prefix(c), c)


def _old_canon_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\ufffd")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


class CanonStringTest(unittest.TestCase):
    def test_same_bytes_as_escaping_each_character(self):
        from halo_record.canon import _canon_string
        rnd = random.Random(3)
        pool = [chr(c) for c in range(0, 0x80)] + ["\ud800", "\udfff", "\ud83d", "\u2028",
                                                   "\u00e9", "\U0001F600", "\x7f", "\ufffd"]
        for _ in range(2000):
            s = "".join(rnd.choice(pool) for _ in range(rnd.randint(0, 40)))
            self.assertEqual(_canon_string(s), _old_canon_string(s), repr(s))

    def test_hashing_1mb_is_fast(self):
        from halo_record.canon import input_hash
        text = _mb('a"\\\n\x01')
        self.assertLess(_took(lambda: input_hash({"q": text})), LIMIT)


if __name__ == "__main__":
    unittest.main()


def _best(fn, runs=3):
    """Fastest of ``runs`` timings of ``fn``, in seconds."""
    out = None
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        took = time.perf_counter() - t
        out = took if out is None else min(out, took)
    return out


class AdjacentShortMatchesAtTheCapTest(unittest.TestCase):
    """Short matches packed edge to edge past the cap (no whitespace) keep the
    cut search linear: each long field costs about as much as scanning it."""

    def test_redact_text_of_adjacent_short_matches_is_fast(self):
        for unit in ("%@b.cd", "a.b@c.de", "(415).555.0132"):
            text = unit * (1_020_000 // len(unit))
            with self.subTest(unit=unit):
                self.assertLess(_best(lambda: redact.redact_text(text)), 0.1)

    def test_build_with_many_long_fields_is_fast(self):
        field = ("%@b.cd" * 12000)[:70000]
        outcome = {"status": "ok", "summary": "s"}
        for i in range(20):
            outcome["f%d" % i] = field
        took = _best(lambda: build("tool_call", "security", tool="t", outcome=outcome))
        self.assertLess(took, 1.5)
