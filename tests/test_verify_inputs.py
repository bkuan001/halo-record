"""Verification reads what it is given and reports, never raises: a missing
path or a directory, integers too long for the parser, CR whitespace and CRLF
line ends, a leading byte-order mark, and backdated timestamps."""

import contextlib
import io
import os
import tempfile
import unittest

from halo_record.cli import main
from halo_record.record import Recorder, build
from halo_record.verify import verify_log

HERE = os.path.join(os.path.dirname(__file__), "fixtures", "differential")


def _verify(path):
    out = []
    ok = verify_log(path, out=out.append)
    return ok, "\n".join(out)


class UnreadablePathTest(unittest.TestCase):
    def test_missing_path_and_directory_fail_cleanly(self):
        d = tempfile.mkdtemp()
        for p in (os.path.join(d, "missing.jsonl"), d):
            ok, text = _verify(p)
            self.assertFalse(ok)
            self.assertIn("FAIL: cannot read", text)

    def test_cli_exits_nonzero_without_traceback(self):
        d = tempfile.mkdtemp()
        for p in (os.path.join(d, "missing.jsonl"), d):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["verify", p])
            self.assertEqual(code, 1)
            self.assertNotIn("Traceback", out.getvalue() + err.getvalue())


class ParserLimitTest(unittest.TestCase):
    def test_integer_with_thousands_of_digits_is_reported(self):
        ok, text = _verify(os.path.join(HERE, "long_int_digits.jsonl"))
        self.assertFalse(ok)
        self.assertIn("record 1", text)


class LineEndingTest(unittest.TestCase):
    def _valid_lines(self):
        with open(os.path.join(HERE, "valid.jsonl"), "rb") as fh:
            return [ln for ln in fh.read().split(b"\n") if ln.strip()]

    def _write(self, body):
        path = os.path.join(tempfile.mkdtemp(), "c.jsonl")
        with open(path, "wb") as fh:
            fh.write(body)
        return path

    def test_cr_as_json_whitespace_verifies(self):
        lines = self._valid_lines()
        lines[1] = lines[1].replace(b',"ts"', b',\r"ts"', 1)
        ok, text = _verify(self._write(b"\n".join(lines) + b"\n"))
        self.assertTrue(ok, text)

    def test_crlf_line_ends_verify(self):
        ok, text = _verify(os.path.join(HERE, "crlf.jsonl"))
        self.assertTrue(ok, text)

    def test_read_log_lines_matches_verify(self):
        from halo_record.verify import read_log_lines
        lines = self._valid_lines()
        lines[1] = lines[1].replace(b',"ts"', b',\r"ts"', 1)
        path = self._write(b"\xef\xbb\xbf" + b"\r\n".join(lines) + b"\r\n")
        self.assertEqual(len(read_log_lines(path)), len(lines))

    def test_leading_byte_order_mark_is_skipped(self):
        with open(os.path.join(HERE, "valid.jsonl"), "rb") as fh:
            body = fh.read()
        d = tempfile.mkdtemp()
        path = os.path.join(d, "bom.jsonl")
        with open(path, "wb") as fh:
            fh.write(b"\xef\xbb\xbf" + body)
        ok, text = _verify(path)
        self.assertTrue(ok, text)


class TimestampOrderTest(unittest.TestCase):
    def _chain(self, stamps):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "c.jsonl")
        rec = Recorder(path)
        for i, ts in enumerate(stamps):
            rec.append(build("tool_call", "security", tool="t%d" % i, ts=ts))
        return path

    def test_backdated_record_is_warned_not_failed(self):
        path = self._chain(["2026-06-02T00:00:00Z", "2026-06-01T00:00:00Z",
                            "2026-06-03T00:00:00Z"])
        ok, text = _verify(path)
        self.assertTrue(ok)
        self.assertIn("record 2: warning: ts 2026-06-01T00:00:00Z is earlier than", text)
        self.assertIn("1 record(s) carry a ts earlier than the record before them", text)

    def test_offsets_are_compared_as_instants(self):
        # 10:00+02:00 is 08:00Z: earlier than 09:00Z.
        path = self._chain(["2026-06-01T09:00:00Z", "2026-06-01T10:00:00+02:00"])
        ok, text = _verify(path)
        self.assertTrue(ok)
        self.assertIn("record 2: warning", text)
        # 11:00+02:00 is 09:00Z: equal, not earlier; fractional digits compare.
        path = self._chain(["2026-06-01T09:00:00Z", "2026-06-01T11:00:00+02:00",
                            "2026-06-01T09:00:00.000000001Z"])
        ok, text = _verify(path)
        self.assertNotIn("warning", text)

    def test_ordered_chain_has_no_warning(self):
        ok, text = _verify(os.path.join(HERE, "valid.jsonl"))
        self.assertTrue(ok)
        self.assertNotIn("warning", text)


if __name__ == "__main__":
    unittest.main()
