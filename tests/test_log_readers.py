"""Every reader of a chain file splits it the way ``halo verify`` does: on "\\n"
only (a CR is JSON whitespace), with a leading byte-order mark skipped. A log
that verifies must load to the same records in report, export, policy, and the
witness's checkpoint log."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from halo_record import anchor, export, policy, report
from halo_record.verify import read_log_lines, verify_log

HERE = os.path.join(os.path.dirname(__file__), "fixtures", "differential")
FIXTURES = ("cr_whitespace.jsonl", "bom.jsonl", "crlf.jsonl")


def _expected(path):
    return [json.loads(ln) for ln in read_log_lines(path)]


class ReadersAgreeWithVerifyTest(unittest.TestCase):
    def test_fixtures_verify(self):
        for name in FIXTURES:
            with self.subTest(fixture=name):
                self.assertTrue(verify_log(os.path.join(HERE, name), out=lambda *_: None))
                self.assertEqual(len(_expected(os.path.join(HERE, name))), 3)

    def test_report_loads_the_records_verify_checked(self):
        for name in FIXTURES:
            path = os.path.join(HERE, name)
            with self.subTest(fixture=name):
                self.assertEqual(report._load(path), _expected(path))

    def test_export_loads_the_records_verify_checked(self):
        for name in FIXTURES:
            path = os.path.join(HERE, name)
            with self.subTest(fixture=name):
                self.assertEqual(export.load_records(path), _expected(path))

    def test_policy_loads_the_records_verify_checked(self):
        for name in FIXTURES:
            path = os.path.join(HERE, name)
            with self.subTest(fixture=name):
                self.assertEqual(policy.load_records(path), _expected(path))

    def test_witness_log_reads_checkpoints_with_cr_and_bom(self):
        cps = [{"subject": "acme", "chain_root": "r%d" % i, "count": i, "head": "h%d" % i}
               for i in range(3)]
        body = "\n".join(json.dumps(c).replace('{"subject"', '{\r"subject"') for c in cps) + "\n"
        d = tempfile.mkdtemp()
        path = os.path.join(d, "witness.jsonl")
        with open(path, "wb") as fh:
            fh.write(b"\xef\xbb\xbf" + body.encode("utf-8"))
        self.assertEqual(anchor.Notary(path).checkpoints(subject="acme"), cps)

    def test_verify_cli_exits_3_for_a_bom_only_log(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "empty.jsonl")
        with open(path, "wb") as fh:
            fh.write(b"\xef\xbb\xbf\n")
        from halo_record.cli import main
        with redirect_stdout(io.StringIO()):
            rc = main(["verify", path])
        self.assertEqual(rc, 3)


if __name__ == "__main__":
    unittest.main()
