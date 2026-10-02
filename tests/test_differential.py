"""The Python and TypeScript verifiers must agree on every file. The same
fixtures and expected verdicts live in both repositories (TypeScript:
test/fixtures/differential/); each suite pins its verifier to them."""

import json
import os
import tempfile
import unittest

from halo_record.record import Recorder, build
from halo_record.verify import verify_log

HERE = os.path.join(os.path.dirname(__file__), "fixtures", "differential")


class DifferentialVerdictTest(unittest.TestCase):
    def test_each_fixture_matches_its_expected_verdict(self):
        with open(os.path.join(HERE, "expected.json")) as fh:
            expected = json.load(fh)
        for name, ok in sorted(expected.items()):
            with self.subTest(fixture=name):
                self.assertEqual(verify_log(os.path.join(HERE, name), out=lambda *_: None), ok)


class RecorderNeverRaisesOnOddTextTest(unittest.TestCase):
    def test_lone_surrogate_in_input_is_recorded_not_raised(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "c.jsonl")
        rec = Recorder(path)
        rec.append(build("tool_call", "security", tool="t", tool_input={"q": "hello \ud800 world"},
                         data={"note": "x \udfff y"}))
        self.assertTrue(verify_log(path, out=lambda *_: None))
        from halo_record.canon import canon_issues
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(canon_issues(json.loads(fh.read())), [])


if __name__ == "__main__":
    unittest.main()
