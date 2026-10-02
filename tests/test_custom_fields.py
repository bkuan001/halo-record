"""Caller-defined outcome and data fields: any value seals, and secrets in them
are found, not only masked.

* bytes, sets, tuples and other objects in custom fields are rendered as text
  (sets as sorted lists) and masked, so the append never fails on them;
* an integer too long to print (more than 4300 digits) is stored as a size
  marker everywhere a record can carry it;
* a secret or personal-data value in a custom outcome or data field produces
  a finding (and ``data.pii_types``), so a policy can see it.
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr

from halo_record.record import Recorder, build
from halo_record.verify import verify_log

KEY = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0"
HUGE = 10 ** 5000


def _append(**kw):
    path = os.path.join(tempfile.mkdtemp(), "c.jsonl")
    rec = Recorder(path)
    with redirect_stderr(io.StringIO()):
        r = build("tool_call", "security", tool="t", **kw)
        rec.append(r)
    ok = verify_log(path, out=lambda *a, **k: None)
    with open(path, encoding="utf-8") as fh:
        stored = json.loads(fh.readline())
    return r, stored, ok


class OddValuesTest(unittest.TestCase):
    def test_bytes_and_sets_in_custom_outcome_and_data_seal(self):
        r, stored, ok = _append(
            outcome={"status": "ok", "detail": {"b": b"\x00\x01raw", "s": {"b", "a"},
                                                "t": ("x", 1), "o": object()}},
            data={"blob": bytearray(b"zz"), "tags": frozenset({"k2", "k1"})})
        self.assertTrue(ok)
        detail = stored["outcome"]["detail"]
        self.assertEqual(detail["s"], ["a", "b"])
        self.assertEqual(detail["t"], ["x", 1])
        self.assertIsInstance(detail["b"], str)
        self.assertIsInstance(detail["o"], str)
        self.assertEqual(stored["data"]["tags"], ["k1", "k2"])
        self.assertIsInstance(stored["data"]["blob"], str)

    def test_secret_bytes_in_a_custom_field_are_masked_and_found(self):
        r, stored, ok = _append(outcome={"status": "ok", "raw": KEY.encode()})
        self.assertTrue(ok)
        self.assertNotIn(KEY[8:], json.dumps(stored))
        self.assertIn("stripe_key", [f["type"] for f in stored["findings"]])

    def test_huge_integers_do_not_raise(self):
        for kw in (dict(tool_input={"n": HUGE}), dict(tool_input={HUGE: 1}),
                   dict(tool_input={"n": {HUGE}}), dict(outcome={"status": "ok", "n": HUGE}),
                   dict(data={"n": HUGE}), dict(tool_input=[-HUGE])):
            with self.subTest(kw=list(kw)):
                r, stored, ok = _append(**kw)
                self.assertTrue(ok)
                self.assertIn("[integer of 16610 bits]", json.dumps(stored))


class CustomFieldFindingsTest(unittest.TestCase):
    def test_custom_outcome_key_produces_a_finding(self):
        r = build("tool_call", "security", tool="t",
                  outcome={"status": "ok", "detail": {"token": "x", "note": "use " + KEY}})
        types = [f["type"] for f in r["findings"]]
        self.assertIn("stripe_key", types)
        self.assertNotIn(KEY[8:], json.dumps(r))

    def test_custom_data_key_produces_pii_types(self):
        r = build("network", "privacy", tool="post",
                  data={"note": "ssn 123-45-6789", "purpose": "support"})
        self.assertIn("ssn", [f["type"] for f in r["findings"]])
        self.assertEqual(r["data"]["pii_types"], ["ssn"])
        self.assertNotIn("123-45-6789", json.dumps(r))

    def test_hash_only_keeps_types_not_samples(self):
        r = build("tool_call", "security", tool="t", summaries=False,
                  outcome={"status": "ok", "detail": KEY})
        self.assertIn("stripe_key", [f["type"] for f in r["findings"]])
        self.assertTrue(all("sample" not in f for f in r["findings"]))

    def test_caller_findings_are_kept_as_given(self):
        r = build("tool_call", "security", tool="t", findings=[],
                  outcome={"status": "ok", "detail": KEY})
        self.assertEqual(r["findings"], [])


if __name__ == "__main__":
    unittest.main()
