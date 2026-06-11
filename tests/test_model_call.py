"""model.generate as a first-class record — provider, ZDR, purpose disclosed."""

import os
import tempfile
import unittest

from halo_record import Recorder
from halo_record.integrations._common import record_model_call
from halo_record.verify import verify_log


class TestRecordModelCall(unittest.TestCase):
    def test_model_call_record_shape(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.jsonl")
            rec = Recorder(path)
            record = record_model_call(
                rec, provider="anthropic", model="claude-opus-4-8", zdr=True,
                purpose="draft SIG questionnaire answers", messages=9,
                response={"summary": "drafted 42 answers"},
                subject="acme-corp", source="litellm")

            self.assertEqual(record["action"]["tool"], "model.generate")
            self.assertEqual(record["action"]["category"], "privacy")
            self.assertEqual(record["action"]["authorization"]["scope"],
                             "model:anthropic")
            summary = record["action"]["input"]["summary"]
            self.assertIn("anthropic", summary)
            self.assertIn("zdr", summary)
            self.assertEqual(record["source"]["capture"], "ingested")
            self.assertTrue(verify_log(path, out=lambda *a, **k: None))

    def test_error_outcome(self):
        with tempfile.TemporaryDirectory() as d:
            rec = Recorder(os.path.join(d, "chain.jsonl"))
            record = record_model_call(
                rec, provider="openai", model="gpt-5", error=RuntimeError("429"))
            self.assertEqual(record["outcome"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
