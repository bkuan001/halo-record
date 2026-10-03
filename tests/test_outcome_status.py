"""``build`` refuses an ``outcome.status`` outside the schema's enum.

The verifier rejects any other value, and an append-only chain has no undo:
a record sealed with ``"success"`` would fail verification for the life of the
chain. The status is checked when the record is built, before anything is
appended.
"""

import os
import tempfile
import unittest

from halo_record.record import Recorder, build
from halo_record.verify import verify_log


class OutcomeStatusTest(unittest.TestCase):
    def test_invalid_status_is_refused_at_build(self):
        for bad in ("success", "OK", "", 1, None, True, ["ok"]):
            for summaries in (True, False):
                with self.assertRaises(ValueError) as cm:
                    build("tool_call", "security", tool="t",
                          outcome={"status": bad}, summaries=summaries)
                self.assertIn("outcome.status", str(cm.exception))
                self.assertIn("ok", str(cm.exception))
        # The rejected value is not echoed: it is caller text and may carry payload.
        with self.assertRaises(ValueError) as cm:
            build("tool_call", "security", tool="t", outcome={"status": "sk_live_SECRETVALUE"})
        self.assertNotIn("SECRETVALUE", str(cm.exception))
        self.assertEqual(str(cm.exception),
                         "outcome.status must be one of ['denied', 'error', 'ok']")

    def test_valid_and_absent_status_still_build(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        rec = Recorder(log)
        for outcome in ({"status": "ok"}, {"status": "error"}, {"status": "denied"},
                        {"summary": "no status"}, None):
            rec.append(build("tool_call", "security", tool="t", outcome=outcome))
        self.assertTrue(verify_log(log, out=lambda *a: None))


class SchemaInputDescriptionTest(unittest.TestCase):
    def test_input_description_states_what_the_summary_holds(self):
        from halo_record.verify import load_schema
        desc = load_schema()["properties"]["action"]["properties"]["input"]["description"]
        self.assertNotIn("MUST NOT appear", desc)
        self.assertIn("appears in the summary in full", desc)


if __name__ == "__main__":
    unittest.main()
