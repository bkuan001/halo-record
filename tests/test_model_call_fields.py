"""A model-call record carries the model and retention terms as structured
fields (so export columns and policy rules can read them, with or without
summaries) and the messages as a count, never their content."""

import json
import os
import tempfile
import unittest

from halo_record import Recorder, record_model_call
from halo_record.integrations._common import record_model_call as adapter_record_model_call

PROMPT = "Summarize the merger terms for Project Bluebird"


def _both(**kw):
    d = tempfile.mkdtemp()
    a = record_model_call(Recorder(os.path.join(d, "a.jsonl")), **kw)
    b = adapter_record_model_call(Recorder(os.path.join(d, "b.jsonl")), **kw)
    return a, b


class ModelCallFieldsTest(unittest.TestCase):
    def test_messages_are_a_count_never_content(self):
        msgs = [{"role": "user", "content": PROMPT}, {"role": "assistant", "content": "ok"}]
        for r in _both(provider="anthropic", model="m-1", messages=msgs):
            blob = json.dumps(r)
            self.assertNotIn("Bluebird", blob)
            self.assertIn("'messages': 2", r["action"]["input"]["summary"])

    def test_integer_message_count_is_kept(self):
        for r in _both(provider="anthropic", model="m-1", messages=9):
            self.assertIn("'messages': 9", r["action"]["input"]["summary"])

    def test_model_and_zdr_are_structured(self):
        for summaries in (True, False):
            for r in _both(provider="anthropic", model="claude-x", zdr=True,
                           summaries=summaries):
                self.assertEqual(r["agent"]["model"], "claude-x")
                self.assertIs(r["data"]["zdr"], True)

    def test_declared_agent_is_kept(self):
        for r in _both(provider="openai", model="gpt-x", zdr=False,
                       agent={"id": "support-bot", "name": "Support", "version": "3"}):
            self.assertEqual(r["agent"]["id"], "support-bot")
            self.assertEqual(r["agent"]["version"], "3")
            self.assertEqual(r["agent"]["model"], "gpt-x")
            self.assertIs(r["data"]["zdr"], False)

    def test_zdr_absent_when_not_declared(self):
        for r in _both(provider="anthropic", model="m-1"):
            self.assertNotIn("zdr", r.get("data") or {})


if __name__ == "__main__":
    unittest.main()
