import os
import tempfile
import unittest
from unittest import mock

from halo_record.hook import hook_agent, record_event
from halo_record.record import Recorder


class HookAgentTest(unittest.TestCase):
    def test_default_agent_has_no_version_claims(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HALO_AGENT_VERSION", None)
            os.environ.pop("HALO_AGENT_MODEL", None)
            agent = hook_agent()
        self.assertEqual(agent, {"id": "claude-code", "name": "claude-code"})

    def test_env_binds_version_and_model(self):
        env = {"HALO_AGENT_VERSION": "2.1.177", "HALO_AGENT_MODEL": "claude-sonnet-4-6"}
        with mock.patch.dict(os.environ, env):
            agent = hook_agent()
        self.assertEqual(agent["version"], "2.1.177")
        self.assertEqual(agent["model"], "claude-sonnet-4-6")

    def test_event_agent_wins_over_env(self):
        env = {"HALO_AGENT_VERSION": "env-version"}
        with mock.patch.dict(os.environ, env):
            agent = hook_agent({"agent": {"version": "1.0.0", "model": "m"}})
        self.assertEqual(agent["version"], "1.0.0")
        self.assertEqual(agent["model"], "m")
        self.assertEqual(agent["id"], "claude-code")  # identity is not overridable upward

    def test_versioned_record_lands_in_chain(self):
        log = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        env = {"HALO_AGENT_VERSION": "3.2.1"}
        with mock.patch.dict(os.environ, env):
            record = record_event(
                {"tool_name": "Read", "tool_input": {"path": "x"}, "session_id": "s"},
                Recorder(log),
            )
        self.assertEqual(record["agent"]["version"], "3.2.1")


if __name__ == "__main__":
    unittest.main()
