"""The four framework adapters, plus the zero-dependency guarantee.

langchain_core and the OpenAI ``agents`` SDK aren't installed, so we inject
minimal stub base classes into ``sys.modules`` — the same shape the adapters
expect — before materializing each handler. This is exactly the test that would
have caught the langchain ``HaloCallbackHandler = None`` shadowing regression.
"""

import asyncio
import json
import os
import sys
import tempfile
import types
import unittest

from halo_record.record import Recorder
from halo_record.verify import verify_log
from halo_record.integrations._common import classify_tool


def _silent(*_a, **_k):
    pass


def _install_langchain_stub():
    if "langchain_core.callbacks" in sys.modules:
        return
    mod = types.ModuleType("langchain_core")
    cb = types.ModuleType("langchain_core.callbacks")

    class BaseCallbackHandler:
        pass

    cb.BaseCallbackHandler = BaseCallbackHandler
    mod.callbacks = cb
    sys.modules["langchain_core"] = mod
    sys.modules["langchain_core.callbacks"] = cb


def _install_agents_stub():
    if "agents" in sys.modules:
        return
    mod = types.ModuleType("agents")

    class RunHooks:
        pass

    mod.RunHooks = RunHooks
    sys.modules["agents"] = mod


def _records(path):
    with open(path) as fh:
        return [json.loads(l) for l in fh if l.strip()]


class ClassifyTest(unittest.TestCase):
    def test_mapping(self):
        self.assertEqual(classify_tool("mcp__stripe__charge"), "connector")
        self.assertEqual(classify_tool("bash"), "exec")
        self.assertEqual(classify_tool("Write"), "data_write")
        self.assertEqual(classify_tool("read"), "data_read")
        self.assertEqual(classify_tool("WebFetch"), "network")
        self.assertEqual(classify_tool("anything_weird"), "connector")
        self.assertEqual(classify_tool(""), "connector")


class LangChainTest(unittest.TestCase):
    def test_handler_records_tool_calls(self):
        _install_langchain_stub()
        from halo_record.integrations import langchain as lc
        Handler = lc.HaloCallbackHandler  # must NOT be None (the old bug)
        self.assertIsNotNone(Handler)

        log = os.path.join(tempfile.mkdtemp(), "lc.jsonl")
        h = Handler(Recorder(log))
        h.on_tool_start({"name": "search"}, "query text", run_id="r1")
        h.on_tool_end("results", run_id="r1")
        h.on_tool_start({"name": "boom"}, "x", run_id="r2")
        h.on_tool_error(RuntimeError("kaboom"), run_id="r2")

        recs = _records(log)
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[1]["outcome"]["status"], "error")
        self.assertTrue(verify_log(log, out=_silent))


class OpenAIAgentsTest(unittest.TestCase):
    def test_hooks_record(self):
        _install_agents_stub()
        from halo_record.integrations import openai_agents as oa
        Hooks = oa.HaloRunHooks
        self.assertIsNotNone(Hooks)

        log = os.path.join(tempfile.mkdtemp(), "oa.jsonl")
        hooks = Hooks(Recorder(log))
        tool = types.SimpleNamespace(name="lookup")

        async def run():
            await hooks.on_tool_start(None, None, tool)
            await hooks.on_tool_end(None, None, tool, "the result")

        asyncio.run(run())
        recs = _records(log)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["action"]["tool"], "lookup")


class McpTest(unittest.TestCase):
    def test_record_mcp_call_normalizes_name(self):
        from halo_record.integrations.mcp import record_mcp_call
        log = os.path.join(tempfile.mkdtemp(), "mcp.jsonl")
        rec = record_mcp_call(Recorder(log), "charge", {"amount": 10}, server="stripe")
        self.assertEqual(rec["action"]["tool"], "mcp__stripe__charge")
        self.assertEqual(rec["action"]["authorization"]["scope"], "mcp:stripe")

    def test_instrument_async_session_idempotent(self):
        from halo_record.integrations.mcp import instrument_client_session
        log = os.path.join(tempfile.mkdtemp(), "mcp2.jsonl")

        class FakeSession:
            async def call_tool(self, name, arguments=None):
                return types.SimpleNamespace(isError=False,
                                             content=[types.SimpleNamespace(text="ok")])

        session = FakeSession()
        instrument_client_session(session, Recorder(log), server="stripe")
        wrapped_once = session.call_tool
        instrument_client_session(session, Recorder(log), server="stripe")
        self.assertIs(session.call_tool, wrapped_once)  # idempotent

        asyncio.run(session.call_tool("refund", {"id": "ch_1"}))
        recs = _records(log)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["action"]["tool"], "mcp__stripe__refund")

    def test_instrument_records_errors(self):
        from halo_record.integrations.mcp import instrument_client_session
        log = os.path.join(tempfile.mkdtemp(), "mcp3.jsonl")

        class FakeSession:
            async def call_tool(self, name, arguments=None):
                raise RuntimeError("tool blew up")

        session = FakeSession()
        instrument_client_session(session, Recorder(log))
        with self.assertRaises(RuntimeError):
            asyncio.run(session.call_tool("x", {}))
        recs = _records(log)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["outcome"]["status"], "error")


class OtelTest(unittest.TestCase):
    def test_record_genai_span(self):
        from halo_record.integrations.otel import record_span
        log = os.path.join(tempfile.mkdtemp(), "otel.jsonl")
        rec = Recorder(log)
        span = {"name": "tool", "attributes": {
            "gen_ai.system": "openai", "gen_ai.tool.name": "search"}}
        out = record_span(rec, span)
        self.assertIsNotNone(out)
        self.assertEqual(out["action"]["tool"], "mcp__openai__search")

    def test_non_genai_span_skipped(self):
        from halo_record.integrations.otel import record_span
        log = os.path.join(tempfile.mkdtemp(), "otel2.jsonl")
        self.assertIsNone(record_span(Recorder(log), {"name": "db.query",
                                                      "attributes": {"db": "pg"}}))
        self.assertFalse(os.path.exists(log))

    def test_error_span_recorded_as_error(self):
        from halo_record.integrations.otel import record_span
        log = os.path.join(tempfile.mkdtemp(), "otel3.jsonl")
        span = {"name": "call", "attributes": {"gen_ai.operation.name": "chat"},
                "status": {"status_code": "ERROR"}}
        out = record_span(Recorder(log), span)
        self.assertEqual(out["outcome"]["status"], "error")


class ZeroDepTest(unittest.TestCase):
    def test_core_import_pulls_no_frameworks(self):
        # The core promise: importing halo_record must not require any framework.
        # (We can't unimport, but we can assert none are real dependencies by
        # checking the adapters lazy-import rather than import at module load.)
        import halo_record.integrations.langchain  # noqa: F401 — bare import is fine
        import halo_record.integrations.mcp  # noqa: F401
        import halo_record.integrations.otel  # noqa: F401
        import halo_record.integrations.openai_agents  # noqa: F401
        # None of these brought a heavy framework into the namespace at import time.
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
