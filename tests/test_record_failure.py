"""A failed record append never turns a completed action into an error.

Records are written after the action runs. When writing fails, every wrapper
returns the action's own result (or re-raises the action's own exception) and
names the missing record on stderr, so a caller never retries an action that
already happened. Strict mode (``strict_recording=True`` or
``HALO_STRICT_RECORDING=1``) raises the recording error instead.
"""

import asyncio
import contextlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

from halo_record import record, record_call, trace
from halo_record.session import current_agent, current_recorder

MSG = "is NOT in the evidence log"


class _Failing:
    def __init__(self):
        self.calls = 0

    def append(self, record):
        self.calls += 1
        raise OSError(28, "No space left on device")


def _quiet(fn, *a, **k):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = fn(*a, **k)
    return out, err.getvalue()


class _Env(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(os.environ)
        p.start()
        os.environ.pop("HALO_STRICT_RECORDING", None)
        self.addCleanup(p.stop)


class RecordCallTest(_Env):
    def test_result_is_kept_and_failure_reported(self):
        ran = []

        def go():
            with record_call(_Failing(), "refund", {"id": 1}) as call:
                ran.append(1)
                call.result = {"refunded": True}
            return call.result

        out, err = _quiet(go)
        self.assertEqual(out, {"refunded": True})
        self.assertEqual(ran, [1])
        self.assertIn("halo-record: FAILED to record 'refund'", err)
        self.assertIn(MSG, err)

    def test_the_actions_own_exception_propagates(self):
        def go():
            with record_call(_Failing(), "refund", {}):
                raise KeyError("tool failed")

        with contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(KeyError):
                go()
        self.assertIn(MSG, err.getvalue())

    def test_strict_raises(self):
        def go():
            with record_call(_Failing(), "refund", {}, strict_recording=True) as call:
                call.result = 1

        with self.assertRaises(OSError):
            go()
        os.environ["HALO_STRICT_RECORDING"] = "1"

        def go2():
            with record_call(_Failing(), "refund", {}) as call:
                call.result = 1

        with self.assertRaises(OSError):
            go2()

    def test_no_recorder_is_refused_before_the_action_runs(self):
        ran = []
        with self.assertRaises(RuntimeError):
            with record_call(None, "refund", {}):
                ran.append(1)
        self.assertEqual(ran, [])


class DecoratorTest(_Env):
    def test_decorated_tool_returns_its_result(self):
        calls = []

        @record(_Failing())
        def refund(amount):
            calls.append(amount)
            return "ok"

        out, err = _quiet(refund, 5)
        self.assertEqual(out, "ok")
        self.assertEqual(calls, [5])
        self.assertIn(MSG, err)

    def test_decorated_tool_error_propagates(self):
        @record(_Failing())
        def refund(amount):
            raise ValueError("declined")

        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(ValueError):
                refund(5)

    def test_strict_decorator_raises(self):
        @record(_Failing(), strict_recording=True)
        def refund(amount):
            return "ok"

        with self.assertRaises(OSError):
            refund(5)


class TraceTest(_Env):
    def _traced(self, fn, **kw):
        t = trace(fn, profile="p", log=os.path.join(tempfile.mkdtemp(), "c.jsonl"), **kw)
        failing = _Failing()
        t.halo_recorder.append = failing.append
        return t

    def test_result_returned_and_context_unbound(self):
        t = self._traced(lambda: 42)
        out, err = _quiet(t)
        self.assertEqual(out, 42)
        self.assertIn(MSG, err)
        self.assertIsNone(current_recorder())
        self.assertIsNone(current_agent())

    def test_agent_error_propagates_and_context_unbound(self):
        def boom():
            raise KeyError("agent failed")

        t = self._traced(boom)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(KeyError):
                t()
        self.assertIsNone(current_recorder())
        self.assertIsNone(current_agent())

    def test_strict_trace_raises_and_still_unbinds(self):
        t = self._traced(lambda: 42, strict_recording=True)
        with self.assertRaises(OSError):
            t()
        self.assertIsNone(current_recorder())
        self.assertIsNone(current_agent())

    def test_build_failure_also_unbinds(self):
        t = trace(lambda: 1, profile="p", log=os.path.join(tempfile.mkdtemp(), "c.jsonl"),
                  category="nope", strict_recording=True)
        with self.assertRaises(ValueError):
            t()
        self.assertIsNone(current_recorder())


def _stub(name, **attrs):
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    return mod


class AdapterTest(_Env):
    def test_openai_agents_on_tool_end(self):
        class RunHooks:
            pass

        with mock.patch.dict(sys.modules, {"agents": _stub("agents", RunHooks=RunHooks)}):
            from halo_record.integrations import openai_agents
            hooks = openai_agents.HaloRunHooks(_Failing())
            tool = types.SimpleNamespace(name="refund")
            out, err = _quiet(asyncio.run, hooks.on_tool_end(None, None, tool, "done"))
            self.assertIn(MSG, err)
            strict = openai_agents.HaloRunHooks(_Failing(), strict_recording=True)
            with self.assertRaises(OSError):
                asyncio.run(strict.on_tool_end(None, None, tool, "done"))

    def test_litellm_logger(self):
        class CustomLogger:
            pass

        mods = {"litellm": _stub("litellm"), "litellm.integrations": _stub("litellm.integrations"),
                "litellm.integrations.custom_logger": _stub("litellm.integrations.custom_logger",
                                                            CustomLogger=CustomLogger)}
        with mock.patch.dict(sys.modules, mods):
            from halo_record.integrations import litellm
            lg = litellm.HaloLiteLLMLogger(_Failing())
            _, err = _quiet(lg.log_success_event, {"model": "m"}, {"ok": 1}, 0, 1)
            self.assertIn(MSG, err)
            _, err = _quiet(lg.log_failure_event, {"model": "m"}, None, 0, 1)
            self.assertIn(MSG, err)
            strict = litellm.HaloLiteLLMLogger(_Failing(), strict_recording=True)
            with self.assertRaises(OSError):
                strict.log_success_event({"model": "m"}, {"ok": 1}, 0, 1)

    def test_langchain_handler_honors_strict(self):
        class BaseCallbackHandler:
            pass

        mods = {"langchain_core": _stub("langchain_core"),
                "langchain_core.callbacks": _stub("langchain_core.callbacks",
                                                  BaseCallbackHandler=BaseCallbackHandler)}
        with mock.patch.dict(sys.modules, mods):
            from halo_record.integrations import langchain
            h = langchain.HaloCallbackHandler(_Failing())
            h.on_tool_start({"name": "refund"}, "x", run_id="r1")
            _, err = _quiet(h.on_tool_end, "done", run_id="r1")
            self.assertIn(MSG, err)
            s = langchain.HaloCallbackHandler(_Failing(), strict_recording=True)
            s.on_tool_start({"name": "refund"}, "x", run_id="r1")
            with self.assertRaises(OSError):
                s.on_tool_end("done", run_id="r1")

    def test_mcp_wrapper_message_and_strict(self):
        from halo_record.integrations.mcp import instrument_client_session

        class S:
            def call_tool(self, name, arguments=None):
                return {"charged": True}

        s = instrument_client_session(S(), _Failing(), server="stripe")
        out, err = _quiet(s.call_tool, "refund", {})
        self.assertEqual(out, {"charged": True})
        self.assertIn(MSG, err)
        s2 = instrument_client_session(S(), _Failing(), server="stripe", strict_recording=True)
        with self.assertRaises(OSError):
            s2.call_tool("refund", {})

    def test_hook_reports_and_exits_zero(self):
        from halo_record import hook
        event = json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                            "tool_input": {"command": "ls"}, "tool_response": {"stdout": "x"}})
        with mock.patch.object(hook, "record_event", side_effect=OSError(28, "No space")), \
                mock.patch("sys.stdin", io.StringIO(event)):
            rc, err = _quiet(hook.main, [])
        self.assertEqual(rc, 0)
        self.assertIn(MSG, err)
        os.environ["HALO_STRICT_RECORDING"] = "1"
        with mock.patch.object(hook, "record_event", side_effect=OSError(28, "No space")), \
                mock.patch("sys.stdin", io.StringIO(event)):
            with self.assertRaises(OSError):
                hook.main([])


if __name__ == "__main__":
    unittest.main()


class HookChainDirectoryTest(unittest.TestCase):
    """`halo hook` reports a chain directory it cannot create the way it
    reports any failed append: the FAILED line, then exit 0 (strict: the line,
    then a non-zero exit), never a bare traceback."""

    def _run(self, strict):
        import subprocess
        import sys
        d = tempfile.mkdtemp()
        blocker = os.path.join(d, "not-a-dir")
        with open(blocker, "w") as fh:
            fh.write("x")
        env = dict(os.environ)
        env.pop("HALO_DIR", None)
        env.pop("HALO_STRICT_RECORDING", None)
        env["HALO_LOG"] = os.path.join(blocker, "sub", "audit.jsonl")
        env["PYTHONPATH"] = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
        if strict:
            env["HALO_STRICT_RECORDING"] = "1"
        event = json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                            "tool_input": {"command": "ls"}, "tool_response": {"stdout": "x"}})
        p = subprocess.run([sys.executable, "-c", "import sys; from halo_record.cli import main; sys.exit(main(['hook']))"],
                           input=event, capture_output=True, text=True, env=env, timeout=60)
        return p.returncode, p.stderr

    def test_default_reports_and_exits_zero(self):
        rc, err = self._run(strict=False)
        self.assertEqual(rc, 0, err)
        self.assertIn("halo-record: FAILED to record 'Bash'", err)
        self.assertIn(MSG, err)
        self.assertNotIn("Traceback", err)

    def test_strict_reports_then_exits_nonzero(self):
        rc, err = self._run(strict=True)
        self.assertNotEqual(rc, 0, err)
        self.assertIn("halo-record: FAILED to record 'Bash'", err)
        self.assertNotIn("Traceback", err)
