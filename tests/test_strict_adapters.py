"""Strict recording in the framework adapters, against the real frameworks.

* Halo's own stderr line is written for every lost record, strict or not;
  strict mode raises after writing it, never instead of it.
* A missing or closed ``sys.stderr`` never turns a lost record into a lost
  tool result.
* LangChain: a strict handler sets ``raise_error``, so LangChain re-raises the
  recording error to the caller of the tool.
* OpenTelemetry and LiteLLM run exporters and callbacks where the caller
  cannot see an exception (the span processor and LiteLLM's logging catch and
  log it). Strict mode there cannot reach the caller; the Halo line is the
  signal, and these tests pin that behavior so the docs stay accurate.

The real-framework classes are skipped when the framework is not installed;
run them with e.g. ``uvx --with langchain-core --with opentelemetry-sdk
--with-editable . pytest tests/test_strict_adapters.py``.
"""

import contextlib
import importlib.util
import io
import logging
import os
import sys
import types
import unittest
from unittest import mock

from halo_record import record_call
from halo_record.session import recording_failed

MSG = "is NOT in the evidence log"
HAS_LC = importlib.util.find_spec("langchain_core") is not None
HAS_OTEL = importlib.util.find_spec("opentelemetry") is not None and \
    importlib.util.find_spec("opentelemetry.sdk") is not None
HAS_LITELLM = importlib.util.find_spec("litellm") is not None


class _Failing:
    def append(self, record):
        raise PermissionError(13, "Permission denied")


class _Env(unittest.TestCase):
    def setUp(self):
        p = mock.patch.dict(os.environ)
        p.start()
        os.environ.pop("HALO_STRICT_RECORDING", None)
        self.addCleanup(p.stop)


class StrictWritesTheLineTest(_Env):
    def test_strict_mode_still_writes_the_halo_line(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(PermissionError):
                recording_failed("refund", PermissionError("denied"), True)
        self.assertIn("halo-record: FAILED to record 'refund'", err.getvalue())
        self.assertIn(MSG, err.getvalue())
        self.assertIn("strict", err.getvalue().lower())

    def test_strict_record_call_writes_the_line_then_raises(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(PermissionError):
                with record_call(_Failing(), "refund", {}, strict_recording=True) as call:
                    call.result = 1
        self.assertIn(MSG, err.getvalue())


class NoStderrTest(_Env):
    def test_none_stderr_keeps_the_result(self):
        with mock.patch.object(sys, "stderr", None), \
                self.assertLogs("halo_record", level="WARNING") as logs:
            with record_call(_Failing(), "refund", {}) as call:
                call.result = {"refunded": True}
        self.assertEqual(call.result, {"refunded": True})
        self.assertTrue(any(MSG in line for line in logs.output))

    def test_a_closed_stderr_keeps_the_result(self):
        closed = io.StringIO()
        closed.close()
        with mock.patch.object(sys, "stderr", closed), \
                self.assertLogs("halo_record", level="WARNING"):
            with record_call(_Failing(), "refund", {}) as call:
                call.result = 7
        self.assertEqual(call.result, 7)

    def test_none_stderr_in_strict_mode_raises_the_recording_error(self):
        with mock.patch.object(sys, "stderr", None), \
                self.assertLogs("halo_record", level="WARNING"):
            with self.assertRaises(PermissionError):
                with record_call(_Failing(), "refund", {}, strict_recording=True) as call:
                    call.result = 7


def _lc_tool():
    from langchain_core.tools import tool

    @tool
    def issue_refund(amount: int) -> str:
        """Issue a refund."""
        return "LCRES"

    return issue_refund


@unittest.skipUnless(HAS_LC, "langchain-core not installed")
class RealLangChainTest(_Env):
    def _handler(self, **kw):
        from halo_record.integrations.langchain import HaloCallbackHandler
        return HaloCallbackHandler(_Failing(), **kw)

    def test_default_returns_the_tool_result_and_warns(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            out = _lc_tool().invoke({"amount": 5}, config={"callbacks": [self._handler()]})
        self.assertEqual(out, "LCRES")
        self.assertIn(MSG, err.getvalue())

    def test_strict_raises_to_the_caller_after_the_line(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(PermissionError):
                _lc_tool().invoke({"amount": 5},
                                  config={"callbacks": [self._handler(strict_recording=True)]})
        self.assertIn(MSG, err.getvalue())

    def test_strict_from_the_environment(self):
        os.environ["HALO_STRICT_RECORDING"] = "1"
        h = self._handler()
        self.assertTrue(h.raise_error)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(PermissionError):
                _lc_tool().invoke({"amount": 5}, config={"callbacks": [h]})
        self.assertFalse(self._handler(strict_recording=False).raise_error)

    def test_the_tool_name_is_recorded(self):
        from halo_record.integrations.langchain import HaloCallbackHandler
        recs = []

        class R:
            def append(self, r):
                recs.append(r)

        _lc_tool().invoke({"amount": 5}, config={"callbacks": [HaloCallbackHandler(R())]})
        self.assertEqual(recs[0]["action"]["tool"], "issue_refund")


@unittest.skipUnless(HAS_OTEL, "opentelemetry-sdk not installed")
class RealOtelTest(_Env):
    def _run(self, exporter):
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer("t")
        with tracer.start_as_current_span("tool") as span:
            span.set_attribute("gen_ai.tool.name", "refund")
            span.set_attribute("gen_ai.system", "stripe")
        with tracer.start_as_current_span("tool2") as span:
            span.set_attribute("gen_ai.tool.name", "lookup")
        provider.shutdown()

    def test_default_warns_per_lost_span(self):
        from halo_record.integrations.otel import HaloSpanExporter
        exp = HaloSpanExporter(_Failing())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self._run(exp)
        self.assertEqual(err.getvalue().count(MSG), 2)
        self.assertEqual(exp.lost_records, 2)

    def test_strict_writes_every_line_and_never_reaches_the_application(self):
        from halo_record.integrations.otel import HaloSpanExporter
        exp = HaloSpanExporter(_Failing(), strict_recording=True)
        err = io.StringIO()
        logging.getLogger("opentelemetry").disabled = True
        self.addCleanup(setattr, logging.getLogger("opentelemetry"), "disabled", False)
        with contextlib.redirect_stderr(err):
            self._run(exp)  # the span processor catches what the exporter raises
        self.assertEqual(err.getvalue().count(MSG), 2)
        self.assertEqual(exp.lost_records, 2)


@unittest.skipUnless(HAS_LITELLM, "litellm not installed")
class RealLiteLLMTest(_Env):
    def test_strict_cannot_reach_the_caller_but_the_line_is_written(self):
        import time
        import litellm
        from halo_record.integrations.litellm import HaloLiteLLMLogger
        lg = HaloLiteLLMLogger(_Failing(), strict_recording=True)
        old = litellm.callbacks
        litellm.callbacks = [lg]
        self.addCleanup(setattr, litellm, "callbacks", old)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            r = litellm.completion(model="gpt-4o-mini", messages=[{"role": "user", "content": "x"}],
                                   mock_response="hi")
            time.sleep(1.5)
        self.assertEqual(r.choices[0].message.content, "hi")
        self.assertIn(MSG, err.getvalue())


class StubOtelStrictTest(_Env):
    """Without the SDK: a strict exporter records every span in the batch,
    writes a line per loss, then raises the first recording error."""

    def test_strict_exporter_finishes_the_batch_before_raising(self):
        fake = types.ModuleType("opentelemetry.sdk.trace.export")

        class SpanExporter:
            pass

        fake.SpanExporter = SpanExporter
        fake.SpanExportResult = types.SimpleNamespace(SUCCESS=0, FAILURE=1)
        mods = {"opentelemetry": types.ModuleType("opentelemetry"),
                "opentelemetry.sdk": types.ModuleType("opentelemetry.sdk"),
                "opentelemetry.sdk.trace": types.ModuleType("opentelemetry.sdk.trace"),
                "opentelemetry.sdk.trace.export": fake}
        recs = []

        class Mixed:
            def append(self, r):
                if r["action"]["tool"].endswith("bad"):
                    raise PermissionError(13, "denied")
                recs.append(r)

        spans = [{"name": n, "attributes": {"gen_ai.tool.name": n}} for n in ("bad", "good", "bad")]
        with mock.patch.dict(sys.modules, mods):
            from halo_record.integrations import otel
            exp = otel.HaloSpanExporter(Mixed(), strict_recording=True)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                with self.assertRaises(PermissionError):
                    exp.export(spans)
        self.assertEqual(len(recs), 1)
        self.assertEqual(err.getvalue().count(MSG), 2)


if __name__ == "__main__":
    unittest.main()
