"""Instrumentation never takes down the agent it records: odd keys, cyclic
structures, and long subject ids are recorded rather than raised, and an
adapter whose recording fails after the tool ran still returns the tool's
result (so a retry cannot repeat the tool's side effects)."""

import asyncio
import contextlib
import io
import os
import tempfile
import unittest

from halo_record.canon import input_hash
from halo_record.integrations.mcp import instrument_client_session
from halo_record.record import Recorder, TenantRecorder, build
from halo_record.verify import verify_log


def _quiet(fn, *a, **kw):
    with contextlib.redirect_stderr(io.StringIO()):
        return fn(*a, **kw)


class OddInputTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.rec = Recorder(os.path.join(self.d, "c.jsonl"))

    def _seal(self, **kw):
        r = _quiet(build, "tool_call", "security", tool="t", **kw)
        self.rec.append(r)
        return r

    def test_non_string_keys(self):
        for odd in ({1: "a"}, {"a": 1, 2: "b"}, {(1, 2): "x"}, {None: 1, 1.5: 2}):
            input_hash(odd)
            self._seal(tool_input=odd, data={"m": odd}, outcome={"status": "ok", "m": odd})
        self.assertTrue(verify_log(self.rec.path, out=lambda *_: None))

    def test_cyclic_structures(self):
        c = {"a": 1}
        c["self"] = c
        lst = [1]
        lst.append(lst)
        input_hash(c)
        self._seal(tool_input=c)
        self._seal(tool_input={"l": lst})
        self._seal(tool_input={"q": 1}, data={"c": c})
        self._seal(tool_input={"q": 1}, outcome={"status": "ok", "c": c})
        self._seal(tool_input={"q": 1}, authority={"snapshot_id": "s", "c": c})
        self.assertTrue(verify_log(self.rec.path, out=lambda *_: None))

    def test_deep_nesting(self):
        deep = {}
        node = deep
        for _ in range(5000):
            node["n"] = {}
            node = node["n"]
        input_hash(deep)
        self._seal(tool_input=deep, data={"d": deep})
        self.assertTrue(verify_log(self.rec.path, out=lambda *_: None))


class LongSubjectTest(unittest.TestCase):
    def test_long_subject_ids_get_distinct_bounded_files(self):
        d = tempfile.mkdtemp()
        t = TenantRecorder(d)
        a, b = "a" * 300, "a" * 299 + "b"
        t.append(build("tool_call", "security", tool="x", subject=a))
        t.append(build("tool_call", "security", tool="x", subject=b))
        pa, pb = t.chain_path_for(a), t.chain_path_for(b)
        self.assertNotEqual(pa, pb)
        for p in (pa, pb):
            self.assertLessEqual(len(os.path.basename(p) + ".lock"), 255)
            self.assertTrue(verify_log(p, out=lambda *_: None))


class _FailingRecorder:
    def append(self, record):
        raise OSError(28, "No space left on device")


class McpRecordingFailureTest(unittest.TestCase):
    def test_sync_tool_result_survives_recording_failure(self):
        class S:
            calls = 0

            def call_tool(self, name, arguments=None):
                S.calls += 1
                return {"charged": True}

        s = instrument_client_session(S(), _FailingRecorder(), server="stripe")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            out = s.call_tool("refund", {"id": "x"})
        self.assertEqual(out, {"charged": True})
        self.assertEqual(S.calls, 1)
        self.assertIn("halo-record", err.getvalue())

    def test_async_tool_result_survives_recording_failure(self):
        class S:
            calls = 0

            async def call_tool(self, name, arguments=None):
                S.calls += 1
                return {"charged": True}

        s = instrument_client_session(S(), _FailingRecorder(), server="stripe")
        with contextlib.redirect_stderr(io.StringIO()):
            out = asyncio.run(s.call_tool("refund", {"id": "x"}))
        self.assertEqual(out, {"charged": True})
        self.assertEqual(S.calls, 1)

    def test_tool_error_propagates_not_recording_error(self):
        class S:
            def call_tool(self, name, arguments=None):
                raise KeyError("tool failed")

        s = instrument_client_session(S(), _FailingRecorder(), server="x")
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(KeyError):
                s.call_tool("t", {})

    def test_odd_arguments_are_recorded(self):
        class S:
            def call_tool(self, name, arguments=None):
                return {"ok": True}

        d = tempfile.mkdtemp()
        rec = Recorder(os.path.join(d, "m.jsonl"))
        s = instrument_client_session(S(), rec, server="stripe")
        self.assertEqual(s.call_tool("refund", {1: "cus_123"}), {"ok": True})
        self.assertTrue(verify_log(rec.path, out=lambda *_: None))
        self.assertEqual(len(open(rec.path).read().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
