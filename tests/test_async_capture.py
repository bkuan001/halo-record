"""``@record`` and ``trace()`` on ``async def`` functions record the real outcome.

The wrapper of a coroutine function is itself a coroutine function: it awaits
the body, then records what it returned or raised. ``trace`` keeps its
recorder and agent bound for the whole awaited body (contextvars), so a
``record_call`` inside it, after any number of awaits, lands on the traced
chain, and concurrent traced agents each see their own recorder.
"""

import asyncio
import contextlib
import inspect
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from halo_record import record, record_call, trace
from halo_record.session import current_agent, current_recorder
from halo_record.verify import verify_log


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


class _Failing:
    def append(self, record):
        raise OSError(28, "No space left on device")


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.log = os.path.join(self.d, "a.jsonl")
        p = mock.patch.dict(os.environ)
        p.start()
        os.environ.pop("HALO_STRICT_RECORDING", None)
        self.addCleanup(p.stop)


class AsyncRecordTest(_Base):
    def test_success_records_the_awaited_value(self):
        from halo_record import Recorder
        rec = Recorder(self.log)

        @record(rec)
        async def lookup(order_id):
            await asyncio.sleep(0)
            return {"order": order_id, "state": "shipped"}

        self.assertTrue(inspect.iscoroutinefunction(lookup))
        self.assertEqual(asyncio.run(lookup(7)), {"order": 7, "state": "shipped"})
        recs = _read(self.log)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["outcome"]["status"], "ok")
        self.assertIn("shipped", recs[0]["outcome"]["summary"])
        self.assertNotIn("coroutine", json.dumps(recs[0]))

    def test_exception_is_recorded_and_reraised(self):
        from halo_record import Recorder
        rec = Recorder(self.log)

        @record(rec)
        async def refund():
            await asyncio.sleep(0)
            raise RuntimeError("card declined")

        with self.assertRaises(RuntimeError):
            asyncio.run(refund())
        recs = _read(self.log)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["outcome"]["status"], "error")
        self.assertIn("card declined", recs[0]["outcome"]["summary"])

    def test_nothing_is_recorded_before_the_coroutine_runs(self):
        from halo_record import Recorder
        rec = Recorder(self.log)

        @record(rec)
        async def t():
            return 1

        coro = t()
        self.assertFalse(os.path.exists(self.log) and _read(self.log))
        self.assertEqual(asyncio.run(coro), 1)
        self.assertEqual(len(_read(self.log)), 1)

    def test_record_failure_passes_the_result_through(self):
        @record(_Failing())
        async def t():
            return "done"

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(asyncio.run(t()), "done")
        self.assertIn("is NOT in the evidence log", err.getvalue())


class AsyncTraceTest(_Base):
    def test_boundary_records_the_real_outcome(self):
        async def agent(q):
            await asyncio.sleep(0)
            return {"answer": q * 2}

        traced = trace(agent, profile="acme", log=self.log)
        self.assertTrue(inspect.iscoroutinefunction(traced))
        self.assertEqual(asyncio.run(traced(21)), {"answer": 42})
        recs = _read(self.log)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["outcome"]["status"], "ok")
        self.assertIn("42", recs[0]["outcome"]["summary"])
        self.assertTrue(verify_log(self.log, out=lambda *a: None))

    def test_boundary_records_an_exception(self):
        async def agent():
            await asyncio.sleep(0)
            raise ValueError("bad plan")

        traced = trace(agent, profile="acme", log=self.log)
        with self.assertRaises(ValueError):
            asyncio.run(traced())
        recs = _read(self.log)
        self.assertEqual(recs[-1]["outcome"]["status"], "error")

    def test_nested_record_call_lands_on_the_traced_chain(self):
        @record()
        async def tool(x):
            await asyncio.sleep(0)
            return x + 1

        async def agent():
            await asyncio.sleep(0)
            self.assertIsNotNone(current_recorder())
            with record_call(None, "lookup", {"k": 1}) as call:
                await asyncio.sleep(0)
                call.result = "found"
            return await tool(1)

        traced = trace(agent, profile="acme", log=self.log)
        self.assertEqual(asyncio.run(traced()), 2)
        self.assertIsNone(current_recorder())
        self.assertIsNone(current_agent())
        recs = _read(self.log)
        self.assertEqual([r["action"].get("tool") for r in recs], ["lookup", "tool", "acme"])
        self.assertEqual([r["outcome"]["status"] for r in recs], ["ok", "ok", "ok"])

    def test_concurrent_agents_keep_their_own_recorders(self):
        log_b = os.path.join(self.d, "b.jsonl")

        async def agent(name):
            for _ in range(3):
                await asyncio.sleep(0)
                with record_call(None, "step-" + name, {}) as call:
                    call.result = name
            return name

        a = trace(agent, profile="a", log=self.log)
        b = trace(agent, profile="b", log=log_b)

        async def main():
            return await asyncio.gather(a("a"), b("b"))

        self.assertEqual(asyncio.run(main()), ["a", "b"])
        self.assertEqual({r["action"]["tool"] for r in _read(self.log)}, {"step-a", "a"})
        self.assertEqual({r["action"]["tool"] for r in _read(log_b)}, {"step-b", "b"})

    def test_a_cancelled_agent_is_not_recorded_as_ok(self):
        async def agent():
            await asyncio.sleep(10)

        traced = trace(agent, profile="acme", log=self.log)

        async def main():
            task = asyncio.ensure_future(traced())
            await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(main())
        self.assertEqual(_read(self.log)[-1]["outcome"]["status"], "error")

    def test_decorator_form_on_async(self):
        @trace(profile="acme", log=self.log)
        async def agent():
            return "ok"

        self.assertEqual(asyncio.run(agent()), "ok")
        self.assertEqual(_read(self.log)[0]["outcome"]["status"], "ok")


if __name__ == "__main__":
    unittest.main()
