"""trace(): one-import instrumentation — boundary + ambient recorder binding."""

import json
import os
import tempfile
import unittest

from halo_record import trace, record, record_call, current_recorder
from halo_record.verify import verify_log


def _silent(*_a, **_k):
    pass


def _read(path):
    with open(path) as fh:
        return [json.loads(l) for l in fh if l.strip()]


class TraceTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "agent.jsonl")

    def test_returns_result_unchanged_and_records_boundary(self):
        def run(x):
            return {"answer": x * 2}

        agent = trace(run, profile="acme", log=self.log)
        self.assertEqual(agent(21), {"answer": 42})

        recs = _read(self.log)
        self.assertEqual(len(recs), 1)  # boundary only
        self.assertEqual(recs[0]["action"]["type"], "agent_message")
        self.assertEqual(recs[0]["outcome"]["status"], "ok")
        self.assertTrue(verify_log(self.log, out=_silent))

    def test_inner_record_lands_on_bound_chain(self):
        @record(category="security", scope="db.read")
        def search(q):
            return {"rows": 1}

        def run(q):
            return search(q)

        agent = trace(run, profile="acme", log=self.log)
        agent("select 1")

        recs = _read(self.log)
        # inner tool call + outer boundary, same chain, in order
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0]["action"]["tool"], "search")
        self.assertEqual(recs[1]["action"]["type"], "agent_message")
        self.assertTrue(verify_log(self.log, out=_silent))

    def test_record_call_uses_active_recorder(self):
        def run():
            with record_call(tool="net", tool_input={"u": "x"}) as call:
                call.result = {"ok": True}
            return "done"

        agent = trace(run, profile="acme", log=self.log)
        self.assertEqual(agent(), "done")
        recs = _read(self.log)
        self.assertEqual(recs[0]["action"]["tool"], "net")

    def test_error_is_recorded_then_reraised(self):
        def run():
            raise ValueError("boom")

        agent = trace(run, profile="acme", log=self.log)
        with self.assertRaises(ValueError):
            agent()
        recs = _read(self.log)
        self.assertEqual(recs[-1]["outcome"]["status"], "error")
        self.assertTrue(verify_log(self.log, out=_silent))

    def test_active_recorder_unbound_after_call(self):
        def run():
            self.assertIsNotNone(current_recorder())
            return 1

        agent = trace(run, profile="acme", log=self.log)
        agent()
        self.assertIsNone(current_recorder())

    def test_decorator_form(self):
        @trace(profile="acme", log=self.log)
        def run(x):
            return x

        self.assertEqual(run(5), 5)
        self.assertEqual(len(_read(self.log)), 1)

    def test_dir_routes_per_subject(self):
        agent = trace(lambda: "ok", profile="acme", dir=self.dir, subject="acme-corp")
        agent()
        self.assertTrue(os.path.exists(os.path.join(self.dir, "acme-corp.jsonl")))

    def test_halo_shim_exposes_trace(self):
        import halo
        self.assertIs(halo.trace, trace)


if __name__ == "__main__":
    unittest.main()
