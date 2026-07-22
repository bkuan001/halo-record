"""Concurrent appends must keep the chain intact — agents call tools in
parallel (LangChain runs tools in threads), so Recorder.append serializes.
Hook-style capture goes further: each tool call spawns its own short-lived
process, so appends must also serialize ACROSS processes."""

import multiprocessing
import os
import tempfile
import threading
import unittest

from halo_record import Recorder, build
from halo_record.verify import verify_log


def _proc_worker(path, worker_id, n):
    rec = Recorder(path)
    for i in range(n):
        rec.append(build("tool_call", "security",
                         tool="p%d-%d" % (worker_id, i), tool_input={"i": i}))


class TestConcurrentAppend(unittest.TestCase):
    def test_parallel_appends_keep_chain_intact(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.jsonl")
            rec = Recorder(path)

            def worker(i):
                rec.append(build("tool_call", "security",
                                 tool="t%d" % i, tool_input={"i": i}))

            threads = [threading.Thread(target=worker, args=(i,))
                       for i in range(50)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            with open(path, "r", encoding="utf-8") as fh:
                lines = [ln for ln in fh.read().splitlines() if ln.strip()]
            self.assertEqual(len(lines), 50)
            self.assertTrue(verify_log(path, out=lambda *a, **k: None))

    def test_last_hash_cached_across_appends_and_fresh_instance(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.jsonl")
            r1 = Recorder(path)
            for i in range(3):
                r1.append(build("tool_call", "security", tool="a%d" % i))

            # a fresh instance must pick up the existing chain head from disk
            r2 = Recorder(path)
            r2.append(build("tool_call", "security", tool="b"))
            self.assertTrue(verify_log(path, out=lambda *a, **k: None))

    def test_interleaved_instances_do_not_fork_the_chain(self):
        # Two Recorder instances on the same file model two hook processes:
        # each caches its own head, so an append by one must invalidate the
        # other's cache — otherwise the chain forks at the stale head.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.jsonl")
            r1, r2 = Recorder(path), Recorder(path)
            for i in range(4):
                r1.append(build("tool_call", "security", tool="r1-%d" % i))
                r2.append(build("tool_call", "security", tool="r2-%d" % i))
            with open(path, "r", encoding="utf-8") as fh:
                lines = [ln for ln in fh.read().splitlines() if ln.strip()]
            self.assertEqual(len(lines), 8)
            self.assertTrue(verify_log(path, out=lambda *a, **k: None))

    def test_parallel_processes_keep_chain_intact(self):
        # The real hook shape: separate processes appending simultaneously.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.jsonl")
            procs = [multiprocessing.Process(target=_proc_worker, args=(path, w, 10))
                     for w in range(4)]
            for p in procs:
                p.start()
            for p in procs:
                p.join()
            self.assertTrue(all(p.exitcode == 0 for p in procs))
            with open(path, "r", encoding="utf-8") as fh:
                lines = [ln for ln in fh.read().splitlines() if ln.strip()]
            self.assertEqual(len(lines), 40)
            self.assertTrue(verify_log(path, out=lambda *a, **k: None))


if __name__ == "__main__":
    unittest.main()
