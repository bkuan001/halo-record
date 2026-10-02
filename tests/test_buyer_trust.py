"""Adversarial regression tests for what a buyer sees: a report, policy
verdict, or verification must never read as passing on a chain the verifier
rejects, and chain data must never become script in the page."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from halo_record.canon import GENESIS_PREV, compute_hash
from halo_record.export import parse_bound
from halo_record.record import Recorder, build
from halo_record.report import render, write_report
from halo_record.verify import verify_log


def _chain(path, n=5):
    rec = Recorder(path)
    return [rec.append(build("tool_call", "security", tool="t%d" % i, subject="acme",
                             ts="2026-06-%02dT12:00:00+00:00" % (i + 1))) for i in range(n)]


def _write(path, records):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records))


class WindowedReportTruncationTest(unittest.TestCase):
    def test_head_truncated_chain_is_refused(self):
        d = tempfile.mkdtemp()
        full = os.path.join(d, "full.jsonl")
        recs = _chain(full)
        cut = os.path.join(d, "cut.jsonl")
        _write(cut, recs[2:])  # first two records dropped
        self.assertFalse(verify_log(cut, out=lambda *_: None))
        with self.assertRaises(ValueError):
            write_report(cut, os.path.join(d, "w.html"),
                         start=parse_bound("2026-01-01", end=False),
                         end=parse_bound("2026-12-31", end=True))

    def test_mid_chain_window_on_an_intact_chain_still_renders(self):
        d = tempfile.mkdtemp()
        full = os.path.join(d, "full.jsonl")
        _chain(full)
        html, n = write_report(full, os.path.join(d, "w.html"),
                               start=parse_bound("2026-06-03", end=False),
                               end=parse_bound("2026-06-05", end=True))
        self.assertEqual(n, 3)


class PolicyOnBrokenChainTest(unittest.TestCase):
    def _broken(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        recs = _chain(log, 3)
        recs[1]["action"]["tool"] = "edited-after-sealing"
        _write(log, recs)
        pol = os.path.join(d, "p.json")
        with open(pol, "w") as fh:
            json.dump([{"id": "r1", "match": {"category": "security"},
                        "require": {"category": "security"}}], fh)
        return log, pol

    def test_policy_is_not_compliant_on_a_broken_chain(self):
        from halo_record.policy import evaluate_log
        log, pol = self._broken()
        result = evaluate_log(log, pol)
        self.assertFalse(result["chain_verified"])
        self.assertFalse(result["compliant"])

    def test_policy_cli_exits_nonzero_on_a_broken_chain(self):
        log, pol = self._broken()
        env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
        p = subprocess.run([sys.executable, "-m", "halo_record.cli", "policy", log, pol],
                           capture_output=True, text=True, env=env)
        self.assertNotEqual(p.returncode, 0, p.stdout)
        self.assertIn("NON-ATTESTABLE", p.stdout)


class DuplicateRecordIdTest(unittest.TestCase):
    def _dup(self):
        d = tempfile.mkdtemp()
        recs, prev, rid = [], GENESIS_PREV, None
        for tool in ("read_faq", "drop_production_db"):
            r = build("tool_call", "security", tool=tool, subject="acme")
            rid = rid or r["record_id"]
            r["record_id"] = rid
            r["integrity"]["prev_hash"] = prev
            r["integrity"]["hash"] = compute_hash(r, prev)
            prev = r["integrity"]["hash"]
            recs.append(r)
        log = os.path.join(d, "c.jsonl")
        _write(log, recs)
        return log, recs

    def test_verify_rejects_duplicate_record_ids(self):
        log, _ = self._dup()
        self.assertFalse(verify_log(log, out=lambda *_: None))

    def test_render_refuses_duplicate_record_ids(self):
        _, recs = self._dup()
        with self.assertRaises(ValueError):
            render(recs)


class ReportScriptHygieneTest(unittest.TestCase):
    def test_drawer_and_banner_treat_chain_data_as_untrusted(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        _chain(log, 2)
        html, _ = write_report(log, os.path.join(d, "r.html"))
        self.assertIn("Array.isArray(r.findings)", html)
        self.assertNotIn("+ f.length +", html)
        self.assertIn("cleanCheckpoints(", html)
        self.assertIn("witnessBase(", html)


if __name__ == "__main__":
    unittest.main()


class ReportVerifiesWholeChainTest(unittest.TestCase):
    FIX = os.path.join(os.path.dirname(__file__), "fixtures", "differential")

    def test_non_windowed_report_refuses_a_chain_verify_rejects(self):
        for name in ("float.jsonl", "big_int.jsonl", "dup_id.jsonl", "float_lexeme.jsonl"):
            with self.subTest(fixture=name):
                with self.assertRaises(ValueError):
                    write_report(os.path.join(self.FIX, name), os.path.join(tempfile.mkdtemp(), "r.html"))

    def test_embedded_policy_is_non_attestable_when_the_chain_is_broken(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        recs = _chain(log, 5)
        recs[0]["action"]["tool"] = "edited-after-sealing"  # break outside the window
        _write(log, recs)
        pol = os.path.join(d, "p.json")
        with open(pol, "w") as fh:
            json.dump([{"id": "r1", "match": {"category": "security"},
                        "require": {"category": "security"}}], fh)
        html, _ = write_report(log, os.path.join(d, "r.html"), policy_path=pol,
                               start=parse_bound("2026-06-03", end=False),
                               end=parse_bound("2026-06-05", end=True))
        self.assertIn("NON-ATTESTABLE", html)
        self.assertNotIn(">COMPLIANT<", html)

    def test_window_must_link_to_the_record_before_it(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        recs = _chain(log, 4)
        prev = "ab" * 32  # fabricated anchor for records 3-4
        for r in recs[2:]:
            r["integrity"]["prev_hash"] = prev
            r["integrity"]["hash"] = compute_hash(r, prev)
            prev = r["integrity"]["hash"]
        _write(log, recs)
        with self.assertRaises(ValueError):
            write_report(log, os.path.join(d, "w.html"),
                         start=parse_bound("2026-06-03", end=False),
                         end=parse_bound("2026-06-04", end=True))
