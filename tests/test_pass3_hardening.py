"""Regression tests for the third adversarial pass."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from halo_record.anchor import Notary, checkpoint, verify_completeness
from halo_record.canon import GENESIS_PREV, compute_hash
from halo_record.export import parse_bound
from halo_record.record import Recorder, TenantRecorder, build
from halo_record.report import _VERIFY_JS, write_report


def _chain(path, n, subject="acme-corp"):
    rec = Recorder(path)
    return [rec.append(build("tool_call", "security", tool="t%d" % i, subject=subject,
                             ts="2026-09-%02dT12:00:00+00:00" % (i + 1))) for i in range(n)]


def _reseal(recs):
    prev = GENESIS_PREV
    for r in recs:
        r["integrity"]["prev_hash"] = prev
        r["integrity"]["hash"] = compute_hash(r, prev)
        prev = r["integrity"]["hash"]
    return recs


def _write(path, recs):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in recs))


class WindowedCompletenessTest(unittest.TestCase):
    def test_windowed_report_refuses_a_chain_the_witness_contradicts(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        recs = _chain(log, 20)
        wlog = os.path.join(d, "w.jsonl")
        Notary(wlog).record_checkpoint(checkpoint(recs[:5]))
        Notary(wlog).record_checkpoint(checkpoint(recs[:10]))
        dropped = _reseal([r for i, r in enumerate(recs) if i != 2])
        _write(log, dropped)
        with self.assertRaises(ValueError):
            write_report(log, os.path.join(d, "w.html"), witness_log=wlog,
                         start=parse_bound("2026-09-12", end=False),
                         end=parse_bound("2026-09-20", end=True))


class PageCompletenessRobustnessTest(unittest.TestCase):
    def test_no_spread_or_apply_over_checkpoint_lists(self):
        self.assertNotIn("Math.max.apply", _VERIFY_JS)

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_page_rejects_userinfo_witness_urls(self):
        page = _VERIFY_JS % {"genesis": json.dumps(GENESIS_PREV), "window_json": "null"}
        funcs = page[:page.index("function completeness(")]
        script = funcs + "\nconsole.log(JSON.stringify([witnessBase('https://witness.example@evil.example'), witnessBase('https://witness.example/')]));"
        js = os.path.join(tempfile.mkdtemp(), "w.mjs")
        open(js, "w").write(script)
        out = json.loads(subprocess.run(["node", js], capture_output=True, text=True).stdout)
        self.assertIsNone(out[0])
        self.assertEqual(out[1], "https://witness.example")


class PinnedSubjectEveryRecordTest(unittest.TestCase):
    def test_report_refuses_when_any_record_has_another_subject(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        rec = Recorder(log)
        rec.append(build("tool_call", "security", tool="a", subject="acme"))
        for _ in range(3):
            rec.append(build("tool_call", "security", tool="b", subject="globex-secret"))
        with self.assertRaises(ValueError):
            write_report(log, os.path.join(d, "r.html"), expected_subject="acme")

    def test_completeness_pin_checks_every_record(self):
        d = tempfile.mkdtemp()
        rec = Recorder(os.path.join(d, "c.jsonl"))
        recs = [rec.append(build("tool_call", "security", tool="a", subject="acme"))]
        recs.append(rec.append(build("tool_call", "security", tool="b", subject="globex")))
        self.assertIs(verify_completeness(recs, [], expected_subject="acme")["ok"], False)


class LoneSurrogateReportTest(unittest.TestCase):
    def test_a_verifiable_chain_with_a_split_emoji_can_be_reported(self):
        src = os.path.join(os.path.dirname(__file__), "fixtures", "differential", "lone_surrogate.jsonl")
        html, n = write_report(src, os.path.join(tempfile.mkdtemp(), "r.html"))
        self.assertEqual(n, 3)


class CollidedLegacyTenantTest(unittest.TestCase):
    def test_a_collided_legacy_file_does_not_raise_into_the_agent(self):
        d = tempfile.mkdtemp()
        legacy = os.path.join(d, "acme_a.jsonl")
        Recorder(legacy).append(build("tool_call", "security", tool="x", subject="acme/a"))
        Recorder(legacy).append(build("tool_call", "security", tool="y", subject="acme_a"))
        tr = TenantRecorder(d)
        r = tr.append(build("tool_call", "security", tool="z", subject="acme_a"))
        self.assertEqual(r["subject"]["id"], "acme_a")


if __name__ == "__main__":
    unittest.main()
