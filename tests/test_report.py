"""The self-verifying HTML report — records + completeness JS + live-witness config."""

import json
import os
import tempfile
import unittest

from halo_record.anchor import checkpoint
from halo_record.record import Recorder, build
from halo_record.report import _load, _subject_id, render, write_report


def _chain(directory, n=2, subject="acme-corp"):
    rec = Recorder(os.path.join(directory, "c.jsonl"))
    for i in range(n):
        rec.append(build("tool_call", "security", tool="t%d" % i, subject=subject))
    return _load(os.path.join(directory, "c.jsonl"))


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.records = _chain(self.dir)

    def test_embeds_records_and_verification_js(self):
        html = render(self.records)
        self.assertIn('id="records"', html)
        self.assertIn("crypto.subtle", html)  # in-browser self-verification
        self.assertIn("function completeness", html)

    def test_subject_id(self):
        self.assertEqual(_subject_id(self.records), "acme-corp")

    def test_witness_url_embeds_live_config(self):
        html = render(self.records, witness_url="https://witness.halo.dev")
        self.assertIn('id="halo-config"', html)
        self.assertIn("liveCheckpoints", html)
        # config carries the witness URL and the subject the browser fetches by
        cfg = json.loads(_extract(html, "halo-config"))
        self.assertEqual(cfg["witnessUrl"], "https://witness.halo.dev")
        self.assertEqual(cfg["subject"], "acme-corp")

    def test_no_witness_url_means_null_config(self):
        html = render(self.records)
        cfg = json.loads(_extract(html, "halo-config"))
        self.assertIsNone(cfg["witnessUrl"])

    def test_embedded_checkpoints_present(self):
        html = render(self.records, [checkpoint(self.records)])
        self.assertIn('id="checkpoints"', html)
        embedded = json.loads(_extract(html, "checkpoints"))
        self.assertEqual(embedded[0]["count"], 2)


class WriteReportTest(unittest.TestCase):
    def test_write_report_end_to_end(self):
        d = tempfile.mkdtemp()
        _chain(d)
        out = os.path.join(d, "report.html")
        path, count = write_report(os.path.join(d, "c.jsonl"), out)
        self.assertEqual(count, 2)
        self.assertTrue(os.path.exists(out))
        with open(out) as fh:
            self.assertIn('id="records"', fh.read())

    def test_write_report_with_witness_url(self):
        d = tempfile.mkdtemp()
        _chain(d)
        out = os.path.join(d, "report.html")
        write_report(os.path.join(d, "c.jsonl"), out,
                     witness_url="https://witness.halo.dev")
        with open(out) as fh:
            html = fh.read()
        cfg = json.loads(_extract(html, "halo-config"))
        self.assertEqual(cfg["witnessUrl"], "https://witness.halo.dev")


def _extract(html, script_id):
    marker = 'id="%s"' % script_id
    i = html.index(marker)
    start = html.index(">", i) + 1
    end = html.index("</script>", start)
    return html[start:end]


def _dated_chain(directory, days=(5, 10, 20, 25)):
    path = os.path.join(directory, "d.jsonl")
    rec = Recorder(path)
    for i, day in enumerate(days):
        rec.append(build("tool_call", "security", tool="t%d" % i,
                         subject="acme-corp",
                         ts="2026-06-%02dT12:00:00+00:00" % day))
    return path


class MultiAgentReportTest(unittest.TestCase):
    """A vendor often runs several agents against one tenant: the header counts
    and names them, and the activity table grows an Agent column."""

    def _multi_chain(self, directory):
        path = os.path.join(directory, "m.jsonl")
        rec = Recorder(path)
        for i, name in enumerate(["support-bot", "billing-bot", "support-bot"]):
            rec.append(build("tool_call", "security", tool="t%d" % i,
                             subject="acme-corp", agent={"id": name, "name": name}))
        return _load(path)

    def test_multi_agent_header_and_column(self):
        d = tempfile.mkdtemp()
        html = render(self._multi_chain(d))
        self.assertIn("2 agents:", html)
        self.assertIn("<b>support-bot</b>", html)
        self.assertIn("<b>billing-bot</b>", html)
        self.assertIn("<th>Agent</th>", html)

    def test_single_agent_report_unchanged(self):
        d = tempfile.mkdtemp()
        records = _chain(d)  # single (default) agent
        html = render(records)
        self.assertNotIn("<th>Agent</th>", html)
        self.assertNotIn("agents:", html)


class WindowedReportTest(unittest.TestCase):
    """--from/--to render a date-windowed report: window records only, anchored
    in-browser verification, full-chain verification at generation."""

    def setUp(self):
        from halo_record.export import parse_bound
        self.parse_bound = parse_bound
        self.dir = tempfile.mkdtemp()
        self.log = _dated_chain(self.dir)

    def _write(self, **kw):
        out = os.path.join(self.dir, "w.html")
        write_report(self.log, out, **kw)
        with open(out, encoding="utf-8") as fh:
            return fh.read()

    def test_window_embeds_only_window_records(self):
        html = self._write(start=self.parse_bound("2026-06-10", end=False),
                           end=self.parse_bound("2026-06-20", end=True))
        recs = json.loads(_extract(html, "records"))
        self.assertEqual(len(recs), 2)
        self.assertTrue(recs[0]["ts"].startswith("2026-06-10"))
        self.assertTrue(recs[1]["ts"].startswith("2026-06-20"))
        embedded = _extract(html, "records")
        self.assertNotIn("2026-06-05", embedded)  # out-of-window never enters the page
        self.assertNotIn("2026-06-25", embedded)

    def test_window_anchor_seeds_browser_verification(self):
        full = _load(self.log)
        html = self._write(start=self.parse_bound("2026-06-10", end=False),
                           end=self.parse_bound("2026-06-20", end=True))
        anchor = full[0]["integrity"]["hash"]  # chain head immediately before the window
        self.assertIn('const GENESIS = "%s"' % anchor, html)
        self.assertIn('"first":2', html)
        self.assertIn('"last":3', html)
        self.assertIn('"total":4', html)
        self.assertIn("Date-windowed report", html)

    def test_full_report_unchanged(self):
        html = self._write()
        self.assertIn("const WINDOW = null;", html)
        self.assertNotIn("Date-windowed report", html)

    def test_window_from_genesis_uses_genesis_anchor(self):
        from halo_record.canon import GENESIS_PREV
        html = self._write(end=self.parse_bound("2026-06-10", end=True))
        self.assertIn('const GENESIS = "%s"' % GENESIS_PREV, html)
        recs = json.loads(_extract(html, "records"))
        self.assertEqual(len(recs), 2)

    def test_empty_window_renders_disclosure(self):
        html = self._write(start=self.parse_bound("2026-07-01", end=False))
        recs = json.loads(_extract(html, "records"))
        self.assertEqual(recs, [])
        self.assertIn("fall in this window", html)

    def test_windowed_report_refused_on_tampered_chain(self):
        records = _load(self.log)
        records[1]["action"]["tool"] = "Tampered"
        with open(self.log, "w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r, separators=(",", ":")) + "\n")
        with self.assertRaises(ValueError):
            self._write(start=self.parse_bound("2026-06-10", end=False))


if __name__ == "__main__":
    unittest.main()
