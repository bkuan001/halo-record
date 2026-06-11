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


if __name__ == "__main__":
    unittest.main()
