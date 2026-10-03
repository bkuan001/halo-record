"""The activity table opens in UTC, the frame the period line and the static
HTML use, so the rows and the "Records span ... UTC" line agree; local time is
one click away and labeled with the viewer's zone when shown."""

import os
import re
import tempfile
import unittest

from halo_record.record import Recorder, build
from halo_record.report import write_report


class TimeLabelTest(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        Recorder(log).append(build("tool_call", "security", tool="t", ts="2026-06-01T10:00:00+02:00"))
        self.html, _ = write_report(log, os.path.join(d, "r.html"))

    def test_table_starts_in_utc(self):
        self.assertRegex(self.html, r"var localMode = false;")
        self.assertIn('id="tz-toggle" class="f-btn">Show local time</button>', self.html)
        self.assertIn('id="th-time" data-sort="data-ts" data-active="desc">Time (UTC)</th>', self.html)
        self.assertIn('<span class="period-tz">UTC</span>', self.html)
        body = self.html[self.html.index('<tbody id="activity-body">'):]
        body = body[:body.index("</tbody>")]
        cells = re.findall(r'<td class="mono dim ts-cell">(.*?)</td>', body)
        self.assertEqual(cells, ["2026-06-01 08:00:00"])


if __name__ == "__main__":
    unittest.main()
