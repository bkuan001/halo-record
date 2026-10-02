"""What the Runtime Report shows for each record: the action (not its result),
gate outcomes, threat flags, the governing fields, UTC-normalized times, the
requested review window, and searchable record ids."""

import json
import os
import re
import tempfile
import unittest

from halo_record.record import Recorder, build
from halo_record.report import render, write_report


def _records(*calls):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "c.jsonl")
    rec = Recorder(path)
    for args, kw in calls:
        rec.append(build(*args, **kw))
    with open(path) as fh:
        return path, [json.loads(l) for l in fh if l.strip()]


def _summary_cells(html):
    body = html[html.index('<tbody id="activity-body">'):html.index("</tbody>")]
    return re.findall(r'<td class="trunc dim">(.*?)</td>', body)


class ReportDisplayTest(unittest.TestCase):
    def test_blocked_and_denied_actions_are_not_described_as_run(self):
        _, recs = _records(
            (("tool_call", "security"), dict(tool="payments.refund", tool_input={"amount": 5},
                                              verification={"status": "blocked"})),
            (("tool_call", "security"), dict(tool="payments.refund", tool_input={"amount": 6},
                                              decision="denied")))
        cells = _summary_cells(render(recs))
        self.assertEqual(len(cells), 2)
        for c in cells:
            self.assertFalse(c.startswith("Ran "), c)
        self.assertTrue(any(c.startswith("Blocked by gate") for c in cells))
        self.assertTrue(any(c.startswith("Denied") for c in cells))

    def test_a_threat_flagged_record_does_not_read_no_flags(self):
        _, recs = _records((("tool_call", "security"),
                            dict(tool="read_email", threats=["prompt_injection_indirect"])))
        body = render(recs)
        body = body[body.index('<tbody id="activity-body">'):body.index("</tbody>")]
        self.assertNotIn("no flags", body)
        self.assertIn("1 threat", body)

    def test_summary_column_describes_the_action_not_its_result(self):
        _, recs = _records((("tool_call", "security"),
                            dict(tool="Bash", tool_input={"command": "rm -rf build"},
                                 outcome={"status": "ok", "summary": "all good"})))
        self.assertEqual(_summary_cells(render(recs)), ["Ran the shell command rm -rf build"])

    def test_record_ids_and_parent_ids_are_searchable(self):
        _, recs = _records((("tool_call", "security"), dict(tool="t", parent_id="p-123")))
        html = render(recs)
        m = re.search(r'data-text="([^"]*)"', html)
        self.assertIn(recs[0]["record_id"].lower(), m.group(1))
        self.assertIn("p-123", m.group(1))

    def test_drawer_shows_the_governing_fields(self):
        from halo_record.report import _PAGINATE_JS
        for label in ("Verification gate", "Threat flags", "Parent action",
                      "On behalf of (human)", "Severity"):
            self.assertIn(label, _PAGINATE_JS)

    def test_times_are_converted_to_utc_and_the_span_sorts_by_instant(self):
        _, recs = _records(
            (("tool_call", "security"), dict(tool="a", ts="2026-06-01T01:00:00+05:00")),
            (("tool_call", "security"), dict(tool="b", ts="2026-05-31T22:00:00Z")))
        html = render(recs)
        period = html[html.index('id="r-period"'):html.index("<!--/r-period-->")]
        # 01:00+05:00 is 20:00Z on the 31st — the earliest instant, though not the earliest text
        self.assertIn("<b>2026-05-31 20:00:00</b> &ndash; <b>2026-05-31 22:00:00</b>", period)
        self.assertIn("2026-05-31 20:00:00", _summary_row_times(html))

    def test_windowed_report_shows_the_requested_window(self):
        from halo_record.export import parse_bound
        path, _ = _records(
            (("tool_call", "security"), dict(tool="a", ts="2026-06-03T10:00:00Z")),
            (("tool_call", "security"), dict(tool="b", ts="2026-06-20T10:00:00Z")))
        html, _ = write_report(path, path + ".html", start=parse_bound("2026-06-01"),
                               end=parse_bound("2026-06-30", end=True))
        self.assertIn("Review window", html)
        self.assertIn("<b>2026-06-01 00:00:00</b> &ndash; <b>2026-06-30 23:59:59</b>", html)
        self.assertIn("Records span", html)


def _summary_row_times(html):
    return " ".join(re.findall(r'<td class="mono dim ts-cell">(.*?)</td>', html))


if __name__ == "__main__":
    unittest.main()
