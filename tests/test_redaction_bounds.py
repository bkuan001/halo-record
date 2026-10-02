"""Redaction stays linear on hostile text: a tool response is untrusted, and the
recorder runs inside the agent, so masking must finish quickly however the
text is shaped."""

import time
import unittest

from halo_record.record import build
from halo_record.redact import redact_text, scan


def _elapsed(fn):
    t = time.perf_counter()
    fn()
    return time.perf_counter() - t


class ConnectionStringMaskBoundTest(unittest.TestCase):
    HOSTILE = [
        "redis://" * 30000,               # 240 KB of repeated scheme prefixes
        "redis://a:" * 24000,             # user:pass shape with no "@"
        "postgres://u:" + "p" * 240000,   # one long password with no "@"
    ]

    def test_redact_and_scan_are_bounded(self):
        for text in self.HOSTILE:
            self.assertLess(_elapsed(lambda: redact_text(text)), 0.5, text[:20])
            self.assertLess(_elapsed(lambda: scan(text)), 0.5, text[:20])

    def test_outcome_summary_of_240kb_is_bounded(self):
        for text in self.HOSTILE:
            took = _elapsed(lambda: build(
                "tool_call", "security", tool="t",
                outcome={"status": "ok", "summary": text}))
            self.assertLess(took, 0.5, text[:20])

    def test_tool_input_of_240kb_is_bounded(self):
        for text in self.HOSTILE:
            took = _elapsed(lambda: build(
                "tool_call", "security", tool="t", tool_input={"q": text}))
            self.assertLess(took, 0.5, text[:20])


if __name__ == "__main__":
    unittest.main()
