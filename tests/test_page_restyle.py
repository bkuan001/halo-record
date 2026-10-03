"""A Runtime Report edited only in its static HTML can restyle the regions its
scripts write to. The page withholds its verdict for the restyles it can
detect from computed layout (the region, or an ancestor, is not displayed,
has no area, sits off the page, is clipped, masked, filtered, flattened by a
transform, skipped by content-visibility, or is hidden later by an animation
or transition). It cannot detect every restyle, so the badge states only what
its scripts did, and LIMITS.md says the JSONL plus ``halo verify`` is the
evidence.

The restyles exercised in headless Chrome below are the ones the page is
expected to catch; restyles it does not catch are listed in LIMITS.md and are
not claimed here."""

import os
import re
import unittest

from tests.test_page_decoy_ids import CHROME, _FAKE, _chrome_dom, _report, _verdicts

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_FAKE_TBODY = "<tbody>" + _FAKE + "</tbody>"


def _restyle(html, css, fake_in_table=False):
    """Add one style rule and fabricated rows; scripts and records untouched."""
    if fake_in_table:
        # A second, fabricated tbody in the same table, after the verified one.
        html = html.replace("</tbody>", "</tbody>" + _FAKE_TBODY, 1)
    else:
        html = html.replace("</body>", "<table>" + _FAKE_TBODY + "</table></body>", 1)
    return html.replace("</head>", "<style>" + css + "</style></head>", 1)


class BadgeWordingTest(unittest.TestCase):
    SENTENCE = ("This page's scripts re-rendered the table and summary from the verified "
                "records; the page's styling and any added content are not checked &mdash; "
                "run <span class='mono'>halo verify</span> on the JSONL for evidence.")

    def test_badge_states_only_what_the_scripts_did(self):
        html = _report()
        # The sentence is built from adjacent string literals in the page script.
        joined = re.sub(r'"\s*\+\s*"', "", html)
        self.assertIn(self.SENTENCE, joined)
        self.assertNotIn("counts and table below were", html)

    def test_limits_says_a_vendor_page_can_be_restyled(self):
        with open(os.path.join(ROOT, "LIMITS.md"), encoding="utf-8") as fh:
            limits = " ".join(fh.read().split())
        self.assertIn("A vendor-supplied report page can be restyled to mislead", limits)
        self.assertIn("The JSONL and `halo verify` are the evidence", limits)


_CAUGHT = {
    "activity_body_display_none": ("#activity-body{display:none}", True),
    "activity_body_rows_display_none": ("#activity-body tr{display:none}", True),
    "offscreen_left": ("#tablewrap{position:absolute;left:-99999px}", False),
    "clip_path": ("#tablewrap{clip-path:inset(50%)}", False),
    "transform_scale0": ("#tablewrap{transform:scale(0)}", False),
    "height0_overflow": ("#tablewrap{height:0;max-height:0;overflow:hidden}", False),
    "filter_opacity0": ("#tablewrap{filter:opacity(0)}", False),
    "content_visibility": ("#tablewrap{content-visibility:hidden}", False),
    "mask_image": ("#tablewrap{-webkit-mask-image:linear-gradient(transparent,transparent);"
                   "mask-image:linear-gradient(transparent,transparent)}", False),
    "ancestor_filter": (".wrap{filter:opacity(0)}", False),
    "delayed_animation": ("@keyframes halohide{to{visibility:hidden}}"
                          "#tablewrap{animation:halohide .01s 1.5s forwards}", False),
}


@unittest.skipUnless(CHROME, "Google Chrome not installed")
class RestyleInHeadlessChromeTest(unittest.TestCase):
    def _assert_withheld(self, name):
        css, in_table = _CAUGHT[name]
        dom = _chrome_dom(_restyle(_report(), css, in_table))
        verdicts = _verdicts(dom)
        self.assertTrue(verdicts, dom[:500])
        for cls, text in verdicts:
            self.assertNotIn("ok", cls, "%s: %s" % (name, text[:300]))
            self.assertNotIn("Verified in your browser", text, name)


def _make(name):
    def test(self):
        self._assert_withheld(name)
    test.__name__ = "test_withheld_" + name
    return test


for _name in _CAUGHT:
    setattr(RestyleInHeadlessChromeTest, "test_withheld_" + _name, _make(_name))


@unittest.skipUnless(CHROME, "Google Chrome not installed")
class RestyleNoFalseAlarmTest(unittest.TestCase):
    def test_long_report_still_verifies(self):
        dom = _chrome_dom(_report(n=150))
        (cls, text), = _verdicts(dom)
        self.assertIn("ok", cls, text[:300])

    def test_record_text_with_markup_like_strings_still_verifies(self):
        dom = _chrome_dom(_report(subject='id="verdict" <div id="rowcount">'))
        (cls, text), = _verdicts(dom)
        self.assertIn("ok", cls, text[:300])


if __name__ == "__main__":
    unittest.main()
