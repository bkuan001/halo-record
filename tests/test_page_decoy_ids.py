"""A Runtime Report edited only in its static HTML (scripts and records
untouched) must not show the verified badge over content the verifier did not
write. Two cheap edits did that: repeating an element id the scripts write to
(a hidden copy placed first takes the verified content, the visible copy keeps
fabricated rows), and hiding the regions the scripts write to with page CSS.
The page withholds in both cases, and the badge sentence is scoped to what its
scripts re-rendered.

The page scripts run under Node against a stand-in DOM (tests/
test_report_table_js.py) and, where Google Chrome is installed, in headless
Chrome against the real DOM and CSS."""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

from halo_record.record import Recorder, build
from halo_record.report import write_report

from tests.test_report_table_js import NODE, _run

CHROME = next((p for p in (
    os.environ.get("HALO_TEST_CHROME"),
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    shutil.which("google-chrome"), shutil.which("chromium"), shutil.which("chromium-browser"),
) if p and os.path.exists(p)), None)

_DECOY = ('<div style="display:none"><table><tbody id="activity-body"></tbody></table>'
          '<div id="r-cards"></div><div id="r-h1"></div><div id="rowcount"></div></div>')
_FAKE = ('<tr data-ts="2030-01-01T00:00:00+00:00" data-tool="DECOYTOOL" data-type="tool_call" '
         'data-sev="INFO" data-status="ok" data-flags="0" data-rid="x" data-text="decoy">'
         '<td>DECOY-FAKE-ROW wire $1M</td></tr>')


def _report(n=3, subject="acme"):
    d = tempfile.mkdtemp()
    log = os.path.join(d, "c.jsonl")
    open(log, "a").close()
    rec = Recorder(log)
    for i in range(n):
        rec.append(build("tool_call", "security", tool="t%d" % i, subject=subject))
    html, _ = write_report(log, os.path.join(d, "r.html"))
    return html


def _decoy(html):
    html = html.replace("<body>", "<body>" + _DECOY, 1)
    return html.replace('<tbody id="activity-body">', '<tbody id="activity-body">' + _FAKE, 2)


def _css_hidden(html):
    hide = ("<style>#tablewrap,#completeness{display:none}</style>"
            "<div class='verdict neutral'>&#10003; COMPLETE &mdash; independently witnessed</div>"
            "<table><tbody>" + _FAKE + "</tbody></table>")
    return html.replace("</body>", hide + "</body>", 1)


class BadgeSentenceTest(unittest.TestCase):
    def test_badge_names_what_the_scripts_rerendered_and_points_at_the_jsonl(self):
        html = _report()
        self.assertNotIn("counts and table below were re-rendered from these verified records.", html)
        self.assertIn("This page's scripts re-rendered the table and summary from the verified ", html)
        self.assertIn("the page's styling and any added content are not checked", html)
        self.assertIn("halo verify</span> on the JSONL for evidence.", html)

    def test_generated_pages_carry_unique_ids(self):
        for html in (_report(), _report(n=0), _report(n=150)):
            markup = re.sub(r"<script>.*?</script>", "", html, flags=re.S)   # page code
            markup = re.sub(r'(<script id="[^"]+" type="application/json">).*?(</script>)',
                            r"\1\2", markup, flags=re.S)
            ids = re.findall(r'\bid="([^"]+)"', markup)
            dups = sorted({i for i in ids if ids.count(i) > 1})
            self.assertEqual(dups, [])


@unittest.skipUnless(NODE, "node not installed")
class RepeatedIdWithheldNodeTest(unittest.TestCase):
    def test_repeated_bound_ids_withhold_the_verdict(self):
        out = _run(_decoy(_report()), ["observe", "filter"])
        self.assertIn("fail", out["verdict"])
        self.assertTrue(out["verdicts"])
        for v in out["verdicts"]:
            self.assertNotIn("ok", v["cls"].split())
            self.assertNotIn("Verified in your browser", v["html"])
        self.assertIn("activity-body", out["verdicts"][0]["html"])

    def test_a_repeated_verdict_id_gets_the_failure_in_every_copy(self):
        html = _report().replace("<body>", '<body><div id="verdict" class="verdict ok">'
                                 '&#10003; Verified in your browser</div>', 1)
        out = _run(html)
        self.assertEqual(len(out["verdicts"]), 2)
        for v in out["verdicts"]:
            self.assertIn("fail", v["cls"])
            self.assertNotIn("Verified in your browser", v["html"])

    def test_unedited_page_still_verifies(self):
        out = _run(_report(), ["observe"])
        self.assertIn("ok", out["verdict"])


def _chrome_dom(html):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "page.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    # Chrome can print the DOM and then stay running, so read until the
    # document ends (or a deadline passes) and stop the whole process group.
    import signal
    import threading
    proc = subprocess.Popen(
        [CHROME, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
         "--user-data-dir=" + os.path.join(d, "prof"), "--virtual-time-budget=8000",
         "--dump-dom", "file://" + path],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    chunks, done = [], threading.Event()

    def pump():
        for line in iter(proc.stdout.readline, b""):
            chunks.append(line)
            if line.rstrip().endswith(b"</html>"):
                break
        done.set()

    threading.Thread(target=pump, daemon=True).start()
    done.wait(90)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass
    proc.wait(10)
    proc.stdout.close()
    return b"".join(chunks).decode("utf-8", "replace")


def _verdicts(dom):
    out = []
    for m in re.finditer(r'<div([^>]*\bid="verdict"[^>]*)>(.*?)</div>', dom, re.S):
        cls = re.search(r'class="([^"]*)"', m.group(1))
        out.append(((cls.group(1) if cls else "").split(), m.group(2)))
    return out


@unittest.skipUnless(CHROME, "Google Chrome not installed")
class DecoyInHeadlessChromeTest(unittest.TestCase):
    def test_unedited_page_verifies(self):
        dom = _chrome_dom(_report())
        (cls, text), = _verdicts(dom)
        self.assertIn("ok", cls, text[:300])

    def test_empty_chain_page_is_not_withheld(self):
        dom = _chrome_dom(_report(n=0))
        (cls, text), = _verdicts(dom)
        self.assertIn("0 records", text)

    def test_repeated_id_decoy_is_withheld(self):
        dom = _chrome_dom(_decoy(_report()))
        verdicts = _verdicts(dom)
        self.assertTrue(verdicts, dom[:500])
        for cls, text in verdicts:
            self.assertNotIn("ok", cls, text[:300])
            self.assertNotIn("Verified in your browser", text)
        self.assertIn("activity-body", verdicts[0][1])
        self.assertIn("Withheld", dom)

    def test_css_hidden_regions_are_withheld(self):
        dom = _chrome_dom(_css_hidden(_report()))
        (cls, text), = _verdicts(dom)
        self.assertIn("fail", cls, text[:300])
        self.assertNotIn("Verified in your browser", text)


if __name__ == "__main__":
    unittest.main()
