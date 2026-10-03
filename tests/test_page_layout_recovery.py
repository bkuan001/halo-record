"""The page's layout check withholds the verdict once a region its scripts
write to is hidden, and keeps withholding for the life of the page. A viewport
that is briefly tiny or collapsed (an iframe or preview pane shrunk to a few
pixels, a frame loaded at zero height or hidden, a nearly-closed window) says
nothing about what the reader is shown, so the check waits while the viewport
is under 100 px or the document is hidden, and runs once it can show the
regions. A region hidden in a normal-size viewport, even for part of an
animation cycle, keeps the page at "Not verified".

Runs in headless Chrome, where installed."""

import json
import os
import re
import signal
import subprocess
import tempfile
import threading
import unittest

from tests.test_page_decoy_ids import CHROME, _report, _verdicts


def _chrome(files, entry, size="1200,900", budget=12000, extra=()):
    d = tempfile.mkdtemp()
    for name, html in files.items():
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(html)
    proc = subprocess.Popen(
        [CHROME, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
         "--user-data-dir=" + os.path.join(d, "prof"), "--virtual-time-budget=%d" % budget,
         "--window-size=" + size] + list(extra) + ["--dump-dom", "file://" + os.path.join(d, entry)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    chunks, done = [], threading.Event()

    def pump():
        for line in iter(proc.stdout.readline, b""):
            chunks.append(line)
            if line.rstrip().endswith(b"</html>"):
                break
        done.set()

    threading.Thread(target=pump, daemon=True).start()
    done.wait(120)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass
    proc.wait(10)
    proc.stdout.close()
    return b"".join(chunks).decode("utf-8", "replace")


_SNAP = ("function haloSnap(doc, tag){var v=doc.getElementById('verdict');"
         "var c=doc.getElementById('rowcount');"
         "var a=JSON.parse(document.documentElement.getAttribute('data-p')||'[]');"
         "a.push([tag, v ? v.className : 'none', v ? v.textContent.slice(0, 120) : '',"
         " c ? c.textContent.slice(0, 120) : '']);"
         "document.documentElement.setAttribute('data-p', JSON.stringify(a));}")


def _snaps(dom):
    m = re.search(r'data-p="([^"]*)"', dom)
    if not m:
        return None
    return {tag: rest for tag, *rest in json.loads(m.group(1).replace("&quot;", '"')
                                                   .replace("&amp;", "&"))}


def _in_frame(start_style, toggles, at=9000):
    """A parent page framing r.html, restyling the frame at the given times
    and recording the framed verdict at each time in ``at``."""
    js = "".join("setTimeout(function(){document.getElementById('f').setAttribute('style',%s)},%d);"
                 % (json.dumps(s), t) for t, s in toggles)
    snaps = "".join("setTimeout(function(){haloSnap(document.getElementById('f').contentDocument,%s)},%d);"
                    % (json.dumps(tag), t) for tag, t in at)
    return ("<!doctype html><html><body><iframe id=f src='r.html' style='%s'></iframe>"
            "<script>%s%s%s</script></body></html>" % (start_style, _SNAP, js, snaps))


def _in_page(html, steps, at):
    """``html`` with a script that runs each step's JS at its time and records
    the verdict at each time in ``at``."""
    js = "".join("setTimeout(function(){%s},%d);" % (code, t) for t, code in steps)
    snaps = "".join("setTimeout(function(){haloSnap(document,%s)},%d);" % (json.dumps(tag), t)
                    for tag, t in at)
    return html.replace("</body>", "<script>%s%s%s</script></body>" % (_SNAP, js, snaps), 1)


@unittest.skipUnless(CHROME, "Google Chrome not installed")
class FramedReportTest(unittest.TestCase):
    X = ["--allow-file-access-from-files"]

    def _final(self, start, toggles):
        dom = _chrome({"r.html": _report(), "page.html": _in_frame(start, toggles,
                                                                   at=[("final", 9000)])},
                      "page.html", budget=12000, extra=self.X)
        snaps = _snaps(dom)
        self.assertIsNotNone(snaps, dom[:300])
        return snaps["final"]

    def assertVerified(self, snap):
        cls, text, _count = snap
        self.assertIn("ok", cls.split(), text)
        self.assertIn("Verified in your browser", text)

    def test_steady_frame_verifies(self):
        self.assertVerified(self._final("width:1000px;height:700px", []))

    def test_frame_collapsed_to_zero_and_restored_verifies(self):
        self.assertVerified(self._final("width:1000px;height:700px",
                                        [(4000, "width:1000px;height:0px"),
                                         (6000, "width:1000px;height:700px")]))

    def test_frame_shrunk_to_20px_and_restored_verifies(self):
        self.assertVerified(self._final("width:1000px;height:700px",
                                        [(4000, "width:1000px;height:20px"),
                                         (6000, "width:1000px;height:700px")]))

    def test_frame_zero_height_at_load_verifies(self):
        self.assertVerified(self._final("width:1000px;height:0",
                                        [(5000, "width:1000px;height:700px")]))

    def test_frame_hidden_at_load_verifies(self):
        self.assertVerified(self._final("display:none",
                                        [(5000, "width:1000px;height:700px")]))


@unittest.skipUnless(CHROME, "Google Chrome not installed")
class TinyWindowTest(unittest.TestCase):
    def test_short_window_does_not_refuse(self):
        dom = _chrome({"r.html": _in_page(_report(), [], at=[("final", 5000)])}, "r.html",
                      size="1200,100", budget=8000)
        cls, text, _count = _snaps(dom)["final"]
        self.assertNotIn("fail", cls.split(), text)


@unittest.skipUnless(CHROME, "Google Chrome not installed")
class LayoutRefusalRecoveryTest(unittest.TestCase):
    def test_layout_refusal_is_kept_when_the_region_shows_again(self):
        html = _in_page(_report(), [
            (3000, "var s=document.createElement('style');s.id='hx';"
                   "s.textContent='#tablewrap{display:none}';document.head.appendChild(s);"),
            (5000, "document.getElementById('hx').remove();"),
        ], at=[("hidden", 4500), ("final", 7500)])
        snaps = _snaps(_chrome({"r.html": html}, "r.html", budget=10000))
        for tag in ("hidden", "final"):
            cls, text, count = snaps[tag]
            self.assertIn("fail", cls.split(), "%s: %s" % (tag, text))
            self.assertIn("Not verified", text, tag)
            self.assertIn("#tablewrap", text, tag)
            self.assertIn("Withheld", count, tag)

    def test_hidden_region_stays_refused(self):
        html = _in_page(_report(), [
            (3000, "var s=document.createElement('style');"
                   "s.textContent='#tablewrap{display:none}';document.head.appendChild(s);"),
        ], at=[("final", 7500)])
        cls, text, count = _snaps(_chrome({"r.html": html}, "r.html", budget=10000))["final"]
        self.assertIn("fail", cls.split(), text)
        self.assertIn("Withheld", count)

    def test_repeated_id_refusal_is_kept_after_the_copy_is_removed(self):
        html = _in_page(_report(), [
            (3000, "var e=document.createElement('div');e.id='rowcount';e.className='dupx';"
                   "document.body.appendChild(e);"),
            (5000, "document.querySelector('.dupx').remove();"),
        ], at=[("dup", 4500), ("final", 7500)])
        snaps = _snaps(_chrome({"r.html": html}, "r.html", budget=10000))
        for tag in ("dup", "final"):
            cls, text, _count = snaps[tag]
            self.assertIn("fail", cls.split(), "%s: %s" % (tag, text))
            self.assertIn("repeats the element id", text, tag)

    def test_region_hidden_at_load_in_a_normal_viewport_stays_refused(self):
        # The region is hidden before verification finishes, in a viewport
        # large enough to show it; showing it later does not lift the refusal,
        # and the completeness line keeps the refusal text.
        html = _in_page(_report(), [
            (0, "var s=document.createElement('style');s.id='hx';"
                "s.textContent='#tablewrap{display:none}';document.head.appendChild(s);"),
            (5000, "document.getElementById('hx').remove();"),
        ], at=[("final", 7500)])
        html = html.replace("</body>", "<script>setTimeout(function(){var c=document."
                            "getElementById('completeness');document.documentElement."
                            "setAttribute('data-c', c ? c.textContent.slice(0,120) : '')},7600)"
                            "</script></body>", 1)
        dom = _chrome({"r.html": html}, "r.html", budget=10000)
        cls, text, count = _snaps(dom)["final"]
        self.assertIn("fail", cls.split(), text)
        self.assertIn("Not verified", text)
        self.assertIn("Withheld", count)
        comp = re.search(r'data-c="([^"]*)"', dom).group(1)
        self.assertIn("Completeness not checked", comp)


def _blink(period, lo, hi):
    """CSS that hides #tablewrap from ``lo``% to ``hi``% of each ``period`` ms
    cycle, with no script."""
    return ("<style>@keyframes hxb{0%%,%s%%{visibility:visible}%s%%,%s%%{visibility:hidden}"
            "%s%%,100%%{visibility:visible}}#tablewrap{animation:hxb %dms step-end infinite}"
            "</style>" % (lo - 0.01, lo, hi, hi + 0.01, period))


_SAMPLER = ("<script>(function(){var n=0,both=0,hid=0;setTimeout(function(){"
            "var iv=setInterval(function(){var w=document.getElementById('tablewrap');"
            "var v=document.getElementById('verdict');"
            "var h=getComputedStyle(w).visibility==='hidden';var ok=/\\bok\\b/.test(v.className);"
            "n++;if(h)hid++;if(h&&ok)both++;document.documentElement.setAttribute('data-s',"
            "JSON.stringify({n:n,hidden:hid,hidden_and_green:both,latched:window.__haloLayoutRefused?1:0,"
            "cls:v.className,text:v.textContent.slice(0,120)}));},20);"
            "setTimeout(function(){clearInterval(iv)},%d);},%d);})();</script>")


@unittest.skipUnless(CHROME, "Google Chrome not installed")
class AnimatedHidingTest(unittest.TestCase):
    """A CSS animation that hides the table for most of each cycle, shown at
    the cycle boundary where animation events fire, ends at "Not verified"
    and stays there."""

    def _run(self, period):
        html = _report().replace("</head>", _blink(period, 5, 95) + "</head>", 1)
        html = html.replace("</body>", _SAMPLER % (12000, 3000) + "</body>", 1)
        dom = _chrome({"r.html": html}, "r.html", budget=16000)
        m = re.search(r'data-s="([^"]*)"', dom)
        self.assertIsNotNone(m, dom[:300])
        return json.loads(m.group(1).replace("&quot;", '"').replace("&amp;", "&"))

    def assertLatched(self, s):
        self.assertGreater(s["hidden"], 0, s)
        self.assertEqual(s["latched"], 1, s)
        self.assertIn("fail", s["cls"].split(), s)
        self.assertIn("Not verified", s["text"], s)

    def test_250ms_blink_latches(self):
        self.assertLatched(self._run(250))

    def test_1s_blink_latches(self):
        # A period equal to the old fixed one-second check, which could stay
        # visible at every check; the check now runs at random times.
        self.assertLatched(self._run(1000))

    def test_4s_blink_latches(self):
        s = self._run(4000)
        self.assertLatched(s)
        # Latched before the sampling began: never green while hidden.
        self.assertEqual(s["hidden_and_green"], 0, s)

if __name__ == "__main__":
    unittest.main()
