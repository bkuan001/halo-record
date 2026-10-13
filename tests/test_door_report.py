"""The door page rendered through the Runtime Report in door mode.

The buyer-side page embeds the full sealed chain and verifies all of it in
the browser; what it displays is one outside agent's rows. On top sit a
header naming the agent in the buyer's platform, five numbered sentences, a
weekly bar chart, the rules checked, the credentials used, the comparison
against the agent's own record (when one was supplied), the door's smaller
tables, what the source cannot show, and the records table under "Every
action". The verification badge is an amber block near the bottom. The
vendor-only controls (expected customer id, witness check, scopes, low notes)
and the headline tiles are not on the page.

Fixture data is synthetic (acme / Globex)."""

import html as _html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from halo_record import _view, door
from halo_record.record import Recorder
from halo_record.report import render

from tests.test_door import AGENT, EXPORT_ROWS, DoorBase
from tests.test_door_salesforce import APP, FIXTURE

NODE = shutil.which("node")
DAY = 86400000
PREPARED = "Oct 12, 2026"


def _static(html):
    """The page as parsed before its scripts: what a reader sees with JS off,
    and what the tests inspect for presence or absence of controls."""
    return html[:html.index('<script id="records"')]


def _embedded(html, script_id):
    marker = 'id="%s"' % script_id
    i = html.index(marker)
    start = html.index(">", i) + 1
    return json.loads(html[start:html.index("</script>", start)])


def _region(html, region_id):
    start = html.index('id="%s"' % region_id)
    start = html.index(">", start) + 1
    return html[start:html.index("<!--/%s-->" % region_id, start)]


def _static_rows(html):
    return re.findall(r'<tr data-ts="[^"]*"[^>]*data-rid="([^"]+)"', _static(html))


def _between(html, start_marker, end_marker):
    a = html.index(start_marker)
    return html[a:html.index(end_marker, a + len(start_marker))]


def _chart(html):
    return _between(_static(html), "<h2>When it acted</h2>", "<h2>Rules</h2>")


def _agent_rows(*timestamps, action="repo.add_topic"):
    return [{"@timestamp": t, "action": action, "actor": "dev", "repo": "acme/widgets",
             "programmatic_access_type": "OAuth access token",
             "oauth_application_name": "Example Agent"} for t in timestamps]


class GitHubDoorPage(DoorBase):
    def setUp(self):
        super().setUp()
        self.chain_records = self.ingested(subject="acme")
        self.mine = door.isolate(self.chain_records, AGENT)
        self.verdict = door.check(self.mine, self.rules())

    def page(self, **kw):
        kw.setdefault("chain", self.chain_records)
        kw.setdefault("prepared", PREPARED)
        return door.render_page(self.mine, door.match(self.mine, []), self.verdict,
                                agent=AGENT, **kw)

    # ---------------------------------------------------------------- header

    def test_header_names_the_agent_in_the_buyers_platform(self):
        html = self.page()
        static = _static(html)
        self.assertIn('<div class="brand">Halo &middot; Runtime Report</div>', static)
        self.assertEqual(_html.unescape(_region(static, "r-h1")), "Example Agent in acme's GitHub")
        self.assertIn("<title>Example Agent in acme&#x27;s GitHub — Runtime Report</title>", static)
        meta = _region(static, "r-meta")
        self.assertIn("Oct 10, 2026 &middot; <b>1 day</b>", meta)
        self.assertIn("Source <b>GitHub security log export</b>", meta)
        self.assertIn("Prepared <b>Oct 12, 2026</b>", meta)
        self.assertNotIn("recorded actions", meta)
        self.assertNotIn("agents:", meta)
        cfg = _embedded(html, "halo-config")["door"]
        self.assertEqual(cfg["title"], "Example Agent in acme's GitHub")
        self.assertEqual(cfg["prepared"], PREPARED)
        self.assertEqual(cfg["source_label"], "GitHub security log export")

    def test_meta_spans_the_period_in_days(self):
        rows = EXPORT_ROWS + _agent_rows(1791590400000 + 94 * DAY)
        chain = self.ingested(rows, subject="acme")
        mine = door.isolate(chain, AGENT)
        html = door.render_page(mine, [], door.check(mine, self.rules()), agent=AGENT,
                                chain=chain, prepared=PREPARED)
        self.assertIn("Oct 10, 2026 &ndash; Jan 12, 2027 &middot; <b>95 days</b>",
                      _region(_static(html), "r-meta"))

    def test_no_headline_tiles_and_no_vendor_controls(self):
        html = _static(self.page())
        for gone in ("Expected customer id", "Check against witness",
                     "completeness rests on the vendor", 'id="completeness"',
                     '<div class="l">Scopes</div>', "Authorized scopes",
                     '<div class="l">Low notes</div>', "Flagged (MEDIUM+)",
                     '<div class="l">Actions</div>', '<div class="l">Tools</div>',
                     'id="r-cards"', 'class="card"', 'id="r-period"', 'id="r-provenance"'):
            self.assertNotIn(gone, html, gone)

    def test_embeds_the_full_chain_and_lists_the_agent_rows(self):
        html = self.page()
        self.assertEqual(len(_embedded(html, "records")), len(self.chain_records))  # 5
        self.assertEqual(sorted(_static_rows(html)), sorted(r["record_id"] for r in self.mine))
        cfg = _embedded(html, "halo-config")
        self.assertEqual(cfg["door"]["agent"], AGENT)
        self.assertEqual(cfg["door"]["hidden"], [])
        self.assertIn("function haloDoorKeeps", html)
        self.assertIn("embeds the full sealed chain", _static(html))

    def test_witness_lookup_code_is_not_shipped_in_door_mode(self):
        html = self.page()
        self.assertNotIn("function liveCheckpoints", html)
        self.assertNotIn("function haloCompleteness", html)
        self.assertNotIn("127.0.0.1", html)
        # the verifier itself stays
        self.assertIn("crypto.subtle", html)
        self.assertIn("async function verify(", html)
        self.assertIn("function haloBind", html)

    def test_normal_report_keeps_its_controls(self):
        html = render(self.chain_records)
        for kept in ("Expected customer id", "Check against witness",
                     '<div class="l">Scopes</div>', "Authorized scopes",
                     '<div class="l">Low notes</div>', "function liveCheckpoints",
                     '<div class="cards" id="r-cards">', '<div class="eyebrow">Halo Runtime Report</div>'):
            self.assertIn(kept, html, kept)
        self.assertNotIn('id="door-summary"', html)
        self.assertNotIn('class="verify"', html)
        self.assertNotIn("When it acted", html)
        self.assertNotIn("door", _embedded(html, "halo-config"))
        self.assertIn('<div class="note prov-note">', html)

    # -------------------------------------------------------------- summary

    def test_summary_lines(self):
        html = _static(self.page(own_supplied=False))
        summary = _region(html, "door-summary")
        self.assertIn("app:Example Agent acted in acme 3 times between 2026-10-10 and 2026-10-10.", summary)
        self.assertIn('<span class="bad">1 rule broken: Repo deletion</span>', summary)
        self.assertNotIn("no-repo-deletion", summary)
        self.assertIn("It used 1 credential: app:Example Agent.", summary)
        self.assertNotIn("look like a person", summary)
        self.assertIn("No vendor record was supplied; this page shows the platform's own log only.", summary)
        self.assertNotIn("not in the agent's own record", summary)
        self.assertEqual(re.findall(r'<span class="n">(\d)</span>', summary), ["1", "2", "3", "4"])

    def test_summary_with_a_vendor_record(self):
        html = _static(self.page(own_supplied=True, as_person=[
            {"ingested": self.chain_records[-1], "gap_seconds": 12.0}]))
        summary = _region(html, "door-summary")
        self.assertIn("3 actions are not in the agent's own record.", summary)
        self.assertIn("1 action looks like a person on the agent's session.", summary)
        self.assertNotIn("No vendor record was supplied", summary)
        self.assertEqual(re.findall(r'<span class="n">(\d)</span>', summary), ["1", "2", "3", "4", "5"])

    # ---------------------------------------------------------------- chart

    def test_chart_has_one_bar_per_iso_week_and_marks_the_broken_week(self):
        # Oct 10 2026 is a Saturday (ISO week of Mon Oct 5); +14 d and +35 d
        # land in the weeks of Oct 19 and Nov 9: six weeks, three with actions.
        rows = EXPORT_ROWS + _agent_rows(1791590400000 + 14 * DAY, 1791590400000 + 35 * DAY)
        chain = self.ingested(rows, subject="acme")
        mine = door.isolate(chain, AGENT)
        html = door.render_page(mine, [], door.check(mine, self.rules()), agent=AGENT, chain=chain)
        chart = _chart(html)
        self.assertIn('<svg class="weeks" viewBox="0 0 800 150" role="img" '
                      'aria-label="Actions per week, Oct 10 to Nov 14, 2026">', chart)
        rects = re.findall(r"<rect [^>]*>", chart)
        self.assertEqual(len(rects), 6)
        bad = [r for r in rects if 'fill="var(--bad)"' in r]
        self.assertEqual(len(bad), 1)
        self.assertIn(bad[0], rects[0])  # the deletion is in the first week
        # the y axis tops out at the busiest week (3 actions) in round steps
        self.assertEqual(re.findall(r'<text x="0" y="[\d.]+">(\d+)</text>', chart), ["3", "2", "1", "0"])
        self.assertIn("<text", _between(chart, "<!--x-->", "</g>"))
        self.assertIn("actions per week", chart)
        self.assertIn("week with a broken rule", chart)

    def test_chart_buckets_by_day_up_to_fourteen_days(self):
        # a single day: one bar, labelled by day
        one = _chart(self.page())
        self.assertEqual(len(re.findall(r"<rect ", one)), 1)
        self.assertIn('aria-label="Actions per day, Oct 10 to Oct 10, 2026"', one)
        self.assertIn("actions per day", one)
        self.assertIn("day with a broken rule", one)
        self.assertEqual(re.findall(r"<text[^>]*>([^<]*)</text>", _between(one, "<!--x-->", "</g>")),
                         ["Oct 10"])
        # seven days (a week-long export): seven bars, one per calendar day, UTC
        rows = EXPORT_ROWS + _agent_rows(*[1791590400000 + d * DAY for d in (2, 2, 4, 6)])
        chain = self.ingested(rows, subject="acme")
        mine = door.isolate(chain, AGENT)
        week = _chart(door.render_page(mine, [], door.check(mine, self.rules()), agent=AGENT, chain=chain))
        rects = re.findall(r'<rect x="[\d.]+" y="[\d.]+" width="[\d.]+" height="([\d.]+)"', week)
        self.assertEqual(len(rects), 7)
        self.assertEqual([h != "0" for h in rects], [True, False, True, False, True, False, True])
        self.assertIn('aria-label="Actions per day, Oct 10 to Oct 16, 2026"', week)
        labels = re.findall(r"<text[^>]*>([^<]*)</text>", _between(week, "<!--x-->", "</g>"))
        self.assertEqual(labels, ["Oct 10", "Oct 11", "Oct 12", "Oct 13", "Oct 14", "Oct 15", "Oct 16"])
        self.assertEqual(re.findall(r'<text x="0" y="[\d.]+">(\d+)</text>', week), ["3", "2", "1", "0"])
        self.assertNotIn("per week", week)
        # fourteen days still by day; fifteen by ISO week
        chain = self.ingested(EXPORT_ROWS + _agent_rows(1791590400000 + 13 * DAY), subject="acme")
        mine = door.isolate(chain, AGENT)
        fourteen = _chart(door.render_page(mine, [], door.check(mine, self.rules()), agent=AGENT, chain=chain))
        self.assertEqual(len(re.findall(r"<rect ", fourteen)), 14)
        self.assertIn("Actions per day, Oct 10 to Oct 23, 2026", fourteen)
        chain = self.ingested(EXPORT_ROWS + _agent_rows(1791590400000 + 14 * DAY), subject="acme")
        mine = door.isolate(chain, AGENT)
        fifteen = _chart(door.render_page(mine, [], door.check(mine, self.rules()), agent=AGENT, chain=chain))
        self.assertEqual(len(re.findall(r"<rect ", fifteen)), 3)  # weeks of Oct 5, 12 and 19
        self.assertIn("Actions per week, Oct 10 to Oct 24, 2026", fifteen)
        self.assertIn("actions per week", fifteen)

    def test_chart_reads_at_sixty_weeks(self):
        rows = EXPORT_ROWS + _agent_rows(1791590400000 + 427 * DAY)
        chain = self.ingested(rows, subject="acme")
        mine = door.isolate(chain, AGENT)
        many = _chart(door.render_page(mine, [], door.check(mine, self.rules()), agent=AGENT, chain=chain))
        rects = re.findall(r'<rect x="([\d.]+)" y="[\d.]+" width="([\d.]+)"', many)
        self.assertEqual(len(rects), 62)
        widths = {w for _, w in rects}
        self.assertEqual(len(widths), 1)
        self.assertLess(float(widths.pop()), 12)
        labels = re.findall(r"<text[^>]*>([^<]*)</text>", _between(many, "<!--x-->", "</g>"))
        self.assertLessEqual(len(labels), 20)
        self.assertGreaterEqual(len(labels), 4)
        self.assertIn("Oct 5", labels[0])
        self.assertTrue(any("2027" in lab for lab in labels), labels)
        self.assertIn("Oct 10, 2026 to Dec 11, 2027", many)

    def test_chart_escapes_what_came_from_the_export(self):
        chain = self.ingested(subject="acme<x>")
        mine = door.isolate(chain, AGENT)
        html = _static(door.render_page(mine, [], door.check(mine, self.rules()), agent=AGENT,
                                        chain=chain, prepared=PREPARED))
        self.assertNotIn("acme<x>", html)
        self.assertIn("Example Agent in acme&lt;x&gt;&#x27;s GitHub", html)

    # ---------------------------------------------------------------- rules

    def test_rules_row_has_one_dot_per_rule(self):
        static = _static(self.page())
        row = _between(static, '<div class="rulesrow">', "</div>")
        spans = re.findall(r"<span[^>]*>[^<]*</span>", row)
        self.assertEqual(len(spans), 5)
        broken = [s for s in spans if 'class="v"' in s]
        self.assertEqual(len(broken), 1)
        self.assertIn("Repo deletion &middot; broken, 1 action</span>", broken[0])
        self.assertIn('title="no-repo-deletion: The agent did not delete or transfer a repository."', broken[0])
        self.assertIn("<span title=", spans[1])
        self.assertIn(">Visibility change</span>", row)
        self.assertNotIn("<table", _between(static, "<h2>Rules</h2>", "<h2>How it signed in</h2>"))

    # ---------------------------------------------------------- credentials

    def test_credential_bars_widest_is_full(self):
        rows = [
            {"@timestamp": 1791590400000, "action": "repo.create", "user": "dev",
             "programmatic_access_type": "OAuth access token", "oauth_application_name": "GitHub CLI",
             "user_agent": "GitHub CLI 2.94.0 Agent/claude-code_2-1-145_agent"},
            {"@timestamp": 1791590410000, "action": "repo.create", "user": "dev",
             "programmatic_access_type": "OAuth access token", "oauth_application_name": "GitHub CLI",
             "user_agent": "GitHub CLI 2.94.0 Agent/claude-code_2-1-145_agent"},
            {"@timestamp": 1791590420000, "action": "repo.create", "user": "dev",
             "programmatic_access_type": "Personal access token (fine-grained)", "token_id": 99,
             "user_agent": "GitHub CLI 2.94.0 Agent/claude-code_2-1-145_agent"},
        ]
        chain = self.ingested(rows, subject="acme")
        mine = door.isolate(chain, "agent:claude-code")
        html = _static(door.render_page(mine, [], door.check(mine, self.rules()),
                                        agent="agent:claude-code", chain=chain, prepared=PREPARED))
        self.assertEqual(_html.unescape(_region(html, "r-h1")), "Claude Code in acme's GitHub")
        section = _between(html, "<h2>How it signed in</h2>", "<h2>")
        bars = re.findall(r'<div class="hbar">.*?<span class="n">\d+</span></div>', section)
        self.assertEqual(len(bars), 2)
        self.assertIn("<span>GitHub CLI</span>", bars[0])
        self.assertIn('<i style="width:100%"></i>', bars[0])
        self.assertIn('<span class="n">2</span>', bars[0])
        self.assertIn('<span class="mono">token:99</span>', bars[1])
        self.assertIn('<i style="width:50%"></i>', bars[1])
        self.assertEqual(section.count("width:100%"), 1)
        self.assertIn("Each credential is a separate way in. Compare against the ones you issued "
                      "this agent.", section)
        self.assertNotIn("<table", section)

    def test_credential_not_issued_is_marked(self):
        html = _static(self.page(expected_credentials=["token:1"]))
        section = _between(html, "<h2>How it signed in</h2>", "<h2>")
        self.assertIn('<span class="v" title="not a credential issued to this agent">Example Agent</span>',
                      section)
        self.assertIn("The agent should act only through the credentials issued to it.", section)

    # ------------------------------------------------- against the own record

    def test_split_bar_only_with_a_vendor_record(self):
        with_own = _static(self.page(own_supplied=True))
        section = _between(with_own, "<h2>Against the agent&#x27;s own record</h2>", "<h2>")
        self.assertIn('<div class="split">', section)
        self.assertIn('<i style="width:0%;background:var(--ok)"></i>', section)
        self.assertIn('<i style="width:100%;background:var(--bar)"></i>', section)
        self.assertIn("0 matched or probable", section)
        self.assertIn("3 not found", section)
        self.assertIn("&quot;Not found&quot; means the agent&#x27;s record has nothing within the matching "
                      "window, whether it skipped the action or never kept one.", section)
        without = _static(self.page(own_supplied=False))
        self.assertNotIn("Against the agent", without)
        self.assertNotIn('class="split"', without)
        self.assertNotIn("matched or probable", without)
        self.assertNotIn("Not in the agent", without)

    def test_every_action_keeps_the_table_and_the_not_in_record_fold(self):
        html = _static(self.page(own_supplied=True))
        every = _between(html, "<h2>Every action</h2>", '<div class="tablewrap" id="tablewrap">')
        self.assertIn("<summary>Not in the agent&#x27;s own record (3)</summary>", every)
        self.assertIn('id="filters"', every)
        self.assertLess(html.index("<h2>Every action</h2>"), html.index('id="tablewrap"'))
        self.assertIn('<th data-sort="data-tool">Tool</th>', html)
        self.assertIn('<aside id="detail" class="detail"', html)

    # -------------------------------------------------------- small tables

    def test_recorded_against_the_person_table(self):
        html = _static(self.page(own_supplied=True, as_person=[
            {"ingested": self.chain_records[-1], "gap_seconds": 12.0}]))
        section = _between(html, "<h2>Recorded against the person</h2>", "<h2>")
        self.assertIn("<th>When (UTC)</th><th>Action</th><th>Agent active within</th>", section)
        self.assertIn("<td>12.0 s</td>", section)
        self.assertIn("A likelihood from timing, not proof", section)
        self.assertNotIn("Recorded against the person", _static(self.page()))

    def test_cannot_show_is_a_list(self):
        html = _static(self.page())
        section = _between(html, "<h2>What this source cannot show</h2>", "<h2>Every action</h2>")
        self.assertIn('<ul class="cannot">', section)
        self.assertIn("<li>This export has no records of clones and fetches, or issues. That does not "
                      "mean none happened: the log did not include them.</li>", section)
        self.assertIn("<li>Most reads, such as viewing files or calling read-only APIs, are not "
                      "recorded in this kind of log.</li>", section)
        self.assertIn("<li>Anything outside GitHub.</li>", section)

    def test_section_order_matches_the_mock(self):
        html = _static(self.page(own_supplied=True, as_person=[
            {"ingested": self.chain_records[-1], "gap_seconds": 12.0}]))
        order = ['<div class="brand">', 'id="door-summary"', "<h2>When it acted</h2>", "<h2>Rules</h2>",
                 "<h2>How it signed in</h2>", "<h2>Against the agent&#x27;s own record</h2>",
                 "<h2>Recorded against the person</h2>", "<h2>What this source cannot show</h2>",
                 "<h2>Every action</h2>", 'id="tablewrap"', '<div class="verify">', "<footer>"]
        positions = [html.index(m) for m in order]
        self.assertEqual(positions, sorted(positions), order)
        self.assertNotIn("<details", html[:html.index("<h2>Every action</h2>")])

    # --------------------------------------------------------------- verify

    def test_verify_block_near_the_bottom(self):
        html = self.page(chain_file="c.jsonl")
        static = _static(html)
        block = _between(static, '<div class="verify">', "<footer>")
        self.assertIn('<div id="verdict" class="verdict neutral">Not verified yet', block)
        self.assertIn("Source: the buyer's own GitHub export, sealed on ingest. The export is as "
                      "complete as what the platform logged; sealing proves this copy has not "
                      "been edited since.", block)
        self.assertIn("Anchor receipt: none", block)
        self.assertIn("relative to a head someone other than the operator holds", block)
        self.assertIn("To check without trusting this page: <code>halo verify c.jsonl</code>.", block)
        self.assertLess(static.index('id="tablewrap"'), static.index('<div class="verify">'))
        self.assertEqual(static.count('id="verdict"'), 1)
        # the in-browser verifier words the door's badge as the amber block
        self.assertIn("Checked in your browser.", html)
        self.assertIn("are this agent's and are listed above", html)
        self.assertIn("re-rendered the header and the table from the verified records", html)
        self.assertNotIn("the table and tiles", html)
        # without a chain file name the line still points at halo verify
        self.assertIn("<code>halo verify</code> on the chain file", _static(self.page()))

    def test_footer(self):
        from halo_record import __version__
        html = _static(self.page())
        self.assertIn('<footer>Prepared with <a href="https://github.com/bkuan001/halo-record">halo-record %s'
                      "</a> from a GitHub security log export supplied by the account owner. Halo records; "
                      "it does not block, approve, or interpret.</footer>" % __version__, html)
        self.assertNotIn("Generated by", html)

    # ---------------------------------------------------------------- style

    def test_style_tokens_and_fonts(self):
        html = _static(self.page())
        style = _between(html, "<style>", "</style>")
        for needle in ("--paper:", "--bad:", "--ok:", "--bar-strong:", "--amber-soft:",
                       "@media (prefers-color-scheme: dark)", ':root:not([data-theme="light"])',
                       ':root[data-theme="dark"]', "text-wrap:balance", "max-width:820px",
                       '"Hanken Grotesk"', '"IBM Plex Mono"', "@media (max-width:560px)"):
            self.assertIn(needle, style, needle)
        self.assertNotIn("Instrument Serif", style)
        self.assertNotIn("Instrument Sans", style)
        self.assertNotIn("<link", html)
        self.assertNotIn("@import", style)
        self.assertNotIn("fonts.googleapis", html)
        self.assertNotIn(".cards{", style)

    def test_sample_banner_only_when_sample(self):
        html = self.page(sample=True)
        self.assertIn("SAMPLE — synthetic export; no real account data.", html)
        self.assertLess(html.index("SAMPLE —"), html.index('<div class="brand">'))
        self.assertNotIn("SAMPLE —", self.page(sample=False))

    def test_routine_rows_are_hidden_but_sealed(self):
        refresh = {"@timestamp": 1791590700000, "action": "oauth_access.regenerate",
                   "actor": "dev", "oauth_application_name": "Example Agent"}
        chain = self.ingested(EXPORT_ROWS + [refresh])
        mine = door.isolate(chain, AGENT)
        shown, hidden = door.split_routine(mine)
        html = door.render_page(shown, [], door.check(shown, self.rules()), agent=AGENT,
                                routine=hidden, chain=chain)
        self.assertEqual(len(_embedded(html, "records")), 6)
        self.assertEqual(len(_static_rows(html)), 3)
        self.assertEqual(_embedded(html, "halo-config")["door"]["hidden"],
                         [hidden[0]["record_id"]])
        self.assertIn("1 automatic token refreshes", html)
        self.assertEqual(_html.unescape(_region(_static(html), "r-h1")),
                         "Example Agent in this account's GitHub")

    @unittest.skipUnless(NODE, "node not installed")
    def test_door_regions_render_identically_in_python_and_the_page(self):
        door_cfg = {"agent": AGENT, "label": "Example", "prepared": PREPARED,
                    "source_label": "GitHub security log export", "hidden": []}
        d = tempfile.mkdtemp()
        data = os.path.join(d, "case.json")
        with open(data, "w", encoding="utf-8") as fh:
            json.dump({"records": self.mine, "door": door_cfg}, fh)
        js = os.path.join(d, "h.js")
        with open(js, "w", encoding="utf-8") as fh:
            fh.write(_DOOR_HARNESS % _view.render_js())
        p = subprocess.run([NODE, js, data], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = json.loads(p.stdout)
        py = _view.regions(self.mine, None, True, None, door=door_cfg)
        for key in py:
            self.assertEqual(got[key], py[key], "region %s" % key)
        self.assertIn("Prepared <b>Oct 12, 2026</b>", py["meta"])
        self.assertIn('<div>Agent key <b class="mono">app:Example Agent</b></div>', py["meta"])
        self.assertEqual(py["cards"], "")


_DOOR_HARNESS = r"""
const fs = require("fs");
%s
const c = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
process.stdout.write(JSON.stringify(HaloView.regions(c.records, null, true, null, c.door)));
"""


class SalesforceDoorPage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        events = door.parse_salesforce_eventlog(FIXTURE, allowlist=door.DEFAULT_ALLOWLIST)
        self.chain_records = door.ingest(events, Recorder(os.path.join(self.tmp, "c.jsonl")))
        self.mine = door.isolate(self.chain_records, APP)
        rules = door.load_rules(door.bundled_rules("salesforce-default"))
        self.html = door.render_page(
            self.mine, door.match(self.mine, []), door.check(self.mine, rules), agent=APP,
            own_supplied=False, sample=True, source="salesforce",
            allowlist=list(door.DEFAULT_ALLOWLIST), chain=self.chain_records,
            shared=door.shared_sessions(events), prepared=PREPARED)

    def test_summary_and_counts(self):
        summary = _region(_static(self.html), "door-summary")
        self.assertRegex(summary, r"app:Acme Collections Agent acted in this org 123 times between "
                                  r"\d{4}-\d{2}-\d{2} and \d{4}-\d{2}-\d{2}\.")
        self.assertIn("4 rules broken: Data export, Login as, Metadata change, Login outside allowlist",
                      summary)
        self.assertNotIn("no-data-export", summary)
        self.assertIn("No vendor record was supplied; this page shows the platform's own log only.", summary)
        self.assertEqual(len(_static_rows(self.html)), 123)
        self.assertEqual(len(_embedded(self.html, "records")), len(self.chain_records))

    def test_platform_vocabulary_and_banner(self):
        static = _static(self.html)
        self.assertEqual(_html.unescape(_region(static, "r-h1")),
                         "Acme Collections Agent in this org's Salesforce")
        self.assertIn("Source <b>Salesforce event log export</b>", _region(static, "r-meta"))
        self.assertIn("Source: the buyer's own Salesforce export, sealed on ingest.", static)
        self.assertTrue(static.index("SAMPLE — synthetic Salesforce export") < static.index("<h1"))
        self.assertIn("<h2>One session, more than one address</h2>", static)
        self.assertNotIn("code pushes", static)
        self.assertIn("from a Salesforce event log export supplied by the account owner", static)
        self.assertNotIn("Recorded against the person", static)

    def test_rules_row_and_chart(self):
        static = _static(self.html)
        row = _between(static, '<div class="rulesrow">', "</div>")
        self.assertEqual(len(re.findall(r"<span[^>]*>[^<]*</span>", row)), 4)
        self.assertEqual(row.count('class="v"'), 4)
        self.assertIn("Login outside allowlist &middot; broken, ", row)
        self.assertIn("192.0.2.0/24", _between(static, "<h2>Rules</h2>", "<h2>How it signed in</h2>"))
        chart = _chart(self.html)
        rects = re.findall(r"<rect [^>]*>", chart)
        # the sample is a seven-day export: one bar per day, not one week
        self.assertEqual(len(rects), 7)
        self.assertIn("Actions per day, ", chart)
        self.assertTrue(any('fill="var(--bad)"' in r for r in rects), rects)
        self.assertEqual(len(re.findall(r'<div class="hbar">', static)), 1)

    def test_no_addresses_outside_test_net_and_no_emails(self):
        self.assertNotRegex(self.html, r"\b(?!192\.0\.2\.|198\.51\.100\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        self.assertNotRegex(self.html, r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


AGENTFORCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "salesforce_agentforce_sample")
BOT = "app:bot:0XxSAMPLE00000001A"


class AgentforceDoorPage(unittest.TestCase):
    """An Agentforce bot with a display name, whose actions include calls
    outside the org (two to api.globex.example, one of them a 502)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.events = door.parse_salesforce_eventlog(AGENTFORCE, allowlist=door.DEFAULT_ALLOWLIST)
        self.chain_records = door.ingest(self.events, Recorder(os.path.join(self.tmp, "c.jsonl")),
                                         subject="globex")
        self.mine = door.isolate(self.chain_records, BOT)
        self.rules = door.load_rules(door.bundled_rules("salesforce-agentforce"))

    def page(self, **kw):
        kw.setdefault("own_supplied", False)
        return _static(door.render_page(
            self.mine, door.match(self.mine, []), door.check(self.mine, self.rules), agent=BOT,
            source="salesforce", allowlist=list(door.DEFAULT_ALLOWLIST), chain=self.chain_records,
            prepared=PREPARED, **kw))

    def test_callout_host_and_status_are_sealed_in_the_record(self):
        calls = [r for r in self.mine if str(r["action"].get("tool", "")).startswith("salesforce:Callout.")]
        self.assertEqual(len(calls), 2)
        self.assertEqual(sorted((r["data"]["host"], r["data"]["status"]) for r in calls),
                         [("api.globex.example", 200), ("api.globex.example", 502)])
        self.assertNotIn("/core/v2/", json.dumps([r["data"] for r in calls]))

    def test_label_names_the_agent_and_the_meta_keeps_the_key(self):
        html = self.page(label="ACE")
        self.assertEqual(_html.unescape(_region(html, "r-h1")), "ACE in globex's Salesforce")
        meta = _region(html, "r-meta")
        self.assertIn('<div>Agent key <b class="mono">app:bot:0XxSAMPLE00000001A</b></div>', meta)
        self.assertLess(meta.index("Agent key"), meta.index("Prepared"))
        summary = _region(html, "door-summary")
        self.assertRegex(summary, r"ACE acted in globex 13 times between \d{4}-\d{2}-\d{2} and \d{4}-\d{2}-\d{2}\.")
        self.assertIn("It used 1 credential: ACE.", summary)
        self.assertNotIn("0XxSAMPLE00000001A", summary)
        signed = _between(html, "<h2>How it signed in</h2>", "<h2>")
        self.assertIn('<div class="hbar"><span>ACE</span><div class="t"><i style="width:100%"></i></div>'
                      '<span class="n">13</span></div>', signed)
        self.assertNotIn("bot:0XxSAMPLE00000001A", signed)

    def test_without_a_label_the_key_prints_as_before(self):
        html = self.page()
        self.assertEqual(_html.unescape(_region(html, "r-h1")), "bot:0XxSAMPLE00000001A in globex's Salesforce")
        self.assertNotIn("Agent key", _region(html, "r-meta"))
        self.assertIn("app:bot:0XxSAMPLE00000001A acted in globex 13 times", _region(html, "door-summary"))
        self.assertIn("<span>bot:0XxSAMPLE00000001A</span>", _between(html, "<h2>How it signed in</h2>", "<h2>"))

    def test_reached_outside_sentence_and_section(self):
        html = self.page(label="ACE")
        summary = _region(html, "door-summary")
        self.assertIn('<li><span class="n">4</span><span>It reached outside the org 2 times, to 1 host.</span></li>',
                      summary)
        self.assertLess(summary.index("reached outside"), summary.index("No vendor record was supplied"))
        self.assertLess(html.index("<h2>How it signed in</h2>"), html.index("<h2>Where it reached</h2>"))
        section = _between(html, "<h2>Where it reached</h2>", "<h2>")
        self.assertIn('<div class="hbar host"><span class="mono">api.globex.example</span>'
                      '<div class="t"><i style="width:100%"></i></div>'
                      '<span class="n">2<span class="f">&middot; 1 failed</span></span></div>', section)
        self.assertNotIn("/core/v2/", section)
        self.assertNotIn("<table", section)

    def test_label_is_escaped(self):
        html = self.page(label="<b>ACE</b>")
        self.assertNotIn("<b>ACE</b>", html)
        self.assertIn("&lt;b&gt;ACE&lt;/b&gt; in globex", _region(html, "r-h1"))

    def test_cli_takes_a_label(self):
        env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
        out = subprocess.run([sys.executable, "-m", "halo_record.cli", "door", AGENTFORCE, "--source",
                              "salesforce", "--agent", BOT, "--label", "ACE", "--rules",
                              "salesforce-agentforce", "--sample", "--subject", "Globex",
                              "--out", "p.html", "--chain", "d.jsonl"],
                             capture_output=True, text=True, env=env, cwd=self.tmp)
        self.assertEqual(out.returncode, 0, out.stderr)
        with open(os.path.join(self.tmp, "p.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertEqual(_html.unescape(_region(_static(html), "r-h1")), "ACE in Globex's Salesforce")
        self.assertIn("Agent key", _region(_static(html), "r-meta"))
        self.assertIn("<h2>Where it reached</h2>", html)
        self.assertIn("<code>halo verify d.jsonl</code>", html)


class GitHubPageHasNoCallouts(DoorBase):
    def test_no_reach_sentence_or_section(self):
        chain = self.ingested(subject="acme")
        mine = door.isolate(chain, AGENT)
        html = _static(door.render_page(mine, [], door.check(mine, self.rules()), agent=AGENT,
                                        chain=chain, own_supplied=False))
        self.assertNotIn("reached outside", html)
        self.assertNotIn("Where it reached", html)
        self.assertEqual(re.findall(r'<span class="n">(\d)</span>', _region(html, "door-summary")),
                         ["1", "2", "3", "4"])


if __name__ == "__main__":
    unittest.main()
