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
import html.parser as _parser
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
    marker = '<script id="records"'
    return html[:html.index(marker)] if marker in html else html


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


class _Words(_parser.HTMLParser):
    """Visible words above the Every action table: text outside script, style
    and svg, outside the body of a <details> (its summary counts), up to the
    "Every action" heading."""

    def __init__(self):
        super().__init__()
        self.words, self.skip, self.details, self.summary, self.h2, self.done = [], 0, 0, False, False, False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "svg"):
            self.skip += 1
        elif tag == "details":
            self.details += 1
        elif tag == "summary":
            self.summary = True
        elif tag == "h2":
            self.h2 = True

    def handle_endtag(self, tag):
        if tag in ("script", "style", "svg"):
            self.skip -= 1
        elif tag == "details":
            self.details -= 1
        elif tag == "summary":
            self.summary = False
        elif tag == "h2":
            self.h2 = False

    def handle_data(self, data):
        if self.done or self.skip:
            return
        if self.h2 and data.strip() == "Every action":
            self.done = True
            return
        if self.details and not self.summary:
            return
        self.words.extend(data.split())


def _visible_words(html):
    w = _Words()
    w.feed(_static(html))
    return w.words


def _sentences(html):
    """The numbered sentences as plain text, in order."""
    summary = _region(_static(html), "door-summary")
    return [_html.unescape(re.sub(r"<[^>]+>", "", li))[1:]
            for li in re.findall(r"<li>.*?</li>", summary)]


LIMITS_H2 = "<h2>What this export can&#x27;t show</h2>"


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
        self.assertIn("Example Agent acted 3 times in one day.", summary)
        self.assertNotIn("2026-10-10", summary)   # the period lives in the header
        self.assertIn('<span class="bad">1 rule broken: Repo deletion.</span>', summary)
        self.assertNotIn("no-repo-deletion", summary)
        self.assertIn("One credential: app:Example Agent.", summary)
        self.assertNotIn("look like a person", summary)
        self.assertIn("No vendor record supplied; this page shows the platform's log only.", summary)
        self.assertNotIn("not in the agent's own record", summary)
        self.assertEqual(re.findall(r'<span class="n">(\d)</span>', summary), ["1", "2", "3", "4"])
        for line in _sentences(html):
            self.assertLessEqual(len(line.split()), 12, line)

    def test_summary_with_a_vendor_record(self):
        html = _static(self.page(own_supplied=True, as_person=[
            {"ingested": self.chain_records[-1], "gap_seconds": 12.0}]))
        summary = _region(html, "door-summary")
        self.assertIn("3 of 3 not in the agent's own record.", summary)
        self.assertIn("1 action recorded against the person.", summary)
        self.assertNotIn("No vendor record", summary)
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

    def test_rules_row_tells_no_match_from_pass(self):
        rules = self.rules() + [{"id": "no-gist-publish", "source": "buyer default", "severity": "LOW",
                                 "description": "The agent did not publish a gist.",
                                 "when": {"action.tool": {"in": ["github:gist.create"]}},
                                 "forbid": {"source.capture": "ingested"}}]
        verdict = door.check(self.mine, rules)
        self.assertEqual([r["status"] for r in verdict["rules"] if r["id"] == "no-gist-publish"], ["no_match"])
        html = _static(door.render_page(self.mine, door.match(self.mine, []), verdict, agent=AGENT,
                                        chain=self.chain_records, prepared=PREPARED))
        row = _between(html, '<div class="rulesrow">', "</div>")
        self.assertIn("Gist publish &middot; not applicable (no matching events)</span>", row)
        self.assertIn(">Visibility change</span>", row)   # a pass still reads as the bare name

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
        self.assertIn('<th data-sort="data-tool">Action</th>', html)
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

    def test_cannot_show_is_three_lines_and_a_fold(self):
        html = _static(self.page())
        section = _between(html, LIMITS_H2, "<h2>Every action</h2>")
        visible, fold = section.split("<details", 1)
        self.assertEqual(re.findall(r"<li>(.*?)</li>", visible), [
            "Clones and fetches, or issues: not in a personal security log.",
            "Most reads, such as viewing files or calling read-only APIs.",
            "Anything outside GitHub.",
        ])
        for line in re.findall(r"<li>(.*?)</li>", visible):
            self.assertLessEqual(len(line.split()), 14, line)
        self.assertIn('<summary>All limits of this source</summary>', fold)
        self.assertIn("<li>This export has no records of clones and fetches, or issues. That does not "
                      "mean none happened: the log did not include them.</li>", fold)
        self.assertIn("<li>Most reads, such as viewing files or calling read-only APIs, are not "
                      "recorded in this kind of log.</li>", fold)
        self.assertIn("<li>Anything outside GitHub.</li>", fold)
        self.assertNotIn("What this source cannot show", html)

    def test_section_order_matches_the_mock(self):
        html = _static(self.page(own_supplied=True, as_person=[
            {"ingested": self.chain_records[-1], "gap_seconds": 12.0}]))
        order = ['<div class="brand">', 'id="door-summary"', "<h2>What broke</h2>", "<h2>When it acted</h2>",
                 "<h2>Rules</h2>",
                 "<h2>How it signed in</h2>", "<h2>Against the agent&#x27;s own record</h2>",
                 "<h2>Recorded against the person</h2>", LIMITS_H2,
                 "<h2>Every action</h2>", 'id="tablewrap"', '<div class="verify">', "<footer>"]
        positions = [html.index(m) for m in order]
        self.assertEqual(positions, sorted(positions), order)
        # the one fold above the table is the full list of limits
        above = html[:html.index("<h2>Every action</h2>")]
        self.assertEqual(above.count("<details"), 1)
        self.assertLess(above.index(LIMITS_H2), above.index("<details"))

    # --------------------------------------------------------------- verify

    def test_verify_block_near_the_bottom(self):
        html = self.page(chain_file="c.jsonl")
        static = _static(html)
        block = _between(static, '<div class="verify">', "<footer>")
        self.assertIn('<div id="verdict" class="verdict neutral">Not verified yet', block)
        # two lines in view: the verdict and the witness line; the rest folds
        visible, fold = block.split("<details", 1)
        self.assertEqual(visible.count("<p"), 1)
        self.assertIn("No outside witness holds a checkpoint yet: this proves nothing was edited, "
                      "not that nothing was removed.", visible)
        self.assertIn("<summary>How to check this yourself</summary>", fold)
        self.assertIn("Source: the buyer's own GitHub export, sealed on ingest. The export is as "
                      "complete as what the platform logged; sealing proves this copy has not "
                      "been edited since.", fold)
        self.assertIn("Anchor receipt: none", fold)
        self.assertIn("relative to a head someone other than the operator holds", fold)
        self.assertIn("To check without trusting this page: <code>halo verify c.jsonl</code>.", fold)
        self.assertIn('id="verdict-detail"', fold)
        self.assertLess(static.index('id="tablewrap"'), static.index('<div class="verify">'))
        self.assertEqual(static.count('id="verdict"'), 1)
        # the in-browser verifier words the door's badge as one line, the rest in the fold
        self.assertIn("Checked in your browser:", html)
        self.assertIn("records match the sealed chain.", html)
        self.assertIn("are this agent's and are listed above", html)
        self.assertIn("re-rendered the header and the table from the verified records", html)
        self.assertNotIn("the table and tiles", html)
        # without a chain file name the line still points at halo verify
        self.assertIn("<code>halo verify</code> on the chain file", _static(self.page()))
        anchored = _static(self.page(anchored="witness.example 2026-10-12"))
        self.assertIn("An outside witness holds a checkpoint (witness.example 2026-10-12): this proves "
                      "nothing was edited, not that nothing was removed.", anchored)
        self.assertNotIn("No outside witness", anchored)

    def test_footer(self):
        from halo_record import __version__
        html = _static(self.page())
        self.assertIn('<footer>Prepared with <a href="https://github.com/bkuan001/halo-record">halo-record %s'
                      "</a> from a GitHub security log export supplied by "
                      "the account owner &mdash; Halo records; it does not block, approve, or interpret. "
                      'Agent key <span class="mono">app:Example Agent</span>.</footer>' % __version__, html)
        self.assertNotIn("Generated by", html)
        # the footer names the package version alone, as the Runtime Report does
        self.assertNotIn("unreleased", html)
        self.assertNotIn("branch", html[html.index("<footer>"):])

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
        self.assertNotIn("Agent key", py["meta"])
        self.assertEqual(py["meta"].count("<div>"), 3)
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
        self.assertIn("Acme Collections Agent ran 123 logged actions.", summary)
        self.assertNotIn("across", summary)   # no Agentforce sessions on a connected app's page
        self.assertIn("One credential: app:Acme Collections Agent.", summary)
        self.assertIn("4 rules broken: Data export, Login as, Metadata change, Login outside allowlist.",
                      summary)
        self.assertNotIn("no-data-export", summary)
        self.assertIn("No vendor record supplied; this page shows the platform's log only.", summary)
        for line in _sentences(self.html):
            self.assertLessEqual(len(line.split()), 12, line)
        self.assertEqual(len(_static_rows(self.html)), 123)
        self.assertEqual(len(_embedded(self.html, "records")), len(self.chain_records))

    def test_platform_vocabulary_and_banner(self):
        static = _static(self.html)
        self.assertEqual(_html.unescape(_region(static, "r-h1")),
                         "Acme Collections Agent in this org's Salesforce")
        self.assertIn("Source <b>Salesforce event log export</b>", _region(static, "r-meta"))
        self.assertIn("Source: the buyer's own Salesforce export, sealed on ingest.", static)
        self.assertTrue(static.index("SAMPLE — synthetic export shaped from public sources; no real org data.")
                        < static.index("<h1"))
        # the shared session LKa10 is not part of a broken rule: the section stays
        self.assertIn("<h2>One session, more than one address</h2>", static)
        self.assertNotIn("LKa10", _between(static, "<h2>What broke</h2>", "<h2>When it acted</h2>"))
        self.assertIn("Worth a look, not a finding.", static)
        self.assertNotIn("code pushes", static)
        self.assertIn("from a Salesforce event log export supplied by the account owner", static)
        self.assertNotIn("Recorded against the person", static)

    def test_rules_row_and_chart(self):
        static = _static(self.html)
        row = _between(static, '<div class="rulesrow">', "</div>")
        self.assertEqual(len(re.findall(r"<span[^>]*>[^<]*</span>", row)), 4)
        self.assertEqual(row.count('class="v"'), 4)
        self.assertIn("Login outside allowlist &middot; broken, ", row)
        # the allowlist aside sits in the verify fold, not under Rules or in the footer
        self.assertNotIn("192.0.2.0/24", _between(static, "<h2>Rules</h2>", "<h2>One session"))
        self.assertIn("192.0.2.0/24", _between(static, "<summary>How to check this yourself</summary>", "</details>"))
        self.assertNotIn("192.0.2.0/24", static[static.index("<footer>"):])
        chart = _chart(self.html)
        rects = re.findall(r"<rect [^>]*>", chart)
        # the sample is a seven-day export: one bar per day, not one week
        self.assertEqual(len(rects), 7)
        self.assertIn("Actions per day, ", chart)
        self.assertTrue(any('fill="var(--bad)"' in r for r in rects), rects)
        # one credential on a Salesforce page: the sentence carries it, no bar section
        self.assertEqual(len(re.findall(r'<div class="hbar">', static)), 0)
        self.assertNotIn("<h2>How it signed in</h2>", static)

    def test_no_addresses_outside_test_net_and_no_emails(self):
        self.assertNotRegex(self.html, r"\b(?!192\.0\.2\.|198\.51\.100\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        self.assertNotRegex(self.html, r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


AGENTFORCE = door.bundled_sample("salesforce_agentforce")
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
        sealed = json.dumps([r["data"] for r in calls])
        self.assertNotIn("0000000123", sealed)   # digit runs in the path are masked
        self.assertNotIn("currency", sealed)     # the query string never enters the chain

    def test_label_names_the_agent_and_the_meta_keeps_the_key(self):
        html = self.page(label="Atlas")
        self.assertEqual(_html.unescape(_region(html, "r-h1")), "Atlas in globex's Salesforce")
        meta = _region(html, "r-meta")
        self.assertNotIn("Agent key", meta)
        self.assertEqual(re.findall(r"<div>(\w+)", meta), ["Oct", "Source", "Prepared"])
        foot = html[html.index("<footer>"):]
        self.assertIn('Agent key <span class="mono">app:bot:0XxSAMPLE00000001A</span>.', foot)
        summary = _region(html, "door-summary")
        self.assertIn("Atlas ran 13 logged actions across 4 sessions.", summary)
        self.assertIn("One identity: its own service user", summary)
        self.assertNotIn("0XxSAMPLE00000001A", summary)
        # one credential on a Salesforce page: no bar section, the sentence carries it
        self.assertNotIn("<h2>How it signed in</h2>", html)
        self.assertNotIn("bot:0XxSAMPLE00000001A", _between(html, 'id="door-summary"', "<h2>Every action</h2>"))

    def test_without_a_label_the_key_prints_as_before(self):
        html = self.page()
        self.assertEqual(_html.unescape(_region(html, "r-h1")), "bot:0XxSAMPLE00000001A in globex's Salesforce")
        self.assertNotIn("Agent key", _region(html, "r-meta"))
        self.assertIn("bot:0XxSAMPLE00000001A ran 13 logged actions across 4 sessions.", _region(html, "door-summary"))
        self.assertIn('Agent key <span class="mono">app:bot:0XxSAMPLE00000001A</span>.', html[html.index("<footer>"):])

    def test_reached_outside_sentence_and_section(self):
        html = self.page(label="Atlas")
        summary = _region(html, "door-summary")
        self.assertIn('<li><span class="n">4</span><span>2 calls to api.globex.example, 1 failed.</span></li>', summary)
        self.assertLess(summary.index("2 calls to"), summary.index("Not yet compared to"))
        section = _between(html, "<h2>Where it reached</h2>", "<h2>")
        self.assertIn('<div class="hbar host"><span class="mono">api.globex.example</span>'
                      '<div class="t"><i style="width:100%"></i></div>'
                      '<span class="n">2<span class="f">&middot; 1 failed</span></span></div>', section)
        self.assertNotIn("/core/v2/", section)
        self.assertNotIn("<table", section)

    def test_expected_credential_applies_with_one_identity(self):
        # One identity folds the credential bars into the summary sentence,
        # but a credential the owner did not issue is still flagged.
        html = self.page(expected_credentials=["app:bot:0XxISSUED00000001A"])
        section = _between(html, "<h2>How it signed in</h2>", "<h2>")
        self.assertIn('class="v" title="not a credential issued to this agent"', section)
        self.assertIn("One marked in red is not among those you named.", section)
        self.assertNotIn("<h2>How it signed in</h2>", self.page(expected_credentials=[BOT]))
        self.assertNotIn("<h2>How it signed in</h2>", self.page())

    def test_label_is_escaped(self):
        html = self.page(label="<b>Atlas</b>")
        self.assertNotIn("<b>Atlas</b>", html)
        self.assertIn("&lt;b&gt;Atlas&lt;/b&gt; in globex", _region(html, "r-h1"))

    def test_cli_takes_a_label(self):
        env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
        out = subprocess.run([sys.executable, "-m", "halo_record.cli", "door", AGENTFORCE, "--source",
                              "salesforce", "--agent", BOT, "--label", "Atlas", "--rules",
                              "salesforce-agentforce", "--sample", "--subject", "Globex",
                              "--out", "p.html", "--chain", "d.jsonl"],
                             capture_output=True, text=True, env=env, cwd=self.tmp)
        self.assertEqual(out.returncode, 0, out.stderr)
        with open(os.path.join(self.tmp, "p.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertEqual(_html.unescape(_region(_static(html), "r-h1")), "Atlas in Globex's Salesforce")
        self.assertNotIn("Agent key", _region(_static(html), "r-meta"))
        self.assertIn("Agent key", html[html.index("<footer>"):])
        self.assertIn("<h2>Where it reached</h2>", html)
        self.assertIn("<code>halo verify d.jsonl</code>", html)


class GitHubPageHasNoCallouts(DoorBase):
    def test_no_reach_sentence_or_section(self):
        chain = self.ingested(subject="acme")
        mine = door.isolate(chain, AGENT)
        html = _static(door.render_page(mine, [], door.check(mine, self.rules()), agent=AGENT,
                                        chain=chain, own_supplied=False))
        self.assertNotIn("calls to", _region(html, "door-summary"))
        self.assertNotIn("Where it reached", html)
        self.assertEqual(re.findall(r'<span class="n">(\d)</span>', _region(html, "door-summary")),
                         ["1", "2", "3", "4"])


class ToolIdsAreNotMasked(unittest.TestCase):
    """An action name or tool id is an enumerated identifier the parser
    derived, never user text: the entropy catch-all does not run over it.
    Named secret formats in a tool name are still masked."""

    def test_build_keeps_long_underscore_names_in_the_tool_field(self):
        from halo_record.record import build
        for tool in ("salesforce:Agent.Financial_Account_Balances",
                     "salesforce:Agent.Answer_Questions_with_Knowledge",
                     "salesforce:Agent.Schedule_Recurring_Payment",
                     "getUserProfileByEmailAddress"):
            self.assertEqual(build("tool_call", "security", tool=tool)["action"]["tool"], tool)

    def test_a_secret_in_a_tool_name_is_still_masked(self):
        from halo_record.record import build
        key = "AKIAABCDEFGHIJKLMNOP"
        tool = build("tool_call", "security", tool="deploy with %s" % key)["action"]["tool"]
        self.assertNotIn(key, tool)
        self.assertIn("****", tool)

    def test_summary_text_is_still_fully_masked(self):
        from halo_record.record import build
        rec = build("tool_call", "security", tool="Bash",
                    tool_input={"command": "export TOKEN=hunter2hunter2HUNTER2hunter2x9"})
        self.assertNotIn("hunter2hunter2HUNTER2hunter2x9", rec["action"]["input"]["summary"])


class AgentforceDoorSheet(unittest.TestCase):
    """The Agentforce page read by a bank's technology-risk lead: what the
    agent did, where it stepped outside its lines, and whether this copy is
    intact. Fixture: the bundled salesforce_agentforce sample (Globex)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.events = door.parse_salesforce_eventlog(AGENTFORCE, allowlist=door.DEFAULT_ALLOWLIST)
        self.chain_records = door.ingest(self.events, Recorder(os.path.join(self.tmp, "c.jsonl")),
                                         subject="globex")
        self.context = door.event_index(self.events, self.chain_records)
        self.mine = door.isolate(self.chain_records, BOT)
        self.rules = door.load_rules(door.bundled_rules("salesforce-agentforce"))
        self.shared = door.shared_sessions(self.events)

    def page(self, **kw):
        kw.setdefault("own_supplied", False)
        kw.setdefault("label", "Atlas")
        kw.setdefault("events", self.context)
        kw.setdefault("shared", self.shared)
        return door.render_page(
            self.mine, door.match(self.mine, []), door.check(self.mine, self.rules), agent=BOT,
            source="salesforce", allowlist=list(door.DEFAULT_ALLOWLIST), chain=self.chain_records,
            prepared=PREPARED, **kw)

    # ------------------------------------------------------------ masking

    def test_tool_ids_keep_their_names_in_the_chain_and_on_the_page(self):
        tools = {r["action"]["tool"] for r in self.mine}
        self.assertIn("salesforce:Agent.Funds_Transfer_to_Own_Account", tools)
        self.assertIn("salesforce:Agent.Card_Lock_Management", tools)
        self.assertFalse(any("****" in t for t in tools), tools)
        html = self.page()
        self.assertNotRegex(html, r"salesforce:Agent\.[A-Za-z_]*\*\*\*\*")

    def test_callout_summary_keeps_the_path_and_masks_digit_runs(self):
        calls = {r["data"]["status"]: r for r in self.mine
                 if str(r["action"].get("tool", "")).startswith("salesforce:Callout.")}
        self.assertEqual(calls[502]["action"]["input"]["summary"],
                         "POST https://api.globex.example/core/v2/transfers · 502 · bot 0XxSAMPLE00000001A")
        self.assertIn("GET https://api.globex.example/core/v2/accounts/****/balances · 200",
                      calls[200]["action"]["input"]["summary"])
        self.assertNotIn("0000000123", json.dumps(calls[200]))
        self.assertEqual(calls[502]["data"]["target"], "api.globex.example/core/v2/transfers")
        self.assertEqual(calls[200]["data"]["target"], "api.globex.example/core/v2/accounts/****/balances")
        self.assertEqual([f["type"] for f in calls[502]["findings"]], [])
        self.assertEqual(calls[502]["severity"], "INFO")

    def test_bot_session_is_parsed_and_sealed_in_data_not_in_text(self):
        sessions = {e.get("bot_session") for e in self.events if e.get("app") == "bot:0XxSAMPLE00000001A"}
        self.assertIn("0XsSAMPLE0000000004", sessions)
        rec = next(r for r in self.mine if r["action"]["tool"] == "salesforce:Agent.Query_Records")
        self.assertEqual(rec["data"]["bot_session"], "0XsSAMPLE0000000004")
        self.assertNotIn("0XsSAMPLE", rec["action"]["input"]["summary"])
        login = next(r for r in self.mine if r["action"]["tool"].startswith("salesforce:Login."))
        self.assertNotIn("bot_session", login["data"])

    def test_target_masks_digit_runs_and_drops_the_query(self):
        sf = door.SALESFORCE_SOURCE["adapter"]
        self.assertEqual(door._target({"adapter": sf, "target": "/00OSAMPLE0000000001A?export=1&xf=csv"}),
                         "/00OSAMPLE****A")
        self.assertEqual(door._target({"adapter": sf, "target": "https://h.example/v2/loans/0000012345/pay?x=1"}),
                         "h.example/v2/loans/****/pay")
        self.assertEqual(door._target({"adapter": sf, "target": "/core/v2/transfers"}), "/core/v2/transfers")
        self.assertEqual(door._target({"adapter": sf, "target": "PFFSC.TravelNotificationService.createCase"}),
                         "PFFSC.TravelNotificationService.createCase")
        self.assertEqual(door._target({"repo": "acme/widgets"}), "acme/widgets")
        self.assertIsNone(door._target({"adapter": sf, "target": None}))

    def test_targets_and_statuses_are_sealed_in_data(self):
        by_tool = {}
        for r in self.mine:
            by_tool.setdefault(r["action"]["tool"], r)
        self.assertEqual(by_tool["salesforce:Agent.Funds_Transfer_to_Own_Account"]["data"]["target"],
                         "GlobexFSC.FundsTransferService.submit")
        self.assertEqual(by_tool["salesforce:ApexExecution.GlobexFSC"]["data"]["target"],
                         "GlobexFSC.FundsTransferService.submit")
        self.assertEqual(by_tool["salesforce:Login.Application"]["data"]["status"], "LOGIN_NO_ERROR")
        self.assertNotIn("target", by_tool["salesforce:Login.Application"]["data"])
        self.assertEqual(by_tool["salesforce:Prompt.Call_Summary_v1"]["data"]["target"], "Call_Summary_v1")

    # ---------------------------------------------------------- sentences

    def test_five_sentences(self):
        lines = _sentences(self.page())
        self.assertEqual(lines, [
            "Atlas ran 13 logged actions across 4 sessions.",
            "1 rule broken: Login outside allowlist.",
            "One identity: its own service user (1 platform sign-in, 1 browser).",
            "2 calls to api.globex.example, 1 failed.",
            "Not yet compared to Atlas's own session trace.",
        ])
        for line in lines:
            self.assertLessEqual(len(line.split()), 12, line)

    def test_counts_carry_a_thousands_separator(self):
        self.assertEqual(door._n(1433), "1,433")
        self.assertEqual(door._n(266), "266")
        self.assertEqual(door._n(2874), "2,874")

    def test_sign_ins_absent_from_the_export(self):
        no_logins = [r for r in self.mine if not r["action"]["tool"].startswith("salesforce:Login.")]
        html = door.render_page(no_logins, [], door.check(no_logins, self.rules), agent=BOT, label="Atlas",
                                source="salesforce", chain=self.chain_records, events=self.context,
                                own_supplied=False, prepared=PREPARED)
        self.assertIn("One identity: its own service user (no sign-ins in this export).",
                      _region(_static(html), "door-summary"))

    def test_github_sentences_are_unchanged(self):
        from tests.test_door import EXPORT_ROWS, DoorBase as _GB
        gb = _GB("setUp")
        gb.setUp()
        chain = gb.ingested(subject="acme")
        mine = door.isolate(chain, AGENT)
        html = _static(door.render_page(mine, [], door.check(mine, gb.rules()), agent=AGENT, chain=chain,
                                        own_supplied=False, prepared=PREPARED))
        summary = _region(html, "door-summary")
        self.assertIn("Example Agent acted 3 times in one day.", summary)
        self.assertIn("One credential: app:Example Agent.", summary)
        self.assertIn("No vendor record supplied; this page shows the platform's log only.", summary)
        self.assertIn("<h2>How it signed in</h2>", html)
        self.assertIn("SAMPLE — synthetic export; no real account data.",
                      door.render_page(mine, [], door.check(mine, gb.rules()), agent=AGENT, chain=chain,
                                       sample=True))

    # --------------------------------------------------------- what broke

    def test_what_broke_paragraph(self):
        html = _static(self.page())
        self.assertLess(html.index('id="door-summary"'), html.index("<h2>What broke</h2>"))
        self.assertLess(html.index("<h2>What broke</h2>"), html.index("<h2>When it acted</h2>"))
        section = _between(html, "<h2>What broke</h2>", "<h2>When it acted</h2>")
        paras = re.findall(r'<p class="broke">(.*?)</p>', section)
        self.assertEqual(len(paras), 1)
        text = _html.unescape(re.sub(r"<[^>]+>", "", paras[0]))
        self.assertTrue(text.startswith("Login outside allowlist."), text)
        self.assertIn("Oct 8, 2026 23:12 UTC", text)
        self.assertIn("Atlas's own service user (s****@globex.example)", text)
        self.assertIn("from 203.0.113.9 (Chrome 141)", text)
        self.assertIn("In that session it ran 2 actions: Query Records ×1 — "
                      "AccountSearchController.search, CustomerProfileController.get.", text)
        self.assertIn("The same session was later used from 198.51.100.9.", text)
        self.assertIn("Rules are the account owner's; edit the list to match what this agent is permitted.",
                      _html.unescape(section))
        self.assertNotIn("LKb08", section)   # the session key stays out of the prose
        self.assertNotIn("svc.agent@", html)

    def test_what_broke_absent_when_nothing_broke(self):
        clean = [r for r in self.mine if r["action"]["tool"] != "salesforce:Login.outside_allowlist"]
        html = _static(door.render_page(clean, [], door.check(clean, self.rules), agent=BOT, label="Atlas",
                                        source="salesforce", chain=self.chain_records, events=self.context,
                                        own_supplied=False, prepared=PREPARED))
        self.assertNotIn("What broke", html)
        self.assertIn("No rules broken.", html)

    def test_what_broke_for_a_non_login_rule(self):
        rules = door.load_rules(door.bundled_rules("salesforce-agentforce"))
        rules[1]["forbid"]["action.tool"]["in"].append("salesforce:Agent.Funds_Transfer_to_Own_Account")
        html = _static(door.render_page(self.mine, [], door.check(self.mine, rules), agent=BOT, label="Atlas",
                                        source="salesforce", chain=self.chain_records, events=self.context,
                                        shared=self.shared, own_supplied=False, prepared=PREPARED))
        section = _between(html, "<h2>What broke</h2>", "<h2>When it acted</h2>")
        paras = [_html.unescape(re.sub(r"<[^>]+>", "", p)) for p in re.findall(r'<p class="broke">(.*?)</p>', section)]
        self.assertEqual(len(paras), 2)
        transfer = next(p for p in paras if p.startswith("External transfer."))
        self.assertIn("Oct 5, 2026 14:20 UTC", transfer)
        self.assertIn("Funds Transfer to Own Account ×1 — GlobexFSC.FundsTransferService.submit", transfer)

    def test_shared_section_is_dropped_when_what_broke_already_names_its_session(self):
        html = _static(self.page())
        self.assertNotIn("One session, more than one address", html)
        self.assertNotIn("LKb08", html)
        self.assertIn("The same session was later used from 198.51.100.9.",
                      _between(html, "<h2>What broke</h2>", "<h2>When it acted</h2>"))

    def test_shared_table_stays_with_the_label_when_no_rule_involves_the_session(self):
        clean = [r for r in self.mine if r["action"]["tool"] != "salesforce:Login.outside_allowlist"]
        html = _static(door.render_page(clean, [], door.check(clean, self.rules), agent=BOT, label="Atlas",
                                        source="salesforce", chain=self.chain_records, events=self.context,
                                        shared=self.shared, own_supplied=False, prepared=PREPARED))
        section = _between(html, "<h2>One session, more than one address</h2>", "<h2>")
        self.assertIn("<td>Atlas</td>", section)
        self.assertNotIn("app:bot:0XxSAMPLE00000001A", section)
        self.assertIn("one sign-in was used from two places.", section)
        self.assertIn("Worth a look, not a finding.", section)

    def test_allow_ip_aside_sits_in_the_verify_fold(self):
        html = _static(self.page())
        rules = _between(html, "<h2>Rules</h2>", "<h2>Where it reached</h2>")
        self.assertNotIn("--allow-ip", rules)
        self.assertNotIn("192.0.2.0/24", rules)
        fold = _between(html, "<summary>How to check this yourself</summary>", "</details>")
        self.assertIn("192.0.2.0/24", fold)
        self.assertIn("login-outside-allowlist", fold)
        self.assertNotIn("192.0.2.0/24", html[html.index("<footer>"):])

    def test_header_meta_is_period_source_prepared(self):
        meta = _region(_static(self.page()), "r-meta")
        self.assertEqual(re.findall(r"<div>(\w+)", meta), ["Oct", "Source", "Prepared"])
        self.assertNotIn("0XxSAMPLE", meta)

    def test_first_screen_word_budget(self):
        words = _visible_words(self.page())
        self.assertLessEqual(len(words), 260, " ".join(words))

    def test_verify_block_two_lines_then_the_fold(self):
        html = _static(self.page(chain_file="c.jsonl"))
        block = _between(html, '<div class="verify">', "<footer>")
        visible, fold = block.split("<details", 1)
        self.assertIn('id="verdict"', visible)
        self.assertIn("No outside witness holds a checkpoint yet: this proves nothing was edited, not that "
                      "nothing was removed.", visible)
        self.assertNotIn("Where this copy stands", visible)
        self.assertNotIn("halo verify", visible)
        self.assertIn("<summary>How to check this yourself</summary>", fold)
        self.assertIn("<code>halo verify c.jsonl</code>", fold)
        self.assertIn("Where this copy stands", fold)
        self.assertIn("a sample is never anchored", _static(self.page(sample=True)))

    # ------------------------------------------------------- cannot show

    def test_cannot_show_three_lines_then_the_full_list(self):
        section = _between(_static(self.page()), LIMITS_H2, "<h2>Every action</h2>")
        visible, fold = section.split("<details", 1)
        short = [_html.unescape(x) for x in re.findall(r"<li>(.*?)</li>", visible)]
        self.assertEqual(short, [
            "What the agent was prompted with, planned, or answered — that lives in Agentforce Session "
            "Tracing (Data 360).",
            "Which customer an action touched, or what the core system did with a call.",
            "Anything outside Salesforce, or in event types this org does not export.",
        ])
        self.assertIn("<summary>All limits of this source</summary>", fold)
        items = [_html.unescape(x) for x in re.findall(r"<li>(.*?)</li>", fold)]
        self.assertGreaterEqual(len(items), 6)
        self.assertIn("Which customers an action touched. Rows for a service-agent carry the agent's own user, "
                      "not the customer; the customer join lives in Agentforce Session Tracing.", items)
        self.assertIn("What the system on the other end of a call did. An Apex Callout row shows the host, "
                      "method and status; the integration layer and core-system side of the call is in their logs.", items)
        for kept in door.AGENTFORCE_CANNOT_SHOW + door.SALESFORCE_CANNOT_SHOW:
            self.assertIn(kept, items)
        # one bullet on prompts and reasoning, not two
        self.assertEqual(sum(1 for x in items if "prompt" in x.lower()), 1)
        self.assertEqual(sum(1 for x in items if "Einstein Audit" in x), 1)
        self.assertEqual(len(items), len(door.AGENTFORCE_CANNOT_SHOW) + len(door.SALESFORCE_CANNOT_SHOW) + 1)
        self.assertIn("The query string of a call.", items[-1])
        self.assertEqual(len(items), len(set(items)))

    # -------------------------------------------------------------- table

    def test_door_table_columns(self):
        html = self.page()
        static = _static(html)
        self.assertIn('<thead><tr><th id="th-time" data-sort="data-ts" data-active="desc">Time (UTC)</th>'
                      '<th data-sort="data-tool">Action</th><th>Target</th><th data-sort="data-status">Status</th>'
                      '<th data-sort="data-flags">Findings</th><th>Hash</th></tr></thead>', html)
        for gone in ("<th>Scope</th>", "<th>Decision</th>", "Outcome</th>", "<th>Source</th>",
                     'data-sort="data-type">Type</th>', 'id="f-type"', "<th>Summary</th>"):
            self.assertNotIn(gone, html, gone)
        rows = re.findall(r"<tr data-ts=.*?</tr>", static, re.S)
        self.assertEqual(len(rows), 13)
        cells = {}
        for row in rows:
            tds = re.findall(r"<td[^>]*>(.*?)</td>", row)
            cells[re.search(r'data-tool="([^"]*)"', row).group(1)] = tds
        self.assertIn("Funds Transfer to Own Account", cells)
        self.assertIn("POST callout", cells)
        self.assertIn("Sign-in (Application)", cells)
        self.assertIn("Sign-in (outside allowlist)", cells)
        self.assertIn("Apex GlobexFSC", cells)
        self.assertIn("Prompt Call Summary v1", cells)
        post = cells["POST callout"]
        self.assertEqual(len(post), 6)
        self.assertEqual(post[1], "POST callout")
        self.assertEqual(post[2], "api.globex.example/core/v2/transfers")
        self.assertEqual(post[3], "502")
        self.assertIn("no flags", post[4])
        self.assertEqual(cells["Sign-in (Application)"][2:4], ["—", "LOGIN_NO_ERROR"])
        self.assertIn('placeholder="Search time, action, target, record id, hash&hellip;"', html)
        self.assertIn('<option value="">All actions</option>', html)

    def test_normal_report_table_is_unchanged(self):
        html = render(self.chain_records)
        self.assertIn('<th data-sort="data-tool">Tool</th><th data-sort="data-type">Type</th><th>Source</th>'
                      '<th>Scope</th><th>Decision</th><th data-sort="data-status">Outcome</th>'
                      '<th data-sort="data-flags">Findings</th><th>Summary</th><th>Hash</th>', html)
        self.assertIn('<option value="">All tools</option>', html)
        self.assertIn('id="f-type"', html)
        row = re.search(r"<tr data-ts=.*?</tr>", html, re.S).group(0)
        self.assertEqual(row, _view.row(list(reversed(self.chain_records))[0], show_agent=True))

    # ---------------------------------------------------- footer, banner

    def test_footer_names_the_package_version(self):
        from halo_record import __version__
        html = _static(self.page())
        foot = html[html.index("<footer>"):]
        self.assertIn("halo-record %s</a>" % __version__, foot)
        self.assertNotIn("unreleased", html)

    def test_sample_banner_and_owner_note(self):
        html = self.page(sample=True)
        self.assertIn('<div class="banner">SAMPLE — synthetic export shaped from public sources; no real org data.'
                      "</div>", html)
        noted = self.page(sample=True, sample_note="a best-guess reconstruction of Globex's Agentforce estate")
        self.assertIn('<div class="banner">SAMPLE — synthetic export shaped from public sources; no real org data; '
                      "a best-guess reconstruction of Globex&#x27;s Agentforce estate.</div>", noted)
        self.assertNotIn('<div class="banner">', _static(self.page(sample=False, sample_note="ignored without --sample")))

    def test_cli_takes_a_sample_note_and_builds_the_context(self):
        env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
        out = subprocess.run([sys.executable, "-m", "halo_record.cli", "door", AGENTFORCE, "--source",
                              "salesforce", "--agent", BOT, "--label", "Atlas", "--rules",
                              "salesforce-agentforce", "--sample", "--sample-note", "a reconstruction",
                              "--subject", "Globex", "--out", "p.html", "--chain", "d.jsonl"],
                             capture_output=True, text=True, env=env, cwd=self.tmp)
        self.assertEqual(out.returncode, 0, out.stderr)
        with open(os.path.join(self.tmp, "p.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("no real org data; a reconstruction.</div>", html)
        self.assertIn("<h2>What broke</h2>", html)
        self.assertIn("from 203.0.113.9 (Chrome 141)", html)
        self.assertIn("The same session was later used from 198.51.100.9.", html)
        self.assertIn("Atlas ran 13 logged actions across 4 sessions.", html)
        self.assertIn("Atlas in Globex&#x27;s Salesforce", html)

    # ------------------------------------------------------------- node

    @unittest.skipUnless(NODE, "node not installed")
    def test_door_regions_render_identically_for_salesforce_rows(self):
        door_cfg = {"agent": BOT, "label": "Atlas", "prepared": PREPARED,
                    "source_label": "Salesforce event log export", "hidden": []}
        data = os.path.join(self.tmp, "case.json")
        with open(data, "w", encoding="utf-8") as fh:
            json.dump({"records": self.mine, "door": door_cfg}, fh)
        js = os.path.join(self.tmp, "h.js")
        with open(js, "w", encoding="utf-8") as fh:
            fh.write(_DOOR_HARNESS % _view.render_js())
        p = subprocess.run([NODE, js, data], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = json.loads(p.stdout)
        py = _view.regions(self.mine, None, True, None, door=door_cfg)
        for key in py:
            self.assertEqual(got[key], py[key], "region %s" % key)
        self.assertTrue(any("POST callout" in r for r in py["rows"]))
        self.assertTrue(any("Funds Transfer to Own Account" in r for r in py["rows"]))

    @unittest.skipUnless(NODE, "node not installed")
    def test_door_table_script_filters_counts_and_opens_the_drawer(self):
        from tests.test_report_table_js import _run
        html = self.page()
        out = _run(html, ["filter", "search:callout", "open:0"])
        self.assertIn("ok", out["verdict"])
        first = out["log"][0]
        self.assertIn("Showing 13 of 13 actions", first["rowcount"])
        self.assertEqual([o["text"] for o in first["toolOptions"]][:3],
                         ["Apex GlobexFSC", "Card Lock Management", "Funds Transfer to Own Account"])
        self.assertEqual(out["log"][1]["order"][0], "Apex GlobexFSC")   # newest first; data-tool is the label
        self.assertIn("Showing 2 of 2 actions (filtered from 13)", out["log"][2]["rowcount"])
        self.assertIn("Argument hash", out["log"][3]["detail"])
        self.assertIn("api.globex.example", out["log"][3]["detail"])


if __name__ == "__main__":
    unittest.main()
