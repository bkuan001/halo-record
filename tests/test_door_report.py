"""The door page rendered through the Runtime Report in door mode.

The buyer-side page embeds the full sealed chain and verifies all of it in
the browser; what it displays (header, tiles, table) is one outside agent's
rows. The door's analysis sits on top as a five-line summary, its detail
sections fold below, and the vendor-only controls (expected customer id,
witness check, scopes, low notes) are not on the page.

Fixture data is synthetic (acme / Globex)."""

import json
import os
import re
import unittest

from halo_record import door
from halo_record.record import Recorder
from halo_record.report import render

from tests.test_door import AGENT, EXPORT_ROWS, DoorBase
from tests.test_door_salesforce import APP, FIXTURE


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


class GitHubDoorPage(DoorBase):
    def setUp(self):
        super().setUp()
        self.chain_records = self.ingested(subject="acme")
        self.mine = door.isolate(self.chain_records, AGENT)
        self.verdict = door.check(self.mine, self.rules())

    def page(self, **kw):
        kw.setdefault("chain", self.chain_records)
        return door.render_page(self.mine, door.match(self.mine, []), self.verdict,
                                agent=AGENT, **kw)

    def test_header_reads_one_agent(self):
        html = self.page()
        meta = _region(html, "r-meta")
        self.assertIn("Outside agent <b>app:Example Agent</b>", meta)
        self.assertIn("<b>3</b> recorded actions", meta)
        self.assertNotIn("agents:", meta)

    def test_embeds_the_full_chain_and_lists_the_agent_rows(self):
        html = self.page()
        self.assertEqual(len(_embedded(html, "records")), len(self.chain_records))  # 5
        self.assertEqual(sorted(_static_rows(html)), sorted(r["record_id"] for r in self.mine))
        cfg = _embedded(html, "halo-config")
        self.assertEqual(cfg["door"]["agent"], AGENT)
        self.assertEqual(cfg["door"]["hidden"], [])
        self.assertIn("function haloDoorKeeps", html)
        self.assertIn("embeds the full sealed chain", _static(html))

    def test_vendor_controls_are_removed(self):
        html = _static(self.page())
        for gone in ("Expected customer id", "Check against witness",
                     "completeness rests on the vendor", 'id="completeness"',
                     '<div class="l">Scopes</div>', "Authorized scopes",
                     '<div class="l">Low notes</div>', "Flagged (MEDIUM+)"):
            self.assertNotIn(gone, html, gone)
        cards = _region(html, "r-cards")
        self.assertIn('<div class="l">Actions</div>', cards)
        self.assertIn('<div class="l">Tools</div>', cards)

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
                     '<div class="l">Low notes</div>', "function liveCheckpoints"):
            self.assertIn(kept, html, kept)
        self.assertNotIn('id="door-summary"', html)
        self.assertNotIn("door", _embedded(html, "halo-config"))
        self.assertIn('<div class="note prov-note">', html)

    def test_summary_lines(self):
        html = _static(self.page(own_supplied=False))
        summary = _region(html, "door-summary")
        self.assertIn("app:Example Agent acted in acme 3 times between 2026-10-10 and 2026-10-10.", summary)
        self.assertIn("1 rule broken: no-repo-deletion", summary)
        self.assertIn("It used 1 credential: app:Example Agent.", summary)
        self.assertNotIn("look like a person", summary)
        self.assertIn("No vendor record was supplied; this page shows the platform's own log only.", summary)
        self.assertNotIn("not in the agent's own record", summary)

    def test_summary_with_a_vendor_record(self):
        html = _static(self.page(own_supplied=True, as_person=[
            {"ingested": self.chain_records[-1], "gap_seconds": 12.0}]))
        summary = _region(html, "door-summary")
        self.assertIn("3 actions are not in the agent's own record.", summary)
        self.assertIn("1 action looks like a person on the agent's session.", summary)
        self.assertNotIn("No vendor record was supplied", summary)

    def test_source_line_names_the_platform(self):
        html = _static(self.page())
        self.assertIn("Source: the buyer's own GitHub export, sealed on ingest. The export is as "
                      "complete as what the platform logged; sealing proves this copy has not "
                      "been edited since.", html)
        self.assertIn("Anchor receipt: none", html)
        self.assertIn("Ingested", html[html.index('id="r-provenance"'):])
        # the vendor-telemetry note under the provenance grid is not on the buyer's page
        self.assertNotIn('<div class="note prov-note">', html)

    def test_detail_sections_fold_below_the_summary(self):
        html = _static(self.page())
        for section in ("Rules", "Credentials the agent used", "What this source cannot show"):
            self.assertIn("<summary>%s" % section, html, section)
        self.assertLess(html.index("door-summary"), html.index("<details"))
        self.assertLess(html.rindex("</details>"), html.index('id="tablewrap"'))

    def test_sample_banner_only_when_sample(self):
        self.assertIn("SAMPLE — synthetic export; no real account data.", self.page(sample=True))
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


class SalesforceDoorPage(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        events = door.parse_salesforce_eventlog(FIXTURE, allowlist=door.DEFAULT_ALLOWLIST)
        self.chain_records = door.ingest(events, Recorder(os.path.join(self.tmp, "c.jsonl")))
        self.mine = door.isolate(self.chain_records, APP)
        rules = door.load_rules(door.bundled_rules("salesforce-default"))
        self.html = door.render_page(
            self.mine, door.match(self.mine, []), door.check(self.mine, rules), agent=APP,
            own_supplied=False, sample=True, source="salesforce",
            allowlist=list(door.DEFAULT_ALLOWLIST), chain=self.chain_records,
            shared=door.shared_sessions(events))

    def test_summary_and_counts(self):
        summary = _region(_static(self.html), "door-summary")
        self.assertRegex(summary, r"app:Acme Collections Agent acted in this org 123 times between "
                                  r"\d{4}-\d{2}-\d{2} and \d{4}-\d{2}-\d{2}\.")
        self.assertIn("4 rules broken: ", summary)
        for rule in ("no-data-export", "no-login-as", "no-metadata-change", "login-outside-allowlist"):
            self.assertIn(rule, summary)
        self.assertIn("No vendor record was supplied; this page shows the platform's own log only.", summary)
        self.assertEqual(len(_static_rows(self.html)), 123)
        self.assertEqual(len(_embedded(self.html, "records")), len(self.chain_records))

    def test_platform_vocabulary_and_banner(self):
        static = _static(self.html)
        self.assertIn("Connected app <b>app:Acme Collections Agent</b>", _region(static, "r-meta"))
        self.assertIn("Source: the buyer's own Salesforce export, sealed on ingest.", static)
        self.assertTrue(static.index("SAMPLE — synthetic Salesforce export") < static.index("<h1"))
        self.assertIn("<summary>One session, more than one address", static)
        self.assertNotIn("code pushes", static)

    def test_no_addresses_outside_test_net_and_no_emails(self):
        self.assertNotRegex(self.html, r"\b(?!192\.0\.2\.|198\.51\.100\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        self.assertNotRegex(self.html, r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


if __name__ == "__main__":
    unittest.main()
