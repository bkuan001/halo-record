"""The door reading a Salesforce Event Monitoring export: EventLogFile CSVs
(Login, RestApi, ApexExecution, URI) normalized into the same event shape the
GitHub reader produces, sealed, isolated to one connected app, checked against
the salesforce-default pack, and rendered.

The bundled sample (halo_record/samples/salesforce_eventlog) is synthetic:
placeholder names (Globex, Acme), TEST-NET addresses, SAMPLE-marked ids."""

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from halo_record import door
from halo_record.record import Recorder

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = door.bundled_sample("salesforce_eventlog")
APP = "app:Acme Collections Agent"
BOT = "app:bot:0XxSAMPLE00000001A"
TEST_NETS = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"))


class SfBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def chain(self, name="c.jsonl"):
        return os.path.join(self.tmp, name)

    def events(self, allowlist=None):
        return door.parse_salesforce_eventlog(FIXTURE, allowlist=allowlist)

    def ingested(self, allowlist=None, **kw):
        return door.ingest(self.events(allowlist), Recorder(self.chain()), **kw)

    def rules(self):
        return door.load_rules(door.bundled_rules("salesforce-default"))

    def csv(self, name, header, rows):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(",".join('"%s"' % h for h in header) + "\n")
            for r in rows:
                fh.write(",".join('"%s"' % v for v in r) + "\n")
        return p


class TestParse(SfBase):
    def test_reads_a_directory_of_eventlog_csvs(self):
        events = self.events()
        self.assertEqual(len(events), 146)
        self.assertEqual(events.skipped, {})
        self.assertTrue(events.sample)
        self.assertEqual([e["ts"] for e in events], sorted(e["ts"] for e in events))

    def test_field_mapping_rest_api(self):
        e = [e for e in self.events() if e["event_type"] == "RestApi"][0]
        self.assertEqual(e["adapter"], "salesforce_eventlog")
        self.assertEqual(e["action"], "RestApi.GET")
        self.assertEqual(e["actor"], "svc.acme@globex.example")
        self.assertEqual(e["app"], "Acme Collections Agent")
        self.assertEqual(e["token_id"], "LKa05")
        self.assertEqual(e["ip"], "192.0.2.10")
        self.assertEqual(e["repo"], "Contact")
        self.assertRegex(e["ts"], r"^2026-10-05T13:\d\d:\d\d\+00:00$")
        self.assertRegex(e["raw_hash"], r"^sha256:[0-9a-f]{64}$")
        self.assertIn("python-requests", e["user_agent"])

    def test_field_mapping_login_apex_uri(self):
        by_type = {}
        for e in self.events():
            by_type.setdefault(e["event_type"], []).append(e)
        login = [e for e in by_type["Login"] if e["actor"] == "svc.acme@globex.example"][0]
        self.assertEqual(login["action"], "Login.Remote_Access_2_0")
        self.assertEqual(login["ip"], "192.0.2.10")
        self.assertEqual(login["token_id"], "LKa05")
        apex = [e for e in by_type["ApexExecution"] if e["action"].startswith("ApexExecution.AcmeCollections")][0]
        self.assertEqual(apex["actor"], "svc.acme@globex.example")   # USER_ID resolved through the other files
        self.assertEqual(apex["repo"], "AcmeCollections.CaseSync.run")
        uri = [e for e in by_type["URI"] if e["action"] == "URI.page"][0]
        self.assertTrue(uri["repo"].startswith("/lightning/"))

    def test_derived_actions_for_the_shapes_rules_name(self):
        actions = {e["action"] for e in self.events()}
        self.assertIn("Login.Login_As", actions)
        self.assertIn("URI.ReportExport", actions)
        self.assertIn("ApexExecution.Metadata", actions)
        self.assertIn("URI.Setup", actions)

    def test_attribution_app_bot_session_and_person(self):
        keys = {}
        for e in self.events():
            keys.setdefault((e["event_type"], e["action"]), set()).add(door.agent_key(e))
        self.assertEqual(keys[("RestApi", "RestApi.GET")], {APP})
        self.assertEqual(keys[("ApexExecution", "ApexExecution.AcmeCollections")], {APP, BOT})
        # rows with no CLIENT_NAME inherit the app through the session key
        self.assertEqual(keys[("URI", "URI.ReportExport")], {APP})
        self.assertEqual(keys[("Login", "Login.Remote_Access_2_0")], {APP})
        # a person in a browser: no programmatic client
        self.assertEqual(keys[("Login", "Login.Application")], {None})
        self.assertEqual(keys[("URI", "URI.Setup")], {None})

    def test_bot_identifier_outranks_the_session(self):
        bot = [e for e in self.events() if door.agent_key(e) == BOT]
        self.assertEqual(len(bot), 3)
        self.assertTrue(all(e["event_type"] == "ApexExecution" for e in bot))

    def test_unknown_event_types_are_skipped_and_counted(self):
        p = self.csv("Logout.csv", ["EVENT_TYPE", "TIMESTAMP_DERIVED", "USER_ID", "LOGIN_KEY"],
                     [["Logout", "2026-10-05T18:00:00.000Z", "005SAMPLE00000001A", "LKa05"],
                      ["Logout", "2026-10-06T18:00:00.000Z", "005SAMPLE00000001A", "LKa06"]])
        events = door.parse_salesforce_eventlog([p, os.path.join(FIXTURE, "Login.csv")])
        self.assertEqual(events.skipped, {"Logout": 2})
        self.assertEqual(len(events), 17)
        self.assertTrue(events.sample)   # any file from the bundled sample marks the whole input
        self.assertFalse(door.parse_salesforce_eventlog(p).sample)

    def test_refuses_a_csv_without_event_type(self):
        p = self.csv("other.csv", ["when", "who"], [["2026-10-05", "x"]])
        with self.assertRaises(ValueError):
            door.parse_salesforce_eventlog(p)

    def test_fixture_is_test_net_and_placeholders_only(self):
        for e in self.events():
            if e.get("ip"):
                self.assertTrue(any(ipaddress.ip_address(e["ip"]) in n for n in TEST_NETS), e["ip"])
            if e.get("actor"):
                self.assertTrue(e["actor"].endswith("@globex.example"), e["actor"])
        with open(os.path.join(FIXTURE, "RestApi.csv"), encoding="utf-8") as fh:
            self.assertNotRegex(fh.read(), r"\b00D[0-9A-Za-z]{12,15}\b")  # no org ids at all

    def test_ip_allowlist(self):
        self.assertTrue(door.ip_allowed("192.0.2.77", ["192.0.2.0/24"]))
        self.assertFalse(door.ip_allowed("198.51.100.7", ["192.0.2.0/24"]))
        self.assertFalse(door.ip_allowed("not-an-ip", ["192.0.2.0/24"]))
        self.assertIsNone(door.ip_allowed(None, ["192.0.2.0/24"]))

    def test_allowlist_classifies_sign_ins(self):
        outside = [e for e in self.events(door.DEFAULT_ALLOWLIST) if e["action"] == "Login.outside_allowlist"]
        self.assertEqual(len(outside), 1)
        self.assertEqual(outside[0]["ip"], "198.51.100.7")
        self.assertIn("outside allowlist", outside[0]["detail"])
        self.assertNotIn("198.51.100.7", outside[0]["detail"])
        # without an allowlist no sign-in is classified; a wider one clears it
        self.assertEqual([e for e in self.events() if e["action"] == "Login.outside_allowlist"], [])
        self.assertEqual([e for e in self.events(["192.0.2.0/24", "198.51.100.0/24"])
                          if e["action"] == "Login.outside_allowlist"], [])


class TestIngest(SfBase):
    def test_seals_salesforce_records_that_verify(self):
        recs = self.ingested(subject="globex", allowlist=door.DEFAULT_ALLOWLIST)
        self.assertEqual(len(recs), 146)
        r = [r for r in recs if r["action"]["tool"] == "salesforce:RestApi.GET"][0]
        self.assertEqual(r["source"]["adapter"], "salesforce_eventlog")
        self.assertEqual(r["source"]["capture"], "ingested")
        self.assertEqual(r["agent"]["id"], APP)
        # the person is sealed as the agent field shows them: initial and domain
        self.assertEqual(r["principal"]["human_id"], "s****@globex.example")
        self.assertEqual(r["data"]["event_type"], "RestApi")
        self.assertRegex(r["data"]["source_row"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(sum(1 for r in recs if r["action"]["tool"] == "salesforce:Login.outside_allowlist"), 1)
        env = dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "src"))
        out = subprocess.run([sys.executable, "-m", "halo_record.cli", "verify", self.chain()],
                             capture_output=True, text=True, env=env)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_raw_row_is_hashed_not_stored(self):
        self.ingested()
        with open(self.chain(), encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("SKa05", text)                      # session keys never sealed
        self.assertNotIn("SELECT Id, Status", text)          # nor query text
        self.assertNotIn("192.0.2.10", text)                 # nor addresses
        self.assertNotIn("SAMPLE-REQ-", text)

    def test_isolate_app_spans_its_sessions(self):
        mine = door.isolate(self.ingested(), APP)
        types = {r["data"]["event_type"] for r in mine}
        self.assertEqual(types, {"Login", "RestApi", "ApexExecution", "URI"})
        self.assertEqual(len(mine), 9 + 97 + 15 + 2)


class TestQueryStrings(SfBase):
    """A query string never enters the chain: the RestApi and URI readers drop
    it before anything is kept, as the ApexCallout reader does."""

    KEY = "k7Qp2ZxLm9VbT4RwYs8HnJ3dFgC1eA6u"
    REST = ["EVENT_TYPE", "TIMESTAMP_DERIVED", "USER_ID", "USER_NAME", "CLIENT_NAME", "METHOD", "URI",
            "ENTITY_NAME", "STATUS_CODE", "LOGIN_KEY"]
    URI = ["EVENT_TYPE", "TIMESTAMP_DERIVED", "USER_ID", "URI", "REQUEST_STATUS", "LOGIN_KEY"]

    def setUp(self):
        super().setUp()
        q = "?apikey=%s&caseId=SECRETNAME" % self.KEY
        self.paths = [
            self.csv("RestApi.csv", self.REST,
                     [["RestApi", "2026-10-05T13:06:41.000Z", "005SAMPLE00000001A", "svc.acme@globex.example",
                       "Acme Collections Agent", "GET", "/services/data/v62.0/query" + q, "Case", "200", "LKq1"]]),
            self.csv("URI.csv", self.URI,
                     [["URI", "2026-10-05T13:07:41.000Z", "005SAMPLE00000001A",
                       "/lightning/o/Case/list" + q, "200", "LKq1"]]),
        ]

    def test_query_string_is_not_sealed_or_rendered(self):
        events = door.parse_salesforce_eventlog(self.paths)
        recs = door.ingest(events, Recorder(self.chain()))
        self.assertEqual(len(recs), 2)
        for r in recs:
            summary = r["action"]["input"]["summary"]
            for leak in (self.KEY, "SECRETNAME", "apikey", "caseId"):
                self.assertNotIn(leak, summary, r["action"]["tool"])
                self.assertNotIn(leak, r["data"]["target"], r["action"]["tool"])
        self.assertEqual(recs[0]["data"]["target"], "/services/data/v62.0/query")
        self.assertEqual(recs[1]["data"]["target"], "/lightning/o/Case/list")
        mine = door.isolate(recs, APP)
        html = door.render_page(mine, door.match(mine, []), door.check(mine, self.rules()), agent=APP,
                                source="salesforce", own_supplied=False, chain=recs,
                                events=door.event_index(events, recs))
        with open(self.chain(), encoding="utf-8") as fh:
            chain_text = fh.read()
        for leak in (self.KEY, "SECRETNAME"):
            self.assertNotIn(leak, html)
            self.assertNotIn(leak, chain_text)


class TestUnreadableRows(SfBase):
    """A row the reader cannot date, or that carries fewer columns than the
    header, is not sealed: it is counted, reported, and named on the page."""

    HEAD = ["EVENT_TYPE", "TIMESTAMP_DERIVED", "USER_ID", "USER_NAME", "CLIENT_NAME", "METHOD", "URI",
            "ENTITY_NAME", "STATUS_CODE", "LOGIN_KEY"]

    def row(self, ts, uri="/services/data/v62.0/query"):
        return ["RestApi", ts, "005SAMPLE00000001A", "svc.acme@globex.example", "Acme Collections Agent",
                "GET", uri, "Case", "200", "LKr1"]

    def test_unreadable_timestamp_is_skipped_and_counted(self):
        p = self.csv("RestApi.csv", self.HEAD, [self.row("2026-10-05T13:06:41.000Z"), self.row("yesterday"),
                                                 self.row(""), self.row("2026-10-05T13:08:41.000Z")])
        events = door.parse_salesforce_eventlog(p)
        self.assertEqual(len(events), 2)
        self.assertTrue(all(e["ts"] for e in events))
        self.assertEqual(events.dropped, {"unreadable timestamp": 2})
        recs = door.ingest(events, Recorder(self.chain()))
        self.assertEqual([r["ts"][:19] for r in recs], ["2026-10-05T13:06:41", "2026-10-05T13:08:41"])

    def test_short_row_is_skipped_and_counted(self):
        p = os.path.join(self.tmp, "RestApi.csv")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(",".join('"%s"' % h for h in self.HEAD) + "\n")
            fh.write(",".join('"%s"' % v for v in self.row("2026-10-05T13:06:41.000Z")) + "\n")
            fh.write('"RestApi","2026-10-05T13:07:41.000Z","005SAMPLE00000001A"\n')   # three of ten columns
        events = door.parse_salesforce_eventlog(p)
        self.assertEqual(len(events), 1)
        self.assertEqual(events.dropped, {"fewer columns than the header": 1})
        self.assertEqual([e["action"] for e in events], ["RestApi.GET"])

    def test_cli_reports_skipped_rows_and_the_page_names_them(self):
        d = os.path.join(self.tmp, "export")
        os.mkdir(d)
        with open(os.path.join(d, "RestApi.csv"), "w", encoding="utf-8") as fh:
            fh.write(",".join('"%s"' % h for h in self.HEAD) + "\n")
            fh.write(",".join('"%s"' % v for v in self.row("2026-10-05T13:06:41.000Z")) + "\n")
            fh.write(",".join('"%s"' % v for v in self.row("yesterday")) + "\n")
            fh.write(",".join('"%s"' % v for v in self.row("10/05/2026 1:06 PM")) + "\n")
            fh.write('"RestApi","2026-10-05T13:07:41.000Z","005SAMPLE00000001A"\n')
        env = dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "src"))
        out = subprocess.run([sys.executable, "-m", "halo_record.cli", "door", d, "--agent", APP,
                              "--out", "p.html", "--chain", "c.jsonl"],
                             capture_output=True, text=True, env=env, cwd=self.tmp)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("2 rows skipped: unreadable timestamp", out.stdout)
        self.assertIn("1 row skipped: fewer columns than the header", out.stdout)
        self.assertIn("1 actions by", out.stdout)
        with open(os.path.join(self.tmp, "p.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("3 rows in the export were not sealed: unreadable timestamp (2), "
                      "fewer columns than the header (1).", html)
        with open(os.path.join(self.tmp, "c.jsonl"), encoding="utf-8") as fh:
            self.assertEqual(len(fh.read().splitlines()), 1)


class TestCliRefusals(SfBase):
    """halo door checks what it can before sealing, and reports what it
    cannot read in one line: no traceback, no orphan chain."""

    HEAD = ["EVENT_TYPE", "TIMESTAMP_DERIVED", "USER_ID", "USER_NAME", "CLIENT_NAME", "METHOD", "URI",
            "ENTITY_NAME", "STATUS_CODE", "LOGIN_KEY"]

    def run_cli(self, *argv):
        env = dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "src"))
        return subprocess.run([sys.executable, "-m", "halo_record.cli", "door", *argv],
                              capture_output=True, text=True, env=env, cwd=self.tmp)

    def export(self):
        d = os.path.join(self.tmp, "export")
        if not os.path.isdir(d):
            shutil.copytree(FIXTURE, d)
        return d

    def test_csv_the_reader_refuses_is_reported_not_raised(self):
        # A field beyond the csv module's field limit is one it refuses to
        # read; the file is named, with the reader's reason, and nothing is sealed.
        d = self.export()
        with open(os.path.join(d, "RestApi.csv"), "a", encoding="utf-8") as fh:
            fh.write('"RestApi","2026-10-05T13:06:41.000Z","005SAMPLE00000001A","%s"\n' % ("x" * 140000))
        out = self.run_cli(d, "--agent", APP, "--out", "p.html", "--chain", "c.jsonl")
        self.assertEqual(out.returncode, 2, out.stdout)
        self.assertIn("halo door: %s: " % os.path.join(d, "RestApi.csv"), out.stderr)
        self.assertNotIn("Traceback", out.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "c.jsonl")))

    def test_nul_byte_in_a_csv_is_never_a_traceback(self):
        # Older csv modules refuse a NUL byte (reported as above); newer ones
        # read it, and the torn row is counted, not sealed.
        d = self.export()
        with open(os.path.join(d, "RestApi.csv"), "ab") as fh:
            fh.write(b'"RestApi","2026-10-05T13:06:41.000Z","005SAMPLE00000001A","x\x00y"\n')
        out = self.run_cli(d, "--agent", APP, "--out", "p.html", "--chain", "c.jsonl")
        self.assertIn(out.returncode, (0, 2), out.stderr)
        self.assertNotIn("Traceback", out.stderr)
        if out.returncode == 2:
            self.assertIn("halo door: %s: " % os.path.join(d, "RestApi.csv"), out.stderr)
            self.assertFalse(os.path.exists(os.path.join(self.tmp, "c.jsonl")))
        else:
            self.assertIn("1 row skipped: fewer columns than the header", out.stdout)

    def test_undecodable_csv_is_reported_not_raised(self):
        d = self.export()
        with open(os.path.join(d, "URI.csv"), "ab") as fh:
            fh.write(b'"URI","2026-10-05T13:06:41.000Z","005SAMPLE00000002A","/\xff\xfe"\n')
        out = self.run_cli(d, "--agent", APP, "--out", "p.html", "--chain", "c.jsonl")
        self.assertEqual(out.returncode, 2, out.stdout)
        self.assertIn("halo door: %s: " % os.path.join(d, "URI.csv"), out.stderr)
        self.assertNotIn("Traceback", out.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "c.jsonl")))

    @unittest.skipIf(os.geteuid() == 0, "root can write anywhere")
    def test_unwritable_out_leaves_no_chain(self):
        d = self.export()
        locked = os.path.join(self.tmp, "locked")
        os.mkdir(locked)
        os.chmod(locked, 0o500)
        try:
            out = self.run_cli(d, "--agent", APP, "--out", os.path.join(locked, "p.html"), "--chain", "c.jsonl")
        finally:
            os.chmod(locked, 0o700)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("halo door: cannot write --out", out.stderr)
        self.assertNotIn("Traceback", out.stderr)
        self.assertEqual(len(out.stderr.strip().splitlines()), 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "c.jsonl")))

    @unittest.skipIf(os.geteuid() == 0, "root can write anywhere")
    def test_unwritable_chain_is_one_line(self):
        d = self.export()
        locked = os.path.join(self.tmp, "locked")
        os.mkdir(locked)
        os.chmod(locked, 0o500)
        try:
            out = self.run_cli(d, "--agent", APP, "--out", "p.html", "--chain", os.path.join(locked, "c.jsonl"))
        finally:
            os.chmod(locked, 0o700)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("halo door: cannot write --chain", out.stderr)
        self.assertNotIn("Traceback", out.stderr)
        self.assertEqual(len(out.stderr.strip().splitlines()), 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "p.html")))

    def test_absent_agent_leaves_no_chain(self):
        out = self.run_cli(self.export(), "--agent", "app:Nobody", "--out", "p.html", "--chain", "c.jsonl")
        self.assertEqual(out.returncode, 3, out.stdout)
        self.assertIn("no actions by 'app:Nobody'", out.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "c.jsonl")))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "p.html")))

    def test_declared_agent_key_is_found_before_sealing(self):
        # agent:NAME selects every credential that declared NAME; the check
        # before sealing follows the same rule as isolate.
        rows = [{"@timestamp": 1791590400000, "action": "git.push", "actor": "dev", "repo": "acme/widgets",
                 "programmatic_access_type": "OAuth access token", "oauth_application_name": "Example Agent",
                 "user_agent": "gh/2.0 Agent/claude-code_1.0_agent"}]
        p = os.path.join(self.tmp, "export.json")
        with open(p, "w") as fh:
            json.dump(rows, fh)
        out = self.run_cli(p, "--agent", "agent:claude-code", "--out", "g.html", "--chain", "g.jsonl")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("1 actions by agent:claude-code", out.stdout)


class TestRules(SfBase):
    def test_each_rule_fires_once_on_the_app(self):
        mine = door.isolate(self.ingested(allowlist=door.DEFAULT_ALLOWLIST), APP)
        by_id = {r["id"]: r for r in door.check(mine, self.rules())["rules"]}
        self.assertEqual(sorted(by_id), ["login-outside-allowlist", "no-data-export",
                                         "no-login-as", "no-metadata-change"])
        for rid, r in by_id.items():
            self.assertEqual(r["status"], "violated", rid)
            self.assertEqual(len(r["violators"]), 1, rid)

    def test_rules_stay_silent_on_clean_rows(self):
        recs = self.ingested(allowlist=door.DEFAULT_ALLOWLIST)
        bot = door.isolate(recs, BOT)
        verdict = door.check(bot, self.rules())
        self.assertEqual(verdict["violations"], 0)
        self.assertEqual({r["status"] for r in verdict["rules"]} - {"pass", "no_match"}, set())

    def test_allowlist_is_configurable(self):
        mine = door.isolate(self.ingested(allowlist=["192.0.2.0/24", "198.51.100.0/24"]), APP)
        by_id = {r["id"]: r for r in door.check(mine, self.rules())["rules"]}
        self.assertEqual(by_id["login-outside-allowlist"]["status"], "pass")
        self.assertEqual(by_id["no-data-export"]["status"], "violated")

    def test_descriptions_read_for_a_controls_owner(self):
        for r in self.rules():
            self.assertNotIn("regex", r["description"].lower())
            self.assertTrue(r["description"].startswith("The integration did not"), r["id"])


class TestSharedSessions(SfBase):
    def test_one_session_two_addresses(self):
        hits = door.shared_sessions(self.events())
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["session"], "LKa10")
        self.assertEqual(hits[0]["ips"], ["192.0.2.10", "198.51.100.23"])
        self.assertEqual(hits[0]["agent"], APP)
        self.assertEqual(hits[0]["rows"], 2)


class TestPage(SfBase):
    def page(self, **kw):
        recs = door.isolate(self.ingested(allowlist=door.DEFAULT_ALLOWLIST), APP)
        kw.setdefault("source", "salesforce")
        kw.setdefault("allowlist", list(door.DEFAULT_ALLOWLIST))
        return door.render_page(recs, door.match(recs, []), door.check(recs, self.rules()),
                                agent=APP, **kw)

    def test_no_vendor_record_state(self):
        html = self.page(own_supplied=False)
        self.assertIn("No vendor record supplied; this page shows the platform's log only", html)
        self.assertNotIn("not in the agent's own record", html)
        self.assertNotIn("matched or probable", html)
        self.assertNotIn("unmatched", html)

    def test_own_record_keeps_the_comparison(self):
        html = self.page(own_supplied=True)
        self.assertIn("not in the agent's own record", html)
        self.assertNotIn("No vendor record supplied", html)

    def test_anchor_sentence(self):
        html = self.page(own_supplied=False)
        self.assertIn("relative to a head someone other than the operator holds", html)
        self.assertIn("Anchor receipt: none", html)
        html = self.page(own_supplied=False, anchored="witness.example 2026-10-12")
        self.assertIn("Anchor receipt: witness.example 2026-10-12", html)

    def test_sample_banner(self):
        self.assertIn("SAMPLE — synthetic export shaped from public sources; no real org data.", self.page(sample=True))
        self.assertNotIn("SAMPLE —", self.page(sample=False))

    def test_rules_row_without_an_allowlist(self):
        recs = door.isolate(self.ingested(allowlist=None), APP)
        html = door.render_page(recs, door.match(recs, []), door.check(recs, self.rules()), agent=APP,
                                source="salesforce", allowlist=None, own_supplied=False)
        row = re.search(r'<div class="rulesrow">(.*?)</div>', html, re.S).group(1)
        self.assertIn('<span class="u" title="login-outside-allowlist: ', row)
        self.assertIn("Login outside allowlist &middot; not evaluated: pass --allow-ip with your "
                      "org&#x27;s addresses</span>", row)
        self.assertNotIn("not applicable", row)
        self.assertIn(">Data export &middot; broken, 1 action</span>", row)
        # with an allowlist the rule reads as checked
        row = re.search(r'<div class="rulesrow">(.*?)</div>', self.page(), re.S).group(1)
        self.assertNotIn("not evaluated", row)

    def test_salesforce_cannot_show_list(self):
        html = self.page(own_supplied=False)
        self.assertIn("What this export can&#x27;t show", html)
        self.assertNotIn("What this source cannot show", html)
        self.assertIn("Agentforce", html)
        self.assertIn("may require", html)
        self.assertNotIn("requires the Event Monitoring", html)
        self.assertNotIn("code pushes", html)

    def test_full_render_smoke(self):
        html = self.page(own_supplied=False, sample=True,
                         shared=door.shared_sessions(self.events()))
        for needle in ("no-data-export", "no-login-as", "no-metadata-change", "login-outside-allowlist",
                       "Acme Collections Agent", "One session, more than one address", "LKa10",
                       "Login_As", "ReportExport", "Metadata", "192.0.2.0/24"):
            self.assertIn(needle, html, needle)
        # No GitHub vocabulary on a Salesforce page; the footer's link to the
        # halo-record repository is the one place the name belongs.
        self.assertNotIn("github", html[:html.index("<footer>")].lower())
        self.assertNotIn("SKa05", html)


class TestCli(SfBase):
    def run_cli(self, *argv):
        env = dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "src"))
        return subprocess.run([sys.executable, "-m", "halo_record.cli", "door", *argv],
                              capture_output=True, text=True, env=env, cwd=self.tmp)

    def test_autodetects_and_lists_clients(self):
        out = self.run_cli(FIXTURE)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(APP, out.stdout)
        self.assertIn(BOT, out.stdout)

    def test_renders_the_sample_page(self):
        out = self.run_cli(FIXTURE, "--source", "salesforce", "--policy", "salesforce-default",
                           "--sample", "--agent", APP, "--out", "p.html", "--chain", "c.jsonl")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("rules broken: 4", out.stdout)
        self.assertIn("vendor record: none supplied", out.stdout)
        with open(os.path.join(self.tmp, "p.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("SAMPLE — synthetic export shaped from public sources; no real org data.", html)
        self.assertIn("No vendor record supplied", html)
        self.assertIn("One session, more than one address", html)
        self.assertNotRegex(html, r"\b(?!192\.0\.2\.|198\.51\.100\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

    def test_bundled_sample_is_marked_sample_without_the_flag(self):
        out = self.run_cli(FIXTURE, "--agent", APP, "--out", "p.html", "--chain", "c.jsonl")
        self.assertEqual(out.returncode, 0, out.stderr)
        with open(os.path.join(self.tmp, "p.html"), encoding="utf-8") as fh:
            self.assertIn("SAMPLE — synthetic", fh.read())

    def test_directory_name_does_not_mark_sample(self):
        # SAMPLE is explicit: the --sample flag, or the bundled sample itself.
        # A real export in a directory that happens to say "sample" is not one.
        d = os.path.join(self.tmp, "acme-sample-2026")
        shutil.copytree(FIXTURE, d)
        out = self.run_cli(d, "--agent", APP, "--allow-ip", "192.0.2.0/24", "--out", "p.html", "--chain", "c.jsonl")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotIn("SAMPLE", out.stdout)
        with open(os.path.join(self.tmp, "p.html"), encoding="utf-8") as fh:
            self.assertNotIn("SAMPLE —", fh.read())
        out = self.run_cli(d, "--sample", "--agent", APP, "--out", "q.html", "--chain", "d.jsonl")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("SAMPLE: synthetic export", out.stdout)
        with open(os.path.join(self.tmp, "q.html"), encoding="utf-8") as fh:
            self.assertIn("SAMPLE — synthetic", fh.read())

    def test_real_export_without_allow_ip_leaves_the_sign_in_rule_unevaluated(self):
        # A real export has no default allowlist: nothing is sealed as
        # outside_allowlist, and the rule row says what to pass.
        d = os.path.join(self.tmp, "export")
        shutil.copytree(FIXTURE, d)
        out = self.run_cli(d, "--agent", APP, "--out", "p.html", "--chain", "c.jsonl")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("rules broken: 3", out.stdout)
        self.assertIn("login-outside-allowlist: not evaluated (pass --allow-ip with your org's addresses)",
                      out.stdout)
        with open(os.path.join(self.tmp, "c.jsonl"), encoding="utf-8") as fh:
            self.assertNotIn("outside_allowlist", fh.read())
        with open(os.path.join(self.tmp, "p.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("Login outside allowlist &middot; not evaluated: pass --allow-ip with your "
                      "org&#x27;s addresses</span>", html)
        self.assertIn("No address allowlist was supplied", html)
        # the bundled sample keeps the fixture's range (rules broken: 4, see
        # test_renders_the_sample_page), as does --sample on a real export
        out = self.run_cli(d, "--sample", "--agent", APP, "--out", "q.html", "--chain", "d.jsonl")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("rules broken: 4", out.stdout)

    def test_allow_ip_overrides_the_default(self):
        out = self.run_cli(FIXTURE, "--agent", APP, "--allow-ip", "192.0.2.0/24",
                           "--allow-ip", "198.51.100.0/24", "--out", "p.html", "--chain", "c.jsonl")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("rules broken: 3", out.stdout)

    def test_sample_flag_alone_runs_the_bundled_agentforce_sample(self):
        # From any directory, with no export path: the bundled Agentforce
        # sample, the agentforce pack, the fixture's allowlist, a SAMPLE page.
        out = self.run_cli("--sample", "--agent", BOT, "--out", "s.html", "--chain", "s.jsonl")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("13 actions by %s" % BOT, out.stdout)
        self.assertIn("rules broken: 1", out.stdout)
        self.assertIn("SAMPLE: synthetic export", out.stdout)
        with open(os.path.join(self.tmp, "s.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("SAMPLE — synthetic export shaped from public sources; no real org data.", html)
        self.assertIn("Where it reached", html)
        self.assertIn("no-external-transfer", html)
        listed = self.run_cli("--sample")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn(BOT, listed.stdout)

    def test_no_export_path_and_no_sample_is_refused(self):
        out = self.run_cli("--agent", BOT)
        self.assertEqual(out.returncode, 2)
        self.assertIn("halo door: pass an export path, or --sample", out.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "door.jsonl")))

    def test_help_describes_the_bundled_sample(self):
        out = self.run_cli("--help")
        self.assertEqual(out.returncode, 0)
        self.assertIn("bundled sample", out.stdout)
        self.assertNotIn("automatic for the bundled fixture", out.stdout)

    def test_own_record_is_not_compared_for_a_salesforce_export(self):
        # No matcher exists for this source yet: the page says so instead of
        # reporting every row as missing from the agent's own record.
        own = os.path.join(self.tmp, "own.jsonl")
        from halo_record.record import build
        Recorder(own).append(build("tool_call", "security", tool="Bash", tool_input={"command": "ls"},
                                   ts="2026-10-05T13:06:41+00:00", agent={"id": "acme-agent"}, source="hook"))
        out = self.run_cli(FIXTURE, "--agent", APP, "--own", own, "--out", "p.html", "--chain", "c.jsonl")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("Comparison with the agent's own record is not available for this source yet",
                      out.stdout)
        self.assertNotIn("unmatched", out.stdout)
        with open(os.path.join(self.tmp, "p.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("Comparison with the agent's own record is not available for this source yet.", html)
        self.assertNotIn("not in the agent's own record", html)
        self.assertNotIn("Against the agent's own record", html)
        self.assertNotIn("No vendor record supplied", html)

    def test_github_export_without_own_also_says_no_vendor_record(self):
        rows = [{"@timestamp": 1791590400000, "action": "git.push", "actor": "dev",
                 "repo": "acme/widgets", "programmatic_access_type": "OAuth access token",
                 "oauth_application_name": "Example Agent"}]
        p = os.path.join(self.tmp, "export.json")
        with open(p, "w") as fh:
            json.dump(rows, fh)
        out = self.run_cli(p, "--agent", "app:Example Agent", "--out", "g.html", "--chain", "g.jsonl")
        self.assertEqual(out.returncode, 0, out.stderr)
        with open(os.path.join(self.tmp, "g.html"), encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("No vendor record supplied", html)
        self.assertNotIn("SAMPLE —", html)


if __name__ == "__main__":
    unittest.main()
