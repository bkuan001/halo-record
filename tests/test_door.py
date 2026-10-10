"""Buyer-side ingest ("the door"): turn a log export the buyer already has into
sealed, ingested-tier records about one outside agent, match them against that
agent's own record, check them against a rules file, and render one page.

Fixture data is synthetic (acme); field shapes follow a GitHub account
security-log export."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from halo_record import door
from halo_record.record import Recorder, build

EXPORT_ROWS = [
    # an outside agent pushing through an OAuth app token
    {"@timestamp": 1791590400000, "action": "git.push", "actor": "dev",
     "repo": "acme/widgets", "programmatic_access_type": "OAuth access token",
     "oauth_application_name": "Example Agent"},
    # the same agent opening a pull request two minutes later
    {"@timestamp": 1791590520000, "action": "pull_request.create", "actor": "dev",
     "repo": "acme/widgets", "programmatic_access_type": "OAuth access token",
     "oauth_application_name": "Example Agent"},
    # the same agent doing something nothing recorded on its own side
    {"@timestamp": 1791594000000, "action": "repo.destroy", "actor": "dev",
     "repo": "acme/old-thing", "programmatic_access_type": "OAuth access token",
     "oauth_application_name": "Example Agent"},
    # a personal-access-token client (a different agent)
    {"@timestamp": 1791590450000, "action": "git.clone", "actor": "dev",
     "repo": "acme/widgets", "programmatic_access_type": "Personal access token (classic)",
     "token_id": 4242},
    # the human in a browser: no programmatic access
    {"@timestamp": 1791590600000, "action": "user.login", "actor": "dev",
     "user_agent": "Mozilla/5.0"},
]

AGENT = "app:Example Agent"


def _own(ts, command):
    return build("tool_call", "security", tool="Bash",
                 tool_input={"command": command}, ts=ts,
                 agent={"id": "example-agent"}, source="hook")


class DoorBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def export(self, rows, jsonl=False):
        p = os.path.join(self.tmp, "export.jsonl" if jsonl else "export.json")
        with open(p, "w") as f:
            if jsonl:
                f.write("\n".join(json.dumps(r) for r in rows) + "\n")
            else:
                json.dump(rows, f)
        return p

    def chain(self, name="c.jsonl"):
        return os.path.join(self.tmp, name)

    def ingested(self, rows=EXPORT_ROWS, **kw):
        events = door.parse_github_log(self.export(rows))
        return door.ingest(events, Recorder(self.chain()), **kw)

    def rules(self):
        return door.load_rules(door.bundled_rules("github-default"))


class TestParse(DoorBase):
    def test_reads_array_and_jsonl(self):
        for jsonl in (False, True):
            events = door.parse_github_log(self.export(EXPORT_ROWS, jsonl=jsonl))
            self.assertEqual(len(events), 5)
            e = events[0]
            self.assertEqual(e["action"], "git.push")
            self.assertEqual(e["actor"], "dev")
            self.assertEqual(e["repo"], "acme/widgets")
            self.assertEqual(e["ts"], "2026-10-10T00:00:00+00:00")

    def test_agent_key_names_the_programmatic_client(self):
        events = door.parse_github_log(self.export(EXPORT_ROWS))
        keys = {e["action"]: door.agent_key(e) for e in events}
        self.assertEqual(keys["git.push"], AGENT)
        self.assertEqual(keys["git.clone"], "token:4242")
        self.assertIsNone(keys["user.login"])  # a browser session is the human

    def test_rejects_non_list(self):
        p = os.path.join(self.tmp, "bad.json")
        with open(p, "w") as f:
            json.dump({"not": "an export"}, f)
        with self.assertRaises(ValueError):
            door.parse_github_log(p)


class TestRealShape(DoorBase):
    """Fields as GitHub actually writes them: the person in "user", the app in
    "integration", and the driving agent declared in the user-agent."""
    ROWS = [
        {"@timestamp": 1791590400000, "action": "repo.create", "user": "dev",
         "programmatic_access_type": "OAuth access token",
         "oauth_application_name": "GitHub CLI",
         "user_agent": "GitHub CLI 2.94.0 Agent/claude-code_2-1-145_agent"},
        {"@timestamp": 1791590410000, "action": "oauth_access.regenerate", "user": "dev",
         "integration": "Example App", "token_id": 77, "user_agent": "python-httpx/0.28.1"},
        {"@timestamp": 1791590420000, "action": "repo.create", "user": "dev",
         "programmatic_access_type": "OAuth access token",
         "oauth_application_name": "GitHub CLI", "user_agent": "GitHub CLI 2.94.0"},
    ]

    def test_user_field_and_declared_agent(self):
        events = door.parse_github_log(self.export(self.ROWS))
        self.assertEqual(events[0]["actor"], "dev")
        keys = [door.agent_key(e) for e in events]
        self.assertEqual(keys[0], "app:GitHub CLI [claude-code]")
        self.assertEqual(keys[1], "app:Example App")
        # the same CLI driven by the person declares no agent: a different client
        self.assertEqual(keys[2], "app:GitHub CLI")

    def test_isolate_by_declared_agent_spans_credentials(self):
        rows = self.ROWS + [dict(self.ROWS[0], **{"@timestamp": 1791590430000,
                                                  "oauth_application_name": None,
                                                  "programmatic_access_type": None,
                                                  "token_id": 99})]
        recs = door.ingest(door.parse_github_log(self.export(rows)), Recorder(self.chain()))
        mine = door.isolate(recs, "agent:claude-code")
        self.assertEqual(sorted(r["agent"]["id"] for r in mine),
                         ["app:GitHub CLI [claude-code]", "token:99 [claude-code]"])

    def test_ua_agent(self):
        self.assertEqual(door.ua_agent("GitHub CLI 2.96.0 Agent/claude-code_2-1-211_agent"),
                         "claude-code")
        self.assertIsNone(door.ua_agent("Mozilla/5.0"))


class TestIngest(DoorBase):
    def test_seals_ingested_records_that_verify(self):
        recs = self.ingested(subject="acme")
        self.assertEqual(len(recs), 5)
        r = recs[0]
        self.assertEqual(r["source"]["capture"], "ingested")
        self.assertEqual(r["source"]["adapter"], "github_audit")
        self.assertEqual(r["ts"], "2026-10-10T00:00:00+00:00")
        self.assertEqual(r["action"]["tool"], "github:git.push")
        self.assertEqual(r["principal"]["human_id"], "dev")
        self.assertEqual(r["agent"]["id"], AGENT)
        self.assertEqual(r["subject"]["id"], "acme")
        env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
        out = subprocess.run([sys.executable, "-m", "halo_record.cli", "verify", self.chain()],
                             capture_output=True, text=True, env=env)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_isolate_keeps_one_agent(self):
        mine = door.isolate(self.ingested(), AGENT)
        self.assertEqual([r["action"]["tool"] for r in mine],
                         ["github:git.push", "github:pull_request.create",
                          "github:repo.destroy"])


class TestMatch(DoorBase):
    def test_tiers(self):
        recs = door.isolate(self.ingested(), AGENT)
        own = [_own("2026-10-10T00:00:03+00:00", "git push origin feature"),
               _own("2026-10-10T00:03:30+00:00", "gh pr create --fill")]
        tiers = {m["ingested"]["action"]["tool"]: m["tier"] for m in door.match(recs, own)}
        self.assertEqual(tiers["github:git.push"], "matched")             # 3 s
        self.assertEqual(tiers["github:pull_request.create"], "probable")  # 90 s
        self.assertEqual(tiers["github:repo.destroy"], "unmatched")

    def test_one_command_accounts_for_its_burst_only(self):
        # a single gh api call set several settings: one own record, several events
        rows = [dict(EXPORT_ROWS[0], action="repo.add_topic", **{"@timestamp": 1791590400000 + i * 1000})
                for i in range(3)]
        # the same kind of event an hour later is not that command's doing
        rows.append(dict(EXPORT_ROWS[0], action="repo.add_topic", **{"@timestamp": 1791594000000}))
        recs = self.ingested(rows)
        own = [_own("2026-10-10T00:00:05+00:00", "gh api -X PUT repos/acme/widgets/topics")]
        self.assertEqual(sorted(m["tier"] for m in door.match(recs, own)),
                         ["matched", "matched", "matched", "unmatched"])

    def test_events_after_the_command_finished_are_not_its_doing(self):
        recs = self.ingested([dict(EXPORT_ROWS[0], **{"@timestamp": 1791590460000})])  # +60 s
        own = [_own("2026-10-10T00:00:00+00:00", "git push")]
        self.assertEqual([m["tier"] for m in door.match(recs, own)], ["unmatched"])


class TestRules(DoorBase):
    def test_flags_a_forbidden_action(self):
        recs = door.isolate(self.ingested(), AGENT)
        by_id = {r["id"]: r for r in door.check(recs, self.rules())["rules"]}
        self.assertEqual(by_id["no-repo-deletion"]["status"], "violated")


class TestPage(DoorBase):
    def page(self, recs):
        return door.render_page(recs, door.match(recs, []), door.check(recs, self.rules()),
                                agent=AGENT)

    def test_escapes_export_fields(self):
        recs = self.ingested([dict(EXPORT_ROWS[2], repo="acme/<script>alert(1)</script>")])
        html = self.page(recs)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_states_its_limits(self):
        html = self.page(door.isolate(self.ingested(), AGENT))
        self.assertIn("ingested", html)
        self.assertIn("not the completeness of the export", html)
        self.assertIn("baseline", html)


if __name__ == "__main__":
    unittest.main()


class TestUnusual(DoorBase):
    def test_rare_device_is_listed_and_escaped(self):
        rows = [dict(EXPORT_ROWS[4]), dict(EXPORT_ROWS[4]), dict(EXPORT_ROWS[4]),
                dict(EXPORT_ROWS[4], action="repo.remove_member",
                     user_agent="Mozilla/5.0 (Windows NT 10.0) <b>x</b>")]
        rows = [dict(r, user_agent=r.get("user_agent", "Mozilla/5.0 (Macintosh)")
                     .replace("Mozilla/5.0", "Mozilla/5.0 (Macintosh)") if i < 3 else r["user_agent"])
                for i, r in enumerate(rows)]
        events = door.parse_github_log(self.export(rows))
        odd = door.unusual_devices(events)
        self.assertEqual([e["action"] for e in odd], ["repo.remove_member"])
        recs = door.ingest(events, Recorder(self.chain()))
        html = door.render_page(recs, door.match(recs, []), door.check(recs, self.rules()),
                                agent=AGENT, unusual=odd)
        self.assertIn("Unusual devices", html)
        self.assertIn("Windows", html)


class TestCli(DoorBase):
    def run_cli(self, *argv):
        env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
        return subprocess.run([sys.executable, "-m", "halo_record.cli", "door", *argv],
                              capture_output=True, text=True, env=env, cwd=self.tmp)

    def test_lists_clients_without_agent(self):
        out = self.run_cli(self.export(EXPORT_ROWS))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(AGENT, out.stdout)
        self.assertIn("token:4242", out.stdout)

    def test_writes_page_and_sealed_chain(self):
        out = self.run_cli(self.export(EXPORT_ROWS), "--agent", AGENT)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("rules broken: 1", out.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "door-report.html")))
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "door.jsonl")))

    def test_refuses_to_reuse_a_chain(self):
        self.run_cli(self.export(EXPORT_ROWS), "--agent", AGENT)
        again = self.run_cli(self.export(EXPORT_ROWS), "--agent", AGENT)
        self.assertEqual(again.returncode, 2)
        self.assertIn("already exists", again.stderr)


def _chrome(ts, url=None, tool="mcp__claude-in-chrome__navigate"):
    return build("tool_call", "security", tool=tool,
                 tool_input={"url": url} if url else {"tabId": 1}, ts=ts,
                 agent={"id": "example-agent"}, source="hook")


class TestDoneAsYou(DoorBase):
    """Events the platform attributes to the person that the agent's own
    browser record shows it was driving the site at the time."""
    ROWS = [
        {"@timestamp": 1791590400000, "action": "repository_ruleset.create", "user": "dev",
         "repo": "acme/widgets", "user_agent": "Mozilla/5.0 (Macintosh)"},
        {"@timestamp": 1791590410000, "action": "user.login", "user": "dev",
         "user_agent": "Mozilla/5.0 (Macintosh)"},
        {"@timestamp": 1791597600000, "action": "dependabot_alerts.enable", "user": "dev",
         "user_agent": "Mozilla/5.0 (Macintosh)"},
    ]

    def test_flags_person_events_inside_an_agent_browser_session(self):
        recs = self.ingested(self.ROWS)
        own = [_chrome("2026-10-10T00:00:30+00:00", "https://github.com/acme/widgets/settings")]
        hits = door.done_as_person(recs, own, site="github.com")
        self.assertEqual([h["ingested"]["action"]["tool"] for h in hits],
                         ["github:repository_ruleset.create"])  # not the login; not 2 h later

    def test_requires_the_site_in_the_agent_record(self):
        recs = self.ingested(self.ROWS)
        own = [_chrome("2026-10-10T00:00:30+00:00", "https://example.com/")]
        self.assertEqual(door.done_as_person(recs, own, site="github.com"), [])


class TestCredentials(DoorBase):
    def test_lists_credentials_and_flags_unexpected_ones(self):
        rows = TestRealShape.ROWS + [dict(TestRealShape.ROWS[0], **{
            "@timestamp": 1791590430000, "oauth_application_name": None,
            "programmatic_access_type": None, "token_id": 99})]
        recs = door.isolate(self.ingested(rows), "agent:claude-code")
        used = door.credentials(recs)
        self.assertEqual(used, {"app:GitHub CLI": 1, "token:99": 1})
        off = door.unexpected_credentials(recs, ["app:GitHub CLI"])
        self.assertEqual([r["agent"]["id"] for r in off], ["token:99 [claude-code]"])
