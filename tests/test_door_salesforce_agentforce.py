"""The door reading an Agentforce agent out of a Salesforce Event Monitoring
export: InvocableAction rows (the agent's actions), ApexCallout rows (what it
reached outside the org), and the sign-ins of the agent's own service user.

The fixture under tests/fixtures/salesforce_agentforce_sample is synthetic:
placeholder names (Globex), TEST-NET addresses, SAMPLE-marked ids."""

import ipaddress
import os
import tempfile
import unittest

from halo_record import door
from halo_record.record import Recorder

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixtures", "salesforce_agentforce_sample")
BOT = "app:bot:0XxSAMPLE00000001A"
TEST_NETS = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"),
             ipaddress.ip_network("203.0.113.0/24"))


class AfBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def events(self, allowlist=None):
        return door.parse_salesforce_eventlog(FIXTURE, allowlist=allowlist)

    def ingested(self, allowlist=None):
        return door.ingest(self.events(allowlist), Recorder(os.path.join(self.tmp, "c.jsonl")))

    def rules(self):
        return door.load_rules(door.bundled_rules("salesforce-agentforce"))


class TestParse(AfBase):
    def test_reads_invocable_action_and_callout(self):
        events = self.events()
        self.assertEqual(events.skipped, {})
        types = {}
        for e in events:
            types[e["event_type"]] = types.get(e["event_type"], 0) + 1
        self.assertEqual(types, {"Login": 3, "ApexExecution": 5, "URI": 1, "InvocableAction": 5, "ApexCallout": 2})
        self.assertTrue(events.sample)

    def test_agent_action_mapping(self):
        ia = {e["repo"]: e for e in self.events() if e["event_type"] == "InvocableAction"
              and e["detail"].startswith("Agent Action")}
        e = ia["Funds Transfer to Own Account"]
        self.assertEqual(e["action"], "Agent.Funds_Transfer_to_Own_Account")
        self.assertEqual(e["app"], "bot:0XxSAMPLE00000001A")
        self.assertEqual(e["actor"], "svc.agent@globex.example")   # USER_ID resolved through Login
        self.assertIsNone(e["token_id"])                           # the row carries no session key
        self.assertIn("GlobexFSC.FundsTransferService.submit", e["detail"])
        self.assertRegex(e["ts"], r"^2026-10-05T14:20:04\+00:00$")  # TIMESTAMP_DERIVED preferred

    def test_prompt_template_and_flow_rows(self):
        rows = {e["action"]: e for e in self.events() if e["event_type"] == "InvocableAction"}
        self.assertIn("Prompt.Call_Summary_v1", rows)
        self.assertEqual(rows["Prompt.Call_Summary_v1"]["app"], "bot:0XxSAMPLE00000001A")
        flow = rows["InvocableAction.Query_Records"]
        self.assertIsNone(flow["app"])
        self.assertIsNone(door.agent_key(flow))   # a flow a person's click ran: no programmatic client

    def test_callout_mapping(self):
        calls = sorted((e for e in self.events() if e["event_type"] == "ApexCallout"), key=lambda e: e["ts"])
        self.assertEqual(calls[0]["action"], "Callout.POST")
        self.assertEqual(calls[0]["repo"], "https://api.globex.example/core/v2/transfers")
        self.assertEqual(calls[0]["app"], "bot:0XxSAMPLE00000001A")
        self.assertEqual(calls[0]["token_id"], "LKb05")
        self.assertIn("502", calls[0]["detail"])
        self.assertEqual(calls[1]["repo"], "https://api.globex.example/core/v2/accounts/0000000123/balances")  # query dropped
        self.assertEqual(door.agent_key(calls[1]), BOT)

    def test_sign_in_behind_a_bot_only_session_belongs_to_the_bot(self):
        logins = {e["token_id"]: e for e in self.events() if e["event_type"] == "Login"}
        self.assertEqual(logins["LKb05"]["app"], "bot:0XxSAMPLE00000001A")   # runtime sign-in, bot work only
        self.assertEqual(logins["LKb08"]["app"], "bot:0XxSAMPLE00000001A")   # interactive sign-in, bot work only
        self.assertIsNone(logins["LKh05"]["app"])                           # a person: page views in the session

    def test_fixture_is_test_net_and_placeholders_only(self):
        for e in self.events():
            if e.get("ip") and e["ip"] != "Salesforce.com IP":
                self.assertTrue(any(ipaddress.ip_address(e["ip"]) in n for n in TEST_NETS), e["ip"])
            if e.get("actor"):
                self.assertTrue(e["actor"].endswith("@globex.example"), e["actor"])


class TestRules(AfBase):
    def test_pack_loads(self):
        ids = [r["id"] for r in self.rules()]
        self.assertEqual(ids, ["login-outside-allowlist", "no-external-transfer", "no-data-export",
                               "no-login-as", "no-metadata-change"])

    def test_outside_sign_in_of_the_service_user_fires(self):
        mine = door.isolate(self.ingested(allowlist=["192.0.2.0/24"]), BOT)
        kinds = {r["data"]["event_type"] for r in mine}
        self.assertEqual(kinds, {"Login", "ApexExecution", "InvocableAction", "ApexCallout"})
        by_id = {r["id"]: r for r in door.check(mine, self.rules())["rules"]}
        self.assertEqual(by_id["login-outside-allowlist"]["status"], "violated")
        self.assertEqual(len(by_id["login-outside-allowlist"]["violators"]), 1)
        for rid in ("no-external-transfer", "no-data-export", "no-login-as", "no-metadata-change"):
            self.assertIn(by_id[rid]["status"], ("pass", "no_match"), rid)

    def test_platform_address_is_not_outside(self):
        actions = {e["token_id"]: e["action"] for e in self.events(allowlist=["192.0.2.0/24"])
                   if e["event_type"] == "Login"}
        self.assertEqual(actions["LKb05"], "Login.Application")       # "Salesforce.com IP" is not an address to check
        self.assertEqual(actions["LKb08"], "Login.outside_allowlist")

    def test_one_session_two_addresses(self):
        hits = door.shared_sessions(self.events())
        self.assertEqual([h["session"] for h in hits], ["LKb08"])
        self.assertEqual(hits[0]["ips"], ["198.51.100.9", "203.0.113.9"])
        self.assertEqual(hits[0]["agent"], BOT)


if __name__ == "__main__":
    unittest.main()
