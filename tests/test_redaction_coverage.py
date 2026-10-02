"""Every caller-supplied text field is scrubbed before it is sealed — not only
the input and outcome summaries — and the scrub itself stays linear."""

import json
import time
import unittest
from dataclasses import dataclass

from halo_record.record import build
from halo_record.redact import redact_text

SECRET = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


@dataclass
class Creds:
    user: str
    api_key: str


def _everywhere(summaries):
    return build(
        "tool_call", "security", tool="run " + SECRET,
        tool_input={"q": "x"}, session_id="s-" + SECRET,
        agent={"id": "a", "name": "n", "version": SECRET},
        scope="scope " + SECRET, decision="human_approved", approver="ops " + SECRET,
        subject={"id": "acme", "name": "Acme " + SECRET},
        principal={"human_id": "u " + SECRET},
        parent_id="p-" + SECRET,
        threats=[{"ref": SECRET, "framework": "owasp-llm", "id": "LLM01"}],
        data={"region": "us " + SECRET, "note": "note " + SECRET},
        verification={"verifier": "v " + SECRET, "policy_ref": "p " + SECRET},
        outcome={"status": "ok", "stdout": "out " + SECRET},
        summaries=summaries)


class FieldCoverageTest(unittest.TestCase):
    def test_no_field_carries_a_known_secret(self):
        for summaries in (True, False):
            raw = json.dumps(_everywhere(summaries))
            self.assertNotIn(SECRET, raw, "summaries=%s" % summaries)

    def test_identity_fields_keep_email_addresses(self):
        r = build("tool_call", "security", tool="t", decision="human_approved",
                  approver="alice@example.com", principal={"human_id": "alice@example.com"})
        self.assertEqual(r["action"]["authorization"]["approver"], "alice@example.com")
        self.assertEqual(r["principal"]["human_id"], "alice@example.com")

    def test_uuid_parent_ids_are_never_masked(self):
        for _ in range(300):
            parent = build("tool_call", "security", tool="a")["record_id"]
            self.assertEqual(build("write", "safety", tool="b", parent_id=parent)["parent_id"], parent)

    def test_subject_id_is_not_rewritten(self):
        r = build("tool_call", "security", tool="t", subject="acme-corp")
        self.assertEqual(r["subject"]["id"], "acme-corp")


class SummaryLeafTest(unittest.TestCase):
    def test_non_string_leaves_are_scrubbed(self):
        cases = {
            "int_card": {"card": 4111111111111111},
            "set": {"tags": {SECRET}},
            "bytes": {"blob": SECRET.encode()},
            "object": {"creds": Creds("bob", SECRET)},
        }
        for name, tool_input in cases.items():
            s = build("tool_call", "security", tool="t", tool_input=tool_input)["action"]["input"]["summary"]
            self.assertNotIn(SECRET, s, name)
            self.assertNotIn("4111111111111111", s, name)

    def test_credential_in_url_path_is_scrubbed(self):
        url = "https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage"
        s = build("tool_call", "security", tool="t", tool_input={"url": url})["action"]["input"]["summary"]
        self.assertNotIn("AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", s)


class LinearScrubTest(unittest.TestCase):
    def test_email_pattern_is_linear(self):
        for hostile in ("a@" + "a." * 40000, "a." * 40000, "a" * 80000 + "@"):
            t0 = time.perf_counter()
            redact_text(hostile)
            self.assertLess(time.perf_counter() - t0, 1.0, hostile[:10])


if __name__ == "__main__":
    unittest.main()
