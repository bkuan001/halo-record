"""Every leaf a caller can hand the recorder is masked the way its finding
says: bytes, sets, and frozensets in tool input; card numbers given as JSON
numbers in data or outcome; and, in hash-only mode, secret-shaped id fields.
Secret-shaped values are assembled at runtime."""

import json
import unittest

from halo_record.record import build

SEC = "Zx8Qp2Lm9Vb4" + "Nc7Kd1Rf6Tg3Hy5Uj0Ws"    # entropy-shaped, no named format
CARD = int("4111" + "1111" + "1111" + "1111")
BIG_CARD = int("4111" + "1111" + "1111" + "1111" + "3")     # 17 digits, > 2**53


class NonTextLeafTest(unittest.TestCase):
    def test_bytes_set_frozenset_leaves_are_masked(self):
        for ti in ({"a": SEC.encode()}, {"b": {SEC}}, {"c": frozenset([SEC])},
                   {"d": [SEC.encode()]}, {"e": bytearray(SEC.encode())}):
            rec = build("tool_call", "security", tool="t", tool_input=ti)
            self.assertNotIn(SEC, json.dumps(rec), ti)
            self.assertIn("high_entropy_secret", [f["type"] for f in rec["findings"]], ti)


class NumericCardTest(unittest.TestCase):
    def test_card_numbers_as_numbers_are_masked(self):
        rec = build("tool_call", "privacy", tool="t",
                    data={"card": CARD, "big": BIG_CARD, "f": float(CARD), "n": [CARD]},
                    outcome={"status": "ok", "acct": CARD, "big": BIG_CARD})
        blob = json.dumps(rec)
        self.assertNotIn(str(CARD), blob)
        self.assertNotIn(str(BIG_CARD), blob)
        self.assertIn("****1111", blob)
        self.assertIn("****1113", blob)

    def test_ordinary_numbers_are_kept(self):
        rec = build("tool_call", "privacy", tool="t",
                    data={"count": 12, "big": 2 ** 60},
                    outcome={"status": "ok", "rows": 1234567890123})
        self.assertEqual(rec["data"]["count"], 12)
        self.assertEqual(rec["data"]["big"], str(2 ** 60))
        self.assertEqual(rec["outcome"]["rows"], 1234567890123)


class HashOnlyIdTest(unittest.TestCase):
    def test_secret_shaped_ids_are_pseudonymized_in_hash_only_mode(self):
        rec = build("tool_call", "security", tool="t", tool_input={"q": 1},
                    summaries=False, session_id=SEC, parent_id=SEC,
                    agent={"id": SEC, "name": "agent " + SEC},
                    threats=[{"type": "x", "ref": SEC}],
                    verification={"status": "allowed", "policy_ref": SEC})
        blob = json.dumps(rec)
        self.assertNotIn(SEC, blob)
        # Deterministic: the same id maps to the same pseudonym, so grouping
        # by session or resolving a parent link still works.
        self.assertEqual(rec["session_id"], rec["parent_id"])
        again = build("tool_call", "security", tool="t", summaries=False, session_id=SEC)
        self.assertEqual(again["session_id"], rec["session_id"])

    def test_opaque_ids_are_kept_in_hash_only_mode(self):
        uid = "3f2b8c1e-9a4d-4e7f-8b2a-1c5d6e7f8a9b"
        rec = build("tool_call", "security", tool="t", summaries=False,
                    session_id="sess-42", parent_id=uid, agent={"id": "billing-bot"})
        self.assertEqual(rec["session_id"], "sess-42")
        self.assertEqual(rec["parent_id"], uid)
        self.assertEqual(rec["agent"]["id"], "billing-bot")

    def test_ids_unchanged_when_summaries_on(self):
        rec = build("tool_call", "security", tool="t", session_id=SEC)
        self.assertEqual(rec["session_id"], SEC)


if __name__ == "__main__":
    unittest.main()
