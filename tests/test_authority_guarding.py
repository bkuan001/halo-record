"""Authority-block guarding: known secret formats are masked at seal time,
snapshot_id reuse over changed content is never silently compacted, and
hash-only records keep only the schema's non-text outcome fields."""

import os
import tempfile
import unittest

from halo_record.record import Recorder, build


class AuthoritySanitizeTest(unittest.TestCase):
    def test_known_secret_formats_are_masked(self):
        rec = build("tool_call", "security", tool="t",
                    authority={"snapshot_id": "auth_1",
                               "skills": {"deploy": "sk-" + "a1B2" * 8},
                               "note": "Bearer " + "tok" * 12})
        auth = rec["authority"]
        self.assertNotIn("sk-" + "a1B2" * 8, str(auth))
        self.assertNotIn("tok" * 12, str(auth))

    def test_hashes_and_refs_survive_unmasked(self):
        legit = {
            "snapshot_id": "auth_1",
            "path_hash": "sha256:" + "ab12" * 16,
            "worktree_hash": "9f" * 32,
            "ref": "refs/heads/main@e908f88",
        }
        rec = build("tool_call", "security", tool="t", authority=dict(legit))
        self.assertEqual(rec["authority"], legit)


class DedupeGuardTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.rec = Recorder(os.path.join(self.dir, "c.jsonl"))

    def test_same_id_same_content_still_compacts(self):
        a = {"snapshot_id": "auth_1", "rules_hash": "ab" * 32}
        self.rec.append(build("tool_call", "security", tool="a", authority=dict(a)))
        second = self.rec.append(build("tool_call", "security", tool="b", authority=dict(a)))
        self.assertEqual(second["authority"],
                         {"snapshot_id": "auth_1", "same_as_previous": True})

    def test_same_id_changed_content_stores_full_body(self):
        self.rec.append(build("tool_call", "security", tool="a",
                              authority={"snapshot_id": "auth_1", "rules_hash": "ab" * 32}))
        changed = {"snapshot_id": "auth_1", "rules_hash": "cd" * 32}
        second = self.rec.append(build("tool_call", "security", tool="b",
                                       authority=dict(changed)))
        self.assertEqual(second["authority"], changed)
        self.assertNotIn("same_as_previous", second["authority"])


class DedupeRestartTest(unittest.TestCase):
    def test_fresh_process_over_compacted_tail_stores_full_body(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "c.jsonl")
        rec = Recorder(path)
        a = {"snapshot_id": "auth_1", "rules_hash": "ab" * 32}
        rec.append(build("tool_call", "security", tool="a", authority=dict(a)))
        rec.append(build("tool_call", "security", tool="b", authority=dict(a)))  # compacted tail
        fresh = Recorder(path)  # restart: previous full body unknown
        changed = {"snapshot_id": "auth_1", "rules_hash": "cd" * 32}
        third = fresh.append(build("tool_call", "security", tool="c", authority=dict(changed)))
        self.assertEqual(third["authority"], changed)
        self.assertNotIn("same_as_previous", third["authority"])


class AuthorityKeyMaskTest(unittest.TestCase):
    def test_secret_used_as_key_is_masked(self):
        rec = build("tool_call", "security", tool="t",
                    authority={"snapshot_id": "auth_1",
                               "sk-" + "a1B2" * 8: "value"})
        self.assertNotIn("sk-" + "a1B2" * 8, str(rec["authority"]))


class PersistedVerifyTest(unittest.TestCase):
    def test_guarded_records_with_boundary_numerics_verify_from_disk(self):
        from halo_record.verify import verify_log
        d = tempfile.mkdtemp()
        path = os.path.join(d, "c.jsonl")
        rec = Recorder(path)
        rec.append(build("tool_call", "security", tool="a",
                         authority={"snapshot_id": "auth_1", "rules_hash": "ab" * 32},
                         data={"cross_region": 1},
                         outcome={"status": "ok", "summary": "x", "count": -(2**53 - 1)}))
        rec.append(build("tool_call", "security", tool="b",
                         authority={"snapshot_id": "auth_1", "rules_hash": "ab" * 32},
                         outcome={"status": "ok", "summary": "y", "big": 2**53}))
        result = verify_log(path)
        self.assertTrue(result["ok"] if isinstance(result, dict) else result)


class HashOnlyOutcomeTest(unittest.TestCase):
    def test_hash_only_keeps_schema_fields_only(self):
        rec = build("tool_call", "security", tool="t",
                    outcome={"status": "ok", "summary": "sent it",
                             "notes": "free text payload", "rows": 3},
                    summaries=False)
        self.assertEqual(set(rec["outcome"].keys()), {"status"})

    def test_hash_only_rejects_payload_shaped_status_and_hash(self):
        rec = build("tool_call", "security", tool="t",
                    outcome={"status": "the customer's SSN is 123-45-6789",
                             "hash": "free text hiding here"},
                    summaries=False)
        self.assertEqual(rec.get("outcome", {}), {})

    def test_hash_only_keeps_valid_hash(self):
        rec = build("tool_call", "security", tool="t",
                    outcome={"status": "ok", "hash": "sha256:" + "ab" * 16},
                    summaries=False)
        self.assertEqual(set(rec["outcome"].keys()), {"status", "hash"})

    def test_default_mode_keeps_custom_outcome_keys(self):
        rec = build("tool_call", "security", tool="t",
                    outcome={"status": "ok", "summary": "sent it", "rows": 3})
        self.assertEqual(rec["outcome"]["rows"], 3)
        self.assertIn("summary", rec["outcome"])


if __name__ == "__main__":
    unittest.main()


class BinaryAuthorityTest(unittest.TestCase):
    def test_bytes_in_authority_fail_loud_at_seal(self):
        d = tempfile.mkdtemp()
        rec = Recorder(os.path.join(d, "c.jsonl"))
        with self.assertRaises(TypeError):
            rec.append(build("tool_call", "security", tool="t",
                             authority={"snapshot_id": "auth_1",
                                        "blob": b"sk-" + b"a1B2" * 8}))


class RecordCallAuthorityTest(unittest.TestCase):
    def test_record_call_passes_authority_through(self):
        from halo_record import Recorder as R, record_call
        d = tempfile.mkdtemp()
        rec = R(os.path.join(d, "c.jsonl"))
        with record_call(rec, "search", {"q": "x"},
                         authority={"snapshot_id": "auth_1", "rules_hash": "ab" * 32}) as call:
            call.result = "ok"
        self.assertEqual(call.record["authority"]["snapshot_id"], "auth_1")
