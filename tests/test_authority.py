"""Authority snapshots: hash-only governance context on runtime records."""

import json
import os
import tempfile
import unittest

from halo_record.hook import load_authority, record_event
from halo_record.record import Recorder, build
from halo_record.verify import validate_record, verify_log


def _silent(*_a, **_k):
    pass


AUTHORITY = {
    "snapshot_id": "auth_2026_07_08T1100Z",
    "captured_at": "2026-07-08T11:00:00Z",
    "scope": "session",
    "workspace": {
        "path_hash": "sha256:workspace",
        "git_commit": "abc1234",
    },
    "refs": [
        {
            "kind": "project_rules",
            "id": "CLAUDE.md",
            "hash": "sha256:claude-md",
            "loaded": True,
            "truncated": False,
        },
        {
            "kind": "mcp_tool_registry",
            "id": "filesystem",
            "hash": "sha256:mcp-tools",
            "version": "2026-07-08",
        },
    ],
    "omissions": [
        {"kind": "private_policy", "reason": "customer_secret", "hash": "sha256:omitted"}
    ],
    "capture_limits": ["raw rule text omitted"],
    "stale_if": ["project_rules_hash_changed", "mcp_tool_registry_hash_changed"],
}


class AuthorityTest(unittest.TestCase):
    def test_build_accepts_privacy_safe_authority_snapshot(self):
        rec = build("tool_call", "security", tool="Bash", authority=AUTHORITY)
        self.assertEqual(validate_record(rec), [])
        self.assertEqual(rec["authority"]["snapshot_id"], "auth_2026_07_08T1100Z")
        self.assertEqual(rec["authority"]["refs"][0]["hash"], "sha256:claude-md")

    def test_authority_snapshot_is_hash_chained(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "audit.jsonl")
        rec = Recorder(path)
        rec.append(build("tool_call", "security", tool="Read", authority=AUTHORITY))
        self.assertTrue(verify_log(path, out=_silent))

        with open(path, "r", encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
        rows[0]["authority"]["refs"][0]["hash"] = "sha256:tampered"
        with open(path, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, separators=(",", ":")) + "\n")
        self.assertFalse(verify_log(path, out=_silent))

    def test_hook_loads_authority_file_without_blocking(self):
        d = tempfile.mkdtemp()
        auth_path = os.path.join(d, "authority.json")
        log_path = os.path.join(d, "audit.jsonl")
        with open(auth_path, "w", encoding="utf-8") as fh:
            json.dump(AUTHORITY, fh)

        authority = load_authority(auth_path)
        record = record_event(
            {
                "tool_name": "Read",
                "tool_input": {"path": "README.md"},
                "session_id": "session-1",
            },
            Recorder(log_path),
            authority=authority,
        )
        self.assertEqual(record["authority"]["snapshot_id"], AUTHORITY["snapshot_id"])
        self.assertTrue(verify_log(log_path, out=_silent))

    def test_hook_ignores_missing_or_malformed_authority_file(self):
        d = tempfile.mkdtemp()
        bad = os.path.join(d, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("not json")
        self.assertIsNone(load_authority(os.path.join(d, "missing.json")))
        self.assertIsNone(load_authority(bad))


if __name__ == "__main__":
    unittest.main()
