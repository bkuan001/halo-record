"""Verification claims: what the gate said at the moment of the action."""

import contextlib
import io
import json
import os
import tempfile
import unittest

from halo_record.capture import record_call
from halo_record.hook import record_event
from halo_record.record import Recorder, build
from halo_record.verify import validate_record, verify_log


def _silent(*_a, **_k):
    pass


VERIFICATION = {
    "status": "allowed",
    "verifier": "gate/1.0",
    "policy_ref": "sha256:policy",
    "checked_at": "2026-08-01T12:00:00Z",
}


class VerificationTest(unittest.TestCase):
    def test_build_accepts_verification_claim(self):
        rec = build("tool_call", "security", tool="Bash", verification=VERIFICATION)
        self.assertEqual(validate_record(rec), [])
        self.assertEqual(rec["verification"], VERIFICATION)

    def test_status_alone_is_a_valid_claim(self):
        rec = build("tool_call", "security", tool="Bash",
                    verification={"status": "unverified"})
        self.assertEqual(validate_record(rec), [])
        self.assertEqual(rec["verification"], {"status": "unverified"})

    def test_absent_block_is_no_claim(self):
        rec = build("tool_call", "security", tool="Bash")
        self.assertNotIn("verification", rec)
        self.assertEqual(validate_record(rec), [])

    def test_invalid_status_is_not_sealed_and_warns(self):
        # A malformed claim is dropped, not sealed as schema-invalid — the
        # recorder never poisons the chain with an unverifiable record. The
        # drop is loud: a single stderr line names the invalid status.
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rec = build("tool_call", "security", tool="Bash",
                        verification={"status": "approved"})
        self.assertNotIn("verification", rec)
        self.assertEqual(validate_record(rec), [])
        warning = stderr.getvalue()
        self.assertIn("verification block dropped", warning)
        self.assertIn("'approved'", warning)

    def test_schema_rejects_invalid_status(self):
        rec = build("tool_call", "security", tool="Bash", verification=VERIFICATION)
        rec["verification"]["status"] = "approved"
        errors = validate_record(rec)
        self.assertTrue(any("verification.status" in e for e in errors))

    def test_verification_claim_is_hash_chained(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "audit.jsonl")
        Recorder(path).append(
            build("tool_call", "security", tool="Read", verification=VERIFICATION))
        self.assertTrue(verify_log(path, out=_silent))

        with open(path, "r", encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
        rows[0]["verification"]["status"] = "blocked"
        with open(path, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, separators=(",", ":")) + "\n")
        self.assertFalse(verify_log(path, out=_silent))

    def test_record_call_passes_verification_through(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "audit.jsonl")
        rec = Recorder(path)
        with record_call(rec, "crm.lookup", {"account": "acct-9"},
                         verification=VERIFICATION) as call:
            call.result = {"ok": True}
        self.assertEqual(call.record["verification"], VERIFICATION)
        self.assertTrue(verify_log(path, out=_silent))

    def test_hook_passes_verification_through(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "audit.jsonl")
        record = record_event(
            {
                "tool_name": "Read",
                "tool_input": {"path": "README.md"},
                "session_id": "session-1",
                "verification": VERIFICATION,
            },
            Recorder(path),
        )
        self.assertEqual(record["verification"], VERIFICATION)
        self.assertTrue(verify_log(path, out=_silent))


if __name__ == "__main__":
    unittest.main()
