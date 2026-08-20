"""build() + Recorder + verify_log: a record is conformant, the chain links,
and tampering is detected."""

import json
import os
import tempfile
import unittest

from halo_record.record import Recorder, build
from halo_record.verify import validate_record, verify_log


def _silent(*_a, **_k):
    pass


class BuildTest(unittest.TestCase):
    def test_valid_record_passes_schema(self):
        rec = build("tool_call", "security", tool="Read",
                    tool_input={"path": "x"})
        self.assertEqual(validate_record(rec), [])

    def test_invalid_action_type_rejected(self):
        with self.assertRaises(ValueError):
            build("bogus", "security")

    def test_invalid_category_rejected(self):
        with self.assertRaises(ValueError):
            build("tool_call", "bogus")

    def test_input_is_hashed_not_stored_structurally(self):
        # Raw arguments never enter the record as structured data — only a
        # content hash and a redacted, truncated summary string.
        rec = build("tool_call", "security", tool="x",
                    tool_input={"password": "hunter2"})
        self.assertLessEqual(set(rec["action"]["input"]), {"hash", "summary"})
        self.assertTrue(rec["action"]["input"]["hash"].startswith("sha256:"))
        self.assertIsInstance(rec["action"]["input"]["summary"], str)

    def test_known_secret_pattern_redacted_from_summary(self):
        rec = build("tool_call", "security", tool="x",
                    tool_input={"dsn": "postgres://user:s3cr3t@db.internal/prod"})
        self.assertNotIn("s3cr3t", json.dumps(rec))

    def test_summaries_false_drops_all_text(self):
        rec = build("tool_call", "security", tool="x",
                    tool_input={"q": "secret-query"},
                    outcome={"status": "ok", "summary": "leaky"},
                    summaries=False)
        self.assertNotIn("summary", rec["action"]["input"])
        self.assertNotIn("summary", rec["outcome"])
        self.assertNotIn("leaky", json.dumps(rec))

    def test_subject_string_normalized(self):
        rec = build("tool_call", "security", subject="acme-corp")
        self.assertEqual(rec["subject"], {"id": "acme-corp"})

    def test_subject_dict_preserved(self):
        rec = build("tool_call", "security", subject={"id": "p", "name": "Acme-corp"})
        self.assertEqual(rec["subject"], {"id": "p", "name": "Acme-corp"})

    def test_authorization_recorded(self):
        rec = build("write", "safety", tool="Write", scope="fs.write",
                    decision="human_approved", approver="alice")
        auth = rec["action"]["authorization"]
        self.assertEqual(auth["decision"], "human_approved")
        self.assertEqual(auth["scope"], "fs.write")
        self.assertEqual(auth["approver"], "alice")


class ChainTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "audit.jsonl")

    def _records(self):
        with open(self.log) as fh:
            return [json.loads(l) for l in fh if l.strip()]

    def test_chain_links_and_verifies(self):
        rec = Recorder(self.log)
        r1 = rec.append(build("tool_call", "security", tool="a"))
        r2 = rec.append(build("tool_call", "security", tool="b"))
        self.assertEqual(r1["integrity"]["prev_hash"], "0" * 64)
        self.assertEqual(r2["integrity"]["prev_hash"], r1["integrity"]["hash"])
        self.assertTrue(verify_log(self.log, out=_silent))

    def test_tamper_breaks_verification(self):
        rec = Recorder(self.log)
        rec.append(build("tool_call", "security", tool="a"))
        rec.append(build("tool_call", "security", tool="b"))
        recs = self._records()
        recs[0]["action"]["tool"] = "TAMPERED"
        with open(self.log, "w") as fh:
            for r in recs:
                fh.write(json.dumps(r, separators=(",", ":")) + "\n")
        self.assertFalse(verify_log(self.log, out=_silent))

    def test_dropped_record_breaks_prev_hash_link(self):
        rec = Recorder(self.log)
        rec.append(build("tool_call", "security", tool="a"))
        rec.append(build("tool_call", "security", tool="b"))
        rec.append(build("tool_call", "security", tool="c"))
        recs = self._records()
        del recs[1]  # drop the middle record
        with open(self.log, "w") as fh:
            for r in recs:
                fh.write(json.dumps(r, separators=(",", ":")) + "\n")
        self.assertFalse(verify_log(self.log, out=_silent))

    def test_record_after_a_stale_hash_break_is_reported_unverifiable(self):
        rec = Recorder(self.log)
        rec.append(build("tool_call", "security", tool="a"))
        rec.append(build("tool_call", "security", tool="b"))
        rec.append(build("tool_call", "security", tool="c"))
        recs = self._records()
        recs[1]["action"]["tool"] = "malicious-action-injected"  # hash left stale
        with open(self.log, "w") as fh:
            for r in recs:
                fh.write(json.dumps(r, separators=(",", ":")) + "\n")

        lines = []
        ok = verify_log(self.log, out=lines.append)

        self.assertFalse(ok)
        joined = "\n".join(lines)
        self.assertIn("record 2", joined)
        self.assertNotIn("record 3: chain", joined)
        self.assertIn("record 3 onward is not verifiable", joined)

    def test_one_old_break_does_not_cascade_into_a_report_per_later_record(self):
        rec = Recorder(self.log)
        for i in range(50):
            rec.append(build("tool_call", "security", tool="t%d" % i))
        recs = self._records()
        recs[1]["action"]["tool"] = "malicious-action-injected"
        with open(self.log, "w") as fh:
            for r in recs:
                fh.write(json.dumps(r, separators=(",", ":")) + "\n")

        lines = []
        ok = verify_log(self.log, out=lines.append)

        self.assertFalse(ok)
        chain_lines = [ln for ln in lines if ln.startswith("record") and ": chain:" in ln]
        unverifiable_lines = [ln for ln in lines if "onward is not verifiable" in ln]
        self.assertEqual(len(chain_lines), 1)
        self.assertEqual(len(unverifiable_lines), 1)


if __name__ == "__main__":
    unittest.main()


class OversizedIntParityTest(unittest.TestCase):
    """Integers beyond JS Number.MAX_SAFE_INTEGER (2**53-1) must be preserved as
    strings by the recorder so the in-browser (JS) verifier and the Python
    verifier compute the SAME canonical bytes. Otherwise a legitimately
    recorded chain would spuriously fail the reader's self-verification."""

    def test_oversized_int_in_data_preserved_as_string(self):
        rec = build("read", "privacy", tool="t",
                    tool_input={"v": "x"},
                    data={"ts_ns": 1704067200000000000})
        self.assertEqual(rec["data"]["ts_ns"], "1704067200000000000")
        self.assertIsInstance(rec["data"]["ts_ns"], str)

    def test_oversized_integer_valued_float_preserved_as_string(self):
        rec = build("read", "privacy", tool="t",
                    tool_input={"v": "x"},
                    data={"ts_ns": 1e21})
        self.assertEqual(rec["data"]["ts_ns"], "1000000000000000000000")

    def test_small_int_untouched(self):
        rec = build("read", "privacy", tool="t",
                    tool_input={"v": "x"},
                    data={"n": 42})
        self.assertIs(rec["data"]["n"], 42)

    def test_chain_with_oversized_int_verifies(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.jsonl")
            rec = Recorder(path)
            rec.append(build("tool_call", "security", tool="db.query",
                             tool_input={"q": "1"},
                             data={"ts_ns": 1704067200000000000}))
            self.assertTrue(verify_log(path, out=_silent))
