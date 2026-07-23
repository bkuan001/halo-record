"""parent_id / principal / threats / data.pii_types population (AIUC-1 E015.2,
A003.3, A006 evidence). These fields were schema-defined but unpopulated; build()
now fills them when given, and derives pii_types from the scanner's findings."""

import csv
import io
import os
import tempfile
import unittest

from halo_record import Recorder, build
from halo_record.canon import compute_hash
from halo_record.export import export, _row
from halo_record.verify import verify_log


class TestProvenanceFields(unittest.TestCase):
    def test_principal_filters_unknown_keys_and_empties(self):
        r = build("tool_call", "security", tool="t",
                  principal={"human_id": "u1", "role_scope": "fin",
                             "bogus": "x", "creator_id": ""})
        self.assertEqual(r["principal"], {"human_id": "u1", "role_scope": "fin"})

    def test_parent_id_links_delegation(self):
        r = build("tool_call", "security", tool="t", parent_id="rec_parent")
        self.assertEqual(r["parent_id"], "rec_parent")

    def test_threats_normalized_from_str_and_dict(self):
        r = build("tool_call", "security", tool="t",
                  threats=["prompt_injection_indirect",
                           {"type": "policy_violation", "ref": "POL-7"},
                           {"ref": "no-type-dropped"}, ""])
        self.assertEqual(r["threats"], [
            {"type": "prompt_injection_indirect"},
            {"type": "policy_violation", "ref": "POL-7"},
        ])

    def test_threats_bare_string_is_single_threat(self):
        # a bare string must be one threat, not iterated character by character
        r = build("tool_call", "security", tool="t", threats="prompt_injection")
        self.assertEqual(r["threats"], [{"type": "prompt_injection"}])

    def test_parent_id_zero_is_preserved(self):
        r = build("tool_call", "security", tool="t", parent_id=0)
        self.assertEqual(r["parent_id"], "0")

    def test_parent_id_empty_string_omitted(self):
        r = build("tool_call", "security", tool="t", parent_id="")
        self.assertNotIn("parent_id", r)

    def test_phone_and_iban_detected_as_pii(self):
        r = build("read", "privacy", tool="t",
                  tool_input={"contact": "call 415-555-2020",
                              "acct": "GB82WEST12345698765432"})
        ftypes = {f["type"] for f in r["findings"]}
        self.assertIn("phone", ftypes)
        self.assertIn("iban", ftypes)
        self.assertIn("phone", r["data"]["pii_types"])
        self.assertIn("iban", r["data"]["pii_types"])

    def test_verify_reports_resolved_delegation(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.jsonl")
            rec = Recorder(path)
            r1 = rec.append(build("tool_call", "security", tool="a"))
            rec.append(build("write", "safety", tool="b",
                             parent_id=r1["record_id"]))
            msgs = []
            self.assertTrue(verify_log(path, out=msgs.append))
            self.assertTrue(any("resolve within this chain" in m for m in msgs))

    def test_verify_flags_orphan_parent_without_failing(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.jsonl")
            rec = Recorder(path)
            rec.append(build("tool_call", "security", tool="a",
                             parent_id="does-not-exist"))
            msgs = []
            # an orphaned parent_id is surfaced but does not fail the chain
            self.assertTrue(verify_log(path, out=msgs.append))
            self.assertTrue(any("not found earlier" in m for m in msgs))

    def test_credit_card_and_iban_tolerate_separators(self):
        # canonical printed formats (spaces/dashes) must not leak raw
        from halo_record.redact import scan, redact_text
        for v in ("4111 1111 1111 1111", "4111-1111-1111-1111", "5555 5555 5555 4444"):
            self.assertIn("credit_card", [f["type"] for f in scan(v)])
            self.assertNotIn(v, redact_text(v))
        for v in ("DE89 3704 0044 0532 0130 00", "GB82 WEST 1234 5698 7654 32"):
            self.assertIn("iban", [f["type"] for f in scan(v)])
            self.assertNotIn(v, redact_text(v))

    def test_iban_not_misclassified_as_credit_card(self):
        # Luhn disambiguation: an IBAN's digit groups must not raise a card finding
        from halo_record.redact import scan
        types = [f["type"] for f in scan("DE89 3704 0044 0532 0130 00")]
        self.assertIn("iban", types)
        self.assertNotIn("credit_card", types)

    def test_threats_non_iterable_never_crashes(self):
        # instrumentation must not crash a host tool on a stray scalar
        r = build("tool_call", "security", tool="t", threats=1)
        self.assertNotIn("threats", r)

    def test_threats_single_dict_is_one_threat(self):
        r = build("tool_call", "security", tool="t",
                  threats={"type": "prompt_injection", "ref": "R1"})
        self.assertEqual(r["threats"], [{"type": "prompt_injection", "ref": "R1"}])

    def test_cross_region_bool_coerced_to_number(self):
        from halo_record.verify import validate_record
        r = build("read", "privacy", tool="t", data={"cross_region": True})
        self.assertEqual(r["data"]["cross_region"], 1)
        self.assertEqual(validate_record(r), [])  # schema-valid, no chain poison

    def test_pii_types_derived_from_findings(self):
        # an email in the input → findings include 'email' → data.pii_types
        r = build("read", "privacy", tool="t",
                  tool_input={"q": "mail to jane@acme.com"})
        self.assertIn("email", r["data"]["pii_types"])

    def test_data_merges_caller_context_with_derived_pii(self):
        r = build("read", "privacy", tool="t",
                  tool_input={"q": "jane@acme.com"},
                  data={"region": "eu", "purpose": "support"})
        self.assertEqual(r["data"]["region"], "eu")
        self.assertEqual(r["data"]["purpose"], "support")
        self.assertEqual(r["data"]["pii_types"], ["email"])

    def test_empty_new_fields_are_omitted(self):
        # back-compat: no empty objects/arrays leak into the record
        r = build("read", "privacy", tool="t", tool_input={"q": "no pii here"})
        for k in ("principal", "parent_id", "threats", "data"):
            self.assertNotIn(k, r)

    def test_new_fields_still_verify_in_chain(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "chain.jsonl")
            rec = Recorder(path)
            r1 = rec.append(build("tool_call", "security", tool="a",
                                  principal={"human_id": "u1"}))
            rec.append(build("write", "safety", tool="b", parent_id=r1["record_id"],
                             threats=["prompt_injection_direct"]))
            self.assertTrue(verify_log(path, out=lambda *a, **k: None))

    def test_export_surfaces_new_columns(self):
        r = build("read", "privacy", tool="t", tool_input={"q": "jane@acme.com"},
                  parent_id="p1", principal={"human_id": "u_alice"},
                  threats=[{"type": "policy_violation"}])
        row = _row(r)
        self.assertEqual(row["parent_id"], "p1")
        self.assertEqual(row["principal"], "human_id=u_alice")
        self.assertEqual(row["threats"], "policy_violation")
        self.assertEqual(row["pii_types"], "email")

    def test_export_end_to_end_includes_columns(self):
        with tempfile.TemporaryDirectory() as d:
            path, out = os.path.join(d, "c.jsonl"), os.path.join(d, "e.csv")
            rec = Recorder(path)
            rec.append(build("read", "privacy", tool="t",
                             tool_input={"q": "jane@acme.com"},
                             principal={"human_id": "u1"}))
            export(path, out, out=lambda *a, **k: None)
            with open(out, newline="") as fh:
                header = next(csv.reader(fh))
            for col in ("parent_id", "principal", "threats", "pii_types"):
                self.assertIn(col, header)


if __name__ == "__main__":
    unittest.main()
