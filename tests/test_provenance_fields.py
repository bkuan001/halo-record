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
