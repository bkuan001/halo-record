"""The starter packs' secret rules cover every secret type the scanner emits.

The finding types are read from ``redact.py``'s source (the ``PATTERNS`` names
and every ``*_TYPE`` constant), not from a list kept beside the packs, so a new
scanner type fails this test until each pack's secret rule forbids it or it is
named here as personal data / a readable-path note.
"""

import ast
import json
import os
import unittest

from halo_record import redact
from halo_record.policy import evaluate, load_policy

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACK_DIRS = [os.path.join(ROOT, "examples", "policies"),
             os.path.join(ROOT, "src", "halo_record", "policies")]
SECRET_RULES = {"owasp-starter.json": "no-secret-disclosure",
                "aiuc-1-starter.json": "no-secret-leakage"}

# Types a secret rule deliberately leaves out: personal data the pack's PII
# rules cover (email, phone, internal IP), and the LOW note for a readable path.
NOT_SECRETS = {"email", "phone", "ip_internal", "high_entropy_path_value"}


def _scanner_types():
    """{type: severity} for every finding type redact.py can emit, from source."""
    with open(redact.__file__, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    types = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        name = getattr(node.targets[0], "id", "")
        if name == "PATTERNS":
            for elt in node.value.elts:
                types[elt.elts[0].value] = elt.elts[1].value
        elif (name.endswith("_TYPE") and isinstance(node.value, ast.Constant)
              and isinstance(node.value.value, str)):
            types[node.value.value] = None
    # Severities of the non-pattern types come from where they are emitted.
    for t in types:
        if types[t] is None:
            types[t] = redact.FINDING_TYPES[t]
    return types


class SecretRulesCoverScannerTest(unittest.TestCase):
    def test_source_and_finding_types_agree(self):
        self.assertEqual(_scanner_types(), redact.FINDING_TYPES)

    def test_every_secret_type_is_forbidden_by_each_pack(self):
        types = _scanner_types()
        self.assertTrue(NOT_SECRETS <= set(types), NOT_SECRETS - set(types))
        for t in NOT_SECRETS:
            self.assertIn(types[t], ("MEDIUM", "LOW"), t)
        secrets = set(types) - NOT_SECRETS
        for d in PACK_DIRS:
            for pack, rule_id in SECRET_RULES.items():
                rules = load_policy(os.path.join(d, pack))
                rule = [r for r in rules if r["id"] == rule_id][0]
                forbidden = set(rule["forbid"]["findings[].type"]["in"])
                self.assertEqual(secrets - forbidden, set(), "%s %s" % (d, pack))
                self.assertEqual(forbidden - set(types), set(), "%s %s" % (d, pack))

    def test_detected_secrets_fail_the_secret_rule(self):
        samples = {
            "stripe_key": "sk_live_" + "a1B2c3D4e5F6g7H8i9J0",
            "github_token": "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
            "password": "password=hunter2xyz",
            "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
        }
        for t, text in samples.items():
            findings = redact.scan(text)
            self.assertIn(t, [f["type"] for f in findings], t)
            rec = {"record_id": "r-" + t, "findings": findings}
            for d in PACK_DIRS:
                for pack, rule_id in SECRET_RULES.items():
                    res = evaluate([rec], load_policy(os.path.join(d, pack)))
                    rule = [r for r in res["rules"] if r["id"] == rule_id][0]
                    self.assertEqual(rule["status"], "violated", "%s %s" % (pack, t))
        cred = redact.scan_fields({"password": "hunter2"})
        self.assertEqual(cred[0]["type"], "credential_field")


if __name__ == "__main__":
    unittest.main()
