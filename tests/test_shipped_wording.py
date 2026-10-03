"""Shipped recorder and adapter source describes provenance in plain terms
("evidentiary tier", "accurate"). The checked words are assembled at runtime,
the same way secret-shaped test values are, so this file does not match its
own check."""

import os
import re
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "src", "halo_record")
FILES = ["record.py", "demo.py", "capture.py", "redact.py", "canon.py", "verify.py",
         os.path.join("integrations", "__init__.py"),
         os.path.join("integrations", "gateway.py"),
         os.path.join("integrations", "langfuse.py"),
         os.path.join("integrations", "litellm.py"),
         os.path.join("integrations", "mcp.py"),
         os.path.join("integrations", "_common.py")]


AVOIDED = re.compile(r"(?i)\b" + "hon" + "est")


class ShippedWordingTest(unittest.TestCase):
    def test_plain_provenance_wording(self):
        for name in FILES:
            with open(os.path.join(SRC, name), encoding="utf-8") as fh:
                text = fh.read()
            self.assertIsNone(AVOIDED.search(text), name)

    def test_captured_tier_is_described_as_declared_by_the_source_tag(self):
        # Same terms as the report's provenance text (_view.CAP_TITLE): the
        # capture tier is what the record's source tag declares, set by the
        # integration that wrote it.
        for name in FILES:
            with open(os.path.join(SRC, name), encoding="utf-8") as fh:
                text = " ".join(fh.read().split())
            self.assertNotIn("saw the call", text, name)
        with open(os.path.join(SRC, "integrations", "__init__.py"), encoding="utf-8") as fh:
            text = " ".join(fh.read().split())
        self.assertIn("source tag", text)
        self.assertIn("not independently verified", text)


if __name__ == "__main__":
    unittest.main()


class StarterPackCitationsTest(unittest.TestCase):
    """The bundled packs cite the control IDs and titles their sources use, and
    the examples/ copies match the shipped ones byte for byte."""

    PACKS = os.path.join(SRC, "policies")
    EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples", "policies")

    def _read(self, d, name):
        with open(os.path.join(d, name), encoding="utf-8") as fh:
            return fh.read()

    def test_examples_match_the_shipped_packs(self):
        for name in ("aiuc-1-starter.json", "owasp-starter.json"):
            self.assertEqual(self._read(self.PACKS, name), self._read(self.EXAMPLES, name), name)

    def test_cited_ids_and_titles(self):
        aiuc = self._read(self.PACKS, "aiuc-1-starter.json")
        self.assertNotIn("B004 (prompt-injection", aiuc)  # B004 is endpoint anti-scraping
        self.assertIn("AIUC-1 B002 / B005 (detect adversarial input; real-time input filtering)", aiuc)
        self.assertIn("evidence toward AIUC-1 E015", aiuc)
        owasp = self._read(self.PACKS, "owasp-starter.json")
        self.assertIn("(T1–T17)", owasp)
        self.assertIn("LLM04:2025 Data & Model Poisoning", owasp)


ROOT = os.path.join(os.path.dirname(__file__), "..")


class MappingDocsMatchClaimsTableTest(unittest.TestCase):
    """The mapping docs describe the witness the way README's claims table and
    LIMITS §4/§18 do: it detects written history removed or rewritten relative
    to its checkpoints, and its payload is the subject id, count, head and chain
    root. Phrases are assembled at runtime so this file does not match itself."""

    DOCS = ["ATC.md", "AARM.md", "OWASP.md", "AICM.md", "ATLAS.md", "AIUC.md"]

    def _text(self, name):
        with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
            return " ".join(fh.read().split())

    def test_no_witness_claim_over_never_written_records(self):
        for name in self.DOCS:
            text = self._text(name)
            self.assertNotIn("decline " + "to write", text, name)
            self.assertNotIn("a count and a head " + "hash, nothing else", text, name)
            self.assertNotIn("count and head" + "-hash", text, name)

    def test_witness_payload_names_subject_and_chain_root(self):
        for name in ("ATC.md", "AARM.md", "OWASP.md"):
            self.assertIn("chain root", self._text(name), name)

    def test_timestamp_not_listed_as_completeness_independence(self):
        self.assertNotIn("or an RFC 3161 " + "timestamp) — see", self._text("AIUC.md"))

    def test_registry_summary_is_scoped_to_the_log_holder(self):
        self.assertIn("verifiable by anyone holding the log", self._text("pyproject.toml"))


class ShippedTextVocabularyTest(unittest.TestCase):
    """Shipped source and the touched tests use neutral vocabulary."""

    WORDS = re.compile(r"(?i)\b(" + "oo" + "ps|" + "sanit" + "ized)\b")

    def test_neutral_vocabulary(self):
        for rel in (os.path.join("src", "halo_record", "witness.py"),
                    os.path.join("tests", "test_policy_digest.py"),
                    os.path.join("tests", "test_tenant.py"),
                    "SECURITY.md", "CONTRIBUTING.md"):
            with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
                text = fh.read()
            self.assertIsNone(self.WORDS.search(text), rel)
            if rel.endswith(".md"):
                self.assertNotIn("ship a " + "fix", text, rel)
                self.assertNotIn("bug" + "-fix", text, rel)
