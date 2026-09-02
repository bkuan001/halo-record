"""Drift guards: the claims the code prints and the claims the docs make must
stay in sync, and retired or forbidden phrasings must not creep back in.

Each exclusion is named with a reason — nothing is skipped silently.
"""

import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DOC_FILES = ["README.md", "PRIVACY.md", "LIMITS.md", "AIUC.md", "ATC.md",
             "AARM.md", "OWASP.md", "SECURITY.md", "RETENTION.md", "REVIEWERS.md",
             "EU-AI-ACT.md", "ISO42001.md", "NIST-AI-RMF.md"]

# Phrases that must never (re)appear, each with the reason it is forbidden.
FORBIDDEN = [
    ("Independent, tamper-evident",
     "reverted overclaim: independence is the unbuilt witness property (LIMITS §1)"),
    ("runtime evidence",
     "retired vocabulary: the category noun is 'audit trail', the format noun 'Runtime Record'"),
    ("runtime-evidence",
     "retired vocabulary in hyphenated disguise — same rule as 'runtime evidence'"),
    ("provably complete",
     "completeness is never provable from a self-held chain (LIMITS §1)"),
    ("cannot be tampered with",
     "absolute; the defensible claim is tamper-EVIDENT, relative to a verified head"),
]

# Named allowlist: (file, phrase) pairs that may legitimately contain a
# forbidden phrase, with the reason. Currently empty on purpose — additions
# must name their reason here, never silently.
ALLOW = {
    # ("LIMITS.md", "example phrase"): "reason",
}


def _read(name):
    with open(os.path.join(REPO, name), "r", encoding="utf-8") as fh:
        return fh.read()


class ForbiddenClaimsTest(unittest.TestCase):
    def test_docs_carry_no_forbidden_phrases(self):
        for name in DOC_FILES:
            path = os.path.join(REPO, name)
            if not os.path.exists(path):
                continue
            text = _read(name)
            for phrase, reason in FORBIDDEN:
                if (name, phrase) in ALLOW:
                    continue
                self.assertNotIn(
                    phrase.lower(), text.lower(),
                    "%s contains forbidden phrase %r (%s)" % (name, phrase, reason))

    def test_source_carries_no_contiguous_pem_header(self):
        # Scanner hygiene: the PEM header must never appear as a contiguous
        # literal in source — detection regexes break it with a group, and the
        # mask is deliberately header-free.
        srcdir = os.path.join(REPO, "src", "halo_record")
        for fn in os.listdir(srcdir):
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(srcdir, fn), "r", encoding="utf-8") as fh:
                self.assertNotIn("-----BEGIN PRIVATE KEY-----", fh.read(),
                                 "%s contains a contiguous PEM header" % fn)


class LimitsSyncTest(unittest.TestCase):
    """The note the verifier prints on every clean run states the integrity-vs-
    completeness boundary; LIMITS.md is the authority on that boundary. If one
    is edited without the other, this fails."""

    def test_verifier_note_phrases_exist_in_limits(self):
        with open(os.path.join(REPO, "src", "halo_record", "verify.py"),
                  "r", encoding="utf-8") as fh:
            verify_src = fh.read()
        self.assertIn("integrity, not completeness", verify_src,
                      "verifier no longer prints the integrity-vs-completeness note")
        limits = _read("LIMITS.md").lower()
        for phrase in ("integrity", "completeness", "re-seal", "witness"):
            self.assertIn(phrase, limits,
                          "LIMITS.md lost the %r concept the verifier note relies on" % phrase)

    def test_readme_network_call_count_matches_privacy(self):
        # Both docs enumerate the opt-in network calls; they must agree.
        readme = _read("README.md")
        privacy = _read("PRIVACY.md")
        self.assertIn("three opt-in", readme.lower())
        self.assertIn("three opt-in", privacy.lower())


if __name__ == "__main__":
    unittest.main()
