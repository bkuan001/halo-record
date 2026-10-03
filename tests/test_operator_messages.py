"""Operator-facing lines from ``halo grant`` and ``halo serve`` name the
actual reason and a command that works:

- a refusal for a chain that does not verify says to run ``halo verify`` and
  restore the chain, without the several-subject-ids explanation;
- a re-issue line for a subject id that is also another chain's file name
  names the chain by its file name, and that command succeeds;
- an orphan grant whose ``<name>.jsonl`` exists says what that file holds
  rather than "if it appears";
- the startup note names the ``--verify-email`` flag."""

import contextlib
import io
import os
import re
import tempfile
import unittest
from unittest import mock

from halo_record import access
from halo_record import serve as serve_mod
from halo_record.serve import reconcile_grants
from tests.test_file_keyed_grants import _plain
from tests.test_legacy_grant_quarantine import _legacy_access, _run, _tenant_write, _write


def _reissue_commands(text, directory):
    """The concrete ``halo grant <dir> <name> <recipient>`` commands in a line."""
    return re.findall(r"halo grant %s (\S+) <recipient>" % re.escape(directory), text)


class WithheldRefusalWordingTest(unittest.TestCase):
    def test_a_chain_that_does_not_verify_is_not_explained_as_multi_subject(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "acme.jsonl")
        _write(path, "acme", "A1")
        _write(path, "acme", "A2")
        with open(path) as fh:
            lines = fh.read().splitlines()
        with open(path, "w") as fh:
            fh.write("\n".join(lines[1:]) + "\n")
        code, out, err = _run(["grant", d, "acme", "acme.com"])
        self.assertEqual(code, 2, out + err)
        self.assertIn("does not verify", err)
        self.assertNotIn("several subject ids", err)
        self.assertNotIn("Split", err)
        self.assertIn("Run halo verify on it, restore the chain, then grant", err)

    def test_a_multi_subject_file_keeps_its_explanation(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "agent.jsonl")
        _plain(path, "P1")
        _write(path, "acme", "A1")
        code, out, err = _run(["grant", d, "agent", "legit.com"])
        self.assertEqual(code, 2, out + err)
        self.assertIn("more than one subject", err)
        self.assertIn("several subject ids is keyed by its file name", err)
        self.assertIn("Split or restore the file", err)


class CollidingReissueLineTest(unittest.TestCase):
    """0.2.45 granted the file ``globex.jsonl``, which holds subject id
    ``hooli``; subject id ``globex`` is served from its digested file. The
    name ``globex`` is refused by ``halo grant`` as ambiguous, so the re-issue
    line names the chain by its file name."""

    def _layout(self):
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "globex.jsonl"), "hooli", "HOOLI")
        _tenant_write(d, "globex", "REAL_GLOBEX")
        _legacy_access(d, {"globex": {"allow": ["globex.com"]}})
        return d

    def test_the_printed_reissue_command_succeeds(self):
        d = self._layout()
        text = "\n".join(reconcile_grants(d))
        self.assertIn("quarantined grant 'globex'", text)
        names = _reissue_commands(text, d)
        self.assertEqual(len(names), 1, text)
        self.assertTrue(names[0].startswith("globex~"), names)
        code, out, err = _run(["grant", d, names[0], "globex.com"])
        self.assertEqual(code, 0, out + err)
        entry = access.load_access(d)["globex"]
        self.assertIn("globex.com", entry.get("allow", []))
        self.assertEqual(entry.get("by"), access.BY_SUBJECT)

    def test_the_line_says_why_the_subject_id_alone_is_refused(self):
        d = self._layout()
        text = "\n".join(reconcile_grants(d))
        self.assertIn("also the file name of globex.jsonl", text)

    def test_a_subject_id_with_no_collision_is_printed_as_itself(self):
        # Shape A from the quarantine tests: no chain's file is named initech,
        # other than the one whose two readings differ (the mixed file).
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "acme.jsonl"), "acme", "A")
        _legacy_access(d, {"acme": {"allow": ["acme.com"]}})
        self.assertNotIn("quarantined", "\n".join(reconcile_grants(d)))


class OrphanLineNamesWhatTheFileHoldsTest(unittest.TestCase):
    def test_existing_file_is_described_not_said_to_appear(self):
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "globex.jsonl"), "hooli", "HOOLI")
        _legacy_access(d, {"globex": {"allow": ["globex.com"]}})
        text = "\n".join(reconcile_grants(d))
        self.assertIn("matches no served chain", text)
        self.assertIn("globex.jsonl holds subject id 'hooli'", text)
        self.assertNotIn("appears", text)

    def test_absent_file_still_says_it_can_appear(self):
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "other.jsonl"), "other", "OTHER")
        _legacy_access(d, {"initech": {"allow": ["evil.com"]}})
        text = "\n".join(reconcile_grants(d))
        self.assertIn("if a chain file initech.jsonl appears", text)


class StartupNoteFlagTest(unittest.TestCase):
    def test_note_names_the_verify_email_flag(self):
        d = tempfile.mkdtemp()

        class _FakeServer:
            def __init__(self, *a, **k):
                pass

            def serve_forever(self):
                raise KeyboardInterrupt

            def server_close(self):
                pass

        out = io.StringIO()
        with mock.patch.object(serve_mod, "ThreadingHTTPServer", _FakeServer), \
                contextlib.redirect_stdout(out):
            serve_mod.serve(d, port=0)
        text = out.getvalue()
        self.assertIn("use --verify-email for one-time-code ownership proof", text)
        self.assertNotIn("--verify ", text)


if __name__ == "__main__":
    unittest.main()
