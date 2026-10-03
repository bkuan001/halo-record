"""A chain whose file holds no subject id is keyed by its file name, and a
chain whose file holds several subject ids is keyed by its file name too but
its report is withheld. ``halo grant`` refuses a name whose report ``halo
serve`` withholds, and records a grant on a subjectless chain for that file, so
a later chain whose subject id equals the file name never inherits it.

A 0.2.45 grant on a subjectless chain is quarantined at startup like any other
name whose two readings can differ; the startup line and LIMITS say why."""

import os
import tempfile
import unittest

from halo_record import access
from halo_record.record import Recorder
from halo_record.serve import reconcile_grants, token_for
from tests.test_legacy_grant_quarantine import (_legacy_access, _run, _Server,
                                                _tenant_write, _write)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _plain(path, tool, n=2):
    """Records with no subject, as a plain ``Recorder`` writes them."""
    import contextlib
    import io
    from halo_record.record import build
    with contextlib.redirect_stderr(io.StringIO()):
        r = Recorder(path)
        for _ in range(n):
            r.append(build("tool_call", "security", tool=tool, tool_input=tool))


class _Shut:
    def assert_shut_out(self, d, email="bob@evil.com", marker="REAL_INITECH"):
        for reconcile in (False, True):
            if reconcile:
                reconcile_grants(d)
            srv = _Server(d)
            try:
                tok = token_for(srv.secret, "initech")
                status, body = srv.post(tok, email)
                self.assertNotIn(marker, body)
                self.assertIn(status, (403, 404))
                status, body = srv.get_with_session(tok, "initech", email)
                self.assertNotIn(marker, body)
            finally:
                srv.close()


class MixedFileGrantTest(_Shut, unittest.TestCase):
    """t10 case D: ``initech.jsonl`` holds ``initech.`` and ``initech..`` (as
    0.2.45 left them), so it is keyed by its file name and its report is
    withheld."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        path = os.path.join(self.d, "initech.jsonl")
        _write(path, "initech.", "EVIL_OWN")
        _write(path, "initech..", "EVIL_OWN2")

    def test_grant_on_the_mixed_file_is_refused(self):
        code, out, err = _run(["grant", self.d, "initech", "evil.com"])
        self.assertEqual(code, 2, out + err)
        self.assertIn("initech.jsonl", err)
        self.assertIn("more than one subject", err)
        self.assertEqual(access.load_access(self.d), {})

    def test_a_later_subject_with_that_name_is_not_opened_to_the_earlier_try(self):
        _run(["grant", self.d, "initech", "evil.com"])
        _tenant_write(self.d, "initech", "REAL_INITECH")
        self.assert_shut_out(self.d)

    def test_subject_and_subjectless_records_in_one_file_are_refused(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "agent.jsonl")
        _plain(path, "NO_SUBJECT", n=1)
        _write(path, "agent", "WITH_SUBJECT")
        code, out, err = _run(["grant", d, "agent", "legit.com"])
        self.assertEqual(code, 2, out + err)
        self.assertIn("more than one subject", err)

    def test_a_chain_that_does_not_verify_is_refused(self):
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
        self.assertEqual(access.load_access(d), {})


class SubjectlessFileGrantTest(_Shut, unittest.TestCase):
    """t10 case E: a plain subjectless ``initech.jsonl`` granted by 0.2.46, then
    subject id ``initech`` is recorded."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        _plain(os.path.join(self.d, "initech.jsonl"), "EVIL_OWN")

    def test_grant_warns_that_the_chain_is_keyed_by_its_file_name(self):
        code, out, err = _run(["grant", self.d, "initech", "evil.com"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("initech.jsonl holds no subject id", err)
        self.assertIn("file name", err)
        self.assertIn("subject id 'initech'", err)
        self.assertIn("admits no one", err)

    def test_grant_admits_its_recipients_to_the_subjectless_chain(self):
        _run(["grant", self.d, "initech", "evil.com"])
        srv = _Server(self.d)
        try:
            status, body = srv.post(token_for(srv.secret, "initech"), "bob@evil.com")
            self.assertEqual(status, 200)
            self.assertIn("EVIL_OWN", body)
        finally:
            srv.close()

    def test_a_later_subject_with_that_name_does_not_inherit_the_grant(self):
        _run(["grant", self.d, "initech", "evil.com"])
        _tenant_write(self.d, "initech", "REAL_INITECH")
        self.assert_shut_out(self.d)

    def test_startup_names_the_grant_once_another_chain_takes_the_name(self):
        _run(["grant", self.d, "initech", "evil.com"])
        _tenant_write(self.d, "initech", "REAL_INITECH")
        text = "\n".join(reconcile_grants(self.d))
        self.assertIn("grant 'initech'", text)
        self.assertIn("evil.com", text)
        self.assertIn("initech.jsonl", text)
        self.assertIn("admits no one", text)

    def test_the_new_tenant_grant_does_not_merge_the_earlier_recipients(self):
        _run(["grant", self.d, "initech", "evil.com"])
        _tenant_write(self.d, "initech", "REAL_INITECH")
        code, out, err = _run(["grant", self.d, "initech", "initech.com"])
        self.assertEqual(code, 0, out + err)
        entry = access.load_access(self.d)["initech"]
        self.assertEqual(entry["allow"], ["initech.com"])
        self.assertIn("evil.com", entry.get("quarantined", []))
        self.assert_shut_out(self.d)
        srv = _Server(self.d)
        try:
            status, body = srv.post(token_for(srv.secret, "initech"), "a@initech.com")
            self.assertEqual(status, 200)
            self.assertIn("REAL_INITECH", body)
        finally:
            srv.close()

    def test_a_subject_chain_grant_does_not_warn(self):
        d = tempfile.mkdtemp()
        _tenant_write(d, "initech", "REAL")
        code, out, err = _run(["grant", d, "initech", "initech.com"])
        self.assertEqual(code, 0)
        self.assertNotIn("holds no subject id", err)


class LegacySubjectlessGrantTest(unittest.TestCase):
    """t10 case A: a 0.2.45 grant on ``agent.jsonl``, written by a plain
    ``Recorder`` with no subject id."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        _plain(os.path.join(self.d, "agent.jsonl"), "AGENT_OWN")
        _legacy_access(self.d, {"agent": {"allow": ["legit.com"]}})

    def test_startup_line_says_the_chain_holds_no_subject_id(self):
        text = "\n".join(reconcile_grants(self.d))
        self.assertIn("quarantined grant 'agent'", text)
        self.assertIn("agent.jsonl holds no subject id", text)
        self.assertNotIn("a different chain", text)
        self.assertIn("keyed by its file name", text)
        self.assertIn("halo grant %s agent <recipient>" % self.d, text)

    def test_reissued_grant_admits_the_recipient(self):
        reconcile_grants(self.d)
        code, out, err = _run(["grant", self.d, "agent", "legit.com"])
        self.assertEqual(code, 0, out + err)
        srv = _Server(self.d)
        try:
            status, body = srv.post(token_for(srv.secret, "agent"), "a@legit.com")
            self.assertEqual(status, 200)
            self.assertIn("AGENT_OWN", body)
        finally:
            srv.close()

    def test_limits_lists_holds_no_subject_id_as_a_quarantine_cause(self):
        with open(os.path.join(ROOT, "LIMITS.md"), encoding="utf-8") as fh:
            text = " ".join(fh.read().split())
        start = text.index("If `<name>` is a served subject id but `<name>.jsonl`")
        bullet = text[start:start + 600]
        self.assertTrue("holds no subject id" in bullet, bullet)


if __name__ == "__main__":
    unittest.main()
