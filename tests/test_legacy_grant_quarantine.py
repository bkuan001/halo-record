"""A grant written before 0.2.46 is keyed by a file name. After the upgrade the
same name is read as a subject id. When those two readings point at different
chains (the file ``initech.jsonl`` holds subject id ``initech.`` while subject
id ``initech`` is served from another file), the grant is quarantined: it
admits no one, and ``halo serve`` prints it with how to re-issue it. A grant
whose two readings point at the same single chain keeps working.

Directories here are laid out the way 0.2.45 left them: plain ``Recorder``
files named with the pre-0.2.46 cleaning, and an access file whose entries
carry no subject-id marker."""

import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode

from halo_record import access
from halo_record.cli import main
from halo_record.record import Recorder, TenantRecorder, build
from halo_record.serve import (_Handler, ambiguous_link_lines, load_secret, reconcile_grants,
                               token_for)

EVIL_SUBJECTS = ["initech.", "initech ", "_initech", "initech/", "initech​",
                 "initech.."]


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def _write(path, subject, tool):
    with contextlib.redirect_stderr(io.StringIO()):
        Recorder(path).append(build("tool_call", "security", tool=tool, subject=subject))


def _tenant_write(directory, subject, tool):
    with contextlib.redirect_stderr(io.StringIO()):
        TenantRecorder(directory).append(build("tool_call", "security", tool=tool,
                                               subject=subject))


def _legacy_access(directory, data):
    """An access file as 0.2.45 wrote it: {file stem: {"allow": [...]}}."""
    with open(os.path.join(directory, access.ACCESS_FILE), "w") as fh:
        json.dump(data, fh)


class _Server:
    def __init__(self, directory, verify=False, gated=True):
        self.dir = directory
        self.secret = load_secret(directory)
        self.otp = access.OtpStore()
        cfg = {"dir": directory, "secret": self.secret, "gated": gated, "verify": verify,
               "otp": self.otp, "witness_url": None, "witness": None, "gate_hint": None}
        handler = type("_B", (_Handler,), {"config": cfg})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _req(self, method, token, body=None, headers=None):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=5)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            c.request(method, "/r/%s" % token, body, headers or {})
            r = c.getresponse()
            data = r.read().decode("utf-8", "replace")
        c.close()
        return r.status, data, out.getvalue()

    def post(self, token, email, code=None):
        fields = {"email": email}
        if code is not None:
            fields["code"] = code
        status, data, _printed = self._req(
            "POST", token, urlencode(fields).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"})
        return status, data

    def get_with_session(self, token, chain, email):
        cookie = "halo_%s=%s" % (token[:16], access.make_session(self.secret, chain, email))
        status, data, _printed = self._req("GET", token, headers={"Cookie": cookie})
        return status, data


class ShapeATest(unittest.TestCase):
    """0.2.45: TenantRecorder wrote the attacker-chosen subject id ``initech.`` to
    ``initech.jsonl``; the victim's records (subject id ``initech``) are in an
    operator-named ``initech-prod.jsonl``. The operator granted the stems."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        _write(os.path.join(self.d, "initech.jsonl"), "initech.", "EVIL_OWN")
        _write(os.path.join(self.d, "initech-prod.jsonl"), "initech", "REAL_INITECH")
        _legacy_access(self.d, {"initech": {"allow": ["evil.com"]},
                                "initech-prod": {"allow": ["initech.com"]}})

    def _assert_evil_shut_out(self, srv):
        status, body = srv.post(token_for(srv.secret, "initech"), "bob@evil.com")
        self.assertNotIn("REAL_INITECH", body)
        self.assertIn(status, (403, 404))

    def test_stem_grant_does_not_reach_the_chain_now_keyed_by_that_name(self):
        reconcile_grants(self.d)
        srv = _Server(self.d)
        try:
            self._assert_evil_shut_out(srv)
        finally:
            srv.close()

    def test_shut_out_even_before_startup_reconciliation_runs(self):
        srv = _Server(self.d)
        try:
            self._assert_evil_shut_out(srv)
        finally:
            srv.close()

    def test_a_session_minted_for_the_stem_does_not_open_the_other_chain(self):
        for reconcile in (False, True):
            if reconcile:
                reconcile_grants(self.d)
            srv = _Server(self.d)
            try:
                status, body = srv.get_with_session(token_for(srv.secret, "initech"),
                                                    "initech", "bob@evil.com")
                self.assertNotIn("REAL_INITECH", body, reconcile)
            finally:
                srv.close()

    def test_verify_email_mode_refuses_before_issuing_a_code(self):
        reconcile_grants(self.d)
        srv = _Server(self.d, verify=True)
        try:
            tok = token_for(srv.secret, "initech")
            status, body = srv.post(tok, "bob@evil.com")
            self.assertEqual(status, 403)
            self.assertNotIn("REAL_INITECH", body)
            self.assertEqual(srv.otp._issued, {})
            self.assertFalse(os.path.exists(os.path.join(self.d, access.OTP_OUTBOX)))
            status, body = srv.post(tok, "bob@evil.com", code="000000")
            self.assertEqual(status, 403)
            self.assertNotIn("REAL_INITECH", body)
        finally:
            srv.close()

    def test_the_quarantined_grant_is_printed_with_a_reissue_line(self):
        text = "\n".join(reconcile_grants(self.d))
        self.assertIn("quarantined grant 'initech'", text)
        self.assertIn("evil.com", text)
        self.assertIn("initech.jsonl", text)
        self.assertIn("'initech.'", text)
        self.assertIn("halo grant %s <subject id> <recipient>" % self.d, text)

    def test_the_quarantined_grant_admits_no_one_and_is_kept_for_the_operator(self):
        reconcile_grants(self.d)
        entry = access.load_access(self.d)["initech"]
        self.assertEqual(entry.get("allow", []), [])
        self.assertEqual(entry.get("quarantined"), ["evil.com"])
        self.assertNotIn("by", entry)
        # Still printed on the next start, and still admits no one.
        text = "\n".join(reconcile_grants(self.d))
        self.assertIn("quarantined grant 'initech'", text)
        self.assertEqual(access.load_access(self.d)["initech"].get("allow", []), [])

    def test_open_mode_does_not_open_the_other_chain_by_the_earlier_link(self):
        # With gating off the link is the only check. The 0.2.45 link for
        # initech.jsonl is the same token as subject id ``initech``'s link.
        srv = _Server(self.d, gated=False)
        try:
            status, body, _ = srv._req("GET", token_for(srv.secret, "initech"))
            self.assertNotIn("REAL_INITECH", body)
            self.assertEqual(status, 404)
            status, body, _ = srv._req("GET", token_for(srv.secret, "initech."))
            self.assertEqual(status, 200)
            self.assertIn("EVIL_OWN", body)
        finally:
            srv.close()
        text = "\n".join(ambiguous_link_lines(self.d))
        self.assertIn("'initech'", text)
        self.assertIn("initech.jsonl", text)

    def test_gated_mode_still_serves_the_subject_link_to_its_recipients(self):
        reconcile_grants(self.d)
        access.grant(self.d, "initech", "initech.com")
        srv = _Server(self.d)
        try:
            status, body = srv.post(token_for(srv.secret, "initech"), "a@initech.com")
            self.assertEqual(status, 200)
            self.assertIn("REAL_INITECH", body)
        finally:
            srv.close()

    def test_the_stem_grant_is_not_carried_to_the_subject_its_file_held(self):
        reconcile_grants(self.d)
        self.assertEqual(access.load_access(self.d).get("initech.", {}).get("allow", []), [])


class ShapeBTest(unittest.TestCase):
    """0.2.45 wrote an attacker-chosen subject id to ``initech.jsonl``; after the
    upgrade the 0.2.46 TenantRecorder writes the real ``initech`` to
    ``initech~<digest>.jsonl`` because ``initech.jsonl`` holds another id."""

    def test_each_variant_is_quarantined(self):
        for evil in EVIL_SUBJECTS:
            with self.subTest(evil=evil):
                d = tempfile.mkdtemp()
                stem = TenantRecorder._safe(evil)
                self.assertEqual(stem, "initech")
                _write(os.path.join(d, stem + ".jsonl"), evil, "EVIL_OWN")
                _legacy_access(d, {stem: {"allow": ["evil.com"]}})
                _tenant_write(d, "initech", "REAL_INITECH")
                files = sorted(f for f in os.listdir(d) if f.endswith(".jsonl"))
                self.assertTrue(any(f.startswith("initech~") for f in files), files)
                for reconcile in (False, True):
                    if reconcile:
                        text = "\n".join(reconcile_grants(d))
                        self.assertIn("quarantined grant 'initech'", text)
                    srv = _Server(d)
                    try:
                        status, body = srv.post(token_for(srv.secret, "initech"),
                                                "bob@evil.com")
                        self.assertNotIn("REAL_INITECH", body)
                        self.assertIn(status, (403, 404))
                    finally:
                        srv.close()


class UnambiguousLegacyGrantTest(unittest.TestCase):
    def test_file_name_equal_to_its_subject_id_keeps_its_grant(self):
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "initech.jsonl"), "initech", "REAL_INITECH")
        _legacy_access(d, {"initech": {"allow": ["initech.com"]}})
        text = "\n".join(reconcile_grants(d))
        self.assertNotIn("quarantined", text)
        self.assertEqual(access.load_access(d)["initech"]["allow"], ["initech.com"])
        srv = _Server(d)
        try:
            status, body = srv.post(token_for(srv.secret, "initech"), "a@initech.com")
            self.assertEqual(status, 200)
            self.assertIn("REAL_INITECH", body)
        finally:
            srv.close()

    def test_carried_before_the_victim_exists_stays_with_its_subject(self):
        # First 0.2.46 start happens before the real ``initech`` has records:
        # the stem grant is carried to ``initech.``, and the later real
        # ``initech`` is not opened to its recipients.
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "initech.jsonl"), "initech.", "EVIL_OWN")
        _legacy_access(d, {"initech": {"allow": ["evil.com"]}})
        text = "\n".join(reconcile_grants(d))
        self.assertIn("carried grant 'initech'", text)
        self.assertEqual(access.load_access(d)["initech."]["allow"], ["evil.com"])
        _tenant_write(d, "initech", "REAL_INITECH")
        reconcile_grants(d)
        srv = _Server(d)
        try:
            status, body = srv.post(token_for(srv.secret, "initech"), "bob@evil.com")
            self.assertNotIn("REAL_INITECH", body)
            status, body = srv.post(token_for(srv.secret, "initech."), "bob@evil.com")
            self.assertEqual(status, 200)
            self.assertIn("EVIL_OWN", body)
        finally:
            srv.close()

    def test_a_grant_issued_by_subject_id_survives_restarts(self):
        # The ambiguous layout from shape B, but the grant was issued by 0.2.46
        # (by subject id, through the file name chain_key accepts).
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "initech.jsonl"), "initech.", "EVIL_OWN")
        _tenant_write(d, "initech", "REAL_INITECH")
        own = [f for f in os.listdir(d) if f.startswith("initech~") and f.endswith(".jsonl")]
        code, out, err = _run(["grant", d, own[0][:-len(".jsonl")], "initech.com"])
        self.assertEqual(code, 0, out + err)
        for _ in range(2):
            self.assertNotIn("quarantined", "\n".join(reconcile_grants(d)))
        srv = _Server(d)
        try:
            status, body = srv.post(token_for(srv.secret, "initech"), "a@initech.com")
            self.assertEqual(status, 200)
            self.assertIn("REAL_INITECH", body)
        finally:
            srv.close()

    def test_halo_grant_does_not_promote_earlier_file_name_recipients(self):
        # Shape A, then the operator adds a recipient by subject id through a
        # path that resolves to ``initech``: the earlier evil.com entry stays
        # quarantined and is not merged into the subject-id grant.
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "initech.jsonl"), "initech.", "EVIL_OWN")
        _tenant_write(d, "initech", "REAL_INITECH")
        _legacy_access(d, {"initech": {"allow": ["evil.com"]}})
        own = [f for f in os.listdir(d) if f.startswith("initech~") and f.endswith(".jsonl")]
        code, out, err = _run(["grant", d, own[0][:-len(".jsonl")], "initech.com"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("quarantined grant 'initech'", out + err)
        entry = access.load_access(d)["initech"]
        self.assertEqual(entry["allow"], ["initech.com"])
        self.assertEqual(entry["quarantined"], ["evil.com"])
        srv = _Server(d)
        try:
            status, body = srv.post(token_for(srv.secret, "initech"), "bob@evil.com")
            self.assertEqual(status, 403)
            status, body = srv.post(token_for(srv.secret, "initech"), "a@initech.com")
            self.assertEqual(status, 200)
        finally:
            srv.close()


class MixedFileShapeTest(unittest.TestCase):
    """SEC-801. 0.2.45 cleaned the attacker-chosen subject ids ``initech.`` and
    ``initech..`` to one file name, so ``initech.jsonl`` holds both; the
    operator granted that stem. A file holding several subjects is keyed by its
    stem, so the name ``initech`` reads as that file and also as the real
    subject ``initech``, which 0.2.46 writes to ``initech~<digest>.jsonl``.
    The grant names a different chain under each reading: quarantined."""

    def _layout(self, victim=True):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "initech.jsonl")
        _write(path, "initech.", "EVIL_OWN")
        _write(path, "initech..", "EVIL_OWN2")
        _legacy_access(d, {"initech": {"allow": ["evil.com"]}})
        if victim:
            self._victim(d)
        return d

    def _victim(self, d):
        _tenant_write(d, "initech", "REAL_INITECH")
        files = sorted(f for f in os.listdir(d) if f.endswith(".jsonl"))
        self.assertTrue(any(f.startswith("initech~") for f in files), files)

    def _assert_evil_shut_out(self, d):
        srv = _Server(d)
        try:
            status, body = srv.post(token_for(srv.secret, "initech"), "bob@evil.com")
            self.assertNotIn("REAL_INITECH", body)
            self.assertIn(status, (403, 404))
            status, body = srv.get_with_session(token_for(srv.secret, "initech"),
                                                "initech", "bob@evil.com")
            self.assertNotIn("REAL_INITECH", body)
        finally:
            srv.close()

    def test_victim_before_first_start(self):
        d = self._layout()
        self._assert_evil_shut_out(d)
        text = "\n".join(reconcile_grants(d))
        self.assertIn("quarantined grant 'initech'", text)
        self.assertIn("evil.com", text)
        entry = access.load_access(d)["initech"]
        self.assertNotIn("by", entry)
        self.assertEqual(entry.get("allow", []), [])
        for _ in range(2):   # restarts
            self._assert_evil_shut_out(d)
            self.assertIn("quarantined grant 'initech'", "\n".join(reconcile_grants(d)))

    def test_victim_after_first_start(self):
        d = self._layout(victim=False)
        text = "\n".join(reconcile_grants(d))
        self.assertIn("quarantined grant 'initech'", text)
        self.assertNotIn("by", access.load_access(d)["initech"])
        self._victim(d)
        self._assert_evil_shut_out(d)
        reconcile_grants(d)
        self._assert_evil_shut_out(d)

    def test_quarantine_line_names_the_mixed_file(self):
        d = self._layout()
        text = "\n".join(reconcile_grants(d))
        self.assertIn("initech.jsonl holds several subject ids", text)
        self.assertIn("initech~", text)

    def test_open_mode_withholds_the_earlier_link(self):
        d = self._layout()
        srv = _Server(d, gated=False)
        try:
            status, body, _ = srv._req("GET", token_for(srv.secret, "initech"))
            self.assertNotIn("REAL_INITECH", body)
            self.assertEqual(status, 404)
        finally:
            srv.close()
        text = "\n".join(ambiguous_link_lines(d))
        self.assertIn("link withheld: subject id 'initech'", text)
        self.assertIn("initech.jsonl", text)

    def test_open_mode_without_the_victim_withholds_nothing(self):
        # Only the mixed file: no other chain has subject id ``initech``.
        d = self._layout(victim=False)
        self.assertEqual(ambiguous_link_lines(d), [])


class OrdinaryUpgradeTest(unittest.TestCase):
    """0.2.45 grants on ordinary tenants keep working after the upgrade, with
    records continuing in 0.2.46."""

    def test_stem_grants_keep_working(self):
        for subject in ["acme", "Acme Corp", "acme.io", "tenant-42", "user@x.com", "ACME",
                        "café", "acme_corp"]:
            with self.subTest(subject=subject):
                d = tempfile.mkdtemp()
                stem = TenantRecorder._safe(subject)
                _write(os.path.join(d, stem + ".jsonl"), subject, "OLD")
                _write(os.path.join(d, "other.jsonl"), "other", "OTHER")
                _legacy_access(d, {stem: {"allow": ["cust.com"]},
                                   "other": {"allow": ["other.com"]}})
                text = "\n".join(reconcile_grants(d))
                self.assertNotIn("quarantined", text)
                _tenant_write(d, subject, "NEW")
                self.assertNotIn("quarantined", "\n".join(reconcile_grants(d)))
                self.assertEqual(ambiguous_link_lines(d), [])
                srv = _Server(d)
                try:
                    for tok in {token_for(srv.secret, subject), token_for(srv.secret, stem)}:
                        status, body = srv.post(tok, "a@cust.com")
                        self.assertEqual(status, 200)
                        self.assertNotIn("OTHER", body)
                        status, body = srv.post(tok, "a@other.com")
                        self.assertEqual(status, 403)
                    status, body = srv.post(token_for(srv.secret, "other"), "a@cust.com")
                    self.assertEqual(status, 403)
                finally:
                    srv.close()


class OrphanGrantLineTest(unittest.TestCase):
    """SEC-803: a 0.2.45 grant whose file is gone admits no one now, and the
    startup line says it can become active if a matching chain appears."""

    def test_line_says_the_grant_can_become_active_later(self):
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "other.jsonl"), "other", "OTHER")
        _legacy_access(d, {"initech": {"allow": ["evil.com"]}})
        text = "\n".join(reconcile_grants(d))
        self.assertIn("grant 'initech' (recipients: evil.com) matches no served chain", text)
        self.assertNotIn("so it admits no one.", text)
        self.assertIn("admits no one now", text)
        self.assertIn("can become active later", text)
        self.assertIn("initech.jsonl", text)
        # And it does: a chain whose file and only subject id are ``initech``.
        _write(os.path.join(d, "initech.jsonl"), "initech", "REAL_INITECH")
        reconcile_grants(d)
        self.assertEqual(access.load_access(d)["initech"].get("by"), access.BY_SUBJECT)


class GrantForAbsentChainTest(unittest.TestCase):
    """SEC-703: a grant for a name that matches no chain pre-grants a subject id
    that may appear later; ``halo grant`` says so."""

    def test_grant_for_an_absent_chain_warns(self):
        d = tempfile.mkdtemp()
        _tenant_write(d, "initech.", "EVIL_OWN")
        code, out, err = _run(["grant", d, "initech", "evil.com"])
        self.assertEqual(code, 0)
        self.assertIn("no chain in %s has subject id or file name 'initech'" % d, err)
        self.assertIn("appears later", err)
        self.assertIn("'initech.'", err)   # the near match is named

    def test_grant_for_an_existing_chain_does_not_warn(self):
        d = tempfile.mkdtemp()
        _tenant_write(d, "initech", "REAL")
        code, out, err = _run(["grant", d, "initech", "initech.com"])
        self.assertEqual(code, 0)
        self.assertNotIn("no chain", err)


if __name__ == "__main__":
    unittest.main()
