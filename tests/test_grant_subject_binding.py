"""A grant follows a chain's subject id, so it must be made against a file
whose name matches that id. A file whose name names one tenant but whose
records carry another tenant's subject id cannot receive a grant, and a subject
served from such a file alongside its own file is withheld rather than handed
to whichever grant was made first. At ``halo serve`` startup, grants and share
links keyed by a 0.2.45 file name are carried to the subject id they serve, or
listed with how to re-issue them."""

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
from halo_record.serve import (_Handler, _served_chains, load_secret, reconcile_grants,
                               token_for)


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def _write(path, subject, tool):
    with contextlib.redirect_stderr(io.StringIO()):
        Recorder(path).append(build("tool_call", "security", tool=tool, subject=subject))


class _Server:
    def __init__(self, directory):
        self.dir = directory
        self.secret = load_secret(directory)
        cfg = {"dir": directory, "secret": self.secret, "gated": True, "verify": False,
               "otp": access.OtpStore(), "witness_url": None, "witness": None,
               "gate_hint": None}
        handler = type("_B", (_Handler,), {"config": cfg})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def post(self, token, email):
        import http.client
        body = urlencode({"email": email}).encode()
        c = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=5)
        with contextlib.redirect_stdout(io.StringIO()):
            c.request("POST", "/r/%s" % token, body,
                      {"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            data = r.read().decode("utf-8", "replace")
        c.close()
        return r.status, data


class MislabeledFileGrantTest(unittest.TestCase):
    """SEC-602: globex.jsonl carries subject id ``initech``."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        _write(os.path.join(self.d, "globex.jsonl"), "initech", "GLOBEX_FILE")

    def test_grant_by_file_name_is_refused_when_the_file_carries_another_subject(self):
        code, out, err = _run(["grant", self.d, "globex", "globex.com"])
        self.assertEqual(code, 2, out + err)
        self.assertIn("globex.jsonl", err)
        self.assertIn("'initech'", err)
        self.assertEqual(access.load_access(self.d), {})

    def test_grant_by_subject_id_is_refused_while_the_only_file_is_mislabeled(self):
        code, out, err = _run(["grant", self.d, "initech", "globex.com"])
        self.assertEqual(code, 2, out + err)
        self.assertIn("globex.jsonl", err)
        self.assertEqual(access.load_access(self.d), {})

    def test_a_later_file_for_that_subject_is_not_handed_to_an_earlier_grant(self):
        # A grant stored under the subject key while only the mislabeled file
        # existed (as an earlier build allowed), then the real tenant's file
        # appears and is granted to its own domain.
        access.grant(self.d, "initech", "globex.com")
        _write(os.path.join(self.d, "initech.jsonl"), "initech", "REAL_INITECH")
        access.grant(self.d, "initech", "initech.com")
        srv = _Server(self.d)
        try:
            status, body = srv.post(token_for(srv.secret, "initech"), "bob@globex.com")
            self.assertNotIn("REAL_INITECH", body)
            self.assertNotEqual(status, 200)
        finally:
            srv.close()
        self.assertNotIn("initech", dict(_served_chains(self.d)))

    def test_the_withheld_subject_is_named_at_startup(self):
        _write(os.path.join(self.d, "initech.jsonl"), "initech", "REAL_INITECH")
        lines = reconcile_grants(self.d)
        text = "\n".join(lines)
        self.assertIn("globex.jsonl", text)
        self.assertIn("'initech'", text)

    def test_grant_against_the_cli_flow_does_not_reach_the_real_tenant(self):
        # The reported repro end to end through the CLI.
        _run(["grant", self.d, "globex", "globex.com"])
        _write(os.path.join(self.d, "initech.jsonl"), "initech", "REAL_INITECH")
        _run(["grant", self.d, "initech", "initech.com"])
        srv = _Server(self.d)
        try:
            for key in ("initech", "globex"):
                status, body = srv.post(token_for(srv.secret, key), "bob@globex.com")
                self.assertNotIn("REAL_INITECH", body, key)
        finally:
            srv.close()

    def test_a_well_named_file_still_takes_a_grant(self):
        d = tempfile.mkdtemp()
        with contextlib.redirect_stderr(io.StringIO()):
            TenantRecorder(d).append(build("tool_call", "security", tool="t", subject="Acme Corp"))
        code, out, err = _run(["grant", d, "Acme Corp", "acme.com"])
        self.assertEqual(code, 0, err)
        self.assertEqual(access.allowed_for(d, "Acme Corp"), ["acme.com"])


class LegacyStemGrantTest(unittest.TestCase):
    """SEC-603: a directory served by 0.2.45, whose grants and links were keyed
    by file stem (``Acme_Corp`` for subject id ``Acme Corp``)."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        # 0.2.45 TenantRecorder named the file with the pre-0.2.46 cleaning.
        _write(os.path.join(self.d, TenantRecorder._safe("Acme Corp") + ".jsonl"),
               "Acme Corp", "ACME")
        _write(os.path.join(self.d, "initech.jsonl"), "initech", "INITECH")
        with open(os.path.join(self.d, access.ACCESS_FILE), "w") as fh:
            json.dump({"Acme_Corp": {"allow": ["acme.com"]},
                       "initech": {"allow": ["initech.com"]},
                       "Gone_Co": {"allow": ["gone.example"]}}, fh)

    def test_stem_keyed_grant_is_carried_to_the_subject_key(self):
        lines = reconcile_grants(self.d)
        data = access.load_access(self.d)
        self.assertEqual(data.get("Acme Corp", {}).get("allow"), ["acme.com"])
        self.assertNotIn("Acme_Corp", data)
        self.assertEqual(data["initech"]["allow"], ["initech.com"])
        text = "\n".join(lines)
        self.assertIn("Acme_Corp", text)
        self.assertIn("'Acme Corp'", text)

    def test_orphaned_grant_is_listed_with_how_to_reissue(self):
        text = "\n".join(reconcile_grants(self.d))
        self.assertIn("Gone_Co", text)
        self.assertIn("gone.example", text)
        self.assertIn("halo grant", text)
        self.assertIn("Gone_Co", access.load_access(self.d))   # left for the operator

    def test_old_link_and_grant_still_admit_the_recipient(self):
        reconcile_grants(self.d)
        srv = _Server(self.d)
        try:
            old = token_for(srv.secret, "Acme_Corp")
            new = token_for(srv.secret, "Acme Corp")
            for token in (old, new):
                status, body = srv.post(token, "a@acme.com")
                self.assertEqual(status, 200, token)
                self.assertIn("ACME", body)
            status, body = srv.post(old, "bob@initech.com")
            self.assertEqual(status, 403)
        finally:
            srv.close()

    def test_reconcile_is_idempotent(self):
        reconcile_grants(self.d)
        first = access.load_access(self.d)
        reconcile_grants(self.d)
        self.assertEqual(access.load_access(self.d), first)

    def test_stem_of_a_mislabeled_file_is_not_carried(self):
        d = tempfile.mkdtemp()
        _write(os.path.join(d, "globex.jsonl"), "initech", "GLOBEX_FILE")
        with open(os.path.join(d, access.ACCESS_FILE), "w") as fh:
            json.dump({"globex": {"allow": ["globex.com"]}}, fh)
        text = "\n".join(reconcile_grants(d))
        data = access.load_access(d)
        self.assertNotIn("initech", data)
        self.assertIn("globex", text)
        srv = _Server(d)
        try:
            status, body = srv.post(token_for(srv.secret, "globex"), "bob@globex.com")
            self.assertNotIn("GLOBEX_FILE", body)
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()
