"""Access gate + lead capture. The gate decides *who may open* a report; it is
strictly separate from the in-browser trust chain (*is it real*)."""

import os
import tempfile
import time
import unittest

from halo_record import access


class AllowListTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_grant_and_allowed_for(self):
        access.grant(self.dir, "acme-corp", "alice@acme-corp.com")
        access.grant(self.dir, "acme-corp", "ACME-CORP.com")  # normalized lower
        allow = access.allowed_for(self.dir, "acme-corp")
        self.assertIn("alice@acme-corp.com", allow)
        self.assertIn("acme-corp.com", allow)

    def test_grant_is_idempotent(self):
        access.grant(self.dir, "acme-corp", "a@acme-corp.com")
        access.grant(self.dir, "acme-corp", "a@acme-corp.com")
        self.assertEqual(access.allowed_for(self.dir, "acme-corp").count("a@acme-corp.com"), 1)

    def test_is_allowed_exact_and_domain(self):
        allow = ["alice@acme-corp.com", "initech.com"]
        self.assertTrue(access.is_allowed("alice@acme-corp.com", allow))
        self.assertTrue(access.is_allowed("anyone@initech.com", allow))
        self.assertTrue(access.is_allowed("x@us.initech.com", allow))  # subdomain
        self.assertFalse(access.is_allowed("bob@acme-corp.com", allow))  # exact only
        self.assertFalse(access.is_allowed("evil@notinitech.com", allow))

    def test_email_ok(self):
        self.assertTrue(access.email_ok("a@b.com"))
        self.assertFalse(access.email_ok("nope"))
        self.assertFalse(access.email_ok(""))
        self.assertFalse(access.email_ok("a@b@c.com"))


class SessionTest(unittest.TestCase):
    SECRET = b"test-secret"

    def test_roundtrip(self):
        cookie = access.make_session(self.SECRET, "acme-corp", "alice@acme-corp.com")
        self.assertEqual(access.verify_session(self.SECRET, cookie, "acme-corp"),
                         "alice@acme-corp.com")

    def test_cookie_bound_to_chain(self):
        cookie = access.make_session(self.SECRET, "acme-corp", "a@acme-corp.com")
        self.assertIsNone(access.verify_session(self.SECRET, cookie, "initech"))

    def test_expired(self):
        cookie = access.make_session(self.SECRET, "acme-corp", "a@acme-corp.com", ttl=-1)
        self.assertIsNone(access.verify_session(self.SECRET, cookie, "acme-corp"))

    def test_tampered_signature(self):
        cookie = access.make_session(self.SECRET, "acme-corp", "a@acme-corp.com")
        self.assertIsNone(access.verify_session(b"wrong-secret", cookie, "acme-corp"))

    def test_garbage_cookie(self):
        self.assertIsNone(access.verify_session(self.SECRET, "not-base64!!", "acme-corp"))
        self.assertIsNone(access.verify_session(self.SECRET, "", "acme-corp"))


class OtpTest(unittest.TestCase):
    def test_success_consumes_code(self):
        store = access.OtpStore()
        code = store.issue("acme-corp", "a@acme-corp.com")
        self.assertTrue(store.check("acme-corp", "a@acme-corp.com", code))
        # one-time: a second use fails
        self.assertFalse(store.check("acme-corp", "a@acme-corp.com", code))

    def test_wrong_code(self):
        store = access.OtpStore()
        store.issue("acme-corp", "a@acme-corp.com")
        self.assertFalse(store.check("acme-corp", "a@acme-corp.com", "000000"))

    def test_attempts_capped(self):
        store = access.OtpStore()
        code = store.issue("acme-corp", "a@acme-corp.com")
        for _ in range(access.OTP_MAX_ATTEMPTS):
            store.check("acme-corp", "a@acme-corp.com", "bad")
        # code is burned even though we now present the right one
        self.assertFalse(store.check("acme-corp", "a@acme-corp.com", code))

    def test_expiry(self):
        store = access.OtpStore()
        code = store.issue("acme-corp", "a@acme-corp.com")
        store._d[("acme-corp", "a@acme-corp.com")]["exp"] = time.time() - 1
        self.assertFalse(store.check("acme-corp", "a@acme-corp.com", code))

    def test_unknown_key(self):
        self.assertFalse(access.OtpStore().check("acme-corp", "a@acme-corp.com", "123456"))


class LeadTest(unittest.TestCase):
    def test_capture_and_read(self):
        d = tempfile.mkdtemp()
        access.capture_lead(d, "alice@acme-corp.com", "acme-corp", subject="Acme-corp")
        access.capture_lead(d, "bob@initech.com", "initech")
        leads = access.read_leads(d)
        self.assertEqual(len(leads), 2)
        self.assertEqual(leads[0]["email"], "alice@acme-corp.com")
        self.assertEqual(leads[0]["chain"], "acme-corp")

    def test_read_leads_empty(self):
        self.assertEqual(access.read_leads(tempfile.mkdtemp()), [])


class GateHintTest(unittest.TestCase):
    """The email gate never reveals who can enter unless a hint is explicitly
    configured (the demo does; real deployments must not leak the grant list)."""

    def test_gate_has_no_hint_by_default(self):
        from halo_record.serve import _gate_html
        html = _gate_html("Acme Corp", "tok123")
        self.assertNotIn("Demo mode", html)
        self.assertNotIn("acme-corp.com", html)

    def test_gate_renders_explicit_hint(self):
        from halo_record.serve import _gate_html
        html = _gate_html("Acme Corp", "tok123", hint="Demo mode: try alice@acme-corp.com")
        self.assertIn("Demo mode: try alice@acme-corp.com", html)


if __name__ == "__main__":
    unittest.main()
