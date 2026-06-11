"""TenantRecorder: per-customer physical isolation, each its own verifiable chain."""

import os
import tempfile
import unittest

from halo_record.record import TenantRecorder, build
from halo_record.verify import verify_log


def _silent(*_a, **_k):
    pass


class TenantTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_routes_to_per_subject_files(self):
        tr = TenantRecorder(self.dir)
        tr.append(build("tool_call", "security", tool="a", subject="acme-corp"))
        tr.append(build("tool_call", "security", tool="b", subject="initech"))
        tr.append(build("tool_call", "security", tool="c", subject="acme-corp"))
        self.assertTrue(os.path.exists(tr.path_for("acme-corp")))
        self.assertTrue(os.path.exists(tr.path_for("initech")))
        # other tenants invisible by construction — acme-corp file has only acme-corp's 2
        with open(tr.path_for("acme-corp")) as fh:
            self.assertEqual(sum(1 for l in fh if l.strip()), 2)

    def test_each_chain_verifies_independently(self):
        tr = TenantRecorder(self.dir)
        for i in range(3):
            tr.append(build("tool_call", "security", tool="p%d" % i, subject="acme-corp"))
        self.assertTrue(verify_log(tr.path_for("acme-corp"), out=_silent))

    def test_subjectless_goes_to_default(self):
        tr = TenantRecorder(self.dir, default="_local")
        tr.append(build("tool_call", "security", tool="x"))
        self.assertTrue(os.path.exists(tr.path_for("_local")))

    def test_unsafe_names_sanitized(self):
        safe = TenantRecorder._safe("../../etc/passwd")
        self.assertNotIn("/", safe)
        self.assertFalse(safe.startswith("."))
        self.assertEqual(TenantRecorder._safe(""), "tenant")
        # a sanitized path can never escape the directory
        p = TenantRecorder(self.dir).path_for("../evil")
        self.assertEqual(os.path.dirname(os.path.abspath(p)),
                         os.path.abspath(self.dir))


if __name__ == "__main__":
    unittest.main()
