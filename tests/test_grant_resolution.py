"""``halo grant`` names a chain by its subject id first, and refuses a name
that is one chain's subject id and another chain's file name."""

import contextlib
import io
import os
import tempfile
import unittest

from halo_record import access
from halo_record.cli import main
from halo_record.record import TenantRecorder, build
from halo_record.serve import _served_chains


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class GrantResolutionTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        tr = TenantRecorder(self.d)
        with contextlib.redirect_stderr(io.StringIO()):
            tr.append(build("tool_call", "security", tool="t", subject="acme/eu"))
        self.victim_stem = os.path.basename(tr.chain_path_for("acme/eu"))[:-len(".jsonl")]
        with contextlib.redirect_stderr(io.StringIO()):
            tr.append(build("tool_call", "security", tool="t", subject=self.victim_stem))
        chains = dict(_served_chains(self.d))
        self.assertIn("acme/eu", chains)
        self.assertIn(self.victim_stem, chains)

    def test_a_subject_named_like_another_tenants_file_is_refused(self):
        code, out, err = _run(["grant", self.d, self.victim_stem, "attacker@evil.example"])
        self.assertEqual(code, 2)
        self.assertIn("ambiguous", err)
        self.assertEqual(access.allowed_for(self.d, "acme/eu"), [])
        self.assertEqual(access.allowed_for(self.d, self.victim_stem), [])

    def test_the_subject_id_still_grants_its_own_chain(self):
        code, out, err = _run(["grant", self.d, "acme/eu", "cfo@acme.com"])
        self.assertEqual(code, 0)
        self.assertEqual(access.allowed_for(self.d, "acme/eu"), ["cfo@acme.com"])

    def test_the_other_chain_is_reachable_by_its_own_file_name(self):
        chains = dict(_served_chains(self.d))
        own = os.path.basename(chains[self.victim_stem])[:-len(".jsonl")]
        self.assertNotEqual(own, self.victim_stem)
        code, out, err = _run(["grant", self.d, own, "ops@other.com"])
        self.assertEqual(code, 0, err)
        self.assertEqual(access.allowed_for(self.d, self.victim_stem), ["ops@other.com"])
        self.assertEqual(access.allowed_for(self.d, "acme/eu"), [])


if __name__ == "__main__":
    unittest.main()
