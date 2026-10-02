"""Secret-bearing files are created owner-only from the first byte, never
written world-readable and tightened afterwards."""

import os
import stat
import tempfile
import unittest
from unittest import mock


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class PrivateFileTest(unittest.TestCase):
    def setUp(self):
        self.old = os.umask(0o022)
        self.addCleanup(os.umask, self.old)
        self.dir = tempfile.mkdtemp()

    def _without_chmod(self, fn):
        # If owner-only depends on a chmod after the write, this exposes it.
        with mock.patch("os.chmod"):
            fn()

    def test_serve_secret(self):
        from halo_record.serve import load_secret
        self._without_chmod(lambda: load_secret(self.dir))
        self.assertEqual(_mode(os.path.join(self.dir, ".halo_serve_secret")), 0o600)

    def test_witness_key(self):
        from halo_record.witness import KEY_FILE, load_keys
        env = os.environ.pop("HALO_WITNESS_KEYS", None)
        self.addCleanup(lambda: env is not None and os.environ.__setitem__("HALO_WITNESS_KEYS", env))
        self._without_chmod(lambda: load_keys(self.dir))
        self.assertEqual(_mode(os.path.join(self.dir, KEY_FILE)), 0o600)

    def test_access_list(self):
        from halo_record.access import _access_path, save_access
        self._without_chmod(lambda: save_access(self.dir, {"c": {"allow": ["a@b.co"]}}))
        self.assertEqual(_mode(_access_path(self.dir)), 0o600)


if __name__ == "__main__":
    unittest.main()
