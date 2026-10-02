"""``halo hook`` never drops an event silently.

An event it cannot read (not JSON, not UTF-8, not a JSON object) produces one
stderr line naming the problem and exits 0, so the agent is not broken and the
missing record is visible.
"""

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from halo_record import hook

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")


class _Stdin:
    def __init__(self, data):
        self.buffer = io.BytesIO(data)

    def read(self):
        return self.buffer.read().decode("utf-8")


class HookInputTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        p = mock.patch.dict(os.environ, {"HALO_LOG": os.path.join(self.d, "c.jsonl")})
        p.start()
        self.addCleanup(p.stop)

    def _run(self, data):
        err = io.StringIO()
        with mock.patch("sys.stdin", _Stdin(data)), contextlib.redirect_stderr(err):
            rc = hook.main([])
        return rc, err.getvalue()

    def test_malformed_json_is_reported(self):
        rc, err = self._run(b"{bad")
        self.assertEqual(rc, 0)
        self.assertIn("halo-record: hook", err)
        self.assertIn("not valid JSON", err)
        self.assertIn("no record", err)

    def test_non_utf8_is_reported(self):
        rc, err = self._run(b'{"tool_name": "\xff"}')
        self.assertEqual(rc, 0)
        self.assertIn("not UTF-8", err)

    def test_a_json_array_is_reported(self):
        rc, err = self._run(b"[1, 2]")
        self.assertEqual(rc, 0)
        self.assertIn("not a JSON object", err)

    def test_empty_input_stays_quiet(self):
        rc, err = self._run(b"  \n")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")

    def test_the_cli_entry_point(self):
        env = dict(os.environ, PYTHONPATH=SRC)
        p = subprocess.run([sys.executable, "-m", "halo_record.cli", "hook"], input=b"{bad",
                           capture_output=True, env=env, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(b"not valid JSON", p.stderr)
        self.assertNotIn(b"Traceback", p.stderr)


if __name__ == "__main__":
    unittest.main()
