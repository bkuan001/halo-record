"""The package version is declared twice — pyproject.toml (build metadata) and
halo_record.__version__ (runtime attribute). They drift silently unless pinned
to each other; a release that bumps one but not the other ships a package that
reports the wrong version at import time."""
import re
import unittest
from pathlib import Path

import halo_record


class TestVersionParity(unittest.TestCase):
    def test_pyproject_matches_module_version(self):
        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        m = re.search(r'^version = "([^"]+)"', pyproject.read_text(), re.M)
        self.assertIsNotNone(m, "version line missing from pyproject.toml")
        self.assertEqual(m.group(1), halo_record.__version__)


if __name__ == "__main__":
    unittest.main()
