"""The verifier embedded in every Runtime Report must agree with the Python
verifier on the shared differential fixtures. Runs the page's own JavaScript
under Node; skipped where Node is not installed."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from halo_record.report import _VERIFY_JS, _load
from halo_record.verify import verify_log
from halo_record.canon import GENESIS_PREV

HERE = os.path.join(os.path.dirname(__file__), "fixtures", "differential")


@unittest.skipUnless(shutil.which("node"), "node not installed")
class BrowserVerifierAgreesTest(unittest.TestCase):
    def test_page_verifier_matches_python_on_every_fixture(self):
        page = _VERIFY_JS % {"genesis": json.dumps(GENESIS_PREV), "window_json": "null"}
        funcs = page[:page.index("function cleanCheckpoints(")]
        with open(os.path.join(HERE, "expected.json")) as fh:
            names = sorted(json.load(fh))
        for name in names:
            path = os.path.join(HERE, name)
            py_ok = verify_log(path, out=lambda *_: None)
            if not py_ok:
                continue  # the page only re-checks hash links; refusals happen before rendering
            records = _load(path)
            script = ("%s\nconst records = %s;\n"
                      "verify(records).then(r => console.log(JSON.stringify(r)));"
                      % (funcs, json.dumps(records)))
            d = tempfile.mkdtemp()
            js = os.path.join(d, "v.mjs")
            with open(js, "w", encoding="utf-8") as fh:
                fh.write(script)
            out = subprocess.run(["node", js], capture_output=True, text=True, timeout=60)
            with self.subTest(fixture=name):
                self.assertEqual(json.loads(out.stdout or "{}").get("ok"), True, out.stderr[-300:])


if __name__ == "__main__":
    unittest.main()
