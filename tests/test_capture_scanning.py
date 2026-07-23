"""Response-borne secrets/PII must be scanned.

Regression (0.2.20): the capture path used to redact the outcome summary before
build() scanned it, so a secret or PII that came back in a tool's *response*
never produced findings, data.pii_types, or an elevated severity. build() is now
the single scan+redact authority — derive_outcome hands it the raw text.
"""

import json
import os
import tempfile
import unittest

from halo_record import Recorder, record
from halo_record.capture import record_call


class TestCaptureScanning(unittest.TestCase):
    def _last(self, path):
        with open(path, encoding="utf-8") as fh:
            return json.loads(fh.read().splitlines()[-1])

    def test_decorator_scans_response_secret_and_pii(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.jsonl")
            rec = Recorder(path)

            @record(rec, category="security")
            def fetch():
                return {"data": "token sk-" + "b" * 25 + " owner bob@corp.io"}

            fetch()
            r = self._last(path)
            ftypes = {f["type"] for f in r["findings"]}
            self.assertIn("api_key", ftypes)
            self.assertIn("email", ftypes)
            self.assertEqual(r["severity"], "CRITICAL")
            self.assertIn("email", r["data"]["pii_types"])
            # the raw secret and raw email never enter the stored record
            blob = json.dumps(r)
            self.assertNotIn("sk-bbbbb", blob)
            self.assertNotIn("bob@corp.io", blob)

    def test_context_manager_scans_response_ssn(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.jsonl")
            rec = Recorder(path)
            with record_call(rec, "lookup", {"q": "ok"}, category="privacy") as call:
                call.result = {"ssn": "123-45-6789"}
            r = self._last(path)
            ftypes = {f["type"] for f in r["findings"]}
            self.assertIn("ssn", ftypes)
            self.assertIn("ssn", r["data"]["pii_types"])
            self.assertNotIn("123-45-6789", json.dumps(r))

    def test_clean_response_stays_info(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.jsonl")
            rec = Recorder(path)

            @record(rec, category="security")
            def ping():
                return {"status": "ok", "rows": 3}

            ping()
            r = self._last(path)
            self.assertEqual(r["findings"], [])
            self.assertEqual(r["severity"], "INFO")
            self.assertNotIn("data", r)


if __name__ == "__main__":
    unittest.main()
