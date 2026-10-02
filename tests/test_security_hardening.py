"""Adversarial regression tests: each reproduces an abuse path first, then
pins the hardened behavior. The vendor is treated as a possible adversary and
every chain-sourced value as attacker-controlled."""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from halo_record.anchor import Notary
from halo_record.canon import compute_hash
from halo_record.capture import record_model_call
from halo_record.export import parse_bound
from halo_record.record import Recorder, TenantRecorder, build
from halo_record.report import write_report
from halo_record.witness import _Handler, parse_key_spec


class TenantIsolationTest(unittest.TestCase):
    """Distinct subject IDs never share a chain file."""

    def test_lossy_ids_do_not_collide(self):
        tr = TenantRecorder(tempfile.mkdtemp())
        self.assertNotEqual(tr.path_for("acme/a"), tr.path_for("acme_a"))
        self.assertNotEqual(tr.path_for("acme a"), tr.path_for("acme_a"))
        self.assertNotEqual(tr.path_for("acme."), tr.path_for("acme"))

    def test_records_stay_in_their_own_file(self):
        tr = TenantRecorder(tempfile.mkdtemp())
        tr.append(build("tool_call", "security", tool="x", subject="acme/a"))
        tr.append(build("tool_call", "security", tool="y", subject="acme_a"))
        with open(tr.path_for("acme_a"), encoding="utf-8") as fh:
            subjects = [json.loads(l)["subject"]["id"] for l in fh if l.strip()]
        self.assertEqual(subjects, ["acme_a"])

    def test_plain_ids_keep_their_existing_filename(self):
        tr = TenantRecorder(tempfile.mkdtemp())
        self.assertEqual(os.path.basename(tr.path_for("acme-corp")), "acme-corp.jsonl")

    def test_existing_plain_named_chain_keeps_receiving_records(self):
        d = tempfile.mkdtemp()
        legacy = os.path.join(d, "acme_corp.jsonl")
        Recorder(legacy).append(build("tool_call", "security", tool="a", subject="acme corp"))
        TenantRecorder(d).append(build("tool_call", "security", tool="b", subject="acme corp"))
        with open(legacy, encoding="utf-8") as fh:
            self.assertEqual(sum(1 for l in fh if l.strip()), 2)
        self.assertEqual([f for f in os.listdir(d) if f.endswith(".jsonl")], ["acme_corp.jsonl"])

    def test_malformed_lines_do_not_break_routing(self):
        d = tempfile.mkdtemp()
        tr = TenantRecorder(d)
        with open(tr.path_for("acme-corp"), "w", encoding="utf-8") as fh:
            fh.write('[1, 2]\n"text"\nnot json\n{"subject": {"id": {"x": 1}}}\n')
        with self.assertRaises(ValueError):  # the dict-id line is another subject
            tr.append(build("tool_call", "security", tool="a", subject="acme-corp"))
        with open(tr.path_for("initech"), "wb") as fh:
            fh.write(b'\xff\xfe[]\n')
        TenantRecorder(d).append(build("tool_call", "security", tool="b", subject="initech"))

    def test_refuses_a_file_holding_another_subject(self):
        d = tempfile.mkdtemp()
        tr = TenantRecorder(d)
        stray = Recorder(tr.path_for("initech"))
        stray.append(build("tool_call", "security", tool="z", subject="acme-corp"))
        with self.assertRaises(ValueError):
            TenantRecorder(d).append(build("tool_call", "security", tool="q", subject="initech"))


def _forged_chain(path, prev):
    recs = []
    for i, day in enumerate((10, 20)):
        r = build("tool_call", "security", tool="t%d" % i, subject="acme-corp",
                  ts="2026-06-%02dT12:00:00+00:00" % day)
        r.setdefault("integrity", {})["prev_hash"] = prev
        r["integrity"]["hash"] = compute_hash(r, prev)
        prev = r["integrity"]["hash"]
        recs.append(r)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(json.dumps(r, separators=(",", ":")) for r in recs) + "\n")


class ReportInjectionTest(unittest.TestCase):
    """A crafted chain anchor never reaches the page as executable script."""

    def test_crafted_anchor_is_refused(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        _forged_chain(log, '";window.__pwned=1;//')
        out = os.path.join(d, "w.html")
        with self.assertRaises(ValueError):
            write_report(log, out, start=parse_bound("2026-06-01", end=False),
                         end=parse_bound("2026-06-30", end=True))
        if os.path.exists(out):
            with open(out, encoding="utf-8") as fh:
                self.assertNotIn("__pwned", fh.read())

    def test_valid_window_still_renders_its_anchor(self):
        d = tempfile.mkdtemp()
        rec = Recorder(os.path.join(d, "c.jsonl"))
        for day in (5, 10, 20):
            rec.append(build("tool_call", "security", tool="t", subject="acme-corp",
                             ts="2026-06-%02dT12:00:00+00:00" % day))
        out = os.path.join(d, "w.html")
        write_report(os.path.join(d, "c.jsonl"), out,
                     start=parse_bound("2026-06-10", end=False),
                     end=parse_bound("2026-06-30", end=True))
        with open(out, encoding="utf-8") as fh:
            self.assertIn("const GENESIS =", fh.read())


class WitnessScopingTest(unittest.TestCase):
    """One vendor's key cannot write checkpoints for another vendor's subject."""

    def _serve(self, keys):
        store = tempfile.mkdtemp()
        handler = type("_W", (_Handler,), {"config": {
            "notary": Notary(os.path.join(store, "witness.jsonl")),
            "keys": keys, "owners_path": os.path.join(store, "owners.json"),
            "lock": threading.Lock()}})
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return "http://127.0.0.1:%d" % httpd.server_address[1]

    def _post(self, url, key, subject, head="a" * 64):
        req = urllib.request.Request(
            url + "/anchor", method="POST",
            data=json.dumps({"subject": subject, "count": 1, "head": head}).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_explicit_scope_blocks_other_subjects(self):
        url = self._serve(parse_key_spec(["keyA=vendor-a-*", "keyB=vendor-b-*"]))
        self.assertEqual(self._post(url, "keyA", "vendor-a-acme"), 201)
        self.assertEqual(self._post(url, "keyB", "vendor-a-acme"), 403)

    def test_first_key_to_anchor_owns_an_unscoped_subject(self):
        url = self._serve(parse_key_spec(["keyA", "keyB"]))
        self.assertEqual(self._post(url, "keyA", "acme-corp"), 201)
        self.assertEqual(self._post(url, "keyB", "acme-corp"), 403)
        self.assertEqual(self._post(url, "keyA", "acme-corp", head="b" * 64), 201)


class PurposeRedactionTest(unittest.TestCase):
    """A secret or personal detail in ``purpose`` is not sealed verbatim."""

    def test_purpose_is_redacted_before_sealing(self):
        for summaries in (True, False):
            d = tempfile.mkdtemp()
            rec = Recorder(os.path.join(d, "m.jsonl"))
            record_model_call(rec, provider="anthropic", model="m", summaries=summaries,
                              purpose="use key sk-ant-api03-SECRETSECRETSECRET1234 for jane@example.com")
            with open(os.path.join(d, "m.jsonl"), encoding="utf-8") as fh:
                raw = fh.read()
            self.assertNotIn("SECRETSECRETSECRET1234", raw)
            self.assertNotIn("jane@example.com", raw)

    def test_plain_purpose_is_kept(self):
        d = tempfile.mkdtemp()
        rec = Recorder(os.path.join(d, "m.jsonl"))
        r = record_model_call(rec, provider="anthropic", model="m", purpose="draft support reply")
        self.assertEqual(r["data"]["purpose"], "draft support reply")


if __name__ == "__main__":
    unittest.main()
