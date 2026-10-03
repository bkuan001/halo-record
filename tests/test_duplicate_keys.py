"""A chain line that repeats a key in one object (at any depth) is refused by
every reader. JSON parsers disagree on which of the two values wins, so such a
line can show a reader text the hash never covered (the sealed value hashes;
the other one rides along beside it). The verifier, report, export, policy,
anchor and the report page's in-browser verifier all refuse it, and the
TypeScript verifier agrees on the shared fixtures."""

import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from halo_record import anchor, export, policy, report
from halo_record.cli import main
from halo_record.record import Recorder, _complete_record, build
from halo_record.verify import read_log_lines, verify_log

HERE = os.path.join(os.path.dirname(__file__), "fixtures", "differential")
DUPS = ("dup_key.jsonl", "dup_key_nested.jsonl")
NODE = shutil.which("node")


def _verify(path):
    out = []
    ok = verify_log(path, out=out.append)
    return ok, "\n".join(out)


def _dup_chain():
    """A three-record chain whose second line gains a repeated "outcome" key in
    front of the sealed one: the sealed value is the one a last-wins reader
    keeps, so the hash still matches."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, "c.jsonl")
    rec = Recorder(path)
    for tool in ("a", "refund.issue", "c"):
        rec.append(build("tool_call", "security", tool=tool, subject="acme",
                         outcome={"status": "ok", "summary": "refund issued"}))
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().split("\n")
    lines[1] = lines[1].replace(
        '"outcome":', '"outcome":{"status":"denied","summary":"refund DENIED by gate"},"outcome":', 1)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return d, path


class VerifyRefusesRepeatedKeysTest(unittest.TestCase):
    def test_fixtures_fail_and_name_the_record(self):
        for name in DUPS:
            with self.subTest(fixture=name):
                ok, text = _verify(os.path.join(HERE, name))
                self.assertFalse(ok)
                self.assertIn("record 2: duplicate key", text)
                self.assertIn("FAIL", text)
                self.assertNotIn("OK:", text)

    def test_injected_outcome_fails_verify_and_cli_exits_1(self):
        _, path = _dup_chain()
        ok, text = _verify(path)
        self.assertFalse(ok)
        self.assertIn("record 2: duplicate key 'outcome'", text)
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["verify", path]), 1)

    def test_the_rest_of_the_chain_is_still_checked(self):
        # The line is refused, not skipped: records after it still link.
        _, path = _dup_chain()
        _, text = _verify(path)
        self.assertNotIn("record 3: chain", text)

    def test_an_intact_chain_still_verifies(self):
        self.assertTrue(verify_log(os.path.join(HERE, "valid.jsonl"), out=lambda *_: None))


class ReadersRefuseRepeatedKeysTest(unittest.TestCase):
    def test_report_refuses(self):
        d, path = _dup_chain()
        with self.assertRaises(ValueError) as cm:
            report._load(path)
        self.assertIn("record 2", str(cm.exception))
        self.assertIn("duplicate key", str(cm.exception))
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertNotEqual(main(["report", path, "-o", os.path.join(d, "r.html")]), 0)
        self.assertFalse(os.path.exists(os.path.join(d, "r.html")))

    def test_export_refuses(self):
        d, path = _dup_chain()
        with self.assertRaises(ValueError):
            export.load_records(path)
        out = os.path.join(d, "e.csv")
        msg = io.StringIO()
        with redirect_stdout(msg), redirect_stderr(msg):
            self.assertEqual(main(["export", path, "-o", out]), 1)
        self.assertFalse(os.path.exists(out))
        self.assertIn("fails verification", msg.getvalue())

    def test_policy_refuses(self):
        _, path = _dup_chain()
        with self.assertRaises(ValueError):
            policy.load_records(path)

    def test_checkpoint_line_with_a_repeated_key_is_damaged(self):
        line = '{"subject":"acme","count":1,"count":2,"head":"%s"}' % ("a" * 64)
        self.assertIsNone(anchor.parse_checkpoint_line(line))
        d = tempfile.mkdtemp()
        w = os.path.join(d, "w.jsonl")
        with open(w, "w") as fh:
            fh.write(line + "\n")
        with self.assertRaises(anchor.WitnessFileError):
            anchor.Notary(w).checkpoints(subject="acme")

    def test_appender_does_not_take_a_repeated_key_line_as_its_head(self):
        _, path = _dup_chain()
        lines = read_log_lines(path)
        self.assertIsNone(_complete_record(lines[1]))
        self.assertIsNotNone(_complete_record(lines[0]))


class RemoteWitnessResponseTest(unittest.TestCase):
    def test_checkpoint_response_with_a_repeated_key_is_refused(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from halo_record.witness import fetch_checkpoints
        body = ('{"checkpoints":[{"subject":"acme","count":1,"count":3,"head":"%s"}]}'
                % ("a" * 64)).encode("utf-8")

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            with self.assertRaises(ValueError):
                fetch_checkpoints("http://127.0.0.1:%d" % httpd.server_address[1], "acme")
        finally:
            httpd.shutdown()
            httpd.server_close()


class HostedWitnessRefusesRepeatedKeysTest(unittest.TestCase):
    def test_anchor_body_with_a_repeated_key_gets_400(self):
        import threading
        import urllib.error
        import urllib.request
        from http.server import ThreadingHTTPServer
        from halo_record.witness import _Handler
        store = tempfile.mkdtemp()
        notary = anchor.Notary(os.path.join(store, "witness.jsonl"))
        handler = type("_BoundWitness", (_Handler,), {"config": {"notary": notary, "keys": ["k-1"]}})
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        body = ('{"subject":"acme","count":1,"count":9,"head":"%s","chain_root":"%s"}'
                % ("a" * 64, "a" * 64)).encode("utf-8")
        req = urllib.request.Request(
            "http://127.0.0.1:%d/anchor" % httpd.server_address[1], data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": "Bearer k-1"})
        try:
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(req, timeout=5)
            self.assertEqual(cm.exception.code, 400)
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(notary.checkpoints(), [])


class ServeRefusesRepeatedKeysTest(unittest.TestCase):
    def test_served_report_is_not_rendered(self):
        import threading
        import urllib.error
        import urllib.request
        from http.server import ThreadingHTTPServer
        from halo_record.serve import _Handler, load_secret, token_for
        d, _ = _dup_chain()
        secret = load_secret(d)
        handler = type("_Bound", (_Handler,), {"config": {
            "dir": d, "secret": secret, "gated": False, "verify": False, "otp": None,
            "witness_url": None, "witness": None}})
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            url = "http://127.0.0.1:%d/r/%s" % (httpd.server_address[1], token_for(secret, "acme"))
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    status, body = r.status, r.read().decode("utf-8")
            except urllib.error.HTTPError as e:
                status, body = e.code, e.read().decode("utf-8")
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertNotEqual(status, 200)
        self.assertNotIn("DENIED", body)
        self.assertNotIn("refund.issue", body)


@unittest.skipUnless(NODE, "node not installed")
class PageVerifierRefusesRepeatedKeysTest(unittest.TestCase):
    """The report page parses its embedded records itself; a repeated key in
    that JSON fails verification there too (parity with the CLI)."""

    def _page_verdict(self, records_text):
        from halo_record.canon import GENESIS_PREV
        from halo_record.report import _VERIFY_JS
        page = _VERIFY_JS % {"genesis": json.dumps(GENESIS_PREV), "window_json": "null"}
        funcs = page[:page.index("function cleanCheckpoints(")]
        script = ("%s\nverifyText(%s).then(r => console.log(JSON.stringify(r)));"
                  % (funcs, json.dumps(records_text)))
        js = os.path.join(tempfile.mkdtemp(), "v.mjs")
        with open(js, "w", encoding="utf-8") as fh:
            fh.write(script)
        p = subprocess.run([NODE, js], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr[-400:])
        return json.loads(p.stdout)

    def test_page_and_cli_agree_on_every_fixture(self):
        with open(os.path.join(HERE, "expected.json")) as fh:
            names = sorted(json.load(fh))
        for name in names:
            path = os.path.join(HERE, name)
            py_ok = verify_log(path, out=lambda *_: None)
            if not py_ok and name not in DUPS:
                continue  # refused before rendering for other reasons
            text = "[" + ",".join(read_log_lines(path)) + "]"
            with self.subTest(fixture=name):
                got = self._page_verdict(text)
                self.assertEqual(got.get("ok"), py_ok, got)
                if name in DUPS:
                    self.assertEqual(got.get("at"), 2)
                    self.assertIn("duplicate key", got.get("why", ""))

    def test_injected_outcome_fails_in_the_page(self):
        _, path = _dup_chain()
        got = self._page_verdict("[" + ",".join(read_log_lines(path)) + "]")
        self.assertFalse(got["ok"])
        self.assertEqual(got["at"], 2)

    def test_generated_page_with_an_edited_records_block_fails(self):
        from tests.test_page_binding import _page_parts, _run_page
        d = tempfile.mkdtemp()
        log = os.path.join(d, "c.jsonl")
        rec = Recorder(log)
        for tool in ("a", "refund.issue", "c"):
            rec.append(build("tool_call", "security", tool=tool, subject="acme"))
        html, _ = report.write_report(log, os.path.join(d, "r.html"))
        blocks, _ = _page_parts(html)
        edited = blocks["records"].replace('"tool":"refund.issue"',
                                           '"tool":"EVIL.wire_transfer","tool":"refund.issue"', 1)
        self.assertNotEqual(edited, blocks["records"])
        out = _run_page(html.replace(blocks["records"], edited))
        self.assertIn("fail", out["verdict"]["className"])
        self.assertIn("duplicate key", out["verdict"]["html"])
        self.assertIsNone(out["rows"])


if __name__ == "__main__":
    unittest.main()
