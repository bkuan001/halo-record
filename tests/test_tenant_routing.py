"""Per-subject routing: a subject named like the default chain gets its own
chain, and a subject whose earlier records sit in a shared file from an
earlier version is told, on stderr, where its new chain starts."""

import contextlib
import io
import json
import os
import tempfile
import unittest

from halo_record.record import Recorder, TenantRecorder, build
from halo_record.verify import verify_log


def _rec(subject=None, tool="t"):
    kw = {"subject": subject} if subject is not None else {}
    return build("tool_call", "security", tool=tool, **kw)


def _subjects(path):
    out = []
    with open(path) as fh:
        for line in fh:
            r = json.loads(line)
            out.append((r.get("subject") or {}).get("id"))
    return out


class DefaultNamedSubjectTest(unittest.TestCase):
    def test_subject_named_like_default_has_its_own_chain(self):
        d = tempfile.mkdtemp()
        t = TenantRecorder(d)
        t.append(_rec(tool="unsubjected"))
        t.append(_rec(subject="_local", tool="tenant-op"))
        default_path = t.chain_path_for(t.default)
        self.assertEqual(_subjects(default_path), [None])
        others = [f for f in os.listdir(d) if f.endswith(".jsonl")
                  and os.path.join(d, f) != default_path]
        self.assertEqual(len(others), 1)
        self.assertEqual(_subjects(os.path.join(d, others[0])), ["_local"])
        # A fresh recorder routes the same way.
        t2 = TenantRecorder(d)
        t2.append(_rec(subject="_local"))
        t2.append(_rec())
        self.assertEqual(_subjects(default_path), [None, None])
        self.assertEqual(_subjects(os.path.join(d, others[0])), ["_local", "_local"])


class SharedLegacyFileTest(unittest.TestCase):
    def test_each_subject_of_a_shared_file_is_told_where_it_continues(self):
        d = tempfile.mkdtemp()
        shared = os.path.join(d, "acme_eu.jsonl")
        r = Recorder(shared)  # an earlier version cleaned both ids to one name
        r.append(_rec(subject="acme/eu"))
        r.append(_rec(subject="acme_eu"))
        for sid in ("acme/eu", "acme_eu"):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                t = TenantRecorder(d)
                t.append(_rec(subject=sid))
            msg = err.getvalue()
            self.assertIn(repr(sid), msg, sid)
            self.assertIn("acme_eu.jsonl", msg, sid)
            new_path = t.chain_path_for(sid)
            self.assertNotEqual(new_path, shared)
            self.assertTrue(verify_log(new_path, out=lambda *_: None))
        self.assertEqual(_subjects(shared), ["acme/eu", "acme_eu"])  # untouched


if __name__ == "__main__":
    unittest.main()
