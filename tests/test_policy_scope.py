"""A rule whose "when" already decides its forbid or require is refused.

``when action.type=network`` with ``forbid action.type=read`` can never be
violated: every selected record has type network. Likewise a ``require`` that
every selected record meets by construction. Both used to evaluate to PASS
and assert nothing. ``validate_policy`` refuses them (the CLI exits 2) and the
report page refuses the same rules with the same message.
"""

import json
import os
import subprocess
import tempfile
import unittest

from halo_record import _view
from halo_record.policy import validate_policy
from tests.test_page_binding import NODE

REFUSED = [
    ({"action.type": "network"}, "forbid", {"action.type": "read"}),
    ({"outcome.status": "denied"}, "forbid", {"outcome.status": "ok"}),
    ({"outcome.status": {"ne": "ok"}}, "forbid", {"outcome.status": "ok"}),
    ({"action.type": {"in": ["network", "read"]}}, "forbid", {"action.type": {"eq": "write"}}),
    ({"action.type": {"in": ["network", "read"]}}, "forbid", {"action.type": {"nin": ["network", "read"]}}),
    ({"action.authorization.approver": {"exists": False}}, "forbid",
     {"action.authorization.approver": "alice"}),
    ({"action.authorization.approver": "alice"}, "forbid",
     {"action.authorization.approver": {"exists": False}}),
    ({"data.cross_region": {"gt": 0}}, "forbid", {"data.cross_region": {"lt": 0}}),
    ({"data.cross_region": 1}, "forbid", {"data.cross_region": {"gt": 1}}),
    ({"action.type": "network"}, "require", {"action.type": "network"}),
    ({"action.type": "network"}, "require", {"action.type": {"in": ["network", "read"]}}),
    ({"action.authorization.approver": {"exists": False}}, "require",
     {"action.authorization.approver": {"exists": False}}),
]

ACCEPTED = [
    ({"action.type": "network"}, "forbid", {"outcome.status": "ok"}),
    ({"action.type": {"in": ["network", "read"]}}, "forbid", {"action.type": "read"}),
    ({"action.type": "network"}, "require", {"action.type": {"ne": "network"}}),
    ({"findings[].type": "ssn"}, "forbid", {"findings[].type": "email"}),
    ({"data.cross_region": {"gt": 0}}, "forbid", {"data.cross_region": {"lt": 5}}),
    ({"outcome.status": {"ne": "denied"}}, "forbid", {"outcome.status": "ok"}),
    ({"action.type": "network"}, "require", {"action.type": "network", "outcome.status": "ok"}),
]


def _rule(when, key, cond):
    return [{"id": "r", "when": when, key: cond}]


class RuleScopeTest(unittest.TestCase):
    def test_refused(self):
        for when, key, cond in REFUSED:
            with self.subTest(when=when, key=key, cond=cond):
                with self.assertRaises(ValueError) as cm:
                    validate_policy(_rule(when, key, cond))
                self.assertIn("can never be violated", str(cm.exception))

    def test_accepted(self):
        for when, key, cond in ACCEPTED:
            with self.subTest(when=when, key=key, cond=cond):
                validate_policy(_rule(when, key, cond))

    def test_bundled_packs_still_validate(self):
        root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "examples", "policies")
        for name in ("owasp-starter.json", "aiuc-1-starter.json"):
            with open(os.path.join(root, name), encoding="utf-8") as fh:
                validate_policy(json.load(fh)["rules"])


_HARNESS = r"""
const fs = require("fs");
%s
const cases = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
process.stdout.write(JSON.stringify(cases.map(c => HaloView.validatePolicy(c))));
"""


@unittest.skipUnless(NODE, "node not installed")
class PageParityTest(unittest.TestCase):
    def test_page_gives_the_same_verdict_and_message(self):
        cases = [_rule(*c) for c in REFUSED + ACCEPTED]
        expected = []
        for c in cases:
            try:
                validate_policy(c)
                expected.append(None)
            except ValueError as e:
                expected.append(str(e))
        d = tempfile.mkdtemp()
        data = os.path.join(d, "cases.json")
        with open(data, "w", encoding="utf-8") as fh:
            json.dump(cases, fh)
        js = os.path.join(d, "h.js")
        with open(js, "w", encoding="utf-8") as fh:
            fh.write(_HARNESS % _view.render_js())
        p = subprocess.run([NODE, js, data], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), expected)


if __name__ == "__main__":
    unittest.main()
