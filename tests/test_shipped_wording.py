"""Shipped recorder and adapter source describes provenance in plain terms
("evidentiary tier", "accurate"). The checked words are assembled at runtime,
the same way secret-shaped test values are, so this file does not match its
own check."""

import os
import re
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "src", "halo_record")
FILES = ["record.py", "demo.py", "capture.py", "redact.py", "canon.py", "verify.py",
         os.path.join("integrations", "__init__.py"),
         os.path.join("integrations", "gateway.py"),
         os.path.join("integrations", "langfuse.py"),
         os.path.join("integrations", "litellm.py"),
         os.path.join("integrations", "mcp.py"),
         os.path.join("integrations", "_common.py")]


AVOIDED = re.compile(r"(?i)\b" + "hon" + "est")


class ShippedWordingTest(unittest.TestCase):
    def test_plain_provenance_wording(self):
        for name in FILES:
            with open(os.path.join(SRC, name), encoding="utf-8") as fh:
                text = fh.read()
            self.assertIsNone(AVOIDED.search(text), name)


if __name__ == "__main__":
    unittest.main()
