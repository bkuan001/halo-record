"""Card numbers are found in the separator styles LIMITS names."""

import unittest

from halo_record.record import build
from halo_record.redact import redact_text, scan

FORMS = ["4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111",
         "4111.1111.1111.1111", "4111 1111 1111 1111",
         "4111 1111 1111 1111", "4111 1111 1111 1111"]


class CardSeparatorTest(unittest.TestCase):
    def test_each_form_is_found_and_masked(self):
        for form in FORMS:
            text = "card " + form + " exp 12/30"
            self.assertIn("credit_card", [f["type"] for f in scan(text)], repr(form))
            out = redact_text(text)
            self.assertIn("****1111", out, repr(form))
            self.assertNotIn("4111", out.replace("****1111", ""), repr(form))
            rec = build("tool_call", "security", tool="t", tool_input={"q": text})
            self.assertEqual(rec["data"]["pii_types"], ["credit_card"], repr(form))

    def test_luhn_still_gates_dotted_numbers(self):
        self.assertNotIn("credit_card", [f["type"] for f in scan("v 4111.1111.1111.1112")])


if __name__ == "__main__":
    unittest.main()
