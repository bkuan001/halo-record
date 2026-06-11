"""RFC 8785 canonicalization + hashing — the root of the whole trust chain."""

import unittest

from halo_record.canon import (
    GENESIS_PREV, canon, compute_hash, input_hash, sha256_hex,
)


class CanonTest(unittest.TestCase):
    def test_primitives(self):
        self.assertEqual(canon(True), "true")
        self.assertEqual(canon(False), "false")
        self.assertEqual(canon(None), "null")
        self.assertEqual(canon(42), "42")
        self.assertEqual(canon("hi"), '"hi"')

    def test_object_keys_are_sorted(self):
        self.assertEqual(canon({"b": 1, "a": 2}), '{"a":2,"b":1}')

    def test_nested_and_arrays(self):
        self.assertEqual(canon({"z": [3, 2, 1], "a": {"y": 1, "x": 2}}),
                         '{"a":{"x":2,"y":1},"z":[3,2,1]}')

    def test_string_escaping(self):
        self.assertEqual(canon('a"b\\c\n'), '"a\\"b\\\\c\\n"')

    def test_non_integer_float_rejected(self):
        # The format is integer-valued only; a fractional float must not silently
        # canonicalize to something a verifier would disagree about.
        with self.assertRaises(ValueError):
            canon(1.5)

    def test_integer_valued_float_ok(self):
        self.assertEqual(canon(3.0), "3")

    def test_deterministic(self):
        a = canon({"x": 1, "y": [1, 2, {"q": "r"}]})
        b = canon({"y": [1, 2, {"q": "r"}], "x": 1})
        self.assertEqual(a, b)


class HashTest(unittest.TestCase):
    def test_genesis_prev_shape(self):
        self.assertEqual(GENESIS_PREV, "0" * 64)
        self.assertEqual(len(GENESIS_PREV), 64)

    def test_input_hash_prefixed(self):
        h = input_hash({"query": "x"})
        self.assertTrue(h.startswith("sha256:"))
        self.assertEqual(len(h), len("sha256:") + 64)

    def test_input_hash_stable_across_key_order(self):
        self.assertEqual(input_hash({"a": 1, "b": 2}), input_hash({"b": 2, "a": 1}))

    def test_input_hash_tolerates_unserializable(self):
        # Must never crash a hook on an odd input — falls back to a stable form.
        self.assertTrue(input_hash({"o": object()}).startswith("sha256:"))

    def test_compute_hash_excludes_hash_field(self):
        rec = {"a": 1, "integrity": {"prev_hash": "x", "hash": "STALE"}}
        h1 = compute_hash(rec, GENESIS_PREV)
        rec["integrity"]["hash"] = "DIFFERENT"
        h2 = compute_hash(rec, GENESIS_PREV)
        self.assertEqual(h1, h2)  # the hash field itself is not part of the digest

    def test_compute_hash_includes_prev(self):
        rec = {"a": 1, "integrity": {}}
        self.assertNotEqual(compute_hash(rec, GENESIS_PREV), compute_hash(rec, "f" * 64))

    def test_compute_hash_is_64_hex_no_prefix(self):
        h = compute_hash({"a": 1, "integrity": {}}, GENESIS_PREV)
        self.assertEqual(len(h), 64)
        self.assertFalse(h.startswith("sha256:"))
        int(h, 16)  # valid hex

    def test_sha256_hex_known_vector(self):
        self.assertEqual(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


if __name__ == "__main__":
    unittest.main()
