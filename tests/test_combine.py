"""Testes de entropyforge.combine: E = SHA-256(A||B), com casos negativos
de comprimento incorreto de B/A."""

import hashlib
import unittest

from entropyforge.combine import ENTROPY_BYTES, combine
from entropyforge.dice import encode


class CombineTests(unittest.TestCase):
    def test_matches_raw_sha256(self):
        a = encode("123456" * 20)
        b = bytes(range(32))
        self.assertEqual(combine(a, b), hashlib.sha256(a + b).digest())

    def test_output_is_32_bytes(self):
        a = encode("135246" * 20)
        b = bytes(32)
        self.assertEqual(len(combine(a, b)), ENTROPY_BYTES)

    def test_deterministic(self):
        a = encode("111111")
        b = bytes(range(32))
        self.assertEqual(combine(a, b), combine(a, b))

    def test_different_a_gives_different_e(self):
        b = bytes(32)
        e1 = combine(encode("111111"), b)
        e2 = combine(encode("222222"), b)
        self.assertNotEqual(e1, e2)

    def test_different_b_gives_different_e(self):
        a = encode("123456")
        e1 = combine(a, bytes(32))
        e2 = combine(a, bytes([1] * 32))
        self.assertNotEqual(e1, e2)

    def test_rejects_b_too_short(self):
        a = encode("123456")
        with self.assertRaises(ValueError):
            combine(a, bytes(31))

    def test_rejects_b_too_long(self):
        a = encode("123456")
        with self.assertRaises(ValueError):
            combine(a, bytes(33))

    def test_rejects_empty_a(self):
        with self.assertRaises(ValueError):
            combine(b"", bytes(32))


if __name__ == "__main__":
    unittest.main()
