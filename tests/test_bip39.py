"""Testes de entropyforge.bip39: formato, checksum, round-trip, casos
negativos (bytes incorretos, comprimento invalido, checksum adulterado)."""

import unittest

from entropyforge.bip39 import (
    Bip39Error,
    ChecksumError,
    entropy_to_mnemonic,
    is_valid_mnemonic,
    mnemonic_to_entropy,
    mnemonic_to_seed,
)


class EntropyToMnemonicTests(unittest.TestCase):
    def test_256_bits_gives_24_words(self):
        mnemonic = entropy_to_mnemonic(bytes(32))
        self.assertEqual(len(mnemonic.split()), 24)

    def test_all_valid_lengths(self):
        for nbytes, nwords in ((16, 12), (20, 15), (24, 18), (28, 21), (32, 24)):
            with self.subTest(nbytes=nbytes):
                mnemonic = entropy_to_mnemonic(bytes(nbytes))
                self.assertEqual(len(mnemonic.split()), nwords)

    def test_rejects_invalid_lengths(self):
        for nbytes in (0, 1, 15, 17, 31, 33, 64):
            with self.subTest(nbytes=nbytes):
                with self.assertRaises(Bip39Error):
                    entropy_to_mnemonic(bytes(nbytes))

    def test_deterministic(self):
        e = bytes(range(32))
        self.assertEqual(entropy_to_mnemonic(e), entropy_to_mnemonic(e))


class MnemonicToEntropyTests(unittest.TestCase):
    def test_roundtrip_many_random(self):
        import os

        for _ in range(200):
            e = os.urandom(32)
            m = entropy_to_mnemonic(e)
            self.assertEqual(mnemonic_to_entropy(m), e)

    def test_rejects_wrong_word_count(self):
        with self.assertRaises(Bip39Error):
            mnemonic_to_entropy("abandon abandon abandon")

    def test_rejects_empty(self):
        with self.assertRaises(Bip39Error):
            mnemonic_to_entropy("")

    def test_rejects_word_outside_wordlist(self):
        words = ["abandon"] * 23 + ["notarealbip39word"]
        with self.assertRaises(Bip39Error):
            mnemonic_to_entropy(" ".join(words))

    def test_rejects_tampered_checksum(self):
        mnemonic = entropy_to_mnemonic(bytes(32))
        words = mnemonic.split()
        words[-1] = "zoo" if words[-1] != "zoo" else "abandon"
        with self.assertRaises(ChecksumError):
            mnemonic_to_entropy(" ".join(words))

    def test_checksum_error_is_bip39_error(self):
        self.assertTrue(issubclass(ChecksumError, Bip39Error))

    def test_extra_whitespace_between_words_is_tolerated(self):
        mnemonic = entropy_to_mnemonic(bytes(32))
        spaced = "  ".join(mnemonic.split())
        self.assertEqual(mnemonic_to_entropy(spaced), bytes(32))


class IsValidMnemonicTests(unittest.TestCase):
    def test_true_for_valid(self):
        self.assertTrue(is_valid_mnemonic(entropy_to_mnemonic(bytes(32))))

    def test_false_for_garbage(self):
        self.assertFalse(is_valid_mnemonic("this is not a mnemonic at all"))

    def test_false_for_tampered_checksum(self):
        mnemonic = entropy_to_mnemonic(bytes(range(32)))
        words = mnemonic.split()
        self.assertNotEqual(words[0], words[1])  # garante que a troca abaixo muda algo
        words[0], words[1] = words[1], words[0]
        self.assertFalse(is_valid_mnemonic(" ".join(words)))


class MnemonicToSeedTests(unittest.TestCase):
    def test_length_is_64_bytes(self):
        mnemonic = entropy_to_mnemonic(bytes(32))
        seed = mnemonic_to_seed(mnemonic, "")
        self.assertEqual(len(seed), 64)

    def test_different_passphrase_different_seed(self):
        mnemonic = entropy_to_mnemonic(bytes(32))
        s1 = mnemonic_to_seed(mnemonic, "")
        s2 = mnemonic_to_seed(mnemonic, "TREZOR")
        self.assertNotEqual(s1, s2)

    def test_deterministic(self):
        mnemonic = entropy_to_mnemonic(bytes(32))
        self.assertEqual(
            mnemonic_to_seed(mnemonic, "x"), mnemonic_to_seed(mnemonic, "x")
        )


if __name__ == "__main__":
    unittest.main()
