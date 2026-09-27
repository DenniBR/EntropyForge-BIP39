"""Testes de integridade da wordlist (entropyforge.wordlist).

Inclui casos NEGATIVOS explicitos: wordlist adulterada (hash inesperado)
deve ser detectada e rejeitada, nao silenciosamente aceita.
"""

import hashlib
import importlib.resources
import unittest

from entropyforge import wordlist


class WordlistIntegrityTests(unittest.TestCase):
    def test_loads_2048_words(self):
        words = wordlist.load_wordlist()
        self.assertEqual(len(words), 2048)

    def test_matches_known_hash(self):
        raw = importlib.resources.files("entropyforge") / "data" / "english.txt"
        digest = hashlib.sha256(raw.read_bytes()).hexdigest()
        self.assertEqual(digest, wordlist.WORDLIST_SHA256)

    def test_sorted_unique_ascii_lowercase(self):
        words = wordlist.load_wordlist()
        self.assertEqual(list(words), sorted(words))
        self.assertEqual(len(set(words)), len(words))
        for w in words:
            self.assertTrue(w.isascii() and w.islower() and w.isalpha())

    def test_unique_four_letter_prefixes(self):
        words = wordlist.load_wordlist()
        prefixes = {w[:4] for w in words}
        self.assertEqual(len(prefixes), len(words))

    def test_word_to_index_roundtrip(self):
        words = wordlist.load_wordlist()
        for i in (0, 1, 1000, 2046, 2047):
            self.assertEqual(wordlist.word_to_index(words[i]), i)

    def test_word_to_index_rejects_unknown_word(self):
        with self.assertRaises(ValueError):
            wordlist.word_to_index("nao-e-uma-palavra-bip39")


class WordlistTamperDetectionTests(unittest.TestCase):
    """Simula uma wordlist adulterada chamando as validacoes internas
    diretamente com dados forjados, sem tocar o arquivo real em disco."""

    def test_wrong_hash_rejected(self):
        fake_words = list(wordlist.load_wordlist())
        fake_raw = ("\n".join(fake_words) + "\n").encode("ascii")
        # adultera 1 byte do conteudo bruto -> hash diverge
        tampered = bytearray(fake_raw)
        tampered[0] ^= 0xFF
        with self.assertRaises(wordlist.WordlistError):
            wordlist._validate(fake_words, bytes(tampered))

    def test_wrong_word_count_rejected(self):
        raw = importlib.resources.files("entropyforge").joinpath("data", "english.txt").read_bytes()
        with self.assertRaises(wordlist.WordlistError):
            wordlist._validate(["abandon", "ability"], raw)

    def test_duplicate_word_rejected(self):
        words = list(wordlist.load_wordlist())
        words[1] = words[0]  # introduz duplicata
        raw = ("\n".join(words) + "\n").encode("ascii")
        with self.assertRaises(wordlist.WordlistError):
            wordlist._validate(words, raw)

    def test_unsorted_rejected(self):
        words = list(wordlist.load_wordlist())
        words[0], words[1] = words[1], words[0]
        raw = ("\n".join(words) + "\n").encode("ascii")
        with self.assertRaises(wordlist.WordlistError):
            wordlist._validate(words, raw)

    def test_non_ascii_word_rejected(self):
        words = list(wordlist.load_wordlist())
        words[0] = "café"
        raw = ("\n".join(words) + "\n").encode("utf-8")
        with self.assertRaises(wordlist.WordlistError):
            wordlist._validate(words, raw)


if __name__ == "__main__":
    unittest.main()
