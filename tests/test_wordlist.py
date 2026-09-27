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
    diretamente com dados forjados, sem tocar o arquivo real em disco.

    IMPORTANTE (correcao de um teste mascarado encontrada em auditoria
    adversarial, ver docs/REDTEAM.md): `_validate(words, raw)` checa o
    hash de `raw` ANTES de checar ordenacao/duplicatas/ASCII em `words`.
    As versoes anteriores destas quatro checagens recalculavam `raw` a
    partir da lista JA ADULTERADA (`"\n".join(words)...`), o que muda o
    hash e faz a checagem de hash disparar PRIMEIRO -- mascarando
    completamente se a checagem especifica (ordenacao, duplicata, ASCII)
    testada por cada metodo realmente funciona. Confirmado por mutation
    testing: remover a checagem de ordenacao ou de duplicatas do codigo-
    fonte NAO fazia nenhum teste falhar. A correcao usa os bytes ORIGINAIS
    corretos (hash valido) e corrompe SO a lista `words` em memoria, para
    que a execucao realmente chegue na checagem especifica sendo testada.
    """

    @classmethod
    def setUpClass(cls):
        cls.original_words = list(wordlist.load_wordlist())
        cls.original_raw = importlib.resources.files("entropyforge").joinpath(
            "data", "english.txt"
        ).read_bytes()
        # pre-condicao: o hash dos bytes originais deve bater, senao os
        # testes abaixo estariam testando a checagem errada por acidente.
        assert hashlib.sha256(cls.original_raw).hexdigest() == wordlist.WORDLIST_SHA256

    def test_wrong_hash_rejected(self):
        tampered = bytearray(self.original_raw)
        tampered[0] ^= 0xFF  # adultera 1 byte do conteudo bruto -> hash diverge
        with self.assertRaises(wordlist.WordlistError):
            wordlist._validate(self.original_words, bytes(tampered))

    def test_wrong_word_count_rejected(self):
        with self.assertRaises(wordlist.WordlistError):
            wordlist._validate(["abandon", "ability"], self.original_raw)

    def test_duplicate_word_rejected(self):
        words = list(self.original_words)
        words[1] = words[0]  # introduz duplicata; RAW permanece o original (hash valido)
        with self.assertRaises(wordlist.WordlistError):
            wordlist._validate(words, self.original_raw)

    def test_unsorted_rejected(self):
        words = list(self.original_words)
        words[0], words[1] = words[1], words[0]  # RAW permanece o original (hash valido)
        with self.assertRaises(wordlist.WordlistError):
            wordlist._validate(words, self.original_raw)

    def test_non_ascii_word_rejected(self):
        words = list(self.original_words)
        words[0] = "café"  # RAW permanece o original (hash valido)
        with self.assertRaises(wordlist.WordlistError):
            wordlist._validate(words, self.original_raw)


if __name__ == "__main__":
    unittest.main()
