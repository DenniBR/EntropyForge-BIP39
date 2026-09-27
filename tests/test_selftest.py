"""Testes de entropyforge.selftest: caminho feliz (tudo passa) e injecao
de falha em um componente critico (hash inesperado da wordlist), para
confirmar que o selftest REALMENTE detecta e reporta a falha em vez de
mascara-la."""

import unittest
from unittest import mock

from entropyforge import selftest, wordlist


class SelfTestHappyPathTests(unittest.TestCase):
    def test_all_items_pass_on_healthy_install(self):
        result = selftest.run_selftest()
        self.assertTrue(result.all_passed, msg=result.format())

    def test_format_includes_overall_result(self):
        result = selftest.run_selftest()
        self.assertIn("RESULTADO GERAL: PASSOU", result.format())


class SelfTestFailureInjectionTests(unittest.TestCase):
    def test_detects_tampered_wordlist_hash(self):
        wordlist.load_wordlist.cache_clear()
        try:
            with mock.patch.object(wordlist, "WORDLIST_SHA256", "0" * 64):
                result = selftest.run_selftest()
                self.assertFalse(result.all_passed)
                item = next(i for i in result.items if i.name == "wordlist_integrity")
                self.assertFalse(item.passed)
                self.assertIn("hash", item.detail.lower())
        finally:
            wordlist.load_wordlist.cache_clear()

    def test_detects_broken_sha256_expectation(self):
        # Substitui um vetor esperado por um valor errado para confirmar
        # que o item realmente compara, nao so "roda sem excecao".
        with mock.patch.object(
            selftest,
            "_SHA256_KAT_VECTORS",
            ((b"abc", "0" * 64),),
        ):
            result = selftest.run_selftest()
            item = next(i for i in result.items if i.name == "sha256_kat_vectors")
            self.assertFalse(item.passed)

    def test_format_shows_fail_marker(self):
        with mock.patch.object(wordlist, "WORDLIST_SHA256", "0" * 64):
            wordlist.load_wordlist.cache_clear()
            try:
                result = selftest.run_selftest()
                self.assertIn("[FAIL]", result.format())
                self.assertIn("RESULTADO GERAL: FALHOU", result.format())
            finally:
                wordlist.load_wordlist.cache_clear()


if __name__ == "__main__":
    unittest.main()
