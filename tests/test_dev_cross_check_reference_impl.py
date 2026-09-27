"""Comparacao cruzada, SOMENTE PARA DESENVOLVIMENTO, com a implementacao de
referencia python-mnemonic (Trezor) citada na propria especificacao
BIP-39 (requisito 11: testes independentes contra uma implementacao
conhecida).

Este teste e pulado automaticamente se o pacote `mnemonic` nao estiver
instalado -- ele NUNCA e uma dependencia de runtime deste projeto (ver
docs/DESIGN.md, decisao de "zero dependencias em runtime"; o teste de AST
em test_security_ast.py so cobre `entropyforge/`, nao `tests/`, e mesmo
assim `mnemonic` nunca e importado la).

Para rodar localmente: `pip install mnemonic` num venv de desenvolvimento
e depois `python3 -m unittest tests.test_dev_cross_check_reference_impl`.
"""

import os
import unittest

from entropyforge.bip39 import entropy_to_mnemonic, mnemonic_to_entropy
from entropyforge.wordlist import load_wordlist

try:
    from mnemonic import Mnemonic

    _HAVE_REFERENCE_IMPL = True
except ImportError:
    _HAVE_REFERENCE_IMPL = False


@unittest.skipUnless(_HAVE_REFERENCE_IMPL, "pacote 'mnemonic' (dev-only) nao instalado")
class CrossCheckReferenceImplementationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ref = Mnemonic("english")

    def test_wordlists_are_identical(self):
        self.assertEqual(list(load_wordlist()), self.ref.wordlist)

    def test_random_entropies_match(self):
        for _ in range(2000):
            nbytes = os.urandom(1)[0] % 5 * 4 + 16  # 16,20,24,28,32
            entropy = os.urandom(nbytes)
            ours = entropy_to_mnemonic(entropy)
            theirs = self.ref.to_mnemonic(entropy)
            self.assertEqual(ours, theirs)
            self.assertEqual(mnemonic_to_entropy(ours), entropy)

    def test_edge_case_entropies_match(self):
        cases = [
            bytes(32), bytes([0xFF] * 32), bytes([0x80] + [0] * 31),
            bytes([0x7F] + [0xFF] * 31), bytes(range(32)),
            bytes(16), bytes([0xFF] * 16),
        ]
        for entropy in cases:
            with self.subTest(entropy=entropy.hex()):
                self.assertEqual(entropy_to_mnemonic(entropy), self.ref.to_mnemonic(entropy))


if __name__ == "__main__":
    unittest.main()
