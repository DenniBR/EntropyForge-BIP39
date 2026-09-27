"""Valida a implementacao BIP-39 contra os 24 vetores OFICIAIS
(trezor/python-mnemonic vectors.json), cobrindo 12/18/24 palavras e
a derivacao de seed com a passphrase de teste "TREZOR" (requisito 11)."""

import json
import unittest
from pathlib import Path

from entropyforge.bip39 import entropy_to_mnemonic, mnemonic_to_entropy, mnemonic_to_seed

VECTORS_PATH = Path(__file__).parent / "vectors" / "bip39_vectors.json"


class OfficialVectorsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VECTORS_PATH) as f:
            data = json.load(f)
        cls.vectors = data["english"]
        cls.assertGreaterEqual(cls, len(cls.vectors), 24)

    def test_all_vectors(self):
        for i, (ent_hex, expected_mnemonic, expected_seed_hex, _xprv) in enumerate(self.vectors):
            with self.subTest(vector=i):
                entropy = bytes.fromhex(ent_hex)
                mnemonic = entropy_to_mnemonic(entropy)
                self.assertEqual(mnemonic, expected_mnemonic)
                self.assertEqual(mnemonic_to_entropy(mnemonic), entropy)
                seed = mnemonic_to_seed(mnemonic, "TREZOR")
                self.assertEqual(seed.hex(), expected_seed_hex)

    def test_covers_all_supported_lengths(self):
        lengths = {len(bytes.fromhex(v[0])) for v in self.vectors}
        self.assertEqual(lengths, {16, 24, 32})


if __name__ == "__main__":
    unittest.main()
