import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.bip39_min import Bip39MinError, entropy_to_mnemonic, is_valid_mnemonic, mnemonic_to_entropy

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORDLIST_PATH = REPO_ROOT / "entropyforge" / "data" / "english.txt"
VECTORS_PATH = REPO_ROOT / "tests" / "vectors" / "bip39_vectors.json"


def _load_wordlist() -> list[str]:
    raw = WORDLIST_PATH.read_bytes()
    return [w for w in raw.decode("ascii").split("\n") if w]


class OfficialVectorsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wordlist = _load_wordlist()
        cls.vectors = json.loads(VECTORS_PATH.read_text())["english"]

    def test_all_24_official_vectors(self):
        for ent_hex, expected_mnemonic, _seed, _xprv in self.vectors:
            entropy = bytes.fromhex(ent_hex)
            with self.subTest(entropy=ent_hex):
                mnemonic = entropy_to_mnemonic(entropy, self.wordlist)
                self.assertEqual(mnemonic, expected_mnemonic)
                self.assertEqual(mnemonic_to_entropy(mnemonic, self.wordlist), entropy)


class RoundTripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wordlist = _load_wordlist()

    def test_roundtrip_random(self):
        import os

        for _ in range(500):
            nbytes = [16, 20, 24, 28, 32][os.urandom(1)[0] % 5]
            entropy = os.urandom(nbytes)
            m = entropy_to_mnemonic(entropy, self.wordlist)
            self.assertEqual(mnemonic_to_entropy(m, self.wordlist), entropy)

    def test_rejects_invalid_entropy_length(self):
        with self.assertRaises(Bip39MinError):
            entropy_to_mnemonic(b"\x00" * 17, self.wordlist)

    def test_rejects_invalid_word_count(self):
        with self.assertRaises(Bip39MinError):
            mnemonic_to_entropy("abandon abandon abandon", self.wordlist)

    def test_rejects_word_outside_wordlist(self):
        words = ["abandon"] * 23 + ["notarealword"]
        with self.assertRaises(Bip39MinError):
            mnemonic_to_entropy(" ".join(words), self.wordlist)

    def test_rejects_tampered_checksum(self):
        mnemonic = entropy_to_mnemonic(bytes(range(32)), self.wordlist)
        words = mnemonic.split()
        words[0], words[1] = words[1], words[0]
        self.assertFalse(is_valid_mnemonic(" ".join(words), self.wordlist))

    def test_rejects_wordlist_of_wrong_size(self):
        with self.assertRaises(Bip39MinError):
            entropy_to_mnemonic(bytes(32), self.wordlist[:100])


if __name__ == "__main__":
    unittest.main()
