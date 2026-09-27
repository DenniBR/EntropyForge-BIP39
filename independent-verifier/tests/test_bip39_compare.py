import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.bip39_compare import compare_against_official_vectors, compare_random_fuzz

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
VECTORS_PATH = REPO_ROOT / "tests" / "vectors" / "bip39_vectors.json"


class CleanEntropyForgeTests(unittest.TestCase):
    def test_no_mismatches_against_real_entropyforge(self):
        r = compare_against_official_vectors(REPO_ROOT / "entropyforge", VECTORS_PATH)
        self.assertIsNone(r.entropyforge_import_error)
        self.assertEqual(r.mismatches, ())
        self.assertTrue(r.ok)

    def test_random_fuzz_no_mismatches(self):
        r = compare_random_fuzz(REPO_ROOT / "entropyforge", n_trials=300)
        self.assertEqual(r.mismatches, ())


class TamperedEntropyForgeTests(unittest.TestCase):
    """Requisito explicito da Fase 4: o verificador deve detectar uma
    versao adulterada de bip39.py."""

    def _make_tampered_copy(self, old: str, new: str) -> Path:
        tmp = Path(tempfile.mkdtemp())
        shutil.copytree(REPO_ROOT / "entropyforge", tmp / "entropyforge")
        p = tmp / "entropyforge" / "bip39.py"
        src = p.read_text()
        self.assertIn(old, src, "pre-condicao: string a adulterar deve existir no arquivo real")
        p.write_text(src.replace(old, new, 1))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        return tmp / "entropyforge"

    def test_detects_checksum_using_wrong_byte(self):
        tampered = self._make_tampered_copy(
            "first_byte = hashlib.sha256(entropy).digest()[0]",
            "first_byte = hashlib.sha256(entropy).digest()[-1]",
        )
        r = compare_against_official_vectors(tampered, VECTORS_PATH)
        self.assertGreater(len(r.mismatches), 0)
        self.assertFalse(r.ok)

    def test_detects_wrong_hash_algorithm(self):
        tampered = self._make_tampered_copy(
            "first_byte = hashlib.sha256(entropy).digest()[0]",
            "first_byte = hashlib.sha1(entropy).digest()[0]",
        )
        r = compare_against_official_vectors(tampered, VECTORS_PATH)
        self.assertGreater(len(r.mismatches), 0)

    def test_detects_syntax_broken_module(self):
        tampered = self._make_tampered_copy("def entropy_to_mnemonic", "def entropy_to_mnemonic_ex")
        r = compare_against_official_vectors(tampered, VECTORS_PATH)
        # entropy_to_mnemonic nao existe mais -> AttributeError, capturado
        # como mismatch (nao deve travar o verificador)
        self.assertGreater(len(r.mismatches), 0)


if __name__ == "__main__":
    unittest.main()
