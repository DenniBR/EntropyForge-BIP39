import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.wordlist_check import check_matches_official_hash, check_wordlist_bytes, check_wordlist_file

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORDLIST_PATH = REPO_ROOT / "entropyforge" / "data" / "english.txt"


class RealWordlistTests(unittest.TestCase):
    def test_real_wordlist_passes_all_checks(self):
        r = check_wordlist_file(WORDLIST_PATH)
        self.assertTrue(r.ok, msg=r.problems)
        self.assertEqual(r.word_count, 2048)

    def test_real_wordlist_matches_known_official_hash(self):
        r = check_wordlist_file(WORDLIST_PATH)
        ok, msg = check_matches_official_hash(r)
        self.assertTrue(ok, msg=msg)


class TamperDetectionTests(unittest.TestCase):
    def setUp(self):
        self.raw = WORDLIST_PATH.read_bytes()
        self.words = [w for w in self.raw.decode("ascii").split("\n") if w]

    def test_detects_word_count_mismatch(self):
        bad = "\n".join(self.words[:-1]).encode("ascii") + b"\n"
        r = check_wordlist_bytes(bad)
        self.assertFalse(r.ok)
        self.assertTrue(any("2048" in p for p in r.problems))

    def test_detects_duplicate(self):
        words = list(self.words)
        words[5] = words[4]
        bad = ("\n".join(words) + "\n").encode("ascii")
        r = check_wordlist_bytes(bad)
        self.assertFalse(r.ok)
        self.assertTrue(any("duplicad" in p for p in r.problems))

    def test_detects_unsorted(self):
        words = list(self.words)
        words[0], words[-1] = words[-1], words[0]
        bad = ("\n".join(words) + "\n").encode("ascii")
        r = check_wordlist_bytes(bad)
        self.assertFalse(r.ok)
        self.assertTrue(any("ordem alfabetica" in p for p in r.problems))

    def test_detects_non_ascii(self):
        raw_text = self.raw.decode("ascii")
        bad = raw_text.replace("abandon\n", "abandón\n", 1).encode("utf-8")
        r = check_wordlist_bytes(bad)
        self.assertFalse(r.ok)

    def test_detects_uppercase(self):
        words = list(self.words)
        words[0] = words[0].upper()
        bad = ("\n".join(words) + "\n").encode("ascii")
        r = check_wordlist_bytes(bad)
        self.assertFalse(r.ok)
        self.assertTrue(any("minusculas" in p for p in r.problems))

    def test_hash_mismatch_reported_separately_from_structural_problems(self):
        # mesmo uma wordlist ESTRUTURALMENTE valida (2048, unica, ordenada)
        # mas diferente da oficial deve reprovar em check_matches_official_hash
        words = list(self.words)
        # troca 'zoo' por algo ainda 'valido' estruturalmente mas != oficial
        # (troca simples preservando ordenacao: adiciona um caractere)
        # Mais simples: so adultera 1 letra no MEIO do alfabeto sem quebrar
        # ordenacao entre vizinhas -- aqui simplificamos aceitando que pode
        # quebrar ordenacao; o importante e confirmar que o hash diverge.
        raw = self.raw.replace(b"zoo\n", b"zoq\n")
        r = check_wordlist_bytes(raw)
        ok, msg = check_matches_official_hash(r)
        self.assertFalse(ok)
        self.assertIn("NAO bate", msg)


if __name__ == "__main__":
    unittest.main()
