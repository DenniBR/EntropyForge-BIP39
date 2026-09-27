import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier import bip39_min
from verifier.bip39_compare import _import_entropyforge_bip39, load_official_vectors
from verifier.divergence import investigate, reproduce

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
VECTORS_PATH = REPO_ROOT / "tests" / "vectors" / "bip39_vectors.json"


class ReproduceTests(unittest.TestCase):
    def test_deterministic_function_reproduces(self):
        r = reproduce(lambda: 2 + 2)
        self.assertTrue(r.reproduced)
        self.assertEqual(r.stable_output, 4)

    def test_nondeterministic_function_does_not_reproduce(self):
        counter = {"n": 0}

        def flaky():
            counter["n"] += 1
            return counter["n"]

        r = reproduce(flaky, times=3)
        self.assertFalse(r.reproduced)
        self.assertEqual(r.outputs, (1, 2, 3))


class InvestigateGenericProtocolTests(unittest.TestCase):
    def test_no_divergence_when_outputs_agree(self):
        r = investigate(description="teste", label_a="A", fn_a=lambda: 42, label_b="B", fn_b=lambda: 42)
        self.assertEqual(r.verdict, "no_divergence")

    def test_a_is_wrong_when_b_matches_official(self):
        r = investigate(
            description="teste", label_a="A", fn_a=lambda: "errado",
            label_b="B", fn_b=lambda: "certo", official="certo",
        )
        self.assertEqual(r.verdict, "A_is_wrong")
        self.assertIn("A DIVERGE da referencia oficial", r.human_summary())

    def test_b_is_wrong_when_a_matches_official(self):
        r = investigate(
            description="teste", label_a="A", fn_a=lambda: "certo",
            label_b="B", fn_b=lambda: "errado", official="certo",
        )
        self.assertEqual(r.verdict, "B_is_wrong")

    def test_both_wrong_when_neither_matches_official(self):
        r = investigate(
            description="teste", label_a="A", fn_a=lambda: "x",
            label_b="B", fn_b=lambda: "y", official="certo",
        )
        self.assertEqual(r.verdict, "both_wrong")

    def test_inconclusive_when_no_official_reference(self):
        r = investigate(
            description="teste", label_a="A", fn_a=lambda: "x",
            label_b="B", fn_b=lambda: "y", has_official_reference=False,
        )
        self.assertEqual(r.verdict, "inconclusive_no_official_reference")
        self.assertIn("nao 'falha'", r.human_summary())

    def test_inconclusive_when_not_reproducible(self):
        counter = {"n": 0}

        def flaky():
            counter["n"] += 1
            return counter["n"]

        r = investigate(description="teste", label_a="A", fn_a=flaky, label_b="B", fn_b=lambda: 1, official=1)
        self.assertEqual(r.verdict, "inconclusive_not_reproducible")

    def test_never_declares_failure_just_because_outputs_differ_without_reference(self):
        # requisito explicito da Fase 15/19: divergencia sem referencia
        # oficial nunca vira "FAIL" -- so "inconclusivo".
        r = investigate(
            description="teste", label_a="A", fn_a=lambda: "x",
            label_b="B", fn_b=lambda: "y", has_official_reference=False,
        )
        self.assertNotIn("fail", r.verdict.lower())
        self.assertNotIn("erro", r.verdict.lower())


class RealBip39DivergenceInvestigationTests(unittest.TestCase):
    """Aplica o protocolo completo a uma divergencia REAL entre
    `entropyforge.bip39` (adulterado de proposito, como as demais copias
    de laboratorio deste projeto) e `verifier.bip39_min`, contra um vetor
    oficial de teste -- demonstra o fluxo fim-a-fim, nao so a logica
    generica de `investigate()`."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        shutil.copytree(REPO_ROOT / "entropyforge", self.tmp / "entropyforge")
        self.wordlist = [
            w for w in (self.tmp / "entropyforge" / "data" / "english.txt").read_text().splitlines() if w
        ]
        vectors = load_official_vectors(VECTORS_PATH)
        self.entropy, self.expected_mnemonic = vectors[0]

    def _tamper_bip39(self, old: str, new: str) -> None:
        p = self.tmp / "entropyforge" / "bip39.py"
        src = p.read_text()
        self.assertIn(old, src)
        p.write_text(src.replace(old, new, 1))

    def test_protocol_correctly_blames_the_tampered_implementation(self):
        self._tamper_bip39(
            "first_byte = hashlib.sha256(entropy).digest()[0]",
            "first_byte = hashlib.sha256(entropy).digest()[-1]",
        )
        ef_bip39 = _import_entropyforge_bip39(self.tmp)

        report = investigate(
            description=f"entropy_to_mnemonic(entropy={self.entropy.hex()})",
            label_a="entropyforge.bip39 (adulterado nesta copia)",
            fn_a=lambda: ef_bip39.entropy_to_mnemonic(self.entropy),
            label_b="verifier.bip39_min (independente)",
            fn_b=lambda: bip39_min.entropy_to_mnemonic(self.entropy, self.wordlist),
            official=self.expected_mnemonic,
        )
        self.assertEqual(report.verdict, "entropyforge.bip39 (adulterado nesta copia)_is_wrong")
        self.assertIn("bug em entropyforge.bip39", report.human_summary())

    def test_protocol_finds_no_divergence_against_clean_entropyforge(self):
        # controle: sem adulteracao nenhuma, ambas as implementacoes
        # concordam entre si E com o vetor oficial.
        ef_bip39 = _import_entropyforge_bip39(self.tmp)
        report = investigate(
            description=f"entropy_to_mnemonic(entropy={self.entropy.hex()})",
            label_a="entropyforge.bip39",
            fn_a=lambda: ef_bip39.entropy_to_mnemonic(self.entropy),
            label_b="verifier.bip39_min",
            fn_b=lambda: bip39_min.entropy_to_mnemonic(self.entropy, self.wordlist),
            official=self.expected_mnemonic,
        )
        self.assertEqual(report.verdict, "no_divergence")


if __name__ == "__main__":
    unittest.main()
