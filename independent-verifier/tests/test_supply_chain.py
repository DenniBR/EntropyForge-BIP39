"""Fase 13: testes de regressao para a matriz de cadeia de suprimentos
(cenarios A-F). Ver `redteam/independent/scripts/run_supply_chain_matrix.py`
para a versao "relatorio legivel" destes mesmos cenarios, e
`redteam/independent/labs/supply_chain/supply_chain_lab.py` para a
descricao completa de cada um.

Estes testes fixam, como REGRESSAO, a propriedade central da Fase 13: cada
cenario adversarial e detectado por PELO MENOS UM controle do verificador,
e o teste registra explicitamente QUAL controle (nao so "detectou/nao
detectou")."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
INDEPENDENT_VERIFIER = REPO_ROOT / "independent-verifier"
LABS_DIR = REPO_ROOT / "redteam" / "independent" / "labs" / "supply_chain"

sys.path.insert(0, str(INDEPENDENT_VERIFIER))
sys.path.insert(0, str(LABS_DIR))

import supply_chain_lab as lab  # type: ignore
from verifier.bip39_compare import compare_against_official_vectors
from verifier.hashing import build_manifest, diff_manifests
from verifier.pyz_inspect import compare_pyz_to_source
from verifier.static_scan import diff_findings, scan_directory
from verifier.wordlist_check import check_matches_official_hash, check_wordlist_file

VECTORS_PATH = REPO_ROOT / "tests" / "vectors" / "bip39_vectors.json"


def _build_pyz(out_path: Path, *, build_script: Path | None = None, cwd_root: Path | None = None) -> None:
    import subprocess

    script = build_script or (REPO_ROOT / "tools" / "build_pyz.py")
    subprocess.run([sys.executable, str(script), str(out_path)], check=True, capture_output=True, text=True)


class ScenarioATests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_manifest_diff_catches_one_line_change_outside_critical_path(self):
        tampered = lab.materialize_scenario_a_one_line_source_change(self.tmp)
        baseline = build_manifest(REPO_ROOT / "entropyforge")
        current = build_manifest(tampered)
        diff = diff_manifests(baseline, current)
        self.assertFalse(diff.is_identical)
        self.assertIn("dice.py", diff.changed)

    def test_bip39_compare_does_not_notice_dice_py_change(self):
        # documenta o limite: bip39_compare so olha o caminho BIP-39, nao
        # dice.py -- por isso este cenario so e pego pelo diff de
        # manifesto, nunca por esta comparacao.
        tampered = lab.materialize_scenario_a_one_line_source_change(self.tmp)
        result = compare_against_official_vectors(tampered, VECTORS_PATH)
        self.assertTrue(result.ok)


class ScenarioBTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_official_hash_check_catches_tampered_wordlist(self):
        tampered = lab.materialize_scenario_b_tampered_wordlist(self.tmp)
        report = check_wordlist_file(tampered / "data" / "english.txt")
        matches, _msg = check_matches_official_hash(report)
        self.assertFalse(matches)

    def test_manifest_diff_also_catches_it(self):
        tampered = lab.materialize_scenario_b_tampered_wordlist(self.tmp)
        baseline = build_manifest(REPO_ROOT / "entropyforge")
        current = build_manifest(tampered)
        diff = diff_manifests(baseline, current)
        self.assertFalse(diff.is_identical)


class ScenarioCTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_pyz_tampered_after_build_is_detected_against_source(self):
        pyz_path = self.tmp / "clean_then_tampered.pyz"
        _build_pyz(pyz_path)
        lab.materialize_scenario_c_tampered_pyz(pyz_path)

        result = compare_pyz_to_source(pyz_path, REPO_ROOT / "entropyforge")
        self.assertFalse(result.ok)
        self.assertIn("entropyforge/_mirror_payload.py", result.unexpected_in_pyz)


class ScenarioDTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_tampered_build_script_is_detected_via_pyz_vs_source_not_via_determinism(self):
        clean_entropyforge = self.tmp / "entropyforge"
        shutil.copytree(REPO_ROOT / "entropyforge", clean_entropyforge)

        tampered_script = lab.materialize_scenario_d_tampered_build_script(self.tmp)
        pyz_path = self.tmp / "built_with_tampered_script.pyz"
        _build_pyz(pyz_path, build_script=tampered_script)

        result = compare_pyz_to_source(pyz_path, clean_entropyforge)
        self.assertFalse(result.ok)
        self.assertIn("entropyforge/_build_backdoor.py", result.unexpected_in_pyz)

        # controle negativo: rodar o MESMO script adulterado duas vezes
        # produz o MESMO hash -- ilustra que "determinismo" nao teria
        # pegado isso (o backdoor e perfeitamente reprodutivel).
        from verifier.hashing import hash_file

        pyz_path_2 = self.tmp / "built_with_tampered_script_2.pyz"
        _build_pyz(pyz_path_2, build_script=tampered_script)
        self.assertEqual(hash_file(pyz_path), hash_file(pyz_path_2))


class ScenarioETests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_impostor_package_detected_against_trusted_reference_manifest(self):
        impostor = lab.materialize_scenario_e_impostor_package(self.tmp)
        baseline = build_manifest(REPO_ROOT / "entropyforge")
        current = build_manifest(impostor)
        diff = diff_manifests(baseline, current)
        self.assertFalse(diff.is_identical)

    def test_impostor_package_combine_change_is_invisible_to_bip39_compare(self):
        # documenta um limite real (nao um bug): bip39_compare exercita
        # SOMENTE entropy_to_mnemonic/mnemonic_to_entropy em
        # entropyforge.bip39 -- ele nunca chama combine.py, entao uma
        # alteracao isolada na ordem de concatenacao A/B em combine.py
        # (o que este cenario faz) e INVISIVEL para esta comparacao,
        # mesmo estando, em sentido amplo, no "caminho critico" de
        # geracao da carteira. Quem pega esta alteracao especifica e o
        # diff de manifesto (ver outro teste desta classe), nao esta
        # comparacao.
        impostor = lab.materialize_scenario_e_impostor_package(self.tmp)
        result = compare_against_official_vectors(impostor, VECTORS_PATH)
        self.assertTrue(result.ok)


class ScenarioFTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_backdoor_in_report_py_not_caught_by_bip39_compare(self):
        # documenta o limite: bip39_compare nao olha report.py.
        tampered = lab.materialize_scenario_f_backdoor_in_irrelevant_module(self.tmp)
        result = compare_against_official_vectors(tampered, VECTORS_PATH)
        self.assertTrue(result.ok)

    def test_static_scan_and_manifest_diff_catch_it_anyway(self):
        tampered = lab.materialize_scenario_f_backdoor_in_irrelevant_module(self.tmp)

        baseline_manifest = build_manifest(REPO_ROOT / "entropyforge")
        current_manifest = build_manifest(tampered)
        self.assertFalse(diff_manifests(baseline_manifest, current_manifest).is_identical)

        baseline_findings = scan_directory(REPO_ROOT / "entropyforge")
        current_findings = scan_directory(tampered)
        new_findings = diff_findings(baseline_findings, current_findings)
        self.assertGreater(len(new_findings), 0)
        self.assertTrue(any(f.category == "rede" for f in new_findings))


if __name__ == "__main__":
    unittest.main()
