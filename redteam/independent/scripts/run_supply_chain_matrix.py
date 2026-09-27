#!/usr/bin/env python3
"""Fase 13: matriz de ataques de cadeia de suprimentos (A-F).

Para cada cenario (ver `redteam/independent/labs/supply_chain/supply_chain_lab.py`
para a descricao completa de cada um), materializa o artefato adversarial
correspondente e roda o subconjunto de checagens do independent-verifier
que faz sentido aplicar, registrando se cada uma detecta (ou nao) a
alteracao.

O objetivo nao e "quantos detectores disparam" -- e mapear, caso a caso,
QUAL controle pega O QUE, e qual RAIZ DE CONFIANCA cada deteccao
pressupoe. Em particular: `compare_pyz_to_source` e `diff_manifests`
so detectam algo se houver uma REFERENCIA (source-tree ou manifesto)
obtida por um canal independente do artefato sob teste -- comparar um
artefato adulterado contra UMA COPIA DELE MESMO nunca prova nada, e este
script deixa isso explicito em cada linha da matriz.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
INDEPENDENT_VERIFIER = REPO_ROOT / "independent-verifier"
LABS_DIR = Path(__file__).resolve().parent.parent / "labs" / "supply_chain"

sys.path.insert(0, str(INDEPENDENT_VERIFIER))
sys.path.insert(0, str(LABS_DIR))

import supply_chain_lab as lab  # type: ignore
from verifier.bip39_compare import compare_against_official_vectors
from verifier.hashing import build_manifest, diff_manifests
from verifier.pyz_inspect import compare_pyz_to_source
from verifier.static_scan import diff_findings, scan_directory
from verifier.wordlist_check import check_matches_official_hash, check_wordlist_file

VECTORS_PATH = REPO_ROOT / "tests" / "vectors" / "bip39_vectors.json"


def _build_pyz(source_root: Path, out_path: Path, *, build_script: Path | None = None) -> None:
    """Constroi um .pyz a partir de `source_root/entropyforge`. Se
    `build_script` for dado, usa ESSE script (possivelmente adulterado -
    Cenario D) em vez do `tools/build_pyz.py` real, rodando-o como
    subprocesso (para que o `REPO_ROOT` calculado dentro dele aponte para
    `source_root`, nao para o repositorio real)."""
    import subprocess

    script = build_script or (REPO_ROOT / "tools" / "build_pyz.py")
    if build_script is not None:
        dest_tools = source_root / "tools"
        dest_tools.mkdir(parents=True, exist_ok=True)
        if not (dest_tools / "build_pyz.py").exists():
            shutil.copy(build_script, dest_tools / "build_pyz.py")
        script = dest_tools / "build_pyz.py"
    subprocess.run([sys.executable, str(script), str(out_path)], check=True, capture_output=True, text=True)


def scenario_a() -> dict:
    tmp = Path(tempfile.mkdtemp())
    try:
        tampered_root = lab.materialize_scenario_a_one_line_source_change(tmp)
        baseline_manifest = build_manifest(REPO_ROOT / "entropyforge")
        tampered_manifest = build_manifest(tampered_root)
        manifest_diff = diff_manifests(baseline_manifest, tampered_manifest)

        static_baseline = scan_directory(REPO_ROOT / "entropyforge")
        static_tampered = scan_directory(tampered_root)
        static_new = diff_findings(static_baseline, static_tampered)

        bip39_result = compare_against_official_vectors(tampered_root, VECTORS_PATH)

        detected = (not manifest_diff.is_identical) or len(static_new) > 0 or (not bip39_result.ok)
        return {
            "id": "A",
            "title": "Uma linha alterada no source (dice.py, fora do caminho critico)",
            "detected": detected,
            "hashing_manifest_diff": not manifest_diff.is_identical,
            "static_scan_new_findings": len(static_new) > 0,
            "bip39_compare_mismatch": not bip39_result.ok,
            "note": (
                "Detectado pelo diff de manifesto (QUALQUER alteracao de "
                "conteudo aparece), mas NAO pela comparacao BIP-39 (dice.py "
                "nao participa dessa logica) nem, tipicamente, pelo scanner "
                "estatico (afrouxar uma checagem de intervalo nao usa "
                "nenhum termo da lista de suspeitos)."
            ),
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def scenario_b() -> dict:
    tmp = Path(tempfile.mkdtemp())
    try:
        tampered_root = lab.materialize_scenario_b_tampered_wordlist(tmp)
        baseline_manifest = build_manifest(REPO_ROOT / "entropyforge")
        tampered_manifest = build_manifest(tampered_root)
        manifest_diff = diff_manifests(baseline_manifest, tampered_manifest)

        report = check_wordlist_file(tampered_root / "data" / "english.txt")
        matches_official, hash_msg = check_matches_official_hash(report)

        detected = (not manifest_diff.is_identical) or (not report.ok) or (not matches_official)
        return {
            "id": "B",
            "title": "Wordlist adulterada (uma palavra trocada)",
            "detected": detected,
            "hashing_manifest_diff": not manifest_diff.is_identical,
            "wordlist_check_ok": report.ok,
            "wordlist_matches_known_official_hash": matches_official,
            "wordlist_hash_check_message": hash_msg,
            "note": (
                "wordlist_check.KNOWN_OFFICIAL_SHA256 e um valor "
                "EMBUTIDO NO PROPRIO VERIFICADOR (nao lido de nenhum "
                "arquivo do EntropyForge), entao ele pega isso mesmo que "
                "um atacante tenha adulterado TANTO o source quanto o "
                "manifesto de referencia usado por hashing.py."
            ),
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def scenario_c() -> dict:
    tmp = Path(tempfile.mkdtemp())
    try:
        pyz_path = tmp / "clean_then_tampered.pyz"
        _build_pyz(REPO_ROOT, pyz_path)
        # nesse ponto, pyz_path e IDENTICO ao que um build legitimo geraria
        lab.materialize_scenario_c_tampered_pyz(pyz_path)

        result = compare_pyz_to_source(pyz_path, REPO_ROOT / "entropyforge")

        return {
            "id": "C",
            "title": ".pyz adulterado APOS o build (artefato de distribuicao comprometido)",
            "detected": not result.ok,
            "pyz_compare_to_source_ok": result.ok,
            "unexpected_in_pyz": result.unexpected_in_pyz,
            "note": (
                "compare_pyz_to_source detecta isso pois compara o .pyz "
                "CONTRA A ARVORE-FONTE, nao contra si mesmo -- pega o "
                "modulo extra independentemente de como/quando ele foi "
                "inserido no artefato."
            ),
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def scenario_d() -> dict:
    tmp = Path(tempfile.mkdtemp())
    try:
        clean_entropyforge = tmp / "entropyforge"
        shutil.copytree(REPO_ROOT / "entropyforge", clean_entropyforge)

        tampered_script = lab.materialize_scenario_d_tampered_build_script(tmp)
        pyz_path = tmp / "built_with_tampered_script.pyz"
        _build_pyz(tmp, pyz_path, build_script=tampered_script)

        result = compare_pyz_to_source(pyz_path, clean_entropyforge)

        return {
            "id": "D",
            "title": "Script de build adulterado (source e wordlist permanecem limpos)",
            "detected": not result.ok,
            "pyz_compare_to_source_ok": result.ok,
            "unexpected_in_pyz": result.unexpected_in_pyz,
            "note": (
                "check_build_determinism (Fase 5) NAO pegaria isso -- o "
                "build adulterado e perfeitamente deterministico (insere "
                "o mesmo arquivo toda vez). Quem pega e compare_pyz_to_source, "
                "que nao se importa em COMO o .pyz foi gerado, so no que "
                "esta dentro dele comparado ao source de confianca."
            ),
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def scenario_e() -> dict:
    tmp = Path(tempfile.mkdtemp())
    try:
        impostor_root = lab.materialize_scenario_e_impostor_package(tmp)
        baseline_manifest = build_manifest(REPO_ROOT / "entropyforge")
        impostor_manifest = build_manifest(impostor_root)
        manifest_diff = diff_manifests(baseline_manifest, impostor_manifest)

        bip39_result = compare_against_official_vectors(impostor_root, VECTORS_PATH)

        detected = (not manifest_diff.is_identical) or (not bip39_result.ok)
        return {
            "id": "E",
            "title": "Pacote impostor (copia com mesmo nome, combine.py com ordem A/B trocada)",
            "detected": detected,
            "hashing_manifest_diff_vs_trusted_reference": not manifest_diff.is_identical,
            "bip39_compare_mismatch": not bip39_result.ok,
            "note": (
                "EntropyForge nao tem NENHUMA dependencia de terceiros "
                "(so biblioteca padrao) -- isso elimina o typosquatting "
                "classico de pacotes PyPI como vetor de ataque a ele "
                "MESMO. O risco residual e um usuario obter uma copia "
                "impostora do PROPRIO entropyforge por um canal nao "
                "confiavel; a unica defesa e ter um manifesto/hash de "
                "REFERENCIA obtido por um canal INDEPENDENTE do artefato "
                "(nunca 'baixe o programa e o hash do mesmo lugar'). "
                "bip39_compare_mismatch e False aqui, de proposito: a "
                "alteracao esta em combine.py (ordem a+b trocada), e "
                "bip39_compare NUNCA exercita combine.py -- ele so testa "
                "entropy_to_mnemonic/mnemonic_to_entropy em "
                "entropyforge.bip39. Quem detecta este cenario e SOMENTE "
                "o diff de manifesto contra uma referencia de confianca; "
                "isso reforca, e nao contradiz, o ponto do Cenario F: um "
                "controle com escopo estreito (aqui, so o modulo bip39) "
                "nao pega alteracoes fora do seu escopo, mesmo quando "
                "elas estao em outro arquivo do caminho critico."
            ),
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def scenario_f() -> dict:
    tmp = Path(tempfile.mkdtemp())
    try:
        tampered_root = lab.materialize_scenario_f_backdoor_in_irrelevant_module(tmp)
        baseline_manifest = build_manifest(REPO_ROOT / "entropyforge")
        tampered_manifest = build_manifest(tampered_root)
        manifest_diff = diff_manifests(baseline_manifest, tampered_manifest)

        static_baseline = scan_directory(REPO_ROOT / "entropyforge")
        static_tampered = scan_directory(tampered_root)
        static_new = diff_findings(static_baseline, static_tampered)

        bip39_result = compare_against_official_vectors(tampered_root, VECTORS_PATH)

        detected = (not manifest_diff.is_identical) or len(static_new) > 0 or (not bip39_result.ok)
        return {
            "id": "F",
            "title": "Codigo malicioso em modulo 'irrelevante' (report.py, fora do caminho critico)",
            "detected": detected,
            "hashing_manifest_diff": not manifest_diff.is_identical,
            "static_scan_new_findings": len(static_new) > 0,
            "static_scan_new_categories": sorted({f.category for f in static_new}),
            "bip39_compare_mismatch": not bip39_result.ok,
            "note": (
                "bip39_compare NAO pega isso (report.py esta fora do "
                "escopo dessa comparacao) -- e exatamente o ponto do "
                "cenario: um controle focado so no 'caminho critico' "
                "deixa passar um backdoor em qualquer outro arquivo do "
                "MESMO pacote, que roda com os MESMOS privilegios. O que "
                "pega e (a) o diff de manifesto contra uma referencia de "
                "confianca cobrindo TODOS os arquivos, sem excecao, e "
                "(b) o scanner estatico, que encontra o import de socket "
                "independentemente de qual arquivo ele esta."
            ),
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    scenarios = [scenario_a, scenario_b, scenario_c, scenario_d, scenario_e, scenario_f]
    results = []
    for fn in scenarios:
        print(f"=== Rodando cenario {fn.__name__} ===")
        r = fn()
        results.append(r)
        for k, v in r.items():
            print(f"  {k}: {v}")
        print()

    print("=== MATRIZ RESUMO ===")
    print(f"{'ID':4} {'DETECTADO?':12} TITULO")
    for r in results:
        print(f"{r['id']:4} {str(r['detected']):12} {r['title']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
