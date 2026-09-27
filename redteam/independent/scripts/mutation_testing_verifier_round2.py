#!/usr/bin/env python3
"""Fase D (Fase 43): segunda rodada de mutation testing do independent-verifier.

A primeira rodada (`mutation_testing_verifier.py`, Fase 14) cobriu hashing,
wordlist_check, pyz_inspect, bip39_min, static_scan e build_repro com um
mutante cada. Esta rodada cobre alvos NAO tocados na primeira rodada,
seguindo pedidos explicitos da Fase D: ignorar um arquivo especifico do
diff, aceitar hash errado numa funcao ainda sem teste
(`verify_against_manifest`), ignorar a wordlist (forjar ok=True), ignorar
`content_mismatches` do .pyz (mutante DIFERENTE do que ignorou
`unexpected_in_pyz` na rodada 1), ignorar TODOS os findings do scanner
estatico, inverter o booleano de seguranca central de `bip39_compare`
(ComparisonResult.ok), e "forjar OK" no proprio `ManifestDiff.is_identical`
(usado por hashing.py, sandbox.py e pelos scripts de matriz de supply
chain como o unico ponto de decisao "bateu ou nao bateu").
"""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
VERIFIER_ROOT = REPO_ROOT / "independent-verifier"


@dataclass
class Mutation:
    name: str
    file: str
    old: str
    new: str
    rationale: str


MUTATIONS = [
    Mutation(
        name="manifestdiff_is_identical_always_true",
        file="verifier/hashing.py",
        old="        return not (self.added or self.removed or self.changed)",
        new="        return True  # MUTANTE: forja OK sempre",
        rationale="ManifestDiff.is_identical() forjado para sempre reportar 'identico' -- "
        "isto e o ponto de decisao central usado por hashing.py, sandbox.py e pela matriz "
        "de supply chain; forjar True aqui aceitaria QUALQUER adulteracao de arquivo.",
    ),
    Mutation(
        name="verify_against_manifest_ignores_current_state",
        file="verifier/hashing.py",
        old="    current = build_manifest(root)\n    return diff_manifests(manifest, current)",
        new="    current = build_manifest(root)\n    return diff_manifests(manifest, manifest)  # MUTANTE: compara o manifesto contra ele mesmo",
        rationale="verify_against_manifest() compara o manifesto de referencia contra SI "
        "MESMO em vez de contra o estado atual de `root` -- sempre reporta 'sem diferenca', "
        "aceitando qualquer estado real do diretorio. Esta funcao nao tinha NENHUM teste "
        "antes da Fase D (achado da propria auditoria).",
    ),
    Mutation(
        name="wordlist_check_forces_ok_true",
        file="verifier/wordlist_check.py",
        old="    return WordlistReport(ok=(len(problems) == 0), word_count=len(words), problems=tuple(problems), sha256=digest)",
        new="    return WordlistReport(ok=True, word_count=len(words), problems=tuple(problems), sha256=digest)  # MUTANTE",
        rationale="WordlistReport.ok forjado como True incondicionalmente -- uma wordlist "
        "com problemas estruturais (duplicatas, fora de ordem, etc.) ainda seria reportada "
        "como 'ok', mesmo com a lista de `problems` continuando a ser preenchida corretamente "
        "(um mutante sutil: os PROBLEMAS ainda aparecem na lista, so o campo `ok` mente).",
    ),
    Mutation(
        name="pyz_inspect_ignores_content_mismatches",
        file="verifier/pyz_inspect.py",
        old="        return not (self.content_mismatches or self.missing_from_pyz or self.unexpected_in_pyz)",
        new="        return not (self.missing_from_pyz or self.unexpected_in_pyz)  # MUTANTE: ignora content_mismatches",
        rationale="PyzSourceComparison.ok ignora ESPECIFICAMENTE content_mismatches (mutante "
        "diferente do da Fase 14, que ignorava unexpected_in_pyz) -- um arquivo com o MESMO "
        "nome do source mas conteudo alterado (ex.: combine.py adulterado dentro do .pyz) "
        "passaria como 'ok'.",
    ),
    Mutation(
        name="static_scan_diff_findings_always_empty",
        file="verifier/static_scan.py",
        old="    baseline_keys = {_finding_key(f) for f in baseline}\n    return [f for f in current if _finding_key(f) not in baseline_keys]",
        new="    return []  # MUTANTE: ignora todos os findings, sempre reporta diff vazio",
        rationale="diff_findings() sempre devolve lista vazia, independente do que mudou -- "
        "um backdoor obviamente novo (import socket, subprocess.Popen) inserido apos o "
        "baseline nunca apareceria como achado NOVO.",
    ),
    Mutation(
        name="bip39_compare_result_ok_ignores_mismatches",
        file="verifier/bip39_compare.py",
        old="        return self.entropyforge_import_error is None and len(self.mismatches) == 0",
        new="        return self.entropyforge_import_error is None  # MUTANTE: ignora len(mismatches)",
        rationale="ComparisonResult.ok ignora a lista de mismatches -- uma implementacao "
        "BIP-39 divergindo dos vetores oficiais em TODOS os casos ainda seria reportada como "
        "'ok', desde que o import de entropyforge.bip39 nao tenha lançado excecao.",
    ),
]


def run_tests() -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=str(VERIFIER_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )
    return proc.returncode == 0, proc.stdout + proc.stderr


def apply_and_test(mutation: Mutation) -> dict:
    path = VERIFIER_ROOT / mutation.file
    original = path.read_text(encoding="utf-8")
    if mutation.old not in original:
        return {"mutation": mutation.name, "status": "ERROR", "detail": "old string nao encontrada no arquivo"}
    mutated = original.replace(mutation.old, mutation.new, 1)
    if mutated == original:
        return {"mutation": mutation.name, "status": "ERROR", "detail": "mutacao nao alterou o arquivo"}
    try:
        path.write_text(mutated, encoding="utf-8")
        ok, output = run_tests()
        status = "SURVIVED (nenhum teste pegou o mutante)" if ok else "KILLED (algum teste pegou o mutante)"
        return {
            "mutation": mutation.name,
            "rationale": mutation.rationale,
            "status": status,
            "tests_passed_despite_mutation": ok,
            "tail_output": "\n".join(output.strip().splitlines()[-6:]),
        }
    finally:
        path.write_text(original, encoding="utf-8")
        assert path.read_text(encoding="utf-8") == original, f"FALHA AO RESTAURAR {path}!"


def main() -> int:
    results = []
    for m in MUTATIONS:
        print(f"--- aplicando mutante: {m.name} ---")
        r = apply_and_test(m)
        results.append(r)
        print(f"    {r['status']}")
        if "SURVIVED" in r.get("status", ""):
            print(f"    ** LACUNA DE COBERTURA NO VERIFICADOR: {r['rationale']} **")
        elif r["status"] == "ERROR":
            print(f"    ERRO: {r['detail']}")

    print("\n=== RESUMO (mutation testing do independent-verifier, rodada 2) ===")
    survived = [r for r in results if r.get("tests_passed_despite_mutation")]
    errors = [r for r in results if r.get("status") == "ERROR"]
    for r in results:
        print(f"{r['mutation']:48s} {r['status']}")
    print(f"\n{len(survived)} de {len(results)} mutantes SOBREVIVERAM (lacunas de cobertura reais).")
    for r in survived:
        print(f"  - {r['mutation']}: {r['rationale']}")
    if errors:
        print(f"\n{len(errors)} mutacoes com ERRO (ponto de insercao nao encontrado -- revisar script):")
        for r in errors:
            print(f"  - {r['mutation']}: {r['detail']}")
    return len(survived) + len(errors)


if __name__ == "__main__":
    sys.exit(main())
