#!/usr/bin/env python3
"""Roda cada backdoor de laboratorio (Fase 6/7) contra `selftest` e contra
uma invocacao "operacional" (`vector`, que usa dados PUBLICOS de teste,
nunca uma seed real) do EntropyForge adulterado, e relata:

  - `selftest` continuou reportando sucesso?
  - o marcador de laboratorio apareceu em stderr (evidencia de que o
    backdoor executou)?
  - para o backdoor 02/03/04 (arquivo/socket/subprocess): o guard do
    proprio EntropyForge bloqueou a tentativa (GuardViolation)?
  - para o backdoor 06: o payload pre-guard escreveu o arquivo em /tmp?
  - para os backdoors 07/08/09 (condicionais): o comportamento difere
    entre a invocacao "selftest" e a invocacao "operacional"?

Nao usa NENHUM dado real. `--a-digits`/`--b-hex` do `vector` sao valores
de teste publicos e triviais.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB_ROOT / "labs" / "backdoors"))
from backdoor_lab import BACKDOORS, LAB_MARKER, materialize_backdoor  # noqa: E402

LAB_TMP_MARKERS = [
    "/tmp/.ef_lab_backdoor_02.bin",
    "/tmp/.ef_lab_04",
    "/tmp/.ef_lab_backdoor_06_ran_pre_guard.txt",
]


def _clean_lab_tmp_files() -> None:
    for p in LAB_TMP_MARKERS:
        try:
            os.remove(p)
        except FileNotFoundError:
            pass


def _run(args: list[str], cwd: Path, timeout: int = 20) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(cwd)
    return subprocess.run(
        [sys.executable, "-B", "-m", "entropyforge", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_one(backdoor_id: str) -> dict:
    backdoor = next(b for b in BACKDOORS if b.id == backdoor_id)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        entropyforge_copy = materialize_backdoor(backdoor_id, tmp)
        repo_copy_root = entropyforge_copy.parent

        _clean_lab_tmp_files()
        selftest_proc = _run(["selftest"], repo_copy_root)
        selftest_out = selftest_proc.stdout + selftest_proc.stderr
        selftest_passed = "RESULTADO GERAL: PASSOU" in selftest_out
        marker_in_selftest = LAB_MARKER in selftest_out
        selftest_files_after = [p for p in LAB_TMP_MARKERS if os.path.exists(p)]
        _clean_lab_tmp_files()

        vector_proc = _run(
            ["vector", "--a-digits", "123456" * 22, "--b-hex", "11" * 32],
            repo_copy_root,
        )
        vector_out = vector_proc.stdout + vector_proc.stderr
        marker_in_vector = LAB_MARKER in vector_out
        vector_files_after = [p for p in LAB_TMP_MARKERS if os.path.exists(p)]
        _clean_lab_tmp_files()

        return {
            "id": backdoor.id,
            "title": backdoor.title,
            "description": backdoor.description,
            "selftest_returncode": selftest_proc.returncode,
            "selftest_reports_passou": selftest_passed,
            "marker_seen_in_selftest": marker_in_selftest,
            "marker_seen_in_vector_but_not_selftest": marker_in_vector and not marker_in_selftest,
            "marker_seen_in_vector": marker_in_vector,
            "files_created_by_selftest": selftest_files_after,
            "files_created_by_vector": vector_files_after,
            "selftest_stderr_tail": "\n".join(selftest_out.strip().splitlines()[-3:]),
            "vector_stderr_tail": "\n".join(vector_out.strip().splitlines()[-3:]),
        }


def main() -> int:
    results = []
    for b in BACKDOORS:
        print(f"=== BACKDOOR {b.id}: {b.title} ===")
        r = run_one(b.id)
        results.append(r)
        print(f"  descricao: {r['description']}")
        print(f"  selftest ainda reporta PASSOU? {r['selftest_reports_passou']}")
        print(f"  marcador do backdoor visto DURANTE selftest? {r['marker_seen_in_selftest']}")
        print(f"  marcador visto em 'vector' mas NAO em selftest (condicional)? {r['marker_seen_in_vector_but_not_selftest']}")
        if r["files_created_by_selftest"]:
            print(f"  *** ARQUIVOS CRIADOS EM /tmp durante selftest: {r['files_created_by_selftest']} ***")
        if r["files_created_by_vector"]:
            print(f"  *** ARQUIVOS CRIADOS EM /tmp durante vector: {r['files_created_by_vector']} ***")
        print(f"  selftest stderr (ultimas linhas): {r['selftest_stderr_tail']!r}")
        print()

    print("=== RESUMO ===")
    print(f"{'ID':4s} {'selftest PASSOU?':18s} {'marcador em selftest':22s} {'condicional detectado':22s} {'arquivo criado?':16s}")
    for r in results:
        print(
            f"{r['id']:4s} {str(r['selftest_reports_passou']):18s} "
            f"{str(r['marker_seen_in_selftest']):22s} "
            f"{str(r['marker_seen_in_vector_but_not_selftest']):22s} "
            f"{str(bool(r['files_created_by_selftest'] or r['files_created_by_vector'])):16s}"
        )

    n_selftest_still_passes_despite_backdoor = sum(
        1 for r in results if r["selftest_reports_passou"]
    )
    print(
        f"\n{n_selftest_still_passes_despite_backdoor}/{len(results)} backdoors deixam "
        "`selftest` continuar reportando RESULTADO GERAL: PASSOU."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
