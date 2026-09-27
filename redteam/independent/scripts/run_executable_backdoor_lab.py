#!/usr/bin/env python3
"""Laboratorio de backdoor contra o PIPELINE DE BUILD DO EXECUTAVEL
(Fase F #6 -- ver docs/EXECUTABLE_RELEASE_CHECKS.md secao 4).

Diferenca em relacao a `redteam/independent/scripts/run_backdoor_lab.py`
(Fase 6/7, ja existente): aquele laboratorio ataca o SOURCE interpretado
(`python -m entropyforge`). Este ataca o proprio PIPELINE DE BUILD DO
EXECUTAVEL standalone (Fase F): parte de uma copia de `entropyforge/`
com um backdoor ou uma alteracao inocente, CONSTROI um executavel real a
partir dela (via `tools/build_executable.build(source_root=...)`), e
verifica se a cadeia MANIFESTO -> HASH -> `verify_executable.py`
detecta a divergencia -- inclusive no cenario mais realista de ataque:
um atacante que controla o source E o manifesto ao mesmo tempo (nesse
caso, a auto-verificacao "bate" -- so um AUDITOR com sua PROPRIA copia
independente de `entropyforge/` pega a divergencia, exatamente como
`verify_release.py`/`verify_executable.py` ja documentam).

Cenarios:

  A. LIMPO: executavel construido a partir do `entropyforge/` real do
     repositorio -- linha de base.
  B. ALTERACAO COSMETICA: um docstring extra em `dice.py` (nao muda
     nenhum comportamento, so um literal de string). Serve para testar
     se a comparacao de hash do executavel enxerga MESMO uma mudanca sem
     efeito funcional (ao contrario do `.pyz`, que sempre enxerga
     qualquer byte diferente por definicao).
  C. BACKDOOR (backdoor 01 do laboratorio existente, reaproveitado):
     `combine.py` passa a escrever a entropia combinada em stderr.
     Resultado correto preservado (passa nos vetores oficiais/selftest -
     "passa nos KATs"), mas vaza o segredo.

Para cada cenario, o script:
  1. constroi o executavel (tools/build_executable.build);
  2. roda `selftest` e `vector` (com dados PUBLICOS de teste, nunca uma
     seed real) no binario construido e procura pelo marcador do
     laboratorio em stdout/stderr;
  3. calcula o hash do manifesto do diretorio do executavel
     (`verifier.release_manifest.executable_manifest_hash`) e compara
     com o cenario A;
  4. simula DOIS auditores possiveis:
       - um "auto-verificador" desonesto: gera o manifesto a partir da
         MESMA copia de source usada para construir (igual a um
         atacante que publica os dois juntos) -- `verify_release`
         PASSA (por definicao: nada aqui e independente).
       - um auditor de verdade: tem sua PROPRIA copia (o `entropyforge/`
         real e revisado do repositorio) e roda
         `independent-verifier/verify_executable.py --entropyforge-root
         <copia dele> --executable-dist <dist do cenario> --manifest
         <manifesto do cenario>` -- isto DEVE falhar no item
         "reconstrucao_a_partir_do_source" para os cenarios B e C.

Nao usa NENHUM dado real -- `vector` usa valores de teste publicos e
triviais, os mesmos ja usados em toda a suite de testes deste projeto.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "independent-verifier"))
sys.path.insert(0, str(REPO_ROOT / "redteam" / "independent" / "labs" / "backdoors"))

import build_executable  # noqa: E402
from backdoor_lab import LAB_MARKER, materialize_backdoor, materialize_clean  # noqa: E402
from verifier.release_manifest import (  # noqa: E402
    compute_release_manifest,
    executable_manifest_hash,
)
import verify_executable as verify_executable_cli  # noqa: E402

ENTROPYFORGE_ROOT = REPO_ROOT / "entropyforge"
VERIFIER_ROOT = REPO_ROOT / "independent-verifier" / "verifier"
BUILD_SCRIPT = REPO_ROOT / "tools" / "build_pyz.py"

# valores de teste PUBLICOS -- ja usados em tests/vectors/bip39_vectors.json
# e em toda a suite deste projeto; nunca uma seed real.
TEST_A_DIGITS = "1" * 300
TEST_B_HEX = "00" * 32


def _materialize_cosmetic_tamper(dest_root: Path) -> Path:
    """Copia entropyforge/ e adiciona um docstring extra em dice.py --
    NENHUM efeito funcional, so um literal de string novo (ao contrario
    de um comentario, que o compilador Python descarta antes mesmo de
    gerar bytecode)."""
    dest = materialize_clean(dest_root)
    target = dest / "dice.py"
    text = target.read_text(encoding="utf-8")
    text += '\n\n_LAB_COSMETIC_TAMPER_MARKER = "isto e uma string nova, sem nenhum efeito funcional"\n'
    target.write_text(text, encoding="utf-8")
    return dest


def _build_dist(label: str, source_entropyforge: Path, out_base: Path) -> Path:
    """`source_entropyforge` e' o diretorio `entropyforge/` (o pacote em
    si). `build_executable.build` espera `source_root` = o diretorio QUE
    CONTEM `entropyforge/` (ou seja, o pai)."""
    out_dir = out_base / f"dist_{label}"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n--- construindo cenario {label} ---")
    dist = build_executable.build(out_dir, source_root=source_entropyforge.parent)
    print(f"{label}: dist={dist}")
    return dist


def _run_bin(main_bin: Path, args: list[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run([str(main_bin), *args], capture_output=True, text=True, timeout=timeout)


def main() -> int:
    report_lines: list[str] = []

    def log(line: str = "") -> None:
        print(line)
        report_lines.append(line)

    with tempfile.TemporaryDirectory(prefix="ef_exe_backdoor_lab_") as tmp_s:
        tmp = Path(tmp_s)

        # --- cenario A: limpo -------------------------------------------------
        clean_src_root = tmp / "clean"
        clean_ef = materialize_clean(clean_src_root)
        dist_a = _build_dist("A_clean", clean_ef, tmp)
        hash_a = executable_manifest_hash(dist_a)

        # --- cenario B: alteracao cosmetica -------------------------------------
        cosmetic_src_root = tmp / "cosmetic"
        cosmetic_ef = _materialize_cosmetic_tamper(cosmetic_src_root)
        dist_b = _build_dist("B_cosmetic_tamper", cosmetic_ef, tmp)
        hash_b = executable_manifest_hash(dist_b)

        # --- cenario C: backdoor (stderr exfil, backdoor 01) --------------------
        backdoor_src_root = tmp / "backdoor"
        backdoor_ef = materialize_backdoor("01", backdoor_src_root)
        dist_c = _build_dist("C_backdoor_01_stderr", backdoor_ef, tmp)
        hash_c = executable_manifest_hash(dist_c)

        log("\n" + "=" * 78)
        log("RESULTADO 1: comparacao de hash do diretorio do executavel")
        log("=" * 78)
        log(f"hash(A limpo)              = {hash_a}")
        log(f"hash(B alteracao cosmetica) = {hash_b}  (== A? {hash_b == hash_a})")
        log(f"hash(C backdoor)            = {hash_c}  (== A? {hash_c == hash_a})")

        # --- cenario A: comportamento operacional --------------------------------
        log("\n" + "=" * 78)
        log("RESULTADO 2: comportamento operacional de cada executavel")
        log("=" * 78)
        for label, dist in (("A (limpo)", dist_a), ("B (cosmetico)", dist_b), ("C (backdoor)", dist_c)):
            main_bin = dist / "entropyforge-bip39"
            selftest_proc = _run_bin(main_bin, ["selftest"])
            selftest_ok = "RESULTADO GERAL: PASSOU" in selftest_proc.stdout
            selftest_leak = LAB_MARKER in selftest_proc.stdout or LAB_MARKER in selftest_proc.stderr

            vector_proc = _run_bin(main_bin, ["vector", "--a-digits", TEST_A_DIGITS, "--b-hex", TEST_B_HEX])
            vector_ok = vector_proc.returncode == 0
            vector_leak = LAB_MARKER in vector_proc.stdout or LAB_MARKER in vector_proc.stderr

            log(f"\n{label}:")
            log(f"  selftest -> PASSOU? {selftest_ok}  marcador de vazamento visto? {selftest_leak}")
            log(f"  vector   -> rc=0?   {vector_ok}  marcador de vazamento visto? {vector_leak}")
            if vector_leak:
                leaked_text = vector_proc.stdout if LAB_MARKER in vector_proc.stdout else vector_proc.stderr
                marker_line = next(ln for ln in leaked_text.splitlines() if LAB_MARKER in ln)
                log(f"  linha vazada (dado de TESTE, nunca real): {marker_line!r}")

        # --- cenario "auto-verificacao desonesta" ---------------------------------
        log("\n" + "=" * 78)
        log("RESULTADO 3: auto-verificacao (manifesto gerado a partir da MESMA")
        log("copia de source usada para construir) -- deve PASSAR mesmo para o")
        log("backdoor, porque nada aqui e independente (documentado desde a Fase E)")
        log("=" * 78)
        for label, ef_root, dist in (
            ("A (limpo)", clean_ef, dist_a),
            ("B (cosmetico)", cosmetic_ef, dist_b),
            ("C (backdoor)", backdoor_ef, dist_c),
        ):
            self_manifest = compute_release_manifest(
                entropyforge_root=ef_root,
                pyz_path=REPO_ROOT / "entropyforge.pyz",
                verifier_root=VERIFIER_ROOT,
                build_script_path=BUILD_SCRIPT,
                executable_dist_dir=dist,
            )
            self_hash_ok = self_manifest.executable_sha256 == executable_manifest_hash(dist)
            log(f"{label}: manifesto autoconsistente com o proprio dist? {self_hash_ok}")

        # --- cenario "auditor de verdade" -----------------------------------------
        log("\n" + "=" * 78)
        log("RESULTADO 4: AUDITOR DE VERDADE -- reconstroi a partir da SUA PROPRIA")
        log("copia (entropyforge/ real e revisado do repositorio), NAO da copia do")
        log("atacante. Isto e' o que independent-verifier/verify_executable.py faz.")
        log("=" * 78)
        for label, ef_root, dist in (
            ("A (limpo)", clean_ef, dist_a),
            ("B (cosmetico)", cosmetic_ef, dist_b),
            ("C (backdoor)", backdoor_ef, dist_c),
        ):
            attacker_manifest = compute_release_manifest(
                entropyforge_root=ef_root,
                pyz_path=REPO_ROOT / "entropyforge.pyz",
                verifier_root=VERIFIER_ROOT,
                build_script_path=BUILD_SCRIPT,
                executable_dist_dir=dist,
            )
            checks = verify_executable_cli.verify_executable(
                attacker_manifest,
                entropyforge_root=ENTROPYFORGE_ROOT,  # a copia REAL do repositorio, nunca a do cenario
                executable_dist_dir=dist,
                skip_rebuild=False,
            )
            rebuild_check = next(c for c in checks if c.name == "executavel.reconstrucao_a_partir_do_source")
            log(f"\n{label}: verify_executable.py (com --entropyforge-root = copia REAL do auditor)")
            for c in checks:
                log(f"  {c}")
            expected_pass = label == "A (limpo)"
            outcome_matches = rebuild_check.ok == expected_pass
            log(f"  >>> deteccao correta (esperado PASS apenas para A)? {outcome_matches}")

        report_path = REPO_ROOT / "redteam" / "independent" / "findings" / "executable_backdoor_lab_output.txt"
        report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
        print(f"\nrelatorio completo escrito em: {report_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
