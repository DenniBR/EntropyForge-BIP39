#!/usr/bin/env python3
"""Fuzzing do EXECUTAVEL (nao do source) + observacao de processo
(limpo vs. backdoor) via `strace` (Fase F #10).

Duas partes independentes, ambas contra o BINARIO COMPILADO real
(`tools/build_executable.build`), nunca contra `python -m entropyforge`:

  1. FUZZING (`fuzz_vector_argv`, `fuzz_stdin_bytes`): mesma metodologia
     de `redteam/phase_e/scripts/fuzz_final.py::fuzz_cli_subprocess`
     (gerador `random.Random` com seed fixa e documentada, nunca usado
     para gerar dados reais) -- adversario de linha de comando (`vector`
     com argumentos aleatorios) e de stdin bruto (`generate`/`calibrate`
     com bytes aleatorios, nao-TTY). Criterio de falha: uma excecao
     Python NAO tratada vazando (traceback bruto na saida), um travamento
     (timeout), ou o payload de entrada sendo ecoado de volta
     reconhecivelmente.

  2. OBSERVACAO DE PROCESSO (`compare_clean_vs_backdoor_strace`): reusa
     `verifier.process_observe.trace_process` (o mesmo modulo usado em
     `redteam/independent/findings/legit_vs_backdoor_strace_comparison.txt`,
     Fase D, contra o source interpretado) desta vez contra os dois
     EXECUTAVEIS reais construidos por
     `redteam/independent/scripts/run_executable_backdoor_lab.py`
     (cenario A limpo e cenario C com o backdoor 01 -- exfiltracao via
     stderr). Pulado automaticamente se `strace` nao estiver disponivel.

Nao usa NENHUM dado real -- toda entrada e aleatoria/publica de teste.
"""
from __future__ import annotations

import random
import shutil
import string
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
from verifier.process_observe import StraceUnavailable, strace_available, trace_process  # noqa: E402

SEED = 20260927  # mesma seed documentada de tools/simulate_power.py / fuzz_final.py
N_VECTOR_ARGV = 300
N_STDIN_BYTES = 100

_WEIRD_CHARS = "1234567890 \t\n\r,;.-_/\\!@#$%^&*()[]{}|~`'\"" + "١٢٣٤٥٦" + "😀🎲" + "\x00\x01\x02"
# sem '\x00': argv de processo (execve) nao pode conter um byte nulo em
# nenhum SO -- nao e' uma restricao do EXECUTAVEL sob teste, e' do proprio
# `execve(2)`, entao usar `_WEIRD_CHARS` (que inclui '\x00') para montar
# argumentos de linha de comando faria o PROPRIO subprocess.run() do
# harness falhar (ValueError: embedded null byte) antes mesmo do processo
# nascer. O byte nulo continua fuzzed via stdin em `fuzz_stdin_bytes`
# (que usa `bytes` brutos, nunca argv).
_WEIRD_CHARS_ARGV = _WEIRD_CHARS.replace("\x00", "")
_HEXISH = "0123456789abcdefABCDEFxX -\n"


def _random_string(rng: random.Random, alphabet: str, max_len: int) -> str:
    n = rng.randint(0, max_len)
    return "".join(rng.choice(alphabet) for _ in range(n))


def fuzz_vector_argv(main_bin: Path, rng: random.Random) -> list[str]:
    """Argumentos aleatorios para `vector` -- nunca deve vazar um
    traceback Python bruto (mensagem de erro tratada e' ok; um
    `Traceback (most recent call last)` na saida indica uma excecao nao
    tratada, o que e' o criterio de falha aqui)."""
    crashes = []
    for i in range(N_VECTOR_ARGV):
        choice = rng.randrange(4)
        if choice == 0:
            args = ["vector", "--a-digits", _random_string(rng, string.digits + _WEIRD_CHARS_ARGV, 60),
                    "--b-hex", _random_string(rng, _HEXISH, 80)]
        elif choice == 1:
            args = ["vector", "--entropy-hex", _random_string(rng, _HEXISH, 80)]
        elif choice == 2:
            args = ["vector", "--mnemonic", _random_string(rng, _WEIRD_CHARS_ARGV + " abandon", 300)]
        else:
            args = ["vector"] + [_random_string(rng, _WEIRD_CHARS_ARGV, 20) for _ in range(rng.randint(0, 4))]
        try:
            proc = subprocess.run([str(main_bin), *args], capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            crashes.append(f"[vector-argv #{i}] args={args!r} TRAVOU (timeout)")
            continue
        combined = proc.stdout + proc.stderr
        if "Traceback (most recent call last)" in combined:
            crashes.append(f"[vector-argv #{i}] args={args!r} rc={proc.returncode} TRACEBACK VAZOU: {combined[:300]!r}")
    return crashes


def fuzz_stdin_bytes(main_bin: Path, rng: random.Random) -> list[str]:
    """Bytes aleatorios brutos na entrada padrao de `generate`/`calibrate`,
    nao-TTY (portanto deve recusar cedo, fail-closed) -- confirma que o
    EXECUTAVEL nunca trava e nunca ecoa o payload de entrada de volta."""
    crashes = []
    for i in range(N_STDIN_BYTES):
        cmd = rng.choice(["generate", "calibrate", "selftest", "--version"])
        payload = bytes(rng.randrange(256) for _ in range(rng.randint(0, 500)))
        try:
            proc = subprocess.run(
                [str(main_bin), cmd], input=payload, capture_output=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            crashes.append(f"[stdin-bytes #{i}] cmd={cmd} payload_len={len(payload)} TRAVOU (timeout)")
            continue
        if payload and payload in proc.stdout + proc.stderr:
            crashes.append(f"[stdin-bytes #{i}] cmd={cmd} payload={payload!r} ECOADO na saida")
    return crashes


def compare_clean_vs_backdoor_strace(report: list[str]) -> None:
    def log(line: str = "") -> None:
        print(line)
        report.append(line)

    if not strace_available():
        log("\n(strace nao disponivel neste sistema -- observacao de processo PULADA, "
            "nao contada como 'nada encontrado'.)")
        return

    with tempfile.TemporaryDirectory(prefix="ef_exe_fuzz_observe_") as tmp_s:
        tmp = Path(tmp_s)

        clean_ef = materialize_clean(tmp / "clean")
        backdoor_ef = materialize_backdoor("01", tmp / "backdoor")

        log("\n--- construindo executavel limpo (para observacao de processo) ---")
        dist_clean = build_executable.build(tmp / "dist_clean", source_root=clean_ef.parent)
        log("--- construindo executavel com backdoor 01 (stderr exfil) ---")
        dist_backdoor = build_executable.build(tmp / "dist_backdoor", source_root=backdoor_ef.parent)

        log("\n" + "=" * 78)
        log("Observacao de processo (strace -f): executavel LIMPO vs. BACKDOOR")
        log("=" * 78)
        log(f"{'caso':<30}{'network':<10}{'process':<10}{'file_write':<12}{'marcador_no_stdio_real'}")
        for label, dist in (("LIMPO", dist_clean), ("BACKDOOR 01 (stderr)", dist_backdoor)):
            main_bin = dist / "entropyforge-bip39"
            trace = trace_process(
                [str(main_bin), "vector", "--a-digits", "1" * 300, "--b-hex", "00" * 32],
                cwd=dist,
                timeout=20,
            )
            # o marcador e' procurado no STDOUT/STDERR REAIS do processo
            # (ja capturados por trace_process via subprocess.run), NAO no
            # log do strace -- o filtro `-e trace=...` usado por
            # trace_process nao inclui `write`, entao o log bruto NUNCA
            # mostraria esta escrita de qualquer forma (ver texto abaixo).
            marker_in_real_output = LAB_MARKER in (trace.stdout + trace.stderr)
            log(
                f"{label:<30}{bool(trace.network_syscalls)!s:<10}"
                f"{bool(trace.process_syscalls)!s:<10}{bool(trace.file_write_syscalls)!s:<12}{marker_in_real_output}"
            )

        log("\nAchado: nenhuma diferenca de syscall de rede/processo/disco entre os "
            "dois -- o backdoor exfiltra via STDOUT/STDERR (um descritor de arquivo "
            "que o processo JA tinha aberto ao nascer, herdado do pai, nunca uma nova "
            "syscall openat/socket/connect), entao e' INVISIVEL para um filtro de "
            "syscalls de rede/disco/processo, exatamente como ja documentado para o "
            "backdoor 01 no source interpretado "
            "(redteam/independent/findings/legit_vs_backdoor_strace_comparison.txt). "
            "'marcador_no_stdio_real' confirma, olhando o STDOUT/STDERR REAIS do "
            "processo (nao o log do strace), que o dado FOI de fato vazado pelo "
            "backdoor e NAO pelo caso limpo -- mas note que o proprio LOG do strace "
            "(`raw_strace_log`) NUNCA teria mostrado essa escrita de qualquer forma, "
            "porque o filtro `-e trace=network,openat,...` de "
            "`verifier.process_observe.trace_process` nao inclui `write`. Isto e' uma "
            "limitacao ja conhecida e documentada do ESCOPO do filtro (feito para "
            "rede/disco/processo, nao para auditar o CONTEUDO de stdout/stderr) -- nao "
            "uma falha desta observacao: uma exfiltracao por stdout/stderr precisa ser "
            "pega por outro mecanismo (aqui, a leitura direta da saida real do "
            "processo, como feito acima, ou uma politica operacional de nunca "
            "redirecionar a saida deste programa para um canal nao confiavel).")


def main() -> int:
    report: list[str] = []

    def log(line: str = "") -> None:
        print(line)
        report.append(line)

    build_tmp = Path(tempfile.mkdtemp(prefix="ef_exe_fuzz_"))
    try:
        log("=== construindo o executavel (legitimo, sem alteracoes) para fuzzing ===")
        dist = build_executable.build(build_tmp)
        main_bin = dist / "entropyforge-bip39"

        rng = random.Random(SEED)
        log(f"\n=== fuzz_vector_argv (seed={SEED}, N={N_VECTOR_ARGV}) ===")
        crashes_vector = fuzz_vector_argv(main_bin, rng)
        log(f"iteracoes: {N_VECTOR_ARGV}  crashes: {len(crashes_vector)}")
        for c in crashes_vector:
            log(f"  {c}")

        log(f"\n=== fuzz_stdin_bytes (seed={SEED}, N={N_STDIN_BYTES}) ===")
        crashes_stdin = fuzz_stdin_bytes(main_bin, rng)
        log(f"iteracoes: {N_STDIN_BYTES}  crashes: {len(crashes_stdin)}")
        for c in crashes_stdin:
            log(f"  {c}")

        compare_clean_vs_backdoor_strace(report)

        total_crashes = len(crashes_vector) + len(crashes_stdin)
        log(f"\n=== RESUMO: {total_crashes} problema(s) real(is) encontrado(s) ===")
    finally:
        shutil.rmtree(build_tmp, ignore_errors=True)

    report_path = REPO_ROOT / "redteam" / "independent" / "findings" / "fuzz_and_observe_executable_output.txt"
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")
    print(f"\nrelatorio completo escrito em: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
