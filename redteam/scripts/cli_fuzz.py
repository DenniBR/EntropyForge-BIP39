#!/usr/bin/env python3
"""Red team: fuzzing da CLI (generate/calibrate/selftest/vector) via
subprocessos reais -- stdin/stdout nao-TTY, Unicode, strings enormes,
argumentos extremos, variaveis de ambiente, e verificacao de que nada
sensivel aparece em stdout/stderr mesmo em condicoes anomalas.

Cada teste roda `python3 -B -m entropyforge <cmd>` como um processo
FILHO de verdade (nao a funcao Python diretamente), para capturar
exatamente o que um usuario/atacante externo veria.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CANARY_ENV_VALUE = "CANARY_SECRET_SHOULD_NEVER_APPEAR_IN_OUTPUT_9f8e7d"


def run(args, stdin_data=None, extra_env=None, timeout=10):
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.run(
            [sys.executable, "-B", "-m", "entropyforge", *args],
            cwd=str(REPO_ROOT),
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return "TIMEOUT", e.stdout or b"", e.stderr or b""


def check_no_canary_leak(label, out, err, canary=CANARY_ENV_VALUE):
    problems = []
    if canary.encode() in out or canary.encode() in err:
        problems.append(f"[{label}] CANARY VAZOU em stdout/stderr!")
    return problems


def main():
    problems = []

    print("=== 1) generate com stdin/stdout redirecionados (nao-TTY) ===")
    rc, out, err = run(["generate"], stdin_data=b"123456\n")
    print("  rc=", rc, " tem 'TTY' no stderr:", b"TTY" in err or b"terminal" in err)
    if rc == 0:
        problems.append("generate NAO recusou entrada nao-TTY (deveria recusar)")
    if b"123456" in out or b"123456" in err:
        problems.append("dados de entrada (digitos) vazaram na saida quando stdin nao e TTY")

    print("\n=== 2) generate com --rolls extremos ===")
    for val in ["0", "-1", "-999999"]:
        rc, out, err = run(["generate", "--rolls", val], stdin_data=b"123456\n", timeout=5)
        print(f"  --rolls {val}: rc={rc}")
        if rc == "TIMEOUT":
            problems.append(f"generate --rolls {val} TRAVOU (nao e TTY entao deveria recusar antes de pedir input, mas se travar e DoS)")

    print("\n=== 3) vector com Unicode/bytes invalidos/strings enormes ===")
    weird_inputs = [
        ["--entropy-hex", "00" * 32 + "Z"],  # caractere extra invalido (nao-hex), sem byte nulo
        ["--entropy-hex", "gg" * 32],
        ["--entropy-hex", "00" * 10000],  # bem maior que qualquer entropia valida (ARG_MAX do SO limita o quao longe dá pra ir aqui)
        ["--mnemonic", "😀" * 24],
        # NOTA: um argv com byte nulo (\x00) e rejeitado pelo proprio
        # modulo `subprocess` do Python (ValueError: embedded null byte)
        # antes mesmo de chegar a um processo -- e uma restricao do SO
        # (execve() usa strings C terminadas em nulo), nao algo que este
        # programa precise tratar. Testado separadamente, fora desta lista.
        ["--a-digits", "1" * 20000, "--b-hex", "00" * 32],
        ["--a-digits", "١٢٣٤٥٦", "--b-hex", "00" * 32],  # digitos arabicos, parecem '123456' visualmente
    ]
    for args in weird_inputs:
        rc, out, err = run(["vector", *args], timeout=15)
        label = " ".join(a[:30] for a in args)
        print(f"  vector {label!r:60s} -> rc={rc}")
        if rc == "TIMEOUT":
            problems.append(f"vector travou com entrada: {label}")
        problems.extend(check_no_canary_leak(f"vector {label}", out, err))

    print("\n=== 4) selftest / generate com variavel de ambiente 'canario' ===")
    rc, out, err = run(["selftest"], extra_env={"ENTROPYFORGE_CANARY": CANARY_ENV_VALUE, "PYTHONPATH": CANARY_ENV_VALUE})
    problems.extend(check_no_canary_leak("selftest+env", out, err))
    print(f"  selftest com env canario: rc={rc}, vazou={CANARY_ENV_VALUE.encode() in out+err}")

    print("\n=== 5) generate interrompido (SIGINT) durante espera de input ===")
    proc = subprocess.Popen(
        [sys.executable, "-B", "-m", "entropyforge", "generate"],
        cwd=str(REPO_ROOT), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    import time, signal
    time.sleep(1.5)
    proc.send_signal(signal.SIGINT)
    try:
        out, err = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        problems.append("generate nao terminou apos SIGINT em 10s (ficou pendurado)")
    print(f"  apos SIGINT: returncode={proc.returncode}")
    problems.extend(check_no_canary_leak("SIGINT", out, err))

    print("\n=== 6) calibrate com --rolls negativo/zero ===")
    rc, out, err = run(["calibrate", "--rolls", "0"], stdin_data=b"\n", timeout=5)
    print(f"  calibrate --rolls 0: rc={rc}")
    if rc == "TIMEOUT":
        problems.append("calibrate --rolls 0 travou")

    print("\n=== 7) argumento desconhecido / malformado ===")
    for bad_args in [["generate", "--rolls"], ["vector", "--entropy-hex"], ["nao-existe"], []]:
        rc, out, err = run(bad_args, timeout=5)
        print(f"  args={bad_args} -> rc={rc}")

    print("\n=== 8) checagem estatica: entropyforge/ le os.environ em algum lugar? ===")
    import ast
    for path in (REPO_ROOT / "entropyforge").rglob("*.py"):
        src = path.read_text()
        if "os.environ" in src or "getenv" in src:
            problems.append(f"USO DE VARIAVEL DE AMBIENTE encontrado em {path}")
    print("  nenhum uso de os.environ/getenv encontrado" if not any("VARIAVEL" in p for p in problems) else "  ENCONTRADO uso de env vars")

    print(f"\n=== RESUMO: {len(problems)} problema(s) encontrados ===")
    for p in problems:
        print(" -", p)
    return len(problems)


if __name__ == "__main__":
    sys.exit(main())
