#!/usr/bin/env python3
"""Red team PoC: o requisito 1 ("nunca gerar a seed por um PRNG proprio")
e verificado ESTATICAMENTE (AST, tests/test_security_ast.py) sobre
imports literais em `entropyforge/*.py`. Este PoC demonstra que esse
check estatico e, em principio, contornavel por um import DINAMICO do
modulo `random`, e explica por que NAO implementamos um bloqueio em
tempo de execucao para isso (ao contrario de rede/disco/subprocess, que
SAO bloqueados em tempo de execucao por entropyforge.guard).

Conclusao (ver docs/REDTEAM.md): informativo, nao uma vulnerabilidade
acionavel. Um bloqueio de importacao completo do modulo `random` quebra
funcionalidade legitima (importlib.resources -> tempfile -> random,
usado por wordlist.py para carregar a wordlist de dentro do .pyz).
"""
from __future__ import annotations

import importlib
import sys


def demo_static_check_blind_spot() -> None:
    print("--- 1) o import dinamico nao aparece na AST como 'import random' ---")
    import ast

    src = "import importlib\nrandom_mod = importlib.import_module('random')\n"
    tree = ast.parse(src)
    literal_imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
    print(f"    imports literais encontrados pela AST: {[ast.dump(n) for n in literal_imports]}")
    print("    (so 'import importlib' aparece; 'random' nunca e mencionado literalmente)")


def demo_guard_does_not_block_it() -> None:
    print("\n--- 2) o audit hook (guard.py) tambem nao bloqueia isso ---")
    print("    (nao ha sys.audit event para 'usar o modulo random'; rodando em subprocesso)")
    import subprocess

    snippet = (
        "import sys; sys.path.insert(0, '.')\n"
        "from entropyforge import guard\n"
        "guard.activate()\n"
        "import importlib\n"
        "m = importlib.import_module('random')\n"
        "print('random importado dinamicamente com sucesso; random.random() =', m.random())\n"
    )
    proc = subprocess.run([sys.executable, "-B", "-c", snippet], capture_output=True, text=True, timeout=10)
    print("   ", (proc.stdout + proc.stderr).strip())


def demo_why_blocking_would_break_things() -> None:
    print("\n--- 3) por que NAO implementamos um bloqueio total de 'random' ---")
    print("    tempfile (usado transitivamente por importlib.resources, que")
    print("    wordlist.py usa para funcionar tanto de um diretorio quanto de")
    print("    dentro do .pyz) importa 'random' internamente, por motivos")
    print("    proprios e inofensivos (nomes de arquivo temporario aleatorios).")
    before = "random" in sys.modules
    import tempfile  # noqa: F401 -- demonstra o import transitivo, de proposito

    after = "random" in sys.modules
    print(f"    'random' em sys.modules antes de importar tempfile: {before}")
    print(f"    'random' em sys.modules depois de importar tempfile: {after}")
    print("    um sys.meta_path que bloqueasse QUALQUER import de 'random' quebraria")
    print("    'importlib.resources', que entropyforge.wordlist depende para funcionar.")


def main() -> None:
    demo_static_check_blind_spot()
    demo_guard_does_not_block_it()
    demo_why_blocking_would_break_things()
    print(
        "\nCONCLUSAO: o requisito 1 e garantido pelo check estatico (AST) sobre o "
        "codigo-fonte de entropyforge/, nao por um mecanismo em tempo de execucao. "
        "Contornar o check estatico exige a mesma capacidade (modificar o codigo-"
        "fonte de entropyforge/) que ja permitiria ataques muito mais diretos e "
        "graves (ver docs/REDTEAM.md, achado sobre backdoor via combine.py) -- "
        "por isso classificamos isto como INFORMATIVO, nao uma vulnerabilidade "
        "acionavel isolada, e decidimos NAO adicionar um bloqueio de importacao "
        "que quebraria funcionalidade legitima da biblioteca padrao."
    )


if __name__ == "__main__":
    main()
