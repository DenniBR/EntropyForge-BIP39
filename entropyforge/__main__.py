"""Ponto de entrada do pacote.

Suporta duas formas de invocacao com o MESMO caminho de codigo:

  1. `python3 -B -m entropyforge <comando>` a partir de um checkout do
     repositorio (SEM `-I`: essa flag implica `-P`, que desativa o
     prepend automatico do diretorio atual ao `sys.path` de que `-m`
     precisa para achar um pacote nao instalado — ver docs/AUDIT.md);
  2. `python3 -I -B entropyforge.pyz <comando>`, o artefato `.pyz` gerado
     por `tools/build_pyz.py` (aqui `-I` funciona normalmente: e o
     proprio arquivo `.pyz`, nao o cwd, que entra no `sys.path`). O
     arquivo `__main__.py` na raiz desse artefato so chama `run()` daqui.

O guard de seguranca (`entropyforge.guard`) e ativado ANTES de importar
`entropyforge.cli` (que por sua vez importa todo o resto do pacote), para
que o bloqueio de rede/escrita/subprocess esteja em vigor pelo maior tempo
possivel durante a vida do processo. A unica janela inevitavel e a
importacao dos proprios modulos `entropyforge` e `entropyforge.guard`
antes de `guard.activate()` poder ser chamado -- nao ha como um guard se
proteger antes de ele mesmo existir.
"""

from __future__ import annotations

import sys


def run() -> int:
    from . import guard

    guard.activate()
    from .cli import main

    return main(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(run())
