"""Ponto de entrada do executavel empacotado (Nuitka --standalone, Fase F).

Identico em espirito ao bootstrap do `.pyz` (`tools/build_pyz.py`,
`EXPECTED_BOOTSTRAP_MAIN`): so chama `entropyforge.__main__.run()`, que
por sua vez ativa o guard ANTES de importar `cli` -- nenhuma logica nova
e introduzida so por causa do empacotamento. Ver docs/EXECUTABLE_BUILD.md.
"""

import sys

from entropyforge.__main__ import run

if __name__ == "__main__":
    sys.exit(run())
