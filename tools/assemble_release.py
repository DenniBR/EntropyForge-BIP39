#!/usr/bin/env python3
"""Monta o diretorio `release/`: o pacote autocontido que sai da maquina
conectada em direcao a maquina permanentemente offline (Fase E, requisito
de estrutura de release).

Pre-requisitos (nesta ordem, ja encadeados por `make release`):
  1. `make build`                      -> entropyforge.pyz, SHA256SUMS
  2. `python3 tools/build_release_manifest.py` -> MANIFEST.txt

Este script so COPIA arquivos ja existentes -- nunca constroi nada, nunca
importa `entropyforge`. O conteudo de `release/` e:

    release/
    ├── entropyforge.pyz    # o unico arquivo que efetivamente RODA
    ├── SHA256SUMS          # hash do .pyz, formato compativel com `sha256sum -c`
    ├── MANIFEST.txt        # hashes/versoes independentemente verificaveis
    └── docs/               # toda a documentacao (para uso 100% offline,
                             # sem depender de acesso a internet na maquina
                             # onde a geracao real vai acontecer)

`README.md` fica FORA de `release/docs/` e e copiado para `release/`
diretamente, como ponto de entrada (e o primeiro arquivo que qualquer
pessoa abre).
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

REQUIRED_INPUTS = ("entropyforge.pyz", "SHA256SUMS", "MANIFEST.txt")


def assemble(out_dir: Path) -> None:
    missing = [name for name in REQUIRED_INPUTS if not (REPO_ROOT / name).exists()]
    if missing:
        raise SystemExit(
            f"erro: arquivo(s) ausente(s) na raiz do repositorio: {missing}. "
            "Rode 'make build' e 'python3 tools/build_release_manifest.py' antes."
        )

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    for name in REQUIRED_INPUTS:
        shutil.copy2(REPO_ROOT / name, out_dir / name)

    shutil.copy2(REPO_ROOT / "README.md", out_dir / "README.md")
    shutil.copytree(
        REPO_ROOT / "docs", out_dir / "docs",
        ignore=shutil.ignore_patterns("__pycache__"),
    )


def main() -> int:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "release"
    assemble(out_dir)
    print(f"release montado em: {out_dir}")
    for p in sorted(out_dir.rglob("*")):
        if p.is_file():
            print(f"  {p.relative_to(out_dir)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
