#!/usr/bin/env python3
"""Monta o diretorio `release/`: o pacote autocontido que sai da maquina
conectada em direcao a maquina permanentemente offline (Fase E, expandido
na Fase F para incluir o executavel standalone).

Pre-requisitos (nesta ordem, ja encadeados por `make release`):
  1. `make build`                              -> entropyforge.pyz, SHA256SUMS
  2. `make executable`                          -> dist_executable/entropyforge-bip39-vX.Y.Z-linux-<arch>/
  3. `python3 tools/build_release_manifest.py`  -> MANIFEST.txt

Este script so COPIA/HASHEIA arquivos ja existentes -- nunca constroi
nada, nunca importa `entropyforge`. O conteudo de `release/` e:

    release/
    ├── entropyforge.pyz                                # o artefato interpretado
    ├── SHA256SUMS                                       # hash do .pyz (sha256sum -c)
    ├── entropyforge-bip39-vX.Y.Z-linux-<arch>/          # o executavel standalone (Fase F)
    ├── entropyforge-bip39-vX.Y.Z-linux-<arch>.sha256    # hash de CADA arquivo do executavel (sha256sum -c)
    ├── independent-verifier/                            # copia do verificador (Fase F) --
    │                                                     # ver aviso em VERIFY.md: rodar as
    │                                                     # checagens contra ESTA copia do source
    │                                                     # nao prova nada sozinho, precisa de um
    │                                                     # entropyforge/ obtido por canal independente
    ├── MANIFEST.txt          # hashes/versoes independentemente verificaveis
    ├── RELEASE-CANDIDATE.md  # resumo executivo desta release
    └── docs/                 # toda a documentacao (para uso 100% offline,
                               # sem depender de acesso a internet na maquina
                               # onde a geracao real vai acontecer)

`README.md` fica FORA de `release/docs/` e e copiado para `release/`
diretamente, como ponto de entrada (e o primeiro arquivo que qualquer
pessoa abre).
"""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_release_manifest import _find_executable_dist_dir  # noqa: E402

REQUIRED_INPUTS = ("entropyforge.pyz", "SHA256SUMS", "MANIFEST.txt", "RELEASE-CANDIDATE.md")

_VERIFIER_TESTS_DIRNAME = "tests"  # nunca copiado -- dev-only, ver _copy_verifier


def _copy_verifier(out_dir: Path) -> None:
    """Copia `independent-verifier/` (o pacote `verifier/` + os scripts
    `verify_release.py`/`verify_executable.py`) para `release/independent-verifier/`,
    preservando exatamente a mesma estrutura relativa do repositorio --
    assim, os comandos ja documentados em `docs/VERIFY.md` continuam
    funcionando sem alteracao, so trocando a raiz do repositorio pela raiz
    do release. NUNCA inclui `independent-verifier/tests/` (dev-only, sem
    nenhum uso na maquina offline)."""
    src = REPO_ROOT / "independent-verifier"
    dest = out_dir / "independent-verifier"
    shutil.copytree(
        src, dest,
        ignore=shutil.ignore_patterns("__pycache__", _VERIFIER_TESTS_DIRNAME),
    )


def _write_executable_sha256(dist_dir: Path, out_dir: Path) -> None:
    """Gera `<nome-do-dist>.sha256`: hash SHA-256 de CADA arquivo dentro
    do diretorio do executavel (nao so o binario principal -- inclui as
    bibliotecas `.so` empacotadas), em formato compativel com
    `sha256sum -c`, com caminhos relativos ao proprio diretorio do
    executavel (para que `cd release/<nome-do-dist> && sha256sum -c
    ../<nome-do-dist>.sha256` funcione depois de copiar a pasta)."""
    lines = []
    for p in sorted(dist_dir.rglob("*")):
        if p.is_file():
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            lines.append(f"{digest}  {p.relative_to(dist_dir)}")
    sha_path = out_dir / f"{dist_dir.name}.sha256"
    sha_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def assemble(out_dir: Path) -> None:
    missing = [name for name in REQUIRED_INPUTS if not (REPO_ROOT / name).exists()]
    if missing:
        raise SystemExit(
            f"erro: arquivo(s) ausente(s) na raiz do repositorio: {missing}. "
            "Rode 'make build' e 'python3 tools/build_release_manifest.py' antes."
        )

    executable_dist_dir = _find_executable_dist_dir(REPO_ROOT)
    if executable_dist_dir is None:
        raise SystemExit(
            "erro: nenhum diretorio de executavel encontrado em dist_executable/. "
            "Rode 'make executable' antes de montar o release."
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

    dest_exe_dir = out_dir / executable_dist_dir.name
    shutil.copytree(executable_dist_dir, dest_exe_dir)
    _write_executable_sha256(dest_exe_dir, out_dir)

    _copy_verifier(out_dir)


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
