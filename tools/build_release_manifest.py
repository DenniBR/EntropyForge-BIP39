#!/usr/bin/env python3
"""Gera `MANIFEST.txt` a partir do estado ATUAL do repositorio, usando o
mesmo codigo de calculo (`independent-verifier/verifier/release_manifest.py`)
que `verify_release.py` usa para RECONFERIR um manifesto ja publicado.

Isto e deliberado: gerar e verificar compartilham a mesma implementacao de
"como calcular cada hash", para que a UNICA coisa que `verify-release`
precisa confirmar seja "o manifesto publicado ainda bate com os arquivos
reais agora" -- nunca "o gerador e o verificador concordam sobre a
formula" (isso e garantido por construcao, sendo o mesmo codigo).

Pre-requisitos: rode `make build` (ou `python3 tools/build_pyz.py`) E
`make executable` (ou `python3 tools/build_executable.py`) ANTES deste
script, para que `entropyforge.pyz` e o diretorio do executavel existam e
reflitam o source-tree atual -- este script nunca constroi nenhum dos
dois sozinho.

Uso:
    python3 tools/build_release_manifest.py [MANIFEST.txt]
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "independent-verifier"))

from verifier.release_manifest import compute_release_manifest  # noqa: E402


def _find_executable_dist_dir() -> Path | None:
    base = REPO_ROOT / "dist_executable"
    if not base.is_dir():
        return None
    candidates = sorted(base.glob("entropyforge-bip39-v*-*-*"))
    return candidates[0] if candidates else None


def main() -> int:
    pyz_path = REPO_ROOT / "entropyforge.pyz"
    if not pyz_path.exists():
        print(
            f"erro: {pyz_path} nao existe. Rode 'make build' (ou "
            "'python3 tools/build_pyz.py') antes de gerar o manifesto de release.",
            file=sys.stderr,
        )
        return 1

    executable_dist_dir = _find_executable_dist_dir()
    if executable_dist_dir is None:
        print(
            "erro: nenhum diretorio de executavel encontrado em dist_executable/. "
            "Rode 'make executable' (ou 'python3 tools/build_executable.py') antes "
            "de gerar o manifesto de release.",
            file=sys.stderr,
        )
        return 1

    manifest = compute_release_manifest(
        entropyforge_root=REPO_ROOT / "entropyforge",
        pyz_path=pyz_path,
        verifier_root=REPO_ROOT / "independent-verifier" / "verifier",
        build_script_path=REPO_ROOT / "tools" / "build_pyz.py",
        executable_dist_dir=executable_dist_dir,
    )

    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "MANIFEST.txt"
    out_path.write_text(manifest.to_text(), encoding="utf-8")
    print(f"{out_path}:")
    print(manifest.to_text(), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
