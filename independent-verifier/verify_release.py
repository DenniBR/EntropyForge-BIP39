#!/usr/bin/env python3
"""Interface `verify-release`: verifica um release do EntropyForge-BIP39
contra um `MANIFEST.txt`, imprimindo SOMENTE `PASS` ou `FAIL` em stdout
por padrao (Fase E, requisito de verificacao independente de release).

Uso:

    python3 independent-verifier/verify_release.py \\
        --manifest MANIFEST.txt \\
        --entropyforge-root entropyforge \\
        --pyz entropyforge.pyz \\
        --verifier-root independent-verifier/verifier \\
        --build-script tools/build_pyz.py \\
        --vectors tests/vectors/bip39_vectors.json \\
        --executable-dist dist_executable/entropyforge-bip39-vX.Y.Z-linux-x86_64

Esta checagem cobre os campos do executavel de forma RAPIDA (compara o
hash do diretorio contra o que o manifesto reivindica), sem reconstruir
nada e sem depender de `nuitka` estar instalado. Para a verificacao FORTE
do executavel (reconstruir a partir do source e comparar), use
`independent-verifier/verify_executable.py` (Fase F).

Saida (stdout, sempre uma unica palavra, para uso em scripts):

    PASS    -- todo campo do manifesto e todo controle independente bateram
    FAIL    -- pelo menos um campo ou controle divergiu

Codigo de saida: 0 para PASS, 1 para FAIL, 2 para erro de uso/arquivo
ausente (nem PASS nem FAIL -- a verificacao nem chegou a rodar).

`--verbose`/`-v` imprime, ALEM da palavra final, o detalhamento
campo-a-campo em stderr (nunca em stdout, para que `stdout` continue
sendo so a palavra PASS/FAIL mesmo com `-v`, seguro para
`resultado=$(python3 verify_release.py ...)` em um script). Nenhuma saida
deste programa, em nenhum modo, jamais inclui uma mnemonic, entropia, A,
B, seed ou passphrase -- este verificador so olha para metadados de build
(hashes de arquivos, numeros de versao), nunca para dados de uma geracao
real.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from verifier.release_manifest import (  # noqa: E402
    ReleaseManifestError,
    read_release_manifest,
    verify_release,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verifica um release do EntropyForge-BIP39 contra um MANIFEST.txt "
        "(saida: PASS ou FAIL)."
    )
    parser.add_argument("--manifest", required=True, type=Path, help="caminho do MANIFEST.txt")
    parser.add_argument(
        "--entropyforge-root", required=True, type=Path,
        help="caminho do diretorio entropyforge/ (o pacote, nao o repositorio inteiro)",
    )
    parser.add_argument("--pyz", required=True, type=Path, help="caminho do artefato .pyz")
    parser.add_argument(
        "--verifier-root", required=True, type=Path,
        help="caminho do diretorio independent-verifier/verifier/",
    )
    parser.add_argument(
        "--build-script", required=True, type=Path,
        help="caminho do script de build (tools/build_pyz.py)",
    )
    parser.add_argument(
        "--vectors", required=True, type=Path,
        help="caminho do JSON de vetores oficiais BIP-39 (tests/vectors/bip39_vectors.json)",
    )
    parser.add_argument(
        "--executable-dist", required=True, type=Path,
        help="caminho do diretorio do executavel standalone (saida de tools/build_executable.py)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="tambem imprime o detalhamento campo-a-campo em stderr",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    for label, path in (
        ("--manifest", args.manifest),
        ("--entropyforge-root", args.entropyforge_root),
        ("--pyz", args.pyz),
        ("--verifier-root", args.verifier_root),
        ("--build-script", args.build_script),
        ("--vectors", args.vectors),
        ("--executable-dist", args.executable_dist),
    ):
        if not path.exists():
            print(f"erro: {label} nao encontrado: {path}", file=sys.stderr)
            return 2

    try:
        manifest = read_release_manifest(args.manifest)
    except ReleaseManifestError as exc:
        print(f"erro: manifesto malformado: {exc}", file=sys.stderr)
        return 2

    result = verify_release(
        manifest,
        entropyforge_root=args.entropyforge_root,
        pyz_path=args.pyz,
        verifier_root=args.verifier_root,
        build_script_path=args.build_script,
        official_vectors_path=args.vectors,
        executable_dist_dir=args.executable_dist,
    )

    if args.verbose:
        print(result.format_report(), file=sys.stderr)

    print("PASS" if result.passed else "FAIL")
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
