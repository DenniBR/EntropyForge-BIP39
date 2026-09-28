#!/usr/bin/env python3
"""Interface `verify-executable` (Fase F): verifica o EXECUTAVEL
standalone contra o source-tree.

Ao contrario do `.pyz` (que contem o source-tree verbatim, permitindo
`pyz_inspect.compare_pyz_to_source` comparar byte a byte SEM reconstruir
nada), um binario compilado pelo Nuitka nao tem correspondencia byte a
byte com o Python original -- a UNICA verificacao realmente forte e
RECONSTRUIR o executavel a partir do source revisado e comparar o hash
resultante contra o executavel em mãos. Por isso este script:

  1. faz checagens RAPIDAS primeiro (hash do diretorio existente bate com
     o que o MANIFEST.txt reivindica; `--version`/`selftest` do binario
     respondem como esperado);
  2. só então RECONSTRÓI o executável a partir de `entropyforge_root`
     (ao vivo, com `tools/build_executable.py` -- por isso este script
     precisa de `nuitka` e um compilador C instalados, ao contrário de
     `verify_release.py`, que continua sem essa dependência);
  3. compara o hash do executável reconstruído contra o hash reivindicado
     pelo manifesto -- se baterem, o executável em mãos corresponde
     exatamente ao source revisado.

Uso:

    python3 independent-verifier/verify_executable.py \\
        --manifest MANIFEST.txt \\
        --entropyforge-root entropyforge \\
        --executable-dist dist_executable/entropyforge-bip39-vX.Y.Z-linux-x86_64

Saída (stdout, sempre uma única palavra): `PASS` ou `FAIL`. Código de
saída: 0/1/2 (PASS/FAIL/erro de uso). `--verbose` manda o detalhamento
para stderr. Nenhuma saída deste programa, em nenhum modo, inclui
mnemonic/entropia/A/B/seed/passphrase -- só metadados de build.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO_ROOT / "tools"))

import build_executable  # noqa: E402 -- so a definicao (nao _check_prereqs()), sempre seguro de importar
from verifier.hashing import build_manifest, hash_bytes, manifest_to_text  # noqa: E402
from verifier.release_manifest import (  # noqa: E402
    ReleaseManifestError,
    executable_manifest_hash,
    read_release_manifest,
)


class ExecutableCheck:
    def __init__(self, name: str, ok: bool, detail: str):
        self.name = name
        self.ok = ok
        self.detail = detail

    def __str__(self) -> str:
        return f"[{'PASS' if self.ok else 'FAIL'}] {self.name}: {self.detail}"


def _run(main_bin: Path, args: list[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run([str(main_bin), *args], capture_output=True, text=True, timeout=timeout)


def verify_executable(
    manifest,
    *,
    entropyforge_root: Path,
    executable_dist_dir: Path,
    skip_rebuild: bool = False,
) -> list[ExecutableCheck]:
    checks: list[ExecutableCheck] = []
    main_bin = executable_dist_dir / build_executable._main_binary_name()

    # 1. o diretorio em maos bate com o hash que o manifesto reivindica?
    current_hash = executable_manifest_hash(executable_dist_dir)
    ok = current_hash == manifest.executable_sha256
    checks.append(
        ExecutableCheck(
            "executavel.hash_vs_manifesto",
            ok,
            "bate com o manifesto" if ok else f"manifesto={manifest.executable_sha256} atual={current_hash}",
        )
    )

    # 2. --version responde como esperado?
    if not main_bin.is_file():
        checks.append(ExecutableCheck("executavel.binario_existe", False, f"nao encontrado: {main_bin}"))
        return checks
    try:
        proc = _run(main_bin, ["--version"])
        ok = (
            proc.returncode == 0
            and manifest.software_version in proc.stdout
            and manifest.wordlist_version in proc.stdout
        )
        checks.append(
            ExecutableCheck(
                "executavel.version",
                ok,
                "bate com o manifesto" if ok else f"saida={proc.stdout!r}",
            )
        )
    except Exception as exc:  # noqa: BLE001
        checks.append(ExecutableCheck("executavel.version", False, f"{type(exc).__name__}: {exc}"))

    # 3. selftest passa?
    try:
        proc = _run(main_bin, ["selftest"])
        ok = proc.returncode == 0 and "RESULTADO GERAL: PASSOU" in proc.stdout
        checks.append(
            ExecutableCheck("executavel.selftest", ok, "PASSOU" if ok else f"rc={proc.returncode} saida={proc.stdout!r}")
        )
    except Exception as exc:  # noqa: BLE001
        checks.append(ExecutableCheck("executavel.selftest", False, f"{type(exc).__name__}: {exc}"))

    # 4. a verificacao FORTE: reconstruir a partir do source e comparar.
    if skip_rebuild:
        checks.append(
            ExecutableCheck(
                "executavel.reconstrucao_a_partir_do_source",
                False,
                "PULADO (--skip-rebuild) -- isto e um FAIL deliberado: sem "
                "reconstruir, nao ha verificacao forte do executavel, so a "
                "confirmacao de que ele bate com um manifesto que poderia "
                "ter sido forjado junto com o proprio artefato",
            )
        )
        return checks
    try:
        build_executable._check_prereqs()
    except Exception as exc:  # noqa: BLE001
        checks.append(
            ExecutableCheck(
                "executavel.reconstrucao_a_partir_do_source",
                False,
                f"pre-requisitos de build ausentes, nao foi possivel reconstruir: {exc}",
            )
        )
        return checks

    with tempfile.TemporaryDirectory() as tmp:
        try:
            rebuilt_dir = build_executable.build(Path(tmp))
            rebuilt_hash = hash_bytes(manifest_to_text(build_manifest(rebuilt_dir)).encode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            checks.append(
                ExecutableCheck(
                    "executavel.reconstrucao_a_partir_do_source", False, f"falha ao reconstruir: {exc}"
                )
            )
            return checks
        ok = rebuilt_hash == manifest.executable_sha256
        checks.append(
            ExecutableCheck(
                "executavel.reconstrucao_a_partir_do_source",
                ok,
                "reconstruido a partir do source bate exatamente com o manifesto"
                if ok
                else f"manifesto={manifest.executable_sha256} reconstruido={rebuilt_hash}",
            )
        )
    return checks


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verifica o executavel standalone do EntropyForge-BIP39 contra o "
        "source-tree, reconstruindo-o (saida: PASS ou FAIL)."
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--entropyforge-root", required=True, type=Path)
    parser.add_argument("--executable-dist", required=True, type=Path)
    parser.add_argument(
        "--skip-rebuild", action="store_true",
        help="NAO reconstroi o executavel (mais rapido, mas so confirma consistencia "
        "interna do manifesto -- resulta em FAIL deliberado no item de reconstrucao, "
        "nunca um PASS silencioso)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    for label, path in (
        ("--manifest", args.manifest),
        ("--entropyforge-root", args.entropyforge_root),
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

    checks = verify_executable(
        manifest,
        entropyforge_root=args.entropyforge_root,
        executable_dist_dir=args.executable_dist,
        skip_rebuild=args.skip_rebuild,
    )
    passed = all(c.ok for c in checks)

    if args.verbose:
        for c in checks:
            print(c, file=sys.stderr)
        print(f"RESULTADO GERAL: {'PASS' if passed else 'FAIL'}", file=sys.stderr)

    print("PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
