#!/usr/bin/env python3
"""Monta o conjunto final de assets de uma GitHub Release a partir dos
artefatos ja construidos pelos jobs `build-linux`/`build-windows` do
workflow (`.github/workflows/release.yml`) -- so empacota/hasheia,
nunca constroi nada (mesmo principio de `tools/assemble_release.py`).
So biblioteca padrao (`tarfile`, `zipfile`, `hashlib`).

Produz, em `--out-dir`:
  - entropyforge-bip39-vX.Y.Z-linux-x86_64.tar.gz   (todo o diretorio do executavel Linux)
  - entropyforge-bip39-vX.Y.Z-windows-x86_64.zip    (todo o diretorio do executavel Windows)
  - entropyforge.pyz                                (copia do .pyz)
  - MANIFEST-linux-x86_64.txt / MANIFEST-windows-x86_64.txt (copias)
  - independent-verifier-bundle.zip                 (verifier/ + verify_release.py +
                                                       verify_executable.py, nunca tests/)
  - um `<nome>.sha256` por arquivo acima
  - SHA256SUMS.txt                                  (todos os hashes acima, um arquivo so)

Uso:
    python3 tools/ci_package_assets.py \\
        --linux-dist dist_executable/entropyforge-bip39-vX.Y.Z-linux-x86_64 \\
        --windows-dist dist_executable/entropyforge-bip39-vX.Y.Z-windows-x86_64 \\
        --pyz entropyforge.pyz \\
        --manifest-linux MANIFEST-linux-x86_64.txt \\
        --manifest-windows MANIFEST-windows-x86_64.txt \\
        --repo-root . \\
        --out-dir release_assets
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_tar_gz(src_dir: Path, out_path: Path) -> None:
    arcname_root = src_dir.name
    with tarfile.open(out_path, "w:gz") as tar:
        tar.add(src_dir, arcname=arcname_root)


def _make_zip(src_dir: Path, out_path: Path) -> None:
    arcname_root = src_dir.name
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(src_dir.rglob("*")):
            if p.is_file():
                zf.write(p, arcname=str(Path(arcname_root) / p.relative_to(src_dir)))


def _make_verifier_bundle_zip(repo_root: Path, out_path: Path) -> None:
    src = repo_root / "independent-verifier"
    skip_dirnames = {"tests", "__pycache__"}
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(src.rglob("*")):
            if p.is_dir():
                continue
            if any(part in skip_dirnames for part in p.relative_to(src).parts):
                continue
            zf.write(p, arcname=str(Path("independent-verifier") / p.relative_to(src)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--linux-dist", type=Path, required=True)
    parser.add_argument("--windows-dist", type=Path, required=True)
    parser.add_argument("--pyz", type=Path, required=True)
    parser.add_argument("--manifest-linux", type=Path, required=True)
    parser.add_argument("--manifest-windows", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    for label, p in (
        ("--linux-dist", args.linux_dist), ("--windows-dist", args.windows_dist),
        ("--pyz", args.pyz), ("--manifest-linux", args.manifest_linux),
        ("--manifest-windows", args.manifest_windows), ("--repo-root", args.repo_root),
    ):
        if not p.exists():
            print(f"erro: {label} nao encontrado: {p}", file=sys.stderr)
            return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    produced: list[Path] = []

    linux_tar = args.out_dir / f"{args.linux_dist.name}.tar.gz"
    print(f"empacotando {args.linux_dist} -> {linux_tar}")
    _make_tar_gz(args.linux_dist, linux_tar)
    produced.append(linux_tar)

    windows_zip = args.out_dir / f"{args.windows_dist.name}.zip"
    print(f"empacotando {args.windows_dist} -> {windows_zip}")
    _make_zip(args.windows_dist, windows_zip)
    produced.append(windows_zip)

    pyz_copy = args.out_dir / "entropyforge.pyz"
    shutil.copy2(args.pyz, pyz_copy)
    produced.append(pyz_copy)

    manifest_linux_copy = args.out_dir / "MANIFEST-linux-x86_64.txt"
    shutil.copy2(args.manifest_linux, manifest_linux_copy)
    produced.append(manifest_linux_copy)

    manifest_windows_copy = args.out_dir / "MANIFEST-windows-x86_64.txt"
    shutil.copy2(args.manifest_windows, manifest_windows_copy)
    produced.append(manifest_windows_copy)

    verifier_zip = args.out_dir / "independent-verifier-bundle.zip"
    print(f"empacotando independent-verifier/ -> {verifier_zip}")
    _make_verifier_bundle_zip(args.repo_root, verifier_zip)
    produced.append(verifier_zip)

    sha_lines = []
    for p in produced:
        digest = _sha256_file(p)
        (args.out_dir / f"{p.name}.sha256").write_text(f"{digest}  {p.name}\n", encoding="utf-8")
        sha_lines.append(f"{digest}  {p.name}")
        print(f"{p.name}: sha256={digest}")

    (args.out_dir / "SHA256SUMS.txt").write_text("\n".join(sorted(sha_lines)) + "\n", encoding="utf-8")

    print(f"\nassets prontos em: {args.out_dir}")
    for p in sorted(args.out_dir.iterdir()):
        print(f"  {p.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
