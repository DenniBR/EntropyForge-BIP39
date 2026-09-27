"""Hashing e manifestos INDEPENDENTES do EntropyForge.

Este modulo nao importa nada de `entropyforge/` (nem `entropyforge.wordlist`,
nem qualquer helper de hash de la). Usa somente `hashlib` da biblioteca
padrao. Essa e a premissa central do independent-verifier: ele calcula
seus proprios hashes, com seu proprio codigo, para que uma adulteracao no
codigo do EntropyForge (incluindo em uma funcao de hash que ele proprio
usasse para "se auto-verificar") nao tenha como enganar o verificador.

Formato do manifesto: texto simples, uma linha por arquivo, campos
separados por UM caractere tab, sempre na ordem `sha256\tsize\tpath`,
`path` sempre em barras (`/`, estilo POSIX) e relativo a raiz verificada,
arquivos ordenados por `path` (para que o manifesto em si seja
deterministico e comparavel byte a byte entre execucoes diferentes).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

_CHUNK_SIZE = 1024 * 1024  # 1 MiB


@dataclass(frozen=True, order=True)
class ManifestEntry:
    path: str  # relativo, sempre com '/'
    size: int
    sha256: str


class ManifestError(Exception):
    pass


def hash_file(path: Path) -> str:
    """SHA-256 de um arquivo, lido em blocos (nao carrega tudo em
    memoria). Implementacao direta com `hashlib`, sem qualquer
    dependencia de `entropyforge`."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_manifest(
    root: Path,
    *,
    include_suffixes: tuple[str, ...] | None = None,
    exclude_dirs: frozenset[str] = frozenset({"__pycache__", ".git"}),
) -> list[ManifestEntry]:
    """Percorre `root` recursivamente e devolve uma lista ordenada de
    `ManifestEntry`. Se `include_suffixes` for dado, so arquivos com um
    desses sufixos entram (ex.: `(".py",)`); caso contrario, TODOS os
    arquivos regulares entram.
    """
    root = root.resolve()
    entries: list[ManifestEntry] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in exclude_dirs for part in path.relative_to(root).parts):
            continue
        if include_suffixes is not None and path.suffix not in include_suffixes:
            continue
        rel = path.relative_to(root).as_posix()
        entries.append(ManifestEntry(path=rel, size=path.stat().st_size, sha256=hash_file(path)))
    entries.sort()
    return entries


def manifest_to_text(entries: list[ManifestEntry]) -> str:
    lines = [f"{e.sha256}\t{e.size}\t{e.path}" for e in sorted(entries)]
    return "\n".join(lines) + ("\n" if lines else "")


def write_manifest(entries: list[ManifestEntry], out_path: Path) -> None:
    out_path.write_text(manifest_to_text(entries), encoding="utf-8")


def parse_manifest_text(text: str) -> list[ManifestEntry]:
    entries = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            raise ManifestError(f"linha {lineno} malformada (esperado 3 campos): {line!r}")
        sha256, size_str, path = parts
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ManifestError(f"linha {lineno}: sha256 invalido: {sha256!r}")
        try:
            size = int(size_str)
        except ValueError as exc:
            raise ManifestError(f"linha {lineno}: tamanho invalido: {size_str!r}") from exc
        entries.append(ManifestEntry(path=path, size=size, sha256=sha256))
    return sorted(entries)


def read_manifest(path: Path) -> list[ManifestEntry]:
    return parse_manifest_text(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class ManifestDiff:
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[str, ...]  # mesmo path, hash e/ou tamanho diferente

    @property
    def is_identical(self) -> bool:
        return not (self.added or self.removed or self.changed)


def diff_manifests(old: list[ManifestEntry], new: list[ManifestEntry]) -> ManifestDiff:
    old_by_path = {e.path: e for e in old}
    new_by_path = {e.path: e for e in new}
    added = tuple(sorted(set(new_by_path) - set(old_by_path)))
    removed = tuple(sorted(set(old_by_path) - set(new_by_path)))
    changed = tuple(
        sorted(
            p
            for p in set(old_by_path) & set(new_by_path)
            if old_by_path[p].sha256 != new_by_path[p].sha256
            or old_by_path[p].size != new_by_path[p].size
        )
    )
    return ManifestDiff(added=added, removed=removed, changed=changed)


def verify_against_manifest(root: Path, manifest: list[ManifestEntry]) -> ManifestDiff:
    """Recalcula os hashes de `root` do zero e compara contra `manifest`
    (que pode ter sido gerado em outro momento/lugar). Este e o uso
    tipico do verificador: 'este diretorio ainda bate com o manifesto
    assinado/publicado?'"""
    current = build_manifest(root)
    return diff_manifests(manifest, current)
