"""Inspecao INDEPENDENTE do artefato `.pyz` empacotado.

Um `.pyz` (zipapp, PEP 441) e um arquivo ZIP com um shebang opcional na
frente. Este modulo le esse arquivo com `zipfile` puro (biblioteca
padrao) e compara byte a byte cada entrada contra o codigo-fonte
correspondente em `entropyforge/` -- sem nunca executar o `.pyz`, sem
importar `entropyforge`, e sem usar `tools/build_pyz.py` (que e parte do
projeto sob teste e pode, ele mesmo, estar comprometido).

Isto e o controle mais forte deste verificador contra um artefato
adulterado: nao importa COMO o `.pyz` foi produzido (build honesto, build
malicioso, editado a mao depois) -- se o conteudo de cada arquivo dentro
dele bate byte a byte com o codigo-fonte que voce ja revisou e hasheou
independentemente, o artefato e, byte por byte, aquele codigo-fonte.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .hashing import ManifestEntry, build_manifest, hash_bytes

ZIP_MAGIC = b"PK\x03\x04"


class PyzFormatError(Exception):
    pass


@dataclass(frozen=True)
class PyzEntry:
    path: str
    size: int
    sha256: str


def _find_zip_start(data: bytes) -> int:
    idx = data.find(ZIP_MAGIC)
    if idx == -1:
        raise PyzFormatError("assinatura ZIP (PK\\x03\\x04) nao encontrada no arquivo")
    return idx


def read_pyz_entries(pyz_path: Path) -> tuple[bytes, dict[str, bytes]]:
    """Devolve (shebang_bytes, {path_interno: conteudo}). Le tudo via
    `zipfile`, sem extrair para disco (evita qualquer risco de
    "zip slip" e nao exige um diretorio temporario)."""
    data = pyz_path.read_bytes()
    zip_start = _find_zip_start(data)
    shebang = data[:zip_start]
    with zipfile.ZipFile(io.BytesIO(data[zip_start:])) as zf:
        # zipfile ja normaliza nomes, mas confirmamos explicitamente que
        # nenhuma entrada tenta escapar do diretorio raiz (defesa em
        # profundidade, mesmo sem extrair para disco).
        contents: dict[str, bytes] = {}
        for info in zf.infolist():
            name = info.filename
            if name.startswith("/") or ".." in Path(name).parts:
                raise PyzFormatError(f"entrada de zip suspeita (path traversal?): {name!r}")
            contents[name] = zf.read(info)
    return shebang, contents


def pyz_manifest(pyz_path: Path) -> list[PyzEntry]:
    _, contents = read_pyz_entries(pyz_path)
    return sorted(
        PyzEntry(path=name, size=len(data), sha256=hash_bytes(data)) for name, data in contents.items()
    )


@dataclass(frozen=True)
class PyzSourceComparison:
    matched: tuple[str, ...]  # arquivos que batem byte a byte
    content_mismatches: tuple[str, ...]  # mesmo path nos dois lados, hash diferente
    missing_from_pyz: tuple[str, ...]  # existe no source, deveria estar no pyz, nao esta
    unexpected_in_pyz: tuple[str, ...]  # existe no pyz mas nao corresponde a nenhum arquivo do source esperado
    expected_extra_files: tuple[str, ...] = field(default_factory=tuple)  # ex.: o __main__.py do bootstrap do zipapp

    @property
    def ok(self) -> bool:
        return not (self.content_mismatches or self.missing_from_pyz or self.unexpected_in_pyz)


def compare_pyz_to_source(
    pyz_path: Path,
    entropyforge_root: Path,
    *,
    expected_extra_files: frozenset[str] = frozenset({"__main__.py"}),
) -> PyzSourceComparison:
    """Compara cada arquivo `entropyforge/**` dentro do `.pyz` contra o
    hash independente do arquivo correspondente em `entropyforge_root`.

    `expected_extra_files` sao paths no `.pyz` que NAO tem correspondente
    no source (ex.: o `__main__.py` de bootstrap do zipapp, que e gerado
    pelo processo de build, nao versionado como arquivo de codigo do
    pacote). Eles aparecem em `expected_extra_files` no resultado, NUNCA
    silenciosamente ignorados -- o chamador decide se quer inspecionar o
    conteudo deles (ex.: com `static_scan.py`).
    """
    source_entries = {
        f"entropyforge/{e.path}": e
        for e in build_manifest(entropyforge_root, include_suffixes=(".py", ".txt"))
    }
    _, pyz_contents = read_pyz_entries(pyz_path)

    matched = []
    mismatches = []
    unexpected = []
    extra = []

    for path, data in pyz_contents.items():
        if path in source_entries:
            expected = source_entries[path]
            actual_hash = hash_bytes(data)
            if actual_hash == expected.sha256 and len(data) == expected.size:
                matched.append(path)
            else:
                mismatches.append(path)
        elif path in expected_extra_files:
            extra.append(path)
        else:
            unexpected.append(path)

    pyz_paths = set(pyz_contents)
    missing = sorted(set(source_entries) - pyz_paths)

    return PyzSourceComparison(
        matched=tuple(sorted(matched)),
        content_mismatches=tuple(sorted(mismatches)),
        missing_from_pyz=tuple(missing),
        unexpected_in_pyz=tuple(sorted(unexpected)),
        expected_extra_files=tuple(sorted(extra)),
    )



# O `__main__.py` de bootstrap do zipapp NAO tem arquivo-fonte
# correspondente em `entropyforge/` (e gerado por `tools/build_pyz.py`),
# entao `compare_pyz_to_source` o trata como "extra esperado" e NAO o
# compara a nada -- o que e exatamente o tipo de arquivo onde um atacante
# esconderia um payload (ver Fase 9 da auditoria). Por isso ele recebe
# uma checagem PROPRIA aqui, com o conteudo exato esperado copiado desta
# revisao do EntropyForge, independente de `tools/build_pyz.py` (se
# aquele script for adulterado para gerar um bootstrap malicioso, ainda
# assim o hash abaixo, fixado pelo VERIFICADOR, vai divergir).
EXPECTED_BOOTSTRAP_MAIN = (
    b'"""Ponto de entrada do artefato .pyz (gerado por tools/build_pyz.py)."""\n'
    b"import sys\n"
    b"from entropyforge.__main__ import run\n"
    b"\n"
    b'if __name__ == "__main__":\n'
    b"    sys.exit(run())\n"
)


def check_bootstrap_main(pyz_path: Path, *, path: str = "__main__.py") -> tuple[bool, str]:
    """Compara o `__main__.py` de bootstrap do `.pyz` contra o conteudo
    EXATO esperado (constante deste modulo, nao derivada de
    `tools/build_pyz.py`). Qualquer desvio -- mesmo um espaco a mais -- e
    reportado; nao tentamos "entender" o que o bootstrap adulterado faz,
    so recusamos aceitar como igual."""
    _, contents = read_pyz_entries(pyz_path)
    if path not in contents:
        return False, f"'{path}' nao encontrado no .pyz"
    actual = contents[path]
    if actual == EXPECTED_BOOTSTRAP_MAIN:
        return True, "bootstrap __main__.py bate exatamente com o esperado"
    return False, (
        f"bootstrap __main__.py DIVERGE do esperado "
        f"(esperado {len(EXPECTED_BOOTSTRAP_MAIN)} bytes, "
        f"sha256={hash_bytes(EXPECTED_BOOTSTRAP_MAIN)}; "
        f"obtido {len(actual)} bytes, sha256={hash_bytes(actual)})"
    )


def list_pyz_python_modules(pyz_path: Path) -> list[str]:
    """Lista todos os arquivos `.py` dentro do `.pyz`, para inspecao
    manual/automatica de modulos inesperados (`sitecustomize.py`,
    `usercustomize.py`, um modulo com nome disfarçado, etc.)."""
    _, contents = read_pyz_entries(pyz_path)
    return sorted(p for p in contents if p.endswith(".py"))
