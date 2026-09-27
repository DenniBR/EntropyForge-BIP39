"""Verificacao INDEPENDENTE da wordlist BIP-39 embutida no EntropyForge.

Nao importa `entropyforge.wordlist`. Le o arquivo `entropyforge/data/english.txt`
diretamente do disco (ou de um `.pyz`, via `pyz_inspect.py`) e reimplementa,
com codigo proprio, as mesmas checagens que um projeto de qualidade
esperaria de uma wordlist BIP-39 -- para nao depender de que a
implementacao de `entropyforge.wordlist` esteja correta ou honesta.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

EXPECTED_WORD_COUNT = 2048

# Hash oficial da wordlist em ingles do BIP-39, conferido de forma
# independente (nesta auditoria) contra
# github.com/bitcoin/bips/blob/master/bip-0039/english.txt em 2026-09-27.
# Mantido aqui como uma constante SEPARADA da de `entropyforge.wordlist`
# -- se algum dia divergirem, isso por si so e um sinal de alerta (ver
# `check_matches_official_hash`).
KNOWN_OFFICIAL_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"


@dataclass(frozen=True)
class WordlistReport:
    ok: bool
    word_count: int
    problems: tuple[str, ...] = field(default_factory=tuple)
    sha256: str = ""


def _sha256_of_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def check_wordlist_bytes(raw: bytes) -> WordlistReport:
    """Roda todas as checagens independentes sobre os BYTES BRUTOS do
    arquivo da wordlist (nao sobre uma lista ja parseada por outra
    biblioteca -- isso importa: se o parsing de `entropyforge.wordlist`
    tivesse um bug que escondesse uma palavra invalida, verificar so a
    lista ja parseada por ELE herdaria o mesmo bug)."""
    problems: list[str] = []

    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        return WordlistReport(
            ok=False,
            word_count=0,
            problems=(f"arquivo nao e ASCII puro: {exc}",),
            sha256=_sha256_of_bytes(raw),
        )

    digest = _sha256_of_bytes(raw)

    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]  # tolera um \n final, como qualquer editor de texto POSIX produz
    words = lines

    if len(words) != EXPECTED_WORD_COUNT:
        problems.append(f"esperado {EXPECTED_WORD_COUNT} palavras, encontrado {len(words)}")

    if len(set(words)) != len(words):
        seen = set()
        dupes = set()
        for w in words:
            if w in seen:
                dupes.add(w)
            seen.add(w)
        problems.append(f"palavras duplicadas: {sorted(dupes)[:10]}")

    if words != sorted(words):
        problems.append("wordlist nao esta em ordem alfabetica (ordenacao ASCII)")

    for i, w in enumerate(words):
        if not w:
            problems.append(f"linha {i}: palavra vazia")
            continue
        if not w.isascii():
            problems.append(f"linha {i}: palavra nao-ASCII: {w!r}")
        if w != w.lower():
            problems.append(f"linha {i}: palavra nao esta em minusculas: {w!r}")
        if not w.isalpha():
            problems.append(f"linha {i}: palavra contem caractere nao-alfabetico: {w!r}")
        if not (3 <= len(w) <= 8):
            problems.append(f"linha {i}: comprimento de palavra fora do esperado (3-8): {w!r}")

    prefixes = {w[:4] for w in words}
    if len(prefixes) != len(words):
        problems.append("prefixos de 4 letras nao sao unicos (ambiguidade em implementacoes que truncam)")

    return WordlistReport(ok=(len(problems) == 0), word_count=len(words), problems=tuple(problems), sha256=digest)


def check_wordlist_file(path: Path) -> WordlistReport:
    return check_wordlist_bytes(path.read_bytes())


def check_matches_official_hash(report: WordlistReport) -> tuple[bool, str]:
    """Compara o hash calculado pelo VERIFICADOR (nao pelo EntropyForge)
    contra a constante `KNOWN_OFFICIAL_SHA256` deste modulo. Devolve
    (bate, mensagem)."""
    if report.sha256 == KNOWN_OFFICIAL_SHA256:
        return True, "hash bate com a wordlist oficial BIP-39 conhecida pelo verificador"
    return False, (
        f"hash NAO bate: verificador calculou {report.sha256}, "
        f"esperava {KNOWN_OFFICIAL_SHA256} (wordlist pode ter sido adulterada, "
        "ou e uma wordlist diferente/mais nova -- investigue antes de confiar)"
    )
