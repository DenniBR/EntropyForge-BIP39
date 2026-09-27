"""Carregamento e verificacao da wordlist oficial do BIP-39 (ingles).

A wordlist e um dado PUBLICO (nao e segredo): e a mesma lista de 2048
palavras usada por toda carteira compativel com BIP-39. O risco relevante
aqui nao e confidencialidade, e sim INTEGRIDADE: se um atacante trocar uma
palavra da lista (ataque de supply chain, ver docs/THREAT_MODEL.md), o
mnemonic gerado pode nao ser reconhecido por outra implementacao, ou pior,
pode ser reconhecido de forma sutilmente diferente. Por isso o arquivo e
conferido por hash a cada carregamento.

Fonte oficial: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
Hash conferido nesta revisao do codigo (SHA-256):
    2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
"""

from __future__ import annotations

import hashlib
import importlib.resources
from functools import lru_cache

WORDLIST_SHA256 = (
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
)
EXPECTED_WORD_COUNT = 2048

# A wordlist fica DENTRO do pacote (entropyforge/data/english.txt), nao ao
# lado dele, e e lida via `importlib.resources` (em vez de um caminho de
# sistema de arquivos com `pathlib.Path`) porque isto precisa funcionar
# tanto rodando de um diretorio normal quanto de dentro do artefato
# `.pyz` empacotado (zipimport), onde nao existe um "caminho de arquivo"
# de verdade para o `Path.read_bytes()` comum abrir.
_PACKAGE = __package__ or "entropyforge"


class WordlistError(Exception):
    """A wordlist embutida falhou em alguma verificacao de integridade."""


def _read_wordlist_bytes() -> bytes:
    try:
        resource = importlib.resources.files(_PACKAGE) / "data" / "english.txt"
        return resource.read_bytes()
    except OSError as exc:
        raise WordlistError(f"nao foi possivel ler a wordlist embutida no pacote {_PACKAGE!r}") from exc


def _validate(words: list[str], raw: bytes) -> None:
    digest = hashlib.sha256(raw).hexdigest()
    if digest != WORDLIST_SHA256:
        raise WordlistError(
            "hash da wordlist nao confere: esperado "
            f"{WORDLIST_SHA256}, obtido {digest}. O arquivo data/english.txt "
            "pode ter sido alterado."
        )
    if len(words) != EXPECTED_WORD_COUNT:
        raise WordlistError(
            f"wordlist deve ter exatamente {EXPECTED_WORD_COUNT} palavras, "
            f"tem {len(words)}"
        )
    if len(set(words)) != len(words):
        raise WordlistError("wordlist contem palavras duplicadas")
    if words != sorted(words):
        raise WordlistError("wordlist nao esta em ordem alfabetica")
    for w in words:
        if not w or not w.isascii() or not w.islower() or not w.isalpha():
            raise WordlistError(f"palavra invalida na wordlist: {w!r}")
    prefixes = {w[:4] for w in words}
    if len(prefixes) != len(words):
        raise WordlistError(
            "wordlist perdeu a propriedade de prefixos de 4 letras unicos"
        )


@lru_cache(maxsize=1)
def load_wordlist() -> tuple[str, ...]:
    """Carrega, verifica e devolve a wordlist oficial (2048 palavras).

    Levanta WordlistError se qualquer verificacao de integridade falhar.
    O resultado e cacheado em memoria (a wordlist nao muda durante a
    execucao do processo).
    """
    raw = _read_wordlist_bytes()
    text = raw.decode("ascii")
    words = text.split("\n")
    if words and words[-1] == "":
        words = words[:-1]
    _validate(words, raw)
    return tuple(words)


@lru_cache(maxsize=1)
def _index_map() -> dict[str, int]:
    return {w: i for i, w in enumerate(load_wordlist())}


def word_to_index(word: str) -> int:
    """Indice (0..2047) de uma palavra na wordlist, ou ValueError."""
    try:
        return _index_map()[word]
    except KeyError as exc:
        raise ValueError(f"palavra fora da wordlist BIP-39: {word!r}") from exc
