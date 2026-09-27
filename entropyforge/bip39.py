"""Implementacao da especificacao BIP-39 (geracao de mnemonic a partir de
entropia, com checksum, e a funcao independente de derivacao de seed).

Especificacao oficial:
    https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

Resumo do algoritmo (para ENT bits de entropia):

    CS   = ENT / 32                       (bits de checksum)
    bits = entropy_bits || sha256(entropy)[0 : CS]     (ENT + CS bits)
    MS   = (ENT + CS) / 11                (numero de palavras)
    cada grupo de 11 bits de `bits`, MSB primeiro, e o indice (0..2047)
    de uma palavra na wordlist.

Este projeto usa exclusivamente ENT = 256 (24 palavras), mas as funcoes
abaixo implementam a especificacao completa (128/160/192/224/256 bits)
porque os vetores de teste oficiais cobrem todos esses tamanhos, e uma
implementacao "so para 256 bits" seria mais dificil de validar de ponta a
ponta contra esses vetores.

IMPORTANTE — o que este modulo NAO faz:
    A derivacao da seed (`mnemonic_to_seed`, PBKDF2-HMAC-SHA512) e fornecida
    aqui apenas para permitir testes de round-trip contra os vetores
    oficiais (ver docs/DESIGN.md, decisao D6). O fluxo `generate` do CLI
    NUNCA chama `mnemonic_to_seed`: a derivacao da seed e feita pela
    carteira do usuario, com a passphrase (opcional) que so o usuario
    conhece. `entropy_to_mnemonic` e `mnemonic_to_entropy` sao as funcoes
    realmente usadas pelo produto.
"""

from __future__ import annotations

import hashlib
import unicodedata

from .wordlist import load_wordlist, word_to_index

VALID_ENTROPY_BIT_LENGTHS = (128, 160, 192, 224, 256)
VALID_WORD_COUNTS = (12, 15, 18, 21, 24)

# O checksum de uma entropia BIP-39 nunca passa de ENT/32 = 256/32 = 8 bits,
# entao sempre cabe no primeiro byte de SHA-256(entropia).
_MAX_CHECKSUM_BITS = 256 // 32


class Bip39Error(ValueError):
    """Erro generico de formato/uso da especificacao BIP-39."""


class ChecksumError(Bip39Error):
    """O checksum embutido no mnemonic nao confere com a entropia."""


def _bytes_to_bitstring(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def _checksum_bits(entropy: bytes, num_bits: int) -> str:
    first_byte = hashlib.sha256(entropy).digest()[0]
    return f"{first_byte:08b}"[:num_bits]


def entropy_to_mnemonic(entropy: bytes) -> str:
    """Converte bytes de entropia em uma frase mnemonic BIP-39.

    `entropy` deve ter exatamente 16, 20, 24, 28 ou 32 bytes (128..256 bits,
    em passos de 32). Este projeto usa sempre 32 bytes (256 bits, mnemonic
    de 24 palavras).
    """
    ent_bits = len(entropy) * 8
    if ent_bits not in VALID_ENTROPY_BIT_LENGTHS:
        raise Bip39Error(
            f"entropia deve ter {VALID_ENTROPY_BIT_LENGTHS} bits, "
            f"recebeu {ent_bits} bits ({len(entropy)} bytes)"
        )
    cs_bits = ent_bits // 32
    bits = _bytes_to_bitstring(entropy) + _checksum_bits(entropy, cs_bits)
    assert len(bits) % 11 == 0  # invariante da especificacao BIP-39

    wordlist = load_wordlist()
    words = [
        wordlist[int(bits[i : i + 11], 2)] for i in range(0, len(bits), 11)
    ]
    return " ".join(words)


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """Converte um mnemonic BIP-39 de volta para os bytes de entropia.

    Verifica o checksum; levanta `ChecksumError` se ele nao conferir e
    `Bip39Error` para formato invalido (numero de palavras errado, palavra
    fora da wordlist).
    """
    words = mnemonic.split()
    n = len(words)
    if n not in VALID_WORD_COUNTS:
        raise Bip39Error(
            f"mnemonic deve ter {VALID_WORD_COUNTS} palavras, recebeu {n}"
        )

    try:
        bits = "".join(f"{word_to_index(w):011b}" for w in words)
    except ValueError as exc:
        raise Bip39Error(str(exc)) from exc

    total_bits = len(bits)
    cs_bits = total_bits // 33  # MS = 33*CS/11 = 3*CS  =>  CS = MS/3
    ent_bits = total_bits - cs_bits
    if ent_bits not in VALID_ENTROPY_BIT_LENGTHS:
        # So pode acontecer se VALID_WORD_COUNTS e VALID_ENTROPY_BIT_LENGTHS
        # ficarem inconsistentes entre si; ambos sao constantes deste
        # modulo, entao isto e defesa em profundidade, nao um caso de uso.
        raise Bip39Error("numero de palavras nao corresponde a nenhum ENT valido")

    entropy_bits = bits[:ent_bits]
    checksum_bits = bits[ent_bits:]
    entropy = int(entropy_bits, 2).to_bytes(ent_bits // 8, "big")

    expected = _checksum_bits(entropy, cs_bits)
    if checksum_bits != expected:
        raise ChecksumError(
            "checksum do mnemonic nao confere: o mnemonic foi digitado "
            "errado, esta incompleto, ou nao foi gerado por este processo"
        )
    return entropy


def is_valid_mnemonic(mnemonic: str) -> bool:
    """True se `mnemonic` tem formato e checksum BIP-39 validos."""
    try:
        mnemonic_to_entropy(mnemonic)
        return True
    except Bip39Error:
        return False


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048, 64 bytes).

    Implementa a derivacao de seed da especificacao BIP-39, usada SOMENTE
    pela suite de testes (para validar contra os vetores oficiais, que
    incluem a seed esperada com a passphrase de teste "TREZOR"). O CLI deste
    projeto (`entropyforge generate`) nunca chama esta funcao: ela fica fora
    do fluxo que toca segredos reais (ver docs/DESIGN.md, decisao D6).

    Note: esta funcao NAO valida o checksum do mnemonic (a especificacao
    BIP-39 tambem nao exige isso para a derivacao da seed).
    """
    mnemonic_norm = unicodedata.normalize("NFKD", mnemonic)
    passphrase_norm = unicodedata.normalize("NFKD", passphrase)
    salt = ("mnemonic" + passphrase_norm).encode("utf-8")
    return hashlib.pbkdf2_hmac(
        "sha512", mnemonic_norm.encode("utf-8"), salt, 2048, dklen=64
    )
