"""Implementacao BIP-39 MINIMA e INDEPENDENTE, usada SOMENTE para
verificacao cruzada (nunca para gerar uma carteira real).

Deliberadamente escrita com uma tecnica DIFERENTE da usada em
`entropyforge/bip39.py` (que concatena e fatiaMio uma string de '0'/'1'):
aqui, a entropia e o checksum sao combinados como um UNICO INTEIRO
gigante e os indices de 11 bits sao extraidos por deslocamento de bits
(`>>` e `&`). Se as duas implementacoes, escritas de formas diferentes a
partir da mesma especificacao, concordarem em milhares de casos e em
todos os vetores oficiais, isso e evidencia muito mais forte de
corretude do que uma unica implementacao "elegante" checada por seus
proprios testes.

Especificacao seguida: bitcoin/bips, bip-0039.mediawiki. Sem nenhum
import de `entropyforge`.
"""

from __future__ import annotations

import hashlib

VALID_ENTROPY_BYTES = (16, 20, 24, 28, 32)
VALID_WORD_COUNTS = (12, 15, 18, 21, 24)


class Bip39MinError(ValueError):
    pass


def _checksum_bit_count(entropy_bytes: int) -> int:
    # CS = ENT / 32, com ENT em bits = entropy_bytes * 8
    return (entropy_bytes * 8) // 32


def entropy_to_mnemonic(entropy: bytes, wordlist: list[str]) -> str:
    if len(wordlist) != 2048:
        raise Bip39MinError(f"wordlist deve ter 2048 palavras, tem {len(wordlist)}")
    if len(entropy) not in VALID_ENTROPY_BYTES:
        raise Bip39MinError(f"entropia deve ter {VALID_ENTROPY_BYTES} bytes, tem {len(entropy)}")

    ent_bits = len(entropy) * 8
    cs_bits = _checksum_bit_count(len(entropy))
    total_bits = ent_bits + cs_bits
    num_words = total_bits // 11

    entropy_int = int.from_bytes(entropy, byteorder="big")
    checksum_full_byte = hashlib.sha256(entropy).digest()[0]
    checksum_bits_value = checksum_full_byte >> (8 - cs_bits)  # os cs_bits mais significativos do 1o byte

    combined = (entropy_int << cs_bits) | checksum_bits_value

    words = []
    for word_index in range(num_words):
        # extrai o grupo de 11 bits mais significativo ainda nao consumido
        shift = total_bits - 11 * (word_index + 1)
        eleven_bits = (combined >> shift) & 0b111_1111_1111
        words.append(wordlist[eleven_bits])
    return " ".join(words)


def mnemonic_to_entropy(mnemonic: str, wordlist: list[str]) -> bytes:
    if len(wordlist) != 2048:
        raise Bip39MinError(f"wordlist deve ter 2048 palavras, tem {len(wordlist)}")
    index_of = {w: i for i, w in enumerate(wordlist)}

    words = mnemonic.split()
    if len(words) not in VALID_WORD_COUNTS:
        raise Bip39MinError(f"mnemonic deve ter {VALID_WORD_COUNTS} palavras, tem {len(words)}")

    combined = 0
    for w in words:
        if w not in index_of:
            raise Bip39MinError(f"palavra fora da wordlist: {w!r}")
        combined = (combined << 11) | index_of[w]

    total_bits = len(words) * 11
    cs_bits = len(words) // 3  # MS = 33*CS/11 = 3*CS  =>  CS = MS/3
    ent_bits = total_bits - cs_bits
    if ent_bits % 8 != 0:
        raise Bip39MinError("numero de bits de entropia nao e multiplo de 8 (inconsistencia interna)")

    checksum_mask = (1 << cs_bits) - 1
    checksum_value = combined & checksum_mask
    entropy_int = combined >> cs_bits
    entropy = entropy_int.to_bytes(ent_bits // 8, byteorder="big")

    expected_checksum_full_byte = hashlib.sha256(entropy).digest()[0]
    expected_checksum_value = expected_checksum_full_byte >> (8 - cs_bits)
    if checksum_value != expected_checksum_value:
        raise Bip39MinError(
            f"checksum nao confere: mnemonic tem {checksum_value:0{cs_bits}b}, "
            f"esperado {expected_checksum_value:0{cs_bits}b}"
        )
    return entropy


def is_valid_mnemonic(mnemonic: str, wordlist: list[str]) -> bool:
    try:
        mnemonic_to_entropy(mnemonic, wordlist)
        return True
    except Bip39MinError:
        return False
