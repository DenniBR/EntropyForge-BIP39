#!/usr/bin/env python3
"""Red team: fuzzing de entropy<->mnemonic contra uma implementacao
BIP-39 INDEPENDENTE (aritmetica de inteiros/deslocamento de bits, em vez
da fatiamento de string usado em entropyforge/bip39.py), mais casos de
fronteira de bits e um fuzzer de mnemonic->entropy com adulteracoes
aleatorias.

A wordlist e lida diretamente do arquivo (I/O proprio), sem importar
`entropyforge.wordlist`, para nao reusar o mesmo codigo de carregamento.
"""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from entropyforge.bip39 import entropy_to_mnemonic, mnemonic_to_entropy, ChecksumError, Bip39Error  # noqa: E402

WORDLIST_PATH = REPO_ROOT / "entropyforge" / "data" / "english.txt"


def load_wordlist_independent() -> list[str]:
    with open(WORDLIST_PATH, "r", encoding="ascii") as f:
        words = [w for w in f.read().split("\n") if w]
    assert len(words) == 2048
    return words


WORDS = load_wordlist_independent()
INDEX = {w: i for i, w in enumerate(WORDS)}


def independent_entropy_to_mnemonic(entropy: bytes) -> str:
    """Implementacao BIP-39 via aritmetica de inteiros e deslocamento de
    bits (bit-shifting), deliberadamente DIFERENTE do metodo de
    concatenacao/fatiamento de strings binarias usado em bip39.py."""
    ent_bits = len(entropy) * 8
    if ent_bits not in (128, 160, 192, 224, 256):
        raise ValueError("comprimento de entropia invalido")
    cs_bits = ent_bits // 32
    ent_int = int.from_bytes(entropy, "big")
    checksum_full_byte = hashlib.sha256(entropy).digest()[0]
    checksum_int = checksum_full_byte >> (8 - cs_bits)  # top cs_bits bits do primeiro byte
    total_bits = ent_bits + cs_bits
    combined = (ent_int << cs_bits) | checksum_int
    num_words = total_bits // 11
    words = []
    for i in range(num_words):
        shift = total_bits - 11 * (i + 1)
        idx = (combined >> shift) & 0x7FF
        words.append(WORDS[idx])
    return " ".join(words)


def independent_mnemonic_to_entropy(mnemonic: str) -> bytes:
    words = mnemonic.split()
    num_words = len(words)
    if num_words not in (12, 15, 18, 21, 24):
        raise ValueError("numero de palavras invalido")
    total_bits = num_words * 11
    cs_bits = num_words // 3
    ent_bits = total_bits - cs_bits
    combined = 0
    for w in words:
        combined = (combined << 11) | INDEX[w]
    checksum_int = combined & ((1 << cs_bits) - 1)
    ent_int = combined >> cs_bits
    entropy = ent_int.to_bytes(ent_bits // 8, "big")
    expected_checksum = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    if checksum_int != expected_checksum:
        raise ValueError("checksum invalido (implementacao independente)")
    return entropy


def fuzz_random(trials: int) -> list[str]:
    problems = []
    for _ in range(trials):
        nbytes = os.urandom(1)[0] % 5 * 4 + 16  # 16,20,24,28,32
        entropy = os.urandom(nbytes)
        ours = entropy_to_mnemonic(entropy)
        indep = independent_entropy_to_mnemonic(entropy)
        if ours != indep:
            problems.append(f"MISMATCH entropy_to_mnemonic: {entropy.hex()} ours={ours!r} indep={indep!r}")
            continue
        back_ours = mnemonic_to_entropy(ours)
        back_indep = independent_mnemonic_to_entropy(indep)
        if back_ours != entropy or back_indep != entropy:
            problems.append(f"MISMATCH roundtrip: {entropy.hex()} back_ours={back_ours.hex()} back_indep={back_indep.hex()}")
    return problems


def fuzz_bit_boundaries() -> list[str]:
    """Casos de fronteira: cada posicao de bit ligada isoladamente, e
    varreduras ao redor dos limites de byte/grupo-de-11-bits, para as 5
    larguras de entropia suportadas."""
    problems = []
    for nbytes in (16, 20, 24, 28, 32):
        nbits = nbytes * 8
        # 1) cada bit individual ligado
        for bit in range(nbits):
            entropy = (1 << bit).to_bytes(nbytes, "big")
            ours = entropy_to_mnemonic(entropy)
            indep = independent_entropy_to_mnemonic(entropy)
            if ours != indep:
                problems.append(f"MISMATCH single-bit nbytes={nbytes} bit={bit}: ours={ours!r} indep={indep!r}")
            if mnemonic_to_entropy(ours) != entropy:
                problems.append(f"ROUNDTRIP-FAIL single-bit nbytes={nbytes} bit={bit}")
        # 2) todos os prefixos de 1s (0b1111...0000...)
        for k in range(nbits + 1):
            value = ((1 << k) - 1) << (nbits - k) if k > 0 else 0
            entropy = value.to_bytes(nbytes, "big")
            ours = entropy_to_mnemonic(entropy)
            indep = independent_entropy_to_mnemonic(entropy)
            if ours != indep:
                problems.append(f"MISMATCH prefix-ones nbytes={nbytes} k={k}")
    return problems


def fuzz_tampered_mnemonics(trials: int) -> list[str]:
    """Adultera aleatoriamente 1 palavra de mnemonics validos e confirma
    que AMBAS as implementacoes (independente e a do projeto) concordam
    sobre aceitar/rejeitar, e que nunca aceitam silenciosamente algo
    invalido."""
    problems = []
    for _ in range(trials):
        entropy = os.urandom(32)
        mnemonic = entropy_to_mnemonic(entropy)
        words = mnemonic.split()
        pos = os.urandom(1)[0] % len(words)
        new_idx = os.urandom(2)
        new_idx = int.from_bytes(new_idx, "big") % 2048
        words[pos] = WORDS[new_idx]
        tampered = " ".join(words)

        ours_ok = True
        try:
            ours_entropy = mnemonic_to_entropy(tampered)
        except Bip39Error:
            ours_ok = False

        indep_ok = True
        try:
            indep_entropy = independent_mnemonic_to_entropy(tampered)
        except ValueError:
            indep_ok = False

        if ours_ok != indep_ok:
            problems.append(f"DISAGREEMENT on tampered mnemonic: ours_ok={ours_ok} indep_ok={indep_ok} mnemonic={tampered!r}")
        elif ours_ok and indep_ok:
            if ours_entropy != indep_entropy:
                problems.append(f"BOTH ACCEPTED but produced different entropy: {tampered!r}")
            if ours_entropy == entropy:
                # coincidencia real (probabilidade ~2^-8 por palavra alterada
                # + reindexacao); nao e um problema, so registrar se ocorrer
                problems.append(f"INFO: tampered mnemonic coincidentally valid with SAME entropy: {tampered!r}")
    return problems


def main():
    print("=== fuzz aleatorio (10000 entropias, todos os tamanhos suportados) ===")
    problems = fuzz_random(10000)
    print(f"problemas: {len(problems)}")
    for p in problems[:20]:
        print(" ", p)

    print("\n=== fuzz de fronteiras de bit (bit unico + prefixos de 1s, todos os tamanhos) ===")
    problems2 = fuzz_bit_boundaries()
    print(f"problemas: {len(problems2)}")
    for p in problems2[:20]:
        print(" ", p)

    print("\n=== fuzz de mnemonics adulterados (5000 tentativas, 1 palavra trocada) ===")
    problems3 = fuzz_tampered_mnemonics(5000)
    real_problems = [p for p in problems3 if not p.startswith("INFO:")]
    info = [p for p in problems3 if p.startswith("INFO:")]
    print(f"problemas reais: {len(real_problems)}  (coincidencias esperadas e registradas: {len(info)})")
    for p in real_problems[:20]:
        print(" ", p)
    for p in info[:5]:
        print(" ", p)

    total = len(problems) + len(problems2) + len(real_problems)
    print(f"\nTOTAL DE PROBLEMAS REAIS ENCONTRADOS: {total}")
    return total


if __name__ == "__main__":
    sys.exit(1 if main() > 0 else 0)
