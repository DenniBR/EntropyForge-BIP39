#!/usr/bin/env python3
"""Re-derivacao matematica INDEPENDENTE (Fase D, secao 2).

Este script NAO importa nada de entropyforge/ ou independent-verifier/.
Toda formula e reimplementada do zero, a partir da especificacao (BIP-39,
definicoes de entropia de Shannon/min-entropia), para servir de segunda
fonte independente contra as contas de docs/MATH.md e
entropyforge/entropy_calc.py.
"""
import math


def log2(x):
    return math.log(x, 2)


# ---------------------------------------------------------------------
# 1. Entropia de um lancamento de d6
# ---------------------------------------------------------------------
print("=== 1. Entropia de Shannon de um d6 honesto ===")
H_d6 = -sum((1 / 6) * log2(1 / 6) for _ in range(6))
print(f"H(d6) = -sum p*log2(p) sobre 6 faces uniformes = {H_d6!r}")
print(f"log2(6) direto                                  = {log2(6)!r}")
assert abs(H_d6 - log2(6)) < 1e-12
print("Confirmado: H(d6 uniforme) == log2(6) (a uniforme MAXIMIZA a entropia")
print("de Shannon sobre um alfabeto de 6 simbolos -- desigualdade de Gibbs).")
print()

# ---------------------------------------------------------------------
# 2. rolls_for_shannon_bits(256) e rolls_for_shannon_bits(128)
# ---------------------------------------------------------------------
print("=== 2. n minimo para X bits teoricos (d6 honesto e i.i.d.) ===")
for target in (128, 256):
    n = math.ceil(target / log2(6))
    bits_at_n = n * log2(6)
    print(f"target={target}: n = ceil({target}/log2(6)) = {n}, bits em n = {bits_at_n:.6f}")
assert math.ceil(256 / log2(6)) == 100
assert math.ceil(128 / log2(6)) == 50
print("Confirmado: 100 lancamentos para 256 bits teoricos, 50 para 128.")
print()

# ---------------------------------------------------------------------
# 3. Min-entropia com viés (p_max = 0.20) e n para 256 bits de min-entropia
# ---------------------------------------------------------------------
print("=== 3. Min-entropia H_inf(n) = -n*log2(p_max) ===")
p_max = 0.20
n_min_entropy_256 = math.ceil(256 / (-log2(p_max)))
print(f"p_max={p_max}: -log2(p_max) = {-log2(p_max):.6f} bits/lancamento")
print(f"n para 256 bits de min-entropia (sem descontar vazamento) = {n_min_entropy_256}")
print()

# ---------------------------------------------------------------------
# 4. Vazamento do relatorio publico: L(n) = log2 C(n+5,5) + 6*log2(3)
# ---------------------------------------------------------------------
print("=== 4. Vazamento do relatorio publico (regra da cadeia DORS 2004) ===")


def report_leak_bits(n, num_verdict_tests=6):
    if n == 0:
        return 0.0
    faces_leak = log2(math.comb(n + 5, 5))
    verdict_leak = num_verdict_tests * log2(3)
    return faces_leak + verdict_leak


for n in (100, 127, 600):
    L = report_leak_bits(n)
    print(f"n={n}: L(n) = log2(C(n+5,5)) + 6*log2(3) = {L:.4f} bits")
print()

# ---------------------------------------------------------------------
# 5. n operacional: menor n tal que H_inf(n,p_max) - L(n) >= 256
# ---------------------------------------------------------------------
print("=== 5. n operacional recomendado (generate) ===")


def rolls_for_operational_target(target_bits, p_max, num_verdict_tests=6):
    n = math.ceil(target_bits / (-log2(p_max)))
    while (-n * log2(p_max)) - report_leak_bits(n, num_verdict_tests) < target_bits:
        n += 1
    return n


n_op = rolls_for_operational_target(256, 0.20)
print(f"n_operacional = {n_op}")
h_inf_at_n = -n_op * log2(p_max)
leak_at_n = report_leak_bits(n_op)
print(f"  H_inf({n_op}, 0.20) = {h_inf_at_n:.4f} bits")
print(f"  L({n_op})           = {leak_at_n:.4f} bits")
print(f"  residual            = {h_inf_at_n - leak_at_n:.4f} bits (deve ser >= 256)")
assert h_inf_at_n - leak_at_n >= 256
# confirma que n_op - 1 FALHARIA (n_op e minimo, nao so suficiente)
h_inf_prev = -(n_op - 1) * log2(p_max)
leak_prev = report_leak_bits(n_op - 1)
print(f"  checagem de minimalidade: n-1={n_op - 1} da residual "
      f"{h_inf_prev - leak_prev:.4f} bits (deve ser < 256)")
assert h_inf_prev - leak_prev < 256
print()

# ---------------------------------------------------------------------
# 6. BIP-39: CS, MS para os 5 tamanhos validos de entropia
# ---------------------------------------------------------------------
print("=== 6. BIP-39: relacao ENT / CS / MS para todos os tamanhos validos ===")
for ent_bits in (128, 160, 192, 224, 256):
    cs_bits = ent_bits // 32
    ms_words = (ent_bits + cs_bits) // 11
    assert (ent_bits + cs_bits) % 11 == 0, "ENT+CS deve ser multiplo de 11"
    print(f"ENT={ent_bits:3d} bits -> CS={cs_bits} bits -> MS=(ENT+CS)/11={ms_words} palavras")
assert (256 // 32) == 8
assert (256 + 8) // 11 == 24
print("Confirmado: ENT=256 -> CS=8 bits -> MS=24 palavras.")
print()

# ---------------------------------------------------------------------
# 7. Probabilidade de uma adulteracao aleatoria de 1 palavra escapar do checksum
# ---------------------------------------------------------------------
print("=== 7. Deteccao de adulteracao pelo checksum (CS=8 bits) ===")
cs_bits = 8
p_escape = 2 ** (-cs_bits)
print(f"P(adulteracao aleatoria de E ainda produz checksum valido) = 2^-{cs_bits} = {p_escape}")
print(f"P(deteccao) = 1 - 2^-{cs_bits} = {1 - p_escape}")
print("NOTA: isto vale para uma alteracao ALEATORIA e uniforme do valor de E/bits.")
print("Uma alteracao ESTRUTURADA (trocar 1 palavra por outra do dicionario,")
print("mudando 11 bits especificos) tem a MESMA probabilidade de escape --")
print("ver verificacao empirica abaixo (secao 7b).")
print()

# 7b. Verificacao empirica: trocar 1 palavra de um mnemonic valido por outra
# palavra aleatoria do dicionario (das 2047 restantes) e contar quantas
# ainda produzem checksum valido. Reimplementacao INDEPENDENTE do check
# (nao usa entropyforge.bip39 nem verifier.bip39_min).
import hashlib
import random


def independent_checksum_bits(entropy: bytes, cs_bits: int) -> int:
    digest = hashlib.sha256(entropy).digest()
    full = int.from_bytes(digest, "big")
    top_bits = full >> (256 - cs_bits)
    return top_bits


def independent_entropy_to_bits_int(entropy: bytes, cs_bits: int) -> int:
    ent_int = int.from_bytes(entropy, "big")
    return (ent_int << cs_bits) | independent_checksum_bits(entropy, cs_bits)


def independent_words(combined_bits: int, total_bits: int, n_words: int):
    words = []
    for i in range(n_words):
        shift = total_bits - (i + 1) * 11
        idx = (combined_bits >> shift) & 0x7FF
        words.append(idx)
    return words


def independent_bits_to_entropy_and_checksum(word_indices, ent_bits, cs_bits):
    combined = 0
    for idx in word_indices:
        combined = (combined << 11) | idx
    total_bits = ent_bits + cs_bits
    checksum_val = combined & ((1 << cs_bits) - 1)
    entropy_val = combined >> cs_bits
    entropy = entropy_val.to_bytes(ent_bits // 8, "big")
    return entropy, checksum_val


rng = random.Random(20260927)  # seed fixa, documentada, so para este estudo
ent_bits = 256
cs_bits = 8
n_words = 24
trials = 5000
escapes = 0
for _ in range(trials):
    entropy = bytes(rng.randrange(256) for _ in range(ent_bits // 8))
    combined = independent_entropy_to_bits_int(entropy, cs_bits)
    words = independent_words(combined, ent_bits + cs_bits, n_words)
    # troca 1 palavra aleatoria por outro indice aleatorio diferente
    pos = rng.randrange(n_words)
    new_idx = rng.randrange(2048)
    while new_idx == words[pos]:
        new_idx = rng.randrange(2048)
    tampered = list(words)
    tampered[pos] = new_idx
    recovered_entropy, recovered_checksum = independent_bits_to_entropy_and_checksum(tampered, ent_bits, cs_bits)
    expected_checksum = independent_checksum_bits(recovered_entropy, cs_bits)
    if recovered_checksum == expected_checksum:
        escapes += 1

print(f"=== 7b. Verificacao empirica (independente, {trials} tentativas) ===")
print(f"trocas de 1 palavra que ESCAPARAM do checksum: {escapes}/{trials} = {escapes / trials:.6f}")
print(f"esperado teorico (2^-8)                        = {p_escape:.6f}")
print()

# ---------------------------------------------------------------------
# 8. Nota tecnica do Flajolet-Odlyzko (docs/MATH.md 5.3) -- recalculo independente
# ---------------------------------------------------------------------
print("=== 8. Recalculo independente de E[K log2 K], K ~ Poisson(1) ===")
# soma direta da serie ate convergencia numerica
import math as _m

total = 0.0
term_sum_check = 0.0
k = 1
while True:
    pk = (_m.e ** -1) / _m.factorial(k)
    term = pk * k * log2(k)
    total += term
    term_sum_check += pk
    if pk < 1e-18 and k > 5:
        break
    k += 1
print(f"E[K log2 K] (K~Poisson(1)) somado ate convergencia = {total:.6f} bits")
print("valor citado em docs/MATH.md (Flajolet-Odlyzko)     = 0.8272 bits")
assert abs(total - 0.8272) < 1e-3
N = 2 ** 256
H_Y = log2(N) - total
print(f"H(Y) para N=2^256 = log2(N) - E[K log2 K] = {H_Y:.4f} bits (docs/MATH.md cita 255.17)")
assert abs(H_Y - 255.17) < 0.01
print()
print("=== FIM: todas as afirmacoes numericas de docs/MATH.md/entropy_calc.py")
print("reproduzidas de forma INDEPENDENTE (nenhum import de entropyforge/).")
