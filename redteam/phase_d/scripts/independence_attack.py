#!/usr/bin/env python3
"""Fase D, secao 5: ataque a independencia -- construir P(X_n | passado)
NAO uniforme mas com frequencia marginal, autocorrelacao simples, runs e
transicoes agregadas todas "saudaveis" o suficiente para nao disparar a
bateria.

Construcao usada: digitos exatos de sqrt(2) em base 6 (calculados com
aritmetica inteira de precisao arbitraria via isqrt -- SEM erro de ponto
flutuante), mapeados para faces 1-6. Isto e mais forte que um mapeamento
"digitos decimais de pi mod 6" (tentado na secao 3 como modelo J): mod 6
sobre digitos DECIMAIS introduz um vies estrutural obvio (10 nao e
multiplo de 6, entao os residuos 0-3 saem com o dobro da frequencia de
4-5), que e facilmente pego por T1. Os digitos em base 6 NATIVA de um
numero irracional nao tem esse problema por construcao.

Isto e 100% deterministico e tem ZERO bits de entropia real para qualquer
atacante que saiba (a) que a fonte e "digitos de sqrt(2) em base 6" e (b)
o deslocamento inicial usado -- mas conjectura-se (nao ha prova) que
numeros algebricos irracionais como sqrt(2) sao "normais" (digitos
equidistribuidos em qualquer base), entao NENHUM teste estatistico de
tempo polinomial deveria conseguir distingui-los de uma fonte real.
"""
import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from entropyforge import stats  # noqa: E402


def sqrt2_base6_digits(n_digits: int, offset: int = 0) -> str:
    """Digitos de sqrt(2) em base 6 (apos o ponto senario), calculados
    com isqrt (precisao inteira exata, sem float). Devolve `n_digits`
    digitos comecando em `offset` (0 = primeiro digito fracionario)."""
    total = offset + n_digits + 5  # margem de seguranca
    # floor(6^total * sqrt(2)) = isqrt(2 * 6^(2*total))
    big = math.isqrt(2 * (6 ** (2 * total)))
    s = str_base6(big, total + 1)  # +1 pela parte inteira ("1")
    frac_digits = s[1:]  # descarta a parte inteira
    return frac_digits[offset: offset + n_digits]


def str_base6(value: int, num_digits: int) -> str:
    digits = []
    for _ in range(num_digits):
        digits.append(value % 6)
        value //= 6
    return "".join(str(d) for d in reversed(digits))


def digits_to_faces(digits: str) -> str:
    # digito 0-5 -> face 1-6
    return "".join(str(int(c) + 1) for c in digits)


def verdict_detail(seq: str):
    b = stats.run_battery(seq)
    return b


N_LIST = [127, 600, 3000]
OFFSETS = (0, 10_000, 50_000)
print("=== Ataque de independencia: digitos de sqrt(2) em base 6 ===\n")
for offset in OFFSETS:
    # calcula os digitos UMA VEZ por offset, no maior n necessario, e fatia
    # para os n's menores -- evita recomputar o isqrt gigante 3x por offset
    max_n = max(N_LIST)
    digits6_full = sqrt2_base6_digits(max_n, offset=offset)
    for n in N_LIST:
        faces = digits_to_faces(digits6_full[:n])
        b = verdict_detail(faces)
        counts = b.face_counts
        print(f"n={n:5d} offset={offset:8d}: overall={b.overall_verdict.value:5s} "
              f"contagens={counts}")
        for t in b.tests:
            marker = "  " if t.verdict.value == "PASS" else ("**" if t.verdict.value == "FAIL" else "~~")
            print(f"    {marker} {t.name:24s} p={t.p_value:.4f} veredito={t.verdict.value}")
    print()

print("=== Controle: mesmo teste em sequencias i.i.d. honestas (para comparar taxa) ===")
rng = random.Random(20260927)
fails = warns = passes = 0
for _ in range(200):
    seq = "".join(str(rng.randint(1, 6)) for _ in range(127))
    v = stats.run_battery(seq).overall_verdict.value
    if v == "FAIL":
        fails += 1
    elif v == "WARN":
        warns += 1
    else:
        passes += 1
print(f"honesto i.i.d. (n=127, 200 tentativas): FAIL={fails} WARN={warns} PASS={passes}")

print()
print("=== Interpretacao ===")
print("Se sqrt(2) em base 6 passar (PASS/WARN) na mesma taxa que sequencias")
print("honestas i.i.d., isso confirma que a bateria estatistica NAO CONSEGUE")
print("distinguir uma fonte com ZERO entropia real (qualquer um que saiba a")
print("formula e o offset pode prever a sequencia exata) de uma fonte")
print("genuinamente aleatoria -- o mesmo limite estrutural ja documentado")
print("(stats.py, docstring) e confirmado empiricamente para K (PRNG com")
print("seed conhecida, secao 3), agora tambem para uma CONSTANTE MATEMATICA")
print("PUBLICA, sem nenhum software de geracao de numeros envolvido.")
