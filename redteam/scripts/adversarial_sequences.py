#!/usr/bin/env python3
"""Red team: sequencias adversariais de d6 contra a bateria estatistica.

Gera sequencias DETERMINISTICAS (entropia real ~= 0, ou muito baixa e
conhecida) desenhadas para tentar passar em `entropyforge.stats.run_battery`,
e mede o resultado. Nenhuma delas usa dados reais de carteira; sao todas
construcoes puramente deterministicas ou com semente fixa, documentada.

Uso: python3 redteam/scripts/adversarial_sequences.py
"""
from __future__ import annotations

import itertools
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from entropyforge import stats, entropy_calc
from entropyforge.stats import Verdict

N_OPERATIONAL = entropy_calc.compute_budget().rolls_operational  # ~127


def digits_of_pi_base6(n: int) -> str:
    """Digitos de pi em base 6, calculados com aritmetica de inteiros
    exata (algoritmo "spigot" simplificado via mpmath-free serie de
    Leibniz-like nao seria preciso o bastante; usamos aqui o metodo dos
    digitos de pi via a formula de Bailey-Borwein-Plouffe adaptada, ou,
    mais simples e totalmente determinista/reproduzivel: multiplicamos pi
    (obtido via a serie de Machin, com precisao de inteiros grande) por
    potencias de 6 e extraimos digitos sucessivos)."""
    # calcula pi com precisao alta usando a formula de Machin, so com
    # inteiros (escala fixa), para nao depender de nenhuma biblioteca.
    prec_bits = int((n + 20) * math.log2(6)) + 200
    scale = 1 << prec_bits

    def arccot(x: int) -> int:
        # arccot(x) * scale, via serie de Taylor 1/x - 1/(3x^3) + 1/(5x^5) - ...
        total = 0
        power = scale // x
        term_index = 1
        xx = x * x
        while power != 0:
            term = power // term_index
            if (term_index // 2) % 2 == 0:
                total += term
            else:
                total -= term
            power //= xx
            term_index += 2
        return total

    pi_scaled = 4 * (4 * arccot(5) - arccot(239))
    # pi_scaled ~= pi * scale (inteiro). Extrai digitos em base 6:
    frac = pi_scaled % scale  # parte fracionaria de pi (pi = 3.14159...), já que 3*scale removido abaixo
    frac = pi_scaled - 3 * scale
    digits = []
    for _ in range(n):
        frac *= 6
        d = frac // scale
        frac -= d * scale
        digits.append(str(int(d) + 1))  # mapeia 0..5 -> 1..6
    return "".join(digits)


def lcg_sequence(n: int, seed: int = 12345, a: int = 1103515245, c: int = 12345, m: int = 2**31) -> str:
    """Gerador congruente linear classico (glibc rand() constants),
    mapeado para 1..6. Determinístico dado (seed, a, c, m) — reproduzivel
    por qualquer pessoa com esses 4 numeros."""
    x = seed
    out = []
    for _ in range(n):
        x = (a * x + c) % m
        out.append(str(x % 6 + 1))
    return "".join(out)


def repeated_first_half(n: int, generator) -> str:
    """Segunda metade = copia exata da primeira metade."""
    half = generator(n // 2 + n % 2)
    return (half + half)[:n]


def mirrored_first_half(n: int, generator) -> str:
    """Segunda metade = primeira metade invertida (mapeando cada face f
    para 7-f, para nao ser uma simetria trivial de indices)."""
    half = generator(n // 2 + n % 2)
    mirror = "".join(str(7 - int(c)) for c in reversed(half))
    return (half + mirror)[:n]


def constant(n: int, face: str = "3") -> str:
    return face * n


def two_face_alternating(n: int, a: str = "1", b: str = "6") -> str:
    return (a + b) * (n // 2 + 1) if False else "".join(a if i % 2 == 0 else b for i in range(n))


def period_p_cycle(n: int, faces: str) -> str:
    return "".join(faces[i % len(faces)] for i in range(n))


def block_repeated(n: int, block: str) -> str:
    return (block * (n // len(block) + 1))[:n]


def markov_low_bias(n: int, stay_prob_num: int, stay_prob_den: int, seed: int = 777) -> str:
    """Cadeia de Markov deterministica via um LCG proprio para decidir
    'ficar/mudar' -- sem usar o modulo `random` (esta e uma ferramenta de
    ataque de desenvolvimento, fora de entropyforge/, entao pode; ver
    redteam/README.md)."""
    x = seed
    def next_bit(den):
        nonlocal x
        x = (1103515245 * x + 12345) % (2**31)
        return (x % den)
    faces = list(range(1, 7))
    seq = [1]
    for _ in range(n - 1):
        r = next_bit(stay_prob_den)
        if r < stay_prob_num:
            seq.append(seq[-1])
        else:
            choices = [f for f in faces if f != seq[-1]]
            seq.append(choices[next_bit(len(choices))])
    return "".join(str(d) for d in seq)


def collision_entropy_bits(digits: str) -> float:
    """H_2 (entropia de colisao/Renyi de ordem 2) das frequencias de FACE
    observadas -- NAO da sequencia inteira (isso exigiria conhecer o
    processo gerador); aqui e so mais um angulo informativo sobre a
    distribuicao marginal, para comparar com H_shannon e H_infinity."""
    n = len(digits)
    counts = [digits.count(str(f)) for f in range(1, 7)]
    probs = [c / n for c in counts if c > 0]
    return -math.log2(sum(p * p for p in probs))


def analyze(name: str, digits: str, true_entropy_bits: float, true_entropy_note: str):
    n = len(digits)
    try:
        battery = stats.run_battery(digits)
        verdict = battery.overall_verdict.value
        per_test = {t.name: t.verdict.value for t in battery.tests}
    except stats.StatsError as exc:
        verdict = f"ERROR: {exc}"
        per_test = {}
    shannon_marginal = -sum(
        (digits.count(str(f)) / n) * math.log2(digits.count(str(f)) / n)
        for f in range(1, 7) if digits.count(str(f)) > 0
    )
    h2 = collision_entropy_bits(digits)
    return {
        "name": name,
        "n": n,
        "overall_verdict": verdict,
        "per_test": per_test,
        "true_entropy_bits": true_entropy_bits,
        "true_entropy_note": true_entropy_note,
        "shannon_marginal_per_roll": shannon_marginal,
        "collision_entropy_marginal_per_roll": h2,
        "theoretical_entropy_if_honest": n * math.log2(6),
    }


def main():
    n = N_OPERATIONAL
    cases = []

    cases.append(("constante (todas as faces = 3)", constant(n), 0.0,
                   "0 bits: unica sequencia possivel, conhecida a priori"))

    cases.append(("alternando 1/6", two_face_alternating(n), 1.0,
                   "<= 1 bit: so 2 sequencias possiveis (comecar com 1 ou com 6)"))

    cases.append(("ciclo 1..6 repetido (periodo 6)", period_p_cycle(n, "123456"), 0.0,
                   "0 bits: unica sequencia possivel dado o padrao"))

    cases.append(("digitos de pi em base 6", digits_of_pi_base6(n), 0.0,
                   "0 bits: totalmente determinada por 'calcule os digitos de pi em base 6', "
                   "que e informacao publica de tamanho fixo (nao escala com n)"))

    cases.append(("LCG (glibc constants, seed=12345)", lcg_sequence(n), math.log2(4),
                   "<= log2(4) ~= 2 bits: a sequencia inteira e determinada pelos 4 "
                   "parametros publicos (seed, a, c, m) do gerador, que um atacante "
                   "pode adivinhar entre um numero pequeno de escolhas 'obvias'"))

    cases.append(("bloco de 12 repetido", block_repeated(n, "134625634162"), 0.0,
                   "0 bits: unica sequencia dado o bloco de 12 lancamentos + a regra de repeticao"))

    pi_half = digits_of_pi_base6(n)
    cases.append(("segunda metade = copia da primeira (base: pi)",
                   repeated_first_half(n, digits_of_pi_base6), 0.0,
                   "0 bits: mesma contagem de informacao que a primeira metade sozinha "
                   "(que ja e 0, por ser pi), mas ilustra que best-case a entropia real "
                   "de uma sequencia de tamanho n com esse padrao e <= H(primeira metade)"))

    cases.append(("segunda metade = espelho (7-f) da primeira (base: pi)",
                   mirrored_first_half(n, digits_of_pi_base6), 0.0,
                   "0 bits pela mesma razao acima"))

    # NOTA IMPORTANTE (achado colateral deste script, ver redteam/findings/):
    # o gerador `markov_low_bias` abaixo usa um LCG fraco propositalmente
    # simples (constantes do glibc rand()) para ficar 100% autocontido e
    # sem `random`. Isso tem um efeito colateral: mesmo o caso "stay=1/6"
    # (que deveria ser estatisticamente identico a i.i.d. uniforme
    # honesta) as vezes e REJEITADO pela bateria, porque LCGs classicos
    # tem correlacao serial conhecida (estrutura de reticulado de
    # Marsaglia) mesmo quando a distribuicao marginal parece uniforme.
    # Isto NAO e um bug do entropyforge: e o teste T2 (diferencas seriais)
    # funcionando corretamente, pegando a fraqueza do PROPRIO gerador do
    # ataque. Confirmado separadamente com uma versao do mesmo Markov
    # dirigida por entropia real (os.getrandom): taxa de FAIL ~2%,
    # consistente com o alpha nominal (ver redteam/findings/01_*.md).
    for stay_num, stay_den, label in [(1, 3, "1/3"), (1, 6, "1/6 (honesto, mas via LCG fraco)"), (2, 5, "2/5")]:
        seq = markov_low_bias(n, stay_num, stay_den)
        # entropia real de uma cadeia de Markov de 1a ordem com essa regra:
        p_stay = stay_num / stay_den
        p_switch_each = (1 - p_stay) / 5
        h_step = -(p_stay * math.log2(p_stay) if p_stay > 0 else 0) - 5 * (
            p_switch_each * math.log2(p_switch_each) if p_switch_each > 0 else 0
        )
        true_bits = (n - 1) * h_step  # primeiro simbolo ~ log2(6), desprezivel
        cases.append((f"Markov 'ficar com prob {label}'", seq, true_bits,
                      f"(n-1)*H(Bernoulli-like por passo) = {true_bits:.1f} bits "
                      f"(< honesto={n*math.log2(6):.1f} se stay>1/6)"))

    results = [analyze(name, seq, tb, note) for name, seq, tb, note in cases]

    print(f"N (operacional) = {n}\n")
    header = f"{'construcao':45s} {'entropia_real<=':>16s} {'entropia_honesta':>17s} {'veredito':>10s}  detalhe por teste"
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r['name']:45s} {r['true_entropy_bits']:16.1f} {r['theoretical_entropy_if_honest']:17.1f} "
            f"{r['overall_verdict']:>10s}  " + ", ".join(f"{k}={v}" for k, v in r["per_test"].items())
        )
        print(f"   -> {r['true_entropy_note']}")
    print()

    passed_or_warn_with_low_entropy = [
        r for r in results if r["overall_verdict"] in ("PASS", "WARN") and r["true_entropy_bits"] < 50
    ]
    print(f"CONSTRUCOES COM ENTROPIA REAL < 50 BITS QUE NAO FORAM REJEITADAS (PASS/WARN): "
          f"{len(passed_or_warn_with_low_entropy)} de {len(results)}")
    for r in passed_or_warn_with_low_entropy:
        print(f"  - {r['name']}: veredito={r['overall_verdict']}, entropia_real<={r['true_entropy_bits']:.1f} bits")

    return results


if __name__ == "__main__":
    main()
