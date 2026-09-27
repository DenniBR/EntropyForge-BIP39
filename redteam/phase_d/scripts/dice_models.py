#!/usr/bin/env python3
"""Fase D, secao 3: modelos adversariais de dado fisico (A-L).

Este script IMPORTA entropyforge.stats (o codigo real sob teste) de
proposito -- ao contrario da secao 2 (re-derivacao matematica pura), aqui
o objetivo e observar como o SISTEMA REAL reage a cada modelo de dado
adversarial, nao re-derivar formulas.
"""
import math
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from entropyforge import stats  # noqa: E402


def shannon_entropy_per_roll(probs):
    return -sum(p * math.log2(p) for p in probs if p > 0)


def min_entropy_per_roll(probs):
    return -math.log2(max(probs))


N_OPERATIONAL = 127  # numero recomendado por generate (assumed_p_max=0.20)
N_LARGE = 3000  # amostra tipica de calibrate
TRIALS = 400  # numero de sequencias simuladas por modelo, por n


def gen_biased(rng, n, p_biased, biased_face=1):
    other_p = (1 - p_biased) / 5
    probs = [other_p] * 6
    probs[biased_face - 1] = p_biased
    faces = list(range(1, 7))
    return "".join(str(rng.choices(faces, weights=probs)[0]) for _ in range(n))


def gen_uniform(rng, n):
    return "".join(str(rng.randint(1, 6)) for _ in range(n))


def gen_deterministic_constant(n, face=3):
    return str(face) * n


def gen_periodic(n, pattern="123456"):
    return (pattern * (n // len(pattern) + 1))[:n]


def gen_pi_digits(n):
    # digitos de pi (conhecidos publicamente), mapeados para 1-6 via (d mod 6) + 1.
    # deterministico, nao repete um padrao curto, mas e 100% previsivel para
    # quem sabe que a fonte e "digitos de pi".
    import mpmath  # ausente? fallback abaixo
    mpmath.mp.dps = n + 10
    s = mpmath.nstr(mpmath.pi, n + 5, strip_zeros=False).replace(".", "").replace("-", "")
    digits = [int(c) for c in s if c.isdigit()][:n]
    return "".join(str((d % 6) + 1) for d in digits)


def gen_pi_digits_fallback(n):
    # fallback sem mpmath: usa uma expansao de pi hardcoded suficientemente longa
    PI_DIGITS = (
        "31415926535897932384626433832795028841971693993751058209749445923078164"
        "06286208998628034825342117067982148086513282306647093844609550582231725"
        "35940812848111745028410270193852110555964462294895493038196"
    )
    digits = [int(c) for c in PI_DIGITS][:n]
    if len(digits) < n:
        digits = (digits * (n // len(digits) + 1))[:n]
    return "".join(str((d % 6) + 1) for d in digits)


def gen_markov_stay(rng, n, stay_prob):
    seq = [rng.randint(1, 6)]
    faces = list(range(1, 7))
    for _ in range(n - 1):
        if rng.random() < stay_prob:
            seq.append(seq[-1])
        else:
            choices = [f for f in faces if f != seq[-1]]
            seq.append(rng.choice(choices))
    return "".join(str(v) for v in seq)


def gen_known_seed_prng(seed, n):
    r = random.Random(seed)
    return "".join(str(r.randint(1, 6)) for _ in range(n))


def evaluate_model(name, description, probs_or_none, sample_fn, n, trials, rng_seed_note):
    fail = warn = passed = 0
    for t in range(trials):
        digits = sample_fn(t)
        try:
            battery = stats.run_battery(digits)
        except stats.StatsError as exc:
            print(f"  [{name}] ERRO stats: {exc}")
            continue
        if battery.overall_verdict.value == "FAIL":
            fail += 1
        elif battery.overall_verdict.value == "WARN":
            warn += 1
        else:
            passed += 1
    total = fail + warn + passed
    fail_rate = fail / total if total else float("nan")
    warn_rate = warn / total if total else float("nan")
    pass_rate = passed / total if total else float("nan")

    if probs_or_none is not None:
        h_shannon = shannon_entropy_per_roll(probs_or_none)
        h_min = min_entropy_per_roll(probs_or_none)
    else:
        h_shannon = h_min = None

    return {
        "name": name,
        "description": description,
        "n": n,
        "trials": total,
        "h_shannon_per_roll": h_shannon,
        "h_min_per_roll": h_min,
        "fail_rate": fail_rate,
        "warn_rate": warn_rate,
        "pass_rate": pass_rate,
        "rng_seed_note": rng_seed_note,
    }


def print_result(r):
    hs = f"{r['h_shannon_per_roll']:.4f}" if r["h_shannon_per_roll"] is not None else "n/a (deterministico ou PRNG)"
    hm = f"{r['h_min_per_roll']:.4f}" if r["h_min_per_roll"] is not None else "n/a"
    print(f"--- {r['name']}: {r['description']} ---")
    print(f"  n={r['n']}, trials={r['trials']}, seed: {r['rng_seed_note']}")
    print(f"  H_Shannon/lancamento = {hs} bits   H_min/lancamento = {hm} bits")
    print(f"  generate/calibrate battery: FAIL={r['fail_rate']:.1%}  WARN={r['warn_rate']:.1%}  PASS={r['pass_rate']:.1%}")
    print()


def main():
    results = []
    rng = random.Random(20260927)  # seed fixa, documentada, so p/ este estudo -- nunca no produto

    for n in (N_OPERATIONAL, N_LARGE):
        print(f"\n############ n = {n} ############\n")

        # A. uniforme perfeito (controle)
        r = evaluate_model(
            "A_uniforme", "d6 perfeitamente uniforme (p=1/6 cada face)",
            [1 / 6] * 6, lambda t: gen_uniform(rng, n), n, TRIALS, "random.Random(20260927), estudo apenas"
        )
        results.append(r); print_result(r)

        # B-F: vies crescente
        for label, p in (("B", 0.17), ("C", 0.18), ("D", 0.20), ("E", 0.25), ("F", 0.30)):
            r = evaluate_model(
                f"{label}_bias_{p}", f"face 1 enviesada com p={p}",
                [p] + [(1 - p) / 5] * 5, lambda t, p=p: gen_biased(rng, n, p), n, TRIALS, "random.Random(20260927)"
            )
            results.append(r); print_result(r)

        # G. dado extremamente enviesado
        p_extreme = 0.60
        r = evaluate_model(
            "G_extremo", f"dado extremamente enviesado (face 1, p={p_extreme})",
            [p_extreme] + [(1 - p_extreme) / 5] * 5, lambda t: gen_biased(rng, n, p_extreme), n, TRIALS, "random.Random(20260927)"
        )
        results.append(r); print_result(r)

        # H. dado deterministico (sempre a mesma face)
        r = evaluate_model(
            "H_deterministico", "sempre a mesma face (ex.: sempre 3)",
            None, lambda t: gen_deterministic_constant(n), n, 1, "nenhum (deterministico)"
        )
        results.append(r); print_result(r)

        # I. sequencia periodica curta
        r = evaluate_model(
            "I_periodico", "repeticao do padrao '123456' (marginal uniforme, ordem 100% previsivel)",
            [1 / 6] * 6, lambda t: gen_periodic(n), n, 1, "nenhum (deterministico)"
        )
        results.append(r); print_result(r)

        # J. sequencia "construida para passar" -- usamos digitos de pi como
        # substituto de uma sequencia otimizada (ver secao 4/tarefa 35 para
        # a busca adversarial de verdade); aqui e so uma demonstracao de que
        # QUALQUER sequencia deterministica "com cara de aleatoria" e aceita.
        try:
            pi_seq = gen_pi_digits(n)
        except Exception:
            pi_seq = gen_pi_digits_fallback(n)
        r = evaluate_model(
            "J_pi_digits", "digitos de pi mod 6 (deterministico, nao periodico simples, 'parece' aleatorio)",
            None, lambda t: pi_seq, n, 1, "nenhum (constante publica, deterministica)"
        )
        results.append(r); print_result(r)

        # K. PRNG com seed conhecida (ex.: um atacante que conhece a seed
        # usada por um gerador comprometido faria isto)
        known_seed = 1234
        r = evaluate_model(
            "K_prng_seed_conhecida", f"random.Random(seed={known_seed}) -- PRNG de alta qualidade estatistica, seed CONHECIDA do atacante",
            None, lambda t: gen_known_seed_prng(known_seed, n), n, 1, f"seed fixa e PUBLICA={known_seed}"
        )
        results.append(r); print_result(r)

        # L. frequencia marginal uniforme, ordem deterministica (Markov com stay_prob alto)
        for label, stay in (("L1", 0.30), ("L2", 0.40)):
            r = evaluate_model(
                f"{label}_markov_stay{stay}", f"cadeia de Markov, repete a face anterior com prob={stay} (marginal ~uniforme)",
                [1 / 6] * 6, lambda t, s=stay: gen_markov_stay(rng, n, s), n, TRIALS, "random.Random(20260927)"
            )
            results.append(r); print_result(r)

    print("\n=== TABELA RESUMO ===")
    print(f"{'modelo':28s} {'n':>5s} {'H_Shan':>8s} {'H_min':>8s} {'FAIL%':>7s} {'WARN%':>7s} {'PASS%':>7s}")
    for r in results:
        hs = f"{r['h_shannon_per_roll']:.3f}" if r["h_shannon_per_roll"] is not None else "  n/a"
        hm = f"{r['h_min_per_roll']:.3f}" if r["h_min_per_roll"] is not None else "  n/a"
        print(f"{r['name']:28s} {r['n']:5d} {hs:>8s} {hm:>8s} {r['fail_rate']*100:6.1f}% {r['warn_rate']*100:6.1f}% {r['pass_rate']*100:6.1f}%")


if __name__ == "__main__":
    main()
