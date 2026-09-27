#!/usr/bin/env python3
"""Estudo de simulacao (SOMENTE PARA DESENVOLVIMENTO) do comportamento da
bateria de testes estatisticos em `entropyforge/stats.py`.

Este script NAO faz parte do produto (nao esta em `entropyforge/`, nao e
importado por nenhum modulo do pacote, e o teste de AST de seguranca em
`tests/test_security_ast.py` so cobre o pacote `entropyforge/`). Ele existe
para gerar, de forma REPRODUTIVEL e documentada, os numeros citados em
docs/MATH.md sobre:

  1. Taxa de falso positivo da bateria (deveria ficar perto de
     stats.ALPHA_FAMILYWISE = 0.01) quando a sequencia e de fato i.i.d.
     uniforme.
  2. Poder estatistico da bateria contra um d6 com uma face viciada, em
     varias magnitudes de vies e tamanhos de amostra.
  3. Poder contra dependencia artificial entre lancamentos (nao apenas
     vies de face).

IMPORTANTE:
  - Isto e uma simulacao em software, NAO uma validacao de hardware fisico.
    Um d6 real pode ter modos de falha que este modelo simplificado
    (Bernoulli/Markov) nao captura (ver docs/THREAT_MODEL.md, ameaca
    T-DICE).
  - "Nao rejeitar H0" nestas simulacoes so quer dizer isso -- a simulacao
    NAO demonstra que a bateria "prova" aleatoriedade em caso algum.
  - Para o caso 1 (falso positivo), a fonte de dados e `os.getrandom`
    (a mesma fonte usada como fonte B do produto), reamostrada por rejeicao
    para produzir digitos uniformes em 1..6 -- ou seja, entropia real do
    SO, nao um PRNG proprio.
  - Para os casos 2 e 3 (vies e dependencia controlados), usa-se
    `random.Random(SEED)` da biblioteca padrao, com uma seed FIXA e
    documentada aqui, exclusivamente para tornar este estudo de
    desenvolvimento reproduzivel. Isto NUNCA e usado para gerar uma
    carteira real (ver entropyforge/osrng.py, que nunca importa `random`).

Uso:
    python3 tools/simulate_power.py > docs/_simulation_output.txt
"""

from __future__ import annotations

import os
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from entropyforge.stats import run_battery, Verdict, ALPHA_FAMILYWISE  # noqa: E402

SIMULATION_SEED = 20260927  # data em que este estudo foi gerado (AAAAMMDD)


def real_d6_sequence(n: int) -> str:
    """n digitos '1'-'6' via rejeicao sobre os.getrandom (entropia real do
    SO, sem vies de implementacao introduzido por este script)."""
    out = []
    while len(out) < n:
        chunk = os.getrandom(max(64, n - len(out)), 0)
        for byte in chunk:
            if byte < 252:  # 252 = 42*6: rejeita os 4 valores que quebrariam a uniformidade
                out.append(str(byte % 6 + 1))
                if len(out) == n:
                    break
    return "".join(out)


def biased_d6_sequence(rng: random.Random, n: int, biased_face: int, p_biased: float) -> str:
    """n digitos, onde `biased_face` sai com probabilidade `p_biased` e as
    outras 5 faces dividem o restante igualmente. Fonte: `random.Random`
    do dev, com seed fixa -- ver aviso no topo do arquivo."""
    other_p = (1.0 - p_biased) / 5.0
    weights = [p_biased if f == biased_face else other_p for f in range(1, 7)]
    faces = list(range(1, 7))
    return "".join(str(rng.choices(faces, weights=weights, k=1)[0]) for _ in range(n))


def markov_dependent_sequence(rng: random.Random, n: int, stay_prob: float) -> str:
    """Sequencia com faces marginalmente uniformes mas NAO independentes:
    uma cadeia de Markov que, com probabilidade `stay_prob`, repete a face
    anterior, e do contrario sorteia uniformemente entre as outras 5. Serve
    para testar o poder de T2/T3/T4/T5 contra dependencia (nao vies)."""
    faces = list(range(1, 7))
    seq = [rng.choice(faces)]
    for _ in range(n - 1):
        if rng.random() < stay_prob:
            seq.append(seq[-1])
        else:
            choices = [f for f in faces if f != seq[-1]]
            seq.append(rng.choice(choices))
    return "".join(str(d) for d in seq)


def false_positive_rate(n: int, trials: int) -> dict:
    fails = warns = 0
    per_test_fail = {}
    for _ in range(trials):
        digits = real_d6_sequence(n)
        res = run_battery(digits)
        if res.overall_verdict == Verdict.FAIL:
            fails += 1
        elif res.overall_verdict == Verdict.WARN:
            warns += 1
        for t in res.tests:
            if t.verdict == Verdict.FAIL:
                per_test_fail[t.name] = per_test_fail.get(t.name, 0) + 1
    return {
        "n": n,
        "trials": trials,
        "fail_rate": fails / trials,
        "warn_rate": warns / trials,
        "per_test_fail_rate": {k: v / trials for k, v in per_test_fail.items()},
    }


def power_against_bias(n: int, p_biased_values: list[float], trials: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    results = []
    for p_biased in p_biased_values:
        fails = 0
        for _ in range(trials):
            digits = biased_d6_sequence(rng, n, biased_face=1, p_biased=p_biased)
            res = run_battery(digits)
            if res.overall_verdict == Verdict.FAIL:
                fails += 1
        results.append({"n": n, "p_biased": p_biased, "trials": trials, "detect_rate": fails / trials})
    return results


def power_against_dependence(n: int, stay_probs: list[float], trials: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    results = []
    for stay in stay_probs:
        fails = 0
        for _ in range(trials):
            digits = markov_dependent_sequence(rng, n, stay_prob=stay)
            res = run_battery(digits)
            if res.overall_verdict == Verdict.FAIL:
                fails += 1
        results.append({"n": n, "stay_prob": stay, "trials": trials, "detect_rate": fails / trials})
    return results


def main() -> None:
    t0 = time.time()
    print(f"# Estudo de simulacao — gerado em {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print(f"# alpha familiar (Holm) = {ALPHA_FAMILYWISE}")
    print(f"# seed do simulador (so para vies/dependencia controlados) = {SIMULATION_SEED}")
    print()

    print("## 1. Taxa de falso positivo (fonte: os.getrandom, entropia real do SO)")
    for n, trials in [(126, 3000), (600, 1000)]:
        r = false_positive_rate(n, trials)
        print(f"n={r['n']:5d} trials={r['trials']:5d} fail_rate={r['fail_rate']:.4f} warn_rate={r['warn_rate']:.4f}")
        for name, rate in sorted(r["per_test_fail_rate"].items()):
            print(f"    {name:24s} fail_rate={rate:.4f}")
    print()

    print("## 2. Poder contra d6 com uma face viciada (fonte: random.Random, seed fixa)")
    for n in (126, 600, 3000):
        for row in power_against_bias(n, [0.18, 0.20, 0.25, 0.30], trials=1500, seed=SIMULATION_SEED):
            print(f"n={row['n']:5d} p_biased={row['p_biased']:.2f} trials={row['trials']:5d} detect_rate={row['detect_rate']:.4f}")
    print()

    print("## 3. Poder contra dependencia markoviana (faces marginalmente uniformes)")
    for n in (126, 600):
        for row in power_against_dependence(n, [0.20, 0.30, 0.40], trials=1500, seed=SIMULATION_SEED):
            print(f"n={row['n']:5d} stay_prob={row['stay_prob']:.2f} trials={row['trials']:5d} detect_rate={row['detect_rate']:.4f}")

    print(f"\n# tempo total: {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()
