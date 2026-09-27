#!/usr/bin/env python3
"""Red team: busca fina do limiar de vies que passa despercebido em n=127
(o n operacional real de `generate`). Complementa docs/simulation_results.txt
(que ja cobre 0.18/0.20/0.25/0.30) com pontos intermediarios.

Fonte de aleatoriedade: random.Random com semente fixa e documentada,
usada SOMENTE neste estudo de desenvolvimento (nunca no produto).
"""
import random, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from entropyforge.stats import run_battery, Verdict

SEED = 20260927001
N = 127
TRIALS = 2000

def biased_seq(rng, n, p_biased, face=1):
    other = (1 - p_biased) / 5
    weights = [p_biased if f == face else other for f in range(1, 7)]
    faces = list(range(1, 7))
    return "".join(str(rng.choices(faces, weights=weights, k=1)[0]) for _ in range(n))

rng = random.Random(SEED)
print(f"n={N}, trials={TRIALS}, seed={SEED}")
print(f"{'p_biased':>10s} {'detect_rate':>12s}")
for p in [1/6, 0.17, 0.18, 0.19, 0.20, 0.21, 0.22, 0.23, 0.24, 0.25]:
    fails = sum(1 for _ in range(TRIALS) if run_battery(biased_seq(rng, N, p)).overall_verdict == Verdict.FAIL)
    print(f"{p:10.3f} {fails/TRIALS:12.4f}")
