#!/usr/bin/env python3
"""Fase D, secao 4: busca adversarial pela sequencia de d6 de MENOR
entropia real que ainda passa pela bateria estatistica em n=127
(operacional).

Duas buscas independentes:

  (1) Bissecao sobre o parametro continuo p_bias (familia "uma face
      enviesada") -- encontra o limiar exato de deteccao com alta
      precisao.

  (2) Hill climbing / simulated annealing DIRETO sobre a sequencia de 127
      digitos: minimiza uma proxy de entropia real (aqui, a MIN-ENTROPIA
      empirica -log2(max_face_freq/n), a mesma grandeza usada por
      entropy_calc.py) sujeita a `run_battery(seq).overall_verdict !=
      FAIL`. Isto explora um espaco MAIOR do que a familia parametrica
      simples de (1): a sequencia otimizada nao precisa ser i.i.d. de
      forma alguma.

Importa entropyforge.stats (o codigo real) de proposito -- o objetivo e
testar o LIMITE DO SISTEMA REAL, nao re-derivar formulas.
"""
import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from entropyforge import stats  # noqa: E402

N = 127
SEARCH_SEED = 20260927  # fixa, documentada, so para este estudo -- nunca no produto


def empirical_min_entropy_bits(seq: str) -> float:
    counts = [seq.count(str(f)) for f in range(1, 7)]
    p_max = max(counts) / len(seq)
    return -math.log2(p_max)


def verdict(seq: str) -> str:
    return stats.run_battery(seq).overall_verdict.value


# ---------------------------------------------------------------------
# (1) Bissecao sobre p_bias (familia parametrica: uma face enviesada)
# ---------------------------------------------------------------------
def gen_biased(rng, n, p_biased):
    other_p = (1 - p_biased) / 5
    probs = [other_p] * 6
    probs[0] = p_biased
    faces = list(range(1, 7))
    return "".join(str(rng.choices(faces, weights=probs)[0]) for _ in range(n))


def fail_rate_at(p_bias, trials=300):
    rng = random.Random(SEARCH_SEED)
    fails = 0
    for _ in range(trials):
        seq = gen_biased(rng, N, p_bias)
        if verdict(seq) == "FAIL":
            fails += 1
    return fails / trials


print("=== (1) Bissecao: limiar de p_bias onde FAIL cruza 50% (n=127) ===")
lo, hi = 1 / 6, 0.5
target = 0.5
# garante que lo da FAIL baixo e hi da FAIL alto antes de bissectar
assert fail_rate_at(lo, trials=200) < target
assert fail_rate_at(hi, trials=200) > target
for step in range(12):
    mid = (lo + hi) / 2
    fr = fail_rate_at(mid, trials=150)
    print(f"  passo {step}: p_bias={mid:.5f} -> FAIL rate ~= {fr:.3f}")
    if fr < target:
        lo = mid
    else:
        hi = mid
p_threshold = (lo + hi) / 2
h_min_at_threshold = -math.log2(p_threshold)
h_shannon_at_threshold = -(p_threshold * math.log2(p_threshold) + 5 * ((1 - p_threshold) / 5) * math.log2((1 - p_threshold) / 5))
print(f"\nLimiar encontrado: p_bias ~= {p_threshold:.4f}")
print(f"  H_min/lancamento nesse limiar    = {h_min_at_threshold:.4f} bits (vs 2.585 honesto)")
print(f"  H_Shannon/lancamento nesse limiar = {h_shannon_at_threshold:.4f} bits")
print(f"  H_min total em n=127             = {127*h_min_at_threshold:.2f} bits (vs 256 requeridos)")
print()

# ---------------------------------------------------------------------
# (2) Hill climbing direto sobre a sequencia de digitos, com REINICIOS
# (basin hopping simples: cada reinicio parte de uma amostra aleatoria
# nova, para nao depender de um unico otimo local)
# ---------------------------------------------------------------------
print("=== (2) Hill climbing direto sobre a sequencia (minimiza H_min empirica) ===")


def hill_climb_once(seed, iters=3000):
    rng = random.Random(seed)
    current = "".join(str(rng.randint(1, 6)) for _ in range(N))
    tries = 0
    while verdict(current) == "FAIL":
        current = "".join(str(rng.randint(1, 6)) for _ in range(N))
        tries += 1
        if tries > 50:
            return None
    current_h = empirical_min_entropy_bits(current)
    initial_h = current_h
    best, best_h = current, current_h
    accepted = rejected_by_battery = rejected_no_improvement = 0
    for _ in range(iters):
        # mutacao CORRETA para minimizar H_min = -log2(max_count/n): a
        # unica direcao que garantidamente aumenta max_count (logo reduz
        # H_min) e converter uma posicao que NAO pertence a face
        # atualmente dominante para essa face dominante (recalculada a
        # cada passo -- um bug da primeira versao deste script fixava a
        # face-alvo em "1", que raramente coincidia com a face ja
        # dominante da amostra, entao quase nenhuma mutacao proposta
        # reduzia H_min de fato).
        counts = {f: current.count(f) for f in "123456"}
        dominant = max(counts, key=counts.get)
        candidates = [j for j, c in enumerate(current) if c != dominant]
        if not candidates:
            break
        pos = rng.choice(candidates)
        proposal = current[:pos] + dominant + current[pos + 1:]
        proposal_h = empirical_min_entropy_bits(proposal)
        if proposal_h >= current_h:
            rejected_no_improvement += 1
            continue
        if verdict(proposal) == "FAIL":
            rejected_by_battery += 1
            continue
        current, current_h = proposal, proposal_h
        accepted += 1
        if current_h < best_h:
            best, best_h = current, current_h
    return {
        "initial_h": initial_h, "best": best, "best_h": best_h,
        "accepted": accepted, "rejected_by_battery": rejected_by_battery,
        "rejected_no_improvement": rejected_no_improvement,
    }


RESTARTS = 15
global_best = None
for r in range(RESTARTS):
    res = hill_climb_once(SEARCH_SEED + 100 + r)
    if res is None:
        continue
    print(f"  reinicio {r}: H_min inicial={res['initial_h']:.4f} -> final={res['best_h']:.4f} "
          f"(aceitas={res['accepted']}, rej.bateria={res['rejected_by_battery']})")
    if global_best is None or res["best_h"] < global_best["best_h"]:
        global_best = res

best = global_best["best"]
best_h = global_best["best_h"]
final_counts = [best.count(str(f)) for f in range(1, 7)]
print(f"\nMelhor de {RESTARTS} reinicios: H_min = {best_h:.4f} bits/lancamento (vs 2.585 honesto)")
print(f"  contagens de face: {final_counts}")
print(f"  veredito final: {verdict(best)}")
print(f"  H_min total em n=127 = {127*best_h:.2f} bits (alvo: 256 bits)")
print(f"  sequencia (primeiros 60 digitos): {best[:60]}...")
print()
print("Interpretacao: o hill climbing local (mutacao=1 digito por vez) fica")
print("PRESO num otimo local rapidamente, porque QUALQUER excesso visivel de")
print("uma face aciona T1 (chi-quadrado) muito antes de a min-entropia cair")
print("de forma significativa -- ao contrario do modelo K (PRNG de seed")
print("conhecida) da secao 3, que tem H_min real = 0 (o atacante sabe a")
print("sequencia exata) mas e ACEITO quase sempre, porque ele nao e i.i.d.")
print("enviesado, e sim ESTRUTURALMENTE indistinguivel de uniforme para")
print("qualquer teste estatistico -- a bateria nao pode, por construcao,")
print("distinguir 'aleatorio de verdade' de 'PRNG bom com seed secreta do")
print("atacante'. O ataque real e por ai, nao por vies i.i.d. disfarcado.")
