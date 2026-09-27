"""Testes de entropyforge.stats: as distribuicoes nulas EXATAS (T3, T4)
verificadas por forca bruta, deteccao de sequencias patologicas, taxa de
falso positivo aproximada em amostras genuinamente aleatorias, e casos
negativos (sequencia curta demais para a bateria)."""

import itertools
import math
import os
import unittest
from collections import Counter

from entropyforge.stats import (
    MIN_BATTERY_ROLLS,
    NUM_VERDICT_TESTS,
    StatsError,
    Verdict,
    _runs_exact_pvalue,
    face_counts,
    run_battery,
)


def _real_d6(n: int) -> str:
    """n digitos de d6 via rejeicao sobre os.getrandom (entropia real do
    SO, usada aqui so para testar o CODIGO DE TESTE estatistico, nao para
    gerar uma carteira)."""
    out = []
    while len(out) < n:
        for byte in os.getrandom(max(64, n - len(out)), 0):
            if byte < 252:
                out.append(str(byte % 6 + 1))
                if len(out) == n:
                    break
    return "".join(out)


class ExactRepeatsDistributionTests(unittest.TestCase):
    """T3: prova por forca bruta de que R ~ Binomial(n-1, 1/6) EXATAMENTE
    (nao uma aproximacao) sob H0, para um n pequeno o suficiente para
    enumerar todo o espaco {1..6}^n."""

    def test_matches_binomial_exactly_for_n6(self):
        n = 6
        empirical = Counter()
        total = 0
        for combo in itertools.product(range(1, 7), repeat=n):
            r = sum(1 for i in range(n - 1) if combo[i] == combo[i + 1])
            empirical[r] += 1
            total += 1
        for r in range(n):
            expected_prob = math.comb(n - 1, r) * (1 / 6) ** r * (5 / 6) ** (n - 1 - r)
            observed_prob = empirical.get(r, 0) / total
            self.assertAlmostEqual(observed_prob, expected_prob, places=9)


class ExactRunsDistributionTests(unittest.TestCase):
    """T4: prova por forca bruta da distribuicao exata de corridas de
    Wald-Wolfowitz condicional em (n0, n1)."""

    def test_matches_brute_force_arrangement_count(self):
        n0, n1 = 4, 5

        def count_runs(seq):
            r = 1
            for i in range(1, len(seq)):
                if seq[i] != seq[i - 1]:
                    r += 1
            return r

        seqs = set(itertools.permutations([0] * n0 + [1] * n1))
        empirical = Counter(count_runs(s) for s in seqs)
        total = len(seqs)

        for r, count in empirical.items():
            # p-valor "tao extremo quanto" deve ser >= a propria prob. do
            # ponto (e igual quando r e o mais extremo possivel).
            p = _runs_exact_pvalue(n0, n1, r)
            self.assertGreaterEqual(p, count / total - 1e-9)

    def test_degenerate_all_one_side_does_not_crash(self):
        p = _runs_exact_pvalue(0, 10, 1)
        self.assertEqual(p, 1.0)


class FaceCountsTests(unittest.TestCase):
    def test_counts_sum_to_n(self):
        digits = _real_d6(200)
        counts = face_counts([int(c) for c in digits])
        self.assertEqual(sum(counts), 200)
        self.assertEqual(len(counts), 6)


class BatteryStructuralTests(unittest.TestCase):
    def test_rejects_too_short_sequence(self):
        with self.assertRaises(StatsError):
            run_battery("1" * (MIN_BATTERY_ROLLS - 1))

    def test_accepts_minimum_length(self):
        run_battery(_real_d6(MIN_BATTERY_ROLLS))  # nao deve levantar

    def test_num_verdict_tests_matches_holm_family_size(self):
        result = run_battery(_real_d6(150))
        # 1 teste (face_frequency) fica fora da familia de Holm (ver docstring)
        self.assertEqual(len(result.tests) - 1, NUM_VERDICT_TESTS)


class PathologicalSequenceTests(unittest.TestCase):
    def test_constant_sequence_fails(self):
        result = run_battery("3" * 150)
        self.assertEqual(result.overall_verdict, Verdict.FAIL)

    def test_alternating_two_faces_fails(self):
        result = run_battery(("16" * 100))
        self.assertEqual(result.overall_verdict, Verdict.FAIL)

    def test_perfectly_cycling_sequence_fails_despite_uniform_faces(self):
        # Contra-exemplo pedagogico: uma sequencia deterministica pode ter
        # frequencia de faces perfeita e ainda assim ser claramente
        # nao-aleatoria; os testes de dependencia (T2/T3/T4) devem pegar
        # isso mesmo quando T1 (frequencia) nao pega.
        digits = ("123456" * 25)[:150]
        result = run_battery(digits)
        face_test = result.by_name("face_frequency")
        self.assertEqual(face_test.verdict, Verdict.PASS)
        self.assertEqual(result.overall_verdict, Verdict.FAIL)


class FalsePositiveRateSanityTests(unittest.TestCase):
    """Nao e uma prova formal (isso esta em tools/simulate_power.py e
    docs/MATH.md, com milhares de tentativas); aqui so um limite frouxo,
    nao-flaky, de que a bateria nao rejeita amostras genuinamente
    aleatorias com frequencia absurda."""

    def test_loose_false_positive_bound(self):
        trials = 300
        fails = 0
        for _ in range(trials):
            digits = _real_d6(126)
            if run_battery(digits).overall_verdict == Verdict.FAIL:
                fails += 1
        # taxa nominal ~= 2*ALPHA_FAMILYWISE (uniao entre T1 e a familia de
        # Holm); com 300 tentativas, uma taxa observada > 15% seria uma
        # evidencia esmagadora de um bug (a probabilidade disso acontecer
        # por acaso, com a taxa nominal, e virtualmente zero).
        self.assertLess(fails / trials, 0.15, f"taxa de falso positivo suspeita: {fails}/{trials}")


if __name__ == "__main__":
    unittest.main()
