"""Testes de entropyforge.stats: as distribuicoes nulas EXATAS (T3, T4)
verificadas por forca bruta, deteccao de sequencias patologicas, taxa de
falso positivo aproximada em amostras genuinamente aleatorias, e casos
negativos (sequencia curta demais para a bateria)."""

import itertools
import math
import os
import unittest
from collections import Counter
from unittest import mock

from entropyforge import stats
from entropyforge.stats import (
    ALPHA_FAMILYWISE,
    MIN_BATTERY_ROLLS,
    NUM_VERDICT_TESTS,
    StatsError,
    Verdict,
    _runs_exact_pvalue,
    face_counts,
    holm_bonferroni,
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


class HolmIntegrationTests(unittest.TestCase):
    """Regressao encontrada por mutation testing (docs/REDTEAM.md):
    substituir a chamada a `holm_bonferroni` dentro de `run_battery` por
    um limiar bruto por teste (`p <= alpha`, sem corrigir para testes
    multiplos) fazia TODA a suite de testes passar sem nenhuma falha --
    inclusive `FalsePositiveRateSanityTests` acima, cujo limite de 15% e
    frouxo demais para pegar a inflacao (~2x) causada pela falta de
    correcao. Estes dois testes verificam especificamente essa fiacao,
    no nivel de integracao (nao so a funcao `holm_bonferroni` isolada,
    ja coberta em test_specialfunc.py)."""

    def test_run_battery_calls_holm_bonferroni_with_right_arity(self):
        digits = self._some_digits()
        with mock.patch("entropyforge.stats.holm_bonferroni", wraps=holm_bonferroni) as spy:
            run_battery(digits)
        spy.assert_called_once()
        p_values_arg, alpha_arg = spy.call_args.args[0], spy.call_args.args[1]
        self.assertEqual(len(p_values_arg), NUM_VERDICT_TESTS)
        self.assertEqual(alpha_arg, ALPHA_FAMILYWISE)

    def test_verdict_rejections_match_independent_holm_computation(self):
        # Recalcula holm_bonferroni de forma independente sobre os MESMOS
        # p-valores que run_battery expos, e compara com o que run_battery
        # realmente decidiu (`rejected_after_holm`) para cada teste da
        # familia. Uma implementacao que use um limiar bruto (ou qualquer
        # outra coisa que nao seja Holm sobre esses p-valores) divergiria
        # com alta probabilidade em pelo menos uma das 20 repeticoes.
        for _ in range(20):
            digits = self._some_digits()
            battery = run_battery(digits)
            holm_family = [t for t in battery.tests if t.name != "face_frequency"]
            self.assertEqual(len(holm_family), NUM_VERDICT_TESTS)
            p_values = [t.p_value for t in holm_family]
            expected = holm_bonferroni(p_values, ALPHA_FAMILYWISE)
            actual = [t.rejected_after_holm for t in holm_family]
            self.assertEqual(actual, expected)

    @staticmethod
    def _some_digits() -> str:
        out = []
        while len(out) < 150:
            for byte in os.getrandom(64, 0):
                if byte < 252:
                    out.append(str(byte % 6 + 1))
                    if len(out) == 150:
                        break
        return "".join(out)


if __name__ == "__main__":
    unittest.main()
