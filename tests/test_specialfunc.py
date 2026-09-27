"""Testes de entropyforge.specialfunc contra valores tabelados/derivados
independentemente (nao contra o proprio codigo)."""

import math
import unittest

from entropyforge.specialfunc import (
    binom_cdf,
    binom_two_sided_pvalue,
    chi_square_sf,
    clopper_pearson_upper,
    holm_bonferroni,
    log_binom_pmf,
    normal_two_sided_pvalue,
)


class ChiSquareSfTests(unittest.TestCase):
    # Valores classicos de tabela de qui-quadrado (df, x_critico, alpha).
    TABLE = [
        (1, 3.841, 0.05), (1, 6.635, 0.01),
        (5, 11.070, 0.05), (5, 15.086, 0.01), (5, 20.515, 0.001),
        (10, 18.307, 0.05), (10, 23.209, 0.01),
    ]

    def test_matches_table(self):
        for df, x, alpha in self.TABLE:
            with self.subTest(df=df, x=x):
                self.assertAlmostEqual(chi_square_sf(x, df), alpha, delta=alpha * 0.02)

    def test_zero_is_certain(self):
        self.assertEqual(chi_square_sf(0.0, 5), 1.0)

    def test_matches_erfc_for_df1(self):
        # qui-quadrado(1) e o quadrado de uma Normal(0,1); sua sobrevivencia
        # tem forma fechada via erfc, independente da nossa implementacao
        # da gama incompleta.
        for x in (0.5, 2.0, 5.0, 10.0):
            expected = math.erfc(math.sqrt(x / 2.0))
            self.assertAlmostEqual(chi_square_sf(x, 1), expected, places=9)

    def test_rejects_invalid_args(self):
        with self.assertRaises(ValueError):
            chi_square_sf(-1.0, 5)
        with self.assertRaises(ValueError):
            chi_square_sf(1.0, 0)


class NormalTwoSidedTests(unittest.TestCase):
    def test_known_values(self):
        self.assertAlmostEqual(normal_two_sided_pvalue(1.959964), 0.05, delta=1e-4)
        self.assertAlmostEqual(normal_two_sided_pvalue(2.575829), 0.01, delta=1e-4)

    def test_symmetric(self):
        self.assertEqual(normal_two_sided_pvalue(1.5), normal_two_sided_pvalue(-1.5))

    def test_zero_is_certain(self):
        self.assertAlmostEqual(normal_two_sided_pvalue(0.0), 1.0, places=9)


class BinomialTests(unittest.TestCase):
    def test_matches_math_comb_manual_cdf(self):
        n, p = 40, 0.3
        for k in (0, 5, 12, 20, 40):
            expected = sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k + 1))
            self.assertAlmostEqual(binom_cdf(n, k, p), expected, places=9)

    def test_pmf_sums_to_one(self):
        n, p = 25, 1 / 6
        total = sum(math.exp(log_binom_pmf(n, k, p)) for k in range(n + 1))
        self.assertAlmostEqual(total, 1.0, places=9)

    def test_two_sided_pvalue_symmetric_fair_coin(self):
        # Para p=0.5 e n par, k=n/2 e o resultado mais provavel: p-valor = 1.
        p = binom_two_sided_pvalue(20, 10, 0.5)
        self.assertAlmostEqual(p, 1.0, places=9)

    def test_two_sided_pvalue_extreme_is_small(self):
        p = binom_two_sided_pvalue(100, 100, 1 / 6)  # 100 repeticoes em 100, p=1/6
        self.assertLess(p, 1e-10)

    def test_large_n_does_not_overflow(self):
        # n grande (regime do modo `calibrate`): nao deve estourar em
        # overflow/underflow de ponto flutuante.
        p = binom_two_sided_pvalue(200_000, 33_500, 1 / 6)
        self.assertGreaterEqual(p, 0.0)
        self.assertLessEqual(p, 1.0)


class ClopperPearsonTests(unittest.TestCase):
    def test_upper_bound_is_above_observed_proportion(self):
        k, n = 500, 3000
        upper = clopper_pearson_upper(k, n, 0.01)
        self.assertGreater(upper, k / n)

    def test_tighter_with_more_data_same_proportion(self):
        upper_small = clopper_pearson_upper(50, 300, 0.01)
        upper_large = clopper_pearson_upper(500, 3000, 0.01)
        self.assertGreater(upper_small, upper_large)

    def test_k_equals_n_gives_one(self):
        self.assertEqual(clopper_pearson_upper(10, 10, 0.01), 1.0)

    def test_matches_manual_root_find(self):
        # Verifica a propriedade que define o limite: CDF(k; n, p_U) ~= alpha
        k, n, alpha = 300, 1800, 0.01
        upper = clopper_pearson_upper(k, n, alpha)
        self.assertAlmostEqual(binom_cdf(n, k, upper), alpha, delta=1e-6)


class HolmBonferroniTests(unittest.TestCase):
    def test_all_pass_when_all_large(self):
        result = holm_bonferroni([0.9, 0.8, 0.7], 0.05)
        self.assertEqual(result, [False, False, False])

    def test_smallest_rejected_if_significant(self):
        result = holm_bonferroni([0.001, 0.5, 0.6], 0.05)
        self.assertEqual(result, [True, False, False])

    def test_stops_at_first_non_rejection(self):
        # ordenado: 0.001 (rejeita, limiar 0.05/3), 0.02 (limiar 0.05/2=0.025,
        # rejeita), 0.5 (limiar 0.05, nao rejeita) -> so os dois primeiros.
        result = holm_bonferroni([0.5, 0.02, 0.001], 0.05)
        self.assertEqual(result, [False, True, True])

    def test_preserves_input_order(self):
        pvals = [0.5, 0.001, 0.9, 0.02]
        result = holm_bonferroni(pvals, 0.05)
        self.assertEqual(len(result), len(pvals))


if __name__ == "__main__":
    unittest.main()
