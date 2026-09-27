"""Testes de entropyforge.entropy_calc: as tres perguntas separadas
(entropia teorica, min-entropia com vies, orcamento operacional com
vazamento descontado)."""

import math
import unittest

from entropyforge.entropy_calc import (
    LOG2_6,
    compute_budget,
    min_entropy_bits,
    report_leak_bits,
    rolls_for_min_entropy,
    rolls_for_operational_target,
    rolls_for_shannon_bits,
    theoretical_entropy_bits,
)


class TheoreticalEntropyTests(unittest.TestCase):
    def test_matches_log2_6(self):
        self.assertAlmostEqual(theoretical_entropy_bits(1), math.log2(6))
        self.assertAlmostEqual(theoretical_entropy_bits(100), 100 * math.log2(6))

    def test_zero_rolls_zero_bits(self):
        self.assertEqual(theoretical_entropy_bits(0), 0.0)

    def test_rejects_negative(self):
        with self.assertRaises(ValueError):
            theoretical_entropy_bits(-1)

    def test_rolls_for_256_bits_is_100(self):
        # 100 * log2(6) = 258.49... >= 256; 99 * log2(6) = 255.9... < 256
        self.assertEqual(rolls_for_shannon_bits(256), 100)
        self.assertLess(theoretical_entropy_bits(99), 256)
        self.assertGreaterEqual(theoretical_entropy_bits(100), 256)

    def test_rolls_for_128_bits(self):
        n = rolls_for_shannon_bits(128)
        self.assertGreaterEqual(theoretical_entropy_bits(n), 128)
        self.assertLess(theoretical_entropy_bits(n - 1), 128)


class MinEntropyTests(unittest.TestCase):
    def test_honest_case_equals_shannon(self):
        n = 100
        self.assertAlmostEqual(min_entropy_bits(n, 1 / 6), theoretical_entropy_bits(n))

    def test_biased_gives_less_entropy_than_honest(self):
        n = 100
        self.assertLess(min_entropy_bits(n, 0.20), min_entropy_bits(n, 1 / 6))

    def test_rejects_p_max_below_one_sixth(self):
        with self.assertRaises(ValueError):
            min_entropy_bits(10, 0.1)

    def test_rejects_p_max_at_or_above_one(self):
        with self.assertRaises(ValueError):
            min_entropy_bits(10, 1.0)

    def test_rolls_for_min_entropy_consistent(self):
        n = rolls_for_min_entropy(256, 0.20)
        self.assertGreaterEqual(min_entropy_bits(n, 0.20), 256)
        self.assertLess(min_entropy_bits(n - 1, 0.20), 256)


class ReportLeakTests(unittest.TestCase):
    def test_zero_rolls_zero_leak(self):
        self.assertEqual(report_leak_bits(0, 6), 0.0)

    def test_increases_with_more_verdict_tests(self):
        self.assertLess(report_leak_bits(100, 4), report_leak_bits(100, 6))

    def test_increases_with_n(self):
        self.assertLess(report_leak_bits(100, 6), report_leak_bits(200, 6))

    def test_rejects_negative_n(self):
        with self.assertRaises(ValueError):
            report_leak_bits(-1, 6)


class OperationalBudgetTests(unittest.TestCase):
    def test_operational_n_survives_its_own_leak(self):
        n = rolls_for_operational_target(256, 0.20, 6)
        residual = min_entropy_bits(n, 0.20) - report_leak_bits(n, 6)
        self.assertGreaterEqual(residual, 256)
        residual_minus_one = min_entropy_bits(n - 1, 0.20) - report_leak_bits(n - 1, 6)
        self.assertLess(residual_minus_one, 256)

    def test_operational_n_is_larger_than_theoretical_floor(self):
        budget = compute_budget(256.0, 0.20, num_verdict_tests=6)
        self.assertGreater(budget.rolls_operational, budget.rolls_theoretical_honest)

    def test_compute_budget_defaults_use_stats_constant(self):
        from entropyforge.stats import NUM_VERDICT_TESTS

        budget = compute_budget()
        self.assertEqual(budget.num_verdict_tests, NUM_VERDICT_TESTS)


if __name__ == "__main__":
    unittest.main()
