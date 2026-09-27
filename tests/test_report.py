"""Testes de entropyforge.report: o relatorio publico (usado em `generate`)
nunca deve conter p-valores/estatisticas; o relatorio completo (usado em
`calibrate`, dados descartaveis) pode conter tudo."""

import os
import unittest

from entropyforge import report, stats


def _real_d6(n: int) -> str:
    out = []
    while len(out) < n:
        for byte in os.getrandom(64, 0):
            if byte < 252:
                out.append(str(byte % 6 + 1))
                if len(out) == n:
                    break
    return "".join(out)


class PublicReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.digits = _real_d6(150)
        cls.battery = stats.run_battery(cls.digits)

    def test_face_counts_present_and_sum_to_n(self):
        r = report.public_report(self.battery)
        self.assertEqual(sum(r.face_counts), 150)

    def test_verdicts_are_only_pass_warn_fail(self):
        r = report.public_report(self.battery)
        allowed = {"PASS", "WARN", "FAIL"}
        for _name, verdict in r.verdicts:
            self.assertIn(verdict, allowed)

    def test_formatted_report_never_contains_raw_digits(self):
        text = report.format_public_report(report.public_report(self.battery))
        self.assertNotIn(self.digits, text)

    def test_formatted_report_never_contains_p_value_looking_numbers(self):
        # Nenhum p-valor (numero com "p=" ou muitas casas decimais de
        # estatistica) deve vazar no relatorio publico.
        text = report.format_public_report(report.public_report(self.battery))
        self.assertNotIn("p=", text)
        self.assertNotIn("stat=", text)

    def test_leak_bits_is_positive_and_bounded(self):
        r = report.public_report(self.battery)
        self.assertGreater(r.leak_bits, 0)
        self.assertLess(r.leak_bits, 100)  # sanidade: nao deve disparar


class FullReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.digits = _real_d6(3000)
        cls.battery = stats.run_battery(cls.digits)

    def test_contains_p_values(self):
        r = report.full_report(self.battery)
        text = report.format_full_report(r)
        self.assertIn("p=", text)

    def test_clopper_pearson_upper_bound_above_naive_max_proportion(self):
        r = report.full_report(self.battery)
        naive = r.max_face_count / r.n
        self.assertGreater(r.max_face_upper_bound, naive)

    def test_never_used_for_wallet_generation_by_construction(self):
        # Verificacao estrutural: o modulo report nao importa bip39 nem
        # combine (o relatorio de calibracao nao tem como, mesmo por
        # engano, alimentar a geracao de uma carteira).
        import entropyforge.report as report_module

        with open(report_module.__file__, encoding="utf-8") as f:
            source = f.read()
        self.assertNotIn("import combine", source)
        self.assertNotIn("import bip39", source)


if __name__ == "__main__":
    unittest.main()
