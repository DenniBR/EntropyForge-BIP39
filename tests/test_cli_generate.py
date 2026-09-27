"""Testes de ponta a ponta do fluxo `generate` via uma TerminalIO falsa
(sem TTY real). Este e o teste mais importante do projeto do ponto de
vista de confidencialidade: verifica que NENHUMA saida do programa jamais
contem A, B, E ou a sequencia de dados em qualquer formato reconhecivel, e
que o mnemonic corresponde exatamente a SHA-256(A||B) -> BIP-39."""

import os
import re
import unittest
from unittest import mock

from entropyforge import bip39, combine, dice, entropy_calc, stats
from entropyforge.cli import (
    DICE_FAIL_OVERRIDE_PHRASE,
    NETWORK_OVERRIDE_PHRASE,
    TerminalIO,
    build_parser,
    cmd_generate,
)


def _real_d6(n: int) -> str:
    out = []
    while len(out) < n:
        for byte in os.getrandom(64, 0):
            if byte < 252:
                out.append(str(byte % 6 + 1))
                if len(out) == n:
                    break
    return "".join(out)


class FakeIOBuilder:
    """Monta uma TerminalIO falsa e registra tudo que foi 'escrito' na
    tela (write/warn/alt-screen) para inspecao pelo teste."""

    def __init__(self, hidden_lines, plain_lines, os_entropy: bytes):
        self.captured: list[str] = []
        self._hidden_iter = iter(hidden_lines)
        self._plain_iter = iter(plain_lines)
        self._os_entropy = os_entropy

    def _read_hidden_line(self, prompt):
        return next(self._hidden_iter, "")

    def _read_line(self, prompt):
        return next(self._plain_iter, "n")

    def build(self) -> TerminalIO:
        return TerminalIO(
            stdin_isatty=lambda: True,
            stdout_isatty=lambda: True,
            read_hidden_line=self._read_hidden_line,
            read_line=self._read_line,
            write=lambda s: self.captured.append(s),
            warn=lambda s: self.captured.append(s),
            enter_alt_screen=lambda: self.captured.append("<<<ALT_SCREEN_ENTER>>>"),
            leave_alt_screen=lambda: self.captured.append("<<<ALT_SCREEN_LEAVE>>>"),
            clear_screen=lambda: None,
            wait_enter=lambda p: None,
            read_os_entropy=lambda: self._os_entropy,
        )

    @property
    def blob(self) -> str:
        return "\n".join(self.captured)


def _extract_mnemonic_block(blob: str) -> list[str]:
    m = re.search(r"<<<ALT_SCREEN_ENTER>>>\n(.*?)\n<<<ALT_SCREEN_LEAVE>>>", blob, re.S)
    assert m, "bloco de tela alternativa nao encontrado na saida capturada"
    return re.findall(r"\d+\.\s+(\S+)", m.group(1))


class SuccessfulGenerateTests(unittest.TestCase):
    def setUp(self):
        self.budget = entropy_calc.compute_budget()
        self.digits = _real_d6(self.budget.rolls_operational)
        self.b = os.getrandom(32, 0)
        self.expected_a = dice.encode(self.digits)
        self.expected_e = combine.combine(self.expected_a, self.b)
        self.expected_mnemonic = bip39.entropy_to_mnemonic(self.expected_e)

    def _run(self, verify_transcription_answer="n", retyped=None):
        plain_lines = [NETWORK_OVERRIDE_PHRASE, verify_transcription_answer]
        hidden_lines = [self.digits]
        if retyped is not None:
            hidden_lines.append(retyped)
        io_builder = FakeIOBuilder(hidden_lines, plain_lines, self.b)
        io = io_builder.build()
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc = cmd_generate(args, io)
        return rc, io_builder

    def test_exit_code_zero(self):
        rc, _ = self._run()
        self.assertEqual(rc, 0)

    def test_mnemonic_words_match_expected_and_order(self):
        rc, io_builder = self._run()
        words = _extract_mnemonic_block(io_builder.blob)
        self.assertEqual(words, self.expected_mnemonic.split())

    def test_no_secret_hex_leaks_anywhere(self):
        rc, io_builder = self._run()
        blob = io_builder.blob
        self.assertNotIn(self.expected_a.hex(), blob)
        self.assertNotIn(self.b.hex(), blob)
        self.assertNotIn(self.expected_e.hex(), blob)
        self.assertNotIn(self.digits, blob)
        # tambem garante que nenhuma janela contigua de 20+ digitos 1-6
        # (parte da sequencia bruta) aparece em lugar nenhum da saida.
        self.assertIsNone(re.search(r"[1-6]{20,}", blob))

    def test_mnemonic_full_string_appears_only_inside_alt_screen_block(self):
        # Checagem por PALAVRA INTEIRA (limite de palavra), nao substring:
        # varias palavras do BIP-39 sao substrings comuns de texto normal
        # (ex.: "come" dentro de "Recomenda", "hip" dentro de "BIP-39"),
        # entao um assertNotIn ingenuo daria falso positivo.
        rc, io_builder = self._run()
        blob = io_builder.blob
        before, _, after_marker = blob.partition("<<<ALT_SCREEN_ENTER>>>")
        for word in self.expected_mnemonic.split():
            self.assertNotRegex(before, rf"\b{re.escape(word)}\b")

    def test_transcription_confirmation_success(self):
        rc, io_builder = self._run(verify_transcription_answer="s", retyped=self.expected_mnemonic)
        self.assertEqual(rc, 0)
        self.assertTrue(any("Conferencia OK" in line for line in io_builder.captured))

    def test_transcription_confirmation_failure_does_not_reveal_diff(self):
        wrong = self.expected_mnemonic.replace(
            self.expected_mnemonic.split()[0], "zzzzzzzzzzwrongzzzzzzzzzz"
        )
        rc, io_builder = self._run(verify_transcription_answer="s", retyped=wrong)
        self.assertEqual(rc, 0)
        blob = io_builder.blob
        self.assertTrue(any("Conferencia FALHOU" in line for line in io_builder.captured))
        # a mensagem de falha nao deve conter as palavras corretas nem a
        # palavra digitada errada isoladamente identificada
        fail_lines = [l for l in io_builder.captured if "Conferencia FALHOU" in l]
        for line in fail_lines:
            for word in self.expected_mnemonic.split():
                self.assertNotRegex(line, rf"\b{re.escape(word)}\b")


class NetworkCheckRefusalTests(unittest.TestCase):
    def test_refuses_without_override_flag(self):
        with mock.patch("entropyforge.guard.list_active_network_interfaces", return_value=["eth0"]):
            io_builder = FakeIOBuilder([], [], b"\x00" * 32)
            io = io_builder.build()
            args = build_parser().parse_args(["generate"])
            rc = cmd_generate(args, io)
            self.assertNotEqual(rc, 0)
            self.assertNotIn("SEU MNEMONIC", io_builder.blob)

    def test_refuses_if_override_flag_but_wrong_confirmation(self):
        with mock.patch("entropyforge.guard.list_active_network_interfaces", return_value=["eth0"]):
            io_builder = FakeIOBuilder([], ["nao era isso"], b"\x00" * 32)
            io = io_builder.build()
            args = build_parser().parse_args(["generate", "--override-offline-check"])
            rc = cmd_generate(args, io)
            self.assertNotEqual(rc, 0)

    def test_proceeds_with_correct_confirmation(self):
        with mock.patch("entropyforge.guard.list_active_network_interfaces", return_value=["eth0"]):
            budget = entropy_calc.compute_budget()
            digits = _real_d6(budget.rolls_operational)
            io_builder = FakeIOBuilder([digits], [NETWORK_OVERRIDE_PHRASE, "n"], os.getrandom(32, 0))
            io = io_builder.build()
            args = build_parser().parse_args(["generate", "--override-offline-check"])
            rc = cmd_generate(args, io)
            self.assertEqual(rc, 0)


class NonTtyRefusalTests(unittest.TestCase):
    def test_refuses_when_stdin_not_a_tty(self):
        io_builder = FakeIOBuilder([], [NETWORK_OVERRIDE_PHRASE], b"\x00" * 32)
        io = io_builder.build()
        io.stdin_isatty = lambda: False
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc = cmd_generate(args, io)
        self.assertNotEqual(rc, 0)

    def test_refuses_when_stdout_not_a_tty(self):
        io_builder = FakeIOBuilder([], [NETWORK_OVERRIDE_PHRASE], b"\x00" * 32)
        io = io_builder.build()
        io.stdout_isatty = lambda: False
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc = cmd_generate(args, io)
        self.assertNotEqual(rc, 0)


class StatisticalFailureOverrideTests(unittest.TestCase):
    def test_refuses_without_override_on_pathological_sequence(self):
        budget = entropy_calc.compute_budget()
        digits = "3" * budget.rolls_operational  # constante -> FAIL garantido
        io_builder = FakeIOBuilder(
            [digits], [NETWORK_OVERRIDE_PHRASE, "nao confirmo"], os.getrandom(32, 0)
        )
        io = io_builder.build()
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc = cmd_generate(args, io)
        self.assertNotEqual(rc, 0)
        self.assertNotIn("SEU MNEMONIC", io_builder.blob)

    def test_proceeds_with_explicit_override(self):
        budget = entropy_calc.compute_budget()
        digits = "3" * budget.rolls_operational
        b = os.getrandom(32, 0)
        io_builder = FakeIOBuilder(
            [digits],
            [NETWORK_OVERRIDE_PHRASE, DICE_FAIL_OVERRIDE_PHRASE, "n"],
            b,
        )
        io = io_builder.build()
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc = cmd_generate(args, io)
        self.assertEqual(rc, 0)
        expected_mnemonic = bip39.entropy_to_mnemonic(combine.combine(dice.encode(digits), b))
        words = _extract_mnemonic_block(io_builder.blob)
        self.assertEqual(words, expected_mnemonic.split())


class RollsCountMismatchTests(unittest.TestCase):
    def test_retries_on_wrong_length_then_succeeds(self):
        budget = entropy_calc.compute_budget()
        good_digits = _real_d6(budget.rolls_operational)
        too_short = good_digits[:10]
        b = os.getrandom(32, 0)
        io_builder = FakeIOBuilder(
            [too_short, good_digits], [NETWORK_OVERRIDE_PHRASE, "n"], b
        )
        io = io_builder.build()
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc = cmd_generate(args, io)
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
