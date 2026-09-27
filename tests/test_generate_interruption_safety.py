"""Caso negativo explicito: interrupcao do processo no meio do fluxo
`generate` (ex.: falha do CSPRNG do SO logo apos a coleta dos lancamentos,
ou uma KeyboardInterrupt) nao deve deixar a sequencia de dados nem
qualquer segredo parcial no texto da excecao/traceback."""

import os
import unittest

from entropyforge import entropy_calc
from entropyforge.cli import NETWORK_OVERRIDE_PHRASE, TerminalIO, build_parser, cmd_generate
from entropyforge.osrng import OsRngError


def _real_d6(n: int) -> str:
    out = []
    while len(out) < n:
        for byte in os.getrandom(64, 0):
            if byte < 252:
                out.append(str(byte % 6 + 1))
                if len(out) == n:
                    break
    return "".join(out)


class InterruptionDuringOsrngReadTests(unittest.TestCase):
    def test_osrng_failure_after_dice_entry_does_not_leak_digits_in_exception(self):
        budget = entropy_calc.compute_budget()
        digits = _real_d6(budget.rolls_operational)
        captured = []

        def failing_read_os_entropy():
            raise OsRngError("falha simulada do CSPRNG apos a coleta dos dados")

        io = TerminalIO(
            stdin_isatty=lambda: True,
            stdout_isatty=lambda: True,
            read_hidden_line=lambda prompt: digits,
            read_line=lambda prompt: NETWORK_OVERRIDE_PHRASE,
            write=lambda s: captured.append(s),
            warn=lambda s: captured.append(s),
            enter_alt_screen=lambda: captured.append("<<<ALT_ENTER>>>"),
            leave_alt_screen=lambda: captured.append("<<<ALT_LEAVE>>>"),
            clear_screen=lambda: None,
            wait_enter=lambda p: None,
            read_os_entropy=failing_read_os_entropy,
        )
        args = build_parser().parse_args(["generate", "--override-offline-check"])

        # cmd_generate trata OsRngError explicitamente (falha limpa, sem
        # traceback cru) e devolve um codigo de saida diferente de zero.
        rc = cmd_generate(args, io)
        self.assertNotEqual(rc, 0)

        blob = "\n".join(captured)
        self.assertNotIn(digits, blob)
        self.assertNotIn("<<<ALT_ENTER>>>", blob)  # nunca chegou a exibir o mnemonic

    def test_keyboard_interrupt_during_hidden_read_does_not_leak_partial_input(self):
        captured = []

        def interrupting_read_hidden_line(prompt):
            raise KeyboardInterrupt()

        io = TerminalIO(
            stdin_isatty=lambda: True,
            stdout_isatty=lambda: True,
            read_hidden_line=interrupting_read_hidden_line,
            read_line=lambda prompt: NETWORK_OVERRIDE_PHRASE,
            write=lambda s: captured.append(s),
            warn=lambda s: captured.append(s),
            enter_alt_screen=lambda: captured.append("<<<ALT_ENTER>>>"),
            leave_alt_screen=lambda: captured.append("<<<ALT_LEAVE>>>"),
            clear_screen=lambda: None,
            wait_enter=lambda p: None,
            read_os_entropy=lambda: os.getrandom(32, 0),
        )
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        with self.assertRaises(KeyboardInterrupt):
            cmd_generate(args, io)
        self.assertNotIn("<<<ALT_ENTER>>>", "\n".join(captured))


if __name__ == "__main__":
    unittest.main()
