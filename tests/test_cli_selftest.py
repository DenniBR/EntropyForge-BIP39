"""Teste do subcomando `selftest` via a interface publica do CLI.

`main()` ativa `guard.activate()` (audit hook que nunca pode ser
removido do processo). Por isso o teste que passa por `main()` roda em um
SUBPROCESSO isolado (como em tests/test_guard.py) -- chama-lo no processo
principal de testes contaminaria permanentemente todos os testes
seguintes na mesma sessao do `unittest`."""

import subprocess
import sys
import unittest
from pathlib import Path

from entropyforge.cli import TerminalIO, build_parser, cmd_selftest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _io():
    captured = []
    return TerminalIO(write=lambda s: captured.append(s), warn=lambda s: captured.append(s)), captured


class CliSelftestTests(unittest.TestCase):
    def test_exit_code_zero_on_healthy_install(self):
        io, captured = _io()
        args = build_parser().parse_args(["selftest"])
        rc = cmd_selftest(args, io)
        self.assertEqual(rc, 0)
        self.assertIn("PASSOU", "\n".join(captured))

    def test_main_dispatches_to_selftest(self):
        proc = subprocess.run(
            [sys.executable, "-B", "-m", "entropyforge", "selftest"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("PASSOU", proc.stdout)


if __name__ == "__main__":
    unittest.main()
