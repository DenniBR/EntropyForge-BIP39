"""Testes de entropyforge.guard.

O audit hook instalado por `guard.activate()` NAO PODE ser removido do
processo Python em que foi instalado (garantia do proprio interpretador,
PEP 578). Por isso, todo teste que efetivamente ativa o guard roda em um
SUBPROCESSO isolado (`python3 -B -c "..."`), para nao contaminar o
restante desta suite de testes. Os testes de `check_offline` (que nao
ativam o hook) rodam normalmente no processo de teste.
"""

import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from entropyforge import guard

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_snippet(snippet: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-B", "-c", snippet],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )


class AuditHookBlocksNetworkTests(unittest.TestCase):
    def test_blocks_socket_creation(self):
        proc = _run_snippet(
            textwrap.dedent(
                """
                from entropyforge import guard
                guard.activate()
                import socket
                try:
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    print("FAIL_NOT_BLOCKED")
                except guard.GuardViolation:
                    print("OK_BLOCKED")
                """
            )
        )
        self.assertIn("OK_BLOCKED", proc.stdout)
        self.assertNotIn("FAIL_NOT_BLOCKED", proc.stdout)


class AuditHookBlocksSubprocessTests(unittest.TestCase):
    def test_blocks_subprocess_popen(self):
        proc = _run_snippet(
            textwrap.dedent(
                """
                from entropyforge import guard
                guard.activate()
                import subprocess as sp
                try:
                    sp.Popen(["true"])
                    print("FAIL_NOT_BLOCKED")
                except guard.GuardViolation:
                    print("OK_BLOCKED")
                """
            )
        )
        self.assertIn("OK_BLOCKED", proc.stdout)

    def test_blocks_os_system(self):
        proc = _run_snippet(
            textwrap.dedent(
                """
                from entropyforge import guard
                guard.activate()
                import os
                try:
                    os.system("true")
                    print("FAIL_NOT_BLOCKED")
                except guard.GuardViolation:
                    print("OK_BLOCKED")
                """
            )
        )
        self.assertIn("OK_BLOCKED", proc.stdout)


class AuditHookBlocksFileWriteTests(unittest.TestCase):
    def test_blocks_write_mode_open(self):
        proc = _run_snippet(
            textwrap.dedent(
                """
                from entropyforge import guard
                guard.activate()
                try:
                    open("/tmp/entropyforge_should_not_exist.txt", "w")
                    print("FAIL_NOT_BLOCKED")
                except guard.GuardViolation:
                    print("OK_BLOCKED")
                """
            )
        )
        self.assertIn("OK_BLOCKED", proc.stdout)

    def test_read_mode_still_works(self):
        proc = _run_snippet(
            textwrap.dedent(
                """
                from entropyforge import guard, wordlist
                guard.activate()
                words = wordlist.load_wordlist()
                print("OK_READ", len(words))
                """
            )
        )
        self.assertIn("OK_READ 2048", proc.stdout)

    def test_blocks_os_remove(self):
        proc = _run_snippet(
            textwrap.dedent(
                """
                from entropyforge import guard
                guard.activate()
                import os
                try:
                    os.remove("/tmp/nonexistent-does-not-matter")
                    print("FAIL_NOT_BLOCKED")
                except guard.GuardViolation:
                    print("OK_BLOCKED")
                except FileNotFoundError:
                    print("FAIL_NOT_BLOCKED")
                """
            )
        )
        self.assertIn("OK_BLOCKED", proc.stdout)


class NetworkOfflineCheckTests(unittest.TestCase):
    """Estes testes NAO ativam o audit hook (so chamam check_offline), por
    isso podem rodar no processo principal de teste."""

    def test_raises_when_interfaces_active(self):
        with mock.patch.object(guard, "list_active_network_interfaces", return_value=["eth0"]):
            with self.assertRaises(guard.GuardViolation):
                guard.check_offline(allow_override=False)

    def test_override_suppresses_active_interfaces(self):
        with mock.patch.object(guard, "list_active_network_interfaces", return_value=["eth0"]):
            result = guard.check_offline(allow_override=True)
            self.assertEqual(result, ["eth0"])

    def test_passes_when_no_interfaces_active(self):
        with mock.patch.object(guard, "list_active_network_interfaces", return_value=[]):
            result = guard.check_offline(allow_override=False)
            self.assertEqual(result, [])

    def test_platform_unsupported_fails_closed(self):
        with mock.patch.object(
            guard, "list_active_network_interfaces", side_effect=NotImplementedError
        ):
            with self.assertRaises(guard.GuardViolation):
                guard.check_offline(allow_override=False)

    def test_platform_unsupported_with_override_passes(self):
        with mock.patch.object(
            guard, "list_active_network_interfaces", side_effect=NotImplementedError
        ):
            result = guard.check_offline(allow_override=True)
            self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
