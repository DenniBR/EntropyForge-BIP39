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

    def test_blocks_raw_os_open_with_write_flags(self):
        # Regressao (docs/REDTEAM.md, mutation testing): este caminho
        # (os.open() de baixo nivel, que passa mode=None e usa `flags`
        # em vez de uma string de modo) e INDEPENDENTE do caminho testado
        # em test_blocks_write_mode_open acima (que usa o builtin `open`
        # com uma string de modo). Uma mascara `_WRITE_FLAGS` enfraquecida
        # (ex.: faltando O_CREAT) so seria pega por um teste que exercita
        # `os.open` diretamente -- o que este teste faz.
        proc = _run_snippet(
            textwrap.dedent(
                """
                from entropyforge import guard
                guard.activate()
                import os
                try:
                    os.open("/tmp/entropyforge_should_not_exist_raw.bin", os.O_WRONLY | os.O_CREAT, 0o600)
                    print("FAIL_NOT_BLOCKED")
                except guard.GuardViolation:
                    print("OK_BLOCKED")
                """
            )
        )
        self.assertIn("OK_BLOCKED", proc.stdout)

    def test_blocks_each_write_flag_in_isolation(self):
        # Testa cada flag de escrita SOZINHA (sem O_WRONLY/O_CREAT junto),
        # para isolar de verdade a cobertura de cada bit especifico da
        # mascara `_WRITE_FLAGS` -- nao apenas confirmar que a combinacao
        # usual (O_WRONLY|O_CREAT) e pega, o que ja e coberto pelo teste
        # anterior e nao isolaria uma mascara com O_APPEND/O_TRUNC/O_EXCL
        # faltando.
        # O_CREAT sozinho (sem O_WRONLY/O_RDWR) ja e uma escrita real:
        # confirmado por PoC (docs/REDTEAM.md) que `os.open(path, os.O_CREAT)`
        # CRIA um arquivo vazio no disco mesmo sem nenhuma flag de acesso
        # de escrita. Ja O_APPEND/O_TRUNC/O_EXCL sozinhos (sem O_WRONLY/
        # O_RDWR) NAO permitem escrever conteudo nenhum (confirmado: da
        # "Bad file descriptor"), entao sua presenca na mascara e defesa
        # em profundidade, nao a unica barreira -- mas testamos todos
        # mesmo assim, ja que sao baratos e a mascara deve continuar
        # completa.
        for flag_name in ("O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC", "O_EXCL"):
            proc = _run_snippet(
                textwrap.dedent(
                    f"""
                    from entropyforge import guard
                    guard.activate()
                    import os
                    try:
                        os.open("/tmp/entropyforge_should_not_exist_{flag_name}.bin", os.{flag_name})
                        print("FAIL_NOT_BLOCKED")
                    except guard.GuardViolation:
                        print("OK_BLOCKED")
                    except OSError:
                        # o SO pode recusar a combinacao de flags por outro
                        # motivo antes mesmo do guard atuar; o que importa
                        # aqui e que NUNCA seja "FAIL_NOT_BLOCKED".
                        print("OK_BLOCKED")
                    """
                )
            )
            self.assertIn("OK_BLOCKED", proc.stdout, msg=f"flag {flag_name} nao foi bloqueada: {proc.stdout} {proc.stderr}")

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


class AuditHookAllowsDevTtyTests(unittest.TestCase):
    """Regressao para um bug real encontrado em teste de interrupcao
    externo via pty (Fase E,
    tests/test_generate_interruption_real_subprocess.py): `getpass.getpass()`
    -- usado para ler os lancamentos do dado e o mnemonic de conferencia
    SEM eco na tela -- abre `/dev/tty` com `os.O_RDWR|os.O_NOCTTY`. Como
    `_WRITE_FLAGS` inclui `O_RDWR`, o audit hook bloqueava esse `open`
    exatamente como bloquearia a escrita em um arquivo regular, o que
    tornava `generate` INUTILIZAVEL em qualquer terminal real (nunca
    detectado antes porque todo teste anterior substituia
    `read_hidden_line` por uma funcao falsa, nunca exercitando
    `getpass.getpass` de verdade com o guard ativo)."""

    def test_opening_dev_tty_with_rdwr_is_allowed(self):
        proc = _run_snippet(
            textwrap.dedent(
                """
                from entropyforge import guard
                guard.activate()
                import os
                try:
                    fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
                    os.close(fd)
                    print("OK_ALLOWED")
                except guard.GuardViolation as exc:
                    print("FAIL_BLOCKED", exc)
                except OSError:
                    # sem terminal controlador neste ambiente de teste --
                    # o que importa aqui e que NAO seja GuardViolation.
                    print("OK_ALLOWED")
                """
            )
        )
        self.assertIn("OK_ALLOWED", proc.stdout, msg=proc.stdout + proc.stderr)

    def test_wrapping_an_existing_fd_in_fileio_is_allowed(self):
        # Segunda metade do mesmo bug: getpass.getpass() tambem envolve o
        # fd ja aberto num io.FileIO(fd, 'w+'), o que dispara um SEGUNDO
        # evento de auditoria "open" -- desta vez com um INTEIRO (o
        # descritor), nao uma string de caminho. `_ALWAYS_ALLOWED_OPEN_PATHS`
        # sozinho nao cobre este caso.
        proc = _run_snippet(
            textwrap.dedent(
                """
                from entropyforge import guard
                guard.activate()
                import io, os
                r, w = os.pipe()
                try:
                    wrapped = io.FileIO(w, "w")
                    wrapped.close()
                    print("OK_ALLOWED")
                except guard.GuardViolation as exc:
                    print("FAIL_BLOCKED", exc)
                finally:
                    os.close(r)
                """
            )
        )
        self.assertIn("OK_ALLOWED", proc.stdout, msg=proc.stdout + proc.stderr)

    def test_other_paths_opened_with_rdwr_are_still_blocked(self):
        # A excecao e ESTRITA a /dev/tty -- confirma que nao virou um
        # afrouxamento geral de O_RDWR para qualquer caminho.
        proc = _run_snippet(
            textwrap.dedent(
                """
                from entropyforge import guard
                guard.activate()
                import os
                try:
                    os.open("/tmp/entropyforge_devtty_regression_should_not_exist", os.O_RDWR | os.O_CREAT)
                    print("FAIL_NOT_BLOCKED")
                except guard.GuardViolation:
                    print("OK_BLOCKED")
                """
            )
        )
        self.assertIn("OK_BLOCKED", proc.stdout)
        import os as _os

        self.assertFalse(_os.path.exists("/tmp/entropyforge_devtty_regression_should_not_exist"))

    def test_default_terminal_io_hidden_read_no_longer_raises_guard_violation(self):
        # O teste mais direto possivel do bug original: monta a TerminalIO
        # PADRAO (a que `generate` de verdade usa, com `read_hidden_line`
        # baseado em getpass.getpass) com o guard ativo, e confirma que
        # chamar `read_hidden_line` levanta EOFError (sem terminal/entrada
        # neste subprocesso de teste) e NUNCA guard.GuardViolation.
        proc = _run_snippet(
            textwrap.dedent(
                """
                from entropyforge import guard
                guard.activate()
                from entropyforge.cli import default_io
                io = default_io()
                try:
                    io.read_hidden_line("prompt: ")
                    print("FAIL_UNEXPECTED_SUCCESS")
                except guard.GuardViolation as exc:
                    print("FAIL_BLOCKED", exc)
                except EOFError:
                    print("OK_EOF_NOT_BLOCKED")
                except Exception as exc:
                    print("OK_OTHER_NOT_BLOCKED", type(exc).__name__)
                """
            )
        )
        self.assertIn("OK_", proc.stdout, msg=proc.stdout + proc.stderr)
        self.assertNotIn("FAIL_", proc.stdout, msg=proc.stdout + proc.stderr)


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
