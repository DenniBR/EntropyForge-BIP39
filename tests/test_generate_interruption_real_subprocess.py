"""Teste de interrupcao EXTERNO (Fase E): interrompe um `entropyforge.pyz
generate` de verdade -- processo filho real, terminal pseudo (`pty`) real,
sinais reais do kernel (SIGINT/SIGTERM) -- em vez de chamar `cmd_generate`
diretamente em processo (como `tests/test_generate_interruption_safety.py`
ja faz). A diferenca importa: aqui a saida capturada e exatamente o que um
observador externo veria (stdout/stderr reais do processo, nao a
abstracao `TerminalIO`), e o sinal e entregue pelo kernel de verdade, nao
simulado levantando uma excecao Python.

Usa `pty.fork()` (biblioteca padrao) para dar ao processo filho um
terminal controlador de verdade -- necessario porque `getpass.getpass()`
(usado para a leitura oculta de digitos) abre `/dev/tty` diretamente, o
que so funciona se o processo tiver um terminal controlador (um
`subprocess.Popen` com pipes comuns NAO satisfaz isso).
"""

from __future__ import annotations

import os
import pty
import re
import select
import shutil
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _real_d6(n: int) -> str:
    out = []
    while len(out) < n:
        for byte in os.getrandom(64, 0):
            if byte < 252:
                out.append(str(byte % 6 + 1))
                if len(out) == n:
                    break
    return "".join(out)


def _build_pyz(out_path: Path) -> None:
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import build_pyz  # type: ignore

    build_pyz.build(out_path)


class _PtyChild:
    """Envolve `pty.fork()` + leitura/escrita nao-bloqueante, para os
    testes desta classe interagirem com o processo filho como um
    terminal real faria."""

    def __init__(self, argv: list[str], cwd: Path):
        self.pid, self.master_fd = pty.fork()
        if self.pid == 0:  # processo filho
            try:
                os.chdir(str(cwd))
                os.execvp(argv[0], argv)
            finally:
                os._exit(127)  # so alcancado se execvp falhar
        self._buf = b""

    def read_until(self, marker: bytes, timeout: float = 15.0) -> bytes:
        """Le do pty ate `marker` aparecer no buffer acumulado, ou ate
        `timeout` segundos se esgotarem (levanta `AssertionError`, para um
        teste travado nunca travar o processo de teste inteiro)."""
        deadline = time.monotonic() + timeout
        while marker not in self._buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    f"timeout esperando por {marker!r} na saida do processo; "
                    f"recebido ate agora: {self._buf!r}"
                )
            r, _, _ = select.select([self.master_fd], [], [], remaining)
            if not r:
                continue
            try:
                chunk = os.read(self.master_fd, 4096)
            except OSError:
                break  # pty fechado do outro lado
            if not chunk:
                break
            self._buf += chunk
        return self._buf

    def send(self, data: bytes) -> None:
        os.write(self.master_fd, data)

    def drain_remaining(self, timeout: float = 3.0) -> bytes:
        """Le tudo que ainda chegar em ate `timeout` segundos (usado apos
        o processo ja ter recebido um sinal, para capturar qualquer saida
        final antes da saida do processo)."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            r, _, _ = select.select([self.master_fd], [], [], remaining)
            if not r:
                break
            try:
                chunk = os.read(self.master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            self._buf += chunk
        return self._buf

    def wait_exit(self, timeout: float = 10.0) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            wpid, status = os.waitpid(self.pid, os.WNOHANG)
            if wpid != 0:
                return status
            time.sleep(0.05)
        os.kill(self.pid, signal.SIGKILL)
        os.waitpid(self.pid, 0)
        raise AssertionError("processo nao terminou apos o sinal (ficou pendurado)")

    def close(self) -> None:
        try:
            os.close(self.master_fd)
        except OSError:
            pass


@unittest.skipUnless(hasattr(pty, "fork"), "pty.fork indisponivel nesta plataforma")
class RealSignalInterruptionTests(unittest.TestCase):
    """Cada teste: builda o .pyz uma vez (setUpClass), roda `generate` de
    verdade sob um pty, avanca ate um ponto especifico do fluxo, envia um
    sinal real do kernel, e confirma (a) o processo termina rapido, (b)
    nenhum digito do dado (nem parcial) aparece em nenhuma saida
    capturada, e (c) nenhum arquivo novo aparece no diretorio de trabalho
    (nem um core dump, nem qualquer outro arquivo -- o programa nunca deve
    escrever em disco, interrompido ou nao)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.pyz = cls.tmp / "entropyforge.pyz"
        _build_pyz(cls.pyz)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.cwd = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.cwd, ignore_errors=True)

    def _spawn(self) -> _PtyChild:
        argv = [sys.executable, "-I", "-B", str(self.pyz), "generate", "--override-offline-check"]
        child = _PtyChild(argv, self.cwd)
        self.addCleanup(child.close)
        return child

    def _advance_past_network_override_if_present(self, child: _PtyChild) -> bytes:
        """Este sandbox tem uma interface de rede ativa (`eth0`), entao
        `generate` sempre pede a frase de confirmacao explicita. Avanca
        por isso e devolve o buffer acumulado ate o prompt de digitos."""
        buf = child.read_until(b"Digite exatamente", timeout=15)
        child.send(b"ENTENDO O RISCO\n")
        buf = child.read_until(b"Digite os", timeout=15)
        return buf

    def _assert_no_new_files(self) -> None:
        leftover = list(self.cwd.rglob("*"))
        self.assertEqual(leftover, [], msg=f"arquivos inesperados criados em {self.cwd}: {leftover}")

    def test_sigint_before_any_digit_typed(self):
        child = self._spawn()
        self._advance_past_network_override_if_present(child)
        os.kill(child.pid, signal.SIGINT)
        status = child.wait_exit()
        self.assertNotEqual(status, 0, msg="processo terminou com codigo 0 apos SIGINT (inesperado)")
        out = child.drain_remaining()
        self.assertNotRegex(out, rb"[1-6]{6,}")
        self._assert_no_new_files()

    def test_sigterm_before_any_digit_typed(self):
        child = self._spawn()
        self._advance_past_network_override_if_present(child)
        os.kill(child.pid, signal.SIGTERM)
        child.wait_exit()
        out = child.drain_remaining()
        self.assertNotRegex(out, rb"[1-6]{6,}")
        self._assert_no_new_files()

    def test_sigint_with_partial_untyped_line_buffered(self):
        # Digita METADE de uma sequencia plausivel de digitos, SEM Enter
        # (fica no buffer de linha do proprio terminal, em modo canonico
        # -- getpass.getpass() ainda nao leu nada disso), depois manda
        # SIGINT. O processo nunca chega a VER esses digitos (ainda estao
        # no buffer do kernel do pty, nunca entregues via read()), entao
        # eles nao podem aparecer em nenhuma saida do processo -- este
        # teste confirma isso empiricamente, nao so por raciocinio.
        child = self._spawn()
        self._advance_past_network_override_if_present(child)
        partial = b"123456" * 10  # nunca confirmado com Enter
        child.send(partial)
        time.sleep(0.3)  # da tempo do driver de tty receber os bytes
        os.kill(child.pid, signal.SIGINT)
        child.wait_exit()
        out = child.drain_remaining()
        self.assertNotIn(partial, out)
        self.assertNotRegex(out, rb"[1-6]{6,}")
        self._assert_no_new_files()

    def test_sigkill_leaves_no_trace_on_disk(self):
        # SIGKILL nao pode ser capturado nem tratado -- o teste mais
        # extremo possivel. A unica coisa que se pode garantir e o que o
        # KERNEL garante (nenhum arquivo novo em disco), nunca uma
        # limpeza feita pelo proprio programa (que nunca roda).
        child = self._spawn()
        self._advance_past_network_override_if_present(child)
        os.kill(child.pid, signal.SIGKILL)
        child.wait_exit()
        self._assert_no_new_files()


@unittest.skipUnless(hasattr(pty, "fork"), "pty.fork indisponivel nesta plataforma")
class RealTerminalHappyPathTests(unittest.TestCase):
    """Confirma que `generate` FUNCIONA de ponta a ponta num terminal
    real (nao interrompido) -- ou seja, que os testes de interrupcao desta
    classe estao testando um caminho que tambem tem sucesso, nao apenas
    testando que falhas de um caminho que nunca funcionaria de qualquer
    jeito nao vazam nada. Esta classe existe porque, sem ela, um bug que
    quebrasse a entrada oculta de digitos em QUALQUER terminal real
    (exatamente o que aconteceu aqui, ver `entropyforge/guard.py`,
    `_ALWAYS_ALLOWED_OPEN_PATHS`) teria feito CADA teste de interrupcao
    desta classe passar por um motivo errado: o processo nunca chega a
    fazer nada de fato, entao 'nada vazou' seria verdade so por
    vacuidade."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.pyz = cls.tmp / "entropyforge.pyz"
        _build_pyz(cls.pyz)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.cwd = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.cwd, ignore_errors=True)

    def test_full_generate_flow_succeeds_on_a_real_pty(self):
        argv = [sys.executable, "-I", "-B", str(self.pyz), "generate", "--override-offline-check"]
        child = _PtyChild(argv, self.cwd)
        self.addCleanup(child.close)

        child.read_until(b"Digite exatamente", timeout=15)
        child.send(b"ENTENDO O RISCO\n")
        buf = child.read_until(b"Digite os", timeout=15)
        m = re.search(rb"Digite os (\d+) lancamentos", buf)
        self.assertIsNotNone(m, msg=f"nao encontrou o numero de lancamentos pedido em {buf!r}")
        n = int(m.group(1))

        digits = _real_d6(n)
        child.send(digits.encode("ascii") + b"\n")
        child.read_until(b"SEU MNEMONIC", timeout=20)
        child.read_until(b"Pressione Enter", timeout=10)
        child.send(b"\n")
        child.read_until(b"Deseja conferir", timeout=10)
        child.send(b"n\n")
        buf = child.read_until(b"Concluido", timeout=10)

        status = child.wait_exit()
        self.assertTrue(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, msg=f"status={status!r}")
        self.assertNotIn(digits.encode("ascii"), buf)
        leftover = list(self.cwd.rglob("*"))
        self.assertEqual(leftover, [], msg=f"arquivos inesperados criados em {self.cwd}: {leftover}")


if __name__ == "__main__":
    unittest.main()
