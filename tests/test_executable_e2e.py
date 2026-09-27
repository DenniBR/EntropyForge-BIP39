"""Testes de ponta a ponta do EXECUTAVEL construido (Fase F, requisito 8):
--version, selftest, vector, generate (via pty real), calibrate, entrada
malformada, interrupcao (SIGINT/SIGTERM), stdin/stdout/stderr, e
isolamento de rede -- tudo contra o binario real produzido por
`tools/build_executable.py`, nao contra o source.

Pulado automaticamente se `nuitka`/gcc nao estiverem disponiveis. Constroi
o executavel UMA VEZ (`setUpClass`) e reusa para todos os testes desta
classe.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import build_executable  # type: ignore  # noqa: E402

from tests.test_generate_interruption_real_subprocess import _PtyChild, _real_d6  # noqa: E402

try:
    build_executable._check_prereqs()
    _PREREQS_OK = True
    _SKIP_REASON = ""
except build_executable.ExecutableBuildError as exc:
    _PREREQS_OK = False
    _SKIP_REASON = str(exc)


@unittest.skipUnless(_PREREQS_OK, f"pre-requisitos de build ausentes: {_SKIP_REASON}")
class ExecutableEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_tmp = Path(tempfile.mkdtemp())
        cls.dist_dir = build_executable.build(cls.build_tmp)
        cls.main_bin = cls.dist_dir / "entropyforge-bip39"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.build_tmp, ignore_errors=True)

    def setUp(self):
        self.cwd = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.cwd, ignore_errors=True)

    # -- subcomandos basicos ------------------------------------------------

    def test_version(self):
        proc = subprocess.run([str(self.main_bin), "--version"], capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("EntropyForge-BIP39", proc.stdout)

    def test_selftest(self):
        proc = subprocess.run([str(self.main_bin), "selftest"], capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("RESULTADO GERAL: PASSOU", proc.stdout)

    def test_vector_entropy_hex(self):
        proc = subprocess.run(
            [str(self.main_bin), "vector", "--entropy-hex", "00" * 32],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("mnemonic:", proc.stdout)

    def test_calibrate_visible_input_via_pipe(self):
        digits = "123456" * 20  # 120 lancamentos, sem TTY necessario (read_line)
        proc = subprocess.run(
            [str(self.main_bin), "calibrate", "--rolls", "120"],
            input=digits + "\n", capture_output=True, text=True, timeout=15, cwd=str(self.cwd),
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("DESCARTAVEIS", proc.stdout.upper())

    # -- entrada malformada ---------------------------------------------------

    def test_malformed_vector_inputs_never_crash_with_traceback(self):
        cases = [
            ["vector", "--entropy-hex", "gg" * 32],
            ["vector", "--entropy-hex", "00" * 10000],
            ["vector", "--mnemonic", "😀" * 24],
            ["vector"],
            ["generate", "--rolls", "0"],
            ["generate", "--rolls", "-1"],
        ]
        for args in cases:
            with self.subTest(args=args):
                proc = subprocess.run(
                    [str(self.main_bin), *args],
                    input=b"", capture_output=True, timeout=15, cwd=str(self.cwd),
                )
                self.assertNotEqual(proc.returncode, 0, msg=f"args={args} deveria ter sido rejeitado")
                combined = proc.stdout + proc.stderr
                self.assertNotIn(b"Traceback (most recent call last)", combined)

    def test_large_but_structurally_valid_vector_input_does_not_crash_or_hang(self):
        # "1"*20000 e um numero GRANDE de lancamentos, mas dentro do
        # limite estrutural (dice.MAX_ROLLS = 65535) -- uma entrada
        # valida, nao malformada; o esperado aqui e sucesso sem travar,
        # nao rejeicao.
        proc = subprocess.run(
            [str(self.main_bin), "vector", "--a-digits", "1" * 20000, "--b-hex", "00" * 32],
            input=b"", capture_output=True, timeout=15, cwd=str(self.cwd),
        )
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn(b"Traceback (most recent call last)", proc.stdout + proc.stderr)

    def test_generate_refuses_nontty_stdin(self):
        proc = subprocess.run(
            [str(self.main_bin), "generate"],
            input=b"123456\n", capture_output=True, timeout=15, cwd=str(self.cwd),
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn(b"123456", proc.stdout + proc.stderr)

    # -- pty real: fluxo completo + interrupcao ------------------------------

    def _advance_to_dice_prompt(self, child: _PtyChild) -> bytes:
        buf = child.read_until(b"Digite exatamente", timeout=15)
        child.send(b"ENTENDO O RISCO\n")
        return child.read_until(b"Digite os", timeout=15)

    def test_full_generate_flow_on_real_pty(self):
        argv = [str(self.main_bin), "generate", "--override-offline-check"]
        child = _PtyChild(argv, self.cwd)
        self.addCleanup(child.close)

        buf = self._advance_to_dice_prompt(child)
        m = re.search(rb"Digite os (\d+) lancamentos", buf)
        self.assertIsNotNone(m)
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
        self.assertEqual(leftover, [], msg=f"arquivos inesperados: {leftover}")

    def test_sigint_during_dice_prompt_leaves_no_trace(self):
        argv = [str(self.main_bin), "generate", "--override-offline-check"]
        child = _PtyChild(argv, self.cwd)
        self.addCleanup(child.close)
        self._advance_to_dice_prompt(child)
        os.kill(child.pid, signal.SIGINT)
        child.wait_exit()
        out = child.drain_remaining()
        self.assertNotRegex(out, rb"[1-6]{6,}")
        self.assertEqual(list(self.cwd.rglob("*")), [])

    def test_sigterm_during_dice_prompt_leaves_no_trace(self):
        argv = [str(self.main_bin), "generate", "--override-offline-check"]
        child = _PtyChild(argv, self.cwd)
        self.addCleanup(child.close)
        self._advance_to_dice_prompt(child)
        os.kill(child.pid, signal.SIGTERM)
        child.wait_exit()
        out = child.drain_remaining()
        self.assertNotRegex(out, rb"[1-6]{6,}")
        self.assertEqual(list(self.cwd.rglob("*")), [])

    # -- ambiente Python hostil ------------------------------------------------

    def test_immune_to_module_shadowing_in_cwd(self):
        # Fase D (docs/INDEPENDENT_VERIFIER.md secao 5) encontrou que
        # `python3 -m entropyforge` (modo dev, sem -I) e vulneravel a um
        # hashlib.py malicioso no diretorio de trabalho. O executavel
        # Nuitka --standalone nao consulta o cwd para resolver modulos
        # (tudo ja esta embutido/compilado) -- este teste confirma isso
        # empiricamente, nao so por design.
        (self.cwd / "hashlib.py").write_text(
            "import sys\n"
            "sys.stderr.write('PWNED: malicious hashlib.py loaded!\\n')\n"
            "def sha256(*a, **k):\n"
            "    raise RuntimeError('hijacked')\n",
            encoding="utf-8",
        )
        proc = subprocess.run(
            [str(self.main_bin), "selftest"], capture_output=True, text=True, timeout=15, cwd=str(self.cwd),
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("RESULTADO GERAL: PASSOU", proc.stdout)
        self.assertNotIn("PWNED", proc.stdout + proc.stderr)

    # -- isolamento de rede ---------------------------------------------------

    @unittest.skipUnless(shutil.which("unshare"), "'unshare' nao disponivel neste sistema")
    def test_runs_correctly_with_network_namespace_isolated(self):
        # `unshare --net` da ao processo filho uma pilha de rede vazia
        # (so loopback) -- generate deve se recusar (sem override) do
        # mesmo jeito que se recusaria com rede real ativa E indisponivel
        # para checar, OU prosseguir se nao houver interface alem de lo
        # (que e exatamente o caso aqui). O que importa e que ele RODE
        # (nao trave, nao precise de rede) e produza a mesma recusa/aceite
        # coerente de sempre.
        try:
            proc = subprocess.run(
                ["unshare", "--net", "--", str(self.main_bin), "selftest"],
                capture_output=True, text=True, timeout=15, cwd=str(self.cwd),
            )
        except PermissionError:
            self.skipTest("sem permissao para criar namespaces de rede neste ambiente")
        if proc.returncode != 0 and "Operation not permitted" in proc.stderr:
            self.skipTest("unshare --net nao permitido neste ambiente (sandbox sem CAP_SYS_ADMIN)")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("RESULTADO GERAL: PASSOU", proc.stdout)


if __name__ == "__main__":
    unittest.main()
