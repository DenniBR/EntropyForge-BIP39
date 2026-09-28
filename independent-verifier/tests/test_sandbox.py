import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.sandbox import SandboxUnavailable, run_in_sandbox, unshare_available

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _build_pyz(out_path: Path) -> None:
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import build_pyz  # type: ignore

    build_pyz.build(out_path)


@unittest.skipUnless(unshare_available(), "requer 'unshare --net' funcionando de fato neste ambiente (binario presente E permitido pelo kernel/container)")
class CleanArtifactSandboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.pyz = cls.tmp / "clean.pyz"
        _build_pyz(cls.pyz)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_selftest_runs_and_workdir_stays_untouched(self):
        workdir = self.tmp / "work_selftest"
        result = run_in_sandbox(
            [sys.executable, "-I", "-B", str(self.pyz), "selftest"],
            workdir=workdir,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("RESULTADO GERAL: PASSOU", result.stdout)
        self.assertTrue(result.network_isolation_applied)
        self.assertTrue(result.workdir_diff.is_identical, msg=result.workdir_diff)

    def test_isolate_network_false_skips_unshare(self):
        workdir = self.tmp / "work_no_isolation"
        result = run_in_sandbox(
            [sys.executable, "-I", "-B", str(self.pyz), "selftest"],
            workdir=workdir,
            isolate_network=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.network_isolation_applied)


@unittest.skipUnless(unshare_available(), "requer 'unshare --net' funcionando de fato neste ambiente (binario presente E permitido pelo kernel/container)")
class NetworkIsolationIsIndependentOfGuardTests(unittest.TestCase):
    """Fase 12: a isolacao de rede do sandbox precisa funcionar mesmo para
    um processo que NAO tem nenhum codigo do EntropyForge (nenhum
    guard.py, nenhum audit hook) -- ela e uma camada do KERNEL (namespace
    de rede vazio), independente de qualquer protecao em nivel de
    aplicacao. Isso e testado aqui com um script Python puro, deliberadamente
    sem nenhuma relacao com entropyforge, que tenta um socket UDP cru."""

    RAW_SOCKET_SCRIPT = (
        "import socket\n"
        "try:\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "    s.sendto(b'leak-test-fictitious-payload', ('198.51.100.1', 9))\n"
        "    print('SENT_OK')\n"
        "except OSError as e:\n"
        "    print('BLOCKED:' + repr(e))\n"
    )

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.script = self.tmp / "raw_net_attempt.py"
        self.script.write_text(self.RAW_SOCKET_SCRIPT)

    def test_raw_socket_send_blocked_under_isolation(self):
        result = run_in_sandbox(
            [sys.executable, str(self.script)],
            workdir=self.tmp / "work_isolated",
            isolate_network=True,
        )
        self.assertTrue(result.network_isolation_applied)
        self.assertIn("BLOCKED:", result.stdout)
        self.assertNotIn("SENT_OK", result.stdout)

    def test_raw_socket_send_succeeds_without_isolation(self):
        # Controle: confirma que o script realmente tentaria enviar (e
        # conseguiria) se a isolacao de rede nao fosse aplicada -- sem
        # este controle, um "BLOCKED" acima poderia ser coincidencia do
        # ambiente, nao efeito da isolacao.
        result = run_in_sandbox(
            [sys.executable, str(self.script)],
            workdir=self.tmp / "work_unisolated",
            isolate_network=False,
        )
        self.assertFalse(result.network_isolation_applied)
        self.assertIn("SENT_OK", result.stdout)


@unittest.skipUnless(unshare_available(), "requer 'unshare --net' funcionando de fato neste ambiente (binario presente E permitido pelo kernel/container)")
class WorkdirDiffDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_detects_file_created_inside_monitored_workdir(self):
        result = run_in_sandbox(
            [sys.executable, "-c", "open('leaked.txt', 'w').write('x')"],
            workdir=self.tmp / "work",
        )
        self.assertFalse(result.workdir_diff.is_identical)
        self.assertIn("leaked.txt", result.workdir_diff.added)

    def test_does_not_see_files_written_outside_workdir(self):
        # Documenta o limite explicito do DISCLAIMER: o sandbox aqui NAO
        # isola o sistema de arquivos, so a rede. Um payload que escreve
        # fora do diretorio de trabalho monitorado (ex.: caminho absoluto
        # para outro diretorio temporario) fica fora do escopo deste
        # diff -- por isso ele nao prova ausencia de escrita em disco.
        outside = self.tmp / "outside_workdir.txt"
        result = run_in_sandbox(
            [sys.executable, "-c", f"open({str(outside)!r}, 'w').write('x')"],
            workdir=self.tmp / "work",
        )
        self.assertTrue(result.workdir_diff.is_identical)
        self.assertTrue(outside.exists())


class SandboxUnavailableTests(unittest.TestCase):
    def test_raises_when_unshare_missing(self):
        with mock.patch("verifier.sandbox.unshare_available", return_value=False):
            with self.assertRaises(SandboxUnavailable):
                run_in_sandbox(
                    [sys.executable, "-c", "pass"],
                    workdir=Path(tempfile.mkdtemp()),
                    isolate_network=True,
                )

    def test_no_error_when_network_isolation_not_requested(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            with mock.patch("verifier.sandbox.unshare_available", return_value=False):
                result = run_in_sandbox(
                    [sys.executable, "-c", "print('ok')"],
                    workdir=tmp / "work",
                    isolate_network=False,
                )
            self.assertEqual(result.returncode, 0)
            self.assertFalse(result.network_isolation_applied)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
