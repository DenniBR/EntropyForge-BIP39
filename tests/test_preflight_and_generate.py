"""Testa tools/preflight_and_generate.py: a cerimonia de pre-geracao
automatizada deve rodar as checagens externas (wordlist, .pyz vs source,
selftest) e SO prosseguir para o comando pedido se todas passarem --
nunca prosseguir silenciosamente em caso de falha (fail-closed)."""

import importlib.util
import io
import sys
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "tools" / "preflight_and_generate.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("preflight_and_generate", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build_pyz(out_path: Path) -> None:
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import build_pyz  # type: ignore

    build_pyz.build(out_path)


class PreflightHappyPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = _load_module()

    def test_clean_pyz_passes_all_preflight_checks(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            pyz = Path(tmp) / "entropyforge.pyz"
            _build_pyz(pyz)
            # nao deve levantar PreflightFailure
            self.module.run_preflight(pyz, REPO_ROOT / "entropyforge")


class PreflightFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = _load_module()

    def setUp(self):
        import shutil
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.pyz = self.tmp / "entropyforge.pyz"
        _build_pyz(self.pyz)

    def _rewrite_pyz(self, mutate) -> None:
        data = self.pyz.read_bytes()
        zstart = data.index(b"PK\x03\x04")
        shebang = data[:zstart]
        with zipfile.ZipFile(io.BytesIO(data[zstart:])) as zin:
            content = {n: zin.read(n) for n in zin.namelist()}
        mutate(content)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zout:
            for name, payload in content.items():
                zout.writestr(name, payload)
        self.pyz.write_bytes(shebang + buf.getvalue())

    def test_aborts_on_pyz_with_extra_module(self):
        self._rewrite_pyz(lambda c: c.__setitem__("entropyforge/_sneaky.py", b"# nao deveria estar aqui\n"))
        with self.assertRaises(self.module.PreflightFailure):
            self.module.run_preflight(self.pyz, REPO_ROOT / "entropyforge")

    def test_aborts_on_pyz_with_tampered_module(self):
        def mutate(c):
            src = c["entropyforge/combine.py"].decode("utf-8")
            c["entropyforge/combine.py"] = src.replace(
                "hashlib.sha256(a + b)", "hashlib.sha256(b + a)"
            ).encode("utf-8")

        self._rewrite_pyz(mutate)
        with self.assertRaises(self.module.PreflightFailure):
            self.module.run_preflight(self.pyz, REPO_ROOT / "entropyforge")

    def test_aborts_on_missing_pyz(self):
        with self.assertRaises(self.module.PreflightFailure):
            self.module.run_preflight(self.tmp / "does_not_exist.pyz", REPO_ROOT / "entropyforge")

    def test_aborts_on_tampered_wordlist_reference_tree(self):
        import shutil

        tampered_root = self.tmp / "entropyforge_tampered_wordlist"
        shutil.copytree(REPO_ROOT / "entropyforge", tampered_root)
        wordlist_path = tampered_root / "data" / "english.txt"
        words = wordlist_path.read_text().splitlines()
        words[0] = "abandonx"
        wordlist_path.write_text("\n".join(words) + "\n")
        with self.assertRaises(self.module.PreflightFailure):
            self.module.check_wordlist(tampered_root)


class PreflightMainCliTests(unittest.TestCase):
    """Fim-a-ponta via subprocess, testando o parsing de argumentos e o
    codigo de saida (nunca o `os.execv` final -- usamos `selftest`, que
    sai sozinho, em vez de `generate`, que exigiria um TTY)."""

    def test_cli_runs_selftest_after_passing_preflight(self):
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            pyz = Path(tmp) / "entropyforge.pyz"
            _build_pyz(pyz)
            proc = subprocess.run(
                [sys.executable, "-B", str(SCRIPT_PATH), "--pyz", str(pyz), "--", "selftest"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertIn("RESULTADO GERAL: PASSOU", proc.stdout)

    def test_cli_exits_nonzero_and_never_runs_pyz_on_bad_pyz_path(self):
        import subprocess

        proc = subprocess.run(
            [sys.executable, "-B", str(SCRIPT_PATH), "--pyz", "/nonexistent/entropyforge.pyz", "--", "selftest"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("RESULTADO GERAL", proc.stdout)


if __name__ == "__main__":
    unittest.main()
