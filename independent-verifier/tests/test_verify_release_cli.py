"""Testes de ponta a ponta do script `independent-verifier/verify_release.py`
via subprocesso real (nao so chamando as funcoes Python diretamente) --
confirma o CONTRATO DE SAIDA exigido pela Fase E: stdout e SOMENTE a
palavra `PASS` ou `FAIL`, nunca mais nada, mesmo com `--verbose` (que deve
mandar o detalhamento para stderr, nao stdout)."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.release_manifest import compute_release_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "independent-verifier" / "verify_release.py"
ENTROPYFORGE_ROOT = REPO_ROOT / "entropyforge"
VERIFIER_ROOT = REPO_ROOT / "independent-verifier" / "verifier"
BUILD_SCRIPT = REPO_ROOT / "tools" / "build_pyz.py"
VECTORS_PATH = REPO_ROOT / "tests" / "vectors" / "bip39_vectors.json"


def _build_pyz(out_path: Path) -> None:
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import build_pyz  # type: ignore

    build_pyz.build(out_path)


def _fake_elf_x86_64_bytes(filler: bytes) -> bytes:
    """Ver docstring gemea em tests/test_release_manifest.py."""
    header = bytearray(20)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # EI_CLASS = ELFCLASS64
    header[5] = 1  # EI_DATA = little-endian
    header[6] = 1  # EI_VERSION
    header[18:20] = (0x3E).to_bytes(2, "little")  # e_machine = EM_X86_64
    return bytes(header) + filler


def _build_fake_executable_dist(out_dir: Path) -> Path:
    """Ver docstring gemea em tests/test_release_manifest.py -- um
    diretorio minimo, nao um executavel Nuitka de verdade, suficiente para
    exercitar o CONTRATO DE SAIDA do CLI sem pagar o custo de um build
    real a cada execucao desta suite. Precisa de um cabecalho ELF valido
    para que `_detect_executable_platform_arch` (usado por
    `verify_release`) o reconheca."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "entropyforge-bip39").write_bytes(
        _fake_elf_x86_64_bytes(b"fake binary, so para hash deterministico")
    )
    return out_dir


class VerifyReleaseCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.pyz = cls.tmp / "entropyforge.pyz"
        _build_pyz(cls.pyz)
        cls.executable_dist = _build_fake_executable_dist(cls.tmp / "fake_exe")
        cls.manifest_path = cls.tmp / "MANIFEST.txt"
        manifest = compute_release_manifest(
            entropyforge_root=ENTROPYFORGE_ROOT,
            pyz_path=cls.pyz,
            verifier_root=VERIFIER_ROOT,
            build_script_path=BUILD_SCRIPT,
            executable_dist_dir=cls.executable_dist,
        )
        cls.manifest_path.write_text(manifest.to_text(), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _run(self, *extra_args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable, "-B", str(SCRIPT),
                "--manifest", str(self.manifest_path),
                "--entropyforge-root", str(ENTROPYFORGE_ROOT),
                "--pyz", str(self.pyz),
                "--verifier-root", str(VERIFIER_ROOT),
                "--build-script", str(BUILD_SCRIPT),
                "--vectors", str(VECTORS_PATH),
                "--executable-dist", str(self.executable_dist),
                *extra_args,
            ],
            capture_output=True, text=True, timeout=60,
        )

    def test_stdout_is_exactly_pass_on_success(self):
        proc = self._run()
        self.assertEqual(proc.stdout.strip(), "PASS")
        self.assertEqual(proc.returncode, 0)

    def test_verbose_keeps_stdout_as_only_the_word_pass(self):
        proc = self._run("--verbose")
        self.assertEqual(proc.stdout.strip(), "PASS")
        self.assertEqual(proc.returncode, 0)
        # o detalhamento vai para stderr, nao para stdout
        self.assertIn("RESULTADO GERAL: PASS", proc.stderr)

    def test_stdout_is_exactly_fail_on_tampered_pyz(self):
        tampered = self.tmp / "tampered_for_cli.pyz"
        data = bytearray(self.pyz.read_bytes())
        data[-1] ^= 0xFF
        tampered.write_bytes(bytes(data))
        proc = subprocess.run(
            [
                sys.executable, "-B", str(SCRIPT),
                "--manifest", str(self.manifest_path),
                "--entropyforge-root", str(ENTROPYFORGE_ROOT),
                "--pyz", str(tampered),
                "--verifier-root", str(VERIFIER_ROOT),
                "--build-script", str(BUILD_SCRIPT),
                "--vectors", str(VECTORS_PATH),
                "--executable-dist", str(self.executable_dist),
            ],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.stdout.strip(), "FAIL")
        self.assertEqual(proc.returncode, 1)

    def test_missing_file_exits_2_without_pass_or_fail(self):
        proc = subprocess.run(
            [
                sys.executable, "-B", str(SCRIPT),
                "--manifest", str(self.tmp / "nao-existe.txt"),
                "--entropyforge-root", str(ENTROPYFORGE_ROOT),
                "--pyz", str(self.pyz),
                "--verifier-root", str(VERIFIER_ROOT),
                "--build-script", str(BUILD_SCRIPT),
                "--vectors", str(VECTORS_PATH),
                "--executable-dist", str(self.executable_dist),
            ],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("PASS", proc.stdout)
        self.assertNotIn("FAIL", proc.stdout)

    def test_no_secret_looking_string_in_any_output(self):
        proc = self._run("--verbose")
        combined = proc.stdout + proc.stderr
        for forbidden in ("mnemonic", "abandon abandon", "passphrase"):
            self.assertNotIn(forbidden, combined.lower())


if __name__ == "__main__":
    unittest.main()
