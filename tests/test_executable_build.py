"""Testes do executável standalone (Fase F, `tools/build_executable.py`).

Pulado automaticamente se `nuitka` ou um compilador C não estiverem
disponíveis -- é uma ferramenta de BUILD/RELEASE, nunca uma dependência
de runtime de `entropyforge/` (confirmado por `tests/test_security_ast.py`).
Constrói o executável UMA VEZ (`setUpClass`, ~15s) e roda várias
checagens contra o mesmo artefato, para não pagar o custo do build a
cada teste.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import build_executable  # type: ignore  # noqa: E402

try:
    build_executable._check_prereqs()
    _PREREQS_OK = True
    _SKIP_REASON = ""
except build_executable.ExecutableBuildError as exc:
    _PREREQS_OK = False
    _SKIP_REASON = str(exc)


FORBIDDEN_CREDENTIAL_PATTERNS = re.compile(
    rb"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}|xoxb-|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}"
)
FORBIDDEN_DEV_VALUES = (
    b"abandon amount liar",  # mnemonic ficticia de docs/WALLET_IMPORT_TEST.md
    b"CANARY_SECRET",  # redteam/scripts/cli_fuzz.py
)
FORBIDDEN_DIR_NAMES = {"tests", "redteam", "independent-verifier", "independent_verifier"}


@unittest.skipUnless(_PREREQS_OK, f"pre-requisitos de build ausentes: {_SKIP_REASON}")
class ExecutableBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.dist_dir = build_executable.build(cls.tmp)
        cls.main_bin = cls.dist_dir / "entropyforge-bip39"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_main_binary_exists_and_is_executable(self):
        self.assertTrue(self.main_bin.is_file())
        self.assertTrue(self.main_bin.stat().st_mode & 0o111, "binario nao tem permissao de execucao")

    def test_selftest_passes(self):
        proc = subprocess.run([str(self.main_bin), "selftest"], capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("RESULTADO GERAL: PASSOU", proc.stdout)

    def test_version_matches_source(self):
        sys.path.insert(0, str(REPO_ROOT))
        from entropyforge import version as src_version

        proc = subprocess.run([str(self.main_bin), "--version"], capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0)
        self.assertIn(src_version.SOFTWARE_VERSION, proc.stdout)
        self.assertIn(src_version.WORDLIST_VERSION, proc.stdout)

    def test_no_dev_only_directories_bundled(self):
        for p in self.dist_dir.rglob("*"):
            if p.is_dir():
                self.assertNotIn(p.name.lower(), FORBIDDEN_DIR_NAMES, msg=str(p))

    def test_wordlist_matches_official_hash(self):
        sys.path.insert(0, str(REPO_ROOT / "independent-verifier"))
        from verifier.wordlist_check import check_matches_official_hash, check_wordlist_file

        wordlist_path = self.dist_dir / "entropyforge" / "data" / "english.txt"
        self.assertTrue(wordlist_path.is_file())
        report = check_wordlist_file(wordlist_path)
        ok, detail = check_matches_official_hash(report)
        self.assertTrue(ok, msg=detail)

    def test_no_openssl_bundled(self):
        names = {p.name.lower() for p in self.dist_dir.rglob("*")}
        for forbidden in ("_hashlib", "libssl", "libcrypto"):
            self.assertFalse(
                any(forbidden in n for n in names),
                msg=f"{forbidden} nao deveria estar no executavel (ver docs/EXECUTABLE_BUILD.md secao 3)",
            )

    def test_no_credential_patterns_in_any_file(self):
        for f in self.dist_dir.rglob("*"):
            if not f.is_file():
                continue
            data = f.read_bytes()
            self.assertIsNone(
                FORBIDDEN_CREDENTIAL_PATTERNS.search(data),
                msg=f"padrao de credencial encontrado em {f}",
            )

    def test_no_fictitious_dev_values_leaked(self):
        for f in self.dist_dir.rglob("*"):
            if not f.is_file():
                continue
            data = f.read_bytes()
            for bad in FORBIDDEN_DEV_VALUES:
                self.assertNotIn(bad, data, msg=f"{bad!r} encontrado em {f}")

    def test_no_build_machine_absolute_paths_in_binary(self):
        data = self.main_bin.read_bytes()
        for pattern in (rb"/home/[a-zA-Z0-9_.-]+", rb"/Users/[a-zA-Z0-9_.-]+"):
            m = re.search(pattern, data)
            self.assertIsNone(m, msg=f"caminho absoluto da maquina de build encontrado: {m}")

    def test_vector_mode_matches_source_computation(self):
        # cruza a saida do EXECUTAVEL contra o calculo feito pelo source
        # diretamente -- confirma que a compilacao Nuitka nao alterou o
        # comportamento observavel do programa.
        sys.path.insert(0, str(REPO_ROOT))
        from entropyforge import bip39

        entropy_hex = "00" * 32
        proc = subprocess.run(
            [str(self.main_bin), "vector", "--entropy-hex", entropy_hex],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proc.returncode, 0)
        expected = bip39.entropy_to_mnemonic(bytes.fromhex(entropy_hex))
        self.assertIn(expected, proc.stdout)


if __name__ == "__main__":
    unittest.main()
