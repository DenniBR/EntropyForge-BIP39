"""Testes de `tools/assemble_release.py`: monta o diretorio `release/` a
partir de arquivos ja construidos (nunca constroi nada sozinho)."""

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "tools" / "assemble_release.py"

_spec = importlib.util.spec_from_file_location("assemble_release", SCRIPT_PATH)
assemble_release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(assemble_release)


class AssembleReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # Simula os artefatos que 'make build' + build_release_manifest.py
        # ja teriam produzido na raiz do repo, sem realmente rodar o build
        # (mais rapido, e este teste so quer confirmar a MONTAGEM).
        self._patch = self._make_fake_repo_root()

    def _make_fake_repo_root(self):
        fake_root = self.tmp / "fake_repo"
        fake_root.mkdir()
        (fake_root / "entropyforge.pyz").write_bytes(b"PK\x03\x04fake pyz content")
        (fake_root / "SHA256SUMS").write_text("deadbeef  entropyforge.pyz\n", encoding="utf-8")
        (fake_root / "MANIFEST.txt").write_text("software_version=9.9.9\n", encoding="utf-8")
        (fake_root / "RELEASE-CANDIDATE.md").write_text("# fake release candidate\n", encoding="utf-8")
        (fake_root / "README.md").write_text("# fake readme\n", encoding="utf-8")
        docs = fake_root / "docs"
        docs.mkdir()
        (docs / "OPERATIONS.md").write_text("op\n", encoding="utf-8")
        (docs / "__pycache__").mkdir()
        (docs / "__pycache__" / "junk.pyc").write_bytes(b"\x00")

        # diretorio de executavel FALSO (Fase F) -- so precisa existir com
        # o nome/forma certos para _find_executable_dist_dir encontrar; o
        # conteudo em si nao importa para estes testes de MONTAGEM.
        exe_dist = fake_root / "dist_executable" / "entropyforge-bip39-v9.9.9-linux-x86_64"
        exe_dist.mkdir(parents=True)
        (exe_dist / "entropyforge-bip39").write_bytes(b"fake compiled binary")
        (exe_dist / "libfake.so").write_bytes(b"fake shared lib")

        # copia FALSA de independent-verifier/ -- confirma que _copy_verifier
        # copia verifier/+scripts e EXCLUI tests/ e __pycache__.
        iv = fake_root / "independent-verifier"
        (iv / "verifier").mkdir(parents=True)
        (iv / "verifier" / "__init__.py").write_text("", encoding="utf-8")
        (iv / "verifier" / "hashing.py").write_text("# fake\n", encoding="utf-8")
        (iv / "verify_release.py").write_text("# fake\n", encoding="utf-8")
        (iv / "verify_executable.py").write_text("# fake\n", encoding="utf-8")
        (iv / "tests").mkdir()
        (iv / "tests" / "test_fake.py").write_text("# nao deve ser copiado\n", encoding="utf-8")
        (iv / "verifier" / "__pycache__").mkdir()
        (iv / "verifier" / "__pycache__" / "junk.pyc").write_bytes(b"\x00")

        return fake_root

    def test_assemble_copies_required_files_and_docs(self):
        out = self.tmp / "release"
        original_root = assemble_release.REPO_ROOT
        assemble_release.REPO_ROOT = self._patch
        try:
            assemble_release.assemble(out)
        finally:
            assemble_release.REPO_ROOT = original_root

        self.assertTrue((out / "entropyforge.pyz").is_file())
        self.assertTrue((out / "SHA256SUMS").is_file())
        self.assertTrue((out / "MANIFEST.txt").is_file())
        self.assertTrue((out / "RELEASE-CANDIDATE.md").is_file())
        self.assertTrue((out / "README.md").is_file())
        self.assertTrue((out / "docs" / "OPERATIONS.md").is_file())
        self.assertEqual((out / "entropyforge.pyz").read_bytes(), b"PK\x03\x04fake pyz content")

        # Fase F: executavel + hash por arquivo + copia do verificador.
        exe_out = out / "entropyforge-bip39-v9.9.9-linux-x86_64"
        self.assertTrue((exe_out / "entropyforge-bip39").is_file())
        self.assertTrue((exe_out / "libfake.so").is_file())
        sha_path = out / "entropyforge-bip39-v9.9.9-linux-x86_64.sha256"
        self.assertTrue(sha_path.is_file())
        sha_text = sha_path.read_text(encoding="utf-8")
        self.assertIn("entropyforge-bip39", sha_text)
        self.assertIn("libfake.so", sha_text)
        # cada linha e' 'hash  caminho', hash de 64 hex chars (SHA-256 real,
        # nao decorativo) do CONTEUDO de cada arquivo do dist.
        import hashlib
        expected_bin_hash = hashlib.sha256(b"fake compiled binary").hexdigest()
        self.assertIn(f"{expected_bin_hash}  entropyforge-bip39", sha_text)

        self.assertTrue((out / "independent-verifier" / "verifier" / "hashing.py").is_file())
        self.assertTrue((out / "independent-verifier" / "verify_release.py").is_file())
        self.assertTrue((out / "independent-verifier" / "verify_executable.py").is_file())
        self.assertFalse((out / "independent-verifier" / "tests").exists())
        self.assertFalse((out / "independent-verifier" / "verifier" / "__pycache__").exists())

    def test_assemble_excludes_pycache(self):
        out = self.tmp / "release"
        original_root = assemble_release.REPO_ROOT
        assemble_release.REPO_ROOT = self._patch
        try:
            assemble_release.assemble(out)
        finally:
            assemble_release.REPO_ROOT = original_root
        self.assertFalse((out / "docs" / "__pycache__").exists())

    def test_assemble_raises_if_pyz_missing(self):
        (self._patch / "entropyforge.pyz").unlink()
        out = self.tmp / "release"
        original_root = assemble_release.REPO_ROOT
        assemble_release.REPO_ROOT = self._patch
        try:
            with self.assertRaises(SystemExit):
                assemble_release.assemble(out)
        finally:
            assemble_release.REPO_ROOT = original_root

    def test_assemble_raises_if_executable_dist_missing(self):
        shutil.rmtree(self._patch / "dist_executable")
        out = self.tmp / "release"
        original_root = assemble_release.REPO_ROOT
        assemble_release.REPO_ROOT = self._patch
        try:
            with self.assertRaises(SystemExit):
                assemble_release.assemble(out)
        finally:
            assemble_release.REPO_ROOT = original_root

    def test_assemble_overwrites_existing_release_dir(self):
        out = self.tmp / "release"
        out.mkdir()
        (out / "stale_file_from_previous_release.txt").write_text("velho\n", encoding="utf-8")
        original_root = assemble_release.REPO_ROOT
        assemble_release.REPO_ROOT = self._patch
        try:
            assemble_release.assemble(out)
        finally:
            assemble_release.REPO_ROOT = original_root
        self.assertFalse((out / "stale_file_from_previous_release.txt").exists())


if __name__ == "__main__":
    unittest.main()
