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
        (fake_root / "README.md").write_text("# fake readme\n", encoding="utf-8")
        docs = fake_root / "docs"
        docs.mkdir()
        (docs / "OPERATIONS.md").write_text("op\n", encoding="utf-8")
        (docs / "__pycache__").mkdir()
        (docs / "__pycache__" / "junk.pyc").write_bytes(b"\x00")
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
        self.assertTrue((out / "README.md").is_file())
        self.assertTrue((out / "docs" / "OPERATIONS.md").is_file())
        self.assertEqual((out / "entropyforge.pyz").read_bytes(), b"PK\x03\x04fake pyz content")

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
