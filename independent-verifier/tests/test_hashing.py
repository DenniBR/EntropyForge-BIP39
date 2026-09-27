import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.hashing import (
    build_manifest,
    diff_manifests,
    hash_bytes,
    hash_file,
    manifest_to_text,
    parse_manifest_text,
    read_manifest,
    verify_against_manifest,
    write_manifest,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class HashFileTests(unittest.TestCase):
    def test_matches_known_sha256_of_empty_and_abc(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "empty.bin"
            p.write_bytes(b"")
            self.assertEqual(hash_file(p), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            p2 = Path(tmp) / "abc.bin"
            p2.write_bytes(b"abc")
            self.assertEqual(hash_file(p2), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_hash_bytes_matches_hash_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.bin"
            data = b"hello world" * 1000
            p.write_bytes(data)
            self.assertEqual(hash_file(p), hash_bytes(data))

    def test_large_file_chunking(self):
        # maior que _CHUNK_SIZE, para exercitar o loop de leitura em blocos
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "big.bin"
            data = b"A" * (2 * 1024 * 1024 + 123)
            p.write_bytes(data)
            self.assertEqual(hash_file(p), hash_bytes(data))


class ManifestTests(unittest.TestCase):
    def test_build_manifest_on_real_entropyforge(self):
        entries = build_manifest(REPO_ROOT / "entropyforge", include_suffixes=(".py",))
        self.assertGreaterEqual(len(entries), 10)
        paths = {e.path for e in entries}
        self.assertIn("bip39.py", paths)
        self.assertIn("wordlist.py", paths)

    def test_manifest_excludes_pycache(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "__pycache__").mkdir()
            (tmp / "__pycache__" / "x.pyc").write_bytes(b"junk")
            (tmp / "real.py").write_text("pass\n")
            entries = build_manifest(tmp)
            paths = {e.path for e in entries}
            self.assertIn("real.py", paths)
            self.assertNotIn("__pycache__/x.pyc", paths)

    def test_roundtrip_text_format(self):
        entries = build_manifest(REPO_ROOT / "entropyforge", include_suffixes=(".py",))
        text = manifest_to_text(entries)
        parsed = parse_manifest_text(text)
        self.assertEqual(parsed, sorted(entries))

    def test_write_read_roundtrip(self):
        entries = build_manifest(REPO_ROOT / "entropyforge", include_suffixes=(".py",))
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "manifest.txt"
            write_manifest(entries, p)
            read_back = read_manifest(p)
            self.assertEqual(read_back, sorted(entries))

    def test_manifest_rejects_malformed_lines(self):
        with self.assertRaises(Exception):
            parse_manifest_text("not-a-valid-manifest-line\n")

    def test_manifest_is_deterministic_across_copies(self):
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            shutil.copytree(REPO_ROOT / "entropyforge", Path(tmp1) / "e")
            shutil.copytree(REPO_ROOT / "entropyforge", Path(tmp2) / "e")
            m1 = manifest_to_text(build_manifest(Path(tmp1) / "e"))
            m2 = manifest_to_text(build_manifest(Path(tmp2) / "e"))
            self.assertEqual(m1, m2)


class DiffTests(unittest.TestCase):
    def test_identical_manifests_have_no_diff(self):
        entries = build_manifest(REPO_ROOT / "entropyforge", include_suffixes=(".py",))
        d = diff_manifests(entries, entries)
        self.assertTrue(d.is_identical)

    def test_detects_tampered_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            shutil.copytree(REPO_ROOT / "entropyforge", tmp / "e")
            before = build_manifest(tmp / "e", include_suffixes=(".py",))
            target = tmp / "e" / "combine.py"
            target.write_text(target.read_text().replace("hashlib.sha256(a + b)", "hashlib.sha256(b + a)"))
            after = build_manifest(tmp / "e", include_suffixes=(".py",))
            d = diff_manifests(before, after)
            self.assertEqual(d.changed, ("combine.py",))
            self.assertFalse(d.is_identical)

    def test_detects_added_and_removed_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            shutil.copytree(REPO_ROOT / "entropyforge", tmp / "e")
            before = build_manifest(tmp / "e", include_suffixes=(".py",))
            (tmp / "e" / "__pycache__").mkdir(exist_ok=True)
            (tmp / "e" / "sneaky_module.py").write_text("# modulo nao documentado\n")
            (tmp / "e" / "dice.py").unlink()
            after = build_manifest(tmp / "e", include_suffixes=(".py",))
            d = diff_manifests(before, after)
            self.assertIn("sneaky_module.py", d.added)
            self.assertIn("dice.py", d.removed)


class VerifyAgainstManifestTests(unittest.TestCase):
    """`verify_against_manifest` nao tinha nenhum teste ate a Fase D desta
    auditoria, apesar de ser a funcao de uso tipico do verificador ('este
    diretorio ainda bate com um manifesto obtido em outro momento/lugar?')."""

    def test_matches_a_manifest_captured_earlier(self):
        # `verify_against_manifest` reconstroi o manifesto de `root` SEM
        # restricao de sufixo (ver build_manifest, include_suffixes=None
        # por padrao) -- o manifesto de referencia precisa ser construido
        # da MESMA forma, senao a comparacao e entre conjuntos de arquivos
        # diferentes (ex.: so .py vs. tudo incluindo data/english.txt).
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            shutil.copytree(REPO_ROOT / "entropyforge", tmp / "e")
            reference_manifest = build_manifest(tmp / "e")
            d = verify_against_manifest(tmp / "e", reference_manifest)
            self.assertTrue(d.is_identical, msg=d)

    def test_detects_drift_from_a_manifest_captured_earlier(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            shutil.copytree(REPO_ROOT / "entropyforge", tmp / "e")
            reference_manifest = build_manifest(tmp / "e")
            target = tmp / "e" / "combine.py"
            target.write_text(target.read_text() + "\n# alterado apos o manifesto de referencia\n")
            d = verify_against_manifest(tmp / "e", reference_manifest)
            self.assertFalse(d.is_identical)
            self.assertIn("combine.py", d.changed)


if __name__ == "__main__":
    unittest.main()
