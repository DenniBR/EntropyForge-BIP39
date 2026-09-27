import hashlib
import io
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.pyz_inspect import (
    ZIP_MAGIC,
    PyzFormatError,
    check_bootstrap_main,
    compare_pyz_to_source,
    list_pyz_python_modules,
    pyz_manifest,
    read_pyz_entries,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _build_pyz(out_path: Path) -> None:
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import build_pyz  # type: ignore

    build_pyz.build(out_path)


def _rewrite_pyz(pyz_path: Path, mutate) -> None:
    """Le o .pyz, aplica `mutate(dict_de_conteudo)` in-place, e regrava."""
    data = pyz_path.read_bytes()
    zstart = data.index(ZIP_MAGIC)
    shebang = data[:zstart]
    with zipfile.ZipFile(io.BytesIO(data[zstart:])) as zin:
        content = {n: zin.read(n) for n in zin.namelist()}
    mutate(content)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zout:
        for name, payload in content.items():
            zout.writestr(name, payload)
    pyz_path.write_bytes(shebang + buf.getvalue())


class CleanPyzTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.pyz = cls.tmp / "clean.pyz"
        _build_pyz(cls.pyz)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_matches_source_exactly(self):
        r = compare_pyz_to_source(self.pyz, REPO_ROOT / "entropyforge")
        self.assertTrue(r.ok, msg=r)
        self.assertEqual(r.content_mismatches, ())
        self.assertEqual(r.missing_from_pyz, ())
        self.assertEqual(r.unexpected_in_pyz, ())
        self.assertEqual(r.expected_extra_files, ("__main__.py",))

    def test_bootstrap_main_matches_expected(self):
        ok, msg = check_bootstrap_main(self.pyz)
        self.assertTrue(ok, msg=msg)

    def test_manifest_lists_all_modules(self):
        modules = list_pyz_python_modules(self.pyz)
        self.assertIn("entropyforge/bip39.py", modules)
        self.assertIn("entropyforge/wordlist.py", modules)
        self.assertIn("__main__.py", modules)

    def test_rejects_non_zip_file(self):
        bogus = self.tmp / "not_a_zip.pyz"
        bogus.write_bytes(b"#!/usr/bin/env python3\nprint('nope')\n")
        with self.assertRaises(PyzFormatError):
            read_pyz_entries(bogus)

    def test_reordering_zip_entries_is_not_flagged_as_tamper(self):
        # Fase D, secao 11: reordenar as entradas do .pyz (MESMO conteudo,
        # ordem diferente) muda o hash BRUTO do arquivo inteiro, mas nao
        # deveria ser tratado como adulteracao -- compare_pyz_to_source
        # compara por NOME (independente de ordem), ao contrario de uma
        # checagem ingenua de hash do arquivo todo (build_repro.py), que
        # teria um falso positivo aqui.
        data = self.pyz.read_bytes()
        zstart = data.index(ZIP_MAGIC)
        shebang = data[:zstart]
        with zipfile.ZipFile(io.BytesIO(data[zstart:])) as zin:
            content = {n: zin.read(n) for n in zin.namelist()}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zout:
            for name in sorted(content.keys(), reverse=True):  # ordem invertida
                zout.writestr(name, content[name])
        reordered = self.tmp / "reordered.pyz"
        reordered.write_bytes(shebang + buf.getvalue())

        self.assertNotEqual(
            hashlib.sha256(reordered.read_bytes()).hexdigest(),
            hashlib.sha256(self.pyz.read_bytes()).hexdigest(),
            msg="pre-condicao: o hash bruto do arquivo deve mudar com a reordenacao",
        )
        r = compare_pyz_to_source(reordered, REPO_ROOT / "entropyforge")
        self.assertTrue(r.ok, msg=r)


class TamperedPyzTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.pyz = self.tmp / "t.pyz"
        _build_pyz(self.pyz)

    def test_detects_hidden_module(self):
        _rewrite_pyz(self.pyz, lambda c: c.__setitem__(
            "sitecustomize.py", b"import os\nos.environ['PWNED']='1'\n"
        ))
        r = compare_pyz_to_source(self.pyz, REPO_ROOT / "entropyforge")
        self.assertFalse(r.ok)
        self.assertIn("sitecustomize.py", r.unexpected_in_pyz)

    def test_detects_hidden_resource_payload(self):
        _rewrite_pyz(self.pyz, lambda c: c.__setitem__(
            "entropyforge/data/.payload.bin", b"NOT_A_REAL_SECRET_LAB_PAYLOAD"
        ))
        r = compare_pyz_to_source(self.pyz, REPO_ROOT / "entropyforge")
        self.assertFalse(r.ok)
        self.assertIn("entropyforge/data/.payload.bin", r.unexpected_in_pyz)

    def test_detects_content_tamper_in_existing_module(self):
        def mutate(c):
            src = c["entropyforge/combine.py"].decode("utf-8")
            c["entropyforge/combine.py"] = src.replace(
                "hashlib.sha256(a + b)", "hashlib.sha256(b + a)"
            ).encode("utf-8")

        _rewrite_pyz(self.pyz, mutate)
        r = compare_pyz_to_source(self.pyz, REPO_ROOT / "entropyforge")
        self.assertFalse(r.ok)
        self.assertIn("entropyforge/combine.py", r.content_mismatches)

    def test_detects_missing_module(self):
        _rewrite_pyz(self.pyz, lambda c: c.pop("entropyforge/guard.py"))
        r = compare_pyz_to_source(self.pyz, REPO_ROOT / "entropyforge")
        self.assertFalse(r.ok)
        self.assertIn("entropyforge/guard.py", r.missing_from_pyz)

    def test_detects_tampered_bootstrap(self):
        _rewrite_pyz(self.pyz, lambda c: c.__setitem__(
            "__main__.py", c["__main__.py"] + b"\nimport os\nos.system('echo pwned')\n"
        ))
        ok, msg = check_bootstrap_main(self.pyz)
        self.assertFalse(ok, msg=msg)
        # o comparador contra o source NAO pega isso sozinho (o __main__.py
        # de bootstrap nao tem arquivo-fonte correspondente) -- documentado
        # de proposito, e por isso check_bootstrap_main existe separado.
        r = compare_pyz_to_source(self.pyz, REPO_ROOT / "entropyforge")
        self.assertIn("__main__.py", r.expected_extra_files)

    def test_old_pyz_stops_matching_modified_source(self):
        # Fase 5: um .pyz construido ANTES de uma mudanca no source deixa
        # de bater assim que o source muda.
        source_copy = self.tmp / "entropyforge_src"
        shutil.copytree(REPO_ROOT / "entropyforge", source_copy)
        r_before = compare_pyz_to_source(self.pyz, source_copy)
        self.assertTrue(r_before.ok)

        target = source_copy / "osrng.py"
        target.write_text(target.read_text() + "\n# alterado apos o build\n")
        r_after = compare_pyz_to_source(self.pyz, source_copy)
        self.assertFalse(r_after.ok)
        self.assertIn("entropyforge/osrng.py", r_after.content_mismatches)


if __name__ == "__main__":
    unittest.main()
