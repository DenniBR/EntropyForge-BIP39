import shutil
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.release_manifest import (
    ReleaseManifest,
    ReleaseManifestError,
    compute_release_manifest,
    parse_release_manifest_text,
    read_version_constants,
    verify_release,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ENTROPYFORGE_ROOT = REPO_ROOT / "entropyforge"
VERIFIER_ROOT = REPO_ROOT / "independent-verifier" / "verifier"
BUILD_SCRIPT = REPO_ROOT / "tools" / "build_pyz.py"
VECTORS_PATH = REPO_ROOT / "tests" / "vectors" / "bip39_vectors.json"


def _build_pyz(out_path: Path) -> None:
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import build_pyz  # type: ignore

    build_pyz.build(out_path)


class ReadVersionConstantsTests(unittest.TestCase):
    def test_reads_all_five_from_real_version_file(self):
        values = read_version_constants(ENTROPYFORGE_ROOT / "version.py")
        self.assertEqual(
            set(values),
            {
                "SOFTWARE_VERSION",
                "PROTOCOL_VERSION_A",
                "GENERATION_PROCEDURE_VERSION",
                "WORDLIST_VERSION",
                "MANIFEST_FORMAT_VERSION",
            },
        )
        self.assertRegex(values["SOFTWARE_VERSION"], r"^\d+\.\d+\.\d+$")

    def test_never_imports_the_module(self):
        # Se este teste passar mesmo com um erro de sintaxe deliberado no
        # meio do arquivo (fora das linhas de versao), confirma que a
        # leitura e puramente textual/regex, nunca `import`/`exec`.
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "version.py"
            p.write_text(
                'SOFTWARE_VERSION = "9.9.9"\n'
                'PROTOCOL_VERSION_A = "1"\n'
                'GENERATION_PROCEDURE_VERSION = "2"\n'
                'WORDLIST_VERSION = "x"\n'
                'MANIFEST_FORMAT_VERSION = "1"\n'
                "isto nao e python valido !!! ((\n",
                encoding="utf-8",
            )
            values = read_version_constants(p)
            self.assertEqual(values["SOFTWARE_VERSION"], "9.9.9")

    def test_missing_constant_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "version.py"
            p.write_text('SOFTWARE_VERSION = "1.0.0"\n', encoding="utf-8")
            with self.assertRaises(ReleaseManifestError):
                read_version_constants(p)


class ManifestTextRoundtripTests(unittest.TestCase):
    def test_to_text_then_parse_is_identity(self):
        m = ReleaseManifest(
            software_version="1.0.0",
            protocol_version_a="1",
            generation_procedure_version="2",
            wordlist_version="bip39-english-2013",
            manifest_format_version="1",
            wordlist_sha256="a" * 64,
            source_manifest_sha256="b" * 64,
            pyz_sha256="c" * 64,
            build_script_sha256="d" * 64,
            verifier_source_sha256="e" * 64,
        )
        self.assertEqual(parse_release_manifest_text(m.to_text()), m)

    def test_missing_field_rejected(self):
        with self.assertRaises(ReleaseManifestError):
            parse_release_manifest_text("software_version=1.0.0\n")

    def test_unexpected_field_rejected(self):
        m = ReleaseManifest(
            software_version="1.0.0", protocol_version_a="1", generation_procedure_version="2",
            wordlist_version="x", manifest_format_version="1", wordlist_sha256="a" * 64,
            source_manifest_sha256="b" * 64, pyz_sha256="c" * 64, build_script_sha256="d" * 64,
            verifier_source_sha256="e" * 64,
        )
        text = m.to_text() + "mnemonic=abandon abandon abandon\n"
        with self.assertRaises(ReleaseManifestError):
            parse_release_manifest_text(text)

    def test_manifest_never_has_a_secret_looking_field(self):
        # Checagem de invariante, nao so de formato: nenhum nome de campo
        # do dataclass deve sugerir dado sensivel de uma geracao real.
        forbidden_substrings = ("mnemonic", "entropy", "seed", "passphrase")
        for f in ReleaseManifest.__dataclass_fields__:
            for bad in forbidden_substrings:
                self.assertNotIn(bad, f.lower())


class ComputeAndVerifyReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.pyz = cls.tmp / "entropyforge.pyz"
        _build_pyz(cls.pyz)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _compute(self) -> ReleaseManifest:
        return compute_release_manifest(
            entropyforge_root=ENTROPYFORGE_ROOT,
            pyz_path=self.pyz,
            verifier_root=VERIFIER_ROOT,
            build_script_path=BUILD_SCRIPT,
        )

    def test_compute_is_deterministic(self):
        self.assertEqual(self._compute(), self._compute())

    def test_verify_release_passes_for_freshly_built_pyz(self):
        manifest = self._compute()
        result = verify_release(
            manifest,
            entropyforge_root=ENTROPYFORGE_ROOT,
            pyz_path=self.pyz,
            verifier_root=VERIFIER_ROOT,
            build_script_path=BUILD_SCRIPT,
            official_vectors_path=VECTORS_PATH,
        )
        self.assertTrue(result.passed, msg=result.format_report())
        self.assertTrue(all(c.ok for c in result.checks))

    def test_verify_release_fails_if_pyz_tampered_after_manifest(self):
        manifest = self._compute()
        tampered = self.tmp / "tampered.pyz"
        data = bytearray(self.pyz.read_bytes())
        data[-1] ^= 0xFF
        tampered.write_bytes(bytes(data))

        result = verify_release(
            manifest,
            entropyforge_root=ENTROPYFORGE_ROOT,
            pyz_path=tampered,
            verifier_root=VERIFIER_ROOT,
            build_script_path=BUILD_SCRIPT,
            official_vectors_path=VECTORS_PATH,
        )
        self.assertFalse(result.passed)
        pyz_field_check = next(c for c in result.checks if c.name == "manifesto.pyz_sha256")
        self.assertFalse(pyz_field_check.ok)

    def test_verify_release_fails_if_manifest_claims_wrong_version(self):
        manifest = replace(self._compute(), software_version="0.0.0-forjado")
        result = verify_release(
            manifest,
            entropyforge_root=ENTROPYFORGE_ROOT,
            pyz_path=self.pyz,
            verifier_root=VERIFIER_ROOT,
            build_script_path=BUILD_SCRIPT,
            official_vectors_path=VECTORS_PATH,
        )
        self.assertFalse(result.passed)
        version_field_check = next(c for c in result.checks if c.name == "manifesto.software_version")
        self.assertFalse(version_field_check.ok)
        # os demais campos, nao alterados, continuam batendo -- a falha e
        # cirurgica, nao um "tudo ou nada" que esconderia qual campo
        # exatamente diverge.
        other_checks = [c for c in result.checks if c.name != "manifesto.software_version"]
        self.assertTrue(all(c.ok for c in other_checks), msg=result.format_report())

    def test_verify_release_fails_if_source_tampered_after_manifest(self):
        manifest = self._compute()
        with tempfile.TemporaryDirectory() as tmp2:
            fake_root = Path(tmp2) / "entropyforge"
            shutil.copytree(ENTROPYFORGE_ROOT, fake_root)
            (fake_root / "dice.py").write_text(
                (fake_root / "dice.py").read_text(encoding="utf-8") + "\n# linha adicionada\n",
                encoding="utf-8",
            )
            result = verify_release(
                manifest,
                entropyforge_root=fake_root,
                pyz_path=self.pyz,
                verifier_root=VERIFIER_ROOT,
                build_script_path=BUILD_SCRIPT,
                official_vectors_path=VECTORS_PATH,
            )
            self.assertFalse(result.passed)


if __name__ == "__main__":
    unittest.main()
