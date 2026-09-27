"""Confirma que o artefato .pyz e byte-a-byte reprodutivel (requisito 15):
dois builds, em diretorios/umask diferentes, produzem o MESMO SHA-256."""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILD_SCRIPT = REPO_ROOT / "tools" / "build_pyz.py"


def _load_build_module():
    spec = importlib.util.spec_from_file_location("build_pyz", BUILD_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReproducibleBuildTests(unittest.TestCase):
    def test_two_builds_produce_identical_hash(self):
        build_pyz = _load_build_module()
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            old_umask = os.umask(0o022)
            try:
                data_a = build_pyz.build(Path(tmp1) / "entropyforge.pyz")
            finally:
                os.umask(old_umask)

            old_umask = os.umask(0o077)
            try:
                data_b = build_pyz.build(Path(tmp2) / "entropyforge.pyz")
            finally:
                os.umask(old_umask)

            import hashlib

            self.assertEqual(hashlib.sha256(data_a).hexdigest(), hashlib.sha256(data_b).hexdigest())
            self.assertEqual(data_a, data_b)

    def test_artifact_runs_selftest_successfully(self):
        import subprocess

        build_pyz = _load_build_module()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "entropyforge.pyz"
            build_pyz.build(out)
            proc = subprocess.run(
                [sys.executable, "-I", "-B", str(out), "selftest"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
            self.assertIn("PASSOU", proc.stdout)

    def test_artifact_excludes_tests_and_tools(self):
        import zipfile

        build_pyz = _load_build_module()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "entropyforge.pyz"
            data = build_pyz.build(out)
            # remove o shebang antes de abrir como zip
            zip_bytes = data[len(build_pyz.SHEBANG):]
            with tempfile.NamedTemporaryFile(suffix=".zip") as tf:
                tf.write(zip_bytes)
                tf.flush()
                with zipfile.ZipFile(tf.name) as zf:
                    names = zf.namelist()
            self.assertTrue(all(not n.startswith("tests/") for n in names))
            self.assertTrue(all(not n.startswith("tools/") for n in names))
            self.assertIn("entropyforge/data/english.txt", names)


if __name__ == "__main__":
    unittest.main()
