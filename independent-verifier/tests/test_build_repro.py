import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.build_repro import BuildReproResult, check_build_determinism

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class BuildDeterminismTests(unittest.TestCase):
    def test_two_builds_under_different_umask_are_identical(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            r = check_build_determinism(REPO_ROOT, Path(a), Path(b), umask_a=0o022, umask_b=0o077)
            self.assertTrue(r.identical, msg=(r.hash_a, r.hash_b))

    def test_result_hashes_are_64_hex_chars(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            r = check_build_determinism(REPO_ROOT, Path(a), Path(b))
            self.assertEqual(len(r.hash_a), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in r.hash_a))


class NonReproducibleBuildDetectionTests(unittest.TestCase):
    """Fase 18 (matriz de testes obrigatoria): 'build nao reprodutivel'
    precisa ser um cenario com evidencia EMPIRICA, nao so uma alegacao. Aqui
    construimos uma copia de `tools/build_pyz.py` que embute o relogio de
    parede (`time.time()`) num arquivo do artefato -- uma causa REAL e
    comum de builds nao-deterministicos -- e confirmamos que
    `check_build_determinism` de fato reporta os dois builds como
    DIFERENTES, ao contrario do `tools/build_pyz.py` real (que usa uma
    data fixa e ja e testado como deterministico acima)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        shutil.copytree(REPO_ROOT / "entropyforge", self.tmp / "entropyforge")

        real_script = (REPO_ROOT / "tools" / "build_pyz.py").read_text(encoding="utf-8")
        needle = 'files["__main__.py"] = TOP_LEVEL_MAIN.encode("utf-8")'
        self.assertIn(needle, real_script)
        non_repro_script = real_script.replace(
            needle,
            needle + "\n"
            '    files["entropyforge/_build_timestamp.txt"] = str(__import__("time").time()).encode("ascii")',
            1,
        )
        self.assertNotEqual(non_repro_script, real_script)
        (self.tmp / "tools").mkdir()
        (self.tmp / "tools" / "build_pyz.py").write_text(non_repro_script, encoding="utf-8")

    def test_wall_clock_embedding_is_detected_as_non_deterministic(self):
        r = check_build_determinism(self.tmp, self.tmp / "a", self.tmp / "b")
        self.assertFalse(r.identical, msg="build com timestamp embutido deveria ser nao-deterministico")


class BuildReproResultIdenticalPropertyTests(unittest.TestCase):
    """Fase 14 (mutation testing do PROPRIO verificador): regressao para um
    mutante que SOBREVIVEU na primeira rodada -- `identical` mutado para
    comparar so `size_a`/`size_b`, ignorando os hashes, ainda passava em
    toda a suite (nenhum teste ate entao construia dois resultados com o
    MESMO tamanho e hashes DIFERENTES). Isso teria feito dois builds de
    tamanhos iguais mas conteudos diferentes serem reportados como
    'identicos' -- uma falsa reprodutibilidade."""

    def test_same_size_different_hash_is_not_identical(self):
        r = BuildReproResult(hash_a="a" * 64, hash_b="b" * 64, size_a=1000, size_b=1000)
        self.assertFalse(r.identical)

    def test_same_hash_and_size_is_identical(self):
        r = BuildReproResult(hash_a="a" * 64, hash_b="a" * 64, size_a=1000, size_b=1000)
        self.assertTrue(r.identical)

    def test_same_hash_but_different_size_is_not_identical(self):
        # caso patologico (nao deveria ocorrer na pratica -- hashes iguais
        # implicam conteudo identico, logo tamanho identico), mas fixa o
        # comportamento exato de `identical` como um AND, nao um OR.
        r = BuildReproResult(hash_a="a" * 64, hash_b="a" * 64, size_a=1000, size_b=999)
        self.assertFalse(r.identical)


if __name__ == "__main__":
    unittest.main()
