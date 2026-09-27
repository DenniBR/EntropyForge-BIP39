import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.static_scan import diff_findings, scan_directory, scan_source_text, summarize

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class AstLayerTests(unittest.TestCase):
    def test_detects_socket_import(self):
        findings = scan_source_text("import socket\n", "x.py")
        self.assertTrue(any(f.category == "rede" and f.layer == "ast" for f in findings))

    def test_detects_subprocess_call(self):
        src = "import subprocess\nsubprocess.Popen(['ls'])\n"
        findings = scan_source_text(src, "x.py")
        categories = {f.category for f in findings}
        self.assertIn("execucao_externa", categories)

    def test_detects_eval_reference(self):
        # 'eval' aparece tanto em 'execucao_externa' quanto em 'reflexao'
        # neste scanner (categorizacao aproximada, nao mutuamente
        # exclusiva); o que importa aqui e que o uso de `eval` sem
        # chamada direta visivel (atribuido a uma variavel) e detectado
        # em ALGUMA categoria, nao uma categoria especifica.
        findings = scan_source_text("f = eval\n", "x.py")
        self.assertTrue(any(f.category in ("reflexao", "execucao_externa") for f in findings))

    def test_ignores_unrelated_calls(self):
        findings = scan_source_text("def f(x):\n    return x + 1\n", "x.py")
        self.assertEqual(findings, [])

    def test_syntax_error_reported_not_raised(self):
        findings = scan_source_text("def f(:\n", "broken.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "erro_de_sintaxe")


class TextualLayerTests(unittest.TestCase):
    def test_detects_mention_in_comment(self):
        # a camada textual encontra ate em comentarios -- e por isso ela
        # tem mais ruido que a camada AST, de proposito documentado.
        findings = scan_source_text("# nunca usamos socket aqui\n", "x.py")
        self.assertTrue(any(f.layer == "textual" and f.category == "rede" for f in findings))

    def test_dns_like_pattern_detected(self):
        src = 'host = "4e509a8f6dd7dd5f1800027ee1f6c828.attacker.example"\n'
        findings = scan_source_text(src, "x.py")
        self.assertTrue(any(f.category == "possivel_exfiltracao_dns" for f in findings))


class DiffTests(unittest.TestCase):
    def test_diff_is_empty_for_identical_scans(self):
        findings = scan_directory(REPO_ROOT / "entropyforge")
        self.assertEqual(diff_findings(findings, findings), [])

    def test_diff_finds_new_backdoor_pattern(self):
        baseline = scan_source_text("def combine(a, b):\n    return a + b\n", "combine.py")
        current = scan_source_text(
            "import socket\n\n\ndef combine(a, b):\n    s = socket.socket()\n    s.send(b'x')\n    return a + b\n",
            "combine.py",
        )
        new = diff_findings(baseline, current)
        self.assertGreater(len(new), 0)
        self.assertTrue(any(f.category == "rede" for f in new))

    def test_relative_paths_allow_cross_directory_comparison(self):
        findings = scan_directory(REPO_ROOT / "entropyforge")
        for f in findings:
            self.assertFalse(Path(f.file).is_absolute(), msg=f.file)


class RealCodebaseTests(unittest.TestCase):
    def test_scan_runs_without_crashing_on_real_source(self):
        findings = scan_directory(REPO_ROOT / "entropyforge")
        self.assertIsInstance(findings, list)
        # nao deve haver erro de sintaxe no codigo real
        self.assertFalse(any(f.category == "erro_de_sintaxe" for f in findings))

    def test_summary_counts_match_findings(self):
        findings = scan_directory(REPO_ROOT / "entropyforge")
        total = sum(summarize(findings).values())
        self.assertEqual(total, len(findings))


if __name__ == "__main__":
    unittest.main()
