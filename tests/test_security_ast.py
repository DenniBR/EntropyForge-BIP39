"""Verificacao ESTATICA (via AST, sem executar nada) de que nenhum modulo
do pacote `entropyforge/` importa: `random` (requisito 1: nunca gerar a
seed por um PRNG proprio), modulos de rede, `subprocess`, `ctypes`,
`logging`, ou funcoes de escrita de arquivo fora do que o proprio `guard.py`
precisa para existir.

Isto e defesa em profundidade complementar ao audit hook em tempo de
execucao (`guard.py`): o audit hook pega uma tentativa de USO em tempo de
execucao; este teste pega a intencao no proprio codigo-fonte, antes mesmo
de rodar.
"""

import ast
import unittest
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent.parent / "entropyforge"

FORBIDDEN_MODULES = {
    "random",
    "socket",
    "ssl",
    "http",
    "http.client",
    "urllib",
    "urllib.request",
    "ftplib",
    "smtplib",
    "telnetlib",
    "subprocess",
    "ctypes",
    "logging",
    "asyncio",  # traz event loops de rede; nao usado neste projeto
    "tkinter",  # unica via da bibl. padrao para clipboard; nunca usado (Fase E)
}


def _iter_imported_module_names(tree: ast.Module):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                yield node.module


class NoForbiddenImportsTests(unittest.TestCase):
    def test_no_module_imports_forbidden_names(self):
        violations = []
        for path in sorted(PACKAGE_DIR.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for name in _iter_imported_module_names(tree):
                top_level = name.split(".")[0]
                if name in FORBIDDEN_MODULES or top_level in FORBIDDEN_MODULES:
                    violations.append((path.relative_to(PACKAGE_DIR.parent), name))
        self.assertEqual(violations, [], f"imports proibidos encontrados: {violations}")

    def test_scans_at_least_the_expected_number_of_modules(self):
        # Guarda contra um erro bobo (ex.: PACKAGE_DIR apontando para
        # lugar errado e o teste "passando" por nao encontrar nada).
        files = [p for p in PACKAGE_DIR.rglob("*.py") if "__pycache__" not in p.parts]
        self.assertGreaterEqual(len(files), 10)


class NoEnvironmentVariableUsageTests(unittest.TestCase):
    """Fase E (auditoria de manuseio de segredos, canal 'variaveis de
    ambiente'): nenhum modulo de `entropyforge/` le `os.environ` nem
    chama `os.getenv`/`os.putenv` -- uma variavel de ambiente "magica" que
    alterasse o comportamento do programa seria um canal de ataque
    invisivel a qualquer teste de resposta conhecida (ver
    docs/INDEPENDENT_VERIFIER.md, backdoors condicionais #09/#13).

    Isto ja era verificado ad-hoc por um script de red team (Fase D,
    `redteam/scripts/cli_fuzz.py`, item 8) -- promovido aqui a teste de
    regressao permanente."""

    def test_no_environ_or_getenv_usage(self):
        violations = []
        for path in sorted(PACKAGE_DIR.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in ("environ", "getenv", "putenv", "unsetenv"):
                    violations.append((path.relative_to(PACKAGE_DIR.parent), node.attr, node.lineno))
        self.assertEqual(violations, [], f"uso de variavel de ambiente encontrado: {violations}")


if __name__ == "__main__":
    unittest.main()
