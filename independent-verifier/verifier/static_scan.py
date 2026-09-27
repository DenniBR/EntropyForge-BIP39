"""Analisador estatico EXTERNO (Fase 8).

Procura, em codigo Python, padroes associados a rede, execucao externa,
E/S de arquivo, e canais indiretos de exfiltracao. Duas camadas,
deliberadamente combinadas (nenhuma sozinha e suficiente):

  1. **AST** -- caminha a arvore sintatica e identifica `import`s e
     chamadas de funcao cujo nome (ou atributo) bate com uma lista de
     termos suspeitos. Mais preciso que busca textual (nao e enganado por
     um comentario ou docstring mencionando "socket"), mas ainda
     enganavel por ofuscacao (`getattr(os, "sys" + "tem")`,
     `__import__("os").system(...)`, construir a string do modulo em
     tempo de execucao, etc.).

  2. **Textual (regex)** -- varre o texto bruto por termos suspeitos,
     incluindo em strings/comentarios. Mais barato e mais sensivel a
     ofuscacao leve (encontra `"os.syst" + "em"` como duas substrings
     ainda reconheciveis, por exemplo), mas gera mais falsos positivos
     (uma docstring que MENCIONA "nunca usamos socket" tambem aparece
     aqui).

**"static scan is evidence, not proof."** Nenhuma das duas camadas prova
a ausencia de um canal de exfiltracao: codigo pode construir nomes
dinamicamente, chamar por reflexao, ou usar canais que este scanner nem
sabe procurar. Um resultado limpo aqui e um dado a mais, nunca uma
certificacao de seguranca.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

# Categoria -> termos que, se aparecerem como nome de modulo importado ou
# como nome/atributo de uma chamada, sao reportados.
SUSPICIOUS_CALL_OR_IMPORT_NAMES: dict[str, tuple[str, ...]] = {
    "rede": ("socket", "connect", "send", "sendto", "sendall", "recv", "getaddrinfo", "create_connection"),
    "execucao_externa": ("subprocess", "popen", "system", "exec", "execv", "execve", "execvp", "posix_spawn", "eval", "fork"),
    "bibliotecas_nativas": ("ctypes", "cdll", "dlopen"),
    "http_dns": ("urllib", "http", "httplib", "requests", "dnspython", "resolver"),
    "arquivo_temporario": ("tempfile", "mkstemp", "mkdtemp", "namedtemporaryfile"),
    "arquivo_generico": ("open", "pathlib", "write", "writelines"),
    "clipboard": ("clipboard", "pyperclip", "xclip", "xsel", "pbcopy", "pbpaste"),
    "logging_debug": ("logging", "traceback", "print_exc", "warnings"),
    "ofuscacao_encoding": ("base64", "b64encode", "b64decode", "zlib", "gzip", "bz2", "lzma", "codecs"),
    "reflexao": ("__import__", "getattr", "importlib", "globals", "exec", "eval"),
}

# Para a camada textual: os mesmos termos, mas tambem casados dentro de
# strings/comentarios (por isso separados -- a camada AST so olha nomes
# de verdade em `import`/chamadas, essa aqui olha o texto inteiro).
_ALL_TERMS = sorted({t for terms in SUSPICIOUS_CALL_OR_IMPORT_NAMES.values() for t in terms}, key=len, reverse=True)
_TEXTUAL_PATTERN = re.compile(r"\b(" + "|".join(re.escape(t) for t in _ALL_TERMS) + r")\b", re.IGNORECASE)

# DNS-like: procura por algo que pareca um hostname com muitos caracteres
# hex seguidos (padrao classico de exfiltracao via subdominio).
_DNS_EXFIL_PATTERN = re.compile(r"[0-9a-fA-F]{16,}\.[a-zA-Z0-9\-.]+")


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    layer: str  # "ast" ou "textual"
    category: str
    detail: str


def _category_for_name(name: str) -> str | None:
    name_lower = name.lower()
    for category, terms in SUSPICIOUS_CALL_OR_IMPORT_NAMES.items():
        if name_lower in terms:
            return category
    return None


def _ast_scan_source(source: str, filename: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return [Finding(file=filename, line=exc.lineno or 0, layer="ast", category="erro_de_sintaxe", detail=str(exc))]

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                cat = _category_for_name(top)
                if cat:
                    findings.append(Finding(filename, node.lineno, "ast", cat, f"import {alias.name}"))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                cat = _category_for_name(top)
                if cat:
                    findings.append(Finding(filename, node.lineno, "ast", cat, f"from {node.module} import ..."))
            for alias in node.names:
                cat = _category_for_name(alias.name)
                if cat:
                    findings.append(Finding(filename, node.lineno, "ast", cat, f"from ... import {alias.name}"))
        elif isinstance(node, ast.Call):
            func = node.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name:
                cat = _category_for_name(name)
                if cat:
                    findings.append(Finding(filename, node.lineno, "ast", cat, f"chamada: {name}(...)"))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            # pega referencias a builtins perigosos usados sem chamada
            # direta visivel (ex.: atribuidos a uma variavel antes de usar)
            cat = _category_for_name(node.id)
            if cat and node.id in ("eval", "exec", "__import__"):
                findings.append(Finding(filename, node.lineno, "ast", cat, f"referencia a {node.id}"))

    return findings


def _textual_scan_source(source: str, filename: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(source.splitlines(), 1):
        for m in _TEXTUAL_PATTERN.finditer(line):
            term = m.group(1).lower()
            cat = _category_for_name(term)
            if cat:
                findings.append(Finding(filename, lineno, "textual", cat, f"termo {term!r} encontrado na linha"))
        for m in _DNS_EXFIL_PATTERN.finditer(line):
            findings.append(
                Finding(filename, lineno, "textual", "possivel_exfiltracao_dns",
                        f"padrao parecido com hostname-com-hex: {m.group(0)!r}")
            )
    return findings


def scan_source_text(source: str, filename: str = "<string>") -> list[Finding]:
    return _ast_scan_source(source, filename) + _textual_scan_source(source, filename)


def scan_file(path: Path) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as exc:
        return [Finding(str(path), 0, "ast", "erro_de_leitura", str(exc))]
    return scan_source_text(source, str(path))


def scan_directory(root: Path, *, suffixes: tuple[str, ...] = (".py",)) -> list[Finding]:
    """Os `Finding.file` resultantes sao caminhos RELATIVOS a `root`
    (nao absolutos), de proposito: isso permite comparar o escaneamento
    de duas copias fisicamente diferentes (ex.: dois diretorios
    temporarios distintos) do "mesmo" codigo via `diff_findings`."""
    findings: list[Finding] = []
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in suffixes and "__pycache__" not in path.parts:
            rel = str(path.relative_to(root))
            for f in scan_file(path):
                findings.append(Finding(file=rel, line=f.line, layer=f.layer, category=f.category, detail=f.detail))
    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.category] = counts.get(f.category, 0) + 1
    return counts


def _finding_key(f: Finding) -> tuple:
    return (f.file, f.line, f.layer, f.category, f.detail)


def diff_findings(baseline: list[Finding], current: list[Finding]) -> list[Finding]:
    """Achados presentes em `current` mas NAO em `baseline`.

    Uso pretendido: escaneie uma versao do codigo que voce ja revisou
    manualmente (o baseline aceito), guarde o resultado, e depois so
    preste atencao em achados NOVOS ao reescanear uma versao futura --
    isso filtra o ruido inerente de termos legitimos (`write`, `open`
    para leitura, etc.) que qualquer projeto real vai ter, e concentra a
    atencao no que MUDOU.
    """
    baseline_keys = {_finding_key(f) for f in baseline}
    return [f for f in current if _finding_key(f) not in baseline_keys]


DISCLAIMER = (
    "static scan is evidence, not proof. Um resultado limpo NAO garante "
    "ausencia de exfiltracao (ofuscacao, reflexao, e canais nao previstos "
    "por este scanner passam despercebidos); um resultado com achados "
    "exige revisao humana -- muitos termos aqui (ex.: 'open', 'logging') "
    "tem usos legitimos abundantes, e este scanner nao tenta distinguir "
    "contexto alem do que a camada AST ja separa (import/chamada vs "
    "mencao textual)."
)
