#!/usr/bin/env python3
"""Cerimonia de geracao automatizada: roda TODAS as pre-condicoes
externas e internas antes de invocar `entropyforge generate`, abortando
(fail-closed) se qualquer uma falhar.

## Por que isto NAO e um subcomando `safe-generate` dentro do proprio
## entropyforge (decisao de engenharia documentada, ver docs/RELEASE_SECURITY_CHECKLIST.md)

`entropyforge generate` ja automatiza TODAS as pre-condicoes INTERNAS que
um comando "safe-generate" poderia oferecer: recusa rede (fail-closed,
`guard.check_offline`), roda `selftest` antes de prosseguir, a wordlist e
validada por hash a cada carregamento (`wordlist.load_wordlist`), o
CSPRNG falha fechado sem fallback (`osrng.read_os_entropy`), a sequencia
de dado e validada estatisticamente com confirmacao explicita exigida em
caso de FAIL, e nao ha logs/clipboard/arquivos em nenhum lugar do
processo (verificado por `tests/test_security_ast.py` e `guard.py`).
Adicionar um "safe-generate" DENTRO do entropyforge que refizesse essas
mesmas checagens seria puramente cosmetico.

O que falta automatizar sao as checagens EXTERNAS -- comparar o artefato
`.pyz` contra o source-tree, verificar a wordlist contra um hash
independente -- e essas, por design (ver docs/INDEPENDENT_VERIFIER.md),
NAO PODEM ser feitas pelo proprio entropyforge se verificando: um `.pyz`
comprometido poderia sempre mentir sobre sua propria integridade. Este
script preenche essa lacuna operacional SEM violar esse principio: ele
roda o `independent-verifier` como um PROCESSO/IMPORT EXTERNO (nunca
importado por entropyforge, nunca parte do artefato distribuido) e so
prossegue para `generate` se todas as checagens externas passarem.

## Uso

    python3 tools/preflight_and_generate.py --pyz entropyforge.pyz -- generate

Qualquer argumento apos `--` e passado literalmente para o comando do
`.pyz` (tipicamente `generate`, mas tambem `selftest`/`calibrate`/`vector`
para conveniencia de teste). Se QUALQUER pre-condicao falhar, o script
sai com codigo != 0 e NUNCA invoca o `.pyz`.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEPENDENT_VERIFIER = REPO_ROOT / "independent-verifier"


class PreflightFailure(RuntimeError):
    pass


def _log(msg: str) -> None:
    print(f"[preflight] {msg}", file=sys.stderr)


def check_wordlist(entropyforge_root: Path) -> None:
    sys.path.insert(0, str(INDEPENDENT_VERIFIER))
    from verifier.wordlist_check import check_matches_official_hash, check_wordlist_file

    wordlist_path = entropyforge_root / "data" / "english.txt"
    report = check_wordlist_file(wordlist_path)
    if not report.ok:
        raise PreflightFailure(f"wordlist reprovada na verificacao estrutural: {report.problems}")
    matches, msg = check_matches_official_hash(report)
    if not matches:
        raise PreflightFailure(f"wordlist nao bate com o hash oficial conhecido pelo verificador: {msg}")
    _log(f"wordlist OK (sha256={report.sha256})")


def check_pyz_matches_source(pyz_path: Path, entropyforge_root: Path) -> None:
    from verifier.pyz_inspect import check_bootstrap_main, compare_pyz_to_source

    result = compare_pyz_to_source(pyz_path, entropyforge_root)
    if not result.ok:
        raise PreflightFailure(
            f".pyz NAO bate com o source-tree: mismatches={result.content_mismatches} "
            f"faltando={result.missing_from_pyz} inesperado={result.unexpected_in_pyz}"
        )
    ok, msg = check_bootstrap_main(pyz_path)
    if not ok:
        raise PreflightFailure(f"bootstrap __main__.py do .pyz diverge do esperado: {msg}")
    _log("`.pyz` bate byte-a-byte com o source-tree (conteudo + bootstrap)")


def check_selftest(pyz_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, "-I", "-B", str(pyz_path), "selftest"],
        capture_output=True, text=True, timeout=30,
    )
    if "RESULTADO GERAL: PASSOU" not in proc.stdout:
        raise PreflightFailure(f"selftest do .pyz nao reportou PASSOU:\n{proc.stdout}\n{proc.stderr}")
    _log("selftest do `.pyz` reportou PASSOU")


def run_preflight(pyz_path: Path, entropyforge_root: Path) -> None:
    if not pyz_path.exists():
        raise PreflightFailure(f".pyz nao encontrado em {pyz_path} -- rode 'make build' primeiro")
    if not entropyforge_root.exists():
        raise PreflightFailure(f"source-tree de referencia nao encontrado em {entropyforge_root}")
    check_wordlist(entropyforge_root)
    check_pyz_matches_source(pyz_path, entropyforge_root)
    check_selftest(pyz_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pyz", type=Path, default=REPO_ROOT / "entropyforge.pyz")
    parser.add_argument("--entropyforge-root", type=Path, default=REPO_ROOT / "entropyforge")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="comando e argumentos para o .pyz (ex.: generate)")
    args = parser.parse_args(argv)

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("informe o comando a rodar apos '--' (ex.: -- generate)")

    try:
        run_preflight(args.pyz.resolve(), args.entropyforge_root.resolve())
    except PreflightFailure as exc:
        _log(f"FALHA na pre-condicao -- abortando, {args.pyz} NAO sera executado: {exc}")
        return 1

    _log(f"todas as pre-condicoes passaram; executando: {args.pyz} {' '.join(command)}")
    os.execv(sys.executable, [sys.executable, "-I", "-B", str(args.pyz), *command])


if __name__ == "__main__":
    sys.exit(main())
