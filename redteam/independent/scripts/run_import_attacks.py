#!/usr/bin/env python3
"""Fase 10: ataques de import (shadowing, PYTHONPATH, sitecustomize, .pth).

Testa, em cada FORMA DE INVOCACAO suportada do EntropyForge, se um
arquivo malicioso plantado no diretorio de trabalho (simulando um
atacante com escrita no cwd, ou um diretorio de download comprometido)
consegue substituir silenciosamente um modulo da biblioteca padrao
(`hashlib`) ou injetar codigo via `sitecustomize.py`.

Resultado principal (ver docs/INDEPENDENT_VERIFIER.md): a forma
RECOMENDADA de uso real (`python3 -I -B entropyforge.pyz <comando>`) e
IMUNE a esse ataque (a flag -I implica -P, que nao adiciona o cwd ao
sys.path). A forma de DESENVOLVIMENTO (`python3 -B -m entropyforge`, sem
-I, a partir de um checkout) e VULNERAVEL: um `hashlib.py` malicioso no
cwd e carregado no lugar do de verdade. Isto ja era mencionado
implicitamente na documentacao do EntropyForge (a recomendacao de usar
sempre o `.pyz` com -I para uso real), mas nao com essa razao especifica
declarada -- ver a correcao de documentacao proposta.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

FAKE_HASHLIB = (
    'print("### LAB: hashlib FALSO CARREGADO (import shadowing) ###")\n'
    "def sha256(*a, **kw):\n"
    "    class _FakeDigest:\n"
    "        def digest(self): return b'\\x00' * 32\n"
    "        def hexdigest(self): return '0' * 64\n"
    "    return _FakeDigest()\n"
)

FAKE_SITECUSTOMIZE = 'print("### LAB: sitecustomize MALICIOSO CARREGADO ###")\n'


def _build_pyz(out_path: Path) -> None:
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import build_pyz  # type: ignore

    build_pyz.build(out_path)


def run_case(label: str, cmd: list[str], cwd: Path, env_extra: dict | None = None) -> str:
    import os

    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=20)
    return proc.stdout + proc.stderr


def main() -> int:
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        pyz_path = tmp / "entropyforge.pyz"
        _build_pyz(pyz_path)
        (tmp / "hashlib.py").write_text(FAKE_HASHLIB)
        (tmp / "sitecustomize.py").write_text(FAKE_SITECUSTOMIZE)

        cases = [
            ("pyz com -I -B (uso real recomendado)", [sys.executable, "-I", "-B", str(pyz_path), "selftest"], {}),
            ("pyz com -S -I -B (site desabilitado, comparacao)", [sys.executable, "-S", "-I", "-B", str(pyz_path), "selftest"], {}),
            ("source com -B -m entropyforge, SEM -I (dev)", [sys.executable, "-B", "-m", "entropyforge", "selftest"], {"PYTHONPATH": str(REPO_ROOT)}),
        ]

        for label, cmd, env_extra in cases:
            out = run_case(label, cmd, tmp, env_extra)
            hashlib_shadowed = "LAB: hashlib FALSO" in out
            site_shadowed = "LAB: sitecustomize" in out
            passed = "RESULTADO GERAL: PASSOU" in out
            results.append((label, hashlib_shadowed, site_shadowed, passed))
            print(f"=== {label} ===")
            print(f"  hashlib.py do cwd foi carregado? {hashlib_shadowed}")
            print(f"  sitecustomize.py do cwd foi carregado? {site_shadowed}")
            print(f"  selftest reporta PASSOU? {passed}")
            print()

    print("=== RESUMO ===")
    for label, hs, ss, passed in results:
        print(f"{label}: hashlib_shadowed={hs} sitecustomize_shadowed={ss} selftest_passou={passed}")

    vulnerable = [r for r in results if r[1] or r[2]]
    print(f"\n{len(vulnerable)}/{len(results)} formas de invocacao sao vulneraveis a shadowing via cwd.")
    for r in vulnerable:
        print(f"  VULNERAVEL: {r[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
