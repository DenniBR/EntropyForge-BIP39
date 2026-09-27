"""Verificacao de reprodutibilidade do build (Fase 5).

Duas checagens complementares, deliberadamente separadas:

1. `check_build_determinism`: chama `tools/build_pyz.py` (do projeto SOB
   TESTE) duas vezes, em diretorios/umask diferentes, e compara os hashes
   calculados pelo PROPRIO verificador (nunca confiando no hash que o
   script de build imprime). Isto confirma que o processo de build e
   DETERMINISTICO -- mas NAO confirma que ele e HONESTO: um
   `tools/build_pyz.py` malicioso poderia embutir um backdoor de forma
   perfeitamente determinística (o mesmo backdoor toda vez), passando
   nesta checagem sem problema.

2. `compare_pyz_to_source` (em `pyz_inspect.py`) e a checagem que
   realmente importa para detectar isso: ela nao se importa com COMO o
   `.pyz` foi gerado, so se o CONTEUDO de cada arquivo dentro dele bate
   com o codigo-fonte ja hasheado independentemente. Um `tools/build_pyz.py`
   malicioso que embute algo A MAIS no artefato (nao presente no source)
   e pego por `compare_pyz_to_source` (vira `unexpected_in_pyz`),
   independentemente de o build ser "reprodutivel" ou nao.

Rode as duas. `check_build_determinism` sozinha NUNCA deve ser
apresentada como prova de integridade.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .hashing import hash_file


@dataclass(frozen=True)
class BuildReproResult:
    hash_a: str
    hash_b: str
    size_a: int
    size_b: int

    @property
    def identical(self) -> bool:
        return self.hash_a == self.hash_b and self.size_a == self.size_b


def _build_via_subprocess(build_script: Path, out_path: Path, umask: int, extra_env: dict | None = None) -> None:
    """Invoca `tools/build_pyz.py` como um SUBPROCESSO (nao importa o
    modulo), com um umask especifico, para reproduzir de forma realista
    duas maquinas/sessoes diferentes construindo o mesmo artefato."""
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    preexec = None
    if sys.platform != "win32":
        def preexec():  # noqa: ANN001
            os.umask(umask)
    subprocess.run(
        [sys.executable, str(build_script), str(out_path)],
        check=True,
        capture_output=True,
        text=True,
        env=env,
        preexec_fn=preexec,
    )


def check_build_determinism(
    repo_root: Path, workdir_a: Path, workdir_b: Path, *, umask_a: int = 0o022, umask_b: int = 0o077
) -> BuildReproResult:
    build_script = repo_root / "tools" / "build_pyz.py"
    if not build_script.exists():
        raise FileNotFoundError(f"script de build nao encontrado: {build_script}")

    out_a = workdir_a / "entropyforge.pyz"
    out_b = workdir_b / "entropyforge.pyz"
    workdir_a.mkdir(parents=True, exist_ok=True)
    workdir_b.mkdir(parents=True, exist_ok=True)

    _build_via_subprocess(build_script, out_a, umask_a)
    _build_via_subprocess(build_script, out_b, umask_b)

    return BuildReproResult(
        hash_a=hash_file(out_a),
        hash_b=hash_file(out_b),
        size_a=out_a.stat().st_size,
        size_b=out_b.stat().st_size,
    )
