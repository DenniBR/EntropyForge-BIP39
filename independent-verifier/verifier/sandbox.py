"""Sandbox de execucao (Fase 12).

Roda um comando com:

  - uma NAMESPACE DE REDE ISOLADA e vazia (`unshare --net`), de modo que
    mesmo que TODO o resto (guard.py, o interpretador, o proprio kernel
    de auditoria) estivesse comprometido, uma tentativa de rede real
    ainda falharia por nao haver nenhuma interface disponivel -- isto e
    independente de qualquer coisa que o EntropyForge faca ou deixe de
    fazer;
  - um DIRETORIO DE TRABALHO TEMPORARIO dedicado, com o conteudo
    hasheado (via `hashing.py`) antes e depois da execucao, para detectar
    qualquer arquivo criado, mesmo fora de `/tmp` (o diretorio de
    trabalho do processo);
  - captura de stdout/stderr e do codigo de saida.

IMPORTANTE (Fase 12, texto exigido pela auditoria): **"nao tentou rede no
sandbox" NAO e prova de que nenhum payload existe.** Um payload pode ser
condicional (so ativa em certas condicoes, como os laboratorios 07/08/09),
pode escrever fora do diretorio de trabalho monitorado (ex.: em `/tmp`
diretamente, que este sandbox NAO isola do sistema de arquivos real -- so
a REDE e isolada aqui), ou pode simplesmente nao ter sido exercitado pela
entrada usada neste teste especifico.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .hashing import ManifestDiff, build_manifest, diff_manifests


class SandboxUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    workdir_diff: ManifestDiff
    network_isolation_applied: bool


def unshare_available() -> bool:
    """Verificacao FUNCIONAL, nao so "o binario existe": alguns
    ambientes de container (ex.: os runners `ubuntu-latest` hospedados
    pelo GitHub Actions, cujo perfil AppArmor padrao restringe a criacao
    de namespaces de rede por processos sem privilegio desde o Ubuntu
    24.04) tem o binario `unshare` instalado, mas o kernel/container
    RECUSA a chamada `unshare(2)` de qualquer forma -- confirmado
    empiricamente ao rodar a suite neste tipo de runner: `unshare --net`
    falhava silenciosamente (retorno != 0), fazendo o sandbox achar que
    isolou a rede quando na verdade nao isolou nada. Rodar um comando
    trivial sob `unshare --net` de verdade, em vez de so checar
    `shutil.which`, e' a unica forma de nao se enganar sobre isso."""
    if shutil.which("unshare") is None:
        return False
    try:
        result = subprocess.run(
            ["unshare", "--net", "--", "true"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def run_in_sandbox(
    cmd: list[str],
    *,
    workdir: Path,
    timeout: int = 30,
    env: dict | None = None,
    stdin_data: str | None = None,
    isolate_network: bool = True,
) -> SandboxResult:
    workdir.mkdir(parents=True, exist_ok=True)
    before = build_manifest(workdir, include_suffixes=None)

    network_applied = False
    if isolate_network:
        if not unshare_available():
            raise SandboxUnavailable("binario 'unshare' nao encontrado; nao e possivel isolar rede")
        full_cmd = ["unshare", "--net", "--"] + cmd
        network_applied = True
    else:
        full_cmd = cmd

    proc = subprocess.run(
        full_cmd,
        cwd=str(workdir),
        env=env,
        input=stdin_data,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    after = build_manifest(workdir, include_suffixes=None)
    diff = diff_manifests(before, after)

    return SandboxResult(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        workdir_diff=diff,
        network_isolation_applied=network_applied,
    )


DISCLAIMER = (
    "nao tentou rede no sandbox NAO e prova de que nenhum payload existe: "
    "o payload pode ser condicional, pode escrever fora do diretorio "
    "monitorado, ou pode simplesmente nao ter sido exercitado pela entrada "
    "usada neste teste."
)
