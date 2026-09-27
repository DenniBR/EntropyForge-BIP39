"""Observacao EXTERNA de processo via `strace` (Fase 11).

Ao contrario de todo o resto deste verificador (que le codigo-fonte ou
bytes de um artefato), este modulo observa o artefato **em execucao**,
no nivel de CHAMADAS DE SISTEMA (syscalls) do kernel -- uma camada que o
proprio programa nao controla e nao pode mentir para (mesmo que o
programa esteja rodando um interpretador Python inteiramente
comprometido, ele ainda precisa fazer syscalls reais para tocar a rede
ou o disco).

Isto e estritamente mais forte do que confiar no audit hook do proprio
EntropyForge (`entropyforge.guard`): se o guard estiver desativado,
removido, ou contornado por algum bug, o `strace` ainda veria a
tentativa de syscall diretamente.

Requer o binario `strace` instalado (Linux). Se nao disponivel, as
funcoes levantam `StraceUnavailable` -- o chamador deve tratar isso como
"nao foi possivel observar", nunca como "nada aconteceu".
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

NETWORK_SYSCALLS = ("connect", "sendto", "send", "socket", "getaddrinfo", "bind")
PROCESS_SYSCALLS = ("execve", "clone", "fork", "vfork")
FILE_WRITE_INDICATORS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")


class StraceUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class TraceResult:
    returncode: int
    stdout: str
    stderr: str
    raw_strace_log: str
    network_syscalls: tuple[str, ...]
    process_syscalls: tuple[str, ...]
    file_write_syscalls: tuple[str, ...]
    openat_calls: tuple[str, ...] = field(default_factory=tuple)

    @property
    def touched_network(self) -> bool:
        return len(self.network_syscalls) > 0

    @property
    def spawned_process(self) -> bool:
        return len(self.process_syscalls) > 0

    @property
    def wrote_to_disk(self) -> bool:
        return len(self.file_write_syscalls) > 0


def strace_available() -> bool:
    return shutil.which("strace") is not None


def _parse_strace_log(log_text: str) -> dict[str, list[str]]:
    """Analisa o log bruto do `strace -f`.

    Cuidado (bug ja corrigido aqui, ver `test_process_observe.py`): a
    PRIMEIRA linha do log e sempre o `execve` do proprio comando de nivel
    superior sendo tracado (e assim que `strace cmd` funciona: ele
    fork+PTRACE_TRACEME+exec o alvo, e esse exec inicial e capturado como
    qualquer outro). Isso NAO e um processo-filho "gerado" pelo programa
    -- e o processo que o CHAMADOR desta funcao pediu para rodar. Contar
    essa linha em `process_calls` tornaria `spawned_process` sempre
    verdadeiro, mesmo para um `python3 -c "1+1"` que nao gera nenhum
    filho -- um falso positivo que anularia a utilidade do sinal. Por
    isso a primeira ocorrencia de `execve` no log inteiro e excluida.
    """
    network, process_calls, file_writes, openat_calls = [], [], [], []
    seen_initial_execve = False
    for line in log_text.splitlines():
        for name in NETWORK_SYSCALLS:
            if re.search(rf"\b{name}\(", line):
                network.append(line.strip())
                break
        for name in PROCESS_SYSCALLS:
            if re.search(rf"\b{name}\(", line):
                if name == "execve" and not seen_initial_execve:
                    seen_initial_execve = True
                else:
                    process_calls.append(line.strip())
                break
        if "openat(" in line or re.search(r"\bopen\(", line):
            openat_calls.append(line.strip())
            if any(flag in line for flag in FILE_WRITE_INDICATORS):
                file_writes.append(line.strip())
    return {
        "network": network,
        "process": process_calls,
        "file_writes": file_writes,
        "openat": openat_calls,
    }


def trace_process(
    cmd: list[str],
    *,
    cwd: Path,
    timeout: int = 30,
    env: dict | None = None,
    stdin_data: str | None = None,
) -> TraceResult:
    """Roda `cmd` sob `strace -f`, capturando syscalls de rede, processo,
    e escrita de arquivo. Devolve um `TraceResult` com o log bruto (para
    inspecao manual) e listas ja filtradas.
    """
    if not strace_available():
        raise StraceUnavailable("binario 'strace' nao encontrado neste sistema")

    with tempfile.NamedTemporaryFile(mode="r", suffix=".straclog", delete=False) as tmp_log:
        log_path = Path(tmp_log.name)

    strace_cmd = [
        "strace",
        "-f",  # segue processos filhos
        "-e",
        "trace=network,openat,open,execve,execveat,clone,fork,vfork,connect,sendto,send",
        "-o",
        str(log_path),
        *cmd,
    ]
    try:
        proc = subprocess.run(
            strace_cmd,
            cwd=str(cwd),
            env=env,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw_log = log_path.read_text(errors="replace") if log_path.exists() else ""
    finally:
        log_path.unlink(missing_ok=True)

    parsed = _parse_strace_log(raw_log)
    return TraceResult(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        raw_strace_log=raw_log,
        network_syscalls=tuple(parsed["network"]),
        process_syscalls=tuple(parsed["process"]),
        file_write_syscalls=tuple(parsed["file_writes"]),
        openat_calls=tuple(parsed["openat"]),
    )
