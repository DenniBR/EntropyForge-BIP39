"""Guarda de seguranca em tempo de execucao: audit hook fail-closed e
verificacao de que a maquina esta offline.

`activate()` deve ser chamada o MAIS CEDO POSSIVEL pelo ponto de entrada
(`__main__.py`), antes de qualquer outra logica do programa. A partir daí,
o processo Python inteiro:

  - aborta (levanta `GuardViolation`, que o CLI trata como erro fatal) se
    qualquer codigo (deste projeto, de uma dependencia, ou injetado por um
    bug) tentar: abrir um socket de rede, iniciar um subprocesso, executar
    outro programa (`os.system`/`os.exec*`), carregar uma biblioteca
    nativa via `ctypes`, ou abrir um arquivo em modo de ESCRITA/ANEXAR/
    CRIACAO;
  - nao pode ter esse hook removido em tempo de execucao -- e uma garantia
    do proprio interpretador (`sys.addaudithook`, PEP 578): uma vez
    registrado, um hook de auditoria so pode ser adicionado, nunca
    removido, dentro do mesmo processo.

LIMITE HONESTO (ver docs/THREAT_MODEL.md): isto e um mecanismo do
INTERPRETADOR Python, util contra bugs e regressoes no nosso proprio
codigo (ex.: um import acidental de `socket` ou uma dependencia que tenta
"telemetria"). NAO e uma defesa contra um adversario que ja controla o
processo, o interpretador, o kernel ou o hardware (ameacas T-OS, T-MAL,
T-HW): esse adversario pode simplesmente nao rodar este codigo, ou rodar
um interpretador modificado que ignora audit hooks.
"""

from __future__ import annotations

import os
import sys

_WRITE_MODE_CHARS = ("w", "a", "x", "+")

_WRITE_FLAGS = 0
for _name in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC", "O_EXCL"):
    _WRITE_FLAGS |= getattr(os, _name, 0)

_BLOCKED_EVENT_PREFIXES = (
    "socket.",
    "subprocess.",
    "os.exec",
    "os.posix_spawn",
    "os.spawn",
    "ctypes.dlopen",
    "ctypes.dlsym",
)

_BLOCKED_EVENTS = {
    "os.system",
    "os.remove",
    "os.rename",
    "os.unlink",
    "os.rmdir",
    "os.mkdir",
    "os.link",
    "os.symlink",
    "os.truncate",
    "shutil.rmtree",
    "shutil.move",
    "shutil.copy",
    "shutil.copyfile",
    "shutil.copytree",
    "tempfile.mkstemp",
    "tempfile.mkdtemp",
    "winreg.CreateKey",
    "winreg.SetValue",
}


class GuardViolation(RuntimeError):
    """Uma operacao bloqueada pela politica de seguranca foi tentada."""


def _is_write_mode(mode: object) -> bool:
    return isinstance(mode, str) and any(c in mode for c in _WRITE_MODE_CHARS)


def _is_write_flags(flags: object) -> bool:
    return isinstance(flags, int) and (flags & _WRITE_FLAGS) != 0


def _audit_hook(event: str, args: tuple) -> None:
    if event == "open":
        # args costuma ser (file, mode, flags); mode e None quando a
        # chamada veio de os.open (que usa flags no lugar de mode).
        file = args[0] if len(args) > 0 else "?"
        mode = args[1] if len(args) > 1 else None
        flags = args[2] if len(args) > 2 else None
        if _is_write_mode(mode) or _is_write_flags(flags):
            raise GuardViolation(
                f"escrita em arquivo bloqueada pela politica de seguranca: "
                f"{file!r} (mode={mode!r}, flags={flags!r}). Este programa "
                "nunca escreve em disco (requisito 14)."
            )
        return
    if event in _BLOCKED_EVENTS or event.startswith(_BLOCKED_EVENT_PREFIXES):
        raise GuardViolation(
            f"operacao bloqueada pela politica de seguranca: evento de "
            f"auditoria {event!r}. Este programa nunca acessa rede, "
            "processos externos ou bibliotecas nativas carregadas "
            "dinamicamente (requisito 13)."
        )


_activated = False


def activate() -> None:
    """Ativa o audit hook e desativa a escrita de bytecode (.pyc).

    Idempotente: chamadas repetidas depois da primeira nao fazem nada (o
    hook so pode ser adicionado uma vez neste processo de qualquer forma;
    `sys.addaudithook` aceita ser chamado varias vezes, mas isso so
    empilharia hooks redundantes).
    """
    global _activated
    if _activated:
        return
    # Sem isto, a PRIMEIRA importacao de cada modulo deste pacote (ou de
    # qualquer coisa que ainda nao tenha um .pyc em cache) dispararia o
    # bloqueio de escrita acima, pois o importador tenta gravar
    # __pycache__/*.pyc. Isto e independente de rodar com a flag `-B`, e
    # torna o guard seguro de ativar em qualquer forma de invocacao.
    sys.dont_write_bytecode = True
    sys.addaudithook(_audit_hook)
    _disable_core_dumps()
    _activated = True


def _disable_core_dumps() -> None:
    """Melhor esforco: impede que um crash grave o processo inteiro (que
    pode conter segredos em memoria) em um arquivo de core dump em disco.
    Nao disponivel em todas as plataformas (ex.: Windows nao tem o modulo
    `resource`); nesse caso, este e apenas um controle a menos, nao um
    erro fatal.
    """
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass


def list_active_network_interfaces() -> list[str]:
    """Linux: le `/sys/class/net/*/operstate` e devolve os nomes das
    interfaces (exceto `lo`, loopback) cujo estado e `up`.

    Levanta NotImplementedError em plataformas sem `/sys/class/net`
    (qualquer coisa que nao seja Linux). Isto e uma LIMITACAO conhecida,
    nao uma alegacao de que outras plataformas estao seguras.
    """
    base = "/sys/class/net"
    if not os.path.isdir(base):
        raise NotImplementedError(
            "verificacao de interfaces de rede via /sys/class/net nao "
            "disponivel nesta plataforma (suporte primario: Linux)"
        )
    active = []
    for iface in sorted(os.listdir(base)):
        if iface == "lo":
            continue
        try:
            with open(os.path.join(base, iface, "operstate"), "r") as f:
                state = f.read().strip()
        except OSError:
            continue
        if state == "up":
            active.append(iface)
    return active


def check_offline(allow_override: bool = False) -> list[str]:
    """Verifica (fail-closed) que a maquina parece estar offline.

    Levanta GuardViolation se: (a) alguma interface de rede alem de `lo`
    estiver em estado `up`, ou (b) a plataforma nao suportar esta
    verificacao -- "nao sei verificar" e tratado como "recuse por
    seguranca", nunca como "assuma que esta tudo bem". `allow_override`
    (so setado por uma confirmacao explicita e interativa no CLI, nunca por
    padrao) desarma as duas checagens.

    IMPORTANTE: esta verificacao so pode detectar a AUSENCIA de interfaces
    de rede ativas no nivel do SO. Ela NAO detecta malware, um SO
    comprometido que mente sobre o estado das interfaces, ou canais
    encobertos de exfiltracao. "Sem interfaces de rede ativas" nao e o
    mesmo que "sem malware" -- ver docs/THREAT_MODEL.md.
    """
    try:
        active = list_active_network_interfaces()
    except NotImplementedError as exc:
        if allow_override:
            return []
        raise GuardViolation(
            "nao foi possivel verificar interfaces de rede nesta "
            "plataforma; recusando continuar (fail-closed). Use a "
            "confirmacao explicita de override para prosseguir mesmo "
            "assim, por sua conta e risco."
        ) from exc
    if active and not allow_override:
        raise GuardViolation(
            f"interface(s) de rede ativa(s) detectada(s): {active}. Este "
            "programa deve rodar totalmente offline. Desligue a rede "
            "(Wi-Fi, Ethernet, Bluetooth) e tente novamente, ou use a "
            "confirmacao explicita de override, por sua conta e risco. "
            "'Sem rede' nao e o mesmo que 'sem malware' -- ver "
            "docs/THREAT_MODEL.md."
        )
    return active
