"""Fonte B: 256 bits do CSPRNG do sistema operacional (requisito 3).

Regras (requisito 1 e secao D3 do design):
  - NUNCA usa o modulo `random` (PRNG nao criptografico, semeavel).
  - NUNCA usa `time`, PID, endereco MAC, nome de maquina, posicao do
    mouse, ou qualquer outra fonte previsivel/observavel.
  - NUNCA cai silenciosamente para uma fonte alternativa se a leitura do
    CSPRNG do SO falhar: falha FECHADO (levanta excecao).

Um teste de AST (tests/test_security_ast.py) verifica estaticamente que
nenhum modulo deste projeto importa `random`.
"""

from __future__ import annotations

import os

OSRNG_BYTES = 32  # 256 bits


class OsRngError(RuntimeError):
    """A fonte B nao pode ser obtida do CSPRNG do sistema operacional."""


def read_os_entropy(nbytes: int = OSRNG_BYTES) -> bytes:
    """Le `nbytes` do CSPRNG do sistema operacional. Falha fechado.

    Linux: `os.getrandom(nbytes, 0)`, a syscall `getrandom(2)`, que
    BLOQUEIA ate o gerador do kernel estar inicializado. Isto e
    deliberadamente diferente de ler `/dev/urandom` diretamente: em
    kernels antigos, `/dev/urandom` pode devolver bytes de baixa
    qualidade antes do gerador terminar de inicializar (ver CVE-2018-1108
    e a motivacao original da syscall `getrandom`).

    Outros sistemas operacionais (macOS, *BSD, Windows): usa `os.urandom`,
    que o proprio interpretador Python implementa sobre a API de CSPRNG
    do SO (`getentropy()` no macOS/BSD, `BCryptGenRandom` no Windows). O
    suporte primario deste projeto e Linux; nesses outros SOs a garantia
    de bloqueio ate a inicializacao do gerador depende da implementacao do
    interpretador, nao deste codigo.
    """
    if nbytes <= 0:
        raise ValueError("nbytes deve ser > 0")
    try:
        if hasattr(os, "getrandom"):
            data = os.getrandom(nbytes, 0)
        else:
            data = os.urandom(nbytes)
    except OSError as exc:
        raise OsRngError(
            "falha ao ler o CSPRNG do sistema operacional "
            f"({exc}). Recusando continuar: este projeto nunca usa uma "
            "fonte alternativa (fail-closed, sem fallback silencioso)."
        ) from exc
    if len(data) != nbytes:
        raise OsRngError(
            f"CSPRNG devolveu {len(data)} bytes, esperado {nbytes}; "
            "recusando continuar."
        )
    _reject_constant_output(data)
    return data


def _reject_constant_output(data: bytes) -> None:
    """Verificacao MINIMA de sanidade: rejeita uma leitura em que todos os
    bytes sao iguais (ex.: um driver quebrado devolvendo so zeros, ou um
    mock/stub esquecido em producao).

    Isto NAO e um teste de aleatoriedade. Para uma leitura de 32 bytes
    genuinamente aleatoria, a chance de todos os bytes coincidirem e
    2**-248 -- ou seja, esta checagem so pega uma falha grosseira e
    obvia. Um CSPRNG comprometido de forma sofisticada (ex.: um gerador
    deterministico disfarcado, ou um algoritmo com backdoor tipo
    Dual_EC_DRBG) passaria por esta checagem sem problema. Ver
    docs/THREAT_MODEL.md, ameaca T-RNG.
    """
    if len(data) > 1 and all(b == data[0] for b in data):
        raise OsRngError(
            f"leitura do CSPRNG tem todos os {len(data)} bytes iguais "
            f"(0x{data[0]:02x}); estatisticamente quase impossivel para um "
            "CSPRNG saudavel. Recusando continuar."
        )


def diagnostic_two_reads_differ(nbytes: int = 16) -> bool:
    """Diagnostico usado por `selftest.py`: le `nbytes` duas vezes e
    verifica que as leituras sao diferentes.

    Este e um diagnostico de sanidade sobre o CSPRNG do sistema, NAO parte
    da geracao real de B (que le exatamente uma vez, em `read_os_entropy`).
    Como a checagem acima, so detecta falha grosseira (ex.: um CSPRNG
    travado sempre devolvendo o mesmo bloco); nao demonstra que o CSPRNG e
    seguro.
    """
    first = read_os_entropy(nbytes)
    second = read_os_entropy(nbytes)
    return first != second
