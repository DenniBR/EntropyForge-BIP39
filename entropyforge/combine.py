"""Combinacao das duas fontes independentes: E = SHA-256(A || B).

Requisito 8, implementado literalmente. O argumento de seguranca completo
(o que esta formula garante e o que NAO garante) esta em docs/DESIGN.md
(decisao D4) e docs/MATH.md. Resumo:

    SHA-256 NAO "gera" entropia. E uma funcao determinística e publica: a
    MESMA entrada sempre produz a MESMA saida de 256 bits. A
    imprevisibilidade de E vem inteiramente da imprevisibilidade das
    entradas A e B -- SHA-256 aqui atua como um misturador/compressor, nao
    como uma fonte de aleatoriedade.

    Sob a hipotese heuristica do "modelo do oraculo aleatorio" (tratar
    SHA-256 como se fosse uma funcao publica escolhida ao acaso), e se
    A e B forem independentes e pelo menos uma delas for desconhecida do
    adversario com min-entropia H_infinity, entao E e computacionalmente
    indistinguivel de uniforme para um adversario limitado a q consultas,
    com vantagem <= q * 2**-H_infinity. Isto NAO e uma prova sobre o
    SHA-256 real (nenhuma funcao de hash tem essa prova no modelo padrao);
    e uma suposicao amplamente usada, mas ainda assim uma suposicao.

    Esta combinacao NAO protege contra um adversario que conhece A e
    controla B (ou vice-versa) -- por exemplo, um sistema operacional
    comprometido que ve as teclas digitadas e fornece a fonte B. Nesse
    cenario E fica inteiramente determinado pelo adversario. A combinacao
    protege contra a FALHA de uma das duas fontes, nao contra o
    comprometimento do ambiente onde as duas se encontram.
"""

from __future__ import annotations

import hashlib

ENTROPY_BYTES = 32  # 256 bits: exatamente o que entropy_to_mnemonic exige


def combine(a: bytes, b: bytes) -> bytes:
    """E = SHA-256(A || B), como bytes de comprimento exatamente 32.

    `a`: saida de `dice.encode` (autodelimitada por seu proprio prefixo de
         comprimento; pode ter qualquer tamanho >= 3 bytes).
    `b`: saida de `osrng.read_os_entropy`; deve ter exatamente 32 bytes.

    Como `b` tem comprimento FIXO (32 bytes) e `a` e autodelimitada (carrega
    o numero de lancamentos `n` no seu prefixo, do qual seu proprio
    comprimento em bytes e uma funcao determinística), a concatenacao
    `a || b` e decodificavel de forma unica: nao ha ambiguidade sobre onde
    `a` termina e `b` comeca.
    """
    if len(b) != ENTROPY_BYTES:
        raise ValueError(
            f"B deve ter exatamente {ENTROPY_BYTES} bytes (256 bits), "
            f"recebeu {len(b)} bytes"
        )
    if len(a) == 0:
        raise ValueError("A nao pode ser vazio")
    digest = hashlib.sha256(a + b).digest()
    assert len(digest) == ENTROPY_BYTES  # invariante de SHA-256
    return digest
