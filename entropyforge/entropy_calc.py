"""Calculadora de entropia para a fonte A (d6 fisico).

Este modulo NAO decide "o" numero magico de lancamentos: ele separa,
explicitamente, tres perguntas diferentes que o requisito do projeto pede
para nao confundir:

    1. Quantos lancamentos sao necessarios para atingir X bits de entropia
       TEORICA, supondo um d6 perfeitamente honesto e lancamentos
       independentes?              -> rolls_for_shannon_bits (fato matematico
                                        CONDICIONAL a essa hipotese)

    2. Quantos lancamentos sao necessarios para uma MARGEM DE SEGURANCA
       operacional, supondo que o d6 pode ter um vies moderado?
                                    -> rolls_for_operational_target (depende
                                        de uma escolha de engenharia, p_max,
                                        que e uma OPINIAO/recomendacao, nao
                                        um fato matematico)

    3. Quantos lancamentos sao necessarios para que os testes estatisticos
       de stats.py tenham poder razoavel de detectar um vies pequeno?
                                    -> NAO respondida por uma formula fechada
                                        aqui. Ver docs/MATH.md secao de poder
                                        estatistico: com dezenas a poucas
                                        centenas de lancamentos (o que e
                                        pratico para uma pessoa digitar), o
                                        poder contra vies pequeno e BAIXO.
                                        Poder razoavel exige milhares de
                                        lancamentos, o que so o modo
                                        `calibrate` (dados descartaveis)
                                        pratica.

Cada funcao abaixo documenta explicitamente sob qual hipotese ela vale.
Nenhuma delas "prova" nada sobre um d6 fisico real.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

LOG2_6 = math.log2(6)  # bits de Shannon de UM lancamento de d6 uniforme e honesto


def theoretical_entropy_bits(n: int) -> float:
    """H(A) = n * log2(6) bits.

    Fato matematico CONDICIONAL: vale se, e somente se, os `n` lancamentos
    forem independentes e cada um deles uniforme sobre {1..6}. O software
    nao pode verificar essa hipotese sobre o dado fisico (ver
    docs/THREAT_MODEL.md); ela e sobre o dado, a tecnica de lancamento e a
    honestidade de quem lanca.
    """
    if n < 0:
        raise ValueError("n deve ser >= 0")
    return n * LOG2_6


def rolls_for_shannon_bits(target_bits: float) -> int:
    """Menor n tal que theoretical_entropy_bits(n) >= target_bits.

    Mesma hipotese de `theoretical_entropy_bits`: d6 honesto e i.i.d.
    Para target_bits=256, o resultado e 100.
    """
    if target_bits <= 0:
        raise ValueError("target_bits deve ser > 0")
    return math.ceil(target_bits / LOG2_6)


def min_entropy_bits(n: int, p_max: float) -> float:
    """H_infinity(A) = -n * log2(p_max).

    Modelo de vies: a face mais provavel do d6 sai com probabilidade
    `p_max` (as demais faces dividem o resto, em qualquer proporcao — o
    pior caso para a min-entropia so depende de p_max). `p_max = 1/6`
    reproduz o caso honesto (H_infinity = H de Shannon, pois a distribuicao
    uniforme maximiza a entropia). Min-entropia, nao entropia de Shannon,
    e o que limita a vantagem de um adversario que tenta adivinhar a
    sequencia inteira em uma unica tentativa — e por isso e o parametro
    relevante para o argumento de seguranca em D4 (docs/DESIGN.md).
    """
    if not (1 / 6 <= p_max < 1):
        raise ValueError("p_max deve estar em [1/6, 1)")
    if n < 0:
        raise ValueError("n deve ser >= 0")
    return -n * math.log2(p_max)


def rolls_for_min_entropy(target_bits: float, p_max: float) -> int:
    """Menor n tal que min_entropy_bits(n, p_max) >= target_bits."""
    if target_bits <= 0:
        raise ValueError("target_bits deve ser > 0")
    if not (1 / 6 <= p_max < 1):
        raise ValueError("p_max deve estar em [1/6, 1)")
    return math.ceil(target_bits / (-math.log2(p_max)))


def report_leak_bits(n: int, num_verdict_tests: int) -> float:
    """Limite superior para o vazamento de informacao (em bits) causado por
    exibir o relatorio publico de `n` lancamentos (ver report.py e
    docs/MATH.md).

    O relatorio mostra: as 6 contagens de faces (que determinam o veredito
    do teste de frequencia) e um veredito PASS/WARN/FAIL para cada um dos
    outros `num_verdict_tests` testes da bateria (stats.NUM_VERDICT_TESTS).
    Pela regra da cadeia para min-entropia (Dodis-Ostrovsky-Reyzin-Smith
    2004), revelar uma funcao de A que assume no maximo |R| valores
    possiveis custa no maximo log2(|R|) bits de min-entropia. Aqui:

        |R_contagens| = C(n+5, 5)             (composicoes de n em 6 partes >= 0)
        |R_vereditos| = 3**num_verdict_tests  (cada teste, 3 veredictos)

    Este e um LIMITE SUPERIOR conservador (trata os vereditos como
    independentes das contagens, o que so pode superestimar o vazamento).
    `num_verdict_tests` e passado explicitamente (em vez de fixado aqui)
    para que este modulo nao precise conhecer a composicao da bateria de
    testes -- essa e uma responsabilidade de stats.py.
    """
    if n < 0:
        raise ValueError("n deve ser >= 0")
    if num_verdict_tests < 0:
        raise ValueError("num_verdict_tests deve ser >= 0")
    if n == 0:
        return 0.0
    faces_leak = math.log2(math.comb(n + 5, 5))
    verdict_leak = num_verdict_tests * math.log2(3)
    return faces_leak + verdict_leak


def rolls_for_operational_target(target_bits: float, p_max: float, num_verdict_tests: int) -> int:
    """Menor n tal que, MESMO DEPOIS de descontar o vazamento do relatorio
    publico, a min-entropia residual de A ainda atinja `target_bits`:

        min_entropy_bits(n, p_max) - report_leak_bits(n, num_verdict_tests) >= target_bits

    Isto responde a pergunta (2) do modulo: quantos lancamentos pedir na
    pratica, supondo um dado com vies ate `p_max` E que o usuario vai ver o
    relatorio de validacao estatistica. `p_max` e um parametro de
    engenharia (uma escolha de margem de seguranca), nao um fato medido —
    quem quiser um numero medido do PROPRIO dado deve rodar `calibrate`.
    """
    n = rolls_for_min_entropy(target_bits, p_max)
    while min_entropy_bits(n, p_max) - report_leak_bits(n, num_verdict_tests) < target_bits:
        n += 1
    return n


@dataclass(frozen=True)
class EntropyBudget:
    """Resumo, para exibicao, das tres perguntas separadas acima — todos os
    campos sao calculados a partir de `target_bits` e `assumed_p_max`, nunca
    hardcoded."""

    target_bits: float
    assumed_p_max: float
    rolls_theoretical_honest: int  # pergunta (1): p_max = 1/6, sem descontar vazamento
    rolls_operational: int  # pergunta (2): assumed_p_max, com vazamento descontado

    @property
    def theoretical_bits_at_operational_n(self) -> float:
        return theoretical_entropy_bits(self.rolls_operational)

    @property
    def min_entropy_bits_at_operational_n(self) -> float:
        return min_entropy_bits(self.rolls_operational, self.assumed_p_max)

    num_verdict_tests: int = 6

    @property
    def leak_bits_at_operational_n(self) -> float:
        return report_leak_bits(self.rolls_operational, self.num_verdict_tests)


def compute_budget(
    target_bits: float = 256.0,
    assumed_p_max: float = 0.20,
    num_verdict_tests: int | None = None,
) -> EntropyBudget:
    """Constroi o resumo acima. `assumed_p_max=0.20` e a margem de seguranca
    padrao deste projeto: uma OPINIAO de engenharia (nao uma medida), que
    supoe um d6 em que a face mais provavel sai ate 20% das vezes (contra
    16,67% de um dado perfeito) — uma forma de tolerar vies moderado sem
    exigir que o usuario calibre o proprio dado antes de cada uso. Um dado
    calibrado (subcomando `calibrate`) pode justificar um valor menor (mais
    proximo de 1/6) ou exigir um valor maior, dependendo do que a
    calibracao efetivamente medir.

    `num_verdict_tests` e importado de `stats.NUM_VERDICT_TESTS` por
    padrao (import feito dentro da funcao para evitar qualquer risco de
    import circular, ja que `stats.py` nao precisa deste modulo em tempo
    de import).
    """
    if num_verdict_tests is None:
        from .stats import NUM_VERDICT_TESTS

        num_verdict_tests = NUM_VERDICT_TESTS
    return EntropyBudget(
        target_bits=target_bits,
        assumed_p_max=assumed_p_max,
        rolls_theoretical_honest=rolls_for_shannon_bits(target_bits),
        rolls_operational=rolls_for_operational_target(target_bits, assumed_p_max, num_verdict_tests),
        num_verdict_tests=num_verdict_tests,
    )
