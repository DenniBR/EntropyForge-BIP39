"""Funcoes matematicas especiais, implementadas apenas com a biblioteca padrao.

Este modulo existe para que os testes estatisticos em `stats.py` nao dependam
de bibliotecas de terceiros (numpy/scipy). Todas as funcoes sao puras
(sem estado, sem I/O) e sao verificadas em `tests/test_specialfunc.py` contra
valores tabelados na literatura (ex.: tabelas de qui-quadrado de livros-texto).

Nenhuma funcao aqui toca segredos: elas operam sobre estatisticas agregadas
(contagens, somas) que ja sao consideradas publicas pelo resto do sistema.
"""

from __future__ import annotations

import math

__all__ = [
    "chi_square_sf",
    "normal_two_sided_pvalue",
    "log_binom_pmf",
    "binom_cdf",
    "binom_sf",
    "binom_two_sided_pvalue",
    "clopper_pearson_upper",
    "holm_bonferroni",
]


# ---------------------------------------------------------------------------
# Funcao gama incompleta regularizada (para a distribuicao qui-quadrado)
# ---------------------------------------------------------------------------
#
# P(a, x) = gamma_lower(a, x) / Gamma(a)   (regularizada, inferior)
# Q(a, x) = 1 - P(a, x)                    (regularizada, superior)
#
# A sobrevivencia (p-valor de cauda superior) de uma variavel qui-quadrado
# com `df` graus de liberdade em x e exatamente Q(df/2, x/2). Implementacao
# classica: serie de potencias para x < a+1, fracao continua (Lentz) para
# x >= a+1. Ver Numerical Recipes, 3a ed., secao 6.2.
#
# _MAXIT/_EPS controlam a convergencia; sao folgados o suficiente para os
# tamanhos de amostra deste projeto (dezenas a poucas centenas de milhares).

_MAXIT = 500
_EPS = 1e-15
_TINY = 1e-300


def _gammainc_lower_reg_series(a: float, x: float) -> float:
    """P(a, x) via serie de potencias. Requer x < a + 1."""
    if x <= 0.0:
        return 0.0
    gln = math.lgamma(a)
    ap = a
    total = 1.0 / a
    delta = total
    for _ in range(_MAXIT):
        ap += 1.0
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * _EPS:
            break
    else:  # pragma: no cover - convergencia garantida no regime usado
        raise ArithmeticError("serie da gama incompleta nao convergiu")
    return total * math.exp(-x + a * math.log(x) - gln)


def _gammainc_upper_reg_cf(a: float, x: float) -> float:
    """Q(a, x) via fracao continua de Lentz. Requer x >= a + 1."""
    gln = math.lgamma(a)
    b = x + 1.0 - a
    c = 1.0 / _TINY
    d = 1.0 / b
    h = d
    for i in range(1, _MAXIT + 1):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < _TINY:
            d = _TINY
        c = b + an / c
        if abs(c) < _TINY:
            c = _TINY
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPS:
            break
    else:  # pragma: no cover
        raise ArithmeticError("fracao continua da gama incompleta nao convergiu")
    return math.exp(-x + a * math.log(x) - gln) * h


def _gammainc_upper_reg(a: float, x: float) -> float:
    """Q(a, x), a funcao gama incompleta regularizada superior."""
    if x < 0.0 or a <= 0.0:
        raise ValueError("gammainc_upper_reg requer a > 0 e x >= 0")
    if x == 0.0:
        return 1.0
    if x < a + 1.0:
        return 1.0 - _gammainc_lower_reg_series(a, x)
    return _gammainc_upper_reg_cf(a, x)


def chi_square_sf(x: float, df: int) -> float:
    """P(X >= x) para X ~ qui-quadrado(df). x deve ser >= 0, df >= 1.

    Esta e a "cauda superior": um p-valor pequeno indica que a estatistica
    observada e maior do que se espera sob H0 (mais desvio do que o
    esperado por acaso).
    """
    if df < 1:
        raise ValueError("df deve ser >= 1")
    if x < 0:
        raise ValueError("x deve ser >= 0")
    if x == 0.0:
        return 1.0
    return _gammainc_upper_reg(df / 2.0, x / 2.0)


def normal_two_sided_pvalue(z: float) -> float:
    """p-valor bicaudal para uma estatistica z ~ Normal(0, 1) sob H0.

    p = 2 * P(Z >= |z|) = erfc(|z| / sqrt(2)).
    `math.erfc` e uma funcao da biblioteca padrao (nao reimplementada aqui).
    """
    return math.erfc(abs(z) / math.sqrt(2.0))


# ---------------------------------------------------------------------------
# Distribuicao binomial exata (em espaco logaritmico, para estabilidade com
# n grande no modo `calibrate`, que pode usar dezenas de milhares de
# lancamentos descartaveis).
# ---------------------------------------------------------------------------


def log_binom_pmf(n: int, k: int, p: float) -> float:
    """log( C(n,k) * p**k * (1-p)**(n-k) ). p em (0, 1); k em [0, n]."""
    if not (0 <= k <= n):
        raise ValueError("k deve estar em [0, n]")
    if not (0.0 < p < 1.0):
        raise ValueError("p deve estar em (0, 1)")
    log_comb = math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
    return log_comb + k * math.log(p) + (n - k) * math.log1p(-p)


def _logsumexp(logs: list[float]) -> float:
    if not logs:
        return float("-inf")
    m = max(logs)
    if m == float("-inf"):
        return float("-inf")
    return m + math.log(sum(math.exp(v - m) for v in logs))


def binom_cdf(n: int, k: int, p: float) -> float:
    """P(X <= k) para X ~ Binomial(n, p), calculado em espaco log."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    logs = [log_binom_pmf(n, i, p) for i in range(0, k + 1)]
    return min(1.0, math.exp(_logsumexp(logs)))


def binom_sf(n: int, k: int, p: float) -> float:
    """P(X >= k) para X ~ Binomial(n, p)."""
    if k <= 0:
        return 1.0
    if k > n:
        return 0.0
    return max(0.0, 1.0 - binom_cdf(n, k - 1, p))


def binom_two_sided_pvalue(n: int, k: int, p: float) -> float:
    """p-valor exato bicaudal (metodo da soma de probabilidades <= pmf(k)).

    Este e o mesmo criterio usado por `binom.test` do R e por
    `scipy.stats.binomtest`: soma-se a probabilidade de todos os resultados
    tao improvaveis quanto (ou menos provaveis que) o observado.
    """
    if not (0 <= k <= n):
        raise ValueError("k deve estar em [0, n]")
    log_pmfs = [log_binom_pmf(n, i, p) for i in range(0, n + 1)]
    log_pk = log_pmfs[k]
    # tolerancia relativa para "igualmente provavel", evita excluir pmf(k)
    # por erro de arredondamento de ponto flutuante.
    tol = 1e-9
    selected = [lp for lp in log_pmfs if lp <= log_pk + tol]
    return min(1.0, math.exp(_logsumexp(selected)))


def clopper_pearson_upper(k: int, n: int, alpha: float) -> float:
    """Limite de confianca superior (1 - alpha), unilateral, de Clopper-Pearson.

    Retorna o maior p_U tal que P(X <= k; n, p_U) = alpha, isto e, o
    limite superior classico "exato" para uma proporcao binomial, obtido
    aqui por busca binaria sobre `binom_cdf` (equivalente ao quantil da
    distribuicao Beta(k+1, n-k), mas sem depender da funcao beta incompleta
    inversa).

    Uso neste projeto: dado o numero de vezes que a face mais frequente de
    um d6 saiu em `n` lancamentos de calibracao, da um limite superior de
    confianca para a probabilidade real dessa face — uma estimativa
    estatistica do dado fisico, nunca uma prova de que o dado e honesto.
    """
    if not (0.0 < alpha < 1.0):
        raise ValueError("alpha deve estar em (0, 1)")
    if k >= n:
        return 1.0
    if k < 0:
        raise ValueError("k deve ser >= 0")

    def cdf_at(p: float) -> float:
        if p <= 0.0:
            return 1.0
        if p >= 1.0:
            return 0.0 if k < n else 1.0
        return binom_cdf(n, k, p)

    lo, hi = k / n, 1.0
    # CDF(k; n, p) e estritamente decrescente em p (para 0 < p < 1), entao
    # ha exatamente uma raiz de cdf_at(p) - alpha = 0 em (k/n, 1].
    if cdf_at(lo) <= alpha:
        return lo
    for _ in range(100):
        mid = (lo + hi) / 2.0
        if cdf_at(mid) > alpha:
            lo = mid
        else:
            hi = mid
    return hi


def holm_bonferroni(p_values: list[float], alpha: float) -> list[bool]:
    """Correcao de Holm-Bonferroni para testes multiplos.

    Recebe uma lista de p-valores (uma hipotese por teste) e devolve uma
    lista de booleanos na MESMA ORDEM de entrada: True = rejeita H0 para
    aquele teste, ao nivel de significancia familiar `alpha`.

    O metodo de Holm controla a taxa de erro familiar (FWER) sem exigir
    independencia entre os testes, o que e importante aqui porque os
    testes da bateria (frequencia, diferencas seriais, repeticoes, runs,
    autocorrelacao) nao sao independentes entre si.
    """
    if not (0.0 < alpha < 1.0):
        raise ValueError("alpha deve estar em (0, 1)")
    m = len(p_values)
    order = sorted(range(m), key=lambda i: p_values[i])
    reject = [False] * m
    for rank, idx in enumerate(order):
        threshold = alpha / (m - rank)
        if p_values[idx] <= threshold:
            reject[idx] = True
        else:
            # Holm para: uma vez que um p-valor (em ordem crescente) falha
            # em ultrapassar seu limiar, todos os seguintes tambem falham.
            break
    return reject
