"""Bateria de testes estatisticos sobre a sequencia de lancamentos de d6.

## O que estes testes fazem e o que NAO fazem

Cada teste testa uma hipotese nula H0 especifica (ex.: "as faces sao
uniformes", "os lancamentos sao independentes") e pode REJEITAR essa
hipotese quando o desvio observado e maior do que o razoavel por acaso.

NENHUM teste estatistico, e nenhuma combinacao deles, PROVA que uma
sequencia e aleatoria -- muito menos que ela e adequada para uso
criptografico. Uma sequencia inteiramente deterministica e "bem
comportada" (por exemplo, uma tabela pre-calculada, ou os digitos de uma
constante matematica em base 6) pode nao rejeitar H0 em todos os testes
abaixo, com zero bits de entropia real. "Nao rejeitar H0" so quer dizer
"esta bateria de testes nao encontrou evidencia de desvio grosseiro"; ver
docs/MATH.md para a discussao completa, incluindo o poder estatistico
(baixo) desta bateria com poucas centenas de lancamentos.

## A bateria

| Teste | O que mede | Distribuicao nula |
|-------|-----------|--------------------|
| T1 face_frequency      | vies de face                    | qui-quadrado(5), ASSINTOTICA |
| T2 serial_difference    | dependencia entre pares          | qui-quadrado(5), ASSINTOTICA |
| T3 repeats              | sequencias "sem repeticao"       | Binomial(n-1, 1/6), EXATA |
| T4 runs                 | agrupamento acima/abaixo de 3.5  | distribuicao exata de corridas, EXATA |
| T5 autocorrelation(k=1,2,3) | dependencia linear por atraso | Normal(0,1), ASSINTOTICA (Bartlett) |

"EXATA" quer dizer que a distribuicao nula usada e a distribuicao exata
(nao uma aproximacao) sob a hipotese H0 de lancamentos i.i.d. uniformes —
nao que o teste "prova" que a hipotese e verdadeira. Provas de que T3 e T4
sao exatos estao em docs/MATH.md.

## Correcao de testes multiplos

Os 6 testes com veredito proprio (T2, T3, T4, e as 3 defasagens de T5; T1
e determinado pelas contagens de faces, que ja sao exibidas por inteiro)
sao combinados com a correcao de Holm-Bonferroni, controlando a taxa de
erro familiar em ALPHA_FAMILYWISE sem exigir que os testes sejam
independentes entre si (o que nao seria verdade aqui).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum

from .specialfunc import (
    binom_two_sided_pvalue,
    chi_square_sf,
    holm_bonferroni,
    normal_two_sided_pvalue,
)

NUM_VERDICT_TESTS = 6
"""Numero de testes com veredito proprio, alem de T1 (face_frequency, que
e determinado pelas contagens de face, ja publicas por inteiro): T2, T3,
T4 e as 3 defasagens de T5. Usado por `entropy_calc.report_leak_bits` para
calcular o orcamento de vazamento do relatorio publico -- fica aqui, e nao
la, porque e a composicao da bateria (nao a formula de vazamento) que
determina esse numero."""

ALPHA_FAMILYWISE = 0.01
"""Nivel de significancia familiar para a correcao de Holm. E uma escolha
CONVENCIONAL (mais rigorosa que o 0.05 mais comum, para reduzir falsos
positivos ao custo de poder estatistico), nao um valor derivado
matematicamente do problema. Ver docs/MATH.md."""

WARN_UNCORRECTED_ALPHA = 0.05
"""Limiar informativo (nao corrigido para testes multiplos) usado so para
marcar um teste como WARN quando ele nao rejeita apos Holm mas ainda assim
tem um p-valor bruto abaixo deste limiar. E puramente informativo: NAO e
uma rejeicao formal de H0."""

# Uniforme discreta em {1,...,6}: media e variancia POPULACIONAIS exatas,
# usadas (em vez de estimadas da amostra) porque H0 especifica a
# distribuicao completamente.
_MU = 3.5
_VAR = 35.0 / 12.0  # Var(Uniforme{1..6}) = (6**2 - 1) / 12

MIN_BATTERY_ROLLS = 30
"""Minimo estrutural para rodar a bateria (T5 usa defasagem ate 3; testes
qui-quadrado precisam de graus de liberdade positivos e de uma amostra
minimamente razoavel). Isto NAO e o minimo recomendado para gerar uma
carteira -- ver entropy_calc.py."""


class Verdict(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass(frozen=True)
class TestResult:
    name: str
    statistic: float
    p_value: float
    rejected_after_holm: bool
    verdict: Verdict
    note: str = ""


@dataclass(frozen=True)
class BatteryResult:
    n: int
    face_counts: tuple[int, ...]
    tests: tuple[TestResult, ...]
    overall_verdict: Verdict

    def by_name(self, name: str) -> TestResult:
        for t in self.tests:
            if t.name == name:
                return t
        raise KeyError(name)


class StatsError(ValueError):
    pass


def _digits_to_ints(digits: str) -> list[int]:
    return [int(c) for c in digits]


def face_counts(values: list[int]) -> tuple[int, int, int, int, int, int]:
    counts = [0] * 6
    for v in values:
        counts[v - 1] += 1
    return tuple(counts)  # type: ignore[return-value]


def _chi_square_gof(observed: list[int], expected: float) -> tuple[float, float]:
    """Estatistica e p-valor (cauda superior) do teste qui-quadrado de
    aderencia, graus de liberdade = len(observed) - 1."""
    stat = sum((o - expected) ** 2 / expected for o in observed)
    df = len(observed) - 1
    return stat, chi_square_sf(stat, df)


def _test_face_frequency(values: list[int]) -> TestResult:
    """T1: as 6 faces saem com frequencia compativel com 1/6 cada?

    A distribuicao nula do qui-quadrado e uma APROXIMACAO ASSINTOTICA
    (teorema de Pearson) a distribuicao exata (multinomial), padrao para
    este tipo de teste. Nao acrescenta vazamento alem das proprias
    contagens de face, ja publicas por inteiro no relatorio (a estatistica
    e uma funcao deterministica das contagens).
    """
    n = len(values)
    counts = list(face_counts(values))
    expected = n / 6.0
    stat, p = _chi_square_gof(counts, expected)
    return TestResult("face_frequency", stat, p, False, Verdict.PASS)  # veredito setado depois


def _test_serial_difference(values: list[int]) -> TestResult:
    """T2: as diferencas consecutivas (mod 6) sao uniformes?

    FATO: se d_1..d_n sao i.i.d. Uniforme{1..6}, entao, condicional em
    d_1..d_i, o proximo lancamento d_{i+1} e um sorteio fresco uniforme
    independente do passado; logo delta_i = (d_{i+1} - d_i) mod 6 tem
    distribuicao EXATAMENTE Uniforme{0..5}, e delta_1..delta_{n-1} sao
    i.i.d (mesmo argumento aplicado repetidamente). A distribuicao nula do
    qui-quadrado sobre as contagens desses deltas e, como em T1, a
    aproximacao assintotica usual — mas a uniformidade e independencia dos
    proprios deltas sob H0 e exata, nao aproximada.
    """
    n = len(values)
    deltas = [(values[i + 1] - values[i]) % 6 for i in range(n - 1)]
    counts = [0] * 6
    for d in deltas:
        counts[d] += 1
    expected = (n - 1) / 6.0
    stat, p = _chi_square_gof(counts, expected)
    return TestResult("serial_difference", stat, p, False, Verdict.PASS)


def _test_repeats(values: list[int]) -> TestResult:
    """T3: quantas vezes um lancamento repete a face do anterior?

    FATO (prova em docs/MATH.md): sob H0, R = #{i : d_i = d_{i+1}} tem
    distribuicao EXATAMENTE Binomial(n-1, 1/6) -- nao uma aproximacao.
    Isso vale porque, para cada i, P(d_{i+1} = d_i | d_1..d_i) = 1/6
    exatamente (d_{i+1} e um sorteio fresco), o que faz dos indicadores
    de repeticao uma sequencia de Bernoulli(1/6) i.i.d., mesmo havendo
    sobreposicao de indices entre pares consecutivos.
    """
    n = len(values)
    r = sum(1 for i in range(n - 1) if values[i] == values[i + 1])
    p = binom_two_sided_pvalue(n - 1, r, 1.0 / 6.0)
    return TestResult("repeats", float(r), p, False, Verdict.PASS)


def _log_comb(n: int, k: int) -> float:
    if k < 0 or k > n:
        return float("-inf")
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def _runs_exact_pvalue(n0: int, n1: int, r_obs: int) -> float:
    """p-valor exato (bicaudal, metodo "tao improvavel quanto o observado")
    para o teste de corridas de Wald-Wolfowitz, condicional em n0 e n1
    (numero de simbolos abaixo/acima do valor de corte). Sob H0
    (sequencia trocavel, o que uma sequencia i.i.d. e), toda ordenacao dos
    n0+n1 simbolos e igualmente provavel, e a distribuicao do numero de
    corridas R e conhecida em forma fechada:

        P(R=2k)   = 2*C(n0-1,k-1)*C(n1-1,k-1) / C(n0+n1,n0)
        P(R=2k+1) = [C(n0-1,k-1)*C(n1-1,k) + C(n0-1,k)*C(n1-1,k-1)] / C(n0+n1,n0)
    """
    if n0 == 0 or n1 == 0:
        # Caso degenerado: todos os lancamentos caem do mesmo lado de 3.5.
        # O teste de corridas classico e CONDICIONAL a (n0, n1): ele testa
        # se a ORDEM dos simbolos e tipica dada a divisao observada, nao se
        # a propria divisao e tipica. Com n0=0 ou n1=0 so ha uma ordem
        # possivel (R=1), entao esse teste em particular nao tem poder
        # nenhum neste caso e devolve p=1.0 (nao informativo) em vez de
        # falhar. Uma divisao tao desigual (ex.: todos os lancamentos em
        # {1,2,3}) e detectada pelo teste de frequencia de faces (T1), que
        # olha para a divisao em si, nao para a ordem.
        return 1.0
    log_total = _log_comb(n0 + n1, n0)
    max_r = 2 * min(n0, n1) + 1
    log_pmfs: dict[int, float] = {}
    for r in range(2, max_r + 1):
        if r % 2 == 0:
            k = r // 2
            lp = math.log(2.0) + _log_comb(n0 - 1, k - 1) + _log_comb(n1 - 1, k - 1)
        else:
            k = (r - 1) // 2
            a = _log_comb(n0 - 1, k - 1) + _log_comb(n1 - 1, k)
            b = _log_comb(n0 - 1, k) + _log_comb(n1 - 1, k - 1)
            m = max(a, b)
            lp = m + math.log(math.exp(a - m) + math.exp(b - m)) if m != float("-inf") else float("-inf")
        log_pmfs[r] = lp - log_total

    log_p_obs = log_pmfs[r_obs]
    tol = 1e-9
    selected = [lp for lp in log_pmfs.values() if lp <= log_p_obs + tol]
    m = max(selected)
    total = m + math.log(sum(math.exp(v - m) for v in selected))
    return min(1.0, math.exp(total))


def _test_runs(values: list[int]) -> TestResult:
    """T4: corridas acima/abaixo do centro do dado (3.5).

    3.5 nao e um valor possivel de lancamento, entao nao ha empates a
    resolver. p-valor exato via `_runs_exact_pvalue` (nao uma aproximacao
    normal).
    """
    above = [v > 3.5 for v in values]
    n1 = sum(above)
    n0 = len(above) - n1
    runs = 1
    for i in range(1, len(above)):
        if above[i] != above[i - 1]:
            runs += 1
    p = _runs_exact_pvalue(n0, n1, runs)
    note = ""
    if n0 == 0 or n1 == 0:
        note = (
            "todos os lancamentos ficaram do mesmo lado de 3.5; este teste "
            "nao e informativo aqui (ver face_frequency)"
        )
    return TestResult("runs", float(runs), p, False, Verdict.PASS, note)


def _test_autocorrelation(values: list[int], lag: int) -> TestResult:
    """T5 (uma defasagem): correlacao serial no atraso `lag`.

    APROXIMACAO ASSINTOTICA classica (formula de Bartlett para ruido
    branco): sob H0, r_lag * sqrt(n - lag) e aproximadamente Normal(0,1)
    para n grande. Esta e uma aproximacao de amostra grande, nao uma
    distribuicao exata; seu comportamento em amostras de ~100-300
    lancamentos e caracterizado por simulacao em docs/MATH.md (nao se
    apoia so na teoria assintotica sem verificacao).
    """
    n = len(values)
    m = n - lag
    if m < 2:
        raise StatsError(f"amostra curta demais para autocorrelacao no atraso {lag}")
    s = sum((values[i] - _MU) * (values[i + lag] - _MU) for i in range(m)) / m
    r = s / _VAR
    z = r * math.sqrt(m)
    p = normal_two_sided_pvalue(z)
    return TestResult(f"autocorrelation_lag{lag}", r, p, False, Verdict.PASS)


def run_battery(digits: str, alpha: float = ALPHA_FAMILYWISE) -> BatteryResult:
    """Roda a bateria completa sobre a sequencia `digits` (string de '1'-'6').

    Levanta StatsError se a sequencia for curta demais (< MIN_BATTERY_ROLLS).
    """
    n = len(digits)
    if n < MIN_BATTERY_ROLLS:
        raise StatsError(
            f"bateria estatistica exige pelo menos {MIN_BATTERY_ROLLS} "
            f"lancamentos, recebeu {n}"
        )
    values = _digits_to_ints(digits)

    t1 = _test_face_frequency(values)
    t2 = _test_serial_difference(values)
    t3 = _test_repeats(values)
    t4 = _test_runs(values)
    t5_lags = [_test_autocorrelation(values, lag) for lag in (1, 2, 3)]

    # T1 nao entra na familia de Holm: seu p-valor e uma funcao
    # deterministica das contagens de face, que ja sao exibidas por
    # inteiro no relatorio publico (ver report.py e entropy_calc.py). As
    # outras 6 formam a familia corrigida.
    holm_family = [t2, t3, t4, *t5_lags]
    p_values = [t.p_value for t in holm_family]
    rejections = holm_bonferroni(p_values, alpha)

    finalized: list[TestResult] = []
    for t, rejected in zip(holm_family, rejections):
        if rejected:
            verdict = Verdict.FAIL
        elif t.p_value < WARN_UNCORRECTED_ALPHA:
            verdict = Verdict.WARN
        else:
            verdict = Verdict.PASS
        finalized.append(
            TestResult(t.name, t.statistic, t.p_value, rejected, verdict, t.note)
        )

    # Veredito de T1 usa o mesmo esquema, mas sem entrar na correcao de
    # Holm (ver comentario acima); usamos ALPHA_FAMILYWISE bruto pois e a
    # unica comparacao feita com essa estatistica.
    t1_verdict = (
        Verdict.FAIL
        if t1.p_value < alpha
        else (Verdict.WARN if t1.p_value < WARN_UNCORRECTED_ALPHA else Verdict.PASS)
    )
    t1_final = TestResult(t1.name, t1.statistic, t1.p_value, t1.p_value < alpha, t1_verdict)

    all_tests = (t1_final, *finalized)
    if any(t.verdict == Verdict.FAIL for t in all_tests):
        overall = Verdict.FAIL
    elif any(t.verdict == Verdict.WARN for t in all_tests):
        overall = Verdict.WARN
    else:
        overall = Verdict.PASS

    return BatteryResult(
        n=n,
        face_counts=face_counts(values),
        tests=all_tests,
        overall_verdict=overall,
    )
