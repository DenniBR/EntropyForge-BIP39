"""Montagem dos relatorios exibidos apos a bateria estatistica.

Tres niveis de detalhe, cada um com seu proprio uso:

  - `full_report` -- usado pelo modo `calibrate` (dados sempre
    descartaveis, nunca usados para gerar uma carteira): mostra tudo,
    estatisticas, p-valores, e o limite de confianca de Clopper-Pearson
    para a face mais provavel do dado. Seguro porque os dados de
    calibracao nunca alimentam `combine.combine`.

  - `public_report` -- o relatorio "reduzido" original (requisito 16 e
    docs/DESIGN.md secao 4.4): mostra as 6 contagens de face e um
    veredito PASS/WARN/FAIL por teste, nunca p-valores nem a sequencia
    original. Mantido e testado por completude e para uso programatico,
    mas o fluxo `generate` NAO o usa mais desde a Fase E (ver abaixo).

  - `minimal_report` -- o que o modo `generate` efetivamente usa desde a
    Fase E (procedimento de geracao v2, `entropyforge/version.py`): so a
    decisao binaria ACCEPTED/REJECTED, sem NENHUMA contagem de face ou
    veredito por teste. Isto reduz o vazamento de informacao sobre A
    ainda mais abaixo do orcamento ja conservador de
    `entropy_calc.report_leak_bits` -- esse orcamento continua sendo
    usado, SEM alteracao, para calcular o numero operacional de
    lancamentos (`rolls_operational`), entao o numero recomendado
    permanece uma margem de seguranca conservadora (o vazamento real
    hoje e MENOR do que o orcamentado, nunca maior).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .entropy_calc import min_entropy_bits, report_leak_bits, theoretical_entropy_bits
from .specialfunc import clopper_pearson_upper
from .stats import ALPHA_FAMILYWISE, NUM_VERDICT_TESTS, BatteryResult, Verdict


@dataclass(frozen=True)
class PublicReport:
    n: int
    face_counts: tuple[int, ...]
    verdicts: tuple[tuple[str, str], ...]  # (nome do teste, veredito)
    overall_verdict: str
    theoretical_bits: float
    leak_bits: float


def public_report(battery: BatteryResult) -> PublicReport:
    """Relatorio reduzido, seguro para exibir mesmo quando A alimenta a
    carteira gerada nesta mesma execucao."""
    return PublicReport(
        n=battery.n,
        face_counts=battery.face_counts,
        verdicts=tuple((t.name, t.verdict.value) for t in battery.tests),
        overall_verdict=battery.overall_verdict.value,
        theoretical_bits=theoretical_entropy_bits(battery.n),
        leak_bits=report_leak_bits(battery.n, NUM_VERDICT_TESTS),
    )


def format_public_report(r: PublicReport) -> str:
    lines = [
        "=== Relatorio publico de validacao estatistica (fonte A) ===",
        f"lancamentos (n)                 : {r.n}",
        f"contagens das faces (1..6)      : {list(r.face_counts)}",
        f"entropia teorica (n*log2(6))    : {r.theoretical_bits:.2f} bits "
        "[SOB A HIPOTESE de d6 honesto e i.i.d.; NAO medida, NAO garantida]",
        f"vazamento estimado deste relat. : ate {r.leak_bits:.1f} bits "
        "(ja descontado do orcamento de entropia, ver docs/MATH.md)",
        f"nivel de significancia familiar : alpha = {ALPHA_FAMILYWISE} (correcao de Holm-Bonferroni)",
        "",
        "vereditos (PASS = nao rejeitou H0; WARN = p bruto < 0.05 mas nao "
        "rejeitou apos Holm; FAIL = rejeitou H0 apos Holm):",
    ]
    for name, verdict in r.verdicts:
        lines.append(f"  {name:24s} {verdict}")
    lines.append(f"veredito geral                   : {r.overall_verdict}")
    lines.append("")
    lines.append(
        "IMPORTANTE: nenhum destes testes prova que a sequencia e aleatoria, "
        "e muito menos que e segura para uso criptografico. Eles so podem "
        "REJEITAR a hipotese de uniformidade/independencia ao detectar "
        "desvio grosseiro. 'PASS' significa apenas 'esta bateria nao "
        "encontrou evidencia de desvio' -- ver docs/MATH.md."
    )
    return "\n".join(lines)


@dataclass(frozen=True)
class FullReport:
    n: int
    face_counts: tuple[int, ...]
    tests: tuple[dict, ...]
    overall_verdict: str
    theoretical_bits: float
    clopper_pearson_alpha: float
    max_face_upper_bound: float
    max_face_observed: int
    max_face_count: int
    implied_min_entropy_per_roll: float


def full_report(battery: BatteryResult, cp_alpha: float = 0.01) -> FullReport:
    """Relatorio completo (estatisticas e p-valores), usado SOMENTE pelo
    modo `calibrate`, cujos dados sao sempre descartaveis.

    Tambem calcula o limite de confianca superior de Clopper-Pearson (nivel
    1 - cp_alpha) para a probabilidade da face mais frequente observada --
    uma estimativa estatistica do vies do dado fisico usado na calibracao,
    nunca uma prova de que o dado e (ou nao e) honesto, e nunca uma
    propriedade do dado usado depois em `generate` (mesmo que seja
    fisicamente o mesmo objeto: o dado pode se comportar de forma diferente
    entre sessoes, e a amostra de calibracao e sempre uma amostra finita).
    """
    max_idx = max(range(6), key=lambda i: battery.face_counts[i])
    max_count = battery.face_counts[max_idx]
    upper = clopper_pearson_upper(max_count, battery.n, cp_alpha)
    tests = tuple(
        {
            "name": t.name,
            "statistic": t.statistic,
            "p_value": t.p_value,
            "rejected_after_holm": t.rejected_after_holm,
            "verdict": t.verdict.value,
            "note": t.note,
        }
        for t in battery.tests
    )
    return FullReport(
        n=battery.n,
        face_counts=battery.face_counts,
        tests=tests,
        overall_verdict=battery.overall_verdict.value,
        theoretical_bits=theoretical_entropy_bits(battery.n),
        clopper_pearson_alpha=cp_alpha,
        max_face_upper_bound=upper,
        max_face_observed=max_idx + 1,
        max_face_count=max_count,
        implied_min_entropy_per_roll=-math.log2(upper),
    )


def format_full_report(r: FullReport) -> str:
    lines = [
        "=== Relatorio completo de calibracao (dados DESCARTAVEIS) ===",
        f"lancamentos (n)                 : {r.n}",
        f"contagens das faces (1..6)      : {list(r.face_counts)}",
        f"entropia teorica (n*log2(6))    : {r.theoretical_bits:.2f} bits "
        "[SOB A HIPOTESE de d6 honesto e i.i.d.]",
        "",
        "testes (estatistica, p-valor, veredito):",
    ]
    for t in r.tests:
        note = f"  ({t['note']})" if t["note"] else ""
        lines.append(
            f"  {t['name']:24s} stat={t['statistic']:.4f}  p={t['p_value']:.6g}  "
            f"{t['verdict']}{note}"
        )
    lines.append(f"veredito geral                   : {r.overall_verdict}")
    lines.append("")
    lines.append(
        f"face mais frequente observada    : {r.max_face_observed} "
        f"({r.max_face_count}/{r.n} = {r.max_face_count/r.n:.4f})"
    )
    lines.append(
        f"limite superior de Clopper-Pearson (confianca "
        f"{100*(1-r.clopper_pearson_alpha):.0f}%) para p_max real: "
        f"<= {r.max_face_upper_bound:.4f}"
    )
    lines.append(
        f"min-entropia por lancamento implicada por esse limite: "
        f">= {r.implied_min_entropy_per_roll:.4f} bits/lancamento "
        "(compare com log2(6) = 2.585 do caso honesto)"
    )
    lines.append("")
    lines.append(
        "Isto e uma ESTIMATIVA ESTATISTICA de uma amostra finita, nao uma "
        "medicao exata nem uma garantia sobre lancamentos futuros do mesmo "
        "dado. Esta sequencia de calibracao e DESCARTAVEL: nunca a use como "
        "fonte A de uma geracao real (o comando `calibrate` nunca chama "
        "combine.combine nem bip39.entropy_to_mnemonic)."
    )
    return "\n".join(lines)


@dataclass(frozen=True)
class MinimalReport:
    decision: str  # "ACCEPTED" ou "REJECTED" -- nunca outro valor


def minimal_report(battery: BatteryResult) -> MinimalReport:
    """Relatorio MINIMO usado pelo fluxo `generate` desde a Fase E
    (procedimento de geracao v2): reduz a bateria estatistica inteira a
    uma unica decisao binaria, sem revelar contagens de face nem veredito
    por teste. `WARN` (aviso informativo, nao uma rejeicao formal de H0)
    e tratado como ACCEPTED, exatamente como o fluxo `generate` ja tratava
    antes -- so um veredito geral FAIL (apos a correcao de Holm) rejeita.
    """
    decision = "REJECTED" if battery.overall_verdict == Verdict.FAIL else "ACCEPTED"
    return MinimalReport(decision=decision)


def format_minimal_report(r: MinimalReport) -> str:
    return (
        "=== Validacao estatistica da fonte A ===\n"
        f"resultado: {r.decision}\n"
        "(nenhuma contagem de face ou estatistica detalhada e exibida "
        "durante geracao real, para minimizar a informacao revelada sobre "
        "a sequencia de dados -- use `calibrate`, com dados descartaveis, "
        "para ver o relatorio estatistico completo)"
    )
