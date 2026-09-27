"""Montagem do relatorio PUBLICO exibido apos a bateria estatistica.

"Publico" aqui tem um sentido preciso (requisito 16 e docs/DESIGN.md,
secao 4.4): o conteudo deste relatorio e limitado deliberadamente para que
o vazamento de informacao sobre a sequencia de dados A fique dentro do
orcamento calculado em `entropy_calc.report_leak_bits`. Por isso:

  - o modo `generate` (que usa os dados para a carteira de verdade) chama
    `public_report`, que mostra as 6 contagens de face e um veredito
    PASS/WARN/FAIL por teste -- NUNCA p-valores, estatisticas, nem a
    sequencia original;
  - o modo `calibrate` (dados sempre descartaveis, nunca usados para gerar
    uma carteira) chama `full_report`, que mostra tudo: estatisticas,
    p-valores e o limite de confianca de Clopper-Pearson para a face mais
    provavel do dado. Isso e seguro porque os dados de calibracao nunca
    alimentam `combine.combine`.
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
