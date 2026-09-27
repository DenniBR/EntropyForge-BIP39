"""Protocolo de investigacao de divergencia (Fase 15).

Sempre que duas fontes discordam -- por exemplo, `entropyforge.bip39`
(implementacao original, string-slicing) contra `verifier.bip39_min`
(implementacao independente, bit-shifting), via `bip39_compare.py` -- isso
NUNCA deve ser tratado como "falha" por si so. Duas implementacoes
discordando prova apenas que ELAS DISCORDAM; nao diz, por si so, qual (se
alguma) esta correta. Poderia ser um bug no EntropyForge, um bug no
PROPRIO independent-verifier (ver Fase 14: o verificador tambem pode ter
bugs), ou um caso legitimamente ambiguo da especificacao.

O protocolo obrigatorio, seguido por `investigate()` abaixo:

  1. REPRODUZIR -- confirmar que a divergencia e DETERMINISTICA (rodar de
     novo com a MESMA entrada produz a MESMA divergencia; uma divergencia
     que desaparece ao repetir e outra categoria de problema -- nao
     determinismo, concorrencia, estado global -- e deve ser investigada
     separadamente, nunca descartada como "flaky").
  2. CAPTURAR um artefato minimo -- a entrada exata que reproduz a
     divergencia (nunca o output/traceback inteiro sem a entrada que o
     causou; sem a entrada, ninguem mais consegue reproduzir).
  3. DETERMINAR qual implementacao esta correta comparando AMBAS contra a
     ESPECIFICACAO OFICIAL (vetores de teste BIP-39 oficiais, por
     exemplo) -- NUNCA uma implementacao contra a outra como arbitro.
     Sem uma referencia oficial, o veredito e "inconclusivo", nunca uma
     adivinhacao de qual "parece mais confiavel".
  4. DOCUMENTAR -- qual estava errada, por que, e a correcao (ou, se
     nenhuma referencia oficial existir para aquele caso, documentar isso
     tambem, explicitamente, como uma limitacao da investigacao).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class ReproductionResult:
    reproduced: bool  # True se todas as `times` execucoes deram o MESMO resultado
    outputs: tuple  # todos os outputs observados, na ordem
    stable_output: object  # outputs[0] -- so tem sentido se reproduced=True


def reproduce(fn: Callable[[], T], *, times: int = 3) -> ReproductionResult:
    """Passo 1 do protocolo: chama `fn` `times` vezes e confirma que o
    resultado e sempre o mesmo. `fn` deve ser um thunk sem efeitos
    colaterais observaveis alem do valor de retorno (ex.: uma lambda
    fechando sobre a entrada fixa que reproduz a divergencia)."""
    outputs = tuple(fn() for _ in range(times))
    reproduced = all(o == outputs[0] for o in outputs)
    return ReproductionResult(reproduced=reproduced, outputs=outputs, stable_output=outputs[0] if outputs else None)


@dataclass(frozen=True)
class DivergenceReport:
    description: str
    reproduced_a: bool
    reproduced_b: bool
    label_a: str
    label_b: str
    output_a: object
    output_b: object
    has_official_reference: bool
    official: object
    verdict: str
    # um de: "no_divergence", "<label>_is_wrong", "both_wrong",
    # "inconclusive_no_official_reference", "inconclusive_not_reproducible"

    def human_summary(self) -> str:
        if self.verdict == "no_divergence":
            return f"{self.description}: sem divergencia -- {self.label_a} e {self.label_b} concordam."
        if self.verdict == "inconclusive_not_reproducible":
            return (
                f"{self.description}: divergencia NAO reproduzivel de forma "
                f"deterministica (outputs de {self.label_a}={self.output_a!r} nao "
                "sao estaveis entre execucoes) -- investigar nao-determinismo "
                "ANTES de comparar contra a especificacao oficial."
            )
        if self.verdict == "inconclusive_no_official_reference":
            return (
                f"{self.description}: {self.label_a} e {self.label_b} DIVERGEM "
                f"({self.output_a!r} vs {self.output_b!r}), mas nao ha referencia "
                "oficial disponivel para decidir qual esta correta -- veredito "
                "INCONCLUSIVO, nao 'falha'. Nao adivinhar qual implementacao "
                "'parece mais confiavel'."
            )
        if self.verdict == "both_wrong":
            return (
                f"{self.description}: AMBAS as implementacoes divergem da "
                f"referencia oficial ({self.official!r}) -- {self.label_a} deu "
                f"{self.output_a!r}, {self.label_b} deu {self.output_b!r}. Bug "
                "em ambas, ou a referencia oficial usada esta incorreta -- "
                "investigar antes de assumir qualquer uma como correta."
            )
        wrong_label = self.verdict.removesuffix("_is_wrong")
        right_label = self.label_b if wrong_label == self.label_a else self.label_a
        wrong_output = self.output_a if wrong_label == self.label_a else self.output_b
        return (
            f"{self.description}: {wrong_label} DIVERGE da referencia oficial "
            f"({wrong_output!r} != {self.official!r}); {right_label} bate com a "
            f"referencia oficial. Veredito: bug em {wrong_label}, nao em "
            f"{right_label}."
        )


def investigate(
    *,
    description: str,
    label_a: str,
    fn_a: Callable[[], object],
    label_b: str,
    fn_b: Callable[[], object],
    official: object = None,
    has_official_reference: bool = True,
    reproduce_times: int = 3,
) -> DivergenceReport:
    """Aplica o protocolo completo (passos 1 e 3; a captura do artefato
    minimo e a documentacao, passos 2 e 4, ficam a cargo do chamador, que
    tem o contexto de qual foi a entrada usada para construir `fn_a`/`fn_b`).

    `has_official_reference=False` sinaliza explicitamente "nao existe
    especificacao oficial aplicavel a este caso" (distinto de
    `official=None` como um valor de retorno REAL, ex.: uma funcao que
    genuinamente deveria devolver `None`)."""
    repro_a = reproduce(fn_a, times=reproduce_times)
    repro_b = reproduce(fn_b, times=reproduce_times)

    if not (repro_a.reproduced and repro_b.reproduced):
        return DivergenceReport(
            description=description,
            reproduced_a=repro_a.reproduced,
            reproduced_b=repro_b.reproduced,
            label_a=label_a,
            label_b=label_b,
            output_a=repro_a.stable_output,
            output_b=repro_b.stable_output,
            has_official_reference=has_official_reference,
            official=official,
            verdict="inconclusive_not_reproducible",
        )

    out_a, out_b = repro_a.stable_output, repro_b.stable_output

    if out_a == out_b:
        verdict = "no_divergence"
    elif not has_official_reference:
        verdict = "inconclusive_no_official_reference"
    else:
        a_matches = out_a == official
        b_matches = out_b == official
        if a_matches and not b_matches:
            verdict = f"{label_b}_is_wrong"
        elif b_matches and not a_matches:
            verdict = f"{label_a}_is_wrong"
        elif not a_matches and not b_matches:
            verdict = "both_wrong"
        else:
            # a_matches and b_matches, mas out_a != out_b: so possivel se
            # `official` nao for um valor unico bem definido (ex.: uma
            # colecao onde ambos aparecem) -- tratado como inconclusivo
            # em vez de "no_divergence" (eles DIVERGEM entre si) ou
            # escolher um lado arbitrariamente.
            verdict = "inconclusive_no_official_reference"

    return DivergenceReport(
        description=description,
        reproduced_a=True,
        reproduced_b=True,
        label_a=label_a,
        label_b=label_b,
        output_a=out_a,
        output_b=out_b,
        has_official_reference=has_official_reference,
        official=official,
        verdict=verdict,
    )
