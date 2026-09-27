"""Interface de linha de comando: `generate`, `calibrate`, `selftest`, `vector`.

Este modulo e deliberadamente estruturado em torno de uma abstracao de E/S
(`TerminalIO`) para que o fluxo completo de `generate` possa ser testado de
ponta a ponta SEM um terminal real (ver tests/test_cli_generate.py), o que
por sua vez e o que permite verificar automaticamente o requisito mais
importante de confidencialidade: que nenhuma saida do programa jamais
contenha A, B, E, ou a seed BIP-39 derivada, e que o mnemonic so apareca
dentro do bloco de exibicao unica.

Nenhuma funcao aqui grava em disco, rede ou clipboard (ver guard.py, que e
ativado antes de qualquer outra coisa em `main()`).
"""

from __future__ import annotations

import argparse
import getpass
import hmac
import sys
from dataclasses import dataclass, field
from typing import Callable

from . import bip39, combine, dice, entropy_calc, guard, osrng, report, selftest, stats

ALT_SCREEN_ENTER = "\x1b[?1049h"
ALT_SCREEN_LEAVE = "\x1b[?1049l"
CLEAR_SCREEN = "\x1b[2J\x1b[H"

NETWORK_OVERRIDE_PHRASE = "ENTENDO O RISCO"
DICE_FAIL_OVERRIDE_PHRASE = "CONTINUAR MESMO ASSIM"


@dataclass
class TerminalIO:
    """Abstracao de E/S do CLI. A implementacao padrao (`default_io`) usa
    o terminal real; os testes injetam uma implementacao falsa."""

    stdin_isatty: Callable[[], bool] = lambda: sys.stdin.isatty()
    stdout_isatty: Callable[[], bool] = lambda: sys.stdout.isatty()
    read_hidden_line: Callable[[str], str] = field(default=lambda prompt: getpass.getpass(prompt))
    read_line: Callable[[str], str] = field(default=lambda prompt: input(prompt))
    write: Callable[[str], None] = field(default=lambda text: print(text))
    warn: Callable[[str], None] = field(default=lambda text: print(f"[AVISO] {text}", file=sys.stderr))
    enter_alt_screen: Callable[[], None] = field(default=lambda: (sys.stdout.write(ALT_SCREEN_ENTER), sys.stdout.flush()))
    leave_alt_screen: Callable[[], None] = field(default=lambda: (sys.stdout.write(ALT_SCREEN_LEAVE), sys.stdout.flush()))
    clear_screen: Callable[[], None] = field(default=lambda: (sys.stdout.write(CLEAR_SCREEN), sys.stdout.flush()))
    wait_enter: Callable[[str], None] = field(default=lambda prompt: input(prompt))
    read_os_entropy: Callable[[], bytes] = field(default=osrng.read_os_entropy)


def default_io() -> TerminalIO:
    return TerminalIO()


def _confirm_phrase(io: TerminalIO, prompt: str, phrase: str) -> bool:
    typed = io.read_line(f"{prompt}\nDigite exatamente '{phrase}' para confirmar (qualquer outra coisa cancela): ")
    return typed.strip() == phrase


def _yes_no(io: TerminalIO, prompt: str, default_no: bool = True) -> bool:
    suffix = " [s/N]: " if default_no else " [S/n]: "
    ans = io.read_line(prompt + suffix).strip().lower()
    if not ans:
        return not default_no
    return ans in ("s", "sim", "y", "yes")


def _validate_rolls_arg(value: int | None) -> str | None:
    """Valida o argumento `--rolls` (usado por `generate` e `calibrate`).
    Devolve uma mensagem de erro se `value` for estruturalmente invalido,
    ou None se for aceitavel (incluindo `None`, que significa "nao
    informado, use o padrao").

    Corrige um bug real encontrado em auditoria adversarial (ver
    docs/REDTEAM.md): `--rolls 0` era descartado silenciosamente porque
    `args.rolls if args.rolls else default` trata 0 como falsy em Python
    (o 0 explicito do usuario virava o padrao calculado, sem aviso), e
    `--rolls` negativo fazia `_read_dice_hidden`/`_read_digits_visible`
    entrar em um laco infinito, pois nenhuma entrada real tem comprimento
    negativo (a condicao `len(raw) != target_n` nunca seria satisfeita).
    """
    if value is None:
        return None
    if value <= 0:
        return f"--rolls deve ser um inteiro positivo; recebido {value}"
    if value > dice.MAX_ROLLS:
        return (
            f"--rolls={value} excede o limite estrutural da codificacao "
            f"(prefixo uint16, maximo {dice.MAX_ROLLS})"
        )
    return None


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------


def cmd_selftest(args: argparse.Namespace, io: TerminalIO) -> int:
    result = selftest.run_selftest()
    io.write(result.format())
    return 0 if result.all_passed else 1


# ---------------------------------------------------------------------------
# vector — modo deterministico, so com dados PUBLICOS
# ---------------------------------------------------------------------------


def cmd_vector(args: argparse.Namespace, io: TerminalIO) -> int:
    io.write(
        "=== MODO DETERMINISTICO DE VERIFICACAO ===\n"
        "Todas as entradas aqui sao fornecidas explicitamente na linha de "
        "comando (dados PUBLICOS de teste). NAO USE ESTE MODO PARA GERAR "
        "OU VERIFICAR FUNDOS REAIS: os valores usados aqui devem ser "
        "tratados como comprometidos, ja que passaram pela linha de "
        "comando/historico do shell."
    )
    try:
        if args.mnemonic is not None:
            entropy = bip39.mnemonic_to_entropy(args.mnemonic)
            io.write(f"entropia (hex): {entropy.hex()}")
            return 0

        if args.entropy_hex is not None:
            entropy = bytes.fromhex(args.entropy_hex)
            mnemonic = bip39.entropy_to_mnemonic(entropy)
            io.write(f"mnemonic: {mnemonic}")
            return 0

        if args.a_digits is not None and args.b_hex is not None:
            a = dice.encode(args.a_digits)
            b = bytes.fromhex(args.b_hex)
            e = combine.combine(a, b)
            mnemonic = bip39.entropy_to_mnemonic(e)
            io.write(f"A (hex)         : {a.hex()}")
            io.write(f"B (hex)         : {b.hex()}")
            io.write(f"E = SHA256(A||B): {e.hex()}")
            io.write(f"mnemonic        : {mnemonic}")
            return 0
    except (bip39.Bip39Error, dice.DiceInputError, ValueError) as exc:
        io.warn(f"entrada invalida: {exc}")
        return 2

    io.warn(
        "especifique --mnemonic, OU --entropy-hex, OU (--a-digits E --b-hex) "
        "juntos"
    )
    return 2


# ---------------------------------------------------------------------------
# calibrate — dados sempre descartaveis
# ---------------------------------------------------------------------------


def _read_digits_visible(io: TerminalIO, target_n: int) -> str:
    """Le `target_n` digitos de forma VISIVEL (eco normal), em blocos, para
    o modo `calibrate`. Aceitavel aqui porque os dados de calibracao sao
    sempre descartados (nunca alimentam `combine`/`bip39`)."""
    collected = ""
    io.write(
        f"Digite os lancamentos (digitos 1-6, sem separadores). Meta: "
        f"{target_n} lancamentos. Pode digitar em varias linhas."
    )
    while len(collected) < target_n:
        remaining = target_n - len(collected)
        chunk = io.read_line(f"[{len(collected)}/{target_n}] proximos digitos: ").strip()
        if not chunk:
            continue
        try:
            dice.validate_rolls(chunk)
        except dice.DiceInputError as exc:
            io.warn(str(exc))
            continue
        collected += chunk[:remaining]
    return collected


def cmd_calibrate(args: argparse.Namespace, io: TerminalIO) -> int:
    rolls_error = _validate_rolls_arg(args.rolls)
    if rolls_error:
        io.warn(rolls_error)
        return 2
    target_n = args.rolls
    io.write(
        "=== calibrate: coleta de lancamentos DESCARTAVEIS para medir o dado ===\n"
        "Estes lancamentos NUNCA sao usados para gerar uma carteira. Sirva-se "
        "de quantos lancamentos quiser: mais lancamentos dao um limite de "
        "confianca mais apertado para o vies do dado (ver relatorio ao final)."
    )
    digits = _read_digits_visible(io, target_n)
    try:
        battery = stats.run_battery(digits)
    except stats.StatsError as exc:
        io.warn(str(exc))
        return 2
    full = report.full_report(battery)
    io.write(report.format_full_report(full))
    return 0


# ---------------------------------------------------------------------------
# generate — o fluxo principal
# ---------------------------------------------------------------------------


def _environment_checks(args: argparse.Namespace, io: TerminalIO) -> int | None:
    """Devolve um codigo de saida se o ambiente reprovar (fatal), ou None
    para continuar."""
    if not sys.flags.isolated:
        io.warn(
            "o interpretador nao esta em modo isolado. Recomenda-se rodar "
            "com 'python3 -I -B' (ignora PYTHONPATH/site-packages do "
            "usuario e nao grava bytecode). Continuando mesmo assim."
        )
    try:
        with open("/proc/swaps") as f:
            lines = f.read().strip().splitlines()
        if len(lines) > 1:
            io.warn(
                "ha swap ativo neste sistema. Segredos em memoria podem ser "
                "gravados em disco pelo kernel sem seu conhecimento. "
                "Prefira um sistema live sem swap (ex.: Tails)."
            )
    except OSError:
        pass  # nao-Linux, ou /proc indisponivel: nao e possivel checar

    try:
        # SEMPRE detecta com allow_override=False: a flag da linha de
        # comando nunca deve suprimir a DETECCAO, so decidir (abaixo) se
        # pedimos uma confirmacao explicita em vez de abortar direto.
        guard.check_offline(allow_override=False)
    except guard.GuardViolation as exc:
        io.warn(str(exc))
        if not args.override_offline_check:
            return 3
        if not _confirm_phrase(
            io,
            "Voce pediu para IGNORAR a verificacao de rede offline. Isto e "
            "PERIGOSO: qualquer processo com acesso a rede neste computador "
            "poderia, em principio, transmitir os dados que voce vai digitar.",
            NETWORK_OVERRIDE_PHRASE,
        ):
            io.warn("confirmacao nao recebida; abortando.")
            return 3
    return None


def _read_dice_hidden(io: TerminalIO, target_n: int) -> str:
    """Le a sequencia de `target_n` lancamentos em UMA linha oculta (sem
    eco). O usuario pode usar backspace normalmente antes de dar Enter
    (isso e apenas a edicao de linha do proprio terminal; o texto nunca e
    ecoado na tela). Repete ate receber exatamente `target_n` digitos
    validos.
    """
    while True:
        raw = io.read_hidden_line(
            f"Digite os {target_n} lancamentos do dado (1-6, sem espacos), "
            "seguido de Enter (a digitacao NAO aparece na tela): "
        )
        try:
            dice.validate_rolls(raw)
        except dice.DiceInputError as exc:
            io.warn(f"entrada invalida ({exc}); tente novamente.")
            continue
        if len(raw) != target_n:
            io.warn(
                f"esperado exatamente {target_n} lancamentos, recebido "
                f"{len(raw)}; tente novamente."
            )
            continue
        return raw


def _zero(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def cmd_generate(args: argparse.Namespace, io: TerminalIO) -> int:
    io.write(
        "=== EntropyForge-BIP39: geracao de mnemonic de 24 palavras ===\n"
        "Este programa NUNCA exibe a entropia combinada, a sequencia de "
        "dados, nem a seed BIP-39 derivada. O mnemonic e mostrado UMA "
        "UNICA VEZ, em seguida a tela e limpa."
    )

    env_result = _environment_checks(args, io)
    if env_result is not None:
        return env_result

    st = selftest.run_selftest()
    io.write(st.format())
    if not st.all_passed:
        io.warn("auto-testes falharam; recusando gerar um mnemonic.")
        return 4

    if not io.stdin_isatty() or not io.stdout_isatty():
        io.warn(
            "esta entrada/saida nao e um terminal interativo (TTY). Este "
            "comando exige um TTY real, para nunca aceitar dados sensiveis "
            "por argumento de linha de comando, pipe ou redirecionamento "
            "de arquivo (que poderiam ficar no historico do shell ou em "
            "um arquivo)."
        )
        return 5

    budget = entropy_calc.compute_budget()
    io.write(
        "\n--- Calculadora de entropia (ver docs/MATH.md para a derivacao) ---\n"
        f"lancamentos para {budget.target_bits:.0f} bits teoricos (d6 honesto, "
        f"log2(6) bits/lancamento): {budget.rolls_theoretical_honest}\n"
        f"lancamentos recomendados (margem operacional, supondo vies ate "
        f"p_max={budget.assumed_p_max:.2f} e descontando o vazamento do "
        f"relatorio publico): {budget.rolls_operational}\n"
        "Poder estatistico contra vies pequeno com poucas centenas de "
        "lancamentos e BAIXO (ver docs/MATH.md); use `calibrate` para "
        "caracterizar o proprio dado com uma amostra grande e descartavel."
    )

    rolls_error = _validate_rolls_arg(args.rolls)
    if rolls_error:
        io.warn(rolls_error)
        return 2
    target_n = args.rolls if args.rolls is not None else budget.rolls_operational
    if target_n < budget.rolls_theoretical_honest:
        io.warn(
            f"{target_n} lancamentos e MENOS que o minimo teorico "
            f"({budget.rolls_theoretical_honest}) para {budget.target_bits:.0f} "
            "bits mesmo com um d6 perfeitamente honesto. Prosseguir e "
            "fortemente desaconselhado."
        )
        if not _yes_no(io, "Prosseguir mesmo assim?", default_no=True):
            return 6

    digits = _read_dice_hidden(io, target_n)

    try:
        battery = stats.run_battery(digits)
    except stats.StatsError as exc:
        io.warn(str(exc))
        del digits
        return 7

    public = report.public_report(battery)
    io.write("\n" + report.format_public_report(public))

    if battery.overall_verdict == stats.Verdict.FAIL:
        io.warn(
            "a bateria estatistica REJEITOU a hipotese de uniformidade/"
            "independencia para esta sequencia (ver veredito acima). Isto "
            "pode indicar um dado viciado, uma tecnica de lancamento "
            "problematica, ou um erro de digitacao. O recomendado e "
            "recomecar com um dado diferente."
        )
        if not _confirm_phrase(
            io,
            "Voce pode prosseguir mesmo assim (a fonte B ainda contribui "
            "256 bits independentes), mas isso NAO e recomendado.",
            DICE_FAIL_OVERRIDE_PHRASE,
        ):
            del digits
            io.warn("confirmacao nao recebida; abortando sem gerar mnemonic.")
            return 8

    a = bytearray(dice.encode(digits))
    del digits

    try:
        b = bytearray(io.read_os_entropy())
    except osrng.OsRngError as exc:
        _zero(a)
        io.warn(
            f"nao foi possivel obter a fonte B do CSPRNG do sistema "
            f"operacional ({exc}). Falhando fechado: nenhum mnemonic sera "
            "gerado, e nenhuma fonte alternativa (menos confiavel) e "
            "usada no lugar."
        )
        return 9

    e = bytearray(combine.combine(bytes(a), bytes(b)))
    mnemonic = bip39.entropy_to_mnemonic(bytes(e))

    _zero(a)
    _zero(b)
    _zero(e)

    words = mnemonic.split()
    lines = [
        "=== SEU MNEMONIC DE 24 PALAVRAS (anote em papel/metal AGORA) ===",
        "",
    ]
    for i in range(0, 24, 4):
        group = words[i : i + 4]
        numbered = "  ".join(f"{i + j + 1:2d}. {w}" for j, w in enumerate(group))
        lines.append(numbered)
    lines.append("")
    lines.append(
        "Este mnemonic NAO sera mostrado novamente por este programa. "
        "Pressione Enter quando terminar de anotar."
    )

    io.enter_alt_screen()
    io.write("\n".join(lines))
    io.wait_enter("")
    io.clear_screen()
    io.leave_alt_screen()

    if _yes_no(io, "\nDeseja conferir a anotacao redigitando as 24 palavras?", default_no=True):
        retry = io.read_hidden_line(
            "Digite as 24 palavras separadas por espaco (NAO aparece na tela): "
        )
        normalized_input = " ".join(retry.split())
        if hmac.compare_digest(normalized_input, mnemonic):
            io.write("Conferencia OK: a anotacao confere com o mnemonic gerado.")
        else:
            io.warn(
                "Conferencia FALHOU: o texto digitado NAO confere com o "
                "mnemonic gerado. Por seguranca, as palavras divergentes "
                "nao sao mostradas. Recomenda-se conferir sua anotacao "
                "com cuidado (o mnemonic nao sera exibido de novo)."
            )
        del retry, normalized_input

    del mnemonic, words, lines
    io.write("\nConcluido. Nenhum dado foi gravado em disco, rede ou clipboard.")
    return 0


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="entropyforge",
        description=(
            "Gerador offline de entropia para mnemonics BIP-39 de 24 "
            "palavras, combinando lancamentos de d6 com o CSPRNG do "
            "sistema operacional. Ver docs/DESIGN.md, docs/MATH.md e "
            "docs/THREAT_MODEL.md."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate", help="gera um mnemonic de 24 palavras (fluxo principal)")
    p_gen.add_argument("--rolls", type=int, default=None, help="numero de lancamentos a pedir (padrao: calculado)")
    p_gen.add_argument(
        "--override-offline-check",
        action="store_true",
        help="permite prosseguir mesmo com interfaces de rede ativas (perigoso; exige confirmacao interativa)",
    )
    p_gen.set_defaults(func=cmd_generate)

    p_cal = sub.add_parser("calibrate", help="coleta lancamentos DESCARTAVEIS para medir o vies do dado")
    p_cal.add_argument("--rolls", type=int, default=3000, help="numero de lancamentos de calibracao (padrao: 3000)")
    p_cal.set_defaults(func=cmd_calibrate)

    p_self = sub.add_parser("selftest", help="roda os auto-testes (KATs) e sai")
    p_self.set_defaults(func=cmd_selftest)

    p_vec = sub.add_parser(
        "vector",
        help="modo deterministico de verificacao com dados PUBLICOS (nunca use para fundos reais)",
    )
    p_vec.add_argument("--entropy-hex", default=None, help="entropia em hex -> mnemonic")
    p_vec.add_argument("--mnemonic", default=None, help="mnemonic -> entropia (verifica checksum)")
    p_vec.add_argument("--a-digits", default=None, help="digitos de d6 (com --b-hex) -> A, B, E, mnemonic")
    p_vec.add_argument("--b-hex", default=None, help="32 bytes em hex (com --a-digits) -> A, B, E, mnemonic")
    p_vec.set_defaults(func=cmd_vector)

    return parser


def main(argv: list[str] | None = None, io: TerminalIO | None = None) -> int:
    guard.activate()
    parser = build_parser()
    args = parser.parse_args(argv)
    io = io or default_io()
    return args.func(args, io)
