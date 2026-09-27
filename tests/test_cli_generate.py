"""Testes de ponta a ponta do fluxo `generate` via uma TerminalIO falsa
(sem TTY real). Este e o teste mais importante do projeto do ponto de
vista de confidencialidade: verifica que NENHUMA saida do programa jamais
contem A, B, E ou a sequencia de dados em qualquer formato reconhecivel, e
que o mnemonic corresponde exatamente a SHA-256(A||B) -> BIP-39.

IMPORTANTE (achado de auditoria adversarial, Fase D): a `TerminalIO` falsa
so registra o que passa pelas funcoes `write`/`warn`/etc. -- um trecho de
codigo que escrevesse diretamente em `sys.stdout`/`sys.stderr` (contornando
essa abstracao) NAO apareceria em `io_builder.blob`. Por isso `_run()`
TAMBEM captura o stdout/stderr REAIS do processo (via `redirect_stdout`/
`redirect_stderr`), e os testes de vazamento de segredo checam AMBAS as
capturas -- nao so a abstrata. Antes desta correcao, um backdoor de
laboratorio que chamava `sys.stdout.write(digest.hex())` diretamente em
`combine.py` passava por TODOS os testes desta classe sem ser detectado
(a string vazada aparecia literalmente no terminal de quem rodava os
testes, mas nenhuma asserção a via)."""

import io as _io_module
import os
import re
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from entropyforge import bip39, combine, dice, entropy_calc, stats
from entropyforge.cli import (
    DICE_FAIL_OVERRIDE_PHRASE,
    NETWORK_OVERRIDE_PHRASE,
    TerminalIO,
    _validate_rolls_arg,
    build_parser,
    cmd_generate,
)


def _real_d6(n: int) -> str:
    out = []
    while len(out) < n:
        for byte in os.getrandom(64, 0):
            if byte < 252:
                out.append(str(byte % 6 + 1))
                if len(out) == n:
                    break
    return "".join(out)


class FakeIOBuilder:
    """Monta uma TerminalIO falsa e registra tudo que foi 'escrito' na
    tela (write/warn/alt-screen) para inspecao pelo teste."""

    def __init__(self, hidden_lines, plain_lines, os_entropy: bytes):
        self.captured: list[str] = []
        self._hidden_iter = iter(hidden_lines)
        self._plain_iter = iter(plain_lines)
        self._os_entropy = os_entropy
        # capturados por `run_capturing_real_stdio` (ver abaixo), NAO pela
        # TerminalIO falsa -- fecham o buraco de um backdoor que escreve
        # diretamente em sys.stdout/sys.stderr, contornando `write`/`warn`.
        self.raw_stdout: str = ""
        self.raw_stderr: str = ""

    def _read_hidden_line(self, prompt):
        return next(self._hidden_iter, "")

    def _read_line(self, prompt):
        return next(self._plain_iter, "n")

    def build(self) -> TerminalIO:
        return TerminalIO(
            stdin_isatty=lambda: True,
            stdout_isatty=lambda: True,
            read_hidden_line=self._read_hidden_line,
            read_line=self._read_line,
            write=lambda s: self.captured.append(s),
            warn=lambda s: self.captured.append(s),
            enter_alt_screen=lambda: self.captured.append("<<<ALT_SCREEN_ENTER>>>"),
            leave_alt_screen=lambda: self.captured.append("<<<ALT_SCREEN_LEAVE>>>"),
            clear_screen=lambda: None,
            wait_enter=lambda p: None,
            read_os_entropy=lambda: self._os_entropy,
        )

    @property
    def blob(self) -> str:
        return "\n".join(self.captured)


def _extract_mnemonic_block(blob: str) -> list[str]:
    m = re.search(r"<<<ALT_SCREEN_ENTER>>>\n(.*?)\n<<<ALT_SCREEN_LEAVE>>>", blob, re.S)
    assert m, "bloco de tela alternativa nao encontrado na saida capturada"
    return re.findall(r"\d+\.\s+(\S+)", m.group(1))


def _run_capturing_real_stdio(fn, *args, **kwargs):
    """Chama `fn(*args, **kwargs)` com stdout/stderr REAIS do processo
    redirecionados para buffers, alem de qualquer captura feita por uma
    TerminalIO falsa passada dentro de `kwargs`/`args`. Ve efeitos
    colaterais que a abstracao `TerminalIO` NAO consegue ver (ex.: um
    `sys.stdout.write(...)`/`print(...)` chamado diretamente por algum
    codigo, contornando `io.write`/`io.warn`)."""
    out, err = _io_module.StringIO(), _io_module.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        result = fn(*args, **kwargs)
    return result, out.getvalue(), err.getvalue()


def _real_d6_not_rejected(n: int, max_attempts: int = 50) -> str:
    """Como `_real_d6`, mas re-sorteia se a bateria estatistica rejeitar
    a sequencia (FAIL).

    Correcao de um teste instavel (flaky) encontrado em auditoria
    adversarial (docs/REDTEAM.md): como `_real_d6` usa entropia real do
    SO, a bateria estatistica REJEITA o resultado com a taxa nominal
    (~2-3%, ver docs/simulation_results.txt) por pura chance. Os testes
    desta classe (`SuccessfulGenerateTests`) nao fornecem a confirmacao de
    override de FAIL, entao uma sequencia rejeitada faz o teste abortar
    antes de exibir o mnemonic -- uma falha esporadica e reproduzida em
    ~15-30% das execucoes da classe inteira (6 metodos, cada um com uma
    sequencia nova). Como o proprio comportamento em caso de FAIL ja tem
    testes dedicados (`StatisticalFailureOverrideTests`), esta funcao
    simplesmente re-sorteia ate obter uma sequencia que a bateria aceite,
    o que continua sendo entropia real do SO, so que condicionada a nao
    ser um dos ~2-3% de casos que a bateria rejeitaria.
    """
    for _ in range(max_attempts):
        digits = _real_d6(n)
        if stats.run_battery(digits).overall_verdict != stats.Verdict.FAIL:
            return digits
    raise AssertionError(
        f"nao obteve uma sequencia aceita pela bateria em {max_attempts} tentativas "
        "(extremamente improvavel; investigar taxa de falso positivo)"
    )


class SuccessfulGenerateTests(unittest.TestCase):
    def setUp(self):
        self.budget = entropy_calc.compute_budget()
        self.digits = _real_d6_not_rejected(self.budget.rolls_operational)
        self.b = os.getrandom(32, 0)
        self.expected_a = dice.encode(self.digits)
        self.expected_e = combine.combine(self.expected_a, self.b)
        self.expected_mnemonic = bip39.entropy_to_mnemonic(self.expected_e)

    def _run(self, verify_transcription_answer="n", retyped=None):
        plain_lines = [NETWORK_OVERRIDE_PHRASE, verify_transcription_answer]
        hidden_lines = [self.digits]
        if retyped is not None:
            hidden_lines.append(retyped)
        io_builder = FakeIOBuilder(hidden_lines, plain_lines, self.b)
        io = io_builder.build()
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc, raw_out, raw_err = _run_capturing_real_stdio(cmd_generate, args, io)
        io_builder.raw_stdout = raw_out
        io_builder.raw_stderr = raw_err
        return rc, io_builder

    def test_exit_code_zero(self):
        rc, _ = self._run()
        self.assertEqual(rc, 0)

    def test_report_is_minimal_accepted_without_face_counts_or_per_test_verdicts(self):
        # Fase E, requisito 6/procedimento de geracao v2: `generate` deve
        # mostrar SOMENTE a decisao ACCEPTED/REJECTED, nunca contagens de
        # face nem o veredito individual de cada teste da bateria (isso
        # continua disponivel apenas em `calibrate`, via `full_report`).
        rc, io_builder = self._run()
        blob = io_builder.blob
        self.assertIn("ACCEPTED", blob)
        self.assertNotIn("REJECTED", blob)
        for leaky_token in (
            "contagens das faces",
            "face_frequency",
            "serial_difference",
            "autocorrelation_lag",
        ):
            self.assertNotIn(leaky_token, blob)

    def test_mnemonic_words_match_expected_and_order(self):
        rc, io_builder = self._run()
        words = _extract_mnemonic_block(io_builder.blob)
        self.assertEqual(words, self.expected_mnemonic.split())

    def test_no_secret_hex_leaks_anywhere(self):
        rc, io_builder = self._run()
        # checa a captura da TerminalIO falsa E o stdout/stderr REAIS do
        # processo (ver docstring do modulo e `_run_capturing_real_stdio`)
        # -- um backdoor que escreva direto em sys.stdout/sys.stderr,
        # contornando `io.write`/`io.warn`, so e pego pela segunda.
        for label, blob in (
            ("TerminalIO falsa", io_builder.blob),
            ("stdout real do processo", io_builder.raw_stdout),
            ("stderr real do processo", io_builder.raw_stderr),
        ):
            self.assertNotIn(self.expected_a.hex(), blob, msg=f"vazou em {label}")
            self.assertNotIn(self.b.hex(), blob, msg=f"vazou em {label}")
            self.assertNotIn(self.expected_e.hex(), blob, msg=f"vazou em {label}")
            self.assertNotIn(self.digits, blob, msg=f"vazou em {label}")
            # tambem garante que nenhuma janela contigua de 20+ digitos 1-6
            # (parte da sequencia bruta) aparece em lugar nenhum da saida.
            self.assertIsNone(re.search(r"[1-6]{20,}", blob), msg=f"vazou em {label}")

    def test_mnemonic_full_string_appears_only_inside_alt_screen_block(self):
        # Checagem por PARES DE PALAVRAS CONSECUTIVAS do mnemonic, nao por
        # palavra isolada. Duas rodadas anteriores desta checagem por
        # palavra isolada (mesmo com limite de palavra via \b) deram falso
        # positivo (docs/REDTEAM.md): "come" como substring de "Recomenda",
        # "hip" como substring de "BIP-39", e depois "use" (palavra INTEIRA
        # em portugues E uma das 2048 palavras da wordlist) aparecendo
        # legitimamente no texto da interface ("... ou use a confirmacao
        # ..."). Com um vocabulario de 2048 palavras em ingles comum, uma
        # palavra isolada colidir com o texto normal da interface e
        # esperado, nao um vazamento. Um PAR de palavras consecutivas do
        # mnemonic (na mesma ordem) aparecer fora do bloco, por outro
        # lado, tem probabilidade desprezivel por acaso e SERIA um sinal
        # real de vazamento.
        rc, io_builder = self._run()
        blob = io_builder.blob
        before, _, after_marker = blob.partition("<<<ALT_SCREEN_ENTER>>>")
        words = self.expected_mnemonic.split()
        for w1, w2 in zip(words, words[1:]):
            self.assertNotRegex(before, rf"\b{re.escape(w1)}\s+{re.escape(w2)}\b")

    def test_transcription_confirmation_success(self):
        rc, io_builder = self._run(verify_transcription_answer="s", retyped=self.expected_mnemonic)
        self.assertEqual(rc, 0)
        self.assertTrue(any("Conferencia OK" in line for line in io_builder.captured))

    def test_transcription_confirmation_failure_does_not_reveal_diff(self):
        wrong = self.expected_mnemonic.replace(
            self.expected_mnemonic.split()[0], "zzzzzzzzzzwrongzzzzzzzzzz"
        )
        rc, io_builder = self._run(verify_transcription_answer="s", retyped=wrong)
        self.assertEqual(rc, 0)
        blob = io_builder.blob
        self.assertTrue(any("Conferencia FALHOU" in line for line in io_builder.captured))
        # a mensagem de falha nao deve conter as palavras corretas nem a
        # palavra digitada errada isoladamente identificada
        fail_lines = [l for l in io_builder.captured if "Conferencia FALHOU" in l]
        for line in fail_lines:
            for word in self.expected_mnemonic.split():
                self.assertNotRegex(line, rf"\b{re.escape(word)}\b")


class NetworkCheckRefusalTests(unittest.TestCase):
    def test_refuses_without_override_flag(self):
        with mock.patch("entropyforge.guard.list_active_network_interfaces", return_value=["eth0"]):
            io_builder = FakeIOBuilder([], [], b"\x00" * 32)
            io = io_builder.build()
            args = build_parser().parse_args(["generate"])
            rc = cmd_generate(args, io)
            self.assertNotEqual(rc, 0)
            self.assertNotIn("SEU MNEMONIC", io_builder.blob)

    def test_refuses_if_override_flag_but_wrong_confirmation(self):
        with mock.patch("entropyforge.guard.list_active_network_interfaces", return_value=["eth0"]):
            io_builder = FakeIOBuilder([], ["nao era isso"], b"\x00" * 32)
            io = io_builder.build()
            args = build_parser().parse_args(["generate", "--override-offline-check"])
            rc = cmd_generate(args, io)
            self.assertNotEqual(rc, 0)

    def test_proceeds_with_correct_confirmation(self):
        with mock.patch("entropyforge.guard.list_active_network_interfaces", return_value=["eth0"]):
            budget = entropy_calc.compute_budget()
            digits = _real_d6_not_rejected(budget.rolls_operational)
            io_builder = FakeIOBuilder([digits], [NETWORK_OVERRIDE_PHRASE, "n"], os.getrandom(32, 0))
            io = io_builder.build()
            args = build_parser().parse_args(["generate", "--override-offline-check"])
            rc = cmd_generate(args, io)
            self.assertEqual(rc, 0)


class NonTtyRefusalTests(unittest.TestCase):
    def test_refuses_when_stdin_not_a_tty(self):
        io_builder = FakeIOBuilder([], [NETWORK_OVERRIDE_PHRASE], b"\x00" * 32)
        io = io_builder.build()
        io.stdin_isatty = lambda: False
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc = cmd_generate(args, io)
        self.assertNotEqual(rc, 0)

    def test_refuses_when_stdout_not_a_tty(self):
        io_builder = FakeIOBuilder([], [NETWORK_OVERRIDE_PHRASE], b"\x00" * 32)
        io = io_builder.build()
        io.stdout_isatty = lambda: False
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc = cmd_generate(args, io)
        self.assertNotEqual(rc, 0)


class StatisticalFailureOverrideTests(unittest.TestCase):
    def test_refuses_without_override_on_pathological_sequence(self):
        budget = entropy_calc.compute_budget()
        digits = "3" * budget.rolls_operational  # constante -> FAIL garantido
        io_builder = FakeIOBuilder(
            [digits], [NETWORK_OVERRIDE_PHRASE, "nao confirmo"], os.getrandom(32, 0)
        )
        io = io_builder.build()
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc = cmd_generate(args, io)
        self.assertNotEqual(rc, 0)
        self.assertNotIn("SEU MNEMONIC", io_builder.blob)
        self.assertIn("REJECTED", io_builder.blob)

    def test_proceeds_with_explicit_override(self):
        budget = entropy_calc.compute_budget()
        digits = "3" * budget.rolls_operational
        b = os.getrandom(32, 0)
        io_builder = FakeIOBuilder(
            [digits],
            [NETWORK_OVERRIDE_PHRASE, DICE_FAIL_OVERRIDE_PHRASE, "n"],
            b,
        )
        io = io_builder.build()
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc = cmd_generate(args, io)
        self.assertEqual(rc, 0)
        self.assertIn("REJECTED", io_builder.blob)
        expected_mnemonic = bip39.entropy_to_mnemonic(combine.combine(dice.encode(digits), b))
        words = _extract_mnemonic_block(io_builder.blob)
        self.assertEqual(words, expected_mnemonic.split())


class RollsCountMismatchTests(unittest.TestCase):
    def test_retries_on_wrong_length_then_succeeds(self):
        budget = entropy_calc.compute_budget()
        good_digits = _real_d6_not_rejected(budget.rolls_operational)
        too_short = good_digits[:10]
        b = os.getrandom(32, 0)
        io_builder = FakeIOBuilder(
            [too_short, good_digits], [NETWORK_OVERRIDE_PHRASE, "n"], b
        )
        io = io_builder.build()
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc = cmd_generate(args, io)
        self.assertEqual(rc, 0)


class RollsArgumentValidationTests(unittest.TestCase):
    """Regressao para um bug real encontrado em auditoria adversarial
    (docs/REDTEAM.md): `--rolls 0` era silenciosamente ignorado (0 e
    falsy em Python) e `--rolls` negativo travava `generate` em um laco
    infinito dentro de `_read_dice_hidden` (nenhuma entrada real jamais
    satisfaria `len(raw) == target_n` para um `target_n` negativo)."""

    def test_validator_rejects_zero(self):
        self.assertIsNotNone(_validate_rolls_arg(0))

    def test_validator_rejects_negative(self):
        self.assertIsNotNone(_validate_rolls_arg(-5))

    def test_validator_rejects_above_structural_limit(self):
        self.assertIsNotNone(_validate_rolls_arg(dice.MAX_ROLLS + 1))


class FlexibleDiceInputNormalizationTests(unittest.TestCase):
    """Fase E, requisito 6: `normalize_dice_input` aceita compacto e
    separado por espacos, mas rejeita qualquer ambiguidade em vez de
    adivinhar a intencao do operador."""

    def test_compact_input_passes_through_unchanged(self):
        self.assertEqual(dice.normalize_dice_input("416235"), "416235")

    def test_space_separated_input_is_joined(self):
        self.assertEqual(dice.normalize_dice_input("4 1 6 2 3 5"), "416235")

    def test_space_separated_input_tolerates_extra_whitespace_and_newlines(self):
        self.assertEqual(dice.normalize_dice_input("  4   1\n6\t2 3 5  "), "416235")

    def test_mixed_format_is_rejected_as_ambiguous(self):
        with self.assertRaises(dice.DiceInputError):
            dice.normalize_dice_input("41 6235")

    def test_multi_digit_token_is_rejected_as_ambiguous(self):
        with self.assertRaises(dice.DiceInputError):
            dice.normalize_dice_input("41 62 35")

    def test_comma_separated_input_is_never_silently_accepted(self):
        # "4,1,6,2,3,5" nao contem espacos, entao `normalize_dice_input`
        # (que so decide entre os formatos COMPACTO/SEPARADO-POR-ESPACO
        # olhando para a presenca de whitespace) a repassa inalterada; a
        # rejeicao final acontece em `validate_rolls` (a virgula nao esta
        # em ALPHABET). O importante, testado aqui, e que a cadeia
        # normalize+validate usada pelo CLI nunca aceita silenciosamente
        # um separador que nao seja espaco em branco.
        normalized = dice.normalize_dice_input("4,1,6,2,3,5")
        with self.assertRaises(dice.DiceInputError):
            dice.validate_rolls(normalized)

    def test_empty_input_is_rejected(self):
        with self.assertRaises(dice.DiceInputError):
            dice.normalize_dice_input("")
        with self.assertRaises(dice.DiceInputError):
            dice.normalize_dice_input("   ")

    def test_error_messages_never_echo_received_characters(self):
        # so o comprimento do token invalido pode aparecer na mensagem,
        # nunca os proprios caracteres recebidos (mesma politica de
        # `validate_rolls`).
        secret_like_token = "letmein"
        try:
            dice.normalize_dice_input(f"4 1 {secret_like_token} 2")
        except dice.DiceInputError as exc:
            self.assertNotIn(secret_like_token, str(exc))
        else:
            self.fail("esperava DiceInputError")

    def test_does_not_validate_face_range_itself(self):
        # normalize_dice_input so lida com FORMATO; a validacao de que os
        # digitos estao em 1..6 continua sendo responsabilidade exclusiva
        # de validate_rolls, chamada depois.
        self.assertEqual(dice.normalize_dice_input("7 8 9"), "789")
        with self.assertRaises(dice.DiceInputError):
            dice.validate_rolls(dice.normalize_dice_input("7 8 9"))


class FlexibleDiceInputCliEndToEndTests(unittest.TestCase):
    """Confirma que o formato separado por espacos tambem funciona de
    ponta a ponta atraves do CLI `generate` (nao so na funcao pura)."""

    def test_generate_accepts_space_separated_dice_sequence(self):
        budget = entropy_calc.compute_budget()
        digits = _real_d6_not_rejected(budget.rolls_operational)
        spaced = " ".join(digits)
        b = os.getrandom(32, 0)
        io_builder = FakeIOBuilder([spaced], [NETWORK_OVERRIDE_PHRASE, "n"], b)
        io = io_builder.build()
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc = cmd_generate(args, io)
        self.assertEqual(rc, 0)
        expected_mnemonic = bip39.entropy_to_mnemonic(combine.combine(dice.encode(digits), b))
        words = _extract_mnemonic_block(io_builder.blob)
        self.assertEqual(words, expected_mnemonic.split())

    def test_generate_rejects_ambiguous_mixed_format_and_retries(self):
        budget = entropy_calc.compute_budget()
        digits = _real_d6_not_rejected(budget.rolls_operational)
        ambiguous = digits[:2] + " " + digits[2:]  # mistura compacto + espaco
        b = os.getrandom(32, 0)
        io_builder = FakeIOBuilder(
            [ambiguous, digits], [NETWORK_OVERRIDE_PHRASE, "n"], b
        )
        io = io_builder.build()
        args = build_parser().parse_args(["generate", "--override-offline-check"])
        rc = cmd_generate(args, io)
        self.assertEqual(rc, 0)
        expected_mnemonic = bip39.entropy_to_mnemonic(combine.combine(dice.encode(digits), b))
        words = _extract_mnemonic_block(io_builder.blob)
        self.assertEqual(words, expected_mnemonic.split())

    def test_validator_accepts_none_and_sane_values(self):
        self.assertIsNone(_validate_rolls_arg(None))
        self.assertIsNone(_validate_rolls_arg(1))
        self.assertIsNone(_validate_rolls_arg(dice.MAX_ROLLS))

    def _run_generate_with_rolls(self, rolls_value: int) -> tuple[int, list[str]]:
        io_builder = FakeIOBuilder([], [NETWORK_OVERRIDE_PHRASE], os.getrandom(32, 0))
        io = io_builder.build()
        args = build_parser().parse_args(
            ["generate", "--override-offline-check", "--rolls", str(rolls_value)]
        )
        rc = cmd_generate(args, io)
        return rc, io_builder.captured

    def test_generate_rejects_zero_rolls_without_hanging(self):
        # Antes da correcao, --rolls 0 era substituido silenciosamente
        # pelo valor padrao calculado; agora deve ser um erro explicito.
        rc, captured = self._run_generate_with_rolls(0)
        self.assertNotEqual(rc, 0)
        self.assertTrue(any("positivo" in line for line in captured))

    def test_generate_rejects_negative_rolls_without_hanging(self):
        # Antes da correcao, isto entrava em loop infinito em
        # _read_dice_hidden (regressao verificada por este teste ter um
        # tempo de execucao normal, nao travar a suite inteira).
        rc, captured = self._run_generate_with_rolls(-5)
        self.assertNotEqual(rc, 0)
        self.assertTrue(any("positivo" in line for line in captured))


if __name__ == "__main__":
    unittest.main()
