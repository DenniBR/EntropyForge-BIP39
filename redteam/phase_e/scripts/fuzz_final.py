#!/usr/bin/env python3
"""Fuzzing final (Fase E): dado (parser + normalizacao + encoding),
mnemonic/checksum BIP-39, parser do modo `vector`, e entrada de CLI via
subprocesso real.

Metodologia: gerador pseudoaleatorio da biblioteca padrao
(`random.Random`), com SEED FIXA E DOCUMENTADA abaixo -- reprodutivel,
nunca usado para nada que alimente uma carteira real. Cada alvo roda um
NUMERO FIXO de iteracoes (documentado na saida). O criterio de falha e
SEMPRE "uma excecao nao esperada, ou nenhuma excecao onde uma era
obrigatoria, ou um travamento" -- nunca "o resultado parece estranho":
funcoes que validam entrada devem SEMPRE recusar entrada invalida com o
tipo de excecao documentado, e NUNCA com outro tipo (TypeError,
AttributeError, IndexError, etc., que indicariam um bug de validacao
incompleta), nem travar (timeout).

Uso: `python3 redteam/phase_e/scripts/fuzz_final.py`
Saida: contagem de iteracoes por alvo, crashes encontrados (lista vazia se
nenhum), e um resumo final.
"""

from __future__ import annotations

import random
import string
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "independent-verifier"))

from entropyforge import bip39, combine, dice  # noqa: E402
from entropyforge.cli import build_parser, cmd_vector, TerminalIO  # noqa: E402
from entropyforge.wordlist import load_wordlist  # noqa: E402
from verifier import bip39_min  # noqa: E402

SEED = 20260927  # mesma convencao de tools/simulate_power.py: fixa, documentada
N_DICE_NORMALIZE = 20000
N_DICE_ENCODE_DECODE = 5000
N_BIP39_ROUNDTRIP = 5000
N_BIP39_CHECKSUM_TAMPER = 5000
N_VECTOR_CLI = 3000
N_CLI_SUBPROCESS = 60  # caro (spawna processo real); mantido pequeno de proposito

_PRINTABLE = string.printable
_WEIRD_CHARS = "1234567890 \t\n\r,;.-_/\\!@#$%^&*()[]{}|~`'\"" + "١٢٣٤٥٦" + "😀🎲" + "\x00\x01\x02"


def _random_string(rng: random.Random, alphabet: str, max_len: int) -> str:
    n = rng.randint(0, max_len)
    return "".join(rng.choice(alphabet) for _ in range(n))


def fuzz_dice_normalize(rng: random.Random) -> list[str]:
    crashes = []
    for i in range(N_DICE_NORMALIZE):
        s = _random_string(rng, _WEIRD_CHARS, 40)
        try:
            dice.normalize_dice_input(s)
        except dice.DiceInputError:
            pass
        except Exception as exc:  # noqa: BLE001
            crashes.append(f"[normalize #{i}] input={s!r} -> {type(exc).__name__}: {exc}")
    return crashes


def fuzz_dice_validate(rng: random.Random) -> list[str]:
    crashes = []
    for i in range(N_DICE_NORMALIZE):
        s = _random_string(rng, _WEIRD_CHARS, 200)
        try:
            dice.validate_rolls(s)
        except dice.DiceInputError:
            pass
        except Exception as exc:  # noqa: BLE001
            crashes.append(f"[validate #{i}] input={s!r} -> {type(exc).__name__}: {exc}")
    return crashes


def fuzz_dice_encode_decode_roundtrip(rng: random.Random) -> list[str]:
    crashes = []
    for i in range(N_DICE_ENCODE_DECODE):
        n = rng.randint(1, 500)
        digits = "".join(rng.choice("123456") for _ in range(n))
        try:
            encoded = dice.encode(digits)
            decoded = dice.decode(encoded)
            if decoded != digits:
                crashes.append(f"[roundtrip #{i}] n={n} digits={digits!r} decoded={decoded!r} MISMATCH")
        except Exception as exc:  # noqa: BLE001
            crashes.append(f"[roundtrip #{i}] n={n} digits={digits!r} -> {type(exc).__name__}: {exc}")
    return crashes


def fuzz_dice_decode_garbage(rng: random.Random) -> list[str]:
    crashes = []
    for i in range(N_DICE_ENCODE_DECODE):
        nbytes = rng.randint(0, 40)
        data = bytes(rng.randrange(256) for _ in range(nbytes))
        try:
            dice.decode(data)
        except dice.DiceInputError:
            pass
        except Exception as exc:  # noqa: BLE001
            crashes.append(f"[decode-garbage #{i}] data={data.hex()} -> {type(exc).__name__}: {exc}")
    return crashes


def fuzz_bip39_roundtrip(rng: random.Random) -> list[str]:
    crashes = []
    valid_lengths = (16, 20, 24, 28, 32)
    for i in range(N_BIP39_ROUNDTRIP):
        nbytes = rng.choice(valid_lengths)
        entropy = bytes(rng.randrange(256) for _ in range(nbytes))
        try:
            m = bip39.entropy_to_mnemonic(entropy)
            back = bip39.mnemonic_to_entropy(m)
            if back != entropy:
                crashes.append(f"[bip39-roundtrip #{i}] entropy={entropy.hex()} MISMATCH apos roundtrip")
            if not bip39.is_valid_mnemonic(m):
                crashes.append(f"[bip39-roundtrip #{i}] mnemonic gerado nao passou is_valid_mnemonic")
        except Exception as exc:  # noqa: BLE001
            crashes.append(f"[bip39-roundtrip #{i}] entropy={entropy.hex()} -> {type(exc).__name__}: {exc}")
    # entropias de comprimento INVALIDO devem ser rejeitadas, nunca aceitas
    for i in range(200):
        nbytes = rng.choice([0, 1, 8, 12, 15, 17, 33, 64, 100])
        entropy = bytes(rng.randrange(256) for _ in range(nbytes))
        try:
            bip39.entropy_to_mnemonic(entropy)
            crashes.append(f"[bip39-invalid-length #{i}] nbytes={nbytes} deveria ter sido rejeitado")
        except bip39.Bip39Error:
            pass
        except Exception as exc:  # noqa: BLE001
            crashes.append(f"[bip39-invalid-length #{i}] nbytes={nbytes} -> {type(exc).__name__}: {exc}")
    return crashes


def fuzz_bip39_checksum_tamper(rng: random.Random) -> list[str]:
    """Mutacoes aleatorias de um mnemonic valido (trocar uma palavra,
    remover, inserir, reordenar, duplicar) sao verificadas contra
    `bip39.mnemonic_to_entropy`.

    IMPORTANTE (nao e um bug, e matematica do proprio BIP-39): o checksum
    tem so `ENT/32` bits (4 a 8 bits para as entropias testadas aqui) --
    uma fracao pequena, mas NAO NULA, das mutacoes aleatorias vai por puro
    acaso corresponder a outro codigo valido (probabilidade `2**-checksum_bits`,
    ate ~6% para uma entropia de 128 bits). Por isso este fuzzer NUNCA trata
    "mutacao aceita" como falha por si so -- ele cruza o resultado contra
    `bip39_min` (implementacao independente do `independent-verifier/`):
    se as duas concordam (mesma decisao de aceitar/rejeitar, e a mesma
    entropia quando aceitam), a mutacao caiu num colisao de checksum
    esperada pela matematica do proprio formato, nao um bug de
    implementacao. Um problema REAL so e reportado se as duas
    implementacoes DIVERGIREM entre si."""
    crashes = []
    accidental_collisions = 0
    words_all = load_wordlist()
    for i in range(N_BIP39_CHECKSUM_TAMPER):
        nbytes = rng.choice((16, 20, 24, 28, 32))
        entropy = bytes(rng.randrange(256) for _ in range(nbytes))
        mnemonic_words = bip39.entropy_to_mnemonic(entropy).split()

        mutation = rng.choice(("swap_word", "drop_word", "add_word", "reorder", "duplicate"))
        mutated = list(mnemonic_words)
        try:
            if mutation == "swap_word":
                idx = rng.randrange(len(mutated))
                new_word = rng.choice(words_all)
                mutated[idx] = new_word
            elif mutation == "drop_word":
                if len(mutated) > 1:
                    mutated.pop(rng.randrange(len(mutated)))
            elif mutation == "add_word":
                mutated.insert(rng.randrange(len(mutated) + 1), rng.choice(words_all))
            elif mutation == "reorder":
                rng.shuffle(mutated)
            elif mutation == "duplicate":
                mutated = mutated + [rng.choice(words_all)]

            mutated_str = " ".join(mutated)
            if mutated_str == " ".join(mnemonic_words):
                continue  # mutacao degenerada (raro), pula

            ours_result = ours_error = None
            theirs_result = theirs_error = None
            try:
                ours_result = bip39.mnemonic_to_entropy(mutated_str)
            except bip39.Bip39Error as exc:
                ours_error = str(exc)
            try:
                theirs_result = bip39_min.mnemonic_to_entropy(mutated_str, words_all)
            except bip39_min.Bip39MinError as exc:
                theirs_error = str(exc)

            ours_accepted = ours_error is None
            theirs_accepted = theirs_error is None
            if ours_accepted != theirs_accepted:
                crashes.append(
                    f"[checksum-tamper #{i}] mutation={mutation} DIVERGENCIA: "
                    f"entropyforge {'aceitou' if ours_accepted else 'rejeitou'}, "
                    f"bip39_min {'aceitou' if theirs_accepted else 'rejeitou'} "
                    f"(mnemonic={mutated_str!r})"
                )
            elif ours_accepted and ours_result != theirs_result:
                crashes.append(
                    f"[checksum-tamper #{i}] mutation={mutation} ambas aceitaram mas "
                    f"DIVERGEM na entropia recuperada: entropyforge={ours_result.hex()} "
                    f"bip39_min={theirs_result.hex()}"
                )
            elif ours_accepted:
                accidental_collisions += 1  # esperado pela matematica do checksum, nao um bug
        except Exception as exc:  # noqa: BLE001
            crashes.append(f"[checksum-tamper #{i}] mutation={mutation} -> {type(exc).__name__}: {exc}")
    if accidental_collisions:
        print(
            f"    (info, nao um problema: {accidental_collisions} mutacao(oes) cairam "
            "numa colisao de checksum esperada pela matematica do BIP-39 -- ambas "
            "implementacoes concordaram; ver docstring de fuzz_bip39_checksum_tamper)"
        )
    return crashes


def fuzz_vector_cli(rng: random.Random) -> list[str]:
    """Chama cmd_vector em processo (rapido) com combinacoes aleatorias de
    argumentos -- nunca deve levantar uma excecao NAO tratada (o try/except
    de cmd_vector deve sempre converter entrada invalida num warn +
    codigo de retorno != 0)."""
    crashes = []
    captured: list[str] = []
    io = TerminalIO(
        write=lambda s: captured.append(s),
        warn=lambda s: captured.append(s),
    )
    parser = build_parser()

    def _rand_hex(max_len):
        return "".join(rng.choice("0123456789abcdefg XYZ") for _ in range(rng.randint(0, max_len)))

    def _rand_digits(max_len):
        return "".join(rng.choice("0123456789") for _ in range(rng.randint(0, max_len)))

    for i in range(N_VECTOR_CLI):
        choice = rng.randrange(4)
        argv = ["vector"]
        if choice == 0:
            argv += ["--entropy-hex", _rand_hex(80)]
        elif choice == 1:
            argv += ["--mnemonic", _random_string(rng, _WEIRD_CHARS, 300)]
        elif choice == 2:
            argv += ["--a-digits", _rand_digits(300), "--b-hex", _rand_hex(80)]
        else:
            argv += []  # nenhum argumento -- deve cair no warn final

        try:
            args = parser.parse_args(argv)
        except SystemExit:
            continue  # argparse rejeitou antes mesmo de chegar em cmd_vector; esperado
        try:
            cmd_vector(args, io)
        except Exception as exc:  # noqa: BLE001
            crashes.append(f"[vector-cli #{i}] argv={argv!r} -> {type(exc).__name__}: {exc}")
        captured.clear()
    return crashes


def fuzz_cli_subprocess(rng: random.Random) -> list[str]:
    """Uma amostra pequena (cara) de fuzzing via subprocesso REAL: envia
    bytes aleatorios pela entrada padrao de `generate`/`calibrate` com
    stdin/stdout redirecionados (nao-TTY, portanto deve recusar cedo) e
    confirma que o processo sempre termina (nunca trava) e nunca ecoa os
    bytes de entrada de volta de forma reconhecivel."""
    crashes = []
    for i in range(N_CLI_SUBPROCESS):
        cmd = rng.choice(["generate", "calibrate"])
        payload = bytes(rng.randrange(256) for _ in range(rng.randint(0, 500)))
        try:
            proc = subprocess.run(
                [sys.executable, "-B", "-m", "entropyforge", cmd],
                cwd=str(REPO_ROOT),
                input=payload,
                capture_output=True,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            crashes.append(f"[cli-subprocess #{i}] cmd={cmd} payload_len={len(payload)} TRAVOU (timeout)")
            continue
        if payload and payload in proc.stdout + proc.stderr:
            crashes.append(
                f"[cli-subprocess #{i}] cmd={cmd} payload={payload!r} ECOADO na saida"
            )
    return crashes


def main() -> int:
    rng_master = random.Random(SEED)
    targets = [
        ("dice.normalize_dice_input", N_DICE_NORMALIZE, fuzz_dice_normalize),
        ("dice.validate_rolls", N_DICE_NORMALIZE, fuzz_dice_validate),
        ("dice.encode/decode roundtrip", N_DICE_ENCODE_DECODE, fuzz_dice_encode_decode_roundtrip),
        ("dice.decode (bytes arbitrarios)", N_DICE_ENCODE_DECODE, fuzz_dice_decode_garbage),
        ("bip39 entropy<->mnemonic roundtrip", N_BIP39_ROUNDTRIP, fuzz_bip39_roundtrip),
        ("bip39 checksum tamper detection", N_BIP39_CHECKSUM_TAMPER, fuzz_bip39_checksum_tamper),
        ("cli vector (parser + cmd_vector)", N_VECTOR_CLI, fuzz_vector_cli),
        ("cli subprocess real (generate/calibrate)", N_CLI_SUBPROCESS, fuzz_cli_subprocess),
    ]

    print(f"=== Fuzzing final (Fase E) -- seed={SEED} ===\n")
    all_crashes: dict[str, list[str]] = {}
    total_iterations = 0
    t0 = time.monotonic()
    for name, n, fn in targets:
        rng = random.Random(rng_master.randrange(2**32))
        start = time.monotonic()
        crashes = fn(rng)
        elapsed = time.monotonic() - start
        total_iterations += n
        all_crashes[name] = crashes
        status = "OK" if not crashes else f"{len(crashes)} PROBLEMA(S)"
        print(f"[{status:>14s}] {name:45s} n={n:<6d} {elapsed:.2f}s")
        for c in crashes[:10]:
            print(f"    - {c}")
        if len(crashes) > 10:
            print(f"    ... e mais {len(crashes) - 10}")

    total_crashes = sum(len(c) for c in all_crashes.values())
    print(f"\n=== RESUMO: {total_iterations} iteracoes totais, "
          f"{total_crashes} problema(s) encontrado(s), {time.monotonic() - t0:.2f}s ===")
    return 0 if total_crashes == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
