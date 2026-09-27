"""Testes de entropyforge.dice: bijecao da codificacao (D2), validacao de
entrada, e casos negativos explicitos (vazio, curto, '0', '7', enorme)."""

import itertools
import unittest

from entropyforge.dice import MAX_ROLLS, DiceInputError, decode, encode, validate_rolls


class ValidateRollsTests(unittest.TestCase):
    def test_accepts_valid(self):
        validate_rolls("123456")  # nao deve levantar

    def test_rejects_empty_sequence(self):
        with self.assertRaises(DiceInputError):
            validate_rolls("")

    def test_rejects_zero_digit(self):
        with self.assertRaises(DiceInputError):
            validate_rolls("120")

    def test_rejects_seven_digit(self):
        with self.assertRaises(DiceInputError):
            validate_rolls("127")

    def test_rejects_non_digit_characters(self):
        for bad in ("12a45", "1,2,3", "1 2 3", "12.3", "١٢٣"):
            with self.subTest(bad=bad):
                with self.assertRaises(DiceInputError):
                    validate_rolls(bad)

    def test_error_message_never_echoes_input(self):
        secret_like = "3141592653"
        try:
            validate_rolls(secret_like + "x")
        except DiceInputError as exc:
            self.assertNotIn(secret_like, str(exc))
        else:
            self.fail("deveria ter levantado DiceInputError")

    def test_rejects_sequence_larger_than_structural_limit(self):
        with self.assertRaises(DiceInputError):
            validate_rolls("1" * (MAX_ROLLS + 1))

    def test_accepts_at_structural_limit(self):
        validate_rolls("1" * MAX_ROLLS)  # nao deve levantar (pode ser lento, mas deve passar)


class EncodeDecodeBijectionTests(unittest.TestCase):
    def test_exhaustive_bijection_small_n(self):
        for n in range(1, 6):
            seen = set()
            for combo in itertools.product("123456", repeat=n):
                digits = "".join(combo)
                encoded = encode(digits)
                self.assertNotIn(encoded, seen)
                seen.add(encoded)
                self.assertEqual(decode(encoded), digits)
            self.assertEqual(len(seen), 6**n)

    def test_no_collision_across_lengths_with_leading_one(self):
        # O caso citado no design: "1,2,3" nao pode colidir com "2,3".
        self.assertNotEqual(encode("123"), encode("23"))
        self.assertNotEqual(encode("111"), encode("11"))

    def test_roundtrip_random_sample_larger_n(self):
        import os

        for _ in range(50):
            n = 50 + (os.urandom(1)[0] % 100)
            digits = "".join(str(b % 6 + 1) for b in os.urandom(n))
            encoded = encode(digits)
            self.assertEqual(decode(encoded), digits)

    def test_length_prefix_is_first_two_bytes(self):
        digits = "123456"
        encoded = encode(digits)
        self.assertEqual(int.from_bytes(encoded[:2], "big"), len(digits))

    def test_encoded_size_exceeds_but_bounds_entropy(self):
        # len(A) em bits deve ser >= n*log2(6) (nunca corta informacao),
        # mas isso NAO significa que A "contem" mais entropia real.
        import math

        digits = "23456" * 30
        n = len(digits)
        encoded = encode(digits)
        self.assertGreaterEqual(len(encoded) * 8, n * math.log2(6))


class DecodeNegativeTests(unittest.TestCase):
    def test_rejects_too_short_input(self):
        with self.assertRaises(DiceInputError):
            decode(b"\x00")

    def test_rejects_inconsistent_length(self):
        good = encode("123456")
        with self.assertRaises(DiceInputError):
            decode(good + b"\x00")  # byte extra nao declarado no prefixo

    def test_rejects_value_out_of_range(self):
        n = 3
        # max_value para n=3 e 6**3-1=215, cabe em 1 byte; 255 esta fora do range.
        payload = n.to_bytes(2, "big") + (255).to_bytes(1, "big")
        with self.assertRaises(DiceInputError):
            decode(payload)

    def test_rejects_zero_length_prefix(self):
        # Achado de auditoria adversarial (Fase D, secao 6): `encode` rejeita
        # explicitamente uma sequencia vazia (validate_rolls), entao um
        # prefixo n=0 e um estado que `encode` NUNCA produz. `decode` deve
        # rejeitar simetricamente, em vez de aceitar e devolver "". Sem
        # impacto de seguranca real (decode so e chamado com dados internos
        # conhecidos-bons, nunca com entrada nao confiavel no fluxo
        # `generate`), mas e uma inconsistencia de validacao real.
        with self.assertRaises(DiceInputError):
            decode((0).to_bytes(2, "big"))


if __name__ == "__main__":
    unittest.main()
