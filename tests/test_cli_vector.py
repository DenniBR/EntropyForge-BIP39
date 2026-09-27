"""Testes do subcomando `vector` (modo deterministico, dados PUBLICOS)."""

import unittest

from entropyforge import bip39, combine, dice
from entropyforge.cli import TerminalIO, build_parser, cmd_vector


def _io():
    captured = []
    io = TerminalIO(
        write=lambda s: captured.append(s),
        warn=lambda s: captured.append(s),
    )
    return io, captured


class VectorEntropyToMnemonicTests(unittest.TestCase):
    def test_entropy_to_mnemonic(self):
        io, captured = _io()
        args = build_parser().parse_args(["vector", "--entropy-hex", "00" * 32])
        rc = cmd_vector(args, io)
        self.assertEqual(rc, 0)
        expected = bip39.entropy_to_mnemonic(bytes(32))
        self.assertTrue(any(expected in line for line in captured))


class VectorMnemonicToEntropyTests(unittest.TestCase):
    def test_mnemonic_to_entropy(self):
        mnemonic = bip39.entropy_to_mnemonic(bytes(32))
        io, captured = _io()
        args = build_parser().parse_args(["vector", "--mnemonic", mnemonic])
        rc = cmd_vector(args, io)
        self.assertEqual(rc, 0)
        self.assertTrue(any("00" * 32 in line for line in captured))

    def test_rejects_invalid_mnemonic(self):
        io, captured = _io()
        args = build_parser().parse_args(["vector", "--mnemonic", "not a real mnemonic"])
        rc = cmd_vector(args, io)
        self.assertNotEqual(rc, 0)


class VectorCombineTests(unittest.TestCase):
    def test_a_digits_and_b_hex(self):
        io, captured = _io()
        args = build_parser().parse_args(
            ["vector", "--a-digits", "123456" * 22, "--b-hex", "11" * 32]
        )
        rc = cmd_vector(args, io)
        self.assertEqual(rc, 0)
        a = dice.encode("123456" * 22)
        b = bytes.fromhex("11" * 32)
        e = combine.combine(a, b)
        expected_mnemonic = bip39.entropy_to_mnemonic(e)
        blob = "\n".join(captured)
        self.assertIn(a.hex(), blob)
        self.assertIn(e.hex(), blob)
        self.assertIn(expected_mnemonic, blob)

    def test_rejects_invalid_dice_digits(self):
        io, captured = _io()
        args = build_parser().parse_args(["vector", "--a-digits", "abc", "--b-hex", "00" * 32])
        rc = cmd_vector(args, io)
        self.assertNotEqual(rc, 0)

    def test_no_arguments_is_an_error(self):
        io, captured = _io()
        args = build_parser().parse_args(["vector"])
        rc = cmd_vector(args, io)
        self.assertNotEqual(rc, 0)

    def test_warns_this_is_not_for_real_funds(self):
        io, captured = _io()
        args = build_parser().parse_args(["vector", "--entropy-hex", "00" * 32])
        cmd_vector(args, io)
        blob = "\n".join(captured)
        self.assertIn("NAO USE", blob.upper())


if __name__ == "__main__":
    unittest.main()
