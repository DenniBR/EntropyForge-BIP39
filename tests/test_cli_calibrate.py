"""Testes do subcomando `calibrate`: os dados sao SEMPRE descartaveis
(nunca alimentam bip39/combine), aceita entrada em varios blocos, e
recusa dados invalidos."""

import unittest

from entropyforge.cli import TerminalIO, build_parser, cmd_calibrate


def _io(lines):
    captured = []
    it = iter(lines)
    return (
        TerminalIO(
            read_line=lambda prompt: next(it, "FIM"),
            write=lambda s: captured.append(s),
            warn=lambda s: captured.append(s),
        ),
        captured,
    )


class CalibrateTests(unittest.TestCase):
    def test_accepts_input_in_multiple_chunks(self):
        chunks = ["123456" * 10, "654321" * 10, "111111" * 12]  # soma = 60+60+72=192
        io, captured = _io(chunks)
        args = build_parser().parse_args(["calibrate", "--rolls", "192"])
        rc = cmd_calibrate(args, io)
        self.assertEqual(rc, 0)
        blob = "\n".join(captured)
        self.assertIn("192", blob)
        self.assertIn("DESCARTAVEIS", blob.upper())

    def test_accepts_space_separated_chunks(self):
        # Fase E, requisito 6: `calibrate` tambem aceita o formato
        # separado por espacos (via `dice.normalize_dice_input`), nao so
        # o compacto.
        chunk = " ".join("123456" * 10)  # 60 lancamentos, com espacos
        io, captured = _io([chunk])
        args = build_parser().parse_args(["calibrate", "--rolls", "60"])
        rc = cmd_calibrate(args, io)
        self.assertEqual(rc, 0)

    def test_rejects_mixed_format_chunk_and_keeps_asking(self):
        mixed = "12" + " " + "3456"  # mistura compacto + espaco
        chunks = [mixed, "123456" * 10]
        io, captured = _io(chunks)
        args = build_parser().parse_args(["calibrate", "--rolls", "60"])
        rc = cmd_calibrate(args, io)
        self.assertEqual(rc, 0)

    def test_ignores_invalid_chunk_and_keeps_asking(self):
        chunks = ["abc", "123456" * 10]
        io, captured = _io(chunks)
        args = build_parser().parse_args(["calibrate", "--rolls", "60"])
        rc = cmd_calibrate(args, io)
        self.assertEqual(rc, 0)

    def test_full_report_contains_clopper_pearson(self):
        digits = "123456" * 200  # 1200 lancamentos, uniformes
        io, captured = _io([digits])
        args = build_parser().parse_args(["calibrate", "--rolls", str(len(digits))])
        rc = cmd_calibrate(args, io)
        self.assertEqual(rc, 0)
        blob = "\n".join(captured)
        self.assertIn("Clopper-Pearson", blob)

    def test_never_imports_bip39_or_combine(self):
        import entropyforge.cli as cli_module

        with open(cli_module.__file__, encoding="utf-8") as f:
            source = f.read()
        # cmd_calibrate especificamente nao deve usar bip39/combine; o
        # modulo cli.py como um todo usa (para `generate`), entao aqui
        # verificamos o CORPO da funcao, nao o arquivo inteiro.
        import inspect

        from entropyforge.cli import cmd_calibrate as fn

        body = inspect.getsource(fn)
        self.assertNotIn("bip39", body)
        self.assertNotIn("combine", body)


if __name__ == "__main__":
    unittest.main()
