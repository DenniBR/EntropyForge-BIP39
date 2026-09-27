"""Testes do versionamento formal (Fase E, requisito 2)."""

import subprocess
import sys
import unittest

from entropyforge import version
from entropyforge.cli import build_parser


class VersionInfoTests(unittest.TestCase):
    def test_current_returns_all_five_independent_numbers(self):
        v = version.current()
        self.assertEqual(v.software_version, version.SOFTWARE_VERSION)
        self.assertEqual(v.protocol_version_a, version.PROTOCOL_VERSION_A)
        self.assertEqual(v.generation_procedure_version, version.GENERATION_PROCEDURE_VERSION)
        self.assertEqual(v.wordlist_version, version.WORDLIST_VERSION)
        self.assertEqual(v.manifest_format_version, version.MANIFEST_FORMAT_VERSION)

    def test_format_mentions_every_field(self):
        text = version.current().format()
        for value in (
            version.SOFTWARE_VERSION,
            version.PROTOCOL_VERSION_A,
            version.GENERATION_PROCEDURE_VERSION,
            version.WORDLIST_VERSION,
            version.MANIFEST_FORMAT_VERSION,
        ):
            self.assertIn(value, text)


class VersionCliTests(unittest.TestCase):
    def test_version_flag_exits_zero_without_requiring_a_subcommand(self):
        proc = subprocess.run(
            [sys.executable, "-B", "-m", "entropyforge", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn(version.SOFTWARE_VERSION, proc.stdout)
        self.assertIn(version.WORDLIST_VERSION, proc.stdout)

    def test_parser_accepts_version_flag_before_subcommand(self):
        parser = build_parser()
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
