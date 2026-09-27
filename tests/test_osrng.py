"""Testes de entropyforge.osrng: leitura real do CSPRNG e casos negativos
de falha (CSPRNG indisponivel, saida degenerada) via injecao de falhas
(monkeypatch), sem depender do estado real do sistema."""

import os
import unittest
from unittest import mock

from entropyforge import osrng


class RealReadTests(unittest.TestCase):
    def test_reads_32_bytes_by_default(self):
        data = osrng.read_os_entropy()
        self.assertEqual(len(data), 32)

    def test_two_reads_differ(self):
        self.assertTrue(osrng.diagnostic_two_reads_differ())

    def test_rejects_nonpositive_nbytes(self):
        with self.assertRaises(ValueError):
            osrng.read_os_entropy(0)
        with self.assertRaises(ValueError):
            osrng.read_os_entropy(-1)


class CsprngUnavailableTests(unittest.TestCase):
    """CSPRNG indisponivel: deve falhar FECHADO, nunca cair para outra
    fonte (ex.: `random`)."""

    def test_oserror_from_getrandom_is_fail_closed(self):
        with mock.patch("os.getrandom", side_effect=OSError("kernel entropy pool unavailable")):
            with self.assertRaises(osrng.OsRngError):
                osrng.read_os_entropy()

    def test_short_read_is_rejected(self):
        with mock.patch("os.getrandom", return_value=b"\x01" * 16):
            with self.assertRaises(osrng.OsRngError):
                osrng.read_os_entropy(32)

    def test_no_fallback_to_random_module_on_failure(self):
        # Mesmo com os.getrandom falhando, o modulo nao deve, em nenhuma
        # circunstancia, produzir bytes por outro caminho: a excecao deve
        # propagar, nao ser engolida.
        with mock.patch("os.getrandom", side_effect=OSError("boom")):
            with self.assertRaises(osrng.OsRngError):
                osrng.read_os_entropy()


class NonLinuxPlatformTests(unittest.TestCase):
    """`os.getrandom` e uma chamada de sistema exclusiva do Linux; em
    outras plataformas (Windows, macOS, *BSD) o modulo `os` do CPython
    simplesmente nao a expoe (ver docs/PLATFORM_SUPPORT.md). Este teste
    simula essa ausencia removendo o atributo temporariamente, para
    confirmar que o modulo usa `os.urandom` -- uma chamada legitima ao
    CSPRNG do SO na plataforma atual (`BCryptGenRandom` no Windows,
    `getentropy()` em macOS/BSD), nunca `random` nem qualquer fonte nao
    criptografica."""

    def test_uses_urandom_when_getrandom_attribute_is_absent(self):
        original = os.getrandom
        del os.getrandom
        try:
            with mock.patch("os.urandom", return_value=bytes(range(32))) as mock_urandom:
                data = osrng.read_os_entropy()
            self.assertEqual(data, bytes(range(32)))
            mock_urandom.assert_called_once_with(32)
        finally:
            os.getrandom = original


class DegenerateOutputTests(unittest.TestCase):
    def test_all_zero_output_rejected(self):
        with mock.patch("os.getrandom", return_value=b"\x00" * 32):
            with self.assertRaises(osrng.OsRngError):
                osrng.read_os_entropy()

    def test_all_same_nonzero_byte_rejected(self):
        with mock.patch("os.getrandom", return_value=b"\x42" * 32):
            with self.assertRaises(osrng.OsRngError):
                osrng.read_os_entropy()

    def test_genuinely_varied_output_accepted(self):
        with mock.patch("os.getrandom", return_value=bytes(range(32))):
            data = osrng.read_os_entropy()
            self.assertEqual(data, bytes(range(32)))


if __name__ == "__main__":
    unittest.main()
