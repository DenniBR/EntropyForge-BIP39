import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.process_observe import StraceUnavailable, strace_available, trace_process


@unittest.skipUnless(strace_available(), "requer o binario 'strace' (Linux)")
class BenignProcessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_plain_script_touches_nothing(self):
        result = trace_process([sys.executable, "-c", "print(1 + 1)"], cwd=self.tmp)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.touched_network)
        self.assertFalse(result.wrote_to_disk)

    def test_plain_script_does_not_falsely_report_spawned_process(self):
        # Regressao: a primeira linha de qualquer log do strace e sempre
        # o execve do PROPRIO comando de nivel superior sendo tracado (e
        # assim que `strace cmd` funciona), nao um processo-filho gerado
        # pelo programa. Antes da correcao, isso fazia `spawned_process`
        # ser sempre True, mesmo aqui, onde nenhum filho e criado.
        result = trace_process([sys.executable, "-c", "print(1 + 1)"], cwd=self.tmp)
        self.assertFalse(result.spawned_process, msg=result.process_syscalls)


@unittest.skipUnless(strace_available(), "requer o binario 'strace' (Linux)")
class MaliciousBehaviorDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_detects_real_subprocess_spawn(self):
        result = trace_process(
            [sys.executable, "-c", "import subprocess; subprocess.run(['true'])"],
            cwd=self.tmp,
        )
        self.assertTrue(result.spawned_process, msg=result.process_syscalls)

    def test_detects_raw_socket_attempt(self):
        script = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "s.sendto(b'fictitious-lab-payload', ('127.0.0.1', 9))\n"
        )
        result = trace_process([sys.executable, "-c", script], cwd=self.tmp)
        self.assertTrue(result.touched_network, msg=result.network_syscalls)

    def test_detects_file_write_via_open_flags(self):
        script = f"open({str(self.tmp / 'leak.bin')!r}, 'wb').write(b'x')\n"
        result = trace_process([sys.executable, "-c", script], cwd=self.tmp)
        self.assertTrue(result.wrote_to_disk, msg=result.file_write_syscalls)

    def test_read_only_open_is_not_reported_as_write(self):
        readable = self.tmp / "readable.txt"
        readable.write_text("hello")
        script = f"open({str(readable)!r}, 'r').read()\n"
        result = trace_process([sys.executable, "-c", script], cwd=self.tmp)
        self.assertFalse(result.wrote_to_disk, msg=result.file_write_syscalls)


class StraceUnavailableTests(unittest.TestCase):
    def test_raises_when_strace_missing(self):
        from unittest import mock

        with mock.patch("verifier.process_observe.strace_available", return_value=False):
            with self.assertRaises(StraceUnavailable):
                trace_process([sys.executable, "-c", "pass"], cwd=Path(tempfile.mkdtemp()))


if __name__ == "__main__":
    unittest.main()
