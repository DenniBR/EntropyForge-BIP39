"""Interoperabilidade fim-a-fim atraves do EXECUTAVEL construido (Fase F
#6), SOMENTE PARA DESENVOLVIMENTO: repete a mesma cadeia completa que
`tests/test_dev_cross_check_bip32.py` ja verifica contra o SOURCE --
d6 -> A -> B -> SHA256(A||B) -> entropia -> mnemonic -> seed -> chave
mestra BIP-32 -> chave derivada BIP-44 -> endereco -- mas desta vez
tomando a entropia/mnemonic do STDOUT REAL do binario compilado
(`vector --a-digits ... --b-hex ...`), nunca reimportando
`entropyforge` em processo. Isto fecha a lacuna que so testar o source
deixaria: confirma que o ARTEFATO DISTRIBUIDO (nao so o codigo-fonte que
o gerou) interopera com implementacoes externas de BIP-39/BIP-32.

Duas implementacoes externas, nenhuma delas dependencia de runtime do
projeto (mesmas de test_dev_cross_check_bip32.py):
  - `mnemonic` (Trezor): mnemonic -> seed.
  - `bip32utils` + uma segunda reimplementacao crua (so `hmac`/`hashlib`):
    seed -> chave mestra BIP-32 -> chave BIP-44 -> endereco.

Pulado automaticamente se `nuitka`/gcc (para construir o executavel) ou
`mnemonic`/`bip32utils` (dev-only) nao estiverem disponiveis. NENHUM dado
real e usado -- `--a-digits`/`--b-hex` sao valores de teste PUBLICOS e
triviais, os mesmos ja usados em tests/test_executable_e2e.py.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import build_executable  # type: ignore  # noqa: E402
from entropyforge.bip39 import mnemonic_to_seed  # noqa: E402

try:
    build_executable._check_prereqs()
    _BUILD_PREREQS_OK = True
    _BUILD_SKIP_REASON = ""
except build_executable.ExecutableBuildError as exc:
    _BUILD_PREREQS_OK = False
    _BUILD_SKIP_REASON = str(exc)

try:
    from mnemonic import Mnemonic

    _HAVE_MNEMONIC = True
except ImportError:
    _HAVE_MNEMONIC = False

try:
    from bip32utils import BIP32_HARDEN, BIP32Key

    _HAVE_BIP32UTILS = True
except ImportError:
    _HAVE_BIP32UTILS = False

_SKIP = not (_BUILD_PREREQS_OK and _HAVE_MNEMONIC and _HAVE_BIP32UTILS)
_SKIP_REASON = "; ".join(
    r
    for r in (
        _BUILD_SKIP_REASON,
        "" if _HAVE_MNEMONIC else "pacote 'mnemonic' (dev-only) nao instalado",
        "" if _HAVE_BIP32UTILS else "pacote 'bip32utils' (dev-only) nao instalado",
    )
    if r
)

# valores de teste PUBLICOS, os mesmos usados em tests/test_executable_e2e.py
# -- nunca dados de uma geracao real.
_TEST_A_DIGITS = "1" * 300
_TEST_B_HEX = "00" * 32

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58check_decode(s: str) -> bytes:
    """Decodificacao Base58Check independente (so `hashlib`) -- nao confia
    no `bip32utils` para validar seu proprio resultado."""
    num = 0
    for ch in s:
        num = num * 58 + _BASE58_ALPHABET.index(ch)
    combined = num.to_bytes((num.bit_length() + 7) // 8, "big")
    n_leading_zeros = len(s) - len(s.lstrip("1"))
    combined = b"\x00" * n_leading_zeros + combined
    payload, checksum = combined[:-4], combined[-4:]
    computed = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if computed != checksum:
        raise ValueError("Base58Check checksum invalido")
    return payload


def _raw_bip32_master_key(seed: bytes) -> tuple[bytes, bytes]:
    """Reimplementacao independente (so `hmac`/`hashlib`) da derivacao da
    chave mestra BIP-32: `I = HMAC-SHA512(key=b"Bitcoin seed", data=seed)`."""
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return digest[:32], digest[32:]


@unittest.skipIf(_SKIP, f"pre-requisitos ausentes: {_SKIP_REASON}")
class ExecutableFullPipelineFictitiousWalletTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_tmp = Path(tempfile.mkdtemp())
        cls.dist_dir = build_executable.build(cls.build_tmp)
        cls.main_bin = cls.dist_dir / "entropyforge-bip39"

        proc = subprocess.run(
            [str(cls.main_bin), "vector", "--a-digits", _TEST_A_DIGITS, "--b-hex", _TEST_B_HEX],
            capture_output=True, text=True, timeout=20,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"'vector' do executavel falhou: rc={proc.returncode} stderr={proc.stderr!r}")
        entropy_match = re.search(r"E = SHA256\(A\|\|B\): ([0-9a-f]{64})", proc.stdout)
        mnemonic_match = re.search(r"mnemonic {8}: (.+)", proc.stdout)
        if not entropy_match or not mnemonic_match:
            raise RuntimeError(f"nao foi possivel extrair entropia/mnemonic da saida do executavel: {proc.stdout!r}")
        cls.entropy_hex = entropy_match.group(1)
        cls.mnemonic_from_executable = mnemonic_match.group(1).strip()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.build_tmp, ignore_errors=True)

    def test_executable_vector_output_is_well_formed(self):
        # confirma que efetivamente lemos algo (nao um match vazio/errado)
        # antes de usar esses valores no resto da cadeia.
        self.assertEqual(len(bytes.fromhex(self.entropy_hex)), 32)
        self.assertEqual(len(self.mnemonic_from_executable.split()), 24)

    def test_mnemonic_from_executable_produces_seed_matching_reference_implementation(self):
        # a mnemonic saiu do BINARIO COMPILADO; a seed e' calculada aqui
        # por DUAS vias independentes -- o source deste projeto
        # (`entropyforge.bip39.mnemonic_to_seed`, interpretado, nunca
        # compilado) e a biblioteca `mnemonic` de terceiros -- e devem
        # bater exatamente.
        ref = Mnemonic("english")
        seed_from_source = mnemonic_to_seed(self.mnemonic_from_executable, "")
        seed_from_reference_lib = ref.to_seed(self.mnemonic_from_executable, passphrase="")
        self.assertEqual(len(seed_from_source), 64)
        self.assertEqual(seed_from_source, seed_from_reference_lib)

    def test_full_chain_from_executable_output_to_bip44_address(self):
        # d6 (fictício, via --a-digits) -> A -> B -> SHA256(A||B) -> E ->
        # mnemonic -> seed -> chave mestra BIP-32 -> BIP-44 -> endereco --
        # cada seta, a partir da mnemonic, e' verificada por uma
        # implementacao EXTERNA (mnemonic/bip32utils), nunca pelo proprio
        # codigo deste projeto.
        ref = Mnemonic("english")
        seed = ref.to_seed(self.mnemonic_from_executable, passphrase="")

        expected_priv, expected_chain = _raw_bip32_master_key(seed)
        key = BIP32Key.fromEntropy(seed)
        self.assertEqual(key.PrivateKey(), expected_priv)
        self.assertEqual(key.ChainCode(), expected_chain)

        for index in (44 + BIP32_HARDEN, 0 + BIP32_HARDEN, 0 + BIP32_HARDEN, 0, 0):
            key = key.ChildKey(index)
        address = key.Address()

        decoded = _base58check_decode(address)
        self.assertEqual(len(decoded), 21)
        self.assertEqual(decoded[0], 0x00)  # P2PKH mainnet

        # NUNCA envie fundos reais para este endereco: a entropia de
        # origem e' publica (--a-digits/--b-hex fixos, de teste), portanto
        # este endereco e' PUBLICO e sua chave privada e' conhecida por
        # qualquer um que leia este arquivo.
        print(f"\n[interop executavel] endereco fictício derivado: {address}")


if __name__ == "__main__":
    unittest.main()
