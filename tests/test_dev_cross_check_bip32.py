"""Interoperabilidade BIP-39/BIP-32, SOMENTE PARA DESENVOLVIMENTO (Fase E,
requisito de interoperabilidade obrigatoria): confirma que a seed BIP-39
produzida por este projeto, alimentada em uma derivacao BIP-32 padrao,
produz uma chave mestra e um endereco que batem com implementacoes
externas conhecidas -- nunca usado em runtime.

Este projeto NAO implementa BIP-32 (nao deriva chaves de carteira nem
enderecos -- ver docs/DESIGN.md, decisao D6, "o que nao e implementado no
produto"). Este teste existe SOMENTE para validar, em desenvolvimento, que
a SEED que o produto entrega ao operador (que ele digitara em uma carteira
externa) e interpretada da mesma forma que qualquer carteira BIP-32/BIP-44
padrao interpretaria.

Duas implementacoes externas, nenhuma delas dependencia de runtime:
  - `mnemonic` (Trezor): mnemonic -> seed (PBKDF2-HMAC-SHA512), cruzado
    contra `entropyforge.bip39.mnemonic_to_seed`.
  - `bip32utils`: seed -> chave mestra BIP-32 -> chave derivada BIP-44 ->
    endereco Bitcoin. A propria derivacao da chave mestra (HMAC-SHA512 com
    chave b"Bitcoin seed", especificacao BIP-32) e cruzada aqui contra uma
    segunda implementacao independente usando SOMENTE `hmac`/`hashlib` da
    biblioteca padrao -- ou seja, a chave mestra e verificada por DUAS
    implementacoes independentes de BIP-32 (`bip32utils` e o calculo cru
    feito neste arquivo de teste), nao so uma.

Pulado automaticamente se `mnemonic` e/ou `bip32utils` nao estiverem
instalados. Para rodar localmente: `pip install mnemonic bip32utils` num
venv de desenvolvimento e depois
`python3 -m unittest tests.test_dev_cross_check_bip32`.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import unittest

from entropyforge.bip39 import entropy_to_mnemonic, mnemonic_to_seed

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

_HAVE_BOTH = _HAVE_MNEMONIC and _HAVE_BIP32UTILS

# Entropia CLARAMENTE FICTICIA (sequencia 0x00..0x1f, nunca uma saida real
# deste programa) -- usada SOMENTE para demonstrar a derivacao completa.
# O mnemonic/endereco resultantes deste valor sao PUBLICOS (aparecem neste
# arquivo de teste e em docs/WALLET_IMPORT_TEST.md): NUNCA envie fundos
# reais para qualquer endereco derivado dele.
_FICTITIOUS_ENTROPY = bytes(range(32))

# Vetor de teste oficial da especificacao BIP-32 (seed publica, usada em
# todo o ecossistema para testar implementacoes de BIP-32; nao e segredo
# de ninguem).
_BIP32_SPEC_TEST_SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def _raw_bip32_master_key(seed: bytes) -> tuple[bytes, bytes]:
    """Reimplementacao independente, usando somente `hmac`/`hashlib` da
    biblioteca padrao, da derivacao da chave mestra BIP-32: `I =
    HMAC-SHA512(key=b"Bitcoin seed", data=seed)`; os 32 bytes esquerdos
    sao a chave privada mestra, os 32 direitos sao o chain code mestre
    (formula publica da especificacao BIP-32, nao um segredo de
    implementacao)."""
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return digest[:32], digest[32:]


@unittest.skipUnless(_HAVE_MNEMONIC, "pacote 'mnemonic' (dev-only) nao instalado")
class SeedCrossCheckTests(unittest.TestCase):
    """`entropyforge.bip39.mnemonic_to_seed` cruzado contra `mnemonic`
    (implementacao de referencia citada na propria especificacao BIP-39)."""

    def test_random_mnemonics_produce_identical_seeds(self):
        ref = Mnemonic("english")
        for _ in range(200):
            nbytes = os.urandom(1)[0] % 5 * 4 + 16  # 16,20,24,28,32
            entropy = os.urandom(nbytes)
            m = entropy_to_mnemonic(entropy)
            self.assertEqual(mnemonic_to_seed(m), ref.to_seed(m, passphrase=""))

    def test_nonempty_passphrase_produces_identical_seeds(self):
        ref = Mnemonic("english")
        m = entropy_to_mnemonic(_FICTITIOUS_ENTROPY)
        for passphrase in ("", "TREZOR", "uma frase secreta ficticia"):
            with self.subTest(passphrase=passphrase):
                self.assertEqual(
                    mnemonic_to_seed(m, passphrase),
                    ref.to_seed(m, passphrase=passphrase),
                )


@unittest.skipUnless(_HAVE_BIP32UTILS, "pacote 'bip32utils' (dev-only) nao instalado")
class Bip32MasterKeyIndependentCrossCheckTests(unittest.TestCase):
    """A derivacao da chave mestra do `bip32utils` cruzada contra uma
    segunda implementacao (a formula HMAC-SHA512 crua deste arquivo, sem
    depender de nenhuma biblioteca alem de `hmac`/`hashlib`)."""

    def _assert_master_key_matches(self, seed: bytes) -> None:
        theirs = BIP32Key.fromEntropy(seed)
        expected_priv, expected_chain = _raw_bip32_master_key(seed)
        self.assertEqual(theirs.PrivateKey(), expected_priv)
        self.assertEqual(theirs.ChainCode(), expected_chain)

    def test_official_bip32_spec_test_vector_1_seed(self):
        self._assert_master_key_matches(_BIP32_SPEC_TEST_SEED)

    def test_fictitious_entropy_derived_seed(self):
        m = entropy_to_mnemonic(_FICTITIOUS_ENTROPY)
        seed = mnemonic_to_seed(m)
        self._assert_master_key_matches(seed)

    def test_random_seeds(self):
        for _ in range(50):
            self._assert_master_key_matches(os.urandom(64))


@unittest.skipUnless(_HAVE_BOTH, "pacotes 'mnemonic'/'bip32utils' (dev-only) nao instalados")
class FullPipelineFictitiousWalletTests(unittest.TestCase):
    """Fluxo completo (SOMENTE dados ficticios, nunca em runtime): entropia
    -> `entropy_to_mnemonic` -> `mnemonic_to_seed` -> chave mestra BIP-32
    -> chave derivada BIP-44 (m/44'/0'/0'/0/0) -> endereco Bitcoin.

    Isto e a mesma cadeia que docs/WALLET_IMPORT_TEST.md pede para o
    operador reproduzir manualmente numa carteira externa (ex.: Sparrow);
    este teste e a verificacao automatizada, em desenvolvimento, de que os
    valores documentados la sao reproduziveis."""

    def test_fictitious_mnemonic_derives_expected_bip44_address(self):
        mnemonic_str = entropy_to_mnemonic(_FICTITIOUS_ENTROPY)
        self.assertEqual(
            mnemonic_str,
            "abandon amount liar amount expire adjust cage candy arch "
            "gather drum bullet absurd math era live bid rhythm alien "
            "crouch range attend journey unaware",
        )
        seed = mnemonic_to_seed(mnemonic_str)
        key = BIP32Key.fromEntropy(seed)
        for index in (44 + BIP32_HARDEN, 0 + BIP32_HARDEN, 0 + BIP32_HARDEN, 0, 0):
            key = key.ChildKey(index)
        address = key.Address()
        # Valor documentado em docs/WALLET_IMPORT_TEST.md -- se este teste
        # falhar, o passo a passo daquele documento tambem esta incorreto
        # e precisa ser atualizado junto.
        self.assertEqual(address, "1K4RSBSNHRWCfb1WziRApwF8yCri43exY7")

    def test_address_has_valid_base58check_p2pkh_shape(self):
        # Checagem estrutural independente do endereco (nao confia so no
        # `bip32utils` ter "dito que sim"): decodifica Base58Check e
        # confirma o byte de versao (0x00 = P2PKH mainnet) e o
        # comprimento do payload (1 byte de versao + 20 bytes de hash160).
        mnemonic_str = entropy_to_mnemonic(_FICTITIOUS_ENTROPY)
        seed = mnemonic_to_seed(mnemonic_str)
        key = BIP32Key.fromEntropy(seed)
        for index in (44 + BIP32_HARDEN, 0 + BIP32_HARDEN, 0 + BIP32_HARDEN, 0, 0):
            key = key.ChildKey(index)
        address = key.Address()
        decoded = _base58check_decode(address)
        self.assertEqual(len(decoded), 21)
        self.assertEqual(decoded[0], 0x00)


_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58check_decode(s: str) -> bytes:
    """Decodificacao Base58Check independente (so `hashlib`), usada para
    verificar o endereco sem depender do proprio `bip32utils` para validar
    seu proprio resultado."""
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


if __name__ == "__main__":
    unittest.main()
