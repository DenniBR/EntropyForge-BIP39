"""Auto-testes (KATs — Known Answer Tests) executados antes de permitir o
fluxo `generate`.

Cada item verifica um componente critico contra uma resposta PUBLICA e
conhecida (vetores oficiais do BIP-39, valores tabelados de SHA-256,
propriedades da wordlist, round-trips deterministicos). NENHUM item usa ou
gera um segredo real.

Se qualquer item falhar, `run_selftest` devolve um resultado com
`all_passed=False`; o CLI (`cli.py`) trata isso como um erro fatal e
recusa continuar para a coleta de dados ou geracao do mnemonic (o produto
nunca gera uma "carteira" a partir de componentes que falharam em
verificacoes basicas).

Os vetores BIP-39 abaixo estao embutidos diretamente no codigo (nao
carregados de tests/vectors/bip39_vectors.json) para que `selftest`
funcione mesmo a partir de um artefato .pyz que nao inclua a pasta
`tests/`. A suite de testes completa (`tests/test_bip39_vectors.py`) usa
os 24 vetores oficiais completos.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import bip39, combine, dice, osrng, specialfunc, wordlist

# Vetores oficiais BIP-39 (ingles), extraidos de
# https://github.com/trezor/python-mnemonic/blob/master/vectors.json
# (entropy_hex, mnemonic_esperado, seed_hex_esperada_com_passphrase_TREZOR)
_BIP39_KAT_VECTORS = (
    (
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f0"
        "9a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art",
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170a"
        "f7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner "
        "thank year wave sausage worth useful legal winner thank year wave "
        "sausage worth title",
        "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b"
        "146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
        "zoo zoo zoo zoo zoo zoo zoo vote",
        "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613"
        "912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
    ),
)

_SHA256_KAT_VECTORS = (
    # (mensagem, digest hex esperado) — FIPS 180-4 / NIST CAVP, valores
    # publicos e amplamente reproduzidos.
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
)


@dataclass(frozen=True)
class SelfTestItem:
    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class SelfTestResult:
    items: tuple[SelfTestItem, ...]

    @property
    def all_passed(self) -> bool:
        return all(item.passed for item in self.items)

    def format(self) -> str:
        lines = ["=== Auto-testes (selftest) ==="]
        for item in self.items:
            status = "OK  " if item.passed else "FAIL"
            lines.append(f"[{status}] {item.name}" + (f" — {item.detail}" if item.detail else ""))
        lines.append("RESULTADO GERAL: " + ("PASSOU" if self.all_passed else "FALHOU"))
        return "\n".join(lines)


def _check(name: str, fn) -> SelfTestItem:
    try:
        fn()
        return SelfTestItem(name, True)
    except Exception as exc:  # noqa: BLE001 — selftest deve capturar QUALQUER falha
        return SelfTestItem(name, False, f"{type(exc).__name__}: {exc}")


def _check_sha256_vectors() -> None:
    for msg, expected in _SHA256_KAT_VECTORS:
        got = hashlib.sha256(msg).hexdigest()
        assert got == expected, f"SHA-256({msg!r}) = {got}, esperado {expected}"


def _check_wordlist() -> None:
    words = wordlist.load_wordlist()
    assert len(words) == 2048


def _check_bip39_vectors() -> None:
    for ent_hex, expected_mnemonic, expected_seed_hex in _BIP39_KAT_VECTORS:
        entropy = bytes.fromhex(ent_hex)
        mnemonic = bip39.entropy_to_mnemonic(entropy)
        assert mnemonic == expected_mnemonic, (
            f"entropy_to_mnemonic({ent_hex}) divergiu do vetor oficial"
        )
        back = bip39.mnemonic_to_entropy(mnemonic)
        assert back == entropy, "mnemonic_to_entropy nao e a inversa de entropy_to_mnemonic"
        seed = bip39.mnemonic_to_seed(mnemonic, "TREZOR")
        assert seed.hex() == expected_seed_hex, "mnemonic_to_seed divergiu do vetor oficial"


def _check_bip39_checksum_rejects_tamper() -> None:
    entropy = bytes(32)
    mnemonic = bip39.entropy_to_mnemonic(entropy)
    words = mnemonic.split()
    words[-1] = "zoo" if words[-1] != "zoo" else "abandon"
    tampered = " ".join(words)
    try:
        bip39.mnemonic_to_entropy(tampered)
    except bip39.ChecksumError:
        return
    raise AssertionError("checksum adulterado nao foi rejeitado")


def _check_dice_roundtrip() -> None:
    for digits in ("1", "666666", "123456123456", "654321"):
        encoded = dice.encode(digits)
        assert dice.decode(encoded) == digits


def _check_dice_rejects_invalid() -> None:
    for bad in ("", "0", "7", "12a"):
        try:
            dice.validate_rolls(bad)
        except dice.DiceInputError:
            continue
        raise AssertionError(f"entrada invalida nao rejeitada: {bad!r}")


def _check_combine_matches_raw_sha256() -> None:
    a = dice.encode("123456" * 20)
    b = bytes(range(32))
    expected = hashlib.sha256(a + b).digest()
    assert combine.combine(a, b) == expected


def _check_specialfunc_values() -> None:
    # valores tabelados classicos de qui-quadrado (df=5)
    assert abs(specialfunc.chi_square_sf(15.086, 5) - 0.01) < 1e-3
    assert abs(specialfunc.chi_square_sf(11.070, 5) - 0.05) < 1e-3
    assert abs(specialfunc.normal_two_sided_pvalue(1.96) - 0.05) < 1e-3


def _check_osrng_reachable() -> None:
    a = osrng.read_os_entropy()
    b = osrng.read_os_entropy()
    assert len(a) == 32 and len(b) == 32
    assert a != b, "duas leituras consecutivas do CSPRNG do SO devolveram o mesmo valor"


def run_selftest() -> SelfTestResult:
    items = [
        _check("sha256_kat_vectors", _check_sha256_vectors),
        _check("wordlist_integrity", _check_wordlist),
        _check("bip39_official_vectors", _check_bip39_vectors),
        _check("bip39_checksum_tamper_rejected", _check_bip39_checksum_rejects_tamper),
        _check("dice_encode_decode_roundtrip", _check_dice_roundtrip),
        _check("dice_rejects_invalid_input", _check_dice_rejects_invalid),
        _check("combine_matches_sha256", _check_combine_matches_raw_sha256),
        _check("specialfunc_tabulated_values", _check_specialfunc_values),
        _check("osrng_reachable", _check_osrng_reachable),
    ]
    return SelfTestResult(tuple(items))
