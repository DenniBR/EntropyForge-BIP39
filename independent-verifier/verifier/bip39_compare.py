"""Comparacao cruzada de tres fontes de verdade para BIP-39:

  1. os VETORES OFICIAIS (bitcoin/bips / trezor python-mnemonic), dados
     publicos, nao codigo;
  2. `bip39_min.py` deste mesmo pacote (implementacao independente, por
     deslocamento de bits);
  3. `entropyforge.bip39` -- o modulo SOB TESTE.

Esta e a UNICA parte do independent-verifier que importa `entropyforge`,
e faz isso de proposito: o objetivo aqui nao e "confiar" em
`entropyforge.bip39`, e sim testar se ele concorda com as outras duas
fontes independentes. Se todas as tres concordarem em milhares de casos,
isso e evidencia forte de corretude -- nunca uma prova absoluta.

Nada neste modulo assume que `entropyforge.bip39` esta correto: qualquer
divergencia e reportada, nunca descartada.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

from . import bip39_min


@dataclass(frozen=True)
class ComparisonResult:
    total_checked: int
    mismatches: tuple[str, ...]
    entropyforge_import_error: str | None = None

    @property
    def ok(self) -> bool:
        return self.entropyforge_import_error is None and len(self.mismatches) == 0


def _load_wordlist(entropyforge_root: Path) -> list[str]:
    raw = (entropyforge_root / "data" / "english.txt").read_bytes()
    words = [w for w in raw.decode("ascii").split("\n") if w]
    return words


def _import_entropyforge_bip39(repo_root: Path) -> ModuleType:
    """Importa `entropyforge.bip39` de um checkout especifico (repo_root
    deve conter o diretorio `entropyforge/`). Usa um `sys.path` isolado
    (inserido e removido) para permitir apontar para copias adversariais
    do projeto sem contaminar o restante do processo do verificador.
    """
    repo_root = str(repo_root.resolve())
    inserted = repo_root not in sys.path
    if inserted:
        sys.path.insert(0, repo_root)
    try:
        # limpa qualquer cache de um 'entropyforge' de OUTRO caminho, para
        # garantir que estamos testando o repo_root pedido, nao um que
        # ficou em cache de uma chamada anterior deste processo.
        for name in list(sys.modules):
            if name == "entropyforge" or name.startswith("entropyforge."):
                del sys.modules[name]
        module = importlib.import_module("entropyforge.bip39")
        return module
    finally:
        if inserted:
            sys.path.remove(repo_root)


def load_official_vectors(vectors_path: Path) -> list[tuple[bytes, str]]:
    data = json.loads(vectors_path.read_text())
    out = []
    for ent_hex, mnemonic, _seed_hex, _xprv in data["english"]:
        out.append((bytes.fromhex(ent_hex), mnemonic))
    return out


def compare_against_official_vectors(
    entropyforge_root: Path, vectors_path: Path
) -> ComparisonResult:
    """Fase 4: entropy -> mnemonic para os 24 vetores oficiais, checado
    contra `bip39_min` E contra `entropyforge.bip39`."""
    wordlist = _load_wordlist(entropyforge_root)
    vectors = load_official_vectors(vectors_path)
    mismatches = []
    ef_error = None
    try:
        ef_bip39 = _import_entropyforge_bip39(entropyforge_root.parent)
    except Exception as exc:  # noqa: BLE001 -- queremos capturar QUALQUER falha de import
        ef_error = f"{type(exc).__name__}: {exc}"
        ef_bip39 = None

    for entropy, expected_mnemonic in vectors:
        got_min = bip39_min.entropy_to_mnemonic(entropy, wordlist)
        if got_min != expected_mnemonic:
            mismatches.append(
                f"bip39_min diverge do vetor oficial para entropy={entropy.hex()}: "
                f"got={got_min!r} expected={expected_mnemonic!r}"
            )
        if ef_bip39 is not None:
            try:
                got_ef = ef_bip39.entropy_to_mnemonic(entropy)
            except Exception as exc:  # noqa: BLE001
                mismatches.append(
                    f"entropyforge.bip39 levantou excecao para entropy={entropy.hex()}: "
                    f"{type(exc).__name__}: {exc}"
                )
                continue
            if got_ef != expected_mnemonic:
                mismatches.append(
                    f"entropyforge.bip39 diverge do vetor oficial para entropy={entropy.hex()}: "
                    f"got={got_ef!r} expected={expected_mnemonic!r}"
                )

    return ComparisonResult(
        total_checked=len(vectors), mismatches=tuple(mismatches), entropyforge_import_error=ef_error
    )


def compare_random_fuzz(
    entropyforge_root: Path, n_trials: int = 5000, seed_note: str = "os.urandom"
) -> ComparisonResult:
    """Fase 4 (fuzzing): `n_trials` entropias aleatorias (via os.urandom,
    nao usadas para nenhuma carteira real), comparando `bip39_min` contra
    `entropyforge.bip39`."""
    wordlist = _load_wordlist(entropyforge_root)
    ef_error = None
    try:
        ef_bip39 = _import_entropyforge_bip39(entropyforge_root.parent)
    except Exception as exc:  # noqa: BLE001
        return ComparisonResult(total_checked=0, mismatches=(), entropyforge_import_error=f"{type(exc).__name__}: {exc}")

    mismatches = []
    sizes = (16, 20, 24, 28, 32)
    for i in range(n_trials):
        nbytes = sizes[os.urandom(1)[0] % len(sizes)]
        entropy = os.urandom(nbytes)
        got_min = bip39_min.entropy_to_mnemonic(entropy, wordlist)
        try:
            got_ef = ef_bip39.entropy_to_mnemonic(entropy)
        except Exception as exc:  # noqa: BLE001
            mismatches.append(f"[{i}] entropyforge.bip39 excecao para {entropy.hex()}: {exc}")
            continue
        if got_min != got_ef:
            mismatches.append(
                f"[{i}] DIVERGENCIA entropy={entropy.hex()}: bip39_min={got_min!r} entropyforge={got_ef!r}"
            )
        # e o round-trip de cada implementacao contra si mesma
        back_min = bip39_min.mnemonic_to_entropy(got_min, wordlist)
        if back_min != entropy:
            mismatches.append(f"[{i}] bip39_min round-trip falhou para {entropy.hex()}")
        try:
            back_ef = ef_bip39.mnemonic_to_entropy(got_ef)
            if back_ef != entropy:
                mismatches.append(f"[{i}] entropyforge.bip39 round-trip falhou para {entropy.hex()}")
        except Exception as exc:  # noqa: BLE001
            mismatches.append(f"[{i}] entropyforge.bip39 round-trip excecao para {entropy.hex()}: {exc}")

    return ComparisonResult(total_checked=n_trials, mismatches=tuple(mismatches), entropyforge_import_error=ef_error)
