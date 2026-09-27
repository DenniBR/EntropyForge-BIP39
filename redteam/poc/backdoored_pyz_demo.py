#!/usr/bin/env python3
"""Red team PoC: o que `selftest` detecta e o que NAO detecta em um
artefato .pyz adulterado.

Cenario 1 (DETECTADO): a wordlist embutida e adulterada (1 palavra
trocada). `selftest` falha (`wordlist_integrity`), porque compara o hash
SHA-256 do arquivo embutido contra a constante `WORDLIST_SHA256`.

Cenario 2 (NAO DETECTADO): `combine.py` e adulterado para vazar a
entropia combinada (E) via stderr -- um "backdoor" minimo. `selftest`
continua reportando "RESULTADO GERAL: PASSOU", porque todos os seus
testes de resposta conhecida (KATs) continuam recebendo a resposta
CORRETA; o backdoor so adiciona um EFEITO COLATERAL (escrita extra em
stderr), que nenhum KAT verifica a ausencia de.

Conclusao (ver docs/REDTEAM.md): `selftest` verifica CORRETUDE
computacional, nao a AUSENCIA de backdoors. A unica defesa real contra um
artefato adulterado e comparar o hash do .pyz contra um build
reprodutivel a partir de codigo-fonte que voce mesmo revisou
(`make repro`) -- nunca confiar cegamente em `selftest` sozinho como
prova de integridade do artefato.

Nenhum dado usado aqui e uma seed real -- tudo e publico/deterministico
(vetores de teste, dado de exemplo "123456...").
"""
from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def build_clean_pyz(out_path: Path) -> None:
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import build_pyz  # type: ignore

    build_pyz.build(out_path)


def _open_zip_parts(pyz_path: Path):
    data = pyz_path.read_bytes()
    zip_start = data.index(b"PK\x03\x04")
    shebang = data[:zip_start]
    zin = zipfile.ZipFile(io.BytesIO(data[zip_start:]))
    content = {n: zin.read(n) for n in zin.namelist()}
    zin.close()
    return shebang, content


def _write_zip(shebang: bytes, content: dict, out_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zout:
        for name, data in content.items():
            zout.writestr(name, data)
    out_path.write_bytes(shebang + buf.getvalue())
    os.chmod(out_path, 0o755)


def make_wordlist_tampered(src: Path, dst: Path) -> None:
    shebang, content = _open_zip_parts(src)
    wl = content["entropyforge/data/english.txt"]
    assert wl.startswith(b"abandon\n")
    content["entropyforge/data/english.txt"] = b"abXndon\n" + wl[len(b"abandon\n"):]
    _write_zip(shebang, content, dst)


def make_backdoored(src: Path, dst: Path) -> None:
    shebang, content = _open_zip_parts(src)
    combine_src = content["entropyforge/combine.py"].decode("utf-8")
    injection = (
        "    digest = hashlib.sha256(a + b).digest()\n"
        "    import sys as _s\n"
        "    _s.stderr.write('REDTEAM_BACKDOOR_POC:' + digest.hex() + chr(10))  # BACKDOOR POC\n"
    )
    injected = combine_src.replace("    digest = hashlib.sha256(a + b).digest()\n", injection, 1)
    assert injected != combine_src
    content["entropyforge/combine.py"] = injected.encode("utf-8")
    _write_zip(shebang, content, dst)


def run_selftest(pyz_path: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-I", "-B", str(pyz_path), "selftest"],
        capture_output=True, text=True, timeout=30,
    )
    return proc.returncode, proc.stdout + proc.stderr


def run_vector(pyz_path: Path) -> str:
    proc = subprocess.run(
        [sys.executable, "-I", "-B", str(pyz_path), "vector",
         "--a-digits", "123456" * 22, "--b-hex", "11" * 32],
        capture_output=True, text=True, timeout=30,
    )
    return proc.stdout + proc.stderr


def main() -> int:
    with TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        clean = tmp / "clean.pyz"
        tampered_wl = tmp / "tampered_wordlist.pyz"
        backdoored = tmp / "backdoored.pyz"

        build_clean_pyz(clean)
        make_wordlist_tampered(clean, tampered_wl)
        make_backdoored(clean, backdoored)

        print("=== cenario 0: artefato limpo ===")
        rc, out = run_selftest(clean)
        print(f"selftest rc={rc}, RESULTADO: {'PASSOU' in out}")

        print("\n=== cenario 1: wordlist adulterada (1 palavra trocada) ===")
        rc, out = run_selftest(tampered_wl)
        detected = "FALHOU" in out
        print(f"selftest rc={rc}, DETECTADO: {detected}")
        if not detected:
            print("*** INESPERADO: adulteracao da wordlist NAO foi detectada! ***")

        print("\n=== cenario 2: backdoor em combine.py (vaza E via stderr) ===")
        rc, out = run_selftest(backdoored)
        passed_anyway = "PASSOU" in out
        leaked_in_selftest = "REDTEAM_BACKDOOR_POC" in out
        print(f"selftest rc={rc}, RESULTADO GERAL ainda diz PASSOU: {passed_anyway}")
        print(f"o proprio selftest ja vazou o marcador do backdoor em sua saida: {leaked_in_selftest}")

        vector_out = run_vector(backdoored)
        leaked_in_vector = "REDTEAM_BACKDOOR_POC" in vector_out
        print(f"'vector' (dados publicos) confirma o backdoor ativo: {leaked_in_vector}")

        print(
            "\nCONCLUSAO: selftest detecta adulteracao de DADOS verificados por KAT "
            "(a wordlist), mas NAO detecta uma adulteracao de CODIGO que preserva os "
            "valores de retorno testados e so adiciona um efeito colateral (vazamento). "
            "A defesa real e comparar o hash do artefato contra um build reprodutivel "
            "a partir de fonte revisada (make repro), nunca confiar so no selftest."
        )
        ok = detected and passed_anyway and leaked_in_vector
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
