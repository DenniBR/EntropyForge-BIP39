#!/usr/bin/env python3
"""Fase D, secao 11: ataque ao build -- reprodutibilidade atraves de
timestamp/ambiente/diretorio/locale/timezone/umask/versao de Python/
sistema de arquivos, seguido de deteccao de alteracao (1 byte, 1 modulo,
metadata, wordlist, ordem de arquivos, build script).
"""
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
BUILD_SCRIPT = REPO_ROOT / "tools" / "build_pyz.py"


def build(python_exe, out_path, env_overrides=None, cwd=None, umask=None):
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    preexec = None
    if umask is not None:
        def preexec():
            os.umask(umask)
    subprocess.run(
        [python_exe, str(BUILD_SCRIPT), str(out_path)],
        check=True, capture_output=True, text=True, env=env,
        cwd=str(cwd) if cwd else None, preexec_fn=preexec,
    )
    return hashlib.sha256(out_path.read_bytes()).hexdigest(), out_path.stat().st_size


tmp = Path(tempfile.mkdtemp(prefix="pd_build_"))
baseline_out = tmp / "baseline.pyz"
baseline_hash, baseline_size = build(sys.executable, baseline_out)
print(f"baseline: {baseline_hash} ({baseline_size} bytes)\n")

results = []


def check(label, python_exe=sys.executable, env=None, cwd=None, umask=None):
    out = tmp / (label.replace(" ", "_").replace("/", "_") + ".pyz")
    try:
        h, size = build(python_exe, out, env_overrides=env, cwd=cwd, umask=umask)
        ok = (h == baseline_hash)
        results.append((label, ok, h))
        print(f"{'OK  ' if ok else 'DIFF'} {label:45s} hash={h[:16]}...")
    except Exception as exc:
        results.append((label, None, str(exc)))
        print(f"ERRO {label:45s} {exc}")


print("=== Variacoes de AMBIENTE (devem dar o MESMO hash) ===")
check("timezone UTC", env={"TZ": "UTC"})
check("timezone America/Sao_Paulo", env={"TZ": "America/Sao_Paulo"})
check("timezone Asia/Tokyo", env={"TZ": "Asia/Tokyo"})
check("locale C", env={"LC_ALL": "C", "LANG": "C"})
check("locale C.utf8", env={"LC_ALL": "C.utf8", "LANG": "C.utf8"})
check("umask 022", umask=0o022)
check("umask 077", umask=0o077)
check("umask 000", umask=0o000)
check("diretorio de trabalho diferente (cwd=/tmp)", cwd=Path("/tmp"))
check("PYTHONHASHSEED=0", env={"PYTHONHASHSEED": "0"})
check("PYTHONHASHSEED=random-ish (42)", env={"PYTHONHASHSEED": "42"})

# filesystem diferente: builda a SAIDA em tmpfs (/dev/shm) em vez do
# filesystem normal (a ENTRADA -- o source-tree -- e sempre a mesma)
shm_out = Path("/dev/shm") / f"pd_build_shm_{os.getpid()}.pyz"
try:
    h, size = build(sys.executable, shm_out)
    ok = (h == baseline_hash)
    results.append(("saida em tmpfs (/dev/shm)", ok, h))
    print(f"{'OK  ' if ok else 'DIFF'} {'saida em tmpfs (/dev/shm)':45s} hash={h[:16]}...")
finally:
    shm_out.unlink(missing_ok=True)

print("\n=== Variacoes de VERSAO do PYTHON (devem dar o MESMO hash) ===")
for exe in ("python3.10", "python3.11", "python3.12", "python3.13"):
    import shutil as _sh
    path = _sh.which(exe)
    if path:
        check(f"interpretador {exe}", python_exe=path)
    else:
        print(f"(pulado: {exe} nao encontrado)")

print("\n=== RESUMO DE REPRODUTIBILIDADE ===")
divergent = [r for r in results if r[1] is False]
errored = [r for r in results if r[1] is None]
print(f"{len(results) - len(divergent) - len(errored)}/{len(results)} variacoes deram o MESMO hash do baseline.")
if divergent:
    print("DIVERGENCIAS ENCONTRADAS (build NAO reprodutivel nessas condicoes):")
    for label, _, h in divergent:
        print(f"  - {label}: {h[:16]}...")
if errored:
    print("ERROS (nao foi possivel testar):")
    for label, _, msg in errored:
        print(f"  - {label}: {msg}")
