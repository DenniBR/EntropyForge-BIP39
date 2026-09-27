#!/usr/bin/env python3
"""Fase D, secao 9: ataques de ambiente Python hostil, contra AMBAS as
formas de invocacao (source sem -I, .pyz com -I -B).

Vetores testados: PYTHONPATH (modulo shadow: os.py, getpass.py,
argparse.py), .pth malicioso em user-site (via PYTHONUSERBASE isolado,
nunca toca o site-packages real desta sessao), sitecustomize.py,
usercustomize.py, PYTHONHOME bogus.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
MARKER = "###LAB_HOSTILE_ENV_MARKER###"


def build_pyz(out_path: Path) -> None:
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import build_pyz
    build_pyz.build(out_path)


def run(cmd, cwd, env_extra):
    env = os.environ.copy()
    env.update(env_extra)
    proc = subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=20)
    return proc.stdout + proc.stderr


def marker_present(output: str) -> bool:
    return MARKER in output


def main():
    tmp = Path(tempfile.mkdtemp(prefix="pd_hostile_"))
    pyz = tmp / "entropyforge.pyz"
    build_pyz(pyz)

    modes = {
        "pyz -I -B (uso real)": ([sys.executable, "-I", "-B", str(pyz), "selftest"], {}),
        "source -B -m entropyforge, SEM -I (dev)": (
            [sys.executable, "-B", "-m", "entropyforge", "selftest"],
            {"PYTHONPATH": str(REPO_ROOT)},
        ),
    }

    results = []

    # --- vetor 1: shadow de modulos stdlib via PYTHONPATH/cwd ---------
    for shadow_name in ("os.py", "getpass.py", "argparse.py", "hashlib.py"):
        work = tmp / f"shadow_{shadow_name}"
        work.mkdir(exist_ok=True)
        (work / shadow_name).write_text(f'print("{MARKER}:{shadow_name}")\n')
        for label, (cmd, env_extra) in modes.items():
            out = run(cmd, work, env_extra)
            hit = marker_present(out)
            results.append((f"shadow {shadow_name}", label, hit))

    # --- vetor 2: .pth malicioso em user-site (PYTHONUSERBASE isolado) --
    fakebase = tmp / "fakebase"
    site_dir = fakebase / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / "zzz_lab.pth").write_text(f'import sys; sys.stderr.write("{MARKER}:pth\\n")\n')
    for label, (cmd, env_extra) in modes.items():
        env2 = dict(env_extra)
        env2["PYTHONUSERBASE"] = str(fakebase)
        out = run(cmd, tmp, env2)
        hit = marker_present(out)
        results.append((".pth malicioso (user-site)", label, hit))

    # --- vetor 3: sitecustomize.py / usercustomize.py em user-site ------
    (site_dir / "sitecustomize.py").write_text(f'print("{MARKER}:sitecustomize")\n')
    (site_dir / "usercustomize.py").write_text(f'print("{MARKER}:usercustomize")\n')
    for label, (cmd, env_extra) in modes.items():
        env2 = dict(env_extra)
        env2["PYTHONUSERBASE"] = str(fakebase)
        out = run(cmd, tmp, env2)
        hit = marker_present(out)
        results.append(("sitecustomize+usercustomize (user-site)", label, hit))
    (site_dir / "zzz_lab.pth").unlink()
    (site_dir / "sitecustomize.py").unlink()
    (site_dir / "usercustomize.py").unlink()

    # --- vetor 4: sitecustomize.py direto no cwd (sem user-site) --------
    work4 = tmp / "sitecustomize_cwd"
    work4.mkdir(exist_ok=True)
    (work4 / "sitecustomize.py").write_text(f'print("{MARKER}:sitecustomize_cwd")\n')
    for label, (cmd, env_extra) in modes.items():
        out = run(cmd, work4, env_extra)
        hit = marker_present(out)
        results.append(("sitecustomize.py no cwd", label, hit))

    # --- vetor 5: PYTHONHOME bogus (redireciona a stdlib inteira) -------
    bogus_home = tmp / "bogus_home"
    bogus_home.mkdir(exist_ok=True)
    for label, (cmd, env_extra) in modes.items():
        env2 = dict(env_extra)
        env2["PYTHONHOME"] = str(bogus_home)
        try:
            out = run(cmd, tmp, env2)
        except subprocess.TimeoutExpired:
            out = "(timeout)"
        crashed = "Traceback" in out or "Fatal Python error" in out or "ModuleNotFoundError" in out or "ImportError" in out
        results.append(("PYTHONHOME bogus", label, f"crashou_ou_falhou={crashed}"))

    # --- vetor 6: import hook malicioso via PYTHONSTARTUP (so afeta REPL
    # interativo, nao scripts/-m -- testado para documentar que NAO se
    # aplica aqui) ---------------------------------------------------
    startup = tmp / "malicious_startup.py"
    startup.write_text(f'print("{MARKER}:pythonstartup")\n')
    for label, (cmd, env_extra) in modes.items():
        env2 = dict(env_extra)
        env2["PYTHONSTARTUP"] = str(startup)
        out = run(cmd, tmp, env2)
        hit = marker_present(out)
        results.append(("PYTHONSTARTUP (so afeta REPL, esperado NAO ativar)", label, hit))

    print("=== RESULTADOS (True/hit = codigo externo executou) ===")
    for vector, label, hit in results:
        print(f"{vector:55s} | {label:42s} | {hit}")

    print()
    vulnerable_pyz = [r for r in results if "pyz" in r[1] and r[2] is True]
    vulnerable_source = [r for r in results if "source" in r[1] and r[2] is True]
    print(f"Vetores que afetaram o .pyz (-I -B):    {len(vulnerable_pyz)} -> {[r[0] for r in vulnerable_pyz]}")
    print(f"Vetores que afetaram o source (sem -I): {len(vulnerable_source)} -> {[r[0] for r in vulnerable_source]}")

    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
