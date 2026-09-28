#!/usr/bin/env python3
"""Build do executável standalone (Nuitka, Fase F). Ver
docs/EXECUTABLE_BUILD.md para a justificativa completa da escolha de
ferramenta (Nuitka `--standalone`, não `--onefile`) e das exclusões de
módulo abaixo.

Dependência de BUILD (nunca de runtime): o pacote `nuitka` (compila
Python -> C -> binário usando o compilador C já presente no sistema --
`gcc`/`cc` em Linux, MSVC ou MinGW64 em Windows) e, em Linux, `patchelf`
(usado internamente pelo Nuitka para corrigir o RPATH dos `.so`
copiados). Nenhuma delas é importada por `entropyforge/` em tempo de
execução -- confirmado por `tests/test_security_ast.py`. Instale num
ambiente de build separado: `pip install nuitka patchelf` (este último
só necessário/aplicável em Linux, se `patchelf` não estiver já no PATH).

Uso:
    python3 tools/build_executable.py [--output-dir DIR]

Produz `DIR/entropyforge-bip39-vX.Y.Z-<plataforma>-<arch>/`, um
diretório autocontido (Nuitka `--standalone` não gera um único arquivo
-- ver docs/EXECUTABLE_BUILD.md seção 1 sobre por que `--onefile` foi
descartado: ele escreve em disco, em `/tmp` ou no `%TEMP%`, a cada
execução). Roda em qualquer sistema operacional suportado pelo Nuitka
`--standalone` (testado em Linux x86_64 e Windows x86_64 -- Fase F/G;
ver docs/EXECUTABLE_BUILD.md seção 8 para o que foi de fato verificado
em cada plataforma). O binário final chama-se `entropyforge-bip39` em
Linux/macOS e `entropyforge-bip39.exe` em Windows -- a única diferença
específica de plataforma neste script; nenhuma linha de
`entropyforge/` muda entre plataformas."""

from __future__ import annotations

import hashlib
import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENTRY_SCRIPT = REPO_ROOT / "tools" / "executable_entry.py"
WORDLIST_PATH = REPO_ROOT / "entropyforge" / "data" / "english.txt"

# Módulos explicitamente excluídos do bundle -- ver docs/EXECUTABLE_BUILD.md
# seção 3 (remoção do OpenSSL: `hashlib` cai para o `_sha256` embutido no
# próprio interpretador, que produz resultado IDÊNTICO e remove uma
# biblioteca externa grande e complexa da superfície do executável).
# `entropyforge/` nunca importa nenhum destes três diretamente -- a
# inclusão viria só da tentativa opcional (`try: import _hashlib`) dentro
# do próprio `hashlib.py` da biblioteca padrão, que o Nuitka detecta
# estaticamente por precaução.
EXCLUDED_MODULES = ("_hashlib", "ssl", "_ssl")

# Nomes que NUNCA devem aparecer no executável final -- checagem de
# sanidade pós-build, independente da lista de exclusão acima (defesa em
# profundidade: se a lista de flags mudar no futuro e alguém esquecer de
# atualizar isto, o build falha de forma barulhenta em vez de distribuir
# OpenSSL silenciosamente).
FORBIDDEN_NAME_FRAGMENTS = ("crypto", "ssl", "hashlib")


class ExecutableBuildError(RuntimeError):
    pass


def _check_prereqs() -> None:
    try:
        import nuitka  # noqa: F401
    except ImportError as exc:
        raise ExecutableBuildError(
            "o pacote 'nuitka' não está instalado neste interpretador "
            "(dependência de BUILD, nunca de runtime -- 'pip install nuitka' "
            "num ambiente de build separado, nunca no artefato distribuído). "
            "Ver docs/EXECUTABLE_BUILD.md."
        ) from exc
    if platform.system() == "Windows":
        # Nuitka no Windows detecta/usa o MSVC ja instalado (ex.: os
        # runners `windows-latest` do GitHub Actions ja tem o Build Tools
        # do Visual Studio) ou baixa um MinGW64 privado sozinho -- nao ha
        # um binario fixo tipo 'gcc'/'cc' para checar aqui de antemao;
        # se nenhum compilador estiver de fato disponivel, o proprio
        # `python -m nuitka` abaixo falha com uma mensagem clara.
        return
    if shutil.which("gcc") is None and shutil.which("cc") is None:
        raise ExecutableBuildError(
            "nenhum compilador C ('gcc'/'cc') encontrado no PATH; necessário "
            "para o Nuitka compilar o C gerado. Ver docs/EXECUTABLE_BUILD.md."
        )


def _software_version() -> str:
    sys.path.insert(0, str(REPO_ROOT))
    from entropyforge import version

    return version.SOFTWARE_VERSION


def _target_arch() -> str:
    return platform.machine().lower().replace("amd64", "x86_64")


def _target_platform() -> str:
    return platform.system().lower()  # "linux", "windows", "darwin"


def _main_binary_name() -> str:
    return "entropyforge-bip39.exe" if platform.system() == "Windows" else "entropyforge-bip39"


def build(output_dir: Path, *, source_root: Path = REPO_ROOT) -> Path:
    """Constrói o executável e devolve o caminho do diretório final
    (`<output_dir>/entropyforge-bip39-vX.Y.Z-<plataforma>-<arch>/`).

    `source_root` (Fase F, laboratorio de backdoor do pipeline de build --
    ver `redteam/independent/scripts/run_executable_backdoor_lab.py`): o
    diretorio que deve conter o `entropyforge/` a ser empacotado. O default
    e o proprio repositorio; um valor diferente permite construir a partir
    de uma copia adulterada de `entropyforge/` SEM tocar no repositorio
    real, exatamente como um build "de verdade" faria se apontado para uma
    arvore de source diferente. A resolucao funciona porque `python -m
    nuitka` adiciona o diretorio de trabalho (`cwd`) ao inicio de
    `sys.path` (mesma regra do `-m` do proprio Python) -- e' esse `cwd`,
    nao o caminho do script de entrada, que decide qual `entropyforge/' e'
    de fato compilado."""
    _check_prereqs()
    if (platform.system(), _target_arch()) not in (("Linux", "x86_64"), ("Windows", "x86_64")):
        print(
            f"AVISO: build não verificado nesta plataforma "
            f"({platform.system()}/{platform.machine()}) -- este projeto só "
            "testou Linux x86_64 e Windows x86_64 (ver docs/EXECUTABLE_BUILD.md "
            "seção 8).",
            file=sys.stderr,
        )

    build_root = output_dir / "_nuitka_build"
    if build_root.exists():
        shutil.rmtree(build_root)
    build_root.mkdir(parents=True)

    wordlist_path = source_root / "entropyforge" / "data" / "english.txt"
    cmd = [
        sys.executable,
        "-m",
        "nuitka",
        "--standalone",
        "--include-package=entropyforge",
        f"--include-data-files={wordlist_path}=entropyforge/data/english.txt",
        *(f"--nofollow-import-to={m}" for m in EXCLUDED_MODULES),
        f"--output-dir={build_root}",
        # so' no Windows: deixa o Nuitka baixar sozinho um MinGW64 privado
        # se nenhum MSVC for detectado, em vez de travar esperando
        # confirmacao interativa (nao existe em CI). Sem efeito em
        # Linux/macOS (gcc/cc ja presentes, nenhum download necessario) --
        # nunca adicionado la, para nao arriscar mudar em nada a linha de
        # comando ja usada para provar reprodutibilidade na Fase F.
        *(["--assume-yes-for-downloads"] if platform.system() == "Windows" else []),
        str(ENTRY_SCRIPT),
    ]
    print("rodando:", " ".join(cmd))
    subprocess.run(cmd, cwd=str(source_root), check=True)

    dist_dir = build_root / "executable_entry.dist"
    if not dist_dir.exists():
        raise ExecutableBuildError(
            f"diretório de saída esperado do Nuitka não encontrado: {dist_dir} "
            f"(conteúdo de {build_root}: {sorted(p.name for p in build_root.iterdir())})"
        )

    # Nuitka nomeia o binario principal 'executable_entry.exe' no Windows
    # e 'executable_entry.bin' em Linux/macOS (mesmo script de entrada,
    # extensao dependente do SO).
    nuitka_bin_name = "executable_entry.exe" if platform.system() == "Windows" else "executable_entry.bin"
    main_bin = dist_dir / nuitka_bin_name
    if not main_bin.exists():
        raise ExecutableBuildError(f"binário principal esperado não encontrado: {main_bin}")
    final_bin_name = _main_binary_name()
    (dist_dir / final_bin_name).write_bytes(b"")  # garante que o rename abaixo nao colide
    (dist_dir / final_bin_name).unlink()
    main_bin.rename(dist_dir / final_bin_name)

    final_name = f"entropyforge-bip39-v{_software_version()}-{_target_platform()}-{_target_arch()}"
    final_dir = output_dir / final_name
    if final_dir.exists():
        shutil.rmtree(final_dir)
    shutil.move(str(dist_dir), str(final_dir))
    shutil.rmtree(build_root, ignore_errors=True)

    _assert_no_forbidden_files(final_dir)
    _assert_no_dev_only_content(final_dir)
    return final_dir


def _assert_no_forbidden_files(dist_dir: Path) -> None:
    problems = [
        str(p)
        for p in dist_dir.rglob("*")
        if any(frag in p.name.lower() for frag in FORBIDDEN_NAME_FRAGMENTS)
    ]
    if problems:
        raise ExecutableBuildError(
            f"arquivos que deveriam ter sido excluídos apareceram no executável: {problems}"
        )


def _assert_no_dev_only_content(dist_dir: Path) -> None:
    """`--include-package=entropyforge` nunca deveria trazer `tests/`,
    `redteam/`, ou `independent-verifier/` -- checagem de sanidade, não
    porque isso já tenha acontecido."""
    forbidden_dirs = ("tests", "redteam", "independent-verifier", "independent_verifier")
    problems = [
        str(p)
        for p in dist_dir.rglob("*")
        if p.is_dir() and p.name.lower() in forbidden_dirs
    ]
    if problems:
        raise ExecutableBuildError(f"diretórios de desenvolvimento vazaram para o executável: {problems}")


def main() -> int:
    output_dir = REPO_ROOT / "dist_executable"
    if len(sys.argv) > 2 and sys.argv[1] == "--output-dir":
        output_dir = Path(sys.argv[2])
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        final_dir = build(output_dir)
    except ExecutableBuildError as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 1

    main_bin = final_dir / _main_binary_name()
    digest = hashlib.sha256(main_bin.read_bytes()).hexdigest()
    print(f"executável construído em: {final_dir}")
    print(f"binário principal       : {main_bin}")
    print(f"sha256(binário principal): {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
