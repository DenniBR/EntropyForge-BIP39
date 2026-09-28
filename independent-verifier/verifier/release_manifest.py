"""Manifesto de release e verificacao `verify-release` (Fase E, requisito
de release verificavel).

Formato do `MANIFEST.txt` (ver `docs/RELEASE_SECURITY_CHECKLIST.md` e
`docs/PLATFORM_SUPPORT.md` para o contexto operacional): texto simples,
uma linha `chave=valor` por campo, ordenado por chave, sempre com um `\n`
final -- o mesmo espirito de determinismo do manifesto de hashing.py.

Campos (nenhum deles e, ou pode se tornar, um segredo -- todos sao
metadados de BUILD, nunca dados de uma geracao real):

  - `software_version`, `protocol_version_a`, `generation_procedure_version`,
    `wordlist_version`, `manifest_format_version`: os cinco numeros de
    `entropyforge/version.py`, lidos como TEXTO por regex (nunca por
    `import entropyforge`, pelo mesmo motivo de `wordlist_check.py`: nao
    depender de que o codigo do EntropyForge esteja correto ou honesto
    para verificar o proprio EntropyForge).
  - `wordlist_sha256`: hash da wordlist embutida (`entropyforge/data/english.txt`).
  - `source_manifest_sha256`: hash do manifesto determinístico (formato de
    `hashing.manifest_to_text`) de todo o pacote `entropyforge/` (`.py` e
    `.txt`).
  - `pyz_sha256`: hash do artefato `.pyz` distribuido.
  - `build_script_sha256`: hash de `tools/build_pyz.py` (o script que
    produziu o `.pyz`).
  - `verifier_source_sha256`: hash do manifesto deterministico do proprio
    `independent-verifier/verifier/` -- um marcador de reprodutibilidade
    (permite duas pessoas confirmarem que estao rodando o MESMO codigo de
    verificador antes de comparar resultados), NAO uma garantia de que o
    verificador em si esta correto (isso e o que a propria suite de testes
    e o mutation testing de `docs/INDEPENDENT_VERIFIER.md` secao 7 cobrem).
  - `executable_sha256` (Fase F): hash do manifesto deterministico de
    TODOS os arquivos do diretorio do executavel standalone (nao so o
    binario principal -- inclui as bibliotecas `.so` empacotadas junto).
    Ao contrario do `.pyz`, o executavel compilado nao tem correspondencia
    byte a byte com o source-tree, entao a UNICA verificacao forte
    possivel e RECONSTRUI-LO a partir do source e comparar hashes -- isso
    e feito por `independent-verifier/verify_executable.py`, nao por
    `verify_release` (que continua rapido e sem depender de `nuitka`).
  - `executable_platform`/`executable_arch` (Fase F): `platform.system()`/
    `platform.machine()` da maquina que construiu o executavel (ex.:
    `Linux`/`x86_64`). Ver docs/PLATFORM_SUPPORT.md e docs/EXECUTABLE_BUILD.md
    para quais combinacoes sao de fato suportadas/verificadas. IMPORTANTE:
    `verify_release` NAO confere estes dois campos comparando contra o SO
    de quem esta verificando (isso so bateria quando build e verificacao
    rodam no mesmo SO) -- em vez disso, le o cabecalho ELF/PE dos proprios
    bytes do binario (`_detect_executable_platform_arch`), o que funciona
    corretamente em qualquer maquina verificadora, para qualquer
    plataforma do artefato.
  - `executable_build_tool` (Fase F): string unica identificando a
    ferramenta de empacotamento e as versoes exatas de Python/gcc usadas
    (ex.: `nuitka-4.2.2+python-3.11.15+gcc-13.3.0`) -- requisito 4 da
    Fase F ("nao assumir que 'Python embutido' e automaticamente
    confiavel": documentar exatamente o que foi usado). Este campo e
    puramente INFORMATIVO em `verify_release`: nao ha como inspecionar o
    binario ja compilado para extrair quais versoes exatas o produziram,
    entao uma divergencia aqui (build numa versao de Python/gcc/Nuitka,
    verificacao noutra) e esperada e nunca reprova o resultado geral.

NUNCA inclua neste manifesto: a mnemonic, a entropia combinada, A, B, uma
seed, ou uma passphrase. Nao ha, hoje, nenhum campo aqui que pudesse
carregar isso -- e deve continuar assim: qualquer novo campo proposto para
este manifesto precisa passar por essa mesma pergunta antes de ser
adicionado.
"""

from __future__ import annotations

import platform
import re
from dataclasses import dataclass, fields
from pathlib import Path

from .bip39_compare import compare_against_official_vectors
from .hashing import build_manifest, hash_bytes, hash_file, manifest_to_text
from .pyz_inspect import check_bootstrap_main, compare_pyz_to_source
from .wordlist_check import check_matches_official_hash, check_wordlist_file

_VERSION_CONST_NAMES = (
    "SOFTWARE_VERSION",
    "PROTOCOL_VERSION_A",
    "GENERATION_PROCEDURE_VERSION",
    "WORDLIST_VERSION",
    "MANIFEST_FORMAT_VERSION",
)

_VERSION_CONST_RE = re.compile(
    r'^(' + "|".join(_VERSION_CONST_NAMES) + r')\s*=\s*"([^"]*)"', re.M
)


class ReleaseManifestError(Exception):
    pass


def read_version_constants(version_py_path: Path) -> dict[str, str]:
    """Le `entropyforge/version.py` como TEXTO BRUTO e extrai os cinco
    valores de versao por regex -- nunca importa o modulo (mesmo
    principio de `wordlist_check.check_wordlist_file`: ler o dado, nao
    confiar na propria interpretacao do EntropyForge dele)."""
    text = version_py_path.read_text(encoding="utf-8")
    values = dict(_VERSION_CONST_RE.findall(text))
    missing = [name for name in _VERSION_CONST_NAMES if name not in values]
    if missing:
        raise ReleaseManifestError(
            f"constantes de versao ausentes ou em formato inesperado em "
            f"{version_py_path}: {missing}"
        )
    return values


@dataclass(frozen=True)
class ReleaseManifest:
    software_version: str
    protocol_version_a: str
    generation_procedure_version: str
    wordlist_version: str
    manifest_format_version: str
    wordlist_sha256: str
    source_manifest_sha256: str
    pyz_sha256: str
    build_script_sha256: str
    verifier_source_sha256: str
    executable_sha256: str
    executable_platform: str
    executable_arch: str
    executable_build_tool: str

    def to_text(self) -> str:
        lines = [f"{f.name}={getattr(self, f.name)}" for f in fields(self)]
        lines.sort()
        return "\n".join(lines) + "\n"


def parse_release_manifest_text(text: str) -> ReleaseManifest:
    values: dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if "=" not in line:
            raise ReleaseManifestError(f"linha {lineno} malformada (esperado 'chave=valor'): {line!r}")
        key, _, value = line.partition("=")
        values[key] = value
    expected_keys = {f.name for f in fields(ReleaseManifest)}
    missing = expected_keys - set(values)
    unexpected = set(values) - expected_keys
    if missing:
        raise ReleaseManifestError(f"campos ausentes no manifesto de release: {sorted(missing)}")
    if unexpected:
        raise ReleaseManifestError(f"campos desconhecidos no manifesto de release: {sorted(unexpected)}")
    return ReleaseManifest(**{k: values[k] for k in expected_keys})


def read_release_manifest(path: Path) -> ReleaseManifest:
    return parse_release_manifest_text(path.read_text(encoding="utf-8"))


def _source_manifest_hash(root: Path, *, include_suffixes: tuple[str, ...]) -> str:
    entries = build_manifest(root, include_suffixes=include_suffixes)
    return hash_bytes(manifest_to_text(entries).encode("utf-8"))


def executable_manifest_hash(dist_dir: Path) -> str:
    """Hash deterministico de TODOS os arquivos do diretorio do
    executavel (binario principal + `.so` empacotados) -- ao contrario do
    `.pyz`, nao ha comparacao byte a byte possivel contra o source (ver
    docstring do modulo)."""
    entries = build_manifest(dist_dir)
    return hash_bytes(manifest_to_text(entries).encode("utf-8"))


def _detect_executable_platform_arch(executable_dist_dir: Path) -> tuple[str, str]:
    """Determina a plataforma/arquitetura REAIS do executavel principal
    lendo os proprios bytes magicos do binario (cabecalho ELF ou PE), em
    vez de perguntar ao SO de quem esta rodando a verificacao.

    Bug corrigido aqui (ver docs/EXECUTABLE_BUILD.md): `verify_release`
    comparava `executable_platform`/`executable_arch` do manifesto contra
    `platform.system()`/`platform.machine()` recalculados na MAQUINA QUE
    VERIFICA -- o que so pode bater, por construcao, quando build e
    verificacao acontecem no mesmo SO. Isso faz a verificacao de um
    executavel Windows (`.exe`) falhar sempre que rodada a partir de
    Linux (e vice-versa), mesmo quando o artefato esta perfeitamente
    integro -- nao e uma falha de seguranca/integridade do artefato, e um
    defeito de desenho do proprio checador. A correcao: inspecionar o
    binario em si (que fisicamente so pode ter um formato: ELF OU PE, nao
    os dois), o que produz uma resposta correta em qualquer maquina
    verificadora, para qualquer plataforma do artefato.

    Os valores retornados usam exatamente a mesma convencao ja gravada
    nos manifestos publicados (nunca normalizados): `("Linux", "x86_64")`
    para ELF x86-64 (igual a `platform.system()`/`platform.machine()`
    nativos do Linux), `("Windows", "AMD64")` para PE amd64 (igual a
    `platform.machine()` nativo do Windows, que reporta "AMD64", nao
    "x86_64") -- ver `tools/build_executable.py:_target_arch()`, que so
    normaliza esse valor para fins de NOMEACAO de diretorio, nunca para o
    manifesto em si.
    """
    main_bin = None
    for name in ("entropyforge-bip39", "entropyforge-bip39.exe"):
        candidate = executable_dist_dir / name
        if candidate.is_file():
            main_bin = candidate
            break
    if main_bin is None:
        raise ReleaseManifestError(
            f"binario principal do executavel nao encontrado em {executable_dist_dir} "
            f"(esperado 'entropyforge-bip39' ou 'entropyforge-bip39.exe')"
        )
    data = main_bin.read_bytes()
    if data[:4] == b"\x7fELF":
        if len(data) < 20:
            raise ReleaseManifestError(f"arquivo ELF truncado (menor que o cabecalho minimo): {main_bin}")
        endian = "little" if data[5] == 1 else "big"
        e_machine = int.from_bytes(data[18:20], endian)
        arch = {0x3E: "x86_64", 0xB7: "aarch64"}.get(e_machine, f"desconhecido(0x{e_machine:x})")
        return "Linux", arch
    if data[:2] == b"MZ":
        if len(data) < 0x40:
            raise ReleaseManifestError(f"arquivo PE truncado (menor que o stub DOS): {main_bin}")
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if len(data) < e_lfanew + 6 or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            raise ReleaseManifestError(f"assinatura PE ausente ou invalida em {main_bin}")
        machine = int.from_bytes(data[e_lfanew + 4 : e_lfanew + 6], "little")
        arch = {0x8664: "AMD64", 0x014C: "x86", 0xAA64: "ARM64"}.get(machine, f"desconhecido(0x{machine:x})")
        return "Windows", arch
    raise ReleaseManifestError(f"formato de binario desconhecido (nem ELF nem PE): {main_bin}")


def build_tool_identifier() -> str:
    """String unica identificando a ferramenta de build e as versoes
    exatas de Python/gcc do AMBIENTE ATUAL -- usada tanto para gravar o
    campo `executable_build_tool` no manifesto quanto, depois, para
    decidir se um rebuild de verificacao esta rodando no mesmo ambiente
    que produziu o release (ver docs/EXECUTABLE_RELEASE_CHECKS.md secao 2
    sobre por que isso importa: reprodutibilidade ENTRE versoes diferentes
    de Python/gcc/Nuitka nao foi testada)."""
    try:
        import nuitka.Version

        nuitka_version = nuitka.Version.getNuitkaVersion()
    except Exception:  # noqa: BLE001
        nuitka_version = "desconhecida"
    python_version = platform.python_version()
    gcc_version = "desconhecida"
    try:
        import subprocess

        out = subprocess.run(["gcc", "-dumpversion"], capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            gcc_version = out.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return f"nuitka-{nuitka_version}+python-{python_version}+gcc-{gcc_version}"


def compute_release_manifest(
    *,
    entropyforge_root: Path,
    pyz_path: Path,
    verifier_root: Path,
    build_script_path: Path,
    executable_dist_dir: Path,
) -> ReleaseManifest:
    """Recalcula, do zero, TODOS os campos do manifesto de release a
    partir dos arquivos reais em disco -- nunca a partir de um manifesto
    ja existente. Esta e a unica funcao deste modulo que produz um
    `ReleaseManifest` "de confianca"; `verify_release` sempre chama esta
    funcao e compara o resultado contra o manifesto fornecido, nunca o
    contrario."""
    versions = read_version_constants(entropyforge_root / "version.py")
    wordlist_report = check_wordlist_file(entropyforge_root / "data" / "english.txt")
    return ReleaseManifest(
        software_version=versions["SOFTWARE_VERSION"],
        protocol_version_a=versions["PROTOCOL_VERSION_A"],
        generation_procedure_version=versions["GENERATION_PROCEDURE_VERSION"],
        wordlist_version=versions["WORDLIST_VERSION"],
        manifest_format_version=versions["MANIFEST_FORMAT_VERSION"],
        wordlist_sha256=wordlist_report.sha256,
        source_manifest_sha256=_source_manifest_hash(entropyforge_root, include_suffixes=(".py", ".txt")),
        pyz_sha256=hash_file(pyz_path),
        build_script_sha256=hash_file(build_script_path),
        verifier_source_sha256=_source_manifest_hash(verifier_root, include_suffixes=(".py",)),
        executable_sha256=executable_manifest_hash(executable_dist_dir),
        executable_platform=platform.system(),
        executable_arch=platform.machine(),
        executable_build_tool=build_tool_identifier(),
    )


@dataclass(frozen=True)
class ReleaseCheck:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class ReleaseVerification:
    checks: tuple[ReleaseCheck, ...]

    @property
    def passed(self) -> bool:
        return all(c.ok for c in self.checks)

    def format_report(self) -> str:
        lines = [f"[{'PASS' if c.ok else 'FAIL'}] {c.name}: {c.detail}" for c in self.checks]
        lines.append(f"RESULTADO GERAL: {'PASS' if self.passed else 'FAIL'}")
        return "\n".join(lines)


def verify_release(
    manifest: ReleaseManifest,
    *,
    entropyforge_root: Path,
    pyz_path: Path,
    verifier_root: Path,
    build_script_path: Path,
    official_vectors_path: Path,
    executable_dist_dir: Path,
) -> ReleaseVerification:
    """Verificacao completa de um release, combinando todos os controles
    independentes ja existentes neste projeto. NUNCA confia em nenhum
    valor do `manifest` fornecido: cada campo dele e comparado contra um
    valor recalculado do zero a partir dos arquivos reais.

    IMPORTANTE (ver docs/INDEPENDENT_VERIFIER.md secao 6): isto so tem
    valor se `manifest` vier de um canal INDEPENDENTE do artefato sob
    teste (ex.: publicado separadamente, conferido com outra pessoa) --
    comparar um artefato adulterado contra um manifesto gerado a partir do
    MESMO artefato adulterado nunca prova nada.
    """
    checks: list[ReleaseCheck] = []

    recomputed = compute_release_manifest(
        entropyforge_root=entropyforge_root,
        pyz_path=pyz_path,
        verifier_root=verifier_root,
        build_script_path=build_script_path,
        executable_dist_dir=executable_dist_dir,
    )

    # `executable_platform`/`executable_arch`/`executable_build_tool` NAO
    # podem ser conferidos comparando contra `recomputed` (valores da
    # maquina que esta VERIFICANDO agora) -- isso so bateria, por
    # construcao, quando quem verifica usa o mesmo SO/versoes exatas de
    # quem fez o build, o que nunca e garantido nem exigido (ver
    # docs/EXECUTABLE_BUILD.md e a docstring de
    # `_detect_executable_platform_arch`). `executable_platform`/
    # `executable_arch` SAO verificaveis de forma independente do
    # ambiente de quem verifica: lendo o cabecalho ELF/PE do proprio
    # binario. `executable_build_tool` nao tem equivalente -- nao ha como
    # extrair do binario compilado quais versoes exatas de Nuitka/Python/
    # gcc o produziram -- entao fica como campo INFORMATIVO apenas (nunca
    # reprova o resultado geral), permitindo transparencia sem falsos
    # negativos entre ambientes de build/verificacao legitimamente
    # diferentes.
    try:
        detected_platform, detected_arch = _detect_executable_platform_arch(executable_dist_dir)
        detection_error: str | None = None
    except ReleaseManifestError as exc:
        detected_platform = detected_arch = None
        detection_error = str(exc)

    for f in fields(ReleaseManifest):
        expected = getattr(manifest, f.name)

        if f.name == "executable_build_tool":
            actual = getattr(recomputed, f.name)
            matches_this_machine = expected == actual
            detail = (
                "informativo apenas (nao afeta o resultado geral); "
                + (
                    "bate com a ferramenta/versoes da maquina que esta verificando agora"
                    if matches_this_machine
                    else f"manifesto={expected!r} maquina_que_verifica={actual!r} -- "
                    "divergencia esperada e inofensiva quando build e verificacao usam "
                    "versoes diferentes de Python/gcc/Nuitka; NAO indica adulteracao"
                )
            )
            checks.append(ReleaseCheck(name=f"manifesto.{f.name}", ok=True, detail=detail))
            continue

        if f.name in ("executable_platform", "executable_arch"):
            if detection_error is not None:
                checks.append(
                    ReleaseCheck(
                        name=f"manifesto.{f.name}",
                        ok=False,
                        detail=f"nao foi possivel inspecionar o binario para conferir: {detection_error}",
                    )
                )
                continue
            detected = detected_platform if f.name == "executable_platform" else detected_arch
            ok = expected == detected
            detail = (
                f"manifesto={expected!r} detectado_nos_bytes_do_binario={detected!r}"
                if not ok
                else "bate com o valor detectado nos proprios bytes (cabecalho ELF/PE) do "
                "binario -- verificacao independente do SO/maquina de quem verifica"
            )
            checks.append(ReleaseCheck(name=f"manifesto.{f.name}", ok=ok, detail=detail))
            continue

        actual = getattr(recomputed, f.name)
        ok = expected == actual
        detail = (
            f"manifesto={expected!r} recalculado={actual!r}"
            if not ok
            else "bate com o valor recalculado de forma independente"
        )
        checks.append(ReleaseCheck(name=f"manifesto.{f.name}", ok=ok, detail=detail))

    wordlist_report = check_wordlist_file(entropyforge_root / "data" / "english.txt")
    checks.append(
        ReleaseCheck(
            name="wordlist.estrutura",
            ok=wordlist_report.ok,
            detail="sem problemas estruturais" if wordlist_report.ok else "; ".join(wordlist_report.problems),
        )
    )
    hash_ok, hash_detail = check_matches_official_hash(wordlist_report)
    checks.append(ReleaseCheck(name="wordlist.hash_oficial", ok=hash_ok, detail=hash_detail))

    pyz_cmp = compare_pyz_to_source(pyz_path, entropyforge_root)
    checks.append(
        ReleaseCheck(
            name="pyz.conteudo_vs_source",
            ok=pyz_cmp.ok,
            detail=(
                "todos os arquivos batem byte a byte"
                if pyz_cmp.ok
                else (
                    f"divergencias={pyz_cmp.content_mismatches} "
                    f"faltando={pyz_cmp.missing_from_pyz} "
                    f"inesperados={pyz_cmp.unexpected_in_pyz}"
                )
            ),
        )
    )
    bootstrap_ok, bootstrap_detail = check_bootstrap_main(pyz_path)
    checks.append(ReleaseCheck(name="pyz.bootstrap_main", ok=bootstrap_ok, detail=bootstrap_detail))

    vectors_cmp = compare_against_official_vectors(entropyforge_root, official_vectors_path)
    checks.append(
        ReleaseCheck(
            name="bip39.vetores_oficiais",
            ok=vectors_cmp.ok,
            detail=(
                f"{vectors_cmp.total_checked} vetores, 0 divergencias"
                if vectors_cmp.ok
                else (
                    f"import_error={vectors_cmp.entropyforge_import_error}; "
                    f"divergencias={vectors_cmp.mismatches[:5]}"
                )
            ),
        )
    )

    return ReleaseVerification(checks=tuple(checks))
