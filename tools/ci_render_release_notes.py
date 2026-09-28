#!/usr/bin/env python3
"""Renderiza o corpo (markdown) de uma GitHub Release a partir dos
hashes reais ja calculados por `tools/ci_package_assets.py`
(`SHA256SUMS.txt` no diretorio de assets) -- nunca hashes inventados ou
copiados de uma execucao anterior. So biblioteca padrao.

Uso:
    python3 tools/ci_render_release_notes.py \\
        --tag v1.0.0 --commit <sha> --assets-dir release_assets --out RELEASE_NOTES.md
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--assets-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def _read_sha256sums(path: Path) -> dict[str, str]:
    hashes = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, name = line.split("  ", 1)
        hashes[name] = digest
    return hashes


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    sums_path = args.assets_dir / "SHA256SUMS.txt"
    if not sums_path.is_file():
        print(f"erro: {sums_path} nao encontrado -- rode ci_package_assets.py antes", file=sys.stderr)
        return 1
    hashes = _read_sha256sums(sums_path)

    def h(name: str) -> str:
        return hashes.get(name, "(hash nao encontrado)")

    linux_tar = next((n for n in hashes if n.endswith("-linux-x86_64.tar.gz")), "entropyforge-bip39-linux-x86_64.tar.gz")
    windows_zip = next((n for n in hashes if n.endswith("-windows-x86_64.zip")), "entropyforge-bip39-windows-x86_64.zip")

    body = f"""\
# EntropyForge-BIP39 {args.tag}

Release com os artefatos prontos para uso (executáveis + `.pyz`) e tudo
o que é necessário para verificar a autenticidade e a integridade deles
antes de usar — ver `docs/VERIFY.md` e `docs/QUICK_START.md` no
repositório para o passo a passo completo.

**Nenhuma alegação de segurança absoluta**: este projeto nunca afirma
que a seed gerada é "inquebrável" ou "impossível de recuperar" — ver
`docs/THREAT_MODEL.md`.

- **Commit:** `{args.commit}`
- **Como cada artefato foi construído:** ver `docs/EXECUTABLE_BUILD.md`
  (Nuitka `--standalone`, nunca `--onefile` — motivo documentado com
  evidência de `strace`). O executável Windows foi construído e testado
  num runner `windows-latest` real do GitHub Actions (Windows de
  verdade, não emulação) durante este mesmo workflow — não é um arquivo
  renomeado nem um placeholder.

## Assets desta release

| Arquivo | SHA-256 |
|---|---|
| `{linux_tar}` | `{h(linux_tar)}` |
| `{windows_zip}` | `{h(windows_zip)}` |
| `entropyforge.pyz` | `{h('entropyforge.pyz')}` |
| `MANIFEST-linux-x86_64.txt` | `{h('MANIFEST-linux-x86_64.txt')}` |
| `MANIFEST-windows-x86_64.txt` | `{h('MANIFEST-windows-x86_64.txt')}` |
| `independent-verifier-bundle.zip` | `{h('independent-verifier-bundle.zip')}` |
| `SHA256SUMS.txt` | (lista todos os hashes acima; verifique-o contra este corpo da release, publicado por um canal diferente do arquivo) |

Cada arquivo acima também tem um `<nome>.sha256` individual publicado
junto, no mesmo formato aceito por `sha256sum -c`.

## Como verificar (resumo — ver `docs/VERIFY.md` para o completo)

```sh
# 1. confira a integridade de tudo que você baixou (mesma pasta):
sha256sum -c SHA256SUMS.txt

# 2. extraia o executável da sua plataforma:
tar xzf {linux_tar}          # Linux
# ou: unzip {windows_zip}    # Windows

# 3. rode o self-test do binário (sem gerar nada real ainda):
./{linux_tar[:-7]}/entropyforge-bip39 --version
./{linux_tar[:-7]}/entropyforge-bip39 selftest

# 4. checagem FORTE (requer git clone do repositório + nuitka/gcc):
python3 independent-verifier/verify_executable.py \\
  --manifest MANIFEST-linux-x86_64.txt \\
  --entropyforge-root entropyforge \\
  --executable-dist ./{linux_tar[:-7]} \\
  --verbose
```

## Testes executados neste workflow antes de publicar

- Suíte principal (`tests/`) e suíte do `independent-verifier/`: **todas
  passando** (job `test`), nos dois sistemas operacionais de build.
- `verify-release` (checagem rápida) e `verify-executable` (checagem
  FORTE — reconstrói o executável a partir do source e compara o hash):
  **`PASS` em Linux E em Windows**, cada um rodado no seu próprio job/SO.
- Smoke test (`--version`, `selftest`, `vector` com dados públicos de
  teste) do binário recém-construído, em ambas as plataformas, incluindo
  uma segunda passada **depois** de empacotar o `.tar.gz` do Linux (para
  confirmar que o empacotamento não corrompeu nada).

## Limitações conhecidas (sem disfarce)

- **Nenhum dos dois artefatos é assinado digitalmente** (Authenticode/GPG)
  — avaliado, documentado como etapa externa e manual em
  `docs/EXECUTABLE_RELEASE_CHECKS.md` seção 6. A verificação por hash
  acima é o mecanismo real de integridade hoje.
- O executável não tem correspondência byte a byte com o source (ao
  contrário do `.pyz`) — a checagem FORTE (`verify_executable.py`)
  reconstrói e compara hashes, e exige `nuitka`+um compilador C no
  ambiente de quem verifica.
- Reprodutibilidade do executável entre versões diferentes de
  Python/gcc/MSVC/Nuitka não foi testada neste workflow (só a cadeia de
  ferramentas dos runners `ubuntu-latest`/`windows-latest` usados aqui).
"""
    args.out.write_text(body, encoding="utf-8")
    print(f"notas da release escritas em: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
