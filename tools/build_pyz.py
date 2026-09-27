#!/usr/bin/env python3
"""Build determinístico do artefato `entropyforge.pyz` (requisito 15).

Constrói o zipapp manualmente (em vez de usar `zipapp.create_archive`
diretamente) para controlar cada byte que afeta o hash do arquivo final:

  - ordem dos arquivos: sempre a mesma (sorted por caminho relativo);
  - timestamp de cada entrada: fixo em 1980-01-01 (o minimo representavel
    no formato ZIP), para nao depender da data em que o build rodou nem
    dos mtimes dos arquivos no disco;
  - permissoes de cada entrada: fixas (0644 para arquivos);
  - compressao: ZIP_STORED (sem compressao), para nao depender da versao
    da biblioteca zlib do sistema que fez o build;
  - shebang fixo, para o arquivo rodar diretamente em sistemas POSIX
    (`chmod +x entropyforge.pyz && ./entropyforge.pyz generate`).

Resultado: o MESMO SHA-256 para o artefato, gerado por qualquer maquina
com Python >= 3.11, independentemente de fuso horario, mtimes dos
arquivos-fonte, ou versao do zlib. Ver `make repro` (Makefile) e
docs/AUDIT.md para o procedimento de verificacao.

O artefato inclui SOMENTE o que e necessario para rodar o programa: o
pacote `entropyforge/` e a wordlist `data/english.txt`. NAO inclui
`tests/`, `tools/` nem `docs/` -- manter o artefato minimo e parte do
objetivo de auditabilidade (requisito 12).
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)
SHEBANG = b"#!/usr/bin/env python3\n"

TOP_LEVEL_MAIN = '''"""Ponto de entrada do artefato .pyz (gerado por tools/build_pyz.py)."""
import sys
from entropyforge.__main__ import run

if __name__ == "__main__":
    sys.exit(run())
'''


def _collect_files() -> list[tuple[str, bytes]]:
    """Devolve [(caminho_no_zip, conteudo)], em ordem determinística."""
    files: dict[str, bytes] = {}

    pkg_dir = REPO_ROOT / "entropyforge"
    for path in pkg_dir.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        files[rel] = path.read_bytes()

    wordlist_path = pkg_dir / "data" / "english.txt"
    files["entropyforge/data/english.txt"] = wordlist_path.read_bytes()

    files["__main__.py"] = TOP_LEVEL_MAIN.encode("utf-8")

    return sorted(files.items())


def build(output_path: Path) -> bytes:
    entries = _collect_files()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_STORED) as zf:
        for rel_path, data in entries:
            info = zipfile.ZipInfo(rel_path, date_time=FIXED_DATE_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.create_system = 3  # unix, fixo (independe do SO que builda)
            zf.writestr(info, data)

    result = SHEBANG + buf.getvalue()
    output_path.write_bytes(result)
    os.chmod(output_path, 0o755)
    return result


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "entropyforge.pyz"
    data = build(out)
    digest = hashlib.sha256(data).hexdigest()
    print(f"{out}: {len(data)} bytes, sha256={digest}")
    (out.parent / "SHA256SUMS").write_text(f"{digest}  {out.name}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
