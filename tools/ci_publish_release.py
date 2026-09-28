#!/usr/bin/env python3
"""Cria (ou reusa) uma GitHub Release para uma tag e publica arquivos
como assets, usando SOMENTE a biblioteca padrao (`urllib.request`) --
nenhuma dependencia de terceiros, mesma filosofia do resto deste
projeto. Roda dentro de `.github/workflows/release.yml`, nunca fora de
CI (precisa de `GITHUB_TOKEN` com permissao `contents: write`).

Por que um script proprio em vez de uma Action de terceiros
(`softprops/action-gh-release` e' a mais comum): este projeto ja trata
qualquer dependencia de build/CI externa como algo a minimizar e
documentar (ver docs/EXECUTABLE_BUILD.md sobre `nuitka`/`patchelf`) --
criar/atualizar uma release e subir assets e' uma chamada direta e
simples da API REST do GitHub, perfeitamente possivel com
`urllib.request`, entao nao ha motivo para confiar o passo mais sensivel
do processo de publicacao (o que efetivamente fica visivel e baixavel
por qualquer usuario) a codigo de terceiros nao revisado aqui.

Idempotente: se a release da tag ja existir, reusa-a (atualiza nome/corpo
se fornecidos); se um asset com o mesmo nome ja existir nela, remove o
antigo antes de subir o novo -- permite re-rodar o workflow depois de
corrigir um problema sem deixar assets duplicados/obsoletos.

Uso:
    python3 tools/ci_publish_release.py \\
        --tag v1.0.0 \\
        --name "EntropyForge-BIP39 v1.0.0" \\
        --body-file RELEASE_NOTES.md \\
        --target-commitish <sha-do-commit> \\
        --asset dist/entropyforge.pyz \\
        --asset dist/entropyforge.pyz.sha256 \\
        [--draft] [--prerelease]

Variaveis de ambiente exigidas: `GITHUB_TOKEN` (ou `GH_TOKEN`),
`GITHUB_REPOSITORY` (formato "owner/repo", ja definida automaticamente
pelo GitHub Actions).

Saida: para cada asset publicado, uma linha
`asset_name sha256 browser_download_url` (formato estavel, pensado para
ser lido por outro passo do workflow ou por um humano revisando o log).
Nunca imprime o token.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

API_ROOT = "https://api.github.com"
UPLOADS_ROOT = "https://uploads.github.com"


class PublishError(RuntimeError):
    pass


def _token() -> str:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        raise PublishError("GITHUB_TOKEN (ou GH_TOKEN) nao definido no ambiente")
    return token


def _repo() -> tuple[str, str]:
    repo_full = os.environ.get("GITHUB_REPOSITORY")
    if not repo_full or "/" not in repo_full:
        raise PublishError(
            f"GITHUB_REPOSITORY ausente ou em formato inesperado: {repo_full!r} (esperado 'owner/repo')"
        )
    owner, repo = repo_full.split("/", 1)
    return owner, repo


def _request(url: str, *, method: str = "GET", token: str, data: bytes | None = None,
             content_type: str = "application/vnd.github+json", timeout: int = 60) -> tuple[int, bytes]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "entropyforge-bip39-ci-publish-release",
    }
    if data is not None:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _json_request(url: str, *, method: str = "GET", token: str, payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    status, body = _request(url, method=method, token=token, data=data)
    parsed = json.loads(body) if body else {}
    return status, parsed


def get_release_by_tag(owner: str, repo: str, tag: str, token: str) -> dict | None:
    status, body = _json_request(f"{API_ROOT}/repos/{owner}/{repo}/releases/tags/{tag}", token=token)
    if status == 200:
        return body
    if status == 404:
        return None
    raise PublishError(f"erro ao consultar release da tag {tag!r}: HTTP {status}: {body}")


def create_release(
    owner: str, repo: str, *, tag: str, name: str, body: str, target_commitish: str | None,
    draft: bool, prerelease: bool, token: str,
) -> dict:
    payload = {
        "tag_name": tag,
        "name": name,
        "body": body,
        "draft": draft,
        "prerelease": prerelease,
    }
    if target_commitish:
        payload["target_commitish"] = target_commitish
    status, resp = _json_request(f"{API_ROOT}/repos/{owner}/{repo}/releases", method="POST", token=token, payload=payload)
    if status not in (200, 201):
        raise PublishError(f"falha ao criar release: HTTP {status}: {resp}")
    return resp


def update_release(owner: str, repo: str, release_id: int, *, name: str, body: str, token: str) -> dict:
    payload = {"name": name, "body": body}
    status, resp = _json_request(
        f"{API_ROOT}/repos/{owner}/{repo}/releases/{release_id}", method="PATCH", token=token, payload=payload
    )
    if status != 200:
        raise PublishError(f"falha ao atualizar release {release_id}: HTTP {status}: {resp}")
    return resp


def delete_asset(owner: str, repo: str, asset_id: int, token: str) -> None:
    status, body = _request(
        f"{API_ROOT}/repos/{owner}/{repo}/releases/assets/{asset_id}", method="DELETE", token=token
    )
    if status not in (204,):
        raise PublishError(f"falha ao remover asset antigo {asset_id}: HTTP {status}: {body}")


def upload_asset(owner: str, repo: str, release_id: int, file_path: Path, token: str) -> dict:
    name = file_path.name
    data = file_path.read_bytes()
    url = f"{UPLOADS_ROOT}/repos/{owner}/{repo}/releases/{release_id}/assets?name={name}"
    status, body = _request(url, method="POST", token=token, data=data, content_type="application/octet-stream")
    parsed = json.loads(body) if body else {}
    if status not in (200, 201):
        raise PublishError(f"falha ao subir asset {name!r}: HTTP {status}: {parsed}")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--body-file", type=Path, required=True)
    parser.add_argument("--target-commitish", default=None, help="SHA/branch para a tag, se a release ainda nao existir")
    parser.add_argument("--asset", action="append", dest="assets", default=[], type=Path, help="arquivo a publicar (repetivel)")
    parser.add_argument("--draft", action="store_true")
    parser.add_argument("--prerelease", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    missing = [str(p) for p in args.assets if not p.is_file()]
    if missing:
        print(f"erro: asset(s) nao encontrado(s): {missing}", file=sys.stderr)
        return 2
    if not args.body_file.is_file():
        print(f"erro: --body-file nao encontrado: {args.body_file}", file=sys.stderr)
        return 2

    try:
        token = _token()
        owner, repo = _repo()
        body_text = args.body_file.read_text(encoding="utf-8")

        existing = get_release_by_tag(owner, repo, args.tag, token)
        if existing is not None:
            print(f"release existente para a tag {args.tag!r} (id={existing['id']}) -- reusando e atualizando")
            release = update_release(owner, repo, existing["id"], name=args.name, body=body_text, token=token)
        else:
            print(f"criando nova release para a tag {args.tag!r}")
            release = create_release(
                owner, repo, tag=args.tag, name=args.name, body=body_text,
                target_commitish=args.target_commitish, draft=args.draft, prerelease=args.prerelease, token=token,
            )

        release_id = release["id"]
        existing_assets = {a["name"]: a["id"] for a in release.get("assets", [])}

        results = []
        for asset_path in args.assets:
            name = asset_path.name
            if name in existing_assets:
                print(f"removendo asset existente com o mesmo nome: {name}")
                delete_asset(owner, repo, existing_assets[name], token)
            digest = hashlib.sha256(asset_path.read_bytes()).hexdigest()
            uploaded = upload_asset(owner, repo, release_id, asset_path, token)
            download_url = uploaded.get("browser_download_url", "")
            results.append((name, digest, download_url))
            print(f"{name} {digest} {download_url}")

        print(f"\nrelease publicada: {release.get('html_url', '')}")
    except PublishError as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
