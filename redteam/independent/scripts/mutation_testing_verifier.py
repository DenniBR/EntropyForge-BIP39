#!/usr/bin/env python3
"""Fase 14: mutation testing do PROPRIO independent-verifier.

Ate aqui, todo o laboratorio testou se o independent-verifier detecta
adulteracoes no EntropyForge. Mas isso so prova algo se o PROPRIO
verificador estiver correto -- um verificador com um bug (ex.: uma
comparacao de hash que sempre retorna True, uma checagem de duplicata que
foi removida por engano) daria uma falsa sensacao de seguranca MUITO pior
do que nao ter verificador nenhum.

Este script reaplica a mesma metodologia de mutation testing usada em
`redteam/scripts/mutation_testing.py` (Fase B, contra entropyforge/),
desta vez contra `independent-verifier/verifier/`, e roda a suite de
testes de `independent-verifier/tests/`. Cada mutante introduz um bug
PLAUSIVEL e REALISTA (o tipo de erro que aceitaria um hash errado,
ignoraria um arquivo alterado, ou ignoraria uma wordlist adulterada) e
verifica se ALGUM teste do verifier pega o bug (mutante "morto") ou se a
suite passa mesmo assim (mutante "sobrevivente" = lacuna de cobertura no
PROPRIO verificador, que precisa ser fechada).

NUNCA deixa o repositorio em estado mutado: cada mutacao e aplicada e
revertida dentro do mesmo bloco try/finally, com um assert de verificacao
da restauracao exata.
"""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
VERIFIER_ROOT = REPO_ROOT / "independent-verifier"


@dataclass
class Mutation:
    name: str
    file: str  # relativo a independent-verifier/
    old: str
    new: str
    rationale: str


MUTATIONS = [
    Mutation(
        name="hashing_diff_ignores_sha256_only_checks_size",
        file="verifier/hashing.py",
        old=(
            "            if old_by_path[p].sha256 != new_by_path[p].sha256\n"
            "            or old_by_path[p].size != new_by_path[p].size"
        ),
        new="            if old_by_path[p].size != new_by_path[p].size",
        rationale="diff_manifests para de comparar o SHA-256, so compara o tamanho -- "
        "um arquivo adulterado mantendo o mesmo numero de bytes passaria despercebido "
        "(o cenario mais basico e grave possivel: 'aceita hash errado').",
    ),
    Mutation(
        name="hashing_hash_file_always_same_value",
        file="verifier/hashing.py",
        old="    return h.hexdigest()",
        new='    return "0" * 64  # MUTANTE: ignora o conteudo real do arquivo',
        rationale="hash_file() ignora o conteudo do arquivo e sempre devolve o mesmo hash "
        "constante -- qualquer verificacao baseada em hash aceitaria qualquer arquivo.",
    ),
    Mutation(
        name="wordlist_check_skip_duplicate_check",
        file="verifier/wordlist_check.py",
        old=(
            "    if len(set(words)) != len(words):\n"
            "        seen = set()\n"
            "        dupes = set()\n"
            "        for w in words:\n"
            "            if w in seen:\n"
            "                dupes.add(w)\n"
            "            seen.add(w)\n"
            "        problems.append(f\"palavras duplicadas: {sorted(dupes)[:10]}\")\n"
        ),
        new="",
        rationale="remove a checagem de palavras duplicadas na wordlist -- uma wordlist "
        "com duas entradas iguais (reduzindo o espaco de mnemonics validos) passaria "
        "como OK.",
    ),
    Mutation(
        name="wordlist_check_official_hash_always_matches",
        file="verifier/wordlist_check.py",
        old="    if report.sha256 == KNOWN_OFFICIAL_SHA256:",
        new="    if True:  # MUTANTE: ignora KNOWN_OFFICIAL_SHA256",
        rationale="check_matches_official_hash() sempre reporta 'bate com a wordlist "
        "oficial', mesmo quando o hash calculado diverge completamente do valor "
        "embutido -- anula a defesa central da Fase 3/13 contra uma wordlist adulterada "
        "de forma consistente (source E manifesto).",
    ),
    Mutation(
        name="pyz_inspect_ignores_unexpected_files",
        file="verifier/pyz_inspect.py",
        old="        return not (self.content_mismatches or self.missing_from_pyz or self.unexpected_in_pyz)",
        new="        return not (self.content_mismatches or self.missing_from_pyz)  # MUTANTE: ignora unexpected_in_pyz",
        rationale="PyzSourceComparison.ok ignora arquivos INESPERADOS dentro do .pyz -- "
        "um modulo extra (sitecustomize.py, um payload escondido) nao derrubaria mais "
        "'ok', mesmo aparecendo em unexpected_in_pyz.",
    ),
    Mutation(
        name="pyz_inspect_bootstrap_check_always_ok",
        file="verifier/pyz_inspect.py",
        old="    if actual == EXPECTED_BOOTSTRAP_MAIN:",
        new="    if True:  # MUTANTE: ignora o conteudo real de __main__.py",
        rationale="check_bootstrap_main() para de comparar o __main__.py real contra o "
        "esperado -- um bootstrap adulterado (ex.: com codigo extra apos o sys.exit) "
        "passaria como identico ao esperado.",
    ),
    Mutation(
        name="bip39_min_checksum_uses_last_byte",
        file="verifier/bip39_min.py",
        old="    checksum_full_byte = hashlib.sha256(entropy).digest()[0]\n    checksum_bits_value",
        new="    checksum_full_byte = hashlib.sha256(entropy).digest()[-1]\n    checksum_bits_value",
        rationale="entropy_to_mnemonic() na implementacao independente usa o ULTIMO byte "
        "do digest para o checksum em vez do PRIMEIRO -- o mesmo tipo de erro plausivel "
        "ja usado como mutante contra entropyforge/bip39.py (Fase B); aqui testamos se "
        "a PROPRIA implementacao independente, se cometesse esse erro, seria pega pelos "
        "vetores oficiais (ela deveria: os vetores BIP-39 oficiais sao a defesa).",
    ),
    Mutation(
        name="static_scan_rede_category_removed",
        file="verifier/static_scan.py",
        old='    "rede": ("socket", "connect", "send", "sendto", "sendall", "recv", "getaddrinfo", "create_connection"),',
        new='    "rede": (),  # MUTANTE: categoria de rede esvaziada',
        rationale="a categoria 'rede' do scanner estatico fica vazia -- imports/chamadas "
        "de socket/connect/send/etc. deixam de ser sinalizados como suspeitos.",
    ),
    Mutation(
        name="build_repro_identical_ignores_hash",
        file="verifier/build_repro.py",
        old="        return self.hash_a == self.hash_b and self.size_a == self.size_b",
        new="        return self.size_a == self.size_b  # MUTANTE: ignora o hash",
        rationale="BuildReproResult.identical() para de comparar os hashes dos dois "
        "builds, so compara o tamanho -- dois builds de tamanhos iguais mas conteudos "
        "diferentes seriam reportados como 'identicos' (reprodutibilidade falsa).",
    ),
]


def run_tests() -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=str(VERIFIER_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )
    return proc.returncode == 0, proc.stdout + proc.stderr


def apply_and_test(mutation: Mutation) -> dict:
    path = VERIFIER_ROOT / mutation.file
    original = path.read_text(encoding="utf-8")
    if mutation.old not in original:
        return {"mutation": mutation.name, "status": "ERROR", "detail": "old string nao encontrada no arquivo"}
    mutated = original.replace(mutation.old, mutation.new, 1)
    if mutated == original:
        return {"mutation": mutation.name, "status": "ERROR", "detail": "mutacao nao alterou o arquivo"}
    try:
        path.write_text(mutated, encoding="utf-8")
        ok, output = run_tests()
        status = "SURVIVED (nenhum teste pegou o mutante)" if ok else "KILLED (algum teste pegou o mutante)"
        return {
            "mutation": mutation.name,
            "rationale": mutation.rationale,
            "status": status,
            "tests_passed_despite_mutation": ok,
            "tail_output": "\n".join(output.strip().splitlines()[-6:]),
        }
    finally:
        path.write_text(original, encoding="utf-8")
        assert path.read_text(encoding="utf-8") == original, f"FALHA AO RESTAURAR {path}!"


def main() -> int:
    results = []
    for m in MUTATIONS:
        print(f"--- aplicando mutante: {m.name} ---")
        r = apply_and_test(m)
        results.append(r)
        print(f"    {r['status']}")
        if "SURVIVED" in r.get("status", ""):
            print(f"    ** LACUNA DE COBERTURA NO VERIFICADOR: {r['rationale']} **")
        elif r["status"] == "ERROR":
            print(f"    ERRO: {r['detail']}")

    print("\n=== RESUMO (mutation testing do independent-verifier) ===")
    survived = [r for r in results if r.get("tests_passed_despite_mutation")]
    errors = [r for r in results if r.get("status") == "ERROR"]
    for r in results:
        print(f"{r['mutation']:48s} {r['status']}")
    print(f"\n{len(survived)} de {len(results)} mutantes SOBREVIVERAM (lacunas de cobertura reais).")
    for r in survived:
        print(f"  - {r['mutation']}: {r['rationale']}")
    if errors:
        print(f"\n{len(errors)} mutacoes com ERRO (ponto de insercao nao encontrado -- revisar script):")
        for r in errors:
            print(f"  - {r['mutation']}: {r['detail']}")
    return len(survived) + len(errors)


if __name__ == "__main__":
    sys.exit(main())
