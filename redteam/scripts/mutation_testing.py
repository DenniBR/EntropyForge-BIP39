#!/usr/bin/env python3
"""Red team: mutation testing dos modulos criticos.

Introduz, um de cada vez, um bug PLAUSIVEL e REALISTA no codigo-fonte de
`entropyforge/`, roda a suite de testes completa, registra se algum teste
pegou o bug (mutante "morto") ou se a suite passou mesmo com o bug
presente (mutante "sobrevivente" = LACUNA DE COBERTURA), e sempre restaura
o arquivo original ao final (mesmo em caso de erro).

NUNCA deixa o repositorio em estado mutado: cada mutacao e aplicada e
revertida dentro do mesmo bloco try/finally.
"""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass
class Mutation:
    name: str
    file: str
    old: str
    new: str
    rationale: str


MUTATIONS = [
    Mutation(
        name="bip39_checksum_wrong_end_of_digest",
        file="entropyforge/bip39.py",
        old='    first_byte = hashlib.sha256(entropy).digest()[0]\n    return f"{first_byte:08b}"[:num_bits]',
        new='    first_byte = hashlib.sha256(entropy).digest()[-1]\n    return f"{first_byte:08b}"[:num_bits]',
        rationale="usa o ULTIMO byte do digest em vez do PRIMEIRO para o checksum "
        "(erro plausivel de leitura da especificacao: 'os primeiros CS bits do hash')",
    ),
    Mutation(
        name="bip39_checksum_off_by_one_bits",
        file="entropyforge/bip39.py",
        old='    return f"{first_byte:08b}"[:num_bits]',
        new='    return f"{first_byte:08b}"[: num_bits + 1]',
        rationale="usa CS+1 bits de checksum em vez de CS (erro de off-by-one)",
    ),
    Mutation(
        name="combine_wrong_order",
        file="entropyforge/combine.py",
        old="    digest = hashlib.sha256(a + b).digest()",
        new="    digest = hashlib.sha256(b + a).digest()",
        rationale="inverte a ordem da concatenacao (B||A em vez de A||B)",
    ),
    Mutation(
        name="combine_wrong_hash",
        file="entropyforge/combine.py",
        old="    digest = hashlib.sha256(a + b).digest()",
        new="    digest = hashlib.md5(a + b).digest() + hashlib.md5(a + b + b'x').digest()[:16]",
        rationale="troca SHA-256 por MD5 (mais rapido de 'errar' que parece: hash errado, "
        "ainda produzindo 32 bytes)",
    ),
    Mutation(
        name="dice_encode_little_endian",
        file="entropyforge/dice.py",
        old='    return n.to_bytes(2, "big") + value.to_bytes(width, "big")',
        new='    return n.to_bytes(2, "big") + value.to_bytes(width, "little")',
        rationale="usa little-endian para o valor de A (mistura de endianness, erro classico)",
    ),
    Mutation(
        name="dice_encode_width_no_rounding",
        file="entropyforge/dice.py",
        old="    width = (max_value.bit_length() + 7) // 8 if max_value > 0 else 0",
        new="    width = max_value.bit_length() // 8 if max_value > 0 else 0",
        rationale="calcula a largura em bytes sem arredondar para cima "
        "(trunca bits que nao completam um byte)",
    ),
    Mutation(
        name="wordlist_skip_sorted_check",
        file="entropyforge/wordlist.py",
        old="    if words != sorted(words):\n        raise WordlistError(\"wordlist nao esta em ordem alfabetica\")\n",
        new="",
        rationale="remove a verificacao de que a wordlist esta ordenada",
    ),
    Mutation(
        name="wordlist_skip_duplicate_check",
        file="entropyforge/wordlist.py",
        old="    if len(set(words)) != len(words):\n        raise WordlistError(\"wordlist contem palavras duplicadas\")\n",
        new="",
        rationale="remove a verificacao de palavras duplicadas",
    ),
    Mutation(
        name="stats_skip_holm_use_raw_alpha",
        file="entropyforge/stats.py",
        old="    rejections = holm_bonferroni(p_values, alpha)",
        new="    rejections = [p <= alpha for p in p_values]  # MUTANTE: sem correcao de Holm",
        rationale="substitui a correcao de Holm-Bonferroni por um limiar bruto (alpha) "
        "por teste, sem corrigir para testes multiplos -- infla a taxa de falso positivo",
    ),
    Mutation(
        name="guard_flags_missing_o_creat",
        file="entropyforge/guard.py",
        old='for _name in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC", "O_EXCL"):',
        new='for _name in ("O_WRONLY", "O_RDWR"):  # MUTANTE: falta O_CREAT/O_APPEND/O_TRUNC/O_EXCL',
        rationale="remove O_CREAT/O_APPEND/O_TRUNC/O_EXCL da mascara de flags de escrita "
        "bloqueadas em os.open() (mode=None) -- so pega O_WRONLY/O_RDWR explicitos",
    ),
    Mutation(
        name="entropy_calc_off_by_one_operational",
        file="entropyforge/entropy_calc.py",
        old="    while min_entropy_bits(n, p_max) - report_leak_bits(n, num_verdict_tests) < target_bits:\n        n += 1",
        new="    while min_entropy_bits(n, p_max) - report_leak_bits(n, num_verdict_tests) <= target_bits:\n        n += 1",
        rationale="troca '<' por '<=' na condicao de parada (exige 1 bit a mais do que "
        "o necessario -- mais conservador, mas MUDA o numero recomendado)",
    ),
]


def run_tests(target: str) -> tuple[bool, str]:
    # NOTA (achado do proprio red team, ver docs/REDTEAM.md): a versao
    # anterior desta funcao passava "discover -s tests" como UM UNICO
    # argumento de string para `unittest`, que o interpreta como um nome
    # de modulo de teste (com espacos!) em vez de um subcomando com
    # flags separadas. Isso fazia TODO teste falhar com ModuleNotFoundError
    # independentemente de qualquer mutacao, inflando falsamente 11/11
    # mutantes para "KILLED". Corrigido para passar os argumentos
    # separadamente, como o shell faria.
    proc = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-s", target, "-v"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    return proc.returncode == 0, proc.stdout + proc.stderr


def apply_and_test(mutation: Mutation, full_suite: bool) -> dict:
    path = REPO_ROOT / mutation.file
    original = path.read_text(encoding="utf-8")
    if mutation.old not in original:
        return {"mutation": mutation.name, "status": "ERROR", "detail": "old string nao encontrada no arquivo"}
    mutated = original.replace(mutation.old, mutation.new, 1)
    try:
        path.write_text(mutated, encoding="utf-8")
        ok, output = run_tests("tests")
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
        # confirma que restaurou exatamente
        assert path.read_text(encoding="utf-8") == original, f"FALHA AO RESTAURAR {path}!"


def main():
    results = []
    for m in MUTATIONS:
        print(f"--- aplicando mutante: {m.name} ---")
        r = apply_and_test(m, full_suite=True)
        results.append(r)
        print(f"    {r['status']}")
        if "SURVIVED" in r["status"]:
            print(f"    ** LACUNA DE COBERTURA: {r['rationale']} **")

    print("\n=== RESUMO ===")
    survived = [r for r in results if r.get("tests_passed_despite_mutation")]
    for r in results:
        print(f"{r['mutation']:40s} {r['status']}")
    print(f"\n{len(survived)} de {len(results)} mutantes SOBREVIVERAM (lacunas de cobertura reais).")
    for r in survived:
        print(f"  - {r['mutation']}: {r['rationale']}")
    return len(survived)


if __name__ == "__main__":
    sys.exit(main())
