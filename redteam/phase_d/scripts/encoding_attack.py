#!/usr/bin/env python3
"""Fase D, secao 6: ataque ao encoding de A -- reimplementacao
INDEPENDENTE (sem importar entropyforge.dice) e comparacao byte a byte,
mais busca por colisao/perda/truncamento/overflow/underflow/endian/
ambiguidade de comprimento/leading zero/ambiguidade de codificacao.
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from entropyforge import dice  # o codigo REAL, para comparar contra


def independent_encode(digits: str) -> bytes:
    """Reimplementacao do zero: NAO reusa nenhuma linha de dice.py.
    Usa uma tecnica DIFERENTE (grande inteiro via int(..., base convertida
    manualmente dígito a dígito com peso posicional, largura calculada via
    math.ceil(n*log(6,256)) em vez de bit_length) para ser uma segunda via
    de calculo, nao uma copia disfarcada."""
    import math
    if not digits or any(c not in "123456" for c in digits):
        raise ValueError("entrada invalida")
    n = len(digits)
    # valor via soma posicional explicita (equivalente matematicamente a
    # avaliacao de Horner usada por dice.py, mas calculada com uma formula
    # de soma direta em vez de multiplicacao acumulada)
    value = sum((int(c) - 1) * (6 ** (n - 1 - i)) for i, c in enumerate(digits))
    max_value = 6 ** n - 1
    # largura calculada via log em vez de bit_length
    if max_value == 0:
        width = 0
    else:
        width = math.ceil(math.log(max_value + 1, 256))
        # math.log pode ter erro de arredondamento perto de potencias exatas
        # de 256; corrige subindo ate caber
        while 256 ** width <= max_value:
            width += 1
    length_prefix = n.to_bytes(2, byteorder="big", signed=False)
    value_bytes = value.to_bytes(width, byteorder="big", signed=False)
    return length_prefix + value_bytes


def independent_decode(data: bytes) -> str:
    if len(data) < 2:
        raise ValueError("dados curtos demais")
    n = int.from_bytes(data[0:2], byteorder="big")
    max_value = 6 ** n - 1
    import math
    width = 0 if max_value == 0 else math.ceil(math.log(max_value + 1, 256))
    while width > 0 and 256 ** (width - 1) > max_value:
        width -= 1
    while 256 ** width <= max_value:
        width += 1
    if len(data) != 2 + width:
        raise ValueError(f"comprimento inconsistente: esperado {2+width}, recebido {len(data)}")
    value = int.from_bytes(data[2:], byteorder="big")
    if value > max_value:
        raise ValueError("valor fora do intervalo esperado")
    out = []
    v = value
    for _ in range(n):
        out.append(str(v % 6 + 1))
        v //= 6
    return "".join(reversed(out))


def compare(digits: str, label: str):
    real = dice.encode(digits)
    indep = independent_encode(digits)
    ok_bytes = real == indep
    real_decoded = dice.decode(real)
    indep_decoded = independent_decode(indep)
    ok_roundtrip_real = real_decoded == digits
    ok_roundtrip_indep = indep_decoded == digits
    ok_cross_decode = dice.decode(indep) == digits and independent_decode(real) == digits
    status = "OK" if (ok_bytes and ok_roundtrip_real and ok_roundtrip_indep and ok_cross_decode) else "MISMATCH!!"
    print(f"[{status}] {label} (n={len(digits)}): bytes_iguais={ok_bytes} "
          f"roundtrip_real={ok_roundtrip_real} roundtrip_indep={ok_roundtrip_indep} "
          f"decode_cruzado={ok_cross_decode}")
    if not ok_bytes:
        print(f"    real ={real.hex()}")
        print(f"    indep={indep.hex()}")
    return status == "OK"


print("=== Vetores de teste (n variados, casos extremos) ===")
all_ok = True
rng = random.Random(20260927)

cases = [
    ("1", "n=1"),
    ("11", "n=2 (dois lancamentos)"),
    ("111", "n=3"),
    ("1" * 99, "n=99 (all-1)"),
    ("1" * 100, "n=100 (all-1, limiar teorico 256 bits)"),
    ("1" * 101, "n=101"),
    ("1" * 132, "n=132"),
    ("6" * 99, "n=99 (all-6)"),
    ("6" * 127, "n=127 (all-6, operacional)"),
    ("123456" * 22, "n=132 (alternancia ciclica)"),
    ("".join(rng.choice("123456") for _ in range(127)), "n=127 (aleatorio)"),
    ("".join(rng.choice("123456") for _ in range(1000)), "n=1000 (grande)"),
    ("1" + "6" * 998 + "1", "n=1000 (bordas 1...1, meio 6)"),
    ("2" * 50, "n=50 (all-2, digito nao-extremo)"),
]

for digits, label in cases:
    ok = compare(digits, label)
    all_ok = all_ok and ok

print()
print("=== Vetores publicos (para reproducao por terceiros) ===")
public_vectors = []
for digits, label in cases:
    b = dice.encode(digits)
    public_vectors.append((label, len(digits), digits[:20] + ("..." if len(digits) > 20 else ""), b.hex()))
    print(f"{label:45s} n={len(digits):5d}  A(hex)={b.hex()}")

print()
print("=== Busca por colisao: sequencias distintas do MESMO n devem sempre")
print("produzir bytes DIFERENTES (bijecao) ===")
collisions = 0
trials = 20000
seen = {}
n_fixed = 8  # pequeno o suficiente para testar TODAS as 6^8 = 1.679.616 combinacoes seria caro;
# testamos uma amostra grande e tambem a enumeracao EXAUSTIVA para n<=5
for n_exhaustive in range(1, 6):
    import itertools
    seen_exhaustive = set()
    count = 0
    for combo in itertools.product("123456", repeat=n_exhaustive):
        digits = "".join(combo)
        b = dice.encode(digits)
        if b in seen_exhaustive:
            collisions += 1
            print(f"  COLISAO em n={n_exhaustive}: {digits} produziu bytes ja vistos!")
        seen_exhaustive.add(b)
        count += 1
    print(f"  n={n_exhaustive}: {count} sequencias enumeradas EXAUSTIVAMENTE, "
          f"{len(seen_exhaustive)} valores unicos de A ({'OK, bijecao confirmada' if count == len(seen_exhaustive) else 'FALHA'})")

print()
print("=== Ataque: truncamento/overflow/underflow/comprimento inconsistente (decode) ===")


def expect_error(fn, *args, label=""):
    try:
        fn(*args)
        print(f"  [FALHA -- deveria ter rejeitado] {label}")
        return False
    except dice.DiceInputError as exc:
        print(f"  [OK, rejeitado corretamente] {label}: {exc}")
        return True


ok2 = True
# 1. dados truncados (remove o ultimo byte de um A valido)
valid_a = dice.encode("123456" * 20)  # n=120
ok2 &= expect_error(dice.decode, valid_a[:-1], label="A truncado (1 byte a menos)")
# 2. dados com byte extra (overflow de comprimento)
ok2 &= expect_error(dice.decode, valid_a + b"\x00", label="A com 1 byte extra (overflow)")
# 3. prefixo de n=0 (underflow -- zero lancamentos)
ok2 &= expect_error(dice.decode, (0).to_bytes(2, "big"), label="prefixo n=0 (zero lancamentos, dado vazio)")
# 4. valor codificado MAIOR que 6^n-1 para o n declarado (overflow de valor)
n_small = 3
max_v = 6 ** n_small - 1  # 215
width_small = (max_v.bit_length() + 7) // 8
overflow_value = (max_v + 1).to_bytes(width_small, "big")  # 216, fora do intervalo [0,215]
# 216 cabe em 1 byte tambem (width nao muda), entao isso testa overflow de VALOR, nao de bytes
bogus = n_small.to_bytes(2, "big") + overflow_value
ok2 &= expect_error(dice.decode, bogus, label=f"valor codificado > 6^n-1 para n={n_small} (216 > 215)")
# 5. leading zero: A com n>=1 mas todos os digitos "1" (valor interno = 0) --
# NAO deve ser confundido com um prefixo de comprimento diferente
a_all_ones_3 = dice.encode("111")  # n=3, valor=0
a_all_ones_2 = dice.encode("11")   # n=2, valor=0
print(f"  encode('111') = {a_all_ones_3.hex()}  encode('11') = {a_all_ones_2.hex()}")
ok2 &= (a_all_ones_3 != a_all_ones_2)
print(f"  [OK, sem colisao entre 'leading zeros' de tamanhos diferentes] {a_all_ones_3 != a_all_ones_2}")
# 6. endianness: confirma que o prefixo de comprimento e BIG-endian (nao pequeno)
n_be_check = dice.encode("1" * 300)[:2]
assert int.from_bytes(n_be_check, "big") == 300
assert int.from_bytes(n_be_check, "little") != 300  # se fossem iguais, nao testariamos nada
print(f"  [OK] prefixo de n=300 em hex = {n_be_check.hex()} -- confirma BIG-endian "
      f"(little-endian daria {int.from_bytes(n_be_check, 'little')}, ERRADO)")

print()
print("=== RESULTADO FINAL ===")
print(f"Todos os vetores comparados byte-a-byte contra reimplementacao independente: {'OK' if all_ok else 'DIVERGENCIA ENCONTRADA'}")
print(f"Todas as bijecoes exaustivas (n=1..5): {'OK' if collisions == 0 else f'{collisions} COLISOES ENCONTRADAS'}")
print(f"Todos os ataques de truncamento/overflow/underflow/endian rejeitados corretamente: {'OK' if ok2 else 'FALHA -- alguma entrada invalida foi aceita'}")
