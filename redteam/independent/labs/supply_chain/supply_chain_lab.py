#!/usr/bin/env python3
"""Laboratorio de ataques de cadeia de suprimentos (Fase 13).

Materializa seis cenarios adversariais distintos (A-F), cada um simulando
um ponto DIFERENTE da cadeia entre "codigo-fonte auditado" e "programa que
o usuario final realmente executa" onde um atacante poderia inserir uma
alteracao:

  A) uma linha alterada em um modulo do source (fora do caminho critico
     combine/bip39) -- o caso mais generico de "alguem editou o codigo".
  B) a wordlist alterada (ja teem testes dedicados em test_wordlist_check.py;
     aqui ela e re-testada especificamente sob a LENTE de cadeia de
     suprimentos: o que detecta isso quando a alteracao chega tanto no
     source QUANTO no .pyz construido a partir dele, de forma consistente).
  C) o .pyz alterado DEPOIS de construido a partir de source legitimo
     (compromete o artefato de distribuicao, nao o source).
  D) o SCRIPT DE BUILD alterado (tools/build_pyz.py) -- o source e a
     wordlist continuam limpos, mas o processo que os empacota insere algo
     extra durante o build.
  E) um pacote IMPOSTOR: uma copia inteira de `entropyforge/` com conteudo
     diferente do legitimo, simulando o cenario em que um usuario obtem o
     programa por um canal nao confiavel (mirror comprometido, upload
     malicioso com o mesmo nome) em vez do source/artefato auditado.
  F) codigo malicioso num modulo "irrelevante" (aqui, `report.py` -- o
     modulo de formatacao de relatorio estatistico, fora do caminho
     critico de combinacao/derivacao de entropia) -- testa se os controles
     dependem implicitamente de "so preciso olhar os arquivos que
     importam" (premissa falsa: qualquer arquivo no pacote roda com os
     mesmos privilegios).

Nenhum cenario aqui usa dados reais; toda entropia envolvida (quando
aplicavel) e proveniente de vetores de teste publicos/foto.
"""
from __future__ import annotations

import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
ENTROPYFORGE_SRC = REPO_ROOT / "entropyforge"
BUILD_SCRIPT_SRC = REPO_ROOT / "tools" / "build_pyz.py"


def materialize_scenario_a_one_line_source_change(dest_root: Path) -> Path:
    """Uma linha alterada em `dice.py`, FORA do caminho critico de
    combinacao (nao mexe em combine.py nem bip39.py): afrouxa a validacao
    de entrada para aceitar um digito de face fora do intervalo 1-6 (um
    d6 fisico so tem seis faces; '7' nunca deveria ser aceito)."""
    dest = dest_root / "entropyforge"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(ENTROPYFORGE_SRC, dest)

    target = dest / "dice.py"
    source = target.read_text(encoding="utf-8")
    needle = 'ALPHABET = "123456"'
    if needle not in source:
        raise RuntimeError("ponto de insercao esperado nao encontrado em dice.py")
    mutated = source.replace(needle, 'ALPHABET = "1234567"  # SUPPLY_CHAIN_LAB_A: limite alargado', 1)
    if mutated == source:
        raise RuntimeError("cenario A nao alterou dice.py")
    target.write_text(mutated, encoding="utf-8")
    return dest


def materialize_scenario_b_tampered_wordlist(dest_root: Path) -> Path:
    """Troca a primeira palavra da wordlist por uma variante grafada
    diferente, mantendo o restante do arquivo intacto -- simula uma
    adulteracao pontual (ex.: um caractere trocado num mirror) em vez de
    uma reescrita completa e obvia."""
    dest = dest_root / "entropyforge"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(ENTROPYFORGE_SRC, dest)

    wordlist_path = dest / "data" / "english.txt"
    words = wordlist_path.read_text(encoding="utf-8").splitlines()
    if words[0] != "abandon":
        raise RuntimeError("wordlist inesperada; abortando cenario B")
    words[0] = "abandonx"  # ainda parece uma palavra plausivel
    wordlist_path.write_text("\n".join(words) + "\n", encoding="utf-8")
    return dest


def materialize_scenario_c_tampered_pyz(pyz_path: Path) -> None:
    """Reescreve um .pyz JA CONSTRUIDO (a partir de source legitimo),
    inserindo um modulo extra nao documentado -- simula compromisso do
    artefato de distribuicao apos o build (ex.: um mirror de downloads
    comprometido), sem tocar no source nem no script de build."""
    import io
    import sys
    import zipfile

    sys.path.insert(0, str(REPO_ROOT / "independent-verifier"))
    from verifier.pyz_inspect import ZIP_MAGIC

    data = pyz_path.read_bytes()
    zstart = data.index(ZIP_MAGIC)
    shebang = data[:zstart]
    with zipfile.ZipFile(io.BytesIO(data[zstart:])) as zin:
        content = {n: zin.read(n) for n in zin.namelist()}
    content["entropyforge/_mirror_payload.py"] = (
        b"# SUPPLY_CHAIN_LAB_C: modulo inserido apos o build, direto no .pyz\n"
        b"# (nunca existiu no source-tree que gerou este artefato)\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zout:
        for name, payload in content.items():
            zout.writestr(name, payload)
    pyz_path.write_bytes(shebang + buf.getvalue())


def materialize_scenario_d_tampered_build_script(dest_root: Path) -> Path:
    """Copia `tools/build_pyz.py` e o modifica para injetar um arquivo
    extra durante o proprio processo de build -- o source-tree usado como
    entrada continua 100% limpo; e o PROCESSO de empacotamento que
    introduz a alteracao."""
    dest_tools = dest_root / "tools"
    dest_tools.mkdir(parents=True, exist_ok=True)
    dest_script = dest_tools / "build_pyz.py"
    source = BUILD_SCRIPT_SRC.read_text(encoding="utf-8")

    needle = 'files["__main__.py"] = TOP_LEVEL_MAIN.encode("utf-8")'
    if needle not in source:
        raise RuntimeError("ponto de insercao esperado nao encontrado em build_pyz.py")
    injected = (
        needle
        + "\n"
        + '    files["entropyforge/_build_backdoor.py"] = '
        + 'b"# SUPPLY_CHAIN_LAB_D: injetado pelo SCRIPT DE BUILD adulterado\\n"'
    )
    mutated = source.replace(needle, injected, 1)
    if mutated == source:
        raise RuntimeError("cenario D nao alterou build_pyz.py")
    dest_script.write_text(mutated, encoding="utf-8")
    return dest_script


def materialize_scenario_e_impostor_package(dest_root: Path) -> Path:
    """Cria uma copia de `entropyforge/` com o MESMO NOME de pacote mas
    conteudo diferente do legitimo (uma versao com `combine.py` alterado),
    simulando o cenario em que o usuario obtem um pacote impostor por um
    canal nao confiavel em vez do source/artefato auditado."""
    dest = dest_root / "entropyforge"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(ENTROPYFORGE_SRC, dest)

    target = dest / "combine.py"
    source = target.read_text(encoding="utf-8")
    needle = "digest = hashlib.sha256(a + b).digest()"
    if needle not in source:
        raise RuntimeError("ponto de insercao esperado nao encontrado em combine.py")
    # ordem trocada: A e B invertidos na concatenacao -- desvio sutil do
    # algoritmo documentado (SHA-256(A||B)), plausivel o suficiente para
    # nao ser obviamente malicioso a uma leitura rapida.
    mutated = source.replace(needle, "digest = hashlib.sha256(b + a).digest()  # SUPPLY_CHAIN_LAB_E", 1)
    target.write_text(mutated, encoding="utf-8")
    return dest


def materialize_scenario_f_backdoor_in_irrelevant_module(dest_root: Path) -> Path:
    """Insere codigo de rede em `report.py` -- o modulo de FORMATACAO DE
    RELATORIO ESTATISTICO, que nao participa da derivacao/combinacao de
    entropia. Testa se os controles dependem (erradamente) da suposicao
    de que so vale a pena revisar os arquivos "obviamente criticos"."""
    dest = dest_root / "entropyforge"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(ENTROPYFORGE_SRC, dest)

    target = dest / "report.py"
    source = target.read_text(encoding="utf-8")
    needle = "def public_report(battery: BatteryResult) -> PublicReport:"
    if needle not in source:
        raise RuntimeError("ponto de insercao esperado nao encontrado em report.py")
    injected = (
        needle
        + "\n"
        + "    try:  # SUPPLY_CHAIN_LAB_F: 'telemetria' disfarcada num modulo irrelevante\n"
        + "        import socket as _lab_socket\n"
        + "        _s = _lab_socket.socket(_lab_socket.AF_INET, _lab_socket.SOCK_DGRAM)\n"
        + "        _s.sendto(bytes(battery.face_counts), ('127.0.0.1', 9))\n"
        + "    except Exception:\n"
        + "        pass\n"
    )
    mutated = source.replace(needle, injected, 1)
    if mutated == source:
        raise RuntimeError("cenario F nao alterou report.py")
    target.write_text(mutated, encoding="utf-8")
    return dest
