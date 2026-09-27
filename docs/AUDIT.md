# Guia de auditoria

Este documento existe para que uma pessoa que não escreveu este código
consiga verificá-lo de ponta a ponta, sem precisar confiar em nada além
do que consegue ler e executar.

## 1. Tamanho e escopo

`entropyforge/*.py` soma **2.449 linhas** (contadas com `wc -l`, incluindo
comentários e docstrings — que são deliberadamente extensos, para que o
código explique seu próprio raciocínio matemático inline). Isto é maior
que a meta informal de ~1.500 linhas do rascunho inicial do design; o
crescimento veio de exigir **provas exatas** (não aproximações) para os
testes T2–T4 (`stats.py`), de uma bateria de funções especiais própria
sem SciPy (`specialfunc.py`), e de uma abstração de E/S (`cli.py`) que
permite testar o fluxo `generate` de ponta a ponta sem TTY real. Ainda é
pequeno o suficiente para ser lido por completo em algumas horas.

`tests/*.py` soma bem mais que isso (191 testes) — não precisa ser
auditado com o mesmo rigor que o código de produto, mas é o que dá
confiança de que o código de produto faz o que diz. Um projeto irmão,
`independent-verifier/` (112 testes próprios, ver
`docs/INDEPENDENT_VERIFIER.md`), verifica boa parte disso de forma
independente, sem reusar nenhum código deste pacote.

## 2. Hashes dos arquivos críticos (nesta revisão)

```
2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda  entropyforge/data/english.txt
3c4340b0a648fd94de77376f89c76b0aedf5d185cae6a6b3772bf87d565d5a74  entropyforge/__init__.py
7c61107528434a2f9769c0156ca8c40a3aa722bf68887583069e4cf66da57900  entropyforge/__main__.py
6955bc7646f9f7ba85a7ee39c1930c45aba17df435db68f1e3df29fa739d3ba0  entropyforge/bip39.py
5cdb20e41171645226170f0a1cdda4f21c753c503b8f6edb9a3cd98a51dd2e45  entropyforge/cli.py
5dbd17ff1a3f1d6ffe9cc5c1e41497efe74dbfe156b6567175b9a79dce3ac6bb  entropyforge/combine.py
64434186558e57261d45a1e6ce0e25a6afc3af6d1c55b646b123aefcca799009  entropyforge/dice.py
3d9e8303456ebbaf9b672d48a3b7c28bbea6a7e075386f596866c1606edbf9cb  entropyforge/entropy_calc.py
1ba12516ce568f5c21b5a48be8d07cfce26d4e79275978abe6a6c296dc995f97  entropyforge/guard.py
5a5641e3715da99f30c2c5c41f56304bbb0bad0cef696224e33c6ffd85b59a73  entropyforge/osrng.py
3807d5e7aa717830834603a3e3cc18df939ffa5aa70b8f27dc7d625b9273b47b  entropyforge/report.py
0aa0e3d7a72593aee9771fa8691758c000d0c2dfb1aa7c1a2a5bdd6ed07213ec  entropyforge/selftest.py
587a9c8f3b190eaaa7f67f4cb651d1c4ba2856f58570df45e09e003430b1c00c  entropyforge/specialfunc.py
c77a51f3d31100d4d4a58215a82802436eea3f556b1b9742f54afd6f1df3bc3c  entropyforge/stats.py
af85bfdcaf6c768f7f5c7da6532527b20d85e73721c94d438bd09fc4da4be2f5  entropyforge/wordlist.py
```

(`cli.py`, `__main__.py` e `dice.py` mudaram de hash em relação a
revisões anteriores deste documento — `cli.py`/`__main__.py` por
correções de auditoria adversarial anteriores, `dice.py` por uma correção
de simetria em `decode()` encontrada na revisão de segurança final, ver
`docs/FINAL_SECURITY_REVIEW.md`. Os hashes acima são os corretos para o
commit atual.)

Estes hashes valem para o commit atual; `git log -1 --format=%H` no
repositório diz exatamente qual commit. Não confie neste arquivo sozinho
— confira `git log` e, se possível, mais de uma cópia independente do
repositório (ex.: um fork de terceiros, ou o histórico do GitHub).

A wordlist é a mesma publicada em
`github.com/bitcoin/bips/blob/master/bip-0039/english.txt`; confira o hash
acima contra esse arquivo diretamente.

## 3. Ordem de leitura recomendada

1. `docs/DESIGN.md` — arquitetura e decisões, para orientação geral.
2. `entropyforge/dice.py` — a fonte física, o menor módulo com lógica de
   verdade; comece por aqui para entender a bijeção (seção 3 de `docs/MATH.md`).
3. `entropyforge/wordlist.py` + `entropyforge/bip39.py` — a especificação
   BIP-39; compare linha a linha com `bip-0039.mediawiki`.
4. `entropyforge/osrng.py` + `entropyforge/combine.py` — as duas fontes se
   encontrando; curto, direto.
5. `entropyforge/specialfunc.py` — funções matemáticas puras; confira
   contra `tests/test_specialfunc.py` e contra uma calculadora/tabela
   independente (ex.: `scipy.stats.chi2.sf`, se você tiver SciPy à mão —
   NUNCA como dependência do produto, só para conferir).
6. `entropyforge/entropy_calc.py` — as três perguntas sobre quantidade de
   lançamentos (seção 2 de `docs/MATH.md`).
7. `entropyforge/stats.py` — a bateria de testes; leia junto com a seção 8
   de `docs/MATH.md`, que prova as distribuições nulas de T2–T4.
8. `entropyforge/report.py` — o que é (e não é) exibido.
9. `entropyforge/guard.py` — o audit hook e a checagem de rede.
10. `entropyforge/selftest.py` — os KATs.
11. `entropyforge/cli.py` — o fluxo interativo; o mais longo, mas
    estruturado em torno de `TerminalIO` justamente para ser auditável e
    testável.
12. `entropyforge/__main__.py` — o ponto de entrada.

## 4. Invariantes a verificar (e onde cada um é testado)

| # | Invariante | Teste |
|---|---|---|
| 1 | Nenhum módulo do pacote importa `random`, módulos de rede, `subprocess`, `ctypes` ou `logging` | `tests/test_security_ast.py` (estático, AST) |
| 2 | O audit hook bloqueia socket, subprocess, `os.system`, escrita em arquivo, `os.remove` | `tests/test_guard.py` (dinâmico, subprocesso isolado) |
| 3 | `dice.encode`/`decode` são inversas exatas, para todo `n` pequeno (exaustivo) e amostrado (n maior) | `tests/test_dice.py` |
| 4 | `entropy_to_mnemonic`/`mnemonic_to_entropy` são inversas exatas | `tests/test_bip39.py` |
| 5 | Os 24 vetores oficiais BIP-39 (12/18/24 palavras, com seed PBKDF2) batem exatamente | `tests/test_bip39_vectors.py` |
| 6 | A implementação bate com `python-mnemonic` em 10.000+ entropias aleatórias e casos extremos | `tests/test_dev_cross_check_reference_impl.py` (pulado se a lib de referência não estiver instalada; NUNCA dependência de runtime) |
| 7 | A wordlist embutida tem o hash, contagem, ordenação e unicidade esperados | `tests/test_wordlist.py` |
| 8 | `combine.combine(a,b) == SHA-256(a‖b)` literalmente | `tests/test_combine.py` |
| 9 | `R ~ Binomial(n-1,1/6)` exatamente (T3) e a distribuição de corridas (T4) batem com enumeração exaustiva | `tests/test_stats.py` |
| 10 | O relatório mostrado por `generate` nunca contém p-valores, estatísticas, contagens de face, veredito por teste, a sequência bruta ou qualquer hex de A/B/E — desde a Fase E (procedimento de geração v2) ele é reduzido a só ACCEPTED/REJECTED (`report.minimal_report`); o relatório reduzido anterior (`report.public_report`, contagens + veredito por teste) continua testado mas não é mais usado por `generate` | `tests/test_report.py`, `tests/test_cli_generate.py` |
| 11 | O fluxo `generate` completo produz exatamente `BIP39(SHA256(dice.encode(A) ‖ B))`, e NENHUMA saída — nem a `TerminalIO` abstrata, nem o stdout/stderr REAIS do processo — contém A, B, E ou a sequência bruta em qualquer formato | `tests/test_cli_generate.py` (o teste mais importante do ponto de vista de confidencialidade; a checagem de stdout/stderr reais foi adicionada na revisão de segurança final, `docs/FINAL_SECURITY_REVIEW.md`, após um backdoor de laboratório que escrevia direto em `sys.stdout` escapar da checagem anterior) |
| 12 | Falha do CSPRNG do SO nunca cai para uma fonte alternativa | `tests/test_osrng.py` |
| 13 | Recusa rodar `generate` com interface de rede ativa, a menos que o operador confirme explicitamente com uma frase digitada | `tests/test_cli_generate.py::NetworkCheckRefusalTests` |
| 14 | O build do artefato `.pyz` é byte-a-byte reprodutível | `tests/test_build_reproducible.py`, `make repro` |
| 15 | Uma falha do CSPRNG ou uma interrupção (Ctrl-C) no meio do fluxo não deixa a sequência de dados em nenhuma saída/exceção capturada | `tests/test_generate_interruption_safety.py` |
| 16 | `dice.decode` rejeita um prefixo de comprimento `n=0`, simetricamente a `encode`/`validate_rolls`, que rejeitam uma sequência vazia | `tests/test_dice.py::DecodeNegativeTests::test_rejects_zero_length_prefix` |
| 17 | `tools/preflight_and_generate.py` recusa invocar o `.pyz` se a wordlist, a comparação `.pyz` vs. source, ou o `selftest` falharem | `tests/test_preflight_and_generate.py` |
| 18 | A seed derivada de uma mnemonic deste projeto (`bip39.mnemonic_to_seed`) bate com a implementação `mnemonic` (Trezor), e uma chave mestra BIP-32 derivada dessa seed (via `bip32utils`) bate com uma segunda implementação independente (HMAC-SHA512 cru, biblioteca padrão) — incluindo o vetor de teste oficial da especificação BIP-32 | `tests/test_dev_cross_check_bip32.py` (pulado se `mnemonic`/`bip32utils` não estiverem instalados; NUNCA dependência de runtime); verificação manual com uma carteira externa em `docs/WALLET_IMPORT_TEST.md` |

## 5. Como rodar tudo você mesmo

```sh
# suíte completa (só biblioteca padrão)
python3 -B -m unittest discover -s tests -v

# auto-testes do próprio produto (a partir do source checkout; sem -I, ver nota abaixo)
python3 -B -m entropyforge selftest

# build determinístico + verificação de reprodutibilidade
make repro

# modo determinístico de verificação (dados públicos, nunca use com fundos reais)
python3 -B -m entropyforge vector --entropy-hex 0000000000000000000000000000000000000000000000000000000000000000
# deve imprimir: abandon abandon ... art  (vetor oficial BIP-39 de 256 bits)

# a forma que USA -I -B (modo isolado) e a do artefato empacotado, nao do
# source checkout — ver docs/OPERATIONS.md:
#   make build && python3 -I -B entropyforge.pyz selftest
# Rodar `-I` junto com `-m entropyforge` a partir do source FALHA com
# "No module named entropyforge": -I implica -P, que desativa o prepend
# automatico do diretorio atual ao sys.path (e implica -E, que ignora
# PYTHONPATH). Isso e um comportamento documentado do interpretador
# (novo em Python 3.11), nao um bug deste projeto — mas e facil de
# confundir, por isso a nota aqui.

# opcional: comparar com a implementação de referência (não é dependência do produto)
python3 -m venv /tmp/audit-venv && /tmp/audit-venv/bin/pip install mnemonic
/tmp/audit-venv/bin/python -m unittest tests.test_dev_cross_check_reference_impl -v
```

## 6. O que `selftest` garante — e o que ele NÃO garante

**`selftest` verifica corretude computacional (testes de resposta
conhecida), não a ausência de backdoors.** Uma auditoria adversarial
(`docs/REDTEAM.md`, seção 5.1) construiu um artefato `.pyz`, a partir do
código-fonte real, com `combine.py` alterado para vazar a entropia
combinada via `stderr`. `selftest` continuou reportando
`RESULTADO GERAL: PASSOU`, porque cada teste de resposta conhecida (KAT)
recebeu a resposta CORRETA — o backdoor só acrescentou um efeito
colateral (uma escrita extra em `stderr`), e nenhum KAT verifica a
AUSÊNCIA de efeitos colaterais além do valor de retorno. Em contraste, a
mesma auditoria confirmou que uma wordlist embutida adulterada (1 palavra
trocada) **é** detectada por `selftest`, via o hash SHA-256 comparado
contra `WORDLIST_SHA256`.

**A conclusão prática:** rodar `selftest` contra um artefato cuja
proveniência você não verificou dá falsa confiança. A única defesa real
contra um artefato (ou uma cópia do código-fonte) adulterado é comparar
seu hash contra um build que **você mesmo** reproduziu (`make repro`,
seção 5) a partir de um código-fonte que **você mesmo** revisou (seção 3).
`selftest` é uma checagem de sanidade sobre uma instalação que você já
confia ser a correta — não um substituto para essa confiança.

## 7. O que NÃO está neste repositório (e por quê)

- **Nenhum binário pré-compilado é commitado.** `entropyforge.pyz` é
  sempre gerado localmente por `tools/build_pyz.py`; confiar em um binário
  que você mesmo não gerou (ou não verificou byte a byte) contraria o
  próprio objetivo deste documento.
- **Nenhuma seed, mnemonic ou dado de teste "parecido com real"** aparece
  em nenhum lugar do repositório. Todos os valores de teste são os
  vetores oficiais públicos da especificação BIP-39, ou padrões triviais
  (`bytes(32)`, `bytes(range(32))`) claramente não-secretos.
