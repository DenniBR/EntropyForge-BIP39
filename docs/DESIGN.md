# EntropyForge-BIP39: arquitetura (documento definitivo, pós-implementação)

> **Status:** implementado. Este documento descreve a arquitetura como
> construída. A proposta original (pré-implementação) previa uma etapa de
> revisão antes do código; a revisão aconteceu já em cima do código (ver
> seção 9, "correções feitas em relação à proposta inicial") em vez de
> antes dele, a pedido explícito de quem encomendou o projeto. Para a
> matemática completa, ver `docs/MATH.md`; para o modelo de ameaças,
> `docs/THREAT_MODEL.md`; para auditoria, `docs/AUDIT.md`; para uso,
> `docs/OPERATIONS.md`.

---

## 1. Objetivo e escopo

Ferramenta **offline** de linha de comando que produz um mnemonic BIP-39
de 24 palavras (256 bits de entropia + 8 bits de checksum) a partir de
duas fontes independentes:

- **A**: sequência de lançamentos de um d6 físico, digitada pelo usuário;
- **B**: 256 bits do CSPRNG do sistema operacional (`os.getrandom`).

Saída: `E = SHA-256(A ‖ B)` (256 bits) → `mnemonic = BIP39(E)`.

**Dentro do escopo:** coleta de A e B, validação estatística de A,
combinação, geração BIP-39, auto-testes, relatório público, documentação
matemática, build reprodutível.

**Fora do escopo (decisão D6):** derivação da seed BIP-39 (PBKDF2),
passphrase BIP-39, BIP-32 e endereços, armazenamento do mnemonic,
assinatura de transações. `docs/OPERATIONS.md` §7 documenta por que a
passphrase fica de fora e o que isso significa para quem for usá-la.

---

## 2. Arquitetura

### 2.1 Linguagem e plataforma: Python ≥ 3.11, só com a biblioteca padrão

Zero dependências de terceiros em tempo de execução — só a biblioteca
padrão (`hashlib`, `os`, `math`, `importlib.resources`, `argparse`,
`getpass`, `unicodedata`, `sys`). Motivo: minimizar a base de confiança
(nada além do interpretador e do sistema operacional precisa ser
verificado ou confiado), e permitir comparação direta com a implementação
de referência da própria especificação BIP-39 (`python-mnemonic`), usada
apenas em desenvolvimento (`tests/test_dev_cross_check_reference_impl.py`,
pulado automaticamente se não instalada).

A limpeza de memória é *best-effort*: dados sensíveis ficam em
`bytearray` e são sobrescritos assim que possível, mas o interpretador
cria cópias intermediárias (inteiros, objetos `hashlib`, `str`) que o
coletor de lixo libera sem zerar. Isto não é uma limitação exclusiva de
Python (é verdade em qualquer linguagem gerenciada); a mitigação real é
ambiental — sistema live sem swap, desligar a máquina após o uso.

### 2.2 Fluxo de dados

```
 ┌──────────────┐  teclado (TTY, sem eco)   ┌─────────────────────────────────────────┐
 │ d6 físico    │ ────────────────────────► │ dice.py     A = encode(d1..dn)          │
 └──────────────┘                           │ stats.py    bateria → relatório público │
                                            │                                          │
 ┌──────────────┐  os.getrandom(32)          │ osrng.py    B (32 bytes)               │
 │ kernel CSPRNG│ ────────────────────────► │                                          │
 └──────────────┘                           │ combine.py  E = SHA-256(A ‖ B)          │
                                            │ bip39.py    24 palavras                 │
                                            └──────────────┬───────────────────────────┘
                                                           │ tela alternativa do terminal,
                                                           ▼ exibida uma vez
                                               usuário transcreve em papel/metal
   Nada vai para disco, rede, clipboard ou log. A, B e E nunca são exibidos.
```

### 2.3 Módulos (pacote `entropyforge/`, 2.449 linhas ao todo)

| Módulo | Responsabilidade |
|---|---|
| `wordlist.py` | carrega `data/english.txt` (embutida no pacote) e verifica hash, contagem, ordenação, unicidade |
| `bip39.py` | `entropy_to_mnemonic`, `mnemonic_to_entropy`, `mnemonic_to_seed` (só para testes) |
| `dice.py` | valida `1-6`, codifica A (bijeção, `docs/MATH.md` §3) |
| `entropy_calc.py` | as três perguntas sobre quantidade de lançamentos (`docs/MATH.md` §2) |
| `osrng.py` | lê B via `os.getrandom`; falha fechado, sem fallback |
| `combine.py` | `E = SHA-256(A ‖ B)` |
| `specialfunc.py` | funções especiais em stdlib pura (gama incompleta, binomial exata, Clopper-Pearson, Holm) |
| `stats.py` | bateria de 6 testes estatísticos + correção de Holm (`docs/MATH.md` §8) |
| `report.py` | relatório público (generate) vs. completo (calibrate) |
| `guard.py` | audit hook fail-closed (rede/escrita/subprocess/ctypes) + checagem de interfaces de rede |
| `selftest.py` | KATs executados antes de qualquer geração real |
| `cli.py` | `generate`/`calibrate`/`selftest`/`vector`, via uma abstração de E/S (`TerminalIO`) que permite testar o fluxo completo sem TTY real |
| `__main__.py` | ponto de entrada; ativa o guard antes de importar o resto do pacote |

### 2.4 Subcomandos

| Comando | Função | Toca segredo real? |
|---|---|---|
| `generate` | fluxo principal (§2.5) | sim |
| `calibrate` | lançamentos **descartáveis** em grande quantidade, para medir o dado; nunca chama `bip39`/`combine` | não |
| `selftest` | roda os KATs e sai | não |
| `vector` | modo determinístico com dados **públicos** fornecidos na linha de comando (nunca use com fundos reais) | não |

`generate` exige um TTY interativo real para os dados de entrada — nunca
aceita a sequência de dados por `argv`, variável de ambiente, pipe ou
arquivo redirecionado.

### 2.5 Fluxo do `generate`

1. `guard.activate()` (audit hook + `RLIMIT_CORE=0`), já feito por
   `__main__.py` antes mesmo deste comando ser despachado.
2. Checagem de ambiente: avisa se não está em modo isolado (`-I`) ou se há
   swap ativo; **recusa continuar** (fail-closed) se houver interface de
   rede ativa, a menos que `--override-offline-check` seja passado **e** o
   usuário digite uma frase de confirmação exata interativamente.
3. Roda os auto-testes (`selftest`); aborta se qualquer um falhar.
4. Exige TTY real em stdin e stdout; aborta caso contrário.
5. Calcula e mostra o orçamento de entropia (`entropy_calc.compute_budget`)
   — números sempre recalculados, nunca uma constante fixa no código.
6. Lê a sequência de dados em uma única linha oculta (sem eco); repete até
   receber exatamente o número de lançamentos pedido, todos em `1-6`.
7. Roda a bateria estatística e mostra o relatório **público** (contagens
   de face + vereditos, nunca p-valores nem a sequência). Se o veredito
   geral for FAIL, exige confirmação explícita para continuar.
8. Lê B (`os.getrandom(32)`); se falhar, aborta de forma limpa (sem
   fallback, sem traceback cru).
9. `E = combine(A, B)`, `mnemonic = bip39.entropy_to_mnemonic(E)`.
10. Sobrescreve os `bytearray` de A, B, E com zeros (best-effort).
11. Mostra o mnemonic **uma única vez**, na tela alternativa do terminal;
    espera Enter; limpa a tela; volta ao normal.
12. Oferece, opcionalmente, conferir a transcrição (redigitar as 24
    palavras, sem eco); reporta só "confere"/"não confere", nunca qual
    palavra diverge.

---

## 3. Decisões criptográficas

Esta seção resume as decisões; a matemática completa (com provas, onde
aplicável) está em `docs/MATH.md`, cujas seções são referenciadas abaixo.

### D1. Fonte A: entropia do d6 (`docs/MATH.md` §1–2)

Um lançamento honesto e independente tem `log2(6) ≈ 2,585` bits de
entropia de Shannon. O projeto separa três perguntas — bits teóricos
(`n·log2(6)`), margem operacional com viés assumido (min-entropia,
`p_max = 0,20` como escolha de engenharia documentada), e poder
estatístico (caracterizado por simulação, não assumido) — em vez de
tratar um único número de lançamentos como verdade universal. `generate`
sempre calcula o número recomendado na hora (`entropy_calc.compute_budget`),
nunca usa uma constante fixa.

### D2. Representação binária de A (`docs/MATH.md` §3)

`A = uint16_be(n) ‖ v.to_bytes(W, 'big')`, onde `v` é a representação em
base 6 dos `n` lançamentos. Bijetora entre `{1,...,6}^n` e `[0, 6^n)`
(prova + teste exaustivo). O prefixo de comprimento é público e existe só
para tornar a codificação injetora entre sequências de tamanhos
diferentes. `len(A)` em bits é maior que a entropia real de A — a
contabilidade de entropia nunca usa `len(A)`, sempre `n·log2(6)` ou a
min-entropia correspondente.

### D3. Fonte B: CSPRNG do SO (`docs/MATH.md` §4)

`os.getrandom(32, 0)` no Linux (bloqueia até o gerador do kernel estar
inicializado); `os.urandom` como equivalente em outros SOs. Falha
**fechada**: qualquer erro na leitura aborta o processo sem fallback para
uma fonte alternativa. O módulo `random` nunca é importado em
`entropyforge/` (verificado estaticamente por AST, `tests/test_security_ast.py`).

### D4. Combinação `E = SHA-256(A ‖ B)` (`docs/MATH.md` §5–6)

Implementada literalmente. SHA-256 **não gera entropia** — é uma função
determinística; toda a imprevisibilidade de E vem de A e B. O argumento de
segurança (heurístico, modelo do oráculo aleatório) limita a vantagem de
um adversário por `q · 2^(-k)`, onde `k` é a min-entropia conjunta de
(A, B) do ponto de vista do adversário: **basta que uma das duas fontes
seja boa e desconhecida do adversário**. A combinação não ajuda se o
adversário conhece A e controla B (ex.: SO comprometido) — protege contra
falha independente de uma fonte, não contra comprometimento do ambiente.

`docs/MATH.md` §5.3 discute, e explicitamente rejeita como argumento de
segurança, um cálculo secundário sobre a entropia de Shannon da *saída*
de uma função aleatória (efeito de ~0,83 bit, via estatística de
mapeamentos aleatórios de Flajolet-Odlyzko) — matematicamente correto sob
suas próprias suposições, mas irrelevante para o argumento real
(min-entropia da entrada, não entropia de Shannon da saída) e numericamente
desprezível. Isso não faz parte de nenhuma conta usada pelo produto.

### D5. BIP-39 (`docs/MATH.md` §7)

Especificação oficial implementada literalmente e verificada contra os 24
vetores oficiais e contra a implementação de referência (10.000+ entropias
aleatórias + casos extremos, em desenvolvimento).

### D6. O que não é implementado no produto

Derivação de seed (PBKDF2) e passphrase ficam fora do fluxo `generate`
(a carteira do usuário faz essa parte); `mnemonic_to_seed` existe só para
testes contra os vetores oficiais. BIP-32/endereços exigiriam secp256k1 e
aumentariam a superfície auditável sem necessidade para o objetivo deste
projeto.

---

## 4. Validação estatística de A

Ver `docs/MATH.md` §8 (as distribuições nulas, com prova onde exata) e
§10 (poder estatístico, por simulação). Resumo: 6 testes com correção de
Holm-Bonferroni (α = 0,01 familiar); T2 (diferenças seriais) e T3
(repetições) têm distribuição nula **exata** sob H0 (prova incluída); T4
(corridas) tem distribuição exata combinatória clássica; T1 (frequência)
e T5 (autocorrelação) usam aproximações assintóticas padrão, cuja validade
no `n` operacional é checada por simulação, não assumida.

**Nenhum teste, nem a bateria completa, prova aleatoriedade** — só pode
rejeitar a hipótese nula ao detectar desvio grosseiro. Isso é reforçado
tanto no código (mensagens do relatório) quanto na documentação.

---

## 5. Garantias matemáticas vs. premissas

Ver `docs/MATH.md` §11 para a tabela completa. Resumo: a bijeção da
codificação, as distribuições nulas exatas de T2–T4, a corretude do
BIP-39 (contra vetores oficiais e implementação de referência), e o
orçamento de vazamento do relatório são **fatos matemáticos verificados**.
A honestidade do dado físico, a qualidade do CSPRNG do SO, e a suposição
de que SHA-256 se comporta como oráculo aleatório são **premissas** que
o software não tem como verificar.

---

## 6. Modelo de ameaças

Ver `docs/THREAT_MODEL.md` — cobre sistema operacional/kernel/firmware/
hardware comprometidos, malware e keyloggers, supply chain, viés e
dependência do dado físico, erro humano, captura do mnemonic (visual,
clipboard, screenshot), swap, arquivos temporários, logs, VMs e
snapshots, comprometimento físico, mídia de boot, implementação
incorreta (com incidentes reais citados), e computação quântica (sem
afirmações absolutas).

---

## 7. Controles de confidencialidade

- **Rede:** audit hook bloqueia qualquer criação de socket; checagem de
  interfaces ativas fail-closed antes de `generate`.
- **Disco:** audit hook bloqueia qualquer `open` em modo de escrita,
  `os.remove`, `os.rename`, `shutil.*`, `tempfile.*`.
- **Saída:** relatório público nunca contém a sequência, p-valores, ou
  hex de A/B/E; mnemonic exibido uma única vez, em tela alternativa do
  terminal (fora do scrollback). Verificado automaticamente em
  `tests/test_cli_generate.py` (captura toda a saída de uma execução
  completa e confirma ausência de vazamento).
- **Clipboard/impressora:** nunca usados (nenhum código de integração
  existe).

---

## 8. Build reprodutível e auditoria

`tools/build_pyz.py` gera um zipapp determinístico (ordem de arquivos
fixa, timestamps fixos em 1980-01-01, `ZIP_STORED`, permissões fixas).
`make repro` builda duas vezes, em diretórios e umask diferentes, e
confirma hash idêntico — verificado também como teste automatizado
(`tests/test_build_reproducible.py`). Ver `docs/AUDIT.md` para hashes,
ordem de leitura sugerida, e a lista completa de invariantes verificados
por teste.

---

## 9. Correções feitas em relação à proposta inicial

A proposta pré-implementação (revisada já em conjunto com o código, a
pedido explícito de quem encomendou o projeto) continha alguns pontos que
não sobreviveram à implementação sem ajuste:

1. **Números de lançamento "mágicos" (119/126/132).** Substituídos por
   `entropy_calc.py`, que separa explicitamente as três perguntas (bits
   teóricos, margem operacional, poder estatístico) e calcula tudo em
   função de parâmetros explícitos (`target_bits`, `p_max`,
   `num_verdict_tests`) — nenhuma dessas quantidades está hardcoded como
   constante solta. O relatório público também foi redesenhado (contagens
   + vereditos, sem p-valores) para reduzir o vazamento de ~50 para ~38
   bits no `n` operacional.
2. **T3 ("repetições") descrito como exato sem prova explícita.** A
   proposta original já usava a palavra "exata", mas sem demonstrar por
   quê. `docs/MATH.md` §8 agora inclui a prova (via o argumento de
   filtração/martingale: cada indicador de repetição é, condicional ao
   passado, um Bernoulli(1/6) exato), verificada também por enumeração
   exaustiva em teste.
3. **T4 (runs) usava aproximação normal na proposta original.** Substituído
   pela distribuição exata combinatória de Wald-Wolfowitz, condicional na
   divisão observada — mais forte que uma aproximação, e sem custo de
   implementação relevante (fórmula fechada em termos de coeficientes
   binomiais).
4. **A afirmação sobre perda de "0,83 bit" na saída de SHA-256** foi
   auditada matematicamente (a conta está correta sob suas próprias
   suposições — estatística de mapeamentos aleatórios de Flajolet-Odlyzko)
   mas **rebaixada** de "argumento de segurança" para "nota técnica
   explicitamente não usada em nenhum lugar do produto", com a distinção
   entre entropia de Shannon, min-entropia, número de estados e segurança
   computacional explicada em `docs/MATH.md` §6. Nenhuma conta do projeto
   depende desse número.
5. **Meta de tamanho de código (~1.500 linhas)** não foi cumprida (o
   total é 2.449 linhas) — documentado honestamente em `docs/AUDIT.md` em
   vez de mantida como uma afirmação desatualizada.
6. **Bug de segurança encontrado pelos próprios testes durante o
   desenvolvimento:** a primeira versão de `cli.py` passava a flag de
   override de rede diretamente para `guard.check_offline`, o que
   **pulava silenciosamente** a etapa de confirmação explícita por frase
   digitada sempre que a flag estivesse presente — o oposto do
   comportamento fail-closed pretendido. Detectado por
   `tests/test_cli_generate.py::NetworkCheckRefusalTests`, corrigido, e
   coberto por um teste de regressão específico
   (`test_refuses_if_override_flag_but_wrong_confirmation`).
7. **Perguntas em aberto da proposta original**, todas resolvidas na
   implementação: codificação de A por inteiro base-6 (D2); fórmula de
   combinação mantida literal, sem tag de domínio (D4); mnemonic exibido
   uma vez, entropia/seed nunca exibidas (§2.5, item 11); conferência de
   transcrição implementada como opcional, padrão desligada (§2.5, item
   12); rede ativa é fail-closed com override explícito e frase de
   confirmação (§2.5, item 2); política em FAIL estatístico é abortar com
   override explícito, não silencioso (§2.5, item 7).

---

## 10. Rastreabilidade dos requisitos

| Req. | Onde |
|---|---|
| 1 sem PRNG próprio | D3; `tests/test_security_ast.py` |
| 2 d6 `1–6` | §2.5, D1, D2 |
| 3 B 256 bits do CSPRNG do SO | D3 |
| 4 validação estatística | §4, `docs/MATH.md` §8 |
| 5 `log2 6` por lançamento | D1, `docs/MATH.md` §1 |
| 6 sem "prova" de aleatoriedade | §4, `docs/MATH.md` §8 (intro) |
| 7 binário sem inflar bits | D2, `docs/MATH.md` §3 |
| 8 `SHA-256(A ‖ B)` 256 bits | D4 |
| 9 e 10 BIP-39 24 palavras com checksum | D5, `docs/MATH.md` §7 |
| 11 testes contra implementação conhecida | `docs/AUDIT.md` §4, item 6 |
| 12 auditoria completa | `docs/AUDIT.md` |
| 13 sem rede | §7; `tests/test_guard.py`, `tests/test_security_ast.py` |
| 14 sem logs, temporários ou clipboard | §7; `tests/test_guard.py` |
| 15 build/reprodução determinística | §8; `tests/test_build_reproducible.py` |
| 16 só métricas públicas | §7; `tests/test_report.py`, `tests/test_cli_generate.py` |
| 17 testes e documentação matemática | `docs/AUDIT.md`, `docs/MATH.md` |
| 18 garantias vs. premissas | §5, `docs/MATH.md` §11 |
| 19 análise de ameaças | `docs/THREAT_MODEL.md` |
| 20 sem afirmações absolutas | `docs/THREAT_MODEL.md` §3; `docs/MATH.md` (rótulos FATO/HEURÍSTICA/PREMISSA/OPINIÃO) |
