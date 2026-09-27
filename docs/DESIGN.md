# EntropyForge-BIP39: proposta de design (v0, para revisão)

> **Status:** proposta. Nenhum código foi escrito. Este documento descreve a
> arquitetura, o modelo de ameaças e as decisões criptográficas. A implementação
> começa só depois da aprovação. As perguntas em aberto estão na seção 12.

---

## 1. Objetivo e escopo

Ferramenta **offline** de linha de comando que produz um mnemonic BIP-39 de
24 palavras (256 bits de entropia + 8 bits de checksum) a partir de duas fontes
independentes:

- **A**: sequência de lançamentos de um d6 físico, digitada pelo usuário;
- **B**: 256 bits do CSPRNG do sistema operacional.

Saída: `E = SHA-256(A || B)` (256 bits) → `mnemonic = BIP39(E)`.

**Dentro do escopo:** coleta de A e B, validação estatística de A, combinação,
geração BIP-39, auto-testes, relatório público, documentação matemática, build
reprodutível.

**Fora do escopo (proposta):** derivação da seed BIP-39 (PBKDF2), passphrase
BIP-39, BIP-32 e endereços, armazenamento do mnemonic, assinatura de transações.
Ver a decisão D6 e a pergunta Q4.

---

## 2. Arquitetura

### 2.1 Linguagem e plataforma: Python ≥ 3.11, só com a biblioteca padrão

| Critério | Python (stdlib) | Go (stdlib) | Rust |
|---|---|---|---|
| Dependências em runtime | **0** | 0 | ≥ 2 crates (sha2, getrandom, zeroize…) |
| Legibilidade para auditoria | **alta** | alta | média |
| Implementação BIP-39 de referência | **python-mnemonic (Trezor), citada na própria BIP-39** | forks de terceiros | crates de terceiros |
| Build bit-a-bit reprodutível | zipapp determinístico (sem compilação) | **excelente (`-trimpath`)** | possível, mais trabalhoso |
| Apagar segredos da memória | **não é garantido** (objetos imutáveis, GC) | parcial | melhor (`zeroize`) |
| Disponível em SO live/air-gapped | **Tails 6/7, Debian, Ubuntu já trazem** | exige levar o binário | exige levar o binário |
| Guardas em runtime | **`sys.addaudithook` (PEP 578)** | — | — |

**Recomendação: Python ≥ 3.11 usando só a biblioteca padrão.** O motivo principal
é o tamanho da base de confiança: nenhuma dependência de terceiros em runtime,
código curto e legível, e comparação direta com a implementação de referência da
BIP-39. A limpeza de memória, ponto fraco do Python, é best-effort em qualquer
linguagem gerenciada, e a mitigação real é o ambiente (seção 7.4). Alternativa
aceitável se você preferir um binário único: Go só com stdlib (pergunta Q1).

### 2.2 Fluxo de dados

```
 ┌──────────────┐  teclado (TTY, sem eco)  ┌────────────────────────────────────────────┐
 │ d6 físico    │ ───────────────────────► │ dice.py  parse → A = enc6(d1..dn)          │
 └──────────────┘                          │ stats.py testes → relatório público (R)    │
                                           │                                            │
 ┌──────────────┐  getrandom(32, bloqueante)│ osrng.py B (32 bytes) + health checks     │
 │ kernel CSPRNG│ ───────────────────────► │                                            │
 └──────────────┘                          │ combine.py  E = SHA-256(A || B)            │
                                           │ bip39.py    CS = SHA-256(E)[0]             │
                                           │             24 × 11 bits → palavras        │
                                           └──────────────┬─────────────────────────────┘
                                                          │ tela alternativa do terminal,
                                                          ▼ exibida uma vez
                                              usuário transcreve em papel/metal
   Nada vai para disco, rede, clipboard ou log. A, B e E nunca são exibidos.
```

### 2.3 Módulos (pacote `entropyforge/`)

| Módulo | Responsabilidade | Toca segredos? |
|---|---|---|
| `wordlist.py` + `data/english.txt` | carrega a wordlist oficial e verifica o SHA-256 fixado `2f5eed53…24dbda` | não |
| `bip39.py` | `entropy_to_mnemonic`, `mnemonic_to_entropy` (checksum); funções puras | sim |
| `dice.py` | valida símbolos `1–6`, codifica A (seção 3.2), contabiliza entropia | sim |
| `osrng.py` | lê B via `os.getrandom(32)`; health checks | sim |
| `combine.py` | `SHA-256(A ‖ B)` | sim |
| `stats.py` | testes estatísticos e funções especiais (gama incompleta, erfc) em stdlib pura | sim (lê A) |
| `report.py` | monta o relatório público e calcula o limite de vazamento L(n) | não (só agregados) |
| `guard.py` | audit hook: bloqueia rede, escrita em arquivo, subprocess, ctypes; `RLIMIT_CORE=0` | não |
| `selftest.py` | KATs na inicialização: SHA-256 (NIST), vetores BIP-39, hash da wordlist | não |
| `cli.py` | fluxo interativo, checagem de TTY e ambiente, exibição na tela alternativa | sim |

Meta de tamanho: **menos de ~1.500 linhas** de código de produto, para que uma
auditoria completa leve horas, não semanas.

### 2.4 Subcomandos

| Comando | Função | Usa segredo real? |
|---|---|---|
| `generate` | fluxo principal (seção 2.5) | sim |
| `calibrate` | centenas a milhares de lançamentos **descartáveis** para medir o viés do dado; relatório completo | não (os dados são descartados) |
| `selftest` | roda todos os KATs e sai | não |
| `vector --file X.json` | **modo determinístico**: calcula `E` e o mnemonic a partir de A e B fixos num arquivo de vetores públicos, para auditores reproduzirem com ferramentas independentes. Imprime aviso: "NÃO USE PARA FUNDOS REAIS" | não |

`generate` **nunca** aceita B vindo de fora, nem dados de dado por `argv`, pipe
ou arquivo: exige TTY interativo.

### 2.5 Fluxo do `generate`

1. Ativa o `guard` (audit hook, `RLIMIT_CORE=0`) e checa o ambiente: interfaces de
   rede ativas, swap ativo, execução sem `-I` (modo isolado). Cada problema gera
   um aviso; se houver interface de rede ativa, a execução é recusada (pergunta Q6).
2. Roda os auto-testes (KATs). Se algum falhar, aborta.
3. Pergunta o número de lançamentos `n` (padrão ≈ 132, mínimo ≈ 119; seção 3.1).
4. Coleta os lançamentos em blocos de 10, **sem eco**, mostrando só o progresso
   (`30/132`). Caracteres fora de `1–6` são rejeitados sem mostrar o que foi digitado.
5. Lê B com `os.getrandom(32)` (bloqueia até o pool do kernel estar inicializado).
6. Roda os testes estatísticos e exibe o relatório público (seção 4.4). Se o
   resultado for FAIL, aborta e sugere trocar de dado ou refazer os lançamentos.
7. Calcula `E = SHA-256(A ‖ B)` e o mnemonic.
8. Muda para a tela alternativa do terminal (`ESC[?1049h`), mostra as 24 palavras
   numeradas, espera Enter, limpa a tela e volta (`ESC[?1049l`).
9. Opcional: o usuário redigita as 24 palavras sem eco, para conferir a
   transcrição (pergunta Q5).
10. Sobrescreve os `bytearray` com segredos (best-effort) e sai.

---

## 3. Decisões criptográficas

### D1. Fonte A: entropia do d6

- Um lançamento de um d6 honesto tem entropia `H = log2 6 ≈ 2,5849625` bits.
  Para uma distribuição uniforme, a entropia de Shannon e a min-entropia coincidem.
- `n` lançamentos i.i.d. honestos têm `H(A) = n · log2 6`.
- Com viés, o que importa para segurança é a **min-entropia**:
  `H∞ = −n · log2 p_max`, onde `p_max` é a probabilidade da face mais provável.

| n | n·log2 6 | H∞ com p_max = 0,18 | H∞ com p_max = 0,20 |
|---|---|---|---|
| 99 | 255,9 | 244,9 | 229,9 |
| 100 | 258,5 | 247,4 | 232,2 |
| 119 | 307,6 | 294,4 | 276,3 |
| 132 | 341,2 | 326,6 | 306,5 |

**Proposta:** exigir que A tenha, sozinha, ≥ 256 bits de min-entropia **depois**
de descontar o que o relatório público revela (seção 4.4). Assim a saída
continua segura mesmo se B estiver totalmente comprometido.

- **Mínimo obrigatório:** `n ≥ 119` (dado honesto, relatório descontado).
- **Padrão recomendado:** `n = 132` (supõe `p_max ≤ 0,20`, relatório descontado).
- Os valores exatos são calculados em código com aritmética inteira e documentados.

A premissa i.i.d. (lançamentos independentes e identicamente distribuídos) **não
pode ser provada** por software. É uma premissa física sobre o dado, a técnica
de lançamento e a honestidade do usuário.

### D2. Representação binária de A (requisito 7)

```
v  = Σ_{i=1..n} (d_i − 1) · 6^(n−i)          (inteiro em [0, 6^n))
W  = ceil( bit_length(6^n − 1) / 8 )          (largura fixa em bytes)
A  = uint16_be(n) ‖ int_to_bytes_be(v, W)
```

- `enc6` é uma **bijeção** entre `{1..6}^n` e `[0, 6^n)`. A codificação não cria
  nem descarta informação.
- O prefixo `n` (público, 0 bits de entropia) torna a codificação injetiva entre
  sequências de comprimentos diferentes. Sem ele, "1,2,3" e "2,3" produziriam o
  mesmo inteiro, porque um `1` à esquerda vira o dígito zero.
- A ocupa `16 + 8W` bits, mas **contém no máximo `n·log2 6` bits de entropia**.
  Exemplo: com n = 132, v cabe em 342 bits; W = 43 bytes = 344 bits. A
  contabilidade usa sempre `n·log2 6` e nunca o tamanho em bits.
- Não usamos mapeamentos com perda ou inflados, como "3 bits por dado", ASCII
  contado como 8 bits por símbolo ou rejeição de 5 e 6.
- Verificável com ferramentas independentes: `bc` com `ibase=6` e `xxd` + `sha256sum`
  (receita no guia de auditoria).

Alternativa (pergunta Q2): A = string ASCII dos dígitos, como faz o Coldcard. É
mais fácil de verificar à mão, mas é menos "binária" no sentido do requisito 7.

### D3. Fonte B: CSPRNG do SO

- Linux: `os.getrandom(32, 0)`. É a syscall `getrandom(2)`, que bloqueia até o
  CRNG do kernel estar inicializado. Não lê `/dev/urandom` diretamente, porque em
  kernels antigos ele pode entregar bytes antes da inicialização.
- Outros SOs: `os.urandom` (macOS usa `getentropy`, Windows usa `BCryptGenRandom`),
  com aviso de que o suporte principal é Linux.
- **Health checks:** as leituras não podem ser todas iguais nem todas zero, e duas
  leituras consecutivas devem ser diferentes. Esses checks **só detectam falhas
  grosseiras**, como um RNG travado. Um RNG com backdoor passa em todos.
- O produto **nunca importa o módulo `random`** nem usa PRNG próprio. Um teste
  estático de AST garante isso (requisito 1).

### D4. Combinação: `E = SHA-256(A ‖ B)`

Implementada exatamente como no requisito 8. Como B tem 32 bytes fixos e A é
autodelimitada, `A ‖ B` é decodificável de forma única. A saída tem exatamente
256 bits.

**O que é possível afirmar:**

1. **Modelo do oráculo aleatório (ROM).** Tratando SHA-256 como função aleatória,
   um adversário que não conhece `A ‖ B` e faz `q` consultas distingue E de
   uniforme com vantagem ≤ `q · 2^(−k)`, onde `k = H∞(A, B | visão do adversário)`.
   Se A e B forem independentes, `k ≥ max(H∞(A), H∞(B))`, ou seja, **basta uma
   fonte boa**, desde que o adversário não conheça a outra.
2. **Limite honesto:** SHA-256 **não tem prova** de ser um extrator de
   aleatoriedade no modelo padrão. O argumento é heurístico (ROM). HKDF-Extract
   (RFC 5869) tem análise mais forte como extrator, mas o requisito fixa
   `SHA-256(A ‖ B)`. Mantemos a fórmula e documentamos a alternativa (pergunta Q3).
3. **Perda na compressão:** uma função aleatória aplicada a uma entrada uniforme
   de exatamente 256 bits produz uma saída com entropia de Shannon ≈ `256 − 0,827`
   bits (`E[K log2 K]` para `K ~ Poisson(1)`). A min-entropia fica ≈ 251 bits. Por
   isso A também deve ter ≥ 256 bits: com as duas fontes boas, a entrada tem
   ≥ 512 bits e a saída fica estatisticamente próxima de uniforme.
4. **Onde a combinação não ajuda:** se o adversário **conhece A e controla B**
   (por exemplo, um SO comprometido que vê as teclas e fornece B), E fica
   totalmente determinada por ele. A combinação protege contra **falha de uma
   fonte**, não contra comprometimento do ambiente onde as duas se encontram.

### D5. BIP-39 (requisitos 9 e 10)

Implementação da especificação oficial (bitcoin/bips, `bip-0039.mediawiki`):

```
ENT = 256 bits  (E)
CS  = ENT/32 = 8 bits = primeiros 8 bits de SHA-256(E)
bits = E ‖ CS   (264 bits)
palavras = 24 grupos de 11 bits, MSB primeiro → índice em english.txt (2048 palavras)
```

- Wordlist embutida; SHA-256 fixado e conferido (hoje) com o repositório oficial:
  `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`. Ela é
  verificada na inicialização e nos testes, junto com: 2048 palavras únicas,
  ordenadas, só ASCII minúsculo, prefixos de 4 letras únicos.
- `mnemonic_to_entropy` com verificação de checksum, para testes de ida e volta.
- Como a wordlist em inglês é ASCII, NFKD não afeta a geração do mnemonic. A
  normalização só importa na derivação PBKDF2, que fica fora do produto (D6).

### D6. O que não será implementado no produto

- **Derivação da seed (PBKDF2-HMAC-SHA512, 2048 iterações) e passphrase:** fora
  do fluxo `generate`. A carteira faz essa parte. Isso reduz a superfície que
  toca segredos. Uma função `mnemonic_to_seed` existe **só na suíte de testes**,
  para validar contra os vetores oficiais (passphrase `"TREZOR"`).
- **BIP-32, endereços, fingerprint:** exigiriam secp256k1 e aumentariam o código
  auditável.

---

## 4. Validação estatística de A (requisito 4)

### 4.1 Hipótese testada

H0: os lançamentos são i.i.d. uniformes em `{1..6}`. Um teste pode **rejeitar**
H0 ao detectar desvio grosseiro. **Nenhum teste prova aleatoriedade**, muito menos
aleatoriedade criptográfica. Uma sequência determinística "bem-comportada", como
os dígitos de π em base 6 ou uma sequência inventada por um humano cuidadoso,
pode passar em todos os testes com entropia ≈ 0 (requisito 6).

### 4.2 Bateria de testes, escolhida para ter distribuição nula válida com n ≈ 130

| # | Teste | Estatística e distribuição sob H0 | O que detecta |
|---|---|---|---|
| T1 | Frequência das faces | contagens `c_1..c_6`, qui-quadrado GoF, gl = 5 | viés de face |
| T2 | Diferenças seriais | `δ_i = (d_{i+1} − d_i) mod 6`. Sob H0 as `δ_i` são **i.i.d. uniformes**, então vale um qui-quadrado GoF exato com gl = 5 | dependência entre lançamentos consecutivos |
| T3 | Repetições | `#{i : d_i = d_{i+1}} ~ Binomial(n−1, 1/6)` exata (consequência de T2) | sequências "inventadas" com poucas repetições |
| T4 | Runs acima/abaixo de 3,5 | Wald–Wolfowitz; não há empates, porque 3,5 não é valor possível | agrupamento, tendência |
| T5 | Autocorrelação lags 1–3 | `r_k·√(n−k)` ≈ N(0,1); combinação por Holm | dependência linear |

- Correção de múltiplos testes: **Holm–Bonferroni** com α familiar = 0,01.
- Descartamos de propósito uma tabela de contingência 6×6 de pares consecutivos:
  com n ≈ 130 as células esperadas ficam em ~3,6, abaixo do mínimo para a
  aproximação qui-quadrado. T2 e T3 cobrem essa independência com nulas exatas.
- Funções especiais em stdlib pura (Q regularizada da gama incompleta, `math.erfc`,
  binomial exata), testadas contra valores tabelados.

### 4.3 Poder estatístico (limitação importante)

Probabilidade de o qui-quadrado (T1, α = 0,01) detectar um dado com **uma** face
viciada. Valores obtidos por simulação na fase de design:

| p da face viciada | n = 130 | n = 600 | n = 3000 |
|---|---|---|---|
| 0,18 | ~1% | ~2% | ~12% |
| 0,20 | ~3% | ~17% | ~93% |
| 0,25 | ~25% | ~97% | ~100% |

**Conclusão:** na sessão real (n ≈ 130) os testes só pegam defeitos **grosseiros**,
como um dado viciado de verdade ou um erro sistemático de digitação. Viés moderado
é tratado por **superdimensionamento** (D1: supor `p_max ≤ 0,20`) e pelo modo
**`calibrate`**, que usa milhares de lançamentos descartáveis e dá um limite
superior de confiança (Clopper–Pearson) para `p_max` do dado. Esse limite pode
substituir o valor 0,20 no cálculo de `n`.

### 4.4 Relatório público e o vazamento que ele causa

Estatísticas calculadas a partir de A **revelam informação sobre A**. Para que o
relatório seja de fato "público" (requisito 16), limitamos o vazamento com a
regra da cadeia para min-entropia média
(Dodis–Ostrovsky–Reyzin–Smith, 2004): `H̃∞(A | R) ≥ H∞(A) − log2 |𝓡|`.

Conteúdo do relatório e cardinalidade de cada item:

- contagens das 6 faces: `log2 C(n+5, 5)` ≈ 28,5 bits para n = 132. O p-valor de
  T1 é função das contagens e não acrescenta vazamento;
- T2 a T5: veredito (PASS/WARN/FAIL) + p-valor com **uma casa decimal**, no máximo
  `log2 33` ≈ 5,04 bits por teste;
- veredito global: `log2 3` bits.

`L(n) ≈ 50` bits. Esse valor já foi descontado nos mínimos de D1. O relatório
**nunca** mostra a sequência, pares, a matriz de transições, B nem E.

Custo de refazer os lançamentos após um FAIL: descartar sequências que falham
(probabilidade α) custa ≤ `−log2(1 − α)` ≈ 0,0145 bit. É desprezível.

---

## 5. Garantias matemáticas vs. premissas (requisito 18)

### 5.1 Garantido por construção e verificável por prova ou teste exaustivo

- `enc6` é bijetora, e A é injetiva entre todos os `n` (prova curta mais teste
  exaustivo para n ≤ 8).
- `E` tem exatamente 256 bits. O mnemonic tem exatamente 24 palavras da wordlist
  oficial.
- O checksum segue a BIP-39. `mnemonic_to_entropy(entropy_to_mnemonic(E)) = E`
  para todo E.
- `f(A, B)` é determinística: as mesmas entradas dão a mesma saída (modo `vector`).
- As contas de entropia e vazamento (D1, 4.4) são corretas **dadas** as premissas.

### 5.2 Depende de premissas que o software não consegue verificar

| Propriedade | Depende de |
|---|---|
| A tem `n·log2 6` bits | dado honesto, lançamentos independentes, usuário lança de fato (não inventa nem escolhe) |
| B tem 256 bits | kernel, hardware (RDRAND, TPM, jitter) e estado de boot corretos e sem backdoor |
| E é indistinguível de uniforme | SHA-256 se comportar como oráculo aleatório (heurística) **e** ≥ 1 fonte boa **e** independência entre A e B |
| Sigilo de E | SO, firmware, hardware e ambiente físico não comprometidos |
| O código faz o que diz | interpretador Python e SO íntegros, código auditado e verificado por hash |

---

## 6. Modelo de ameaças (requisito 19)

### 6.1 Ativos

E e o mnemonic (críticos); A e B (críticos: com os dois se reconstrói E);
integridade do código; integridade da wordlist.

### 6.2 Fronteira de confiança

Tudo que roda no host (firmware, kernel, interpretador, terminal, este programa)
está **em um único domínio de confiança**. Se o host for comprometido, A, B e E
ficam expostos juntos. A redundância das duas fontes protege contra **falha de
fonte**, não contra **comprometimento do host**.

### 6.3 Ameaças

| # | Ameaça | Exemplo real / vetor | Mitigação proposta | Risco residual |
|---|---|---|---|---|
| T-OS | **Comprometimento do SO** | kernel ou userland adulterados, rootkit | SO live amnésico verificado (Tails, ISO com assinatura conferida), máquina air-gapped, nunca reconectada; checagem de rede e swap no início | **Alto se ocorrer**: o SO vê tudo. Nenhum software dentro do SO resolve |
| T-MAL | **Malware** | keylogger, captura de tela, exfiltração posterior por USB ou canal coberto | air-gap; boot limpo; sem clipboard; tela alternativa; sem arquivos; audit hook | Malware no host vence. A mitigação é ambiental |
| T-RNG | **RNG defeituoso** | Debian OpenSSL (2008), Android `SecureRandom` (2013), Dual_EC_DRBG, RDRAND da AMD retornando `0xFFFFFFFF` (2019), baixa entropia no boot | `getrandom` bloqueante; A independente com ≥ 256 bits; health checks (só falhas grosseiras) | Se B tiver backdoor **e** A for fraca, a saída é fraca |
| T-DICE | **Viés do dado / fonte física** | dado de baixa qualidade, dado viciado, técnica de lançamento, usuário que "escolhe" ou inventa números, digitação errada sistemática | dados de cassino, copo; superdimensionar `n`; `calibrate`; testes T1–T5 (só grosseiros); B cobre A fraca | Viés sutil não é detectável com n ≈ 130; sequência inventada com cuidado passa nos testes |
| T-IMPL | **Implementação incorreta** | CVE-2023-39910 "Milk Sad" (libbitcoin `bx`, mt19937 com seed de 32 bits); Trust Wallet 2023 (mt19937); erros de endianness, checksum ou wordlist | proibir PRNG próprio (teste de AST); vetores oficiais; comparação com python-mnemonic em milhares de entradas; testes de propriedade; KATs na inicialização; wordlist com hash fixado; código pequeno | Erro comum ao nosso código e à referência (mitigado pelos vetores oficiais e por uma 2ª implementação no estilo "string de bits" nos testes) |
| T-SC | **Supply chain** | download adulterado, interpretador Python comprometido, conta do repositório comprometida, dependência de teste maliciosa, CI comprometido, "Trusting Trust" | 0 dependências em runtime; dependências de teste fixadas por hash (`--require-hashes`) e usadas só no ambiente de desenvolvimento; build reprodutível com `SHA256SUMS`; tags assinadas; verificação da ISO do SO | Confiança no interpretador e no SO é inevitável; mitigar com verificação por várias partes |
| T-HW | **Comprometimento do hardware** | firmware ou microcódigo, Intel ME / AMD PSP, teclado com keylogger, dispositivo USB malicioso, emanação eletromagnética (TEMPEST), acústica, câmeras, cold-boot de RAM | máquina dedicada sem Wi-Fi/Bluetooth (módulos removidos), teclado confiável, ambiente físico privado; desligar e esperar após o uso | Não verificável por software |
| T-OBS | **Observação física** | câmera filmando os dados, a tela ou o papel | ambiente privado; entrada sem eco; mnemonic exibido uma vez | Depende do usuário |
| T-PERSIST | **Persistência acidental** | swap, hibernação, core dump, scrollback do terminal (macOS Terminal salva scrollback), histórico do shell, `.pyc`, tracebacks com valores | sem `argv`/pipe para segredos; `RLIMIT_CORE=0`; aviso se houver swap; tela alternativa; `python -I -B`; `sys.excepthook` que imprime só o tipo do erro; sem módulo `logging`; audit hook bloqueia `open(...,'w')` | Liberação de memória sem zerar no Python (best-effort, ver 7.4) |
| T-USER | **Erro do usuário / engenharia social** | site falso, instrução para "digitar a seed online" | documentação operacional; o programa nunca pede o mnemonic, exceto na conferência local opcional | Fora do controle do software |
| T-Q | **Computação quântica** | Grover: busca em espaço de 2^256 cai para ordem de 2^128 avaliações quânticas; Shor quebra ECDSA/Schnorr secp256k1 **depois que a chave pública é exposta** | fora do escopo da geração; documentar sem afirmações absolutas | O mnemonic não protege chaves públicas já expostas contra um computador quântico criptograficamente relevante, se um existir |

---

## 7. Controles de confidencialidade

### 7.1 Rede (requisito 13)

- Nenhum módulo de rede é importado (`socket`, `ssl`, `http`, `urllib`, `asyncio`,
  etc.). Um teste de AST garante isso.
- O audit hook aborta o processo em qualquer evento `socket.*`, `urllib.Request`,
  `subprocess.Popen`, `os.system`, `os.exec*`, `ctypes.*`, `import` de módulos de rede.
- Na inicialização, lê `/sys/class/net/*/operstate` e recusa rodar se houver uma
  interface diferente de `lo` com estado `up` (flag de override: pergunta Q6).
- Limite: um audit hook não se defende de um interpretador comprometido. Ele
  pega regressões e bugs, não um adversário que já controla o processo.

### 7.2 Disco, logs, clipboard (requisito 14)

- Nenhum arquivo é escrito. O audit hook bloqueia `open` em modo de escrita,
  `os.rename`, `os.remove`, `shutil.*` e `tempfile`.
- Não há `logging`, clipboard, `readline` nem histórico.
- Segredos não entram por `argv` nem por variáveis de ambiente, só por TTY sem eco.

### 7.3 Saída (requisito 16)

- Exibidos: progresso, relatório público (4.4), auto-testes, avisos de ambiente.
- Exibido **uma vez**, na tela alternativa: o mnemonic, que é o produto. Precisa
  ser mostrado para ser transcrito (pergunta Q4).
- **Nunca** exibidos: A, a sequência de dados, B, E em hex, a seed BIP-39.
- Teste automatizado: roda o fluxo completo com B injetado e verifica que os
  hex/b64 de A, B e E não aparecem em stdout ou stderr, e que o mnemonic aparece
  só dentro do bloco da tela alternativa.

### 7.4 Memória (limite honesto)

Segredos ficam em `bytearray` e são sobrescritos no fim. Mesmo assim o Python cria
cópias imutáveis (`int` do base-6, estado interno do `hashlib`, `str` das
palavras) que o coletor de lixo libera **sem zerar**. **Não prometemos apagamento
de memória.** A mitigação real: SO amnésico sem swap (Tails), desligar a máquina
após o uso e esperar alguns minutos (cold-boot).

---

## 8. Build reprodutível e auditoria (requisitos 12 e 15)

- **Artefato:** `entropyforge.pyz` (zipapp) gerado por `tools/build_pyz.py`,
  determinístico: entradas ordenadas, `date_time = 1980-01-01`, permissões fixas,
  `ZIP_STORED` (sem compressão, para não depender da versão do zlib). Um
  `SHA256SUMS` é publicado junto com o artefato.
- **Reprodução:** `make repro` gera o artefato duas vezes, em diretórios e umask
  diferentes, e compara os hashes. Qualquer pessoa com Python ≥ 3.11 obtém o
  mesmo SHA-256.
- **Execução:** `python3 -I -B entropyforge.pyz generate`. `-I` ignora
  `PYTHONPATH`, site-packages do usuário e `usercustomize`; `-B` não escreve `.pyc`.
  O programa avisa se não estiver em modo isolado.
- **Modo determinístico de cálculo:** o subcomando `vector` reproduz `E` e o
  mnemonic a partir de entradas públicas. O guia de auditoria mostra como obter o
  mesmo resultado com `bc`, `xxd` e `sha256sum` mais python-mnemonic, fora deste
  código.
- **`docs/AUDIT.md`:** lista de arquivos com hashes, número de linhas, ordem
  sugerida de leitura, invariantes a verificar.

---

## 9. Estratégia de testes (requisitos 11 e 17)

Só `unittest` da stdlib no núcleo da suíte.

| Tipo | Conteúdo |
|---|---|
| Unitários | `enc6` (bijeção exaustiva para n ≤ 8), bordas (n mínimo, todos 1, todos 6), largura W, rejeição de símbolos inválidos, parsing do TTY |
| Vetores conhecidos | SHA-256 (NIST FIPS 180-4 / CAVP); **todos** os vetores oficiais BIP-39 em inglês (`vectors.json` da Trezor, incluindo 256 bits e seed com `"TREZOR"`); vetores próprios de `SHA-256(A ‖ B)` gerados com `sha256sum` |
| Referência independente | comparação com **python-mnemonic (Trezor)**, versão fixada por hash, em ≥ 10.000 entropias aleatórias e casos extremos (`00…00`, `ff…ff`, `80…00`, `7f…ff`). Uma 2ª implementação didática "string de bits" dentro dos testes |
| Estatísticos | funções especiais contra valores tabelados; taxa de falso positivo ≈ α em sequências do CSPRNG; poder contra alternativas viciadas; T3 detecta sequências "sem repetição" |
| Segurança | AST: sem `random`, sem módulos de rede, sem `logging`, sem escrita em arquivo; audit hook bloqueia socket, escrita e subprocess; saída sem segredos (7.3); `generate` recusa stdin que não é TTY |
| Reprodutibilidade | dois builds geram o mesmo SHA-256 |

---

## 10. Linguagem das afirmações (requisitos 6 e 20)

A documentação e as mensagens **não** usam "inquebrável", "impossível",
"à prova de quântico/governos" nem "testes provam aleatoriedade". Formulações
permitidas, sempre condicionais:

> "Sob as premissas P1–P3, o melhor ataque genérico conhecido exige da ordem de
> 2^255 avaliações de SHA-256 no modelo clássico e da ordem de 2^128 avaliações
> quânticas com Grover, **segundo o conhecimento público atual**."

> "Os testes não rejeitaram a hipótese de uniformidade ao nível α = 0,01. Isso
> **não** demonstra que a sequência é aleatória."

---

## 11. Rastreabilidade dos requisitos

| Req. | Onde |
|---|---|
| 1 sem PRNG próprio | D3, teste AST (9) |
| 2 d6 `1–6` | 2.5, D1, D2 |
| 3 B 256 bits do CSPRNG do SO | D3 |
| 4 validação estatística | 4.1–4.3 |
| 5 `log2 6` por lançamento | D1 |
| 6 sem "prova" de aleatoriedade | 4.1, 10 |
| 7 binário sem inflar bits | D2 |
| 8 `SHA-256(A ‖ B)` 256 bits | D4 |
| 9 e 10 BIP-39 24 palavras com checksum | D5 |
| 11 testes contra implementação conhecida | 9 |
| 12 auditoria completa | 2.3 (tamanho), 8 (`AUDIT.md`) |
| 13 sem rede | 7.1 |
| 14 sem logs, temporários ou clipboard | 7.2, 7.4 |
| 15 build/reprodução determinística | 8 |
| 16 só métricas públicas | 4.4, 7.3 |
| 17 testes e documentação matemática | 9, `docs/MATH.md` |
| 18 garantias vs. premissas | 5 |
| 19 análise de ameaças | 6 |
| 20 sem afirmações absolutas | 10 |

---

## 12. Perguntas em aberto para revisão

- **Q1. Linguagem:** Python stdlib (recomendado) ou Go stdlib (binário único,
  reprodutibilidade nativa)?
- **Q2. Codificação de A:** inteiro base-6 com prefixo `n` (recomendado, D2) ou
  string ASCII dos dígitos (estilo Coldcard, mais fácil de verificar à mão)?
- **Q3. Combinação:** manter literalmente `SHA-256(A ‖ B)` (recomendado, conforme
  o requisito) ou adicionar uma tag de domínio/versão
  (`SHA-256("EntropyForge-v1" ‖ A ‖ B)`)? A tag não muda a segurança no ROM, mas
  sai da fórmula exigida.
- **Q4. Exibição:** o requisito 16 diz "nunca exibir a seed". Proposta: a seed
  BIP-39 (512 bits) e a entropia E nunca são exibidas; o **mnemonic** é exibido
  uma vez, porque sem isso não há como transcrever. Confirma essa interpretação?
- **Q5. Conferência da transcrição:** pedir que o usuário redigite as 24 palavras
  sem eco? Proposta: opcional, desativada por padrão.
- **Q6. Rede ativa:** recusar rodar (proposta) ou só avisar? Ter
  `--i-understand-network-is-up` para testes?
- **Q7. Quantidade de lançamentos:** mínimo 119 e padrão 132 (D1) estão bons?
  Prefere um relatório público menor (contagens + só vereditos, sem p-valores)
  para baixar o mínimo para 113 e o padrão para 126?
- **Q8. Política em FAIL estatístico:** abortar (proposta) ou permitir continuar
  com confirmação explícita, já que B ainda cobre?

---

## 13. Plano de implementação (após aprovação)

1. Esqueleto, `guard.py`, testes de AST de segurança.
2. `wordlist.py` + `bip39.py` + vetores oficiais + comparação com python-mnemonic.
3. `dice.py` (D2) + testes exaustivos; `osrng.py`; `combine.py` + KATs.
4. `stats.py` + validação das funções especiais + testes de poder e falso positivo.
5. `report.py` com cálculo de L(n); `cli.py`; testes de "saída sem segredos".
6. `selftest.py`; build reprodutível; `make repro`.
7. Documentação: `MATH.md`, `THREAT_MODEL.md`, `AUDIT.md`, `OPERATIONS.md`.
