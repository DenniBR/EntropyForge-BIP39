# Documentação matemática

> Este documento é normativo: o código (`entropyforge/entropy_calc.py`,
> `entropyforge/specialfunc.py`, `entropyforge/stats.py`, `entropyforge/combine.py`)
> implementa exatamente o que está aqui, e os testes em `tests/` verificam
> isso. Onde o código e este documento divergirem, é um bug — abra uma
> issue citando a seção.
>
> Convenção de rótulos usada no texto: **[FATO]** = demonstrável e
> verificado por teste/prova; **[HEURÍSTICA]** = suposição amplamente
> usada na criptografia prática, sem prova no modelo padrão;
> **[PREMISSA FÍSICA]** = depende do dado/usuário/hardware, não
> verificável por software; **[OPINIÃO]** = decisão de engenharia
> (parâmetro escolhido), não uma verdade matemática.

## Sumário

1. [Entropia de um lançamento de d6](#1-entropia-de-um-lançamento-de-d6)
2. [De n lançamentos a bits: três perguntas separadas](#2-de-n-lançamentos-a-bits-três-perguntas-separadas)
3. [Codificação binária de A (bijeção)](#3-codificação-binária-de-a-bijeção)
4. [Fonte B: o CSPRNG do sistema operacional](#4-fonte-b-o-csprng-do-sistema-operacional)
5. [Combinação E = SHA-256(A ‖ B)](#5-combinação-e--sha-256a--b)
6. [Min-entropia vs. entropia de Shannon vs. número de estados vs. segurança computacional](#6-min-entropia-vs-entropia-de-shannon-vs-número-de-estados-vs-segurança-computacional)
7. [BIP-39: de E ao mnemonic](#7-bip-39-de-e-ao-mnemonic)
8. [Bateria de testes estatísticos: distribuições nulas](#8-bateria-de-testes-estatísticos-distribuições-nulas)
9. [Orçamento de vazamento do relatório público](#9-orçamento-de-vazamento-do-relatório-público)
10. [Poder estatístico: o que a bateria consegue e não consegue detectar](#10-poder-estatístico-o-que-a-bateria-consegue-e-não-consegue-detectar)
11. [Tabela-resumo: garantido vs. assumido](#11-tabela-resumo-garantido-vs-assumido)
12. [Referências](#12-referências)

---

## 1. Entropia de um lançamento de d6

**[FATO, condicional]** Um dado de 6 faces cujos resultados são
independentes e uniformemente distribuídos em `{1,...,6}` tem entropia de
Shannon por lançamento:

```
H = -Σ_{i=1}^{6} P(i) log2 P(i) = -6 · (1/6) · log2(1/6) = log2(6) ≈ 2,5849625007 bits
```

Como a distribuição uniforme é a que **maximiza** a entropia de Shannon
sobre um alfabeto de 6 símbolos, `log2(6)` é também o **máximo possível**
por lançamento — nenhum d6 pode dar mais que isso, mesmo em teoria.

Este número é uma consequência da fórmula de Shannon aplicada à hipótese
de uniformidade e independência. **Ele não mede, nem pode medir, se um d6
físico específico realmente satisfaz essa hipótese** — isso é uma
**[PREMISSA FÍSICA]** sobre o dado, a técnica de lançamento e a
honestidade de quem lança (ver `docs/THREAT_MODEL.md`, ameaça T-DICE).

## 2. De n lançamentos a bits: três perguntas separadas

O projeto distingue deliberadamente três perguntas que são fáceis de
confundir (implementadas em `entropy_calc.py`):

### 2.1 Quantos lançamentos para X bits teóricos?

**[FATO, condicional a d6 honesto e i.i.d.]**

```
H(n) = n · log2(6)
rolls_for_shannon_bits(X) = ceil(X / log2(6))
```

Para X = 256: `rolls_for_shannon_bits(256) = 100` (100 · log2(6) ≈ 258,50 bits).
Para X = 128: `rolls_for_shannon_bits(128) = 50`.

### 2.2 Quantos lançamentos para uma margem de segurança operacional?

Se o dado tiver viés, a grandeza relevante para segurança **não** é a
entropia de Shannon, e sim a **min-entropia** (seção 6):

```
H∞(n) = -n · log2(p_max)
```

onde `p_max ∈ [1/6, 1)` é a probabilidade da face mais provável. Isto é
o pior caso: para uma dada `p_max`, a min-entropia mínima ocorre quando as
5 faces restantes dividem a probabilidade remanescente de qualquer forma
(a fórmula não depende de como elas dividem, só do valor de `p_max`).

`p_max` **não é medido pelo software** — é um parâmetro de engenharia.
Este projeto usa por padrão `p_max = 0,20` **[OPINIÃO]**: uma escolha de
margem (contra 0,1667 de um dado perfeito), documentada, não derivada.
Quem quiser um valor medido do próprio dado deve rodar `calibrate`
(seção 8, teste de calibração com limite de Clopper-Pearson).

### 2.3 Quantos lançamentos para poder estatístico razoável?

**Esta pergunta não tem uma fórmula fechada aqui**, porque o poder
depende da magnitude do desvio que se quer detectar (uma alternativa não
especificada por H0). A seção 10 caracteriza numericamente, por simulação,
o poder da bateria em função de `n` e do desvio.

**Conclusão prática:** com as poucas centenas de lançamentos viáveis para
uma pessoa digitar (a faixa operacional deste projeto, calculada abaixo),
o poder contra um viés pequeno a moderado é **baixo**. Se você quer
caracterizar seu dado com poder alto, use `calibrate` com milhares de
lançamentos descartáveis.

### 2.4 O número operacional recomendado (`generate`)

`generate` combina 2.2 com o custo do próprio relatório público (seção 9):
encontra o menor `n` tal que

```
H∞(n, p_max) - vazamento(n) ≥ 256
```

Com `p_max = 0,20` e o formato de relatório deste projeto (seção 9), isso
dá **n = 127** no momento em que este documento foi escrito — mas o valor
**não está congelado em nenhum lugar do código como constante mágica**:
`generate` sempre chama `entropy_calc.compute_budget()` e mostra o número
recalculado, com as três quantidades acima lado a lado. Se você mudar o
formato do relatório ou a suposição de `p_max`, o número recomendado muda
automaticamente e continua correto.

## 3. Codificação binária de A (bijeção)

Ver `entropyforge/dice.py`. Para uma sequência `d_1, ..., d_n ∈ {1,...,6}`:

```
v = Σ_{i=1}^{n} (d_i - 1) · 6^(n-i)              ∈ [0, 6^n)
W = ceil( bit_length(6^n - 1) / 8 )                (bytes)
A = uint16_be(n) ‖ v.to_bytes(W, 'big')
```

**[FATO]** `v` é a representação usual de `(d_1-1, ..., d_n-1)` como um
número em base 6 (dígito mais significativo primeiro). A função
`(d_1,...,d_n) ↦ v` é uma bijeção entre `{1,...,6}^n` e `[0, 6^n)`: é a
representação posicional padrão em base 6, cuja bijetividade é um
resultado clássico (todo inteiro em `[0, b^n)` tem uma única representação
com `n` dígitos em base `b`, com zeros à esquerda permitidos). Verificado
por enumeração exaustiva para `n ≤ 6` e por amostragem para `n` maiores em
`tests/test_dice.py`.

**Por que o prefixo `n`:** sem ele, `enc(1,2,3) = enc(2,3)` porque o
dígito `1` inicial vira `0` em base 6 e desaparece à esquerda (exatamente
como `007` e `7` são o mesmo número em base 10). O prefixo torna a
codificação **injetora entre sequências de comprimentos diferentes**, o
que é necessário para que `A ‖ B` seja decodificável de forma única em
`combine.py`.

**O que isso NÃO significa:** `len(A)` em bits é `16 + 8W`, que é **maior**
que `n · log2(6)` (por exemplo, para `n=127`, `v` cabe em 44 bytes = 352
bits, mas a entropia continua sendo no máximo `127 · log2(6) ≈ 328,3`
bits). A contabilidade de entropia deste projeto usa **sempre**
`n · log2(6)` (ou a min-entropia da seção 2.2), nunca o tamanho em bytes
da codificação.

## 4. Fonte B: o CSPRNG do sistema operacional

Ver `entropyforge/osrng.py`. `B = os.getrandom(32, 0)` no Linux.

**[HEURÍSTICA/PREMISSA]** Assume-se que o gerador do kernel, uma vez
inicializado, produz saídas computacionalmente indistinguíveis de
uniformes para um adversário sem acesso ao estado interno do kernel. Isso
depende da implementação do kernel, do hardware (fontes de entropia de
boot, RDRAND/jitter/TPM) e da ausência de comprometimento do sistema — não
é verificável pelo software de espaço de usuário (ver
`docs/THREAT_MODEL.md`, ameaça T-RNG).

As únicas checagens feitas (`_reject_constant_output`,
`diagnostic_two_reads_differ`) detectam **falhas grosseiras** (saída
constante, leituras repetidas idênticas). Elas não validam, e não têm como
validar, a qualidade criptográfica do gerador.

## 5. Combinação E = SHA-256(A ‖ B)

Ver `entropyforge/combine.py`. `A` é autodelimitada (carrega `n` no
prefixo) e `B` tem comprimento fixo de 32 bytes, então `A ‖ B` é
decodificável de forma única — não há ambiguidade sobre onde `A` termina.

### 5.1 O que SHA-256 NÃO faz

**[FATO]** SHA-256 é uma função determinística e pública:
`SHA-256(x) = SHA-256(x)` sempre, para todo `x`. Ela **não gera** nem
**cria** entropia — é impossível para qualquer função determinística
aumentar a incerteza de uma variável aleatória (a entropia condicional
`H(f(X) | X) = 0` para `f` determinística). Toda a imprevisibilidade de
`E` vem de `A` e `B`; SHA-256 apenas **combina e comprime** essa
imprevisibilidade em uma saída de tamanho fixo.

### 5.2 O argumento de segurança (o que realmente sustenta a construção)

**[HEURÍSTICA — modelo do oráculo aleatório, ROM]** Trata-se SHA-256 como
se fosse uma função escolhida uniformemente ao acaso entre todas as
funções de `{0,1}*` para `{0,1}^256` (uma idealização; nenhuma função
concreta pode de fato ser "escolhida ao acaso" e ser eficientemente
computável — este é um modelo heurístico, não uma propriedade provada do
SHA-256 real).

Sob o ROM: seja `k = H∞(A, B | vista do adversário)` a min-entropia
conjunta de `(A, B)` do ponto de vista de um adversário que não conhece o
valor exato de pelo menos uma das duas fontes. Um adversário que faz até
`q` consultas ao oráculo (ou ao SHA-256 real, sob a heurística) distingue
`E` de uma string uniforme de 256 bits com vantagem

```
Adv ≤ q · 2^(-k)
```

Isto é uma aplicação padrão do argumento de "adivinhar a entrada" no ROM:
o adversário só pode "acertar" `E` adivinhando a entrada exata que o
gerou; cada consulta acerta com probabilidade no máximo `2^(-k)` sobre a
incerteza que resta na entrada, e a vantagem de distinguir soma ao longo
das consultas.

**Consequência prática:** `k ≥ max(H∞(A), H∞(B))` quando `A` e `B` são
independentes — **basta que UMA das duas fontes seja boa e desconhecida do
adversário**, mesmo que a outra esteja totalmente comprometida. É por
isso que a arquitetura usa duas fontes independentes: não para "somar"
entropia de forma ingênua, mas para que a falha de uma não derrube a
segurança da saída, **desde que o adversário não conheça a outra fonte
inteira**.

**Limite honesto:** este argumento é heurístico. SHA-256 **não tem prova**
de se comportar como um extrator de aleatoriedade ou como um oráculo
aleatório no modelo padrão (nenhuma função de hash concreta tem essa
prova — é uma limitação conhecida e aceita da criptografia baseada em
hash). HKDF-Extract (RFC 5869) tem uma análise mais direcionada como
extrator (via a suposição de que HMAC é uma família de funções
pseudoaleatórias), mas o requisito deste projeto fixa a fórmula
`SHA-256(A ‖ B)` literalmente, e é isso que está implementado.

**Onde isso NÃO ajuda:** se o adversário **conhece A e controla B** (por
exemplo, um sistema operacional comprometido que registra as teclas
digitadas e fornece a "aleatoriedade" de B), então `k = 0` e `E` fica
inteiramente determinado pelo adversário — a combinação não cria segurança
a partir do nada. Ela protege contra a **falha independente** de uma
fonte, não contra o **comprometimento do ambiente** onde as duas se
encontram (ver `docs/THREAT_MODEL.md`, seção "fronteira de confiança").

### 5.3 Nota técnica: a saída de SHA-256 não é exatamente uniforme (irrelevante na prática)

Esta subseção existe só para não deixar uma afirmação solta: **mesmo que
a entrada de SHA-256 fosse exatamente uniforme sobre todo o seu domínio de
256 bits**, a saída de uma função (mesmo "aleatória" no sentido do ROM)
**não é exatamente uniforme**, porque colisões e "buracos" na imagem
distorcem a distribuição. O efeito é caracterizado pela teoria clássica de
estatística de mapeamentos aleatórios (Flajolet & Odlyzko, 1990): para uma
função `f: [N] → [N]` escolhida uniformemente ao acaso e `X` uniforme em
`[N]`, o número de pré-imagens de cada ponto segue, no limite, uma
distribuição de Poisson(1), e a entropia de Shannon da saída `Y = f(X)` é

```
H(Y) ≈ log2(N) - E[K log2 K],    K ~ Poisson(1)
E[K log2 K] = Σ_{k≥1} (e^-1/k!) · k · log2(k) ≈ 0,8272 bits
```

(valor calculado por soma numérica direta da série, não medido por
simulação; ver `tools/simulate_power.py` não usa este número — ele não
entra em nenhum cálculo do produto).

Com `N = 2^256`, isso dá `H(Y) ≈ 255,17` bits de entropia de **Shannon**
da saída, **sob a suposição adicional de que a entrada é exatamente
uniforme sobre todo o domínio de 256 bits** (o que só é exatamente verdade
se B for uniforme E A for fixo/conhecido — na prática A também contribui
incerteza, então a situação real é pelo menos tão boa quanto esta).

**Por que isto não é usado como argumento de segurança do projeto:**

1. É uma propriedade de **entropia de Shannon da saída**, não de
   **min-entropia** nem de **vantagem de distinguibilidade** — as
   grandezas que realmente limitam o que um adversário consegue fazer
   (seção 6). Uma perda de "0,83 bit de entropia de Shannon" não se
   traduz diretamente em "0,83 bit a menos de segurança".
2. É numericamente irrelevante: 255,17 contra 256 é uma diferença de
   0,3%, muito menor que qualquer margem de segurança já embutida no
   projeto (ex.: a diferença entre usar 100 ou 127 lançamentos).
3. Depende de tratar SHA-256 literalmente como uma função aleatória
   **fixa e sorteada uma vez** (o modelo de "estatística de mapeamentos
   aleatórios"), uma suposição ainda mais forte e específica que o ROM
   "sob consulta" usado na seção 5.2.

Este projeto **não afirma** um número de bits de entropia perdida na
saída de SHA-256 como parte do seu argumento de segurança. O argumento
real é o da seção 5.2 (min-entropia da entrada, vantagem de
distinguibilidade), que não depende deste cálculo.

## 6. Min-entropia vs. entropia de Shannon vs. número de estados vs. segurança computacional

Estas quatro noções são frequentemente confundidas; este projeto as trata
como conceitos **distintos**:

| Conceito | Definição | Para que serve aqui |
|---|---|---|
| **Número de estados possíveis** | `\|espaço amostral\|` (ex.: `6^n` sequências de dado, `2^256` valores de E) | Uma contagem combinatória. **Não é**, por si só, uma medida de segurança: um espaço grande com distribuição muito enviesada pode ter pouquíssima entropia. |
| **Entropia de Shannon** | `H(X) = -Σ P(x) log2 P(x)` | Mede incerteza **em média**. É o limite de compressão sem perdas. **Não** limita o sucesso de um adversário que faz uma única tentativa de adivinhação (um evento raro de alta probabilidade pode dominar mesmo com H(X) alto). |
| **Min-entropia** | `H∞(X) = -log2( max_x P(x) )` | Mede o **pior caso**: a probabilidade do evento mais provável. **É** a grandeza que limita a vantagem de um adversário que tenta adivinhar `X` de uma vez (seção 5.2). Sempre `H∞(X) ≤ H(X)`, com igualdade só para a distribuição uniforme. |
| **Segurança computacional** | Custo computacional (ex.: número de avaliações de SHA-256, ou de operações de um algoritmo de busca) para quebrar uma propriedade, sob um MODELO de adversário | Depende da min-entropia da entrada (via o argumento do ROM) **e** da suposição heurística sobre o primitivo (SHA-256 se comportar como oráculo aleatório) **e** do modelo de custo (clássico vs. quântico, seção do Threat Model). Não é uma propriedade puramente informacional: envolve também o que é computacionalmente viável. |

**Por que este projeto usa min-entropia, não entropia de Shannon, como
critério operacional:** o argumento de segurança da seção 5.2 é sobre a
vantagem de um adversário que tenta **adivinhar** a entrada — esse é
exatamente o cenário que a min-entropia mede. Uma fonte com entropia de
Shannon alta mas min-entropia baixa (ex.: 99% das vezes um valor fixo, 1%
das vezes uniforme sobre um espaço enorme) teria alta incerteza "em
média", mas seria adivinhada corretamente 99% das vezes — inaceitável para
uma seed. É por isso que a seção 2.2 usa `H∞(n, p_max) = -n log2(p_max)`,
não `n log2(6)`, como base para o número operacional de lançamentos.

## 7. BIP-39: de E ao mnemonic

Ver `entropyforge/bip39.py` e a especificação oficial
(`bip-0039.mediawiki`). Para `ENT` bits de entropia (este projeto: sempre
256):

```
CS   = ENT / 32                                    (bits de checksum; 8 para ENT=256)
bits = E ‖ SHA-256(E)[0 : CS]                       (ENT + CS bits; 264 para ENT=256)
MS   = (ENT + CS) / 11                              (número de palavras; 24 para ENT=256)
palavra_i = wordlist[ bits[11i : 11i+11] ]           (11 bits por palavra, MSB primeiro)
```

**[FATO]** Implementado literalmente; `entropy_to_mnemonic` e
`mnemonic_to_entropy` são funções inversas uma da outra (verificado por
round-trip em milhares de entradas aleatórias e por todos os 24 vetores
oficiais em `tests/test_bip39_vectors.py`), e concordam com a
implementação de referência `python-mnemonic` (Trezor) em 10.000+
entropias aleatórias e casos extremos (`tests/test_dev_cross_check_reference_impl.py`,
rodado durante o desenvolvimento; não é dependência de runtime).

O checksum é uma função determinística de `E`: **não adiciona
entropia**, apenas permite detectar (não corrigir) um mnemonic digitado
errado ou incompleto. Uma adulteração aleatória de uma palavra é detectada
com probabilidade `1 - 2^(-8)` (para ENT=256, CS=8 bits) — não `1`, porque
uma fração `2^-8` das adulterações aleatórias, por coincidência, ainda
produz um checksum válido.

## 8. Bateria de testes estatísticos: distribuições nulas

Hipótese nula comum a todos: `H0`: os lançamentos `d_1,...,d_n` são
i.i.d. Uniforme`{1,...,6}`. Nível de significância familiar:
`α = 0,01` **[OPINIÃO]** (convencional; mais rigoroso que o 0,05 mais
comum, ao custo de menos poder). Correção de Holm-Bonferroni para os 6
testes com veredito próprio (controla a taxa de erro familiar sem exigir
independência entre os testes).

### T1 — Frequência das faces

Estatística: `Σ (c_i - n/6)² / (n/6)`, `c_i` = contagem da face `i`.
**[HEURÍSTICA — aproximação assintótica de Pearson]** sob H0, converge em
distribuição para qui-quadrado com 5 graus de liberdade quando `n → ∞`;
para `n` finito é uma aproximação (como em qualquer teste qui-quadrado de
aderência).

### T2 — Diferenças seriais

`δ_i = (d_{i+1} - d_i) mod 6`, para `i = 1,...,n-1`.

**[FATO]** Prova: condicional em `d_1,...,d_i`, o próximo lançamento
`d_{i+1}` é, sob H0, um sorteio uniforme fresco, independente do passado.
Como `δ_i` é uma função bijetora de `d_{i+1}` para `d_i` fixo
(`d_{i+1} ↦ (d_{i+1}-d_i) mod 6` é uma bijeção de `{1..6}` para `{0..5}`),
`δ_i | d_1,...,d_i` é uniforme em `{0,...,5}`, **qualquer que seja o
passado**. Por indução, `δ_1,...,δ_{n-1}` são i.i.d. Uniforme`{0,...,5}`
— um fato **exato**, não assintótico. O teste qui-quadrado aplicado às
contagens desses `δ_i` usa a mesma aproximação assintótica de Pearson que
T1 (a exatidão está na distribuição dos `δ_i`, não na do qui-quadrado
sobre eles).

### T3 — Repetições

`R = #{i : d_i = d_{i+1}}`.

**[FATO]** Prova: seja `X_i = 1{d_i = d_{i+1}}`. Pelo mesmo argumento de
T2, condicional em `d_1,...,d_i`, `P(X_i = 1) = P(d_{i+1} = d_i) = 1/6`
**exatamente**, qualquer que seja o passado (incluindo `X_1,...,X_{i-1}`).
Isso significa que `X_i` é, condicional em toda a história anterior, um
Bernoulli(1/6) — a definição de uma sequência i.i.d. Bernoulli(1/6) via
seu filtro natural. Logo `R = Σ X_i ~ Binomial(n-1, 1/6)` **exatamente**,
apesar dos `X_i` serem definidos sobre pares sobrepostos. Verificado por
enumeração exaustiva de `{1,...,6}^6` em `tests/test_stats.py`
(distribuição empírica idêntica à Binomial(5, 1/6) até erro de ponto
flutuante).

p-valor: bicaudal exato (`specialfunc.binom_two_sided_pvalue`), método
"soma das probabilidades tão prováveis quanto ou menos que a observada"
(o mesmo critério usado por `binom.test` do R).

### T4 — Corridas (runs) acima/abaixo de 3,5

Classifica cada lançamento como abaixo (`{1,2,3}`) ou acima (`{4,5,6}`) de
3,5 (não há empates possíveis: 3,5 não é um resultado de dado). Seja
`n0, n1` as contagens de cada lado e `R` o número de corridas.

**[FATO]** Condicional em `(n0, n1)`, sob H0 (trocabilidade — implicada
por i.i.d.) toda ordenação dos `n0+n1` símbolos é igualmente provável.
Isso dá a distribuição exata clássica de Wald-Wolfowitz:

```
P(R=2k)   = 2·C(n0-1,k-1)·C(n1-1,k-1) / C(n0+n1,n0)
P(R=2k+1) = [C(n0-1,k-1)·C(n1-1,k) + C(n0-1,k)·C(n1-1,k-1)] / C(n0+n1,n0)
```

Verificado por enumeração exaustiva de todos os arranjos para `(n0,n1)`
pequenos em `tests/test_stats.py`. **Caso degenerado:** se `n0=0` ou
`n1=0` (todos os lançamentos do mesmo lado), o teste, condicional a essa
divisão, não tem poder (só há uma ordenação possível) — devolve p-valor 1
e uma nota explicando isso; um desvio tão grande na própria divisão
`n0/n1` é capturado por T1 (frequência de faces), não por T4.

### T5 — Autocorrelação nos atrasos 1, 2 e 3

`r_k = (1/(n-k)) · Σ_{i} (d_i - 3,5)(d_{i+k} - 3,5) / Var`, onde
`Var = Var(Uniforme{1..6}) = 35/12` (variância populacional teórica, usada
em vez de estimada da amostra porque H0 especifica a distribuição por
completo).

**[HEURÍSTICA — aproximação assintótica de Bartlett, 1946]** sob H0
(ruído branco), `r_k · sqrt(n-k)` é aproximadamente Normal(0,1) para `n`
grande. **Não há forma fechada exata simples** para o `n` finito deste
projeto; a validade da aproximação em `n ≈ 100-300` é caracterizada por
simulação (seção 10), não assumida sem verificação.

## 9. Orçamento de vazamento do relatório público

O relatório exibido em `generate` (`report.public_report`) NÃO mostra a
sequência, os p-valores nem as estatísticas — só as 6 contagens de face e
um veredito PASS/WARN/FAIL por teste (exceto T1, cujo veredito é
determinado pelas próprias contagens). Ainda assim, ele **revela
informação** sobre `A`, e essa informação precisa ser contabilizada.

**[FATO, regra da cadeia para min-entropia — Dodis, Ostrovsky, Reyzin,
Smith, 2004]** Para qualquer função `f` de `A` que assume no máximo `|R|`
valores possíveis, `H̃∞(A | f(A)) ≥ H∞(A) - log2|R|` (min-entropia média
condicional). Aplicando isso ao relatório:

```
|R_contagens| = C(n+5, 5)      (número de composições de n em 6 partes ≥ 0)
|R_vereditos| = 3^6             (6 testes com veredito próprio, 3 vereditos cada)

L(n) = log2 C(n+5,5) + 6·log2(3)
```

Este é um **limite superior conservador** (trata as contagens e os
vereditos como se fossem informacionalmente independentes entre si, o que
só pode superestimar o vazamento real). `entropy_calc.report_leak_bits(n,
num_verdict_tests)` implementa exatamente esta fórmula, com
`num_verdict_tests` importado de `stats.NUM_VERDICT_TESTS` (não duplicado
como constante solta).

O número operacional de lançamentos (seção 2.4) já desconta este
vazamento do orçamento de 256 bits.

## 10. Poder estatístico: o que a bateria consegue e não consegue detectar

**Nenhuma simulação abaixo "prova" nada sobre um dado físico real** — são
estudos de software, com fontes de aleatoriedade e modelos de viés
explicitados, servindo só para caracterizar o COMPORTAMENTO DO CÓDIGO DE
TESTE, não para validar hardware. Ver `tools/simulate_power.py` (script
completo, reprodutível, com seed documentada) e
`docs/simulation_results.txt` (saída bruta gerada por ele).

**Método:** taxa de falso positivo medida sobre sequências de entropia
real do SO (`os.getrandom`, reamostrada por rejeição para uniformidade em
`{1..6}`); poder contra viés e contra dependência markoviana medido com
`random.Random(20260927)` da biblioteca padrão (semente fixa, documentada,
usada **só** neste estudo de desenvolvimento — nunca no produto).

### 10.1 Taxa de falso positivo (fonte: entropia real do SO)

| n | tentativas | taxa de FAIL | taxa de WARN |
|---|---|---|---|
| 126 | 3000 | 2,37% | 24,6% |
| 600 | 1000 | 1,10% | 28,1% |

A taxa nominal esperada (união entre T1 e a família de Holm, ambas a
α=0,01) é de ordem `2α = 2%` — os valores medidos são consistentes com
isso. A taxa de WARN é alta por construção (o limiar de 0,05 não
corrigido é, por definição, ultrapassado por acaso em ~5% de cada teste
individual, e há 7 testes).

### 10.2 Poder contra um d6 com uma face viciada

Probabilidade de o veredito geral ser FAIL, para uma face saindo com
probabilidade `p_biased` (as outras 5 dividem o resto igualmente):

| p_biased | n=126 | n=600 | n=3000 |
|---|---|---|---|
| 0,18 | 1,8% | 2,9% | 11,7% |
| 0,20 | 4,4% | 18,4% | 91,8% |
| 0,25 | 24,1% | 95,3% | 100% |
| 0,30 | 68,5% | 100% | 100% |

**Leitura:** na faixa operacional (`n ≈ 126`), um viés pequeno a moderado
(até ~20%) tem poder de detecção **baixo** (< 5%). É por isso que o
projeto (a) assume `p_max = 0,20` como margem, em vez de contar com o
teste para pegar esse nível de viés, e (b) oferece `calibrate` com
amostras muito maiores para quem quiser caracterizar o próprio dado com
poder alto.

### 10.3 Poder contra dependência (faces marginalmente uniformes)

Sequência gerada por uma cadeia de Markov que repete a face anterior com
probabilidade `stay_prob` (marginal ainda uniforme sobre as 6 faces, mas
lançamentos dependentes):

| stay_prob | n=126 | n=600 |
|---|---|---|
| 0,20 | 4,7% | 19,2% |
| 0,30 | 74,6% | 100% |
| 0,40 | 99,9% | 100% |

Isto demonstra o valor de T2/T3/T4/T5: um teste que olhasse **só** a
frequência das faces (T1) teria poder próximo de zero contra este tipo de
desvio (as faces continuam uniformes), mas a bateria completa detecta
dependência moderada com poder razoável mesmo em `n=126`.

## 11. Tabela-resumo: garantido vs. assumido

| Propriedade | Categoria | Onde |
|---|---|---|
| `enc6` é bijetora | **[FATO]**, prova + teste exaustivo | seção 3 |
| `δ_i` são i.i.d. exatamente uniformes sob H0 | **[FATO]**, prova | seção 8 (T2) |
| `R ~ Binomial(n-1, 1/6)` exatamente sob H0 | **[FATO]**, prova + teste exaustivo | seção 8 (T3) |
| distribuição exata de corridas | **[FATO]**, prova + teste exaustivo | seção 8 (T4) |
| `E` tem exatamente 256 bits; BIP-39 correto | **[FATO]**, teste contra vetores oficiais e impl. de referência | seção 7 |
| checksum detecta erro aleatório com prob. `1-2^-8` | **[FATO]** | seção 7 |
| vazamento do relatório ≤ `L(n)` bits | **[FATO]**, regra da cadeia (DORS 2004) | seção 9 |
| d6 é honesto e i.i.d. | **[PREMISSA FÍSICA]**, não verificável | seções 1, 2 |
| `p_max ≤ 0,20` | **[OPINIÃO]**, margem de engenharia | seção 2.2 |
| CSPRNG do SO produz saída indistinguível de uniforme | **[HEURÍSTICA/PREMISSA]** | seção 4 |
| SHA-256 se comporta como oráculo aleatório | **[HEURÍSTICA]**, sem prova no modelo padrão | seção 5.2 |
| qui-quadrado (T1, T2) e autocorrelação (T5) são boas aproximações no `n` operacional | **[HEURÍSTICA]**, checada por simulação, não assumida | seções 8, 10 |
| "os testes não rejeitaram H0" ⇒ a sequência é aleatória | **FALSO — nunca afirmado** | seção 8 (intro), `docs/THREAT_MODEL.md` |

## 12. Referências

- M. Bellare, P. Rogaway. *Random Oracles are Practical: A Paradigm for
  Designing Efficient Protocols*. CCS 1993. (modelo do oráculo aleatório)
- Y. Dodis, R. Ostrovsky, L. Reyzin, A. Smith. *Fuzzy Extractors: How to
  Generate Strong Keys from Biometrics and Other Noisy Data*. 2004 (regra
  da cadeia para min-entropia média usada na seção 9).
- P. Flajolet, A. Odlyzko. *Random Mapping Statistics*. EUROCRYPT 1989 /
  Algorithmica 1990 (estatística de mapeamentos aleatórios, seção 5.3).
- M. S. Bartlett. *On the Theoretical Specification of Sampling
  Properties of Autocorrelated Time Series*. JRSS-B, 1946 (aproximação
  usada em T5).
- A. Wald, J. Wolfowitz. *On a Test Whether Two Samples are from the Same
  Population*. Annals of Mathematical Statistics, 1940 (teste de
  corridas, T4).
- H. Krawczyk. *Cryptographic Extraction and Key Derivation: The HKDF
  Scheme*. CRYPTO 2010 (RFC 5869) — mencionado na seção 5.2 como
  alternativa mais bem analisada à combinação por hash simples.
- BIP-39: *Mnemonic code for generating deterministic keys*.
  `github.com/bitcoin/bips/blob/master/bip-0039.mediawiki`.
- FIPS 180-4 (SHA-256) e o repositório de vetores de teste do NIST CAVP.
