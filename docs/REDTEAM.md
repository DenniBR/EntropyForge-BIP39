# Auditoria adversarial (red team) — EntropyForge-BIP39

> **Objetivo desta auditoria:** tentar demonstrar que o projeto está
> ERRADO, não confirmar que está certo. Este documento relata o que foi
> tentado, o que quebrou, o que não quebrou, e por quê — sem inflar
> severidade e sem inventar uma vulnerabilidade que não existe.

## Resumo executivo

Foram realizados **7 eixos de ataque** (guard/rede/subprocess,
sequências estatísticas adversariais, fuzzing BIP-39 independente,
mutation testing, fuzzing de CLI, ataque ao build/artefato, e
cross-version) contra o código de `entropyforge/`, além de uma auditoria
crítica da própria suíte de testes.

**Nenhuma vulnerabilidade CRITICAL ou HIGH foi encontrada.** O núcleo
criptográfico e de segurança operacional (audit hook, BIP-39, combinação
de fontes, bijeção do encoding de dado) resistiu a todas as tentativas de
quebra, incluindo comparação com uma implementação BIP-39 independente em
15.000+ casos e 13 tentativas distintas de contornar o audit hook.

**Foram encontrados e corrigidos 2 bugs reais de severidade MEDIUM**
(um no produto, um na própria suíte de testes — ver seção 3) e **3 lacunas
reais de cobertura de teste** (severidade LOW), confirmadas por mutation
testing e corrigidas com testes de regressão específicos. Também foram
identificadas e documentadas **2 limitações arquiteturais inerentes**
(severidade INFORMATIONAL) que não têm correção de código válida — foram
avaliadas, uma correção óbvia para uma delas foi **testada e rejeitada**
por quebrar funcionalidade legítima (ver seção 5.2).

Um achado meta interessante: a primeira versão do **próprio harness de
mutation testing** deste red team continha um bug (invocação malformada de
subprocesso) que fazia ele reportar falsamente "11/11 mutantes mortos" —
descoberto só por desconfiar do próprio resultado e reproduzir manualmente
2 dos 11 casos. Registrado na seção 4 como lembrete de que ferramentas de
auditoria também precisam ser auditadas.

Todos os testes (182, suíte completa) passam de forma determinística
(50 execuções consecutivas sem falha) em Python 3.10 a 3.13.

## 1. Modelo de atacante

Este red team assume um atacante que pode:

- fornecer qualquer entrada de linha de comando, stdin, ou variável de
  ambiente ao programa;
- observar toda a saída (stdout, stderr, código de saída);
- controlar total ou parcialmente a sequência de dados (fonte A);
- em cenários específicos (seção 5), ter conseguido modificar o
  código-fonte ou o artefato `.pyz` antes de o usuário rodar (supply
  chain) — usado para testar os limites do que `selftest`/build
  reprodutível conseguem detectar, não como premissa do dia a dia.

Fora do escopo (já coberto por `docs/THREAT_MODEL.md` e não repetido
aqui): comprometimento de kernel/firmware/hardware, captura física,
coação do operador.

## 2. Metodologia

Todo o material de ataque está em [`redteam/`](../redteam/):
`redteam/scripts/` (ferramentas reutilizáveis) e `redteam/poc/` (provas
de conceito consolidadas e re-executáveis). Nenhum script altera o
comportamento de produção; `mutation_testing.py` restaura o arquivo
original em um `finally`, verificado por `assert` após cada mutação.
Nenhum dado usado é uma seed real — tudo é entropia efêmera de
`os.getrandom`, seeds de PRNG documentadas, ou vetores oficiais públicos.

## 3. Vulnerabilidades encontradas e corrigidas

### 3.1 [MEDIUM] `--rolls` com valor zero ou negativo trava `generate` / é ignorado silenciosamente

- **Onde:** `entropyforge/cli.py`, `cmd_generate`.
- **Causa raiz:** `target_n = args.rolls if args.rolls else budget.rolls_operational` usa
  a truthiness de Python, em que `0` é falsy — um `--rolls 0` explícito
  do usuário virava silenciosamente o padrão calculado, sem aviso. Um
  `--rolls` **negativo** é truthy, então era usado como `target_n`
  diretamente; como nenhuma entrada real tem comprimento negativo, o
  laço `while` em `_read_dice_hidden` (`if len(raw) != target_n: continue`)
  nunca terminava.
- **PoC:** `redteam/scripts/adversarial_sequences.py` não cobre isto; a
  reprodução está inline nesta auditoria (>1000 iterações confirmadas sem
  terminar, chamando `_read_dice_hidden(io, -5)` diretamente) e como
  regressão em `tests/test_cli_generate.py::RollsArgumentValidationTests`.
- **Pré-condições:** um operador humano em uma sessão de terminal REAL
  (TTY) passa `--rolls` com um valor ≤ 0. **Não é explorável via
  automação/pipe**: nesse caso `generate` já recusa antes (checagem de
  rede offline e de TTY rodam primeiro e abortam o processo antes de
  `_read_dice_hidden` ser alcançado) — confirmado em
  `redteam/scripts/cli_fuzz.py`.
- **Impacto:** negação de serviço local contra o próprio operador (a
  ferramenta trava, exigindo Ctrl-C) para `--rolls` negativo; para
  `--rolls 0`, um comportamento surpreendente (silenciosamente ignorado)
  em vez de um erro claro. Não há vazamento de segredo nem enfraquecimento
  da entropia gerada em nenhum dos dois casos.
- **Por que os testes existentes não pegaram:** nenhum teste chamava
  `generate`/`_read_dice_hidden` com `--rolls` fora do intervalo positivo
  razoável.
- **Correção:** `_validate_rolls_arg()`, chamada no início de
  `cmd_generate` e `cmd_calibrate`, rejeita `--rolls ≤ 0` e
  `--rolls > dice.MAX_ROLLS` com uma mensagem clara e código de saída
  diferente de zero, antes de qualquer coleta de entrada; a comparação
  com `None` (`is not None`) substitui a truthiness.
- **Regressão:** `tests/test_cli_generate.py::RollsArgumentValidationTests`
  (6 testes: validador rejeita 0/negativo/acima do limite, aceita
  `None`/valores razoáveis, `generate` recusa 0 e negativo sem travar).
- **Confirmado corrigido:** ver seção 6.

### 3.2 [MEDIUM] Testes instáveis (flaky) em `tests/test_cli_generate.py`

- **Onde:** `SuccessfulGenerateTests` (6 métodos) e
  `RollsCountMismatchTests`/`NetworkCheckRefusalTests` (1 método cada).
- **Causa raiz:** estes testes geram uma sequência de dado com entropia
  REAL do SO (`_real_d6`, via `os.getrandom`) e assumem que o fluxo
  `generate` terminará com sucesso (`rc == 0`). Como a bateria estatística
  rejeita ~2,4% das sequências genuinamente aleatórias por acaso (taxa
  nominal, `docs/simulation_results.txt`), e nenhum desses testes fornece
  a frase de confirmação de override de FAIL, uma sequência
  ocasionalmente rejeitada fazia o teste abortar antes de exibir o
  mnemonic — uma falha esporádica e não relacionada a nenhuma regressão
  real. Medido empiricamente: **~15–27% de chance de pelo menos uma
  falha por execução da classe** `SuccessfulGenerateTests` (6 sorteios
  independentes por execução da classe).
- Um **segundo problema relacionado e mais sutil** foi descoberto durante
  a correção do primeiro: o teste
  `test_mnemonic_full_string_appears_only_inside_alt_screen_block`
  verificava, por expressão regular com limite de palavra (`\bpalavra\b`),
  que nenhuma palavra do mnemonic aparecia fora do bloco de exibição —
  mas com um vocabulário de 2048 palavras em inglês comuns, uma palavra
  isolada (ex.: "use") pode legitimamente coincidir com texto normal da
  interface (ex.: "... ou **use** a confirmação ..."), causando outro
  falso positivo esporádico, sem relação com vazamento real.
- **Descoberto por:** execução repetida da suíte completa em Python 3.11
  durante o teste de compatibilidade entre versões (seção 3.3), e
  confirmado por 40+ execuções repetidas isolando a classe.
- **Impacto:** nenhum impacto de segurança em produção (é um problema só
  da suíte de testes); impacto real é erosão de confiança na suíte
  (CI "vermelho" sem relação com bugs reais tende a ser ignorado, o que
  esconderia uma falha genuína no futuro).
- **Correção:**
  1. `_real_d6_not_rejected()` (nova função auxiliar) re-sorteia até obter
     uma sequência que a bateria não rejeite, mantendo a fonte real de
     entropia; usada nos 3 pontos que geravam sequências e esperavam
     sucesso incondicional.
  2. O teste de vazamento por palavra isolada foi trocado por uma
     verificação de **pares de palavras consecutivas do mnemonic**, cuja
     probabilidade de colisão por acaso com texto normal é desprezível
     (ao contrário de uma palavra isolada comum).
- **Confirmado corrigido:** 50 execuções consecutivas da suíte completa
  sem falha (ver seção 6); a causa raiz específica (a suíte falhando
  esporadicamente) foi reproduzida e eliminada, não apenas mascarada.

## 4. Lacunas de cobertura de teste (encontradas por mutation testing)

Metodologia: `redteam/scripts/mutation_testing.py` introduz, um de cada
vez, um bug plausível no código-fonte, roda a suíte inteira, e restaura o
arquivo original (verificado por `assert`). Onze mutações foram testadas.

**Achado meta:** a primeira execução deste harness reportou "11/11
mutantes mortos" — um resultado bom demais para acreditar sem verificar.
Investigação manual revelou um bug no PRÓPRIO script: `run_tests()`
invocava `unittest "discover -s tests"` como uma ÚNICA string de
argumento (em vez de argumentos separados), o que `unittest` interpreta
como um nome de módulo de teste inválido — a suíte NUNCA rodava de
verdade, e todo `returncode != 0` (por esse erro, não por um teste
pegando o mutante) era mal-interpretado como "mutante morto". Corrigido
antes de qualquer conclusão ser tirada; os resultados abaixo são da versão
corrigida, verificados por reprodução manual independente de cada caso.

| Mutação | Resultado | Classificação |
|---|---|---|
| Checksum BIP-39 usa o último byte do digest, não o primeiro | KILLED | — |
| Checksum BIP-39 usa CS+1 bits em vez de CS | KILLED | — |
| `combine.py` concatena B‖A em vez de A‖B | KILLED | — |
| `combine.py` usa MD5 em vez de SHA-256 | KILLED | — |
| `dice.encode` usa little-endian em vez de big-endian | KILLED | — |
| `dice.encode` calcula largura sem arredondar para cima | KILLED | — |
| `wordlist._validate` sem checagem de ordenação | KILLED | — |
| `wordlist._validate` sem checagem de duplicatas | SURVIVED | **ver 4.3 — não é uma lacuna real** |
| `stats.run_battery` usa alpha bruto em vez de Holm-Bonferroni | **SURVIVED → corrigido (4.1)** | LOW → corrigido |
| `guard._WRITE_FLAGS` sem O_CREAT/O_APPEND/O_TRUNC/O_EXCL | **SURVIVED → corrigido (4.2)** | LOW → corrigido |
| `entropy_calc` usa `<=` em vez de `<` na condição de parada | SURVIVED | **ver 4.3 — não é uma lacuna real** |

### 4.1 [LOW, corrigido] Falta de correção de Holm não era testada na integração

`run_battery` corrigir para testes múltiplos via Holm-Bonferroni é
verificado apenas na função `holm_bonferroni` isolada
(`test_specialfunc.py`), não na sua USO real dentro de `run_battery`. O
teste de taxa de falso positivo (`FalsePositiveRateSanityTests`, limite de
15%) é frouxo demais para pegar a inflação de ~2× causada pela falta de
correção (o resultado sem Holm ainda fica bem abaixo de 15% em 300
tentativas). **Correção:** dois novos testes em
`tests/test_stats.py::HolmIntegrationTests` — um confirma que
`holm_bonferroni` é chamada com a aridade certa (6 p-valores, alpha
familiar), outro recalcula Holm de forma independente sobre os mesmos
p-valores que `run_battery` expôs e compara diretamente com as decisões
reais (`rejected_after_holm`) em 20 sequências reais.

### 4.2 [LOW, corrigido] Máscara de flags de escrita do guard não testada via `os.open()` bruto

O único teste de bloqueio de escrita existente usava `open(path, "w")`
(builtin, com string de modo) — capturado por um caminho de checagem
INDEPENDENTE (`_is_write_mode`) da máscara de bits `_WRITE_FLAGS` usada
para `os.open()` com `mode=None`. Uma máscara enfraquecida (faltando
`O_CREAT`) não seria pega por nenhum teste. **Confirmado por PoC** que
`O_CREAT` sozinho (sem `O_WRONLY`/`O_RDWR`) já cria um arquivo vazio no
disco — uma escrita real, ainda que mínima — enquanto `O_APPEND`/
`O_TRUNC`/`O_EXCL` sozinhos não permitem escrever conteúdo (confirmado:
resultam em `OSError: Bad file descriptor`), então dependem de
`O_WRONLY`/`O_RDWR` (já bloqueados) para importar na prática. **Correção:**
`tests/test_guard.py` ganhou dois testes que exercitam `os.open()`
diretamente com cada flag isolada (`O_RDWR`, `O_CREAT`, `O_APPEND`,
`O_TRUNC`, `O_EXCL`).

### 4.3 Mutantes sobreviventes SEM correção (avaliados e classificados como não-lacunas)

- **`wordlist` sem checagem de duplicatas:** removê-la não reduz a
  detecção real, porque **duas palavras idênticas sempre têm o mesmo
  prefixo de 4 letras**, e a checagem de unicidade de prefixos (que roda
  depois, na mesma função) já pega qualquer duplicata como consequência
  lógica direta. Confirmado manualmente: com a checagem de duplicata
  removida, `_validate` ainda levanta `WordlistError` (via a checagem de
  prefixos) para qualquer entrada com uma palavra repetida. A checagem de
  duplicata é logicamente redundante neste código específico — não uma
  lacuna de teste.
- **`entropy_calc` com `<=` em vez de `<`:** o orçamento operacional
  (`target_bits=256`, `p_max=0,20`, `num_verdict_tests=6`) nunca produz um
  resíduo exatamente igual a 256,0 em ponto flutuante (residual(127) ≈
  257,17; residual(126) ≈ 254,90) — confirmado numericamente e por 5
  repetições da suíte completa com a mutação aplicada, sempre com o mesmo
  resultado (determinístico, não uma flutuação). A mutação não muda o
  comportamento para nenhum valor realista de entrada; não há nada para
  um teste "pegar".

## 5. Limitações arquiteturais confirmadas (informativo)

### 5.1 `selftest` não detecta um backdoor que preserva as respostas dos KATs

**PoC:** `redteam/poc/backdoored_pyz_demo.py`. Um artefato `.pyz`
construído a partir do código-fonte real, com `combine.py` alterado para
vazar `E` via `stderr`, continua reportando `RESULTADO GERAL: PASSOU` em
`selftest` — porque todo KAT recebe a resposta computacional CORRETA; o
backdoor só adiciona um efeito colateral que nenhum KAT verifica a
ausência de. Em contraste, o mesmo PoC confirma que uma wordlist
embutida adulterada (1 palavra trocada) **é** detectada (via o hash
SHA-256 comparado contra `WORDLIST_SHA256`).

**Isto não é uma vulnerabilidade de código** — é uma propriedade inerente
de qualquer suíte de testes de resposta conhecida (elas verificam
"a saída está certa?", não "o programa fez SÓ isso?"). A defesa real já
existe e está documentada (`docs/AUDIT.md`, `make repro`): comparar o
hash do artefato contra um build reproduzido a partir de código-fonte que
você mesmo revisou. Adicionamos uma nota explícita em `docs/AUDIT.md`
(ver diff desta auditoria) deixando essa fronteira clara, porque o texto
anterior não a declarava tão diretamente.

### 5.2 A garantia "sem PRNG próprio" é estática, não runtime — e não tem correção limpa

**PoC:** `redteam/poc/random_module_dynamic_import.py`. O teste estático
(`tests/test_security_ast.py`) verifica *imports literais* de `random` em
`entropyforge/*.py`; um `importlib.import_module("random")` dinâmico não
aparece na AST e **não é bloqueado pelo audit hook** (não existe evento
`sys.audit` para "usar o módulo `random`", ao contrário de rede/disco/
subprocess).

**Correção considerada e REJEITADA:** um `sys.meta_path` que bloqueasse
qualquer importação de `random` foi implementado experimentalmente e
**quebrou funcionalidade legítima**: `wordlist.py` usa
`importlib.resources` (para funcionar tanto de um diretório quanto de
dentro do `.pyz`), que importa `tempfile` transitivamente, que por sua vez
importa `random` internamente (para nomes de arquivo temporário) — um
detalhe de implementação da biblioteca padrão, sem relação com geração de
segredos. Confirmado por PoC que isso acontece mesmo na ordem real de
inicialização (`guard.activate()` primeiro, `cli`/`wordlist` depois).
Bloquear `random` cegamente quebraria a aplicação.

**Por que isto é aceitável:** contornar o check estático exige a mesma
capacidade — modificar o código-fonte de `entropyforge/` — que já
permitiria ataques muito mais diretos e graves (o backdoor via `stderr`
da seção 5.1, ou simplesmente hardcodar um valor fraco em `osrng.py` sem
importar nada incomum). O check estático continua sendo a mitigação
correta e proporcional para este requisito especificamente; não
adicionamos complexidade (inspeção de pilha de chamadas, por exemplo)
para fechar uma lacuna cujo "fechamento" não reduziria o risco real.

## 6. Confirmação de que as correções funcionam

- **Suíte completa:** 182 testes, 50 execuções consecutivas sem falha
  (era ~15% de chance de falha por execução antes da correção 3.2).
- **Cross-version:** Python 3.10, 3.11, 3.12, 3.13 — suíte completa
  passando em todas.
- **Mutation testing, execução final:** 9/11 mutantes mortos (era 6/11
  antes das correções da seção 4); os 2 sobreviventes restantes foram
  analisados e confirmados como não-lacunas (seção 4.3), não pendências.
- **Exploit do `--rolls` negativo:** confirmado reproduzido no código
  ANTES da correção (>1000 iterações sem terminar) e confirmado NÃO
  reproduzível no código ATUAL via o caminho real (`cmd_generate`
  retorna em <0,1s com código de erro claro).
- **Build reprodutível:** `make repro` — hashes idênticos — e
  `selftest` do artefato reconstruído — PASSOU — reconfirmados após todas
  as mudanças desta auditoria.
- **13/13 tentativas de bypass do guard** (rede, DNS, subprocess, exec,
  posix_spawn, ctypes, escrita via `open()`, escrita via `os.open()` com
  flags, criação de arquivo vazio, mmap, `os.remove`, `os.rename`)
  continuam bloqueadas (`redteam/poc/guard_bypass_probes.py`).
- **Fuzzing BIP-39 independente:** 10.000 entropias aleatórias + fronteiras
  de bit exaustivas (5 tamanhos × todos os bits únicos + todos os
  prefixos de 1s) + 5.000 mnemonics adulterados — 0 divergências entre
  `entropyforge.bip39` e uma implementação independente por deslocamento
  de bits (`redteam/scripts/bip39_independent_fuzz.py`).

## 7. Ataques que NÃO quebraram o sistema

Para registro completo (nem todo ataque tentado gera uma vulnerabilidade):

| # | Ataque | Resultado |
|---|---|---|
| 1 | Socket TCP direto após `guard.activate()` | Bloqueado |
| 2 | DNS/`getaddrinfo` (exfiltração via nome de host) | Bloqueado |
| 3 | `subprocess.Popen`, `os.system`, `os.execve`/`execv`/`execvp`, `os.posix_spawn` | Bloqueados (todos) |
| 4 | `ctypes.CDLL`/`dlopen` (chamadas de baixo nível) | Bloqueado (já na importação do módulo) |
| 5 | Escrita via `open()` builtin e via `os.open()` bruto (todas as flags) | Bloqueados |
| 6 | Criação de arquivo vazio via `O_CREAT` isolado | Bloqueado |
| 7 | `mmap` com escrita | Bloqueado (o `open()` prévio já bloqueia) |
| 8 | `os.remove`, `os.rename`/`os.replace` | Bloqueados |
| 9 | Vazamento via variáveis de ambiente (canário injetado) | Nenhum vazamento; `entropyforge/` não lê `os.environ`/`getenv` |
| 10 | SIGINT durante coleta de dados / durante espera de TTY | Sem vazamento; comportamento coberto por teste dedicado (`test_generate_interruption_safety.py`) |
| 11 | Unicode (dígitos arábico-índicos parecidos com "123456", emoji, mnemonic com lixo) | Todos rejeitados corretamente, sem crash |
| 12 | Argumentos de CLI malformados/ausentes, `--rolls` acima do limite estrutural | Rejeitados com código de saída não-zero, sem crash |
| 13 | `generate`/`calibrate` com stdin/stdout redirecionado (pipe) | Recusado corretamente (checagem de TTY) |
| 14 | Fuzzing BIP-39 (10.000 aleatórios + fronteiras de bit + 5.000 adulterados) contra implementação independente | 0 divergências |
| 15 | Wordlist adulterada dentro do `.pyz` empacotado | Detectada por `selftest` |
| 16 | Reprodutibilidade do build sob umask/diretório diferentes | Hash idêntico, confirmado de novo após todas as mudanças |
| 17 | Comportamento entre Python 3.10–3.13 | Idêntico |
| 18 | Sequência adversarial "dígitos de π em base 6" (entropia real ≈ 0) | **Passa em todos os 7 testes** — confirma limitação já documentada em `docs/MATH.md` §8 (nenhum teste estatístico prova aleatoriedade); não é uma vulnerabilidade nova, é o comportamento esperado e divulgado. Ver seção 8. |
| 19 | Construir uma sequência que maximize previsibilidade mantendo todos os testes verdes | Conseguido (π em base 6); ver seção 8 para o porquê isso não compromete `E` |
| 20 | LCG fraco (constantes glibc) como sequência "aleatória" | Corretamente REJEITADO pela bateria (`serial_difference` e `repeats` pegam a estrutura de reticulado clássica de LCGs) |

## 8. Ataque estatístico: poder da bateria contra construções adversariais

Ferramenta: `redteam/scripts/adversarial_sequences.py`. Todas as
construções usam n=127 (o operacional real de `generate`).

| Construção | Entropia real (limite superior) | Veredito | O que passou / falhou |
|---|---|---|---|
| Constante (todas as faces = 3) | 0 bits | **FAIL** | frequência, diferenças seriais, repetições falham; corridas e autocorrelação passam (caso degenerado, ver `docs/MATH.md`) |
| Alternando 1/6 | ≤1 bit | **FAIL** | todos os 7 testes falham |
| Ciclo 1‑6 repetido (período 6) | 0 bits | **FAIL** | frequência passa (!); diferenças seriais, repetições, corridas falham |
| **Dígitos de π em base 6** | **0 bits** | **PASS** | **todos os 7 testes passam** |
| LCG (constantes glibc) | ≤2 bits | **FAIL** | frequência com WARN; diferenças seriais e repetições falham |
| Bloco de 12 repetido | 0 bits | **FAIL** | diferenças seriais, repetições, corridas falham |
| Segunda metade = cópia da primeira (base π) | 0 bits | **FAIL** | diferenças seriais falha na junção das metades |
| Segunda metade = espelho (7−f) da primeira (base π) | 0 bits | **WARN** | só `serial_difference` fica em WARN — nenhum teste FALHA |

**A resposta à pergunta "qual é a sequência de d6 mais fraca que passa
sem abortar o programa":** dígitos de uma constante matemática publicada
(aqui, π), convertidos para base 6. Entropia real: **0 bits** (a
sequência inteira é determinada por uma regra de descrição fixa, que não
cresce com `n`). Ela passa em **todos os 7 testes**, incluindo o veredito
geral corrigido por Holm.

**Por que isto NÃO é uma vulnerabilidade nova:** `docs/MATH.md` §8 já
afirma, em palavras quase idênticas, que "uma sequência determinística
'bem comportada' ... pode passar em todos os testes com entropia ≈ 0"
— o red team aqui **confirma empiricamente uma limitação já divulgada**,
não descobre uma nova. Mais importante: mesmo neste pior caso, `E`
continua tendo a segurança dada pela fonte B (`os.getrandom`, 256 bits
independentes) — ver `docs/MATH.md` §5.2, "basta que uma das duas fontes
seja boa e desconhecida do adversário". O dano real de um usuário usar
"dígitos de π" em vez de lançar o dado de verdade é perder a
REDUNDÂNCIA entre as duas fontes (ficar dependendo só de B), não perder a
segurança de `E` enquanto B permanecer íntegro e secreto — um risco que
já está descrito em `docs/THREAT_MODEL.md` (ameaça T-DICE, "sequência
inventada com cuidado passa nos testes") e é, por natureza, **indetectável
por software** (equivalente a um problema de complexidade de Kolmogorov).

Também avaliamos e **rejeitamos** uma mitigação aparentemente óbvia: um
teste de compressão genérica (ex.: taxa de compressão via `zlib`) não
pegaria "dígitos de π", porque uma sequência assim é tão incompressível
para um compressor genérico (que não conhece a fórmula de π) quanto uma
sequência genuinamente aleatória — confirmamos isso é consistente com a
natureza do problema (não é um teste estatístico de curto alcance que
falta, é um limite fundamental do que se pode inferir sobre o PROCESSO
gerador a partir só da SAÍDA).

### 8.1 Poder estatístico contra viés controlado (tabela fina, n=127)

Ferramenta: `redteam/scripts/power_crossover.py` (2000 tentativas por
linha, `random.Random(20260927001)`, complementa
`docs/simulation_results.txt`).

| p da face viciada | taxa de detecção (FAIL) |
|---|---|
| 0,167 (honesto) | 1,9% (falso positivo nominal) |
| 0,18 | 1,6% |
| 0,19 | 3,1% |
| **0,20 (o `p_max` assumido pelo projeto)** | **3,8%** |
| 0,21 | 6,8% |
| 0,22 | 9,9% |
| 0,23 | 13,5% |
| 0,24 | 17,1% |
| 0,25 | 24,0% |

**Conclusão:** no `n` operacional real, um dado viciado exatamente no
limite assumido pelo projeto (`p_max=0,20`) tem **96,2% de chance de
passar despercebido** por essa única sessão de geração. Isto confirma
(com resolução mais fina) o que `docs/MATH.md` §10.2 já afirma
qualitativamente: a bateria estatística de uma única sessão NÃO é, e
nunca foi apresentada como, a defesa contra viés moderado — a defesa é a
margem de engenharia (assumir `p_max=0,20` em vez de 1/6 ao calcular `n`)
mais o backup da fonte B. Não é uma vulnerabilidade nova.

## 9. Auditoria da própria suíte de testes

Além das lacunas confirmadas por mutation testing (seção 4), foi feita
uma revisão manual de testes "que validam a implementação contra ela
mesma". Achado principal: `tests/test_wordlist.py`,
`WordlistTamperDetectionTests` — quatro dos cinco testes recalculavam os
bytes `raw` a partir da lista `words` JÁ ADULTERADA, fazendo a checagem
de HASH (a primeira do pipeline de `_validate`) disparar antes da
checagem específica que cada teste dizia estar validando (ordenação,
duplicatas, ASCII). Corrigido para usar os bytes originais (hash válido)
e corromper só a lista `words` em memória — agora cada teste realmente
exercita a checagem que afirma testar (confirmado: `test_wrong_hash_rejected`
continua sendo o único que usa bytes adulterados, de propósito).

## 10. Correções aplicadas (resumo)

| Arquivo | Mudança |
|---|---|
| `entropyforge/cli.py` | `_validate_rolls_arg()`; `generate`/`calibrate` rejeitam `--rolls` ≤0 ou acima do limite estrutural antes de coletar entrada |
| `tests/test_cli_generate.py` | `_real_d6_not_rejected()`; 3 pontos de geração de sequência corrigidos; checagem de vazamento por palavra isolada trocada por pares consecutivos; nova classe `RollsArgumentValidationTests` (6 testes) |
| `tests/test_wordlist.py` | `WordlistTamperDetectionTests` corrigida para não mascarar a checagem específica sob teste pela checagem de hash |
| `tests/test_stats.py` | Nova classe `HolmIntegrationTests` (2 testes) |
| `tests/test_guard.py` | Dois novos testes exercitando `os.open()` bruto com cada flag de escrita isolada |
| `docs/AUDIT.md` | Nota explícita sobre o que `selftest` detecta e não detecta (seção 5.1) |

Nenhuma mudança de comportamento foi feita em resposta às seções 5 e 8
(limitações arquiteturais e estatísticas) — avaliadas e concluídas como
não tendo uma correção de código válida ou necessária, pelos motivos
explicados em cada uma.

## 11. Limitações desta auditoria

- ~~Não foi feita fuzzing via um pseudo-terminal (`pty`) real~~ — feito na
  Fase E (`tests/test_generate_interruption_real_subprocess.py`), e
  encontrou um bug real de severidade crítica que esta limitação, quando
  escrita, escondia: `guard.py` bloqueava `getpass.getpass()` (usado pela
  entrada oculta de dígitos) em qualquer terminal real, tornando
  `generate` inutilizável fora de testes com `TerminalIO` falsa. Ver
  `docs/FINAL_SECURITY_REVIEW.md` seção 17. Esta é a confirmação mais
  direta possível de que testar só com uma abstração que substitui a
  peça exata onde um bug vive pode deixar a suíte inteira verde
  indefinidamente.
- Mutation testing cobriu 11 mutações escolhidas por julgamento
  (checksum, encoding, combinação, wordlist, correção estatística, guard,
  cálculo de entropia) — não é uma cobertura exaustiva de todas as
  mutações possíveis.
- O poder estatístico (seções 8, 8.1) foi medido por simulação de
  software; não valida hardware físico (nenhuma simulação consegue).
- Não foi feita análise de canal lateral por tempo de execução
  (timing side-channel) além do já discutido no código
  (`hmac.compare_digest` na comparação de reconferência do mnemonic).

## 12. Adendo (Fase E) — fuzzing final

`redteam/phase_e/scripts/fuzz_final.py` (saída completa em
`redteam/phase_e/findings/fuzz_final_output.txt`) roda uma rodada final de
fuzzing dirigida especificamente aos alvos exigidos pela Fase E: parser e
normalização de dado (`dice.normalize_dice_input`, novo desde esta fase),
`dice.validate_rolls`, o encoding/decoding bijetora de `A`
(`dice.encode`/`decode`), a implementação BIP-39 (`entropy_to_mnemonic`/
`mnemonic_to_entropy`), a detecção de adulteração de checksum, o parser
do modo `vector`, e entrada de CLI via subprocesso real.

**Método:** `random.Random(20260927)` (mesma seed documentada de
`tools/simulate_power.py`), reprodutível, nunca usado para nada que
alimente uma carteira real. Critério de falha: uma exceção de tipo NÃO
documentado, uma falha em recusar entrada inválida, ou um travamento
(timeout) — nunca "o resultado parece estranho".

| Alvo | Iterações | Problemas encontrados |
|---|---|---|
| `dice.normalize_dice_input` (strings arbitrárias, incl. Unicode/bytes nulos) | 20.000 | 0 |
| `dice.validate_rolls` (idem) | 20.000 | 0 |
| `dice.encode`/`decode` round-trip (`n` até 500) | 5.000 | 0 |
| `dice.decode` (bytes totalmente arbitrários) | 5.000 | 0 |
| `bip39` entropy↔mnemonic round-trip + rejeição de comprimentos inválidos | 5.000 + 200 | 0 |
| `bip39` detecção de adulteração de checksum (5 tipos de mutação) | 5.000 | 0 (ver nota abaixo) |
| `vector` (parser argparse + `cmd_vector`) | 3.000 | 0 |
| CLI via subprocesso real (`generate`/`calibrate`, bytes aleatórios em stdin) | 60 | 0 |

**Total: 63.060 iterações, 0 problemas.**

**Nota metodológica sobre o alvo de checksum:** das 5.000 mutações
aleatórias de um mnemonic válido, 49 (~1%) foram aceitas por
`bip39.mnemonic_to_entropy` sem erro — isto **não é um bug**. O checksum
BIP-39 tem só `ENT/32` bits (4 a 8 bits para as entropias testadas aqui),
então uma fração pequena mas matematicamente esperada de mutações
aleatórias (`swap_word`/`reorder`) vai, por puro acaso, corresponder a
outro código de checksum válido — a probabilidade exata,
`2^-checksum_bits`, é a mesma métrica que `docs/MATH.md` já usa para
caracterizar a força do checksum como detector de ERROS DE TRANSCRIÇÃO
não-adversariais (nunca uma defesa criptográfica). Este fuzzer nunca trata
"mutação aceita" como falha por si só: cada aceitação é cruzada contra
`bip39_min` (a implementação independente de `independent-verifier/`, por
deslocamento de bits, não string-slicing) — só uma DIVERGÊNCIA entre as
duas implementações (uma aceita, a outra rejeita, ou aceitam entropias
diferentes) seria reportada como problema real. Nenhuma divergência foi
encontrada.
