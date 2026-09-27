# Independent Verifier — verificação de segunda ordem do EntropyForge-BIP39

> **Pergunta que este documento responde:** *"Como verificar que o
> programa que gera a carteira é realmente o programa que foi auditado, e
> que ele não consegue produzir a resposta correta enquanto exfiltra o
> segredo?"*
>
> **Resposta curta:** não se pode provar isso de forma absoluta — nenhuma
> auditoria de software prova a ausência total de um comportamento oculto
> arbitrariamente sofisticado. O que se pode fazer, e o que este projeto
> faz, é reduzir a superfície de dúvida a um conjunto pequeno e explícito
> de suposições (seção 9), verificar tudo o que for tecnicamente
> verificável de forma **independente** do próprio EntropyForge (nunca
> confiando no seu `selftest`, na sua suíte de testes, ou no seu processo
> de build para validar a si mesmos), e documentar honestamente o que
> permanece uma suposição.

## Sumário

1. [Por que este projeto existe separado do EntropyForge](#1-por-que-este-projeto-existe-separado-do-entropyforge)
2. [Arquitetura e inventário](#2-arquitetura-e-inventário)
3. [O que é verificado, e como, módulo por módulo](#3-o-que-é-verificado-e-como-módulo-por-módulo)
4. [Laboratório de backdoors — o que `selftest` detecta e o que não detecta](#4-laboratório-de-backdoors--o-que-selftest-detecta-e-o-que-não-detecta)
5. [Ataques de import e observação externa de processo](#5-ataques-de-import-e-observação-externa-de-processo)
6. [Matriz de ataques de cadeia de suprimentos](#6-matriz-de-ataques-de-cadeia-de-suprimentos)
7. [O verificador também precisa ser auditado (mutation testing)](#7-o-verificador-também-precisa-ser-auditado-mutation-testing)
8. [Protocolo de divergência](#8-protocolo-de-divergência)
9. [Raiz de confiança — o que você precisa assumir](#9-raiz-de-confiança--o-que-você-precisa-assumir)
10. [Modelo de ameaça](#10-modelo-de-ameaça)
11. [Tabela final de testes obrigatórios](#11-tabela-final-de-testes-obrigatórios)
12. [Princípio de não-caixa-preta](#12-princípio-de-não-caixa-preta)
13. [Limitações conhecidas](#13-limitações-conhecidas)
14. [Recomendações](#14-recomendações)
15. [Como reproduzir esta auditoria](#15-como-reproduzir-esta-auditoria)

---

## 1. Por que este projeto existe separado do EntropyForge

`docs/REDTEAM.md` já submeteu `entropyforge/` a uma auditoria adversarial
extensa — mas essa auditoria usou, em grande parte, as próprias
ferramentas do projeto (sua suíte de testes, seu `selftest`, seu processo
de build). Isso deixa uma pergunta em aberto: **e se o próprio conjunto de
ferramentas estiver comprometido?** Um `selftest` malicioso poderia, em
princípio, mentir sobre si mesmo. Uma suíte de testes adulterada poderia
ser feita para sempre passar.

`independent-verifier/` existe para responder a essa pergunta com uma
regra estrutural simples, aplicada em todo o projeto:

> **Nenhum módulo em `independent-verifier/verifier/` importa código de
> `entropyforge/`, com exceção de `bip39_compare.py` — e mesmo ali, o
> propósito é EXPLICITAMENTE comparar `entropyforge.bip39` contra duas
> fontes independentes (vetores oficiais e uma implementação própria),
> nunca confiar nele.**

Cada verificação (hashing, checagem de wordlist, implementação BIP-39,
inspeção do `.pyz`, build reprodutível, análise estática, observação de
processo, sandbox) é escrita do zero, usando apenas a biblioteca padrão
do Python, para que uma adulteração em `entropyforge/` — incluindo em
qualquer coisa que ele use para se auto-verificar — não tenha como
comprometer o veredito do verificador.

## 2. Arquitetura e inventário

```
independent-verifier/
├── verifier/
│   ├── hashing.py          # SHA-256 + manifestos independentes (Fase 2-3)
│   ├── wordlist_check.py   # validação da wordlist BIP-39 (Fase 3)
│   ├── bip39_min.py        # implementação BIP-39 independente, bit-shifting (Fase 4)
│   ├── bip39_compare.py    # ÚNICO módulo que importa entropyforge (Fase 4)
│   ├── build_repro.py      # build reprodutível (Fase 5)
│   ├── pyz_inspect.py      # inspeção byte-a-byte do .pyz (Fase 9)
│   ├── static_scan.py      # análise estática AST + textual (Fase 8)
│   ├── process_observe.py  # observação via strace (Fase 11)
│   ├── sandbox.py          # execução isolada via unshare --net (Fase 12)
│   ├── divergence.py       # protocolo de investigação de divergência (Fase 15)
│   └── trust_chain.py      # análise da raiz de confiança (Fase 16)
└── tests/                  # 106 testes, um arquivo por módulo acima
```

Material de ataque e laboratórios ficam em `redteam/independent/`:

```
redteam/independent/
├── labs/
│   ├── backdoors/backdoor_lab.py       # 10 backdoors de laboratório (Fase 6)
│   └── supply_chain/supply_chain_lab.py # 6 cenários A-F (Fase 13)
├── scripts/
│   ├── run_backdoor_lab.py
│   ├── run_import_attacks.py
│   ├── run_supply_chain_matrix.py
│   └── mutation_testing_verifier.py    # Fase 14
└── findings/                            # saídas reais, re-executáveis
```

**Fora do escopo desta verificação** (ver seção 9 para os detalhes de
cada um): firmware/BIOS/UEFI, o hardware físico (CPU, RNG de hardware), o
kernel do sistema operacional em si (apenas observado, não auditado linha
a linha), o interpretador CPython em si, e o operador humano (lançamento
físico dos dados, ambiente livre de câmeras/observadores).

## 3. O que é verificado, e como, módulo por módulo

| Módulo | O que verifica | Como | Detecta adulteração de |
|---|---|---|---|
| `hashing.py` | Integridade de qualquer árvore de arquivos | SHA-256 próprio + manifesto texto determinístico | qualquer arquivo, byte a byte |
| `wordlist_check.py` | A wordlist de 2048 palavras | estrutura (contagem, ordem, ASCII, duplicatas) + hash **embutido no próprio verificador** (`KNOWN_OFFICIAL_SHA256`) | wordlist adulterada, mesmo se o hash de referência do EntropyForge também for adulterado |
| `bip39_min.py` + `bip39_compare.py` | entropy↔mnemonic | implementação independente (inteiro + deslocamento de bits, não string-slicing como `entropyforge/bip39.py`) comparada contra 24 vetores oficiais **e** contra `entropyforge.bip39` | bugs/backdoors no algoritmo BIP-39 |
| `pyz_inspect.py` | O artefato `.pyz` distribuído | extrai o zip, compara cada arquivo contra o source-tree; compara o bootstrap `__main__.py` contra um valor exato hardcoded (não derivado do build) | módulo extra, arquivo faltando, conteúdo alterado, bootstrap adulterado |
| `build_repro.py` | O processo de build | roda `tools/build_pyz.py` duas vezes (diretórios/umask diferentes), compara hashes | builds não-deterministas — **não** prova honestidade (ver seção 6) |
| `static_scan.py` | Código-fonte | AST + regex por termos de rede/execução externa/ofuscação | imports/chamadas suspeitas, incluindo diff contra um baseline revisado |
| `process_observe.py` | Comportamento em tempo real | `strace -f` a nível de syscall do kernel | tentativa real de rede/subprocess/escrita, independente de qualquer coisa que o audit hook do EntropyForge diga |
| `sandbox.py` | Comportamento em tempo real, com contenção | `unshare --net` (namespace de rede vazio) + diff de diretório de trabalho | confirma que uma tentativa de rede FALHA mesmo que todo o resto esteja comprometido |
| `divergence.py` | Metodologia de investigação | reproduz → compara contra especificação oficial → nunca declara "falha" sem referência | uso interno de todos os módulos acima |
| `trust_chain.py` | A cadeia de confiança em si | enumera 11 elos e classifica cada um (verificável/redutível/substituível/auditável/mensurável/hipótese) | nada — é a documentação estrutural da seção 9 |

## 4. Laboratório de backdoors — o que `selftest` detecta e o que não detecta

`redteam/independent/labs/backdoors/backdoor_lab.py` materializa 10
cópias completas de `entropyforge/`, cada uma com **um** backdoor de
laboratório inserido (nunca dados reais — toda entropia "vazada" vem de
vetores de teste públicos). `redteam/independent/scripts/run_backdoor_lab.py`
roda `selftest` e `vector` contra cada cópia e registra os resultados reais
em `redteam/independent/findings/backdoor_lab_output.txt`. Resumo:

| # | Backdoor | `selftest` reporta PASSOU? | Marcador visível em `selftest`? | Ativo só fora do `selftest`? | Bloqueado pelo guard? |
|---|---|---|---|---|---|
| 01 | Exfiltração via stderr | **True** | True | não | não (stderr não é bloqueado — por design, é a saída pública) |
| 02 | Cópia em `/tmp` | **True** | True (tentativa, bloqueada) | não | **sim**, `GuardViolation` |
| 03 | Socket UDP | **True** | True (tentativa, bloqueada) | não | **sim**, `GuardViolation` |
| 04 | Subprocess | **True** | True (tentativa, bloqueada) | não | **sim**, `GuardViolation` |
| 05 | DNS | **True** | True (tentativa, bloqueada) | não | **sim**, `GuardViolation` |
| 06 | Payload pré-guard em `__init__.py` | **True** | False | não | **não** — roda antes de `guard.activate()` existir; escreve em `/tmp` com sucesso |
| 07 | Condicional a `sys.argv` | **True** | False | **sim** | n/a (não tenta nada bloqueável, só escreve em stderr fora do selftest) |
| 08 | Condicional à pilha de chamadas | **True** | False | **sim** | n/a |
| 09 | Condicional a variável de ambiente | **True** | True | depende da env | n/a |
| 10 | `atexit` | **True** | True | não | n/a |

**Todos os 10 backdoors deixam `selftest` reportar `RESULTADO GERAL: PASSOU`.**
Isso é o resultado esperado e documentado, não uma falha de `selftest`:
cada teste de resposta conhecida (KAT) recebe a resposta CORRETA — os
backdoors só acrescentam efeitos colaterais que nenhum KAT verifica a
ausência de.

O achado mais importante desta fase é o **Backdoor 06**: é o único, dos
dez, que consegue **realmente escrever em disco com sucesso** (os outros
que tentam I/O — 02, 03, 04, 05 — são bloqueados pelo próprio
`entropyforge.guard`, ativado em `__main__.py` antes de qualquer
importação de `cli`). O Backdoor 06 explora uma janela real e já
documentada no próprio código do EntropyForge: código em
`entropyforge/__init__.py` roda **antes** que `guard.activate()` possa
ser chamado. Nenhuma correção de código é proposta aqui — fechar essa
janela exigiria mudar a ordem de inicialização do pacote Python em si
(algo fora do controle do próprio `__init__.py`), e o `docs/AUDIT.md`
(seção 6) já documenta esse limite. É registrado aqui como uma limitação
estrutural conhecida, não uma vulnerabilidade nova.

> **"Selftest validates correctness, not provenance."** Esta é a frase
> central desta fase, e é um limite ESTRUTURAL esperado de qualquer
> verificação de caixa-preta que rode DENTRO do mesmo processo/binário
> que está sendo verificado — não uma falha de implementação do
> EntropyForge. Um `selftest` só pode verificar que as saídas batem com
> as esperadas; ele não tem, e não pode ter, visibilidade sobre efeitos
> colaterais que o autor do backdoor tomou cuidado para não afetar essas
> saídas. `docs/AUDIT.md` seção 6 documenta a mesma conclusão do lado do
> EntropyForge.

## 5. Ataques de import e observação externa de processo

**Import shadowing** (`redteam/independent/scripts/run_import_attacks.py`,
saída em `findings/import_attacks_output.txt`): um `hashlib.py` malicioso
plantado no diretório de trabalho é carregado no lugar do `hashlib` real
quando o EntropyForge roda como `python3 -B -m entropyforge` a partir do
source, **sem** a flag `-I` (o modo de desenvolvimento). A forma de uso
real recomendada, `python3 -I -B entropyforge.pyz <comando>`, é **imune**
a esse ataque especifico (a flag `-I` implica `-P`, que não adiciona o
diretório de trabalho a `sys.path`) — confirmado empiricamente, não só
por leitura da documentação do Python.

**Observação de processo via `strace`** (Fase 11) e **sandbox com rede
isolada via `unshare --net`** (Fase 12): ver
`redteam/independent/findings/sandbox_and_process_observe_output.txt`
para os resultados completos. Destaque: um script Python puro, sem
nenhuma relação com o EntropyForge, tentando um `socket.sendto()` cru,
**falha** (`OSError: Network is unreachable`) quando rodado dentro do
sandbox de rede isolada, e **funciona** sem o isolamento — confirmando que
essa camada de defesa é independente de qualquer coisa que
`entropyforge.guard` faça ou deixe de fazer.

Um bug real foi encontrado e corrigido no PRÓPRIO verificador durante esta
fase: `process_observe.TraceResult.spawned_process` sempre retornava
`True` (mesmo para um script que não gera nenhum processo filho), porque
o parser contava o `execve` inicial do PRÓPRIO comando sendo tracejado
(um artefato de como `strace cmd` funciona) como se fosse um processo
gerado pelo programa observado. Corrigido; teste de regressão em
`tests/test_process_observe.py::BenignProcessTests::test_plain_script_does_not_falsely_report_spawned_process`.

## 6. Matriz de ataques de cadeia de suprimentos

Fase 13. Seis cenários (`redteam/independent/labs/supply_chain/supply_chain_lab.py`),
cada um comprometendo um ponto DIFERENTE entre "código-fonte auditado" e
"programa que o usuário executa". Resultado completo em
`redteam/independent/findings/supply_chain_matrix_output.txt`; regressão em
`tests/test_supply_chain.py`.

| Cenário | Descrição | Detectado? | Por qual controle | Limitação |
|---|---|---|---|---|
| A | Uma linha alterada em `dice.py` (fora do caminho crítico) | **Sim** | diff de manifesto (`hashing.py`) | `bip39_compare` e o scanner estático **não** pegam isso — o primeiro por escopo (não olha `dice.py`), o segundo porque afrouxar uma checagem de intervalo não usa nenhum termo suspeito |
| B | Uma palavra da wordlist trocada | **Sim** | `wordlist_check.check_matches_official_hash` (hash embutido no verificador) | a checagem estrutural (`report.ok`) sozinha **não** pega isso — a palavra trocada ainda parece uma palavra válida |
| C | `.pyz` adulterado após o build | **Sim** | `pyz_inspect.compare_pyz_to_source` | nenhuma — este é o caso ideal para este controle |
| D | Script de build (`tools/build_pyz.py`) adulterado | **Sim** | `pyz_inspect.compare_pyz_to_source` | `build_repro.check_build_determinism` **não** pegaria isso: o build adulterado é perfeitamente determinístico (mesmo backdoor toda vez) |
| E | Pacote impostor (mesmo nome, `combine.py` com ordem A/B trocada) | **Sim** | diff de manifesto contra referência de confiança | `bip39_compare` **não** pega esta alteração específica (ela está em `combine.py`, que `bip39_compare` nunca exercita) — só o diff de manifesto pega |
| F | Backdoor em `report.py` (módulo "irrelevante") | **Sim** | diff de manifesto + `static_scan` (categoria `rede`) | `bip39_compare` **não** pega isso — está fora do escopo dele; ilustra que um controle de escopo estreito não cobre arquivos fora dele, mesmo no mesmo pacote |

**Conclusão da Fase 13:** nenhum controle individual cobre todos os
cenários. A defesa real é a COMBINAÇÃO — em particular, o diff de
manifesto contra uma referência de confiança **obtida por um canal
independente do artefato sob teste** é o único controle que detecta os
seis cenários (às vezes como o único a fazê-lo). Isso reforça a
importância da seção 9: a força de qualquer verificação por hash depende
inteiramente de como o hash de referência foi obtido.

## 7. O verificador também precisa ser auditado (mutation testing)

Fase 14. Se o próprio `independent-verifier` tiver um bug — por exemplo,
uma comparação de hash que ignora o conteúdo real, ou uma checagem de
duplicata removida por engano — ele daria uma falsa sensação de segurança
**pior** do que não ter verificador nenhum.
`redteam/independent/scripts/mutation_testing_verifier.py` aplica a mesma
metodologia de mutation testing usada contra `entropyforge/`
(`docs/REDTEAM.md`, seção 4), desta vez contra `independent-verifier/verifier/`:

| Mutante | O que quebra | Resultado |
|---|---|---|
| `hashing`: diff ignora SHA-256, só compara tamanho | aceitaria um arquivo adulterado do mesmo tamanho | **KILLED** |
| `hashing`: `hash_file` sempre retorna o mesmo valor | aceitaria qualquer arquivo | **KILLED** |
| `wordlist_check`: checagem de duplicata removida | aceitaria wordlist com palavras repetidas | **KILLED** |
| `wordlist_check`: hash oficial sempre "bate" | aceitaria qualquer wordlist como oficial | **KILLED** |
| `pyz_inspect`: ignora arquivos inesperados no `.pyz` | aceitaria um módulo extra escondido | **KILLED** |
| `pyz_inspect`: bootstrap sempre "bate" | aceitaria um `__main__.py` adulterado | **KILLED** |
| `bip39_min`: checksum usa o último byte, não o primeiro | quebraria silenciosamente a implementação independente | **KILLED** |
| `static_scan`: categoria "rede" esvaziada | pararia de sinalizar `socket`/`connect`/`send` | **KILLED** |
| `build_repro`: `identical` ignora o hash, só compara tamanho | reportaria builds diferentes como "idênticos" | **SURVIVED na 1ª rodada → corrigido** |

O mutante `build_repro_identical_ignores_hash` **sobreviveu** na primeira
rodada: nenhum teste existente construía dois `BuildReproResult` com o
MESMO tamanho e hashes DIFERENTES. Isso era uma lacuna de cobertura real
no próprio verificador (embora não uma vulnerabilidade explorável neste
caso específico — `check_build_determinism` sempre popula os hashes a
partir de builds reais). Corrigido com
`tests/test_build_repro.py::BuildReproResultIdenticalPropertyTests` (3
testes novos). Após a correção: **9 de 9 mutantes mortos** — nenhuma
lacuna de cobertura conhecida permanece no verificador.

Este é o mesmo tipo de achado meta que o `docs/REDTEAM.md` (seção 4)
registrou para o harness de mutation testing original: **ferramentas de
auditoria também precisam ser auditadas** — e, quando um problema é
encontrado nelas, a resposta é a mesma (corrigir + testes de regressão +
re-rodar tudo), não descartar a ferramenta.

## 8. Protocolo de divergência

Fase 15, implementado em `verifier/divergence.py`. Sempre que duas fontes
discordam, a regra obrigatória é: (1) **reproduzir** de forma
determinística, (2) **capturar** a entrada mínima que causa a
divergência, (3) **determinar** qual está correta comparando AMBAS contra
a especificação oficial — nunca uma implementação contra a outra como
árbitro — e (4) **documentar**. `investigate()` implementa os passos 1 e
3 e nunca produz um veredito de "falha" quando não há referência oficial
disponível: o veredito nesse caso é explicitamente `inconclusive_no_official_reference`,
distinto de `<implementação>_is_wrong`. Testado em `tests/test_divergence.py`,
incluindo um caso real (uma cópia adulterada de `entropyforge/bip39.py`
comparada contra `bip39_min.py` e contra um vetor oficial), confirmando
que o protocolo culpa corretamente a implementação adulterada, não a
independente.

## 9. Raiz de confiança — o que você precisa assumir

Fase 16, implementado em `verifier/trust_chain.py`
(`render_markdown_table()` gera a tabela abaixo a partir dos mesmos dados
usados pelos testes de `tests/test_trust_chain.py` — não há duas fontes
de verdade divergentes aqui).

| Componente | Verificável | Redutível | Substituível | Auditável | Mensurável | Permanece hipótese |
|---|---|---|---|---|---|---|
| Firmware / BIOS / UEFI | não | não | sim | não | não | **SIM** |
| Hardware (CPU, RAM, controladores) | não | não | sim | não | sim | **SIM** |
| Kernel do sistema operacional | sim | sim | sim | sim | sim | não |
| Interpretador Python (CPython) | sim | sim | sim | sim | sim | não |
| Código-fonte de `entropyforge/` | sim | não | não | sim | sim | não |
| Wordlist BIP-39 (`data/english.txt`) | sim | sim | não | sim | sim | não |
| Processo de build (`tools/build_pyz.py`) | sim | sim | sim | sim | sim | não |
| Artefato distribuído (`.pyz`) | sim | sim | não | sim | sim | não |
| CSPRNG do sistema operacional (fonte B) | sim | sim | não | não | sim | **SIM** |
| Dado físico (d6) e o operador | sim | não | sim | não | sim | **SIM** |
| Ambiente de execução (terminal, display, SO em uso) | sim | não | sim | não | sim | **SIM** |

**Cinco elos permanecem, estruturalmente, uma hipótese não-eliminável:**
firmware/BIOS/UEFI, hardware, o CSPRNG do SO (no sentido criptográfico —
"esta saída é computacionalmente indistinguível de aleatória" é uma
suposição padrão da criptografia moderna, não algo que uma aplicação pode
provar sozinha), o dado físico e o operador que o lança, e o ambiente de
execução mais amplo (outros processos na mesma máquina). **Isso não é uma
falha desta análise — é o resultado honesto dela.** Qualquer alegação de
que este projeto (ou qualquer projeto de software) "prova" segurança
absoluta contra um atacante com controle total de firmware/hardware seria
falsa. O que este projeto proporciona é a eliminação de TODAS as demais
categorias de dúvida — código-fonte, wordlist, artefato distribuído,
processo de build — deixando o usuário livre para focar sua atenção
(e sua própria diligência, ex.: comprar hardware de fontes confiáveis, usar
uma máquina air-gapped) exatamente nos cinco elos que nenhuma auditoria de
software resolve.

## 10. Modelo de ameaça

Fase 17. Nove categorias de atacante, cada uma respondida por referência
às seções acima:

1. **Controla o código-fonte** (antes de você clonar/revisar) — mitigado
   por auditoria de código (`docs/REDTEAM.md`) + comparação de hash contra
   uma cópia que você mesmo revisou (seção 9: "código-fonte" é
   auditável, mas não redutível — você precisa realmente lê-lo, ao menos
   uma vez, ou confiar em quem leu).
2. **Controla o processo de build** — mitigado por
   `pyz_inspect.compare_pyz_to_source` (seção 6, cenário D): o resultado
   do build é verificado contra o source-tree, independente de como foi
   produzido.
3. **Adultera o artefato `.pyz` distribuído** (após o build, ex.: mirror
   comprometido) — mitigado pelo mesmo `compare_pyz_to_source` (seção 6,
   cenário C) + `check_bootstrap_main`.
4. **Controla o interpretador Python** (uma build de CPython trojanizada)
   — **fora do escopo de qualquer verificação que rode dentro desse
   mesmo interpretador** (seção 9: reduzido a "confio na cadeia de
   distribuição do meu SO/gerenciador de pacotes para o `python3` que
   estou usando").
5. **Controla o sistema operacional** (kernel comprometido) — parcialmente
   mitigado por observação de syscall via `strace` (seção 5), que opera
   numa camada que o kernel não controla sobre si mesmo SE o mecanismo de
   ptrace em si não estiver comprometido; um kernel adversarial poderia,
   em princípio, mentir também para o `strace`. Reduzido, não eliminado.
6. **Controla o hardware** (CPU/firmware backdoored) — **fora do escopo**
   de qualquer verificação de software (seção 9); nenhuma ferramenta
   deste projeto ou de qualquer outro consegue provar a ausência disso a
   partir de dentro do próprio hardware suspeito.
7. **Observa o terminal** (screen scraping, keylogger, câmera) — fora do
   escopo do processo do EntropyForge em si (que não pode controlar o
   restante do ambiente); mitigado operacionalmente (não por este
   verificador) usando `docs/OPERATIONS.md` (ambiente livre de
   câmeras/observadores).
8. **Observa o sistema de arquivos** (outro processo lendo `/tmp`, por
   exemplo) — o EntropyForge nunca escreve em disco por design
   (`entropyforge.guard`, requisito 14); o sandbox (Fase 12) confirma
   isso por observação externa, não só por leitura do código-fonte.
9. **Tem acesso físico ao operador ou ao dispositivo** (coação, dado
   viciado, máquina já comprometida antes de o usuário a obter) — fora do
   escopo de qualquer verificação de software; ver seção 9, "dado físico
   e o operador" e "firmware/hardware".

## 11. Tabela final de testes obrigatórios

Fase 18. Os 14 cenários exigidos pela auditoria, e o que os detecta hoje:

| # | Ataque | Detectado? | Por qual controle | Limitação |
|---|---|---|---|---|
| 1 | Versão legítima (controle negativo) | n/a (nada deveria ser detectado) | todos os módulos concordam: `ok=True`/`is_identical=True` em toda a suíte | nenhuma — é o baseline |
| 2 | Source alterado (uma linha, fora do caminho crítico) | **Sim** | `hashing.diff_manifests` | controles de escopo estreito (`bip39_compare`, `static_scan` neste caso específico) não pegam |
| 3 | Wordlist adulterada | **Sim** | `wordlist_check.check_matches_official_hash` (hash embutido) | checagem estrutural sozinha não basta |
| 4 | `.pyz` adulterado | **Sim** | `pyz_inspect.compare_pyz_to_source` | requer uma cópia de confiança do source-tree para comparar |
| 5 | Backdoor via stderr | `selftest` continua PASSOU | `static_scan` (se `stderr`/termo suspeito aparecer) + revisão manual do diff de `combine.py` | `selftest` sozinho nunca pega (ver seção 4) |
| 6 | Backdoor de arquivo (`/tmp`) | bloqueado em runtime pelo `guard`; `selftest` continua PASSOU | `entropyforge.guard` (runtime) + `process_observe`/`sandbox` (observação externa) | o backdoor pré-guard (#06 do laboratório) **escapa** de ambos — ver seção 4 |
| 7 | Backdoor de socket | bloqueado em runtime pelo `guard`; `selftest` continua PASSOU | `entropyforge.guard` + `sandbox` (isolamento de rede independente do guard) | nenhuma neste caso — dupla camada (audit hook + namespace de rede vazia) |
| 8 | Backdoor de subprocess | bloqueado em runtime pelo `guard`; `selftest` continua PASSOU | `entropyforge.guard` + `process_observe` (syscall `execve`/`clone`) | nenhuma neste caso |
| 9 | Payload condicional a `argv` ("só fora de `generate`/`selftest`") | `selftest` continua PASSOU, SEM marcador visível | **nenhum controle de caixa-preta** — só a leitura do código-fonte (`static_scan`/revisão manual) pega a lógica condicional em si | limitação estrutural: nenhum teste de comportamento consegue provar ausência de um `if` que o evita |
| 10 | Payload condicional à pilha de chamadas (detecta `selftest`) | `selftest` continua PASSOU, SEM marcador visível | mesma limitação do #9 — mais difícil ainda de mascarar por engano, mas igualmente invisível a testes de comportamento | idem |
| 11 | Módulo escondido no `.pyz` | **Sim** | `pyz_inspect.compare_pyz_to_source` (`unexpected_in_pyz`) | nenhuma |
| 12 | Import shadowing (`hashlib.py` malicioso no cwd) | **Sim, no modo dev**; **imune no `.pyz` com `-I`** | observação empírica direta (Fase 10) | modo de desenvolvimento (`-m entropyforge` sem `-I`) permanece vulnerável por design (é para dev, não para uso real) |
| 13 | Ambiente adulterado (variável de ambiente mágica) | `selftest` continua PASSOU se a variável não estiver setada durante o teste | mesma limitação dos #9/#10 — comportamento condicional a estado externo é invisível a testes de resposta conhecida | idem |
| 14 | Build não-reprodutível | **Sim** | `build_repro.check_build_determinism` (demonstrado com um build de laboratório que embute `time.time()`) | só detecta NÃO-determinismo; um build determinístico mas DESONESTO (cenário D, seção 6) passa por este controle e só é pego por `pyz_inspect` |

## 12. Princípio de não-caixa-preta

Fase 19. Este documento, e todo o código de `independent-verifier/`,
evita deliberadamente frases como *"o verificador não encontrou backdoor,
logo o programa é seguro"*. A afirmação correta, seguida consistentemente
aqui, tem sempre a forma:

> **"O verificador detectou / não detectou os comportamentos X, Y, Z sob
> as condições A, B, C."**

Por exemplo: "o sandbox não detectou tentativa de rede" significa
exatamente isso — nenhuma tentativa de rede ocorreu **na execução
observada, com a entrada usada, no tempo em que a observação durou** —
nunca "não existe nenhum caminho de código que tentaria rede". As seções
4, 6, 8 e 11 deste documento contêm, cada uma, pelo menos um caso onde
essa distinção é a diferença entre um veredito correto e um falso senso
de segurança (os backdoors condicionais #07/#08/#09 são o exemplo mais
direto: eles **não são detectados** por nenhum teste de comportamento
deste projeto, e este documento diz isso explicitamente, em vez de
omitir).

## 13. Limitações conhecidas

- **Payloads condicionais ao contexto de execução** (`argv`, pilha de
  chamadas, variáveis de ambiente) não são detectáveis por nenhum teste
  de comportamento de caixa-preta, incluindo os deste verificador — só
  pela leitura direta do código-fonte relevante. `static_scan.py` ajuda
  (sinaliza `import os`, `sys.argv`, `inspect.stack`), mas não prova
  ausência de lógica condicional maliciosa.
- **`static_scan.py` é evidência, não prova**: ofuscação (`getattr(os,
  "sys"+"tem")`, construção dinâmica de nomes) escapa tanto da camada AST
  quanto da textual.
- **`process_observe.py`/`sandbox.py` só veem o que a entrada usada
  exercita**: um payload que só ativa com uma combinação específica de
  argumentos não testada não aparece.
- **`sandbox.py` só isola rede**, não o sistema de arquivos fora do
  diretório de trabalho monitorado — um payload que escreve diretamente
  em `/tmp` (como o Backdoor 06 do laboratório) não é pego por ele.
- **A comparação de hash (manifesto, `.pyz` vs. source) só tem valor se o
  valor de referência vier de um canal independente do artefato sob
  teste** — comparar um artefato adulterado contra um manifesto gerado a
  partir do MESMO artefato nunca prova nada (seção 6, cenário E).
- **`observação via `strace`` pressupõe que o mecanismo de `ptrace` do
  kernel não está, ele mesmo, comprometido** — um kernel adversarial
  poderia, em princípio, ocultar syscalls do `strace` também.
- Nenhum item desta lista foi corrigido porque nenhum tem uma correção de
  código válida — são limites estruturais de qualquer verificação de
  software, documentados aqui em vez de escondidos.

## 14. Recomendações

Para um usuário que queira o nível de confiança mais alto praticável:

1. **Revise o source-tree você mesmo** (ou confie em alguém que o fez) —
   nenhuma verificação automatizada substitui isso para o elo
   "código-fonte" (seção 9).
2. **Construa o `.pyz` você mesmo** com `make pyz` a partir do source
   revisado, em vez de baixar um artefato pré-construído de qualquer
   fonte — elimina inteiramente os cenários C, D e E da seção 6.
3. **Rode a suíte de testes de `independent-verifier/` você mesmo**,
   antes de gerar uma carteira real, contra a sua cópia do
   `entropyforge/` e do `.pyz` que você construiu (seção 15 tem os
   comandos exatos).
4. **Use uma máquina dedicada, offline, sem outros processos rodando** —
   mitiga (não elimina) as categorias de atacante 7 e 8 da seção 10.
5. **Trate o hardware e o firmware como fora do escopo de qualquer
   verificação de software** — se seu modelo de ameaça inclui um atacante
   capaz de comprometer firmware/hardware, nenhuma ferramenta descrita
   aqui (ou em qualquer projeto de software puro) resolve isso; considere
   hardware de fontes conhecidas e, se aplicável, firmware livre auditável
   (ex.: coreboot), que fica fora do escopo deste projeto.
6. **Não trate um `selftest` bem-sucedido, sozinho, como prova de nada
   além de corretude computacional** (seção 4) — sempre combine com pelo
   menos a verificação de proveniência do artefato (item 2 acima).

## 15. Como reproduzir esta auditoria

```bash
# 1. Rodar a suíte completa do EntropyForge (182 testes)
python3 -B -m unittest discover -s tests -v

# 2. Rodar a suíte completa do independent-verifier (106 testes)
cd independent-verifier && python3 -B -m unittest discover -s tests -v && cd ..

# 3. Reproduzir o laboratório de backdoors (Fase 6-7)
python3 -B redteam/independent/scripts/run_backdoor_lab.py

# 4. Reproduzir os ataques de import (Fase 10)
python3 -B redteam/independent/scripts/run_import_attacks.py

# 5. Reproduzir a matriz de cadeia de suprimentos (Fase 13)
python3 -B redteam/independent/scripts/run_supply_chain_matrix.py

# 6. Reproduzir o mutation testing do PRÓPRIO verificador (Fase 14)
python3 -B redteam/independent/scripts/mutation_testing_verifier.py

# 7. Verificar a wordlist e o hash de referência independentes
python3 -B -c "
import sys; sys.path.insert(0, 'independent-verifier')
from pathlib import Path
from verifier.wordlist_check import check_wordlist_file, check_matches_official_hash
r = check_wordlist_file(Path('entropyforge/data/english.txt'))
print('ok:', r.ok, 'sha256:', r.sha256)
print(check_matches_official_hash(r))
"
```

Hashes de referência calculados de forma independente pelo verificador,
para o estado do source-tree neste commit (recalcule os seus — o valor do
`.pyz` MUDA a cada alteração de source, por design; é exatamente isso que
o torna útil como verificação):

```
sha256(entropyforge/data/english.txt) = 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
sha256(entropyforge.pyz, construído agora via tools/build_pyz.py) = fce2241c419abb47cecda55da098101fa525f2974bee4ba3c174e89a2e5557e4
sha256(manifesto de entropyforge/, 15 arquivos, formato hashing.manifest_to_text) = 09fd4ab4f49a3f64ee70a0f13fb999ce2294b141e0e71b96dd98114c804f036d
```
