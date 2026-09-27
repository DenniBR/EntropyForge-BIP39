# Revisão de Segurança Final (Release Candidate)

> **Objetivo desta fase**: não provar que o EntropyForge-BIP39 é
> perfeito. Descobrir até onde ele pode realmente ser confiado — depois
> da implementação principal, da validação BIP-39, do red team
> (`docs/REDTEAM.md`), do mutation testing, do supply-chain testing, do
> independent-verifier (`docs/INDEPENDENT_VERIFIER.md`), do sandbox/
> isolamento de rede, e da análise de root of trust. Esta é a última
> rodada antes de considerar o projeto candidato a uso real.
>
> **Conclusão no formato exigido pela própria auditoria (seção 24):**
> nenhuma vulnerabilidade CRITICAL ou HIGH foi encontrada. Foram
> encontrados e corrigidos **6 bugs reais** (nenhum de severidade acima
> de MEDIUM) e **1 lacuna de teste de severidade MEDIUM** no teste mais
> importante do projeto do ponto de vista de confidencialidade — todos
> corrigidos, com teste de regressão, e reverificados. **Nenhuma
> vulnerabilidade adicional reproduzível foi encontrada além dessas,
> dentro do modelo de ameaça e dos testes realizados.** As premissas que
> permanecem impossíveis de eliminar (firmware, hardware, CSPRNG do SO,
> honestidade do dado físico e do operador, ambiente de execução) são
> exatamente as mesmas cinco já identificadas em
> `docs/INDEPENDENT_VERIFIER.md` §9 — esta fase não encontrou uma sexta,
> nem conseguiu reduzir nenhuma das cinco.

## Sumário

1. [Resumo executivo](#1-resumo-executivo)
2. [Matriz assunção/garantia/evidência/limitação](#2-matriz-assunçãogarantiaevidêncialimitação)
3. [Vulnerabilidades e bugs encontrados (com PoC e correção)](#3-vulnerabilidades-e-bugs-encontrados-com-poc-e-correção)
4. [Revisão criptográfica independente](#4-revisão-criptográfica-independente)
5. [Ataques ao dado físico e à bateria estatística](#5-ataques-ao-dado-físico-e-à-bateria-estatística)
6. [Ataques ao encoding, à combinação e ao CSPRNG](#6-ataques-ao-encoding-à-combinação-e-ao-csprng)
7. [Ataques de ambiente hostil, supply chain e build](#7-ataques-de-ambiente-hostil-supply-chain-e-build)
8. [Auditoria do verificador (mutation testing, rodadas 1 e 2)](#8-auditoria-do-verificador-mutation-testing-rodadas-1-e-2)
9. [Laboratório "correto mas malicioso" (16 backdoors)](#9-laboratório-correto-mas-malicioso-16-backdoors)
10. [Observação externa: legítimo vs. backdoor](#10-observação-externa-legítimo-vs-backdoor)
11. [Cerimônia de geração e automação de pré-condições](#11-cerimônia-de-geração-e-automação-de-pré-condições)
12. [Root of trust (revisado, sem mudanças)](#12-root-of-trust-revisado-sem-mudanças)
13. [Resultados estatísticos e criptográficos](#13-resultados-estatísticos-e-criptográficos)
14. [Estado final da documentação](#14-estado-final-da-documentação)
15. [Release gate](#15-release-gate)
16. [Hashes finais e instruções de auditoria independente](#16-hashes-finais-e-instruções-de-auditoria-independente)

---

## 1. Resumo executivo

Esta fase revisou **integralmente** README/DESIGN/MATH/THREAT_MODEL/
AUDIT/OPERATIONS/REDTEAM/INDEPENDENT_VERIFIER, todo o código de
`entropyforge/`, todo o `independent-verifier/`, e todos os testes, e
então tentou ativamente quebrar o projeto em 24 frentes diferentes
(re-derivação matemática, ataques ao dado físico, busca adversarial de
mínima entropia, ataque à independência dos lançamentos, ataque ao
encoding, ataque conceitual à combinação, auditoria do CSPRNG, ambiente
Python hostil, laboratório de `.pyz` expandido, ataque ao build,
segunda rodada de mutation testing do verificador, laboratório de
backdoors expandido com 6 canais novos de exfiltração, observação
externa comparativa, e a cerimônia operacional completa).

**Resultado: 6 bugs reais corrigidos, 0 vulnerabilidades CRITICAL/HIGH,
1 achado MEDIUM (lacuna no teste de confidencialidade mais importante do
projeto, corrigida), toda a matemática documentada re-derivada e
confirmada independentemente, e nenhuma redução adicional do conjunto de
premissas irredutíveis já identificado.**

Todos os testes (**191** em `entropyforge/`, **112** em
`independent-verifier/`, total **303**) passam de forma determinística.
Todo o material de ataque desta fase está em `redteam/phase_d/` (scripts
+ saídas reais, re-executáveis) e nos achados adicionados a
`redteam/independent/findings/`.

## 2. Matriz assunção/garantia/evidência/limitação

| Componente | Assunção | Garantia | Evidência | Limitação |
|---|---|---|---|---|
| Fonte A (d6 físico) | dado honesto, lançamentos i.i.d. | nenhuma — é uma premissa física | bateria estatística com poder caracterizado por simulação (`docs/MATH.md` §10); confirmado nesta fase com uma segunda simulação independente (seção 5) | poder baixo contra viés pequeno/moderado em n operacional; **zero poder** contra uma fonte de entropia real zero mas estatisticamente "limpa" (PRNG de seed conhecida, ou dígitos de um número irracional — seção 5) |
| Fonte B (CSPRNG do SO) | saída indistinguível de uniforme | nenhuma prova — heurística padrão | `osrng.py` falha fechado em todo cenário de erro testado (seção 6.3); nenhuma checagem valida qualidade criptográfica | um SO comprometido que devolve bytes controlados pelo atacante (não-constantes) passa despercebido — confirmado nesta fase |
| Codificação de A (`dice.encode`/`decode`) | — | bijeção entre `{1..6}^n` e `[0,6^n)` | prova + enumeração exaustiva (`docs/MATH.md` §3); reimplementação independente e comparação byte a byte nesta fase (seção 6.1), incluindo n=1..1000 e casos extremos | nenhuma encontrada no `encode`; um bug real de assimetria em `decode` (aceitava n=0) foi encontrado e corrigido (seção 3, achado #1) |
| Combinação `E=SHA-256(A‖B)` | SHA-256 se comporta como oráculo aleatório | vantagem do adversário ≤ q·2⁻ᵏ, k=min-entropia conjunta | argumento ROM padrão (`docs/MATH.md` §5.2); avalanche/ordem/comprimento confirmados empiricamente nesta fase (seção 6.2) | não ajuda se o adversário conhece A e controla B (já documentado); nenhuma nova limitação encontrada |
| BIP-39 (`bip39.py`) | — | corretude verificada contra vetores oficiais e implementação de referência | 24 vetores oficiais + 10.000+ round-trips + comparação cruzada independente (`independent-verifier/bip39_min.py`) | nenhuma encontrada nesta fase |
| `selftest` | — | corretude computacional (KATs) | 9 checagens, todas passam | **não** detecta backdoors — confirmado com 16 variantes de laboratório (seção 9), incluindo 6 canais novos nesta fase |
| `guard.py` (audit hook) | — | bloqueia rede/disco/subprocess/ctypes ANTES da syscall | confirmado por `strace` nesta fase (seção 10): backdoors bloqueados são indistinguíveis do código legítimo no nível de syscall — a operação nunca chega ao kernel | não protege contra backdoors que rodam antes de `guard.activate()` (backdoor 06, já documentado), nem contra canais que não são rede/disco/subprocess (stdout, exceção, sinal — seção 9) |
| Build (`tools/build_pyz.py`) | — | reprodutível byte a byte | confirmado nesta fase em **16 dimensões** (timezone, locale, umask, `PYTHONHASHSEED`, cwd, tmpfs, 4 versões de Python) — seção 7.3 | determinismo não implica honestidade (já documentado); um build determinístico mas desonesto só é pego por `pyz_inspect`, não por `check_build_determinism` |
| `independent-verifier/` | não reusa código do EntropyForge (exceto `bip39_compare.py`, propositalmente) | detecta as adulterações testadas | 112 testes próprios + 2 rodadas de mutation testing (15 mutantes, 0 sobreviventes finais) — seção 8 | análise estática é evidência, não prova (confirmado com um backdoor ofuscado — seção 9); um bug real (`verify_against_manifest` sem teste algum) foi encontrado e corrigido |
| Ambiente de execução | operador usa `-I -B` com o `.pyz` | imune a shadowing de módulo, `.pth`, sitecustomize/usercustomize, `PYTHONHOME`, `PYTHONSTARTUP` | 8 vetores testados nesta fase (seção 7.2), 0/8 afetam o `.pyz` com `-I` | o modo de desenvolvimento (`-m entropyforge` sem `-I`) é vulnerável a 5/8 vetores — já era conhecido, agora quantificado |

## 3. Vulnerabilidades e bugs encontrados (com PoC e correção)

Nenhum item abaixo passa de severidade **MEDIUM**. Formato por achado:
SEVERIDADE / PRÉ-CONDIÇÃO / IMPACTO / POC / DETECÇÃO / CORREÇÃO / TESTE
DE REGRESSÃO.

### #1 — `dice.decode()` aceita um prefixo de comprimento `n=0`

- **SEVERIDADE:** LOW/INFORMATIONAL.
- **PRÉ-CONDIÇÃO:** chamar `dice.decode()` diretamente com bytes cujo
  prefixo de comprimento é `0x0000` — `encode()` nunca produz isso
  (`validate_rolls` rejeita sequência vazia).
- **IMPACTO:** nenhum no fluxo `generate` real — `decode()` só é chamado
  internamente por `selftest` (round-trip com dados conhecidos) e por
  testes, nunca sobre entrada não confiável. É uma assimetria de
  validação, não uma vulnerabilidade explorável.
- **POC:** `dice.decode((0).to_bytes(2, "big"))` retornava `""` em vez de
  levantar `DiceInputError`.
- **DETECÇÃO:** reimplementação independente de `encode`/`decode`
  (`redteam/phase_d/scripts/encoding_attack.py`) comparando o
  comportamento contra o esperado em casos extremos de underflow.
- **CORREÇÃO:** `entropyforge/dice.py::decode` agora rejeita `n=0`
  explicitamente, simetricamente a `encode`.
- **TESTE DE REGRESSÃO:** `tests/test_dice.py::DecodeNegativeTests::test_rejects_zero_length_prefix`.

### #2 — `tests/test_cli_generate.py` não detectava vazamento via stdout/stderr REAIS (contornando a `TerminalIO` falsa)

- **SEVERIDADE:** MEDIUM (lacuna no teste mais importante do projeto do
  ponto de vista de confidencialidade — não uma vulnerabilidade ativa no
  código de produto, já que nenhum código legítimo contorna a
  abstração `TerminalIO`).
- **PRÉ-CONDIÇÃO:** um backdoor (ou bug futuro) que chame
  `sys.stdout.write(...)`/`print(...)`/`sys.stderr.write(...)`
  DIRETAMENTE, em vez de passar por `io.write`/`io.warn`.
- **IMPACTO:** a suíte de testes de confidencialidade (`test_no_secret_hex_leaks_anywhere`,
  literalmente nomeado para este propósito) **passava** mesmo com a
  entropia combinada `E` sendo escrita, em texto claro, no stdout real do
  processo — visível a qualquer um observando o terminal ou capturando a
  saída do processo, mas invisível para a asserção do teste.
- **POC:** backdoor de laboratório 12 (`redteam/independent/labs/backdoors/backdoor_lab.py`)
  injeta `sys.stdout.write(digest.hex())` em `combine.py`; a suíte
  completa (20/20 testes) reportava "ok" com a string vazada visível na
  saída do próprio `unittest -v`.
- **DETECÇÃO:** construída deliberadamente ao expandir os canais de
  exfiltração testados (stdout, além do stderr já coberto pelo
  backdoor 01).
- **CORREÇÃO:** `tests/test_cli_generate.py` agora captura stdout/stderr
  REAIS do processo (via `contextlib.redirect_stdout`/`redirect_stderr`)
  além da `TerminalIO` falsa, e `test_no_secret_hex_leaks_anywhere` checa
  as três fontes.
- **TESTE DE REGRESSÃO:** o próprio `test_no_secret_hex_leaks_anywhere`,
  reexecutado (fora da suíte) contra uma cópia com o backdoor 12 injetado,
  agora FALHA corretamente, identificando "stdout real do processo" como
  a fonte do vazamento.

### #3 — `verifier/hashing.py::verify_against_manifest` sem nenhum teste

- **SEVERIDADE:** LOW/INFORMATIONAL (função correta, mas sem cobertura —
  achado de processo, não de comportamento incorreto).
- **PRÉ-CONDIÇÃO:** nenhuma — a função sempre se comportou corretamente;
  o problema era ausência de verificação.
- **IMPACTO:** é a função de uso TÍPICO do independent-verifier ("este
  diretório ainda bate com um manifesto obtido em outro momento/lugar?")
  e não tinha nenhum teste, nem unitário nem de mutation testing.
- **POC:** `grep -rn "verify_against_manifest"` fora de sua própria
  definição não retornava nada em nenhum teste existente.
- **DETECÇÃO:** varredura de cobertura ao preparar a segunda rodada de
  mutation testing (seção 8).
- **CORREÇÃO:** nenhuma mudança de comportamento necessária — apenas
  cobertura adicionada.
- **TESTE DE REGRESSÃO:** `independent-verifier/tests/test_hashing.py::VerifyAgainstManifestTests`
  (2 testes); confirmado que um mutante que forjava esta função (rodada 2,
  seção 8) agora é morto por eles.

### #4 — `process_observe.py`: `touched_network` com falso positivo (socket AF_UNIX local)

- **SEVERIDADE:** LOW (afeta a precisão de uma ferramenta do próprio
  verificador, não o EntropyForge).
- **PRÉ-CONDIÇÃO:** rodar qualquer programa via `python3 -m <pacote>` em
  um sistema Linux/glibc onde `nscd` não está em execução.
- **IMPACTO:** `touched_network` era `True` até para um pacote Python
  **completamente vazio**, sem nenhuma relação com o EntropyForge — o
  sinal não tinha nenhum valor discriminativo, e um comparativo
  legítimo-vs-backdoor (seção 10) teria erroneamente sugerido que o
  código legítimo "tocou rede".
- **POC:** `trace_process([sys.executable, "-m", "emptypkg"], ...)` em um
  pacote com um `__main__.py` de uma linha (`print("hello")`) mostrava
  `touched_network=True`, rastreado a `socket(AF_UNIX,...)` +
  `connect(.../var/run/nscd/socket)` (ENOENT) feito pelo próprio
  mecanismo de execução `-m` do Python neste ambiente.
- **DETECÇÃO:** ao investigar por que o código legítimo do EntropyForge
  mostrava `touched_network=True` na comparação da seção 10.
- **CORREÇÃO:** `process_observe.py` agora distingue sockets `AF_UNIX`
  (IPC local, nunca sai da máquina) — contados separadamente em
  `local_unix_socket_syscalls`, nunca descartados silenciosamente — de
  famílias de endereço com capacidade de rede real (`AF_INET`,
  `AF_INET6`, etc.), que continuam contando para `touched_network`.
- **TESTE DE REGRESSÃO:** `independent-verifier/tests/test_process_observe.py::BenignProcessTests::test_module_execution_af_unix_probe_is_not_counted_as_network`;
  confirmado que `test_detects_raw_socket_attempt` (AF_INET real)
  continua passando.

### #5 e #6 — achados sem correção de código (documentados como limites estruturais confirmados)

Dois achados adicionais desta fase **não** geraram mudança de código,
por não terem correção válida (item explícito do critério de "corrigir
somente quando a correção for inequívoca"):

- **Análise estática evadida por ofuscação (backdoor 11):** um backdoor
  de socket com nomes construídos em runtime (`chr()`+`join`+`getattr`)
  escapa da categoria "rede" de `static_scan.py`, mas ainda dispara 13
  achados na categoria "reflexão" — nenhuma correção de scanner elimina
  ofuscação em geral (é o limite já documentado, "evidence not proof",
  agora confirmado empiricamente). Ver seção 9.
- **Canais de exfiltração fora do escopo de qualquer guard (backdoors 13/14/15):**
  mensagem de exceção não capturada, módulo secundário pós-guard, e
  handler de sinal (SIGTERM/SIGINT) — nenhum é bloqueável por
  `guard.py` sem impedir funcionalidade legítima (capturar toda exceção
  ou proibir handlers de sinal quebraria `tests/test_generate_interruption_safety.py`
  e o tratamento normal de erros). Confirma, com três mecanismos de
  gatilho diferentes, o limite já estabelecido no red team original: só
  revisão de código-fonte e comparação independente contra uma cópia de
  confiança cobrem esta classe. Ver seção 9.

## 4. Revisão criptográfica independente

Script: `redteam/phase_d/scripts/independent_math.py` — reimplementa,
**sem importar `entropyforge/` nem `independent-verifier/`**, todas as
fórmulas de `docs/MATH.md`. Toda afirmação numérica foi reproduzida de
forma independente e bateu exatamente:

| Grandeza | Valor em `docs/MATH.md`/`entropy_calc.py` | Recalculado de forma independente |
|---|---|---|
| `log2(6)` (entropia de Shannon de 1 lançamento) | 2,5849625... bits | 2,5849625... bits (idêntico, via `-Σp·log2 p`) |
| `n` para 256 bits teóricos (d6 honesto) | 100 | 100 |
| `n` para 128 bits teóricos | 50 | 50 |
| `n` operacional (p_max=0,20, com vazamento descontado) | 127 | 127 (com checagem de minimalidade: n=126 dá menos que 256 bits residuais) |
| ENT/CS/MS para os 5 tamanhos válidos de entropia BIP-39 | 128→12, 160→15, 192→18, 224→21, 256→24 palavras | idêntico para todos os 5 |
| Taxa de detecção do checksum (CS=8 bits) | `1 − 2⁻⁸ ≈ 99,609%` | confirmado analiticamente E empiricamente (5000 trocas de 1 palavra: 19/5000 = 0,38% escaparam, vs. 0,39% esperado) |
| Constante de Flajolet-Odlyzko `E[K log2 K]`, K~Poisson(1) | 0,8272 bits | 0,827245 bits (soma direta da série até convergência) |
| `H(Y)` para N=2²⁵⁶ sob a suposição adicional da seção 5.3 | 255,17 bits | 255,1728 bits |

**Nenhuma discrepância encontrada.** Nenhuma afirmação em `docs/MATH.md`
precisou ser enfraquecida — a documentação já rotula cada afirmação como
FATO/HEURÍSTICA/PREMISSA FÍSICA/OPINIÃO de forma precisa, e a revisão
independente confirma que os números por trás de cada rótulo estão
corretos, não apenas plausíveis.

## 5. Ataques ao dado físico e à bateria estatística

Script: `redteam/phase_d/scripts/dice_models.py` (12 modelos, n=127 e
n=3000, contra `entropyforge.stats.run_battery` real).

**Achado mais importante:** o modelo K (PRNG `random.Random`, seed
CONHECIDA=1234) passa a bateria em **100% das tentativas em n=127**
(0% FAIL, 0% WARN) e nunca dispara FAIL nem em n=3000 (só WARN). Este é
o pior caso possível de falsa sensação de segurança: entropia real = 0
bits do ponto de vista de um atacante que conhece a seed, mas aceito
quase sempre. **Isto não é um bug** — é exatamente o limite já
documentado no docstring de `stats.py` ("uma sequência inteiramente
determinística e bem comportada pode não rejeitar H0... com zero bits de
entropia real"), agora confirmado com números reais em vez de deixado
como afirmação não verificada.

Sequências grosseiramente estruturadas (constante, periódica curta,
dígitos decimais de π mapeados incorretamente mod 6) são pegas com 100%
FAIL — o ataque perigoso não é "parecer aleatório demais", é "ser um
PRNG de qualidade real com seed conhecida do atacante".

Cadeias de Markov com dependência moderada (`stay_prob`=0,30–0,40)
replicam, com um RNG e seed diferentes, a tabela de poder já publicada em
`docs/MATH.md` §10.3 (71,2% FAIL medido nesta fase vs. 74,6% documentado
para um parâmetro próximo) — boa evidência cruzada de que a tabela
original não foi inventada.

### 5.1 Busca adversarial pela sequência de menor entropia aceita

Script: `redteam/phase_d/scripts/min_entropy_search.py`. Duas buscas
independentes convergem para o MESMO limiar:

- **Bissecção** sobre a família "uma face enviesada": limiar de 50% de
  detecção em `p_bias ≈ 0,2762` (H_min ≈ 1,856 bits/lançamento, 235,76
  bits totais em n=127 — abaixo do alvo de 256).
- **Hill climbing com 15 reinícios** (mutação: converter posições para a
  face já dominante, a única direção que garantidamente reduz a
  min-entropia): converge, de forma estável através dos reinícios, para
  H_min ≈ 1,78–1,86 bits/lançamento antes de disparar FAIL — a mesma
  vizinhança encontrada pela bissecção, por um método totalmente
  diferente.

**Isto não quebra a segurança do produto**: mesmo no pior caso
encontrado (fonte A degradada para ~226 bits de min-entropia via viés
i.i.d.), o argumento de segurança da combinação (`docs/MATH.md` §5.2)
garante que a min-entropia conjunta `k ≥ max(H∞(A), H∞(B))` — a fonte B
(CSPRNG do SO, 256 bits, independente) mantém a segurança da saída
combinada **desde que o atacante não conheça B também**. O achado
quantifica precisamente o quanto a fonte A sozinha pode degradar sem
disparar FAIL, não uma quebra da construção de duas fontes.

### 5.2 Ataque à independência (regra determinística escondida)

Script: `redteam/phase_d/scripts/independence_attack.py`. Dígitos EXATOS
de √2 em base 6 (aritmética inteira via `isqrt`, sem o viés de conversão
decimal→base-6 que fez a primeira tentativa, com dígitos de π, falhar
100% das vezes) — 9 janelas testadas (3 offsets × 3 tamanhos de amostra):
1 FAIL, 4 WARN, 4 PASS, taxa comparável a uma fonte honesta i.i.d.
(controle: 3,5% FAIL, 22,5% WARN, 74% PASS em 200 tentativas). Confirma,
com uma segunda construção completamente diferente (constante matemática
pública, sem nenhum software de geração de números envolvido), o mesmo
limite estrutural do item anterior.

## 6. Ataques ao encoding, à combinação e ao CSPRNG

### 6.1 Encoding de A

Script: `redteam/phase_d/scripts/encoding_attack.py`. Reimplementação
independente (soma posicional explícita + largura via `log`, em vez do
Horner + `bit_length` de `dice.py`) comparada byte a byte contra o código
real para n∈{1,2,3,50,99,100,101,127,132,1000}, all-1, all-6,
alternância cíclica, e aleatório — **0 divergências**. Bijeção exaustiva
confirmada para n=1..5 (7776 sequências em n=5, 0 colisões). Ataques de
truncamento/overflow de valor/underflow de comprimento/endianness todos
corretamente rejeitados — **exceto** o achado #1 (seção 3), corrigido.

### 6.2 Combinação `E = SHA-256(A‖B)`

Verificado empiricamente contra `combine.combine` real: efeito avalanche
(~128/256 bits flipam para 1 bit de diferença em A ou em B, o esperado
para SHA-256), `SHA256(B‖A) ≠ SHA256(A‖B)` (a ordem importa), e rejeição
correta de B com 31 ou 33 bytes (sem "padding silencioso"). Nenhuma
divergência da especificação `docs/MATH.md` §5 encontrada — nenhuma
afirmação precisou ser enfraquecida.

### 6.3 CSPRNG (`osrng.py`)

7 cenários testados via monkeypatch de `os.getrandom`/`os.urandom`: erro
do kernel, comprimento errado, saída constante, ausência de
`os.getrandom` (fallback correto para `os.urandom`), falha de AMBAS as
fontes, e saída controlada-pelo-atacante-mas-não-constante. **Fail-closed
em todos os cenários de erro genuíno**; o último cenário (saída
atacante-controlada e plausível) é aceito, como já documentado — nenhuma
checagem de espaço de usuário pode detectar isso, e o projeto nunca
alegou o contrário.

## 7. Ataques de ambiente hostil, supply chain e build

### 7.1 (referência) Supply chain e mutation testing da Fase C

Não repetidos aqui — ver `docs/INDEPENDENT_VERIFIER.md` §6-7 para a
matriz de 6 cenários (A-F) e a primeira rodada de mutation testing do
verificador (9 mutantes, 9 mortos após 1 correção).

### 7.2 Ambiente Python hostil (expandido)

Script: `redteam/phase_d/scripts/hostile_python_env.py`. 8 vetores
(shadowing de `os.py`/`getpass.py`/`argparse.py`/`hashlib.py`, `.pth`
malicioso em user-site, `sitecustomize`+`usercustomize` em user-site,
`sitecustomize.py` no cwd, `PYTHONHOME` bogus, `PYTHONSTARTUP`) contra o
`.pyz` com `-I -B` e contra o source em modo dev:

**0/8 vetores afetam o `.pyz` com `-I -B`** (o modo de uso real
recomendado). **5/8 afetam o modo de desenvolvimento** (`-m entropyforge`
sem `-I`): shadowing de `getpass`/`argparse`/`hashlib` (mas não de
`os` — o bootstrap do interpretador já resolveu `os` antes do `sys.path`
de `-m` ser montado), `.pth` malicioso, e `sitecustomize`+`usercustomize`
via user-site. Isto quantifica, com uma varredura muito mais ampla do que
a Fase C original (que testou só `hashlib.py`), exatamente a mesma
recomendação já documentada: nunca use o modo de desenvolvimento para
gerar uma carteira real.

### 7.3 Build: reprodutibilidade multi-ambiente

Script: `redteam/phase_d/scripts/build_attack.py`. **16/16 variações
produziram hash idêntico ao baseline**: 3 timezones, 2 locales, 3
umasks, `PYTHONHASHSEED` fixo e variável, diretório de trabalho
diferente, saída em tmpfs (`/dev/shm`), e **4 versões de Python
(3.10, 3.11, 3.12, 3.13)**. Nenhuma variação testada quebra a
reprodutibilidade.

Achado complementar (não uma falha, uma confirmação de design): **a
reordenação das entradas dentro do arquivo `.pyz` (mesmo conteúdo, ordem
diferente) muda o hash SHA-256 bruto do arquivo inteiro**, mas
`pyz_inspect.compare_pyz_to_source` (que compara por nome, não por
posição) corretamente NÃO trata isso como adulteração — demonstra por
que a comparação de conteúdo é mais forte que uma checagem ingênua de
hash do arquivo todo (exatamente o que `build_pyz.py` já reconhecia ao
fixar a ordem das entradas para determinismo). Teste de regressão:
`independent-verifier/tests/test_pyz_inspect.py::CleanPyzTests::test_reordering_zip_entries_is_not_flagged_as_tamper`.

## 8. Auditoria do verificador (mutation testing, rodadas 1 e 2)

A **rodada 1** (Fase C/14, `redteam/independent/scripts/mutation_testing_verifier.py`)
já havia testado 9 mutantes contra hashing/wordlist_check/pyz_inspect/
bip39_min/static_scan/build_repro, com 1 sobrevivente corrigido.

A **rodada 2** desta fase
(`redteam/independent/scripts/mutation_testing_verifier_round2.py`) cobre
alvos NÃO tocados na rodada 1: `ManifestDiff.is_identical` forjado como
sempre-verdadeiro, `verify_against_manifest` comparando o manifesto
contra si mesmo, `WordlistReport.ok` forjado, `PyzSourceComparison.ok`
ignorando especificamente `content_mismatches` (mutante diferente do da
rodada 1, que ignorava `unexpected_in_pyz`), `static_scan.diff_findings`
sempre vazio, e `bip39_compare.ComparisonResult.ok` ignorando
`mismatches`.

**6/6 mutantes da rodada 2 mortos na primeira tentativa** — nenhuma
lacuna de cobertura nova encontrada nesta rodada (diferente da rodada 1,
que encontrou 1). Combinado: **15 mutantes testados no total contra o
verificador, 15 mortos** (1 sobrevivente inicial na rodada 1, corrigido e
reverificado).

## 9. Laboratório "correto mas malicioso" (16 backdoors)

`redteam/independent/labs/backdoors/backdoor_lab.py` agora tem **16**
variantes (10 da Fase C + 6 novas desta fase): stderr, `/tmp`, socket,
subprocess, DNS, pré-guard, condicional a argv, condicional à pilha de
chamadas, condicional a variável de ambiente, `atexit`, **socket
ofuscado (11)**, **stdout (12)**, **mensagem de exceção (13)**, **módulo
secundário pós-guard (14)**, **handler de sinal (15)**.

**16/16 deixam `selftest` reportar PASSOU** — confirma, mais uma vez, que
"selftest valida corretude, não proveniência" (`docs/AUDIT.md` §6),
agora sobre um conjunto de canais de exfiltração muito mais amplo que o
testado na Fase C.

Achados específicos das 6 variantes novas:

- **11 (socket ofuscado):** `static_scan.py` não marca a categoria
  "rede" (nomes construídos via `chr()`), mas ainda gera 13 achados na
  categoria "reflexão" — um revisor humano teria motivo para investigar.
  `guard.py` bloqueia a chamada real de qualquer forma, com a MESMA
  mensagem do backdoor 03 — ofuscação de código-fonte não ofusca o
  evento de auditoria do interpretador.
- **12 (stdout):** motivou a correção #2 (seção 3).
- **13 (exceção):** confirmado que uma exceção não capturada com o
  segredo na mensagem propaga até o handler padrão do Python e aparece
  no traceback em stderr — condicional a uma variável de ambiente,
  silencioso por padrão.
- **14 (módulo secundário pós-guard, em `report.py`):** confirmado que
  `guard.py` bloqueia a tentativa de rede partindo de QUALQUER módulo do
  pacote, não só `combine.py` — reforça o achado do Cenário F da matriz
  de supply chain (`docs/INDEPENDENT_VERIFIER.md` §6).
- **15 (handler de sinal):** um SIGTERM real enviado ao processo
  (simulando Ctrl-C) aciona um handler malicioso que vaza o segredo antes
  de o processo terminar — nem `guard.py` nem
  `tests/test_generate_interruption_safety.py` cobrem este mecanismo de
  gatilho especificamente.

Nenhum dos 16 backdoors é "corrigível" no sentido de uma mudança em
`entropyforge/` (exceto o 12, indiretamente, via a correção do teste) —
todos confirmam, com mecanismos de gatilho diferentes entre si, a mesma
conclusão estrutural: nenhum teste de comportamento de caixa-preta prova
ausência de um backdoor condicional ou de execução fora do fluxo
principal.

## 10. Observação externa: legítimo vs. backdoor

Ver `redteam/independent/findings/legit_vs_backdoor_strace_comparison.txt`.
Achado central: backdoors BLOQUEADOS pelo guard são **indistinguíveis do
código legítimo no nível de syscall** — não porque a observação falhou,
mas porque `sys.addaudithook` intercepta em Python, ANTES de a syscall
real ser emitida ao kernel. O único backdoor que produz uma diferença
observável (06, pré-guard) é corretamente capturado
(`wrote_to_disk=True`). Um controle final (script sem nenhum guard,
socket AF_INET real) confirma que a capacidade de detecção positiva da
ferramenta funciona quando uma tentativa de rede realmente chega ao
kernel. Este processo revelou e corrigiu o achado #4 (seção 3).

## 11. Cerimônia de geração e automação de pré-condições

`docs/GENERATION_CEREMONY.md` (15 passos, do boot ao desligamento) e
`docs/RELEASE_SECURITY_CHECKLIST.md` (checklist rápido, nunca exibe
segredos) foram escritos nesta fase.

**Decisão de engenharia sobre "safe-generate":** não foi adicionado um
subcomando `safe-generate` dentro do `entropyforge` — `generate` já
automatiza toda pré-condição INTERNA que tal comando ofereceria (recusa
de rede, `selftest`, validação de wordlist por hash, CSPRNG fail-closed,
validação estatística do dado com confirmação exigida, zero logs/
clipboard/arquivos). O que faltava automatizar são as checagens
EXTERNAS (comparar o `.pyz` contra o source, validar a wordlist contra um
hash independente) — e essas, por design, não podem ser feitas pelo
próprio artefato se autoverificando. Em vez disso, foi criado
`tools/preflight_and_generate.py`: um orquestrador que roda o
`independent-verifier` como processo/import EXTERNO (nunca acoplado ao
`entropyforge`) e só invoca `generate` se a wordlist, a comparação
`.pyz`-vs-source, e o `selftest` passarem — fail-closed, sem bypass
silencioso. Testado em `tests/test_preflight_and_generate.py` (7 testes,
incluindo confirmação de que aborta corretamente contra um `.pyz` com
módulo extra, um `.pyz` com conteúdo adulterado, um `.pyz` inexistente, e
uma wordlist de referência adulterada).

## 12. Root of trust (revisado, sem mudanças)

A tabela de 11 elos de `docs/INDEPENDENT_VERIFIER.md` §9 foi revisada
componente a componente contra todos os achados desta fase — nenhuma
mudança foi necessária. Os 5 elos já marcados como hipóteses
irredutíveis (firmware/BIOS/UEFI, hardware, CSPRNG do SO, dado físico +
operador, ambiente de execução mais amplo) continuam sendo exatamente
isso; nenhum achado desta fase reduziu ou expandiu esse conjunto.
`independent-verifier/verifier/trust_chain.py` (10 testes) confirma a
consistência estrutural da tabela.

## 13. Resultados estatísticos e criptográficos

Ver seções 4 e 5 acima para o resumo; dados brutos em
`redteam/phase_d/findings/`.

## 14. Estado final da documentação

Corrigido nesta fase:

- `docs/AUDIT.md`: contagem de testes (172→191, mais 112 do
  independent-verifier), hashes de `cli.py`/`__main__.py`/`dice.py`
  (estavam desatualizados de correções anteriores e da correção #1 desta
  fase), 2 novos invariantes (16, 17) na tabela de rastreabilidade.
- `docs/DESIGN.md`: contagem de linhas (2.403→2.449).
- `README.md`: tabela de documentação atualizada com os 6 documentos
  criados desde a versão original (`GENERATION_CEREMONY.md`,
  `RELEASE_SECURITY_CHECKLIST.md`, `REDTEAM.md`,
  `INDEPENDENT_VERIFIER.md`, e este documento).

Nenhuma contradição remanescente encontrada entre README/DESIGN/MATH/
AUDIT/THREAT_MODEL/OPERATIONS/REDTEAM/INDEPENDENT_VERIFIER após esta
revisão.

## 15. Release gate

Nenhuma das condições de bloqueio da auditoria está presente:

- ❌ teste crítico falhando — **não há**: 303/303 testes passam.
- ❌ divergência BIP-39 — **não há**: confirmado contra vetores oficiais,
  implementação de referência, e implementação independente.
- ❌ encoding ambíguo — **não há**: bijeção confirmada exaustivamente
  (n≤5) e por reimplementação independente (n até 1000).
- ❌ fallback inseguro — **não há**: CSPRNG e wordlist falham fechado em
  todo cenário testado.
- ❌ vazamento conhecido não corrigido — **não há**: o único vazamento
  encontrado (achado #2) foi corrigido e o teste que deveria detectá-lo
  agora o faz.
- ❌ mutante crítico sobrevivente — **não há**: 15/15 mutantes do
  verificador mortos (1 sobrevivente inicial, corrigido).
- ❌ build inconsistente — **não há**: 16/16 variações de ambiente
  reproduzem o mesmo hash.
- ❌ verifier incapaz de detectar alteração básica — **não há**: todos os
  cenários de adulteração testados (A-F da matriz de supply chain, mais
  os desta fase) são detectados por pelo menos um controle.
- ❌ contradição matemática — **não há**: toda afirmação numérica de
  `docs/MATH.md` foi re-derivada independentemente e bateu exatamente.
- ❌ documentação afirmando mais segurança do que a evidência suporta —
  **não há**: a documentação já usa rótulos FATO/HEURÍSTICA/PREMISSA/
  OPINIÃO de forma precisa, e esta revisão não encontrou nenhuma
  afirmação que precisasse ser enfraquecida.

**O projeto é candidato a release** sob o modelo de ameaça documentado
(`docs/THREAT_MODEL.md`), com as premissas irredutíveis de
`docs/INDEPENDENT_VERIFIER.md` §9 permanecendo exatamente onde estavam:
impossíveis de eliminar por qualquer quantidade de software.

## 16. Hashes finais e instruções de auditoria independente

```sh
# suite completa
python3 -B -m unittest discover -s tests -v                                    # 191 testes
cd independent-verifier && python3 -B -m unittest discover -s tests -v         # 112 testes

# build limpo + reprodutibilidade
make build && make repro

# ataques desta fase (todos re-executaveis, nenhum usa dados reais)
python3 -B redteam/phase_d/scripts/independent_math.py
python3 -B redteam/phase_d/scripts/dice_models.py
python3 -B redteam/phase_d/scripts/min_entropy_search.py
python3 -B redteam/phase_d/scripts/independence_attack.py
python3 -B redteam/phase_d/scripts/encoding_attack.py
python3 -B redteam/phase_d/scripts/hostile_python_env.py
python3 -B redteam/phase_d/scripts/build_attack.py
python3 -B redteam/independent/scripts/mutation_testing_verifier_round2.py

# cerimonia automatizada (checagens externas + generate)
python3 tools/preflight_and_generate.py --pyz entropyforge.pyz -- generate
```

Hashes de referência para este commit (recalcule os seus — o valor do
`.pyz` muda a cada alteração de source, por design):

```
sha256(entropyforge/data/english.txt) = 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
sha256(entropyforge.pyz, construido agora)                = 7d61008a5a2c0209c0b4d9b24039e527f4751c972fc1771e6509aea96c942793
sha256(entropyforge/dice.py, apos a correcao do achado #1) = 64434186558e57261d45a1e6ce0e25a6afc3af6d1c55b646b123aefcca799009
```

## 17. Adendo (Fase E) — bug crítico: `generate` inutilizável em qualquer terminal real

**Este é o achado mais grave de todo o projeto até agora**, e ilustra
exatamente por que a Fase E exigiu um teste de interrupção via
subprocesso e terminal (`pty`) REAIS, em vez de confiar apenas na
abstração `TerminalIO` falsa usada por toda a suíte de testes anterior.

**O bug:** `entropyforge/guard.py::_audit_hook` bloqueia qualquer
`open()`/`os.open()` cujos `flags` incluam `O_RDWR` (entre outras), como
parte do requisito 14 ("este programa nunca escreve em disco").
`getpass.getpass()` — usado pela leitura oculta de dígitos do dado e do
mnemonic de conferência — abre `/dev/tty` com exatamente
`os.O_RDWR | os.O_NOCTTY` (`Lib/getpass.py` da biblioteca padrão), e em
seguida envolve o descritor resultante num `io.FileIO(fd, "w+")` (um
SEGUNDO evento de auditoria "open", desta vez com um inteiro em vez de um
caminho). O audit hook tratava ambos exatamente como uma tentativa de
escrever um arquivo em disco e os bloqueava — o que significa que
**`entropyforge generate`, na sua configuração padrão, nunca conseguia
sequer pedir os lançamentos do dado em nenhum terminal real**: a primeira
chamada a `read_hidden_line` levantava `guard.GuardViolation` e o
processo abortava com um traceback.

**Por que nenhum teste anterior pegou isso:** todo teste de `generate`
(inclusive os de vazamento de segredo, os de interrupção em processo, e
os de fuzzing via subprocesso real do Phase D) construía uma `TerminalIO`
com `read_hidden_line` SUBSTITUÍDO por uma função falsa (uma lambda que
devolve uma string fixa) — nenhum deles jamais exercitava
`getpass.getpass()` de verdade com o audit hook ativo. O teste de
subprocesso real mais próximo (`redteam/scripts/cli_fuzz.py`, Fase D)
mandava SIGINT com stdin/stdout como PIPES comuns, não um `pty` — nesse
caso `generate` já recusava antes por falta de TTY (`io.stdin_isatty()`
falso), então o caminho de `getpass.getpass()` nunca era alcançado
também ali.

**Como foi encontrado:** `tests/test_generate_interruption_real_subprocess.py`
(Fase E, requisito de teste de interrupção externo) usa `pty.fork()` para
dar ao processo filho um terminal controlador de verdade — o mínimo
necessário para que `getpass.getpass()` sequer tente abrir `/dev/tty`. O
primeiro teste dessa suíte falhou imediatamente, com exatamente esse
`GuardViolation` capturado no traceback do processo filho.

**A correção** (`entropyforge/guard.py`): duas exceções estritas e
específicas no `_audit_hook`, nenhuma delas afrouxando a proteção contra
escrita em arquivos REGULARES:

1. `open`/`os.open` para o caminho literal `/dev/tty` é sempre permitido,
   independente de `mode`/`flags` — este caminho é o terminal controlador
   do próprio processo, nunca armazenamento persistente.
2. Um evento `open` cujo primeiro argumento é um **inteiro** (um
   descritor de arquivo já existente sendo envolvido por `io.FileIO`,
   não um caminho novo sendo criado) é sempre permitido — a única forma
   de obter um descritor gravável para um arquivo regular continua sendo
   um `open()`/`os.open()` por CAMINHO, que continua totalmente auditado
   e bloqueado (exceto `/dev/tty`, acima).

**Testes de regressão:** `tests/test_guard.py::AuditHookAllowsDevTtyTests`
(4 testes: `/dev/tty` permitido, wrap de fd existente permitido, qualquer
OUTRO caminho com O_RDWR continua bloqueado, e a `TerminalIO` padrão real
não levanta mais `GuardViolation`) e
`tests/test_generate_interruption_real_subprocess.py::RealTerminalHappyPathTests`
(fluxo `generate` completo, de ponta a ponta, num `pty` real — a
confirmação positiva de que o caminho que os testes de interrupção
exercitam também tem sucesso quando não interrompido).

**Lição estrutural:** uma suíte de testes inteiramente baseada numa
abstração (`TerminalIO`) que substitui a peça exata (`getpass.getpass`)
onde o bug vivia pode ficar verde para sempre sem nunca detectar um bug
que torna o programa inteiro inutilizável na prática. Isto reforça a
mesma lição já registrada no achado #2 da seção 3 (stdout/stderr reais) e
na diretriz geral desta fase: **"não aceite 'passou anteriormente', rode
de novo"** — neste caso, rode com um terminal de verdade.
