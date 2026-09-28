# EntropyForge-BIP39 — release candidate (Fase F)

Este documento é o resumo executivo de uma release, com só fatos
verificáveis: nenhuma alegação de segurança absoluta aparece aqui (nem em
nenhum outro lugar deste projeto — ver `docs/THREAT_MODEL.md`). Ele não
substitui a leitura de `docs/PHASE_E_TEST_MATRIX.md` (a matriz completa da
Fase E), `docs/EXECUTABLE_RELEASE_CHECKS.md` (as evidências completas da
Fase F) e `docs/VERIFY.md`/`docs/QUICK_START.md` (como reproduzir a
verificação e a cerimônia você mesmo).

## Identificação

- **Commit desta revisão:** `423eb2714209cd587cfff2554a5ee192f74592a7`
  (branch `claude/jolly-ptolemy-2bmru7`). Este arquivo foi escrito com
  base no estado do repositório nesse commit; o commit que efetivamente
  contém este arquivo é necessariamente um commit posterior a esse (não
  há como um commit referenciar o próprio hash antes de existir) — rode
  `git log -1 --format=%H` no seu checkout para o hash exato do que você
  está de fato auditando, e `git log --oneline 423eb27..HEAD` para ver
  exatamente o que mudou depois desta revisão.
- **Versões formais** (`entropyforge/version.py`, `--version`):
  - software: `1.0.0`
  - protocolo do formato A (`dice.py`): `1`
  - procedimento de geração: `2`
  - wordlist: `bip39-english-2013`
  - formato do manifesto de release: `2` (subiu de `1` para `2` nesta
    fase: quatro campos novos — `executable_sha256`,
    `executable_platform`, `executable_arch`, `executable_build_tool` —
    ver `entropyforge/version.py` e
    `independent-verifier/verifier/release_manifest.py`)

## Release publicada no GitHub (v1.0.0, Fase G)

**Isto substitui, para uso prático, a seção "Plataformas" abaixo (escrita
na Fase F, antes de haver uma máquina Windows real disponível para
build):** a release `v1.0.0` está publicada em
**https://github.com/DenniBR/EntropyForge-BIP39/releases/tag/v1.0.0**,
com artefatos prontos para download — não só código-fonte. Produzida
pelo workflow `.github/workflows/release.yml` (`workflow_dispatch`),
que roda o build do Linux num runner `ubuntu-latest` real e o build do
**Windows num runner `windows-latest` real** do próprio GitHub Actions
(nunca uma emulação, cross-compilação, ou arquivo renomeado) — ver
`docs/EXECUTABLE_BUILD.md` para o raciocínio técnico da build
multiplataforma. A execução mais recente que publicou os assets abaixo:
run `#5`, id `36371737591`
(https://github.com/DenniBR/EntropyForge-BIP39/actions/runs/36371737591),
commit `f929c5eef8d534be9c72463c9f60030f473b40f2` — todos os 4 jobs
(`test`, `build-linux`, `build-windows`, `publish`) com `conclusion:
success`, incluindo a checagem FORTE `verify-executable` (reconstrução a
partir do source) passando genuinamente nos dois jobs de build nesta
execução (não mascarada por `continue-on-error` — ver nota abaixo sobre
por que esse passo específico não é o gate bloqueante da CI).

### Assets publicados (nome exato · SHA-256)

```
entropyforge-bip39-v1.0.0-linux-x86_64.tar.gz    bdeb8cfc78c632449d91b97f4cc55d1ffae156b830fbefea7b8348d2dbe1e9cc
entropyforge-bip39-v1.0.0-windows-x86_64.zip     6ec0ff11be48e5ec2a32a4dd5cc371c447e15b4a10d0b8c49610426ebfbe3fb6
entropyforge.pyz                                 a09b5662f1d16f4b92d5e07b84e8e90343b0f027cfb94b500a1e2bdf9876aa0d
MANIFEST-linux-x86_64.txt                        8d41cf96208d197adcabd78e12b133e1deb60eccd0fbad8ff9c1a716461dca23
MANIFEST-windows-x86_64.txt                      ec26a3af83d51b72a220ccb1d3377144a9dbe015917a5ae44959c1d31942189d
independent-verifier-bundle.zip                  5ce10e5e4ef454656e810b3c8eff069fbcdc61fd7e8c858e0dce9c216f2e6941
SHA256SUMS.txt                                   58b0344b40d9ce3bd352664d116a45eb4c346b1e130c7fca1635f4870490e89f
```

Cada um dos seis arquivos de conteúdo acima também tem um `<nome>.sha256`
individual publicado ao lado (11 assets no total, mais o
`SHA256SUMS.txt` combinado = 13 assets — confira a lista completa e os
hashes você mesmo na página da release, nunca só neste documento). Todos
os hashes acima são os que `tools/ci_publish_release.py` imprimiu ao
final da run `#5` e foram reconferidos, nesta revisão, baixando os
arquivos de verdade da própria URL pública da release (não só arquivos
locais de build) — ver `docs/VERIFY.md` seção 6 para os comandos exatos.

### O que cada verificação realmente mostrou (assets baixados da Release, run #5)

- `sha256sum -c SHA256SUMS.txt` e cada `.sha256` individual: **OK** para
  os 6 arquivos de conteúdo.
- Binário Linux extraído do `.tar.gz` baixado: `--version`, `selftest`
  (`RESULTADO GERAL: PASSOU`) e `vector` com o vetor de teste público
  (`--a-digits 111111111111111111111111 --b-hex 000...0`) produziram a
  mesma mnemonic de sempre nesta série de builds — execução real do
  binário publicado, não de uma cópia local.
- `independent-verifier/verify_release.py` contra o `MANIFEST-linux-x86_64.txt`
  e o `entropyforge.pyz` baixados: **PASS** em todos os 14 campos do
  manifesto + wordlist + `.pyz` vs. source + vetores BIP-39 oficiais.
- `independent-verifier/verify_release.py` contra o
  `MANIFEST-windows-x86_64.txt` baixado e o diretório do `.exe` extraído
  do `.zip` baixado, **rodado a partir desta máquina Linux**: **PASS** —
  incluindo `executable_platform`/`executable_arch`, que agora são
  conferidos lendo o cabeçalho PE dos próprios bytes do `.exe` (`MZ` +
  assinatura `PE\0\0` + `Machine=0x8664`/AMD64), não perguntando ao SO de
  quem verifica (ver "Bug corrigido nesta revisão" abaixo — antes desta
  correção, verificar um asset Windows a partir de Linux falhava sempre,
  por desenho, mesmo com o artefato íntegro).
- `independent-verifier/verify_executable.py` (checagem FORTE,
  reconstrução do zero) contra o Linux baixado, rodado NESTA máquina
  (diferente da máquina `ubuntu-latest` que fez o build original):
  `hash_vs_manifesto`/`version`/`selftest` **PASS**;
  `reconstrucao_a_partir_do_source` **FAIL** — a mesma
  não-determinística dependente de `--output-dir` já documentada em
  `docs/EXECUTABLE_BUILD.md` seção 4 (reconstruir num diretório diferente
  do build original produz um hash de diretório diferente numa unidade de
  compilação do Nuitka). **Isto não é uma falha de integridade do
  artefato** — os três primeiros checks da mesma chamada, que SÃO checks
  de integridade, passaram; é uma limitação conhecida e documentada da
  reprodutibilidade bit-a-bit do Nuitka entre diretórios de build
  diferentes, não uma evidência de adulteração.
- Windows `.exe` extraído do `.zip` baixado: SHA-256 confere com
  `MANIFEST-windows-x86_64.txt`; PE32+/`AMD64` genuíno (cabeçalho `MZ`/`PE\0\0`
  conferido byte a byte); importa somente `python311.dll`, `KERNEL32.dll`,
  `VCRUNTIME140.dll` e os forwarders padrão do Universal CRT
  (`api-ms-win-crt-*.dll`) — nenhuma DLL de rede (`ws2_32`, `wininet`,
  `winhttp`); layout de seções padrão de um build Nuitka não empacotado
  (sem seções de packer tipo UPX); varredura de strings em TODOS os
  arquivos do pacote (`.exe` + `.dll` + `.pyd`) por assinaturas de
  mineração (`XMRig`, `CryptoNote`, `Monero`, `Stratum`, `mining pool`,
  `RandomX`, `NiceHash`, `CoinHive`, `hashrate`, `xmr-stak`, `cpuminer`):
  **zero ocorrências reais** — a única string "STRATUM" encontrada está
  em `unicodedata.pyd` (runtime padrão do CPython) e é um fragmento
  alfabético da tabela de nomes de caracteres Unicode
  (`STREAMER`/`STRAWBERRY`/`STRAW`/`STRATUM-2`/`STRATUM`/`STRATU`/`STRATIA`
  aparecem em sequência alfabética), não uma referência ao protocolo
  Stratum de mineração. **Limitação declarada:** o `.exe` não pôde ser
  EXECUTADO nesta sessão (ambiente Linux, sem Wine) — só inspecionado
  estaticamente; e não há acesso a uma API do VirusTotal configurada
  neste ambiente para rodar uma varredura multi-engine real contra o hash
  exato acima.
- Suítes locais completas re-executadas após todas as mudanças desta
  revisão: `tests/` — 257 testes, `OK`; `independent-verifier/tests/` —
  129 testes, `OK`.

### Bug corrigido nesta revisão (verificação cross-plataforma)

`verify_release()` comparava `executable_platform`/`executable_arch` do
manifesto contra `platform.system()`/`platform.machine()` da **máquina
que está verificando**, não do artefato — o que só podia bater quando
build e verificação rodam no mesmo SO, tornando impossível verificar
honestamente um `.exe` do Windows a partir de Linux (ou vice-versa),
mesmo com o artefato perfeitamente íntegro (o `executable_sha256`, que já
é uma função pura dos bytes do arquivo, sempre bateu). Corrigido lendo o
cabeçalho ELF/PE dos próprios bytes do executável
(`_detect_executable_platform_arch` em
`independent-verifier/verifier/release_manifest.py`), o que funciona
corretamente em qualquer máquina verificadora. `executable_build_tool`
(que não tem como ser extraído do binário já compilado) passou a ser
puramente informativo — mostrado no relatório, mas nunca reprova o
resultado geral. Isto corrige um defeito de desenho, não afrouxa nenhuma
checagem de segurança/integridade — a versão corrigida do verificador foi
reconstruída e republicada dentro desta mesma release (`v1.0.0`, run #5),
então `independent-verifier-bundle.zip` já contém a correção.

## O que mudou nesta fase (Fase F)

A Fase E entregou um artefato distribuível (`entropyforge.pyz`) que exige
Python ≥ 3.11 já instalado. A Fase F entrega um **segundo artefato**: um
**executável standalone** (Nuitka `--standalone`, Linux x86_64) que roda
sem Python instalado na máquina de destino. Nenhuma linha de
`entropyforge/` foi alterada para isto — o executável embrulha
exatamente o mesmo código-fonte já revisado nas fases anteriores. Ver
`docs/EXECUTABLE_BUILD.md` para a justificativa técnica completa da
escolha de ferramenta (com evidência de `strace`, não preferência) e
`docs/EXECUTABLE_RELEASE_CHECKS.md` para todas as evidências empíricas
resumidas abaixo.

## Método e ambiente de build (ambos os artefatos)

| | `.pyz` | Executável |
|---|---|---|
| Ferramenta | `zipapp` (`tools/build_pyz.py`) | Nuitka `--standalone` (`tools/build_executable.py`) |
| O que roda no final | bytecode Python interpretado | binário nativo compilado (Python → C → máquina, via `gcc` local) |
| Precisa de Python instalado para RODAR | Sim (≥ 3.11) | Não |
| Auditável byte a byte contra o source | Sim (`pyz_inspect.compare_pyz_to_source`) | Não — só reconstruindo e comparando hash (`verify_executable.py`) |

**Ambiente de build usado para as evidências deste documento:** Python
`3.11.15`, `gcc 13` (Ubuntu 24.04), Nuitka `4.2.2`, arquitetura
`x86_64`, Linux. Estes valores são gravados automaticamente em
`MANIFEST.txt` (campo `executable_build_tool`) a cada build — nunca
hardcoded, sempre lidos do ambiente real (`build_tool_identifier()` em
`release_manifest.py`).

## Plataformas

- **Linux x86_64**: **produzido e testado** para os dois artefatos
  (`.pyz` e executável).
- **Windows x86_64 (executável)**: **histórico da Fase F, já superado —
  ver a seção "Release publicada no GitHub" acima.** Na Fase F, nenhuma
  máquina Windows estava disponível neste ambiente de desenvolvimento
  (nem PyInstaller nem Nuitka fazem cross-compilação de Linux para
  Windows, e alternativas via Wine foram avaliadas e rejeitadas por não
  atenderem à barra de "tecnicamente segura e reprodutível"). Isso foi
  resolvido na Fase G usando um runner `windows-latest` REAL do próprio
  GitHub Actions (`.github/workflows/release.yml`, job `build-windows`) —
  o `.exe` publicado em `v1.0.0` é um build Windows genuíno, construído e
  testado (smoke test, `selftest`, `verify-release`, `verify-executable`)
  numa máquina Windows de verdade, nunca um placeholder ou arquivo
  renomeado.
- **Windows XP**: explicitamente **NÃO SUPORTADA**, para ambos os
  artefatos — nenhuma versão do CPython exigida por este projeto (≥
  3.11) roda nela.
- **Tails / Debian live**: suporte idêntico ao Linux genérico (nenhum
  código específico para eles) — ver `docs/PLATFORM_SUPPORT.md` §2.

## Hashes de referência

Recalcule os seus — nunca confie nos valores abaixo sozinhos (ver
`docs/VERIFY.md`). Os valores abaixo foram observados e reproduzidos
neste commit, a partir de **quatro builds independentes de cada
artefato** (diretórios/`umask`/`TZ`/`PYTHONHASHSEED` diferentes, todos a
partir de extrações `git archive` separadas — nunca do diretório de
desenvolvimento):

```
sha256(entropyforge/data/english.txt)                    = 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
sha256(entropyforge.pyz)                                  = a09b5662f1d16f4b92d5e07b84e8e90343b0f027cfb94b500a1e2bdf9876aa0d
sha256(entropyforge-bip39, binário principal, Linux x86_64) = e42fb9168acb8fc760b25303bab79766a0c841013df3726f2dac60aaa987c1eb
```

O `MANIFEST.txt` completo (incluindo `executable_sha256`, que cobre TODO
o diretório do executável — não só o binário principal — e
`source_manifest_sha256`) varia a cada build por design (é o que faz
`verify-release`/`verify-executable` úteis); gere o seu com
`make release` e confirme com `make verify-release` e
`make verify-executable` (ambos devem imprimir `PASS`).

## Contagem de testes (neste commit)

- `tests/` (EntropyForge): **257 testes**, todos passando
  (`python3 -B -m unittest discover -s tests`) — 231 da Fase E + 22
  testes do executável (`test_executable_build.py`,
  `test_executable_e2e.py`) + 3 de interoperabilidade via executável
  (`test_executable_dev_cross_check_bip32.py`, pulados automaticamente
  se `mnemonic`/`bip32utils` — dev-only — não estiverem instalados) + 1
  novo caso de erro em `test_assemble_release.py`.
- `independent-verifier/tests/`: **129 testes**, todos passando.
- Fuzzing final da Fase E (`redteam/phase_e/scripts/fuzz_final.py`, seed
  `20260927`, reproduzível): **RE-EXECUTADO nesta fase, do zero, a
  partir de um checkout limpo** — 63.060 iterações, 0 problemas reais
  (49 colisões de checksum BIP-39 esperadas pela matemática do próprio
  formato, confirmadas como não-bugs).
- Fuzzing do executável, novo nesta fase
  (`redteam/independent/scripts/fuzz_and_observe_executable.py`, mesma
  seed `20260927`): 300 iterações de argumentos adversariais para
  `vector` + 100 de bytes aleatórios brutos via stdin contra o
  **binário compilado real** — 400 iterações, 0 problemas.
- Revisão estática final (`docs/STATIC_SCAN_FINAL.md`): 85 ocorrências em
  `entropyforge/`, todas explicadas individualmente como falso positivo
  (inalterado — o source não mudou nesta fase).

## Reprodutibilidade

`make repro` (`.pyz`) e `make repro-exe` (executável) confirmam que
builds independentes do mesmo commit produzem o **mesmo SHA-256** —
**verificado nesta revisão a partir de um checkout inteiramente limpo**
(`git archive HEAD` para um diretório novo, sem qualquer estado residual
do diretório de desenvolvimento). Para o executável especificamente,
foram feitos 4 builds variando diretório/`umask`/`TZ`/`PYTHONHASHSEED`,
com uma comparação hash-por-arquivo (não só o binário principal) entre
dois deles — todos idênticos (ver `docs/EXECUTABLE_RELEASE_CHECKS.md`
seção 2 para a tabela completa).

**Limitação declarada, sem disfarce:** só havia uma versão de
Python/gcc/Nuitka disponível neste ambiente de build.
**Reprodutibilidade ENTRE versões diferentes da cadeia de ferramentas do
executável NÃO foi testada** — isto é uma lacuna real, documentada, não
uma alegação escondida. O `.pyz`, por depender só do bytecode do CPython
(não de um compilador C), é estruturalmente menos sensível a essa
variação.

## Teste de máquina limpa (Fase F)

Nesta revisão: extrair o commit acima com `git archive` para um diretório
totalmente novo e, a partir dele (sem qualquer `__pycache__`, artefato de
build, ou estado deixado por uma sessão de desenvolvimento anterior):

1. `python3 -B -m unittest discover -s tests` → 257 testes, `OK`.
2. `independent-verifier`: `python3 -B -m unittest discover -s tests` →
   129 testes, `OK`.
3. `make build` → `entropyforge.pyz`, hash idêntico ao já observado no
   diretório de desenvolvimento.
4. `make repro` → `REPRODUTIVEL: hashes identicos`.
5. `make executable` → executável construído, hash do binário principal
   **idêntico** ao já observado no diretório de desenvolvimento —
   confirma que o build do executável também **não depende de nada do
   diretório de desenvolvimento**.
6. `make repro-exe` → `REPRODUTIVEL: todos os hashes identicos`.
7. `make release` → `release/` montado (com o `.pyz`, o executável, o
   `MANIFEST.txt`, e uma cópia de `independent-verifier/`).
8. `make verify-release` → `PASS`.
9. `make verify-executable` → `PASS` (checagem FORTE: reconstrói o
   executável a partir do source e compara — bateu exatamente).
10. `redteam/phase_e/scripts/fuzz_final.py` (seed fixa) → 63.060
    iterações, 0 problemas.
11. O executável recém-construído respondeu corretamente a `--version` e
    `selftest` (`RESULTADO GERAL: PASSOU`).

Todos os passos passaram exatamente como no checkout de desenvolvimento.
Isto confirma que nenhum teste, build, ou verificação depende de estado
não-versionado — para os dois artefatos, não só o `.pyz` como na Fase E.

## Interoperabilidade e teste de backdoor no pipeline de build (Fase F)

**Interoperabilidade através do executável, não só do source:**
`tests/test_executable_dev_cross_check_bip32.py` lê a mnemonic do
**stdout real do binário compilado** (`vector`, dados públicos de teste)
e a leva até um endereço Bitcoin BIP-44 via `mnemonic` (Trezor) +
`bip32utils`, mais uma reimplementação crua da derivação BIP-32
(`hmac`/`hashlib`) — as três checagens bateram.

**Teste de backdoor contra o pipeline de build do executável**
(`redteam/independent/scripts/run_executable_backdoor_lab.py`): três
executáveis reais foram construídos a partir de três cópias de source —
limpa, com uma alteração puramente cosmética (um literal de string novo,
sem efeito funcional), e com um backdoor experimental (exfiltração da
entropia combinada via `stderr`) que passa em todos os KATs. Achado
central, com hashes reais (`docs/EXECUTABLE_RELEASE_CHECKS.md` seção 4):
a auto-verificação (manifesto gerado a partir da MESMA cópia usada para
construir) sempre "passa", inclusive para o backdoor — comportamento
correto, não uma falha, e exatamente por isso a verificação real precisa
vir de um `--entropyforge-root` obtido por canal independente.
`independent-verifier/verify_executable.py`, reconstruindo a partir da
cópia REAL e revisada do repositório, detecta tanto o backdoor quanto a
alteração cosmética (`FAIL` em `executavel.reconstrucao_a_partir_do_source`),
com zero falsos positivos no cenário legítimo.

**Observação de processo** (`strace -f`, limpo vs. backdoor): sintaxe de
rede/processo/disco idêntica entre os dois (o backdoor escreve num
descritor já aberto, nunca uma nova syscall) — achado esperado, já
documentado para o source na Fase D. A distinção real está no
stdout/stderr reais capturados do processo, não no log do `strace`
(`docs/EXECUTABLE_RELEASE_CHECKS.md` seção 7).

## Cerimônia fictícia de ponta a ponta, cross-checada externamente (Fase E, reconfirmada)

Reproduzida nesta revisão, com dados inteiramente fictícios (nunca uma
entropia real, nunca para fundos reais):

1. `entropyforge.pyz vector --a-digits ... --b-hex ...` com um `A` e um
   `B` públicos e fixos produziu um mnemonic de 24 palavras.
2. Esse mnemonic foi recalculado **do zero**, com uma reimplementação
   independente do encoding de `A`, da combinação `SHA-256(A‖B)` (só
   `hashlib` da biblioteca padrão) e do BIP-39
   (`independent-verifier/verifier/bip39_min.py`) — **bateu
   exatamente** com a saída do `entropyforge.pyz`.
3. Esse mesmo mnemonic foi levado até um endereço Bitcoin BIP-44
   (`m/44'/0'/0'/0/0`) via `bip32utils` (implementação externa),
   fechando o ciclo completo "dado → mnemonic → carteira" com dados
   públicos e reproduzíveis.
4. O fluxo interativo real (`generate`, com um terminal `pty` de
   verdade, dígitos de dado reais via `os.getrandom`, sinais reais do
   kernel) foi confirmado de ponta a ponta e sob interrupção.

Nenhum destes passos gerou, ou deveria ser tratado como, uma carteira com
fundos reais.

## Auditoria de segredos no executável (Fase F)

`docs/EXECUTABLE_SECRET_AUDIT.md`: inventário completo de arquivos do
executável construído, grep por padrões de credencial, busca pelos
valores fictícios conhecidos do próprio projeto, busca por caminhos
absolutos da máquina de build nas strings do binário, verificação do
hash da wordlist embutida — todos limpos.

## O que foi encontrado e corrigido nesta fase

Nenhum bug de correção foi encontrado em `entropyforge/` durante a Fase
F (nenhuma linha do pacote foi alterada). Dois problemas de
**infraestrutura de release** foram encontrados e corrigidos:

1. `make release`/`make verify-release` ficaram quebrados assim que
   `build_release_manifest.py` passou a exigir o diretório do
   executável — o `Makefile` não havia sido atualizado para depender de
   `make executable` primeiro. Corrigido (`Makefile`: `release: build
   executable`; `verify-release` agora passa `--executable-dist`).
2. `tools/assemble_release.py` não incluía o executável, o
   `RELEASE-CANDIDATE.md`, nem uma cópia do verificador no pacote
   `release/` — corrigido, com testes de regressão em
   `tests/test_assemble_release.py`.

Para o bug crítico da Fase E (`guard.py` bloqueando `getpass.getpass()`),
ver `docs/FINAL_SECURITY_REVIEW.md` seção 17 (inalterado nesta fase).

## Limitações (sem promessas absolutas)

- Zeração de memória é melhor esforço, nunca garantida (linguagem
  gerenciada) — ver `docs/GENERATION_CEREMONY.md`.
- A checagem automática de rede offline só existe em Linux — ver
  `docs/PLATFORM_SUPPORT.md`.
- A tela do operador é uma raiz de confiança residual que nenhum software
  deste projeto protege — ver `docs/GENERATION_CEREMONY.md`.
- Firmware, hardware, o CSPRNG do sistema operacional (no sentido
  criptográfico), o dado físico e o operador continuam sendo hipóteses
  não-elimináveis por qualquer verificação de software — ver
  `docs/INDEPENDENT_VERIFIER.md` §9.
- **Novo nesta fase:** o executável não tem correspondência byte a byte
  com o source (ao contrário do `.pyz`) — a única verificação forte é
  reconstruí-lo e comparar hashes (`verify_executable.py`), o que exige
  `nuitka`+`gcc` no ambiente de verificação. Reprodutibilidade do
  executável entre versões diferentes de Python/gcc/Nuitka não foi
  testada (só uma cadeia de ferramentas estava disponível nesta fase).
  Nenhum dos dois artefatos é assinado digitalmente (avaliado, documentado
  como etapa externa/manual — ver `docs/EXECUTABLE_RELEASE_CHECKS.md`
  seção 6).
- **Fase G (release publicada, ver seção acima):** um executável Windows
  x86_64 real FOI produzido, num runner `windows-latest` do GitHub
  Actions. A checagem FORTE de reconstrução (`verify_executable.py`)
  passou genuinamente na própria CI que fez o build, mas é conhecida por
  divergir quando reconstruída num diretório diferente do build original
  (não-determinismo do Nuitka dependente de `--output-dir`, evidenciado
  com o log do `clcache` — ver `docs/EXECUTABLE_BUILD.md` seção 4); por
  isso esse passo específico roda com `continue-on-error: true` na CI
  (nunca escondido — o resultado aparece normalmente no log) e o gate
  real da CI é `verify-release` (hash do diretório já construído contra o
  manifesto, sem reconstruir). O Windows `.exe` publicado foi
  inspecionado estaticamente (PE/imports/seções/strings) mas não pôde ser
  executado nesta sessão (sem ambiente Windows/Wine), e não há acesso a
  uma API do VirusTotal configurada neste ambiente para uma varredura
  multi-engine real.
- Este documento, e todo este projeto, **nunca afirma** que a seed
  gerada é "segura", "inquebrável", "impossível de quebrar",
  "impossível para computador quântico" ou "impossível para governo" —
  ver `docs/THREAT_MODEL.md`.

## Premissas de confiança (trust assumptions)

Isto é o que uma pessoa precisa aceitar, mesmo depois de todas as
verificações acima retornarem `PASS`, para confiar no resultado (ver
`docs/INDEPENDENT_VERIFIER.md` §9 e `docs/EXECUTABLE_BUILD.md` seção 7
para a cadeia completa SOURCE → BUILD → EXECUTÁVEL → HASH → MANIFESTO →
VERIFICADOR):

- que o `entropyforge/` que você está usando como `--entropyforge-root`
  na verificação é de fato o código que você (ou alguém em quem confia)
  revisou linha a linha — nenhuma ferramenta aqui prova isso por si só;
- que o compilador Nuitka e o `gcc` do seu ambiente de build não estão,
  eles mesmos, comprometidos (uma camada de confiança que o `.pyz`, por
  não passar por compilação C, não exige — ver
  `docs/EXECUTABLE_BUILD.md` seção 2 para o raciocínio completo);
- que o hardware, o firmware, e o sistema operacional da máquina de
  geração não estão comprometidos;
- que o dado físico é honesto e os lançamentos são independentes;
- que o SHA-256 se comporta como um "oráculo aleatório" (suposição
  heurística padrão, sem prova formal);
- que a wordlist BIP-39 embutida é a oficial (verificável
  independentemente contra um hash conhecido, não fornecido pelo próprio
  projeto — `verifier.wordlist_check.KNOWN_OFFICIAL_SHA256`).

## Portão de release (release gate)

Uma release **não deve** ser considerada candidata a uso real se
QUALQUER uma destas condições for verdadeira:

- [ ] `make test` (EntropyForge) ou a suíte de `independent-verifier`
      tem qualquer teste falhando;
- [ ] `make verify-release` não imprime `PASS`;
- [ ] `make verify-executable` não imprime `PASS` (se for usar o
      executável);
- [ ] `make repro` ou `make repro-exe` reportam hashes divergentes;
- [ ] a wordlist embutida não bate com o hash oficial conhecido pelo
      verificador independente;
- [ ] qualquer interface de rede fica ativa durante `generate` sem uma
      confirmação explícita do operador;
- [ ] um vazamento de segredo (A, B, E, sequência de dado, ou mnemonic)
      é encontrado em qualquer saída, log, exceção ou canal auditado
      (`docs/AUDIT.md` §8, `docs/EXECUTABLE_SECRET_AUDIT.md`);
- [ ] existe um fallback silencioso para uma fonte de aleatoriedade
      menos confiável (o CSPRNG do SO falhando deve sempre abortar, nunca
      substituir por outra fonte);
- [ ] o comportamento do `.pyz` ou do executável diverge do
      comportamento do código-fonte (`verify-release`/`verify-executable`
      cobrem isso);
- [ ] existe uma inconsistência de documentação não resolvida entre os
      documentos citados nesta release.

**Estado no commit `423eb27` (véspera desta release candidate):** nenhuma
das condições acima está presente — todos os testes passam (257 + 129),
os dois builds são reprodutíveis, `verify-release` e `verify-executable`
reportam `PASS`, e o teste de máquina limpa desta fase confirmou tudo do
zero, incluindo o executável.

**Regra permanente:** nenhuma alegação deste documento (ou de qualquer
outro deste projeto) deve ser aceita como "já verificado antes" sem
reexecução. Rode `make test`, a suíte de `independent-verifier`,
`make repro`, `make repro-exe`, `make verify-release` e
`make verify-executable` você mesmo antes de confiar nesta release.
