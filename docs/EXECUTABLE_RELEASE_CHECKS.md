# Checagens de release do executável (Fase F)

Este documento acumula as evidências empíricas por trás das alegações de
`docs/EXECUTABLE_BUILD.md` — reprodutibilidade, build limpo,
interoperabilidade, teste de backdoor, avaliação de Windows, e assinatura
de código. Cada seção lista exatamente o comando usado, para que qualquer
pessoa possa reproduzir a mesma investigação.

## 1. Build limpo (a partir de um checkout `git archive`, não do diretório de desenvolvimento)

Todos os builds descritos nas seções abaixo foram feitos a partir de
extrações **novas** de `git archive HEAD` para diretórios temporários
inteiramente separados do diretório de desenvolvimento — nunca
reaproveitando `__pycache__`, `dist_executable/`, ou qualquer outro
estado residual. Comando usado para cada extração:

```sh
git archive HEAD | tar -x -C <diretorio-novo>
cd <diretorio-novo> && python3 tools/build_executable.py --output-dir <saida>
```

## 2. Reprodutibilidade

Quatro builds independentes, cada um a partir de uma extração `git
archive` **separada**, variando:

| Build | Diretório | `umask` | `TZ` | `PYTHONHASHSEED` |
|---|---|---|---|---|
| A | `/tmp/.../repro_a` | 022 | (padrão do sistema) | (padrão) |
| B | `/tmp/.../repro_b` | 077 | (padrão do sistema) | (padrão) |
| C | `/tmp/.../repro_c` | (padrão) | `America/Sao_Paulo` | `42` |
| D (dev) | diretório de desenvolvimento | (padrão) | (padrão do sistema) | (padrão) |

**Resultado: SHA-256 do binário principal idêntico nos quatro builds**
(`ada1ef3296fbaae2aba890a1d5b6505952ab382e9c50bff50b082997aedf533d` para
o commit em que este documento foi escrito — recalcule o seu, este valor
muda a cada alteração de source, por design).

Entre os builds A e B, foi feita uma comparação mais rigorosa: **hash de
CADA arquivo** do diretório de saída (não só o binário principal),
confirmando lista de arquivos idêntica e hash idêntico arquivo por
arquivo:

```sh
diff <(cd dist_a/.../ && find . -type f -exec sha256sum {} \; | sort -k2) \
     <(cd dist_b/.../ && find . -type f -exec sha256sum {} \; | sort -k2)
# (sem diferenças)
```

Isto é automatizado e reproduzível via `make repro-exe`.

### O que NÃO foi testado (limitação honesta)

Só havia **uma** versão de Python (3.11.15), **um** compilador (`gcc`
13.3.0 do Ubuntu 24.04), e **uma** versão do Nuitka (4.2.2) disponíveis
neste ambiente de build. **Reprodutibilidade ENTRE versões diferentes
de Python/gcc/Nuitka não foi testada** — isto é uma lacuna real, não
uma alegação escondida. Ao contrário do `.pyz` (que é bytecode Python
interpretado e, por isso, muito mais insensível à versão exata do
compilador C usado — só depende da versão do CPython), um binário
compilado por Nuitka é, em princípo, mais sensível a mudanças na
cadeia de ferramentas de compilação. Recomendação para quem for
reproduzir uma release: usar a MESMA versão de Python, gcc e Nuitka
documentada no `MANIFEST.txt` daquela release (campo `build metadata`,
seção 9 deste documento), não confiar em "deveria dar igual em
qualquer ambiente".

## 3. Interoperabilidade de ponta a ponta (dados fictícios)

Executado contra o **executável real** (não o source):

```sh
EXE=dist_executable/entropyforge-bip39-v1.0.0-linux-x86_64/entropyforge-bip39
$EXE vector --a-digits "$(python3 -c "print(('123456'*22)[:127])")" \
             --b-hex   "$(python3 -c "print(bytes(range(32)).hex())")"
```

Produz o mesmo mnemonic já documentado e cross-checado em
`RELEASE-CANDIDATE.md` ("Cerimônia fictícia de ponta a ponta") — a
saída do executável bate exatamente com a saída do source E com a
reimplementação independente (stdlib-only) daquele documento. Ver também
`tests/test_executable_e2e.py::test_vector_mode_matches_source_computation`,
que faz essa comparação automaticamente a cada execução da suíte de
testes do executável.

Além disso, `tests/test_executable_dev_cross_check_bip32.py` (dev-only,
pulado automaticamente se `mnemonic`/`bip32utils` não estiverem
instalados) repete a cadeia completa **d6 → A → B → SHA256(A‖B) →
entropia → mnemonic → seed → chave mestra BIP-32 → chave BIP-44 →
endereço** a partir da mnemonic **lida do stdout real do binário
compilado** (`vector --a-digits ... --b-hex ...`, valores públicos de
teste), nunca reimportando `entropyforge` para obtê-la. Cada seta a
partir da mnemonic é conferida por uma implementação externa
(`mnemonic` da Trezor para mnemonic→seed; `bip32utils` + uma
reimplementação crua com `hmac`/`hashlib` para seed→chave mestra→
endereço BIP-44; decodificação Base58Check independente do endereço
final). As três checagens passam (`python3 -m unittest
tests.test_executable_dev_cross_check_bip32 -v`). Isto fecha a lacuna
que testar só o source deixaria: confirma que o **artefato distribuído**
— não só o código-fonte que o gerou — interopera com implementações de
terceiros.

## 4. Teste de backdoor contra o pipeline de build

Script: `redteam/independent/scripts/run_executable_backdoor_lab.py`.
Saída completa: `redteam/independent/findings/executable_backdoor_lab_output.txt`.

Três cenários, cada um **construído do zero** (`tools/build_executable.build`,
usando o novo parâmetro `source_root` para apontar para uma cópia
isolada de `entropyforge/`, nunca o diretório de desenvolvimento):

  - **A (limpo)**: `entropyforge/` real do repositório.
  - **B (alteração cosmética)**: cópia idêntica + um docstring extra em
    `dice.py` (nenhum efeito funcional, só um literal de string novo).
  - **C (backdoor)**: cópia com o backdoor 01 do laboratório existente
    (`redteam/independent/labs/backdoors/backdoor_lab.py`) — `combine.py`
    passa a escrever `A||B` combinado em `stderr`. Resultado (entropia,
    mnemonic, vetores oficiais, `selftest`) permanece **correto** — o
    backdoor "passa nos KATs" — mas vaza o segredo.

**Resultado 1 — hash do diretório do executável**: A, B e C produzem
**três hashes diferentes**. Notável: mesmo a alteração puramente
cosmética (cenário B, sem nenhum efeito em tempo de execução) já muda o
binário compilado — ao contrário de um comentário Python (descartado
antes mesmo da geração de bytecode), um literal de string novo é
embutido nas constantes do módulo e o Nuitka o compila. Isto confirma
que a comparação de hash do executável tem sensibilidade pelo menos tão
fina quanto a do `.pyz` para este tipo de mudança — não foi apenas
assumido, foi construído e medido.

**Resultado 2 — comportamento operacional**: `selftest` reporta `PASSOU`
nos três cenários (A, B, e **C, o backdoor incluído** — nenhum KAT
detecta o vazamento, mesma limitação estrutural já documentada para o
`.pyz` em `docs/INDEPENDENT_VERIFIER.md`). `vector` (com
`--a-digits`/`--b-hex` públicos de teste) também retorna sucesso nos
três, mas **só o cenário C** imprime o marcador de laboratório com a
entropia vazada em stdout/stderr — confirmado rodando o **binário
compilado real**, não uma simulação.

**Resultado 3 — auto-verificação (o que NÃO detecta nada)**: gerar o
manifesto a partir da MESMA cópia de source usada para construir sempre
"bate" consigo mesma, inclusive para o backdoor — isto é o comportamento
correto e já documentado (`verify_release.py`/`verify_executable.py`:
"só tem valor se o manifesto vier de um canal independente do
artefato"). Um atacante que controla source e manifesto ao mesmo tempo
não é pego por essa checagem sozinha.

**Resultado 4 — o que de fato detecta (auditor independente)**: rodando
`independent-verifier/verify_executable.py` com `--entropyforge-root`
apontando para a cópia **real e revisada do repositório** (não a cópia
do cenário) contra o manifesto e o `dist/` de cada cenário:

| Cenário | `hash_vs_manifesto` | `selftest` | `reconstrucao_a_partir_do_source` | `RESULTADO GERAL` |
|---|---|---|---|---|
| A (limpo) | PASS | PASS | **PASS** | PASS |
| B (cosmético) | PASS | PASS | **FAIL** | FAIL |
| C (backdoor) | PASS | PASS | **FAIL** | FAIL |

A checagem de reconstrução — a única que reconstrói a partir de uma
cópia de source que o AUDITOR controla, não o publicador do artefato —
detecta tanto o backdoor quanto a alteração puramente cosmética, com
zero falsos positivos (o cenário legítimo passa) e zero falsos negativos
nesta amostra. As duas primeiras checagens (`hash_vs_manifesto`,
`selftest`) sozinhas **não** detectariam nem B nem C — reforça por que
`verify_release.py` (rápido, sem reconstruir) nunca deve ser tratado
como suficiente; `verify_executable.py` (Fase F, com reconstrução) é a
checagem que carrega o peso real desta garantia.

## 5. Windows

Ver `docs/EXECUTABLE_BUILD.md` seção 8. Resumo: **não produzido nesta
fase.** Nenhuma das duas ferramentas avaliadas (PyInstaller, Nuitka) faz
cross-compilação de Linux para Windows de forma oficial/suportada — cada
uma precisa RODAR no sistema operacional alvo para produzir um binário
para ele. Este ambiente de build é um container Linux, sem acesso a uma
máquina Windows real. Alternativas não-oficiais (compilar via Wine, por
exemplo) não foram tentadas porque não atendem à barra de "tecnicamente
segura e reprodutível" que este projeto exige para qualquer artefato
distribuído — usar uma ferramenta de compatibilidade para emular
Windows introduziria uma camada adicional, pouco testada, exatamente no
processo de build que este projeto mais precisa poder confiar. **Isto é
documentado explicitamente como uma lacuna, não uma alegação de suporte
inexistente.**

## 6. Assinatura de código

Avaliado, não implementado. Assinar o executável (Authenticode no
Windows, ou uma assinatura GPG/`minisign` detached para o Linux)
exigiria uma chave privada — que **nunca** deve existir dentro deste
repositório nem ser gerada por um agente automatizado sem supervisão
humana explícita sobre sua custódia. Gerar uma assinatura "de teste" ou
"de demonstração" aqui seria pior do que não assinar: daria a impressão
de uma cadeia de confiança que não existe de verdade. Por isso, a
assinatura de código é documentada como uma **etapa externa e manual**
do processo de release, a ser feita por quem publica a release, com uma
chave que eles controlam, DEPOIS que `make verify-release` e
`verify-executable` já confirmaram que o artefato bate com o código
revisado. Recomendação de mecanismo, para quando essa etapa for
implementada por um humano com uma chave real: assinatura destacada
(`.sig` ou `.asc`, não embutida no binário) com uma chave PGP publicada
separadamente (ex.: keyserver + fingerprint documentado no site do
projeto), verificável com `gpg --verify` — mais simples de auditar do
que Authenticode, e funciona igual em Linux/Windows.

## 7. Fuzzing do executável e observação de processo (limpo vs. backdoor)

Script: `redteam/independent/scripts/fuzz_and_observe_executable.py`.
Saída completa: `redteam/independent/findings/fuzz_and_observe_executable_output.txt`.
Ver também `docs/FINAL_SECURITY_REVIEW.md` ("Executable Release
Security") para a versão resumida deste achado.

**Fuzzing** (mesma metodologia de `redteam/phase_e/scripts/fuzz_final.py`
— `random.Random` com seed fixa `20260927`, documentada, nunca usada para
gerar dados reais), contra o **binário compilado real**, não o source:

- `fuzz_vector_argv` (300 iterações): argumentos aleatórios/malformados
  para `vector` (`--a-digits`/`--b-hex`/`--entropy-hex`/`--mnemonic`
  com strings aleatórias, incluindo unicode e caracteres de controle) —
  critério de falha: um traceback Python bruto vazando na saída, ou um
  travamento.
- `fuzz_stdin_bytes` (100 iterações): bytes aleatórios brutos (0–255) na
  entrada padrão de `generate`/`calibrate`/`selftest`/`--version`,
  processo não-TTY — critério de falha: travamento (timeout) ou o
  payload de entrada sendo ecoado de volta na saída.

**Resultado: 0 problemas em 400 iterações totais.** Nenhum traceback
vazado, nenhum travamento, nenhum eco de payload.

**Observação de processo** (`strace -f`, via
`verifier.process_observe.trace_process`, o mesmo módulo já usado no
comparativo do source na Fase D): dois executáveis reais construídos
para este teste — limpo e com o backdoor 01 (exfiltração via `stderr`,
reaproveitado do laboratório de backdoor da seção 4) — rodando `vector`
com dados públicos de teste:

| Caso | `network` | `process` | `file_write` | marcador no stdout/stderr real |
|---|---|---|---|---|
| Limpo | False | False | False | False |
| Backdoor 01 (stderr) | False | False | False | **True** |

**Achado, e sua interpretação correta:** as três colunas de syscall
(rede/processo/escrita em disco) são **idênticas** entre limpo e
backdoor — o backdoor 01 exfiltra escrevendo num descritor de arquivo
(`stderr`) que o processo já possuía ao nascer (herdado do pai via
`fork`/`exec`, não uma nova syscall `openat`/`socket`/`connect`), então é
estruturalmente invisível para um filtro de `strace` focado em
rede/disco/processo — exatamente a mesma conclusão já documentada para o
source interpretado em
`redteam/independent/findings/legit_vs_backdoor_strace_comparison.txt`.
A quarta coluna (marcador procurado no **stdout/stderr real capturados
pelo próprio subprocesso**, não no log do `strace`) é o que de fato
distingue os dois casos — e ela distingue corretamente. **Limitação
honesta:** o log bruto do `strace` (`raw_strace_log`) nunca teria
mostrado essa escrita de qualquer forma, porque o filtro `-e
trace=network,openat,...` usado por `trace_process` não inclui `write` —
isso não é uma falha desta observação, é o escopo deliberado da
ferramenta (auditar rede/disco/processo, não o conteúdo de stdout/stderr).
Uma exfiltração por stdout/stderr precisa ser pega por outro mecanismo:
aqui, a leitura direta da saída real do processo (como feito acima), ou,
operacionalmente, nunca redirecionar a saída deste programa para um
canal não confiável durante uma geração real.
