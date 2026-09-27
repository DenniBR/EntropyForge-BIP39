# EntropyForge-BIP39 — release candidate (Fase E)

Este documento é o resumo executivo de uma release, com só fatos
verificáveis: nenhuma alegação de segurança absoluta aparece aqui (nem em
nenhum outro lugar deste projeto — ver `docs/THREAT_MODEL.md`). Ele não
substitui a leitura de `docs/PHASE_E_TEST_MATRIX.md` (a matriz completa) e
`docs/VERIFY.md` (como reproduzir a verificação você mesmo).

## Identificação

- **Commit desta revisão:** `d72d5c42f07bc119eb8e1f64f87ad364bcfe8420`
  (branch `claude/jolly-ptolemy-2bmru7`). Este arquivo foi escrito com
  base no estado do repositório nesse commit; o commit que efetivamente
  contém este arquivo é necessariamente um commit posterior a esse (não
  há como um commit referenciar o próprio hash antes de existir) — rode
  `git log -1 --format=%H` no seu checkout para o hash exato do que você
  está de fato auditando, e `git log --oneline d72d5c4..HEAD` para ver
  exatamente o que mudou depois desta revisão.
- **Versões formais** (`entropyforge/version.py`, `--version`):
  - software: `1.0.0`
  - protocolo do formato A (`dice.py`): `1`
  - procedimento de geração: `2`
  - wordlist: `bip39-english-2013`
  - formato do manifesto de release: `1`

## Hashes de referência

Recalcule os seus — nunca confie nos valores abaixo sozinhos (ver
`docs/VERIFY.md`):

```
sha256(entropyforge/data/english.txt) = 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
```

O hash do `entropyforge.pyz` e o `MANIFEST.txt` completo variam a cada
build (por design — é o que faz `verify-release` útil); gere os seus com
`make release` e confirme com `make verify-release` (deve imprimir
`PASS`).

## Contagem de testes (neste commit)

- `tests/` (EntropyForge): **231 testes**, todos passando
  (`python3 -B -m unittest discover -s tests`).
- `independent-verifier/tests/`: **129 testes**, todos passando.
- Fuzzing final (`redteam/phase_e/scripts/fuzz_final.py`, seed
  `20260927`, reproduzível): **63.060 iterações, 0 problemas reais**
  encontrados (49 colisões de checksum BIP-39 esperadas pela matemática
  do próprio formato, confirmadas como não-bugs por concordância com uma
  implementação independente — ver `docs/REDTEAM.md` §12).
- Revisão estática final (`docs/STATIC_SCAN_FINAL.md`): 85 ocorrências em
  `entropyforge/`, todas explicadas individualmente como falso positivo.

## Reprodutibilidade

`make repro` confirma que duas builds independentes (diretórios e umask
diferentes) do mesmo commit produzem o **mesmo SHA-256** — verificado
nesta revisão, inclusive a partir de um checkout inteiramente limpo
(`git archive HEAD`, sem nenhum estado residual do diretório de
desenvolvimento).

## Teste de máquina limpa

Esta revisão incluiu extrair o commit acima com `git archive` para um
diretório totalmente novo e, a partir dele (sem qualquer arquivo,
`__pycache__` ou estado deixado por uma sessão de desenvolvimento
anterior): rodar as duas suítes de teste completas, `make build`,
`make repro`, `make release`, e `make verify-release` — todos passaram
exatamente como no checkout de desenvolvimento. Isto confirma que nenhum
teste ou processo de build depende de estado não-versionado.

## Cerimônia fictícia de ponta a ponta, cross-checada externamente

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
   públicos e reproduzíveis (mesmos passos de
   `docs/WALLET_IMPORT_TEST.md`, agora também confirmados nesta revisão).
4. O fluxo interativo real (`generate`, com um terminal `pty` de
   verdade, dígitos de dado reais via `os.getrandom`, sinais reais do
   kernel) foi confirmado de ponta a ponta e sob interrupção —
   `tests/test_generate_interruption_real_subprocess.py`.

Nenhum destes passos gerou, ou deveria ser tratado como, uma carteira com
fundos reais.

## O que foi encontrado e corrigido nesta fase

Um bug de severidade crítica: `entropyforge/guard.py` bloqueava
`getpass.getpass()` (usado pela entrada oculta de dígitos/mnemonic),
tornando `generate` inutilizável em qualquer terminal real fora de
testes com uma abstração falsa. Encontrado pelo teste de interrupção via
`pty` real desta fase, corrigido, com quatro testes de regressão
dedicados. Detalhe completo em `docs/FINAL_SECURITY_REVIEW.md` seção 17.

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
- Este documento, e todo este projeto, **nunca afirma** que a seed
  gerada é "segura", "inquebrável", "impossível de quebrar",
  "impossível para computador quântico" ou "impossível para governo" —
  ver `docs/THREAT_MODEL.md`.

## Portão de release (release gate)

Uma release **não deve** ser considerada candidata a uso real se
QUALQUER uma destas condições for verdadeira:

- [ ] `make test` (EntropyForge) ou a suíte de `independent-verifier`
      tem qualquer teste falhando;
- [ ] `make verify-release` não imprime `PASS`;
- [ ] `make repro` reporta hashes divergentes;
- [ ] a wordlist embutida não bate com o hash oficial conhecido pelo
      verificador independente;
- [ ] qualquer interface de rede fica ativa durante `generate` sem uma
      confirmação explícita do operador;
- [ ] um vazamento de segredo (A, B, E, sequência de dado, ou mnemonic)
      é encontrado em qualquer saída, log, exceção ou canal auditado
      (`docs/AUDIT.md` §8);
- [ ] existe um fallback silencioso para uma fonte de aleatoriedade
      menos confiável (o CSPRNG do SO falhando deve sempre abortar, nunca
      substituir por outra fonte);
- [ ] o comportamento do `.pyz` diverge do comportamento do código-fonte
      (`verify-release` cobre isso);
- [ ] existe uma inconsistência de documentação não resolvida entre os
      documentos citados nesta release.

**Estado no commit `d72d5c4` (véspera desta release candidate):**
nenhuma das condições acima está presente — todos os testes passam, o
build é reprodutível, `verify-release` reporta `PASS`, e a passagem de
consistência de documentação desta fase não encontrou nenhuma
contradição não resolvida entre os documentos.

**Regra permanente:** nenhuma alegação deste documento (ou de qualquer
outro deste projeto) deve ser aceita como "já verificado antes" sem
reexecução. Rode `make test`, a suíte de `independent-verifier`,
`make repro` e `make verify-release` você mesmo antes de confiar nesta
release.
