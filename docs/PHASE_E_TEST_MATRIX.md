# Matriz consolidada de testes — Fase E (release de produção)

Esta matriz mapeia cada requisito da Fase E ("PHASE E — PRODUCTION
RELEASE / USABLE OFFLINE WALLET GENERATOR") à cobertura de teste ou
documentação que o satisfaz hoje, no mesmo espírito de
`docs/INDEPENDENT_VERIFIER.md` §11 (a tabela equivalente da fase
anterior). "Coberto" significa que existe um teste automatizado e/ou
documentação verificável — não uma alegação sem evidência.

| # | Requisito | Coberto por | Status |
|---|---|---|---|
| 1 | Versionamento formal (5 números independentes, expostos via `--version`) | `entropyforge/version.py`, `tests/test_version.py` | ✅ |
| 2 | Fluxo `generate` mostra só ACCEPTED/REJECTED (sem contagens de face) | `entropyforge/report.py::minimal_report`, `tests/test_cli_generate.py::SuccessfulGenerateTests::test_report_is_minimal_accepted_without_face_counts_or_per_test_verdicts` | ✅ |
| 3 | Entrada de d6 flexível (compacto/espaçado), ambiguidade sempre rejeitada | `entropyforge/dice.py::normalize_dice_input`, `tests/test_cli_generate.py::FlexibleDiceInputNormalizationTests` (9 testes) + `FlexibleDiceInputCliEndToEndTests` | ✅ |
| 4 | Matriz de plataformas suportadas (Linux/Tails/Debian live sim; Windows avaliado; XP explicitamente não suportado) | `docs/PLATFORM_SUPPORT.md`, `tests/test_osrng.py::NonLinuxPlatformTests` | ✅ |
| 5 | Seed BIP-39 cross-checada contra implementação externa (`mnemonic`) | `tests/test_dev_cross_check_bip32.py::SeedCrossCheckTests` (dev-only, pulado se lib ausente) | ✅ |
| 6 | Chave mestra BIP-32 cross-checada contra implementação externa (`bip32utils`) E contra HMAC-SHA512 cru independente | `tests/test_dev_cross_check_bip32.py::Bip32MasterKeyIndependentCrossCheckTests` (inclui vetor oficial da spec BIP-32) | ✅ |
| 7 | Pipeline completo entropia→mnemonic→seed→endereço com dados fictícios | `tests/test_dev_cross_check_bip32.py::FullPipelineFictitiousWalletTests` | ✅ |
| 8 | Cerimônia de importação em carteira externa documentada (dados fictícios) | `docs/WALLET_IMPORT_TEST.md` (Sparrow Wallet, passo a passo) | ✅ |
| 9 | `MANIFEST.txt` nunca contém mnemonic/entropia/A/B/seed/passphrase | `independent-verifier/verifier/release_manifest.py::ReleaseManifest` (10 campos, todos metadados de build) + `tests/test_release_manifest.py::ManifestTextRoundtripTests::test_manifest_never_has_a_secret_looking_field` | ✅ |
| 10 | `verify-release` imprime SOMENTE PASS/FAIL em stdout | `independent-verifier/verify_release.py`, `tests/test_verify_release_cli.py` (via subprocesso real) | ✅ |
| 11 | `verify-release` detecta artefato `.pyz` adulterado | `tests/test_release_manifest.py::test_verify_release_fails_if_pyz_tampered_after_manifest` | ✅ |
| 12 | `verify-release` detecta source-tree adulterado | `tests/test_release_manifest.py::test_verify_release_fails_if_source_tampered_after_manifest` | ✅ |
| 13 | `verify-release` detecta versão reivindicada incorreta no manifesto | `tests/test_release_manifest.py::test_verify_release_fails_if_manifest_claims_wrong_version` | ✅ |
| 14 | `make release`/`make verify-release` funcionam de ponta a ponta | `Makefile`, verificado manualmente nesta fase (build→manifest→assemble→verify = PASS) | ✅ |
| 15 | Estrutura de diretório de release (`release/`: `.pyz`+hashes+docs) | `tools/assemble_release.py`, `tests/test_assemble_release.py` (4 testes) | ✅ |
| 16 | Cerimônia com rotulagem explícita conectado/offline, duas máquinas | `docs/GENERATION_CEREMONY.md` (passos A–P) | ✅ |
| 17 | "Tela do operador é uma raiz de confiança residual" documentado explicitamente | `docs/GENERATION_CEREMONY.md`, seção homônima | ✅ |
| 18 | Sem alegação falsa de zeração garantida de memória | `docs/GENERATION_CEREMONY.md`, "O que este programa NÃO promete sobre memória"; `docs/AUDIT.md` §8, linha "memória (zeração)" | ✅ |
| 19 | Passphrase é manual/separada, nunca auto-gerada | `docs/OPERATIONS.md` §7 (pré-existente, revisado nesta fase) | ✅ |
| 20 | Proibição explícita de QR export / rede / integração com exchange-nuvem | `docs/DESIGN.md` D6, `docs/GENERATION_CEREMONY.md` "O que este projeto nunca vai ter" | ✅ |
| 21 | Auditoria de manuseio de segredo, canal por canal (12 canais) | `docs/AUDIT.md` §8 | ✅ |
| 22 | Teste de interrupção externo real (subprocesso + pty + SIGINT/SIGTERM/SIGKILL) | `tests/test_generate_interruption_real_subprocess.py::RealSignalInterruptionTests` (4 testes) | ✅ |
| 23 | Confirmação positiva de que o fluxo interrompido também funciona sem interrupção (controle positivo) | `tests/test_generate_interruption_real_subprocess.py::RealTerminalHappyPathTests` | ✅ |
| 24 | Nenhuma variável de ambiente lida por `entropyforge/` | `tests/test_security_ast.py::NoEnvironmentVariableUsageTests` | ✅ |
| 25 | Nenhuma via de clipboard (`tkinter` proibido) | `tests/test_security_ast.py` (FORBIDDEN_MODULES) | ✅ |
| 26 | Fuzzing final: dado/encoding/mnemonic/checksum/vector/CLI, seed/método/contagem/crashes documentados | `redteam/phase_e/scripts/fuzz_final.py`, `redteam/phase_e/findings/fuzz_final_output.txt`, `docs/REDTEAM.md` §12 — 63.060 iterações, 0 problemas reais | ✅ |
| 27 | Revisão estática final com falsos positivos explicados | `docs/STATIC_SCAN_FINAL.md` — 85 ocorrências em `entropyforge/`, todas explicadas como falso positivo | ✅ |
| 28 | Bug crítico de usabilidade real encontrado e corrigido (`guard` bloqueava `getpass`) | `docs/FINAL_SECURITY_REVIEW.md` §17, `entropyforge/guard.py`, `tests/test_guard.py::AuditHookAllowsDevTtyTests` | ✅ |
| 29 | Consistência de documentação de ponta a ponta (números de teste, referências cruzadas, hashes de arquivo, seções renomeadas) | passagem dedicada nesta fase — contagens de testes/linhas/hashes recalculados em `docs/AUDIT.md`, `docs/FINAL_SECURITY_REVIEW.md`, `docs/INDEPENDENT_VERIFIER.md`, `docs/THREAT_MODEL.md`; 0 links quebrados (verificado programaticamente) | ✅ |
| 30 | Teste de máquina limpa (`git archive`/checkout fresco) | `git archive HEAD` extraído para um diretório novo; `make test` (231), suíte de `independent-verifier` (129), `make build`, `make repro`, `make release`, `make verify-release` (PASS) e os testes de interrupção via `pty` real — todos passaram sem depender de estado do diretório de desenvolvimento | ✅ |
| 31 | Cerimônia fictícia de ponta a ponta cruzada externamente (re-execução final, não confiar em "passou antes") | `vector` com A/B fictícios públicos → mnemonic recalculado do ZERO por uma reimplementação stdlib-only do encoding+combinação+BIP-39 (bateu exatamente) → BIP-32/BIP-44 até um endereço via `bip32utils` — ver `RELEASE-CANDIDATE.md`, seção "Cerimônia fictícia de ponta a ponta" | ✅ |
| 32 | Portão de release explícito (bloqueia em qualquer teste falhando, divergência externa, hash inconsistente, wordlist com problema, rede durante geração, vazamento conhecido, fallback inseguro, diferença de comportamento source/pyz, inconsistência de documentação) | `RELEASE-CANDIDATE.md`, seção "Portão de release" — critérios explícitos + estado atual declarado (nenhuma condição de bloqueio presente) | ✅ |

**Nota sobre o número "27" do requisito original:** esta matriz cresceu
para 32 linhas ao mapear cada sub-requisito da Fase E individualmente
(mais granular do que uma contagem redonda) — nenhum requisito foi
comprimido ou omitido para bater um número específico; completude da
cobertura importa mais do que a contagem exata.

## Estado agregado no momento em que esta matriz foi escrita

- **32 de 32 itens: ✅ cobertos e verificados nesta sessão**, incluindo
  reexecução completa em uma máquina limpa (item 30) — nenhum item foi
  aceito com base em "já passou antes".
- **231 testes unitários** (`python3 -B -m unittest discover -s tests`)
  mais **129 testes do `independent-verifier`** mais **63.060 iterações
  de fuzzing** (`redteam/phase_e/scripts/fuzz_final.py`) passam nesta
  revisão, sem nenhum problema real encontrado além do bug crítico já
  corrigido (item 28) — todos reconfirmados em `git archive HEAD` puro.
- Ver `RELEASE-CANDIDATE.md` para o resumo executivo desta release e o
  portão de release explícito.
