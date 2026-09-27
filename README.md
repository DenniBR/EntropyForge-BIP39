# EntropyForge-BIP39

Gerador **offline** de entropia para um mnemonic BIP-39 de 24 palavras,
combinando lançamentos de um dado de 6 faces (d6) físico com o CSPRNG do
sistema operacional. Zero dependências de terceiros em tempo de execução;
só a biblioteca padrão do Python (≥ 3.11).

```
E = SHA-256( encode(lançamentos_do_d6) ‖ os.getrandom(32) )
mnemonic = BIP39(E)     # 24 palavras
```

## Por que duas fontes

Se **qualquer uma** das duas fontes for boa e desconhecida de um
adversário, a saída combinada permanece segura sob o modelo de segurança
descrito em `docs/MATH.md` — mesmo que a outra fonte esteja totalmente
comprometida. Isso não é uma garantia absoluta: veja `docs/THREAT_MODEL.md`
para os limites reais dessa proteção (ela não ajuda, por exemplo, contra
um sistema operacional que já vê tudo).

## Início rápido

```sh
python3 --version   # exige >= 3.11

make test            # suíte de testes (só biblioteca padrão)
make build            # gera entropyforge.pyz (build determinístico)
make repro            # confirma que o build é reprodutível

python3 -I -B entropyforge.pyz selftest    # auto-testes
python3 -I -B entropyforge.pyz generate    # gera um mnemonic real (exige TTY, offline)
```

**Antes de usar para fundos reais**, leia `docs/OPERATIONS.md` (como
operar com segurança) e `docs/THREAT_MODEL.md` (o que este programa
protege, e o que não protege).

## Documentação

| Documento | Conteúdo |
|---|---|
| [`docs/DESIGN.md`](docs/DESIGN.md) | Arquitetura, decisões criptográficas, rastreabilidade de requisitos |
| [`docs/MATH.md`](docs/MATH.md) | Toda a matemática: entropia, provas das distribuições estatísticas, orçamento de vazamento, o que é fato vs. heurística vs. premissa vs. opinião |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Modelo de ameaças completo (SO, hardware, supply chain, dado enviesado, computação quântica, etc.) |
| [`docs/AUDIT.md`](docs/AUDIT.md) | Guia de auditoria: hashes, ordem de leitura, invariantes e onde cada um é testado |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | Como operar com segurança, passo a passo, incluindo a nota sobre passphrase BIP-39 |
| [`docs/PLATFORM_SUPPORT.md`](docs/PLATFORM_SUPPORT.md) | Matriz de suporte a plataformas: Linux/Tails/Debian live (suportado), Windows (avaliado, não recomendado), Windows XP (não suportada) |
| [`docs/GENERATION_CEREMONY.md`](docs/GENERATION_CEREMONY.md) | Os 15 passos da cerimônia de geração offline, do boot ao desligamento |
| [`docs/RELEASE_SECURITY_CHECKLIST.md`](docs/RELEASE_SECURITY_CHECKLIST.md) | Checklist rápido pré-geração (sem exibir nenhum segredo) |
| [`docs/REDTEAM.md`](docs/REDTEAM.md) | Auditoria adversarial (red team): o que foi atacado, o que quebrou, o que foi corrigido |
| [`docs/INDEPENDENT_VERIFIER.md`](docs/INDEPENDENT_VERIFIER.md) | Verificação de segunda ordem: um verificador separado que não confia no EntropyForge nem em si mesmo sem se testar |
| [`docs/FINAL_SECURITY_REVIEW.md`](docs/FINAL_SECURITY_REVIEW.md) | Revisão de segurança final antes de considerar o projeto candidato a uso real |

## O que este programa garante (e o que não garante)

**Garantido matematicamente e verificado por teste** (ver `docs/MATH.md`
§11 para a lista completa): a codificação da fonte física é uma bijeção
(não infla nem perde bits); a implementação do BIP-39 bate com os 24
vetores oficiais e com a implementação de referência (`python-mnemonic`);
`E` tem exatamente 256 bits; o relatório estatístico exibido nunca vaza
mais do que um orçamento de bits explicitamente calculado.

**Depende de premissas que o software não pode verificar** (ver
`docs/MATH.md` §11 e `docs/THREAT_MODEL.md`): que o dado físico é honesto
e os lançamentos são independentes; que o CSPRNG do sistema operacional
não está comprometido; que o SHA-256 se comporta como um "oráculo
aleatório" (uma suposição heurística padrão da criptografia prática, sem
prova formal); que o ambiente (SO, firmware, hardware) não está
comprometido.

**Este projeto nunca afirma** que a seed gerada é "inquebrável",
"impossível de recuperar" ou "segura contra computadores quânticos/
governos" em termos absolutos, nem que os testes estatísticos "provam"
aleatoriedade. Ver `docs/THREAT_MODEL.md` §3 para a discussão (sem
números inventados) sobre computação quântica.

## Segurança operacional em uma frase

Nada é escrito em disco, nada é enviado pela rede, o mnemonic é mostrado
uma única vez em uma tela que não fica no histórico do terminal, e a
sequência de dados nunca aparece em nenhuma saída do programa — tudo isso
é verificado automaticamente pela suíte de testes, não apenas prometido
na documentação (`tests/test_cli_generate.py`, `tests/test_guard.py`).

## Licença

Ver o repositório para os termos de licença aplicáveis.
