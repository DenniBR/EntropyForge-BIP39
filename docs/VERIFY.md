# Como verificar um release (guia rápido)

Este documento é o **HOWTO prático**: o que rodar, na máquina conectada,
para confirmar que um release do EntropyForge-BIP39 (o diretório `release/`
que você recebeu ou montou) bate com o código-fonte publicado, antes de
levá-lo para a máquina offline. Para o raciocínio completo por trás de
cada checagem (o que ela detecta, o que ela NÃO detecta, e por quê), veja
`docs/INDEPENDENT_VERIFIER.md`.

## 1. O que você precisa

- O repositório completo (`git clone`), não só a pasta `release/` —
  `verify-release` recalcula hashes a partir do código-fonte, então
  precisa dele.
- Python ≥ 3.11, só biblioteca padrão (nenhuma dependência de terceiros é
  necessária para verificar).

## 2. Caso 1: você mesmo construiu o release

Se você rodou `make release` você mesmo, a partir de um checkout que
revisou:

```sh
make verify-release
```

Isso reconstrói o manifesto do zero e compara contra `MANIFEST.txt` que
`make release` acabou de gerar — na prática, confirma que o processo de
build não teve um efeito colateral inesperado entre a geração do
manifesto e agora (útil como uma dupla checagem, não como a verificação
mais forte possível: ver seção 4).

Saída esperada: a palavra `PASS` (e código de saída `0`). Qualquer outra
coisa é um sinal para investigar antes de usar este release para uma
geração real — nunca prossiga com um `FAIL`.

## 3. Caso 2: alguém mais te deu um `MANIFEST.txt` (ou uma pasta `release/`)

Este é o caso que realmente importa para segurança: alguém publicou um
release (ex.: em um repositório Git, um servidor de arquivos, um pen
drive) e você quer confirmar que o que você recebeu bate com o
`MANIFEST.txt` publicado **separadamente** (ex.: em um canal diferente —
outro commit assinado, uma mensagem verificada de outra forma, etc.).

```sh
python3 independent-verifier/verify_release.py \
  --manifest /caminho/para/MANIFEST.txt \
  --entropyforge-root entropyforge \
  --pyz /caminho/para/entropyforge.pyz \
  --verifier-root independent-verifier/verifier \
  --build-script tools/build_pyz.py \
  --vectors tests/vectors/bip39_vectors.json
```

Ajuste os caminhos de `--pyz`/`--manifest` para onde estão os arquivos que
você recebeu (por exemplo, dentro de uma pasta `release/` que veio junto).
`--entropyforge-root`, `--verifier-root`, `--build-script` e `--vectors`
sempre apontam para o SEU checkout do repositório (o código que você já
revisou/confia), nunca para nada que veio junto com o release recebido.

Use `--verbose` para ver o detalhamento campo a campo (vai para stderr,
nunca para stdout — a saída padrão continua sendo só `PASS`/`FAIL`,
segura para uso em scripts: `resultado=$(python3 ... )`).

## 4. O que isso prova, e o que não prova

**Prova:** que o `entropyforge.pyz` que você tem, o código-fonte
`entropyforge/` que você tem, o script de build, a wordlist, e a versão
do próprio `independent-verifier`, todos batem EXATAMENTE com os hashes
registrados no `MANIFEST.txt` fornecido — e que a implementação BIP-39
bate com os vetores oficiais.

**Não prova**, por si só, que o `MANIFEST.txt` fornecido é legítimo: se um
atacante controla tanto o artefato quanto o manifesto (ex.: ambos vieram
do mesmo mirror comprometido), `verify-release` vai dizer `PASS` para uma
combinação adulterada consistente consigo mesma. A força real desta
verificação vem de obter o `MANIFEST.txt` por um canal INDEPENDENTE do
artefato — por exemplo, conferindo o hash do manifesto com outra pessoa
que também o calculou, ou usando um commit Git específico como referência
de confiança. Ver `docs/INDEPENDENT_VERIFIER.md` seção 6 para o motivo
detalhado (a mesma limitação estrutural de qualquer verificação por hash).

**Também não prova** nada sobre o hardware, o firmware, ou o sistema
operacional da máquina onde você vai rodar o `.pyz` — ver
`docs/THREAT_MODEL.md` e `docs/PLATFORM_SUPPORT.md`.

## 5. Depois de um `PASS`

1. Transfira `entropyforge.pyz` (e, se quiser, a pasta `release/` inteira,
   incluindo a documentação) para a máquina permanentemente offline — por
   mídia física (pendrive), nunca por rede.
2. Na máquina offline, **antes** de gerar qualquer mnemonic real, rode
   `python3 -I -B entropyforge.pyz selftest` — isso não substitui a
   verificação acima (que exige o código-fonte, indisponível numa máquina
   minimalista), mas confirma que o `.pyz` transferido não foi corrompido
   na transferência e passa nos testes de resposta conhecida.
3. Siga `docs/GENERATION_CEREMONY.md` para o fluxo completo de geração.
