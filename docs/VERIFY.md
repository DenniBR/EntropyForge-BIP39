# Como verificar um release (guia rápido)

Este documento é o **HOWTO prático**: o que rodar, na máquina conectada,
para confirmar que um release do EntropyForge-BIP39 (o diretório `release/`
que você recebeu ou montou) bate com o código-fonte publicado, antes de
levá-lo para a máquina offline. Para o raciocínio completo por trás de
cada checagem (o que ela detecta, o que ela NÃO detecta, e por quê), veja
`docs/INDEPENDENT_VERIFIER.md`.

Desde a Fase F, `release/` contém DOIS artefatos que rodam o produto —
`entropyforge.pyz` (interpretado) e `entropyforge-bip39-vX.Y.Z-linux-<arch>/`
(executável standalone, não precisa de Python instalado) — e uma cópia do
próprio verificador (`release/independent-verifier/`), incluída por
conveniência. **Importante:** rodar o verificador bundlado em `release/`
contra o `entropyforge/` que também está dentro desse MESMO `release/`
nunca prova nada sozinho (ver seção 4) — o `--entropyforge-root` usado
abaixo deve sempre ser o seu PRÓPRIO checkout git, obtido por um canal
independente do artefato que você está conferindo.

## 1. O que você precisa

- O repositório completo (`git clone`), não só a pasta `release/` —
  `verify-release` recalcula hashes a partir do código-fonte, então
  precisa dele.
- Python ≥ 3.11, só biblioteca padrão (nenhuma dependência de terceiros é
  necessária para verificar o `.pyz` ou rodar a checagem rápida do
  executável).
- **Só para a checagem FORTE do executável** (seção 3b, que reconstrói o
  binário do zero): `nuitka` e um compilador C (`gcc`/`cc`) instalados —
  dependência de BUILD, nunca de runtime do produto em si. Sem eles, a
  checagem rápida (hash do diretório contra o manifesto, `--version`,
  `selftest`) ainda funciona; só a reconstrução é pulada.

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
mais forte possível: ver seção 4). Para a checagem FORTE do executável
(reconstrução completa, ver seção 3b), rode também:

```sh
make verify-executable
```

Saída esperada, para ambos: a palavra `PASS` (e código de saída `0`).
Qualquer outra coisa é um sinal para investigar antes de usar este
release para uma geração real — nunca prossiga com um `FAIL`.

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
  --vectors tests/vectors/bip39_vectors.json \
  --executable-dist /caminho/para/entropyforge-bip39-vX.Y.Z-linux-x86_64
```

Ajuste os caminhos de `--pyz`/`--manifest`/`--executable-dist` para onde
estão os arquivos que você recebeu (por exemplo, dentro de uma pasta
`release/` que veio junto — pode usar `release/independent-verifier/verify_release.py`,
a cópia bundlada, para não precisar clonar `independent-verifier/`
separadamente). `--entropyforge-root`, `--verifier-root`, `--build-script`
e `--vectors` sempre apontam para o SEU checkout do repositório (o código
que você já revisou/confia), nunca para nada que veio junto com o release
recebido — nem mesmo `release/independent-verifier/verifier`, que
funciona igualmente bem, mas cujo texto convém você mesmo ler antes de
confiar nele.

Use `--verbose` para ver o detalhamento campo a campo (vai para stderr,
nunca para stdout — a saída padrão continua sendo só `PASS`/`FAIL`,
segura para uso em scripts: `resultado=$(python3 ... )`).

## 3b. Checagem FORTE do executável (Fase F): reconstrução a partir do source

`verify-release`/`verify_release.py` acima só compara o hash do
diretório do executável que você recebeu contra o que o `MANIFEST.txt`
reivindica — rápido, mas não prova que aquele hash corresponde de fato
ao código-fonte revisado (um atacante que forjou os dois juntos passaria
nessa checagem). Para a prova forte — reconstruir o executável a partir
do `entropyforge/` que você mesmo revisou e comparar o hash resultante —
use `verify_executable.py` (requer `nuitka`+`gcc`; ver seção 1):

```sh
python3 independent-verifier/verify_executable.py \
  --manifest /caminho/para/MANIFEST.txt \
  --entropyforge-root entropyforge \
  --executable-dist /caminho/para/entropyforge-bip39-vX.Y.Z-linux-x86_64 \
  --verbose
```

(ou `make verify-executable`, se você tem o repositório completo e já
rodou `make release`). Saída, igual à de `verify_release.py`: só `PASS`
ou `FAIL` em stdout. Se `nuitka`/`gcc` não estiverem disponíveis, use
`--skip-rebuild` para rodar só as checagens rápidas — isso produz um
**FAIL deliberado** no item de reconstrução (nunca um `PASS` silencioso
por pular a checagem mais forte).

## 4. O que isso prova, e o que não prova

**Prova:** que o `entropyforge.pyz` que você tem, o diretório do
executável standalone que você tem (Fase F), o código-fonte
`entropyforge/` que você tem, o script de build, a wordlist, e a versão
do próprio `independent-verifier`, todos batem EXATAMENTE com os hashes
registrados no `MANIFEST.txt` fornecido — e que a implementação BIP-39
bate com os vetores oficiais. Com `verify_executable.py` (seção 3b),
prova adicionalmente que o binário reconstruído A PARTIR do seu
`entropyforge/` bate exatamente com o binário que você recebeu — a
diferença entre "o hash bate com o que o manifesto diz" e "eu mesmo
reconstruí isso e deu igual".

**Não prova**, por si só, que o `MANIFEST.txt` fornecido é legítimo: se um
atacante controla tanto o artefato quanto o manifesto (ex.: ambos vieram
do mesmo mirror comprometido), `verify-release` vai dizer `PASS` para uma
combinação adulterada consistente consigo mesma — isso vale igualmente
para `verify_executable.py`, A MENOS que você use seu próprio
`--entropyforge-root` (nunca uma cópia que veio junto com o artefato sob
teste): é exatamente esse cenário — manifesto e artefato forjados juntos,
mas `--entropyforge-root` independente — que expõe a divergência (ver
`redteam/independent/scripts/run_executable_backdoor_lab.py` e
`docs/EXECUTABLE_RELEASE_CHECKS.md` seção 4 para a demonstração completa,
com hashes reais, de um backdoor sendo detectado desta forma). A força
real desta verificação vem de obter o `MANIFEST.txt` por um canal
INDEPENDENTE do artefato — por exemplo, conferindo o hash do manifesto
com outra pessoa que também o calculou, ou usando um commit Git
específico como referência de confiança. Ver
`docs/INDEPENDENT_VERIFIER.md` seção 6 para o motivo detalhado (a mesma
limitação estrutural de qualquer verificação por hash).

**Também não prova** nada sobre o hardware, o firmware, ou o sistema
operacional da máquina onde você vai rodar o `.pyz`/executável — ver
`docs/THREAT_MODEL.md` e `docs/PLATFORM_SUPPORT.md`.

**Sobre assinatura de código:** nenhum dos dois artefatos (`.pyz`,
executável) é assinado digitalmente por este projeto — ver
`docs/EXECUTABLE_RELEASE_CHECKS.md` seção 6 para o raciocínio completo
(gerar uma assinatura "de demonstração" sem uma chave real e sua devida
custódia seria pior do que não assinar). A verificação por hash acima é,
hoje, o mecanismo real de integridade deste projeto.

## 4b. Baixando e verificando os assets da GitHub Release (v1.0.0)

Desde a Fase G, você não precisa mais montar `release/` você mesmo: a
release `v1.0.0` já está publicada, com todos os artefatos prontos para
download, em
**https://github.com/DenniBR/EntropyForge-BIP39/releases/tag/v1.0.0**
(construída e publicada por `.github/workflows/release.yml`, nunca
manualmente — ver `RELEASE-CANDIDATE.md` seção "Release publicada no
GitHub" para o run de CI exato que a gerou).

Assets publicados (13 arquivos: 6 de conteúdo + um `.sha256` para cada um
+ o `SHA256SUMS.txt` combinado):

```
entropyforge-bip39-v1.0.0-linux-x86_64.tar.gz     (+ .sha256)
entropyforge-bip39-v1.0.0-windows-x86_64.zip      (+ .sha256)
entropyforge.pyz                                  (+ .sha256)
MANIFEST-linux-x86_64.txt                         (+ .sha256)
MANIFEST-windows-x86_64.txt                       (+ .sha256)
independent-verifier-bundle.zip                   (+ .sha256)
SHA256SUMS.txt
```

**1. Baixe os assets** (substitua por `curl`/navegador/qualquer cliente
HTTP; os nomes de arquivo abaixo são exatamente os publicados):

```sh
mkdir release_download && cd release_download
BASE=https://github.com/DenniBR/EntropyForge-BIP39/releases/download/v1.0.0
for f in SHA256SUMS.txt \
         MANIFEST-linux-x86_64.txt MANIFEST-linux-x86_64.txt.sha256 \
         MANIFEST-windows-x86_64.txt MANIFEST-windows-x86_64.txt.sha256 \
         entropyforge-bip39-v1.0.0-linux-x86_64.tar.gz entropyforge-bip39-v1.0.0-linux-x86_64.tar.gz.sha256 \
         entropyforge-bip39-v1.0.0-windows-x86_64.zip entropyforge-bip39-v1.0.0-windows-x86_64.zip.sha256 \
         entropyforge.pyz entropyforge.pyz.sha256 \
         independent-verifier-bundle.zip independent-verifier-bundle.zip.sha256; do
  curl -sSL -o "$f" "$BASE/$f"
done
```

**2. Confira os hashes** (contra o `SHA256SUMS.txt` combinado e/ou cada
`.sha256` individual — os dois cobrem o mesmo conjunto de 6 arquivos de
conteúdo, por redundância):

```sh
sha256sum -c SHA256SUMS.txt
for f in *.sha256; do sha256sum -c "$f"; done
```

Saída esperada: `OK` para todos. Se qualquer arquivo não bater, **pare —
não use este download**, baixe novamente, e se persistir, trate como uma
adulteração em trânsito ou uma release comprometida (nunca ignore um
`FAILED` aqui).

**3. Extraia e rode a checagem rápida e a checagem forte** (a partir do
SEU checkout git deste repositório, nunca de dentro de
`independent-verifier-bundle.zip` — ver seção 4 sobre por que isso
importa):

```sh
tar xzf entropyforge-bip39-v1.0.0-linux-x86_64.tar.gz
LINUX_DIST=entropyforge-bip39-v1.0.0-linux-x86_64

python3 independent-verifier/verify_release.py \
  --manifest MANIFEST-linux-x86_64.txt \
  --entropyforge-root /caminho/para/seu/checkout/entropyforge \
  --pyz entropyforge.pyz \
  --verifier-root /caminho/para/seu/checkout/independent-verifier/verifier \
  --build-script /caminho/para/seu/checkout/tools/build_pyz.py \
  --vectors /caminho/para/seu/checkout/tests/vectors/bip39_vectors.json \
  --executable-dist "$LINUX_DIST" \
  --verbose

python3 independent-verifier/verify_executable.py \
  --manifest MANIFEST-linux-x86_64.txt \
  --entropyforge-root /caminho/para/seu/checkout/entropyforge \
  --executable-dist "$LINUX_DIST" \
  --verbose
```

O mesmo par de comandos funciona para o Windows, trocando
`MANIFEST-linux-x86_64.txt`→`MANIFEST-windows-x86_64.txt` e
`--executable-dist` para o diretório extraído de
`entropyforge-bip39-v1.0.0-windows-x86_64.zip` — `verify_release.py`
detecta a plataforma/arquitetura lendo o cabeçalho PE do próprio `.exe`,
então funciona corretamente mesmo rodado a partir de Linux (você só não
consegue EXECUTAR o `.exe` fora de um Windows/Wine, nem rodar
`verify_executable.py` para ele sem um ambiente Windows com
`nuitka`+MSVC/MinGW64).

**Resultado esperado, honestamente reportado (não um "deveria passar"):**
`verify_release.py` — `PASS` para os dois manifestos.
`verify_executable.py` — as três primeiras checagens
(`hash_vs_manifesto`/`version`/`selftest`) `PASS`; a checagem de
reconstrução (`executavel.reconstrucao_a_partir_do_source`) pode dar
`FAIL` se o seu ambiente de build não for byte-a-byte idêntico ao que fez
o build original (mesmo problema documentado em
`docs/EXECUTABLE_BUILD.md` seção 4 — não é sinal de adulteração enquanto
as três primeiras checagens passarem).

## 5. Depois de um `PASS`

1. Transfira `entropyforge.pyz` E/OU o diretório do executável (e, se
   quiser, a pasta `release/` inteira, incluindo a documentação) para a
   máquina permanentemente offline — por mídia física (pendrive), nunca
   por rede. O executável tem a vantagem de não exigir Python instalado
   na máquina offline; o `.pyz` tem a vantagem de ser auditável byte a
   byte contra o source (ver `docs/EXECUTABLE_BUILD.md` seção 2).
2. Na máquina offline, **antes** de gerar qualquer mnemonic real, rode
   `python3 -I -B entropyforge.pyz selftest` (ou
   `./entropyforge-bip39-vX.Y.Z-linux-x86_64/entropyforge-bip39 selftest`,
   se for usar o executável) — isso não substitui a verificação acima
   (que exige o código-fonte, indisponível numa máquina minimalista), mas
   confirma que o artefato transferido não foi corrompido na
   transferência e passa nos testes de resposta conhecida. Para o
   executável, `sha256sum -c ../entropyforge-bip39-vX.Y.Z-linux-x86_64.sha256`
   (rodado de dentro da pasta do executável) confirma que TODOS os
   arquivos chegaram intactos, não só o binário principal.
3. Siga `docs/GENERATION_CEREMONY.md` para o fluxo completo de geração.
