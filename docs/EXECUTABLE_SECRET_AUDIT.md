# Auditoria de segredos no executável construído (Fase F)

Busca automatizada, reproduzível, sobre o executável Linux x86_64
realmente construído por `tools/build_executable.py` (não uma alegação
sobre o que "deveria" estar lá).

## 1. Inventário de arquivos

```sh
find dist_executable/entropyforge-bip39-v1.0.0-linux-x86_64 -type f
```

18 arquivos: o binário principal (`entropyforge-bip39`), 12 extensões da
biblioteca padrão do Python (`.so`), 4 bibliotecas C transitivas
(`libbz2`, `libexpat`, `liblzma` — dependências do próprio interpretador
Python para descompressão/parsing, não deste projeto), e a wordlist
(`entropyforge/data/english.txt`). **Nenhum arquivo de `tests/`,
`redteam/`, ou `independent-verifier/`** — confirmado tanto pela lista
acima quanto por uma checagem automática em `tools/build_executable.py::_assert_no_dev_only_content`,
que falha o build se qualquer diretório desses aparecer.

## 2. Busca por padrões de credencial

```sh
grep -rlaE "BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}|xoxb-|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}" dist_executable/.../
```

Zero ocorrências (chaves privadas PEM, credenciais AWS, tokens Slack/GitHub/
estilo-OpenAI).

## 3. Busca por valores fictícios de desenvolvimento

Confirmado que NENHUM destes vazou para o executável (todos existem só em
`tests/`/`redteam/`/`docs/`, nunca em `entropyforge/`):

- a mnemonic fictícia de `docs/WALLET_IMPORT_TEST.md`/
  `tests/test_dev_cross_check_bip32.py` ("abandon amount liar ...");
- o canário de `redteam/scripts/cli_fuzz.py` (`CANARY_SECRET_...`);
- a seed de fuzzing documentada (`20260927`).

## 4. Caminhos absolutos da máquina de build

```sh
strings dist_executable/.../entropyforge-bip39 | grep -E "/home/[a-zA-Z0-9_-]+|/root/|/Users/"
```

Zero ocorrências — o Nuitka não embutiu o caminho absoluto do diretório
onde o build rodou (relevante tanto para privacidade quanto para
reprodutibilidade: um caminho de build embutido mudaria o hash entre
máquinas diferentes).

## 5. Varredura ampla por palavras-chave sensíveis

```sh
strings <cada .so e o binário principal> | grep -iE "password|private_key|api[_-]?key|secret_key"
```

As únicas ocorrências são strings de documentação da própria `glibc`
(`gr_passwd - group password (encrypted)`, de `<grp.h>`/`<pwd.h>`) —
sobre o formato do arquivo `/etc/group` do sistema operacional, nada
relacionado a este projeto. Nenhuma outra ocorrência.

## 6. Integridade da wordlist embutida

```sh
sha256sum dist_executable/.../entropyforge/data/english.txt
```

`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` —
bate exatamente com o hash oficial conhecido de forma independente
(`independent-verifier/verifier/wordlist_check.py::KNOWN_OFFICIAL_SHA256`).

## Conclusão

Nenhum segredo real ou fictício, credencial, token, chave, ou dado de
desenvolvimento foi encontrado no executável construído. Esta é uma
busca por padrões conhecidos, não uma prova de ausência de qualquer
vazamento possível — a garantia estrutural mais forte continua sendo que
`entropyforge/` (o único código-fonte do produto incluído) nunca lida com
segredos fora do fluxo `generate`, e que esse fluxo nunca grava em disco
(`entropyforge.guard`, testado extensivamente em `tests/test_guard.py` e
`tests/test_cli_generate.py`).
