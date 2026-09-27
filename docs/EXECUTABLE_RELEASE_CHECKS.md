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

## 4. Teste de backdoor contra o pipeline de build

Ver seção dedicada em `docs/FINAL_SECURITY_REVIEW.md` ("Executable
Release Security") — resumo: um backdoor experimental foi inserido numa
cópia do source (`combine.py` vazando `A||B` por `stderr`, o mesmo tipo
de backdoor já catalogado em `docs/REDTEAM.md`/`docs/INDEPENDENT_VERIFIER.md`
para o `.pyz`), o executável foi construído a partir dessa cópia
adulterada, e confirmado que: (a) `selftest` continua reportando
`PASSOU` (nenhum KAT detecta o vazamento, mesma limitação estrutural já
documentada para o `.pyz`); (b) o hash do executável, do manifesto de
release, e do `verify-executable` (seção 8 de `docs/EXECUTABLE_BUILD.md`)
TODOS divergem do release legítimo e reportam `FAIL`.

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

## 7. Observação de processo (limpo vs. backdoor)

Ver seção dedicada em `docs/FINAL_SECURITY_REVIEW.md` ("Executable
Release Security") para o comparativo `strace` completo entre o
executável limpo e o executável com o backdoor experimental da seção 4.
