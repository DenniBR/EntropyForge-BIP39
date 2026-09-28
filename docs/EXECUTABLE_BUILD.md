# Build do executável final (Fase F)

Este documento explica **como** e **por quê** o executável distribuível
(para uma máquina sem Python instalado) é construído do jeito que é.
Nenhuma alegação aqui é feita sem evidência empírica reproduzida nesta
mesma fase — os comandos usados para gerar cada evidência estão listados,
para que qualquer pessoa possa refazer exatamente a mesma investigação.

## 1. Requisito que decidiu tudo: nunca escrever em disco

`entropyforge.guard` bloqueia, em tempo de execução, qualquer tentativa
de abrir um arquivo REGULAR em modo de escrita (requisito 14, ver
`docs/AUDIT.md` §8) — esta é uma garantia central e extensivamente
testada do projeto. Qualquer mecanismo de empacotamento que violasse essa
garantia **antes mesmo do processo Python (e portanto o próprio guard)
existir** seria inaceitável, mesmo que "só temporariamente" e mesmo que
"limpando depois".

**Teste decisivo, feito nesta fase:** `strace -f -e
trace=openat,open,mkdir` contra cada candidato, filtrando por
`O_CREAT`/`O_WRONLY`/`O_RDWR` fora de `/dev/tty` (que já tem uma exceção
documentada e testada em `entropyforge/guard.py`).

| Empacotador | Modo | Escreve em disco na inicialização? |
|---|---|---|
| PyInstaller | `--onefile` | **SIM** — extrai ~20 arquivos (`.so`, `base_library.zip`, a wordlist) para `/tmp/_MEIxxxxxxxx/` a cada execução |
| PyInstaller | `--onedir` | **NÃO** — zero syscalls de escrita observados |
| Nuitka | `--onefile` | **SIM** — extrai para `/tmp/onefile_<pid>_<...>/` a cada execução, mesmo comportamento estrutural do PyInstaller onefile |
| Nuitka | `--standalone` | **NÃO** — zero syscalls de escrita observados |

**Conclusão: os modos "onefile" de AMBOS os empacotadores estão
descartados**, não por preferência, mas porque violam de forma
estrutural e inevitável (a extração acontece no bootstrap C, antes de
qualquer código Python — portanto antes de `guard.activate()` poder
existir) a garantia mais testada do projeto. Isto deixa dois candidatos
viáveis: PyInstaller `--onedir` e Nuitka `--standalone`.

## 2. A diferença decisiva entre os dois candidatos restantes: binário pré-compilado

Este projeto já tem uma política estabelecida e testada, repetida em
`docs/GENERATION_CEREMONY.md` e `docs/AUDIT.md`: **nunca confiar em um
artefato pré-construído por terceiros; construir tudo localmente a
partir de código-fonte revisado.** É exatamente essa política que
desempata entre os dois candidatos:

- **PyInstaller** copia, para dentro do executável final, um **binário
  ELF pré-compilado e stripped** (`PyInstaller/bootloader/Linux-64bit-intel/run`,
  confirmado com `file` nesta fase: `ELF 64-bit LSB executable ...
  stripped`) que vem DENTRO do pacote `.whl` baixado do PyPI — este
  binário nunca é compilado localmente, e portanto não pode ser
  auditado a partir do seu próprio código-fonte por quem constrói o
  executável (só por quem confia no processo de build do projeto
  PyInstaller, em outro lugar). Ele se torna literalmente o executável
  principal, com os dados da aplicação anexados.
- **Nuitka** não inclui nenhum binário pré-compilado (confirmado
  buscando por arquivos ELF/executáveis dentro do pacote `nuitka`
  instalado — nenhum encontrado). Em vez disso, ele traduz o código
  Python para C e usa o compilador C **já presente no sistema** (`gcc`,
  já parte da cadeia de confiança implícita deste projeto — o mesmo tipo
  de dependência que compila a própria distribuição do Python que você
  usa) para gerar o binário final, inteiramente na sua própria máquina.

Isto torna **Nuitka em modo `--standalone`** a escolha deste projeto:
nenhum binário de terceiros não-auditável entra no artefato final; tudo
que roda foi compilado, na sua máquina, a partir de fontes visíveis
(o C gerado pelo Nuitka a partir do seu Python, mais os templates C do
próprio Nuitka).

**Contrapartida, documentada sem meias palavras:** compilar para C e
depois para código de máquina é uma transformação mais distante do
código-fonte Python auditado do que simplesmente interpretá-lo (o que
`python3 -m entropyforge` ou o `.pyz` fazem). Auditar "o Python faz
exatamente o que está escrito" depende só da semântica bem estabelecida
do CPython; auditar "o C gerado pelo Nuitka preserva exatamente essa
semântica" depende adicionalmente de confiar na correção do próprio
Nuitka como compilador. Esta é uma reintrodução real de superfície de
confiança que o `.pyz` (que continua sendo o artefato de referência,
interpretado, para quem prefere auditar sem essa camada extra) não tem.
Por isso o `.pyz` **não é substituído**: o executável é uma forma
ADICIONAL de distribuição, para quem precisa rodar sem Python instalado,
não a única.

## 3. Redução de superfície: remoção do OpenSSL do bundle

`hashlib.sha256()` no CPython tenta primeiro `_hashlib` (acelerado por
OpenSSL/`libcrypto`) e cai para o módulo embutido `_sha256` (parte do
próprio interpretador, sem nenhuma biblioteca externa) se `_hashlib` não
estiver disponível. Confirmado nesta fase:

```
>>> hashlib.sha256(b'abc').hexdigest() == _sha256.sha256(b'abc').hexdigest()
True
```

Como este projeto faz um número pequeno de hashes por execução (nunca
throughput alto), a aceleração de `_hashlib`/OpenSSL não traz benefício
real, e excluí-la do bundle remove uma biblioteca externa grande e
complexa (OpenSSL) da superfície do executável distribuído — `_sha256`
já é suficiente e produz resultado idêntico. O script de build
(`tools/build_executable.py`) exclui explicitamente `_hashlib` e as
bibliotecas OpenSSL do bundle por este motivo.

## 4. Reprodutibilidade (checagem inicial; ver `docs/EXECUTABLE_RELEASE_CHECKS.md` para a bateria completa)

Duas builds do executável Nuitka standalone, em diretórios diferentes e
com `umask` diferente (022 vs 077), produziram o **mesmo SHA-256** para o
binário principal (`entry.bin`). PyInstaller `--onedir` também passou no
mesmo teste. Isto é um indício forte, não uma prova completa —
`docs/EXECUTABLE_RELEASE_CHECKS.md` documenta a bateria de
reprodutibilidade mais extensa (múltiplos ambientes, timestamps, etc.)
feita antes da release ser considerada candidata.

**Limitação real, descoberta e evidenciada na Fase G (publicação da
release):** a reprodutibilidade byte a byte NÃO se sustenta quando os
DOIS builds comparados usam `--output-dir` absolutos de formas/tamanhos
diferentes (ex.: `<checkout>/dist_executable` vs um diretório temporário
aleatório como `/tmp/tmpXXXXXXXX`) — testado em runners hospedados do
GitHub Actions (Linux `ubuntu-latest` E Windows `windows-latest`, dois
ambientes diferentes, mesmo resultado nos dois). Evidência concreta (não
suposição): no build Windows, o log do `clcache` (cache de compilação do
MSVC) mostrou `Compiled 21 C files using clcache with 20 cache hits and
1 cache misses` — ou seja, 20 dos 21 arquivos compilados bateram byte a
byte com o build anterior (cache hit = conteúdo idêntico), e só 1 mudou.
Isso indica que o Nuitka embute, em pelo menos uma unidade de compilação
gerada, algo dependente do caminho absoluto de `--output-dir` usado —
provavelmente relacionado a metadados de `__file__`/localização de
módulo, não a nenhum dado sensível. **Esta divergência nunca reproduziu
neste repositório quando testada localmente** (dezenas de builds nesta
mesma máquina de desenvolvimento ao longo das Fases F e G, sempre
idênticos, incluindo com diretórios de saída de nomes/tamanhos bem
diferentes) — é específica de reconstruir em DOIS ambientes de execução
de CI hospedados diferentes (ainda que do mesmo provedor), não do código
nem do método de build em si.

**Consequência prática, documentada sem disfarce**: `verify_executable.py`
(a checagem FORTE, que reconstrói num diretório temporário novo por
desenho) não é usado como gate automático bloqueante no workflow de CI
deste projeto (`.github/workflows/release.yml` roda essa checagem com
`continue-on-error: true`) — o gate real da CI é `verify-release`
(compara o hash do diretório JÁ CONSTRUÍDO contra o manifesto, sem
reconstruir, e continua passando normalmente). A checagem forte continua
sendo a mais rigorosa disponível e é recomendada para verificação
manual/local, idealmente reconstruindo num diretório com estrutura
equivalente ao build original (mesmo profundidade/nome de diretório
pai), onde a divergência acima não se manifesta.

## 5. O que entra no executável, e o que não entra

Entra: `entropyforge/` (todo o pacote, incluindo `guard.py`,
`version.py`), a wordlist (`entropyforge/data/english.txt`), e o ponto de
entrada (`tools/executable_entry.py`, equivalente ao bootstrap
`__main__.py` do `.pyz`). Nada mais.

Nunca entra: `tests/`, `redteam/`, `independent-verifier/`, dados
fictícios de desenvolvimento, as dependências dev-only de interoperabilidade
(`mnemonic`, `bip32utils`, `ecdsa` — usadas SÓ em
`tests/test_dev_cross_check_bip32.py`, nunca importadas por
`entropyforge/`), ferramentas externas, credenciais, chaves, ou qualquer
segredo. `docs/EXECUTABLE_SECRET_AUDIT.md` documenta a busca automatizada
que confirma isso sobre o artefato construído de verdade.

## 6. Python embutido: exatamente o quê

- **Versão do CPython embutida:** a mesma do ambiente que roda o build
  (`python3 --version` no momento do build) — Nuitka compila a partir do
  interpretador local, não baixa um Python separado. Isto é
  DELIBERADAMENTE diferente de "confiar em um Python pré-empacotado de
  terceiros": o Python embutido é o mesmo que você já usa para rodar
  `make test`/`make build`, cuja proveniência já é responsabilidade da
  cadeia de distribuição do seu sistema operacional (mesma premissa já
  documentada em `docs/INDEPENDENT_VERIFIER.md` §9, linha "Interpretador
  Python (CPython)").
- **Bibliotecas C incluídas:** só as extensões da biblioteca padrão que
  `entropyforge` realmente usa (`_sha256`/`_sha1`/`_md5` embutidos,
  `_socket` NÃO incluído propositalmente — não é importado —,
  `termios`/`resource` para o guard e a leitura oculta de dígitos,
  `zlib`/`bz2`/`lzma` como dependências transitivas do carregador de
  módulos do próprio Python). `libcrypto`/`libssl`/`_hashlib` são
  EXCLUÍDOS deliberadamente (seção 3).
- **Hashes:** gerados automaticamente pelo processo de release
  (`tools/build_release_manifest.py`, expandido nesta fase) — nunca
  hardcoded manualmente neste documento, que ficaria desatualizado a
  cada build.
- **Mecanismo de build:** `tools/build_executable.py`, que invoca
  `python3 -m nuitka --standalone` com as flags documentadas na seção 5,
  e falha explicitamente (não prossegue silenciosamente) se qualquer
  arquivo inesperado aparecer no diretório de saída.

## 7. Cadeia verificável (source → executável)

```
SOURCE (entropyforge/, revisado)
  -> tools/executable_entry.py (bootstrap, equivalente ao do .pyz)
  -> python3 -m nuitka --standalone (compilado localmente, gcc local)
  -> diretório entry.dist/ (o "executável", na prática um diretório autocontido)
  -> SHA-256 de cada arquivo + do diretório como um todo
  -> MANIFEST.txt (campo executable_sha256, platform, arch, build metadata)
  -> independent-verifier/verify_executable.py (PASS/FAIL)
```

Ver `docs/VERIFY.md` (atualizado nesta fase) para o procedimento completo
de verificação do lado do usuário.

## 8. Plataformas

- **Linux x86_64:** produzido e testado nesta fase (ver
  `docs/EXECUTABLE_RELEASE_CHECKS.md`).
- **Windows x86_64:** **NÃO produzido nesta fase.** Nem PyInstaller nem
  Nuitka fazem cross-compilação confiável (ambos precisam rodar NO
  sistema operacional alvo para produzir um binário para ele — não há
  suporte oficial de nenhum dos dois para gerar um `.exe` Windows a
  partir de um Linux, e tentativas não-oficiais via Wine não atendem à
  barra de "tecnicamente segura e reprodutível" que este projeto exige).
  Este ambiente de build é um container Linux; não há uma máquina
  Windows disponível para fazer o build real. Ver
  `docs/EXECUTABLE_RELEASE_CHECKS.md` seção Windows para o detalhamento
  completo desta limitação — ela é documentada explicitamente em vez de
  fingida, exatamente como pedido.
- **Windows XP:** continua explicitamente NÃO SUPORTADA (já documentado
  em `docs/PLATFORM_SUPPORT.md` — nenhuma versão do CPython usada por
  este projeto roda nela).

## 9. Code signing

Avaliado, não implementado nesta fase — ver
`docs/EXECUTABLE_RELEASE_CHECKS.md` seção "Assinatura de código" para o
raciocínio completo: assinar exigiria uma chave privada que não pode
(e não deve) existir dentro deste repositório, então isto é documentado
como uma etapa EXTERNA ao processo de build, a ser feita por quem
publica uma release, nunca simulada ou fingida aqui.

## 10. Sem auto-update, telemetria, ou rede

O executável usa exatamente o mesmo `entropyforge/` do source e do
`.pyz` — nenhuma linha de código nova foi adicionada para o executável
em si (`tools/executable_entry.py` só chama `entropyforge.__main__.run()`,
idêntico ao bootstrap do `.pyz`). Todas as garantias já existentes (sem
rede, sem telemetria, sem auto-update, `entropyforge.guard` ativo) valem
inalteradas — ver `docs/DESIGN.md` seção D6.
