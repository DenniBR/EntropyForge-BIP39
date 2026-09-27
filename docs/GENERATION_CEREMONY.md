# Cerimônia de geração offline

> Este documento descreve o procedimento operacional completo para gerar
> um mnemonic **real**, passo a passo, do ponto de vista de "o que fazer",
> não "o que o software garante" (isso está em `docs/MATH.md` e
> `docs/THREAT_MODEL.md`) nem "por que confiar nisso" (isso está em
> `docs/INDEPENDENT_VERIFIER.md`, seção 9). Leia os três antes de operar
> com fundos reais. **Nenhum valor usado ao praticar este procedimento
> deve ser tratado como uma seed real** — pratique com `vector`/`selftest`
> (dados públicos), nunca gerando um mnemonic de verdade só para testar o
> fluxo.

## Duas máquinas, duas fases

Esta cerimônia usa **duas máquinas fisicamente separadas**, nunca uma só:

- **Máquina de PREPARO** — pode estar conectada à internet (precisa
  estar, ao menos para clonar o repositório). Todo o trabalho de
  verificação e build acontece aqui. **Nunca digite lançamentos de dado
  reais nesta máquina.**
- **Máquina de GERAÇÃO** — permanentemente offline, idealmente nunca
  conectada à internet em momento algum. É aqui, e só aqui, que o
  mnemonic real é gerado.

A transferência entre as duas é sempre por **mídia física** (pendrive),
**nunca por rede** — mesmo que as duas máquinas estejam na mesma sala.

Cada passo abaixo é rotulado **[CONECTADA]** (só faz sentido/só pode
acontecer na máquina de preparo, com rede disponível), **[OFFLINE]** (deve
acontecer já com toda rede desligada — na máquina de geração, ou na
própria máquina de preparo se você optar por usar só uma máquina com a
rede desligada durante os passos F–H) ou **[FÍSICO]** (uma ação no mundo
real, não em um terminal).

Existem duas formas de seguir os passos A–G (a fase de preparo):

- **Manual**, exatamente como descrito abaixo;
- **Semi-automatizada**, usando `tools/preflight_and_generate.py`, que
  automatiza a verificação de código/build/`.pyz`/independent-verifier/
  `selftest` e só invoca `generate` se tudo passar (ver a nota ao final
  da fase de preparo).

---

## Fase 1 — Preparo (máquina CONECTADA)

### A. [CONECTADA] Obter o código-fonte

```sh
git clone <url-do-repositorio>
cd EntropyForge-BIP39
git log -1 --format=%H   # anote o commit exato
```

### B. [CONECTADA ou OFFLINE] Revisão do código-fonte

Revise, no mínimo, os módulos críticos na ordem sugerida por
`docs/AUDIT.md` §3 (`dice.py`, `wordlist.py`+`bip39.py`, `osrng.py`+
`combine.py`, `guard.py`, ...). Se você já revisou esta versão exata
antes (mesmo commit), pode pular a releitura completa, mas confirme o
hash do commit contra o que lembra de ter revisado. Esta etapa não
depende de rede — pode ser feita com a rede já desligada, se preferir.

### C. [CONECTADA ou OFFLINE] Build e verificação de reprodutibilidade

```sh
make build   # gera entropyforge.pyz a partir do source local
make repro   # confirma que o build e reprodutivel (duas builds, hashes iguais)
```

Nunca baixe um `.pyz` pré-construído de qualquer fonte — construa
localmente, a partir do código revisado no passo B. Este passo não
precisa de rede.

### D. [CONECTADA ou OFFLINE] Montagem e verificação do release

```sh
make release          # gera MANIFEST.txt e monta release/ (o .pyz + docs)
make verify-release   # reconfere tudo do zero; DEVE imprimir PASS
```

Isto substitui (e automatiza) a comparação manual `.pyz`-vs-source e a
checagem de hash da wordlist contra o valor oficial embutido no
verificador — ver `docs/VERIFY.md` para o que exatamente `PASS` significa
(e não significa). Se o resultado for `FAIL`, **pare** — não continue
para a máquina de geração com um release que falhou a verificação.

### E. [CONECTADA ou OFFLINE] Suíte de testes completa

```sh
make test
cd independent-verifier && python3 -B -m unittest discover -s tests -v && cd ..
```

Todos os testes devem passar. **Nota:** os passos C–E são exatamente o
que `tools/preflight_and_generate.py` automatiza (exceto a revisão manual
de código do passo B, que continua sendo humana por natureza):

```sh
python3 tools/preflight_and_generate.py --pyz entropyforge.pyz -- generate
```

### F. [FÍSICO] Transferência para a máquina de geração

Copie **`entropyforge.pyz`** (o arquivo dentro de `release/`, ou o
`release/` inteiro se quiser levar a documentação junto) para um pendrive
e leve fisicamente até a máquina de geração. Nunca transfira por rede
(SSH, e-mail, nuvem, compartilhamento de rede) — isso reintroduziria
exatamente o canal que a máquina de geração existe para não ter.

### G. [OFFLINE] Verificação pós-transferência

Na máquina de geração, **antes** de gerar qualquer mnemonic real:

```sh
python3 -I -B entropyforge.pyz selftest
```

Deve reportar `RESULTADO GERAL: PASSOU`. Isto confirma que a transferência
não corrompeu o arquivo e que os testes de resposta conhecida (KATs)
passam nesta máquina especificamente — não substitui a verificação da
fase de preparo (que exige o código-fonte, normalmente indisponível numa
máquina de geração minimalista), é uma checagem adicional.

---

## Fase 2 — Geração (máquina OFFLINE, permanentemente desconectada)

### H. [FÍSICO] Desligar toda a rede

Desligue Wi-Fi, Ethernet e Bluetooth — pelo hardware sempre que possível
(botão físico, remoção do cabo), não só pelo sistema operacional.
`entropyforge generate` verifica isto automaticamente
(`guard.check_offline`) e se recusa a continuar se detectar uma interface
ativa — mas essa checagem só vê o que o *sistema operacional* reporta; um
SO comprometido que mentisse sobre isso não seria pego (ver
`docs/THREAT_MODEL.md`). A desconexão física é a garantia real. Ver
`docs/PLATFORM_SUPPORT.md` — esta checagem automática só existe em Linux;
em outras plataformas a responsabilidade é inteiramente manual.

### I. [FÍSICO] Preparar o ambiente e o dado físico

Um d6 de boa qualidade, papel/caneta ou placa de metal prontos, e um
ambiente fisicamente privado (sem câmeras, sem ninguém olhando por cima
do ombro) — ver `docs/OPERATIONS.md` §1 e a seção "A tela como raiz de
confiança residual" abaixo. Se quiser medir o viés do seu dado antes de
usá-lo para valer, rode `calibrate` com uma amostra grande e descartável
(`docs/OPERATIONS.md` §4) — os lançamentos de calibração NUNCA são usados
para gerar uma carteira.

### J. [OFFLINE] Rodar `generate`

```sh
python3 -I -B entropyforge.pyz generate
```

Repete o `selftest` e a checagem de rede automaticamente.

### K. [OFFLINE] Coleta dos lançamentos do d6

Digite os lançamentos pedidos quando solicitado — colados
(`"416235"`) ou separados por espaço (`"4 1 6 2 3 5"`), nunca os dois
formatos juntos. A digitação não aparece na tela.

### L. [OFFLINE] Coleta de B, combinação e geração BIP-39 (automático)

`generate` lê 256 bits do CSPRNG do sistema operacional
automaticamente — se essa leitura falhar, o programa aborta sem gerar
nada (fail-closed, sem fallback). Em seguida calcula `E = SHA-256(A ‖ B)`
e deriva o mnemonic de 24 palavras. Nem `A`, `B`, nem `E` são exibidos em
nenhum momento.

### M. [OFFLINE] Anotação manual

O mnemonic aparece **uma única vez**, numa tela alternativa do terminal
(fora do histórico de rolagem). Anote com cuidado, em papel ou metal,
ANTES de pressionar Enter — ele não será mostrado de novo.

### N. [OFFLINE] Conferência (opcional)

Redigite as 24 palavras quando o programa perguntar; ele confirma
"confere"/"não confere" sem nunca revelar qual palavra diverge (para não
vazar informação parcial a quem estiver observando a tela nesse momento).

### O. [FÍSICO] Limpeza

O programa sobrescreve os buffers internos de `A`, `B`, `E` com zeros
antes de sair — best-effort, **não uma garantia absoluta** (ver "O que
este programa NÃO promete sobre memória", abaixo). Feche o terminal. Se o
sistema tiver swap ativo, o programa já terá avisado — trate a máquina
como potencialmente tendo tocado o disco de qualquer forma.

### P. [FÍSICO] Desligamento

Desligue a máquina completamente (não hibernar/suspender — isso persiste
a memória no disco). Espere alguns minutos antes de religar, se possível
(mitiga parcialmente ataques de cold-boot à RAM, sem garantia —
`docs/OPERATIONS.md` §6).

---

## A tela como raiz de confiança residual

Depois de todas as verificações de código, build e artefato, **a tela do
operador continua sendo uma raiz de confiança residual que nenhum
software deste projeto consegue verificar ou proteger.** Isto é
deliberado e honesto, não um descuido: qualquer coisa que capture o que
aparece na tela no momento em que o mnemonic é exibido — uma câmera
apontada para o monitor, um keylogger de hardware entre o teclado e a
máquina, um software de captura de tela já instalado no sistema
operacional, um segundo monitor espelhado, um observador humano por cima
do ombro — vê exatamente o mesmo mnemonic que o operador vê,
independentemente de qualquer garantia que `entropyforge` ofereça sobre
não escrever em disco ou não usar rede. Nenhuma auditoria de código, hash
de build, ou verificação de artefato reduz esse risco: ele existe no
ambiente físico ao redor da tela, não no software. Mitigação é
inteiramente operacional (ambiente privado, sem câmeras, máquina cuja
integridade de hardware você confia) — ver `docs/THREAT_MODEL.md` e
`docs/INDEPENDENT_VERIFIER.md` §10, categoria de atacante 7 ("observa o
terminal").

## O que este programa NÃO promete sobre memória

O `bytearray` que guarda `A`, `B` e `E` é sobrescrito com zeros antes do
programa sair (`_zero()` em `cli.py`) — isso é best-effort, não uma
garantia. Em um interpretador Python gerenciado, cópias intermediárias de
dados sensíveis (por exemplo, o `str` retornado por `getpass.getpass()`
com os dígitos do dado, ou o `str` do mnemonic antes de ser dividido em
palavras) podem já ter existido como objetos imutáveis que o coletor de
lixo do CPython pode ou não já ter reaproveitado a memória, sem que o
programa tenha qualquer controle direto sobre o momento disso acontecer.
Este projeto nunca afirma "zeração garantida de memória" — apenas que
faz o que é razoavelmente possível na linguagem escolhida, e documenta
essa limitação em vez de prometer algo que não pode cumprir (ver
`docs/DESIGN.md` sobre a escolha de Python puro).

## Sobre a passphrase BIP-39 (25ª palavra)

`entropyforge` **nunca gera, sugere, nem pede** uma passphrase BIP-39
(também chamada de "25ª palavra"). Se você quiser usar uma, ela é
inteiramente manual e separada deste programa: você mesmo a escolhe (ou a
gera por outro meio de sua confiança), memoriza ou anota separadamente do
mnemonic, e a digita na carteira externa (Sparrow, hardware wallet, etc.)
no momento de importar o mnemonic — nunca aqui. Ver `docs/OPERATIONS.md`
§7 para a discussão completa (incluindo por que uma passphrase errada
produz uma carteira DIFERENTE, sem aviso, em vez de um erro).

## O que este projeto nunca vai ter (minimização de superfície de ataque)

Deliberadamente, e não por limitação técnica: **nenhuma exportação de QR
code, nenhuma funcionalidade de rede, nenhuma integração com exchanges ou
serviços de nuvem.** Cada uma dessas funcionalidades adicionaria uma
superfície de ataque nova (um QR code pode ser fotografado/reconstruído à
distância; qualquer código de rede é, por definição, incompatível com o
modelo de ameaça "totalmente offline"; qualquer integração externa exige
confiar em mais um sistema) sem necessidade: a única saída deste programa
é o mnemonic mostrado uma vez na tela, para ser anotado à mão. Ver
`docs/DESIGN.md` seção "D6. O que não é implementado no produto" para a
lista completa e o raciocínio de cada exclusão.

## Artefatos que precisam ser verificados ANTES da primeira geração real

Esta lista é o que o operador precisa ter conferido, pelo menos uma vez
por versão do código usada, antes de confiar no resultado de `generate`:

1. o commit exato do source-tree (`git log -1 --format=%H`) e uma
   revisão humana de, no mínimo, `dice.py`, `wordlist.py`, `bip39.py`,
   `osrng.py`, `combine.py`, `guard.py`;
2. `make verify-release` (ou `make repro` + a comparação manual
   `.pyz`-vs-source) reporta sucesso;
3. a suíte de testes completa do EntropyForge (`make test`) e do
   independent-verifier passam inteiramente;
4. `selftest` do `.pyz` transferido para a máquina de geração reporta
   `PASSOU`.

Ver `docs/RELEASE_SECURITY_CHECKLIST.md` para a versão em formato de
checklist rápido desta mesma lista, e `docs/VERIFY.md` para o guia
detalhado de `verify-release`.
