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

Existem duas formas de seguir esta cerimônia:

- **Manual**, passo a passo, exatamente como descrito abaixo — dá
  controle e visibilidade total sobre cada etapa;
- **Semi-automatizada**, usando `tools/preflight_and_generate.py`, que
  automatiza os passos 3–7 (verificação de código, build, `.pyz`,
  independent-verifier, e `selftest`) e só invoca `generate` se todos
  passarem — ver a nota ao final de cada uma dessas seções.

## Os 15 passos

### 1. Máquina offline

Use um computador **dedicado**, sem conexão Wi-Fi/Ethernet/Bluetooth
ativa — idealmente um que nunca foi (e nunca será) conectado à internet.
Ver `docs/OPERATIONS.md` §1. `entropyforge generate` verifica isso
automaticamente (`guard.check_offline`) e se recusa a continuar se
detectar uma interface ativa — mas essa checagem só vê o que o *sistema
operacional* reporta; um SO comprometido que mentisse sobre isso não
seria pego (ver `docs/THREAT_MODEL.md`, "sistema operacional
comprometido"). A desconexão física é a garantia real.

### 2. Sistema live verificável

Prefira um sistema operacional live (ex.: Tails) iniciado de uma mídia
cuja assinatura/hash você conferiu antes de gravar. Isto está **fora do
alcance de qualquer software deste repositório** — é a raiz de confiança
sobre a qual tudo mais é construído (ver `docs/INDEPENDENT_VERIFIER.md`
§9, linha "Firmware / BIOS / UEFI" e "Hardware").

### 3. Verificação do código-fonte

Clone o repositório (ou confirme que já tem uma cópia) e revise, no
mínimo, os módulos críticos na ordem sugerida por `docs/AUDIT.md` §3
(`dice.py`, `wordlist.py`+`bip39.py`, `osrng.py`+`combine.py`, ...). Se
você já revisou esta versão exata antes (mesmo commit), pode pular a
releitura completa, mas confirme o hash do commit (`git log -1
--format=%H`) contra o que você lembra de ter revisado.

### 4. Verificação do build

```sh
make build   # gera entropyforge.pyz a partir do source local
make repro   # confirma que o build e reprodutivel (duas builds, hashes iguais)
```

Nunca baixe um `.pyz` pré-construído de qualquer fonte — construa
localmente, a partir do código que você revisou no passo 3
(`docs/AUDIT.md` §7).

### 5. Verificação do `.pyz`

Compare o artefato construído no passo 4 contra o source-tree, byte a
byte, usando o **independent-verifier** (não as próprias ferramentas do
EntropyForge — ver `docs/INDEPENDENT_VERIFIER.md` §1 para o porquê):

```sh
cd independent-verifier
python3 -B -c "
from pathlib import Path
from verifier.pyz_inspect import compare_pyz_to_source, check_bootstrap_main
r = compare_pyz_to_source(Path('../entropyforge.pyz'), Path('../entropyforge'))
print('bate com o source:', r.ok, r)
print(check_bootstrap_main(Path('../entropyforge.pyz')))
"
```

Se `r.ok` for `False`, **pare** — o artefato não corresponde ao source
revisado.

### 6. Execução do independent-verifier

Rode a suíte completa do verificador independente (não só a checagem do
`.pyz`) contra a sua cópia:

```sh
cd independent-verifier && python3 -B -m unittest discover -s tests -v
```

Todos os testes devem passar. Isto inclui a verificação independente da
wordlist (hash embutido no próprio verificador, não lido do
EntropyForge), a comparação BIP-39 cruzada, e a checagem de build
reprodutível.

**Nota:** os passos 3–6 são exatamente o que `tools/preflight_and_generate.py`
automatiza (exceto a revisão manual de código do passo 3, que continua
sendo humana por natureza). Rodar

```sh
python3 tools/preflight_and_generate.py --pyz entropyforge.pyz -- generate
```

executa os passos 5 (comparação `.pyz` vs. source), parte do 6 (checagem
de wordlist contra o hash oficial embutido) e o passo 7 (`selftest`)
automaticamente, e só invoca `generate` (passo 8 em diante) se tudo
passar — nunca prossegue silenciosamente em caso de falha.

### 7. Selftest

```sh
python3 -I -B entropyforge.pyz selftest
```

Deve reportar `RESULTADO GERAL: PASSOU`. Lembre-se do limite documentado
em `docs/AUDIT.md` §6: isto verifica corretude computacional, não
ausência de backdoors — é uma checagem de sanidade sobre uma instalação
em que você **já** confia por causa dos passos 3–6, não um substituto
para eles.

### 8. Coleta do d6

Tenha um d6 físico de boa qualidade, papel/caneta ou placa de metal
prontos, e um ambiente fisicamente privado (sem câmeras, sem ninguém
olhando por cima do ombro) — ver `docs/OPERATIONS.md` §1. Se quiser medir
o viés do seu dado antes de usá-lo para valer, rode `calibrate` com uma
amostra grande e descartável (`docs/OPERATIONS.md` §4) — os lançamentos
de calibração NUNCA são usados para gerar uma carteira.

### 9. Coleta de B

`entropyforge generate` lê 256 bits do CSPRNG do sistema operacional
(`os.getrandom`) automaticamente, sem nenhuma ação do operador. Se essa
leitura falhar por qualquer motivo, o programa aborta sem gerar nada (ver
`entropyforge/osrng.py`, fail-closed, sem fallback).

### 10. Combinação

`E = SHA-256(A ‖ B)`, calculada automaticamente. Nem `A`, `B`, nem `E` são
exibidos em nenhum momento.

### 11. Geração BIP-39

O mnemonic de 24 palavras é derivado de `E` automaticamente.

### 12. Anotação manual

O mnemonic aparece **uma única vez**, numa tela alternativa do terminal
(fora do histórico de rolagem). Anote com cuidado, em papel ou metal,
ANTES de pressionar Enter — ele não será mostrado de novo.

### 13. Conferência

Opcionalmente, redigite as 24 palavras quando o programa perguntar; ele
confirma "confere"/"não confere" sem nunca revelar qual palavra diverge
(para não vazar informação parcial sobre o mnemonic a quem estiver
observando a tela nesse momento).

### 14. Limpeza

O programa sobrescreve os buffers internos de `A`, `B`, `E` com zeros
antes de sair (`_zero()` em `cli.py`) — best-effort, não uma garantia
absoluta (ver `docs/DESIGN.md` §2.1 sobre limitações de linguagens
gerenciadas). Feche o terminal. Se o sistema tiver swap ativo, o programa
já terá avisado — trate a máquina como potencialmente tendo tocado o
disco de qualquer forma.

### 15. Desligamento

Desligue a máquina completamente (não hibernar/suspender — isso persiste
a memória no disco). Espere alguns minutos antes de religar, se possível
(mitiga parcialmente ataques de cold-boot à RAM, sem garantia —
`docs/OPERATIONS.md` §6).

## Artefatos que precisam ser verificados ANTES da primeira geração real

Esta lista é o que o operador precisa ter conferido, pelo menos uma vez
por versão do código usada, antes de confiar no resultado de `generate`:

1. o commit exato do source-tree (`git log -1 --format=%H`) e uma
   revisão humana de, no mínimo, `dice.py`, `wordlist.py`, `bip39.py`,
   `osrng.py`, `combine.py`, `guard.py`;
2. o hash do `.pyz` construído localmente reproduz entre duas builds
   (`make repro`);
3. o `.pyz` bate byte a byte contra o source-tree revisado
   (`verifier.pyz_inspect.compare_pyz_to_source`, independent-verifier);
4. a wordlist embutida bate com o hash oficial conhecido (embutido de
   forma independente em `verifier.wordlist_check`, não lido de nenhum
   arquivo do EntropyForge);
5. a suíte de testes completa do EntropyForge (`make test`) e do
   independent-verifier (`cd independent-verifier && python3 -B -m
   unittest discover -s tests`) passam inteiramente;
6. `selftest` do `.pyz` construído reporta `PASSOU`.

Ver `docs/RELEASE_SECURITY_CHECKLIST.md` para a versão em formato de
checklist rápido desta mesma lista.
