# Guia rápido (para quem não conhece Python)

Este documento é o caminho mais curto e mais simples para usar o
EntropyForge-BIP39 com o **executável** (você não precisa instalar
Python, nem saber o que é um `.pyz`, nem ler código). Ele tem duas
partes bem separadas porque a segurança deste programa depende disso:

- **SETUP ONLINE** — feito numa máquina normal, conectada à internet.
- **CERIMÔNIA OFFLINE** — feito numa segunda máquina, **totalmente
  desconectada da internet**, onde o mnemonic de verdade é gerado.

Se você quer o procedimento completo, com todas as opções e o raciocínio
por trás de cada passo (inclusive para quem sabe ler código Python e quer
revisá-lo antes de confiar), use `docs/GENERATION_CEREMONY.md` e
`docs/VERIFY.md` em vez deste documento — este aqui é a versão curta.

**Antes de tudo, três avisos que valem para o guia inteiro:**

1. Este programa **nunca** promete que a seed gerada é "inquebrável",
   "impossível de recuperar" ou algo do tipo — nenhuma ferramenta pode
   prometer isso honestamente. Ele documenta, sem esconder nada, o que
   verifica e o que não pode verificar (`docs/THREAT_MODEL.md`).
2. **Pratique primeiro com dados de teste**, nunca gerando uma carteira
   de verdade só para aprender o fluxo. Este guia mostra como praticar
   com segurança (seção "Praticar antes de valer").
3. Se qualquer passo abaixo falhar, resultar em erro, ou disser `FAIL`:
   **pare**. Não force, não ignore, não pule a etapa. Peça ajuda a
   alguém técnico antes de continuar.

---

## SETUP ONLINE (máquina conectada à internet)

Faça isto numa máquina comum — notebook, desktop — conectada à internet
normalmente. **Nunca gere um mnemonic de verdade nesta máquina.**

### 1. Baixe o release

Baixe a pasta `release/` deste projeto (o repositório completo, ou pelo
menos a pasta `release/` já montada por quem publicou a versão que você
vai usar). Dentro dela você vai encontrar algo parecido com:

```
release/
├── entropyforge-bip39-v1.0.0-linux-x86_64/   <- o programa em si
├── entropyforge-bip39-v1.0.0-linux-x86_64.sha256
├── MANIFEST.txt
├── RELEASE-CANDIDATE.md
├── VERIFY.md, EXECUTABLE_BUILD.md, ...
└── (mais documentação)
```

### 2. Confira que os arquivos não foram corrompidos

Abra um terminal dentro da pasta do executável e rode:

```sh
cd release/entropyforge-bip39-v1.0.0-linux-x86_64
sha256sum -c ../entropyforge-bip39-v1.0.0-linux-x86_64.sha256
```

Toda linha deve terminar em `OK`. Se alguma disser `FAILED`, o arquivo
foi corrompido ou alterado na transferência — baixe de novo, não use.

Se você (ou alguém técnico de sua confiança) sabe rodar Python e quer a
verificação mais forte — confirmar que o executável realmente corresponde
ao código-fonte revisado, não só que os arquivos não corromperam — use
`docs/VERIFY.md` (comando `verify_executable.py`) antes de prosseguir.
Essa etapa é opcional para o uso básico, mas é a única que realmente prova
que ninguém adulterou o programa entre o código e o binário.

### 3. Teste que o programa funciona (ainda com dados de teste, ainda online)

```sh
./entropyforge-bip39 --version
./entropyforge-bip39 selftest
```

O segundo comando deve terminar com `RESULTADO GERAL: PASSOU`. Isso
confirma que o programa passa nos seus próprios testes de resposta
conhecida — não confirma que ele é seguro para gerar fundos reais (isso
depende também do seu dado físico, do seu ambiente, e de você mesmo
seguir a cerimônia offline corretamente).

### 4. Transfira para a máquina offline

Copie a pasta inteira `entropyforge-bip39-v1.0.0-linux-x86_64/` (e, se
quiser, a documentação) para um pendrive, e desse pendrive para a máquina
que você vai usar na cerimônia offline. **Nunca por rede — sempre por
mídia física.**

---

## Praticar antes de valer (ainda com a máquina online, ou já offline)

Antes de gerar qualquer coisa real, pratique o fluxo com dados
**inteiramente públicos e fictícios**:

```sh
./entropyforge-bip39 vector --a-digits 111111111111111111111111 --b-hex 0000000000000000000000000000000000000000000000000000000000000000
```

Isso mostra exatamente o formato da saída (`E = SHA256(A||B)`, a
mnemonic) sem usar nenhum dado seu. **A mnemonic que aparece aqui é
pública** (qualquer pessoa que rode este mesmo comando recebe a mesma
saída) — nunca a use para guardar fundos reais.

Quando estiver confortável com o formato, siga para a cerimônia real.

---

## CERIMÔNIA OFFLINE (segunda máquina, sem internet)

Esta parte só deve acontecer numa máquina que:

- **não está, e nunca vai estar, conectada à internet** durante o
  processo (idealmente, desligue Wi-Fi/Ethernet/Bluetooth pelo hardware,
  não só pelo sistema operacional);
- tem só o executável (transferido no passo 4 acima) e nada mais que
  você não confie;
- está num lugar sem câmeras apontadas para a tela, sem outras pessoas
  olhando por cima do ombro.

Tenha papel e caneta (ou uma placa de metal para gravar a seed) **em
mãos antes de começar** — o programa mostra o mnemonic **uma única vez**.

### 5. Confirme, de novo, que está tudo certo (offline agora)

```sh
./entropyforge-bip39 selftest
```

Deve dizer `RESULTADO GERAL: PASSOU`, exatamente como no passo 3. Se for
diferente do que você viu online, **pare** — algo mudou no arquivo entre
as duas máquinas.

### 6. Rode o gerador de verdade

```sh
./entropyforge-bip39 generate
```

O programa vai:
- confirmar que não há rede ativa (e se recusar a continuar se houver —
  isso é proposital, não um bug);
- pedir para você jogar um dado físico de 6 faces várias vezes e digitar
  cada resultado;
- combinar isso com uma segunda fonte de aleatoriedade interna do próprio
  sistema operacional;
- mostrar o mnemonic de 24 palavras **uma única vez**.

**Escreva as 24 palavras imediatamente**, na ordem exata, em papel ou
metal. Não tire foto da tela. Não copie para um arquivo de texto. Não
digite em nenhum outro programa.

### 7. Depois de gerar

- Se o programa perguntar se você quer redigitar as 24 palavras para
  conferência, faça isso — é a forma de confirmar que você escreveu
  certo, sem ter feito uma segunda geração de verdade.
- Feche o terminal.
- Desligue a máquina completamente (não hiberne, não suspenda). Espere
  alguns minutos antes de religar, se for reutilizar essa máquina.
- Guarde o papel/metal com as 24 palavras num lugar seguro. Essa
  sequência de palavras **é** a sua carteira — qualquer pessoa que a veja
  pode acessar os fundos.

### 8. Confirme que nada ficou gravado

Nenhum arquivo é criado por este programa (verificado pela suíte de
testes do projeto, não só prometido). Ainda assim, como checagem
operacional: confirme que não existe nenhum arquivo novo na pasta onde
você rodou o programa, e trate a máquina como "já viu a seed" para
qualquer decisão futura sobre reutilizá-la ou descartá-la.

---

## Se algo der errado

- `selftest` disse `FALHOU` em vez de `PASSOU`: não use este binário.
  Volte para a máquina online, baixe de novo, refaça a verificação
  (passo 2).
- `generate` recusou por causa de rede ativa: desligue a rede de fato
  (pelo hardware, se possível) e tente de novo. Não use
  `--override-offline-check` a menos que você entenda exatamente o que
  essa opção desarma (ver `docs/PLATFORM_SUPPORT.md`).
- Qualquer mensagem de erro que você não entende: pare, não prossiga com
  uma geração real, peça ajuda a alguém técnico com este projeto em mãos.

## Para ir mais fundo

| Se você quer... | Leia |
|---|---|
| o procedimento completo, com todas as variações e o porquê de cada passo | `docs/GENERATION_CEREMONY.md` |
| verificar de forma forte que o binário bate com o código-fonte | `docs/VERIFY.md` |
| o checklist rápido antes de uma geração real | `docs/RELEASE_SECURITY_CHECKLIST.md` |
| entender o que este programa garante e o que não garante | `docs/THREAT_MODEL.md`, `docs/MATH.md` |
| como o executável foi construído e por quê | `docs/EXECUTABLE_BUILD.md` |
