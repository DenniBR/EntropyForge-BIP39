# Guia operacional

Este documento é para quem vai efetivamente **usar** o programa para
gerar um mnemonic real. Leia `docs/THREAT_MODEL.md` primeiro: as
recomendações abaixo existem para reduzir riscos específicos listados lá.

## 1. Antes de começar

- **Plataforma:** use Linux (qualquer distro moderna, Tails e Debian live
  incluídos) — é a única plataforma com a checagem automática de rede
  offline funcional e com toda a auditoria de segurança deste projeto
  aplicada. Windows roda o código, mas sem essa checagem automática (a
  responsabilidade de garantir offline vira manual); Windows XP não roda
  o programa. Ver `docs/PLATFORM_SUPPORT.md` para a matriz completa antes
  de escolher o computador.
- **Ambiente:** idealmente, um computador dedicado, iniciado a partir de
  uma mídia live verificada (ex.: Tails), sem conexão Wi-Fi/Ethernet
  ativa, sem Bluetooth, sem outros processos abertos. Se possível, um
  computador que nunca foi (e nunca será) conectado à internet.
- **Dado físico:** um d6 de boa qualidade (dados de cassino/RPG
  balanceados são preferíveis a dados de brinde). Lance em uma superfície
  plana, de uma altura razoável, deixando o dado quicar/girar livremente.
  Não "ajude" o resultado.
- **Anotação:** papel e caneta, ou uma placa de metal para gravar as
  palavras — prontos ANTES de começar (você terá pouco tempo na tela).
- **Privacidade física:** ambiente sem câmeras apontadas para a tela ou
  para o papel, sem outras pessoas olhando por cima do ombro.

## 2. Obtendo e verificando o programa

```sh
git clone <url-do-repositorio>
cd EntropyForge-BIP39
python3 --version   # deve ser >= 3.11

# construa o artefato localmente (nunca baixe um .pyz pronto de outra pessoa)
make build

# opcional, mas recomendado: confirme que o build é reprodutível
make repro

# rode toda a suíte de testes
make test
```

## 3. Rodando os auto-testes

Antes de qualquer geração real, confirme que os componentes críticos
passam:

```sh
python3 -I -B entropyforge.pyz selftest
```

Se qualquer item falhar (`[FAIL]`), **não prossiga**. Isso indica uma
wordlist corrompida, um problema com o CSPRNG do sistema, ou uma
instalação de Python quebrada.

## 4. (Opcional, recomendado) Calibrando seu dado

Antes de usar um dado específico para uma geração real, você pode medir
seu comportamento estatístico com uma amostra grande e **descartável**
(esses lançamentos nunca são usados para gerar uma carteira):

```sh
python3 -I -B entropyforge.pyz calibrate --rolls 3000
```

Digite os lançamentos (não precisa ser oculto — são dados descartáveis).
Ao final, o relatório mostra o limite de confiança de Clopper-Pearson para
a probabilidade da face mais frequente do seu dado. Se esse limite for
muito maior que 1/6 ≈ 0,167 (ex.: acima de 0,25), considere trocar de
dado.

## 5. Gerando o mnemonic

```sh
python3 -I -B entropyforge.pyz generate
```

O programa vai:

1. Checar se há interfaces de rede ativas — se houver, **ele se recusa a
   continuar** por padrão. Desligue a rede e rode de novo. (Se você tem um
   motivo específico para prosseguir mesmo assim — não recomendado — use
   `--override-offline-check` e digite a frase de confirmação exata que
   ele pedir.)
2. Rodar os auto-testes de novo.
3. Mostrar quantos lançamentos ele recomenda (calculado na hora, não um
   número fixo) e pedir esse tanto de lançamentos do seu d6.
4. Você digita os resultados (1–6): pode colar tudo junto, sem espaços
   (`416235`), ou separado por espaços (`4 1 6 2 3 5`) — nunca misture os
   dois formatos na mesma entrada. A digitação **não aparece na tela**.
5. Ele roda a bateria estatística e mostra somente **ACCEPTED** ou
   **REJECTED** — nenhuma contagem de face nem veredito por teste é
   exibida durante uma geração real (isso minimiza ainda mais a
   informação revelada sobre a sequência; o relatório estatístico
   completo, com contagens e vereditos PASS/WARN/FAIL por teste, continua
   disponível só no modo `calibrate`, com dados sempre descartáveis). Se o
   resultado for REJECTED, ele avisa e pede uma confirmação explícita para
   continuar mesmo assim (não recomendado — prefira recomeçar com outro
   dado).
6. Ele lê 256 bits do gerador do sistema operacional.
7. Ele combina as duas fontes e calcula o mnemonic.
8. A tela muda para uma tela alternativa do terminal (isso evita que o
   mnemonic fique no histórico de rolagem do terminal) e mostra as 24
   palavras numeradas, **uma única vez**. Anote com cuidado.
9. Pressione Enter. A tela volta ao normal; **o mnemonic não será
   mostrado de novo por este programa**.
10. Opcionalmente, ele oferece conferir sua anotação: você redigita as 24
    palavras (também sem eco), e ele confirma se bate ou não — sem nunca
    mostrar quais palavras, se houver, estão erradas.

## 6. Depois de gerar

- Desligue a máquina. Se possível, espere alguns minutos antes de ligá-la
  de novo (mitiga parcialmente ataques de "cold boot" à RAM — sem
  garantia).
- Guarde a anotação em um local seguro, fisicamente, longe de câmeras,
  fotografias digitais, ou qualquer forma de armazenamento digital.
- Nunca digite o mnemonic em nenhum site, aplicativo de mensagens, ou
  formulário. Nenhuma entidade legítima jamais precisa da sua seed
  completa para "verificar", "recuperar" ou "sincronizar" uma carteira.
- Este programa não deriva a seed da carteira nem endereços — isso é
  trabalho do software da sua carteira, a partir do mnemonic. Leia a
  documentação dessa carteira para os próximos passos (incluindo, se você
  optar por usar uma, a passphrase BIP-39 — ver seção 7).

## 7. Sobre a passphrase BIP-39 (não gerada por este programa)

A especificação BIP-39 permite uma **passphrase opcional** (às vezes
chamada de "25ª palavra") que, combinada com o mnemonic, determina uma
seed completamente diferente. Este programa **não gera nem gerencia**
passphrase — isso é uma decisão e uma responsabilidade da carteira e do
usuário. Pontos importantes:

- **Mnemonic e passphrase são conceitos diferentes.** O mnemonic (as 24
  palavras) e a passphrase são combinados por PBKDF2-HMAC-SHA512 para
  produzir a seed final (`bip39.mnemonic_to_seed`, usada apenas nos testes
  deste projeto para validar contra vetores oficiais).
- **A passphrase muda TUDO.** Mnemonic + passphrase A produz uma carteira
  completamente diferente de mnemonic + passphrase B (ou sem passphrase).
  Esquecer a passphrase é equivalente a perder os fundos, mesmo com o
  mnemonic em mãos.
- **A passphrase NÃO é "entropia extra de graça".** Se você escolher uma
  passphrase memorável (uma frase, uma senha reutilizada), ela pode ter
  entropia muito baixa e virar o elo mais fraco de toda a construção —
  pior do que não usar passphrase nenhuma, se a alternativa fosse confiar
  só nos 256 bits deste programa. Se for usar uma passphrase com
  intenção de segurança real, ela precisa vir de uma fonte com entropia
  genuína e ser tratada com o mesmo cuidado que o mnemonic.
- **Nunca escreva a passphrase em log, arquivo ou nota digital** — a
  mesma disciplina do mnemonic se aplica a ela.

## 8. Solução de problemas

| Sintoma | Causa provável |
|---|---|
| `selftest` reporta `[FAIL] wordlist_integrity` | O arquivo `entropyforge/data/english.txt` foi alterado ou está corrompido; reclone o repositório e confira o hash em `docs/AUDIT.md` |
| `generate` se recusa dizendo "interface de rede ativa" | Desligue Wi-Fi/Ethernet/Bluetooth; alguns sistemas mantêm uma interface "up" mesmo sem cabo — confira `ip link` |
| `generate` diz que não é um TTY interativo | Você está rodando dentro de um pipe, redirecionamento, ou terminal não-interativo; rode diretamente em um terminal normal |
| A bateria estatística dá FAIL | Pode ser um dado realmente enviesado, uma técnica de lançamento problemática, ou erro de digitação; o mais seguro é recomeçar com um dado diferente, não usar o override |
| `os.getrandom` falha | O kernel não conseguiu fornecer entropia (raro); o programa se recusa a continuar em vez de usar uma fonte pior — tente novamente, ou investigue o estado do gerador de entropia do kernel (`cat /proc/sys/kernel/random/entropy_avail` no Linux) |
