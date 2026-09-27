# Modelo de ameaças

> Este documento assume que você já leu `docs/MATH.md` (o que é garantido
> matematicamente) e `docs/DESIGN.md` (a arquitetura). Aqui tratamos do que
> acontece quando as premissas físicas e ambientais falham.
>
> **Princípio central:** este software roda inteiramente em um único
> processo, em um único computador, operado por uma única pessoa. Tudo
> que roda nesse computador — firmware, kernel, interpretador Python,
> terminal, este programa — está no MESMO domínio de confiança. Se
> qualquer camada abaixo do programa for comprometida, o programa não tem
> como se defender sozinho. As mitigações abaixo reduzem superfície de
> ataque e aumentam a chance de detecção; elas não eliminam a necessidade
> de um ambiente confiável.

## 1. Ativos e fronteira de confiança

**Ativos:** a sequência de dados `A` (fonte física); a saída `B` do
CSPRNG; a entropia combinada `E`; o mnemonic de 24 palavras; a integridade
do código-fonte e da wordlist embutida.

**Fronteira de confiança:** não há uma. Firmware, kernel, interpretador
Python, terminal e este programa formam um único domínio. A separação em
duas fontes (`A`, `B`) protege contra a **falha independente de uma
fonte**, não contra o **comprometimento do ambiente** que as processa
(ver `docs/MATH.md`, seção 5.2, "onde isso não ajuda").

**Fora do escopo deste programa** (mas dentro do escopo de segurança da
carteira, tratado na documentação operacional): a derivação da seed a
partir do mnemonic (PBKDF2 + passphrase), a geração de chaves BIP-32, o
armazenamento de longo prazo do mnemonic (papel, metal), e o software da
carteira que efetivamente gasta os fundos.

## 2. Tabela de ameaças

Cada linha classifica a mitigação como: **detecção** (o programa percebe
e recusa continuar), **redução de superfície** (dificulta ou limita o
dano, sem eliminar o risco) ou **fora do alcance do software** (só o
ambiente/operador resolve).

| Ameaça | Descrição | Mitigação neste projeto | Classe |
|---|---|---|---|
| **Malware genérico** | Software malicioso já em execução no host durante a geração | Nenhuma — ver "sistema operacional comprometido" abaixo | fora do alcance do software |
| **Keylogger** (software ou hardware) | Captura das teclas digitadas (a sequência de dados, ou o mnemonic na reconferência) | Entrada sem eco reduz *observação visual* (ombro, câmera apontada para a tela), mas um keylogger de teclado captura as teclas independentemente do eco | reduz um vetor (observação visual); não mitiga o keylogger em si |
| **Sistema operacional comprometido** (rootkit, kernel modificado) | O SO vê tudo que o processo faz e pode alterar o comportamento de qualquer syscall, incluindo `getrandom` | Nenhuma mitigação eficaz é possível a partir de dentro do SO comprometido; a única defesa real é não confiar no SO (boot de mídia verificada, air-gap) | fora do alcance do software |
| **Kernel comprometido** | Caso específico do acima: o gerador de números aleatórios do kernel (`getrandom`) pode ser manipulado para devolver valores previsíveis | As checagens de sanidade (`osrng._reject_constant_output`, `diagnostic_two_reads_differ`) só pegam manipulação grosseira (saída constante); um kernel comprometido de forma sofisticada passa despercebido. A fonte A independente limita o dano SE o adversário não souber A | detecção parcial (falhas grosseiras) + redução de superfície (via A independente) |
| **BIOS/UEFI comprometido** | Firmware malicioso pode interceptar E/S antes do SO, ou plantar código que sobrevive à reinstalação do SO | Fora do alcance de qualquer software de aplicação. Mitigação real: Boot Guard/Secure Boot verificado, ou hardware dedicado sem histórico de reflash suspeito | fora do alcance do software |
| **Hardware comprometido** (implante, chip malicioso, teclado adulterado) | Componente físico que grava ou retransmite dados | Fora do alcance de software. Mitigação real: cadeia de custódia do hardware, inspeção física, usar um dispositivo dedicado nunca conectado à rede | fora do alcance do software |
| **Supply chain** (download adulterado, dependência maliciosa, conta de repositório comprometida) | O código publicado difere do código auditado | Zero dependências de terceiros em tempo de execução (só biblioteca padrão); build determinístico (`tools/build_pyz.py`) permite qualquer pessoa reproduzir o mesmo hash a partir do mesmo código-fonte; wordlist embutida com hash conferido (`docs/AUDIT.md`) | detecção (hash divergente é visível) + redução de superfície (0 deps) |
| **Binário adulterado** | O artefato `.pyz` distribuído foi alterado após a build | `make repro` reproduz o hash a partir do código-fonte; comparar o `SHA256SUMS` publicado com o hash local antes de rodar | detecção, se o usuário verificar |
| **Biblioteca/interpretador adulterado** | O próprio `python3` do sistema foi comprometido | Fora do alcance deste projeto — qualquer programa rodando sob um interpretador comprometido está comprometido. Mitigação real: usar a distribuição do Python de um SO live verificado (Tails) | fora do alcance do software |
| **Dado (d6) enviesado** | Fabricação imperfeita, desgaste, dado de má qualidade | Bateria estatística (T1, `docs/MATH.md` §8) detecta viés **grosseiro**; contra viés pequeno/moderado o poder é baixo em `n` operacional (`docs/MATH.md` §10.2). Mitigação real: usar dados de cassino/qualidade certificada; rodar `calibrate` com amostra grande para medir o próprio dado | detecção (grosseiro) + `calibrate` (medição, não prevenção) |
| **Lançamentos não independentes** | Técnica de lançamento problemática (dado não gira o suficiente, quica sempre igual), ou usuário "ajudando" o resultado | T2/T3/T4/T5 detectam dependência serial com poder razoável mesmo em `n` moderado (`docs/MATH.md` §10.3) contra dependência moderada a forte; dependência sutil pode escapar | detecção (moderado a forte) |
| **Erro humano / usuário digita em vez de lançar** | Usuário inventa números "aleatórios" de cabeça em vez de lançar o dado de verdade | Nenhum teste estatístico pode provar que uma sequência foi realmente lançada (uma pessoa cuidadosa pode produzir uma sequência que passa nos testes com entropia real ≈ 0 — ver `docs/MATH.md`, introdução da seção 8). Isto é fundamentalmente indetectável por software | fora do alcance do software |
| **Engenharia social** | Instruções falsas para digitar o mnemonic em um site, ou "compartilhar para verificar" | O programa nunca envia nada pela rede e nunca pede o mnemonic de volta, exceto a reconferência local opcional. Documentação operacional deve reforçar isso | redução de superfície + educação do operador |
| **Captura do mnemonic (visual)** | Câmera, pessoa por trás, gravação de tela | Exibição em tela alternativa do terminal (não fica no scrollback), uma única vez; recomenda-se ambiente fisicamente privado | redução de superfície |
| **Clipboard** | Copiar acidentalmente o mnemonic para a área de transferência (compartilhada por outros apps, sincronizada na nuvem em alguns SOs) | O programa nunca escreve no clipboard (nenhuma chamada a ferramentas de clipboard existe no código; verificado por `tests/test_security_ast.py` e pela ausência de qualquer integração desse tipo) | prevenção |
| **Captura de tela (screenshot/screen recording)** | Software de captura de tela ativo durante a exibição do mnemonic | Fora do alcance deste programa detectar software de terceiros rodando. Mitigação real: SO minimalista e confiável, sem processos desnecessários | fora do alcance do software |
| **Swap** | O kernel grava páginas de memória (que podem conter segredos) em disco | O programa verifica `/proc/swaps` e avisa se houver swap ativo (Linux); não pode desativar o swap nem impedir o kernel de usar a memória do processo como quiser | detecção + aviso (não prevenção) |
| **Arquivos temporários** | Segredos gravados incidentalmente em `/tmp`, cache, etc. | O programa nunca escreve arquivos (audit hook em `guard.py` bloqueia qualquer `open` em modo de escrita, `os.remove`, `shutil.*`, `tempfile.*`); verificado em `tests/test_guard.py` | prevenção (para este processo) |
| **Logs** | Registro incidental de segredos em logs do sistema, do shell, ou do próprio programa | O programa não usa o módulo `logging` (verificado por `tests/test_security_ast.py`) nem escreve em stdout/stderr nada além do relatório público e do mnemonic (uma vez, na tela alternativa); ver `tests/test_cli_generate.py` para a verificação automatizada de ausência de vazamento | prevenção (para este processo) |
| **Impressoras** | Enviar o mnemonic para uma impressora de rede pode deixar cópias em cache do driver, spool, ou na própria rede | O programa nunca imprime nada; a impressão é uma decisão do operador, fora do escopo do programa, e é desaconselhada na documentação operacional | educação do operador |
| **Máquinas virtuais** | Uma VM pode ter snapshots, memória compartilhada com o host, ou um hypervisor comprometido | Recomenda-se **não** usar VM para a geração real (prefira hardware dedicado e um SO live); se usada, snapshots tirados durante ou após a execução podem persistir a memória do processo (incluindo segredos que o Python não conseguiu zerar — ver limitação de memória abaixo) | fora do alcance do software; recomendação operacional |
| **Snapshots** (de VM, de sistema de arquivos, ou de hibernação) | Persistem o estado da memória (potencialmente com segredos) para o disco | Mesma limitação de "swap": o programa não controla isso. Evite hibernar a máquina com o processo em execução; prefira desligar completamente após o uso | fora do alcance do software |
| **Comprometimento físico** (acesso não autorizado ao equipamento) | Alguém com acesso físico pode instalar hardware/firmware malicioso, ou simplesmente ler o papel com o mnemonic | Fora do alcance de software. Segurança física do ambiente e da mídia onde o mnemonic é anotado é responsabilidade do operador | fora do alcance do software |
| **Manipulação da mídia de boot** | Um pendrive/ISO do SO live adulterado antes de dar boot | O programa não controla o processo de boot. Recomenda-se verificar a assinatura/hash da ISO do SO live antes de gravar a mídia (ex.: Tails publica assinaturas PGP) | fora do alcance do software; recomendação operacional |
| **Implementação incorreta** (bug no próprio código) | Erro de lógica no encoding, no BIP-39, no checksum, etc. | Vetores oficiais BIP-39 (24 vetores), comparação com a implementação de referência `python-mnemonic` em 10.000+ entropias e casos extremos, testes de propriedade (bijeção exaustiva), `selftest` executado antes de qualquer geração real. Ver histórico de incidentes reais abaixo | detecção (testes) |

### Incidentes reais que motivam a categoria "implementação incorreta"

- **CVE-2023-39910 ("Milk Sad")**: a biblioteca `libbitcoin-system` (usada
  pela ferramenta `bx`) gerava entropia de carteira usando o PRNG
  `mt19937` semeado com apenas 32 bits, tornando a busca por força bruta
  viável. Motivou o requisito 1 deste projeto (proibição de PRNG próprio,
  verificada estaticamente).
- **Trust Wallet (2023, extensão de navegador)**: uso de um gerador
  pseudoaleatório não criptográfico para gerar chaves, com espaço de
  busca pequeno o suficiente para permitir recuperação de fundos por
  terceiros.
- **Android `SecureRandom` (2013)**: uma falha na inicialização do
  OpenSSL em versões do Android levou a geração de chaves de carteiras
  Bitcoin com entropia insuficiente, causando perdas reais de fundos.
- **Debian OpenSSL (2008, CVE-2008-0166)**: uma modificação no código de
  inicialização de entropia do OpenSSL em pacotes Debian reduziu o espaço
  de chaves possíveis para poucos milhares de valores, afetando chaves
  SSH e SSL geradas no período.

Nenhum desses casos foi causado por uma falha na *matemática* do
algoritmo — todos foram falhas de *implementação* (fonte de entropia
errada, PRNG errado, ou inicialização incorreta). É essa classe de erro
que os testes de vetores/referência deste projeto visam capturar.

## 3. Computação quântica

**[SEM AFIRMAÇÕES ABSOLUTAS — ver `docs/MATH.md` para os limites do
argumento clássico]**

Duas primitivas diferentes estão em jogo e não devem ser confundidas:

1. **A entropia de 256 bits e o mnemonic BIP-39 em si.** O ataque
   genérico contra uma string aleatória de 256 bits é a busca exaustiva.
   O algoritmo de Grover permite, em um modelo de computação quântica
   idealizado, uma busca não-estruturada em um espaço de tamanho `N` com
   da ordem de `√N` avaliações em vez de `N`; para 256 bits isso significa
   da ordem de `2^128` avaliações quânticas em vez de `2^256` clássicas.
   Isto **não é o mesmo** que dizer que a segurança "cai para 128 bits" na
   prática: o modelo de custo de uma avaliação quântica de Grover contra
   SHA-256/BIP-39 é diferente do custo de uma avaliação clássica, envolve
   suposições sobre paralelização, correção de erros e engenharia de um
   computador quântico com essa capacidade — nenhuma das quais existe
   hoje, e sobre cujo cronograma futuro este documento não faz previsão.
2. **As chaves derivadas do mnemonic (fora do escopo deste programa).**
   Uma vez que uma chave pública ECDSA/Schnorr (secp256k1) é exposta
   *on-chain* (ex.: em um endereço já gasto), o algoritmo de Shor
   permitiria, em um computador quântico criptograficamente relevante,
   recuperar a chave privada correspondente a partir da chave pública —
   isso é qualitativamente diferente de "quebrar" a entropia da seed, e
   depende inteiramente da existência futura de tal computador, sobre a
   qual não fazemos previsão.

Este projeto **não afirma** que o mnemonic gerado é "resistente a
computadores quânticos", "impossível de quebrar" ou qualquer variante
absoluta dessas frases. O que se pode dizer, de forma sustentável: **sob o
conhecimento público atual** sobre algoritmos quânticos e a ausência de um
computador quântico criptograficamente relevante em operação, não há um
ataque conhecido e praticável contra uma seed de 256 bits gerada por este
processo — uma afirmação sobre o estado presente do conhecimento público,
não uma garantia permanente.

## 4. O que este documento não cobre

Ataques ao *software da carteira* (não a este gerador), à rede Bitcoin, a
contratos ou pontes, engenharia social pós-geração (ex.: phishing meses
depois pedindo a seed), ou coação física do operador ("wrench attack") —
todos reais, todos fora do escopo de um gerador de entropia offline.
