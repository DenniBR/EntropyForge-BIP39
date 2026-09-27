# Teste de importação em carteira externa (Sparrow Wallet)

Este documento é uma **cerimônia de verificação**, não parte do produto:
um passo a passo para confirmar, manualmente, em uma carteira Bitcoin
externa e amplamente usada, que a seed BIP-39 que este programa entrega é
interpretada exatamente como qualquer carteira BIP-32/BIP-44 padrão
interpretaria. Ela usa uma **mnemonic inteiramente fictícia**, nunca uma
mnemonic gerada de verdade.

> **NUNCA envie fundos reais para qualquer endereço derivado da mnemonic
> abaixo.** Ela é pública (está neste repositório, em texto claro) e é
> usada exatamente por isso: só serve para provar que o software se
> comporta como esperado, nunca para guardar valor.

## 1. Por que este teste existe

`entropyforge` não implementa BIP-32 (não deriva chaves de carteira nem
endereços — ver `docs/DESIGN.md`, decisão D6). Ele entrega só a mnemonic
de 24 palavras. A responsabilidade de transformar essa mnemonic em chaves
e endereços é sempre de uma carteira externa (Sparrow, Electrum, um
hardware wallet, etc.). Este teste confirma que essa transformação, feita
por um software popular e independente, bate com o que uma segunda
implementação independente (usada em `tests/test_dev_cross_check_bip32.py`)
calcula a partir da mesma mnemonic.

## 2. Dados fictícios usados neste teste

Estes valores foram gerados a partir da entropia fixa e claramente
artificial `00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14
15 16 17 18 19 1a 1b 1c 1d 1e 1f` (32 bytes sequenciais, nunca uma saída
real de `entropyforge generate`), e são reproduzidos automaticamente por
`tests/test_dev_cross_check_bip32.py::FullPipelineFictitiousWalletTests`.
Se algum dia esse teste automatizado falhar, os valores abaixo estão
desatualizados e precisam ser recalculados junto.

**Mnemonic (24 palavras, passphrase BIP-39 vazia):**

```
abandon amount liar amount expire adjust cage candy arch gather drum
bullet absurd math era live bid rhythm alien crouch range attend journey
unaware
```

**Derivação esperada, caminho BIP-44 `m/44'/0'/0'/0/0` (Bitcoin, mainnet,
conta 0, endereço de recebimento 0):**

| Campo | Valor |
|---|---|
| Endereço (P2PKH, legado, começa com `1`) | `1K4RSBSNHRWCfb1WziRApwF8yCri43exY7` |
| Chave mestra estendida privada (`xprv`) | `xprv9s21ZrQH143K2VqrrWbcFGpF6RBabiU5bv9V8kgy1zfcQwq46iGuzhSbWPvA3ZxAFQ1jtDSEgnSvZjBBydNYobTUbsSBRxKKb5LMHzN1Cmi` |
| Chave mestra estendida pública (`xpub`) | `xpub661MyMwAqRbcEyvKxY8ccQkyeT251BBvy955w96aaLCbHkACeFbAYVm5MhASZnXjfHrgyDNGN7KXFg3qPWXHM6r7DGwShht9Pq726W46zjs` |

Se sua carteira mostrar um endereço de um tipo diferente por padrão (ex.:
SegWit nativo `bc1q...`, que começa em `m/84'/0'/0'/0/0`, não
`m/44'`), isso é esperado — configure explicitamente a derivação legada
(BIP-44, "Legacy"/"P2PKH") para reproduzir o valor acima, ou refaça o
cálculo do zero para o caminho que sua carteira usa por padrão
(`tests/test_dev_cross_check_bip32.py` mostra como).

## 3. Passo a passo no Sparrow Wallet

1. Baixe e verifique o Sparrow Wallet a partir do site oficial
   (`sparrowwallet.com`), seguindo a verificação de assinatura/hash que o
   próprio projeto Sparrow documenta — este passo não é diferente do que
   você faria para uma geração real, e é uma boa prática treiná-lo aqui.
2. Abra o Sparrow, escolha **File → New Wallet**, dê um nome claro como
   `TESTE-FICTICIO-NAO-USAR` (para nunca confundir com uma carteira real).
3. Em **Script Type**, escolha **Legacy (P2PKH)** (é o tipo que corresponde
   ao caminho `m/44'/0'/0'/0/0` usado acima).
4. Escolha a opção de importar por mnemonic/frase de recuperação (**New or
   Imported Software Wallet** → **BIP39**).
5. Cole a mnemonic de 24 palavras da seção 2 exatamente como está escrita
   (todas minúsculas, uma única linha, separadas por espaço simples).
   Deixe a passphrase BIP-39 (25ª palavra) em branco.
6. Confirme/importe. O Sparrow deve mostrar a `xpub` da carteira — compare
   com o valor da tabela acima (Sparrow normalmente mostra a `xpub` da
   conta, `m/44'/0'/0'`, não a `xpub` mestra `m` da tabela; se for o caso,
   use `tests/test_dev_cross_check_bip32.py` como referência para
   recalcular a `xpub` no nível exato que o Sparrow exibe, em vez de
   comparar níveis diferentes por engano).
7. Abra a lista de endereços de recebimento da conta. O primeiro endereço
   (índice 0) deve ser exatamente `1K4RSBSNHRWCfb1WziRApwF8yCri43exY7`.
8. **Resultado esperado:** o endereço bate. Isso confirma que a mnemonic
   entregue por `entropyforge` é interpretada por uma carteira externa
   popular exatamente como as duas implementações independentes usadas em
   `tests/test_dev_cross_check_bip32.py` (`mnemonic` para a seed, e a
   verificação cruzada de BIP-32 daquele arquivo) preveem.
9. Se o endereço **não bater**: pare, não repita este teste com uma
   mnemonic gerada de verdade, e abra uma investigação (comece por
   conferir se a passphrase ficou em branco, se o tipo de script é
   Legacy/P2PKH, e se a mnemonic foi colada sem espaços extras ou
   quebras de linha).
10. Ao terminar, delete a carteira de teste do Sparrow (**Right-click →
    Delete Wallet**) — ela nunca deve ficar salva ao lado de uma carteira
    real, mesmo sendo fictícia, para não gerar confusão futura.

## 4. O que este teste NÃO prova

- Não prova que o CSPRNG do sistema operacional ou o dado físico usados
  numa geração real são bons — isso é responsabilidade das outras
  camadas do projeto (`docs/MATH.md`, `docs/THREAT_MODEL.md`).
- Não prova que o Sparrow Wallet (ou qualquer carteira) está livre de
  bugs ou backdoors — é uma dependência externa, fora do controle deste
  projeto.
- Não substitui rodar `tests/test_dev_cross_check_bip32.py` (que cobre
  muito mais casos, incluindo o vetor de teste oficial da especificação
  BIP-32 e centenas de entropias aleatórias) — este documento é a versão
  manual, de uma amostra, para quem quer ver o resultado com os próprios
  olhos numa carteira de verdade antes de confiar no projeto.
