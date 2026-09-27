# Checklist de segurança pré-geração

> Checklist rápido para o operador, imediatamente antes de rodar
> `generate` com a intenção de gerar uma carteira **real**. Para o
> procedimento completo passo a passo, ver `docs/GENERATION_CEREMONY.md`;
> para o que cada item garante ou não garante, ver `docs/MATH.md` e
> `docs/THREAT_MODEL.md`.
>
> **Este checklist nunca pede, mostra, ou registra nenhum segredo** (A, B,
> E, a sequência de dado, ou o mnemonic) — só confirma o ESTADO do
> ambiente e do artefato antes da geração.

## Antes de ligar a máquina

- [ ] **Mídia**: a mídia de boot (ex.: ISO do Tails) teve sua assinatura/
      hash conferidos antes de ser gravada.
- [ ] **Ambiente físico**: sem câmeras apontadas para a tela/mesa, sem
      outras pessoas olhando por cima do ombro, papel/caneta ou placa de
      metal prontos.

## Depois de ligar, antes de construir o artefato

- [ ] **Sistema**: rodando a partir da mídia live verificada, sem
      Wi-Fi/Ethernet/Bluetooth ativos (`ip link` para conferir).
- [ ] **Código**: o commit do repositório (`git log -1 --format=%H`)
      corresponde a uma versão que você (ou alguém em quem confia) já
      revisou linha a linha nos módulos críticos (`docs/AUDIT.md` §3).
- [ ] **Ambiente Python**: `python3 --version` ≥ 3.11; nenhum
      `hashlib.py`/`os.py`/outro módulo suspeito no diretório de trabalho
      ou em `PYTHONPATH` (relevante só se for rodar a partir do source;
      o `.pyz` com `-I` é imune a isso — ver
      `docs/INDEPENDENT_VERIFIER.md` §5).

## Build e verificação do artefato

Forma rápida (recomendada — automatiza os itens abaixo):

- [ ] **Release verificado**: `make release && make verify-release`
      imprime `PASS` (ver `docs/VERIFY.md` para o que isso prova e não
      prova).

Ou manualmente, item a item:

- [ ] **Build**: `make build` executado localmente, a partir do código
      revisado (nunca um `.pyz` baixado de terceiros).
- [ ] **Hash/reprodutibilidade**: `make repro` confirma que duas builds
      independentes produzem o mesmo SHA-256.
- [ ] **Verifier**: `cd independent-verifier && python3 -B -m unittest
      discover -s tests` passa 100%.
- [ ] **Wordlist**: o hash da wordlist embutida bate com o valor
      conhecido de forma independente pelo verificador (não só o valor
      que o próprio EntropyForge diz esperar — ver
      `verifier.wordlist_check.KNOWN_OFFICIAL_SHA256`).
- [ ] **Artefato**: `verifier.pyz_inspect.compare_pyz_to_source` confirma
      que o `.pyz` construído bate byte a byte com o source-tree
      revisado, incluindo o bootstrap `__main__.py`.

## Imediatamente antes de `generate`

- [ ] **Rede**: nenhuma interface ativa (o programa verifica isso
      automaticamente e se recusa a continuar, mas confirme
      independentemente).
- [ ] **Selftest**: `python3 -I -B entropyforge.pyz selftest` reporta
      `RESULTADO GERAL: PASSOU`.
- [ ] **Estado do dado**: o d6 físico foi inspecionado (sem rachaduras,
      desgaste visível, marcações); se possível, já foi calibrado
      previamente com `calibrate` (dados descartáveis) e o limite de
      Clopper-Pearson relatado é aceitável (`docs/OPERATIONS.md` §4).
- [ ] **Número de lançamentos**: você sabe quantos lançamentos vai fazer
      (o padrão calculado por `generate`, ou um valor maior — nunca
      menor que o mínimo teórico, `docs/MATH.md` §2.1).

## Durante e depois de `generate`

- [ ] **Gravação do mnemonic**: papel/metal em mãos ANTES de o mnemonic
      aparecer; ele só é mostrado uma vez.
- [ ] **Conferência** (opcional, recomendada): redigite as 24 palavras
      quando o programa perguntar.
- [ ] **Limpeza**: feche o terminal; se houver swap ativo (o programa já
      avisa), trate a máquina como potencialmente tendo tocado o disco.
- [ ] **Desligamento**: desligue completamente (não hiberne/suspenda);
      espere alguns minutos antes de religar, se possível.

## Se qualquer item acima falhar

**Pare.** Não use `--override-offline-check`, não ignore um `selftest`
com `[FAIL]`, não prossiga com um `.pyz` que `compare_pyz_to_source`
reportou como divergente. Nenhum desses overrides existe para uso
rotineiro — cada um exige confirmação explícita justamente para que não
sejam usados por hábito. Investigue a causa raiz antes de gerar uma
carteira real.

## Automação disponível (não substitui os itens acima, os automatiza)

```sh
python3 tools/preflight_and_generate.py --pyz entropyforge.pyz -- generate
```

Roda as checagens de wordlist, `.pyz` vs. source, e `selftest`
automaticamente, e só invoca `generate` se todas passarem. Não substitui
a revisão de código humana (item "Código" acima) nem os itens
operacionais/físicos (mídia, ambiente físico, rede, dado, anotação,
limpeza) — ver `docs/GENERATION_CEREMONY.md` para a explicação de por que
essas checagens específicas não podem ser automatizadas pelo próprio
EntropyForge.
