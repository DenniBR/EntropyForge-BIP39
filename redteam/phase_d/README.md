# Fase D — Revisão de Segurança Final (Release Candidate)

Material de ataque e re-derivação matemática da revisão de segurança
final, feita depois do red team (`redteam/scripts/`, `redteam/poc/`) e do
independent-verifier (`redteam/independent/`). O objetivo declarado desta
fase não era provar que o EntropyForge é perfeito, e sim descobrir até
onde ele pode realmente ser confiado — ver `docs/FINAL_SECURITY_REVIEW.md`
para o relatório completo.

## `scripts/`

| Script | O que faz |
|---|---|
| `independent_math.py` | Re-derivação matemática independente (sem importar `entropyforge/`) de todos os números citados em `docs/MATH.md`: entropia de Shannon do d6, n operacional, relação ENT/CS/MS do BIP-39, taxa de detecção de checksum, e a constante de Flajolet-Odlyzko. |
| `dice_models.py` | 12+ modelos adversariais de dado físico (uniforme, enviesado 17–30%, extremo, determinístico, periódico, PRNG com seed conhecida, Markov) rodados contra `entropyforge.stats.run_battery` real. |
| `min_entropy_search.py` | Bisseção + hill climbing com reinícios para encontrar a sequência i.i.d.-enviesada de menor min-entropia que ainda passa a bateria em n=127. |
| `independence_attack.py` | Dígitos exatos de √2 em base 6 (aritmética inteira, sem viés de conversão de base) como fonte de entropia zero que a bateria não consegue distinguir de aleatória. |
| `encoding_attack.py` | Reimplementação independente de `dice.encode`/`decode`, comparação byte a byte, bijeção exaustiva (n≤5), e busca por colisão/truncamento/overflow/endian/ambiguidade — encontrou o bug real corrigido em `dice.decode` (aceitava um prefixo `n=0` que `encode` nunca produz). |
| `hostile_python_env.py` | PYTHONPATH/module-shadowing, `.pth` malicioso, `sitecustomize`/`usercustomize`, `PYTHONHOME` bogus, `PYTHONSTARTUP` — contra o `.pyz` (`-I -B`) e contra o source em modo dev. |
| `build_attack.py` | Reprodutibilidade do build através de timezone/locale/umask/`PYTHONHASHSEED`/diretório/tmpfs/4 versões de Python (3.10–3.13). |

## `findings/`

Saída real e re-executável de cada script acima, mais três achados
específicos escritos à mão:

- `obfuscation_vs_static_scan` (em `redteam/independent/findings/`) — backdoor de socket ofuscado (nomes construídos em runtime) contra `static_scan.py` e `guard.py`.
- `backdoor_lab_supplementary_13_14_15.txt` (em `redteam/independent/findings/`) — canais de exfiltração via stdout, mensagem de exceção, módulo secundário pós-guard, e handler de sinal.
- `legit_vs_backdoor_strace_comparison.txt` (em `redteam/independent/findings/`) — comparação de observação de processo entre código legítimo e backdoors bloqueados pelo guard.

Nenhum script usa dados reais; toda entropia/seed usada é pública,
fictícia, ou vem de `os.getrandom` sem nunca ser reutilizada para gerar
uma carteira.
