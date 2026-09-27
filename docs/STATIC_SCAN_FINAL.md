# Revisão estática final (Fase E)

Varredura estática final do pacote `entropyforge/` (o código que é
efetivamente empacotado em `entropyforge.pyz` e roda em produção),
usando o scanner AST + textual independente
(`independent-verifier/verifier/static_scan.py`, que não importa nada de
`entropyforge/` — ver `docs/INDEPENDENT_VERIFIER.md` §3). Reproduzível:

```sh
python3 -c "
import sys; sys.path.insert(0, 'independent-verifier')
from pathlib import Path
from verifier.static_scan import scan_directory, summarize
findings = scan_directory(Path('entropyforge'))
print(len(findings), summarize(findings))
"
```

**Resultado: 85 ocorrências, 0 confirmadas como reais.** Todas as 85 são
falsos positivos do scanner (que sinaliza qualquer aparição textual de um
termo sensível, mesmo dentro de comentários/docstrings que só *descrevem*
um controle de segurança) — nenhuma corresponde a uso real de rede,
execução externa, escrita em disco fora do permitido, ou ofuscação.
Explicado categoria por categoria:

| Categoria | Ocorrências | Explicação |
|---|---|---|
| `execucao_externa` (7) | `__main__.py:16`, `guard.py:11,41-43,65` | Todas dentro de **docstrings/comentários** ou da própria definição do conjunto `_BLOCKED_EVENTS`/`_BLOCKED_EVENT_PREFIXES` de `guard.py` — os termos `subprocess`/`exec`/`system`/`posix_spawn` aparecem como *nomes de eventos que o guard bloqueia* (strings literais numa lista de bloqueio) ou em prosa explicando isso, nunca como uma chamada real. Confirmado pelo teste AST independente `tests/test_security_ast.py` (nenhum `import subprocess`/`os.system` real em `entropyforge/`) e pelo teste dinâmico `tests/test_guard.py` (esses eventos são efetivamente bloqueados, não usados). |
| `arquivo_generico` (58) | `cli.py` (maioria), `guard.py:193` | A esmagadora maioria são chamadas a `io.write(...)` — o método da própria abstração `TerminalIO` que escreve texto NA TELA (nunca em disco) — e o termo textual `"write"` aparecendo nessas mesmas linhas. A única chamada real a `open()` fora de comentários (`guard.py:193`) é `open(os.path.join(base, iface, "operstate"), "r")` — leitura (modo `"r"`, nunca escrita) de um arquivo virtual do kernel Linux (`/sys/class/net/*/operstate`) para a checagem de interfaces de rede ativas; não é gravação em disco, e o próprio guard permitiria leitura de qualquer forma (só bloqueia abertura em modo de escrita). |
| `clipboard` (2) | `cli.py:11,436` | Ambas são comentários/mensagens que dizem explicitamente que o programa **nunca** usa clipboard (`"Nenhuma funcao aqui grava em disco, rede ou clipboard"`, `"Nenhum dado foi gravado em disco, rede ou clipboard."`) — o scanner sinaliza a palavra, não o comportamento; o comportamento real (ausência de qualquer API de clipboard) é confirmado por `tests/test_security_ast.py` (import de `tkinter` proibido) e pela ausência estrutural de qualquer outra via na biblioteca padrão. |
| `reflexao` (6) | `guard.py:37`, `wordlist.py:19,28,42` | `guard.py:37` é `getattr(os, _name, 0)`, usado para montar a máscara `_WRITE_FLAGS` a partir de nomes de constante (`O_WRONLY`, `O_CREAT`, ...) que podem não existir em toda plataforma — introspecção defensiva e estática (a lista de nomes é um literal fixo no próprio código, nunca vinda de entrada externa), não execução dinâmica de código arbitrário. `wordlist.py` usa `importlib.resources`, a forma padrão e recomendada da biblioteca padrão para ler um arquivo de dados empacotado (a wordlist) de forma portável entre rodar a partir do source e rodar a partir do `.pyz` — não é reflexão perigosa. |
| `rede` (3) | `guard.py:10,21,40` | Comentários/docstrings descrevendo que sockets são bloqueados (a palavra `"socket"` em prosa) — confirmado sem `import socket` real por `tests/test_security_ast.py`. |
| `bibliotecas_nativas` (4) | `guard.py:12,45,46` | Comentários/definição do bloqueio de `ctypes.dlopen`/`ctypes.dlsym` (strings literais na lista de eventos bloqueados) — confirmado sem `import ctypes` real. |
| `arquivo_temporario` (4) | `guard.py:79,80` | Definição do bloqueio de `tempfile.mkstemp`/`tempfile.mkdtemp` (strings literais em `_BLOCKED_EVENTS`) — o módulo `tempfile` nunca é importado por `entropyforge/`. |
| `http_dns` (1) | `stats.py:251` | Falso positivo puro de linguagem natural: a palavra portuguesa "resolver" (verbo, "to resolve") numa frase sobre empates estatísticos ("não há empates a resolver"), nada a ver com resolução de DNS. |

**Conclusão:** nenhuma das 85 ocorrências corresponde a um uso real de
rede, execução externa, escrita em disco fora do permitido, acesso a
clipboard, biblioteca nativa, ou ofuscação — cada uma foi verificada
manualmente (tabela acima) e cruzada contra os testes dinâmicos/AST
independentes já existentes (`tests/test_security_ast.py`,
`tests/test_guard.py`). Isto é consistente com, e não substitui, a mesma
conclusão já registrada em `docs/INDEPENDENT_VERIFIER.md` §3 e §13 sobre
os limites estruturais de qualquer scanner estático (não pega ofuscação
dinâmica de nomes, ex. `getattr(os, "sys"+"tem")`).

## Escopo adicional: `tools/`

`tools/` (scripts de desenvolvimento/build/cerimônia — nunca empacotados
em `entropyforge.pyz`, fora do artefato distribuído) foi escaneado à
parte: 18 ocorrências, todas esperadas dado o propósito de cada script —
`preflight_and_generate.py` usa `subprocess`/`execv` deliberadamente (é a
sua função: invocar o `.pyz` construído como um processo separado, após
checagens — já auditado em `docs/FINAL_SECURITY_REVIEW.md` §11);
`build_pyz.py` menciona `zlib` só em um comentário sobre por que usa
`ZIP_STORED` (sem compressão, para não depender da versão da lib);
`assemble_release.py`/`build_release_manifest.py`/`simulate_power.py`
usam `pathlib.Path` (manipulação de caminho, não um risco). Nenhum destes
scripts roda automaticamente durante `generate` — todos exigem invocação
explícita e deliberada pelo operador.
