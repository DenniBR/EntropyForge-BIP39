# redteam/

Material de suporte da auditoria adversarial registrada em
[`docs/REDTEAM.md`](../docs/REDTEAM.md). Nada aqui faz parte do produto
(`entropyforge/`); é ferramentaria de ataque e evidência.

- `scripts/` — os scripts de ataque (probes de guard, sequências
  adversariais, fuzzer BIP-39 independente, mutation testing, fuzzer de
  CLI). Todos podem ser executados de novo a qualquer momento:
  `python3 -B redteam/scripts/<nome>.py`. Nenhum altera o comportamento
  de produção; o `mutation_testing.py` aplica mutações temporárias e
  **sempre restaura o arquivo original**, mesmo em caso de erro.
- `findings/` — saída bruta capturada de cada script, para referência
  (a narrativa e as conclusões estão em `docs/REDTEAM.md`).
- `poc/` — reservado para provas de conceito adicionais, caso necessário
  no futuro.

Todos os dados usados (entropia, mnemonics, sequências de dado) são
fictícios: gerados por `os.getrandom`, seeds de PRNG documentadas, ou
vetores oficiais públicos do BIP-39. Nada aqui é uma seed real.
