"""independent-verifier: verificacao externa e independente do
EntropyForge-BIP39.

Regra de ouro deste pacote: NUNCA importar `entropyforge` para fazer uma
verificacao (hashing, wordlist, BIP-39, escaneamento estatico). A UNICA
excecao explicita e `bip39_compare.py`, que importa `entropyforge.bip39`
de proposito, para COMPARAR sua saida com a de uma implementacao
independente e com vetores oficiais -- nunca para calcular o resultado
"correto" que o resto do verificador confia.

Ver docs/INDEPENDENT_VERIFIER.md (na raiz do repositorio EntropyForge-BIP39)
para a arquitetura completa, o modelo de ameaca, e a raiz de confianca.
"""

__version__ = "1.0.0"
