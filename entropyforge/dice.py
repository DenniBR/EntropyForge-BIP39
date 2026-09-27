"""Validacao e codificacao binaria da fonte A (lancamentos de d6 fisico).

Um lancamento e um digito ASCII em '1'..'6'. Internamente (para
`validate_rolls`/`encode`/`decode`), a sequencia inteira e sempre uma
string desses digitos, sem separadores -- essa e a unica forma que essas
tres funcoes aceitam, e permanece assim deliberadamente (bijecao simples,
sem uma etapa de parsing entre a entrada e a validacao).

A ENTRADA DO OPERADOR (o que ele digita/cola no terminal) pode estar num
de dois formatos human-friendly, normalizados para o formato compacto
acima por `normalize_dice_input` ANTES de chegar em `validate_rolls`/
`encode` -- ver essa funcao para os dois formatos aceitos (compacto e
separado por espacos) e a regra exata de rejeicao de ambiguidade (Fase E,
requisito 6). O CLI le esses caracteres de um TTY sem eco (ver cli.py);
este modulo so lida com a string ja capturada.

A codificacao binaria (funcao `encode`) implementa a decisao D2 do design
(docs/DESIGN.md): uma bijecao entre {1..6}^n e um intervalo de inteiros,
com um prefixo de comprimento para tornar a codificacao injetora entre
sequencias de tamanhos diferentes. Ela NAO atribui mais bits de entropia
a fonte do que ela realmente tem: a contabilidade de entropia e sempre
feita por `entropy_calc.py` a partir de `n`, nunca a partir do tamanho em
bytes do resultado de `encode`.
"""

from __future__ import annotations

ALPHABET = "123456"

# 65535 e o maior valor representavel no prefixo de 2 bytes (uint16) usado
# por `encode`. Este e um limite ESTRUTURAL da codificacao (nao uma
# recomendacao operacional): mesmo o minimo teorico para 256 bits (secao
# entropy_calc.py) fica na casa das centenas de lancamentos, muito abaixo
# disto.
MAX_ROLLS = 0xFFFF


class DiceInputError(ValueError):
    """Sequencia de lancamentos invalida ou fora dos limites suportados."""


def normalize_dice_input(raw: str) -> str:
    """Normaliza a entrada BRUTA de um operador para o formato compacto
    exigido por `validate_rolls`/`encode` (Fase E, requisito 6).

    Dois formatos sao aceitos, sem ambiguidade entre eles:

      - COMPACTO: digitos colados, sem nenhum espaco em branco em
        lugar nenhum da string (ex.: "416235").
      - SEPARADO POR ESPACOS: exatamente um digito por token, separados
        por qualquer quantidade de espacos/tabs (ex.: "4 1 6 2 3 5").

    Qualquer entrada que misture os dois formatos, ou tenha um token com
    mais ou menos de um caractere no formato separado por espacos, e
    rejeitada explicitamente aqui como AMBIGUA (`DiceInputError`) em vez
    de o programa tentar adivinhar a intencao do operador. A mensagem de
    erro nunca inclui o conteudo dos caracteres recebidos, so o
    comprimento do token invalido (mesma politica de `validate_rolls`).

    Um separador que NAO seja espaco em branco (virgula, ponto-e-virgula,
    etc.) nao e detectado por esta funcao especificamente -- por nao
    conter nenhum whitespace, essa entrada e tratada como "formato
    compacto" e repassada adiante sem alteracao. Ela nunca e aceita de
    forma silenciosa, porem: `validate_rolls`, chamada logo em seguida
    pelo chamador, rejeita esses caracteres (por nao estarem em '1'..'6')
    com um erro de "caractere invalido", so que sem a palavra especifica
    "ambigua". O efeito pratico (a sequencia inteira e sempre rejeitada)
    e o mesmo.

    Esta funcao NAO valida se os digitos estao em '1'..'6' -- isso
    continua sendo responsabilidade exclusiva de `validate_rolls`,
    chamada depois desta normalizacao.
    """
    if raw is None:
        raise DiceInputError("entrada vazia")
    stripped = raw.strip()
    if not stripped:
        raise DiceInputError("sequencia de lancamentos vazia")
    if any(c.isspace() for c in stripped):
        tokens = stripped.split()
        for tok in tokens:
            if len(tok) != 1:
                raise DiceInputError(
                    "entrada separada por espacos deve ter EXATAMENTE um "
                    f"digito por token; encontrado um token de {len(tok)} "
                    "caractere(s) -- formato ambiguo, rejeitado (nunca "
                    "misture o formato compacto com o separado por espacos)"
                )
        return "".join(tokens)
    return stripped


def validate_rolls(digits: str) -> None:
    """Levanta DiceInputError se `digits` nao for uma sequencia nao vazia
    de caracteres em '1'..'6', dentro do limite estrutural de tamanho.

    A mensagem de erro NUNCA inclui os caracteres recebidos: só a posicao
    do primeiro caractere invalido. Isso evita que uma sequencia parcial
    (ainda que so parte dela seja invalida) apareca ecoada em uma tela de
    erro, terminal com scrollback, ou log.
    """
    if not digits:
        raise DiceInputError("sequencia de lancamentos vazia")
    if len(digits) > MAX_ROLLS:
        raise DiceInputError(
            f"sequencia tem {len(digits)} lancamentos; o limite estrutural "
            f"da codificacao (prefixo uint16) e {MAX_ROLLS}"
        )
    for i, ch in enumerate(digits):
        if ch not in ALPHABET:
            raise DiceInputError(
                f"caractere invalido na posicao {i}: so sao aceitos os "
                "digitos 1-6 (um d6 tem seis faces)"
            )


def encode(digits: str) -> bytes:
    """Codificacao biunivoca de uma sequencia de lancamentos de d6.

        v = sum( (d_i - 1) * 6**(n - i) for i in 1..n )   # inteiro em [0, 6**n)
        W = ceil( bit_length(6**n - 1) / 8 )               # largura fixa em bytes
        A = uint16_be(n) || v.to_bytes(W, 'big')

    Propriedades:
      - Bijetora entre {1..6}^n e [0, 6**n): nenhuma sequencia distinta
        produz o mesmo `v`, e todo `v` em [0, 6**n) corresponde a uma
        sequencia.
      - O prefixo `n` e publico e nao carrega informacao secreta: e apenas
        o comprimento, necessario porque, sem ele, sequencias de
        comprimentos diferentes poderiam colidir (ex.: "1,2,3" e "2,3"
        produziriam o mesmo inteiro, pois um "1" a esquerda mapeia para o
        digito 0 em base 6).
      - O tamanho em bits de `A` (16 + 8*W) e maior do que a entropia real
        da fonte (no maximo n*log2(6) bits); ver entropy_calc.py. Nunca
        trate len(A) como a entropia de A.
    """
    validate_rolls(digits)
    n = len(digits)
    value = 0
    for ch in digits:
        value = value * 6 + (int(ch) - 1)
    max_value = 6**n - 1
    width = (max_value.bit_length() + 7) // 8 if max_value > 0 else 0
    return n.to_bytes(2, "big") + value.to_bytes(width, "big")


def decode(data: bytes) -> str:
    """Inversa de `encode`. Usada em testes de round-trip e no modo `vector`
    (nunca no fluxo `generate`, que so codifica, jamais decodifica, uma
    sequencia real).
    """
    if len(data) < 2:
        raise DiceInputError("dados curtos demais para conter o prefixo de comprimento (2 bytes)")
    n = int.from_bytes(data[:2], "big")
    if n == 0:
        # Simetria com `encode`/`validate_rolls`, que rejeitam explicitamente
        # uma sequencia vazia: `decode` nao deve aceitar um prefixo n=0 que
        # `encode` nunca produziria (achado de auditoria adversarial, Fase D
        # -- sem impacto de seguranca real, ja que `decode` so e chamado
        # internamente pelo round-trip do selftest e por testes, nunca sobre
        # dados nao confiaveis no fluxo `generate`; corrigido por completude).
        raise DiceInputError("prefixo de comprimento n=0: nenhuma sequencia valida tem zero lancamentos")
    max_value = 6**n - 1
    width = (max_value.bit_length() + 7) // 8 if max_value > 0 else 0
    if len(data) != 2 + width:
        raise DiceInputError(
            f"comprimento de A ({len(data)} bytes) inconsistente com o "
            f"prefixo n={n} (esperado {2 + width} bytes)"
        )
    value = int.from_bytes(data[2:], "big")
    if value > max_value:
        raise DiceInputError("valor codificado fora do intervalo [0, 6**n) esperado para n")
    digits = []
    for _ in range(n):
        digits.append(str(value % 6 + 1))
        value //= 6
    return "".join(reversed(digits))
