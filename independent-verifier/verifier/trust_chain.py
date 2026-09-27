"""Analise da raiz de confianca (Fase 16).

Pergunta central: "O que eu preciso confiar para acreditar no mnemonic
gerado?" Este modulo enumera, EXPLICITAMENTE, cada elo da cadeia entre
"seis lancamentos de dado fisico" e "24 palavras BIP-39 na tela", e
classifica cada um segundo cinco perguntas independentes:

  - VERIFICAVEL: existe um procedimento CONCRETO (executavel hoje, por
    este projeto ou por ferramentas de terceiros amplamente auditadas)
    para confirmar que este elo se comporta como esperado?
  - REDUTIVEL: a confianca neste elo pode ser reduzida a confianca em
    outro elo JA coberto por esta analise (ex.: "confio no artefato .pyz"
    reduz a "confio que ele bate byte a byte com o source-tree", que por
    sua vez e uma questao de auditar o source)?
  - SUBSTITUIVEL: o operador pode trocar este componente por uma
    implementacao/instancia diferente (de outro fornecedor, outra versao,
    outra maquina) sem reconstruir tudo, permitindo comparacao cruzada?
  - AUDITAVEL: o codigo-fonte, configuracao ou design deste elo pode ser
    lido e revisado por um humano (mesmo que a leitura nao seja trivial)?
  - MENSURAVEL: propriedades deste elo podem ser medidas empiricamente
    (testes estatisticos, benchmarks, observacao de syscalls) em vez de
    apenas lidas como codigo?

Um elo pode ser VERIFICAVEL sem ser AUDITAVEL (ex.: um binario de
terceiros testado por observacao externa, mas sem acesso ao source), e
vice-versa. Nenhum desses atributos, isoladamente ou em conjunto, elimina
a necessidade de confiar em ALGO no fim da cadeia -- os elos marcados
`remains_hypothesis=True` sao esse residuo: mesmo depois de toda a
verificacao possivel, uma suposicao sem prova completa permanece (ex.:
"este processador Intel/AMD especifico nao tem um backdoor de hardware").
Isso NAO e uma falha desta analise -- e o resultado honesto dela.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TrustLink:
    component: str
    description: str
    verifiable: bool
    reducible: bool
    replaceable: bool
    auditable: bool
    measurable: bool
    remains_hypothesis: bool
    notes: str


TRUST_CHAIN: tuple[TrustLink, ...] = (
    TrustLink(
        component="Firmware / BIOS / UEFI",
        description="O firmware da placa-mae/CPU que roda antes de qualquer sistema operacional.",
        verifiable=False,
        reducible=False,
        replaceable=True,
        auditable=False,
        measurable=False,
        remains_hypothesis=True,
        notes=(
            "Nao ha, na pratica, como um usuario comum auditar ou medir o "
            "firmware de um dispositivo comercial. Substituivel apenas no "
            "sentido de trocar de maquina/fornecedor (o que muda A QUEM "
            "voce esta confiando, nao elimina a necessidade de confiar). "
            "Projetos como coreboot/Heads reduzem (nao eliminam) esse "
            "residuo, mas fogem do escopo deste projeto."
        ),
    ),
    TrustLink(
        component="Hardware (CPU, RAM, controladores)",
        description="O silicio que executa todas as instrucoes -- incluindo o gerador de numeros aleatorios de hardware (RDRAND/RDSEED), se usado.",
        verifiable=False,
        reducible=False,
        replaceable=True,
        auditable=False,
        measurable=True,
        remains_hypothesis=True,
        notes=(
            "MENSURAVEL parcialmente: a saida do OS RNG (que pode misturar "
            "RDRAND) pode ser submetida a bateria estatistica (como este "
            "projeto ja faz para a fonte fisica A) -- mas testes "
            "estatisticos so detectam falhas GROSSEIRAS de aleatoriedade, "
            "nunca provam ausencia de um enviesamento deliberado e sutil "
            "inserido no silicio. Um backdoor de hardware bem projetado "
            "passaria por qualquer bateria estatistica plausivel de rodar "
            "em tempo humano."
        ),
    ),
    TrustLink(
        component="Kernel do sistema operacional",
        description="Le e entrega chamadas de sistema, gerencia memoria/processos, implementa (ou repassa) o CSPRNG do SO.",
        verifiable=True,
        reducible=True,
        replaceable=True,
        auditable=True,
        measurable=True,
        remains_hypothesis=False,
        notes=(
            "REDUTIVEL a 'o kernel usado e um dos grandes kernels open-source "
            "amplamente auditados (Linux, *BSD)', o que e uma forma de "
            "confianca DELEGADA -- reduz o problema, nao o elimina. "
            "AUDITAVEL (codigo aberto) e MENSURAVEL (strace, como este "
            "projeto ja faz na Fase 11, observa o comportamento real do "
            "kernel a nivel de syscall, uma camada que o kernel nao pode "
            "'mentir' sobre sem ser ele mesmo o atacante)."
        ),
    ),
    TrustLink(
        component="Interpretador Python (CPython)",
        description="Executa o codigo-fonte de entropyforge/independent-verifier.",
        verifiable=True,
        reducible=True,
        replaceable=True,
        auditable=True,
        measurable=True,
        remains_hypothesis=False,
        notes=(
            "Open-source, amplamente auditado, com processo de release "
            "publico e assinado. REDUTIVEL a 'confio na cadeia de "
            "distribuicao do meu SO/gerenciador de pacotes para o binario "
            "python3 que estou usando' -- ainda uma forma de confianca "
            "delegada. SUBSTITUIVEL (rodar o mesmo source em duas versoes "
            "diferentes de Python, ou em PyPy, e comparar resultados, e um "
            "teste de robustez adicional nao feito ainda por este "
            "projeto)."
        ),
    ),
    TrustLink(
        component="Codigo-fonte de entropyforge/",
        description="O que este projeto audita mais diretamente: dice.py, bip39.py, combine.py, guard.py etc.",
        verifiable=True,
        reducible=False,
        replaceable=False,
        auditable=True,
        measurable=True,
        remains_hypothesis=False,
        notes=(
            "NAO reducivel a outra coisa -- e o proprio objeto sob auditoria "
            "(reduzir 'confio no source' a 'confio no source' seria "
            "circular). AUDITAVEL diretamente (Python legivel, sem "
            "ofuscacao). MENSURAVEL via testes automatizados, mutation "
            "testing (Fase B/14), e comparacao cruzada com implementacoes "
            "independentes (bip39_min.py). NAO SUBSTITUIVEL no sentido de "
            "'trocar por outra implementacao e comparar' ser MENOS "
            "aplicavel aqui -- e exatamente essa comparacao que "
            "bip39_compare.py fornece, entao esse atributo poderia ser "
            "argumentado como True; mantido False aqui porque o codigo "
            "inteiro (nao so bip39.py) nao tem uma implementacao "
            "alternativa completa para SUBSTITUIR, so para COMPARAR "
            "trechos especificos."
        ),
    ),
    TrustLink(
        component="Wordlist BIP-39 (data/english.txt)",
        description="As 2048 palavras que codificam a entropia final.",
        verifiable=True,
        reducible=True,
        replaceable=False,
        auditable=True,
        measurable=True,
        remains_hypothesis=False,
        notes=(
            "REDUTIVEL a 'confio no hash SHA-256 oficial da wordlist BIP-39 "
            "publicado pela comunidade Bitcoin/Trezor' -- verificavel por "
            "hash EMBUTIDO no proprio independent-verifier (Fase 3), "
            "independente de qualquer coisa que o EntropyForge diga sobre "
            "si mesmo (ver wordlist_check.KNOWN_OFFICIAL_SHA256)."
        ),
    ),
    TrustLink(
        component="Processo de build (tools/build_pyz.py)",
        description="Transforma o source-tree em entropyforge.pyz.",
        verifiable=True,
        reducible=True,
        replaceable=True,
        auditable=True,
        measurable=True,
        remains_hypothesis=False,
        notes=(
            "REDUTIVEL: nao precisa ser confiado diretamente, porque "
            "`compare_pyz_to_source` (Fase 9) verifica o RESULTADO do "
            "build contra o source-tree, independentemente de como o "
            "build foi feito (ver Fase 13, Cenario D: um build_pyz.py "
            "adulterado ainda e pego dessa forma). check_build_determinism "
            "(Fase 5) e um teste COMPLEMENTAR, mais fraco (so prova "
            "determinismo, nao honestidade)."
        ),
    ),
    TrustLink(
        component="Artefato distribuido (.pyz)",
        description="O arquivo que o usuario final efetivamente baixa/executa.",
        verifiable=True,
        reducible=True,
        replaceable=False,
        auditable=True,
        measurable=True,
        remains_hypothesis=False,
        notes=(
            "REDUTIVEL a 'bate byte a byte com o source-tree auditado' via "
            "`compare_pyz_to_source` + `check_bootstrap_main` (Fase 9). "
            "Isso SO funciona se o usuario tiver acesso a um source-tree "
            "de confianca para comparar -- que por sua vez depende do "
            "canal usado para obter esse source (ver Fase 13, Cenario E: "
            "um pacote impostor com o MESMO nome quebra isso se a "
            "referencia tambem vier do canal comprometido)."
        ),
    ),
    TrustLink(
        component="CSPRNG do sistema operacional (fonte B)",
        description="os.urandom() / getrandom() -- a metade 'eletronica' da entropia combinada.",
        verifiable=True,
        reducible=True,
        replaceable=False,
        auditable=False,
        measurable=True,
        remains_hypothesis=True,
        notes=(
            "REDUTIVEL a 'confio na implementacao do CSPRNG do kernel', que "
            "por sua vez e NAO totalmente AUDITAVEL no sentido de "
            "'consigo provar que a saida e computacionalmente "
            "indistinguivel de aleatoria' -- isso e uma suposicao "
            "criptografica padrao (a mesma que sustenta TLS, SSH, etc.), "
            "nao algo que este projeto (ou qualquer projeto de aplicacao) "
            "pode provar por conta propria. MENSURAVEL via bateria "
            "estatistica (Fase de calibracao), mas com a mesma ressalva do "
            "hardware: testes estatisticos nao provam ausencia de "
            "enviesamento deliberado."
        ),
    ),
    TrustLink(
        component="Dado fisico (d6) e o operador que o lanca",
        description="A fonte A: os lancamentos fisicos e a pessoa que os realiza e transcreve.",
        verifiable=True,
        reducible=False,
        replaceable=True,
        auditable=False,
        measurable=True,
        remains_hypothesis=True,
        notes=(
            "MENSURAVEL diretamente pela bateria estatistica do proprio "
            "EntropyForge (contagem de faces, runs, etc.) -- a UNICA fonte "
            "de entropia deste projeto que e testada estatisticamente em "
            "TEMPO REAL, a cada execucao, nao so uma vez em auditoria. "
            "NAO AUDITAVEL no sentido de codigo (e um objeto fisico, nao "
            "software) -- SUBSTITUIVEL por outro dado, mas isso so muda "
            "QUAL dado voce esta confiando ser justo, nao elimina a "
            "confianca. O operador (transcricao correta, ausencia de vies "
            "humano ao lancar, ambiente livre de camera/observador) "
            "permanece uma hipotese fora do escopo de qualquer verificacao "
            "de software."
        ),
    ),
    TrustLink(
        component="Ambiente de execucao (terminal, display, SO em uso)",
        description="A tela onde o mnemonic e exibido, o terminal, e o restante do SO rodando simultaneamente (outros processos, clipboard, etc.).",
        verifiable=True,
        reducible=False,
        replaceable=True,
        auditable=False,
        measurable=True,
        remains_hypothesis=True,
        notes=(
            "MENSURAVEL/VERIFICAVEL PARCIALMENTE por observacao externa "
            "(Fase 11/12: strace, sandbox) -- mas isso so cobre o "
            "PROCESSO do EntropyForge, nao o restante do sistema (outro "
            "processo com acesso ao terminal via /dev/pts, um keylogger, "
            "um malware de captura de tela) -- esses ficam, por definicao, "
            "fora do escopo de qualquer coisa que rode DENTRO do processo "
            "auditado, e permanecem uma hipotese ('a maquina nao esta "
            "comprometida de outra forma') que nenhum software rodando "
            "NELA pode provar sobre si mesma."
        ),
    ),
)


def irreducible_hypotheses() -> tuple[TrustLink, ...]:
    """Os elos que, mesmo apos toda verificacao possivel, permanecem uma
    suposicao (nunca uma prova). Esta lista NAO deveria, estruturalmente,
    ficar vazia -- uma lista vazia aqui seria sinal de uma analise
    excessivamente otimista, nao de um sistema perfeito."""
    return tuple(link for link in TRUST_CHAIN if link.remains_hypothesis)


def fully_reducible_links() -> tuple[TrustLink, ...]:
    """Elos onde a confianca PODE ser reduzida a verificacao concreta
    (mesmo que a verificacao em si dependa de outro elo)."""
    return tuple(link for link in TRUST_CHAIN if link.reducible and link.verifiable)


def render_markdown_table() -> str:
    header = (
        "| Componente | Verificavel | Redutivel | Substituivel | Auditavel | Mensuravel | Permanece hipotese |\n"
        "|---|---|---|---|---|---|---|\n"
    )
    rows = []
    for link in TRUST_CHAIN:
        rows.append(
            "| {component} | {v} | {r} | {s} | {a} | {m} | {h} |".format(
                component=link.component,
                v="sim" if link.verifiable else "nao",
                r="sim" if link.reducible else "nao",
                s="sim" if link.replaceable else "nao",
                a="sim" if link.auditable else "nao",
                m="sim" if link.measurable else "nao",
                h="**SIM**" if link.remains_hypothesis else "nao",
            )
        )
    return header + "\n".join(rows) + "\n"
