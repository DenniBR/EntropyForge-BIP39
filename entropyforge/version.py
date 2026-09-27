"""Versionamento formal do projeto (Fase E, requisito 2).

Cinco números DIFERENTES, deliberadamente separados, porque cada um pode
mudar independentemente dos outros sem quebrar compatibilidade com os
demais:

  - `SOFTWARE_VERSION`: versão do pacote `entropyforge` em si (código,
    CLI, mensagens). Segue SemVer.
  - `PROTOCOL_VERSION_A`: versão do FORMATO de codificação da fonte A
    (a bijeção implementada em `dice.py`: prefixo de 2 bytes + valor em
    base 6). Muda SOMENTE se o formato de bytes de `A` mudar de forma
    incompatível (ex.: outro tamanho de prefixo, outra base). Uma nova
    versão do software que mantém o mesmo formato de A NÃO incrementa
    isto -- é o que garante que uma sequência de dado codificada por uma
    versão v1.x sempre decodifica da mesma forma em qualquer v1.y.
  - `GENERATION_PROCEDURE_VERSION`: versão da SEQUÊNCIA DE PASSOS do
    fluxo `generate` (`docs/GENERATION_CEREMONY.md`). Muda se a ordem ou
    a natureza dos passos operacionais mudar de forma que afete como um
    operador deveria seguir a cerimônia (ex.: a mudança desta própria
    fase, que reduziu o relatório de `generate` para ACCEPTED/REJECTED).
  - `WORDLIST_VERSION`: identificador da EDIÇÃO da wordlist BIP-39 em
    inglês embutida (o conteúdo é verificado por hash em `wordlist.py`;
    isto é um rótulo humano para qual edição esse hash corresponde).
  - `MANIFEST_FORMAT_VERSION`: versão do FORMATO do manifesto de release
    (`MANIFEST.txt` -- quais campos ele tem e em que ordem), não do
    conteúdo de uma release específica.

Nenhuma mudança futura deve alterar SILENCIOSAMENTE o significado de
qualquer um destes números — um bump exige atualizar este arquivo e
`docs/FINAL_SECURITY_REVIEW.md`/`docs/RELEASE_SECURITY_CHECKLIST.md`
explicitamente.
"""

from __future__ import annotations

from dataclasses import dataclass

SOFTWARE_VERSION = "1.0.0"
PROTOCOL_VERSION_A = "1"
GENERATION_PROCEDURE_VERSION = "2"
WORDLIST_VERSION = "bip39-english-2013"
MANIFEST_FORMAT_VERSION = "1"


@dataclass(frozen=True)
class VersionInfo:
    software_version: str
    protocol_version_a: str
    generation_procedure_version: str
    wordlist_version: str
    manifest_format_version: str

    def format(self) -> str:
        return (
            f"EntropyForge-BIP39 v{self.software_version}\n"
            f"  protocolo do formato A (dice.py) : v{self.protocol_version_a}\n"
            f"  procedimento de geracao            : v{self.generation_procedure_version}\n"
            f"  wordlist                           : {self.wordlist_version}\n"
            f"  formato do manifesto de release    : v{self.manifest_format_version}"
        )


def current() -> VersionInfo:
    return VersionInfo(
        software_version=SOFTWARE_VERSION,
        protocol_version_a=PROTOCOL_VERSION_A,
        generation_procedure_version=GENERATION_PROCEDURE_VERSION,
        wordlist_version=WORDLIST_VERSION,
        manifest_format_version=MANIFEST_FORMAT_VERSION,
    )
