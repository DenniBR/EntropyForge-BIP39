# Matriz de suporte a plataformas

Este documento diz, para cada sistema operacional, se `generate` funciona
com as mesmas garantias de segurança descritas em `docs/THREAT_MODEL.md`
e `docs/DESIGN.md`, ou se algum controle específico fica degradado ou
ausente. Nenhuma linha desta tabela é uma afirmação de que a plataforma
"suportada" é segura em termos absolutos — só que os controles do próprio
programa (checagem de rede, CSPRNG do SO, prevenção de core dump) foram
implementados, testados e (nas plataformas Linux) auditados de forma
adversarial para ela.

## 1. Tabela resumo

| Plataforma | Suportada? | Checagem de rede offline (`guard.check_offline`) | Fonte B (CSPRNG do SO) | Prevenção de core dump |
|---|---|---|---|---|
| Linux moderno (kernel com `/sys/class/net`, qualquer distro) | **Sim** (plataforma primária) | Funcional: le `/sys/class/net`, recusa se houver interface `up` | `os.getrandom(nbytes, 0)` (bloqueia até o gerador do kernel inicializar) | `resource.RLIMIT_CORE=0` (`resource` disponível) |
| Tails (baseado em Debian, live, amnésico) | **Sim** — ver §2 | Idêntica ao Linux genérico | Idêntica ao Linux genérico | Idêntica ao Linux genérico |
| Debian live (USB, sem instalar) | **Sim** — ver §2 | Idêntica ao Linux genérico | Idêntica ao Linux genérico | Idêntica ao Linux genérico |
| Windows (10/11) | **Não recomendada — ver §3** | Levanta `NotImplementedError`; `generate` **sempre** recusa (fail-closed) a menos que o operador passe `--override-offline-check` e digite a frase de confirmação, desarmando a checagem por completo, sem verificação alguma | `os.urandom` (`BCryptGenRandom` via CPython) — nunca `os.getrandom`, que não existe nesta plataforma | Não implementada (`resource` não existe fora de POSIX); é um controle a menos, não um erro fatal |
| Windows XP | **Explicitamente NÃO SUPORTADA — ver §4** | N/A | N/A | N/A |
| macOS / *BSD | **Não avaliada formalmente** — ver §5 | Mesmo comportamento que Windows: `NotImplementedError`, fail-closed sem override | `os.urandom` (`getentropy()`) | Depende: `resource` normalmente existe em POSIX, mas o comportamento exato de `RLIMIT_CORE` não foi verificado nesta plataforma |

## 2. Linux (incl. Tails e Debian live) — suporte primário

Esta é a única família de plataformas para a qual o projeto foi
desenvolvido, testado e submetido a auditoria adversarial extensa
(`docs/REDTEAM.md`, `docs/FINAL_SECURITY_REVIEW.md`). Toda a suíte de
testes (`tests/`) roda neste ambiente. Não há nenhuma dependência de uma
distribuição específica: `guard.list_active_network_interfaces` só exige
que `/sys/class/net` exista (uma interface padrão do kernel Linux, não de
uma distro em particular), e a fonte B usa `os.getrandom`, uma chamada de
sistema do kernel Linux exposta pelo módulo `os` do CPython desde a versão
3.6.

Tails e uma live image Debian (USB, sem instalar em disco) atendem a este
requisito exatamente da mesma forma que qualquer outro Linux — não há
código específico para elas neste projeto. Elas são mencionadas
separadamente na tabela porque são o tipo de ambiente mais adequado para
a cerimônia descrita em `docs/GENERATION_CEREMONY.md` (sessão live,
descartável, sem persistência por padrão), não porque recebam tratamento
técnico diferente.

**Limitação conhecida, já documentada em `guard.py`:** a checagem de rede
só enxerga o que o próprio kernel relata em `/sys/class/net`. Um SO
comprometido que minta sobre o estado das interfaces não seria detectado
— isto vale igualmente para qualquer distro Linux, Tails incluído.

## 3. Windows — avaliada, não recomendada para uso real

Windows **executa** o código (a biblioteca padrão do Python cobre as
chamadas necessárias em ambas as plataformas), mas dois controles de
segurança relevantes ficam degradados:

1. **A checagem automática de rede offline não existe nesta plataforma.**
   `guard.list_active_network_interfaces` depende de `/sys/class/net`, uma
   interface exclusiva do kernel Linux. Em Windows, `check_offline` sempre
   levanta `NotImplementedError` internamente e — por design fail-closed —
   `generate` sempre se recusa a continuar, a menos que o operador use
   `--override-offline-check` e digite a frase de confirmação exata. Ao
   contrário do Linux (onde o override desarma uma checagem que *funciona*
   e encontrou algo), em Windows o override desarma uma checagem que
   **nunca chega a rodar** — ou seja, em Windows este programa não tem
   NENHUM mecanismo automático para detectar uma interface de rede ativa.
   A responsabilidade de garantir que a máquina está offline recai
   inteiramente sobre o operador (desligar Wi-Fi/Ethernet manualmente,
   idealmente pelo hardware, e confirmar por conta própria).
2. **A prevenção de core dump (`resource.RLIMIT_CORE=0`) não existe nesta
   plataforma.** O módulo `resource` é exclusivo de sistemas POSIX; em
   Windows, `_disable_core_dumps` simplesmente não faz nada (falha
   silenciosa e documentada, não um erro fatal). Isto não é uma lacuna
   introduzida por este projeto — é a ausência, no próprio Windows, de um
   equivalente direto exposto pela biblioteca padrão do Python — mas o
   efeito prático é que um crash do processo tem uma superfície de
   vazamento por dump que este projeto não neutraliza nesta plataforma.

A fonte B em si (`os.urandom`, que a CPython implementa sobre
`BCryptGenRandom`) é uma chamada legítima ao CSPRNG do sistema
operacional — não é um "fallback" para uma fonte de qualidade inferior,
só o nome de API correto para esta plataforma (`os.getrandom` é
especificamente uma chamada de sistema Linux e nem existe no módulo `os`
em Windows). Isto não muda a avaliação acima: os dois controles acima
(rede e core dump) são reais lacunas de suporte, não uma questão de
qualidade de entropia.

**Recomendação:** não usar Windows para uma geração real de fundos
verdadeiros enquanto esta lacuna não for endereçada (nenhum código deste
projeto tenta detectar rede em Windows hoje). Windows pode ser usado para
desenvolvimento, leitura de código e rodar a suíte de testes.

**Nota (Fase F, executável standalone):** esta seção descreve o
comportamento do PRÓPRIO PROGRAMA quando rodado com um interpretador
Python em Windows (fonte ou `.pyz`). Isto é diferente de "existe um
executável Windows pronto para distribuir" — **não existe**: nenhuma das
ferramentas de empacotamento avaliadas (PyInstaller, Nuitka) faz
cross-compilação de Linux para Windows, e não havia máquina Windows
disponível neste ambiente de build para produzir um binário nativo. Ver
`docs/EXECUTABLE_BUILD.md` seção 8 e `docs/EXECUTABLE_RELEASE_CHECKS.md`
seção 5 para a avaliação completa e honesta dessa lacuna.

## 4. Windows XP — explicitamente NÃO SUPORTADA

Este projeto exige Python ≥ 3.11 (ver `README.md`). Não existe, e nunca
existiu, uma distribuição oficial do CPython 3.11 (nem de nenhuma versão
3.9+) para Windows XP: o instalador oficial do Python já exige Windows
8.1 ou mais recente desde a série 3.9, e o suporte a versões de Windows
anteriores a isso foi removido progressivamente nas séries anteriores.
Windows XP atingiu fim de vida (sem atualizações de segurança da
Microsoft) em 2014. Não há como este programa rodar em Windows XP com um
interpretador Python suportado — isto não é uma limitação deste projeto
especificamente, é uma consequência de o interpretador Python exigido não
existir para essa plataforma.

## 5. macOS / *BSD — não avaliada formalmente

O código tem, em teoria, os mesmos dois pontos de degradação do Windows
(sem `/sys/class/net`, portanto sem checagem automática de rede;
`os.urandom` no lugar de `os.getrandom`), mas ao contrário do Windows,
**nenhum teste deste projeto rodou nestas plataformas** — a lista acima é
uma inferência a partir do código-fonte, não uma observação verificada.
`resource.RLIMIT_CORE` provavelmente existe (macOS e *BSD são POSIX), mas
o comportamento exato não foi confirmado. Trate como "não suportada" até
que alguém rode a suíte de testes completa (`make test`) nestas
plataformas e documente o resultado aqui.

## 6. Resumo para quem só quer a resposta rápida

- **Use Linux** (qualquer distro moderna, Tails e Debian live incluídos)
  para uma geração real. É a única plataforma com checagem automática de
  rede funcional e com toda a bateria de testes/auditoria adversarial
  aplicada.
- **Windows** roda o código, mas sem a checagem automática de rede — a
  responsabilidade de garantir "offline" vira inteiramente manual.
- **Windows XP não roda o programa**, ponto final: o interpretador Python
  exigido não existe para essa versão do Windows.
- **macOS/*BSD**: sem avaliação formal; trate como não suportada até ser
  testada.
