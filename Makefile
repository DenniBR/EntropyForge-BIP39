PYTHON ?= python3

.PHONY: test selftest vectors build repro lint clean simulate

## Roda toda a suite de testes (unittest da stdlib; sem dependencias de terceiros).
test:
	$(PYTHON) -B -m unittest discover -s tests -v

## Roda os auto-testes (KATs) do proprio produto. Nota: usamos -m a partir
## do source checkout, entao NAO passamos -I aqui: a flag -I implica -P,
## que desativa o prepend automatico do diretorio atual ao sys.path que
## `-m` precisa para achar um pacote nao instalado (ver docs/AUDIT.md). O
## artefato .pyz empacotado (tools/build_pyz.py) roda com -I -B normalmente
## porque nesse caso e o proprio arquivo .pyz, nao o cwd, que e adicionado
## ao sys.path.
selftest:
	$(PYTHON) -B -m entropyforge selftest

## Constroi o artefato deterministico entropyforge.pyz.
build:
	$(PYTHON) tools/build_pyz.py entropyforge.pyz

## Constroi o artefato duas vezes (em diretorios e umask diferentes) e
## confirma que o SHA-256 e identico (requisito 15: build reprodutivel).
repro:
	@rm -rf /tmp/entropyforge-repro-a /tmp/entropyforge-repro-b
	@mkdir -p /tmp/entropyforge-repro-a /tmp/entropyforge-repro-b
	@umask 022 && $(PYTHON) tools/build_pyz.py /tmp/entropyforge-repro-a/entropyforge.pyz
	@umask 077 && $(PYTHON) tools/build_pyz.py /tmp/entropyforge-repro-b/entropyforge.pyz
	@A=$$(sha256sum /tmp/entropyforge-repro-a/entropyforge.pyz | cut -d' ' -f1); \
	 B=$$(sha256sum /tmp/entropyforge-repro-b/entropyforge.pyz | cut -d' ' -f1); \
	 echo "build A: $$A"; echo "build B: $$B"; \
	 if [ "$$A" = "$$B" ]; then echo "REPRODUTIVEL: hashes identicos"; else echo "DIVERGENTE: build nao reprodutivel"; exit 1; fi

## Verificacoes estaticas de seguranca que nao exigem ferramentas externas
## (o AST de seguranca ja roda dentro de `make test`; isto so reforca
## checagens rapidas de grep, uteis num pre-commit local).
lint:
	@echo "--- checando ausencia de 'random', rede, subprocess, logging no pacote ---"
	@! grep -rnE '^\s*(import random|from random)' entropyforge/ || (echo "FALHOU: uso de random encontrado" && exit 1)
	@! grep -rnE '^\s*(import (socket|subprocess|urllib|http\.client|ftplib|smtplib|telnetlib)|from (socket|subprocess|urllib|http\.client))' entropyforge/ || (echo "FALHOU: import de rede/subprocess encontrado" && exit 1)
	@! grep -rnE '^\s*import logging' entropyforge/ || (echo "FALHOU: uso de logging encontrado" && exit 1)
	@echo "OK"

## Roda o estudo de simulacao (dev-only) do poder estatistico da bateria.
simulate:
	$(PYTHON) tools/simulate_power.py

clean:
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	rm -f entropyforge.pyz SHA256SUMS
