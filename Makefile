PYTHON ?= python3

.PHONY: test selftest vectors build repro lint clean simulate release verify-release executable repro-exe

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

## Fluxo OFICIAL de release (Fase E): builda o .pyz, gera o manifesto de
## release (MANIFEST.txt) e monta o pacote autocontido em release/ (o
## .pyz, os hashes, e toda a documentacao) -- o que deve ser levado para a
## maquina permanentemente offline. Ver docs/VERIFY.md para o passo a
## passo de verificacao e docs/GENERATION_CEREMONY.md para a cerimonia de
## geracao em si.
release: build
	$(PYTHON) tools/build_release_manifest.py
	$(PYTHON) tools/assemble_release.py

## Fluxo OFICIAL de verificacao (Fase E): reconfere, do zero, cada campo
## de MANIFEST.txt contra o codigo-fonte e o .pyz atuais (nao contra o
## conteudo de release/, que e so uma copia -- rode `make release` de
## novo se quiser reconferir a copia tambem). Imprime SOMENTE PASS/FAIL.
## Requer que `make release` (ou ao menos `make build` +
## `tools/build_release_manifest.py`) ja tenha rodado.
verify-release:
	@test -f MANIFEST.txt || (echo "erro: MANIFEST.txt nao existe -- rode 'make release' primeiro" && exit 2)
	@test -f entropyforge.pyz || (echo "erro: entropyforge.pyz nao existe -- rode 'make release' primeiro" && exit 2)
	$(PYTHON) independent-verifier/verify_release.py \
		--manifest MANIFEST.txt \
		--entropyforge-root entropyforge \
		--pyz entropyforge.pyz \
		--verifier-root independent-verifier/verifier \
		--build-script tools/build_pyz.py \
		--vectors tests/vectors/bip39_vectors.json \
		--verbose

## Constroi o executavel standalone (Fase F, Nuitka -- ver
## docs/EXECUTABLE_BUILD.md). Requer 'nuitka' e um compilador C instalados
## num ambiente de BUILD (nunca dependencias de runtime do produto).
executable:
	$(PYTHON) tools/build_executable.py

## Constroi o executavel duas vezes (diretorios/umask diferentes) e
## confirma que o SHA-256 de CADA arquivo e identico (Fase F, requisito
## de build reprodutivel do executavel -- ver docs/EXECUTABLE_BUILD.md).
repro-exe:
	@rm -rf /tmp/entropyforge-exe-repro-a /tmp/entropyforge-exe-repro-b
	@mkdir -p /tmp/entropyforge-exe-repro-a /tmp/entropyforge-exe-repro-b
	@umask 022 && $(PYTHON) tools/build_executable.py --output-dir /tmp/entropyforge-exe-repro-a
	@umask 077 && $(PYTHON) tools/build_executable.py --output-dir /tmp/entropyforge-exe-repro-b
	@(cd /tmp/entropyforge-exe-repro-a/entropyforge-bip39-*/ && find . -type f -exec sha256sum {} \; | sort -k2) > /tmp/entropyforge-exe-repro-a.hashes
	@(cd /tmp/entropyforge-exe-repro-b/entropyforge-bip39-*/ && find . -type f -exec sha256sum {} \; | sort -k2) > /tmp/entropyforge-exe-repro-b.hashes
	@diff -q /tmp/entropyforge-exe-repro-a.hashes /tmp/entropyforge-exe-repro-b.hashes \
	 && echo "REPRODUTIVEL: todos os hashes identicos" || (echo "DIVERGENTE: build do executavel nao reprodutivel" && exit 1)

clean:
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf release dist_executable
	rm -f entropyforge.pyz SHA256SUMS MANIFEST.txt
