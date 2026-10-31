# Outils de développement (pas nécessaires pour utiliser finalcut)
#   make lint        analyse du code avec shellcheck
#   make fmt         met le code en forme avec shfmt
#   make fmt-check   vérifie la mise en forme sans rien modifier
#   make check       tout ce qui précède, plus « bash -n »

SCRIPTS := finalcut.sh $(wildcard lib/*.sh) $(wildcard tests/*.sh)
# 4 espaces, « case » indentés, opérateurs (| && ||) en début de ligne
SHFMT := shfmt -i 4 -ci -bn

.PHONY: lint fmt fmt-check check

lint:
	shellcheck -x -S warning $(SCRIPTS)

fmt:
	$(SHFMT) -w $(SCRIPTS)

fmt-check:
	$(SHFMT) -d $(SCRIPTS)

check: lint fmt-check
	@for f in $(SCRIPTS); do bash -n "$$f" || exit 1; done
	@echo "Tout est en ordre."
