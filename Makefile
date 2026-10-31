# Outils de développement (pas nécessaires pour utiliser finalcut)
#   make lint        analyse du code avec shellcheck
#   make fmt         met le code en forme avec shfmt
#   make fmt-check   vérifie la mise en forme sans rien modifier
#   make check       tout ce qui précède, plus « bash -n »

SCRIPTS := finalcut.sh $(wildcard lib/*.sh) $(wildcard tests/*.sh)
# 4 espaces, « case » indentés, opérateurs (| && ||) en début de ligne
SHFMT := shfmt -i 4 -ci -bn

.PHONY: lint fmt fmt-check check

# Exclusions : le script est découpé en fichiers chargés par finalcut.sh (les
# variables d'un fichier servent dans les autres : SC2034, SC2154) et charge
# dynamiquement ses fichiers d'état /etc/finalcut/*.conf (SC1090, SC1091).
lint:
	shellcheck -x -P SCRIPTDIR -S warning -e SC2034,SC2154,SC1090,SC1091 $(SCRIPTS)

fmt:
	$(SHFMT) -w $(SCRIPTS)

fmt-check:
	$(SHFMT) -d $(SCRIPTS)

check: lint fmt-check
	@for f in $(SCRIPTS); do bash -n "$$f" || exit 1; done
	@echo "Tout est en ordre."
