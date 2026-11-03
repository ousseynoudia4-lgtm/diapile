# =================================================================
# DIAPILE — Network Redteam Grapher v2.0
# Makefile — toutes les commandes opérationnelles
#
# Usage :
#   make scan TARGETS="192.168.1.1:80,192.168.1.1:22"
#   make scan-native TARGETS="http://mon.site:443"
#   make scan-ai TARGETS="192.168.1.0/24:80"
# =================================================================

SHELL            := /bin/bash
# Cibles par défaut : lab Docker local (make up requis)
LAB_TARGETS      := http://localhost:8080,127.0.0.1:6379,127.0.0.1:2222,127.0.0.1:1025,127.0.0.1:21
TARGETS          ?= $(LAB_TARGETS)

# Listes externes (.txt) : placez vos fichiers dans ./lists/ puis passez les flags
# ex. make scan-brute BRUTE_EXTRA="--brute-users /app/lists/users.txt --brute-passwords /app/lists/pass.txt"
BRUTE_EXTRA      ?=
# ex. make scan-web WEB_URL=https://lab.local WEB_EXTRA="--web-payloads sqli=/app/lists/sqli.txt"
WEB_EXTRA        ?=
WEB_URL          ?= http://localhost:8080

OUT_DIR          := $(CURDIR)/out
LISTS_DIR        := $(CURDIR)/lists
DASHBOARD        := $(CURDIR)/dashboard.html
NRTG_BIN         := $(CURDIR)/target/release/nrtg
DOCKER_COMPOSE   := docker compose

.DEFAULT_GOAL    := help
.PHONY: help up down restart logs build build-docker \
        scan scan-ai scan-native scan-brute scan-web scan-local \
        doctor dash report update-cve test lint check clean

# -----------------------------------------------------------------
help: ## Affiche ce menu d'aide
	@echo ""
	@echo "  🎯 TARGETS actuelles : \033[33m$(TARGETS)\033[0m"
	@echo "     Surchargez avec : make scan TARGETS=\"192.168.1.1:80,192.168.1.1:22\""
	@awk 'BEGIN {FS = ":.*##"; printf "\n\033[36m» DIAPILE — commandes disponibles\033[0m\n\n"} \
		/^[a-zA-Z_-]+:.*##/ { printf "  \033[32m%-22s\033[0m %s\n", $$1, $$2 } \
		END { printf "\n\033[90mExemple : make up && make scan TARGETS=\"192.168.1.1:80,192.168.1.1:22\"\033[0m\n\n" }' \
		$(MAKEFILE_LIST)

# -----------------------------------------------------------------
# Lab Docker (cibles de simulation vulnérables pour tests)
# -----------------------------------------------------------------
up: ## Démarre les cibles de simulation Docker (nginx/redis/ssh/smtp/ftp)
	@mkdir -p $(OUT_DIR) $(LISTS_DIR)
	$(DOCKER_COMPOSE) up -d
	@echo ""
	@echo "  → Ports : 8080 (nginx), 6379 (redis), 2222 (ssh), 1025 (smtp), 21 (ftp)"
	@echo "  → Lancer un scan : make scan TARGETS=\"$(LAB_TARGETS)\""

down: ## Arrête la stack Docker
	$(DOCKER_COMPOSE) down --remove-orphans

restart: down up ## Redémarre les cibles de simulation

logs: ## Affiche les logs des cibles Docker en temps réel
	$(DOCKER_COMPOSE) logs -f

# -----------------------------------------------------------------
# Builds
# -----------------------------------------------------------------
build: ## Compile le binaire Rust release (local — nécessite Rust/Cargo)
	cargo build --release

build-docker: ## Construit l'image Docker nrtg:latest
	docker build -t nrtg:latest -t nrtg:2.0.0 .

# -----------------------------------------------------------------
# Scans — utilisent tous TARGETS
# -----------------------------------------------------------------
scan: build-docker ## Build Docker + scan (RECOMMANDÉ). TARGETS obligatoire en dehors du lab.
	@mkdir -p $(OUT_DIR)
	@echo "  🎯 Cibles : $(TARGETS)"
	docker run --rm \
		--env-file .env \
		--add-host host.docker.internal:host-gateway \
		-v "$(OUT_DIR):/app/out" \
		-v "$(CURDIR)/sessions:/app/sessions" \
		nrtg:latest \
		-t "$(TARGETS)" \
		--output /app/out/graph.json \
		--csv --md --export-api-report \
		--parallel 20
	@$(MAKE) --no-print-directory _ls_out

scan-ai: build-docker ## Scan + rapport IA (OPENROUTER_API_KEY dans .env requise)
	@mkdir -p $(OUT_DIR)
	@if [ "$(TARGETS)" = "$(LAB_TARGETS)" ]; then \
		echo "⚠️  ATTENTION : vous utilisez les cibles lab par défaut."; fi
	@echo "  🎯 Cibles : $(TARGETS)"
	docker run --rm \
		--env-file .env \
		--add-host host.docker.internal:host-gateway \
		-v "$(OUT_DIR):/app/out" \
		-v "$(CURDIR)/sessions:/app/sessions" \
		nrtg:latest \
		-t "$(TARGETS)" \
		--output /app/out/graph.json \
		--csv --md --export-api-report \
		--ai-report --ai-targets 10 \
		--llm-provider openrouter \
		--parallel 20
	@$(MAKE) --no-print-directory _ls_out

scan-native: build ## Scan Rust local (sans Docker — cibles joignables depuis la machine)
	@mkdir -p $(OUT_DIR)
	@if [ ! -f "$(NRTG_BIN)" ]; then echo "Binaire absent — lancez : make build"; exit 1; fi
	@echo "  🎯 Cibles : $(TARGETS)"
	$(NRTG_BIN) \
		-t "$(TARGETS)" \
		--output $(OUT_DIR)/graph.json \
		--csv --md --export-api-report \
		--parallel 20
	@$(MAKE) --no-print-directory _ls_out

scan-brute: build-docker ## Scan + bruteforce de credentials (⚠️ actif — autorisation requise). BRUTE_EXTRA pour les listes .txt
	@mkdir -p $(OUT_DIR) $(LISTS_DIR)
	@echo "  🎯 Cibles : $(TARGETS)"
	docker run --rm \
		--env-file .env \
		--add-host host.docker.internal:host-gateway \
		-v "$(OUT_DIR):/app/out" \
		-v "$(LISTS_DIR):/app/lists:ro" \
		nrtg:latest \
		-t "$(TARGETS)" \
		--brute --brute-mode quick --yes \
		$(BRUTE_EXTRA) \
		--output /app/out/graph.json \
		--csv --md --export-api-report
	@$(MAKE) --no-print-directory _ls_out

scan-web: build-docker ## Attaque web (WEB_URL=... ; payloads externes via WEB_EXTRA="--web-payloads sqli=/app/lists/sqli.txt")
	@mkdir -p $(OUT_DIR) $(LISTS_DIR)
	@echo "  🎯 Cible web : $(WEB_URL)"
	docker run --rm \
		--env-file .env \
		--add-host host.docker.internal:host-gateway \
		-v "$(OUT_DIR):/app/out" \
		-v "$(LISTS_DIR):/app/lists:ro" \
		nrtg:latest \
		--web-scan "$(WEB_URL)" \
		$(WEB_EXTRA) \
		--output /app/out/graph.json \
		--csv --md --export-api-report
	@$(MAKE) --no-print-directory _ls_out

scan-local: build-docker ## Détecte automatiquement la gateway et scanne le réseau local
	@mkdir -p $(OUT_DIR)
	docker run --rm \
		--env-file .env \
		--add-host host.docker.internal:host-gateway \
		-v "$(OUT_DIR):/app/out" \
		nrtg:latest \
		--scan-local
	@$(MAKE) --no-print-directory _ls_out

# -----------------------------------------------------------------
# Utilitaires
# -----------------------------------------------------------------
doctor: ## Vérifie l'environnement DIAPILE (deps, config, réseau)
	@if [ -f "$(NRTG_BIN)" ]; then \
		$(NRTG_BIN) --doctor; \
	else \
		docker run --rm --env-file .env nrtg:latest --doctor 2>/dev/null || \
		echo "Compilez d'abord : make build"; fi

dash: ## Ouvre le dashboard D3.js dans le navigateur
	@if [ -f $(OUT_DIR)/graph.json ]; then \
		cp -f $(OUT_DIR)/graph.json $(CURDIR)/graph.json 2>/dev/null || true; fi
	@xdg-open $(DASHBOARD) 2>/dev/null || \
	 open $(DASHBOARD) 2>/dev/null || \
	 echo "  → Ouvrez manuellement : $(DASHBOARD)"

report: ## Affiche le rapport Markdown du dernier scan
	@if [ -f $(OUT_DIR)/graph.md ]; then \
		cat $(OUT_DIR)/graph.md; \
	else \
		echo "Aucun rapport trouvé — lancez make scan d'abord."; fi

update-cve: ## Télécharge la base CVE depuis NVD API v2
	@if [ -f "$(NRTG_BIN)" ]; then \
		$(NRTG_BIN) --update-cve-db; \
	else \
		docker run --rm --env-file .env nrtg:latest --update-cve-db; fi

# -----------------------------------------------------------------
# Dev & CI
# -----------------------------------------------------------------
test: ## Tests unitaires Rust
	cargo test --all

lint: ## Vérifications fmt + clippy (CI)
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings

check: ## Cargo check rapide (sans compiler)
	cargo check

clean: ## Supprime les artifacts (target/, out/, sessions/)
	-cargo clean
	-rm -rf $(OUT_DIR) $(CURDIR)/sessions
	-docker rmi nrtg:latest nrtg:2.0.0 2>/dev/null || true

# -----------------------------------------------------------------
# Interne
# -----------------------------------------------------------------
_ls_out:
	@echo ""
	@echo "── Rapports générés dans $(OUT_DIR)/ ──"
	@ls -1 $(OUT_DIR) 2>/dev/null | sed 's/^/  /' || echo "  (vide)"
	@echo "───────────────────────────────────────"
