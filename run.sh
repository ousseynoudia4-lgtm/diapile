#!/usr/bin/env bash
# ================================================================
# DIAPILE — Script de lancement rapide (Linux / macOS)
# Usage : bash run.sh [target1,target2,...] [options nrtg]
# ================================================================
set -euo pipefail

FIRE='\033[0;91m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

echo ""
echo -e "${FIRE}${BOLD}"
echo "  ██████╗ ██╗ █████╗ ██████╗ ██╗██╗     ███████╗"
echo "  ██╔══██╗██║██╔══██╗██╔══██╗██║██║     ██╔════╝"
echo "  ██║  ██║██║███████║██████╔╝██║██║     █████╗  "
echo "  ██║  ██║██║██╔══██║██╔═══╝ ██║██║     ██╔══╝  "
echo "  ██████╔╝██║██║  ██║██║     ██║███████╗███████╗"
echo "  ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝"
echo -e "${NC}"
echo -e "${ORANGE}  Network Redteam Grapher v2.0 — Docker Runner${NC}"
echo ""

# Charger .env si présent
if [ -f ".env" ]; then
    set -a; source .env; set +a
    echo -e "${GREEN}[OK]${NC}  .env chargé"
else
    echo -e "${ORANGE}[WARN]${NC} .env absent — copiez .env.example en .env pour configurer"
fi

mkdir -p out sessions

# Vérifier que l'image existe
if ! docker image inspect nrtg:latest &>/dev/null; then
    echo -e "\n${FIRE}[BUILD]${NC} Image nrtg:latest absente — build en cours..."
    docker build -t nrtg:latest -t nrtg:2.0.0 .
    echo -e "${GREEN}[OK]${NC}  Image construite"
fi

# Construire la commande docker run
DOCKER_OPTS=(
    "--rm"
    "-v" "$(pwd)/out:/app/out"
    "-v" "$(pwd)/sessions:/app/sessions"
)

# Injecter les clés API si définies
[ -n "${OPENROUTER_API_KEY:-}" ] && DOCKER_OPTS+=("-e" "OPENROUTER_API_KEY=${OPENROUTER_API_KEY}")
[ -n "${OPENAI_API_KEY:-}"     ] && DOCKER_OPTS+=("-e" "OPENAI_API_KEY=${OPENAI_API_KEY}")
[ -n "${RUST_LOG:-}"           ] && DOCKER_OPTS+=("-e" "RUST_LOG=${RUST_LOG}")

# Réseau hôte (Linux uniquement — permet de scanner le réseau local)
if [[ "$(uname)" == "Linux" ]]; then
    DOCKER_OPTS+=("--add-host" "host.docker.internal:host-gateway")
fi

# Arguments passés au script = arguments nrtg
NRTG_ARGS=("${@}")

# Si aucun argument → afficher l'aide DIAPILE
if [ "${#NRTG_ARGS[@]}" -eq 0 ]; then
    NRTG_ARGS=("--features")
fi

echo -e "${CYAN}[RUN]${NC}  docker run nrtg ${NRTG_ARGS[*]}"
echo ""
docker run "${DOCKER_OPTS[@]}" nrtg:latest "${NRTG_ARGS[@]}"

# Afficher les sorties générées
if ls out/graph.* &>/dev/null 2>&1; then
    echo ""
    echo -e "${GREEN}Sorties générées dans ./out/ :${NC}"
    ls -lh out/graph.* 2>/dev/null | awk '{print "  " $5 "  " $9}'
fi
