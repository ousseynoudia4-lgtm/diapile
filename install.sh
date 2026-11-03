#!/usr/bin/env bash
# ================================================================
# DIAPILE / NRTG — Installateur universel Linux / macOS v2.0
# Détecte l'OS, installe les dépendances, configure l'IA.
# Usage : bash install.sh [--skip-build] [--docker-only] [--llm-provider <p>] [--llm <model>]
# ================================================================
set -euo pipefail

FIRE='\033[0;91m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${ORANGE}[WARN]${NC}  $*"; }
step()  { echo -e "\n${BOLD}${FIRE}▍ $*${NC}"; }
error() { echo -e "${FIRE}[ERROR]${NC} $*"; exit 1; }

# ── Args ─────────────────────────────────────────────────────────
SKIP_BUILD=0
DOCKER_ONLY=0
LLM_PROVIDER=""   # vide = on conserve config.json tel quel
LLM_MODEL=""      # vide = on conserve config.json tel quel

for arg in "$@"; do
    case "$arg" in
        --skip-build)   SKIP_BUILD=1 ;;
        --docker-only)  DOCKER_ONLY=1 ;;
        --llm-provider) shift; LLM_PROVIDER="${1:-}" ;;
        --llm)          shift; LLM_MODEL="${1:-}" ;;
        --help|-h)
            echo "Usage: bash install.sh [--skip-build] [--docker-only] [--llm-provider <p>] [--llm <model>]"
            echo ""
            echo "Options:"
            echo "  --skip-build            Ne pas compiler après l'install des deps"
            echo "  --docker-only           Build via Docker uniquement"
            echo "  --llm-provider <p>      openrouter | openai | ollama (défaut: config.json)"
            echo "  --llm <model>           Nom du modèle (défaut: config.json)"
            echo ""
            echo "Tous les providers OpenAI-compatibles sont acceptés."
            echo "Exemples :"
            echo "  --llm-provider ollama     --llm llama3               (local, gratuit, zéro clé)"
            echo "  --llm-provider openrouter --llm openai/gpt-4o-mini   (clé OPENROUTER_API_KEY)"
            echo "  --llm-provider openai     --llm gpt-4o-mini          (clé OPENAI_API_KEY)"
            exit 0
            ;;
    esac
done

# ── Bannière ─────────────────────────────────────────────────────
echo ""
echo -e "${FIRE}${BOLD}"
echo "  ██████╗ ██╗ █████╗ ██████╗ ██╗██╗     ███████╗"
echo "  ██╔══██╗██║██╔══██╗██╔══██╗██║██║     ██╔════╝"
echo "  ██║  ██║██║███████║██████╔╝██║██║     █████╗  "
echo "  ██║  ██║██║██╔══██║██╔═══╝ ██║██║     ██╔══╝  "
echo "  ██████╔╝██║██║  ██║██║     ██║███████╗███████╗"
echo "  ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝"
echo -e "${NC}"
echo -e "${ORANGE}  Network Redteam Grapher v2.0 — Installateur universel${NC}"
echo ""

OS="$(uname -s)"
ARCH="$(uname -m)"
info "Système : $OS / $ARCH"
info "LLM provider : ${LLM_PROVIDER:-config.json}"
info "LLM modèle   : ${LLM_MODEL:-config.json}"

# ── Docker-only ───────────────────────────────────────────────────
if [ "$DOCKER_ONLY" = "1" ]; then
    step "Mode Docker uniquement"
    command -v docker &>/dev/null || error "Docker non trouvé. Installez depuis : https://www.docker.com/products/docker-desktop/"
    info "Build de l'image Docker DIAPILE..."
    docker build -t nrtg .
    ok "Image nrtg construite"
    docker run --rm nrtg --features
    exit 0
fi

# ================================================================
# LINUX
# ================================================================
install_linux() {
    step "Installation des dépendances Linux"
    SUDO=""; [ "$(id -u)" != "0" ] && SUDO="sudo"

    if command -v apt-get &>/dev/null; then
        info "Distro : Debian / Ubuntu / Kali"
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq \
            build-essential pkg-config ca-certificates \
            libpcap-dev libssl-dev curl git
        ok "Dépendances Debian OK"

    elif command -v dnf &>/dev/null; then
        info "Distro : Fedora"
        $SUDO dnf install -y -q \
            gcc make pkg-config openssl-devel libpcap-devel ca-certificates curl git
        ok "Dépendances Fedora OK"

    elif command -v yum &>/dev/null; then
        info "Distro : CentOS / RHEL"
        $SUDO yum install -y -q epel-release
        $SUDO yum install -y -q gcc make pkg-config openssl-devel libpcap-devel curl git
        ok "Dépendances CentOS OK"

    elif command -v pacman &>/dev/null; then
        info "Distro : Arch / Manjaro"
        $SUDO pacman -Syu --needed --noconfirm base-devel openssl libpcap pkg-config curl git
        ok "Dépendances Arch OK"

    elif command -v zypper &>/dev/null; then
        info "Distro : openSUSE"
        $SUDO zypper install -y gcc make pkg-config libopenssl-devel libpcap-devel curl git
        ok "Dépendances openSUSE OK"

    elif command -v apk &>/dev/null; then
        info "Distro : Alpine Linux"
        $SUDO apk add --no-cache build-base pkgconf openssl-dev libpcap-dev curl git
        ok "Dépendances Alpine OK"

    else
        warn "Gestionnaire de paquets non reconnu."
        warn "Installez manuellement : libpcap-dev  libssl-dev  pkg-config  build-essential  curl  git"
    fi
}

# ================================================================
# macOS
# ================================================================
install_macos() {
    step "Installation des dépendances macOS"

    # Xcode CLT
    if ! xcode-select -p &>/dev/null 2>&1; then
        info "Installation des Xcode Command Line Tools..."
        xcode-select --install
        warn "Attendez la fin de l'installation Xcode, puis relancez ce script."
        exit 0
    else
        ok "Xcode CLT déjà installé"
    fi

    # Homebrew
    if ! command -v brew &>/dev/null; then
        info "Installation de Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        # Apple Silicon
        [ -f "/opt/homebrew/bin/brew" ] && eval "$(/opt/homebrew/bin/brew shellenv)"
    else
        ok "Homebrew : $(brew --version | head -1)"
    fi

    # OpenSSL
    if ! brew list openssl &>/dev/null 2>&1; then
        info "Installation d'OpenSSL via Homebrew..."
        brew install openssl
    else
        ok "OpenSSL déjà installé"
    fi

    ok "libpcap natif macOS disponible"

    # Variables d'env pour la compilation
    OPENSSL_PREFIX="$(brew --prefix openssl)"
    export OPENSSL_DIR="$OPENSSL_PREFIX"
    export PKG_CONFIG_PATH="$OPENSSL_PREFIX/lib/pkgconfig"

    # Persister dans le profil shell
    SHELL_RC=""
    [ -f "$HOME/.zshrc" ]       && SHELL_RC="$HOME/.zshrc"
    [ -f "$HOME/.bash_profile" ] && SHELL_RC="$HOME/.bash_profile"

    if [ -n "$SHELL_RC" ] && ! grep -q "OPENSSL_DIR" "$SHELL_RC" 2>/dev/null; then
        {
            echo ""
            echo "# DIAPILE — OpenSSL via Homebrew"
            echo "export OPENSSL_DIR=\"$OPENSSL_PREFIX\""
            echo "export PKG_CONFIG_PATH=\"$OPENSSL_PREFIX/lib/pkgconfig\""
        } >> "$SHELL_RC"
        ok "Variables OPENSSL ajoutées à $SHELL_RC"
    fi

    ok "Dépendances macOS prêtes"
}

# ================================================================
# RUST
# ================================================================
install_rust() {
    step "Vérification de Rust"
    if command -v rustc &>/dev/null && command -v cargo &>/dev/null; then
        ok "Rust : $(rustc --version)"
        rustup update stable --no-self-update 2>/dev/null || true
    else
        info "Installation de Rust via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        # shellcheck source=/dev/null
        [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
        ok "Rust installé : $(rustc --version)"
    fi
}

# ================================================================
# DOCKER CHECK
# ================================================================
check_docker() {
    step "Vérification Docker"
    if command -v docker &>/dev/null; then
        ok "Docker : $(docker --version)"
    else
        warn "Docker non trouvé — méthode Docker non disponible."
        warn "Installer depuis : https://www.docker.com/products/docker-desktop/"
    fi
}

# ================================================================
# CONFIGURATION LLM (tous providers OpenAI-compatibles)
#   openrouter · openai · ollama (local) · tout endpoint custom
# ================================================================
configure_llm() {
    step "Configuration LLM (provider OpenAI-compatible)"
    ENV_FILE=".env"

    # Créer .env depuis le template si absent
    if [ ! -f "$ENV_FILE" ]; then
        cp ".env.example" "$ENV_FILE" 2>/dev/null || touch "$ENV_FILE"
    fi

    # Renseigner config.json UNIQUEMENT si l'utilisateur a fourni des valeurs en CLI
    if [ -n "$LLM_PROVIDER" ] || [ -n "$LLM_MODEL" ]; then
        if command -v python3 &>/dev/null && [ -f "config.json" ]; then
            LLM_PROVIDER="$LLM_PROVIDER" LLM_MODEL="$LLM_MODEL" python3 - <<'PYEOF'
import json, os
with open("config.json") as f:
    c = json.load(f)
opts = c.setdefault("options", {})
provider = os.environ.get("LLM_PROVIDER", "").strip()
model    = os.environ.get("LLM_MODEL", "").strip()
if provider:
    opts["llm_provider"] = provider
if model:
    opts["llm_model"] = model
with open("config.json", "w") as f:
    json.dump(c, f, indent=2, ensure_ascii=False)
PYEOF
            ok "config.json → llm_provider=${LLM_PROVIDER:-inchangé} · llm_model=${LLM_MODEL:-inchangé}"
        else
            warn "python3 non disponible — mettez à jour config.json manuellement :"
            [ -n "$LLM_PROVIDER" ] && warn "  \"llm_provider\": \"$LLM_PROVIDER\""
            [ -n "$LLM_MODEL" ]    && warn "  \"llm_model\": \"$LLM_MODEL\""
        fi
    else
        info "Provider/modèle conservés tels quels (config.json)."
    fi

    # Variable de clé attendue selon le provider choisi
    case "${LLM_PROVIDER:-openrouter}" in
        ollama|local) KEY_VAR="";               KEY_URL="";;
        openai|oai)   KEY_VAR="OPENAI_API_KEY"; KEY_URL="https://platform.openai.com/api-keys";;
        *)            KEY_VAR="OPENROUTER_API_KEY"; KEY_URL="https://openrouter.ai/keys";;
    esac

    # Provider local : aucune clé nécessaire
    if [ -z "$KEY_VAR" ]; then
        ok "Provider local (Ollama) — aucune clé API requise."
        return 0
    fi

    # Clé déjà renseignée (non vide et non placeholder) ?
    if grep -Eq "^${KEY_VAR}=.+" "$ENV_FILE" 2>/dev/null && \
       ! grep -q "^${KEY_VAR}=sk-xxxx" "$ENV_FILE" 2>/dev/null; then
        ok "${KEY_VAR} déjà configurée dans .env"
        return 0
    fi

    echo ""
    warn "${KEY_VAR} non configurée."
    echo -e "  ${CYAN}Pour activer l'agent IA, ajoutez votre clé dans .env :${NC}"
    echo -e "  ${ORANGE}  ${KEY_VAR}=...${NC}"
    [ -n "$KEY_URL" ] && echo -e "  ${CYAN}Obtenez une clé sur : ${KEY_URL}${NC}"
    echo ""
    read -rp "  Entrez votre clé ${KEY_VAR} (ou Entrée pour passer) : " KEY
    if [ -n "$KEY" ]; then
        if grep -q "^${KEY_VAR}=" "$ENV_FILE"; then
            sed -i "s|^${KEY_VAR}=.*|${KEY_VAR}=${KEY}|" "$ENV_FILE"
        else
            echo "${KEY_VAR}=${KEY}" >> "$ENV_FILE"
        fi
        ok "Clé ${KEY_VAR} sauvegardée dans .env"
    else
        warn "Clé non fournie — les providers distants seront indisponibles."
        warn "Alternative locale sans clé : --llm-provider ollama --llm-model llama3"
    fi
}

# ================================================================
# BUILD
# ================================================================
build_nrtg() {
    step "Compilation de DIAPILE / NRTG"

    # Recharger cargo si besoin
    command -v cargo &>/dev/null || { [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"; }

    mkdir -p out

    # Déterminer le nombre de jobs selon CPU
    JOBS=2
    if command -v nproc &>/dev/null; then
        CPU=$(nproc)
        [ "$CPU" -gt 4 ] && JOBS=4
        [ "$CPU" -gt 8 ] && JOBS=6
    elif command -v sysctl &>/dev/null; then
        CPU=$(sysctl -n hw.ncpu 2>/dev/null || echo 2)
        [ "$CPU" -gt 4 ] && JOBS=4
    fi

    info "Compilation release avec $JOBS jobs (patience — première fois ~3-8 min)..."
    cargo build --release -j"$JOBS"

    BINARY="./target/release/nrtg"
    if [ -f "$BINARY" ]; then
        ok "Binaire : $BINARY"
        DIAPILE_VER=$($BINARY --version 2>/dev/null | head -1 || echo "v2.0.0")
        echo ""
        echo -e "${FIRE}${BOLD}"
        echo "  ╔══════════════════════════════════════════════════════╗"
        echo "  ║  ✅  DIAPILE installé avec succès !                  ║"
        echo "  ║                                                      ║"
        echo "  ║  Commandes de démarrage :                            ║"
        echo "  ║    ./target/release/nrtg --features                  ║"
        echo "  ║    ./target/release/nrtg --examples                  ║"
        echo "  ║    ./target/release/nrtg --doctor                    ║"
        echo "  ║    ./target/release/nrtg --tutorial                  ║"
        echo "  ║                                                      ║"
        echo "  ║  Rapport HTML : ouvrir graph.report.html             ║"
        echo "  ║  Dashboard   : ouvrir dashboard.html                 ║"
        echo "  ╚══════════════════════════════════════════════════════╝"
        echo -e "${NC}"
    else
        error "Compilation échouée — vérifiez les erreurs ci-dessus."
    fi
}

# ================================================================
# VÉRIFICATION POST-INSTALL
# ================================================================
run_doctor() {
    step "Vérification de l'environnement (--doctor)"
    command -v cargo &>/dev/null || { [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"; }
    BINARY="./target/release/nrtg"
    if [ -f "$BINARY" ]; then
        "$BINARY" --doctor || true
    else
        warn "Binaire non trouvé — compilez d'abord avec : cargo build --release"
    fi
}

# ================================================================
# MAIN
# ================================================================
case "$OS" in
    Linux)
        install_linux
        ;;
    Darwin)
        install_macos
        ;;
    MINGW*|CYGWIN*|MSYS*)
        warn "Windows détecté via Bash (Git Bash/MSYS)."
        warn "Utilisez install.ps1 en PowerShell natif :"
        warn "  powershell -ExecutionPolicy Bypass -File install.ps1"
        warn "Ou utilisez WSL2 et relancez ce script dans WSL."
        exit 1
        ;;
    *)
        error "OS non supporté : $OS. Utilisez Linux, macOS ou Docker."
        ;;
esac

install_rust
check_docker
configure_llm

# ── Outils Python optionnels (impacket, bloodhound-python, sshpass) ──
step "Outils Python optionnels (impacket, sshpass)"
SUDO=""; [ "$(id -u)" != "0" ] && SUDO="sudo"

# sshpass — pour bruteforce SSH
if ! command -v sshpass &>/dev/null; then
    if command -v apt-get &>/dev/null; then
        $SUDO apt-get install -y -qq sshpass 2>/dev/null && ok "sshpass installé" || warn "sshpass non disponible"
    elif command -v dnf &>/dev/null; then
        $SUDO dnf install -y -q sshpass 2>/dev/null && ok "sshpass installé" || warn "sshpass non disponible"
    fi
else
    ok "sshpass déjà installé"
fi

# impacket — pour Kerberoasting, PTH, DCSync
if command -v python3 &>/dev/null; then
    if ! python3 -c "import impacket" 2>/dev/null; then
        info "Installation impacket (Kerberoasting/PTH/DCSync)..."
        pip3 install impacket --quiet 2>/dev/null && ok "impacket installé" || warn "impacket : pip3 requis (pip3 install impacket)"
    else
        ok "impacket déjà installé"
    fi
    # bloodhound-python — pour BloodHound AD collection
    if ! python3 -c "import bloodhound" 2>/dev/null; then
        pip3 install bloodhound --quiet 2>/dev/null && ok "bloodhound-python installé" || warn "bloodhound-python : pip3 install bloodhound"
    else
        ok "bloodhound-python déjà installé"
    fi
fi

if [ "$SKIP_BUILD" = "0" ]; then
    build_nrtg
    run_doctor
else
    info "Build ignoré (--skip-build). Compilez avec : cargo build --release"
fi
