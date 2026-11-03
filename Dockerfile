# ================================================================
# DIAPILE — Network Redteam Grapher v2.0
# Multi-stage build : builder Rust → runtime Debian bookworm slim
#
# PRÉREQUIS : Docker 20.10+
# BUILD     : docker build -t nrtg:latest .
# RUN       : docker run --rm -v "${PWD}/out:/app/out" nrtg:latest --features
# ================================================================

# ── Stage 1 : Builder ──────────────────────────────────────────────────────
# rust:bookworm = Debian 12 + dernière version Rust stable (~1.88+)
# Supporte edition2024, icu_*, idna_adapter, toutes les dépendances
FROM rust:bookworm AS builder

WORKDIR /build

# Dépendances système pour compiler DIAPILE
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpcap-dev \
        pkg-config \
        libssl-dev \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ── Cache des dépendances Cargo ──────────────────────────────────────────────
# Copier seulement Cargo.toml/lock + .cargo config AVANT le code source
# → les dépendances sont compilées une seule fois et cachées entre les builds
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo

# Build des dépendances avec un main.rs vide (crée un cache BuildKit réutilisable)
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs \
    && cargo build --release 2>/dev/null || true \
    && rm -rf src target/release/nrtg* target/release/deps/nrtg-* \
               target/release/deps/network_redteam_grapher-*

# ── Sources réelles ───────────────────────────────────────────────────────────
COPY src        ./src

# ── Compilation finale + strip ────────────────────────────────────────────────
RUN cargo build --release \
    && strip /build/target/release/nrtg \
    && ls -lh /build/target/release/nrtg \
    && echo "✅ DIAPILE build OK"

# ── Stage 2 : Runtime ──────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.title="DIAPILE — Network Redteam Grapher" \
      org.opencontainers.image.description="AI-Powered Red Team Framework" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.licenses="MIT"

# Runtime libs + tini + curl + outils red team Python
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libpcap0.8 \
        libssl3 \
        tini \
        curl \
        iputils-ping \
        net-tools \
        python3 \
        python3-pip \
        sshpass \
        nmap \
        netcat-openbsd \
    && pip3 install --no-cache-dir --break-system-packages \
        impacket \
        bloodhound \
        ldap3 \
    && rm -rf /var/lib/apt/lists/* /root/.cache/pip \
    && useradd -m -u 1000 -s /bin/bash nrtg \
    && mkdir -p /app/out /app/sessions \
    && chown -R nrtg:nrtg /app

WORKDIR /app

# Binaire
COPY --from=builder /build/target/release/nrtg /usr/local/bin/nrtg

# Configs
COPY --chown=nrtg:nrtg config.json     ./config.json
COPY --chown=nrtg:nrtg cve_db.json    ./cve_db.json
COPY --chown=nrtg:nrtg risk_rules.json ./risk_rules.json
COPY --chown=nrtg:nrtg exploits.yaml  ./exploits.yaml
COPY --chown=nrtg:nrtg dashboard.html ./dashboard.html
COPY --chown=nrtg:nrtg launcher.html  ./launcher.html

# Variables d'environnement par défaut
ENV RUST_LOG=info \
    NRTG_OUTPUT=/app/out/graph.json \
    NRTG_CONFIG=/app/config.json

VOLUME ["/app/out", "/app/sessions"]

HEALTHCHECK --interval=60s --timeout=10s --start-period=5s --retries=2 \
    CMD nrtg --version || exit 1

USER nrtg

ENTRYPOINT ["/usr/bin/tini", "--", "nrtg"]
CMD ["--features"]
