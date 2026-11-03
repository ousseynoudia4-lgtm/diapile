# DIAPILE — Network Redteam Grapher (NRTG) v2.0.0

```
██████╗ ██╗ █████╗ ██████╗ ██╗██╗     ███████╗
██╔══██╗██║██╔══██╗██╔══██╗██║██║     ██╔════╝
██║  ██║██║███████║██████╔╝██║██║     █████╗
██║  ██║██║██╔══██║██╔═══╝ ██║██║     ██╔══╝
██████╔╝██║██║  ██║██║     ██║███████╗███████╗
╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝

AI-Powered Red Team Framework — v2.0.0
```

🔥 **Framework d'opérations Red Team automatisé** — analyse de risques, orchestration offensive, agent IA autonome, cartographie de surfaces d'attaque.

> **NOUVEAU v2.0** — Scanner enrichi (30+ services), rapport HTML DIAPILE dark theme, 29 signatures d'exploit, agent IA multi-provider (OpenRouter payant, OpenAI, ou **Ollama local 100 % gratuit**), détection WAF/OS/tech-stack avancée.

---

## ⚠️ Avertissement Légal

Cet outil est conçu **exclusivement pour des opérations Red Team autorisées et des audits de sécurité professionnels**. L'utilisation de NRTG sur des infrastructures sans autorisation écrite explicite est strictement interdite et illégale.

---

## 📑 Sommaire

1. [Nouveautés v2.0](#-nouveautés-v20)
2. [Capacités Opérationnelles](#️-capacités-opérationnelles)
3. [Installation Universelle](#-installation-universelle-tous-os) · [INSTALL.md](INSTALL.md)
4. [Quick Start 5 minutes](#-quick-start---5-minutes)
5. [Agent IA Autonome](#-agent-ia-autonome-red-team)
6. [Utilisation CLI](#-utilisation-cli)
7. [Sorties générées](#-sorties-générées)
8. [Configuration LLM](#-configuration-llm)
9. [Dépannage](#-dépannage)
10. [Structure du projet](#-structure-du-projet)

---

## 🆕 Nouveautés v2.0

| Composant | Avant | Maintenant |
|---|---|---|
| **Scanner** | 15 services/ports | **30+ services** : SMB, RDP, LDAP, Elasticsearch, Memcached, RabbitMQ, Docker API, etcd, Kibana, Kafka, Zookeeper… |
| **Banners HTTP** | Server header seulement | **Full headers** + body snippet + `<title>` extraction + tech stack |
| **WAF detection** | 9 signatures | **16 WAF** : Cloudflare, Fastly, Radware, Wallarm, StackPath… |
| **OS fingerprint** | 5 TTL signatures | **7 signatures** : Cisco IOS, AIX, OpenBSD, Windows, Linux… |
| **Tech stack** | 4 CMS | **8 CMS + 9 frameworks + 7 JS libs + CDN + auth provider** |
| **Rapport HTML** | Tailwind CDN basique | **DIAPILE dark cyberpunk** — standalone, zero CDN, risk gauge, NVD links |
| **Signatures exploit** | 13 | **29** : +Redis INFO/write, VSFTPD backdoor, MySQL root/anonyme, WinRM, Kubernetes, VNC, MQTT, SNMP public, Kerberos, Docker API, etcd, Kibana, Grafana, PHP2Shell |
| **LLM modèle** | google/gemma-2-9b-it (404) | **Multi-provider** : OpenRouter payant, OpenAI, ou **Ollama local** (gratuit, sans clé) — les modèles OpenRouter `:free` ont été retirés |
| **Headers sécurité** | — | **Analyse passive** : CORS wildcard, HSTS faible, headers manquants, default-creds |
| **Outils tiers** | Installation seule (suggestion de commande) | **Installation + exécution réelle** (action `external_tool`) + **parsing structuré** : 26 capacités (intention → outil), sortie réinjectée en mémoire |

> 📜 **Historique complet des versions** : [CHANGELOG.md](CHANGELOG.md) · version courante : [VERSION](VERSION) (miroir de [Cargo.toml](Cargo.toml)).

---

## 🛠️ Capacités Opérationnelles

### 1. Reconnaissance & Scanner

- **30+ services** : HTTP/S, SSH, FTP, SMTP, Redis, MySQL, PostgreSQL, MSSQL, MongoDB, SMB, RDP, LDAP, Elasticsearch, Memcached, RabbitMQ, Docker API, etcd, Kibana, InfluxDB, Kafka, Zookeeper, Telnet, DNS…
- **Probes spécialisés par protocole** : Redis `INFO`, MongoDB isMaster, SMTP EHLO, FTP FEAT, Elasticsearch JSON, AMQP header…
- **HTTP full-header capture** : Server, X-Powered-By, WAF headers, Set-Cookie analysis, page `<title>` extraction
- **Fingerprinting** : version précise (regex + semver), OS guess par TTL, stack technique complète, détection protections périmétriques

### 2. Détection WAF & Sécurité Headers (passive)

16 signatures WAF : Cloudflare, Akamai, AWS WAF, ModSecurity, F5 BIG-IP, Imperva, Sucuri, Barracuda, FortiWeb, Radware, Fastly, Varnish, Reblaze, Wallarm, StackPath, Nginx WAF.

Analyse passive des headers : CORS wildcard, HSTS absent/faible, Server version disclosure, X-Powered-By leak, cookies insecure, headers sécurité manquants.

### 3. Signatures d'Exploit (29 total, dry-run par défaut)

| ID | Catégorie | Sévérité | Service |
|---|---|---|---|
| `REDIS-ANON-INFO` | misconfiguration | HIGH | Redis |
| `REDIS-ANON-PING` | misconfiguration | HIGH | Redis |
| `REDIS-UNAUTH-WRITE` | misconfiguration | CRITICAL | Redis |
| `FTP-ANON-LOGIN` | misconfiguration | MEDIUM | FTP |
| `VSFTPD-234-SMILEY-BACKDOOR` | remote-code-execution | CRITICAL | VSFTPD / FTP |
| `MONGO-NOAUTH` | misconfiguration | HIGH | MongoDB |
| `MYSQL-ROOT-EMPTY-PASSWORD` | weak-credentials | CRITICAL | MySQL / MariaDB |
| `MYSQL-ANON-EMPTY` | weak-credentials | HIGH | MySQL / MariaDB |
| `HTTP-DEFAULT-ADMIN-BASIC` | weak-credentials | HIGH | HTTP/S |
| `HTTP-PATH-TRAV-SAFE` | injection | HIGH | HTTP/S |
| `HTTP-MISSING-SECURITY-HEADERS` | misconfiguration | MEDIUM | HTTP/S |
| `SSH-WEAK-KEX` | crypto | MEDIUM | SSH |
| `SMB-NULL-SESSION` | misconfiguration | HIGH | SMB |
| `ELASTICSEARCH-OPEN` | misconfiguration | HIGH | Elasticsearch |
| `SMTP-OPEN-RELAY` | misconfiguration | HIGH | SMTP |
| `TELNET-PLAINTEXT` | crypto | HIGH | Telnet |
| `SNMP-DEFAULT-COMMUNITY` | weak-credentials | HIGH | SNMP |
| `SNMP-PUBLIC-COMMUNITY` | weak-credentials | HIGH | SNMP |
| `JENKINS-UNAUTH` | misconfiguration | CRITICAL | Jenkins |
| `DOCKER-API-UNAUTH` | misconfiguration | CRITICAL | Docker API |
| `ETCD-OPEN` | misconfiguration | CRITICAL | etcd |
| `KIBANA-OPEN` | misconfiguration | HIGH | Kibana |
| `GRAFANA-DEFAULT-CREDS` | weak-credentials | HIGH | Grafana |
| `WINRM-DEFAULT-CREDS` | weak-credentials | CRITICAL | WinRM |
| `KUBERNETES-API-UNAUTH` | misconfiguration | CRITICAL | Kubernetes API |
| `VNC-NO-AUTH` | misconfiguration | CRITICAL | VNC |
| `MQTT-UNAUTH-BROKER` | misconfiguration | HIGH | MQTT |
| `KERBEROS-KDC-EXPOSED` | misconfiguration | MEDIUM | Kerberos |
| `PHP2SHELL-VERSION-EXPOSED` | vulnerable-version | CRITICAL | HTTP/S |

> `PHP2SHELL-VERSION-EXPOSED` est une détection **passive** (GET bénin + empreinte de version
> exposée) : le vecteur réel de PHP2Shell (CVE-2026-109618 / CVE-2026-109619) étant un
> épuisement de mémoire, aucun probe destructeur n'est jamais envoyé. Elle n'est évaluée
> qu'à la profondeur `deep` (catégorie `vulnerable-version`).

### 4. Evasion & Stealth

- **Anti-Analyse** : détection sandbox/VM (VMware/VBox/Hyper-V/QEMU), debuggers (x64dbg/IDA/gdb/strace)
- **Encodeurs payload** : XOR, Base64, Shikata Ga Nai polymorphe, AES-256-GCM
- **Traffic Obfuscation** : DNS tunneling, Domain Fronting, HTTPS factice
- **Mode Low & Slow** : jitter configurable, buffer_unordered pour scan parallèle limité

### 5. Agent IA Autonome

Voir section dédiée ci-dessous.

### 6. Intégrations

- **Metasploit RPC** : auth.login, module.execute, sessions, credentials
- **BloodHound AD** : User/Computer/Group/Domain/GPO/OU, Unconstrained Delegation, LocalAdmins

---

## 🚀 Installation Universelle (tous OS)

> 📖 **Guide détaillé** — prérequis, build manuel, Docker, **outils tiers optionnels** et dépannage : **[INSTALL.md](INSTALL.md)**.

### 🪟 Windows

```powershell
# Option 1 — Script automatique (recommandé)
powershell -ExecutionPolicy Bypass -File install.ps1

# Option 2 — Avec llvm-mingw local (si VS Build Tools absent)
$env:PATH = "C:\chemin\vers\llvm-mingw\bin;" + $env:PATH
cargo build -j2

# Options du script :
#   -SkipNpcap   : sans capture live (scan TCP/HTTP OK)
#   -SkipVS      : sans VS Build Tools
#   -DockerOnly  : build via Docker uniquement
```

### 🐧 Linux

```bash
bash install.sh
# Détecte automatiquement : Ubuntu/Debian/Kali, Fedora, CentOS, Arch, openSUSE, Alpine
```

### 🍎 macOS

```bash
bash install.sh
# Installe : Xcode CLT + Homebrew + OpenSSL + Rust
```

### 🐳 Docker (tous OS, recommandé)

```bash
# Build
docker build -t nrtg .

# Scan lab local
docker run --rm -v "${PWD}/out:/app/out" \
  --add-host=host.docker.internal:host-gateway \
  nrtg -t http://host.docker.internal:8080,host.docker.internal:6379

# Capture LIVE (Linux uniquement)
docker run --rm --network host --cap-add=NET_RAW \
  -v "${PWD}/out:/app/out" \
  nrtg --capture-iface eth0 --capture-duration 45
```

---

## ⚡ Quick Start — 5 minutes

```bash
# 1. Lab Docker vulnérable (nginx, redis, ssh, smtp, ftp)
docker compose up -d

# 2. Scan complet + tous les exports
cargo run --release -- \
  -t http://localhost:8080,127.0.0.1:6379,127.0.0.1:2222,127.0.0.1:1025,127.0.0.1:21 \
  --csv --md --export-api-report --parallel 20

# 3. Ouvrir le rapport HTML DIAPILE
#   Windows : start graph.report.html
#   macOS   : open graph.report.html
#   Linux   : xdg-open graph.report.html

# 4. Vérification de l'environnement
cargo run --release -- --doctor

# 5. Scan réseau local (gateway)
cargo run --release -- \
  -t "192.168.1.1:80,192.168.1.1:443,192.168.1.1:22,192.168.1.1:8080,192.168.1.1:23" \
  --csv --md --export-api-report --tcp-timeout 2 --http-timeout 4
```

---

## 🤖 Agent IA Autonome Red Team

### Principe

L'agent IA pilote le cycle complet d'une opération offensive. Le LLM planifie la kill-chain, demande confirmation avant toute action HIGH/CRITICAL, et retient tout en mémoire persistante pour reprendre après interruption.

```
Recon scan → Plan LLM → Confirmation humaine → Exécution → Mémoire → Rapport
```

### Démarrage rapide

```powershell
# 1. Configurer la clé OpenRouter dans .env
echo "OPENROUTER_API_KEY=sk-or-v1-..." >> .env

# 2. Lancer l'agent
.\target\debug\nrtg.exe --ai-agent `
  --targets 192.168.1.0/24 `
  --objective "identifier les hôtes vulnérables et tenter un premier accès"

# 3. Mode stealth (low & slow, évite les IDS)
.\target\debug\nrtg.exe --ai-agent --ai-stealth `
  --targets 10.0.0.0/24 --objective "pivot interne depuis 10.0.0.5"

# 4. Reprendre une campagne après interruption
.\target\debug\nrtg.exe --ai-agent `
  --session-id op-20260829-143022 `
  --targets 192.168.1.0/24 `
  --objective "compromettre le contrôleur de domaine"
```

### Options agent

| Option | Défaut | Description |
|---|---|---|
| `--ai-agent` | false | Active le mode agent IA autonome |
| `--objective` | "identifier les hôtes vulnérables" | Objectif de la mission |
| `--session-id` | auto (timestamp) | Reprendre une campagne |
| `--sessions-dir` | `./sessions` | Dossier de persistance |
| `--ai-stealth` | false | Mode low & slow (agent IA) |
| `--confirm-all` | false | Confirmation pour toutes les actions |
| `--parallel` | 20 | Workers de scan parallèles |

### Confirmation humaine (actions HIGH/CRITICAL)

```
╔══ CONFIRMATION REQUISE ═══════════════════════════════╗
║  🟠 Risque : HIGH
║  Action   : Exploit
║  Cible    : 192.168.1.10:22
║  Méthode  : CVE-2018-15473 SSH user enumeration
║  Raison   : SSH 7.6 détecté, enum users avant bruteforce
║  Succès   : 75%
╠═══════════════════════════════════════════════════════╣
║  [o]ui = exécuter  [n]on = passer  [s]top = arrêter  ║
╚══ Votre choix :
```

### Exécution d'outils tiers (`external_tool`)

Au-delà de ses modules natifs, l'agent peut **installer puis exécuter réellement** un outil tiers (nmap, ffuf, sqlmap, nuclei, impacket-*, …) et **réinjecter sa sortie** dans la mémoire de campagne — plus de simple suggestion de commande.

- **Registre de capacités** ([ai/capability_registry.rs](src/ai/capability_registry.rs)) : le LLM n'a plus à deviner le binaire. Il exprime une **intention** (ex. « fuzzing de répertoires ») ; le registre sélectionne le premier outil **présent dans le PATH** parmi des candidats ordonnés, puis génère les arguments (`{host}`, `{port}`, `{url}`, `{wordlist}`…).
- **Parsing structuré** ([ai/tool_parsers.rs](src/ai/tool_parsers.rs)) : la sortie brute devient des artefacts typés injectés automatiquement — ports/services → `HostMemory.services`, chemins web → `WebSurface.endpoints`, identifiants vérifiés et hashs Kerberos/NTLM → `credentials`, DNS/comptes → `notes`, SQLi → hypothèses.
- **26 capacités** couvrant recon, web, AD/Kerberos, post-exploitation, pivot et C2 (détail dans [HELP.md](HELP.md#10--agent-ia-autonome)).

```bash
# Autonome : installe, exécute et parse sans intervention
nrtg --ai-agent --autonomous --targets 10.0.0.0/24 \
     --objective "cartographier et exploiter les services exposés"
```

### Modèles LLM — état 2026

> Utiliser un modèle payant OpenRouter, un endpoint OpenAI-compatible, ou **Ollama en local** (gratuit, aucune clé).

| Option | Coût | Recommandé pour |
|---|---|---|
| **Ollama local** (`llama3`, `mistral`…) | 🆓 Gratuit, zéro clé | **Défaut conseillé** — Recon, planning, 100 % on-device |
| `meta-llama/llama-3.1-70b-instruct` (OpenRouter) | 💰 ~0.1$/1k | Campagnes complexes |
| `openai/gpt-4o` (OpenRouter) | 💰 ~0.5$/1k | Opérations critiques |
| Endpoint OpenAI-compatible (vLLM, LM Studio, Groq…) | variable | Déploiements sur mesure |

Pour changer de modèle :
```json
{ "options": { "llm_model": "meta-llama/llama-3.1-70b-instruct" } }
```

---

## 💻 Utilisation CLI

```bash
# Aide étendue interactive
nrtg                    # aide colorisée complète
nrtg --features         # modules + sorties disponibles
nrtg --examples         # 10 exemples prêts à copier
nrtg --tutorial         # guide pas à pas
nrtg --doctor           # vérification environnement

# ── Scans ──
# Scan simple HTTP+TCP avec exports
nrtg -t http://prod.example:443,10.0.0.5:22,10.0.0.5:3306 --csv --md --export-api-report

# CIDR complet /24 avec un port
nrtg -t 192.168.1.0/24:22 --parallel 30 --tcp-timeout 2

# Scan parallèle gateway
nrtg -t 192.168.1.1:80,192.168.1.1:443,192.168.1.1:22,192.168.1.1:8080 \
     --parallel 20 --tcp-timeout 2 --http-timeout 4 \
     --csv --md --export-api-report -o gateway.json

# ── Exploits ──
# Dry-run (défaut — aucun paquet envoyé)
nrtg -t 127.0.0.1:6379 --exploit-depth deep

# Exploits actifs (probes read-only)
nrtg -t 127.0.0.1:6379 --run-exploits --exploit-depth deep --yes

# ── IA ──
# Rapport IA OpenRouter
nrtg -t http://lab:80 --ai-report --ai-targets 10 \
     --llm-provider openrouter --llm-model meta-llama/llama-3.1-70b-instruct

# IA locale Ollama (gratuit, zéro API key)
nrtg -t http://lab:80 --ai-report \
     --llm-provider ollama --llm-api-base http://localhost:11434 --llm-model llama3

# ── Listes externes (.txt) ──
# Bruteforce : fusion additive des wordlists (par défaut)
nrtg -t 10.0.0.5:22 --brute --yes \
     --brute-users users.txt --brute-passwords pass.txt

# Bruteforce : remplacer les listes embarquées au lieu de fusionner
nrtg -t 10.0.0.5:22 --brute --yes \
     --brute-users users.txt --brute-passwords pass.txt --brute-lists-replace

# Web : payloads externes par famille (répétable, colonnes séparées par TAB)
#   format : payload [TAB] marqueur_détection_optionnel  (ssti = 3 colonnes)
nrtg --web-scan https://lab.local \
     --web-payloads sqli=mes_sqli.txt --web-payloads xss=mes_xss.txt

# Web : remplacer les payloads embarqués de la famille
nrtg --web-scan https://lab.local --web-payloads sqli=mes_sqli.txt --web-payloads-replace

# Spider : extensions statiques supplémentaires exclues du crawl (une par ligne)
nrtg --web-spider https://lab.local --spider-ext exclusions.txt

# ── Installation auto des outils tiers (opt-in) ──
# L'agent installe N'IMPORTE QUEL outil tiers dont il a besoin : détection du
# gestionnaire de paquets (apt/dnf/pacman/brew/winget/pip) + registre d'outils
# connus (sshpass, impacket-*, hydra, kinit, msfvenom, iproute2…). Repli : binaire = nom de paquet.
# Sans ce flag : fail-closed (aucune installation, simple suggestion).
# Garde-fou : seuls les outils « Low » (diagnostic réseau) sont auto-confirmés
# par --yes ; Medium/High/inconnu exige une validation humaine.
# Mode autonome (non-interactif complet) : --autonomous ⟹ --auto-install + --yes
# et lève le verrou de confirmation. Tracé dans diapile_installs.log.
nrtg -t 10.0.0.5:22 --brute --yes --auto-install
nrtg -t 10.0.0.5 --ai-agent --autonomous
nrtg --kerberoast --dc-ip 10.0.0.10 --ad-domain corp.local \
     --ad-user svc --ad-pass 'P@ss' --yes --auto-install

# ── Utilitaires ──
nrtg --update-cve-db          # Télécharger CVEs depuis NVD API v2
nrtg --list-ifaces            # Lister les interfaces réseau
nrtg --capture-iface eth0 --capture-duration 45 -t 192.168.1.10:22
```

### Format des fichiers `.txt`

Une entrée par ligne ; lignes vides et commentaires (`#`) ignorés ; `trim` appliqué et dédoublonnage automatique. Les listes externes **s'ajoutent** aux valeurs embarquées par défaut ; les flags `--brute-lists-replace` / `--web-payloads-replace` substituent la famille concernée. Plafonds : 100 000 entrées (wordlists) et 20 000 entrées par famille (payloads web). Les chemins sont résolus par rapport au binaire (ou au répertoire courant).

---

## 📁 Sorties générées

Chaque scan génère automatiquement :

| Fichier | Description |
|---|---|
| `graph.json` | Graphe complet (nœuds + liens + métadonnées) |
| `graph.extras.json` | Sidecar : exploits findings, WAF/OS/tech, analyses IA |
| `graph.csv` | Plat CSV importable Sheets/Excel |
| `graph.md` | Résumé Markdown humain |
| `graph.api.json` | ApiReport JSON structuré |
| `graph.report.html` | **Rapport DIAPILE standalone** (dark theme, zero CDN) |
| `graph.ai-report.md` | Rapport narratif IA (si `--ai-report`) |

Le rapport HTML contient :
- Bannière DIAPILE fire ASCII
- Gauge de risque global
- Cartes statistiques (hosts, ports, CVEs, critical)
- Tableau des hôtes avec banners et services détectés
- Tableau CVEs trié par sévérité avec liens NVD
- Breakdown risque par hôte avec facteurs
- Section flows réseau (si capture active)

---

## 🔧 Configuration LLM

Copiez `.env.example` vers `.env` :

```bash
# Option A — OpenRouter (recommandé — modèles gratuits disponibles)
OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxxx

# Option B — OpenAI
OPENAI_API_KEY=sk-xxxxxxxxxx

# Option C — Ollama local (100% gratuit, zéro clé)
# ollama pull mistral
# nrtg --llm-provider ollama --llm-model mistral --llm-api-base http://localhost:11434
```

Dans `config.json` :
```json
{
  "options": {
    "llm_provider": "openrouter",
    "llm_model": "meta-llama/llama-3.1-70b-instruct",
    "llm_api_key_env": "OPENROUTER_API_KEY"
  }
}
```

---

## 🔍 Dépannage

| Symptôme | Cause | Solution |
|---|---|---|
| `link.exe not found` | VS Build Tools C++ absent | `winget install Microsoft.VisualStudio.2022.BuildTools` ou `install.ps1` |
| `cannot find -lPacket` | NPCAP absent (Windows) | Installer NPCAP : [npcap.com](https://npcap.com) |
| `dlltool not found` | llvm-mingw pas dans PATH | Ajouter `tools\llvm-mingw-20240619-ucrt-x86_64\bin` au PATH |
| `libpcap not found` | libpcap-dev manquant (Linux) | `sudo apt-get install libpcap-dev` |
| `OPENSSL_DIR not set` | OpenSSL absent (macOS) | `brew install openssl` puis relancer `install.sh` |
| `HTTP 404 LLM` | Modèle OpenRouter `:free` retiré | Utiliser un modèle payant, un endpoint OpenAI-compatible, ou Ollama local dans `config.json` |
| `0 hosts reachable` | Firewall bloque les ports | Essayer d'autres ports : 80, 443, 53, 22 |
| Build OOM | Trop de jobs | `cargo build -j2` |
| Rapport IA vide / 401 | Clé API manquante | Vérifier `OPENROUTER_API_KEY` dans `.env` |
| `duplicate field` exploits.yaml | YAML malformé | Vérifier qu'il n'y a pas de champ dupliqué |

```bash
# Diagnostic complet
nrtg --doctor

# Build minimal de vérification
cargo run -- -t http://localhost:8080 --md
```

---

## 📁 Structure du projet

```
hackist/
├─ src/
│  ├─ agents/               # Sous-agents à contexte borné (discovery · web · exploit · post-exploit · latéral · reporting)
│  ├─ ai/                   # attack_planner · campaign_memory · autonomous_agent · hypothesis · recommendation_engine · rl_agent · capability_registry · tool_parsers
│  ├─ c2/                   # Canaux C2 : HTTP · WebSocket · DNS + crypto agent
│  ├─ horde/                # Coordination distribuée : coordinator · swarm · worker · transport · report
│  ├─ integrations/         # Metasploit RPC · BloodHound AD
│  ├─ scanner/              # enhanced.rs : 16 WAF · 7 OS TTL · 8 CMS · 9 frameworks · CDN · sec headers
│  ├─ stress/               # Tests de charge (goldeneye)
│  ├─ main.rs               # CLI Clap + bannière DIAPILE + run_doctor + run_ai_agent
│  ├─ main_helpers.rs       # Helpers CLI partagés
│  ├─ scanner.rs            # 30+ services · probes spécialisés · page title · HTTP headers
│  ├─ netscan.rs            # Moteur de scan réseau (ports, timeouts durs)
│  ├─ network_advanced.rs   # Techniques réseau avancées
│  ├─ capture.rs            # Sniffing promiscuous pnet (stub Windows)
│  ├─ flows.rs              # Analyse de flux réseau
│  ├─ evasion.rs            # Anti-VM · Anti-debug · SGN · AES-GCM · DNS tunnel
│  ├─ exploits.rs           # Orchestrateur YAML (29 probes, 3 profondeurs)
│  ├─ exploit_engine.rs     # Exploits concrets (vsftpd, Shellshock…)
│  ├─ bruteforce.rs         # Brute-force multi-protocoles + listes externes .txt
│  ├─ web_attack.rs         # SQLi · XSS · LFI · SSRF · XXE · CMDi · SSTI · CRLF + payloads externes
│  ├─ web_spider.rs         # Crawl + injections + extensions exclues
│  ├─ ad.rs                 # Reconnaissance Active Directory
│  ├─ kerberos.rs           # AS-REP / Kerberoasting
│  ├─ ntlm.rs               # NTLM (relay / pass-the-hash)
│  ├─ post_exploit.rs       # Actions post-exploitation
│  ├─ pivot.rs              # Pivot / tunneling
│  ├─ shell.rs              # Gestion de sessions shell
│  ├─ iot_scada.rs          # Cibles IoT / SCADA
│  ├─ iptv.rs               # Cibles IPTV
│  ├─ osint.rs              # Collecte OSINT
│  ├─ oob.rs                # Callbacks out-of-band
│  ├─ orchestrator.rs       # Campagnes 7 phases · pivoting · sessions C2
│  ├─ llm.rs                # OpenAI · OpenRouter · Ollama + rapport IA
│  ├─ llm_exploit.rs        # Générateur exploits IA
│  ├─ mission_pack.rs       # Empaquetage de mission
│  ├─ live_dashboard.rs     # Dashboard live
│  ├─ exports.rs            # HTML DIAPILE dark theme · CSV · ApiReport JSON
│  ├─ report_gen.rs         # Génération de rapports
│  ├─ reports.rs            # GraphNode · ScanGraph · Markdown
│  ├─ cve.rs                # Matching CVE produit/version
│  ├─ nvd.rs                # Client NVD API v2
│  ├─ risk.rs               # Scoring risque 1→5 (règles JSON)
│  ├─ config.rs             # Chargement/résolution de configuration
│  ├─ logging.rs            # Initialisation du logging
│  └─ errors.rs             # Types d'erreurs
├─ exploits.yaml            # 29 signatures (Redis, VSFTPD, MySQL, WinRM, Kubernetes, VNC, MQTT, Kerberos, PHP2Shell…)
├─ config.json              # Runtime config (LLM : provider + modèle, clé via .env)
├─ cve_db.json              # Base CVE locale (mise à jour : --update-cve-db)
├─ risk_rules.json          # Règles de scoring de risque
├─ dashboard.html           # Visualisation D3.js cyberpunk
├─ launcher.html            # Launcher web
├─ Dockerfile               # Multi-stage (builder Rust + runtime slim)
├─ docker-compose.yml       # Lab de simulation local (tests)
├─ docker-compose.ai.yml    # Extension IA (OpenRouter)
├─ Makefile                 # Commandes opérationnelles (make scan, scan-web…)
├─ install.sh               # Linux/macOS universel
├─ install.ps1              # Windows universel
└─ .env.example             # Template clés API
```

---

## ✅ Build & Tests

```bash
# Build debug
cargo build -j2

# Build release optimisé
cargo build --release

# Tests unitaires
cargo test --all

# Vérification rapide
cargo check

# Lint
cargo clippy --all-targets
```

---

**DIAPILE — Visualiser, Comprendre, Conquérir.**
*Réservé aux opérations Red Team autorisées. MIT License.*
