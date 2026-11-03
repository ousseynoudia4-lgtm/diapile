# INSTALL — Installation de DIAPILE / NRTG

> **DIAPILE — Network Redteam Grapher v2.0.0** · Binaire : `nrtg` · Crate : `network_redteam_grapher`
>
> ⚠️ **Usage exclusivement réservé aux opérations Red Team autorisées.**

Version faisant foi : [Cargo.toml](Cargo.toml) (`CARGO_PKG_VERSION`) · Miroir : [VERSION](VERSION) · Historique : [CHANGELOG.md](CHANGELOG.md).

---

## 📑 Sommaire

1. [Prérequis](#-prérequis)
2. [Installation rapide](#-installation-rapide)
3. [Build manuel](#-build-manuel)
4. [Docker](#-docker)
5. [Outils tiers optionnels](#-outils-tiers-optionnels)
6. [Vérification](#-vérification)
7. [Désinstallation](#-désinstallation)

---

## 📦 Prérequis

| Composant | Requis | Rôle |
|---|---|---|
| **Rust** (stable, ≥ 1.75) | oui | compilation du binaire `nrtg` |
| **libpcap / Npcap** | oui | capture promiscuous (`--capture-iface`), scan SYN |
| **OpenSSL** (`libssl-dev`) | oui | TLS, C2, mission pack |
| `pkg-config`, `gcc`/`make` | oui (Linux/macOS) | dépendances natives |
| VS Build Tools C++ **ou** llvm-mingw | oui (Windows) | édition de liens MSVC/GNU |
| `sshpass` | optionnel | bruteforce SSH |
| Outils tiers (nmap, ffuf, …) | optionnel | capacités `external_tool` |

---

## ⚡ Installation rapide

### 🐧 Linux / 🍎 macOS

```bash
bash install.sh
```

Détecte automatiquement la distribution (**Ubuntu / Debian / Kali, Fedora, CentOS, Arch, openSUSE, Alpine**), installe les dépendances de build puis compile en release. Sur macOS : Xcode CLT + Homebrew + OpenSSL + Rust.

```bash
bash install.sh --skip-build     # installer les deps sans compiler
```

### 🪟 Windows

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

| Option | Effet |
|---|---|
| `-SkipNpcap` | sans capture live (scan TCP/HTTP conservé) |
| `-SkipVS` | sans VS Build Tools (nécessite llvm-mingw) |
| `-DockerOnly` | build via Docker uniquement |

Variante dédiée aux toolchains C++ : `install_vs_buildtools.ps1`.

---

## 🔨 Build manuel

```bash
# Debug
cargo build -j2

# Release optimisé
cargo build --release
# → target/release/nrtg

# Windows (toolchain GNU)
cargo build --release --target x86_64-pc-windows-gnu

# Vérifications
cargo check
cargo test --bin nrtg
```

> Sous Windows natif, si `link.exe` est absent, utiliser WSL (`wsl -e bash -lc "cargo build"`) ou ajouter `tools\llvm-mingw-20240619-ucrt-x86_64\bin` au `PATH`.

---

## 🐳 Docker

```bash
# Build
docker build -t nrtg:latest -t nrtg:2.0.0 .

# Scan d'un lab local
docker run --rm -v "${PWD}/out:/app/out" \
  --add-host=host.docker.internal:host-gateway \
  nrtg:latest -t http://host.docker.internal:8080 --csv --md

# Capture LIVE (Linux uniquement)
docker run --rm --network host --cap-add=NET_RAW \
  -v "${PWD}/out:/app/out" \
  nrtg:latest --capture-iface eth0 --capture-duration 45

# Variante IA via compose
docker compose -f docker-compose.ai.yml run --rm nrtg
```

---

## 🧰 Outils tiers optionnels

Le binaire est **autonome** pour ses modules natifs. Les outils ci-dessous ne sont nécessaires qu'aux **capacités `external_tool`** (voir [HELP.md § 10](HELP.md#10--agent-ia-autonome)). L'agent peut les installer lui-même avec `--auto-install` (opt-in) ou `--autonomous`.

### Installation automatique par l'agent

```bash
# L'agent détecte le gestionnaire de paquets et installe ce qui manque
nrtg -t 10.0.0.5 --ai-agent --auto-install

# Mode autonome complet (implique --auto-install + --yes, lève la confirmation)
nrtg -t 10.0.0.0/24 --ai-agent --autonomous
```

### Installation manuelle (Debian / Kali)

```bash
sudo apt-get install -y \
  nmap masscan ffuf gobuster dirb feroxbuster nikto whatweb sqlmap \
  gobuster nuclei wpscan hydra medusa hashcat john smtp-user-enum swaks \
  snmp snmp-mibs-downloader sslscan dnsutils ldap-utils smbclient smbmap \
  enum4linux-ng tcpdump tshark socat openssh-client exploitdb
```

| Domaine | Outils |
|---|---|
| **Recon réseau** | `nmap`, `masscan`, `naabu` |
| **Web** | `ffuf`, `feroxbuster`, `gobuster`, `dirb`, `nikto`, `whatweb`, `katana`, `gospider`, `nuclei`, `wpscan`, `wapiti`, `sqlmap`, `gowitness`, `eyewitness` |
| **DNS / sous-domaines** | `subfinder`, `amass`, `dnsrecon`, `dnsenum`, `fierce`, `dig` (dnsutils) |
| **Identifiants** | `hydra`, `medusa`, `ncrack`, `hashcat`, `john`, `smtp-user-enum`, `swaks` |
| **SNMP / TLS** | `snmpwalk` (snmp), `snmp-check`, `onesixtyone`, `sslscan`, `testssl.sh` |
| **AD / Kerberos** | `kerbrute`, `certipy`, `bloodhound-python`, `impacket-*`, `nxc`, `smbmap`, `smbclient`, `enum4linux-ng`, `ldapsearch`, `evil-winrm`, `lsassy` |
| **Tunnel / pivot** | `chisel`, `ligolo-ng`, `socat`, `ssh` |
| **C2 / exploit** | `msfconsole` (Metasploit), `sliver-client`, `searchsploit` (exploitdb) |
| **Capture** | `tcpdump`, `tshark` |

> **Sans `--auto-install`**, l'agent reste *fail-closed* : il affiche la commande d'installation exacte et poursuit la mission sans blocage. La confirmation est obligatoire pour tout outil `Medium`/`High` (levée uniquement par `--autonomous`). Chaque installation est tracée dans `diapile_installs.log`.

---

## 🩺 Vérification

```bash
nrtg --doctor        # environnement : deps, config, réseau, clés API
nrtg --features      # modules et sorties disponibles
nrtg -h              # liste complète des flags
```

---

## 🗑 Désinstallation

```bash
# Supprimer le binaire et les caches de build
rm -f ~/.cargo/bin/nrtg 2>/dev/null
cargo clean
```

Les fichiers de travail générés (`graph.*`, `sessions/`, `diapile_installs.log`) sont listés dans [.gitignore](.gitignore) ; supprimez-les manuellement pour effacer toute trace d'opération.

---

**DIAPILE — Visualiser, Comprendre, Conquérir.** · MIT License.
