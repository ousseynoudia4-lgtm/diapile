# Changelog

Toutes les modifications notables de **DIAPILE / NRTG — Network Redteam Grapher** sont documentées ici.

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) · Versionnage : [SemVer](https://semver.org/lang/fr/).

> La version **faisant foi** est celle de [Cargo.toml](Cargo.toml) (`CARGO_PKG_VERSION`). Le fichier [VERSION](VERSION) en est le miroir.

---

## [Unreleased]

## [2.0.0] — 2026-10-30

Première version publique du framework. Périmètre fonctionnel complet ci-dessous.

### Ajouté

#### Reconnaissance & scan réseau

- Moteur de scan **inspiré de nmap, réécrit en Rust original** ([src/netscan.rs](src/netscan.rs)) : scan connect, fingerprinting de versions (regex + semver), OS guess par TTL.
- **30+ services** détectés : HTTP/S, SSH, FTP, SMTP, Redis, MySQL, PostgreSQL, MSSQL, MongoDB, SMB, RDP, LDAP, Elasticsearch, Memcached, RabbitMQ, Docker API, etcd, Kibana, InfluxDB, Kafka, Zookeeper, Telnet, DNS…
- **Probes spécialisés par protocole** : Redis `INFO`, MongoDB `isMaster`, SMTP `EHLO`, FTP `FEAT`, Elasticsearch JSON, en-tête AMQP…
- **Capture HTTP full-headers** + snippet de corps + extraction `<title>` + empreinte de stack technique.
- **Protocoles réseau avancés** ([src/network_advanced.rs](src/network_advanced.rs)) : SNMP, IPMI, Kubernetes, MS-RPC.
- **Recon IPTV / streaming** ([src/iptv.rs](src/iptv.rs)) : protocoles de diffusion média souvent absents des scanners classiques (sortie JSON pour reporting/dashboard).
- **Capture paquets** ([src/capture.rs](src/capture.rs)) — intégration `tcpdump` / `tshark`, bind loopback.
- **Corrélation CVE / Exploit-DB** : base locale [cve_db.json](cve_db.json), client **NVD API v2.0** ([src/nvd.rs](src/nvd.rs) — lookup CVE, CPE matching, mise à jour de base), moteur [src/exploits.rs](src/exploits.rs).

#### Détection WAF, OS & en-têtes de sécurité (passive)

- **16 signatures WAF** : Cloudflare, Akamai, AWS WAF, ModSecurity, F5 BIG-IP, Imperva, Sucuri, Barracuda, FortiWeb, Radware, Fastly, Varnish, Reblaze, Wallarm, StackPath, Nginx WAF.
- **7 signatures OS** (Cisco IOS, AIX, OpenBSD, Windows, Linux…).
- **Analyse passive des en-têtes** : CORS wildcard, HSTS absent/faible, divulgation de version `Server`/`X-Powered-By`, cookies non sécurisés, en-têtes de sécurité manquants.
- **Classification de risque** ([src/risk.rs](src/risk.rs), [risk_rules.json](risk_rules.json)).

#### Moteur d'exploitation

- **29 signatures d'exploit** ([exploits.yaml](exploits.yaml)) — **dry-run par défaut**, exécution live opt-in : Redis, VSFTPD backdoor, MySQL root/anonyme, Jenkins, Docker API, etcd, Kibana, Grafana, WinRM, Kubernetes API, VNC, MQTT, Kerberos, PHP2Shell, SMB null session, SMTP open relay, SNMP, Telnet, SSH weak-KEX…
- **Modules d'exploitation réels** ([src/exploit_engine.rs](src/exploit_engine.rs)) et **analyse/génération d'exploit assistée par LLM** ([src/llm_exploit.rs](src/llm_exploit.rs)).

#### Attaques web

- [src/web_attack.rs](src/web_attack.rs) : SQLi, XSS, SSTI, CORS, request smuggling, SSRF, LFI (gating d'applicabilité déterministe, aucun retry sur les sondes temporelles).
- [src/web_spider.rs](src/web_spider.rs) : crawl de surface.
- **Écouteur OOB** ([src/oob.rs](src/oob.rs)) : canaux d'exfiltration Out-Of-Band partageant un registre de tokens.

#### Bruteforce & credential checking

- [src/bruteforce.rs](src/bruteforce.rs) — échanges réseau **natifs** : FTP, Redis, PostgreSQL, MSSQL, SMB 2/3.1.1, MySQL, MongoDB, VNC, RDP ; enveloppes HTTP ; **WinRM** (`/wsman`) handshake Negotiate/NTLMSSP maison.
- Moteur d'exécution `run_credential_attempts` : `max_parallel`, `delay_ms` et gestion du **lockout**.
- **Listes externes `.txt`** : fusion additive (défaut) ou remplacement des listes embarquées.

#### Active Directory / Kerberos

- [src/kerberos.rs](src/kerberos.rs) : AS-REP Roasting, Kerberoasting, password spraying, kerbrute.
- [src/ad.rs](src/ad.rs) : dump LDAP, support BloodHound.
- [src/ntlm.rs](src/ntlm.rs) : primitives NTLMSSP / SPNEGO / DES partagées (aucun secret journalisé, masquage via `mask_secret`).

#### Post-exploitation, pivot & C2

- [src/post_exploit.rs](src/post_exploit.rs) : énumération système automatisée après compromission.
- [src/pivot.rs](src/pivot.rs) : tunnel SOCKS5 dynamique, proxy chains, cartographie réseau interne.
- [src/shell.rs](src/shell.rs) : gestion des sessions shell et reverse shell listener.
- [src/c2/](src/c2/) : framework C2 — canal HTTP polling, WebSocket push bidirectionnel ([src/c2/ws_c2.rs](src/c2/ws_c2.rs)), **DNS tunneling** ([src/c2/dns_c2.rs](src/c2/dns_c2.rs)), sleep mode ; crypto AES-256-GCM + HMAC-SHA256, **clé dérivée par canal** (OPSEC multi-canal).
- [src/mission_pack.rs](src/mission_pack.rs) : persistance **chiffrée AES-256-GCM** d'une campagne complète + anti-forensique (nonce aléatoire par blob, overwrite NIST SP 800-88).

#### IoT / SCADA

- [src/iot_scada.rs](src/iot_scada.rs) : inventaire et exploitation de protocoles industriels — Modbus, S7, BACnet, MQTT…

#### Évasion & stealth

- [src/evasion.rs](src/evasion.rs) : détection sandbox/VM (VMware/VBox/Hyper-V/QEMU) et debuggers (x64dbg/IDA/gdb/strace) ; encodeurs payload XOR, Base64, Shikata Ga Nai polymorphe, AES-256-GCM ; obfuscation de trafic (DNS tunneling, domain fronting, HTTPS factice) ; mode **low & slow** (jitter configurable, parallélisme borné).

#### HORDE (DDoS distribué) & stress

- [src/horde/](src/horde/) : infrastructure distribuée d'attaques volumétriques — coordinateur + workers distants + swarm orchestrant des bots **GoldenEye v3**, transport WebSocket RFC 6455 maison, génération de rapports.
- [src/stress/](src/stress/) : test de résilience via [src/stress/goldeneye.rs](src/stress/goldeneye.rs).

#### OSINT

- [src/osint.rs](src/osint.rs) : reconnaissance passive — sous-domaines, fuites GitHub, Shodan, crt.sh, HIBP.

#### Agent IA autonome

- **Boucle agentique** Recon → Plan (LLM) → Confirm (si risque) → Execute → Adapt → Loop ([src/ai/autonomous_agent.rs](src/ai/autonomous_agent.rs)) + **orchestrateur de sous-agents** ([src/orchestrator.rs](src/orchestrator.rs), [src/agents/](src/agents/)) : découverte, analyse web, exploitation, post-exploitation, mouvement latéral, reporting — contexte borné via `AgentBrief`/`AgentReport`.
- **Registre de capacités** ([src/ai/capability_registry.rs](src/ai/capability_registry.rs)) — 26 capacités (intention → outil) couvrant reconnaissance, web, AD/Kerberos, post-exploitation, pivot et C2 ; sélection du premier outil **présent dans le `PATH`** parmi des candidats ordonnés, génération d'arguments par gabarit (`{host}`, `{port}`, `{url}`, `{wordlist}`…), catalogue injecté dans le prompt du planificateur.
- **Parsing structuré des sorties** ([src/ai/tool_parsers.rs](src/ai/tool_parsers.rs)) — conversion de la sortie brute d'outils tiers en **artefacts typés** réinjectés dans la mémoire de campagne : ports/services, chemins web, identifiants vérifiés, hashs Kerberos/NTLM, injections SQL, enregistrements DNS, comptes, CVE/avis.
- **Exécution réelle d'outils tiers** — action `external_tool` : l'agent **installe puis exécute** un binaire et **ingère sa sortie** (nmap, ffuf, sqlmap, nuclei, impacket-*, …), au lieu de se limiter à suggérer une commande.
- **Moteur d'hypothèses bayésien** ([src/ai/hypothesis.rs](src/ai/hypothesis.rs)) : Thompson sampling (Beta-Bernoulli) + gating d'applicabilité.
- **Agent RL kill-chain** ([src/ai/rl_agent.rs](src/ai/rl_agent.rs)) et **mémoire de campagne persistante** ([src/ai/campaign_memory.rs](src/ai/campaign_memory.rs)).
- **Intégrations** : Metasploit RPC ([src/integrations/metasploit.rs](src/integrations/metasploit.rs)) et BloodHound AD ([src/integrations/bloodhound.rs](src/integrations/bloodhound.rs)).
- **Client LLM multi-fournisseur** ([src/llm.rs](src/llm.rs)) : OpenRouter, OpenAI, Ollama (local).

#### Dashboard temps réel & reporting

- [src/live_dashboard.rs](src/live_dashboard.rs) : dashboard **temps réel** via WebSocket, **bind loopback uniquement** (`127.0.0.1:24601`), sous-protocole `diapile-live`, zéro dépendance externe.
- [dashboard.html](dashboard.html) et [launcher.html](launcher.html) : UI cyberpunk autonome.
- **Exports** ([src/exports.rs](src/exports.rs)) : JSON, CSV, HTML standalone (thème DIAPILE dark) + [src/report_gen.rs](src/report_gen.rs) rapport de pentest complet (executive summary, kill-chain timeline) et [src/reports.rs](src/reports.rs).

#### Installation & versionnage

- [src/installer.rs](src/installer.rs) : auto-installation **opt-in** des outils tiers (détection apt/dnf/pacman/brew/winget/pip), classification de risque, `diapile_installs.log`.
- **[INSTALL.md](INSTALL.md)** : guide d'installation dédié — prérequis, scripts (`install.sh` / `install.ps1`), Docker, build manuel et **outils tiers optionnels**.
- **[CHANGELOG.md](CHANGELOG.md)** et **[VERSION](VERSION)** : historique et version courante.

### Modifié

- [README.md](README.md) — sous-section « Exécution d'outils tiers (`external_tool`) », ligne « Outils tiers » dans les nouveautés v2.0, arborescence IA mise à jour (`capability_registry`, `tool_parsers`), liens vers [INSTALL.md](INSTALL.md) / [CHANGELOG.md](CHANGELOG.md) / [VERSION](VERSION).
- [HELP.md](HELP.md) — § 5 « Usage effectif » (l'outil installé est réellement exécuté) et § 10 (table des 26 capacités).

### Corrigé

- `parse_nuclei` — valeur `str` non `Sized` transmise à `format!` (erreur `E0277`).
- `parse_secretsdump` — passages multiples corrigés en une passe unique préservant l'ordre documentaire, avec préfixe `DOMAINE\` optionnel.

### Sécurité / OPSEC

- Dashboard et coordinateur HORDE **bind exclusivement sur `127.0.0.1`** ; toute connexion non-loopback est rejetée silencieusement.
- `--auto-install` **opt-in / fail-closed** : sans le flag, aucune installation — suggestion de commande seulement. Confirmation humaine obligatoire pour tout outil `Medium`/`High`, levée uniquement par `--autonomous`.
- Secrets masqués via `mask_secret` ; clés API LLM via variables d'environnement `NRTG_LLM_*` ; aucune clé C2 en clair (`C2_SHARED_KEY`, `C2_MASTER_KEY`).
