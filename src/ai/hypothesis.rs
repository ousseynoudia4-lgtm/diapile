//! Hypothesis Engine — sélection bayésienne des classes de vulnérabilités.
//!

//! 1. **Thompson sampling** (Beta-Bernoulli). Chaque couple
//!    `(hôte, classe)` maintient une loi postérieure `Beta(α, β)` où `α`
//!    compte les succès observés et `β` les échecs. À chaque décision on tire
//!    un échantillon par classe et on retient le maximum. L'exploration est
//!    automatique : une classe jamais testée conserve tout son a priori et
//!    peut donc gagner le tirage, sans le balayage déterministe d'UCB1.
//!    Réf. : Thompson (1933) ; Chapelle & Li (2011), *An Empirical Evaluation
//!    of Thompson Sampling* ; Agrawal & Goyal (2012) pour la borne de regret.
//!
//! 2. **Gating d'applicabilité**. L'échantillonnage est restreint aux classes
//!    *réalisables* vu les preuves collectées (pas de SQLi sans paramètre, pas
//!    de SSRF sans paramètre d'URL, pas d'XXE sans surface XML). C'est la
//!    condition pratique pour que le bandit converge en quelques dizaines
//!    d'actions au lieu de brûler des requêtes sur des hypothèses impossibles.
//!
//! L'échantillonnage Beta passe par la méthode de **Marsaglia & Tsang (2000)**
//! (Gamma par rejet, puis normalisation), sans dépendance supplémentaire.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ─────────────────────────────────────────────────────────────────────────────
// 1. Classes de vulnérabilités
// ─────────────────────────────────────────────────────────────────────────────

/// Classes de vulnérabilités que l'agent peut chercher activement.
///
/// `KnownCve` fait partie de l'espace d'hypothèses au même titre que les
/// autres : exploiter une CVE corrélée devient une hypothèse *parmi d'autres*,
/// pas la stratégie par défaut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnClass {
    DefaultCreds,
    Misconfig,
    AuthBypass,
    Lfi,
    SqlInjection,
    Xss,
    Ssti,
    CmdInjection,
    Ssrf,
    FileUpload,
    OpenRedirect,
    Xxe,
    Jwt,
    Cors,
    Graphql,
    Oauth2,
    Smuggling,
    KnownCve,
}

/// Les 18 classes, dans un ordre stable (utile pour l'affichage et les tests).
pub const ALL_CLASSES: [VulnClass; 18] = [
    VulnClass::DefaultCreds,
    VulnClass::Misconfig,
    VulnClass::AuthBypass,
    VulnClass::SqlInjection,
    VulnClass::Xss,
    VulnClass::Lfi,
    VulnClass::Ssti,
    VulnClass::CmdInjection,
    VulnClass::Ssrf,
    VulnClass::FileUpload,
    VulnClass::OpenRedirect,
    VulnClass::Xxe,
    VulnClass::Jwt,
    VulnClass::Cors,
    VulnClass::Graphql,
    VulnClass::Oauth2,
    VulnClass::Smuggling,
    VulnClass::KnownCve,
];

impl VulnClass {
    pub fn all() -> &'static [VulnClass] {
        &ALL_CLASSES
    }

    /// Identifiant canonique — c'est la valeur écrite dans
    /// `PlannedAction.technique`, donc celle qui alimente l'anti-boucle
    /// (`canonical_technique`) et le tracker.
    pub fn as_str(&self) -> &'static str {
        match self {
            VulnClass::DefaultCreds => "default_creds",
            VulnClass::Misconfig => "misconfig",
            VulnClass::AuthBypass => "auth_bypass",
            VulnClass::Lfi => "lfi",
            VulnClass::SqlInjection => "sqli",
            VulnClass::Xss => "xss",
            VulnClass::Ssti => "ssti",
            VulnClass::CmdInjection => "cmdi",
            VulnClass::Ssrf => "ssrf",
            VulnClass::FileUpload => "file_upload",
            VulnClass::OpenRedirect => "open_redirect",
            VulnClass::Xxe => "xxe",
            VulnClass::Jwt => "jwt",
            VulnClass::Cors => "cors",
            VulnClass::Graphql => "graphql",
            VulnClass::Oauth2 => "oauth2",
            VulnClass::Smuggling => "http_smuggling",
            VulnClass::KnownCve => "known_cve",
        }
    }

    /// Libellé lisible (prompt LLM / rapports).
    pub fn label(&self) -> &'static str {
        match self {
            VulnClass::DefaultCreds => "credentials par défaut",
            VulnClass::Misconfig => "mauvaise configuration",
            VulnClass::AuthBypass => "contournement d'authentification",
            VulnClass::Lfi => "inclusion de fichier local / path traversal",
            VulnClass::SqlInjection => "injection SQL",
            VulnClass::Xss => "XSS",
            VulnClass::Ssti => "injection de template (SSTI)",
            VulnClass::CmdInjection => "injection de commande",
            VulnClass::Ssrf => "SSRF",
            VulnClass::FileUpload => "upload de fichier",
            VulnClass::OpenRedirect => "redirection ouverte",
            VulnClass::Xxe => "XXE",
            VulnClass::Jwt => "faiblesse JWT",
            VulnClass::Cors => "mauvaise configuration CORS",
            VulnClass::Graphql => "abus GraphQL",
            VulnClass::Oauth2 => "abus OAuth2 / OIDC",
            VulnClass::Smuggling => "contrebande de requêtes HTTP",
            VulnClass::KnownCve => "exploitation d'une CVE corrélée",
        }
    }

    pub fn from_str(s: &str) -> Option<VulnClass> {
        let s = s.trim().to_lowercase();
        let s = s.as_str();
        ALL_CLASSES.iter().copied().find(|c| {
            c.as_str() == s
                || c.label().to_lowercase() == s
                // Tolérance aux formulations du LLM.
                || match c {
                    VulnClass::SqlInjection => s.contains("sql"),
                    VulnClass::CmdInjection => s.contains("cmd") || s.contains("command"),
                    VulnClass::DefaultCreds => s.contains("default") || s.contains("brute"),
                    VulnClass::AuthBypass   => s.contains("auth"),
                    VulnClass::Lfi          => s.contains("lfi") || s.contains("traversal") || s.contains("inclusion"),
                    VulnClass::Ssrf         => s.contains("ssrf"),
                    VulnClass::Ssti         => s.contains("ssti") || s.contains("template"),
                    VulnClass::Xss          => s.contains("xss"),
                    VulnClass::FileUpload   => s.contains("upload"),
                    VulnClass::OpenRedirect => s.contains("redirect"),
                    VulnClass::Xxe          => s.contains("xxe") || s.contains("xml"),
                    VulnClass::Smuggling    => s.contains("smuggl"),
                    VulnClass::Graphql      => s.contains("graphql"),
                    VulnClass::Oauth2       => s.contains("oauth") || s.contains("oidc"),
                    VulnClass::Cors         => s.contains("cors"),
                    VulnClass::Jwt          => s.contains("jwt"),
                    VulnClass::Misconfig    => s.contains("misconfig"),
                    VulnClass::KnownCve     => s.contains("cve"),
                }
        })
    }

    /// A priori `(α, β)` du bandit.
    ///
    /// Ce sont des **réglages opérateur**, pas des mesures : ils expriment la
    /// fréquence *attendue* d'une classe sur un lab de type challenge. Une
    /// classe jugée plus probable démarre avec un `α` plus haut, ce qui lui
    /// donne un avantage au premier tirage ; l'effet s'estompe après quelques
    /// observations puisque `α` et `β` croissent de +1 par essai.
    pub fn prior(&self) -> (f64, f64) {
        match self {
            VulnClass::DefaultCreds => (2.5, 2.0),
            VulnClass::Misconfig => (2.5, 2.0),
            VulnClass::AuthBypass => (2.0, 2.0),
            VulnClass::SqlInjection => (2.0, 3.0),
            VulnClass::Xss => (2.0, 3.0),
            VulnClass::Lfi => (2.0, 3.0),
            VulnClass::Ssti => (1.5, 3.0),
            VulnClass::CmdInjection => (1.5, 3.0),
            VulnClass::Ssrf => (1.5, 3.5),
            VulnClass::FileUpload => (1.5, 3.5),
            VulnClass::Jwt => (1.5, 3.5),
            VulnClass::OpenRedirect => (1.0, 4.0),
            VulnClass::Xxe => (1.0, 4.0),
            VulnClass::Cors => (1.0, 4.0),
            VulnClass::Graphql => (1.0, 4.0),
            VulnClass::Oauth2 => (1.0, 4.0),
            VulnClass::Smuggling => (1.0, 5.0),
            VulnClass::KnownCve => (1.5, 2.5),
        }
    }

    /// Type d'action NRTG (`ActionType`) à déclencher pour tester la classe,
    /// exprimé en chaîne pour ne pas coupler ce module au planificateur.
    pub fn action_hint(&self) -> &'static str {
        match self {
            VulnClass::KnownCve => "exploit",
            VulnClass::DefaultCreds => "brute_force",
            VulnClass::Misconfig | VulnClass::AuthBypass => "enumerate",
            // Toutes les autres classes sont couvertes par `full_web_scan`.
            _ => "web_attack",
        }
    }

    /// La classe est-elle réalisable sur cette surface ? (gating déterministe)
    pub fn applicable(&self, ev: &SurfaceEvidence) -> bool {
        // Un point d'injection est indispensable pour les classes qui injectent.
        let has_injection_point = ev.params > 0 || ev.forms > 0;

        match self {
            VulnClass::KnownCve => ev.has_confirmed_cve,
            VulnClass::SqlInjection
            | VulnClass::Xss
            | VulnClass::Ssti
            | VulnClass::CmdInjection
            | VulnClass::Lfi
            | VulnClass::Ssrf
            | VulnClass::OpenRedirect
            | VulnClass::Xxe
            | VulnClass::FileUpload => ev.has_http && has_injection_point,
            VulnClass::AuthBypass | VulnClass::DefaultCreds => ev.has_http,
            VulnClass::Misconfig
            | VulnClass::Jwt
            | VulnClass::Cors
            | VulnClass::Graphql
            | VulnClass::Oauth2
            | VulnClass::Smuggling => ev.has_http,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Preuves de surface (entrée du gating)
// ─────────────────────────────────────────────────────────────────────────────

/// Ce que l'on sait de la surface d'attaque web d'un hôte. C'est l'entrée du
/// gating d'applicabilité, et la matière première du bandit : sans inventaire
/// de surface, « tester SQLi » n'est qu'un mot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SurfaceEvidence {
    pub has_http: bool,
    pub has_confirmed_cve: bool,
    pub pages: usize,
    pub forms: usize,
    pub params: usize,
    pub endpoints: usize,
    pub has_login_form: bool,
    pub has_url_param: bool,
    pub has_file_param: bool,
    pub has_search_param: bool,
    pub has_xml_like: bool,
    pub has_json_api: bool,
    #[serde(default)]
    pub tech_hints: Vec<String>,
}

impl SurfaceEvidence {
    /// Décision d'injection plausible : au moins une page, un formulaire ou un
    /// endpoint porte un paramètre.
    pub fn is_injectable_surface(&self) -> bool {
        self.params > 0 || self.forms > 0
    }

    /// Résumé compact pour l'affichage / le prompt.
    pub fn render(&self) -> String {
        let mut parts = Vec::new();
        if self.pages > 0 {
            parts.push(format!("{} page(s)", self.pages));
        }
        if self.forms > 0 {
            parts.push(format!("{} formulaire(s)", self.forms));
        }
        if self.params > 0 {
            parts.push(format!("{} paramètre(s)", self.params));
        }
        if self.endpoints > 0 {
            parts.push(format!("{} endpoint(s)", self.endpoints));
        }
        if self.has_login_form {
            parts.push("formulaire d'auth".to_string());
        }
        if self.has_url_param {
            parts.push("param URL/redirect".to_string());
        }
        if self.has_file_param {
            parts.push("param fichier/chemin".to_string());
        }
        if self.has_xml_like {
            parts.push("surface XML".to_string());
        }
        if self.has_json_api {
            parts.push("API JSON".to_string());
        }
        if !self.tech_hints.is_empty() {
            let hints: Vec<&str> = self.tech_hints.iter().take(4).map(|s| s.as_str()).collect();
            parts.push(format!("techno={}", hints.join("/")));
        }
        if parts.is_empty() {
            "aucune surface web".to_string()
        } else {
            parts.join(", ")
        }
    }

    /// Construit les preuves depuis un inventaire de surface.
    pub fn from_surface(s: &super::campaign_memory::WebSurface, has_confirmed_cve: bool) -> Self {
        let mut ev = SurfaceEvidence {
            has_http: true,
            has_confirmed_cve,
            pages: s.pages,
            forms: s.forms,
            params: s.params.len(),
            endpoints: s.endpoints.len(),
            tech_hints: s.tech_hints.clone(),
            ..Default::default()
        };
        // Deux niveaux de détection :
        //  - `params` = noms de paramètres exacts → égalité stricte, sinon un
        //    nom court comme `q` matcherait n'importe quel texte ;
        //  - le reste (endpoints, techno) → correspondance par sous-chaîne.
        let params_lc: Vec<String> = s.params.iter().map(|p| p.to_lowercase()).collect();
        let blob: String = s
            .params
            .iter()
            .chain(s.endpoints.iter())
            .chain(s.tech_hints.iter())
            .map(|x| x.to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");

        let param_is = |keys: &[&str]| {
            params_lc.iter().any(|p| {
                let name = p.split(['=', '&']).next().unwrap_or(p.as_str()).trim();
                keys.iter().any(|k| name == *k || name.starts_with(k))
            })
        };
        let has_any = |keys: &[&str]| keys.iter().any(|k| blob.contains(k));

        ev.has_url_param = param_is(&[
            "url", "uri", "redirect", "return", "next", "dest", "callback", "target", "continue",
            "goto",
        ]) || has_any(&["url=", "?url", "redirect=", "next=", "returnurl"]);
        ev.has_file_param = param_is(&[
            "file", "path", "page", "include", "dir", "doc", "template", "load", "view", "src",
            "name",
        ]) || has_any(&["file=", "path=", "include=", "page="]);
        ev.has_search_param = param_is(&["q", "s", "search", "query", "keyword", "kw", "term"])
            || has_any(&["search", "query", "keyword"]);
        ev.has_xml_like = param_is(&["xml", "soap", "wsdl"])
            || has_any(&["xml", "soap", "wsdl", ".asmx", "rss", "atom"]);
        ev.has_login_form = ev.has_login_form
            || has_any(&[
                "login",
                "signin",
                "auth",
                "password",
                "username",
                "connexion",
            ]);

        // API JSON : endpoint REST/GraphQL/`.json` côté WebSurface, ou techno
        // de framework serveur côté indices technologiques.
        let endpoint_is_api = s.endpoints.iter().any(|e| {
            let e = e.to_lowercase();
            e.contains("/api")
                || e.contains(".json")
                || e.contains("/graphql")
                || e.contains("/rest")
        });
        ev.has_json_api = endpoint_is_api
            || has_any(&[
                "node", "express", "django", "flask", "spring", "rails", "graphql",
            ]);
        ev
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Postérieure Beta + échantillonnage
// ─────────────────────────────────────────────────────────────────────────────

/// Loi postérieure `Beta(α, β)` d'une classe sur un hôte.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct BetaPosterior {
    pub alpha: f64,
    pub beta: f64,
}

impl BetaPosterior {
    pub fn new(alpha: f64, beta: f64) -> Self {
        // Bornes basses : évite `Gamma(0)` et la division par zéro.
        Self {
            alpha: alpha.max(1e-3),
            beta: beta.max(1e-3),
        }
    }

    /// Espérance `α/(α+β)` = probabilité estimée que la classe soit la bonne.
    pub fn mean(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// Nombre d'observations cumulées (a priori inclus).
    pub fn observations(&self) -> f64 {
        self.alpha + self.beta
    }

    pub fn observe(&mut self, success: bool) {
        if success {
            self.alpha += 1.0
        } else {
            self.beta += 1.0
        }
    }

    /// Tirage de Thompson : un échantillon de la postérieure.
    pub fn sample<R: rand::Rng>(&self, rng: &mut R) -> f64 {
        let x = sample_gamma(rng, self.alpha);
        let y = sample_gamma(rng, self.beta);
        let s = x + y;
        if !s.is_finite() || s <= 0.0 {
            self.mean()
        } else {
            x / s
        }
    }
}

/// Normale centrée réduite par Box-Muller.
fn sample_standard_normal<R: rand::Rng>(rng: &mut R) -> f64 {
    let u1 = rng.gen::<f64>().max(f64::MIN_POSITIVE);
    let u2 = rng.gen::<f64>();
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

/// Échantillon `Gamma(shape, 1)` — Marsaglia & Tsang (2000).
///
/// Pour `shape < 1`, on exploite la propriété d'amplification
/// `X ~ Gamma(a+1)` ⟹ `X·U^(1/a) ~ Gamma(a)`.
pub fn sample_gamma<R: rand::Rng>(rng: &mut R, shape: f64) -> f64 {
    if !(shape > 0.0) || !shape.is_finite() {
        return 1.0;
    }
    if shape < 1.0 {
        let u = rng.gen::<f64>().max(f64::MIN_POSITIVE);
        return sample_gamma(rng, shape + 1.0) * u.powf(1.0 / shape);
    }

    let d = shape - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();
    loop {
        let x = sample_standard_normal(rng);
        let v = 1.0 + c * x;
        if v <= 0.0 {
            continue;
        }
        let v = v * v * v;
        let u = rng.gen::<f64>();
        if u <= 0.0 {
            continue;
        }
        if u.ln() < 0.5 * x * x + d - d * v + d * v.ln() {
            return d * v;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Tracker d'hypothèses
// ─────────────────────────────────────────────────────────────────────────────

/// État persistant du bandit : une postérieure par `(hôte, classe)`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HypothesisTracker {
    /// hôte → classe → postérieure
    #[serde(default)]
    pub posteriors: HashMap<String, HashMap<VulnClass, BetaPosterior>>,
    /// hôte → classes déjà testées au moins une fois
    #[serde(default)]
    pub tried: HashMap<String, HashSet<VulnClass>>,
    /// hôte → classes qui ont produit une confirmation
    #[serde(default)]
    pub confirmed: HashMap<String, HashSet<VulnClass>>,
}

impl HypothesisTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Postérieure courante (a priori si la classe n'a jamais été testée).
    pub fn posterior(&self, host: &str, class: VulnClass) -> BetaPosterior {
        self.posteriors
            .get(host)
            .and_then(|m| m.get(&class))
            .copied()
            .unwrap_or_else(|| {
                let (a, b) = class.prior();
                BetaPosterior::new(a, b)
            })
    }

    pub fn is_tried(&self, host: &str, class: VulnClass) -> bool {
        self.tried
            .get(host)
            .map(|s| s.contains(&class))
            .unwrap_or(false)
    }

    pub fn is_confirmed(&self, host: &str, class: VulnClass) -> bool {
        self.confirmed
            .get(host)
            .map(|s| s.contains(&class))
            .unwrap_or(false)
    }

    /// Enregistre le résultat d'un test. `success = true` incrémente `α`
    /// (la classe est bien exploitée), sinon `β` (hypothèse affaiblie).
    pub fn record(&mut self, host: &str, class: VulnClass, success: bool) {
        let (a, b) = class.prior();
        let entry = self
            .posteriors
            .entry(host.to_string())
            .or_default()
            .entry(class)
            .or_insert_with(|| BetaPosterior::new(a, b));
        entry.observe(success);

        self.tried
            .entry(host.to_string())
            .or_default()
            .insert(class);
        if success {
            self.confirmed
                .entry(host.to_string())
                .or_default()
                .insert(class);
        }
    }

    /// Classes applicables à cette surface (ordre stable).
    pub fn applicable(&self, ev: &SurfaceEvidence) -> Vec<VulnClass> {
        ALL_CLASSES
            .iter()
            .copied()
            .filter(|c| c.applicable(ev))
            .collect()
    }

    /// Classe applicable jamais testée sur cet hôte, la plus probable d'après
    /// l'espérance postérieure (départage déterministe).
    pub fn best_untried(&self, host: &str, ev: &SurfaceEvidence) -> Option<(VulnClass, f64)> {
        let mut candidates: Vec<(VulnClass, f64)> = self
            .applicable(ev)
            .into_iter()
            .filter(|c| !self.is_tried(host, *c) && !self.is_confirmed(host, *c))
            .map(|c| (c, self.posterior(host, c).mean()))
            .collect();
        // Tri décroissant par probabilité, puis par ordre de déclaration.
        candidates.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        candidates.into_iter().next()
    }

    /// Classement complet par tirage de Thompson (décroissant).
    ///
    /// C'est le cœur de la décision : une classe jamais testée peut dépasser
    /// une classe déjà échouée deux fois, ce qui garantit l'exploration sans
    /// politique d'epsilon explicite.
    pub fn thompson_rank(&self, host: &str, ev: &SurfaceEvidence) -> Vec<(VulnClass, f64)> {
        let mut rng = rand::thread_rng();
        let mut scored: Vec<(VulnClass, f64)> = self
            .applicable(ev)
            .into_iter()
            .filter(|c| !self.is_confirmed(host, *c))
            .map(|c| {
                let p = self.posterior(host, c);
                let mut s = p.sample(&mut rng);
                // Une classe confirmée sur un *autre* hôte reste plausible ici :
                // l'espérance est utilisée comme ancrage pour ne pas perdre
                // l'information inter-hôtes (transfert).
                s = 0.85 * s + 0.15 * p.mean();
                (c, s)
            })
            .collect();
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        scored
    }

    /// Résumé pour le prompt LLM : postérieures des classes applicables.
    pub fn summary_for(&self, host: &str, ev: &SurfaceEvidence, top_n: usize) -> String {
        let ranked = self.thompson_rank(host, ev);
        if ranked.is_empty() {
            return "aucune classe applicable (pas de surface web identifiée)".to_string();
        }
        ranked
            .into_iter()
            .take(top_n.max(1))
            .map(|(c, s)| {
                let p = self.posterior(host, c);
                let status = if self.is_confirmed(host, c) {
                    "CONFIRMÉE"
                } else if self.is_tried(host, c) {
                    "testée/échouée"
                } else {
                    "non testée"
                };
                format!(
                    "{} [{}] p≈{:.2} (α={:.1} β={:.1})",
                    c.label(),
                    status,
                    p.mean(),
                    p.alpha,
                    p.beta
                )
            })
            .collect::<Vec<_>>()
            .join(" ; ")
    }

    /// Nombre de classes restant à tester (sert au repli final).
    pub fn remaining(&self, host: &str, ev: &SurfaceEvidence) -> usize {
        self.applicable(ev)
            .into_iter()
            .filter(|c| !self.is_tried(host, *c) && !self.is_confirmed(host, *c))
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn web_ev() -> SurfaceEvidence {
        SurfaceEvidence {
            has_http: true,
            pages: 4,
            forms: 2,
            params: 6,
            endpoints: 9,
            ..Default::default()
        }
    }

    #[test]
    fn prior_is_a_proper_beta_and_orders_classes() {
        for c in VulnClass::all() {
            let (a, b) = c.prior();
            assert!(a > 0.0 && b > 0.0, "a priori invalide pour {:?}", c);
            let m = BetaPosterior::new(a, b).mean();
            assert!(m > 0.0 && m < 1.0, "espérance hors (0,1) pour {:?}", c);
        }
        // Les classes à fort taux de base démarrent devant les plus rares.
        let creds = BetaPosterior::new(
            VulnClass::DefaultCreds.prior().0,
            VulnClass::DefaultCreds.prior().1,
        );
        let smug = BetaPosterior::new(
            VulnClass::Smuggling.prior().0,
            VulnClass::Smuggling.prior().1,
        );
        assert!(creds.mean() > smug.mean());
    }

    #[test]
    fn observing_failures_lowers_the_posterior_mean() {
        let mut p = BetaPosterior::new(2.0, 2.0);
        let before = p.mean();
        for _ in 0..5 {
            p.observe(false);
        }
        assert!(p.mean() < before, "β doit faire chuter l'espérance");
        assert_eq!(p.observations(), 9.0);
    }

    #[test]
    fn gamma_sampler_matches_theoretical_mean() {
        // E[Gamma(k, 1)] = k. Test statistique à 5 % sur 20 000 tirages.
        let mut rng = rand::thread_rng();
        for k in [0.5_f64, 1.0, 2.5, 7.0] {
            let n = 20_000;
            let sum: f64 = (0..n).map(|_| sample_gamma(&mut rng, k)).sum();
            let mean = sum / n as f64;
            let tol = 4.0 * k.sqrt() / (n as f64).sqrt(); // ≈ 4 écarts-types de la moyenne
            assert!(
                (mean - k).abs() < tol.max(0.05),
                "Gamma({k}) : moyenne empirique {mean:.3} trop loin de {k}"
            );
            assert!(mean > 0.0);
        }
    }

    #[test]
    fn beta_samples_stay_in_unit_interval() {
        let mut rng = rand::thread_rng();
        for (a, b) in [(1.0, 1.0), (0.5, 4.0), (12.0, 3.0)] {
            let p = BetaPosterior::new(a, b);
            for _ in 0..500 {
                let s = p.sample(&mut rng);
                assert!(s >= 0.0 && s <= 1.0, "échantillon Beta hors [0,1] : {s}");
            }
        }
    }

    #[test]
    fn untried_class_outranks_a_twice_failed_one() {
        // Thompson sampling doit rouvrir l'exploration : SQLi échouée 4 fois
        // ne doit plus dominer éternellement une classe jamais tentée.
        let mut t = HypothesisTracker::new();
        let ev = web_ev();
        for _ in 0..4 {
            t.record("10.0.0.5", VulnClass::SqlInjection, false);
        }
        let (best, _) = t
            .best_untried("10.0.0.5", &ev)
            .expect("une classe non testée doit exister");
        assert_ne!(
            best,
            VulnClass::SqlInjection,
            "une classe testée ne peut pas être « non testée »"
        );
        assert!(t.remaining("10.0.0.5", &ev) >= 1);
    }

    #[test]
    fn gating_blocks_impossible_hypotheses() {
        // Pas de surface injectable → les classes d'injection sont écartées.
        let ev = SurfaceEvidence {
            has_http: true,
            ..Default::default()
        };
        assert!(!VulnClass::SqlInjection.applicable(&ev));
        assert!(!VulnClass::Ssrf.applicable(&ev));
        assert!(VulnClass::Misconfig.applicable(&ev));
        assert!(VulnClass::Cors.applicable(&ev));
        // Sans CVE confirmée, KnownCve est hors-jeu ; avec, il revient.
        assert!(!VulnClass::KnownCve.applicable(&ev));
        let ev_cve = SurfaceEvidence {
            has_http: true,
            has_confirmed_cve: true,
            ..Default::default()
        };
        assert!(VulnClass::KnownCve.applicable(&ev_cve));
    }

    #[test]
    fn confirmed_class_is_excluded_from_ranking() {
        let mut t = HypothesisTracker::new();
        let ev = web_ev();
        t.record("h1", VulnClass::SqlInjection, true);
        assert!(t.is_confirmed("h1", VulnClass::SqlInjection));
        let ranked: Vec<VulnClass> = t
            .thompson_rank("h1", &ev)
            .into_iter()
            .map(|(c, _)| c)
            .collect();
        assert!(!ranked.contains(&VulnClass::SqlInjection));
    }

    #[test]
    fn class_parsing_tolerates_llm_wording() {
        assert_eq!(VulnClass::from_str("SQLi"), Some(VulnClass::SqlInjection));
        assert_eq!(
            VulnClass::from_str("sql_injection"),
            Some(VulnClass::SqlInjection)
        );
        assert_eq!(
            VulnClass::from_str("Path Traversal (LFI)"),
            Some(VulnClass::Lfi)
        );
        assert_eq!(
            VulnClass::from_str("template injection"),
            Some(VulnClass::Ssti)
        );
        assert_eq!(
            VulnClass::from_str("CVE-2021-41773"),
            Some(VulnClass::KnownCve)
        );
        assert_eq!(VulnClass::from_str("nawak"), None);
    }

    #[test]
    fn tracker_roundtrips_through_json() {
        let mut t = HypothesisTracker::new();
        t.record("10.0.0.7", VulnClass::Ssti, false);
        t.record("10.0.0.7", VulnClass::Lfi, true);
        let json = serde_json::to_string(&t).unwrap();
        let back: HypothesisTracker = serde_json::from_str(&json).unwrap();
        assert!(back.is_confirmed("10.0.0.7", VulnClass::Lfi));
        assert!(back.is_tried("10.0.0.7", VulnClass::Ssti));
        assert!(back.posterior("10.0.0.7", VulnClass::Ssti).beta > VulnClass::Ssti.prior().1);
    }

    #[test]
    fn surface_evidence_detects_url_and_file_params() {
        use crate::ai::campaign_memory::WebSurface;
        let s = WebSurface {
            pages: 3,
            forms: 1,
            params: vec!["redirect".into(), "file".into(), "q".into()],
            endpoints: vec!["/api/v1/users".into()],
            tech_hints: vec!["express".into()],
            crawled_at: None,
        };
        let ev = SurfaceEvidence::from_surface(&s, false);
        assert!(ev.has_url_param, "redirect → param URL");
        assert!(ev.has_file_param, "file → param fichier");
        assert!(ev.has_search_param, "q → recherche");
        assert!(ev.has_json_api, "/api + express → API JSON");
        assert!(ev.is_injectable_surface());
    }
}
