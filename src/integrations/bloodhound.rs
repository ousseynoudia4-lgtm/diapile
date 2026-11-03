//! BloodHound Integration
//!
//! This module provides integration with BloodHound for Active Directory analysis.
//! Supports data ingestion and attack path discovery.

// Bloodhound API fields are PascalCase (C# origin — SharpHound collector).
// Exact naming is REQUIRED for JSON deserialization of raw BH responses.
// We silence the non_snake_case lint here rather than renaming fields.
#![allow(non_snake_case)]

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// BloodHound API Client
pub struct BloodHoundClient {
    client: Client,
    base_url: String,
    username: String,
    password: String,
    token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloodHoundNode {
    pub objectid: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub properties: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloodHoundEdge {
    pub sourceid: String,
    pub targetid: String,
    #[serde(rename = "relationship")]
    pub relationship: String,
    pub properties: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloodHoundData {
    pub computers: Vec<ComputerObject>,
    pub users: Vec<UserObject>,
    pub groups: Vec<GroupObject>,
    pub domains: Vec<DomainObject>,
    pub gpos: Vec<GPOObject>,
    pub ous: Vec<OUObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputerObject {
    pub Properties: ComputerProperties,
    pub ObjectIdentifier: String,
    #[serde(default)]
    pub IsDeleted: bool,
    #[serde(default)]
    pub IsACLProtected: bool,
    #[serde(default)]
    pub AllowedToDelegate: Vec<String>,
    #[serde(default)]
    pub AllowedToActAsDelegatesFor: Vec<String>,
    #[serde(default)]
    pub UnconstrainedDelegation: bool,
    #[serde(default)]
    pub Enabled: bool,
    #[serde(default)]
    pub TrustedToAuth: bool,
    #[serde(default)]
    pub DumpSMSAPassword: Vec<String>,
    #[serde(default)]
    pub Sessions: Vec<Session>,
    #[serde(default)]
    pub SessionsUnrolled: bool,
    #[serde(default)]
    pub LocalAdmins: Vec<LocalAdmin>,
    #[serde(default)]
    pub RemoteDesktopUsers: Vec<RemoteDesktopUser>,
    #[serde(default)]
    pub DcomUsers: Vec<DcomUser>,
    pub PrimaryGroupID: Option<i32>,
    #[serde(default)]
    pub HasSIDHistory: Vec<String>,
    #[serde(default)]
    pub SidFiltering: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputerProperties {
    pub name: String,
    pub domainsid: Option<String>,
    pub domain: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub unconstraineddelegation: bool,
    #[serde(default)]
    pub trustedtoauth: bool,
    #[serde(default)]
    pub isdc: bool,
    pub sid: Option<String>,
    pub whencreated: Option<i64>,
    pub lastlogon: Option<i64>,
    pub pwdlastset: Option<i64>,
    pub operatingsystem: Option<String>,
    #[serde(default)]
    pub serviceprincipalnames: Vec<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub sidhistory: Vec<String>,
    #[serde(default)]
    pub allowedtoactasdelegatesfor: Vec<String>,
    #[serde(default)]
    pub allowedtodelegate: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub computer: String,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAdmin {
    pub ObjectIdentifier: String,
    pub ResultingGPOs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteDesktopUser {
    pub ObjectIdentifier: String,
    pub ResultingGPOs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcomUser {
    pub ObjectIdentifier: String,
    pub ResultingGPOs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserObject {
    pub Properties: UserProperties,
    pub ObjectIdentifier: String,
    #[serde(default)]
    pub IsDeleted: bool,
    #[serde(default)]
    pub IsACLProtected: bool,
    #[serde(default)]
    pub AllowedToDelegate: Vec<String>,
    #[serde(default)]
    pub AllowedToActAsDelegatesFor: Vec<String>,
    #[serde(default)]
    pub UnconstrainedDelegation: bool,
    #[serde(default)]
    pub Enabled: bool,
    #[serde(default)]
    pub TrustedToAuth: bool,
    #[serde(default)]
    pub HasSIDHistory: Vec<String>,
    pub PrimaryGroupID: Option<i32>,
    pub AdminCount: bool,
    #[serde(default)]
    pub ServicePrincipalNames: Vec<String>,
    #[serde(default)]
    pub UserPassword: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProperties {
    pub name: String,
    pub domainsid: Option<String>,
    pub domain: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub unconstraineddelegation: bool,
    #[serde(default)]
    pub trustedtoauth: bool,
    pub sid: Option<String>,
    pub whencreated: Option<i64>,
    pub lastlogon: Option<i64>,
    pub pwdlastset: Option<i64>,
    pub description: Option<String>,
    pub title: Option<String>,
    pub displayname: Option<String>,
    pub email: Option<String>,
    #[serde(default)]
    pub userpassword: Vec<String>,
    #[serde(default)]
    pub sidhistory: Vec<String>,
    #[serde(default)]
    pub allowedtoactasdelegatesfor: Vec<String>,
    #[serde(default)]
    pub allowedtodelegate: Vec<String>,
    #[serde(default)]
    pub admincount: bool,
    #[serde(default)]
    pub serviceprincipalnames: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupObject {
    pub Properties: GroupProperties,
    pub ObjectIdentifier: String,
    pub IsDeleted: bool,
    pub IsACLProtected: bool,
    pub Members: Vec<Member>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupProperties {
    pub name: String,
    pub domainsid: Option<String>,
    pub domain: String,
    pub sid: Option<String>,
    pub description: Option<String>,
    pub admincount: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub ObjectIdentifier: String,
    pub MemberType: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainObject {
    pub Properties: DomainProperties,
    pub ObjectIdentifier: String,
    pub IsDeleted: bool,
    pub IsACLProtected: bool,
    pub Trusts: Vec<Trust>,
    pub Links: Vec<Link>,
    pub ChildObjects: Vec<ChildObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainProperties {
    pub name: String,
    pub domainsid: String,
    pub description: Option<String>,
    pub functionallevel: Option<String>,
    pub whencreated: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trust {
    pub TargetDomainSid: String,
    pub TargetDomainName: String,
    pub IsTransitive: bool,
    pub SidFiltering: bool,
    pub TrustDirection: String,
    pub TrustType: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    pub IsEnforced: bool,
    pub GUID: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildObject {
    pub ObjectIdentifier: String,
    #[serde(rename = "type")]
    pub ObjectType: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GPOObject {
    pub Properties: GPOProperties,
    pub ObjectIdentifier: String,
    pub IsDeleted: bool,
    pub IsACLProtected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GPOProperties {
    pub name: String,
    pub domainsid: Option<String>,
    pub domain: String,
    pub description: Option<String>,
    pub whencreated: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OUObject {
    pub Properties: OUProperties,
    pub ObjectIdentifier: String,
    pub IsDeleted: bool,
    pub IsACLProtected: bool,
    pub Links: Vec<Link>,
    pub ChildObjects: Vec<ChildObject>,
    pub GPOChanges: GPOChanges,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OUProperties {
    pub name: String,
    pub domainsid: Option<String>,
    pub domain: String,
    pub description: Option<String>,
    pub whencreated: Option<i64>,
    pub gplink: Vec<String>,
    pub gpoptions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GPOChanges {
    pub AffectedComputers: Vec<String>,
    pub LocalAdmins: Vec<LocalAdmin>,
    pub RemoteDesktopUsers: Vec<RemoteDesktopUser>,
    pub DcomUsers: Vec<DcomUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub start_node: String,
    pub end_node: String,
    pub path: Vec<PathSegment>,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSegment {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub relationship: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloodHoundQuery {
    pub query: String,
    pub params: HashMap<String, serde_json::Value>,
}

impl BloodHoundClient {
    /// Create a new BloodHound API client
    pub fn new(base_url: &str, username: &str, password: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            token: None,
        }
    }

    /// Login to BloodHound API
    pub async fn login(&mut self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let response = self
            .client
            .post(&format!("{}/api/v2/login", self.base_url))
            .json(&serde_json::json!({
                "username": self.username,
                "password": self.password
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        if let Some(token) = response.get("token").and_then(|v| v.as_str()) {
            self.token = Some(token.to_string());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Ingest BloodHound data
    pub async fn ingest_data(
        &self,
        data: &BloodHoundData,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let response = self
            .client
            .post(&format!("{}/api/v2/file-upload/cypher", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(data)
            .send()
            .await?;

        Ok(response.status().is_success())
    }

    /// Query BloodHound for attack paths
    pub async fn get_attack_paths(
        &self,
        start_node: &str,
        end_node: &str,
    ) -> Result<Vec<AttackPath>, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        // Query to find shortest paths
        let query = format!(
            "MATCH p=shortestPath((start {{name:'{}'}})-[*1..5]->(end {{name:'{}'}})) RETURN p",
            start_node, end_node
        );

        let response = self
            .client
            .post(&format!("{}/api/v2/cypher", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({
                "query": query
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        self.parse_attack_paths(&response)
    }

    /// Get all domain computers
    pub async fn get_domain_computers(
        &self,
        domain: &str,
    ) -> Result<Vec<ComputerObject>, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let query = format!("MATCH (c:Computer) WHERE c.domain = '{}' RETURN c", domain);

        let response = self
            .client
            .post(&format!("{}/api/v2/cypher", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({
                "query": query
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        self.parse_computers(&response)
    }

    /// Get all domain users
    pub async fn get_domain_users(
        &self,
        domain: &str,
    ) -> Result<Vec<UserObject>, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let query = format!("MATCH (u:User) WHERE u.domain = '{}' RETURN u", domain);

        let response = self
            .client
            .post(&format!("{}/api/v2/cypher", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({
                "query": query
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        self.parse_users(&response)
    }

    /// Get all groups
    pub async fn get_groups(
        &self,
        domain: &str,
    ) -> Result<Vec<GroupObject>, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let query = format!("MATCH (g:Group) WHERE g.domain = '{}' RETURN g", domain);

        let response = self
            .client
            .post(&format!("{}/api/v2/cypher", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({
                "query": query
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        self.parse_groups(&response)
    }

    /// Find Kerberoastable users
    pub async fn find_kerberoastable(
        &self,
    ) -> Result<Vec<UserObject>, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let query = "MATCH (u:User {hasspn:true}) RETURN u";

        let response = self
            .client
            .post(&format!("{}/api/v2/cypher", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({
                "query": query
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        self.parse_users(&response)
    }

    /// Find users with unconstrained delegation
    pub async fn find_unconstrained_delegation(
        &self,
    ) -> Result<Vec<ComputerObject>, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let query = "MATCH (c:Computer {unconstraineddelegation:true}) RETURN c";

        let response = self
            .client
            .post(&format!("{}/api/v2/cypher", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({
                "query": query
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        self.parse_computers(&response)
    }

    /// Find AS-REP roastable users
    pub async fn find_asrep_roastable(
        &self,
    ) -> Result<Vec<UserObject>, Box<dyn std::error::Error + Send + Sync>> {
        let token = match &self.token {
            Some(t) => t,
            None => return Err("Not authenticated".into()),
        };

        let query = "MATCH (u:User {dontreqpreauth:true}) RETURN u";

        let response = self
            .client
            .post(&format!("{}/api/v2/cypher", self.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({
                "query": query
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        self.parse_users(&response)
    }

    fn parse_attack_paths(
        &self,
        response: &serde_json::Value,
    ) -> Result<Vec<AttackPath>, Box<dyn std::error::Error + Send + Sync>> {
        let mut paths = Vec::new();
        let rows = response
            .get("data")
            .and_then(|d| d.get("paths"))
            .or_else(|| response.get("paths"))
            .or_else(|| response.get("rows"));

        if let Some(list) = rows.and_then(|v| v.as_array()) {
            for row in list {
                let nodes = row
                    .get("nodes")
                    .and_then(|n| n.as_array())
                    .cloned()
                    .unwrap_or_default();
                let edges = row
                    .get("relationships")
                    .and_then(|r| r.as_array())
                    .cloned()
                    .unwrap_or_default();
                if nodes.is_empty() {
                    continue;
                }

                let start_node = nodes
                    .first()
                    .and_then(|n| n.get("name").and_then(|v| v.as_str()))
                    .unwrap_or("?")
                    .to_string();
                let end_node = nodes
                    .last()
                    .and_then(|n| n.get("name").and_then(|v| v.as_str()))
                    .unwrap_or("?")
                    .to_string();

                let mut hops: Vec<PathSegment> = Vec::new();
                for (i, node) in nodes.iter().enumerate() {
                    let nid = node
                        .get("objectid")
                        .or_else(|| node.get("id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let name = node
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let ty = node
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Node")
                        .to_string();
                    let rel = edges
                        .get(i)
                        .and_then(|e| e.get("relationship"))
                        .or_else(|| edges.get(i).and_then(|e| e.get("kind")))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    hops.push(PathSegment {
                        id: nid,
                        name,
                        node_type: ty,
                        relationship: rel,
                    });
                }

                paths.push(AttackPath {
                    start_node,
                    end_node,
                    path: hops,
                    length: nodes.len().saturating_sub(1),
                });
            }
        }
        Ok(paths)
    }

    fn parse_computers(
        &self,
        response: &serde_json::Value,
    ) -> Result<Vec<ComputerObject>, Box<dyn std::error::Error + Send + Sync>> {
        let mut out = Vec::new();
        let nodes = response
            .get("data")
            .and_then(|d| d.as_array())
            .or_else(|| response.as_array());
        if let Some(list) = nodes {
            for entry in list {
                let raw = entry
                    .get("c")
                    .or_else(|| entry.get("Computer"))
                    .or_else(|| entry.get("n"))
                    .unwrap_or(entry);
                if let Ok(computer) = serde_json::from_value::<ComputerObject>(raw.clone()) {
                    out.push(computer);
                } else if let Some(props) = raw.get("properties") {
                    let merged = merge_props(raw, props)?;
                    if let Ok(computer) = serde_json::from_value::<ComputerObject>(merged) {
                        out.push(computer);
                    }
                }
            }
        }
        Ok(out)
    }

    fn parse_users(
        &self,
        response: &serde_json::Value,
    ) -> Result<Vec<UserObject>, Box<dyn std::error::Error + Send + Sync>> {
        let mut out = Vec::new();
        let nodes = response
            .get("data")
            .and_then(|d| d.as_array())
            .or_else(|| response.as_array());
        if let Some(list) = nodes {
            for entry in list {
                let raw = entry
                    .get("u")
                    .or_else(|| entry.get("User"))
                    .or_else(|| entry.get("n"))
                    .unwrap_or(entry);
                if let Ok(obj) = serde_json::from_value::<UserObject>(raw.clone()) {
                    out.push(obj);
                } else if let Some(props) = raw.get("properties") {
                    let merged = merge_props(raw, props)?;
                    if let Ok(obj) = serde_json::from_value::<UserObject>(merged) {
                        out.push(obj);
                    }
                }
            }
        }
        Ok(out)
    }

    fn parse_groups(
        &self,
        response: &serde_json::Value,
    ) -> Result<Vec<GroupObject>, Box<dyn std::error::Error + Send + Sync>> {
        let mut out = Vec::new();
        let nodes = response
            .get("data")
            .and_then(|d| d.as_array())
            .or_else(|| response.as_array());
        if let Some(list) = nodes {
            for entry in list {
                let raw = entry
                    .get("g")
                    .or_else(|| entry.get("Group"))
                    .or_else(|| entry.get("n"))
                    .unwrap_or(entry);
                if let Ok(obj) = serde_json::from_value::<GroupObject>(raw.clone()) {
                    out.push(obj);
                } else if let Some(props) = raw.get("properties") {
                    let merged = merge_props(raw, props)?;
                    if let Ok(obj) = serde_json::from_value::<GroupObject>(merged) {
                        out.push(obj);
                    }
                }
            }
        }
        Ok(out)
    }
}

fn merge_props(
    raw: &serde_json::Value,
    props: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let mut obj = raw.clone();
    if let Some(map) = obj.as_object_mut() {
        if let Some(pmap) = props.as_object() {
            for (k, v) in pmap {
                let lower = k
                    .chars()
                    .next()
                    .map(|c| c.to_lowercase().to_string() + &k[1..])
                    .unwrap_or_else(|| k.clone());
                if !map.contains_key(k) {
                    map.insert(k.clone(), v.clone());
                }
                if !map.contains_key(&lower) {
                    map.insert(lower, v.clone());
                }
            }
        }
    }
    Ok(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bloodhound_client_creation() {
        let client = BloodHoundClient::new("http://localhost:7474", "neo4j", "password");
        assert_eq!(client.base_url, "http://localhost:7474");
        assert_eq!(client.username, "neo4j");
        assert!(client.token.is_none());
    }

    #[test]
    fn test_parse_computers_from_cypher_rows() {
        let bh = BloodHoundClient::new("http://localhost:7474", "neo4j", "password");
        let payload = serde_json::json!({
            "data": [
                {"c": {"ObjectIdentifier": "S-1-5-21-1-1", "IsDeleted": false, "UnconstrainedDelegation": true, "Enabled": true,
                 "Properties": {"name": "DC01.AD.LAB", "domain": "AD.LAB", "sid": "S-1-5-21-1-1", "operatingsystem": "Windows Server 2019",
                                "isdc": true, "unconstraineddelegation": true, "enabled": true}}}
            ]
        });
        let computers = bh.parse_computers(&payload).unwrap();
        assert_eq!(computers.len(), 1);
        assert_eq!(computers[0].Properties.name, "DC01.AD.LAB");
        assert_eq!(computers[0].ObjectIdentifier, "S-1-5-21-1-1");
        assert!(computers[0].UnconstrainedDelegation);
        assert!(computers[0].Properties.isdc);
    }

    #[test]
    fn test_parse_users_from_cypher_rows() {
        let bh = BloodHoundClient::new("http://localhost:7474", "neo4j", "password");
        let payload = serde_json::json!({
            "data": [
                {"u": {"ObjectIdentifier": "S-1-5-21-1-500", "IsDeleted": false, "AdminCount": true,
                 "Properties": {"name": "Administrator@AD.LAB", "domain": "AD.LAB", "sid": "S-1-5-21-1-500",
                                "enabled": true, "admincount": true, "dontreqpreauth": false, "hasspn": false}}}
            ]
        });
        let users = bh.parse_users(&payload).unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].Properties.name, "Administrator@AD.LAB");
        assert_eq!(users[0].ObjectIdentifier, "S-1-5-21-1-500");
        assert!(users[0].AdminCount);
    }

    #[test]
    fn test_parse_attack_paths_from_relationships() {
        let bh = BloodHoundClient::new("http://localhost:7474", "neo4j", "password");
        let payload = serde_json::json!({
            "paths": [{
                "nodes": [
                    {"objectid": "1", "name": "DOMAIN USER@AD.LAB", "type": "User"},
                    {"objectid": "2", "name": "WORKSTATION01.AD.LAB", "type": "Computer"},
                    {"objectid": "3", "name": "DOMAIN ADMINS@AD.LAB", "type": "Group"}
                ],
                "relationships": [
                    {"relationship": "GenericAll"},
                    {"relationship": "MemberOf"}
                ]
            }]
        });
        let paths = bh.parse_attack_paths(&payload).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].start_node, "DOMAIN USER@AD.LAB");
        assert_eq!(paths[0].end_node, "DOMAIN ADMINS@AD.LAB");
        assert_eq!(paths[0].length, 2);
        assert_eq!(paths[0].path[1].relationship, "MemberOf");
    }
}
