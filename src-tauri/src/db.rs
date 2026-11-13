use chrono::{
    DateTime, FixedOffset, LocalResult, NaiveDate, NaiveDateTime, SecondsFormat, TimeZone, Utc,
};
use chrono_tz::Tz;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

use crate::history::{record_commit_tx, ActorIdentity, EntityChangeInput};

pub type AppResult<T> = Result<T, String>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub name: String,
    pub description: String,
    pub client_name: String,
    pub investigator: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    pub id: String,
    pub name: String,
    pub subnet: String,
    pub network_type: String,
    pub description: String,
    pub vlan_id: Option<String>,
    #[serde(default)]
    pub quick_note: Option<String>,
    /// The site this segment is at, when recorded.
    #[serde(default)]
    pub site_id: Option<String>,
    /// Who the client says owns or governs the segment (department, business unit).
    #[serde(default)]
    pub owner: Option<String>,
    /// Who runs it day to day (admin team, managed service provider, vendor).
    #[serde(default)]
    pub operator: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    #[serde(default)]
    pub network_id: Option<String>,
    #[serde(default)]
    pub network_name: Option<String>,
    pub name: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub asset_type: String,
    pub os: Option<String>,
    pub user_name: Option<String>,
    #[serde(default)]
    pub suspicious: bool,
    #[serde(default = "default_compromise_status")]
    pub compromise_status: String,
    #[serde(default = "default_investigation_status")]
    pub investigation_status: String,
    pub properties: Option<String>,
    pub scan_results: Option<String>,
    #[serde(default)]
    pub quick_note: Option<String>,
    #[serde(default)]
    pub site_id: Option<String>,
    /// Who the client says owns the asset (department, business owner).
    #[serde(default)]
    pub owner: Option<String>,
    /// Who administers it (admin team, managed service provider, vendor).
    #[serde(default)]
    pub operator: Option<String>,
    /// How the case learned of the asset: the client's own inventory, our own
    /// discovery, or not recorded.
    #[serde(default = "default_asset_origin")]
    pub origin: String,
    /// When the asset was last seen active (ARP entry, scan, lease), RFC 3339.
    #[serde(default)]
    pub last_observed: Option<String>,
    pub created_at: String,
}

/// A physical or organizational location: a head office, a plant, a data
/// center. Networks and assets can say which site they are at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub description: String,
    pub created_at: String,
}

/// A directed link between two assets: a VM runs on a hypervisor host, a host
/// is managed by a console, a server backs up to another. `source_name` and
/// `target_name` are the asset names when the row was read, for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRelation {
    pub id: String,
    pub source_asset_id: String,
    #[serde(default)]
    pub source_name: Option<String>,
    pub target_asset_id: String,
    #[serde(default)]
    pub target_name: Option<String>,
    #[serde(default = "default_relation_type")]
    pub relation_type: String,
    #[serde(default)]
    pub note: String,
    pub created_at: String,
}

/// The environment fields of an asset that older callers do not send. On
/// create a missing field takes its default; on update a missing field keeps
/// the stored value and an empty string clears it, so a caller that predates
/// these fields cannot erase them.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetContext {
    #[serde(default)]
    pub site_id: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub origin: Option<String>,
    #[serde(default)]
    pub last_observed: Option<String>,
}

/// The same for a network.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkContext {
    #[serde(default)]
    pub site_id: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub operator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub id: String,
    pub asset_id: String,
    pub name: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub network_id: Option<String>,
    #[serde(default)]
    pub network_name: Option<String>,
    #[serde(default)]
    pub is_primary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub id: String,
    pub asset_id: Option<String>,
    #[serde(default)]
    pub asset_name: Option<String>,
    pub timestamp: String,
    #[serde(default)]
    pub raw_timestamp: Option<String>,
    #[serde(default)]
    pub raw_timezone: Option<String>,
    #[serde(default)]
    pub server_timestamp_utc: Option<String>,
    #[serde(default)]
    pub correct_timestamp_raw: Option<String>,
    #[serde(default)]
    pub correct_timezone: Option<String>,
    #[serde(default)]
    pub clock_profile_id: Option<String>,
    #[serde(default)]
    pub clock_profile_name: Option<String>,
    #[serde(default)]
    pub clock_offset_ms: i64,
    #[serde(default = "default_time_precision")]
    pub time_precision: String,
    #[serde(default = "default_unknown_time_precision")]
    pub correct_time_precision: String,
    pub event_type: String,
    pub description: String,
    pub severity: String,
    pub source: Option<String>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub created_at: String,
    /// Where the event came from when it was promoted from stored evidence:
    /// the event-log batch and record, the original timestamp text, and an
    /// excerpt of the raw record, so a recipient can trace the finding back.
    #[serde(default)]
    pub source_ref: Option<Value>,
}

/// An entity a capture was turned into while it was processed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CaptureLink {
    pub entity_type: String,
    pub entity_id: String,
    #[serde(default)]
    pub title: String,
}

/// Raw information recorded the moment it was learned ("APP01, 10.0.0.15,
/// probably on ESX03. Finance owns it."), kept verbatim with who captured it
/// and when. Classification and linking happen later, when it is processed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capture {
    pub id: String,
    pub content: String,
    #[serde(default)]
    pub source: String,
    #[serde(default = "default_capture_status")]
    pub status: String,
    #[serde(default)]
    pub captured_by: String,
    #[serde(default)]
    pub team: Option<String>,
    #[serde(default)]
    pub links: Vec<CaptureLink>,
    #[serde(default)]
    pub resolution: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockProfile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub server_reference_raw: String,
    pub server_timezone: String,
    pub server_reference_utc: String,
    pub correct_reference_raw: String,
    pub correct_timezone: String,
    pub correct_reference_utc: String,
    pub offset_ms: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimePreview {
    pub input: String,
    pub timezone: String,
    pub interpreted_utc: String,
    pub corrected_utc: String,
    pub precision: String,
    pub epoch_millis: i64,
    pub offset_ms: i64,
    pub used_embedded_timezone: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub id: String,
    pub title: String,
    pub content: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub id: String,
    pub ioc_type: String,
    pub value: String,
    pub description: String,
    pub threat_level: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Firewall {
    pub id: String,
    pub network_id: Option<String>,
    #[serde(default)]
    pub network_name: Option<String>,
    pub name: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub rules: Option<String>,
    pub config_text: Option<String>,
    #[serde(default)]
    pub quick_note: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallInterface {
    pub id: String,
    pub firewall_id: String,
    pub name: String,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    pub mac_address: Option<String>,
    pub network_id: Option<String>,
    #[serde(default)]
    pub network_name: Option<String>,
    pub vlan_id: Option<String>,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub is_primary: bool,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallNatRule {
    pub id: String,
    pub firewall_id: String,
    pub name: String,
    pub nat_type: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub protocol: String,
    pub source_cidr: Option<String>,
    pub original_destination: Option<String>,
    pub original_port: Option<String>,
    pub translated_source: Option<String>,
    pub translated_destination: Option<String>,
    pub translated_port: Option<String>,
    pub inbound_interface_id: Option<String>,
    pub outbound_interface_id: Option<String>,
    #[serde(default)]
    pub description: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub id: String,
    pub source_network_id: String,
    #[serde(default)]
    pub source_network_name: Option<String>,
    pub target_network_id: String,
    #[serde(default)]
    pub target_network_name: Option<String>,
    pub connection_type: String,
    pub description: String,
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocSighting {
    pub id: String,
    pub ioc_id: String,
    #[serde(default)]
    pub ioc_value: Option<String>,
    #[serde(default)]
    pub ioc_type: Option<String>,
    #[serde(default)]
    pub threat_level: Option<String>,
    pub entity_kind: String,
    pub entity_id: String,
    #[serde(default)]
    pub entity_name: Option<String>,
    pub sighted_at: Option<String>,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub note: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEdge {
    pub id: String,
    pub source_kind: String,
    pub source_id: String,
    #[serde(default)]
    pub source_name: Option<String>,
    pub target_kind: String,
    pub target_id: String,
    #[serde(default)]
    pub target_name: Option<String>,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_edge_type")]
    pub edge_type: String,
    #[serde(default = "default_confidence")]
    pub confidence: String,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub occurred_at: Option<String>,
    pub timeline_event_id: Option<String>,
    #[serde(default)]
    pub timeline_event_time: Option<String>,
    #[serde(default)]
    pub sequence: i64,
    #[serde(default)]
    pub ioc_ids: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationView {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub state: Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationViewSummary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfectionEntitySummary {
    pub entity_kind: String,
    pub entity_id: String,
    pub entity_name: String,
    pub sighting_count: i64,
    pub max_threat_level: String,
    pub ioc_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfectionIocEntityRef {
    pub entity_kind: String,
    pub entity_id: String,
    pub entity_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfectionIocSummary {
    pub ioc_id: String,
    pub entity_count: i64,
    pub entities: Vec<InfectionIocEntityRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InfectionSummary {
    pub entities: Vec<InfectionEntitySummary>,
    pub iocs: Vec<InfectionIocSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TopologyNodePosition {
    pub id: String,
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TopologyViewState {
    pub layout: String,
    pub positions: Vec<TopologyNodePosition>,
    pub zoom: f64,
    pub pan_x: f64,
    pub pan_y: f64,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportEntitySummary {
    pub inserted: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportSummary {
    pub entities: HashMap<String, ImportEntitySummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportData {
    #[serde(default = "default_format_version")]
    pub format_version: u32,
    #[serde(default)]
    pub exported_at: String,
    pub case_info: Option<Case>,
    #[serde(default)]
    pub networks: Vec<Network>,
    #[serde(default)]
    pub assets: Vec<Asset>,
    #[serde(default)]
    pub network_interfaces: Vec<NetworkInterface>,
    #[serde(default)]
    pub clock_profiles: Vec<ClockProfile>,
    #[serde(default)]
    pub timeline_events: Vec<TimelineEvent>,
    #[serde(default)]
    pub notes: Vec<Note>,
    #[serde(default)]
    pub iocs: Vec<Ioc>,
    #[serde(default)]
    pub firewalls: Vec<Firewall>,
    #[serde(default)]
    pub firewall_interfaces: Vec<FirewallInterface>,
    #[serde(default)]
    pub firewall_nat_rules: Vec<FirewallNatRule>,
    #[serde(default)]
    pub network_connections: Vec<NetworkConnection>,
    #[serde(default)]
    pub ioc_sightings: Vec<IocSighting>,
    #[serde(default)]
    pub attack_edges: Vec<AttackEdge>,
    #[serde(default)]
    pub investigation_views: Vec<InvestigationView>,
    #[serde(default)]
    pub captures: Vec<Capture>,
    #[serde(default)]
    pub sites: Vec<Site>,
    #[serde(default)]
    pub asset_relations: Vec<AssetRelation>,
}

fn default_format_version() -> u32 {
    1
}

fn default_asset_origin() -> String {
    "unknown".to_string()
}

fn default_relation_type() -> String {
    "other".to_string()
}

fn default_capture_status() -> String {
    "open".to_string()
}

fn default_edge_type() -> String {
    "other".to_string()
}

fn default_confidence() -> String {
    "suspected".to_string()
}

fn default_true() -> bool {
    true
}

fn default_compromise_status() -> String {
    "unknown".to_string()
}

fn default_investigation_status() -> String {
    "not_started".to_string()
}

fn default_time_precision() -> String {
    "millisecond".to_string()
}

fn default_unknown_time_precision() -> String {
    "unknown".to_string()
}

pub fn configure_connection(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )
    .map_err(|e| e.to_string())
}

pub fn init_database(conn: &Connection) -> AppResult<()> {
    configure_connection(conn)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            client_name TEXT NOT NULL DEFAULT '',
            investigator TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            metadata TEXT
        );
        CREATE TABLE IF NOT EXISTS networks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            subnet TEXT NOT NULL,
            network_type TEXT NOT NULL DEFAULT 'LAN',
            description TEXT NOT NULL DEFAULT '',
            vlan_id TEXT,
            quick_note TEXT,
            site_id TEXT REFERENCES sites(id),
            owner TEXT,
            operator TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY,
            network_id TEXT REFERENCES networks(id),
            name TEXT NOT NULL,
            ip_address TEXT NOT NULL DEFAULT '',
            mac_address TEXT,
            asset_type TEXT NOT NULL DEFAULT 'workstation',
            os TEXT,
            user_name TEXT,
            suspicious INTEGER NOT NULL DEFAULT 0,
            compromise_status TEXT NOT NULL DEFAULT 'unknown',
            investigation_status TEXT NOT NULL DEFAULT 'not_started',
            properties TEXT,
            scan_results TEXT,
            quick_note TEXT,
            site_id TEXT REFERENCES sites(id),
            owner TEXT,
            operator TEXT,
            origin TEXT NOT NULL DEFAULT 'unknown',
            last_observed TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS network_interfaces (
            id TEXT PRIMARY KEY,
            asset_id TEXT NOT NULL REFERENCES assets(id),
            name TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            mac_address TEXT,
            network_id TEXT REFERENCES networks(id),
            is_primary INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS network_connections (
            id TEXT PRIMARY KEY,
            source_network_id TEXT NOT NULL REFERENCES networks(id),
            target_network_id TEXT NOT NULL REFERENCES networks(id),
            connection_type TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            device_name TEXT
        );
        CREATE TABLE IF NOT EXISTS firewalls (
            id TEXT PRIMARY KEY,
            network_id TEXT REFERENCES networks(id),
            name TEXT NOT NULL,
            vendor TEXT,
            model TEXT,
            rules TEXT,
            config_text TEXT,
            quick_note TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS firewall_interfaces (
            id TEXT PRIMARY KEY,
            firewall_id TEXT NOT NULL REFERENCES firewalls(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            ip_addresses TEXT NOT NULL DEFAULT '[]',
            mac_address TEXT,
            network_id TEXT REFERENCES networks(id),
            vlan_id TEXT,
            role TEXT NOT NULL DEFAULT 'other',
            is_primary INTEGER NOT NULL DEFAULT 0,
            description TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS firewall_nat_rules (
            id TEXT PRIMARY KEY,
            firewall_id TEXT NOT NULL REFERENCES firewalls(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            nat_type TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            protocol TEXT NOT NULL DEFAULT 'any',
            source_cidr TEXT,
            original_destination TEXT,
            original_port TEXT,
            translated_source TEXT,
            translated_destination TEXT,
            translated_port TEXT,
            inbound_interface_id TEXT REFERENCES firewall_interfaces(id) ON DELETE SET NULL,
            outbound_interface_id TEXT REFERENCES firewall_interfaces(id) ON DELETE SET NULL,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS clock_profiles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            server_reference_raw TEXT NOT NULL,
            server_timezone TEXT NOT NULL,
            server_reference_utc TEXT NOT NULL,
            correct_reference_raw TEXT NOT NULL,
            correct_timezone TEXT NOT NULL,
            correct_reference_utc TEXT NOT NULL,
            offset_ms INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS timeline_events (
            id TEXT PRIMARY KEY,
            asset_id TEXT REFERENCES assets(id),
            timestamp TEXT NOT NULL,
            raw_timestamp TEXT,
            raw_timezone TEXT,
            server_timestamp_utc TEXT,
            correct_timestamp_raw TEXT,
            correct_timezone TEXT,
            clock_profile_id TEXT REFERENCES clock_profiles(id),
            clock_offset_ms INTEGER NOT NULL DEFAULT 0,
            time_precision TEXT NOT NULL DEFAULT 'millisecond',
            correct_time_precision TEXT NOT NULL DEFAULT 'unknown',
            event_type TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            source TEXT,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            created_at TEXT NOT NULL,
            source_ref TEXT
        );
        CREATE TABLE IF NOT EXISTS notes (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS iocs (
            id TEXT PRIMARY KEY,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            threat_level TEXT NOT NULL DEFAULT 'medium',
            first_seen TEXT,
            last_seen TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS topology_views (
            layout TEXT PRIMARY KEY,
            positions_json TEXT NOT NULL,
            zoom REAL NOT NULL,
            pan_x REAL NOT NULL,
            pan_y REAL NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ioc_sightings (
            id TEXT PRIMARY KEY,
            ioc_id TEXT NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
            asset_id TEXT REFERENCES assets(id) ON DELETE CASCADE,
            network_id TEXT REFERENCES networks(id) ON DELETE CASCADE,
            firewall_id TEXT REFERENCES firewalls(id) ON DELETE CASCADE,
            sighted_at TEXT,
            location TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            CHECK ((asset_id IS NOT NULL) + (network_id IS NOT NULL) + (firewall_id IS NOT NULL) = 1)
        );
        CREATE TABLE IF NOT EXISTS attack_edges (
            id TEXT PRIMARY KEY,
            source_kind TEXT NOT NULL,
            source_id TEXT NOT NULL,
            target_kind TEXT NOT NULL,
            target_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            edge_type TEXT NOT NULL DEFAULT 'other',
            confidence TEXT NOT NULL DEFAULT 'suspected',
            mitre_tactic TEXT,
            mitre_technique TEXT,
            occurred_at TEXT,
            timeline_event_id TEXT REFERENCES timeline_events(id) ON DELETE SET NULL,
            sequence INTEGER NOT NULL DEFAULT 0,
            ioc_ids TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS investigation_views (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            state_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS history_commits (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            author_name TEXT NOT NULL,
            session_id TEXT NOT NULL,
            message TEXT NOT NULL,
            scope_json TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS history_commit_parents (
            commit_id TEXT NOT NULL REFERENCES history_commits(id),
            parent_commit_id TEXT NOT NULL,
            position INTEGER NOT NULL,
            PRIMARY KEY(commit_id, parent_commit_id)
        );
        CREATE TABLE IF NOT EXISTS history_changes (
            id TEXT PRIMARY KEY,
            commit_id TEXT NOT NULL REFERENCES history_commits(id),
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            base_revision INTEGER NOT NULL,
            new_revision INTEGER NOT NULL,
            before_json TEXT,
            after_json TEXT,
            source_change_id TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS history_entity_heads (
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            last_commit_id TEXT NOT NULL,
            deleted INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(entity_type, entity_id)
        );
        CREATE TABLE IF NOT EXISTS history_state (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            head_commit_id TEXT NOT NULL,
            shared_base_commit_id TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS captures (
            id TEXT PRIMARY KEY,
            content TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            captured_by TEXT NOT NULL DEFAULT '',
            team TEXT,
            links TEXT NOT NULL DEFAULT '[]',
            resolution TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        -- Unsaved form input per expert. Working state, not evidence: it has no
        -- history and is left out of snapshots and change bundles.
        CREATE TABLE IF NOT EXISTS drafts (
            owner TEXT NOT NULL,
            draft_key TEXT NOT NULL,
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (owner, draft_key)
        );
        -- The original commits behind a merge, so a contributor's authorship,
        -- times, and team survive the merger's single merge commit.
        CREATE TABLE IF NOT EXISTS history_merged_commits (
            merge_commit_id TEXT NOT NULL REFERENCES history_commits(id),
            commit_id TEXT NOT NULL,
            bundle_id TEXT NOT NULL,
            author_name TEXT NOT NULL,
            session_id TEXT NOT NULL,
            message TEXT NOT NULL,
            scope_json TEXT,
            created_at TEXT NOT NULL,
            changes_json TEXT NOT NULL,
            PRIMARY KEY (merge_commit_id, commit_id)
        );
        -- Where equipment is. Networks and assets point at a site; a site cannot
        -- be deleted while anything does.
        CREATE TABLE IF NOT EXISTS sites (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            location TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        -- Directed links between assets (VM runs on host, managed by, backs up to).
        CREATE TABLE IF NOT EXISTS asset_relations (
            id TEXT PRIMARY KEY,
            source_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            target_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            relation_type TEXT NOT NULL DEFAULT 'other',
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            CHECK (source_asset_id <> target_asset_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_relations_unique
            ON asset_relations(source_asset_id, target_asset_id, relation_type);
        CREATE INDEX IF NOT EXISTS idx_asset_relations_target ON asset_relations(target_asset_id);
        CREATE INDEX IF NOT EXISTS idx_assets_network ON assets(network_id);
        CREATE INDEX IF NOT EXISTS idx_timeline_asset ON timeline_events(asset_id);
        CREATE INDEX IF NOT EXISTS idx_timeline_time ON timeline_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_timeline_clock_profile ON timeline_events(clock_profile_id);
        CREATE INDEX IF NOT EXISTS idx_interfaces_asset ON network_interfaces(asset_id);
        CREATE INDEX IF NOT EXISTS idx_interfaces_network ON network_interfaces(network_id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_interfaces_one_primary
            ON network_interfaces(asset_id) WHERE is_primary = 1;
        CREATE INDEX IF NOT EXISTS idx_firewall_interfaces_firewall ON firewall_interfaces(firewall_id);
        CREATE INDEX IF NOT EXISTS idx_firewall_interfaces_network ON firewall_interfaces(network_id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_firewall_interfaces_one_primary
            ON firewall_interfaces(firewall_id) WHERE is_primary = 1;
        CREATE INDEX IF NOT EXISTS idx_firewall_nat_firewall ON firewall_nat_rules(firewall_id);
        CREATE INDEX IF NOT EXISTS idx_connections_source ON network_connections(source_network_id);
        CREATE INDEX IF NOT EXISTS idx_connections_target ON network_connections(target_network_id);
        CREATE INDEX IF NOT EXISTS idx_history_changes_entity ON history_changes(entity_type, entity_id);
        CREATE INDEX IF NOT EXISTS idx_history_changes_commit ON history_changes(commit_id);
        CREATE INDEX IF NOT EXISTS idx_ioc_sightings_ioc ON ioc_sightings(ioc_id);
        CREATE INDEX IF NOT EXISTS idx_ioc_sightings_asset ON ioc_sightings(asset_id);
        CREATE INDEX IF NOT EXISTS idx_attack_edges_source ON attack_edges(source_kind, source_id);
        CREATE INDEX IF NOT EXISTS idx_attack_edges_target ON attack_edges(target_kind, target_id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_investigation_views_name ON investigation_views(LOWER(name));
        CREATE INDEX IF NOT EXISTS idx_captures_status ON captures(status);
        CREATE INDEX IF NOT EXISTS idx_history_merged_commits_merge ON history_merged_commits(merge_commit_id);
        PRAGMA user_version = 9;",
    )
    .map_err(|e| e.to_string())
}

fn table_exists(conn: &Connection, table: &str) -> AppResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        params![table],
        |row| row.get::<_, i64>(0),
    )
    .map(|value| value != 0)
    .map_err(|e| e.to_string())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> AppResult<bool> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| e.to_string())?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(names.iter().any(|name| name == column))
}

pub fn validate_and_migrate_case(conn: &mut Connection) -> AppResult<()> {
    configure_connection(conn)?;
    for table in [
        "cases",
        "networks",
        "assets",
        "timeline_events",
        "notes",
        "iocs",
    ] {
        if !table_exists(conn, table)? {
            return Err(format!(
                "Not a DFIR Investigator case: missing '{table}' table"
            ));
        }
    }
    let case_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM cases", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if case_count != 1 {
        return Err(format!(
            "A case database must contain exactly one case record; found {case_count}"
        ));
    }

    // Create the referenced table before adding timeline correlation columns.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS clock_profiles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            server_reference_raw TEXT NOT NULL,
            server_timezone TEXT NOT NULL,
            server_reference_utc TEXT NOT NULL,
            correct_reference_raw TEXT NOT NULL,
            correct_timezone TEXT NOT NULL,
            correct_reference_utc TEXT NOT NULL,
            offset_ms INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );",
    )
    .map_err(|e| e.to_string())?;

    let added_compromise_status = !column_exists(conn, "assets", "compromise_status")?;
    if added_compromise_status {
        conn.execute(
            "ALTER TABLE assets ADD COLUMN compromise_status TEXT NOT NULL DEFAULT 'unknown'",
            [],
        )
        .map_err(|e| e.to_string())?;
    }

    for (column, definition) in [
        ("raw_timestamp", "TEXT"),
        ("raw_timezone", "TEXT"),
        ("server_timestamp_utc", "TEXT"),
        ("correct_timestamp_raw", "TEXT"),
        ("correct_timezone", "TEXT"),
        ("clock_profile_id", "TEXT REFERENCES clock_profiles(id)"),
        ("clock_offset_ms", "INTEGER NOT NULL DEFAULT 0"),
        ("time_precision", "TEXT NOT NULL DEFAULT 'millisecond'"),
        ("correct_time_precision", "TEXT NOT NULL DEFAULT 'unknown'"),
    ] {
        if !column_exists(conn, "timeline_events", column)? {
            conn.execute(
                &format!("ALTER TABLE timeline_events ADD COLUMN {column} {definition}"),
                [],
            )
            .map_err(|e| e.to_string())?;
        }
    }
    conn.execute(
        "UPDATE timeline_events
         SET raw_timestamp=COALESCE(raw_timestamp,timestamp),
             raw_timezone=COALESCE(raw_timezone,'UTC'),
             time_precision=COALESCE(NULLIF(time_precision,''),'millisecond')",
        [],
    )
    .map_err(|e| e.to_string())?;
    let legacy_server_times = {
        let mut statement = conn
            .prepare(
                "SELECT id,raw_timestamp,COALESCE(raw_timezone,'UTC') FROM timeline_events
                 WHERE server_timestamp_utc IS NULL AND raw_timestamp IS NOT NULL AND TRIM(raw_timestamp)<>''",
            )
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        rows
    };
    for (id, raw, timezone) in legacy_server_times {
        if let Ok(preview) = parse_timestamp_preview(&raw, &timezone, 0) {
            conn.execute(
                "UPDATE timeline_events SET server_timestamp_utc=?1 WHERE id=?2",
                params![preview.interpreted_utc, id],
            )
            .map_err(|e| e.to_string())?;
        }
    }
    if !column_exists(conn, "assets", "investigation_status")? {
        conn.execute(
            "ALTER TABLE assets ADD COLUMN investigation_status TEXT NOT NULL DEFAULT 'not_started'",
            [],
        )
        .map_err(|e| e.to_string())?;
    }
    if added_compromise_status {
        conn.execute(
            "UPDATE assets SET compromise_status = CASE WHEN suspicious <> 0 THEN 'suspected' ELSE 'unknown' END",
            [],
        )
        .map_err(|e| e.to_string())?;
    } else {
        conn.execute(
            "UPDATE assets SET compromise_status = CASE WHEN suspicious <> 0 THEN 'suspected' ELSE 'unknown' END
             WHERE compromise_status IS NULL OR compromise_status = ''",
            [],
        )
        .map_err(|e| e.to_string())?;
    }

    if table_exists(conn, "network_interfaces")?
        && column_exists(conn, "network_interfaces", "is_primary")?
    {
        conn.execute(
            "UPDATE network_interfaces SET is_primary=0
             WHERE is_primary=1 AND rowid NOT IN (
               SELECT MIN(rowid) FROM network_interfaces WHERE is_primary=1 GROUP BY asset_id
             )",
            [],
        )
        .map_err(|e| e.to_string())?;
    }
    if table_exists(conn, "firewall_interfaces")? {
        conn.execute(
            "UPDATE firewall_interfaces SET is_primary=0
             WHERE is_primary=1 AND rowid NOT IN (
               SELECT MIN(rowid) FROM firewall_interfaces WHERE is_primary=1 GROUP BY firewall_id
             )",
            [],
        )
        .map_err(|e| e.to_string())?;
    }
    init_database(conn)?;
    // Quick notes are per-row investigator remarks on the primary entity
    // tables. Runs after init_database so legacy files that predate a table
    // entirely see it created (with the column) before the ALTER is attempted.
    for table in ["assets", "networks", "firewalls"] {
        if !column_exists(conn, table, "quick_note")? {
            conn.execute(
                &format!("ALTER TABLE {table} ADD COLUMN quick_note TEXT"),
                [],
            )
            .map_err(|e| e.to_string())?;
        }
    }
    // Schema 8: promoted timeline events keep a reference to their raw record.
    if !column_exists(conn, "timeline_events", "source_ref")? {
        conn.execute("ALTER TABLE timeline_events ADD COLUMN source_ref TEXT", [])
            .map_err(|e| e.to_string())?;
    }
    // Schema 9: sites, who is responsible, and how an asset became known.
    for (table, column, definition) in [
        ("networks", "site_id", "TEXT REFERENCES sites(id)"),
        ("networks", "owner", "TEXT"),
        ("networks", "operator", "TEXT"),
        ("assets", "site_id", "TEXT REFERENCES sites(id)"),
        ("assets", "owner", "TEXT"),
        ("assets", "operator", "TEXT"),
        ("assets", "origin", "TEXT NOT NULL DEFAULT 'unknown'"),
        ("assets", "last_observed", "TEXT"),
    ] {
        if !column_exists(conn, table, column)? {
            conn.execute(
                &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
                [],
            )
            .map_err(|e| e.to_string())?;
        }
    }
    repair_legacy_references(conn)?;
    backfill_primary_interfaces(conn)?;
    initialize_history(conn)?;
    verify_integrity(conn)
}

fn repair_legacy_references(conn: &mut Connection) -> AppResult<()> {
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE assets SET network_id=NULL WHERE network_id IS NOT NULL
         AND network_id NOT IN (SELECT id FROM networks)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE network_interfaces SET network_id=NULL WHERE network_id IS NOT NULL
         AND network_id NOT IN (SELECT id FROM networks)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE timeline_events SET asset_id=NULL WHERE asset_id IS NOT NULL
         AND asset_id NOT IN (SELECT id FROM assets)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE timeline_events SET clock_profile_id=NULL WHERE clock_profile_id IS NOT NULL
         AND clock_profile_id NOT IN (SELECT id FROM clock_profiles)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE networks SET site_id=NULL WHERE site_id IS NOT NULL
         AND site_id NOT IN (SELECT id FROM sites)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE assets SET site_id=NULL WHERE site_id IS NOT NULL
         AND site_id NOT IN (SELECT id FROM sites)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "DELETE FROM asset_relations WHERE source_asset_id NOT IN (SELECT id FROM assets)
         OR target_asset_id NOT IN (SELECT id FROM assets)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE firewalls SET network_id=NULL WHERE network_id IS NOT NULL
         AND network_id NOT IN (SELECT id FROM networks)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE firewall_interfaces SET network_id=NULL WHERE network_id IS NOT NULL
         AND network_id NOT IN (SELECT id FROM networks)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "DELETE FROM firewall_interfaces WHERE firewall_id NOT IN (SELECT id FROM firewalls)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "DELETE FROM firewall_nat_rules WHERE firewall_id NOT IN (SELECT id FROM firewalls)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "DELETE FROM network_interfaces WHERE asset_id NOT IN (SELECT id FROM assets)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "DELETE FROM network_connections WHERE source_network_id NOT IN (SELECT id FROM networks)
         OR target_network_id NOT IN (SELECT id FROM networks)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "DELETE FROM ioc_sightings WHERE ioc_id NOT IN (SELECT id FROM iocs)
         OR (asset_id IS NOT NULL AND asset_id NOT IN (SELECT id FROM assets))
         OR (network_id IS NOT NULL AND network_id NOT IN (SELECT id FROM networks))
         OR (firewall_id IS NOT NULL AND firewall_id NOT IN (SELECT id FROM firewalls))",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "DELETE FROM attack_edges
         WHERE (source_kind='asset' AND source_id NOT IN (SELECT id FROM assets))
         OR (source_kind='network' AND source_id NOT IN (SELECT id FROM networks))
         OR (source_kind='firewall' AND source_id NOT IN (SELECT id FROM firewalls))
         OR (target_kind='asset' AND target_id NOT IN (SELECT id FROM assets))
         OR (target_kind='network' AND target_id NOT IN (SELECT id FROM networks))
         OR (target_kind='firewall' AND target_id NOT IN (SELECT id FROM firewalls))",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE attack_edges SET timeline_event_id=NULL WHERE timeline_event_id IS NOT NULL
         AND timeline_event_id NOT IN (SELECT id FROM timeline_events)",
        [],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

fn backfill_primary_interfaces(conn: &mut Connection) -> AppResult<()> {
    let rows = get_assets(conn)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    for asset in rows {
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM network_interfaces WHERE asset_id=?1",
                params![asset.id],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if count == 0 {
            tx.execute(
                "INSERT INTO network_interfaces
                 (id, asset_id, name, ip_address, mac_address, network_id, is_primary)
                 VALUES (?1, ?2, 'Primary', ?3, ?4, ?5, 1)",
                params![
                    Uuid::new_v4().to_string(),
                    asset.id,
                    asset.ip_address,
                    asset.mac_address,
                    asset.network_id
                ],
            )
            .map_err(|e| e.to_string())?;
        } else {
            let primary_count: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM network_interfaces WHERE asset_id=?1 AND is_primary=1",
                    params![asset.id],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            if primary_count == 0 {
                tx.execute(
                    "UPDATE network_interfaces SET is_primary=1 WHERE id=(
                       SELECT id FROM network_interfaces WHERE asset_id=?1 ORDER BY rowid LIMIT 1
                     )",
                    params![asset.id],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        let projection: (Option<String>, String, Option<String>) = tx
            .query_row(
                "SELECT network_id,ip_address,mac_address FROM network_interfaces
                 WHERE asset_id=?1 AND is_primary=1 LIMIT 1",
                params![asset.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|e| e.to_string())?;
        tx.execute(
            "UPDATE assets SET network_id=?1,ip_address=?2,mac_address=?3 WHERE id=?4",
            params![projection.0, projection.1, projection.2, asset.id],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())
}

fn verify_integrity(conn: &Connection) -> AppResult<()> {
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if integrity != "ok" {
        return Err(format!("SQLite integrity check failed: {integrity}"));
    }
    let fk_errors: i64 = conn
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|e| e.to_string())?;
    if fk_errors != 0 {
        return Err(format!(
            "SQLite foreign-key check found {fk_errors} problem(s)"
        ));
    }
    Ok(())
}

pub fn create_case_record(
    conn: &Connection,
    name: &str,
    description: &str,
    client_name: &str,
    investigator: &str,
) -> AppResult<Case> {
    validate_required("Case name", name)?;
    validate_required("Investigator", investigator)?;
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO cases (id,name,description,client_name,investigator,status,created_at,updated_at)
         VALUES (?1,?2,?3,?4,?5,'active',?6,?6)",
        params![id, name.trim(), description.trim(), client_name.trim(), investigator.trim(), now],
    )
    .map_err(|e| e.to_string())?;
    let case = Case {
        id,
        name: name.trim().to_string(),
        description: description.trim().to_string(),
        client_name: client_name.trim().to_string(),
        investigator: investigator.trim().to_string(),
        status: "active".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: None,
    };
    initialize_history(conn)?;
    Ok(case)
}

pub fn initialize_history(conn: &Connection) -> AppResult<()> {
    let case = get_case(conn)?.ok_or_else(|| "Case metadata is missing".to_string())?;
    let baseline = format!("baseline:{}:v2", case.id);
    conn.execute(
        "INSERT OR IGNORE INTO history_commits
         (id,case_id,author_name,session_id,message,scope_json,created_at)
         VALUES (?1,?2,'system','system','Legacy case baseline',NULL,?3)",
        params![baseline, case.id, case.created_at],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT OR IGNORE INTO history_state(id,head_commit_id,shared_base_commit_id) VALUES (1,?1,?1)",
        params![baseline],
    )
    .map_err(|e| e.to_string())?;

    let mut baseline_entities = vec![(
        "case",
        case.id.clone(),
        serde_json::to_value(case).map_err(|e| e.to_string())?,
    )];
    for item in get_networks(conn)? {
        baseline_entities.push((
            "network",
            item.id.clone(),
            serde_json::to_value(item).map_err(|e| e.to_string())?,
        ));
    }
    for item in get_assets(conn)? {
        baseline_entities.push((
            "asset",
            item.id.clone(),
            serde_json::to_value(item).map_err(|e| e.to_string())?,
        ));
    }
    for item in get_network_interfaces(conn, None)? {
        baseline_entities.push((
            "network_interface",
            item.id.clone(),
            serde_json::to_value(item).map_err(|e| e.to_string())?,
        ));
    }
    for item in get_clock_profiles(conn)? {
        baseline_entities.push((
            "clock_profile",
            item.id.clone(),
            serde_json::to_value(item).map_err(|e| e.to_string())?,
        ));
    }
    for item in get_network_connections(conn)? {
        baseline_entities.push((
            "network_connection",
            item.id.clone(),
            serde_json::to_value(item).map_err(|e| e.to_string())?,
        ));
    }
    for item in get_firewalls(conn)? {
        baseline_entities.push((
            "firewall",
            item.id.clone(),
            serde_json::to_value(item).map_err(|e| e.to_string())?,
        ));
    }
    for item in get_firewall_interfaces(conn, None)? {
        baseline_entities.push((
            "firewall_interface",
            item.id.clone(),
            serde_json::to_value(item).map_err(|e| e.to_string())?,
        ));
    }
    for item in get_firewall_nat_rules(conn, None)? {
        baseline_entities.push((
            "firewall_nat_rule",
            item.id.clone(),
            serde_json::to_value(item).map_err(|e| e.to_string())?,
        ));
    }
    for item in get_timeline_events(conn)? {
        baseline_entities.push((
            "timeline_event",
            item.id.clone(),
            serde_json::to_value(item).map_err(|e| e.to_string())?,
        ));
    }
    for item in get_notes(conn)? {
        baseline_entities.push((
            "note",
            item.id.clone(),
            serde_json::to_value(item).map_err(|e| e.to_string())?,
        ));
    }
    for item in get_iocs(conn)? {
        baseline_entities.push((
            "ioc",
            item.id.clone(),
            serde_json::to_value(item).map_err(|e| e.to_string())?,
        ));
    }
    for item in get_captures(conn)? {
        baseline_entities.push((
            "capture",
            item.id.clone(),
            serde_json::to_value(item).map_err(|e| e.to_string())?,
        ));
    }
    for (entity_type, entity_id, _) in baseline_entities {
        conn.execute(
            "INSERT OR IGNORE INTO history_entity_heads
             (entity_type,entity_id,revision,last_commit_id,deleted) VALUES (?1,?2,1,?3,0)",
            params![entity_type, entity_id, baseline],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn get_case(conn: &Connection) -> AppResult<Option<Case>> {
    conn.query_row(
        "SELECT id,name,description,client_name,investigator,status,created_at,updated_at,metadata FROM cases LIMIT 1",
        [],
        map_case,
    )
    .optional()
    .map_err(|e| e.to_string())
}

fn map_case(row: &rusqlite::Row<'_>) -> rusqlite::Result<Case> {
    Ok(Case {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        client_name: row.get(3)?,
        investigator: row.get(4)?,
        status: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        metadata: row.get(8)?,
    })
}

const NETWORK_SELECT: &str = "SELECT id,name,subnet,network_type,description,vlan_id,quick_note,site_id,owner,operator,created_at FROM networks";

fn map_network(row: &rusqlite::Row<'_>) -> rusqlite::Result<Network> {
    Ok(Network {
        id: row.get(0)?,
        name: row.get(1)?,
        subnet: row.get(2)?,
        network_type: row.get(3)?,
        description: row.get(4)?,
        vlan_id: row.get(5)?,
        quick_note: row.get(6)?,
        site_id: row.get(7)?,
        owner: row.get(8)?,
        operator: row.get(9)?,
        created_at: row.get(10)?,
    })
}

pub fn get_networks(conn: &Connection) -> AppResult<Vec<Network>> {
    query_vec(
        conn,
        &format!("{NETWORK_SELECT} ORDER BY name"),
        [],
        map_network,
    )
}

fn validate_topology_layout(layout: &str) -> AppResult<()> {
    if [
        "dagre",
        "grid",
        "circle",
        "concentric",
        "breadthfirst",
        "mindmap",
    ]
    .contains(&layout)
    {
        Ok(())
    } else {
        Err(format!("Unsupported topology layout: {layout}"))
    }
}

pub fn get_topology_view(conn: &Connection, layout: &str) -> AppResult<Option<TopologyViewState>> {
    validate_topology_layout(layout)?;
    let stored = conn
        .query_row(
            "SELECT positions_json,zoom,pan_x,pan_y,updated_at FROM topology_views WHERE layout=?1",
            params![layout],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, f64>(2)?,
                    row.get::<_, f64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|e| e.to_string())?;
    stored
        .map(|(positions_json, zoom, pan_x, pan_y, updated_at)| {
            let positions = serde_json::from_str(&positions_json).map_err(|e| e.to_string())?;
            Ok(TopologyViewState {
                layout: layout.to_string(),
                positions,
                zoom,
                pan_x,
                pan_y,
                updated_at,
            })
        })
        .transpose()
}

pub fn save_topology_view(
    conn: &Connection,
    layout: &str,
    positions: Vec<TopologyNodePosition>,
    zoom: f64,
    pan_x: f64,
    pan_y: f64,
) -> AppResult<TopologyViewState> {
    validate_topology_layout(layout)?;
    if positions.len() > 20_000 {
        return Err("Topology view contains too many node positions".to_string());
    }
    if !(0.05..=10.0).contains(&zoom)
        || !pan_x.is_finite()
        || !pan_y.is_finite()
        || positions.iter().any(|position| {
            position.id.trim().is_empty()
                || position.id.len() > 512
                || !position.x.is_finite()
                || !position.y.is_finite()
                || position.x.abs() > 10_000_000.0
                || position.y.abs() > 10_000_000.0
        })
    {
        return Err("Topology view contains an invalid position, pan, or zoom value".to_string());
    }
    let updated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let positions_json = serde_json::to_string(&positions).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO topology_views(layout,positions_json,zoom,pan_x,pan_y,updated_at)
         VALUES (?1,?2,?3,?4,?5,?6)
         ON CONFLICT(layout) DO UPDATE SET positions_json=excluded.positions_json,
             zoom=excluded.zoom,pan_x=excluded.pan_x,pan_y=excluded.pan_y,updated_at=excluded.updated_at",
        params![layout, positions_json, zoom, pan_x, pan_y, updated_at],
    )
    .map_err(|e| e.to_string())?;
    Ok(TopologyViewState {
        layout: layout.to_string(),
        positions,
        zoom,
        pan_x,
        pan_y,
        updated_at,
    })
}

pub fn get_assets(conn: &Connection) -> AppResult<Vec<Asset>> {
    query_vec(conn,
        "SELECT a.id,a.network_id,n.name,a.name,a.ip_address,a.mac_address,a.asset_type,a.os,a.user_name,
                a.suspicious,a.compromise_status,a.investigation_status,a.properties,a.scan_results,a.quick_note,a.site_id,a.owner,a.operator,a.origin,a.last_observed,a.created_at
         FROM assets a LEFT JOIN networks n ON n.id=a.network_id ORDER BY a.name", [], map_asset)
}

pub fn get_assets_by_network(conn: &Connection, network_id: &str) -> AppResult<Vec<Asset>> {
    query_vec(conn,
        "SELECT DISTINCT a.id,a.network_id,pn.name,a.name,a.ip_address,a.mac_address,a.asset_type,a.os,a.user_name,
                a.suspicious,a.compromise_status,a.investigation_status,a.properties,a.scan_results,a.quick_note,a.site_id,a.owner,a.operator,a.origin,a.last_observed,a.created_at
         FROM assets a LEFT JOIN networks pn ON pn.id=a.network_id
         LEFT JOIN network_interfaces ni ON ni.asset_id=a.id
         WHERE a.network_id=?1 OR ni.network_id=?1 ORDER BY a.name", params![network_id], map_asset)
}

fn map_asset(row: &rusqlite::Row<'_>) -> rusqlite::Result<Asset> {
    Ok(Asset {
        id: row.get(0)?,
        network_id: row.get(1)?,
        network_name: row.get(2)?,
        name: row.get(3)?,
        ip_address: row.get(4)?,
        mac_address: row.get(5)?,
        asset_type: row.get(6)?,
        os: row.get(7)?,
        user_name: row.get(8)?,
        suspicious: row.get::<_, i64>(9)? != 0,
        compromise_status: row.get(10)?,
        investigation_status: row.get(11)?,
        properties: row.get(12)?,
        scan_results: row.get(13)?,
        quick_note: row.get(14)?,
        site_id: row.get(15)?,
        owner: row.get(16)?,
        operator: row.get(17)?,
        origin: row.get(18)?,
        last_observed: row.get(19)?,
        created_at: row.get(20)?,
    })
}

pub fn get_network_interfaces(
    conn: &Connection,
    asset_id: Option<&str>,
) -> AppResult<Vec<NetworkInterface>> {
    if let Some(asset_id) = asset_id {
        query_vec(conn,
            "SELECT ni.id,ni.asset_id,ni.name,ni.ip_address,ni.mac_address,ni.network_id,n.name,ni.is_primary
             FROM network_interfaces ni LEFT JOIN networks n ON n.id=ni.network_id WHERE ni.asset_id=?1
             ORDER BY ni.is_primary DESC,ni.name", params![asset_id], map_interface)
    } else {
        query_vec(conn,
            "SELECT ni.id,ni.asset_id,ni.name,ni.ip_address,ni.mac_address,ni.network_id,n.name,ni.is_primary
             FROM network_interfaces ni LEFT JOIN networks n ON n.id=ni.network_id
             ORDER BY ni.asset_id,ni.is_primary DESC,ni.name", [], map_interface)
    }
}

fn map_interface(row: &rusqlite::Row<'_>) -> rusqlite::Result<NetworkInterface> {
    Ok(NetworkInterface {
        id: row.get(0)?,
        asset_id: row.get(1)?,
        name: row.get(2)?,
        ip_address: row.get(3)?,
        mac_address: row.get(4)?,
        network_id: row.get(5)?,
        network_name: row.get(6)?,
        is_primary: row.get::<_, i64>(7)? != 0,
    })
}

pub fn get_timeline_events(conn: &Connection) -> AppResult<Vec<TimelineEvent>> {
    query_vec(conn,
        "SELECT e.id,e.asset_id,a.name,e.timestamp,e.raw_timestamp,e.raw_timezone,
                e.server_timestamp_utc,e.correct_timestamp_raw,e.correct_timezone,
                e.clock_profile_id,cp.name,e.clock_offset_ms,e.time_precision,e.correct_time_precision,
                e.event_type,e.description,e.severity,e.source,e.mitre_tactic,e.mitre_technique,e.created_at,
                e.source_ref
         FROM timeline_events e
         LEFT JOIN assets a ON a.id=e.asset_id
         LEFT JOIN clock_profiles cp ON cp.id=e.clock_profile_id
         ORDER BY CASE WHEN e.timestamp='' THEN 1 ELSE 0 END,e.timestamp,e.created_at", [], map_timeline)
}

/// JSON kept in a TEXT column. Text that is not JSON is preserved as a string
/// rather than dropped, so a hand-edited value never disappears silently.
fn json_text_value(text: Option<String>) -> Option<Value> {
    text.filter(|value| !value.trim().is_empty())
        .map(|value| serde_json::from_str(&value).unwrap_or(Value::String(value)))
}

fn json_value_text(value: &Option<Value>) -> AppResult<Option<String>> {
    value
        .as_ref()
        .filter(|value| !value.is_null())
        .map(|value| serde_json::to_string(value).map_err(|e| e.to_string()))
        .transpose()
}

fn map_timeline(row: &rusqlite::Row<'_>) -> rusqlite::Result<TimelineEvent> {
    Ok(TimelineEvent {
        id: row.get(0)?,
        asset_id: row.get(1)?,
        asset_name: row.get(2)?,
        timestamp: row.get(3)?,
        raw_timestamp: row.get(4)?,
        raw_timezone: row.get(5)?,
        server_timestamp_utc: row.get(6)?,
        correct_timestamp_raw: row.get(7)?,
        correct_timezone: row.get(8)?,
        clock_profile_id: row.get(9)?,
        clock_profile_name: row.get(10)?,
        clock_offset_ms: row.get(11)?,
        time_precision: row.get(12)?,
        correct_time_precision: row.get(13)?,
        event_type: row.get(14)?,
        description: row.get(15)?,
        severity: row.get(16)?,
        source: row.get(17)?,
        mitre_tactic: row.get(18)?,
        mitre_technique: row.get(19)?,
        created_at: row.get(20)?,
        source_ref: json_text_value(row.get(21)?),
    })
}

pub fn get_clock_profiles(conn: &Connection) -> AppResult<Vec<ClockProfile>> {
    query_vec(
        conn,
        "SELECT id,name,description,server_reference_raw,server_timezone,server_reference_utc,
                correct_reference_raw,correct_timezone,correct_reference_utc,offset_ms,created_at,updated_at
         FROM clock_profiles ORDER BY name",
        [],
        map_clock_profile,
    )
}

fn map_clock_profile(row: &rusqlite::Row<'_>) -> rusqlite::Result<ClockProfile> {
    Ok(ClockProfile {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        server_reference_raw: row.get(3)?,
        server_timezone: row.get(4)?,
        server_reference_utc: row.get(5)?,
        correct_reference_raw: row.get(6)?,
        correct_timezone: row.get(7)?,
        correct_reference_utc: row.get(8)?,
        offset_ms: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

pub fn get_notes(conn: &Connection) -> AppResult<Vec<Note>> {
    query_vec(
        conn,
        "SELECT id,title,content,created_at,updated_at FROM notes ORDER BY updated_at DESC",
        [],
        |row| {
            Ok(Note {
                id: row.get(0)?,
                title: row.get(1)?,
                content: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        },
    )
}

pub fn get_iocs(conn: &Connection) -> AppResult<Vec<Ioc>> {
    query_vec(conn, "SELECT id,ioc_type,value,description,threat_level,first_seen,last_seen,created_at FROM iocs ORDER BY created_at DESC", [], |row| {
        Ok(Ioc { id: row.get(0)?, ioc_type: row.get(1)?, value: row.get(2)?, description: row.get(3)?, threat_level: row.get(4)?, first_seen: row.get(5)?, last_seen: row.get(6)?, created_at: row.get(7)? })
    })
}

const CAPTURE_SELECT: &str = "SELECT id,content,source,status,captured_by,team,links,resolution,created_at,updated_at FROM captures";

fn map_capture(row: &rusqlite::Row<'_>) -> rusqlite::Result<Capture> {
    let links: String = row.get(6)?;
    Ok(Capture {
        id: row.get(0)?,
        content: row.get(1)?,
        source: row.get(2)?,
        status: row.get(3)?,
        captured_by: row.get(4)?,
        team: row.get(5)?,
        links: serde_json::from_str(&links).unwrap_or_default(),
        resolution: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

/// Open captures first, newest first within each status.
pub fn get_captures(conn: &Connection) -> AppResult<Vec<Capture>> {
    query_vec(
        conn,
        &format!(
            "{CAPTURE_SELECT} ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, created_at DESC"
        ),
        [],
        map_capture,
    )
}

pub fn get_capture(conn: &Connection, id: &str) -> AppResult<Option<Capture>> {
    get_row_optional(
        conn,
        &format!("{CAPTURE_SELECT} WHERE id=?1"),
        id,
        map_capture,
    )
}

fn capture_links_text(links: &[CaptureLink]) -> AppResult<String> {
    serde_json::to_string(links).map_err(|e| e.to_string())
}

fn normalized_capture_links(links: Vec<CaptureLink>) -> Vec<CaptureLink> {
    let mut result: Vec<CaptureLink> = Vec::new();
    for link in links {
        let link = CaptureLink {
            entity_type: link.entity_type.trim().to_string(),
            entity_id: link.entity_id.trim().to_string(),
            title: link.title.trim().chars().take(200).collect(),
        };
        if !result
            .iter()
            .any(|item| item.entity_type == link.entity_type && item.entity_id == link.entity_id)
        {
            result.push(link);
        }
    }
    result
}

/// Record what was learned exactly as written. Only the text is required;
/// the capturing expert and their team come from the session.
pub fn create_capture(
    conn: &mut Connection,
    actor: &ActorIdentity,
    content: &str,
    source: &str,
) -> AppResult<Capture> {
    let now = Utc::now().to_rfc3339();
    let item = Capture {
        id: Uuid::new_v4().to_string(),
        content: content.trim().to_string(),
        source: source.trim().to_string(),
        status: "open".to_string(),
        captured_by: actor.name.clone(),
        team: actor.team.clone(),
        links: Vec::new(),
        resolution: String::new(),
        created_at: now.clone(),
        updated_at: now,
    };
    validate_capture_model(&item)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO captures(id,content,source,status,captured_by,team,links,resolution,created_at,updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            item.id,
            item.content,
            item.source,
            item.status,
            item.captured_by,
            item.team,
            capture_links_text(&item.links)?,
            item.resolution,
            item.created_at,
            item.updated_at
        ],
    )
    .map_err(|e| e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        "Captured information",
        vec![single_change(
            "capture",
            &item.id,
            "create",
            None,
            Some(to_value(&item)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

#[allow(clippy::too_many_arguments)]
pub fn update_capture(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    content: &str,
    source: &str,
    status: &str,
    links: Vec<CaptureLink>,
    resolution: &str,
) -> AppResult<Capture> {
    let before = require_existing(get_capture(conn, id)?, "Capture")?;
    let after = Capture {
        content: content.trim().to_string(),
        source: source.trim().to_string(),
        status: status.trim().to_string(),
        links: normalized_capture_links(links),
        resolution: resolution.trim().to_string(),
        updated_at: Utc::now().to_rfc3339(),
        ..before.clone()
    };
    validate_capture_model(&after)?;
    let message = if after.status == before.status {
        "Updated capture"
    } else {
        match after.status.as_str() {
            "processed" => "Processed capture",
            "dismissed" => "Dismissed capture",
            _ => "Reopened capture",
        }
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let changed = tx
        .execute(
            "UPDATE captures SET content=?1,source=?2,status=?3,links=?4,resolution=?5,updated_at=?6 WHERE id=?7",
            params![
                after.content,
                after.source,
                after.status,
                capture_links_text(&after.links)?,
                after.resolution,
                after.updated_at,
                id
            ],
        )
        .map_err(|e| e.to_string())?;
    if changed == 0 {
        return Err("Capture was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        message,
        vec![single_change(
            "capture",
            id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

pub fn delete_capture(conn: &mut Connection, actor: &ActorIdentity, id: &str) -> AppResult<()> {
    let before = require_existing(get_entity_json(conn, "capture", id)?, "Capture")?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx
        .execute("DELETE FROM captures WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Capture was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Deleted capture",
        vec![single_change("capture", id, "delete", Some(before), None)],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())
}

// ---- drafts -----------------------------------------------------------------
// Unsaved form input, kept per expert so it survives a restart or a crash.
// Working state, not evidence: no history, no revision bump on the server,
// and never part of a snapshot or change bundle.

/// Longest draft key accepted; keys are UI identifiers such as `assets.form`.
const MAX_DRAFT_KEY_CHARS: usize = 200;
/// Largest single draft persisted. Bigger values (a pasted multi-megabyte log)
/// stay in the window's memory only.
pub const MAX_DRAFT_BYTES: usize = 256 * 1024;
const MAX_DRAFTS_PER_SAVE: usize = 500;

pub fn load_drafts(conn: &Connection, owner: &str) -> AppResult<serde_json::Map<String, Value>> {
    let rows = query_vec(
        conn,
        "SELECT draft_key,value_json FROM drafts WHERE owner=?1 ORDER BY draft_key",
        params![owner.trim()],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;
    let mut drafts = serde_json::Map::new();
    for (key, json) in rows {
        if let Ok(value) = serde_json::from_str::<Value>(&json) {
            drafts.insert(key, value);
        }
    }
    Ok(drafts)
}

/// Upsert each draft; a `null` value deletes it. One transaction per call.
pub fn save_drafts(
    conn: &mut Connection,
    owner: &str,
    drafts: &serde_json::Map<String, Value>,
) -> AppResult<usize> {
    let owner = owner.trim();
    validate_required("Draft owner", owner)?;
    if drafts.len() > MAX_DRAFTS_PER_SAVE {
        return Err(format!("Save at most {MAX_DRAFTS_PER_SAVE} drafts at once"));
    }
    let now = Utc::now().to_rfc3339();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    for (key, value) in drafts {
        if key.trim().is_empty() || key.chars().count() > MAX_DRAFT_KEY_CHARS {
            return Err("Draft keys must be 1 to 200 characters".to_string());
        }
        if value.is_null() {
            tx.execute(
                "DELETE FROM drafts WHERE owner=?1 AND draft_key=?2",
                params![owner, key],
            )
            .map_err(|e| e.to_string())?;
            continue;
        }
        let json = serde_json::to_string(value).map_err(|e| e.to_string())?;
        if json.len() > MAX_DRAFT_BYTES {
            return Err(format!(
                "Draft '{key}' is larger than {} KiB and stays unsaved",
                MAX_DRAFT_BYTES / 1024
            ));
        }
        tx.execute(
            "INSERT INTO drafts(owner,draft_key,value_json,updated_at) VALUES (?1,?2,?3,?4)
             ON CONFLICT(owner,draft_key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",
            params![owner, key, json, now],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(drafts.len())
}

// ---- case-wide search -------------------------------------------------------

/// One case-wide search result. `entity_type`/`entity_id` say where to go;
/// `field` and `detail` say why it matched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SearchHit {
    pub entity_type: String,
    pub entity_id: String,
    pub title: String,
    pub field: String,
    pub detail: String,
}

/// A searchable record set. Every identifier is a compile-time constant, so
/// the generated SQL never contains user input; the query is a bound pattern.
struct SearchSource {
    entity_type: &'static str,
    from: &'static str,
    id_expr: &'static str,
    title_expr: &'static str,
    fields: &'static [(&'static str, &'static str)],
}

const SEARCH_SOURCES: &[SearchSource] = &[
    SearchSource {
        entity_type: "asset",
        from: "assets",
        id_expr: "id",
        title_expr: "name",
        fields: &[
            ("name", "name"),
            ("IP", "ip_address"),
            ("MAC", "mac_address"),
            ("OS", "os"),
            ("user / owner", "user_name"),
            ("owner", "owner"),
            ("operated by", "operator"),
            ("quick note", "quick_note"),
            ("details", "properties"),
        ],
    },
    SearchSource {
        entity_type: "asset",
        from: "network_interfaces ni JOIN assets a ON a.id=ni.asset_id",
        id_expr: "a.id",
        title_expr: "a.name",
        fields: &[
            ("interface IP", "ni.ip_address"),
            ("interface MAC", "ni.mac_address"),
            ("interface", "ni.name"),
        ],
    },
    SearchSource {
        entity_type: "network",
        from: "networks",
        id_expr: "id",
        title_expr: "name",
        fields: &[
            ("name", "name"),
            ("subnet", "subnet"),
            ("VLAN", "vlan_id"),
            ("description", "description"),
            ("owner", "owner"),
            ("operated by", "operator"),
            ("quick note", "quick_note"),
        ],
    },
    SearchSource {
        entity_type: "site",
        from: "sites",
        id_expr: "id",
        title_expr: "name",
        fields: &[
            ("name", "name"),
            ("location", "location"),
            ("description", "description"),
        ],
    },
    SearchSource {
        entity_type: "firewall",
        from: "firewalls",
        id_expr: "id",
        title_expr: "name",
        fields: &[
            ("name", "name"),
            ("vendor", "vendor"),
            ("model", "model"),
            ("quick note", "quick_note"),
            ("configuration", "config_text"),
        ],
    },
    SearchSource {
        entity_type: "firewall",
        from: "firewall_interfaces fi JOIN firewalls f ON f.id=fi.firewall_id",
        id_expr: "f.id",
        title_expr: "f.name",
        fields: &[
            ("interface IP", "fi.ip_addresses"),
            ("interface MAC", "fi.mac_address"),
            ("interface", "fi.name"),
        ],
    },
    SearchSource {
        entity_type: "ioc",
        from: "iocs",
        id_expr: "id",
        title_expr: "value",
        fields: &[("value", "value"), ("description", "description")],
    },
    SearchSource {
        entity_type: "timeline_event",
        from: "timeline_events",
        id_expr: "id",
        title_expr: "description",
        fields: &[
            ("description", "description"),
            ("source", "source"),
            ("server time", "raw_timestamp"),
            ("MITRE technique", "mitre_technique"),
            ("MITRE tactic", "mitre_tactic"),
            ("source record", "source_ref"),
        ],
    },
    SearchSource {
        entity_type: "note",
        from: "notes",
        id_expr: "id",
        title_expr: "title",
        fields: &[("title", "title"), ("content", "content")],
    },
    SearchSource {
        entity_type: "capture",
        from: "captures",
        id_expr: "id",
        title_expr: "content",
        fields: &[("text", "content"), ("source", "source")],
    },
    SearchSource {
        entity_type: "attack_edge",
        from: "attack_edges",
        id_expr: "id",
        title_expr: "title",
        fields: &[("title", "title"), ("description", "description")],
    },
];

const SEARCH_MIN_CHARS: usize = 2;
const SEARCH_PER_SOURCE: usize = 25;

fn like_pattern(text: &str) -> String {
    let escaped = text
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

/// MAC addresses are written with ':' or '-' separators; search both forms.
fn search_variants(query: &str) -> Vec<String> {
    let mut variants = vec![query.to_lowercase()];
    let separated_hex = query
        .chars()
        .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '-'))
        && query.contains([':', '-']);
    if separated_hex {
        for (from, to) in [(':', "-"), ('-', ":")] {
            let variant = query.to_lowercase().replace(from, to);
            if !variants.contains(&variant) {
                variants.push(variant);
            }
        }
    }
    variants
}

/// Character offset of `needle` (already lower-cased) in `haystack`.
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let lower = haystack.to_lowercase();
    let byte = lower.find(needle)?;
    Some(lower[..byte].chars().count())
}

fn search_snippet(value: &str, position: usize, needle_chars: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    let start = position.saturating_sub(30).min(chars.len());
    let end = (position + needle_chars + 60).min(chars.len()).max(start);
    let mut text = chars[start..end]
        .iter()
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if start > 0 {
        text.insert(0, '…');
    }
    if end < chars.len() {
        text.push('…');
    }
    text
}

fn search_title(value: &str) -> String {
    let line = value
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("");
    let short: String = line.chars().take(90).collect();
    if line.chars().count() > 90 {
        format!("{short}…")
    } else {
        short
    }
}

/// Find hostnames, IPs, MACs, hashes, IOC values, and text anywhere in the
/// case. Exact field matches rank first, then prefix matches, then the rest.
pub fn search_case(conn: &Connection, query: &str, limit: usize) -> AppResult<Vec<SearchHit>> {
    let query: String = query.trim().chars().take(200).collect();
    if query.chars().count() < SEARCH_MIN_CHARS {
        return Ok(Vec::new());
    }
    let exact = query.to_lowercase();
    let needles = search_variants(&query);
    let limit = limit.clamp(1, 200);
    let mut scored: Vec<(u8, usize, SearchHit)> = Vec::new();
    for (source_index, source) in SEARCH_SOURCES.iter().enumerate() {
        let columns: Vec<&str> = source.fields.iter().map(|(_, column)| *column).collect();
        let condition = columns
            .iter()
            .map(|column| format!("{column} LIKE ?1 ESCAPE '\\'"))
            .collect::<Vec<_>>()
            .join(" OR ");
        let sql = format!(
            "SELECT {},{},{} FROM {} WHERE {} LIMIT {}",
            source.id_expr,
            source.title_expr,
            columns.join(","),
            source.from,
            condition,
            SEARCH_PER_SOURCE
        );
        let mut statement = conn.prepare(&sql).map_err(|e| e.to_string())?;
        for needle in &needles {
            let rows = statement
                .query_map(params![like_pattern(needle)], |row| {
                    let id: String = row.get(0)?;
                    let title: Option<String> = row.get(1)?;
                    let mut values = Vec::with_capacity(columns.len());
                    for index in 0..columns.len() {
                        values.push(row.get::<_, Option<String>>(index + 2)?);
                    }
                    Ok((id, title.unwrap_or_default(), values))
                })
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            for (id, title, values) in rows {
                if scored
                    .iter()
                    .any(|(_, _, hit)| hit.entity_type == source.entity_type && hit.entity_id == id)
                {
                    continue;
                }
                let matched =
                    source
                        .fields
                        .iter()
                        .zip(values.iter())
                        .find_map(|((label, _), value)| {
                            let value = value.as_deref()?;
                            let (position, needle_chars) = needles.iter().find_map(|needle| {
                                find_ci(value, needle).map(|at| (at, needle.chars().count()))
                            })?;
                            let lower = value.trim().to_lowercase();
                            let score = if lower == exact {
                                0
                            } else if lower.starts_with(&exact) {
                                1
                            } else {
                                2
                            };
                            Some((
                                score,
                                (*label).to_string(),
                                search_snippet(value, position, needle_chars),
                            ))
                        });
                let Some((score, field, detail)) = matched else {
                    continue;
                };
                scored.push((
                    score,
                    source_index,
                    SearchHit {
                        entity_type: source.entity_type.to_string(),
                        entity_id: id,
                        title: search_title(&title),
                        field,
                        detail,
                    },
                ));
            }
        }
    }
    scored.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    Ok(scored
        .into_iter()
        .take(limit)
        .map(|(_, _, hit)| hit)
        .collect())
}

pub fn get_firewalls(conn: &Connection) -> AppResult<Vec<Firewall>> {
    query_vec(
        conn,
        "SELECT f.id,f.network_id,n.name,f.name,f.vendor,f.model,f.rules,f.config_text,f.quick_note,f.created_at
         FROM firewalls f LEFT JOIN networks n ON n.id=f.network_id ORDER BY f.name",
        [],
        |row| {
            Ok(Firewall {
                id: row.get(0)?,
                network_id: row.get(1)?,
                network_name: row.get(2)?,
                name: row.get(3)?,
                vendor: row.get(4)?,
                model: row.get(5)?,
                rules: row.get(6)?,
                config_text: row.get(7)?,
                quick_note: row.get(8)?,
                created_at: row.get(9)?,
            })
        },
    )
}

pub fn get_firewall_interfaces(
    conn: &Connection,
    firewall_id: Option<&str>,
) -> AppResult<Vec<FirewallInterface>> {
    let sql = "SELECT fi.id,fi.firewall_id,fi.name,fi.ip_addresses,fi.mac_address,
                      fi.network_id,n.name,fi.vlan_id,fi.role,fi.is_primary,fi.description
               FROM firewall_interfaces fi LEFT JOIN networks n ON n.id=fi.network_id";
    let mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<FirewallInterface> {
        let addresses: String = row.get(3)?;
        Ok(FirewallInterface {
            id: row.get(0)?,
            firewall_id: row.get(1)?,
            name: row.get(2)?,
            ip_addresses: serde_json::from_str(&addresses).unwrap_or_default(),
            mac_address: row.get(4)?,
            network_id: row.get(5)?,
            network_name: row.get(6)?,
            vlan_id: row.get(7)?,
            role: row.get(8)?,
            is_primary: row.get::<_, i64>(9)? != 0,
            description: row.get(10)?,
        })
    };
    if let Some(id) = firewall_id {
        query_vec(
            conn,
            &format!("{sql} WHERE fi.firewall_id=?1 ORDER BY fi.is_primary DESC,fi.name"),
            params![id],
            mapper,
        )
    } else {
        query_vec(
            conn,
            &format!("{sql} ORDER BY fi.firewall_id,fi.is_primary DESC,fi.name"),
            [],
            mapper,
        )
    }
}

pub fn get_firewall_nat_rules(
    conn: &Connection,
    firewall_id: Option<&str>,
) -> AppResult<Vec<FirewallNatRule>> {
    let sql = "SELECT id,firewall_id,name,nat_type,enabled,protocol,source_cidr,
                      original_destination,original_port,translated_source,
                      translated_destination,translated_port,inbound_interface_id,
                      outbound_interface_id,description,created_at
               FROM firewall_nat_rules";
    let mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<FirewallNatRule> {
        Ok(FirewallNatRule {
            id: row.get(0)?,
            firewall_id: row.get(1)?,
            name: row.get(2)?,
            nat_type: row.get(3)?,
            enabled: row.get::<_, i64>(4)? != 0,
            protocol: row.get(5)?,
            source_cidr: row.get(6)?,
            original_destination: row.get(7)?,
            original_port: row.get(8)?,
            translated_source: row.get(9)?,
            translated_destination: row.get(10)?,
            translated_port: row.get(11)?,
            inbound_interface_id: row.get(12)?,
            outbound_interface_id: row.get(13)?,
            description: row.get(14)?,
            created_at: row.get(15)?,
        })
    };
    if let Some(id) = firewall_id {
        query_vec(
            conn,
            &format!("{sql} WHERE firewall_id=?1 ORDER BY name"),
            params![id],
            mapper,
        )
    } else {
        query_vec(
            conn,
            &format!("{sql} ORDER BY firewall_id,name"),
            [],
            mapper,
        )
    }
}

pub fn get_network_connections(conn: &Connection) -> AppResult<Vec<NetworkConnection>> {
    query_vec(conn,
        "SELECT c.id,c.source_network_id,s.name,c.target_network_id,t.name,c.connection_type,c.description,c.device_name
         FROM network_connections c JOIN networks s ON s.id=c.source_network_id JOIN networks t ON t.id=c.target_network_id
         ORDER BY s.name,t.name", [], |row| {
        Ok(NetworkConnection { id: row.get(0)?, source_network_id: row.get(1)?, source_network_name: row.get(2)?,
            target_network_id: row.get(3)?, target_network_name: row.get(4)?, connection_type: row.get(5)?,
            description: row.get(6)?, device_name: row.get(7)? })
    })
}

const SIGHTING_SELECT: &str = "SELECT s.id,s.ioc_id,i.value,i.ioc_type,i.threat_level,
        CASE WHEN s.asset_id IS NOT NULL THEN 'asset'
             WHEN s.network_id IS NOT NULL THEN 'network' ELSE 'firewall' END,
        COALESCE(s.asset_id,s.network_id,s.firewall_id),
        COALESCE(a.name,n.name,f.name),
        s.sighted_at,s.location,s.note,s.created_at
    FROM ioc_sightings s
    JOIN iocs i ON i.id=s.ioc_id
    LEFT JOIN assets a ON a.id=s.asset_id
    LEFT JOIN networks n ON n.id=s.network_id
    LEFT JOIN firewalls f ON f.id=s.firewall_id";

fn map_sighting(row: &rusqlite::Row<'_>) -> rusqlite::Result<IocSighting> {
    Ok(IocSighting {
        id: row.get(0)?,
        ioc_id: row.get(1)?,
        ioc_value: row.get(2)?,
        ioc_type: row.get(3)?,
        threat_level: row.get(4)?,
        entity_kind: row.get(5)?,
        entity_id: row.get(6)?,
        entity_name: row.get(7)?,
        sighted_at: row.get(8)?,
        location: row.get(9)?,
        note: row.get(10)?,
        created_at: row.get(11)?,
    })
}

pub fn get_ioc_sightings(
    conn: &Connection,
    ioc_id: Option<&str>,
    entity_kind: Option<&str>,
    entity_id: Option<&str>,
) -> AppResult<Vec<IocSighting>> {
    if let Some(kind) = entity_kind {
        validate_enum("entity kind", kind, SIGHTING_ENTITY_KINDS)?;
    }
    let sql =
        format!("{SIGHTING_SELECT} ORDER BY s.sighted_at IS NULL, s.sighted_at, s.created_at");
    let rows = query_vec(conn, &sql, [], map_sighting)?;
    Ok(rows
        .into_iter()
        .filter(|row| ioc_id.map(|id| row.ioc_id == id).unwrap_or(true))
        .filter(|row| {
            entity_kind
                .map(|kind| row.entity_kind == kind)
                .unwrap_or(true)
        })
        .filter(|row| entity_id.map(|id| row.entity_id == id).unwrap_or(true))
        .collect())
}

pub fn get_infection_summary(conn: &Connection) -> AppResult<InfectionSummary> {
    let sightings = get_ioc_sightings(conn, None, None, None)?;
    let mut entities: Vec<InfectionEntitySummary> = Vec::new();
    let mut iocs: Vec<InfectionIocSummary> = Vec::new();
    for sighting in &sightings {
        let entity_name = sighting.entity_name.clone().unwrap_or_default();
        let threat = sighting.threat_level.as_deref().unwrap_or("");
        match entities
            .iter_mut()
            .find(|e| e.entity_kind == sighting.entity_kind && e.entity_id == sighting.entity_id)
        {
            Some(entry) => {
                entry.sighting_count += 1;
                if threat_rank(threat) > threat_rank(&entry.max_threat_level) {
                    entry.max_threat_level = threat.to_string();
                }
                if !entry.ioc_ids.contains(&sighting.ioc_id) {
                    entry.ioc_ids.push(sighting.ioc_id.clone());
                }
            }
            None => entities.push(InfectionEntitySummary {
                entity_kind: sighting.entity_kind.clone(),
                entity_id: sighting.entity_id.clone(),
                entity_name: entity_name.clone(),
                sighting_count: 1,
                max_threat_level: threat.to_string(),
                ioc_ids: vec![sighting.ioc_id.clone()],
            }),
        }
        match iocs.iter_mut().find(|i| i.ioc_id == sighting.ioc_id) {
            Some(entry) => {
                if !entry.entities.iter().any(|e| {
                    e.entity_kind == sighting.entity_kind && e.entity_id == sighting.entity_id
                }) {
                    entry.entity_count += 1;
                    entry.entities.push(InfectionIocEntityRef {
                        entity_kind: sighting.entity_kind.clone(),
                        entity_id: sighting.entity_id.clone(),
                        entity_name,
                    });
                }
            }
            None => iocs.push(InfectionIocSummary {
                ioc_id: sighting.ioc_id.clone(),
                entity_count: 1,
                entities: vec![InfectionIocEntityRef {
                    entity_kind: sighting.entity_kind.clone(),
                    entity_id: sighting.entity_id.clone(),
                    entity_name,
                }],
            }),
        }
    }
    Ok(InfectionSummary { entities, iocs })
}

const ATTACK_EDGE_SELECT: &str = "SELECT e.id,e.source_kind,e.source_id,
        CASE e.source_kind WHEN 'asset' THEN sa.name WHEN 'network' THEN sn.name
             WHEN 'firewall' THEN sf.name ELSE e.source_id END,
        e.target_kind,e.target_id,
        CASE e.target_kind WHEN 'asset' THEN ta.name WHEN 'network' THEN tn.name ELSE tf.name END,
        e.title,e.description,e.edge_type,e.confidence,e.mitre_tactic,e.mitre_technique,
        e.occurred_at,e.timeline_event_id,te.timestamp,e.sequence,e.ioc_ids,e.created_at
    FROM attack_edges e
    LEFT JOIN assets sa ON sa.id=e.source_id AND e.source_kind='asset'
    LEFT JOIN networks sn ON sn.id=e.source_id AND e.source_kind='network'
    LEFT JOIN firewalls sf ON sf.id=e.source_id AND e.source_kind='firewall'
    LEFT JOIN assets ta ON ta.id=e.target_id AND e.target_kind='asset'
    LEFT JOIN networks tn ON tn.id=e.target_id AND e.target_kind='network'
    LEFT JOIN firewalls tf ON tf.id=e.target_id AND e.target_kind='firewall'
    LEFT JOIN timeline_events te ON te.id=e.timeline_event_id";

fn map_attack_edge(row: &rusqlite::Row<'_>) -> rusqlite::Result<AttackEdge> {
    let ioc_ids: String = row.get(17)?;
    Ok(AttackEdge {
        id: row.get(0)?,
        source_kind: row.get(1)?,
        source_id: row.get(2)?,
        source_name: row.get(3)?,
        target_kind: row.get(4)?,
        target_id: row.get(5)?,
        target_name: row.get(6)?,
        title: row.get(7)?,
        description: row.get(8)?,
        edge_type: row.get(9)?,
        confidence: row.get(10)?,
        mitre_tactic: row.get(11)?,
        mitre_technique: row.get(12)?,
        occurred_at: row.get(13)?,
        timeline_event_id: row.get(14)?,
        timeline_event_time: row.get(15)?,
        sequence: row.get(16)?,
        ioc_ids: serde_json::from_str(&ioc_ids).unwrap_or_default(),
        created_at: row.get(18)?,
    })
}

pub fn get_attack_edges(conn: &Connection) -> AppResult<Vec<AttackEdge>> {
    let sql = format!(
        "{ATTACK_EDGE_SELECT} ORDER BY e.sequence, e.occurred_at IS NULL, e.occurred_at, e.created_at"
    );
    query_vec(conn, &sql, [], map_attack_edge)
}

fn map_investigation_view(row: &rusqlite::Row<'_>) -> rusqlite::Result<InvestigationView> {
    let state_json: String = row.get(3)?;
    Ok(InvestigationView {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        state: serde_json::from_str(&state_json).unwrap_or(Value::Null),
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

pub fn get_investigation_views(conn: &Connection) -> AppResult<Vec<InvestigationViewSummary>> {
    query_vec(
        conn,
        "SELECT id,name,description,created_at,updated_at FROM investigation_views ORDER BY LOWER(name)",
        [],
        |row| {
            Ok(InvestigationViewSummary {
                id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        },
    )
}

pub fn get_investigation_view(conn: &Connection, id: &str) -> AppResult<InvestigationView> {
    require_existing(
        get_row_optional(
            conn,
            "SELECT id,name,description,state_json,created_at,updated_at FROM investigation_views WHERE id=?1",
            id,
            map_investigation_view,
        )?,
        "Investigation view",
    )
}

fn query_vec<P, F, T>(conn: &Connection, sql: &str, params: P, mapper: F) -> AppResult<Vec<T>>
where
    P: rusqlite::Params,
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params, mapper)
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(rows)
}

/// Asset types every write path accepts: the Assets form, snapshot and bundle
/// upserts, and reviewed imports. Keep in step with `BATCH_ASSET_TYPES` in
/// `src/lib/vm-inventory.ts` and the type dropdown in `AssetManager.tsx`.
const ASSET_ORIGINS: &[&str] = &["unknown", "client_inventory", "discovered"];
const RELATION_TYPES: &[&str] = &[
    "runs_on",
    "managed_by",
    "backs_up_to",
    "depends_on",
    "connects_to",
    "other",
];
/// Owner and operator are names of departments or vendors, not documents.
const MAX_PARTY_CHARS: usize = 200;

const ASSET_TYPES: &[&str] = &[
    "workstation",
    "server",
    "vm",
    "hypervisor",
    "mobile",
    "laptop",
    "router",
    "switch",
    "firewall",
    "other",
];

fn validate_required(label: &str, value: &str) -> AppResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn validate_enum(label: &str, value: &str, allowed: &[&str]) -> AppResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!("Invalid {label}: {value}"))
    }
}

fn validate_subnet(value: &str) -> AppResult<()> {
    // Layer-2 VLANs discovered from switch configurations may be real topology
    // objects before an SVI/gateway address is known. Keep the subnet empty
    // rather than inventing a misleading CIDR; routed analysis treats it as
    // unresolved until an address is supplied.
    if value.trim().is_empty() {
        return Ok(());
    }
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| "Subnet must use CIDR notation".to_string())?;
    let ip: IpAddr = address
        .parse()
        .map_err(|_| "Subnet contains an invalid IP address".to_string())?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| "Subnet prefix is invalid".to_string())?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        Err(format!("Subnet prefix must be between 0 and {max}"))
    } else {
        Ok(())
    }
}

fn validate_ip(value: &str) -> AppResult<()> {
    if value.trim().is_empty() {
        return Ok(());
    }
    value
        .parse::<IpAddr>()
        .map(|_| ())
        .map_err(|_| "IP address is invalid".to_string())
}

/// Parsed CIDR block: network address plus prefix length.
type SubnetCidr = (IpAddr, u8);

fn parse_subnet_cidr(value: &str) -> Option<SubnetCidr> {
    let (address, prefix) = value.trim().split_once('/')?;
    let ip: IpAddr = address.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        None
    } else {
        Some((ip, prefix))
    }
}

fn cidr_contains(cidr: SubnetCidr, ip: IpAddr) -> bool {
    match (cidr.0, ip) {
        (IpAddr::V4(net), IpAddr::V4(addr)) => {
            let prefix = u32::from(cidr.1);
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(net) & mask) == (u32::from(addr) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(addr)) => {
            let prefix = u32::from(cidr.1);
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(net) & mask) == (u128::from(addr) & mask)
        }
        _ => false,
    }
}

/// Result of placing one address among the recorded subnets.
enum SubnetMatch<'a> {
    None,
    /// Exactly one network is the most specific container.
    Unique(&'a Network),
    /// Two or more equally specific networks contain the address — isolated
    /// sites or departments reusing the same private range. Choosing one would
    /// silently merge them, so the endpoint is left for the investigator.
    Ambiguous,
}

fn match_network_for_ip<'a>(networks: &'a [Network], ip_text: &str) -> SubnetMatch<'a> {
    let Ok(ip) = ip_text.trim().parse::<IpAddr>() else {
        return SubnetMatch::None;
    };
    let mut best_prefix: Option<u8> = None;
    let mut best: Vec<&Network> = Vec::new();
    for network in networks {
        let Some(cidr) = parse_subnet_cidr(&network.subnet) else {
            continue;
        };
        if !cidr_contains(cidr, ip) {
            continue;
        }
        match best_prefix {
            Some(prefix) if cidr.1 < prefix => {}
            Some(prefix) if cidr.1 == prefix => best.push(network),
            _ => {
                best_prefix = Some(cidr.1);
                best = vec![network];
            }
        }
    }
    match best.as_slice() {
        [] => SubnetMatch::None,
        [only] => SubnetMatch::Unique(only),
        _ => SubnetMatch::Ambiguous,
    }
}

/// The network whose subnet most specifically contains `ip_text`. Equally
/// specific candidates are ambiguous and yield no network, so the endpoint
/// stays unassigned instead of joining whichever was recorded first. An
/// explicit assignment always wins over this.
fn best_network_for_ip(
    conn: &Connection,
    ip_text: &str,
) -> AppResult<Option<(String, Option<String>)>> {
    Ok(match match_network_for_ip(&get_networks(conn)?, ip_text) {
        SubnetMatch::Unique(network) => Some((network.id.clone(), Some(network.name.clone()))),
        SubnetMatch::None | SubnetMatch::Ambiguous => None,
    })
}

fn validate_mac(value: Option<&str>) -> AppResult<()> {
    let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
        return Ok(());
    };
    let normalized = value.replace('-', ":");
    let parts: Vec<&str> = normalized.split(':').collect();
    if parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        Ok(())
    } else {
        Err("MAC address must contain six hexadecimal octets".to_string())
    }
}

fn validate_optional_json(label: &str, value: Option<&str>) -> AppResult<()> {
    if let Some(value) = value.filter(|v| !v.trim().is_empty()) {
        serde_json::from_str::<Value>(value)
            .map_err(|e| format!("{label} must be valid JSON: {e}"))?;
    }
    Ok(())
}

fn validate_timestamp(label: &str, value: &str) -> AppResult<()> {
    normalize_timestamp(label, value).map(|_| ())
}

fn normalize_timestamp(label: &str, value: &str) -> AppResult<String> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|date| format_utc(date.with_timezone(&Utc)))
        .map_err(|_| format!("{label} must be an RFC 3339 timestamp"))
}

fn format_utc(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn epoch_datetime(milliseconds: i64) -> AppResult<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp_millis(milliseconds)
        .ok_or_else(|| "Timestamp is outside the supported date range".to_string())
}

fn parse_epoch(value: &str) -> Option<AppResult<(DateTime<Utc>, String)>> {
    if value.contains('.') {
        let seconds = value.parse::<f64>().ok()?;
        if !seconds.is_finite() {
            return Some(Err("Unix epoch value is not finite".to_string()));
        }
        let milliseconds = seconds * 1_000.0;
        if milliseconds < i64::MIN as f64 || milliseconds > i64::MAX as f64 {
            return Some(Err(
                "Unix epoch value is outside the supported range".to_string()
            ));
        }
        return Some(epoch_datetime(milliseconds.round() as i64).map(|v| (v, "epoch".into())));
    }
    let raw = value.parse::<i128>().ok()?;
    let absolute = raw.unsigned_abs();
    let milliseconds = if absolute >= 100_000_000_000_000_000 {
        raw / 1_000_000 // nanoseconds
    } else if absolute >= 100_000_000_000_000 {
        raw / 1_000 // microseconds
    } else if absolute >= 100_000_000_000 {
        raw // milliseconds
    } else {
        raw.checked_mul(1_000)? // seconds
    };
    Some(
        i64::try_from(milliseconds)
            .map_err(|_| "Unix epoch value is outside the supported range".to_string())
            .and_then(epoch_datetime)
            .map(|v| (v, "epoch".into())),
    )
}

fn parse_naive_timestamp(value: &str) -> AppResult<(NaiveDateTime, String)> {
    let split_at = value.find(|c| c == 'T' || c == ' ');
    let (date_text, time_text) = match split_at {
        Some(index) => (&value[..index], value[index + 1..].trim()),
        None => (value, ""),
    };
    let date_parts: Vec<&str> = date_text.split('-').collect();
    if date_parts.len() != 3 {
        return Err("Use DD-MM-YYYY, ISO/RFC 3339, or a Unix epoch value".to_string());
    }
    let (year, month, day) = if date_parts[0].len() == 4 {
        (
            date_parts[0].parse::<i32>(),
            date_parts[1].parse::<u32>(),
            date_parts[2].parse::<u32>(),
        )
    } else {
        (
            date_parts[2].parse::<i32>(),
            date_parts[1].parse::<u32>(),
            date_parts[0].parse::<u32>(),
        )
    };
    let date = NaiveDate::from_ymd_opt(
        year.map_err(|_| "Invalid year")?,
        month.map_err(|_| "Invalid month")?,
        day.map_err(|_| "Invalid day")?,
    )
    .ok_or_else(|| "Invalid calendar date".to_string())?;
    if time_text.is_empty() {
        return Ok((date.and_hms_milli_opt(0, 0, 0, 0).unwrap(), "date".into()));
    }
    let time_parts: Vec<&str> = time_text.split(':').collect();
    if time_parts.len() > 3 || time_parts.is_empty() {
        return Err("Time must use 24-hour HH, HH:mm, HH:mm:ss, or HH:mm:ss.SSS".into());
    }
    let hour = time_parts[0].parse::<u32>().map_err(|_| "Invalid hour")?;
    let minute = time_parts
        .get(1)
        .map(|v| v.parse::<u32>().map_err(|_| "Invalid minute"))
        .transpose()?
        .unwrap_or(0);
    let (second, millisecond, precision) = if let Some(value) = time_parts.get(2) {
        let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
        let second = whole.parse::<u32>().map_err(|_| "Invalid second")?;
        let millisecond = if fraction.is_empty() {
            0
        } else {
            if fraction.len() > 9 || !fraction.chars().all(|c| c.is_ascii_digit()) {
                return Err("Fractional seconds must contain 1 to 9 digits".into());
            }
            let padded = format!("{fraction:0<3}");
            padded[..3]
                .parse::<u32>()
                .map_err(|_| "Invalid milliseconds")?
        };
        (
            second,
            millisecond,
            if fraction.is_empty() {
                "second"
            } else {
                "millisecond"
            },
        )
    } else {
        (
            0,
            0,
            if time_parts.len() == 1 {
                "hour"
            } else {
                "minute"
            },
        )
    };
    let datetime = date
        .and_hms_milli_opt(hour, minute, second, millisecond)
        .ok_or_else(|| "Invalid 24-hour time".to_string())?;
    Ok((datetime, precision.into()))
}

pub fn fixed_offset(value: &str) -> Option<AppResult<FixedOffset>> {
    let trimmed = value.trim();
    let without_prefix = trimmed
        .strip_prefix("UTC")
        .or_else(|| trimmed.strip_prefix("utc"))
        .unwrap_or(trimmed);
    let sign = match without_prefix.as_bytes().first().copied() {
        Some(b'+') => 1,
        Some(b'-') => -1,
        _ => return None,
    };
    let parts: Vec<&str> = without_prefix[1..].split(':').collect();
    if parts.len() > 2 || parts[0].is_empty() {
        return Some(Err(
            "Fixed timezone must look like +07:00 or UTC-05:30".into()
        ));
    }
    let hours = match parts[0].parse::<i32>() {
        Ok(value) => value,
        Err(_) => return Some(Err("Invalid fixed timezone hour".into())),
    };
    let minutes = match parts.get(1).unwrap_or(&"0").parse::<i32>() {
        Ok(value) => value,
        Err(_) => return Some(Err("Invalid fixed timezone minute".into())),
    };
    if hours > 23 || minutes > 59 {
        return Some(Err("Fixed timezone is outside the supported range".into()));
    }
    Some(
        FixedOffset::east_opt(sign * (hours * 3_600 + minutes * 60))
            .ok_or_else(|| "Invalid fixed timezone".to_string()),
    )
}

fn local_to_utc(naive: NaiveDateTime, timezone: &str) -> AppResult<DateTime<Utc>> {
    let timezone = timezone.trim();
    if timezone.eq_ignore_ascii_case("UTC") || timezone == "Z" {
        return Ok(naive.and_utc());
    }
    if let Some(offset) = fixed_offset(timezone) {
        return match offset?.from_local_datetime(&naive) {
            LocalResult::Single(value) => Ok(value.with_timezone(&Utc)),
            _ => Err("Invalid fixed-offset timestamp".into()),
        };
    }
    let zone: Tz = timezone.parse().map_err(|_| {
        format!("Unknown timezone '{timezone}'. Use UTC, a fixed offset, or an IANA zone such as Europe/London")
    })?;
    match zone.from_local_datetime(&naive) {
        LocalResult::Single(value) => Ok(value.with_timezone(&Utc)),
        LocalResult::Ambiguous(first, second) => Err(format!(
            "This local time occurs twice in {timezone} because of daylight-saving time ({} or {}). Use an explicit UTC offset.",
            first.offset(), second.offset()
        )),
        LocalResult::None => Err(format!(
            "This local time does not exist in {timezone} because of a clock change"
        )),
    }
}

fn parse_flexible_timestamp(
    value: &str,
    timezone: &str,
) -> AppResult<(DateTime<Utc>, String, bool)> {
    let value = value.trim();
    if value.is_empty() {
        return Err("Timestamp is required".into());
    }
    if let Some(result) = parse_epoch(value) {
        let (datetime, precision) = result?;
        return Ok((datetime, precision, true));
    }
    if let Ok(datetime) = DateTime::parse_from_rfc3339(value) {
        let precision = if value.contains('.') {
            "millisecond"
        } else {
            "second"
        };
        return Ok((datetime.with_timezone(&Utc), precision.into(), true));
    }
    if value.contains(' ') {
        let iso = value.replacen(' ', "T", 1);
        if let Ok(datetime) = DateTime::parse_from_rfc3339(&iso) {
            let precision = if value.contains('.') {
                "millisecond"
            } else {
                "second"
            };
            return Ok((datetime.with_timezone(&Utc), precision.into(), true));
        }
    }
    let (naive, precision) = parse_naive_timestamp(value)?;
    Ok((local_to_utc(naive, timezone)?, precision, false))
}

pub fn parse_timestamp_preview(
    input: &str,
    timezone: &str,
    offset_ms: i64,
) -> AppResult<TimePreview> {
    let (interpreted, precision, embedded) = parse_flexible_timestamp(input, timezone)?;
    let corrected_ms = interpreted
        .timestamp_millis()
        .checked_add(offset_ms)
        .ok_or_else(|| "Clock correction is outside the supported range".to_string())?;
    let corrected = epoch_datetime(corrected_ms)?;
    Ok(TimePreview {
        input: input.trim().to_string(),
        timezone: timezone.trim().to_string(),
        interpreted_utc: format_utc(interpreted),
        corrected_utc: format_utc(corrected),
        precision,
        epoch_millis: corrected_ms,
        offset_ms,
        used_embedded_timezone: embedded,
    })
}

/// Interpret one externally supplied timestamp (event-log importers) and
/// return the normalized UTC string the investigation model stores.
pub fn parse_log_timestamp(value: &str, timezone: &str) -> AppResult<String> {
    let (datetime, _precision, _embedded) = parse_flexible_timestamp(value, timezone)?;
    Ok(format_utc(datetime))
}

/// IOC types every write path accepts. File paths, file names, and process
/// names cover what reverse engineers and endpoint teams hand over most.
pub const IOC_TYPES: &[&str] = &[
    "IP", "Hash", "Domain", "URL", "Email", "Registry", "Mutex", "FilePath", "FileName", "Process",
];

fn validate_ioc_value(ioc_type: &str, value: &str) -> AppResult<()> {
    validate_enum("IOC type", ioc_type, IOC_TYPES)?;
    let value = value.trim();
    match ioc_type {
        "IP" => validate_ip(value),
        "Hash" if value.len() < 16 || !value.chars().all(|c| c.is_ascii_hexdigit()) => {
            Err("Hash IOC must contain at least 16 hexadecimal characters".to_string())
        }
        "Domain"
            if value.contains(char::is_whitespace)
                || value.starts_with('.')
                || value.ends_with('.') =>
        {
            Err("Domain IOC is invalid".to_string())
        }
        "URL"
            if !(value.starts_with("http://") || value.starts_with("https://"))
                || value.contains(char::is_whitespace) =>
        {
            Err("URL IOC must be an HTTP or HTTPS URL without spaces".to_string())
        }
        "Email" if value.split_once('@').is_none() || value.contains(char::is_whitespace) => {
            Err("Email IOC is invalid".to_string())
        }
        "FilePath" if value.contains(['\n', '\r']) || !value.contains(['\\', '/']) => {
            Err("File path IOC must include a directory, e.g. C:\\Users\\Public\\a.exe".to_string())
        }
        "FileName" if value.contains(['\n', '\r', '\\', '/']) => Err(
            "File name IOC must be a name without a directory; use File path for full paths"
                .to_string(),
        ),
        "Process" if value.contains(['\n', '\r']) => {
            Err("Process IOC must fit on one line".to_string())
        }
        _ => Ok(()),
    }
}

fn validate_network_model(value: &Network) -> AppResult<()> {
    validate_required("Network name", &value.name)?;
    validate_subnet(&value.subnet)?;
    validate_enum(
        "network type",
        &value.network_type,
        &["LAN", "DMZ", "DMS", "WAN", "GUEST", "MANAGEMENT", "OTHER"],
    )?;
    clean_text("Owner", value.owner.as_deref(), MAX_PARTY_CHARS)?;
    clean_text("Operated by", value.operator.as_deref(), MAX_PARTY_CHARS)?;
    Ok(())
}

/// Trimmed text, or `None` when it is empty. Text over `max` characters is refused.
fn clean_text(label: &str, value: Option<&str>, max: usize) -> AppResult<Option<String>> {
    let value = value.map(str::trim).filter(|item| !item.is_empty());
    if let Some(item) = value {
        if item.chars().count() > max {
            return Err(format!("{label} is limited to {max} characters"));
        }
    }
    Ok(value.map(String::from))
}

fn apply_asset_context(
    conn: &Connection,
    asset: &mut Asset,
    context: &AssetContext,
) -> AppResult<()> {
    if let Some(site) = context.site_id.as_deref() {
        let site = site.trim();
        asset.site_id = if site.is_empty() {
            None
        } else if exists(conn, "sites", site)? {
            Some(site.to_string())
        } else {
            return Err("Selected site was not found".into());
        };
    }
    if let Some(owner) = context.owner.as_deref() {
        asset.owner = clean_text("Owner", Some(owner), MAX_PARTY_CHARS)?;
    }
    if let Some(operator) = context.operator.as_deref() {
        asset.operator = clean_text("Operated by", Some(operator), MAX_PARTY_CHARS)?;
    }
    if let Some(origin) = context.origin.as_deref() {
        let origin = origin.trim();
        asset.origin = if origin.is_empty() {
            default_asset_origin()
        } else {
            validate_enum("asset origin", origin, ASSET_ORIGINS)?;
            origin.to_string()
        };
    }
    if let Some(observed) = context.last_observed.as_deref() {
        let observed = observed.trim();
        asset.last_observed = if observed.is_empty() {
            None
        } else {
            Some(normalize_timestamp("Last observed", observed)?)
        };
    }
    Ok(())
}

fn apply_network_context(
    conn: &Connection,
    network: &mut Network,
    context: &NetworkContext,
) -> AppResult<()> {
    if let Some(site) = context.site_id.as_deref() {
        let site = site.trim();
        network.site_id = if site.is_empty() {
            None
        } else if exists(conn, "sites", site)? {
            Some(site.to_string())
        } else {
            return Err("Selected site was not found".into());
        };
    }
    if let Some(owner) = context.owner.as_deref() {
        network.owner = clean_text("Owner", Some(owner), MAX_PARTY_CHARS)?;
    }
    if let Some(operator) = context.operator.as_deref() {
        network.operator = clean_text("Operated by", Some(operator), MAX_PARTY_CHARS)?;
    }
    Ok(())
}

fn validate_asset_model(value: &Asset) -> AppResult<()> {
    validate_required("Asset name", &value.name)?;
    validate_ip(&value.ip_address)?;
    validate_mac(value.mac_address.as_deref())?;
    validate_enum("asset type", &value.asset_type, ASSET_TYPES)?;
    validate_enum(
        "compromise status",
        &value.compromise_status,
        &["unknown", "clean", "suspected", "infected"],
    )?;
    validate_enum(
        "investigation status",
        &value.investigation_status,
        &["not_started", "in_progress", "completed"],
    )?;
    validate_enum("asset origin", &value.origin, ASSET_ORIGINS)?;
    if let Some(observed) = value.last_observed.as_deref() {
        validate_timestamp("Last observed", observed)?;
    }
    clean_text("Owner", value.owner.as_deref(), MAX_PARTY_CHARS)?;
    clean_text("Operated by", value.operator.as_deref(), MAX_PARTY_CHARS)?;
    validate_optional_json("Scan results", value.scan_results.as_deref())
}

fn validate_site_model(value: &Site) -> AppResult<()> {
    validate_required("Site name", &value.name)?;
    clean_text("Site name", Some(&value.name), 200)?;
    clean_text("Site location", Some(&value.location), 300)?;
    clean_text("Site description", Some(&value.description), 4_000)?;
    Ok(())
}

fn validate_relation_model(value: &AssetRelation) -> AppResult<()> {
    validate_enum("relation type", &value.relation_type, RELATION_TYPES)?;
    validate_required("Relation source", &value.source_asset_id)?;
    validate_required("Relation target", &value.target_asset_id)?;
    if value.source_asset_id == value.target_asset_id {
        return Err("An asset cannot be related to itself".into());
    }
    clean_text("Relation note", Some(&value.note), 2_000)?;
    Ok(())
}

fn validate_interface_model(value: &NetworkInterface) -> AppResult<()> {
    validate_required("Interface name", &value.name)?;
    validate_ip(&value.ip_address)?;
    validate_mac(value.mac_address.as_deref())
}

fn validate_timeline_model(value: &TimelineEvent) -> AppResult<()> {
    validate_required("Event type", &value.event_type)?;
    validate_required("Event description", &value.description)?;
    if !value.timestamp.trim().is_empty() {
        validate_timestamp("Correct incident timestamp", &value.timestamp)?;
    }
    if let Some(timestamp) = value.server_timestamp_utc.as_deref() {
        validate_timestamp("Normalized server timestamp", timestamp)?;
    }
    validate_enum(
        "severity",
        &value.severity,
        &["info", "low", "medium", "high", "critical"],
    )
}

fn validate_clock_profile_model(value: &ClockProfile) -> AppResult<()> {
    validate_required("Clock profile name", &value.name)?;
    let server = parse_timestamp_preview(&value.server_reference_raw, &value.server_timezone, 0)?;
    let correct =
        parse_timestamp_preview(&value.correct_reference_raw, &value.correct_timezone, 0)?;
    let offset = correct
        .epoch_millis
        .checked_sub(server.epoch_millis)
        .ok_or_else(|| "Clock profile offset is outside the supported range".to_string())?;
    if offset != value.offset_ms {
        return Err(format!(
            "Clock profile '{}' has an inconsistent offset",
            value.name
        ));
    }
    Ok(())
}

const CAPTURE_STATUSES: &[&str] = &["open", "processed", "dismissed"];
/// Captured text is pasted notes, not a file store; the cap keeps one paste
/// from bloating every snapshot and bundle that carries it.
const MAX_CAPTURE_CHARS: usize = 200_000;
/// Entities a processed capture may point at.
const CAPTURE_LINK_TYPES: &[&str] = &[
    "asset",
    "network",
    "network_interface",
    "firewall",
    "ioc",
    "ioc_sighting",
    "timeline_event",
    "note",
    "attack_edge",
    "network_connection",
    "clock_profile",
];

fn validate_capture_model(value: &Capture) -> AppResult<()> {
    validate_required("Captured text", &value.content)?;
    if value.content.chars().count() > MAX_CAPTURE_CHARS {
        return Err(format!(
            "Captured text is limited to {MAX_CAPTURE_CHARS} characters; keep large material as evidence files"
        ));
    }
    validate_enum("capture status", &value.status, CAPTURE_STATUSES)?;
    for link in &value.links {
        validate_enum("capture link type", &link.entity_type, CAPTURE_LINK_TYPES)?;
        validate_required("Capture link id", &link.entity_id)?;
    }
    Ok(())
}

fn validate_ioc_model(value: &Ioc) -> AppResult<()> {
    validate_required("IOC value", &value.value)?;
    validate_ioc_value(&value.ioc_type, &value.value)?;
    validate_enum(
        "threat level",
        &value.threat_level,
        &["low", "medium", "high", "critical"],
    )?;
    if let Some(first) = &value.first_seen {
        validate_timestamp("First seen", first)?;
    }
    if let Some(last) = &value.last_seen {
        validate_timestamp("Last seen", last)?;
    }
    if let (Some(first), Some(last)) = (&value.first_seen, &value.last_seen) {
        if chrono::DateTime::parse_from_rfc3339(last).map_err(|e| e.to_string())?
            < chrono::DateTime::parse_from_rfc3339(first).map_err(|e| e.to_string())?
        {
            return Err("Last seen cannot be before first seen".into());
        }
    }
    Ok(())
}

fn validate_firewall_model(value: &Firewall) -> AppResult<()> {
    validate_required("Firewall name", &value.name)?;
    validate_optional_json("Firewall rules", value.rules.as_deref())
}

fn validate_ip_or_cidr(label: &str, value: Option<&str>) -> AppResult<()> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if value.contains('/') {
        validate_subnet(value).map_err(|error| format!("{label}: {error}"))
    } else {
        validate_ip(value).map_err(|error| format!("{label}: {error}"))
    }
}

fn validate_port_spec(label: &str, value: Option<&str>) -> AppResult<()> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    for part in value.split(',').map(str::trim) {
        let parse = |text: &str| {
            text.parse::<u16>().map_err(|_| {
                format!("{label} must contain ports 1-65535, ranges, or comma-separated values")
            })
        };
        if let Some((start, end)) = part.split_once('-') {
            let start = parse(start.trim())?;
            let end = parse(end.trim())?;
            if start == 0 || end == 0 || start > end {
                return Err(format!("{label} contains an invalid port range"));
            }
        } else if parse(part)? == 0 {
            return Err(format!("{label} cannot contain port 0"));
        }
    }
    Ok(())
}

fn validate_firewall_interface_model(value: &FirewallInterface) -> AppResult<()> {
    validate_required("Firewall interface name", &value.name)?;
    validate_mac(value.mac_address.as_deref())?;
    validate_enum(
        "firewall interface role",
        &value.role,
        &["wan", "lan", "dmz", "management", "ha", "vpn", "other"],
    )?;
    for address in &value.ip_addresses {
        validate_ip_or_cidr("Firewall interface address", Some(address))?;
    }
    Ok(())
}

fn validate_firewall_nat_model(value: &FirewallNatRule) -> AppResult<()> {
    validate_required("NAT rule name", &value.name)?;
    validate_enum(
        "NAT type",
        &value.nat_type,
        &["vip", "dnat", "snat", "port_mapping"],
    )?;
    validate_enum(
        "NAT protocol",
        &value.protocol,
        &["any", "tcp", "udp", "icmp", "sctp", "other"],
    )?;
    validate_ip_or_cidr("Source", value.source_cidr.as_deref())?;
    validate_ip_or_cidr(
        "Original destination",
        value.original_destination.as_deref(),
    )?;
    validate_ip_or_cidr("Translated source", value.translated_source.as_deref())?;
    validate_ip_or_cidr(
        "Translated destination",
        value.translated_destination.as_deref(),
    )?;
    validate_port_spec("Original port", value.original_port.as_deref())?;
    validate_port_spec("Translated port", value.translated_port.as_deref())?;
    match value.nat_type.as_str() {
        "snat"
            if value
                .translated_source
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty() =>
        {
            Err("SNAT requires a translated source address".into())
        }
        "vip" | "dnat"
            if value
                .original_destination
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
                || value
                    .translated_destination
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty() =>
        {
            Err("VIP/DNAT requires original and translated destination addresses".into())
        }
        "port_mapping"
            if value
                .original_destination
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
                || value
                    .translated_destination
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                || value
                    .original_port
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                || value
                    .translated_port
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty() =>
        {
            Err("Port mapping requires original/translated destinations and ports".into())
        }
        _ => Ok(()),
    }
}

fn validate_connection_model(value: &NetworkConnection) -> AppResult<()> {
    validate_required("Connection type", &value.connection_type)?;
    if value.source_network_id == value.target_network_id {
        Err("A network connection must link two different networks".into())
    } else {
        Ok(())
    }
}

const SIGHTING_ENTITY_KINDS: &[&str] = &["asset", "network", "firewall"];
const ATTACK_EDGE_TYPES: &[&str] = &[
    "initial_access",
    "lateral_movement",
    "privilege_escalation",
    "persistence",
    "c2",
    "exfiltration",
    "other",
];
const ATTACK_EDGE_CONFIDENCE: &[&str] = &["confirmed", "probable", "suspected"];

fn compromise_rank(status: &str) -> i32 {
    match status {
        "infected" => 2,
        "suspected" => 1,
        _ => 0,
    }
}

fn threat_rank(level: &str) -> i32 {
    match level {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn entity_kind_table(kind: &str) -> AppResult<&'static str> {
    match kind {
        "asset" => Ok("assets"),
        "network" => Ok("networks"),
        "firewall" => Ok("firewalls"),
        _ => Err(format!("Invalid entity kind: {kind}")),
    }
}

fn verify_graph_entity_ref(conn: &Connection, kind: &str, id: &str) -> AppResult<()> {
    if !exists(conn, entity_kind_table(kind)?, id)? {
        return Err(format!("Referenced {kind} was not found"));
    }
    Ok(())
}

fn validate_sighting_model(value: &IocSighting) -> AppResult<()> {
    validate_enum("entity kind", &value.entity_kind, SIGHTING_ENTITY_KINDS)?;
    validate_required("Sighting entity", &value.entity_id)?;
    validate_required("Sighting IOC", &value.ioc_id)?;
    if let Some(sighted_at) = value.sighted_at.as_deref() {
        validate_timestamp("Sighted at", sighted_at)?;
    }
    Ok(())
}

fn validate_attack_edge_model(value: &AttackEdge) -> AppResult<()> {
    validate_required("Attack edge title", &value.title)?;
    validate_enum(
        "source kind",
        &value.source_kind,
        &["asset", "network", "firewall", "external"],
    )?;
    validate_enum("target kind", &value.target_kind, SIGHTING_ENTITY_KINDS)?;
    validate_enum("edge type", &value.edge_type, ATTACK_EDGE_TYPES)?;
    validate_enum("confidence", &value.confidence, ATTACK_EDGE_CONFIDENCE)?;
    if value.source_kind == "external" {
        let label = value.source_id.trim();
        if label.is_empty() {
            return Err("External origins need a non-empty label".into());
        }
        if label.chars().count() > 120 {
            return Err("External origin labels are limited to 120 characters".into());
        }
    }
    if value.source_kind == value.target_kind && value.source_id == value.target_id {
        return Err("An attack edge must connect two different entities".into());
    }
    if value.sequence < 0 {
        return Err("Attack edge sequence cannot be negative".into());
    }
    if let Some(occurred_at) = value.occurred_at.as_deref() {
        validate_timestamp("Occurred at", occurred_at)?;
    }
    Ok(())
}

fn verify_attack_edge_refs(conn: &Connection, value: &AttackEdge) -> AppResult<()> {
    if value.source_kind != "external" {
        verify_graph_entity_ref(conn, &value.source_kind, &value.source_id)?;
    }
    verify_graph_entity_ref(conn, &value.target_kind, &value.target_id)?;
    if let Some(event_id) = value.timeline_event_id.as_deref() {
        if !exists(conn, "timeline_events", event_id)? {
            return Err("Linked timeline event was not found".into());
        }
    }
    for ioc_id in &value.ioc_ids {
        if !exists(conn, "iocs", ioc_id)? {
            return Err(format!("Linked IOC {ioc_id} was not found"));
        }
    }
    Ok(())
}

const INVESTIGATION_VIEW_STATE_VERSION: i64 = 1;

fn validate_investigation_view_state(state: &Value) -> AppResult<()> {
    let object = state
        .as_object()
        .ok_or_else(|| "Invalid view state: it must be a JSON object".to_string())?;
    if object.get("version").and_then(Value::as_i64) != Some(INVESTIGATION_VIEW_STATE_VERSION) {
        return Err(format!(
            "Invalid view state: version must be {INVESTIGATION_VIEW_STATE_VERSION}"
        ));
    }
    if let Some(layout) = object.get("layout").and_then(Value::as_str) {
        validate_topology_layout(layout)?;
    } else {
        return Err("Invalid view state: layout is required".into());
    }
    for field in ["zoom", "pan_x", "pan_y"] {
        let number = object
            .get(field)
            .and_then(Value::as_f64)
            .ok_or_else(|| format!("Invalid view state: {field} must be a number"))?;
        if !number.is_finite() {
            return Err(format!("Invalid view state: {field} must be finite"));
        }
    }
    for field in ["hidden_network_ids", "hidden_node_ids"] {
        if let Some(value) = object.get(field) {
            let items = value
                .as_array()
                .ok_or_else(|| format!("Invalid view state: {field} must be an array"))?;
            if items.iter().any(|item| !item.is_string()) {
                return Err(format!("Invalid view state: {field} must contain strings"));
            }
        }
    }
    if let Some(positions) = object.get("positions") {
        let items = positions
            .as_array()
            .ok_or_else(|| "Invalid view state: positions must be an array".to_string())?;
        for item in items {
            let entry = item
                .as_object()
                .filter(|entry| entry.get("id").map(Value::is_string).unwrap_or(false));
            let valid = entry
                .map(|entry| {
                    ["x", "y"].iter().all(|axis| {
                        entry
                            .get(*axis)
                            .and_then(Value::as_f64)
                            .map(f64::is_finite)
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            if !valid {
                return Err("Invalid view state: each position needs an id and finite x/y".into());
            }
        }
    }
    for field in ["filters", "display"] {
        if let Some(value) = object.get(field) {
            if !value.is_object() {
                return Err(format!("Invalid view state: {field} must be an object"));
            }
        }
    }
    Ok(())
}

fn validate_investigation_view_model(value: &InvestigationView) -> AppResult<()> {
    validate_required("View name", &value.name)?;
    if value.name.trim().chars().count() > 120 {
        return Err("View names are limited to 120 characters".into());
    }
    validate_investigation_view_state(&value.state)
}

fn validate_export_data(data: &ExportData) -> AppResult<()> {
    for value in &data.networks {
        validate_network_model(value)?;
    }
    for value in &data.assets {
        validate_asset_model(value)?;
    }
    for value in &data.network_interfaces {
        validate_interface_model(value)?;
    }
    for value in &data.clock_profiles {
        validate_clock_profile_model(value)?;
    }
    for value in &data.timeline_events {
        validate_timeline_model(value)?;
    }
    for value in &data.notes {
        validate_required("Note title", &value.title)?;
    }
    for value in &data.iocs {
        validate_ioc_model(value)?;
    }
    for value in &data.firewalls {
        validate_firewall_model(value)?;
    }
    for value in &data.firewall_interfaces {
        validate_firewall_interface_model(value)?;
    }
    for value in &data.firewall_nat_rules {
        validate_firewall_nat_model(value)?;
    }
    for value in &data.network_connections {
        validate_connection_model(value)?;
    }
    for value in &data.ioc_sightings {
        validate_sighting_model(value)?;
    }
    for value in &data.attack_edges {
        validate_attack_edge_model(value)?;
    }
    for value in &data.investigation_views {
        validate_investigation_view_model(value)?;
    }
    for value in &data.captures {
        validate_capture_model(value)?;
    }
    for value in &data.sites {
        validate_site_model(value)?;
    }
    for value in &data.asset_relations {
        validate_relation_model(value)?;
    }
    Ok(())
}

fn to_value<T: Serialize>(value: &T) -> AppResult<Value> {
    serde_json::to_value(value).map_err(|e| e.to_string())
}

fn single_change(
    entity_type: &str,
    entity_id: &str,
    operation: &str,
    before: Option<Value>,
    after: Option<Value>,
) -> EntityChangeInput {
    EntityChangeInput {
        entity_type: entity_type.to_string(),
        entity_id: entity_id.to_string(),
        operation: operation.to_string(),
        before,
        after,
        source_change_id: None,
    }
}

fn get_row_optional<T, F>(conn: &Connection, sql: &str, id: &str, mapper: F) -> AppResult<Option<T>>
where
    F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    conn.query_row(sql, params![id], mapper)
        .optional()
        .map_err(|e| e.to_string())
}

pub fn get_entity_json(conn: &Connection, entity_type: &str, id: &str) -> AppResult<Option<Value>> {
    match entity_type {
        "case" => get_case(conn)?.filter(|v| v.id == id).map(|v| to_value(&v)).transpose(),
        "network" => get_row_optional(conn, &format!("{NETWORK_SELECT} WHERE id=?1"), id, map_network)?.map(|v| to_value(&v)).transpose(),
        "asset" => get_row_optional(conn,
            "SELECT a.id,a.network_id,n.name,a.name,a.ip_address,a.mac_address,a.asset_type,a.os,a.user_name,a.suspicious,
                    a.compromise_status,a.investigation_status,a.properties,a.scan_results,a.quick_note,a.site_id,a.owner,a.operator,a.origin,a.last_observed,a.created_at
             FROM assets a LEFT JOIN networks n ON n.id=a.network_id WHERE a.id=?1", id, map_asset)?.map(|v| to_value(&v)).transpose(),
        "network_interface" => get_row_optional(conn,
            "SELECT ni.id,ni.asset_id,ni.name,ni.ip_address,ni.mac_address,ni.network_id,n.name,ni.is_primary
             FROM network_interfaces ni LEFT JOIN networks n ON n.id=ni.network_id WHERE ni.id=?1", id, map_interface)?.map(|v| to_value(&v)).transpose(),
        "clock_profile" => get_row_optional(conn,
            "SELECT id,name,description,server_reference_raw,server_timezone,server_reference_utc,
                    correct_reference_raw,correct_timezone,correct_reference_utc,offset_ms,created_at,updated_at
             FROM clock_profiles WHERE id=?1", id, map_clock_profile)?.map(|v| to_value(&v)).transpose(),
        "timeline_event" => get_row_optional(conn,
            "SELECT e.id,e.asset_id,a.name,e.timestamp,e.raw_timestamp,e.raw_timezone,
                    e.server_timestamp_utc,e.correct_timestamp_raw,e.correct_timezone,
                    e.clock_profile_id,cp.name,e.clock_offset_ms,e.time_precision,e.correct_time_precision,
                    e.event_type,e.description,e.severity,e.source,e.mitre_tactic,e.mitre_technique,e.created_at,
                    e.source_ref
             FROM timeline_events e LEFT JOIN assets a ON a.id=e.asset_id
             LEFT JOIN clock_profiles cp ON cp.id=e.clock_profile_id WHERE e.id=?1", id, map_timeline)?.map(|v| to_value(&v)).transpose(),
        "note" => get_row_optional(conn, "SELECT id,title,content,created_at,updated_at FROM notes WHERE id=?1", id, |row| {
            Ok(Note { id: row.get(0)?, title: row.get(1)?, content: row.get(2)?, created_at: row.get(3)?, updated_at: row.get(4)? })
        })?.map(|v| to_value(&v)).transpose(),
        "ioc" => get_row_optional(conn, "SELECT id,ioc_type,value,description,threat_level,first_seen,last_seen,created_at FROM iocs WHERE id=?1", id, |row| {
            Ok(Ioc { id: row.get(0)?, ioc_type: row.get(1)?, value: row.get(2)?, description: row.get(3)?, threat_level: row.get(4)?, first_seen: row.get(5)?, last_seen: row.get(6)?, created_at: row.get(7)? })
        })?.map(|v| to_value(&v)).transpose(),
        "firewall" => get_row_optional(conn,
            "SELECT f.id,f.network_id,n.name,f.name,f.vendor,f.model,f.rules,f.config_text,f.quick_note,f.created_at
             FROM firewalls f LEFT JOIN networks n ON n.id=f.network_id WHERE f.id=?1", id, |row| {
            Ok(Firewall { id: row.get(0)?, network_id: row.get(1)?, network_name: row.get(2)?, name: row.get(3)?, vendor: row.get(4)?, model: row.get(5)?, rules: row.get(6)?, config_text: row.get(7)?, quick_note: row.get(8)?, created_at: row.get(9)? })
        })?.map(|v| to_value(&v)).transpose(),
        "firewall_interface" => get_firewall_interfaces(conn, None)?
            .into_iter()
            .find(|value| value.id == id)
            .map(|value| to_value(&value))
            .transpose(),
        "firewall_nat_rule" => get_firewall_nat_rules(conn, None)?
            .into_iter()
            .find(|value| value.id == id)
            .map(|value| to_value(&value))
            .transpose(),
        "network_connection" => get_row_optional(conn,
            "SELECT c.id,c.source_network_id,s.name,c.target_network_id,t.name,c.connection_type,c.description,c.device_name
             FROM network_connections c JOIN networks s ON s.id=c.source_network_id JOIN networks t ON t.id=c.target_network_id WHERE c.id=?1", id, |row| {
            Ok(NetworkConnection { id: row.get(0)?, source_network_id: row.get(1)?, source_network_name: row.get(2)?, target_network_id: row.get(3)?, target_network_name: row.get(4)?, connection_type: row.get(5)?, description: row.get(6)?, device_name: row.get(7)? })
        })?.map(|v| to_value(&v)).transpose(),
        "ioc_sighting" => get_row_optional(conn, &format!("{SIGHTING_SELECT} WHERE s.id=?1"), id, map_sighting)?
            .map(|v| to_value(&v)).transpose(),
        "attack_edge" => get_row_optional(conn, &format!("{ATTACK_EDGE_SELECT} WHERE e.id=?1"), id, map_attack_edge)?
            .map(|v| to_value(&v)).transpose(),
        "capture" => get_row_optional(conn, &format!("{CAPTURE_SELECT} WHERE id=?1"), id, map_capture)?
            .map(|v| to_value(&v)).transpose(),
        "site" => get_row_optional(conn, &format!("{SITE_SELECT} WHERE id=?1"), id, map_site)?
            .map(|v| to_value(&v)).transpose(),
        "asset_relation" => get_row_optional(conn, &format!("{RELATION_SELECT} WHERE r.id=?1"), id, map_relation)?
            .map(|v| to_value(&v)).transpose(),
        _ => Err(format!("Unsupported entity type: {entity_type}")),
    }
}

fn require_existing<T>(value: Option<T>, label: &str) -> AppResult<T> {
    value.ok_or_else(|| format!("{label} was not found"))
}

fn exists(conn: &Connection, table: &str, id: &str) -> AppResult<bool> {
    conn.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id=?1)"),
        params![id],
        |row| row.get::<_, i64>(0),
    )
    .map(|value| value != 0)
    .map_err(|e| e.to_string())
}

pub fn update_case(
    conn: &mut Connection,
    actor: &ActorIdentity,
    name: &str,
    description: &str,
    client_name: &str,
    status: &str,
) -> AppResult<Case> {
    validate_required("Case name", name)?;
    validate_enum("case status", status, &["active", "closed", "archived"])?;
    let before = require_existing(get_case(conn)?, "Case")?;
    let now = Utc::now().to_rfc3339();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE cases SET name=?1,description=?2,client_name=?3,status=?4,updated_at=?5 WHERE id=?6",
        params![name.trim(), description.trim(), client_name.trim(), status, now, before.id],
    )
    .map_err(|e| e.to_string())?;
    let after = Case {
        name: name.trim().into(),
        description: description.trim().into(),
        client_name: client_name.trim().into(),
        status: status.into(),
        updated_at: now,
        ..before.clone()
    };
    record_commit_tx(
        &tx,
        actor,
        "Updated case details",
        vec![single_change(
            "case",
            &after.id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

/// Links interfaces and assets that carry no network assignment yet and whose
/// IP has `network` as its single most specific subnet. Explicit assignments
/// are never overridden, and an address that an equally specific network also
/// contains stays unassigned. History changes for every touched row are
/// returned so callers can record them in the same commit.
fn link_unassigned_endpoints_to_network(
    tx: &Transaction<'_>,
    network: &Network,
) -> AppResult<Vec<EntityChangeInput>> {
    let mut changes = Vec::new();
    if parse_subnet_cidr(&network.subnet).is_none() {
        return Ok(changes);
    }
    // `network` has already been written in this transaction, so the list
    // holds its new subnet alongside every competing one.
    let networks = get_networks(tx)?;
    let belongs_here = |ip: &str| matches!(match_network_for_ip(&networks, ip), SubnetMatch::Unique(best) if best.id == network.id);
    let mut primary_asset_ids = Vec::new();
    for mut interface in get_network_interfaces(tx, None)? {
        if interface.network_id.is_some() || !belongs_here(&interface.ip_address) {
            continue;
        }
        let before = interface.clone();
        interface.network_id = Some(network.id.clone());
        interface.network_name = Some(network.name.clone());
        tx.execute(
            "UPDATE network_interfaces SET network_id=?1 WHERE id=?2",
            params![network.id, interface.id],
        )
        .map_err(|e| e.to_string())?;
        if interface.is_primary {
            primary_asset_ids.push(interface.asset_id.clone());
        }
        changes.push(single_change(
            "network_interface",
            &interface.id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&interface)?),
        ));
    }
    // The asset projection mirrors the primary interface's network, so a
    // backfilled primary NIC must carry the asset along when the asset has no
    // assignment of its own. Assets recorded with an IP but no NIC rows are
    // linked directly.
    for asset_before in get_assets(tx)? {
        if asset_before.network_id.is_some()
            || (!primary_asset_ids.contains(&asset_before.id)
                && !belongs_here(&asset_before.ip_address))
        {
            continue;
        }
        let asset_after = Asset {
            network_id: Some(network.id.clone()),
            network_name: Some(network.name.clone()),
            ..asset_before.clone()
        };
        tx.execute(
            "UPDATE assets SET network_id=?1 WHERE id=?2",
            params![network.id, asset_before.id],
        )
        .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "asset",
            &asset_before.id,
            "update",
            Some(to_value(&asset_before)?),
            Some(to_value(&asset_after)?),
        ));
    }
    Ok(changes)
}

/// Shorthand for callers (and tests) that have no environment fields to send.
#[allow(dead_code)]
pub fn create_network(
    conn: &mut Connection,
    actor: &ActorIdentity,
    name: &str,
    subnet: &str,
    network_type: &str,
    description: &str,
    vlan_id: Option<&str>,
) -> AppResult<Network> {
    create_network_with_context(
        conn,
        actor,
        name,
        subnet,
        network_type,
        description,
        vlan_id,
        &NetworkContext::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn create_network_with_context(
    conn: &mut Connection,
    actor: &ActorIdentity,
    name: &str,
    subnet: &str,
    network_type: &str,
    description: &str,
    vlan_id: Option<&str>,
    context: &NetworkContext,
) -> AppResult<Network> {
    validate_required("Network name", name)?;
    validate_subnet(subnet.trim())?;
    validate_enum(
        "network type",
        network_type,
        &["LAN", "DMZ", "DMS", "WAN", "GUEST", "MANAGEMENT", "OTHER"],
    )?;
    let mut item = Network {
        id: Uuid::new_v4().to_string(),
        name: name.trim().into(),
        subnet: subnet.trim().into(),
        network_type: network_type.into(),
        description: description.trim().into(),
        vlan_id: vlan_id
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        quick_note: None,
        site_id: None,
        owner: None,
        operator: None,
        created_at: Utc::now().to_rfc3339(),
    };
    apply_network_context(conn, &mut item, context)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO networks(id,name,subnet,network_type,description,vlan_id,site_id,owner,operator,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![item.id,item.name,item.subnet,item.network_type,item.description,item.vlan_id,item.site_id,item.owner,item.operator,item.created_at],
    ).map_err(|e| e.to_string())?;
    let mut changes = vec![single_change(
        "network",
        &item.id,
        "create",
        None,
        Some(to_value(&item)?),
    )];
    let mut message = format!("Created network {}", item.name);
    let linked = link_unassigned_endpoints_to_network(&tx, &item)?;
    if !linked.is_empty() {
        message.push_str(&format!(
            " and linked {} unassigned endpoint(s)",
            linked.len()
        ));
        changes.extend(linked);
    }
    record_commit_tx(&tx, actor, &message, changes, &[])?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

/// Shorthand for callers (and tests) that have no environment fields to send.
#[allow(dead_code)]
pub fn update_network(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    name: &str,
    subnet: &str,
    network_type: &str,
    description: &str,
    vlan_id: Option<&str>,
) -> AppResult<Network> {
    update_network_with_context(
        conn,
        actor,
        id,
        name,
        subnet,
        network_type,
        description,
        vlan_id,
        &NetworkContext::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn update_network_with_context(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    name: &str,
    subnet: &str,
    network_type: &str,
    description: &str,
    vlan_id: Option<&str>,
    context: &NetworkContext,
) -> AppResult<Network> {
    validate_required("Network name", name)?;
    validate_subnet(subnet.trim())?;
    validate_enum(
        "network type",
        network_type,
        &["LAN", "DMZ", "DMS", "WAN", "GUEST", "MANAGEMENT", "OTHER"],
    )?;
    let before: Network = require_existing(
        get_row_optional(
            conn,
            &format!("{NETWORK_SELECT} WHERE id=?1"),
            id,
            map_network,
        )?,
        "Network",
    )?;
    let mut after = Network {
        name: name.trim().into(),
        subnet: subnet.trim().into(),
        network_type: network_type.into(),
        description: description.trim().into(),
        vlan_id: vlan_id
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        ..before.clone()
    };
    apply_network_context(conn, &mut after, context)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let changed = tx.execute("UPDATE networks SET name=?1,subnet=?2,network_type=?3,description=?4,vlan_id=?5,site_id=?6,owner=?7,operator=?8 WHERE id=?9",
        params![after.name,after.subnet,after.network_type,after.description,after.vlan_id,after.site_id,after.owner,after.operator,id]).map_err(|e| e.to_string())?;
    if changed == 0 {
        return Err("Network was not found".into());
    }
    let mut changes = vec![single_change(
        "network",
        id,
        "update",
        Some(to_value(&before)?),
        Some(to_value(&after)?),
    )];
    let mut message = format!("Updated network {}", after.name);
    let linked = link_unassigned_endpoints_to_network(&tx, &after)?;
    if !linked.is_empty() {
        message.push_str(&format!(
            " and linked {} unassigned endpoint(s)",
            linked.len()
        ));
        changes.extend(linked);
    }
    record_commit_tx(&tx, actor, &message, changes, &[])?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

pub fn delete_network(conn: &mut Connection, actor: &ActorIdentity, id: &str) -> AppResult<()> {
    let before = require_existing(get_entity_json(conn, "network", id)?, "Network")?;
    let dependencies = [
        ("assets", "SELECT COUNT(*) FROM assets WHERE network_id=?1"),
        ("interfaces", "SELECT COUNT(*) FROM network_interfaces WHERE network_id=?1"),
        ("firewall interfaces", "SELECT COUNT(*) FROM firewall_interfaces WHERE network_id=?1"),
        ("firewalls", "SELECT COUNT(*) FROM firewalls WHERE network_id=?1"),
        ("connections", "SELECT COUNT(*) FROM network_connections WHERE source_network_id=?1 OR target_network_id=?1"),
        ("IOC sightings", "SELECT COUNT(*) FROM ioc_sightings WHERE network_id=?1"),
        ("attack edges", "SELECT COUNT(*) FROM attack_edges WHERE (source_kind='network' AND source_id=?1) OR (target_kind='network' AND target_id=?1)"),
    ];
    let mut used = Vec::new();
    for (label, sql) in dependencies {
        let count: i64 = conn
            .query_row(sql, params![id], |row| row.get(0))
            .map_err(|e| e.to_string())?;
        if count > 0 {
            used.push(format!("{count} {label}"));
        }
    }
    if !used.is_empty() {
        return Err(format!(
            "Network is still referenced by {}. Reassign or remove those records first.",
            used.join(", ")
        ));
    }
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let changed = tx
        .execute("DELETE FROM networks WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?;
    if changed == 0 {
        return Err("Network was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Deleted network",
        vec![single_change("network", id, "delete", Some(before), None)],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())
}

/// Shorthand for callers (and tests) that have no environment fields to send.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn create_asset(
    conn: &mut Connection,
    actor: &ActorIdentity,
    network_id: Option<&str>,
    name: &str,
    ip_address: &str,
    mac_address: Option<&str>,
    asset_type: &str,
    os: Option<&str>,
    user_name: Option<&str>,
    compromise_status: &str,
    investigation_status: &str,
    properties: Option<&str>,
    scan_results: Option<&str>,
) -> AppResult<Asset> {
    create_asset_with_context(
        conn,
        actor,
        network_id,
        name,
        ip_address,
        mac_address,
        asset_type,
        os,
        user_name,
        compromise_status,
        investigation_status,
        properties,
        scan_results,
        &AssetContext::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn create_asset_with_context(
    conn: &mut Connection,
    actor: &ActorIdentity,
    network_id: Option<&str>,
    name: &str,
    ip_address: &str,
    mac_address: Option<&str>,
    asset_type: &str,
    os: Option<&str>,
    user_name: Option<&str>,
    compromise_status: &str,
    investigation_status: &str,
    properties: Option<&str>,
    scan_results: Option<&str>,
    context: &AssetContext,
) -> AppResult<Asset> {
    validate_required("Asset name", name)?;
    validate_ip(ip_address.trim())?;
    validate_mac(mac_address)?;
    validate_enum("asset type", asset_type, ASSET_TYPES)?;
    validate_enum(
        "compromise status",
        compromise_status,
        &["unknown", "clean", "suspected", "infected"],
    )?;
    validate_enum(
        "investigation status",
        investigation_status,
        &["not_started", "in_progress", "completed"],
    )?;
    validate_optional_json("Scan results", scan_results)?;
    // Same rule as interfaces: an asset recorded with an IP but no zone joins
    // the subnet that contains the address, so it never dangles ungrouped
    // while its subnet exists.
    let (network_id, network_name) = match network_id {
        Some(nid) => {
            if !exists(conn, "networks", nid)? {
                return Err("Selected network was not found".into());
            }
            let network_name = conn
                .query_row(
                    "SELECT name FROM networks WHERE id=?1",
                    params![nid],
                    |row| row.get(0),
                )
                .optional()
                .ok()
                .flatten();
            (Some(nid.to_string()), network_name)
        }
        None => best_network_for_ip(conn, ip_address.trim())?
            .map_or((None, None), |(id, name)| (Some(id), name)),
    };
    let suspicious = matches!(compromise_status, "suspected" | "infected");
    let mut item = Asset {
        id: Uuid::new_v4().to_string(),
        network_id,
        network_name,
        name: name.trim().into(),
        ip_address: ip_address.trim().into(),
        mac_address: mac_address
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        asset_type: asset_type.into(),
        os: os
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        user_name: user_name
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        suspicious,
        compromise_status: compromise_status.into(),
        investigation_status: investigation_status.into(),
        properties: properties
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        scan_results: scan_results
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        quick_note: None,
        site_id: None,
        owner: None,
        operator: None,
        origin: default_asset_origin(),
        last_observed: None,
        created_at: Utc::now().to_rfc3339(),
    };
    apply_asset_context(conn, &mut item, context)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO assets(id,network_id,name,ip_address,mac_address,asset_type,os,user_name,suspicious,compromise_status,investigation_status,properties,scan_results,site_id,owner,operator,origin,last_observed,created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
        params![item.id,item.network_id,item.name,item.ip_address,item.mac_address,item.asset_type,item.os,item.user_name,
            if item.suspicious {1} else {0},item.compromise_status,item.investigation_status,item.properties,item.scan_results,
            item.site_id,item.owner,item.operator,item.origin,item.last_observed,item.created_at]
    ).map_err(|e| e.to_string())?;
    let mut changes = vec![single_change(
        "asset",
        &item.id,
        "create",
        None,
        Some(to_value(&item)?),
    )];
    if item.network_id.is_some() || !item.ip_address.is_empty() {
        let iface = NetworkInterface {
            id: Uuid::new_v4().to_string(),
            asset_id: item.id.clone(),
            name: "Primary".into(),
            ip_address: item.ip_address.clone(),
            mac_address: item.mac_address.clone(),
            network_id: item.network_id.clone(),
            network_name: item.network_name.clone(),
            is_primary: true,
        };
        tx.execute("INSERT INTO network_interfaces(id,asset_id,name,ip_address,mac_address,network_id,is_primary) VALUES (?1,?2,?3,?4,?5,?6,1)",
            params![iface.id,iface.asset_id,iface.name,iface.ip_address,iface.mac_address,iface.network_id]).map_err(|e| e.to_string())?;
        changes.push(single_change(
            "network_interface",
            &iface.id,
            "create",
            None,
            Some(to_value(&iface)?),
        ));
    }
    record_commit_tx(
        &tx,
        actor,
        &format!("Created asset {}", item.name),
        changes,
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

/// Shorthand for callers (and tests) that have no environment fields to send.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn update_asset(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    network_id: Option<&str>,
    name: &str,
    ip_address: &str,
    mac_address: Option<&str>,
    asset_type: &str,
    os: Option<&str>,
    user_name: Option<&str>,
    compromise_status: &str,
    investigation_status: &str,
    properties: Option<&str>,
    scan_results: Option<&str>,
) -> AppResult<Asset> {
    update_asset_with_context(
        conn,
        actor,
        id,
        network_id,
        name,
        ip_address,
        mac_address,
        asset_type,
        os,
        user_name,
        compromise_status,
        investigation_status,
        properties,
        scan_results,
        &AssetContext::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn update_asset_with_context(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    network_id: Option<&str>,
    name: &str,
    ip_address: &str,
    mac_address: Option<&str>,
    asset_type: &str,
    os: Option<&str>,
    user_name: Option<&str>,
    compromise_status: &str,
    investigation_status: &str,
    properties: Option<&str>,
    scan_results: Option<&str>,
    context: &AssetContext,
) -> AppResult<Asset> {
    validate_required("Asset name", name)?;
    validate_ip(ip_address.trim())?;
    validate_mac(mac_address)?;
    validate_enum("asset type", asset_type, ASSET_TYPES)?;
    validate_enum(
        "compromise status",
        compromise_status,
        &["unknown", "clean", "suspected", "infected"],
    )?;
    validate_enum(
        "investigation status",
        investigation_status,
        &["not_started", "in_progress", "completed"],
    )?;
    validate_optional_json("Scan results", scan_results)?;
    if let Some(network_id) = network_id {
        if !exists(conn, "networks", network_id)? {
            return Err("Selected network was not found".into());
        }
    }
    let before: Asset =
        require_existing(get_assets(conn)?.into_iter().find(|a| a.id == id), "Asset")?;
    // Same re-derivation rule as interfaces: only assets that were never
    // assigned a zone and whose IP is being corrected pick one up; clearing
    // the assignment while keeping the IP stays cleared.
    let (network_id, network_name) = match network_id {
        Some(nid) => {
            let network_name = conn
                .query_row(
                    "SELECT name FROM networks WHERE id=?1",
                    params![nid],
                    |row| row.get(0),
                )
                .optional()
                .ok()
                .flatten();
            (Some(nid.to_string()), network_name)
        }
        None if before.network_id.is_none() && before.ip_address != ip_address.trim() => {
            best_network_for_ip(conn, ip_address.trim())?
                .map_or((None, None), |(nid, name)| (Some(nid), name))
        }
        None => (None, None),
    };
    let mut after = Asset {
        network_id,
        network_name,
        name: name.trim().into(),
        ip_address: ip_address.trim().into(),
        mac_address: mac_address
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        asset_type: asset_type.into(),
        os: os
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        user_name: user_name
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        suspicious: matches!(compromise_status, "suspected" | "infected"),
        compromise_status: compromise_status.into(),
        investigation_status: investigation_status.into(),
        properties: properties
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        scan_results: scan_results
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        ..before.clone()
    };
    apply_asset_context(conn, &mut after, context)?;
    let primary_before = get_network_interfaces(conn, Some(id))?
        .into_iter()
        .find(|v| v.is_primary);
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let changed = tx.execute(
        "UPDATE assets SET network_id=?1,name=?2,ip_address=?3,mac_address=?4,asset_type=?5,os=?6,user_name=?7,suspicious=?8,
         compromise_status=?9,investigation_status=?10,properties=?11,scan_results=?12,site_id=?13,owner=?14,operator=?15,origin=?16,last_observed=?17 WHERE id=?18",
        params![after.network_id,after.name,after.ip_address,after.mac_address,after.asset_type,after.os,after.user_name,
            if after.suspicious {1}else{0},after.compromise_status,after.investigation_status,after.properties,after.scan_results,
            after.site_id,after.owner,after.operator,after.origin,after.last_observed,id]
    ).map_err(|e| e.to_string())?;
    if changed == 0 {
        return Err("Asset was not found".into());
    }
    let mut changes = vec![single_change(
        "asset",
        id,
        "update",
        Some(to_value(&before)?),
        Some(to_value(&after)?),
    )];
    if let Some(mut iface) = primary_before {
        let old = iface.clone();
        iface.network_id = after.network_id.clone();
        iface.network_name = after.network_name.clone();
        iface.ip_address = after.ip_address.clone();
        iface.mac_address = after.mac_address.clone();
        tx.execute(
            "UPDATE network_interfaces SET network_id=?1,ip_address=?2,mac_address=?3 WHERE id=?4",
            params![
                iface.network_id,
                iface.ip_address,
                iface.mac_address,
                iface.id
            ],
        )
        .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "network_interface",
            &iface.id,
            "update",
            Some(to_value(&old)?),
            Some(to_value(&iface)?),
        ));
    } else if after.network_id.is_some() || !after.ip_address.is_empty() {
        let iface = NetworkInterface {
            id: Uuid::new_v4().to_string(),
            asset_id: id.into(),
            name: "Primary".into(),
            ip_address: after.ip_address.clone(),
            mac_address: after.mac_address.clone(),
            network_id: after.network_id.clone(),
            network_name: after.network_name.clone(),
            is_primary: true,
        };
        tx.execute("INSERT INTO network_interfaces(id,asset_id,name,ip_address,mac_address,network_id,is_primary) VALUES (?1,?2,?3,?4,?5,?6,1)",
            params![iface.id,iface.asset_id,iface.name,iface.ip_address,iface.mac_address,iface.network_id]).map_err(|e| e.to_string())?;
        changes.push(single_change(
            "network_interface",
            &iface.id,
            "create",
            None,
            Some(to_value(&iface)?),
        ));
    }
    record_commit_tx(
        &tx,
        actor,
        &format!("Updated asset {}", after.name),
        changes,
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

pub fn update_asset_suspicious(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    suspicious: bool,
) -> AppResult<()> {
    let before = require_existing(get_assets(conn)?.into_iter().find(|a| a.id == id), "Asset")?;
    let status = if suspicious { "suspected" } else { "unknown" };
    let after = Asset {
        suspicious,
        compromise_status: status.into(),
        ..before.clone()
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE assets SET suspicious=?1,compromise_status=?2 WHERE id=?3",
        params![if suspicious { 1 } else { 0 }, status, id],
    )
    .map_err(|e| e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        "Changed asset compromise status",
        vec![single_change(
            "asset",
            id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())
}

/// Sets or clears the per-row investigator remark on an asset, network, or
/// firewall. The note is a column on the entity row itself, so it flows through
/// snapshots, expert merges, and history like any other field.
pub fn set_quick_note(
    conn: &mut Connection,
    actor: &ActorIdentity,
    entity_type: &str,
    id: &str,
    quick_note: Option<&str>,
) -> AppResult<()> {
    let (table, label) = match entity_type {
        "asset" => ("assets", "Asset"),
        "network" => ("networks", "Network"),
        "firewall" => ("firewalls", "Firewall"),
        other => return Err(format!("Quick notes are not supported for {other}s")),
    };
    let note = quick_note
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(String::from);
    let before = require_existing(get_entity_json(conn, entity_type, id)?, label)?;
    let mut after = before.clone();
    after["quick_note"] = note.clone().map(Value::String).unwrap_or(Value::Null);
    let name = before["name"].as_str().unwrap_or_default().to_string();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let changed = tx
        .execute(
            &format!("UPDATE {table} SET quick_note=?1 WHERE id=?2"),
            params![note, id],
        )
        .map_err(|e| e.to_string())?;
    if changed == 0 {
        return Err(format!("{label} was not found"));
    }
    let message = if after["quick_note"].is_null() {
        format!("Cleared quick note on {entity_type} {name}")
    } else {
        format!("Set quick note on {entity_type} {name}")
    };
    record_commit_tx(
        &tx,
        actor,
        &message,
        vec![single_change(
            entity_type,
            id,
            "update",
            Some(before),
            Some(after),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())
}

pub fn delete_asset(conn: &mut Connection, actor: &ActorIdentity, id: &str) -> AppResult<()> {
    let asset = require_existing(get_entity_json(conn, "asset", id)?, "Asset")?;
    let interfaces = get_network_interfaces(conn, Some(id))?;
    let events: Vec<TimelineEvent> = get_timeline_events(conn)?
        .into_iter()
        .filter(|e| e.asset_id.as_deref() == Some(id))
        .collect();
    let sightings = get_ioc_sightings(conn, None, Some("asset"), Some(id))?;
    let attack_edges: Vec<AttackEdge> = get_attack_edges(conn)?
        .into_iter()
        .filter(|edge| {
            (edge.source_kind == "asset" && edge.source_id == id)
                || (edge.target_kind == "asset" && edge.target_id == id)
        })
        .collect();
    let relations: Vec<AssetRelation> = get_asset_relations(conn)?
        .into_iter()
        .filter(|relation| relation.source_asset_id == id || relation.target_asset_id == id)
        .collect();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut changes = Vec::new();
    for relation in relations {
        tx.execute(
            "DELETE FROM asset_relations WHERE id=?1",
            params![relation.id],
        )
        .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "asset_relation",
            &relation.id,
            "delete",
            Some(to_value(&relation)?),
            None,
        ));
    }
    for sighting in sightings {
        tx.execute(
            "DELETE FROM ioc_sightings WHERE id=?1",
            params![sighting.id],
        )
        .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "ioc_sighting",
            &sighting.id,
            "delete",
            Some(to_value(&sighting)?),
            None,
        ));
    }
    for edge in attack_edges {
        tx.execute("DELETE FROM attack_edges WHERE id=?1", params![edge.id])
            .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "attack_edge",
            &edge.id,
            "delete",
            Some(to_value(&edge)?),
            None,
        ));
    }
    for event in events {
        let before = event.clone();
        let after = TimelineEvent {
            asset_id: None,
            asset_name: None,
            ..event
        };
        tx.execute(
            "UPDATE timeline_events SET asset_id=NULL WHERE id=?1",
            params![after.id],
        )
        .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "timeline_event",
            &after.id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        ));
    }
    for iface in interfaces {
        tx.execute(
            "DELETE FROM network_interfaces WHERE id=?1",
            params![iface.id],
        )
        .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "network_interface",
            &iface.id,
            "delete",
            Some(to_value(&iface)?),
            None,
        ));
    }
    let changed = tx
        .execute("DELETE FROM assets WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?;
    if changed == 0 {
        return Err("Asset was not found".into());
    }
    changes.push(single_change("asset", id, "delete", Some(asset), None));
    record_commit_tx(&tx, actor, "Deleted asset", changes, &[])?;
    tx.commit().map_err(|e| e.to_string())
}

#[allow(clippy::too_many_arguments)]
pub fn create_network_interface(
    conn: &mut Connection,
    actor: &ActorIdentity,
    asset_id: &str,
    name: &str,
    ip_address: &str,
    mac_address: Option<&str>,
    network_id: Option<&str>,
    is_primary: bool,
) -> AppResult<NetworkInterface> {
    validate_required("Interface name", name)?;
    validate_ip(ip_address.trim())?;
    validate_mac(mac_address)?;
    if !exists(conn, "assets", asset_id)? {
        return Err("Asset was not found".into());
    }
    // An interface recorded without a zone follows its IP: if a subnet
    // covering the address already exists, join it so endpoints grouped here
    // never dangle when their subnet is added later. Explicit choices always
    // win; unassigned interfaces are also backfilled when the subnet itself
    // is created or edited.
    let (network_id, network_name) = match network_id {
        Some(nid) => {
            if !exists(conn, "networks", nid)? {
                return Err("Selected network was not found".into());
            }
            let network_name = conn
                .query_row(
                    "SELECT name FROM networks WHERE id=?1",
                    params![nid],
                    |row| row.get(0),
                )
                .optional()
                .ok()
                .flatten();
            (Some(nid.to_string()), network_name)
        }
        None => best_network_for_ip(conn, ip_address.trim())?
            .map_or((None, None), |(id, name)| (Some(id), name)),
    };
    let item = NetworkInterface {
        id: Uuid::new_v4().to_string(),
        asset_id: asset_id.into(),
        name: name.trim().into(),
        ip_address: ip_address.trim().into(),
        mac_address: mac_address
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        network_id,
        network_name,
        is_primary,
    };
    let old_primary = if is_primary {
        get_network_interfaces(conn, Some(asset_id))?
            .into_iter()
            .find(|v| v.is_primary)
    } else {
        None
    };
    let asset_before = if is_primary {
        get_assets(conn)?.into_iter().find(|a| a.id == asset_id)
    } else {
        None
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut changes = Vec::new();
    if let Some(mut old) = old_primary {
        let before = old.clone();
        old.is_primary = false;
        tx.execute(
            "UPDATE network_interfaces SET is_primary=0 WHERE id=?1",
            params![old.id],
        )
        .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "network_interface",
            &old.id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&old)?),
        ));
    }
    tx.execute("INSERT INTO network_interfaces(id,asset_id,name,ip_address,mac_address,network_id,is_primary) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![item.id,item.asset_id,item.name,item.ip_address,item.mac_address,item.network_id,if item.is_primary {1}else{0}]).map_err(|e| e.to_string())?;
    changes.push(single_change(
        "network_interface",
        &item.id,
        "create",
        None,
        Some(to_value(&item)?),
    ));
    if let Some(before) = asset_before {
        tx.execute(
            "UPDATE assets SET network_id=?1,ip_address=?2,mac_address=?3 WHERE id=?4",
            params![item.network_id, item.ip_address, item.mac_address, asset_id],
        )
        .map_err(|e| e.to_string())?;
        let after = Asset {
            network_id: item.network_id.clone(),
            network_name: item.network_name.clone(),
            ip_address: item.ip_address.clone(),
            mac_address: item.mac_address.clone(),
            ..before.clone()
        };
        changes.push(single_change(
            "asset",
            asset_id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        ));
    }
    record_commit_tx(
        &tx,
        actor,
        &format!("Added interface {}", item.name),
        changes,
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

#[allow(clippy::too_many_arguments)]
pub fn update_network_interface(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    name: &str,
    ip_address: &str,
    mac_address: Option<&str>,
    network_id: Option<&str>,
    is_primary: bool,
) -> AppResult<NetworkInterface> {
    validate_required("Interface name", name)?;
    validate_ip(ip_address.trim())?;
    validate_mac(mac_address)?;
    if let Some(nid) = network_id {
        if !exists(conn, "networks", nid)? {
            return Err("Selected network was not found".into());
        }
    }
    let before = require_existing(
        get_network_interfaces(conn, None)?
            .into_iter()
            .find(|v| v.id == id),
        "Interface",
    )?;
    // Re-derive the zone from the IP only for interfaces that were never
    // assigned and whose address is being corrected; clearing the assignment
    // while keeping the IP is a deliberate detach and must stick.
    let (network_id, network_name) = match network_id {
        Some(nid) => {
            let network_name = conn
                .query_row(
                    "SELECT name FROM networks WHERE id=?1",
                    params![nid],
                    |row| row.get(0),
                )
                .optional()
                .ok()
                .flatten();
            (Some(nid.to_string()), network_name)
        }
        None if before.network_id.is_none() && before.ip_address != ip_address.trim() => {
            best_network_for_ip(conn, ip_address.trim())?
                .map_or((None, None), |(id, name)| (Some(id), name))
        }
        None => (None, None),
    };
    let after = NetworkInterface {
        name: name.trim().into(),
        ip_address: ip_address.trim().into(),
        mac_address: mac_address
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        network_id,
        network_name,
        is_primary,
        ..before.clone()
    };
    let prior_primary = if is_primary {
        get_network_interfaces(conn, Some(&before.asset_id))?
            .into_iter()
            .find(|v| v.is_primary && v.id != id)
    } else {
        None
    };
    let asset_before = if is_primary || before.is_primary {
        get_assets(conn)?
            .into_iter()
            .find(|a| a.id == before.asset_id)
    } else {
        None
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut changes = Vec::new();
    if let Some(mut old) = prior_primary {
        let old_before = old.clone();
        old.is_primary = false;
        tx.execute(
            "UPDATE network_interfaces SET is_primary=0 WHERE id=?1",
            params![old.id],
        )
        .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "network_interface",
            &old.id,
            "update",
            Some(to_value(&old_before)?),
            Some(to_value(&old)?),
        ));
    }
    tx.execute("UPDATE network_interfaces SET name=?1,ip_address=?2,mac_address=?3,network_id=?4,is_primary=?5 WHERE id=?6",
        params![after.name,after.ip_address,after.mac_address,after.network_id,if after.is_primary {1}else{0},id]).map_err(|e| e.to_string())?;
    changes.push(single_change(
        "network_interface",
        id,
        "update",
        Some(to_value(&before)?),
        Some(to_value(&after)?),
    ));
    if let Some(asset_before) = asset_before {
        let replacement = if after.is_primary {
            Some(after.clone())
        } else {
            get_network_interfaces(&tx, Some(&before.asset_id))?
                .into_iter()
                .find(|v| v.is_primary)
        };
        let (nid, nname, ip, mac) = replacement
            .map(|v| (v.network_id, v.network_name, v.ip_address, v.mac_address))
            .unwrap_or((None, None, String::new(), None));
        tx.execute(
            "UPDATE assets SET network_id=?1,ip_address=?2,mac_address=?3 WHERE id=?4",
            params![nid, ip, mac, before.asset_id],
        )
        .map_err(|e| e.to_string())?;
        let asset_after = Asset {
            network_id: nid,
            network_name: nname,
            ip_address: ip,
            mac_address: mac,
            ..asset_before.clone()
        };
        changes.push(single_change(
            "asset",
            &before.asset_id,
            "update",
            Some(to_value(&asset_before)?),
            Some(to_value(&asset_after)?),
        ));
    }
    record_commit_tx(
        &tx,
        actor,
        &format!("Updated interface {}", after.name),
        changes,
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

pub fn set_primary_interface(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
) -> AppResult<NetworkInterface> {
    let iface = require_existing(
        get_network_interfaces(conn, None)?
            .into_iter()
            .find(|v| v.id == id),
        "Interface",
    )?;
    update_network_interface(
        conn,
        actor,
        id,
        &iface.name,
        &iface.ip_address,
        iface.mac_address.as_deref(),
        iface.network_id.as_deref(),
        true,
    )
}

pub fn delete_network_interface(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
) -> AppResult<()> {
    let before = require_existing(
        get_network_interfaces(conn, None)?
            .into_iter()
            .find(|v| v.id == id),
        "Interface",
    )?;
    let asset_before = get_assets(conn)?
        .into_iter()
        .find(|a| a.id == before.asset_id);
    let replacement = if before.is_primary {
        get_network_interfaces(conn, Some(&before.asset_id))?
            .into_iter()
            .find(|v| v.id != id)
    } else {
        None
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut changes = vec![single_change(
        "network_interface",
        id,
        "delete",
        Some(to_value(&before)?),
        None,
    )];
    tx.execute("DELETE FROM network_interfaces WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?;
    if before.is_primary {
        if let Some(mut next) = replacement {
            let next_before = next.clone();
            next.is_primary = true;
            tx.execute(
                "UPDATE network_interfaces SET is_primary=1 WHERE id=?1",
                params![next.id],
            )
            .map_err(|e| e.to_string())?;
            changes.push(single_change(
                "network_interface",
                &next.id,
                "update",
                Some(to_value(&next_before)?),
                Some(to_value(&next)?),
            ));
            tx.execute(
                "UPDATE assets SET network_id=?1,ip_address=?2,mac_address=?3 WHERE id=?4",
                params![
                    next.network_id,
                    next.ip_address,
                    next.mac_address,
                    before.asset_id
                ],
            )
            .map_err(|e| e.to_string())?;
            if let Some(asset_before) = asset_before {
                let asset_after = Asset {
                    network_id: next.network_id,
                    network_name: next.network_name,
                    ip_address: next.ip_address,
                    mac_address: next.mac_address,
                    ..asset_before.clone()
                };
                changes.push(single_change(
                    "asset",
                    &before.asset_id,
                    "update",
                    Some(to_value(&asset_before)?),
                    Some(to_value(&asset_after)?),
                ));
            }
        } else {
            tx.execute(
                "UPDATE assets SET network_id=NULL,ip_address='',mac_address=NULL WHERE id=?1",
                params![before.asset_id],
            )
            .map_err(|e| e.to_string())?;
            if let Some(asset_before) = asset_before {
                let asset_after = Asset {
                    network_id: None,
                    network_name: None,
                    ip_address: String::new(),
                    mac_address: None,
                    ..asset_before.clone()
                };
                changes.push(single_change(
                    "asset",
                    &before.asset_id,
                    "update",
                    Some(to_value(&asset_before)?),
                    Some(to_value(&asset_after)?),
                ));
            }
        }
    }
    record_commit_tx(&tx, actor, "Deleted network interface", changes, &[])?;
    tx.commit().map_err(|e| e.to_string())
}

#[allow(clippy::too_many_arguments)]
pub fn create_clock_profile(
    conn: &mut Connection,
    actor: &ActorIdentity,
    name: &str,
    description: &str,
    server_reference_raw: &str,
    server_timezone: &str,
    correct_reference_raw: &str,
    correct_timezone: &str,
) -> AppResult<ClockProfile> {
    validate_required("Clock profile name", name)?;
    let server = parse_timestamp_preview(server_reference_raw, server_timezone, 0)?;
    let correct = parse_timestamp_preview(correct_reference_raw, correct_timezone, 0)?;
    let offset_ms = correct
        .epoch_millis
        .checked_sub(server.epoch_millis)
        .ok_or_else(|| "Clock offset is outside the supported range".to_string())?;
    let now = format_utc(Utc::now());
    let item = ClockProfile {
        id: Uuid::new_v4().to_string(),
        name: name.trim().to_string(),
        description: description.trim().to_string(),
        server_reference_raw: server_reference_raw.trim().to_string(),
        server_timezone: server_timezone.trim().to_string(),
        server_reference_utc: server.interpreted_utc,
        correct_reference_raw: correct_reference_raw.trim().to_string(),
        correct_timezone: correct_timezone.trim().to_string(),
        correct_reference_utc: correct.interpreted_utc,
        offset_ms,
        created_at: now.clone(),
        updated_at: now,
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO clock_profiles
         (id,name,description,server_reference_raw,server_timezone,server_reference_utc,
          correct_reference_raw,correct_timezone,correct_reference_utc,offset_ms,created_at,updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![item.id,item.name,item.description,item.server_reference_raw,item.server_timezone,
                item.server_reference_utc,item.correct_reference_raw,item.correct_timezone,
                item.correct_reference_utc,item.offset_ms,item.created_at,item.updated_at],
    )
    .map_err(|e| e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        "Created server clock profile",
        vec![single_change(
            "clock_profile",
            &item.id,
            "create",
            None,
            Some(to_value(&item)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

#[allow(clippy::too_many_arguments)]
pub fn update_clock_profile(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    name: &str,
    description: &str,
    server_reference_raw: &str,
    server_timezone: &str,
    correct_reference_raw: &str,
    correct_timezone: &str,
) -> AppResult<ClockProfile> {
    let before = require_existing(
        get_clock_profiles(conn)?
            .into_iter()
            .find(|item| item.id == id),
        "Clock profile",
    )?;
    validate_required("Clock profile name", name)?;
    let server = parse_timestamp_preview(server_reference_raw, server_timezone, 0)?;
    let correct = parse_timestamp_preview(correct_reference_raw, correct_timezone, 0)?;
    let offset_ms = correct
        .epoch_millis
        .checked_sub(server.epoch_millis)
        .ok_or_else(|| "Clock offset is outside the supported range".to_string())?;
    let after = ClockProfile {
        name: name.trim().to_string(),
        description: description.trim().to_string(),
        server_reference_raw: server_reference_raw.trim().to_string(),
        server_timezone: server_timezone.trim().to_string(),
        server_reference_utc: server.interpreted_utc,
        correct_reference_raw: correct_reference_raw.trim().to_string(),
        correct_timezone: correct_timezone.trim().to_string(),
        correct_reference_utc: correct.interpreted_utc,
        offset_ms,
        updated_at: format_utc(Utc::now()),
        ..before.clone()
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let changed = tx.execute(
        "UPDATE clock_profiles SET name=?1,description=?2,server_reference_raw=?3,server_timezone=?4,
         server_reference_utc=?5,correct_reference_raw=?6,correct_timezone=?7,correct_reference_utc=?8,
         offset_ms=?9,updated_at=?10 WHERE id=?11",
        params![after.name,after.description,after.server_reference_raw,after.server_timezone,
                after.server_reference_utc,after.correct_reference_raw,after.correct_timezone,
                after.correct_reference_utc,after.offset_ms,after.updated_at,id],
    ).map_err(|e| e.to_string())?;
    if changed == 0 {
        return Err("Clock profile was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Updated server clock profile",
        vec![single_change(
            "clock_profile",
            id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

pub fn delete_clock_profile(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
) -> AppResult<()> {
    let before = require_existing(get_entity_json(conn, "clock_profile", id)?, "Clock profile")?;
    let references: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM timeline_events WHERE clock_profile_id=?1",
            params![id],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if references > 0 {
        return Err(format!("Clock profile is used by {references} timeline event(s). Reassign those events before deleting it."));
    }
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx
        .execute("DELETE FROM clock_profiles WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Clock profile was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Deleted server clock profile",
        vec![single_change(
            "clock_profile",
            id,
            "delete",
            Some(before),
            None,
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())
}

struct ResolvedEventTimes {
    timestamp: String,
    raw_timestamp: Option<String>,
    raw_timezone: Option<String>,
    server_timestamp_utc: Option<String>,
    correct_timestamp_raw: Option<String>,
    correct_timezone: Option<String>,
    clock_profile_id: Option<String>,
    clock_profile_name: Option<String>,
    clock_offset_ms: i64,
    time_precision: String,
    correct_time_precision: String,
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn resolve_event_times(
    conn: &Connection,
    server_timestamp: Option<&str>,
    server_timezone: Option<&str>,
    correct_timestamp: Option<&str>,
    correct_timezone: Option<&str>,
    clock_profile_id: Option<&str>,
) -> AppResult<ResolvedEventTimes> {
    let server_raw = nonempty(server_timestamp);
    let correct_raw = nonempty(correct_timestamp);
    let profile_id = nonempty(clock_profile_id);
    if correct_raw.is_some() && profile_id.is_some() {
        return Err(
            "Use either a directly entered real time or a saved clock profile, not both".into(),
        );
    }
    if profile_id.is_some() && server_raw.is_none() {
        return Err("A saved clock profile requires a server/evidence timestamp".into());
    }

    let server_zone = nonempty(server_timezone).unwrap_or("UTC");
    let correct_zone = nonempty(correct_timezone).unwrap_or("UTC");
    let server = server_raw
        .map(|value| parse_timestamp_preview(value, server_zone, 0))
        .transpose()?;
    let direct_correct = correct_raw
        .map(|value| parse_timestamp_preview(value, correct_zone, 0))
        .transpose()?;
    let profile = profile_id
        .map(|id| {
            get_clock_profiles(conn)?
                .into_iter()
                .find(|item| item.id == id)
                .ok_or_else(|| "Selected clock profile was not found".to_string())
        })
        .transpose()?;

    let (timestamp, offset_ms, correct_precision) = if let Some(correct) = &direct_correct {
        let offset = server
            .as_ref()
            .map(|server| {
                correct
                    .epoch_millis
                    .checked_sub(server.epoch_millis)
                    .ok_or_else(|| {
                        "Direct clock correction is outside the supported range".to_string()
                    })
            })
            .transpose()?
            .unwrap_or(0);
        (
            correct.interpreted_utc.clone(),
            offset,
            correct.precision.clone(),
        )
    } else if let (Some(server), Some(profile)) = (&server, &profile) {
        let corrected = parse_timestamp_preview(
            server_raw.unwrap_or_default(),
            server_zone,
            profile.offset_ms,
        )?;
        (
            corrected.corrected_utc,
            profile.offset_ms,
            server.precision.clone(),
        )
    } else {
        (String::new(), 0, "unknown".to_string())
    };

    Ok(ResolvedEventTimes {
        timestamp,
        raw_timestamp: server_raw.map(str::to_string),
        raw_timezone: server_raw.map(|_| server_zone.to_string()),
        server_timestamp_utc: server.as_ref().map(|value| value.interpreted_utc.clone()),
        correct_timestamp_raw: correct_raw.map(str::to_string),
        correct_timezone: correct_raw.map(|_| correct_zone.to_string()),
        clock_profile_id: profile.as_ref().map(|item| item.id.clone()),
        clock_profile_name: profile.as_ref().map(|item| item.name.clone()),
        clock_offset_ms: offset_ms,
        time_precision: server
            .as_ref()
            .map(|value| value.precision.clone())
            .unwrap_or_else(default_unknown_time_precision),
        correct_time_precision: correct_precision,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn create_timeline_event(
    conn: &mut Connection,
    actor: &ActorIdentity,
    asset_id: Option<&str>,
    server_timestamp: Option<&str>,
    server_timezone: Option<&str>,
    correct_timestamp: Option<&str>,
    correct_timezone: Option<&str>,
    clock_profile_id: Option<&str>,
    event_type: &str,
    description: &str,
    severity: &str,
    source: Option<&str>,
    mitre_tactic: Option<&str>,
    mitre_technique: Option<&str>,
) -> AppResult<TimelineEvent> {
    create_timeline_event_with_source(
        conn,
        actor,
        asset_id,
        server_timestamp,
        server_timezone,
        correct_timestamp,
        correct_timezone,
        clock_profile_id,
        event_type,
        description,
        severity,
        source,
        mitre_tactic,
        mitre_technique,
        None,
    )
}

/// `create_timeline_event` plus a structured reference to the evidence the
/// event was promoted from (see `TimelineEvent::source_ref`).
#[allow(clippy::too_many_arguments)]
pub fn create_timeline_event_with_source(
    conn: &mut Connection,
    actor: &ActorIdentity,
    asset_id: Option<&str>,
    server_timestamp: Option<&str>,
    server_timezone: Option<&str>,
    correct_timestamp: Option<&str>,
    correct_timezone: Option<&str>,
    clock_profile_id: Option<&str>,
    event_type: &str,
    description: &str,
    severity: &str,
    source: Option<&str>,
    mitre_tactic: Option<&str>,
    mitre_technique: Option<&str>,
    source_ref: Option<Value>,
) -> AppResult<TimelineEvent> {
    let times = resolve_event_times(
        conn,
        server_timestamp,
        server_timezone,
        correct_timestamp,
        correct_timezone,
        clock_profile_id,
    )?;
    validate_required("Event type", event_type)?;
    validate_required("Event description", description)?;
    validate_enum(
        "severity",
        severity,
        &["info", "low", "medium", "high", "critical"],
    )?;
    if let Some(aid) = asset_id {
        if !exists(conn, "assets", aid)? {
            return Err("Selected asset was not found".into());
        }
    }
    let asset_name = asset_id.and_then(|aid| {
        conn.query_row("SELECT name FROM assets WHERE id=?1", params![aid], |r| {
            r.get(0)
        })
        .optional()
        .ok()
        .flatten()
    });
    let item = TimelineEvent {
        source_ref: source_ref.filter(|value| !value.is_null()),
        id: Uuid::new_v4().to_string(),
        asset_id: asset_id.map(String::from),
        asset_name,
        timestamp: times.timestamp,
        raw_timestamp: times.raw_timestamp,
        raw_timezone: times.raw_timezone,
        server_timestamp_utc: times.server_timestamp_utc,
        correct_timestamp_raw: times.correct_timestamp_raw,
        correct_timezone: times.correct_timezone,
        clock_profile_id: times.clock_profile_id,
        clock_profile_name: times.clock_profile_name,
        clock_offset_ms: times.clock_offset_ms,
        time_precision: times.time_precision,
        correct_time_precision: times.correct_time_precision,
        event_type: event_type.into(),
        description: description.trim().into(),
        severity: severity.into(),
        source: source
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        mitre_tactic: mitre_tactic
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        mitre_technique: mitre_technique
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        created_at: Utc::now().to_rfc3339(),
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let source_ref_text = json_value_text(&item.source_ref)?;
    tx.execute("INSERT INTO timeline_events(id,asset_id,timestamp,raw_timestamp,raw_timezone,server_timestamp_utc,correct_timestamp_raw,correct_timezone,clock_profile_id,clock_offset_ms,time_precision,correct_time_precision,event_type,description,severity,source,mitre_tactic,mitre_technique,created_at,source_ref) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
        params![item.id,item.asset_id,item.timestamp,item.raw_timestamp,item.raw_timezone,item.server_timestamp_utc,item.correct_timestamp_raw,item.correct_timezone,item.clock_profile_id,item.clock_offset_ms,item.time_precision,item.correct_time_precision,item.event_type,item.description,item.severity,item.source,item.mitre_tactic,item.mitre_technique,item.created_at,source_ref_text]).map_err(|e|e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        "Created timeline event",
        vec![single_change(
            "timeline_event",
            &item.id,
            "create",
            None,
            Some(to_value(&item)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

#[allow(clippy::too_many_arguments)]
pub fn update_timeline_event(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    asset_id: Option<&str>,
    server_timestamp: Option<&str>,
    server_timezone: Option<&str>,
    correct_timestamp: Option<&str>,
    correct_timezone: Option<&str>,
    clock_profile_id: Option<&str>,
    event_type: &str,
    description: &str,
    severity: &str,
    source: Option<&str>,
    mitre_tactic: Option<&str>,
    mitre_technique: Option<&str>,
) -> AppResult<TimelineEvent> {
    let times = resolve_event_times(
        conn,
        server_timestamp,
        server_timezone,
        correct_timestamp,
        correct_timezone,
        clock_profile_id,
    )?;
    validate_required("Event type", event_type)?;
    validate_required("Event description", description)?;
    validate_enum(
        "severity",
        severity,
        &["info", "low", "medium", "high", "critical"],
    )?;
    if let Some(aid) = asset_id {
        if !exists(conn, "assets", aid)? {
            return Err("Selected asset was not found".into());
        }
    }
    let before = require_existing(
        get_timeline_events(conn)?.into_iter().find(|v| v.id == id),
        "Timeline event",
    )?;
    let asset_name = asset_id.and_then(|aid| {
        conn.query_row("SELECT name FROM assets WHERE id=?1", params![aid], |r| {
            r.get(0)
        })
        .optional()
        .ok()
        .flatten()
    });
    let after = TimelineEvent {
        asset_id: asset_id.map(String::from),
        asset_name,
        timestamp: times.timestamp,
        raw_timestamp: times.raw_timestamp,
        raw_timezone: times.raw_timezone,
        server_timestamp_utc: times.server_timestamp_utc,
        correct_timestamp_raw: times.correct_timestamp_raw,
        correct_timezone: times.correct_timezone,
        clock_profile_id: times.clock_profile_id,
        clock_profile_name: times.clock_profile_name,
        clock_offset_ms: times.clock_offset_ms,
        time_precision: times.time_precision,
        correct_time_precision: times.correct_time_precision,
        event_type: event_type.into(),
        description: description.trim().into(),
        severity: severity.into(),
        source: source
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        mitre_tactic: mitre_tactic
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        mitre_technique: mitre_technique
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        ..before.clone()
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let changed=tx.execute("UPDATE timeline_events SET asset_id=?1,timestamp=?2,raw_timestamp=?3,raw_timezone=?4,server_timestamp_utc=?5,correct_timestamp_raw=?6,correct_timezone=?7,clock_profile_id=?8,clock_offset_ms=?9,time_precision=?10,correct_time_precision=?11,event_type=?12,description=?13,severity=?14,source=?15,mitre_tactic=?16,mitre_technique=?17 WHERE id=?18",
        params![after.asset_id,after.timestamp,after.raw_timestamp,after.raw_timezone,after.server_timestamp_utc,after.correct_timestamp_raw,after.correct_timezone,after.clock_profile_id,after.clock_offset_ms,after.time_precision,after.correct_time_precision,after.event_type,after.description,after.severity,after.source,after.mitre_tactic,after.mitre_technique,id]).map_err(|e|e.to_string())?;
    if changed == 0 {
        return Err("Timeline event was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Updated timeline event",
        vec![single_change(
            "timeline_event",
            id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

pub fn delete_timeline_event(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
) -> AppResult<()> {
    let before = require_existing(
        get_entity_json(conn, "timeline_event", id)?,
        "Timeline event",
    )?;
    let linked_edges: Vec<AttackEdge> = get_attack_edges(conn)?
        .into_iter()
        .filter(|edge| edge.timeline_event_id.as_deref() == Some(id))
        .collect();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut changes = Vec::new();
    for edge in linked_edges {
        let mut after = edge.clone();
        after.timeline_event_id = None;
        after.timeline_event_time = None;
        tx.execute(
            "UPDATE attack_edges SET timeline_event_id=NULL WHERE id=?1",
            params![edge.id],
        )
        .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "attack_edge",
            &edge.id,
            "update",
            Some(to_value(&edge)?),
            Some(to_value(&after)?),
        ));
    }
    if tx
        .execute("DELETE FROM timeline_events WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Timeline event was not found".into());
    }
    changes.push(single_change(
        "timeline_event",
        id,
        "delete",
        Some(before),
        None,
    ));
    record_commit_tx(&tx, actor, "Deleted timeline event", changes, &[])?;
    tx.commit().map_err(|e| e.to_string())
}

pub fn create_note(
    conn: &mut Connection,
    actor: &ActorIdentity,
    title: &str,
    content: &str,
) -> AppResult<Note> {
    validate_required("Note title", title)?;
    let now = Utc::now().to_rfc3339();
    let item = Note {
        id: Uuid::new_v4().to_string(),
        title: title.trim().into(),
        content: content.into(),
        created_at: now.clone(),
        updated_at: now,
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO notes(id,title,content,created_at,updated_at) VALUES (?1,?2,?3,?4,?5)",
        params![
            item.id,
            item.title,
            item.content,
            item.created_at,
            item.updated_at
        ],
    )
    .map_err(|e| e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        "Created note",
        vec![single_change(
            "note",
            &item.id,
            "create",
            None,
            Some(to_value(&item)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

pub fn update_note(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    title: &str,
    content: &str,
) -> AppResult<Note> {
    validate_required("Note title", title)?;
    let before = require_existing(get_notes(conn)?.into_iter().find(|v| v.id == id), "Note")?;
    let after = Note {
        title: title.trim().into(),
        content: content.into(),
        updated_at: Utc::now().to_rfc3339(),
        ..before.clone()
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx
        .execute(
            "UPDATE notes SET title=?1,content=?2,updated_at=?3 WHERE id=?4",
            params![after.title, after.content, after.updated_at, id],
        )
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Note was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Updated note",
        vec![single_change(
            "note",
            id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

pub fn delete_note(conn: &mut Connection, actor: &ActorIdentity, id: &str) -> AppResult<()> {
    let before = require_existing(get_entity_json(conn, "note", id)?, "Note")?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx
        .execute("DELETE FROM notes WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Note was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Deleted note",
        vec![single_change("note", id, "delete", Some(before), None)],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())
}

#[allow(clippy::too_many_arguments)]
pub fn create_ioc(
    conn: &mut Connection,
    actor: &ActorIdentity,
    ioc_type: &str,
    value: &str,
    description: &str,
    threat_level: &str,
    first_seen: Option<&str>,
    last_seen: Option<&str>,
) -> AppResult<Ioc> {
    validate_required("IOC value", value)?;
    validate_ioc_value(ioc_type, value)?;
    validate_enum(
        "threat level",
        threat_level,
        &["low", "medium", "high", "critical"],
    )?;
    let first_seen = first_seen
        .map(|value| normalize_timestamp("First seen", value))
        .transpose()?;
    let last_seen = last_seen
        .map(|value| normalize_timestamp("Last seen", value))
        .transpose()?;
    if let (Some(first), Some(last)) = (&first_seen, &last_seen) {
        if chrono::DateTime::parse_from_rfc3339(last).map_err(|e| e.to_string())?
            < chrono::DateTime::parse_from_rfc3339(first).map_err(|e| e.to_string())?
        {
            return Err("Last seen cannot be before first seen".into());
        }
    }
    let item = Ioc {
        id: Uuid::new_v4().to_string(),
        ioc_type: ioc_type.into(),
        value: value.trim().into(),
        description: description.trim().into(),
        threat_level: threat_level.into(),
        first_seen,
        last_seen,
        created_at: Utc::now().to_rfc3339(),
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("INSERT INTO iocs(id,ioc_type,value,description,threat_level,first_seen,last_seen,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![item.id,item.ioc_type,item.value,item.description,item.threat_level,item.first_seen,item.last_seen,item.created_at]).map_err(|e|e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        "Created IOC",
        vec![single_change(
            "ioc",
            &item.id,
            "create",
            None,
            Some(to_value(&item)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

#[allow(clippy::too_many_arguments)]
pub fn update_ioc(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    ioc_type: &str,
    value: &str,
    description: &str,
    threat_level: &str,
    first_seen: Option<&str>,
    last_seen: Option<&str>,
) -> AppResult<Ioc> {
    validate_required("IOC value", value)?;
    validate_ioc_value(ioc_type, value)?;
    validate_enum(
        "threat level",
        threat_level,
        &["low", "medium", "high", "critical"],
    )?;
    let first_seen = first_seen
        .map(|value| normalize_timestamp("First seen", value))
        .transpose()?;
    let last_seen = last_seen
        .map(|value| normalize_timestamp("Last seen", value))
        .transpose()?;
    if let (Some(first), Some(last)) = (&first_seen, &last_seen) {
        if chrono::DateTime::parse_from_rfc3339(last).map_err(|e| e.to_string())?
            < chrono::DateTime::parse_from_rfc3339(first).map_err(|e| e.to_string())?
        {
            return Err("Last seen cannot be before first seen".into());
        }
    }
    let before = require_existing(get_iocs(conn)?.into_iter().find(|v| v.id == id), "IOC")?;
    let after = Ioc {
        ioc_type: ioc_type.into(),
        value: value.trim().into(),
        description: description.trim().into(),
        threat_level: threat_level.into(),
        first_seen,
        last_seen,
        ..before.clone()
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx.execute("UPDATE iocs SET ioc_type=?1,value=?2,description=?3,threat_level=?4,first_seen=?5,last_seen=?6 WHERE id=?7",params![after.ioc_type,after.value,after.description,after.threat_level,after.first_seen,after.last_seen,id]).map_err(|e|e.to_string())?==0{return Err("IOC was not found".into());}
    record_commit_tx(
        &tx,
        actor,
        "Updated IOC",
        vec![single_change(
            "ioc",
            id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

pub fn delete_ioc(conn: &mut Connection, actor: &ActorIdentity, id: &str) -> AppResult<()> {
    let before = require_existing(get_entity_json(conn, "ioc", id)?, "IOC")?;
    let sightings = get_ioc_sightings(conn, Some(id), None, None)?;
    let linked_edges: Vec<AttackEdge> = get_attack_edges(conn)?
        .into_iter()
        .filter(|edge| edge.ioc_ids.iter().any(|linked| linked == id))
        .collect();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut changes = Vec::new();
    for sighting in sightings {
        tx.execute(
            "DELETE FROM ioc_sightings WHERE id=?1",
            params![sighting.id],
        )
        .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "ioc_sighting",
            &sighting.id,
            "delete",
            Some(to_value(&sighting)?),
            None,
        ));
    }
    for edge in linked_edges {
        let mut after = edge.clone();
        after.ioc_ids.retain(|linked| linked != id);
        tx.execute(
            "UPDATE attack_edges SET ioc_ids=?1 WHERE id=?2",
            params![
                serde_json::to_string(&after.ioc_ids).map_err(|e| e.to_string())?,
                after.id
            ],
        )
        .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "attack_edge",
            &edge.id,
            "update",
            Some(to_value(&edge)?),
            Some(to_value(&after)?),
        ));
    }
    if tx
        .execute("DELETE FROM iocs WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("IOC was not found".into());
    }
    changes.push(single_change("ioc", id, "delete", Some(before), None));
    record_commit_tx(&tx, actor, "Deleted IOC", changes, &[])?;
    tx.commit().map_err(|e| e.to_string())
}

pub fn create_ioc_sighting(
    conn: &mut Connection,
    actor: &ActorIdentity,
    ioc_id: &str,
    entity_kind: &str,
    entity_id: &str,
    sighted_at: Option<&str>,
    location: &str,
    note: &str,
    set_compromise_status: Option<&str>,
) -> AppResult<IocSighting> {
    validate_enum("entity kind", entity_kind, SIGHTING_ENTITY_KINDS)?;
    if !exists(conn, "iocs", ioc_id)? {
        return Err("Referenced IOC was not found".into());
    }
    verify_graph_entity_ref(conn, entity_kind, entity_id)?;
    let sighted_at = sighted_at
        .map(|value| normalize_timestamp("Sighted at", value))
        .transpose()?;
    if let Some(status) = set_compromise_status {
        validate_enum("compromise status", status, &["suspected", "infected"])?;
        if entity_kind != "asset" {
            return Err("Compromise status can only be raised on assets".into());
        }
    }
    let id = Uuid::new_v4().to_string();
    let created_at = Utc::now().to_rfc3339();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO ioc_sightings(id,ioc_id,asset_id,network_id,firewall_id,sighted_at,location,note,created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            id,
            ioc_id,
            (entity_kind == "asset").then_some(entity_id),
            (entity_kind == "network").then_some(entity_id),
            (entity_kind == "firewall").then_some(entity_id),
            sighted_at,
            location.trim(),
            note.trim(),
            created_at
        ],
    )
    .map_err(|e| e.to_string())?;
    let item: IocSighting = serde_json::from_value(require_existing(
        get_entity_json(&tx, "ioc_sighting", &id)?,
        "IOC sighting",
    )?)
    .map_err(|e| e.to_string())?;
    let mut changes = vec![single_change(
        "ioc_sighting",
        &id,
        "create",
        None,
        Some(to_value(&item)?),
    )];
    let mut message = "Recorded IOC sighting".to_string();
    if let Some(status) = set_compromise_status {
        let asset_value = require_existing(get_entity_json(&tx, "asset", entity_id)?, "Asset")?;
        let asset: Asset = serde_json::from_value(asset_value).map_err(|e| e.to_string())?;
        if compromise_rank(status) > compromise_rank(&asset.compromise_status) {
            let after = Asset {
                compromise_status: status.to_string(),
                suspicious: true,
                ..asset.clone()
            };
            tx.execute(
                "UPDATE assets SET compromise_status=?1,suspicious=1 WHERE id=?2",
                params![status, entity_id],
            )
            .map_err(|e| e.to_string())?;
            changes.push(single_change(
                "asset",
                entity_id,
                "update",
                Some(to_value(&asset)?),
                Some(to_value(&after)?),
            ));
            message = format!("Recorded IOC sighting; escalated asset to {status}");
        }
    }
    record_commit_tx(&tx, actor, &message, changes, &[])?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

pub fn update_ioc_sighting(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    sighted_at: Option<&str>,
    location: &str,
    note: &str,
) -> AppResult<IocSighting> {
    let before_value =
        require_existing(get_entity_json(conn, "ioc_sighting", id)?, "IOC sighting")?;
    let before: IocSighting = serde_json::from_value(before_value).map_err(|e| e.to_string())?;
    let sighted_at = sighted_at
        .map(|value| normalize_timestamp("Sighted at", value))
        .transpose()?;
    let after = IocSighting {
        sighted_at,
        location: location.trim().into(),
        note: note.trim().into(),
        ..before.clone()
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx
        .execute(
            "UPDATE ioc_sightings SET sighted_at=?1,location=?2,note=?3 WHERE id=?4",
            params![after.sighted_at, after.location, after.note, id],
        )
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("IOC sighting was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Updated IOC sighting",
        vec![single_change(
            "ioc_sighting",
            id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

pub fn delete_ioc_sighting(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
) -> AppResult<()> {
    let before = require_existing(get_entity_json(conn, "ioc_sighting", id)?, "IOC sighting")?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx
        .execute("DELETE FROM ioc_sightings WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("IOC sighting was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Deleted IOC sighting",
        vec![single_change(
            "ioc_sighting",
            id,
            "delete",
            Some(before),
            None,
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())
}

#[allow(clippy::too_many_arguments)]
fn build_attack_edge(
    conn: &Connection,
    id: String,
    source_kind: &str,
    source_id: &str,
    target_kind: &str,
    target_id: &str,
    title: &str,
    description: &str,
    edge_type: &str,
    confidence: &str,
    mitre_tactic: Option<&str>,
    mitre_technique: Option<&str>,
    occurred_at: Option<&str>,
    timeline_event_id: Option<&str>,
    sequence: Option<i64>,
    ioc_ids: Vec<String>,
    created_at: String,
) -> AppResult<AttackEdge> {
    let occurred_at = occurred_at
        .map(|value| normalize_timestamp("Occurred at", value))
        .transpose()?;
    let mut deduped: Vec<String> = Vec::new();
    for ioc_id in ioc_ids {
        if !deduped.contains(&ioc_id) {
            deduped.push(ioc_id);
        }
    }
    let sequence = match sequence {
        Some(value) => value,
        None => conn
            .query_row(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM attack_edges",
                [],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?,
    };
    let edge = AttackEdge {
        id,
        source_kind: source_kind.into(),
        source_id: if source_kind == "external" {
            source_id.trim().into()
        } else {
            source_id.into()
        },
        source_name: None,
        target_kind: target_kind.into(),
        target_id: target_id.into(),
        target_name: None,
        title: title.trim().into(),
        description: description.trim().into(),
        edge_type: edge_type.into(),
        confidence: confidence.into(),
        mitre_tactic: cleaned(mitre_tactic),
        mitre_technique: cleaned(mitre_technique),
        occurred_at,
        timeline_event_id: cleaned(timeline_event_id),
        timeline_event_time: None,
        sequence,
        ioc_ids: deduped,
        created_at,
    };
    validate_attack_edge_model(&edge)?;
    verify_attack_edge_refs(conn, &edge)?;
    Ok(edge)
}

#[allow(clippy::too_many_arguments)]
pub fn create_attack_edge(
    conn: &mut Connection,
    actor: &ActorIdentity,
    source_kind: &str,
    source_id: &str,
    target_kind: &str,
    target_id: &str,
    title: &str,
    description: &str,
    edge_type: &str,
    confidence: &str,
    mitre_tactic: Option<&str>,
    mitre_technique: Option<&str>,
    occurred_at: Option<&str>,
    timeline_event_id: Option<&str>,
    sequence: Option<i64>,
    ioc_ids: Vec<String>,
) -> AppResult<AttackEdge> {
    let edge = build_attack_edge(
        conn,
        Uuid::new_v4().to_string(),
        source_kind,
        source_id,
        target_kind,
        target_id,
        title,
        description,
        edge_type,
        confidence,
        mitre_tactic,
        mitre_technique,
        occurred_at,
        timeline_event_id,
        sequence,
        ioc_ids,
        Utc::now().to_rfc3339(),
    )?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO attack_edges(id,source_kind,source_id,target_kind,target_id,title,description,edge_type,confidence,mitre_tactic,mitre_technique,occurred_at,timeline_event_id,sequence,ioc_ids,created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        params![
            edge.id,
            edge.source_kind,
            edge.source_id,
            edge.target_kind,
            edge.target_id,
            edge.title,
            edge.description,
            edge.edge_type,
            edge.confidence,
            edge.mitre_tactic,
            edge.mitre_technique,
            edge.occurred_at,
            edge.timeline_event_id,
            edge.sequence,
            serde_json::to_string(&edge.ioc_ids).map_err(|e| e.to_string())?,
            edge.created_at
        ],
    )
    .map_err(|e| e.to_string())?;
    let item: AttackEdge = serde_json::from_value(require_existing(
        get_entity_json(&tx, "attack_edge", &edge.id)?,
        "Attack edge",
    )?)
    .map_err(|e| e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        "Recorded attack edge",
        vec![single_change(
            "attack_edge",
            &edge.id,
            "create",
            None,
            Some(to_value(&item)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

#[allow(clippy::too_many_arguments)]
pub fn update_attack_edge(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    source_kind: &str,
    source_id: &str,
    target_kind: &str,
    target_id: &str,
    title: &str,
    description: &str,
    edge_type: &str,
    confidence: &str,
    mitre_tactic: Option<&str>,
    mitre_technique: Option<&str>,
    occurred_at: Option<&str>,
    timeline_event_id: Option<&str>,
    sequence: i64,
    ioc_ids: Vec<String>,
) -> AppResult<AttackEdge> {
    let before_value = require_existing(get_entity_json(conn, "attack_edge", id)?, "Attack edge")?;
    let before: AttackEdge = serde_json::from_value(before_value).map_err(|e| e.to_string())?;
    let edge = build_attack_edge(
        conn,
        id.to_string(),
        source_kind,
        source_id,
        target_kind,
        target_id,
        title,
        description,
        edge_type,
        confidence,
        mitre_tactic,
        mitre_technique,
        occurred_at,
        timeline_event_id,
        Some(sequence),
        ioc_ids,
        before.created_at.clone(),
    )?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx
        .execute(
            "UPDATE attack_edges SET source_kind=?1,source_id=?2,target_kind=?3,target_id=?4,title=?5,description=?6,edge_type=?7,confidence=?8,mitre_tactic=?9,mitre_technique=?10,occurred_at=?11,timeline_event_id=?12,sequence=?13,ioc_ids=?14 WHERE id=?15",
            params![
                edge.source_kind,
                edge.source_id,
                edge.target_kind,
                edge.target_id,
                edge.title,
                edge.description,
                edge.edge_type,
                edge.confidence,
                edge.mitre_tactic,
                edge.mitre_technique,
                edge.occurred_at,
                edge.timeline_event_id,
                edge.sequence,
                serde_json::to_string(&edge.ioc_ids).map_err(|e| e.to_string())?,
                id
            ],
        )
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Attack edge was not found".into());
    }
    let item: AttackEdge = serde_json::from_value(require_existing(
        get_entity_json(&tx, "attack_edge", id)?,
        "Attack edge",
    )?)
    .map_err(|e| e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        "Updated attack edge",
        vec![single_change(
            "attack_edge",
            id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&item)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

pub fn delete_attack_edge(conn: &mut Connection, actor: &ActorIdentity, id: &str) -> AppResult<()> {
    let before = require_existing(get_entity_json(conn, "attack_edge", id)?, "Attack edge")?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx
        .execute("DELETE FROM attack_edges WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Attack edge was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Deleted attack edge",
        vec![single_change(
            "attack_edge",
            id,
            "delete",
            Some(before),
            None,
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())
}

pub fn save_investigation_view(
    conn: &mut Connection,
    id: Option<&str>,
    name: &str,
    description: &str,
    state: &Value,
) -> AppResult<InvestigationView> {
    let now = Utc::now().to_rfc3339();
    let item = InvestigationView {
        id: id
            .map(String::from)
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        name: name.trim().into(),
        description: description.trim().into(),
        state: state.clone(),
        created_at: now.clone(),
        updated_at: now,
    };
    validate_investigation_view_model(&item)?;
    let duplicate: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM investigation_views WHERE LOWER(name)=LOWER(?1) AND id<>?2",
            params![item.name, item.id],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if duplicate > 0 {
        return Err(format!(
            "An investigation view named \"{}\" already exists",
            item.name
        ));
    }
    let state_json = serde_json::to_string(&item.state).map_err(|e| e.to_string())?;
    if let Some(id) = id {
        let updated = conn
            .execute(
                "UPDATE investigation_views SET name=?1,description=?2,state_json=?3,updated_at=?4 WHERE id=?5",
                params![item.name, item.description, state_json, item.updated_at, id],
            )
            .map_err(|e| e.to_string())?;
        if updated == 0 {
            return Err("Investigation view was not found".into());
        }
        get_investigation_view(conn, id)
    } else {
        conn.execute(
            "INSERT INTO investigation_views(id,name,description,state_json,created_at,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                item.id,
                item.name,
                item.description,
                state_json,
                item.created_at,
                item.updated_at
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(item)
    }
}

pub fn delete_investigation_view(conn: &Connection, id: &str) -> AppResult<()> {
    if conn
        .execute("DELETE FROM investigation_views WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Investigation view was not found".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn create_firewall(
    conn: &mut Connection,
    actor: &ActorIdentity,
    network_id: Option<&str>,
    name: &str,
    vendor: Option<&str>,
    model: Option<&str>,
    rules: Option<&str>,
    config_text: Option<&str>,
) -> AppResult<Firewall> {
    validate_required("Firewall name", name)?;
    validate_optional_json("Firewall rules", rules)?;
    if let Some(nid) = network_id {
        if !exists(conn, "networks", nid)? {
            return Err("Selected network was not found".into());
        }
    }
    let network_name = network_id.and_then(|nid| {
        conn.query_row("SELECT name FROM networks WHERE id=?1", params![nid], |r| {
            r.get(0)
        })
        .optional()
        .ok()
        .flatten()
    });
    let item = Firewall {
        id: Uuid::new_v4().to_string(),
        network_id: network_id.map(String::from),
        network_name,
        name: name.trim().into(),
        vendor: vendor
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        model: model
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        rules: rules
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        config_text: config_text.map(String::from),
        quick_note: None,
        created_at: Utc::now().to_rfc3339(),
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("INSERT INTO firewalls(id,network_id,name,vendor,model,rules,config_text,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![item.id,item.network_id,item.name,item.vendor,item.model,item.rules,item.config_text,item.created_at]).map_err(|e|e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        "Created firewall",
        vec![single_change(
            "firewall",
            &item.id,
            "create",
            None,
            Some(to_value(&item)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

#[allow(clippy::too_many_arguments)]
pub fn update_firewall(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    network_id: Option<&str>,
    name: &str,
    vendor: Option<&str>,
    model: Option<&str>,
    rules: Option<&str>,
    config_text: Option<&str>,
) -> AppResult<Firewall> {
    validate_required("Firewall name", name)?;
    validate_optional_json("Firewall rules", rules)?;
    if let Some(nid) = network_id {
        if !exists(conn, "networks", nid)? {
            return Err("Selected network was not found".into());
        }
    }
    let before = require_existing(
        get_firewalls(conn)?.into_iter().find(|v| v.id == id),
        "Firewall",
    )?;
    let network_name = network_id.and_then(|nid| {
        conn.query_row("SELECT name FROM networks WHERE id=?1", params![nid], |r| {
            r.get(0)
        })
        .optional()
        .ok()
        .flatten()
    });
    let after = Firewall {
        network_id: network_id.map(String::from),
        network_name,
        name: name.trim().into(),
        vendor: vendor
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        model: model
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        rules: rules
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        config_text: config_text.map(String::from),
        ..before.clone()
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx.execute("UPDATE firewalls SET network_id=?1,name=?2,vendor=?3,model=?4,rules=?5,config_text=?6 WHERE id=?7",params![after.network_id,after.name,after.vendor,after.model,after.rules,after.config_text,id]).map_err(|e|e.to_string())?==0{return Err("Firewall was not found".into());}
    record_commit_tx(
        &tx,
        actor,
        "Updated firewall",
        vec![single_change(
            "firewall",
            id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

pub fn delete_firewall(conn: &mut Connection, actor: &ActorIdentity, id: &str) -> AppResult<()> {
    let before = require_existing(get_entity_json(conn, "firewall", id)?, "Firewall")?;
    let interfaces = get_firewall_interfaces(conn, Some(id))?;
    let nat_rules = get_firewall_nat_rules(conn, Some(id))?;
    let sightings = get_ioc_sightings(conn, None, Some("firewall"), Some(id))?;
    let attack_edges: Vec<AttackEdge> = get_attack_edges(conn)?
        .into_iter()
        .filter(|edge| {
            (edge.source_kind == "firewall" && edge.source_id == id)
                || (edge.target_kind == "firewall" && edge.target_id == id)
        })
        .collect();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut changes = Vec::new();
    for sighting in &sightings {
        tx.execute(
            "DELETE FROM ioc_sightings WHERE id=?1",
            params![sighting.id],
        )
        .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "ioc_sighting",
            &sighting.id,
            "delete",
            Some(to_value(sighting)?),
            None,
        ));
    }
    for edge in &attack_edges {
        tx.execute("DELETE FROM attack_edges WHERE id=?1", params![edge.id])
            .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "attack_edge",
            &edge.id,
            "delete",
            Some(to_value(edge)?),
            None,
        ));
    }
    if tx
        .execute("DELETE FROM firewalls WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Firewall was not found".into());
    }
    for item in interfaces {
        changes.push(single_change(
            "firewall_interface",
            &item.id,
            "delete",
            Some(to_value(&item)?),
            None,
        ));
    }
    for item in nat_rules {
        changes.push(single_change(
            "firewall_nat_rule",
            &item.id,
            "delete",
            Some(to_value(&item)?),
            None,
        ));
    }
    changes.push(single_change("firewall", id, "delete", Some(before), None));
    record_commit_tx(&tx, actor, "Deleted firewall", changes, &[])?;
    tx.commit().map_err(|e| e.to_string())
}

fn cleaned(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn normalized_addresses(values: Vec<String>) -> Vec<String> {
    let mut result = Vec::new();
    for value in values {
        let value = value.trim().to_string();
        if !value.is_empty() && !result.contains(&value) {
            result.push(value);
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
pub fn create_firewall_interface(
    conn: &mut Connection,
    actor: &ActorIdentity,
    firewall_id: &str,
    name: &str,
    ip_addresses: Vec<String>,
    mac_address: Option<&str>,
    network_id: Option<&str>,
    vlan_id: Option<&str>,
    role: &str,
    is_primary: bool,
    description: &str,
) -> AppResult<FirewallInterface> {
    if !exists(conn, "firewalls", firewall_id)? {
        return Err("Firewall was not found".into());
    }
    if let Some(id) = network_id {
        if !exists(conn, "networks", id)? {
            return Err("Selected network was not found".into());
        }
    }
    let first = get_firewall_interfaces(conn, Some(firewall_id))?.is_empty();
    let item = FirewallInterface {
        id: Uuid::new_v4().to_string(),
        firewall_id: firewall_id.into(),
        name: name.trim().into(),
        ip_addresses: normalized_addresses(ip_addresses),
        mac_address: cleaned(mac_address),
        network_id: cleaned(network_id),
        network_name: None,
        vlan_id: cleaned(vlan_id),
        role: role.into(),
        is_primary: is_primary || first,
        description: description.trim().into(),
    };
    validate_firewall_interface_model(&item)?;
    let before_firewall = get_entity_json(conn, "firewall", firewall_id)?;
    let addresses = serde_json::to_string(&item.ip_addresses).map_err(|e| e.to_string())?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if item.is_primary {
        tx.execute(
            "UPDATE firewall_interfaces SET is_primary=0 WHERE firewall_id=?1",
            params![firewall_id],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.execute("INSERT INTO firewall_interfaces(id,firewall_id,name,ip_addresses,mac_address,network_id,vlan_id,role,is_primary,description) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![item.id,item.firewall_id,item.name,addresses,item.mac_address,item.network_id,item.vlan_id,item.role,if item.is_primary{1}else{0},item.description]).map_err(|e|e.to_string())?;
    let mut changes = vec![single_change(
        "firewall_interface",
        &item.id,
        "create",
        None,
        Some(to_value(&item)?),
    )];
    if item.is_primary {
        tx.execute(
            "UPDATE firewalls SET network_id=?1 WHERE id=?2",
            params![item.network_id, firewall_id],
        )
        .map_err(|e| e.to_string())?;
        let after_firewall = get_entity_json(&tx, "firewall", firewall_id)?;
        if before_firewall != after_firewall {
            changes.push(single_change(
                "firewall",
                firewall_id,
                "update",
                before_firewall,
                after_firewall,
            ));
        }
    }
    record_commit_tx(&tx, actor, "Created firewall interface", changes, &[])?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(get_firewall_interfaces(conn, Some(firewall_id))?
        .into_iter()
        .find(|v| v.id == item.id)
        .unwrap_or(item))
}

#[allow(clippy::too_many_arguments)]
pub fn update_firewall_interface(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    name: &str,
    ip_addresses: Vec<String>,
    mac_address: Option<&str>,
    network_id: Option<&str>,
    vlan_id: Option<&str>,
    role: &str,
    is_primary: bool,
    description: &str,
) -> AppResult<FirewallInterface> {
    let before = require_existing(
        get_firewall_interfaces(conn, None)?
            .into_iter()
            .find(|v| v.id == id),
        "Firewall interface",
    )?;
    if let Some(network) = network_id {
        if !exists(conn, "networks", network)? {
            return Err("Selected network was not found".into());
        }
    }
    let mut after = FirewallInterface {
        name: name.trim().into(),
        ip_addresses: normalized_addresses(ip_addresses),
        mac_address: cleaned(mac_address),
        network_id: cleaned(network_id),
        network_name: None,
        vlan_id: cleaned(vlan_id),
        role: role.into(),
        is_primary,
        description: description.trim().into(),
        ..before.clone()
    };
    let siblings = get_firewall_interfaces(conn, Some(&before.firewall_id))?;
    if before.is_primary && !after.is_primary && !siblings.iter().any(|v| v.id != id) {
        after.is_primary = true;
    }
    validate_firewall_interface_model(&after)?;
    let before_firewall = get_entity_json(conn, "firewall", &before.firewall_id)?;
    let addresses = serde_json::to_string(&after.ip_addresses).map_err(|e| e.to_string())?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if after.is_primary {
        tx.execute(
            "UPDATE firewall_interfaces SET is_primary=0 WHERE firewall_id=?1 AND id<>?2",
            params![after.firewall_id, id],
        )
        .map_err(|e| e.to_string())?;
    }
    if tx.execute("UPDATE firewall_interfaces SET name=?1,ip_addresses=?2,mac_address=?3,network_id=?4,vlan_id=?5,role=?6,is_primary=?7,description=?8 WHERE id=?9",
        params![after.name,addresses,after.mac_address,after.network_id,after.vlan_id,after.role,if after.is_primary{1}else{0},after.description,id]).map_err(|e|e.to_string())?==0 { return Err("Firewall interface was not found".into()); }
    if before.is_primary && !after.is_primary {
        if let Some(replacement) = siblings.iter().find(|v| v.id != id) {
            tx.execute(
                "UPDATE firewall_interfaces SET is_primary=1 WHERE id=?1",
                params![replacement.id],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "UPDATE firewalls SET network_id=?1 WHERE id=?2",
                params![replacement.network_id, before.firewall_id],
            )
            .map_err(|e| e.to_string())?;
        }
    } else if after.is_primary {
        tx.execute(
            "UPDATE firewalls SET network_id=?1 WHERE id=?2",
            params![after.network_id, before.firewall_id],
        )
        .map_err(|e| e.to_string())?;
    }
    let stored = get_firewall_interfaces(&tx, Some(&before.firewall_id))?
        .into_iter()
        .find(|v| v.id == id)
        .ok_or_else(|| "Firewall interface was not found".to_string())?;
    let mut changes = vec![single_change(
        "firewall_interface",
        id,
        "update",
        Some(to_value(&before)?),
        Some(to_value(&stored)?),
    )];
    let after_firewall = get_entity_json(&tx, "firewall", &before.firewall_id)?;
    if before_firewall != after_firewall {
        changes.push(single_change(
            "firewall",
            &before.firewall_id,
            "update",
            before_firewall,
            after_firewall,
        ));
    }
    record_commit_tx(&tx, actor, "Updated firewall interface", changes, &[])?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(stored)
}

pub fn delete_firewall_interface(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
) -> AppResult<()> {
    let before = require_existing(
        get_firewall_interfaces(conn, None)?
            .into_iter()
            .find(|v| v.id == id),
        "Firewall interface",
    )?;
    let before_firewall = get_entity_json(conn, "firewall", &before.firewall_id)?;
    let siblings = get_firewall_interfaces(conn, Some(&before.firewall_id))?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM firewall_interfaces WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?;
    if before.is_primary {
        if let Some(next) = siblings.iter().find(|v| v.id != id) {
            tx.execute(
                "UPDATE firewall_interfaces SET is_primary=1 WHERE id=?1",
                params![next.id],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "UPDATE firewalls SET network_id=?1 WHERE id=?2",
                params![next.network_id, before.firewall_id],
            )
            .map_err(|e| e.to_string())?;
        } else {
            tx.execute(
                "UPDATE firewalls SET network_id=NULL WHERE id=?1",
                params![before.firewall_id],
            )
            .map_err(|e| e.to_string())?;
        }
    }
    let mut changes = vec![single_change(
        "firewall_interface",
        id,
        "delete",
        Some(to_value(&before)?),
        None,
    )];
    let after_firewall = get_entity_json(&tx, "firewall", &before.firewall_id)?;
    if before_firewall != after_firewall {
        changes.push(single_change(
            "firewall",
            &before.firewall_id,
            "update",
            before_firewall,
            after_firewall,
        ));
    }
    record_commit_tx(&tx, actor, "Deleted firewall interface", changes, &[])?;
    tx.commit().map_err(|e| e.to_string())
}

fn verify_nat_interface(
    conn: &Connection,
    firewall_id: &str,
    interface_id: Option<&str>,
) -> AppResult<()> {
    if let Some(id) = interface_id {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM firewall_interfaces WHERE id=?1 AND firewall_id=?2",
                params![id, firewall_id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if count == 0 {
            return Err("Selected NAT interface does not belong to this firewall".into());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn create_firewall_nat_rule(
    conn: &mut Connection,
    actor: &ActorIdentity,
    firewall_id: &str,
    name: &str,
    nat_type: &str,
    enabled: bool,
    protocol: &str,
    source_cidr: Option<&str>,
    original_destination: Option<&str>,
    original_port: Option<&str>,
    translated_source: Option<&str>,
    translated_destination: Option<&str>,
    translated_port: Option<&str>,
    inbound_interface_id: Option<&str>,
    outbound_interface_id: Option<&str>,
    description: &str,
) -> AppResult<FirewallNatRule> {
    if !exists(conn, "firewalls", firewall_id)? {
        return Err("Firewall was not found".into());
    }
    verify_nat_interface(conn, firewall_id, inbound_interface_id)?;
    verify_nat_interface(conn, firewall_id, outbound_interface_id)?;
    let item = FirewallNatRule {
        id: Uuid::new_v4().to_string(),
        firewall_id: firewall_id.into(),
        name: name.trim().into(),
        nat_type: nat_type.into(),
        enabled,
        protocol: protocol.into(),
        source_cidr: cleaned(source_cidr),
        original_destination: cleaned(original_destination),
        original_port: cleaned(original_port),
        translated_source: cleaned(translated_source),
        translated_destination: cleaned(translated_destination),
        translated_port: cleaned(translated_port),
        inbound_interface_id: cleaned(inbound_interface_id),
        outbound_interface_id: cleaned(outbound_interface_id),
        description: description.trim().into(),
        created_at: Utc::now().to_rfc3339(),
    };
    validate_firewall_nat_model(&item)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("INSERT INTO firewall_nat_rules(id,firewall_id,name,nat_type,enabled,protocol,source_cidr,original_destination,original_port,translated_source,translated_destination,translated_port,inbound_interface_id,outbound_interface_id,description,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",params![item.id,item.firewall_id,item.name,item.nat_type,if item.enabled{1}else{0},item.protocol,item.source_cidr,item.original_destination,item.original_port,item.translated_source,item.translated_destination,item.translated_port,item.inbound_interface_id,item.outbound_interface_id,item.description,item.created_at]).map_err(|e|e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        "Created firewall NAT rule",
        vec![single_change(
            "firewall_nat_rule",
            &item.id,
            "create",
            None,
            Some(to_value(&item)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

#[allow(clippy::too_many_arguments)]
pub fn update_firewall_nat_rule(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    name: &str,
    nat_type: &str,
    enabled: bool,
    protocol: &str,
    source_cidr: Option<&str>,
    original_destination: Option<&str>,
    original_port: Option<&str>,
    translated_source: Option<&str>,
    translated_destination: Option<&str>,
    translated_port: Option<&str>,
    inbound_interface_id: Option<&str>,
    outbound_interface_id: Option<&str>,
    description: &str,
) -> AppResult<FirewallNatRule> {
    let before = require_existing(
        get_firewall_nat_rules(conn, None)?
            .into_iter()
            .find(|v| v.id == id),
        "Firewall NAT rule",
    )?;
    verify_nat_interface(conn, &before.firewall_id, inbound_interface_id)?;
    verify_nat_interface(conn, &before.firewall_id, outbound_interface_id)?;
    let after = FirewallNatRule {
        name: name.trim().into(),
        nat_type: nat_type.into(),
        enabled,
        protocol: protocol.into(),
        source_cidr: cleaned(source_cidr),
        original_destination: cleaned(original_destination),
        original_port: cleaned(original_port),
        translated_source: cleaned(translated_source),
        translated_destination: cleaned(translated_destination),
        translated_port: cleaned(translated_port),
        inbound_interface_id: cleaned(inbound_interface_id),
        outbound_interface_id: cleaned(outbound_interface_id),
        description: description.trim().into(),
        ..before.clone()
    };
    validate_firewall_nat_model(&after)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx.execute("UPDATE firewall_nat_rules SET name=?1,nat_type=?2,enabled=?3,protocol=?4,source_cidr=?5,original_destination=?6,original_port=?7,translated_source=?8,translated_destination=?9,translated_port=?10,inbound_interface_id=?11,outbound_interface_id=?12,description=?13 WHERE id=?14",params![after.name,after.nat_type,if after.enabled{1}else{0},after.protocol,after.source_cidr,after.original_destination,after.original_port,after.translated_source,after.translated_destination,after.translated_port,after.inbound_interface_id,after.outbound_interface_id,after.description,id]).map_err(|e|e.to_string())?==0{return Err("Firewall NAT rule was not found".into());}
    record_commit_tx(
        &tx,
        actor,
        "Updated firewall NAT rule",
        vec![single_change(
            "firewall_nat_rule",
            id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

pub fn delete_firewall_nat_rule(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
) -> AppResult<()> {
    let before = require_existing(
        get_firewall_nat_rules(conn, None)?
            .into_iter()
            .find(|v| v.id == id),
        "Firewall NAT rule",
    )?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx
        .execute("DELETE FROM firewall_nat_rules WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Firewall NAT rule was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Deleted firewall NAT rule",
        vec![single_change(
            "firewall_nat_rule",
            id,
            "delete",
            Some(to_value(&before)?),
            None,
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())
}

#[allow(clippy::too_many_arguments)]
pub fn create_network_connection(
    conn: &mut Connection,
    actor: &ActorIdentity,
    source_network_id: &str,
    target_network_id: &str,
    connection_type: &str,
    description: &str,
    device_name: Option<&str>,
) -> AppResult<NetworkConnection> {
    if source_network_id == target_network_id {
        return Err("A network connection must link two different networks".into());
    }
    if !exists(conn, "networks", source_network_id)?
        || !exists(conn, "networks", target_network_id)?
    {
        return Err("Source or target network was not found".into());
    }
    validate_required("Connection type", connection_type)?;
    let source_name = conn
        .query_row(
            "SELECT name FROM networks WHERE id=?1",
            params![source_network_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let target_name = conn
        .query_row(
            "SELECT name FROM networks WHERE id=?1",
            params![target_network_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let item = NetworkConnection {
        id: Uuid::new_v4().to_string(),
        source_network_id: source_network_id.into(),
        source_network_name: source_name,
        target_network_id: target_network_id.into(),
        target_network_name: target_name,
        connection_type: connection_type.trim().into(),
        description: description.trim().into(),
        device_name: device_name
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("INSERT INTO network_connections(id,source_network_id,target_network_id,connection_type,description,device_name) VALUES (?1,?2,?3,?4,?5,?6)",
        params![item.id,item.source_network_id,item.target_network_id,item.connection_type,item.description,item.device_name]).map_err(|e|e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        "Created network connection",
        vec![single_change(
            "network_connection",
            &item.id,
            "create",
            None,
            Some(to_value(&item)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

#[allow(clippy::too_many_arguments)]
pub fn update_network_connection(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    source_network_id: &str,
    target_network_id: &str,
    connection_type: &str,
    description: &str,
    device_name: Option<&str>,
) -> AppResult<NetworkConnection> {
    if source_network_id == target_network_id {
        return Err("A network connection must link two different networks".into());
    }
    if !exists(conn, "networks", source_network_id)?
        || !exists(conn, "networks", target_network_id)?
    {
        return Err("Source or target network was not found".into());
    }
    validate_required("Connection type", connection_type)?;
    let before = require_existing(
        get_network_connections(conn)?
            .into_iter()
            .find(|v| v.id == id),
        "Network connection",
    )?;
    let source_name = conn
        .query_row(
            "SELECT name FROM networks WHERE id=?1",
            params![source_network_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let target_name = conn
        .query_row(
            "SELECT name FROM networks WHERE id=?1",
            params![target_network_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let after = NetworkConnection {
        source_network_id: source_network_id.into(),
        source_network_name: source_name,
        target_network_id: target_network_id.into(),
        target_network_name: target_name,
        connection_type: connection_type.trim().into(),
        description: description.trim().into(),
        device_name: device_name
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        ..before.clone()
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx.execute("UPDATE network_connections SET source_network_id=?1,target_network_id=?2,connection_type=?3,description=?4,device_name=?5 WHERE id=?6",params![after.source_network_id,after.target_network_id,after.connection_type,after.description,after.device_name,id]).map_err(|e|e.to_string())?==0{return Err("Network connection was not found".into());}
    record_commit_tx(
        &tx,
        actor,
        "Updated network connection",
        vec![single_change(
            "network_connection",
            id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

pub fn delete_network_connection(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
) -> AppResult<()> {
    let before = require_existing(
        get_entity_json(conn, "network_connection", id)?,
        "Network connection",
    )?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx
        .execute("DELETE FROM network_connections WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Network connection was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Deleted network connection",
        vec![single_change(
            "network_connection",
            id,
            "delete",
            Some(before),
            None,
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())
}

pub fn export_case_data(conn: &Connection) -> AppResult<ExportData> {
    Ok(ExportData {
        format_version: 4,
        exported_at: Utc::now().to_rfc3339(),
        case_info: get_case(conn)?,
        networks: get_networks(conn)?,
        assets: get_assets(conn)?,
        network_interfaces: get_network_interfaces(conn, None)?,
        clock_profiles: get_clock_profiles(conn)?,
        timeline_events: get_timeline_events(conn)?,
        notes: get_notes(conn)?,
        iocs: get_iocs(conn)?,
        firewalls: get_firewalls(conn)?,
        firewall_interfaces: get_firewall_interfaces(conn, None)?,
        firewall_nat_rules: get_firewall_nat_rules(conn, None)?,
        network_connections: get_network_connections(conn)?,
        ioc_sightings: get_ioc_sightings(conn, None, None, None)?,
        attack_edges: get_attack_edges(conn)?,
        investigation_views: {
            let mut views = Vec::new();
            for summary in get_investigation_views(conn)? {
                views.push(get_investigation_view(conn, &summary.id)?);
            }
            views
        },
        captures: get_captures(conn)?,
        sites: get_sites(conn)?,
        asset_relations: get_asset_relations(conn)?,
    })
}

fn summary_increment(summary: &mut ImportSummary, key: &str, inserted: bool) {
    let entry = summary.entities.entry(key.into()).or_default();
    if inserted {
        entry.inserted += 1
    } else {
        entry.skipped += 1
    }
}

pub fn import_case_data(
    conn: &mut Connection,
    actor: &ActorIdentity,
    data: &ExportData,
) -> AppResult<ImportSummary> {
    let current = require_existing(get_case(conn)?, "Case")?;
    let incoming = data
        .case_info
        .as_ref()
        .ok_or_else(|| "Import is missing case_info".to_string())?;
    if current.id != incoming.id {
        return Err("Import belongs to a different case".into());
    }
    validate_export_data(data)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut summary = ImportSummary::default();
    let mut changes = Vec::new();
    macro_rules! insert_item {
        ($key:expr,$etype:expr,$id:expr,$sql:expr,$params:expr,$value:expr) => {{
            let count = tx.execute($sql, $params).map_err(|e| e.to_string())?;
            summary_increment(&mut summary, $key, count > 0);
            if count > 0 {
                changes.push(single_change(
                    $etype,
                    $id,
                    "create",
                    None,
                    Some(to_value($value)?),
                ));
            }
        }};
    }
    for v in &data.sites {
        insert_item!("sites","site",&v.id,"INSERT OR IGNORE INTO sites(id,name,location,description,created_at) VALUES (?1,?2,?3,?4,?5)",params![v.id,v.name,v.location,v.description,v.created_at],v);
    }
    for v in &data.networks {
        insert_item!("networks","network",&v.id,"INSERT OR IGNORE INTO networks(id,name,subnet,network_type,description,vlan_id,quick_note,site_id,owner,operator,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![v.id,v.name,v.subnet,v.network_type,v.description,v.vlan_id,v.quick_note,v.site_id,v.owner,v.operator,v.created_at],v);
    }
    for v in &data.assets {
        insert_item!("assets","asset",&v.id,"INSERT OR IGNORE INTO assets(id,network_id,name,ip_address,mac_address,asset_type,os,user_name,suspicious,compromise_status,investigation_status,properties,scan_results,quick_note,site_id,owner,operator,origin,last_observed,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",params![v.id,v.network_id,v.name,v.ip_address,v.mac_address,v.asset_type,v.os,v.user_name,if v.suspicious{1}else{0},v.compromise_status,v.investigation_status,v.properties,v.scan_results,v.quick_note,v.site_id,v.owner,v.operator,v.origin,v.last_observed,v.created_at],v);
    }
    for v in &data.asset_relations {
        insert_item!("asset_relations","asset_relation",&v.id,"INSERT OR IGNORE INTO asset_relations(id,source_asset_id,target_asset_id,relation_type,note,created_at) VALUES (?1,?2,?3,?4,?5,?6)",params![v.id,v.source_asset_id,v.target_asset_id,v.relation_type,v.note,v.created_at],v);
    }
    for v in &data.network_interfaces {
        insert_item!("network_interfaces","network_interface",&v.id,"INSERT OR IGNORE INTO network_interfaces(id,asset_id,name,ip_address,mac_address,network_id,is_primary) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![v.id,v.asset_id,v.name,v.ip_address,v.mac_address,v.network_id,if v.is_primary{1}else{0}],v);
    }
    for v in &data.clock_profiles {
        insert_item!("clock_profiles","clock_profile",&v.id,"INSERT OR IGNORE INTO clock_profiles(id,name,description,server_reference_raw,server_timezone,server_reference_utc,correct_reference_raw,correct_timezone,correct_reference_utc,offset_ms,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",params![v.id,v.name,v.description,v.server_reference_raw,v.server_timezone,v.server_reference_utc,v.correct_reference_raw,v.correct_timezone,v.correct_reference_utc,v.offset_ms,v.created_at,v.updated_at],v);
    }
    for v in &data.firewalls {
        insert_item!("firewalls","firewall",&v.id,"INSERT OR IGNORE INTO firewalls(id,network_id,name,vendor,model,rules,config_text,quick_note,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![v.id,v.network_id,v.name,v.vendor,v.model,v.rules,v.config_text,v.quick_note,v.created_at],v);
    }
    for v in &data.firewall_interfaces {
        let addresses = serde_json::to_string(&v.ip_addresses).map_err(|e| e.to_string())?;
        insert_item!("firewall_interfaces","firewall_interface",&v.id,"INSERT OR IGNORE INTO firewall_interfaces(id,firewall_id,name,ip_addresses,mac_address,network_id,vlan_id,role,is_primary,description) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![v.id,v.firewall_id,v.name,addresses,v.mac_address,v.network_id,v.vlan_id,v.role,if v.is_primary{1}else{0},v.description],v);
    }
    for v in &data.firewall_nat_rules {
        insert_item!("firewall_nat_rules","firewall_nat_rule",&v.id,"INSERT OR IGNORE INTO firewall_nat_rules(id,firewall_id,name,nat_type,enabled,protocol,source_cidr,original_destination,original_port,translated_source,translated_destination,translated_port,inbound_interface_id,outbound_interface_id,description,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",params![v.id,v.firewall_id,v.name,v.nat_type,if v.enabled{1}else{0},v.protocol,v.source_cidr,v.original_destination,v.original_port,v.translated_source,v.translated_destination,v.translated_port,v.inbound_interface_id,v.outbound_interface_id,v.description,v.created_at],v);
    }
    for v in &data.network_connections {
        insert_item!("network_connections","network_connection",&v.id,"INSERT OR IGNORE INTO network_connections(id,source_network_id,target_network_id,connection_type,description,device_name) VALUES (?1,?2,?3,?4,?5,?6)",params![v.id,v.source_network_id,v.target_network_id,v.connection_type,v.description,v.device_name],v);
    }
    for original in &data.timeline_events {
        let mut v = original.clone();
        if !v.timestamp.trim().is_empty() {
            v.timestamp = normalize_timestamp("Event timestamp", &v.timestamp)?;
        }
        if v.raw_timestamp.is_none() && !v.timestamp.trim().is_empty() {
            v.raw_timestamp = Some(v.timestamp.clone());
        }
        if v.raw_timestamp.is_some() && v.raw_timezone.is_none() {
            v.raw_timezone = Some("UTC".into());
        }
        if v.server_timestamp_utc.is_none() {
            if let (Some(raw), Some(zone)) = (v.raw_timestamp.as_deref(), v.raw_timezone.as_deref())
            {
                v.server_timestamp_utc =
                    Some(parse_timestamp_preview(raw, zone, 0)?.interpreted_utc);
            }
        }
        let source_ref_text = json_value_text(&v.source_ref)?;
        insert_item!("timeline_events","timeline_event",&v.id,"INSERT OR IGNORE INTO timeline_events(id,asset_id,timestamp,raw_timestamp,raw_timezone,server_timestamp_utc,correct_timestamp_raw,correct_timezone,clock_profile_id,clock_offset_ms,time_precision,correct_time_precision,event_type,description,severity,source,mitre_tactic,mitre_technique,created_at,source_ref) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",params![v.id,v.asset_id,v.timestamp,v.raw_timestamp,v.raw_timezone,v.server_timestamp_utc,v.correct_timestamp_raw,v.correct_timezone,v.clock_profile_id,v.clock_offset_ms,v.time_precision,v.correct_time_precision,v.event_type,v.description,v.severity,v.source,v.mitre_tactic,v.mitre_technique,v.created_at,source_ref_text],&v);
    }
    for v in &data.notes {
        insert_item!("notes","note",&v.id,"INSERT OR IGNORE INTO notes(id,title,content,created_at,updated_at) VALUES (?1,?2,?3,?4,?5)",params![v.id,v.title,v.content,v.created_at,v.updated_at],v);
    }
    for original in &data.iocs {
        let mut v = original.clone();
        v.first_seen = v
            .first_seen
            .as_deref()
            .map(|value| normalize_timestamp("First seen", value))
            .transpose()?;
        v.last_seen = v
            .last_seen
            .as_deref()
            .map(|value| normalize_timestamp("Last seen", value))
            .transpose()?;
        insert_item!("iocs","ioc",&v.id,"INSERT OR IGNORE INTO iocs(id,ioc_type,value,description,threat_level,first_seen,last_seen,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![v.id,v.ioc_type,v.value,v.description,v.threat_level,v.first_seen,v.last_seen,v.created_at],&v);
    }
    for original in &data.ioc_sightings {
        let mut v = original.clone();
        v.sighted_at = v
            .sighted_at
            .as_deref()
            .map(|value| normalize_timestamp("Sighted at", value))
            .transpose()?;
        insert_item!("ioc_sightings","ioc_sighting",&v.id,"INSERT OR IGNORE INTO ioc_sightings(id,ioc_id,asset_id,network_id,firewall_id,sighted_at,location,note,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![v.id,v.ioc_id,(v.entity_kind=="asset").then_some(&v.entity_id),(v.entity_kind=="network").then_some(&v.entity_id),(v.entity_kind=="firewall").then_some(&v.entity_id),v.sighted_at,v.location,v.note,v.created_at],&v);
    }
    for original in &data.attack_edges {
        let mut v = original.clone();
        v.occurred_at = v
            .occurred_at
            .as_deref()
            .map(|value| normalize_timestamp("Occurred at", value))
            .transpose()?;
        let ioc_ids = serde_json::to_string(&v.ioc_ids).map_err(|e| e.to_string())?;
        insert_item!("attack_edges","attack_edge",&v.id,"INSERT OR IGNORE INTO attack_edges(id,source_kind,source_id,target_kind,target_id,title,description,edge_type,confidence,mitre_tactic,mitre_technique,occurred_at,timeline_event_id,sequence,ioc_ids,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",params![v.id,v.source_kind,v.source_id,v.target_kind,v.target_id,v.title,v.description,v.edge_type,v.confidence,v.mitre_tactic,v.mitre_technique,v.occurred_at,v.timeline_event_id,v.sequence,ioc_ids,v.created_at],&v);
    }
    for v in &data.captures {
        let links = capture_links_text(&v.links)?;
        insert_item!("captures","capture",&v.id,"INSERT OR IGNORE INTO captures(id,content,source,status,captured_by,team,links,resolution,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![v.id,v.content,v.source,v.status,v.captured_by,v.team,links,v.resolution,v.created_at,v.updated_at],v);
    }
    // Investigation views are presentation state: imported for convenience but
    // deliberately excluded from evidence history.
    for v in &data.investigation_views {
        let state_json = serde_json::to_string(&v.state).map_err(|e| e.to_string())?;
        let count = tx.execute("INSERT OR IGNORE INTO investigation_views(id,name,description,state_json,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6)",params![v.id,v.name,v.description,state_json,v.created_at,v.updated_at]).map_err(|e|e.to_string())?;
        summary_increment(&mut summary, "investigation_views", count > 0);
    }
    if !changes.is_empty() {
        record_commit_tx(&tx, actor, "Imported legacy case snapshot", changes, &[])?;
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(summary)
}

// Merge application uses these direct helpers inside a single reviewed merge transaction.
pub fn upsert_entity_json(tx: &Transaction<'_>, entity_type: &str, value: &Value) -> AppResult<()> {
    match entity_type {
        "case" => {
            let v: Case = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_required("Case name", &v.name)?;
            validate_enum("case status", &v.status, &["active", "closed", "archived"])?;
            tx.execute("UPDATE cases SET name=?1,description=?2,client_name=?3,investigator=?4,status=?5,updated_at=?6,metadata=?7 WHERE id=?8",params![v.name,v.description,v.client_name,v.investigator,v.status,v.updated_at,v.metadata,v.id]).map_err(|e|e.to_string())?;
        }
        "network" => {
            let v: Network = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_network_model(&v)?;
            tx.execute("INSERT INTO networks(id,name,subnet,network_type,description,vlan_id,quick_note,site_id,owner,operator,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) ON CONFLICT(id) DO UPDATE SET name=excluded.name,subnet=excluded.subnet,network_type=excluded.network_type,description=excluded.description,vlan_id=excluded.vlan_id,quick_note=excluded.quick_note,site_id=excluded.site_id,owner=excluded.owner,operator=excluded.operator",params![v.id,v.name,v.subnet,v.network_type,v.description,v.vlan_id,v.quick_note,v.site_id,v.owner,v.operator,v.created_at]).map_err(|e|e.to_string())?;
        }
        "site" => {
            let v: Site = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_site_model(&v)?;
            tx.execute("INSERT INTO sites(id,name,location,description,created_at) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(id) DO UPDATE SET name=excluded.name,location=excluded.location,description=excluded.description",params![v.id,v.name,v.location,v.description,v.created_at]).map_err(|e|e.to_string())?;
        }
        "asset_relation" => {
            let v: AssetRelation =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_relation_model(&v)?;
            if !exists(tx, "assets", &v.source_asset_id)?
                || !exists(tx, "assets", &v.target_asset_id)?
            {
                return Err("Both assets of a relation must exist".into());
            }
            tx.execute("INSERT INTO asset_relations(id,source_asset_id,target_asset_id,relation_type,note,created_at) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(id) DO UPDATE SET source_asset_id=excluded.source_asset_id,target_asset_id=excluded.target_asset_id,relation_type=excluded.relation_type,note=excluded.note",params![v.id,v.source_asset_id,v.target_asset_id,v.relation_type,v.note,v.created_at]).map_err(relation_sql_error)?;
        }
        "asset" => {
            let v: Asset = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_asset_model(&v)?;
            tx.execute("INSERT INTO assets(id,network_id,name,ip_address,mac_address,asset_type,os,user_name,suspicious,compromise_status,investigation_status,properties,scan_results,quick_note,site_id,owner,operator,origin,last_observed,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20) ON CONFLICT(id) DO UPDATE SET network_id=excluded.network_id,name=excluded.name,ip_address=excluded.ip_address,mac_address=excluded.mac_address,asset_type=excluded.asset_type,os=excluded.os,user_name=excluded.user_name,suspicious=excluded.suspicious,compromise_status=excluded.compromise_status,investigation_status=excluded.investigation_status,properties=excluded.properties,scan_results=excluded.scan_results,quick_note=excluded.quick_note,site_id=excluded.site_id,owner=excluded.owner,operator=excluded.operator,origin=excluded.origin,last_observed=excluded.last_observed",params![v.id,v.network_id,v.name,v.ip_address,v.mac_address,v.asset_type,v.os,v.user_name,if v.suspicious{1}else{0},v.compromise_status,v.investigation_status,v.properties,v.scan_results,v.quick_note,v.site_id,v.owner,v.operator,v.origin,v.last_observed,v.created_at]).map_err(|e|e.to_string())?;
        }
        "network_interface" => {
            let v: NetworkInterface =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_interface_model(&v)?;
            if v.is_primary {
                tx.execute(
                    "UPDATE network_interfaces SET is_primary=0 WHERE asset_id=?1 AND id<>?2",
                    params![v.asset_id, v.id],
                )
                .map_err(|e| e.to_string())?;
            }
            tx.execute("INSERT INTO network_interfaces(id,asset_id,name,ip_address,mac_address,network_id,is_primary) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(id) DO UPDATE SET asset_id=excluded.asset_id,name=excluded.name,ip_address=excluded.ip_address,mac_address=excluded.mac_address,network_id=excluded.network_id,is_primary=excluded.is_primary",params![v.id,v.asset_id,v.name,v.ip_address,v.mac_address,v.network_id,if v.is_primary{1}else{0}]).map_err(|e|e.to_string())?;
        }
        "clock_profile" => {
            let v: ClockProfile =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_clock_profile_model(&v)?;
            tx.execute("INSERT INTO clock_profiles(id,name,description,server_reference_raw,server_timezone,server_reference_utc,correct_reference_raw,correct_timezone,correct_reference_utc,offset_ms,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,server_reference_raw=excluded.server_reference_raw,server_timezone=excluded.server_timezone,server_reference_utc=excluded.server_reference_utc,correct_reference_raw=excluded.correct_reference_raw,correct_timezone=excluded.correct_timezone,correct_reference_utc=excluded.correct_reference_utc,offset_ms=excluded.offset_ms,updated_at=excluded.updated_at",params![v.id,v.name,v.description,v.server_reference_raw,v.server_timezone,v.server_reference_utc,v.correct_reference_raw,v.correct_timezone,v.correct_reference_utc,v.offset_ms,v.created_at,v.updated_at]).map_err(|e|e.to_string())?;
        }
        "timeline_event" => {
            let mut v: TimelineEvent =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_timeline_model(&v)?;
            if !v.timestamp.trim().is_empty() {
                v.timestamp = normalize_timestamp("Event timestamp", &v.timestamp)?;
            }
            if v.raw_timestamp.is_none() && !v.timestamp.trim().is_empty() {
                v.raw_timestamp = Some(v.timestamp.clone());
            }
            if v.raw_timestamp.is_some() && v.raw_timezone.is_none() {
                v.raw_timezone = Some("UTC".into());
            }
            if v.server_timestamp_utc.is_none() {
                if let (Some(raw), Some(zone)) =
                    (v.raw_timestamp.as_deref(), v.raw_timezone.as_deref())
                {
                    v.server_timestamp_utc =
                        Some(parse_timestamp_preview(raw, zone, 0)?.interpreted_utc);
                }
            }
            let source_ref_text = json_value_text(&v.source_ref)?;
            tx.execute("INSERT INTO timeline_events(id,asset_id,timestamp,raw_timestamp,raw_timezone,server_timestamp_utc,correct_timestamp_raw,correct_timezone,clock_profile_id,clock_offset_ms,time_precision,correct_time_precision,event_type,description,severity,source,mitre_tactic,mitre_technique,created_at,source_ref) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20) ON CONFLICT(id) DO UPDATE SET asset_id=excluded.asset_id,timestamp=excluded.timestamp,raw_timestamp=excluded.raw_timestamp,raw_timezone=excluded.raw_timezone,server_timestamp_utc=excluded.server_timestamp_utc,correct_timestamp_raw=excluded.correct_timestamp_raw,correct_timezone=excluded.correct_timezone,clock_profile_id=excluded.clock_profile_id,clock_offset_ms=excluded.clock_offset_ms,time_precision=excluded.time_precision,correct_time_precision=excluded.correct_time_precision,event_type=excluded.event_type,description=excluded.description,severity=excluded.severity,source=excluded.source,mitre_tactic=excluded.mitre_tactic,mitre_technique=excluded.mitre_technique,source_ref=excluded.source_ref",params![v.id,v.asset_id,v.timestamp,v.raw_timestamp,v.raw_timezone,v.server_timestamp_utc,v.correct_timestamp_raw,v.correct_timezone,v.clock_profile_id,v.clock_offset_ms,v.time_precision,v.correct_time_precision,v.event_type,v.description,v.severity,v.source,v.mitre_tactic,v.mitre_technique,v.created_at,source_ref_text]).map_err(|e|e.to_string())?;
        }
        "note" => {
            let v: Note = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_required("Note title", &v.title)?;
            tx.execute("INSERT INTO notes(id,title,content,created_at,updated_at) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(id) DO UPDATE SET title=excluded.title,content=excluded.content,updated_at=excluded.updated_at",params![v.id,v.title,v.content,v.created_at,v.updated_at]).map_err(|e|e.to_string())?;
        }
        "ioc" => {
            let mut v: Ioc = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_ioc_model(&v)?;
            v.first_seen = v
                .first_seen
                .as_deref()
                .map(|item| normalize_timestamp("First seen", item))
                .transpose()?;
            v.last_seen = v
                .last_seen
                .as_deref()
                .map(|item| normalize_timestamp("Last seen", item))
                .transpose()?;
            tx.execute("INSERT INTO iocs(id,ioc_type,value,description,threat_level,first_seen,last_seen,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO UPDATE SET ioc_type=excluded.ioc_type,value=excluded.value,description=excluded.description,threat_level=excluded.threat_level,first_seen=excluded.first_seen,last_seen=excluded.last_seen",params![v.id,v.ioc_type,v.value,v.description,v.threat_level,v.first_seen,v.last_seen,v.created_at]).map_err(|e|e.to_string())?;
        }
        "firewall" => {
            let v: Firewall = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_firewall_model(&v)?;
            tx.execute("INSERT INTO firewalls(id,network_id,name,vendor,model,rules,config_text,quick_note,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(id) DO UPDATE SET network_id=excluded.network_id,name=excluded.name,vendor=excluded.vendor,model=excluded.model,rules=excluded.rules,config_text=excluded.config_text,quick_note=excluded.quick_note",params![v.id,v.network_id,v.name,v.vendor,v.model,v.rules,v.config_text,v.quick_note,v.created_at]).map_err(|e|e.to_string())?;
        }
        "firewall_interface" => {
            let v: FirewallInterface =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_firewall_interface_model(&v)?;
            if v.is_primary {
                tx.execute(
                    "UPDATE firewall_interfaces SET is_primary=0 WHERE firewall_id=?1 AND id<>?2",
                    params![v.firewall_id, v.id],
                )
                .map_err(|e| e.to_string())?;
            }
            let addresses = serde_json::to_string(&v.ip_addresses).map_err(|e| e.to_string())?;
            tx.execute("INSERT INTO firewall_interfaces(id,firewall_id,name,ip_addresses,mac_address,network_id,vlan_id,role,is_primary,description) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(id) DO UPDATE SET firewall_id=excluded.firewall_id,name=excluded.name,ip_addresses=excluded.ip_addresses,mac_address=excluded.mac_address,network_id=excluded.network_id,vlan_id=excluded.vlan_id,role=excluded.role,is_primary=excluded.is_primary,description=excluded.description",params![v.id,v.firewall_id,v.name,addresses,v.mac_address,v.network_id,v.vlan_id,v.role,if v.is_primary{1}else{0},v.description]).map_err(|e|e.to_string())?;
        }
        "firewall_nat_rule" => {
            let v: FirewallNatRule =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_firewall_nat_model(&v)?;
            verify_nat_interface(tx, &v.firewall_id, v.inbound_interface_id.as_deref())?;
            verify_nat_interface(tx, &v.firewall_id, v.outbound_interface_id.as_deref())?;
            tx.execute("INSERT INTO firewall_nat_rules(id,firewall_id,name,nat_type,enabled,protocol,source_cidr,original_destination,original_port,translated_source,translated_destination,translated_port,inbound_interface_id,outbound_interface_id,description,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16) ON CONFLICT(id) DO UPDATE SET firewall_id=excluded.firewall_id,name=excluded.name,nat_type=excluded.nat_type,enabled=excluded.enabled,protocol=excluded.protocol,source_cidr=excluded.source_cidr,original_destination=excluded.original_destination,original_port=excluded.original_port,translated_source=excluded.translated_source,translated_destination=excluded.translated_destination,translated_port=excluded.translated_port,inbound_interface_id=excluded.inbound_interface_id,outbound_interface_id=excluded.outbound_interface_id,description=excluded.description",params![v.id,v.firewall_id,v.name,v.nat_type,if v.enabled{1}else{0},v.protocol,v.source_cidr,v.original_destination,v.original_port,v.translated_source,v.translated_destination,v.translated_port,v.inbound_interface_id,v.outbound_interface_id,v.description,v.created_at]).map_err(|e|e.to_string())?;
        }
        "network_connection" => {
            let v: NetworkConnection =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_connection_model(&v)?;
            tx.execute("INSERT INTO network_connections(id,source_network_id,target_network_id,connection_type,description,device_name) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(id) DO UPDATE SET source_network_id=excluded.source_network_id,target_network_id=excluded.target_network_id,connection_type=excluded.connection_type,description=excluded.description,device_name=excluded.device_name",params![v.id,v.source_network_id,v.target_network_id,v.connection_type,v.description,v.device_name]).map_err(|e|e.to_string())?;
        }
        "ioc_sighting" => {
            let mut v: IocSighting =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_sighting_model(&v)?;
            if !exists(tx, "iocs", &v.ioc_id)? {
                return Err("Referenced IOC was not found".into());
            }
            verify_graph_entity_ref(tx, &v.entity_kind, &v.entity_id)?;
            v.sighted_at = v
                .sighted_at
                .as_deref()
                .map(|item| normalize_timestamp("Sighted at", item))
                .transpose()?;
            tx.execute("INSERT INTO ioc_sightings(id,ioc_id,asset_id,network_id,firewall_id,sighted_at,location,note,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(id) DO UPDATE SET ioc_id=excluded.ioc_id,asset_id=excluded.asset_id,network_id=excluded.network_id,firewall_id=excluded.firewall_id,sighted_at=excluded.sighted_at,location=excluded.location,note=excluded.note",params![v.id,v.ioc_id,(v.entity_kind=="asset").then_some(&v.entity_id),(v.entity_kind=="network").then_some(&v.entity_id),(v.entity_kind=="firewall").then_some(&v.entity_id),v.sighted_at,v.location,v.note,v.created_at]).map_err(|e|e.to_string())?;
        }
        "attack_edge" => {
            let mut v: AttackEdge =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_attack_edge_model(&v)?;
            verify_attack_edge_refs(tx, &v)?;
            v.occurred_at = v
                .occurred_at
                .as_deref()
                .map(|item| normalize_timestamp("Occurred at", item))
                .transpose()?;
            let ioc_ids = serde_json::to_string(&v.ioc_ids).map_err(|e| e.to_string())?;
            tx.execute("INSERT INTO attack_edges(id,source_kind,source_id,target_kind,target_id,title,description,edge_type,confidence,mitre_tactic,mitre_technique,occurred_at,timeline_event_id,sequence,ioc_ids,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16) ON CONFLICT(id) DO UPDATE SET source_kind=excluded.source_kind,source_id=excluded.source_id,target_kind=excluded.target_kind,target_id=excluded.target_id,title=excluded.title,description=excluded.description,edge_type=excluded.edge_type,confidence=excluded.confidence,mitre_tactic=excluded.mitre_tactic,mitre_technique=excluded.mitre_technique,occurred_at=excluded.occurred_at,timeline_event_id=excluded.timeline_event_id,sequence=excluded.sequence,ioc_ids=excluded.ioc_ids",params![v.id,v.source_kind,v.source_id,v.target_kind,v.target_id,v.title,v.description,v.edge_type,v.confidence,v.mitre_tactic,v.mitre_technique,v.occurred_at,v.timeline_event_id,v.sequence,ioc_ids,v.created_at]).map_err(|e|e.to_string())?;
        }
        "capture" => {
            let v: Capture = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_capture_model(&v)?;
            let links = capture_links_text(&v.links)?;
            tx.execute("INSERT INTO captures(id,content,source,status,captured_by,team,links,resolution,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(id) DO UPDATE SET content=excluded.content,source=excluded.source,status=excluded.status,captured_by=excluded.captured_by,team=excluded.team,links=excluded.links,resolution=excluded.resolution,updated_at=excluded.updated_at",params![v.id,v.content,v.source,v.status,v.captured_by,v.team,links,v.resolution,v.created_at,v.updated_at]).map_err(|e|e.to_string())?;
        }
        _ => return Err(format!("Unsupported entity type: {entity_type}")),
    }
    Ok(())
}

pub fn reconcile_asset_primary_interface(tx: &Transaction<'_>, asset_id: &str) -> AppResult<()> {
    if tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM assets WHERE id=?1)",
            params![asset_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|e| e.to_string())?
        == 0
    {
        return Ok(());
    }
    let primary: Option<(String, Option<String>, String, Option<String>)> = tx
        .query_row(
            "SELECT id,network_id,ip_address,mac_address FROM network_interfaces
             WHERE asset_id=?1 ORDER BY is_primary DESC,rowid LIMIT 1",
            params![asset_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if let Some((interface_id, network_id, ip_address, mac_address)) = primary {
        tx.execute(
            "UPDATE network_interfaces SET is_primary=CASE WHEN id=?1 THEN 1 ELSE 0 END WHERE asset_id=?2",
            params![interface_id, asset_id],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "UPDATE assets SET network_id=?1,ip_address=?2,mac_address=?3 WHERE id=?4",
            params![network_id, ip_address, mac_address, asset_id],
        )
        .map_err(|e| e.to_string())?;
    } else {
        tx.execute(
            "UPDATE assets SET network_id=NULL,ip_address='',mac_address=NULL WHERE id=?1",
            params![asset_id],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn reconcile_firewall_primary_interface(
    tx: &Transaction<'_>,
    firewall_id: &str,
) -> AppResult<()> {
    if !exists(tx, "firewalls", firewall_id)? {
        return Ok(());
    }
    let primary: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT id,network_id FROM firewall_interfaces
             WHERE firewall_id=?1 ORDER BY is_primary DESC,rowid LIMIT 1",
            params![firewall_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if let Some((interface_id, network_id)) = primary {
        tx.execute(
            "UPDATE firewall_interfaces SET is_primary=CASE WHEN id=?1 THEN 1 ELSE 0 END WHERE firewall_id=?2",
            params![interface_id, firewall_id],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "UPDATE firewalls SET network_id=?1 WHERE id=?2",
            params![network_id, firewall_id],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn delete_entity_direct(tx: &Transaction<'_>, entity_type: &str, id: &str) -> AppResult<()> {
    let table = match entity_type {
        "network" => "networks",
        "asset" => "assets",
        "network_interface" => "network_interfaces",
        "clock_profile" => "clock_profiles",
        "timeline_event" => "timeline_events",
        "note" => "notes",
        "ioc" => "iocs",
        "firewall" => "firewalls",
        "firewall_interface" => "firewall_interfaces",
        "firewall_nat_rule" => "firewall_nat_rules",
        "network_connection" => "network_connections",
        "ioc_sighting" => "ioc_sightings",
        "attack_edge" => "attack_edges",
        "capture" => "captures",
        "site" => "sites",
        "asset_relation" => "asset_relations",
        _ => return Err(format!("Unsupported deletion type: {entity_type}")),
    };
    tx.execute(&format!("DELETE FROM {table} WHERE id=?1"), params![id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---- sites -----------------------------------------------------------------

const SITE_SELECT: &str = "SELECT id,name,location,description,created_at FROM sites";

fn map_site(row: &rusqlite::Row<'_>) -> rusqlite::Result<Site> {
    Ok(Site {
        id: row.get(0)?,
        name: row.get(1)?,
        location: row.get(2)?,
        description: row.get(3)?,
        created_at: row.get(4)?,
    })
}

pub fn get_sites(conn: &Connection) -> AppResult<Vec<Site>> {
    query_vec(
        conn,
        &format!("{SITE_SELECT} ORDER BY name COLLATE NOCASE"),
        [],
        map_site,
    )
}

fn site_name_taken(conn: &Connection, name: &str, except_id: Option<&str>) -> AppResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sites WHERE LOWER(name)=LOWER(?1) AND (?2 IS NULL OR id<>?2))",
        params![name, except_id],
        |row| row.get::<_, i64>(0),
    )
    .map(|value| value != 0)
    .map_err(|e| e.to_string())
}

pub fn create_site(
    conn: &mut Connection,
    actor: &ActorIdentity,
    name: &str,
    location: &str,
    description: &str,
) -> AppResult<Site> {
    let item = Site {
        id: Uuid::new_v4().to_string(),
        name: name.trim().into(),
        location: location.trim().into(),
        description: description.trim().into(),
        created_at: Utc::now().to_rfc3339(),
    };
    validate_site_model(&item)?;
    if site_name_taken(conn, &item.name, None)? {
        return Err(format!("A site named '{}' already exists", item.name));
    }
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO sites(id,name,location,description,created_at) VALUES (?1,?2,?3,?4,?5)",
        params![
            item.id,
            item.name,
            item.location,
            item.description,
            item.created_at
        ],
    )
    .map_err(|e| e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        &format!("Created site {}", item.name),
        vec![single_change(
            "site",
            &item.id,
            "create",
            None,
            Some(to_value(&item)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

pub fn update_site(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    name: &str,
    location: &str,
    description: &str,
) -> AppResult<Site> {
    let before = require_existing(
        get_row_optional(conn, &format!("{SITE_SELECT} WHERE id=?1"), id, map_site)?,
        "Site",
    )?;
    let after = Site {
        name: name.trim().into(),
        location: location.trim().into(),
        description: description.trim().into(),
        ..before.clone()
    };
    validate_site_model(&after)?;
    if site_name_taken(conn, &after.name, Some(id))? {
        return Err(format!("A site named '{}' already exists", after.name));
    }
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE sites SET name=?1,location=?2,description=?3 WHERE id=?4",
        params![after.name, after.location, after.description, id],
    )
    .map_err(|e| e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        &format!("Updated site {}", after.name),
        vec![single_change(
            "site",
            id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

/// A site cannot be deleted while a network or an asset is still at it, the
/// same rule as networks, so nothing silently loses its place.
pub fn delete_site(conn: &mut Connection, actor: &ActorIdentity, id: &str) -> AppResult<()> {
    let before = require_existing(get_entity_json(conn, "site", id)?, "Site")?;
    let mut used = Vec::new();
    for (label, sql) in [
        ("networks", "SELECT COUNT(*) FROM networks WHERE site_id=?1"),
        ("assets", "SELECT COUNT(*) FROM assets WHERE site_id=?1"),
    ] {
        let count: i64 = conn
            .query_row(sql, params![id], |row| row.get(0))
            .map_err(|e| e.to_string())?;
        if count > 0 {
            used.push(format!("{count} {label}"));
        }
    }
    if !used.is_empty() {
        return Err(format!(
            "Site is still used by {}. Move those records to another site first.",
            used.join(", ")
        ));
    }
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM sites WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        "Deleted site",
        vec![single_change("site", id, "delete", Some(before), None)],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())
}

// ---- asset relations ---------------------------------------------------------

const RELATION_SELECT: &str = "SELECT r.id,r.source_asset_id,s.name,r.target_asset_id,t.name,r.relation_type,r.note,r.created_at FROM asset_relations r JOIN assets s ON s.id=r.source_asset_id JOIN assets t ON t.id=r.target_asset_id";

fn map_relation(row: &rusqlite::Row<'_>) -> rusqlite::Result<AssetRelation> {
    Ok(AssetRelation {
        id: row.get(0)?,
        source_asset_id: row.get(1)?,
        source_name: row.get(2)?,
        target_asset_id: row.get(3)?,
        target_name: row.get(4)?,
        relation_type: row.get(5)?,
        note: row.get(6)?,
        created_at: row.get(7)?,
    })
}

pub fn get_asset_relations(conn: &Connection) -> AppResult<Vec<AssetRelation>> {
    query_vec(
        conn,
        &format!("{RELATION_SELECT} ORDER BY s.name COLLATE NOCASE,r.relation_type,t.name COLLATE NOCASE"),
        [],
        map_relation,
    )
}

fn relation_sql_error(error: rusqlite::Error) -> String {
    let text = error.to_string();
    if text.contains("UNIQUE") {
        "Those assets are already related this way".to_string()
    } else {
        text
    }
}

pub fn relation_phrase(relation_type: &str) -> &'static str {
    match relation_type {
        "runs_on" => "runs on",
        "managed_by" => "is managed by",
        "backs_up_to" => "backs up to",
        "depends_on" => "depends on",
        "connects_to" => "connects to",
        _ => "is related to",
    }
}

pub fn create_asset_relation(
    conn: &mut Connection,
    actor: &ActorIdentity,
    source_asset_id: &str,
    target_asset_id: &str,
    relation_type: &str,
    note: &str,
) -> AppResult<AssetRelation> {
    let source = require_existing(get_asset(conn, source_asset_id)?, "Source asset")?;
    let target = require_existing(get_asset(conn, target_asset_id)?, "Target asset")?;
    let item = AssetRelation {
        id: Uuid::new_v4().to_string(),
        source_asset_id: source.id.clone(),
        source_name: Some(source.name.clone()),
        target_asset_id: target.id.clone(),
        target_name: Some(target.name.clone()),
        relation_type: relation_type.trim().into(),
        note: note.trim().into(),
        created_at: Utc::now().to_rfc3339(),
    };
    validate_relation_model(&item)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO asset_relations(id,source_asset_id,target_asset_id,relation_type,note,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
        params![item.id, item.source_asset_id, item.target_asset_id, item.relation_type, item.note, item.created_at],
    )
    .map_err(relation_sql_error)?;
    record_commit_tx(
        &tx,
        actor,
        &format!(
            "Linked {} {} {}",
            source.name,
            relation_phrase(&item.relation_type),
            target.name
        ),
        vec![single_change(
            "asset_relation",
            &item.id,
            "create",
            None,
            Some(to_value(&item)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(item)
}

pub fn update_asset_relation(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
    relation_type: &str,
    note: &str,
) -> AppResult<AssetRelation> {
    let before = require_existing(
        get_row_optional(
            conn,
            &format!("{RELATION_SELECT} WHERE r.id=?1"),
            id,
            map_relation,
        )?,
        "Relation",
    )?;
    let after = AssetRelation {
        relation_type: relation_type.trim().into(),
        note: note.trim().into(),
        ..before.clone()
    };
    validate_relation_model(&after)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE asset_relations SET relation_type=?1,note=?2 WHERE id=?3",
        params![after.relation_type, after.note, id],
    )
    .map_err(relation_sql_error)?;
    record_commit_tx(
        &tx,
        actor,
        "Updated asset relation",
        vec![single_change(
            "asset_relation",
            id,
            "update",
            Some(to_value(&before)?),
            Some(to_value(&after)?),
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(after)
}

pub fn delete_asset_relation(
    conn: &mut Connection,
    actor: &ActorIdentity,
    id: &str,
) -> AppResult<()> {
    let before = require_existing(get_entity_json(conn, "asset_relation", id)?, "Relation")?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM asset_relations WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        "Removed asset relation",
        vec![single_change(
            "asset_relation",
            id,
            "delete",
            Some(before),
            None,
        )],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())
}

// ---- merging duplicate assets ------------------------------------------------

const ASSET_SELECT: &str = "SELECT a.id,a.network_id,n.name,a.name,a.ip_address,a.mac_address,a.asset_type,a.os,a.user_name,a.suspicious,a.compromise_status,a.investigation_status,a.properties,a.scan_results,a.quick_note,a.site_id,a.owner,a.operator,a.origin,a.last_observed,a.created_at FROM assets a LEFT JOIN networks n ON n.id=a.network_id";

fn get_asset(conn: &Connection, id: &str) -> AppResult<Option<Asset>> {
    get_row_optional(
        conn,
        &format!("{ASSET_SELECT} WHERE a.id=?1"),
        id,
        map_asset,
    )
}

/// What a merge moved onto the surviving asset.
#[derive(Debug, Clone, Serialize)]
pub struct AssetMergeSummary {
    pub asset: Asset,
    pub interfaces_moved: usize,
    pub interfaces_dropped: usize,
    pub timeline_events: usize,
    pub sightings: usize,
    pub attack_edges: usize,
    pub relations: usize,
}

fn ids_where<P: rusqlite::Params>(conn: &Connection, sql: &str, args: P) -> AppResult<Vec<String>> {
    query_vec(conn, sql, args, |row| row.get::<_, String>(0))
}

fn tracked_update<P: rusqlite::Params>(
    tx: &Transaction<'_>,
    changes: &mut Vec<EntityChangeInput>,
    entity_type: &str,
    id: &str,
    sql: &str,
    args: P,
) -> AppResult<()> {
    let before = get_entity_json(tx, entity_type, id)?;
    tx.execute(sql, args).map_err(|e| e.to_string())?;
    let after = get_entity_json(tx, entity_type, id)?;
    if before != after {
        changes.push(single_change(entity_type, id, "update", before, after));
    }
    Ok(())
}

fn tracked_delete(
    tx: &Transaction<'_>,
    changes: &mut Vec<EntityChangeInput>,
    entity_type: &str,
    id: &str,
    table: &str,
) -> AppResult<()> {
    let before = get_entity_json(tx, entity_type, id)?;
    tx.execute(&format!("DELETE FROM {table} WHERE id=?1"), params![id])
        .map_err(|e| e.to_string())?;
    if before.is_some() {
        changes.push(single_change(entity_type, id, "delete", before, None));
    }
    Ok(())
}

fn plain_mac(value: Option<&str>) -> String {
    value
        .unwrap_or_default()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// The same NIC recorded twice: the same address, and hardware addresses that
/// agree or are missing on one side (an ARP entry knows the MAC, a typed one
/// does not). Two NICs with nothing to compare are not assumed to be one.
fn same_interface(left: &NetworkInterface, right: &NetworkInterface) -> bool {
    let (left_mac, right_mac) = (
        plain_mac(left.mac_address.as_deref()),
        plain_mac(right.mac_address.as_deref()),
    );
    let ip = left.ip_address.trim();
    if ip.is_empty() && left_mac.is_empty() && right_mac.is_empty() {
        return false;
    }
    ip.eq_ignore_ascii_case(right.ip_address.trim())
        && (left_mac == right_mac || left_mac.is_empty() || right_mac.is_empty())
}

/// For merging: an unknown status loses to a determination, and a clean
/// determination loses to any suspicion.
fn merge_status_rank(status: &str) -> u8 {
    match status {
        "infected" => 3,
        "suspected" => 2,
        "clean" => 1,
        _ => 0,
    }
}

fn origin_rank(origin: &str) -> u8 {
    match origin {
        "client_inventory" => 2,
        "discovered" => 1,
        _ => 0,
    }
}

/// Fold the asset `remove` into the asset `keep`. Everything that pointed at
/// `remove` (interfaces, timeline events, IOC sightings, attack paths, relations)
/// points at `keep` afterwards, `keep`'s empty fields are filled from `remove`,
/// the worse compromise status and the better origin win, and `remove` is
/// deleted. One commit records every change, so a bundle replays the merge.
pub fn merge_assets(
    conn: &mut Connection,
    actor: &ActorIdentity,
    keep_id: &str,
    remove_id: &str,
) -> AppResult<AssetMergeSummary> {
    if keep_id == remove_id {
        return Err("Choose two different assets to merge".into());
    }
    let keep = require_existing(get_asset(conn, keep_id)?, "Asset to keep")?;
    let remove = require_existing(get_asset(conn, remove_id)?, "Asset to merge away")?;
    let keep_before = to_value(&keep)?;
    let keep_nics = get_network_interfaces(conn, Some(keep_id))?;
    let remove_nics = get_network_interfaces(conn, Some(remove_id))?;
    let event_ids = ids_where(
        conn,
        "SELECT id FROM timeline_events WHERE asset_id=?1",
        params![remove_id],
    )?;
    let sighting_ids = ids_where(
        conn,
        "SELECT id FROM ioc_sightings WHERE asset_id=?1",
        params![remove_id],
    )?;
    let edge_ids = ids_where(
        conn,
        "SELECT id FROM attack_edges WHERE (source_kind='asset' AND source_id=?1) OR (target_kind='asset' AND target_id=?1)",
        params![remove_id],
    )?;
    let relation_ids = ids_where(
        conn,
        "SELECT id FROM asset_relations WHERE source_asset_id=?1 OR target_asset_id=?1",
        params![remove_id],
    )?;

    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut changes: Vec<EntityChangeInput> = Vec::new();
    let mut summary = AssetMergeSummary {
        asset: keep.clone(),
        interfaces_moved: 0,
        interfaces_dropped: 0,
        timeline_events: 0,
        sightings: 0,
        attack_edges: 0,
        relations: 0,
    };

    // An asset whose address lives only on its own row gets that NIC first, so
    // the interfaces moved over cannot displace it.
    let mut keep_has_primary = keep_nics.iter().any(|nic| nic.is_primary);
    if keep_nics.is_empty() && (keep.network_id.is_some() || !keep.ip_address.is_empty()) {
        let nic = NetworkInterface {
            id: Uuid::new_v4().to_string(),
            asset_id: keep_id.to_string(),
            name: "Primary".into(),
            ip_address: keep.ip_address.clone(),
            mac_address: keep.mac_address.clone(),
            network_id: keep.network_id.clone(),
            network_name: keep.network_name.clone(),
            is_primary: true,
        };
        tx.execute(
            "INSERT INTO network_interfaces(id,asset_id,name,ip_address,mac_address,network_id,is_primary) VALUES (?1,?2,?3,?4,?5,?6,1)",
            params![nic.id, nic.asset_id, nic.name, nic.ip_address, nic.mac_address, nic.network_id],
        )
        .map_err(|e| e.to_string())?;
        changes.push(single_change(
            "network_interface",
            &nic.id,
            "create",
            None,
            Some(to_value(&nic)?),
        ));
        keep_has_primary = true;
    }
    for nic in &remove_nics {
        if let Some(existing) = keep_nics
            .iter()
            .find(|existing| same_interface(existing, nic))
        {
            // The surviving NIC keeps its identity and learns the MAC it lacked.
            if plain_mac(existing.mac_address.as_deref()).is_empty()
                && !plain_mac(nic.mac_address.as_deref()).is_empty()
            {
                tracked_update(
                    &tx,
                    &mut changes,
                    "network_interface",
                    &existing.id,
                    "UPDATE network_interfaces SET mac_address=?1 WHERE id=?2",
                    params![nic.mac_address, existing.id],
                )?;
            }
            tracked_delete(
                &tx,
                &mut changes,
                "network_interface",
                &nic.id,
                "network_interfaces",
            )?;
            summary.interfaces_dropped += 1;
            continue;
        }
        let make_primary = !keep_has_primary && nic.is_primary;
        keep_has_primary |= make_primary;
        tracked_update(
            &tx,
            &mut changes,
            "network_interface",
            &nic.id,
            "UPDATE network_interfaces SET asset_id=?1,is_primary=?2 WHERE id=?3",
            params![keep_id, if make_primary { 1 } else { 0 }, nic.id],
        )?;
        summary.interfaces_moved += 1;
    }
    if !keep_has_primary {
        // Nothing was primary on either side: promote one, recorded.
        let first = ids_where(
            &tx,
            "SELECT id FROM network_interfaces WHERE asset_id=?1 ORDER BY rowid LIMIT 1",
            params![keep_id],
        )?;
        if let Some(first) = first.first() {
            tracked_update(
                &tx,
                &mut changes,
                "network_interface",
                first,
                "UPDATE network_interfaces SET is_primary=1 WHERE id=?1",
                params![first],
            )?;
        }
    }

    for id in &event_ids {
        tracked_update(
            &tx,
            &mut changes,
            "timeline_event",
            id,
            "UPDATE timeline_events SET asset_id=?1 WHERE id=?2",
            params![keep_id, id],
        )?;
        summary.timeline_events += 1;
    }
    for id in &sighting_ids {
        tracked_update(
            &tx,
            &mut changes,
            "ioc_sighting",
            id,
            "UPDATE ioc_sightings SET asset_id=?1 WHERE id=?2",
            params![keep_id, id],
        )?;
        summary.sightings += 1;
    }
    for id in &edge_ids {
        let edge = require_existing(get_entity_json(&tx, "attack_edge", id)?, "Attack edge")?;
        let field = |name: &str| edge[name].as_str().unwrap_or_default().to_string();
        let (source_kind, target_kind) = (field("source_kind"), field("target_kind"));
        let source = if source_kind == "asset" && field("source_id") == remove_id {
            keep_id.to_string()
        } else {
            field("source_id")
        };
        let target = if target_kind == "asset" && field("target_id") == remove_id {
            keep_id.to_string()
        } else {
            field("target_id")
        };
        if source_kind == target_kind && source == target {
            // An edge between the two duplicates would now point at itself.
            tracked_delete(&tx, &mut changes, "attack_edge", id, "attack_edges")?;
        } else {
            tracked_update(
                &tx,
                &mut changes,
                "attack_edge",
                id,
                "UPDATE attack_edges SET source_id=?1,target_id=?2 WHERE id=?3",
                params![source, target, id],
            )?;
        }
        summary.attack_edges += 1;
    }
    for id in &relation_ids {
        let relation = require_existing(get_entity_json(&tx, "asset_relation", id)?, "Relation")?;
        let field = |name: &str| relation[name].as_str().unwrap_or_default().to_string();
        let source = if field("source_asset_id") == remove_id {
            keep_id.to_string()
        } else {
            field("source_asset_id")
        };
        let target = if field("target_asset_id") == remove_id {
            keep_id.to_string()
        } else {
            field("target_asset_id")
        };
        let already: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM asset_relations WHERE source_asset_id=?1 AND target_asset_id=?2 AND relation_type=?3 AND id<>?4",
                params![source, target, field("relation_type"), id],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if source == target || already > 0 {
            tracked_delete(&tx, &mut changes, "asset_relation", id, "asset_relations")?;
        } else {
            tracked_update(
                &tx,
                &mut changes,
                "asset_relation",
                id,
                "UPDATE asset_relations SET source_asset_id=?1,target_asset_id=?2 WHERE id=?3",
                params![source, target, id],
            )?;
        }
        summary.relations += 1;
    }

    // The surviving record keeps its own values and takes what it lacked.
    let compromise = if merge_status_rank(&remove.compromise_status)
        > merge_status_rank(&keep.compromise_status)
    {
        remove.compromise_status.clone()
    } else {
        keep.compromise_status.clone()
    };
    let investigation = if keep.investigation_status == remove.investigation_status {
        keep.investigation_status.clone()
    } else {
        "in_progress".to_string()
    };
    let origin = if origin_rank(&remove.origin) > origin_rank(&keep.origin) {
        remove.origin.clone()
    } else {
        keep.origin.clone()
    };
    let last_observed = match (
        keep.last_observed.as_deref(),
        remove.last_observed.as_deref(),
    ) {
        (Some(a), Some(b)) => Some(if b > a { b } else { a }.to_string()),
        (Some(a), None) => Some(a.to_string()),
        (None, Some(b)) => Some(b.to_string()),
        (None, None) => None,
    };
    let mut quick_note = match (keep.quick_note.as_deref(), remove.quick_note.as_deref()) {
        (Some(a), Some(b)) if a != b => Some(format!("{a} | {b}")),
        (Some(a), _) => Some(a.to_string()),
        (None, Some(b)) => Some(b.to_string()),
        (None, None) => None,
    };
    if !keep.name.eq_ignore_ascii_case(&remove.name) {
        let alias = format!("also known as {}", remove.name);
        quick_note = Some(match quick_note {
            Some(note) => format!("{note} | {alias}"),
            None => alias,
        });
    }
    tx.execute(
        "UPDATE assets SET os=?1,user_name=?2,site_id=?3,owner=?4,operator=?5,origin=?6,last_observed=?7,
         compromise_status=?8,investigation_status=?9,suspicious=?10,properties=?11,scan_results=?12,quick_note=?13 WHERE id=?14",
        params![
            keep.os.clone().or_else(|| remove.os.clone()),
            keep.user_name.clone().or_else(|| remove.user_name.clone()),
            keep.site_id.clone().or_else(|| remove.site_id.clone()),
            keep.owner.clone().or_else(|| remove.owner.clone()),
            keep.operator.clone().or_else(|| remove.operator.clone()),
            origin,
            last_observed,
            compromise,
            investigation,
            if matches!(compromise.as_str(), "suspected" | "infected") { 1 } else { 0 },
            keep.properties.clone().or_else(|| remove.properties.clone()),
            keep.scan_results.clone().or_else(|| remove.scan_results.clone()),
            quick_note,
            keep_id,
        ],
    )
    .map_err(|e| e.to_string())?;
    // The address, zone, and MAC columns follow the primary interface.
    reconcile_asset_primary_interface(&tx, keep_id)?;

    tracked_delete(&tx, &mut changes, "asset", remove_id, "assets")?;
    let keep_after = require_existing(get_entity_json(&tx, "asset", keep_id)?, "Asset to keep")?;
    if keep_after != keep_before {
        changes.push(single_change(
            "asset",
            keep_id,
            "update",
            Some(keep_before),
            Some(keep_after),
        ));
    }
    record_commit_tx(
        &tx,
        actor,
        &format!("Merged asset {} into {}", remove.name, keep.name),
        changes,
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    summary.asset = require_existing(get_asset(conn, keep_id)?, "Asset to keep")?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::get_history;

    fn actor(name: &str) -> ActorIdentity {
        ActorIdentity::new(name.to_string(), None, Vec::new()).unwrap()
    }

    fn fresh_case() -> (Connection, Case, ActorIdentity) {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();
        let case = create_case_record(&conn, "IR-42", "Test", "Client", "Alice").unwrap();
        (conn, case, actor("Alice"))
    }

    #[test]
    fn case_updates_preserve_legacy_investigator_and_use_session_attribution() {
        let (mut conn, _, active_expert) = fresh_case();
        let updated = update_case(
            &mut conn,
            &active_expert,
            "IR-42",
            "Updated test",
            "Client",
            "active",
        )
        .unwrap();
        assert_eq!(updated.investigator, "Alice");
        let stored = get_case(&conn).unwrap().unwrap();
        assert_eq!(stored.investigator, "Alice");
        let history = get_history(&conn, 1).unwrap();
        assert_eq!(history[0].author_name, "Alice");
        assert_eq!(
            history[0].changes[0].after.as_ref().unwrap()["investigator"],
            "Alice"
        );
    }

    fn add_network(
        conn: &mut Connection,
        actor: &ActorIdentity,
        name: &str,
        subnet: &str,
    ) -> Network {
        create_network(conn, actor, name, subnet, "LAN", "", None).unwrap()
    }

    #[test]
    fn layer_two_vlan_can_be_recorded_before_its_subnet_is_known() {
        let (mut conn, _, active_expert) = fresh_case();
        let network = create_network(
            &mut conn,
            &active_expert,
            "Camera VLAN",
            "",
            "LAN",
            "Discovered from switch configuration",
            Some("20"),
        )
        .unwrap();
        assert_eq!(network.subnet, "");
        assert_eq!(network.vlan_id.as_deref(), Some("20"));
    }

    #[test]
    fn network_created_after_endpoints_links_them_by_subnet() {
        let (mut conn, _, active_expert) = fresh_case();
        let asset = create_asset(
            &mut conn,
            &active_expert,
            None,
            "SRV-1",
            "10.0.0.5",
            None,
            "server",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap();
        assert!(asset.network_id.is_none());
        let extra = create_network_interface(
            &mut conn,
            &active_expert,
            &asset.id,
            "Eth1",
            "10.0.0.9",
            None,
            None,
            false,
        )
        .unwrap();
        assert!(extra.network_id.is_none());

        let network = add_network(&mut conn, &active_expert, "Office", "10.0.0.0/24");

        let interfaces = get_network_interfaces(&conn, Some(&asset.id)).unwrap();
        assert!(!interfaces.is_empty());
        assert!(interfaces
            .iter()
            .all(|item| item.network_id.as_deref() == Some(network.id.as_str())));
        let projected = get_assets(&conn)
            .unwrap()
            .into_iter()
            .find(|a| a.id == asset.id)
            .unwrap();
        assert_eq!(projected.network_id.as_deref(), Some(network.id.as_str()));
        assert_eq!(
            get_assets_by_network(&conn, &network.id)
                .unwrap()
                .iter()
                .filter(|a| a.id == asset.id)
                .count(),
            1
        );
        let history = get_history(&conn, 1).unwrap();
        assert!(history[0].message.contains("linked"));
        assert!(history[0].changes.iter().any(
            |change| change.entity_type == "network_interface" && change.operation == "update"
        ));
    }

    #[test]
    fn network_subnet_edit_backfills_newly_matching_endpoints() {
        let (mut conn, _, active_expert) = fresh_case();
        let dmz = add_network(&mut conn, &active_expert, "DMZ", "172.16.0.0/24");
        let asset = create_asset(
            &mut conn,
            &active_expert,
            None,
            "WEB-1",
            "10.20.30.40",
            None,
            "server",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap();
        assert!(asset.network_id.is_none());

        update_network(
            &mut conn,
            &active_expert,
            &dmz.id,
            "DMZ",
            "10.20.30.0/24",
            "DMZ",
            "",
            None,
        )
        .unwrap();

        let projected = get_assets(&conn)
            .unwrap()
            .into_iter()
            .find(|a| a.id == asset.id)
            .unwrap();
        assert_eq!(projected.network_id.as_deref(), Some(dmz.id.as_str()));
    }

    #[test]
    fn endpoints_without_a_zone_follow_their_ip_into_the_most_specific_subnet() {
        let (mut conn, _, active_expert) = fresh_case();
        let wide = add_network(&mut conn, &active_expert, "Corp", "10.0.0.0/16");
        let narrow = add_network(&mut conn, &active_expert, "Servers", "10.0.0.0/24");
        let asset = create_asset(
            &mut conn,
            &active_expert,
            None,
            "SRV-1",
            "192.168.1.10",
            None,
            "server",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap();
        assert!(asset.network_id.is_none());

        let in_narrow = create_network_interface(
            &mut conn,
            &active_expert,
            &asset.id,
            "Eth0",
            "10.0.0.5",
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(in_narrow.network_id.as_deref(), Some(narrow.id.as_str()));
        assert_eq!(in_narrow.network_name.as_deref(), Some("Servers"));

        let in_wide = create_network_interface(
            &mut conn,
            &active_expert,
            &asset.id,
            "Eth1",
            "10.0.200.5",
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(in_wide.network_id.as_deref(), Some(wide.id.as_str()));

        let ipv6 = create_network_interface(
            &mut conn,
            &active_expert,
            &asset.id,
            "Eth2",
            "2001:db8::1",
            None,
            None,
            false,
        )
        .unwrap();
        assert!(ipv6.network_id.is_none());

        // An explicit assignment is never overridden, not even by a more
        // specific subnet added later.
        let explicit = create_network_interface(
            &mut conn,
            &active_expert,
            &asset.id,
            "Eth3",
            "10.0.0.7",
            None,
            Some(&wide.id),
            false,
        )
        .unwrap();
        assert_eq!(explicit.network_id.as_deref(), Some(wide.id.as_str()));
        let narrow_too = add_network(&mut conn, &active_expert, "Narrow", "10.0.0.0/28");
        assert_ne!(explicit.network_id.as_deref(), Some(narrow_too.id.as_str()));
    }

    #[test]
    fn interface_zone_can_be_cleared_and_derives_again_only_on_ip_change() {
        let (mut conn, _, active_expert) = fresh_case();
        let office = add_network(&mut conn, &active_expert, "Office", "10.0.0.0/24");
        let asset = create_asset(
            &mut conn,
            &active_expert,
            None,
            "PC-1",
            "10.0.0.5",
            None,
            "workstation",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap();
        let iface = create_network_interface(
            &mut conn,
            &active_expert,
            &asset.id,
            "Eth0",
            "10.0.0.5",
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(iface.network_id.as_deref(), Some(office.id.as_str()));

        let cleared = update_network_interface(
            &mut conn,
            &active_expert,
            &iface.id,
            "Eth0",
            "10.0.0.5",
            None,
            None,
            false,
        )
        .unwrap();
        assert!(cleared.network_id.is_none());

        let moved = update_network_interface(
            &mut conn,
            &active_expert,
            &iface.id,
            "Eth0",
            "10.0.0.42",
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(moved.network_id.as_deref(), Some(office.id.as_str()));
    }

    #[test]
    fn equally_specific_subnets_leave_endpoints_unassigned() {
        let (mut conn, _, active_expert) = fresh_case();
        // Two isolated departments that both use 10.0.0.0/24.
        let site_a = add_network(&mut conn, &active_expert, "Site A users", "10.0.0.0/24");
        let site_b = add_network(&mut conn, &active_expert, "Site B users", "10.0.0.0/24");
        let asset = create_asset(
            &mut conn,
            &active_expert,
            None,
            "APP01",
            "10.0.0.15",
            None,
            "server",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap();
        assert!(asset.network_id.is_none());
        let extra = create_network_interface(
            &mut conn,
            &active_expert,
            &asset.id,
            "Eth1",
            "10.0.0.16",
            None,
            None,
            false,
        )
        .unwrap();
        assert!(extra.network_id.is_none());

        // Editing one twin does not let it claim the shared range either.
        update_network(
            &mut conn,
            &active_expert,
            &site_b.id,
            "Site B users",
            "10.0.0.0/24",
            "LAN",
            "Branch office",
            None,
        )
        .unwrap();
        assert!(get_assets_by_network(&conn, &site_a.id).unwrap().is_empty());
        assert!(get_assets_by_network(&conn, &site_b.id).unwrap().is_empty());
        assert!(get_network_interfaces(&conn, Some(&asset.id))
            .unwrap()
            .iter()
            .all(|item| item.network_id.is_none()));

        // A strictly more specific subnet is still an unambiguous home.
        let servers = add_network(&mut conn, &active_expert, "Site A servers", "10.0.0.0/25");
        let stored = get_assets(&conn)
            .unwrap()
            .into_iter()
            .find(|item| item.id == asset.id)
            .unwrap();
        assert_eq!(stored.network_id.as_deref(), Some(servers.id.as_str()));
    }

    #[test]
    fn mobile_and_firewall_assets_with_free_text_findings_are_accepted() {
        let (mut conn, _, active_expert) = fresh_case();
        let finding = "Finance says they own it. Ask infrastructure for logs.";
        let phone = create_asset(
            &mut conn,
            &active_expert,
            None,
            "CEO-PHONE",
            "",
            None,
            "mobile",
            Some("Android 14"),
            None,
            "unknown",
            "not_started",
            Some(finding),
            None,
        )
        .unwrap();
        assert_eq!(phone.asset_type, "mobile");
        assert_eq!(phone.properties.as_deref(), Some(finding));

        let edge = create_asset(
            &mut conn,
            &active_expert,
            None,
            "EDGE-FW",
            "203.0.113.2",
            None,
            "firewall",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap();
        let updated = update_asset(
            &mut conn,
            &active_expert,
            &edge.id,
            None,
            "EDGE-FW",
            "203.0.113.2",
            None,
            "firewall",
            None,
            None,
            "unknown",
            "in_progress",
            Some("Seen in the VPN logs"),
            None,
        )
        .unwrap();
        assert_eq!(updated.properties.as_deref(), Some("Seen in the VPN logs"));

        // Scan results stay structured, and unknown types are still refused.
        let not_json = create_asset(
            &mut conn,
            &active_expert,
            None,
            "SCAN",
            "",
            None,
            "server",
            None,
            None,
            "unknown",
            "not_started",
            None,
            Some("open ports: 22"),
        );
        assert!(not_json
            .unwrap_err()
            .contains("Scan results must be valid JSON"));
        let unknown = create_asset(
            &mut conn,
            &active_expert,
            None,
            "TOASTER",
            "",
            None,
            "toaster",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        );
        assert!(unknown.unwrap_err().contains("Invalid asset type"));

        // Reviewed imports and merged bundles accept the same types and text.
        let mut value = to_value(&phone).unwrap();
        value["asset_type"] = Value::String("firewall".into());
        value["properties"] = Value::String("Plain text, not JSON".into());
        let tx = conn.transaction().unwrap();
        upsert_entity_json(&tx, "asset", &value).unwrap();
        tx.commit().unwrap();
        let stored = get_assets(&conn)
            .unwrap()
            .into_iter()
            .find(|item| item.id == phone.id)
            .unwrap();
        assert_eq!(stored.asset_type, "firewall");
        assert_eq!(stored.properties.as_deref(), Some("Plain text, not JSON"));
    }

    #[test]
    fn quick_notes_attach_to_assets_networks_and_firewalls() {
        let (mut conn, case, active_expert) = fresh_case();
        let network = add_network(&mut conn, &active_expert, "Office", "10.0.0.0/24");
        let asset = create_asset(
            &mut conn,
            &active_expert,
            Some(&network.id),
            "PC-1",
            "10.0.0.5",
            None,
            "workstation",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap();
        let firewall = create_firewall(
            &mut conn,
            &active_expert,
            Some(&network.id),
            "Edge",
            None,
            None,
            None,
            None,
        )
        .unwrap();

        set_quick_note(
            &mut conn,
            &active_expert,
            "asset",
            &asset.id,
            Some("Reimaged on site"),
        )
        .unwrap();
        set_quick_note(
            &mut conn,
            &active_expert,
            "network",
            &network.id,
            Some("Client HQ segment"),
        )
        .unwrap();
        set_quick_note(
            &mut conn,
            &active_expert,
            "firewall",
            &firewall.id,
            Some("Terminates the site VPN"),
        )
        .unwrap();

        assert_eq!(
            get_assets(&conn)
                .unwrap()
                .iter()
                .find(|item| item.id == asset.id)
                .and_then(|item| item.quick_note.as_deref()),
            Some("Reimaged on site")
        );
        assert_eq!(
            get_networks(&conn)
                .unwrap()
                .iter()
                .find(|item| item.id == network.id)
                .and_then(|item| item.quick_note.as_deref()),
            Some("Client HQ segment")
        );
        assert_eq!(
            get_firewalls(&conn)
                .unwrap()
                .iter()
                .find(|item| item.id == firewall.id)
                .and_then(|item| item.quick_note.as_deref()),
            Some("Terminates the site VPN")
        );
        let history = get_history(&conn, 1).unwrap();
        assert_eq!(history[0].message, "Set quick note on firewall Edge");
        assert_eq!(history[0].changes[0].entity_type, "firewall");
        assert_eq!(
            history[0].changes[0].after.as_ref().unwrap()["quick_note"],
            "Terminates the site VPN"
        );

        // A whitespace-only note clears the field instead of storing blanks,
        // and unsupported entities are rejected.
        set_quick_note(&mut conn, &active_expert, "asset", &asset.id, Some("   ")).unwrap();
        assert!(get_assets(&conn)
            .unwrap()
            .iter()
            .find(|item| item.id == asset.id)
            .is_none_or(|item| item.quick_note.is_none()));
        assert!(set_quick_note(&mut conn, &active_expert, "note", "nope", Some("x")).is_err());

        // Full snapshots carry the notes to another case file.
        let data = export_case_data(&conn).unwrap();
        let mut target = Connection::open_in_memory().unwrap();
        init_database(&target).unwrap();
        target.execute(
            "INSERT INTO cases(id,name,description,client_name,investigator,status,created_at,updated_at,metadata) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![case.id, case.name, case.description, case.client_name, case.investigator, case.status, case.created_at, case.updated_at, case.metadata],
        )
        .unwrap();
        initialize_history(&target).unwrap();
        import_case_data(&mut target, &active_expert, &data).unwrap();
        assert_eq!(
            get_networks(&target)
                .unwrap()
                .iter()
                .find(|item| item.id == network.id)
                .and_then(|item| item.quick_note.as_deref()),
            Some("Client HQ segment")
        );
    }

    #[test]
    fn migrates_legacy_orphans_and_backfills_primary_interface() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE cases(id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT NOT NULL,client_name TEXT NOT NULL,investigator TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,metadata TEXT);
             CREATE TABLE networks(id TEXT PRIMARY KEY,name TEXT NOT NULL,subnet TEXT NOT NULL,network_type TEXT NOT NULL,description TEXT NOT NULL,vlan_id TEXT,created_at TEXT NOT NULL);
             CREATE TABLE assets(id TEXT PRIMARY KEY,network_id TEXT,name TEXT NOT NULL,ip_address TEXT NOT NULL,mac_address TEXT,asset_type TEXT NOT NULL,os TEXT,user_name TEXT,suspicious INTEGER NOT NULL,properties TEXT,scan_results TEXT,created_at TEXT NOT NULL);
             CREATE TABLE timeline_events(id TEXT PRIMARY KEY,asset_id TEXT,timestamp TEXT NOT NULL,event_type TEXT NOT NULL,description TEXT NOT NULL,severity TEXT NOT NULL,source TEXT,mitre_tactic TEXT,mitre_technique TEXT,created_at TEXT NOT NULL);
             CREATE TABLE notes(id TEXT PRIMARY KEY,title TEXT NOT NULL,content TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
             CREATE TABLE iocs(id TEXT PRIMARY KEY,ioc_type TEXT NOT NULL,value TEXT NOT NULL,description TEXT NOT NULL,threat_level TEXT NOT NULL,first_seen TEXT,last_seen TEXT,created_at TEXT NOT NULL);
             INSERT INTO cases VALUES('case-1','Legacy','','Client','Alice','active','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z',NULL);
             INSERT INTO assets VALUES('asset-1','missing-network','PC-1','10.1.2.3',NULL,'workstation',NULL,NULL,1,NULL,NULL,'2025-01-01T00:00:00Z');"
        ).unwrap();

        validate_and_migrate_case(&mut conn).unwrap();

        let asset = get_assets(&conn).unwrap().pop().unwrap();
        assert_eq!(asset.network_id, None);
        assert_eq!(asset.compromise_status, "suspected");
        let interfaces = get_network_interfaces(&conn, Some("asset-1")).unwrap();
        assert_eq!(interfaces.len(), 1);
        assert!(interfaces[0].is_primary);
        assert_eq!(interfaces[0].ip_address, "10.1.2.3");
        assert_eq!(
            conn.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            9
        );
        // The v7 investigation tables exist after migrating a legacy case.
        for table in ["ioc_sightings", "attack_edges", "investigation_views"] {
            assert!(table_exists(&conn, table).unwrap(), "{table} missing");
        }
        // Schema 9: sites, relations, and the environment columns, defaulted.
        for table in ["sites", "asset_relations"] {
            assert!(table_exists(&conn, table).unwrap(), "{table} missing");
        }
        for (table, column) in [
            ("networks", "site_id"),
            ("networks", "owner"),
            ("networks", "operator"),
            ("assets", "site_id"),
            ("assets", "owner"),
            ("assets", "operator"),
            ("assets", "origin"),
            ("assets", "last_observed"),
        ] {
            assert!(
                column_exists(&conn, table, column).unwrap(),
                "{table}.{column}"
            );
        }
        assert_eq!(asset.origin, "unknown");
        assert!(asset.site_id.is_none() && asset.owner.is_none() && asset.last_observed.is_none());
    }

    #[test]
    fn topology_views_round_trip_and_are_scoped_by_layout() {
        let (conn, _, _) = fresh_case();
        let first = save_topology_view(
            &conn,
            "grid",
            vec![TopologyNodePosition {
                id: "asset-a".into(),
                x: 12.5,
                y: -4.0,
            }],
            1.25,
            40.0,
            80.0,
        )
        .unwrap();
        assert_eq!(get_topology_view(&conn, "grid").unwrap(), Some(first));
        assert_eq!(get_topology_view(&conn, "circle").unwrap(), None);

        let updated = save_topology_view(
            &conn,
            "grid",
            vec![TopologyNodePosition {
                id: "asset-a".into(),
                x: 90.0,
                y: 30.0,
            }],
            0.8,
            -12.0,
            15.0,
        )
        .unwrap();
        assert_eq!(get_topology_view(&conn, "grid").unwrap(), Some(updated));
        assert!(get_topology_view(&conn, "not-a-layout").is_err());
        assert!(save_topology_view(&conn, "grid", Vec::new(), f64::NAN, 0.0, 0.0).is_err());
    }

    #[test]
    fn firewall_interfaces_and_nat_are_structured_and_exported() {
        let (mut conn, _, actor) = fresh_case();
        let wan = add_network(&mut conn, &actor, "Internet edge", "203.0.113.0/24");
        let dmz = add_network(&mut conn, &actor, "DMZ", "10.20.0.0/24");
        let firewall = create_firewall(
            &mut conn,
            &actor,
            Some(&wan.id),
            "PA-EDGE",
            Some("Palo Alto"),
            Some("PA-440"),
            None,
            None,
        )
        .unwrap();
        let outside = create_firewall_interface(
            &mut conn,
            &actor,
            &firewall.id,
            "ethernet1/1",
            vec!["203.0.113.10/24".into(), "2001:db8::10/64".into()],
            Some("00:11:22:33:44:55"),
            Some(&wan.id),
            None,
            "wan",
            true,
            "ISP handoff",
        )
        .unwrap();
        let inside = create_firewall_interface(
            &mut conn,
            &actor,
            &firewall.id,
            "ethernet1/2",
            vec!["10.20.0.1/24".into()],
            None,
            Some(&dmz.id),
            Some("20"),
            "dmz",
            false,
            "DMZ gateway",
        )
        .unwrap();
        let vip = create_firewall_nat_rule(
            &mut conn,
            &actor,
            &firewall.id,
            "Exchange HTTPS",
            "port_mapping",
            true,
            "tcp",
            None,
            Some("203.0.113.10"),
            Some("443"),
            None,
            Some("10.20.0.25"),
            Some("8443"),
            Some(&outside.id),
            Some(&inside.id),
            "Public VIP to Exchange",
        )
        .unwrap();

        assert_eq!(outside.ip_addresses.len(), 2);
        assert_eq!(vip.nat_type, "port_mapping");
        let exported = export_case_data(&conn).unwrap();
        assert_eq!(exported.format_version, 4);
        assert_eq!(exported.firewall_interfaces.len(), 2);
        assert_eq!(exported.firewall_nat_rules.len(), 1);
        assert!(delete_network(&mut conn, &actor, &dmz.id)
            .unwrap_err()
            .contains("firewall interfaces"));
    }

    #[test]
    fn primary_interface_changes_keep_asset_projection_in_sync() {
        let (mut conn, _, actor) = fresh_case();
        let first = add_network(&mut conn, &actor, "Office", "10.0.0.0/24");
        let second = add_network(&mut conn, &actor, "DMZ", "172.16.0.0/24");
        let asset = create_asset(
            &mut conn,
            &actor,
            Some(&first.id),
            "PC-1",
            "10.0.0.5",
            None,
            "workstation",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap();
        let secondary = create_network_interface(
            &mut conn,
            &actor,
            &asset.id,
            "Ethernet 2",
            "172.16.0.8",
            Some("00:11:22:33:44:55"),
            Some(&second.id),
            true,
        )
        .unwrap();

        let projected = get_assets(&conn)
            .unwrap()
            .into_iter()
            .find(|item| item.id == asset.id)
            .unwrap();
        assert_eq!(projected.network_id.as_deref(), Some(second.id.as_str()));
        assert_eq!(projected.ip_address, "172.16.0.8");
        assert_eq!(
            get_network_interfaces(&conn, Some(&asset.id))
                .unwrap()
                .iter()
                .filter(|item| item.is_primary)
                .count(),
            1
        );

        delete_network_interface(&mut conn, &actor, &secondary.id).unwrap();
        let projected = get_assets(&conn)
            .unwrap()
            .into_iter()
            .find(|item| item.id == asset.id)
            .unwrap();
        assert_eq!(projected.network_id.as_deref(), Some(first.id.as_str()));
        assert_eq!(projected.ip_address, "10.0.0.5");
    }

    #[test]
    fn network_delete_is_blocked_and_asset_delete_retains_timeline_evidence() {
        let (mut conn, _, actor) = fresh_case();
        let network = add_network(&mut conn, &actor, "Office", "10.0.0.0/24");
        let asset = create_asset(
            &mut conn,
            &actor,
            Some(&network.id),
            "PC-1",
            "10.0.0.5",
            None,
            "workstation",
            None,
            None,
            "suspected",
            "in_progress",
            None,
            None,
        )
        .unwrap();
        let event = create_timeline_event(
            &mut conn,
            &actor,
            Some(&asset.id),
            Some("2025-01-02T03:04:05+02:00"),
            Some("UTC"),
            Some("2025-01-02T03:04:05+02:00"),
            Some("UTC"),
            None,
            "logon",
            "Suspicious logon",
            "high",
            None,
            None,
            None,
        )
        .unwrap();

        let error = delete_network(&mut conn, &actor, &network.id).unwrap_err();
        assert!(error.contains("assets"));
        assert!(error.contains("interfaces"));
        delete_asset(&mut conn, &actor, &asset.id).unwrap();
        let retained = get_timeline_events(&conn)
            .unwrap()
            .into_iter()
            .find(|item| item.id == event.id)
            .unwrap();
        assert_eq!(retained.asset_id, None);
        assert_eq!(retained.timestamp, "2025-01-02T01:04:05.000Z");
        assert!(delete_asset(&mut conn, &actor, "missing")
            .unwrap_err()
            .contains("not found"));
    }

    #[test]
    fn flexible_timestamps_support_partial_local_iso_and_epoch_values() {
        let date_only = parse_timestamp_preview("18-07-2026", "UTC", 0).unwrap();
        assert_eq!(date_only.corrected_utc, "2026-07-18T00:00:00.000Z");
        assert_eq!(date_only.precision, "date");

        let local = parse_timestamp_preview("18-07-2026 14:05", "+07:00", 0).unwrap();
        assert_eq!(local.corrected_utc, "2026-07-18T07:05:00.000Z");
        assert_eq!(local.precision, "minute");

        let iso = parse_timestamp_preview("2026-07-18T07:05:03.127Z", "UTC", 0).unwrap();
        let seconds = parse_timestamp_preview("1784358303.127", "UTC", 0).unwrap();
        let millis = parse_timestamp_preview("1784358303127", "UTC", 0).unwrap();
        assert_eq!(iso.epoch_millis, seconds.epoch_millis);
        assert_eq!(seconds.epoch_millis, millis.epoch_millis);
    }

    #[test]
    fn clock_profile_correction_preserves_raw_evidence_time() {
        let (mut conn, _, actor) = fresh_case();
        let profile = create_clock_profile(
            &mut conn,
            &actor,
            "DC01",
            "Server is 90 seconds slow",
            "18-07-2026 10:00:00",
            "UTC",
            "18-07-2026 10:01:30",
            "UTC",
        )
        .unwrap();
        assert_eq!(profile.offset_ms, 90_000);
        let event = create_timeline_event(
            &mut conn,
            &actor,
            None,
            Some("18-07-2026 11:00"),
            Some("UTC"),
            None,
            None,
            Some(&profile.id),
            "logon",
            "Server event",
            "medium",
            Some("security.log"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(event.raw_timestamp.as_deref(), Some("18-07-2026 11:00"));
        assert_eq!(event.timestamp, "2026-07-18T11:01:30.000Z");
        assert_eq!(event.clock_offset_ms, 90_000);
        assert_eq!(event.clock_profile_name.as_deref(), Some("DC01"));
    }

    #[test]
    fn timeline_allows_unknown_and_independent_server_and_correct_times() {
        let (mut conn, _, actor) = fresh_case();
        let unknown = create_timeline_event(
            &mut conn,
            &actor,
            None,
            None,
            None,
            None,
            None,
            None,
            "other",
            "Observed event with time still unknown",
            "info",
            None,
            None,
            None,
        )
        .unwrap();
        assert!(unknown.timestamp.is_empty());
        assert!(unknown.server_timestamp_utc.is_none());

        let server_only = create_timeline_event(
            &mut conn,
            &actor,
            None,
            Some("06-08-2000 04:23"),
            Some("UTC"),
            None,
            None,
            None,
            "other",
            "Server time only",
            "info",
            None,
            None,
            None,
        )
        .unwrap();
        assert!(server_only.timestamp.is_empty());
        assert_eq!(
            server_only.server_timestamp_utc.as_deref(),
            Some("2000-08-06T04:23:00.000Z")
        );

        let direct = create_timeline_event(
            &mut conn,
            &actor,
            None,
            Some("06-08-2000 04:23"),
            Some("UTC"),
            Some("06-08-2000 11:23"),
            Some("Asia/Novosibirsk"),
            None,
            "other",
            "Directly correlated",
            "info",
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(direct.timestamp, "2000-08-06T04:23:00.000Z");
        assert_eq!(direct.clock_offset_ms, 0);
        assert_eq!(
            direct.correct_timestamp_raw.as_deref(),
            Some("06-08-2000 11:23")
        );
    }

    #[test]
    fn ambiguous_daylight_saving_time_requires_an_explicit_offset() {
        let error = parse_timestamp_preview("26-10-2025 01:30", "Europe/London", 0).unwrap_err();
        assert!(error.contains("occurs twice"));
        assert!(parse_timestamp_preview("2025-10-26T01:30:00+01:00", "Europe/London", 0).is_ok());
    }

    #[test]
    fn snapshot_import_is_same_case_repeatable_and_transactional() {
        let (mut source, case, source_actor) = fresh_case();
        let network = add_network(&mut source, &source_actor, "Office", "10.0.0.0/24");
        create_asset(
            &mut source,
            &source_actor,
            Some(&network.id),
            "PC-1",
            "10.0.0.5",
            None,
            "workstation",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap();
        let data = export_case_data(&source).unwrap();

        let mut target = Connection::open_in_memory().unwrap();
        init_database(&target).unwrap();
        target.execute("INSERT INTO cases(id,name,description,client_name,investigator,status,created_at,updated_at,metadata) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![case.id,case.name,case.description,case.client_name,case.investigator,case.status,case.created_at,case.updated_at,case.metadata]).unwrap();
        initialize_history(&target).unwrap();
        let target_actor = actor("Merger");

        let first = import_case_data(&mut target, &target_actor, &data).unwrap();
        assert_eq!(first.entities["assets"].inserted, 1);
        assert_eq!(first.entities["network_interfaces"].inserted, 1);
        let second = import_case_data(&mut target, &target_actor, &data).unwrap();
        assert_eq!(second.entities["assets"].skipped, 1);

        let mut malformed = data.clone();
        malformed.networks.push(Network {
            id: "rollback-network".into(),
            name: "Rollback".into(),
            subnet: "192.0.2.0/24".into(),
            network_type: "LAN".into(),
            description: String::new(),
            vlan_id: None,
            quick_note: None,
            site_id: None,
            owner: None,
            operator: None,
            created_at: Utc::now().to_rfc3339(),
        });
        malformed.assets.push(Asset {
            id: "bad-asset".into(),
            network_id: Some("does-not-exist".into()),
            network_name: None,
            name: "Bad".into(),
            ip_address: "192.0.2.2".into(),
            mac_address: None,
            asset_type: "workstation".into(),
            os: None,
            user_name: None,
            suspicious: false,
            compromise_status: "unknown".into(),
            investigation_status: "not_started".into(),
            properties: None,
            scan_results: None,
            quick_note: None,
            site_id: None,
            owner: None,
            operator: None,
            origin: "unknown".into(),
            last_observed: None,
            created_at: Utc::now().to_rfc3339(),
        });
        assert!(import_case_data(&mut target, &target_actor, &malformed).is_err());
        assert!(!exists(&target, "networks", "rollback-network").unwrap());

        let (mut other, _, other_actor) = fresh_case();
        assert!(import_case_data(&mut other, &other_actor, &data)
            .unwrap_err()
            .contains("different case"));
    }

    #[test]
    fn legacy_json_defaults_new_asset_fields() {
        let value = serde_json::json!({
            "case_info": null,
            "networks": [],
            "assets": [{
                "id":"a","network_id":null,"name":"PC","ip_address":"","mac_address":null,
                "asset_type":"workstation","os":null,"user_name":null,"suspicious":false,
                "properties":null,"scan_results":null,"created_at":"2025-01-01T00:00:00Z"
            }],
            "timeline_events": [], "notes": [], "iocs": [], "firewalls": [], "network_connections": []
        });
        let parsed: ExportData = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.format_version, 1);
        assert!(parsed.network_interfaces.is_empty());
        assert_eq!(parsed.assets[0].compromise_status, "unknown");
        assert_eq!(parsed.assets[0].investigation_status, "not_started");
        assert!(parsed.ioc_sightings.is_empty());
        assert!(parsed.attack_edges.is_empty());
        assert!(parsed.investigation_views.is_empty());
    }

    fn add_asset(conn: &mut Connection, actor: &ActorIdentity, network: &str, name: &str) -> Asset {
        create_asset(
            conn,
            actor,
            Some(network),
            name,
            "10.0.0.9",
            None,
            "workstation",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap()
    }

    fn add_ioc(conn: &mut Connection, actor: &ActorIdentity, value: &str) -> Ioc {
        create_ioc(conn, actor, "IP", value, "", "high", None, None).unwrap()
    }

    #[test]
    fn sighting_creation_syncs_infection_state_and_never_downgrades() {
        let (mut conn, _, actor) = fresh_case();
        let network = add_network(&mut conn, &actor, "Office", "10.0.0.0/24");
        let asset = add_asset(&mut conn, &actor, &network.id, "PC-1");
        let ioc = add_ioc(&mut conn, &actor, "203.0.113.7");

        let sighting = create_ioc_sighting(
            &mut conn,
            &actor,
            &ioc.id,
            "asset",
            &asset.id,
            Some("2026-07-20T02:14:00Z"),
            "C:\\Windows\\Temp\\payload.exe",
            "Found during triage",
            Some("infected"),
        )
        .unwrap();
        assert_eq!(sighting.entity_kind, "asset");
        assert_eq!(sighting.ioc_value.as_deref(), Some("203.0.113.7"));
        assert_eq!(sighting.entity_name.as_deref(), Some("PC-1"));

        let updated = get_assets(&conn)
            .unwrap()
            .into_iter()
            .find(|item| item.id == asset.id)
            .unwrap();
        assert_eq!(updated.compromise_status, "infected");
        assert!(updated.suspicious);
        // One commit carries both the sighting create and the asset escalation.
        let history = get_history(&conn, 1).unwrap();
        assert_eq!(history[0].changes.len(), 2);

        // A later 'suspected' sighting must not downgrade the infected asset.
        let second = add_ioc(&mut conn, &actor, "203.0.113.8");
        create_ioc_sighting(
            &mut conn,
            &actor,
            &second.id,
            "asset",
            &asset.id,
            None,
            "",
            "",
            Some("suspected"),
        )
        .unwrap();
        let still_infected = get_assets(&conn)
            .unwrap()
            .into_iter()
            .find(|item| item.id == asset.id)
            .unwrap();
        assert_eq!(still_infected.compromise_status, "infected");

        let summary = get_infection_summary(&conn).unwrap();
        let entry = summary
            .entities
            .iter()
            .find(|item| item.entity_id == asset.id)
            .unwrap();
        assert_eq!(entry.sighting_count, 2);
        assert_eq!(entry.max_threat_level, "high");
        assert_eq!(entry.ioc_ids.len(), 2);
        assert_eq!(summary.iocs.len(), 2);

        assert!(create_ioc_sighting(
            &mut conn,
            &actor,
            &ioc.id,
            "network",
            &network.id,
            None,
            "",
            "",
            Some("infected"),
        )
        .unwrap_err()
        .contains("only be raised on assets"));
        assert!(create_ioc_sighting(
            &mut conn, &actor, &ioc.id, "asset", "missing", None, "", "", None,
        )
        .unwrap_err()
        .contains("not found"));
    }

    #[test]
    fn deleting_ioc_or_entity_cascades_sightings_with_history() {
        let (mut conn, _, actor) = fresh_case();
        let network = add_network(&mut conn, &actor, "Office", "10.0.0.0/24");
        let asset = add_asset(&mut conn, &actor, &network.id, "PC-1");
        let ioc = add_ioc(&mut conn, &actor, "203.0.113.7");
        let sighting = create_ioc_sighting(
            &mut conn, &actor, &ioc.id, "asset", &asset.id, None, "", "", None,
        )
        .unwrap();

        delete_ioc(&mut conn, &actor, &ioc.id).unwrap();
        assert!(get_ioc_sightings(&conn, None, None, None)
            .unwrap()
            .is_empty());
        let history = get_history(&conn, 1).unwrap();
        assert!(history[0]
            .changes
            .iter()
            .any(|change| change.entity_type == "ioc_sighting"
                && change.entity_id == sighting.id
                && change.operation == "delete"));

        // Entity deletion also removes its sightings.
        let second = add_ioc(&mut conn, &actor, "203.0.113.9");
        create_ioc_sighting(
            &mut conn, &actor, &second.id, "asset", &asset.id, None, "", "", None,
        )
        .unwrap();
        delete_asset(&mut conn, &actor, &asset.id).unwrap();
        assert!(get_ioc_sightings(&conn, None, None, None)
            .unwrap()
            .is_empty());

        // A network with a sighting refuses deletion, listing the dependency.
        create_ioc_sighting(
            &mut conn,
            &actor,
            &second.id,
            "network",
            &network.id,
            None,
            "",
            "",
            None,
        )
        .unwrap();
        assert!(delete_network(&mut conn, &actor, &network.id)
            .unwrap_err()
            .contains("IOC sightings"));
    }

    #[test]
    fn attack_edges_validate_order_and_ripple_on_deletes() {
        let (mut conn, _, actor) = fresh_case();
        let network = add_network(&mut conn, &actor, "Office", "10.0.0.0/24");
        let web = add_asset(&mut conn, &actor, &network.id, "WEB-01");
        let dc = add_asset(&mut conn, &actor, &network.id, "DC-01");
        let ioc = add_ioc(&mut conn, &actor, "203.0.113.7");
        let event = create_timeline_event(
            &mut conn,
            &actor,
            Some(&web.id),
            Some("2026-07-20T02:14:00Z"),
            Some("UTC"),
            None,
            None,
            None,
            "initial_access",
            "First RDP success",
            "high",
            None,
            None,
            None,
        )
        .unwrap();

        let first = create_attack_edge(
            &mut conn,
            &actor,
            "external",
            "Internet",
            "asset",
            &web.id,
            "Initial access via exposed RDP",
            "",
            "initial_access",
            "confirmed",
            Some("TA0001"),
            Some("T1110.001"),
            Some("2026-07-20T02:14:00Z"),
            Some(&event.id),
            None,
            vec![ioc.id.clone(), ioc.id.clone()],
        )
        .unwrap();
        assert_eq!(first.sequence, 1);
        assert_eq!(first.ioc_ids, vec![ioc.id.clone()]);
        assert_eq!(first.source_name.as_deref(), Some("Internet"));
        assert_eq!(first.target_name.as_deref(), Some("WEB-01"));
        assert!(first.timeline_event_time.is_some());

        let second = create_attack_edge(
            &mut conn,
            &actor,
            "asset",
            &web.id,
            "asset",
            &dc.id,
            "Lateral movement to DC",
            "",
            "lateral_movement",
            "probable",
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(second.sequence, 2);
        let ordered = get_attack_edges(&conn).unwrap();
        assert_eq!(ordered[0].id, first.id);
        assert_eq!(ordered[1].id, second.id);

        // Validation failures.
        assert!(create_attack_edge(
            &mut conn,
            &actor,
            "asset",
            &web.id,
            "asset",
            &web.id,
            "Loop",
            "",
            "other",
            "suspected",
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .unwrap_err()
        .contains("two different entities"));
        assert!(create_attack_edge(
            &mut conn,
            &actor,
            "asset",
            "missing",
            "asset",
            &dc.id,
            "Bad",
            "",
            "other",
            "suspected",
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .unwrap_err()
        .contains("not found"));
        assert!(create_attack_edge(
            &mut conn,
            &actor,
            "external",
            "Internet",
            "asset",
            &dc.id,
            "Bad",
            "",
            "other",
            "suspected",
            None,
            None,
            None,
            None,
            None,
            vec!["missing-ioc".into()],
        )
        .unwrap_err()
        .contains("Linked IOC"));

        // Timeline event deletion detaches, IOC deletion rewrites the link list.
        delete_timeline_event(&mut conn, &actor, &event.id).unwrap();
        let detached = get_attack_edges(&conn)
            .unwrap()
            .into_iter()
            .find(|edge| edge.id == first.id)
            .unwrap();
        assert_eq!(detached.timeline_event_id, None);
        delete_ioc(&mut conn, &actor, &ioc.id).unwrap();
        let unlinked = get_attack_edges(&conn)
            .unwrap()
            .into_iter()
            .find(|edge| edge.id == first.id)
            .unwrap();
        assert!(unlinked.ioc_ids.is_empty());

        // Asset deletion removes the edges that touch it.
        delete_asset(&mut conn, &actor, &web.id).unwrap();
        assert!(get_attack_edges(&conn).unwrap().is_empty());
    }

    #[test]
    fn investigation_views_are_named_validated_and_not_history_tracked() {
        let (mut conn, _, _actor) = fresh_case();
        let commits_before = get_history(&conn, 100).unwrap().len();
        let state = serde_json::json!({
            "version": 1,
            "hidden_network_ids": [],
            "hidden_node_ids": ["asset-x"],
            "filters": {"compromise": ["infected"]},
            "display": {"show_attack_edges": true},
            "layout": "dagre",
            "positions": [{"id": "asset-x", "x": 1.5, "y": 2.0}],
            "zoom": 1.0,
            "pan_x": 0.0,
            "pan_y": 0.0
        });
        let view =
            save_investigation_view(&mut conn, None, "Pathway", "For briefing", &state).unwrap();
        assert_eq!(view.name, "Pathway");
        assert!(
            save_investigation_view(&mut conn, None, "  pathway ", "", &state)
                .unwrap_err()
                .contains("already exists")
        );

        let renamed =
            save_investigation_view(&mut conn, Some(&view.id), "Pathway v2", "", &state).unwrap();
        assert_eq!(renamed.name, "Pathway v2");
        assert_eq!(get_investigation_views(&conn).unwrap().len(), 1);
        let loaded = get_investigation_view(&conn, &view.id).unwrap();
        assert_eq!(loaded.state["positions"][0]["x"], 1.5);

        let bad_state = serde_json::json!({"version": 2, "layout": "dagre", "zoom": 1.0, "pan_x": 0.0, "pan_y": 0.0});
        assert!(
            save_investigation_view(&mut conn, None, "Bad", "", &bad_state)
                .unwrap_err()
                .contains("version")
        );

        // Presentation state stays out of evidence history.
        assert_eq!(get_history(&conn, 100).unwrap().len(), commits_before);
        delete_investigation_view(&conn, &view.id).unwrap();
        assert!(get_investigation_views(&conn).unwrap().is_empty());
    }

    #[test]
    fn investigation_entities_round_trip_through_snapshot_export() {
        let (mut source, case, source_actor) = fresh_case();
        let network = add_network(&mut source, &source_actor, "Office", "10.0.0.0/24");
        let asset = add_asset(&mut source, &source_actor, &network.id, "PC-1");
        let ioc = add_ioc(&mut source, &source_actor, "203.0.113.7");
        create_ioc_sighting(
            &mut source,
            &source_actor,
            &ioc.id,
            "asset",
            &asset.id,
            None,
            "",
            "",
            None,
        )
        .unwrap();
        create_attack_edge(
            &mut source,
            &source_actor,
            "external",
            "Internet",
            "asset",
            &asset.id,
            "Initial access",
            "",
            "initial_access",
            "confirmed",
            None,
            None,
            None,
            None,
            None,
            vec![ioc.id.clone()],
        )
        .unwrap();
        let state =
            serde_json::json!({"version":1,"layout":"dagre","zoom":1.0,"pan_x":0.0,"pan_y":0.0});
        save_investigation_view(&mut source, None, "Shared", "", &state).unwrap();
        let data = export_case_data(&source).unwrap();
        assert_eq!(data.ioc_sightings.len(), 1);
        assert_eq!(data.attack_edges.len(), 1);
        assert_eq!(data.investigation_views.len(), 1);

        let mut target = Connection::open_in_memory().unwrap();
        init_database(&target).unwrap();
        target.execute("INSERT INTO cases(id,name,description,client_name,investigator,status,created_at,updated_at,metadata) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![case.id,case.name,case.description,case.client_name,case.investigator,case.status,case.created_at,case.updated_at,case.metadata]).unwrap();
        initialize_history(&target).unwrap();
        let target_actor = actor("Merger");
        let summary = import_case_data(&mut target, &target_actor, &data).unwrap();
        assert_eq!(summary.entities["ioc_sightings"].inserted, 1);
        assert_eq!(summary.entities["attack_edges"].inserted, 1);
        assert_eq!(summary.entities["investigation_views"].inserted, 1);
        assert_eq!(
            get_ioc_sightings(&target, None, None, None).unwrap().len(),
            1
        );
        assert_eq!(get_attack_edges(&target).unwrap().len(), 1);
        assert_eq!(get_investigation_views(&target).unwrap().len(), 1);
        // Imported views stay out of history while evidence entities are recorded.
        let history = get_history(&target, 1).unwrap();
        assert!(history[0]
            .changes
            .iter()
            .all(|change| change.entity_type != "investigation_view"));
        assert!(history[0]
            .changes
            .iter()
            .any(|change| change.entity_type == "attack_edge"));
    }

    #[test]
    fn captures_keep_the_text_and_who_captured_it_through_history_and_snapshots() {
        let (mut conn, _, _) = fresh_case();
        let alice = actor("Alice")
            .with_team(Some("Log analysis".into()))
            .unwrap();
        let text = "APP01, 10.0.0.15, probably on ESX03.\nFinance says they own it.";
        let capture = create_capture(
            &mut conn,
            &alice,
            &format!("  {text}\n"),
            " Finance interview ",
        )
        .unwrap();
        assert_eq!(capture.content, text);
        assert_eq!(capture.source, "Finance interview");
        assert_eq!(capture.status, "open");
        assert_eq!(capture.captured_by, "Alice");
        assert_eq!(capture.team.as_deref(), Some("Log analysis"));
        assert!(create_capture(&mut conn, &alice, "   ", "")
            .unwrap_err()
            .contains("Captured text is required"));

        let asset = create_asset(
            &mut conn,
            &alice,
            None,
            "APP01",
            "10.0.0.15",
            None,
            "server",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap();
        let link = |title: &str| CaptureLink {
            entity_type: "asset".into(),
            entity_id: asset.id.clone(),
            title: title.into(),
        };
        let processed = update_capture(
            &mut conn,
            &alice,
            &capture.id,
            text,
            "Finance interview",
            "processed",
            vec![link("APP01"), link("duplicate")],
            "Asset recorded",
        )
        .unwrap();
        assert_eq!(processed.links, vec![link("APP01")]);
        assert_eq!(
            get_history(&conn, 1).unwrap()[0].message,
            "Processed capture"
        );
        assert!(update_capture(
            &mut conn,
            &alice,
            &capture.id,
            text,
            "",
            "archived",
            Vec::new(),
            ""
        )
        .unwrap_err()
        .contains("Invalid capture status"));

        // Snapshots carry captures, and the add-only import restores them.
        let snapshot = export_case_data(&conn).unwrap();
        assert_eq!(snapshot.captures.len(), 1);
        delete_capture(&mut conn, &alice, &capture.id).unwrap();
        assert!(get_captures(&conn).unwrap().is_empty());
        let summary = import_case_data(&mut conn, &alice, &snapshot).unwrap();
        assert_eq!(summary.entities["captures"].inserted, 1);
        let restored = get_captures(&conn).unwrap();
        assert_eq!(restored[0].links, processed.links);
        assert_eq!(restored[0].team.as_deref(), Some("Log analysis"));
    }

    #[test]
    fn drafts_are_per_expert_and_never_become_history_or_snapshot_content() {
        let (mut conn, _, _) = fresh_case();
        let head = get_history(&conn, 1).unwrap()[0].id.clone();
        let mut drafts = serde_json::Map::new();
        drafts.insert(
            "assets.form".into(),
            serde_json::json!({ "name": "DRAFT-HOST-7" }),
        );
        drafts.insert("notes.title".into(), Value::String("Half written".into()));
        assert_eq!(save_drafts(&mut conn, "Alice", &drafts).unwrap(), 2);
        assert_eq!(load_drafts(&conn, "Alice").unwrap().len(), 2);
        assert!(load_drafts(&conn, "Bob").unwrap().is_empty());

        let mut clear = serde_json::Map::new();
        clear.insert("notes.title".into(), Value::Null);
        save_drafts(&mut conn, "Alice", &clear).unwrap();
        let left = load_drafts(&conn, "Alice").unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left["assets.form"]["name"], "DRAFT-HOST-7");
        assert_eq!(get_history(&conn, 1).unwrap()[0].id, head);
        assert!(!serde_json::to_string(&export_case_data(&conn).unwrap())
            .unwrap()
            .contains("DRAFT-HOST-7"));

        let mut huge = serde_json::Map::new();
        huge.insert("big".into(), Value::String("x".repeat(MAX_DRAFT_BYTES + 1)));
        assert!(save_drafts(&mut conn, "Alice", &huge)
            .unwrap_err()
            .contains("stays unsaved"));
        let mut blank_key = serde_json::Map::new();
        blank_key.insert(" ".into(), Value::Bool(true));
        assert!(save_drafts(&mut conn, "Alice", &blank_key).is_err());
    }

    #[test]
    fn case_search_finds_hosts_addresses_macs_hashes_and_text() {
        let (mut conn, _, alice) = fresh_case();
        let asset = create_asset(
            &mut conn,
            &alice,
            None,
            "APP01",
            "10.0.0.15",
            Some("00:1A:2B:3C:4D:5E"),
            "server",
            Some("Windows Server 2019"),
            None,
            "unknown",
            "not_started",
            Some("Finance owns it"),
            None,
        )
        .unwrap();
        create_asset(
            &mut conn,
            &alice,
            None,
            "APP01-OLD",
            "",
            None,
            "server",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap();
        create_network_interface(
            &mut conn,
            &alice,
            &asset.id,
            "Backup NIC",
            "192.168.50.7",
            None,
            None,
            false,
        )
        .unwrap();
        create_ioc(
            &mut conn,
            &alice,
            "Hash",
            "44d88612fea8a8f36de82e1278abb02f",
            "EICAR test",
            "high",
            None,
            None,
        )
        .unwrap();
        create_note(
            &mut conn,
            &alice,
            "Interview",
            "The finance team mentioned ESX03 twice",
        )
        .unwrap();
        create_capture(
            &mut conn,
            &alice,
            "Ask infra for VPN logs from 2026-11-01",
            "Standup",
        )
        .unwrap();

        let first = |query: &str| {
            search_case(&conn, query, 20)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        // An exact name outranks a longer one that only starts with it.
        let by_name = first("app01");
        assert_eq!(
            (
                by_name.entity_type.as_str(),
                by_name.entity_id.as_str(),
                by_name.field.as_str()
            ),
            ("asset", asset.id.as_str(), "name")
        );
        let by_nic = first("192.168.50.7");
        assert_eq!(
            (by_nic.entity_id.as_str(), by_nic.field.as_str()),
            (asset.id.as_str(), "interface IP")
        );
        assert_eq!(first("00-1a-2b-3c-4d-5e").field, "MAC");
        assert_eq!(first("44D88612FEA8A8F36DE82E1278ABB02F").entity_type, "ioc");
        assert_eq!(first("esx03").entity_type, "note");
        let capture = first("vpn logs");
        assert_eq!(capture.entity_type, "capture");
        assert!(capture.detail.contains("VPN logs"), "{}", capture.detail);
        let finance = search_case(&conn, "finance", 20).unwrap();
        assert!(finance
            .iter()
            .any(|hit| hit.entity_type == "asset" && hit.field == "details"));
        assert!(finance.iter().any(|hit| hit.entity_type == "note"));
        // LIKE wildcards in the query are literal, and one character is too short.
        assert!(search_case(&conn, "%_", 20).unwrap().is_empty());
        assert!(search_case(&conn, "a", 20).unwrap().is_empty());
    }

    #[test]
    fn file_and_process_indicators_are_validated() {
        let (mut conn, _, alice) = fresh_case();
        for (kind, value) in [
            ("FilePath", r"C:\Users\Public\svc.exe"),
            ("FilePath", "/tmp/.x/payload"),
            ("FileName", "invoice.pdf.exe"),
            ("Process", "rundll32.exe shell32.dll,Control_RunDLL"),
        ] {
            create_ioc(&mut conn, &alice, kind, value, "", "medium", None, None).unwrap();
        }
        assert!(
            create_ioc(&mut conn, &alice, "FilePath", "svc.exe", "", "medium", None, None)
                .unwrap_err()
                .contains("directory")
        );
        assert!(create_ioc(
            &mut conn,
            &alice,
            "FileName",
            r"C:\svc.exe",
            "",
            "medium",
            None,
            None
        )
        .unwrap_err()
        .contains("without a directory"));
        assert!(
            create_ioc(&mut conn, &alice, "Process", "a\nb", "", "medium", None, None)
                .unwrap_err()
                .contains("one line")
        );
        assert!(
            create_ioc(&mut conn, &alice, "Malware", "x", "", "medium", None, None)
                .unwrap_err()
                .contains("Invalid IOC type")
        );
    }

    #[test]
    fn schema_8_migration_adds_captures_drafts_and_source_references() {
        let (mut conn, _, _) = fresh_case();
        conn.execute_batch(
            "DROP TABLE captures; DROP TABLE drafts; DROP TABLE history_merged_commits;
             ALTER TABLE timeline_events DROP COLUMN source_ref; PRAGMA user_version = 7;",
        )
        .unwrap();
        validate_and_migrate_case(&mut conn).unwrap();
        for table in ["captures", "drafts", "history_merged_commits"] {
            assert!(table_exists(&conn, table).unwrap(), "{table}");
        }
        assert!(column_exists(&conn, "timeline_events", "source_ref").unwrap());
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        // Migrating always ends on the current schema, not the one it added.
        assert_eq!(version, 9);
    }

    fn plain_asset(
        conn: &mut Connection,
        actor: &ActorIdentity,
        name: &str,
        ip: &str,
        asset_type: &str,
    ) -> Asset {
        create_asset(
            conn,
            actor,
            None,
            name,
            ip,
            None,
            asset_type,
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn sites_owners_and_origin_are_recorded_kept_and_cleared_explicitly() {
        let (mut conn, _, active_expert) = fresh_case();
        let hq = create_site(
            &mut conn,
            &active_expert,
            " HQ Berlin ",
            "Alexanderplatz 1",
            "Head office",
        )
        .unwrap();
        assert_eq!(hq.name, "HQ Berlin");
        let duplicate = create_site(&mut conn, &active_expert, "hq berlin", "", "").unwrap_err();
        assert!(duplicate.contains("already exists"), "{duplicate}");

        let context = NetworkContext {
            site_id: Some(hq.id.clone()),
            owner: Some("Plant IT".into()),
            operator: Some("  SecureCo MSP ".into()),
        };
        let network = create_network_with_context(
            &mut conn,
            &active_expert,
            "Plant LAN",
            "10.20.0.0/16",
            "LAN",
            "",
            None,
            &context,
        )
        .unwrap();
        assert_eq!(network.site_id.as_deref(), Some(hq.id.as_str()));
        assert_eq!(network.operator.as_deref(), Some("SecureCo MSP"));

        let asset = create_asset_with_context(
            &mut conn,
            &active_expert,
            None,
            "APP01",
            "10.20.0.15",
            None,
            "server",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
            &AssetContext {
                site_id: Some(hq.id.clone()),
                owner: Some("Finance".into()),
                operator: Some("SecureCo MSP".into()),
                origin: Some("discovered".into()),
                last_observed: Some("2026-11-13T08:30:00+01:00".into()),
            },
        )
        .unwrap();
        assert_eq!(asset.origin, "discovered");
        assert_eq!(
            asset.last_observed.as_deref(),
            Some("2026-11-13T07:30:00.000Z")
        );
        // The subnet linked it to the zone as before.
        assert_eq!(asset.network_id.as_deref(), Some(network.id.as_str()));

        // A caller that predates these fields cannot erase them.
        let renamed = update_asset(
            &mut conn,
            &active_expert,
            &asset.id,
            asset.network_id.as_deref(),
            "APP01-renamed",
            "10.20.0.15",
            None,
            "server",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
        )
        .unwrap();
        assert_eq!(renamed.owner.as_deref(), Some("Finance"));
        assert_eq!(renamed.origin, "discovered");
        assert_eq!(renamed.site_id.as_deref(), Some(hq.id.as_str()));
        let stored = get_assets(&conn).unwrap().pop().unwrap();
        assert_eq!(stored.operator.as_deref(), Some("SecureCo MSP"));

        // An empty string clears; a value replaces.
        let cleared = update_asset_with_context(
            &mut conn,
            &active_expert,
            &asset.id,
            asset.network_id.as_deref(),
            "APP01-renamed",
            "10.20.0.15",
            None,
            "server",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
            &AssetContext {
                owner: Some("".into()),
                origin: Some("client_inventory".into()),
                site_id: Some("".into()),
                ..AssetContext::default()
            },
        )
        .unwrap();
        assert!(cleared.owner.is_none() && cleared.site_id.is_none());
        assert_eq!(cleared.origin, "client_inventory");
        assert_eq!(cleared.operator.as_deref(), Some("SecureCo MSP"));

        for (context, expected) in [
            (
                AssetContext {
                    origin: Some("rumour".into()),
                    ..AssetContext::default()
                },
                "Invalid asset origin",
            ),
            (
                AssetContext {
                    site_id: Some("nope".into()),
                    ..AssetContext::default()
                },
                "site was not found",
            ),
            (
                AssetContext {
                    last_observed: Some("yesterday".into()),
                    ..AssetContext::default()
                },
                "RFC 3339",
            ),
            (
                AssetContext {
                    owner: Some("x".repeat(201)),
                    ..AssetContext::default()
                },
                "limited to 200",
            ),
        ] {
            let error = update_asset_with_context(
                &mut conn,
                &active_expert,
                &asset.id,
                None,
                "APP01-renamed",
                "10.20.0.15",
                None,
                "server",
                None,
                None,
                "unknown",
                "not_started",
                None,
                None,
                &context,
            )
            .unwrap_err();
            assert!(error.contains(expected), "{error}");
        }

        // The site stays while the network is at it.
        let refused = delete_site(&mut conn, &active_expert, &hq.id).unwrap_err();
        assert!(refused.contains("1 networks"), "{refused}");
        update_network_with_context(
            &mut conn,
            &active_expert,
            &network.id,
            "Plant LAN",
            "10.20.0.0/16",
            "LAN",
            "",
            None,
            &NetworkContext {
                site_id: Some("".into()),
                ..NetworkContext::default()
            },
        )
        .unwrap();
        delete_site(&mut conn, &active_expert, &hq.id).unwrap();
        assert!(get_sites(&conn).unwrap().is_empty());
        let history = get_history(&conn, 3).unwrap();
        assert_eq!(history[0].message, "Deleted site");
    }

    #[test]
    fn hypervisor_hosts_and_the_vms_that_run_on_them_are_linked_and_replayed_in_snapshots() {
        let (mut conn, case, active_expert) = fresh_case();
        let host = plain_asset(
            &mut conn,
            &active_expert,
            "ESX01",
            "10.0.9.10",
            "hypervisor",
        );
        let vm = plain_asset(&mut conn, &active_expert, "APP01", "10.0.0.15", "vm");
        let relation = create_asset_relation(
            &mut conn,
            &active_expert,
            &vm.id,
            &host.id,
            "runs_on",
            "vCenter export",
        )
        .unwrap();
        assert_eq!(relation.source_name.as_deref(), Some("APP01"));
        assert_eq!(relation.target_name.as_deref(), Some("ESX01"));
        assert_eq!(
            get_history(&conn, 1).unwrap()[0].message,
            "Linked APP01 runs on ESX01"
        );

        let again =
            create_asset_relation(&mut conn, &active_expert, &vm.id, &host.id, "runs_on", "")
                .unwrap_err();
        assert!(again.contains("already related"), "{again}");
        assert!(
            create_asset_relation(&mut conn, &active_expert, &vm.id, &vm.id, "runs_on", "")
                .unwrap_err()
                .contains("itself")
        );
        assert!(
            create_asset_relation(&mut conn, &active_expert, &vm.id, &host.id, "owns", "")
                .unwrap_err()
                .contains("Invalid relation type")
        );
        // The same pair may be related in a different way.
        create_asset_relation(
            &mut conn,
            &active_expert,
            &vm.id,
            &host.id,
            "backs_up_to",
            "",
        )
        .unwrap();
        let updated = update_asset_relation(
            &mut conn,
            &active_expert,
            &relation.id,
            "managed_by",
            "now via vCenter",
        )
        .unwrap();
        assert_eq!(updated.relation_type, "managed_by");

        // Snapshots carry sites and relations, and an import rebuilds them.
        let site = create_site(&mut conn, &active_expert, "DC East", "", "").unwrap();
        let exported = export_case_data(&conn).unwrap();
        assert_eq!(exported.sites.len(), 1);
        assert_eq!(exported.asset_relations.len(), 2);
        let mut target = Connection::open_in_memory().unwrap();
        init_database(&target).unwrap();
        target.execute("INSERT INTO cases(id,name,description,client_name,investigator,status,created_at,updated_at,metadata) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![case.id,case.name,case.description,case.client_name,case.investigator,case.status,case.created_at,case.updated_at,case.metadata]).unwrap();
        initialize_history(&target).unwrap();
        let summary = import_case_data(&mut target, &actor("Merger"), &exported).unwrap();
        assert_eq!(summary.entities["sites"].inserted, 1);
        assert_eq!(summary.entities["asset_relations"].inserted, 2);
        assert_eq!(get_sites(&target).unwrap()[0].id, site.id);
        assert_eq!(get_asset_relations(&target).unwrap().len(), 2);

        // Deleting the host removes its relations, each recorded.
        delete_asset(&mut conn, &active_expert, &host.id).unwrap();
        assert!(get_asset_relations(&conn).unwrap().is_empty());
        let last = &get_history(&conn, 1).unwrap()[0];
        let removed: Vec<_> = last
            .changes
            .iter()
            .filter(|c| c.entity_type == "asset_relation")
            .collect();
        assert_eq!(removed.len(), 2);
        assert!(removed.iter().all(|c| c.operation == "delete"));
    }

    fn seed_duplicate_pair(conn: &mut Connection, actor: &ActorIdentity) -> (Asset, Asset, Asset) {
        let keep = create_asset_with_context(
            conn,
            actor,
            None,
            "APP01",
            "10.0.0.5",
            None,
            "server",
            None,
            None,
            "unknown",
            "not_started",
            None,
            None,
            &AssetContext {
                origin: Some("discovered".into()),
                last_observed: Some("2026-11-10T08:00:00Z".into()),
                ..AssetContext::default()
            },
        )
        .unwrap();
        let remove = create_asset_with_context(
            conn,
            actor,
            None,
            "app01.corp.local",
            "10.0.0.5",
            Some("AA:BB:CC:DD:EE:FF"),
            "server",
            Some("Windows Server 2022"),
            Some("svc-app"),
            "suspected",
            "in_progress",
            Some("ownership notes"),
            None,
            &AssetContext {
                owner: Some("Finance".into()),
                origin: Some("client_inventory".into()),
                last_observed: Some("2026-11-12T09:00:00Z".into()),
                ..AssetContext::default()
            },
        )
        .unwrap();
        let other = plain_asset(conn, actor, "DB02", "10.0.0.40", "server");
        create_network_interface(
            conn,
            actor,
            &remove.id,
            "eth1",
            "192.168.1.5",
            None,
            None,
            false,
        )
        .unwrap();
        create_network_interface(
            conn,
            actor,
            &remove.id,
            "mgmt",
            "172.16.5.5",
            None,
            None,
            false,
        )
        .unwrap();
        // The same NIC recorded on both: the copy on the merged-away asset is dropped.
        create_network_interface(
            conn,
            actor,
            &keep.id,
            "eth9",
            "192.168.1.5",
            None,
            None,
            false,
        )
        .unwrap();
        conn.execute_batch(&format!(
            "INSERT INTO timeline_events(id,asset_id,timestamp,event_type,description,severity,created_at)
               VALUES('event-1','{remove}','2026-11-11T10:00:00Z','login','Odd login','medium','2026-11-11T10:00:00Z');
             INSERT INTO iocs(id,ioc_type,value,description,threat_level,created_at)
               VALUES('ioc-1','IP','198.51.100.7','','medium','2026-11-11T10:00:00Z');
             INSERT INTO ioc_sightings(id,ioc_id,asset_id,created_at) VALUES('sight-1','ioc-1','{remove}','2026-11-11T10:00:00Z');
             INSERT INTO attack_edges(id,source_kind,source_id,target_kind,target_id,title,created_at)
               VALUES('edge-between','asset','{keep}','asset','{remove}','A to B','2026-11-11T10:00:00Z'),
                     ('edge-out','asset','{remove}','asset','{other}','B to DB02','2026-11-11T10:00:00Z');",
            remove = remove.id, keep = keep.id, other = other.id
        ))
        .unwrap();
        create_asset_relation(conn, actor, &remove.id, &other.id, "depends_on", "").unwrap();
        create_asset_relation(conn, actor, &keep.id, &other.id, "depends_on", "").unwrap();
        (keep, remove, other)
    }

    #[test]
    fn merging_assets_moves_everything_and_records_one_commit() {
        let (mut conn, _, active_expert) = fresh_case();
        let (keep, remove, other) = seed_duplicate_pair(&mut conn, &active_expert);

        let summary = merge_assets(&mut conn, &active_expert, &keep.id, &remove.id).unwrap();
        assert_eq!(
            (
                summary.interfaces_moved,
                summary.interfaces_dropped,
                summary.timeline_events,
                summary.sightings,
                summary.attack_edges,
                summary.relations
            ),
            (1, 2, 1, 1, 2, 1)
        );
        assert!(get_asset(&conn, &remove.id).unwrap().is_none());

        let merged = get_asset(&conn, &keep.id).unwrap().unwrap();
        // The survivor keeps its identity and takes what it lacked.
        assert_eq!(merged.name, "APP01");
        assert_eq!(merged.owner.as_deref(), Some("Finance"));
        assert_eq!(merged.os.as_deref(), Some("Windows Server 2022"));
        assert_eq!(merged.user_name.as_deref(), Some("svc-app"));
        assert_eq!(merged.properties.as_deref(), Some("ownership notes"));
        assert_eq!(merged.origin, "client_inventory");
        assert_eq!(
            merged.last_observed.as_deref(),
            Some("2026-11-12T09:00:00.000Z")
        );
        assert_eq!(merged.compromise_status, "suspected");
        assert!(merged.suspicious);
        assert_eq!(merged.investigation_status, "in_progress");
        assert_eq!(
            merged.quick_note.as_deref(),
            Some("also known as app01.corp.local")
        );

        // Interfaces: both duplicated NICs collapse (the survivor's primary learns
        // the MAC), the management NIC moves over, and exactly one stays primary.
        let nics = get_network_interfaces(&conn, Some(&keep.id)).unwrap();
        assert_eq!(nics.len(), 3);
        assert_eq!(nics.iter().filter(|nic| nic.is_primary).count(), 1);
        let primary = nics.iter().find(|nic| nic.is_primary).unwrap();
        assert_eq!(primary.ip_address, "10.0.0.5");
        assert_eq!(primary.mac_address.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert!(nics.iter().any(|nic| nic.ip_address == "172.16.5.5"));
        assert_eq!(merged.ip_address, "10.0.0.5");
        assert_eq!(merged.mac_address.as_deref(), Some("AA:BB:CC:DD:EE:FF"));

        // Everything that pointed at the merged-away asset points at the survivor.
        let event_owner: String = conn
            .query_row(
                "SELECT asset_id FROM timeline_events WHERE id='event-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(event_owner, keep.id);
        let sighting_owner: String = conn
            .query_row(
                "SELECT asset_id FROM ioc_sightings WHERE id='sight-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(sighting_owner, keep.id);
        let edges: Vec<(String, String, String)> = query_vec(
            &conn,
            "SELECT id,source_id,target_id FROM attack_edges ORDER BY id",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
        // The edge between the two duplicates would point at itself, so it is gone.
        assert_eq!(
            edges,
            vec![("edge-out".to_string(), keep.id.clone(), other.id.clone())]
        );
        // The two "depends on DB02" relations collapse into one.
        let relations = get_asset_relations(&conn).unwrap();
        assert_eq!(relations.len(), 1);
        assert_eq!(
            (
                relations[0].source_asset_id.as_str(),
                relations[0].target_asset_id.as_str()
            ),
            (keep.id.as_str(), other.id.as_str())
        );

        // One commit carries all of it.
        let commit = &get_history(&conn, 1).unwrap()[0];
        assert_eq!(commit.message, "Merged asset app01.corp.local into APP01");
        let kinds: std::collections::BTreeSet<_> = commit
            .changes
            .iter()
            .map(|c| c.entity_type.as_str())
            .collect();
        for kind in [
            "asset",
            "network_interface",
            "timeline_event",
            "ioc_sighting",
            "attack_edge",
            "asset_relation",
        ] {
            assert!(kinds.contains(kind), "{kind} missing from {kinds:?}");
        }
        assert!(commit.changes.iter().any(|c| c.entity_type == "asset"
            && c.operation == "delete"
            && c.entity_id == remove.id));
        assert!(commit.changes.iter().any(|c| c.entity_type == "asset"
            && c.operation == "update"
            && c.entity_id == keep.id));
    }

    #[test]
    fn merging_assets_refuses_nonsense_and_leaves_the_case_alone() {
        let (mut conn, _, active_expert) = fresh_case();
        let first = plain_asset(&mut conn, &active_expert, "A", "10.0.0.1", "server");
        let before = get_history(&conn, 50).unwrap().len();
        assert!(
            merge_assets(&mut conn, &active_expert, &first.id, &first.id)
                .unwrap_err()
                .contains("two different")
        );
        assert!(
            merge_assets(&mut conn, &active_expert, &first.id, "missing")
                .unwrap_err()
                .contains("not found")
        );
        assert!(
            merge_assets(&mut conn, &active_expert, "missing", &first.id)
                .unwrap_err()
                .contains("not found")
        );
        assert_eq!(get_history(&conn, 50).unwrap().len(), before);
        assert!(get_asset(&conn, &first.id).unwrap().is_some());
    }
}
