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
    pub created_at: String,
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
}

fn default_format_version() -> u32 {
    1
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
            created_at TEXT NOT NULL
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
        PRAGMA user_version = 6;",
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

pub fn get_networks(conn: &Connection) -> AppResult<Vec<Network>> {
    query_vec(conn, "SELECT id,name,subnet,network_type,description,vlan_id,created_at FROM networks ORDER BY name", [], |row| {
        Ok(Network { id: row.get(0)?, name: row.get(1)?, subnet: row.get(2)?, network_type: row.get(3)?, description: row.get(4)?, vlan_id: row.get(5)?, created_at: row.get(6)? })
    })
}

fn validate_topology_layout(layout: &str) -> AppResult<()> {
    if ["dagre", "grid", "circle", "concentric", "breadthfirst"].contains(&layout) {
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
                a.suspicious,a.compromise_status,a.investigation_status,a.properties,a.scan_results,a.created_at
         FROM assets a LEFT JOIN networks n ON n.id=a.network_id ORDER BY a.name", [], map_asset)
}

pub fn get_assets_by_network(conn: &Connection, network_id: &str) -> AppResult<Vec<Asset>> {
    query_vec(conn,
        "SELECT DISTINCT a.id,a.network_id,pn.name,a.name,a.ip_address,a.mac_address,a.asset_type,a.os,a.user_name,
                a.suspicious,a.compromise_status,a.investigation_status,a.properties,a.scan_results,a.created_at
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
        created_at: row.get(14)?,
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
                e.event_type,e.description,e.severity,e.source,e.mitre_tactic,e.mitre_technique,e.created_at
         FROM timeline_events e
         LEFT JOIN assets a ON a.id=e.asset_id
         LEFT JOIN clock_profiles cp ON cp.id=e.clock_profile_id
         ORDER BY CASE WHEN e.timestamp='' THEN 1 ELSE 0 END,e.timestamp,e.created_at", [], map_timeline)
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

pub fn get_firewalls(conn: &Connection) -> AppResult<Vec<Firewall>> {
    query_vec(
        conn,
        "SELECT f.id,f.network_id,n.name,f.name,f.vendor,f.model,f.rules,f.config_text,f.created_at
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
                created_at: row.get(8)?,
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

fn fixed_offset(value: &str) -> Option<AppResult<FixedOffset>> {
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

fn validate_ioc_value(ioc_type: &str, value: &str) -> AppResult<()> {
    validate_enum(
        "IOC type",
        ioc_type,
        &["IP", "Hash", "Domain", "URL", "Email", "Registry", "Mutex"],
    )?;
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
    )
}

fn validate_asset_model(value: &Asset) -> AppResult<()> {
    validate_required("Asset name", &value.name)?;
    validate_ip(&value.ip_address)?;
    validate_mac(value.mac_address.as_deref())?;
    validate_enum(
        "asset type",
        &value.asset_type,
        &[
            "workstation",
            "server",
            "vm",
            "laptop",
            "router",
            "switch",
            "other",
        ],
    )?;
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
    validate_optional_json("Asset properties", value.properties.as_deref())?;
    validate_optional_json("Scan results", value.scan_results.as_deref())
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
        "network" => get_row_optional(conn, "SELECT id,name,subnet,network_type,description,vlan_id,created_at FROM networks WHERE id=?1", id, |row| {
            Ok(Network { id: row.get(0)?, name: row.get(1)?, subnet: row.get(2)?, network_type: row.get(3)?, description: row.get(4)?, vlan_id: row.get(5)?, created_at: row.get(6)? })
        })?.map(|v| to_value(&v)).transpose(),
        "asset" => get_row_optional(conn,
            "SELECT a.id,a.network_id,n.name,a.name,a.ip_address,a.mac_address,a.asset_type,a.os,a.user_name,a.suspicious,
                    a.compromise_status,a.investigation_status,a.properties,a.scan_results,a.created_at
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
                    e.event_type,e.description,e.severity,e.source,e.mitre_tactic,e.mitre_technique,e.created_at
             FROM timeline_events e LEFT JOIN assets a ON a.id=e.asset_id
             LEFT JOIN clock_profiles cp ON cp.id=e.clock_profile_id WHERE e.id=?1", id, map_timeline)?.map(|v| to_value(&v)).transpose(),
        "note" => get_row_optional(conn, "SELECT id,title,content,created_at,updated_at FROM notes WHERE id=?1", id, |row| {
            Ok(Note { id: row.get(0)?, title: row.get(1)?, content: row.get(2)?, created_at: row.get(3)?, updated_at: row.get(4)? })
        })?.map(|v| to_value(&v)).transpose(),
        "ioc" => get_row_optional(conn, "SELECT id,ioc_type,value,description,threat_level,first_seen,last_seen,created_at FROM iocs WHERE id=?1", id, |row| {
            Ok(Ioc { id: row.get(0)?, ioc_type: row.get(1)?, value: row.get(2)?, description: row.get(3)?, threat_level: row.get(4)?, first_seen: row.get(5)?, last_seen: row.get(6)?, created_at: row.get(7)? })
        })?.map(|v| to_value(&v)).transpose(),
        "firewall" => get_row_optional(conn,
            "SELECT f.id,f.network_id,n.name,f.name,f.vendor,f.model,f.rules,f.config_text,f.created_at
             FROM firewalls f LEFT JOIN networks n ON n.id=f.network_id WHERE f.id=?1", id, |row| {
            Ok(Firewall { id: row.get(0)?, network_id: row.get(1)?, network_name: row.get(2)?, name: row.get(3)?, vendor: row.get(4)?, model: row.get(5)?, rules: row.get(6)?, config_text: row.get(7)?, created_at: row.get(8)? })
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

pub fn create_network(
    conn: &mut Connection,
    actor: &ActorIdentity,
    name: &str,
    subnet: &str,
    network_type: &str,
    description: &str,
    vlan_id: Option<&str>,
) -> AppResult<Network> {
    validate_required("Network name", name)?;
    validate_subnet(subnet.trim())?;
    validate_enum(
        "network type",
        network_type,
        &["LAN", "DMZ", "DMS", "WAN", "GUEST", "MANAGEMENT", "OTHER"],
    )?;
    let item = Network {
        id: Uuid::new_v4().to_string(),
        name: name.trim().into(),
        subnet: subnet.trim().into(),
        network_type: network_type.into(),
        description: description.trim().into(),
        vlan_id: vlan_id
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        created_at: Utc::now().to_rfc3339(),
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO networks(id,name,subnet,network_type,description,vlan_id,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![item.id,item.name,item.subnet,item.network_type,item.description,item.vlan_id,item.created_at],
    ).map_err(|e| e.to_string())?;
    record_commit_tx(
        &tx,
        actor,
        &format!("Created network {}", item.name),
        vec![single_change(
            "network",
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
    validate_required("Network name", name)?;
    validate_subnet(subnet.trim())?;
    validate_enum(
        "network type",
        network_type,
        &["LAN", "DMZ", "DMS", "WAN", "GUEST", "MANAGEMENT", "OTHER"],
    )?;
    let before: Network = require_existing(
        get_row_optional(conn, "SELECT id,name,subnet,network_type,description,vlan_id,created_at FROM networks WHERE id=?1", id, |row| {
            Ok(Network { id: row.get(0)?, name: row.get(1)?, subnet: row.get(2)?, network_type: row.get(3)?, description: row.get(4)?, vlan_id: row.get(5)?, created_at: row.get(6)? })
        })?, "Network")?;
    let after = Network {
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
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let changed = tx.execute("UPDATE networks SET name=?1,subnet=?2,network_type=?3,description=?4,vlan_id=?5 WHERE id=?6",
        params![after.name,after.subnet,after.network_type,after.description,after.vlan_id,id]).map_err(|e| e.to_string())?;
    if changed == 0 {
        return Err("Network was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        &format!("Updated network {}", after.name),
        vec![single_change(
            "network",
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

pub fn delete_network(conn: &mut Connection, actor: &ActorIdentity, id: &str) -> AppResult<()> {
    let before = require_existing(get_entity_json(conn, "network", id)?, "Network")?;
    let dependencies = [
        ("assets", "SELECT COUNT(*) FROM assets WHERE network_id=?1"),
        ("interfaces", "SELECT COUNT(*) FROM network_interfaces WHERE network_id=?1"),
        ("firewall interfaces", "SELECT COUNT(*) FROM firewall_interfaces WHERE network_id=?1"),
        ("firewalls", "SELECT COUNT(*) FROM firewalls WHERE network_id=?1"),
        ("connections", "SELECT COUNT(*) FROM network_connections WHERE source_network_id=?1 OR target_network_id=?1"),
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
    validate_required("Asset name", name)?;
    validate_ip(ip_address.trim())?;
    validate_mac(mac_address)?;
    validate_enum(
        "asset type",
        asset_type,
        &[
            "workstation",
            "server",
            "vm",
            "laptop",
            "router",
            "switch",
            "other",
        ],
    )?;
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
    validate_optional_json("Asset properties", properties)?;
    validate_optional_json("Scan results", scan_results)?;
    if let Some(network_id) = network_id {
        if !exists(conn, "networks", network_id)? {
            return Err("Selected network was not found".into());
        }
    }
    let suspicious = matches!(compromise_status, "suspected" | "infected");
    let mut item = Asset {
        id: Uuid::new_v4().to_string(),
        network_id: network_id.map(String::from),
        network_name: None,
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
        created_at: Utc::now().to_rfc3339(),
    };
    item.network_name = item.network_id.as_ref().and_then(|network_id| {
        conn.query_row(
            "SELECT name FROM networks WHERE id=?1",
            params![network_id],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    });
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO assets(id,network_id,name,ip_address,mac_address,asset_type,os,user_name,suspicious,compromise_status,investigation_status,properties,scan_results,created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![item.id,item.network_id,item.name,item.ip_address,item.mac_address,item.asset_type,item.os,item.user_name,
            if item.suspicious {1} else {0},item.compromise_status,item.investigation_status,item.properties,item.scan_results,item.created_at]
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
    validate_required("Asset name", name)?;
    validate_ip(ip_address.trim())?;
    validate_mac(mac_address)?;
    validate_enum(
        "asset type",
        asset_type,
        &[
            "workstation",
            "server",
            "vm",
            "laptop",
            "router",
            "switch",
            "other",
        ],
    )?;
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
    validate_optional_json("Asset properties", properties)?;
    validate_optional_json("Scan results", scan_results)?;
    if let Some(network_id) = network_id {
        if !exists(conn, "networks", network_id)? {
            return Err("Selected network was not found".into());
        }
    }
    let before: Asset =
        require_existing(get_assets(conn)?.into_iter().find(|a| a.id == id), "Asset")?;
    let network_name = network_id.and_then(|nid| {
        conn.query_row(
            "SELECT name FROM networks WHERE id=?1",
            params![nid],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    });
    let after = Asset {
        network_id: network_id.map(String::from),
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
    let primary_before = get_network_interfaces(conn, Some(id))?
        .into_iter()
        .find(|v| v.is_primary);
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let changed = tx.execute(
        "UPDATE assets SET network_id=?1,name=?2,ip_address=?3,mac_address=?4,asset_type=?5,os=?6,user_name=?7,suspicious=?8,
         compromise_status=?9,investigation_status=?10,properties=?11,scan_results=?12 WHERE id=?13",
        params![after.network_id,after.name,after.ip_address,after.mac_address,after.asset_type,after.os,after.user_name,
            if after.suspicious {1}else{0},after.compromise_status,after.investigation_status,after.properties,after.scan_results,id]
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

pub fn delete_asset(conn: &mut Connection, actor: &ActorIdentity, id: &str) -> AppResult<()> {
    let asset = require_existing(get_entity_json(conn, "asset", id)?, "Asset")?;
    let interfaces = get_network_interfaces(conn, Some(id))?;
    let events: Vec<TimelineEvent> = get_timeline_events(conn)?
        .into_iter()
        .filter(|e| e.asset_id.as_deref() == Some(id))
        .collect();
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut changes = Vec::new();
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
    if let Some(nid) = network_id {
        if !exists(conn, "networks", nid)? {
            return Err("Selected network was not found".into());
        }
    }
    let network_name = network_id.and_then(|nid| {
        conn.query_row(
            "SELECT name FROM networks WHERE id=?1",
            params![nid],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    });
    let item = NetworkInterface {
        id: Uuid::new_v4().to_string(),
        asset_id: asset_id.into(),
        name: name.trim().into(),
        ip_address: ip_address.trim().into(),
        mac_address: mac_address
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        network_id: network_id.map(String::from),
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
    let network_name = network_id.and_then(|nid| {
        conn.query_row(
            "SELECT name FROM networks WHERE id=?1",
            params![nid],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    });
    let after = NetworkInterface {
        name: name.trim().into(),
        ip_address: ip_address.trim().into(),
        mac_address: mac_address
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(String::from),
        network_id: network_id.map(String::from),
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
    tx.execute("INSERT INTO timeline_events(id,asset_id,timestamp,raw_timestamp,raw_timezone,server_timestamp_utc,correct_timestamp_raw,correct_timezone,clock_profile_id,clock_offset_ms,time_precision,correct_time_precision,event_type,description,severity,source,mitre_tactic,mitre_technique,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
        params![item.id,item.asset_id,item.timestamp,item.raw_timestamp,item.raw_timezone,item.server_timestamp_utc,item.correct_timestamp_raw,item.correct_timezone,item.clock_profile_id,item.clock_offset_ms,item.time_precision,item.correct_time_precision,item.event_type,item.description,item.severity,item.source,item.mitre_tactic,item.mitre_technique,item.created_at]).map_err(|e|e.to_string())?;
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
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx
        .execute("DELETE FROM timeline_events WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Timeline event was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Deleted timeline event",
        vec![single_change(
            "timeline_event",
            id,
            "delete",
            Some(before),
            None,
        )],
        &[],
    )?;
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
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx
        .execute("DELETE FROM iocs WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("IOC was not found".into());
    }
    record_commit_tx(
        &tx,
        actor,
        "Deleted IOC",
        vec![single_change("ioc", id, "delete", Some(before), None)],
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())
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
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    if tx
        .execute("DELETE FROM firewalls WHERE id=?1", params![id])
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Firewall was not found".into());
    }
    let mut changes = Vec::new();
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
    for v in &data.networks {
        insert_item!("networks","network",&v.id,"INSERT OR IGNORE INTO networks(id,name,subnet,network_type,description,vlan_id,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![v.id,v.name,v.subnet,v.network_type,v.description,v.vlan_id,v.created_at],v);
    }
    for v in &data.assets {
        insert_item!("assets","asset",&v.id,"INSERT OR IGNORE INTO assets(id,network_id,name,ip_address,mac_address,asset_type,os,user_name,suspicious,compromise_status,investigation_status,properties,scan_results,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",params![v.id,v.network_id,v.name,v.ip_address,v.mac_address,v.asset_type,v.os,v.user_name,if v.suspicious{1}else{0},v.compromise_status,v.investigation_status,v.properties,v.scan_results,v.created_at],v);
    }
    for v in &data.network_interfaces {
        insert_item!("network_interfaces","network_interface",&v.id,"INSERT OR IGNORE INTO network_interfaces(id,asset_id,name,ip_address,mac_address,network_id,is_primary) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![v.id,v.asset_id,v.name,v.ip_address,v.mac_address,v.network_id,if v.is_primary{1}else{0}],v);
    }
    for v in &data.clock_profiles {
        insert_item!("clock_profiles","clock_profile",&v.id,"INSERT OR IGNORE INTO clock_profiles(id,name,description,server_reference_raw,server_timezone,server_reference_utc,correct_reference_raw,correct_timezone,correct_reference_utc,offset_ms,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",params![v.id,v.name,v.description,v.server_reference_raw,v.server_timezone,v.server_reference_utc,v.correct_reference_raw,v.correct_timezone,v.correct_reference_utc,v.offset_ms,v.created_at,v.updated_at],v);
    }
    for v in &data.firewalls {
        insert_item!("firewalls","firewall",&v.id,"INSERT OR IGNORE INTO firewalls(id,network_id,name,vendor,model,rules,config_text,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![v.id,v.network_id,v.name,v.vendor,v.model,v.rules,v.config_text,v.created_at],v);
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
        insert_item!("timeline_events","timeline_event",&v.id,"INSERT OR IGNORE INTO timeline_events(id,asset_id,timestamp,raw_timestamp,raw_timezone,server_timestamp_utc,correct_timestamp_raw,correct_timezone,clock_profile_id,clock_offset_ms,time_precision,correct_time_precision,event_type,description,severity,source,mitre_tactic,mitre_technique,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",params![v.id,v.asset_id,v.timestamp,v.raw_timestamp,v.raw_timezone,v.server_timestamp_utc,v.correct_timestamp_raw,v.correct_timezone,v.clock_profile_id,v.clock_offset_ms,v.time_precision,v.correct_time_precision,v.event_type,v.description,v.severity,v.source,v.mitre_tactic,v.mitre_technique,v.created_at],&v);
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
            tx.execute("INSERT INTO networks(id,name,subnet,network_type,description,vlan_id,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(id) DO UPDATE SET name=excluded.name,subnet=excluded.subnet,network_type=excluded.network_type,description=excluded.description,vlan_id=excluded.vlan_id",params![v.id,v.name,v.subnet,v.network_type,v.description,v.vlan_id,v.created_at]).map_err(|e|e.to_string())?;
        }
        "asset" => {
            let v: Asset = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            validate_asset_model(&v)?;
            tx.execute("INSERT INTO assets(id,network_id,name,ip_address,mac_address,asset_type,os,user_name,suspicious,compromise_status,investigation_status,properties,scan_results,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14) ON CONFLICT(id) DO UPDATE SET network_id=excluded.network_id,name=excluded.name,ip_address=excluded.ip_address,mac_address=excluded.mac_address,asset_type=excluded.asset_type,os=excluded.os,user_name=excluded.user_name,suspicious=excluded.suspicious,compromise_status=excluded.compromise_status,investigation_status=excluded.investigation_status,properties=excluded.properties,scan_results=excluded.scan_results",params![v.id,v.network_id,v.name,v.ip_address,v.mac_address,v.asset_type,v.os,v.user_name,if v.suspicious{1}else{0},v.compromise_status,v.investigation_status,v.properties,v.scan_results,v.created_at]).map_err(|e|e.to_string())?;
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
            tx.execute("INSERT INTO timeline_events(id,asset_id,timestamp,raw_timestamp,raw_timezone,server_timestamp_utc,correct_timestamp_raw,correct_timezone,clock_profile_id,clock_offset_ms,time_precision,correct_time_precision,event_type,description,severity,source,mitre_tactic,mitre_technique,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19) ON CONFLICT(id) DO UPDATE SET asset_id=excluded.asset_id,timestamp=excluded.timestamp,raw_timestamp=excluded.raw_timestamp,raw_timezone=excluded.raw_timezone,server_timestamp_utc=excluded.server_timestamp_utc,correct_timestamp_raw=excluded.correct_timestamp_raw,correct_timezone=excluded.correct_timezone,clock_profile_id=excluded.clock_profile_id,clock_offset_ms=excluded.clock_offset_ms,time_precision=excluded.time_precision,correct_time_precision=excluded.correct_time_precision,event_type=excluded.event_type,description=excluded.description,severity=excluded.severity,source=excluded.source,mitre_tactic=excluded.mitre_tactic,mitre_technique=excluded.mitre_technique",params![v.id,v.asset_id,v.timestamp,v.raw_timestamp,v.raw_timezone,v.server_timestamp_utc,v.correct_timestamp_raw,v.correct_timezone,v.clock_profile_id,v.clock_offset_ms,v.time_precision,v.correct_time_precision,v.event_type,v.description,v.severity,v.source,v.mitre_tactic,v.mitre_technique,v.created_at]).map_err(|e|e.to_string())?;
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
            tx.execute("INSERT INTO firewalls(id,network_id,name,vendor,model,rules,config_text,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO UPDATE SET network_id=excluded.network_id,name=excluded.name,vendor=excluded.vendor,model=excluded.model,rules=excluded.rules,config_text=excluded.config_text",params![v.id,v.network_id,v.name,v.vendor,v.model,v.rules,v.config_text,v.created_at]).map_err(|e|e.to_string())?;
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
        _ => return Err(format!("Unsupported deletion type: {entity_type}")),
    };
    tx.execute(&format!("DELETE FROM {table} WHERE id=?1"), params![id])
        .map_err(|e| e.to_string())?;
    Ok(())
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
            6
        );
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
    }
}
