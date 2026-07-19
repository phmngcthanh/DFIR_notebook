use chrono::Utc;
use rusqlite::{Connection, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use uuid::Uuid;

use crate::db::{
    get_case, get_entity_json, reconcile_asset_primary_interface,
    reconcile_firewall_primary_interface, upsert_entity_json, AppResult, ClockProfile, ExportData,
};
use crate::history::{record_commit_tx, ActorIdentity, EntityChangeInput};

pub const PARTIAL_IMPORT_FORMAT: &str = "dfir-investigator-partial";
pub const PARTIAL_IMPORT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialImportDocument {
    pub format: String,
    #[serde(default = "default_version")]
    pub format_version: u32,
    #[serde(default)]
    pub case_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub changes: Vec<PartialImportChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialImportChange {
    #[serde(default)]
    pub change_id: Option<String>,
    #[serde(alias = "entityType")]
    pub entity_type: String,
    #[serde(default = "default_operation")]
    pub operation: String,
    #[serde(default, alias = "targetId")]
    pub target_id: Option<String>,
    #[serde(default, alias = "data")]
    pub values: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialFieldDiff {
    pub field: String,
    pub current: Option<Value>,
    pub incoming: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialImportPreviewChange {
    pub id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub operation: String,
    pub title: String,
    pub valid: bool,
    pub error: Option<String>,
    pub recommended_selected: bool,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub fields: Vec<PartialFieldDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialImportPreview {
    pub preview_id: String,
    pub case_id: String,
    pub source: String,
    pub source_kind: String,
    pub changes: Vec<PartialImportPreviewChange>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PreparedPartialChange {
    pub id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub before: Option<Value>,
    pub after: Value,
}

#[derive(Debug, Clone)]
pub struct PreparedPartialImport {
    pub preview: PartialImportPreview,
    pub changes: Vec<PreparedPartialChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSelectionValidation {
    pub valid: bool,
    pub errors: Vec<String>,
    pub selected_count: usize,
    pub create_count: usize,
    pub update_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PartialApplySummary {
    pub created: usize,
    pub updated: usize,
    pub entities: BTreeMap<String, usize>,
    pub commit_id: Option<String>,
}

fn default_version() -> u32 {
    PARTIAL_IMPORT_VERSION
}

fn default_operation() -> String {
    "upsert".to_string()
}

fn strip_json_fence(input: &str) -> &str {
    let trimmed = input.trim();
    if !trimmed.starts_with("```") {
        return trimmed;
    }
    let Some(first_line_end) = trimmed.find('\n') else {
        return trimmed;
    };
    let body = &trimmed[first_line_end + 1..];
    body.strip_suffix("```").map(str::trim).unwrap_or(trimmed)
}

fn normalized_entity_type(value: &str) -> AppResult<String> {
    let normalized = value.trim().to_ascii_lowercase().replace([' ', '-'], "_");
    let entity = match normalized.as_str() {
        "case" | "case_info" => "case",
        "network" | "networks" | "zone" | "zones" => "network",
        "asset" | "assets" | "device" | "devices" | "computer" | "computers" => "asset",
        "network_interface" | "network_interfaces" | "interface" | "interfaces" | "nic"
        | "nics" => "network_interface",
        "clock_profile" | "clock_profiles" | "server_clock" | "server_clocks" => "clock_profile",
        "firewall" | "firewalls" => "firewall",
        "firewall_interface" | "firewall_interfaces" | "firewall_nic" | "firewall_nics" => {
            "firewall_interface"
        }
        "firewall_nat_rule" | "firewall_nat_rules" | "nat" | "nat_rule" | "nat_rules" => {
            "firewall_nat_rule"
        }
        "network_connection" | "network_connections" | "connection" | "connections" => {
            "network_connection"
        }
        "timeline_event" | "timeline_events" | "timeline" | "event" | "events" => "timeline_event",
        "ioc" | "iocs" | "indicator" | "indicators" => "ioc",
        "note" | "notes" => "note",
        _ => return Err(format!("Unsupported entity type '{value}'")),
    };
    Ok(entity.to_string())
}

fn entity_rank(entity_type: &str) -> usize {
    match entity_type {
        "case" => 0,
        "network" => 1,
        "asset" => 2,
        "network_interface" | "clock_profile" | "firewall" => 3,
        "firewall_interface" => 4,
        "firewall_nat_rule" | "network_connection" => 5,
        "timeline_event" | "ioc" | "note" => 6,
        _ => 9,
    }
}

fn object_id(value: &Map<String, Value>) -> Option<String> {
    value.get("id").and_then(Value::as_str).map(str::to_string)
}

fn snapshot_changes(data: ExportData) -> Vec<PartialImportChange> {
    let mut changes = Vec::new();
    macro_rules! add_values {
        ($entity:expr, $values:expr) => {
            for value in $values {
                if let Ok(Value::Object(object)) = serde_json::to_value(value) {
                    changes.push(PartialImportChange {
                        change_id: None,
                        entity_type: $entity.to_string(),
                        operation: "upsert".to_string(),
                        target_id: object_id(&object),
                        values: object,
                    });
                }
            }
        };
    }
    add_values!("network", data.networks);
    add_values!("asset", data.assets);
    add_values!("network_interface", data.network_interfaces);
    add_values!("clock_profile", data.clock_profiles);
    add_values!("firewall", data.firewalls);
    add_values!("firewall_interface", data.firewall_interfaces);
    add_values!("firewall_nat_rule", data.firewall_nat_rules);
    add_values!("network_connection", data.network_connections);
    add_values!("timeline_event", data.timeline_events);
    add_values!("ioc", data.iocs);
    add_values!("note", data.notes);
    changes
}

fn parse_document(input: &str) -> AppResult<(PartialImportDocument, String)> {
    let plaintext = strip_json_fence(input);
    let root: Value = serde_json::from_str(plaintext).map_err(|error| {
        format!("Invalid JSON: {error}. Paste only one JSON object or a fenced JSON block.")
    })?;
    if root.get("format").and_then(Value::as_str) == Some("dfir-investigator-encrypted") {
        return Err("Partial intake is intentionally plain JSON. Use Snapshot import or Expert bundle for encrypted files.".into());
    }
    if root.get("case_info").is_some() {
        let data: ExportData = serde_json::from_value(root)
            .map_err(|error| format!("Invalid case snapshot: {error}"))?;
        let case_id = data.case_info.as_ref().map(|case| case.id.clone());
        return Ok((
            PartialImportDocument {
                format: PARTIAL_IMPORT_FORMAT.to_string(),
                format_version: PARTIAL_IMPORT_VERSION,
                case_id,
                source: Some("Plain case snapshot".to_string()),
                changes: snapshot_changes(data),
            },
            "snapshot".to_string(),
        ));
    }
    let document: PartialImportDocument = serde_json::from_value(root)
        .map_err(|error| format!("Invalid partial-import document: {error}"))?;
    if document.format != PARTIAL_IMPORT_FORMAT || document.format_version != PARTIAL_IMPORT_VERSION
    {
        return Err(format!(
            "Expected format '{PARTIAL_IMPORT_FORMAT}' version {PARTIAL_IMPORT_VERSION}"
        ));
    }
    Ok((document, "partial".to_string()))
}

fn current_case_id(conn: &Connection) -> AppResult<String> {
    get_case(conn)?
        .map(|case| case.id)
        .ok_or_else(|| "No case is open".to_string())
}

fn value_string(value: &Value) -> Option<String> {
    value.as_str().map(str::to_string)
}

fn stringify_json_fields(entity_type: &str, object: &mut Map<String, Value>) -> AppResult<()> {
    let fields: &[&str] = match entity_type {
        "asset" => &["properties", "scan_results"],
        "firewall" => &["rules"],
        _ => &[],
    };
    for field in fields {
        if let Some(value) = object.get_mut(*field) {
            if value.is_object() || value.is_array() {
                *value = Value::String(serde_json::to_string(value).map_err(|e| e.to_string())?);
            }
        }
    }
    Ok(())
}

fn new_entity(entity_type: &str, id: &str, now: &str) -> AppResult<Map<String, Value>> {
    let value = match entity_type {
        "network" => {
            json!({"id":id,"name":"","subnet":"","network_type":"LAN","description":"","vlan_id":null,"created_at":now})
        }
        "asset" => {
            json!({"id":id,"network_id":null,"network_name":null,"name":"","ip_address":"","mac_address":null,"asset_type":"workstation","os":null,"user_name":null,"suspicious":false,"compromise_status":"unknown","investigation_status":"not_started","properties":null,"scan_results":null,"created_at":now})
        }
        "network_interface" => {
            json!({"id":id,"asset_id":"","name":"","ip_address":"","mac_address":null,"network_id":null,"network_name":null,"is_primary":false})
        }
        "clock_profile" => {
            json!({"id":id,"name":"","description":"","server_reference_raw":"","server_timezone":"UTC","server_reference_utc":"","correct_reference_raw":"","correct_timezone":"UTC","correct_reference_utc":"","offset_ms":0,"created_at":now,"updated_at":now})
        }
        "firewall" => {
            json!({"id":id,"network_id":null,"network_name":null,"name":"","vendor":null,"model":null,"rules":null,"config_text":null,"created_at":now})
        }
        "firewall_interface" => {
            json!({"id":id,"firewall_id":"","name":"","ip_addresses":[],"mac_address":null,"network_id":null,"network_name":null,"vlan_id":null,"role":"other","is_primary":false,"description":""})
        }
        "firewall_nat_rule" => {
            json!({"id":id,"firewall_id":"","name":"","nat_type":"dnat","enabled":true,"protocol":"any","source_cidr":null,"original_destination":null,"original_port":null,"translated_source":null,"translated_destination":null,"translated_port":null,"inbound_interface_id":null,"outbound_interface_id":null,"description":"","created_at":now})
        }
        "network_connection" => {
            json!({"id":id,"source_network_id":"","source_network_name":null,"target_network_id":"","target_network_name":null,"connection_type":"","description":"","device_name":null})
        }
        "timeline_event" => {
            json!({"id":id,"asset_id":null,"asset_name":null,"timestamp":"","raw_timestamp":null,"raw_timezone":null,"server_timestamp_utc":null,"correct_timestamp_raw":null,"correct_timezone":null,"clock_profile_id":null,"clock_profile_name":null,"clock_offset_ms":0,"time_precision":"unknown","correct_time_precision":"unknown","event_type":"other","description":"","severity":"info","source":null,"mitre_tactic":null,"mitre_technique":null,"created_at":now})
        }
        "ioc" => {
            json!({"id":id,"ioc_type":"IP","value":"","description":"","threat_level":"medium","first_seen":null,"last_seen":null,"created_at":now})
        }
        "note" => json!({"id":id,"title":"","content":"","created_at":now,"updated_at":now}),
        _ => {
            return Err(format!(
                "'{entity_type}' cannot be created through partial import"
            ))
        }
    };
    value
        .as_object()
        .cloned()
        .ok_or_else(|| "Internal entity template error".into())
}

fn merge_values(target: &mut Map<String, Value>, patch: &Map<String, Value>) {
    for (field, value) in patch {
        target.insert(field.clone(), value.clone());
    }
}

fn recompute_clock_profile(object: &mut Map<String, Value>) -> AppResult<()> {
    let server_raw = object
        .get("server_reference_raw")
        .and_then(Value::as_str)
        .unwrap_or("");
    let server_zone = object
        .get("server_timezone")
        .and_then(Value::as_str)
        .unwrap_or("UTC");
    let correct_raw = object
        .get("correct_reference_raw")
        .and_then(Value::as_str)
        .unwrap_or("");
    let correct_zone = object
        .get("correct_timezone")
        .and_then(Value::as_str)
        .unwrap_or("UTC");
    let server = crate::db::parse_timestamp_preview(server_raw, server_zone, 0)?;
    let correct = crate::db::parse_timestamp_preview(correct_raw, correct_zone, 0)?;
    let offset = correct
        .epoch_millis
        .checked_sub(server.epoch_millis)
        .ok_or_else(|| "Clock profile offset is outside the supported range".to_string())?;
    object.insert(
        "server_reference_utc".into(),
        Value::String(server.interpreted_utc),
    );
    object.insert(
        "correct_reference_utc".into(),
        Value::String(correct.interpreted_utc),
    );
    object.insert("offset_ms".into(), Value::Number(offset.into()));
    object.insert("updated_at".into(), Value::String(Utc::now().to_rfc3339()));
    Ok(())
}

fn recompute_timeline(tx: &Transaction<'_>, object: &mut Map<String, Value>) -> AppResult<()> {
    let server_raw = object
        .get("raw_timestamp")
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .map(str::to_string);
    let server_timezone = object
        .get("raw_timezone")
        .and_then(Value::as_str)
        .unwrap_or("UTC")
        .to_string();
    let direct_raw = object
        .get("correct_timestamp_raw")
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .map(str::to_string);
    let correct_timezone = object
        .get("correct_timezone")
        .and_then(Value::as_str)
        .unwrap_or("UTC")
        .to_string();
    let profile_id = object.get("clock_profile_id").and_then(Value::as_str);
    if direct_raw.is_some() && profile_id.is_some() {
        return Err("Use either correct_timestamp_raw or clock_profile_id, not both".into());
    }
    if profile_id.is_some() && server_raw.is_none() {
        return Err("clock_profile_id requires raw_timestamp".into());
    }
    let profile = profile_id
        .map(|id| {
            get_entity_json(tx, "clock_profile", id)?
                .ok_or_else(|| format!("Clock profile '{id}' was not found"))
                .and_then(|value| {
                    serde_json::from_value::<ClockProfile>(value).map_err(|e| e.to_string())
                })
        })
        .transpose()?;
    let server = server_raw
        .as_deref()
        .map(|input| crate::db::parse_timestamp_preview(input, &server_timezone, 0))
        .transpose()?;
    let direct = direct_raw
        .as_deref()
        .map(|input| crate::db::parse_timestamp_preview(input, &correct_timezone, 0))
        .transpose()?;
    let legacy_timestamp = object
        .get("timestamp")
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty());
    let (timestamp, offset, correct_precision) = if let Some(correct) = &direct {
        let offset = server
            .as_ref()
            .map(|s| correct.epoch_millis - s.epoch_millis)
            .unwrap_or(0);
        (
            correct.interpreted_utc.clone(),
            offset,
            correct.precision.clone(),
        )
    } else if let (Some(server_raw), Some(profile)) = (&server_raw, &profile) {
        let corrected =
            crate::db::parse_timestamp_preview(server_raw, &server_timezone, profile.offset_ms)?;
        (
            corrected.corrected_utc,
            profile.offset_ms,
            server
                .as_ref()
                .map(|v| v.precision.clone())
                .unwrap_or_else(|| "unknown".into()),
        )
    } else if let Some(value) = legacy_timestamp {
        let parsed = crate::db::parse_timestamp_preview(value, "UTC", 0)?;
        (parsed.interpreted_utc, 0, parsed.precision)
    } else {
        (String::new(), 0, "unknown".into())
    };
    object.insert("timestamp".into(), Value::String(timestamp));
    object.insert(
        "raw_timestamp".into(),
        server_raw.clone().map(Value::String).unwrap_or(Value::Null),
    );
    object.insert(
        "raw_timezone".into(),
        server_raw
            .as_ref()
            .map(|_| Value::String(server_timezone))
            .unwrap_or(Value::Null),
    );
    object.insert(
        "server_timestamp_utc".into(),
        server
            .as_ref()
            .map(|v| Value::String(v.interpreted_utc.clone()))
            .unwrap_or(Value::Null),
    );
    object.insert(
        "correct_timestamp_raw".into(),
        direct_raw.clone().map(Value::String).unwrap_or(Value::Null),
    );
    object.insert(
        "correct_timezone".into(),
        direct_raw
            .as_ref()
            .map(|_| Value::String(correct_timezone))
            .unwrap_or(Value::Null),
    );
    object.insert("clock_offset_ms".into(), Value::Number(offset.into()));
    object.insert(
        "time_precision".into(),
        Value::String(
            server
                .map(|v| v.precision)
                .unwrap_or_else(|| "unknown".into()),
        ),
    );
    object.insert(
        "correct_time_precision".into(),
        Value::String(correct_precision),
    );
    object.insert(
        "clock_profile_name".into(),
        profile
            .map(|value| Value::String(value.name))
            .unwrap_or(Value::Null),
    );
    Ok(())
}

fn prepare_after(
    tx: &Transaction<'_>,
    entity_type: &str,
    entity_id: &str,
    before: &Option<Value>,
    patch: &Map<String, Value>,
) -> AppResult<Value> {
    let creating = before.is_none();
    let now = Utc::now().to_rfc3339();
    let mut object = if let Some(Value::Object(existing)) = before {
        existing.clone()
    } else {
        new_entity(entity_type, entity_id, &now)?
    };
    merge_values(&mut object, patch);
    if entity_type == "case" {
        if let Some(legacy_value) = before.as_ref().and_then(|value| value.get("investigator")) {
            object.insert("investigator".into(), legacy_value.clone());
        }
    }
    object.insert("id".to_string(), Value::String(entity_id.to_string()));
    stringify_json_fields(entity_type, &mut object)?;

    if entity_type == "clock_profile"
        && (creating
            || [
                "server_reference_raw",
                "server_timezone",
                "correct_reference_raw",
                "correct_timezone",
            ]
            .iter()
            .any(|field| patch.contains_key(*field)))
    {
        recompute_clock_profile(&mut object)?;
    }
    if entity_type == "timeline_event"
        && (creating
            || [
                "timestamp",
                "raw_timestamp",
                "raw_timezone",
                "correct_timestamp_raw",
                "correct_timezone",
                "clock_profile_id",
            ]
            .iter()
            .any(|field| patch.contains_key(*field)))
    {
        recompute_timeline(tx, &mut object)?;
    }
    if entity_type == "note" && !creating {
        object.insert("updated_at".into(), Value::String(now));
    }
    if entity_type == "asset" {
        if let Some(status) = object.get("compromise_status").and_then(Value::as_str) {
            object.insert(
                "suspicious".into(),
                Value::Bool(matches!(status, "suspected" | "infected")),
            );
        }
    }
    Ok(Value::Object(object))
}

fn field_diffs(before: &Option<Value>, after: &Value) -> Vec<PartialFieldDiff> {
    let current = before.as_ref().and_then(Value::as_object);
    let incoming = after.as_object();
    let mut fields = HashSet::new();
    if let Some(values) = current {
        fields.extend(values.keys().cloned());
    }
    if let Some(values) = incoming {
        fields.extend(values.keys().cloned());
    }
    let mut fields: Vec<String> = fields.into_iter().collect();
    fields.sort();
    fields
        .into_iter()
        .filter_map(|field| {
            let left = current.and_then(|values| values.get(&field)).cloned();
            let right = incoming.and_then(|values| values.get(&field)).cloned();
            (left != right).then_some(PartialFieldDiff {
                field,
                current: left,
                incoming: right,
            })
        })
        .collect()
}

fn entity_title(entity_type: &str, value: &Value, id: &str) -> String {
    let object = value.as_object();
    for field in ["name", "title", "value", "description", "timestamp"] {
        if let Some(text) = object
            .and_then(|item| item.get(field))
            .and_then(value_string)
        {
            if !text.trim().is_empty() {
                return text;
            }
        }
    }
    format!("{entity_type} {id}")
}

pub fn preview_partial_import(
    conn: &mut Connection,
    input: &str,
) -> AppResult<PreparedPartialImport> {
    let (document, source_kind) = parse_document(input)?;
    let case_id = current_case_id(conn)?;
    if let Some(incoming_case_id) = document.case_id.as_deref() {
        if incoming_case_id != case_id {
            return Err(format!(
                "Partial import belongs to case '{incoming_case_id}', not the open case"
            ));
        }
    }
    if document.changes.is_empty() {
        return Err("The partial import contains no changes".into());
    }
    let source = document.source.clone().unwrap_or_else(|| {
        if source_kind == "snapshot" {
            "Plain case snapshot".into()
        } else {
            "Structured intake".into()
        }
    });
    let mut raw = Vec::new();
    for (position, change) in document.changes.into_iter().enumerate() {
        let entity_type = normalized_entity_type(&change.entity_type);
        let id = change
            .change_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("change-{}", position + 1));
        raw.push((id, entity_type, change));
    }
    raw.sort_by_key(|(_, entity, _)| entity.as_ref().map(|value| entity_rank(value)).unwrap_or(9));

    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut preview_changes = Vec::new();
    let mut prepared = Vec::new();
    let mut seen_changes = HashSet::new();
    let mut seen_entities = HashSet::new();
    for (change_id, entity_result, change) in raw {
        let result: AppResult<(String, String, Option<Value>, Value)> = (|| {
            if !seen_changes.insert(change_id.clone()) {
                return Err(format!("Duplicate change_id '{change_id}'"));
            }
            let entity_type = entity_result?;
            let operation = change.operation.trim().to_ascii_lowercase();
            if !matches!(operation.as_str(), "create" | "update" | "upsert") {
                return Err(
                    "Operation must be create, update, or upsert; deletion is not accepted".into(),
                );
            }
            let entity_id = if entity_type == "case" {
                case_id.clone()
            } else {
                change
                    .target_id
                    .clone()
                    .or_else(|| object_id(&change.values))
                    .unwrap_or_else(|| Uuid::new_v4().to_string())
            };
            if !seen_entities.insert((entity_type.clone(), entity_id.clone())) {
                return Err(format!(
                    "The document changes {entity_type} '{entity_id}' more than once"
                ));
            }
            let before = get_entity_json(&tx, &entity_type, &entity_id)?;
            if operation == "create" && before.is_some() {
                return Err(format!(
                    "Cannot create {entity_type} '{entity_id}': it already exists"
                ));
            }
            if operation == "update" && before.is_none() {
                return Err(format!(
                    "Cannot update {entity_type} '{entity_id}': it was not found"
                ));
            }
            if entity_type == "case" && operation == "create" {
                return Err("A partial import cannot create or replace the case record".into());
            }
            let after = prepare_after(&tx, &entity_type, &entity_id, &before, &change.values)?;
            upsert_entity_json(&tx, &entity_type, &after)?;
            if entity_type == "network_interface" {
                let asset_id = after
                    .get("asset_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "Network interface requires asset_id".to_string())?;
                reconcile_asset_primary_interface(&tx, asset_id)?;
            }
            if entity_type == "firewall_interface" {
                let firewall_id = after
                    .get("firewall_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "Firewall interface requires firewall_id".to_string())?;
                reconcile_firewall_primary_interface(&tx, firewall_id)?;
            }
            Ok((entity_type, entity_id, before, after))
        })();
        match result {
            Ok((entity_type, entity_id, before, after)) => {
                let unchanged = before.as_ref() == Some(&after);
                let operation = if unchanged {
                    "unchanged"
                } else if before.is_some() {
                    "update"
                } else {
                    "create"
                };
                let recommended = !unchanged && (source_kind == "partial" || operation == "create");
                preview_changes.push(PartialImportPreviewChange {
                    id: change_id.clone(),
                    entity_type: entity_type.clone(),
                    entity_id: entity_id.clone(),
                    operation: operation.into(),
                    title: entity_title(&entity_type, &after, &entity_id),
                    valid: true,
                    error: None,
                    recommended_selected: recommended,
                    fields: field_diffs(&before, &after),
                    before: before.clone(),
                    after: Some(after.clone()),
                });
                if !unchanged {
                    prepared.push(PreparedPartialChange {
                        id: change_id,
                        entity_type,
                        entity_id,
                        before,
                        after,
                    });
                }
            }
            Err(error) => preview_changes.push(PartialImportPreviewChange {
                id: change_id,
                entity_type: change.entity_type,
                entity_id: change.target_id.unwrap_or_default(),
                operation: "invalid".into(),
                title: "Invalid proposed record".into(),
                valid: false,
                error: Some(error),
                recommended_selected: false,
                before: None,
                after: Some(Value::Object(change.values)),
                fields: Vec::new(),
            }),
        }
    }
    drop(tx);
    let invalid = preview_changes
        .iter()
        .filter(|change| !change.valid)
        .count();
    let warnings = if invalid > 0 {
        vec![format!(
            "{invalid} record(s) are invalid and cannot be selected"
        )]
    } else {
        Vec::new()
    };
    let preview = PartialImportPreview {
        preview_id: Uuid::new_v4().to_string(),
        case_id,
        source,
        source_kind,
        changes: preview_changes,
        warnings,
    };
    Ok(PreparedPartialImport {
        preview,
        changes: prepared,
    })
}

fn selected_prepared<'a>(
    pending: &'a PreparedPartialImport,
    selected: &[String],
) -> AppResult<Vec<&'a PreparedPartialChange>> {
    let requested: HashSet<&str> = selected.iter().map(String::as_str).collect();
    if requested.is_empty() {
        return Err("Select at least one valid change".into());
    }
    let known: HashSet<&str> = pending
        .changes
        .iter()
        .map(|change| change.id.as_str())
        .collect();
    if let Some(unknown) = requested.iter().find(|id| !known.contains(**id)) {
        return Err(format!(
            "Selected change '{unknown}' is invalid, unchanged, or no longer available"
        ));
    }
    let mut values: Vec<&PreparedPartialChange> = pending
        .changes
        .iter()
        .filter(|change| requested.contains(change.id.as_str()))
        .collect();
    values.sort_by_key(|change| entity_rank(&change.entity_type));
    Ok(values)
}

fn dry_run_selection(
    conn: &mut Connection,
    pending: &PreparedPartialImport,
    selected: &[String],
) -> AppResult<(usize, usize)> {
    if current_case_id(conn)? != pending.preview.case_id {
        return Err("The open case changed after this preview was created".into());
    }
    let changes = selected_prepared(pending, selected)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut creates = 0;
    let mut updates = 0;
    let mut affected_assets = HashSet::new();
    let mut affected_firewalls = HashSet::new();
    for change in changes {
        let current = get_entity_json(&tx, &change.entity_type, &change.entity_id)?;
        if current != change.before {
            return Err(format!(
                "{} '{}' changed after preview; reload the partial import",
                change.entity_type, change.entity_id
            ));
        }
        if current.is_some() {
            updates += 1
        } else {
            creates += 1
        }
        upsert_entity_json(&tx, &change.entity_type, &change.after)?;
        if change.entity_type == "network_interface" {
            if let Some(asset_id) = change.after.get("asset_id").and_then(Value::as_str) {
                affected_assets.insert(asset_id.to_string());
            }
        }
        if change.entity_type == "firewall_interface" {
            if let Some(firewall_id) = change.after.get("firewall_id").and_then(Value::as_str) {
                affected_firewalls.insert(firewall_id.to_string());
            }
        }
    }
    for asset_id in affected_assets {
        reconcile_asset_primary_interface(&tx, &asset_id)?;
    }
    for firewall_id in affected_firewalls {
        reconcile_firewall_primary_interface(&tx, &firewall_id)?;
    }
    let foreign_key_errors: i64 = tx
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|e| e.to_string())?;
    if foreign_key_errors > 0 {
        return Err(format!(
            "Selection would create {foreign_key_errors} foreign-key violation(s)"
        ));
    }
    drop(tx);
    Ok((creates, updates))
}

pub fn validate_partial_selection(
    conn: &mut Connection,
    pending: &PreparedPartialImport,
    selected: &[String],
) -> PartialSelectionValidation {
    match dry_run_selection(conn, pending, selected) {
        Ok((create_count, update_count)) => PartialSelectionValidation {
            valid: true,
            errors: Vec::new(),
            selected_count: create_count + update_count,
            create_count,
            update_count,
        },
        Err(error) => PartialSelectionValidation {
            valid: false,
            errors: vec![error],
            selected_count: selected.len(),
            create_count: 0,
            update_count: 0,
        },
    }
}

pub fn apply_partial_import(
    conn: &mut Connection,
    actor: &ActorIdentity,
    pending: &PreparedPartialImport,
    selected: &[String],
) -> AppResult<PartialApplySummary> {
    dry_run_selection(conn, pending, selected)?;
    let changes = selected_prepared(pending, selected)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut originals: HashMap<(String, String), Option<Value>> = HashMap::new();
    let mut affected_assets = HashSet::new();
    let mut affected_firewalls = HashSet::new();
    for change in &changes {
        originals.insert(
            (change.entity_type.clone(), change.entity_id.clone()),
            get_entity_json(&tx, &change.entity_type, &change.entity_id)?,
        );
        if change.entity_type == "network_interface" {
            if let Some(asset_id) = change.after.get("asset_id").and_then(Value::as_str) {
                originals
                    .entry(("asset".into(), asset_id.into()))
                    .or_insert(get_entity_json(&tx, "asset", asset_id)?);
                affected_assets.insert(asset_id.to_string());
            }
        }
        if change.entity_type == "firewall_interface" {
            if let Some(firewall_id) = change.after.get("firewall_id").and_then(Value::as_str) {
                originals
                    .entry(("firewall".into(), firewall_id.into()))
                    .or_insert(get_entity_json(&tx, "firewall", firewall_id)?);
                affected_firewalls.insert(firewall_id.to_string());
            }
        }
        upsert_entity_json(&tx, &change.entity_type, &change.after)?;
    }
    for asset_id in affected_assets {
        reconcile_asset_primary_interface(&tx, &asset_id)?;
    }
    for firewall_id in affected_firewalls {
        reconcile_firewall_primary_interface(&tx, &firewall_id)?;
    }

    let mut audit = Vec::new();
    let mut summary = PartialApplySummary::default();
    for ((entity_type, entity_id), before) in originals {
        let after = get_entity_json(&tx, &entity_type, &entity_id)?;
        if before == after {
            continue;
        }
        let operation = if before.is_none() {
            summary.created += 1;
            "create"
        } else {
            summary.updated += 1;
            "update"
        };
        *summary.entities.entry(entity_type.clone()).or_default() += 1;
        audit.push(EntityChangeInput {
            entity_type,
            entity_id,
            operation: operation.into(),
            before,
            after,
            source_change_id: None,
        });
    }
    if audit.is_empty() {
        return Err("The selected import would not change the case".into());
    }
    let commit_id = record_commit_tx(
        &tx,
        actor,
        &format!(
            "Applied reviewed partial import: {}",
            pending.preview.source
        ),
        audit,
        &[],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    summary.commit_id = Some(commit_id);
    Ok(summary)
}

pub fn partial_import_template(conn: &Connection) -> AppResult<String> {
    let case = get_case(conn)?.ok_or_else(|| "No case is open".to_string())?;
    let export = crate::db::export_case_data(conn)?;
    let compact = |items: Vec<Value>, label_fields: &[&str]| -> Vec<Value> {
        items
            .into_iter()
            .filter_map(|value| {
                let object = value.as_object()?;
                let mut result = Map::new();
                if let Some(id) = object.get("id") {
                    result.insert("id".into(), id.clone());
                }
                for field in label_fields {
                    if let Some(value) = object.get(*field) {
                        result.insert((*field).into(), value.clone());
                    }
                }
                Some(Value::Object(result))
            })
            .collect()
    };
    let to_values = |value: Value| value.as_array().cloned().unwrap_or_default();
    let catalog = json!({
        "case": [{"id": case.id, "name": case.name}],
        "networks": compact(to_values(serde_json::to_value(export.networks).map_err(|e|e.to_string())?), &["name","subnet"]),
        "assets": compact(to_values(serde_json::to_value(export.assets).map_err(|e|e.to_string())?), &["name","ip_address"]),
        "network_interfaces": compact(to_values(serde_json::to_value(export.network_interfaces).map_err(|e|e.to_string())?), &["name","asset_id","ip_address"]),
        "clock_profiles": compact(to_values(serde_json::to_value(export.clock_profiles).map_err(|e|e.to_string())?), &["name"]),
        "firewalls": compact(to_values(serde_json::to_value(export.firewalls).map_err(|e|e.to_string())?), &["name"]),
        "firewall_interfaces": compact(to_values(serde_json::to_value(export.firewall_interfaces).map_err(|e|e.to_string())?), &["name","firewall_id","ip_addresses","network_id"]),
        "firewall_nat_rules": compact(to_values(serde_json::to_value(export.firewall_nat_rules).map_err(|e|e.to_string())?), &["name","firewall_id","nat_type","original_destination","translated_destination"]),
        "network_connections": compact(to_values(serde_json::to_value(export.network_connections).map_err(|e|e.to_string())?), &["source_network_id","target_network_id","connection_type"]),
        "timeline_events": compact(to_values(serde_json::to_value(export.timeline_events).map_err(|e|e.to_string())?), &["timestamp","description"]),
        "iocs": compact(to_values(serde_json::to_value(export.iocs).map_err(|e|e.to_string())?), &["ioc_type","value"]),
        "notes": compact(to_values(serde_json::to_value(export.notes).map_err(|e|e.to_string())?), &["title"]),
    });
    let template = json!({
        "format": PARTIAL_IMPORT_FORMAT,
        "format_version": PARTIAL_IMPORT_VERSION,
        "case_id": case.id,
        "source": "Describe who or what produced this intake",
        "instructions": {
            "purpose": "Return this object as plain JSON. Put only supported proposed creates or partial updates in changes.",
            "operations": ["create", "update", "upsert"],
            "safety": "Deletion is not supported. update requires target_id. create may include a UUID in values.id; use explicit UUIDs when newly created records reference one another.",
            "selection": "The app validates and previews every record. The investigator chooses Skip, Add only, or Use incoming before confirmation.",
            "entity_types": ["case","network","asset","network_interface","clock_profile","firewall","firewall_interface","firewall_nat_rule","network_connection","timeline_event","ioc","note"],
            "field_notes": {
                "network": "name, subnet, network_type, description, vlan_id",
                "asset": "network_id, name, ip_address, mac_address, asset_type, os, user_name, compromise_status, investigation_status, properties, scan_results",
                "network_interface": "asset_id, name, ip_address, mac_address, network_id, is_primary",
                "clock_profile": "name, description, server_reference_raw, server_timezone, correct_reference_raw, correct_timezone",
                "firewall": "network_id, name, vendor, model, rules, config_text",
                "firewall_interface": "firewall_id, name, ip_addresses (array of IPv4/IPv6 addresses or CIDRs), mac_address, network_id, vlan_id, role (wan/lan/dmz/management/ha/vpn/other), is_primary, description",
                "firewall_nat_rule": "firewall_id, name, nat_type (vip/dnat/snat/port_mapping), enabled, protocol, source_cidr, original_destination, original_port, translated_source, translated_destination, translated_port, inbound_interface_id, outbound_interface_id, description",
                "network_connection": "source_network_id, target_network_id, connection_type, description, device_name",
                "timeline_event": "asset_id, optional raw_timestamp + raw_timezone, optional correct_timestamp_raw + correct_timezone, or clock_profile_id, event_type, description, severity, source, mitre_tactic, mitre_technique. Both times may be omitted and added later.",
                "ioc": "ioc_type, value, description, threat_level, first_seen, last_seen",
                "note": "title, content",
                "case": "name, description, client_name, status, metadata. Session expert names provide attribution; legacy investigator metadata is not editable."
            }
        },
        "reference_catalog": catalog,
        "changes": [],
        "examples_remove_before_use": [
            {"change_id":"example-note","entity_type":"note","operation":"create","values":{"title":"Example finding","content":"Markdown note"}},
            {"change_id":"example-asset-patch","entity_type":"asset","operation":"update","target_id":"COPY-AN-ASSET-ID-FROM-reference_catalog","values":{"compromise_status":"suspected","investigation_status":"in_progress"}}
        ]
    });
    serde_json::to_string_pretty(&template).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{create_case_record, init_database};

    fn actor() -> ActorIdentity {
        ActorIdentity::new("Reviewer".into(), None, Vec::new()).unwrap()
    }

    fn case() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();
        create_case_record(&conn, "Case", "", "Client", "Lead").unwrap();
        conn
    }

    #[test]
    fn partial_import_previews_then_applies_selected_sections() {
        let mut conn = case();
        let case_id = current_case_id(&conn).unwrap();
        let document = json!({
            "format": PARTIAL_IMPORT_FORMAT,
            "format_version": 1,
            "case_id": case_id,
            "source": "LLM extraction reviewed by analyst",
            "changes": [
                {"change_id":"network","entity_type":"network","operation":"create","values":{"id":"11111111-1111-4111-8111-111111111111","name":"DMZ","subnet":"10.0.0.0/24","network_type":"DMZ"}},
                {"change_id":"note","entity_type":"note","operation":"create","values":{"title":"Finding","content":"Observed activity"}}
            ]
        });
        let pending = preview_partial_import(&mut conn, &document.to_string()).unwrap();
        assert_eq!(pending.preview.changes.len(), 2);
        assert!(pending.preview.changes.iter().all(|change| change.valid));
        assert!(
            get_entity_json(&conn, "network", "11111111-1111-4111-8111-111111111111")
                .unwrap()
                .is_none()
        );

        let selected = vec!["note".to_string()];
        assert!(validate_partial_selection(&mut conn, &pending, &selected).valid);
        let summary = apply_partial_import(&mut conn, &actor(), &pending, &selected).unwrap();
        assert_eq!(summary.created, 1);
        assert!(
            get_entity_json(&conn, "network", "11111111-1111-4111-8111-111111111111")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn snapshot_updates_are_previewed_but_not_recommended() {
        let mut conn = case();
        let mut snapshot = crate::db::export_case_data(&conn).unwrap();
        snapshot.notes.push(crate::db::Note {
            id: "note-1".into(),
            title: "Expert note".into(),
            content: "Text".into(),
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
        });
        let first =
            preview_partial_import(&mut conn, &serde_json::to_string(&snapshot).unwrap()).unwrap();
        apply_partial_import(&mut conn, &actor(), &first, &["change-1".to_string()]).unwrap();

        snapshot.notes[0].content = "Incoming overwrite".into();
        let second =
            preview_partial_import(&mut conn, &serde_json::to_string(&snapshot).unwrap()).unwrap();
        let update = second
            .preview
            .changes
            .iter()
            .find(|change| change.entity_type == "note")
            .unwrap();
        assert_eq!(update.operation, "update");
        assert!(!update.recommended_selected);
    }

    #[test]
    fn invalid_and_delete_requests_never_mutate_the_case() {
        let mut conn = case();
        let case_id = current_case_id(&conn).unwrap();
        let input = json!({"format":PARTIAL_IMPORT_FORMAT,"format_version":1,"case_id":case_id,"changes":[
            {"entity_type":"network","operation":"delete","target_id":"x","values":{}},
            {"entity_type":"network","operation":"create","values":{"name":"Bad","subnet":"not-cidr"}}
        ]});
        let pending = preview_partial_import(&mut conn, &input.to_string()).unwrap();
        assert!(pending.preview.changes.iter().all(|change| !change.valid));
        assert_eq!(crate::db::get_networks(&conn).unwrap().len(), 0);
    }

    #[test]
    fn notes_and_timeline_can_be_selected_independently_without_removing_the_other() {
        let mut conn = case();
        let case_id = current_case_id(&conn).unwrap();
        let initial = json!({"format":PARTIAL_IMPORT_FORMAT,"format_version":1,"case_id":case_id,"changes":[
            {"change_id":"note-create","entity_type":"note","operation":"create","values":{"id":"note-1","title":"Expert note","content":"Initial note"}},
            {"change_id":"event-create","entity_type":"timeline_event","operation":"create","values":{"id":"event-1","timestamp":"2026-07-19T01:02:03.004Z","event_type":"other","description":"Initial event","severity":"info"}}
        ]});
        let first = preview_partial_import(&mut conn, &initial.to_string()).unwrap();
        apply_partial_import(
            &mut conn,
            &actor(),
            &first,
            &["note-create".into(), "event-create".into()],
        )
        .unwrap();

        let proposed = json!({"format":PARTIAL_IMPORT_FORMAT,"format_version":1,"case_id":case_id,"changes":[
            {"change_id":"note-update","entity_type":"note","operation":"update","target_id":"note-1","values":{"content":"Incoming expert note"}},
            {"change_id":"event-update","entity_type":"timeline_event","operation":"update","target_id":"event-1","values":{"description":"Incoming event overwrite"}}
        ]});
        let second = preview_partial_import(&mut conn, &proposed.to_string()).unwrap();
        apply_partial_import(&mut conn, &actor(), &second, &["note-update".into()]).unwrap();

        assert_eq!(
            crate::db::get_notes(&conn).unwrap()[0].content,
            "Incoming expert note"
        );
        assert_eq!(
            crate::db::get_timeline_events(&conn).unwrap()[0].description,
            "Initial event"
        );
    }

    #[test]
    fn worked_thirty_machine_scenario_previews_and_imports_transactionally() {
        let mut conn = case();
        let input = include_str!("../../examples/scenario-30-machines.partial.json");
        let pending = preview_partial_import(&mut conn, input).unwrap();
        let invalid: Vec<_> = pending
            .preview
            .changes
            .iter()
            .filter(|change| !change.valid)
            .map(|change| (change.id.clone(), change.error.clone()))
            .collect();
        assert!(invalid.is_empty(), "invalid scenario records: {invalid:?}");
        assert_eq!(pending.preview.changes.len(), 92);

        let selected: Vec<String> = pending
            .changes
            .iter()
            .map(|change| change.id.clone())
            .collect();
        let validation = validate_partial_selection(&mut conn, &pending, &selected);
        assert!(
            validation.valid,
            "selection errors: {:?}",
            validation.errors
        );
        apply_partial_import(&mut conn, &actor(), &pending, &selected).unwrap();

        assert_eq!(crate::db::get_networks(&conn).unwrap().len(), 6);
        assert_eq!(crate::db::get_assets(&conn).unwrap().len(), 30);
        assert_eq!(
            crate::db::get_network_interfaces(&conn, None)
                .unwrap()
                .len(),
            30
        );
        assert_eq!(crate::db::get_firewalls(&conn).unwrap().len(), 2);
        assert_eq!(
            crate::db::get_firewall_interfaces(&conn, None)
                .unwrap()
                .len(),
            6
        );
        assert_eq!(
            crate::db::get_firewall_nat_rules(&conn, None)
                .unwrap()
                .len(),
            7
        );
        let events = crate::db::get_timeline_events(&conn).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events
            .iter()
            .any(|event| event.timestamp == "2026-06-23T08:23:45.000Z"));
        assert!(events
            .iter()
            .any(|event| event.timestamp == "2026-01-24T03:25:25.000Z"));
    }
}
