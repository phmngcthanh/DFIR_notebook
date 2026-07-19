use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use uuid::Uuid;

use crate::db::{
    delete_entity_direct, get_case, get_entity_json, reconcile_asset_primary_interface,
    reconcile_firewall_primary_interface, upsert_entity_json, AppResult,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorIdentity {
    pub name: String,
    pub session_id: String,
    pub scope_label: Option<String>,
    pub scope_network_ids: Vec<String>,
}

impl ActorIdentity {
    pub fn new(
        name: String,
        scope_label: Option<String>,
        scope_network_ids: Vec<String>,
    ) -> AppResult<Self> {
        if name.trim().is_empty() {
            return Err("Expert name is required".to_string());
        }
        Ok(Self {
            name: name.trim().to_string(),
            session_id: Uuid::new_v4().to_string(),
            scope_label: scope_label
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            scope_network_ids,
        })
    }

    fn scope_json(&self) -> AppResult<Option<String>> {
        if self.scope_label.is_none() && self.scope_network_ids.is_empty() {
            return Ok(None);
        }
        serde_json::to_string(&serde_json::json!({
            "label": self.scope_label,
            "network_ids": self.scope_network_ids,
        }))
        .map(Some)
        .map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct EntityChangeInput {
    pub entity_type: String,
    pub entity_id: String,
    pub operation: String,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub source_change_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryChange {
    pub id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub operation: String,
    pub base_revision: i64,
    pub new_revision: i64,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub source_change_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryCommit {
    pub id: String,
    pub author_name: String,
    pub session_id: String,
    pub message: String,
    pub scope: Option<Value>,
    pub created_at: String,
    pub parent_ids: Vec<String>,
    pub changes: Vec<HistoryChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeBundle {
    pub format: String,
    pub format_version: u32,
    pub bundle_id: String,
    pub case_id: String,
    pub base_commit_id: String,
    pub head_commit_id: String,
    pub exported_by: String,
    pub exported_at: String,
    pub commits: Vec<HistoryCommit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDiff {
    pub field: String,
    pub base: Option<Value>,
    pub local: Option<Value>,
    pub incoming: Option<Value>,
    pub conflict: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergePreviewChange {
    pub id: String,
    pub source_change_ids: Vec<String>,
    pub entity_type: String,
    pub entity_id: String,
    pub operation: String,
    pub classification: String,
    pub author_name: String,
    pub message: String,
    pub scope: Option<Value>,
    pub before: Option<Value>,
    pub local: Option<Value>,
    pub incoming: Option<Value>,
    pub suggested: Option<Value>,
    pub fields: Vec<FieldDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergePreview {
    pub bundle_id: String,
    pub case_id: String,
    pub base_commit_id: String,
    pub head_commit_id: String,
    pub exported_by: String,
    pub exported_at: String,
    pub common_base: bool,
    pub changes: Vec<MergePreviewChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeDecision {
    pub change_id: String,
    pub selected: bool,
    pub resolved_after: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MergeApplySummary {
    pub applied: usize,
    pub skipped: usize,
    pub merge_commit_id: Option<String>,
}

pub fn record_commit_tx(
    tx: &Transaction<'_>,
    actor: &ActorIdentity,
    message: &str,
    changes: Vec<EntityChangeInput>,
    extra_parent_ids: &[String],
) -> AppResult<String> {
    if changes.is_empty() {
        return Err("Cannot record an empty commit".to_string());
    }
    let case_id: String = tx
        .query_row("SELECT id FROM cases LIMIT 1", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    let current_head: String = tx
        .query_row(
            "SELECT head_commit_id FROM history_state WHERE id=1",
            [],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    let commit_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    tx.execute(
        "INSERT INTO history_commits(id,case_id,author_name,session_id,message,scope_json,created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![commit_id, case_id, actor.name, actor.session_id, message, actor.scope_json()?, now],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO history_commit_parents(commit_id,parent_commit_id,position) VALUES (?1,?2,0)",
        params![commit_id, current_head],
    )
    .map_err(|e| e.to_string())?;
    let mut seen = HashSet::new();
    seen.insert(current_head);
    for parent in extra_parent_ids {
        if seen.insert(parent.clone()) {
            let position = seen.len() as i64 - 1;
            tx.execute(
                "INSERT INTO history_commit_parents(commit_id,parent_commit_id,position) VALUES (?1,?2,?3)",
                params![commit_id, parent, position],
            )
            .map_err(|e| e.to_string())?;
        }
    }

    for change in changes {
        let base_revision: i64 = tx
            .query_row(
                "SELECT revision FROM history_entity_heads WHERE entity_type=?1 AND entity_id=?2",
                params![change.entity_type, change.entity_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .unwrap_or(0);
        let new_revision = base_revision + 1;
        let change_id = Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO history_changes
             (id,commit_id,entity_type,entity_id,operation,base_revision,new_revision,before_json,after_json,source_change_id,created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                change_id,
                commit_id,
                change.entity_type,
                change.entity_id,
                change.operation,
                base_revision,
                new_revision,
                option_json_string(&change.before)?,
                option_json_string(&change.after)?,
                change.source_change_id,
                now,
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO history_entity_heads(entity_type,entity_id,revision,last_commit_id,deleted)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(entity_type,entity_id) DO UPDATE SET
                revision=excluded.revision,last_commit_id=excluded.last_commit_id,deleted=excluded.deleted",
            params![change.entity_type, change.entity_id, new_revision, commit_id, if change.after.is_none() { 1 } else { 0 }],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.execute(
        "UPDATE history_state SET head_commit_id=?1 WHERE id=1",
        params![commit_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(commit_id)
}

fn option_json_string(value: &Option<Value>) -> AppResult<Option<String>> {
    value
        .as_ref()
        .map(|value| serde_json::to_string(value).map_err(|e| e.to_string()))
        .transpose()
}

fn parse_optional_json(value: Option<String>) -> AppResult<Option<Value>> {
    value
        .map(|value| serde_json::from_str(&value).map_err(|e| e.to_string()))
        .transpose()
}

pub fn mark_shared_baseline(conn: &Connection) -> AppResult<String> {
    let head: String = conn
        .query_row(
            "SELECT head_commit_id FROM history_state WHERE id=1",
            [],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    conn.execute(
        "UPDATE history_state SET shared_base_commit_id=?1 WHERE id=1",
        params![head],
    )
    .map_err(|e| e.to_string())?;
    Ok(head)
}

pub fn get_history(conn: &Connection, limit: usize) -> AppResult<Vec<HistoryCommit>> {
    let mut stmt = conn
        .prepare("SELECT id FROM history_commits ORDER BY created_at DESC LIMIT ?1")
        .map_err(|e| e.to_string())?;
    let ids = stmt
        .query_map(params![limit as i64], |row| row.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    ids.into_iter().map(|id| load_commit(conn, &id)).collect()
}

fn load_commit(conn: &Connection, id: &str) -> AppResult<HistoryCommit> {
    let (author_name, session_id, message, scope_json, created_at): (String, String, String, Option<String>, String) = conn
        .query_row(
            "SELECT author_name,session_id,message,scope_json,created_at FROM history_commits WHERE id=?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .map_err(|e| e.to_string())?;
    let mut parent_stmt = conn
        .prepare("SELECT parent_commit_id FROM history_commit_parents WHERE commit_id=?1 ORDER BY position")
        .map_err(|e| e.to_string())?;
    let parent_ids = parent_stmt
        .query_map(params![id], |row| row.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let mut change_stmt = conn
        .prepare(
            "SELECT id,entity_type,entity_id,operation,base_revision,new_revision,before_json,after_json,source_change_id,created_at
             FROM history_changes WHERE commit_id=?1 ORDER BY rowid",
        )
        .map_err(|e| e.to_string())?;
    let rows = change_stmt
        .query_map(params![id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, String>(9)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let changes = rows
        .into_iter()
        .map(|row| {
            Ok(HistoryChange {
                id: row.0,
                entity_type: row.1,
                entity_id: row.2,
                operation: row.3,
                base_revision: row.4,
                new_revision: row.5,
                before: parse_optional_json(row.6)?,
                after: parse_optional_json(row.7)?,
                source_change_id: row.8,
                created_at: row.9,
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok(HistoryCommit {
        id: id.to_string(),
        author_name,
        session_id,
        message,
        scope: parse_optional_json(scope_json)?,
        created_at,
        parent_ids,
        changes,
    })
}

pub fn export_change_bundle(conn: &Connection, actor: &ActorIdentity) -> AppResult<ChangeBundle> {
    let case = get_case(conn)?.ok_or_else(|| "Case metadata is missing".to_string())?;
    let (head, base): (String, String) = conn
        .query_row(
            "SELECT head_commit_id,shared_base_commit_id FROM history_state WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| e.to_string())?;
    let mut ids = Vec::new();
    let mut cursor = head.clone();
    let mut guard = 0usize;
    while cursor != base {
        ids.push(cursor.clone());
        cursor = conn
            .query_row(
                "SELECT parent_commit_id FROM history_commit_parents WHERE commit_id=?1 AND position=0",
                params![cursor],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Shared baseline is not on the current main history path".to_string())?;
        guard += 1;
        if guard > 100_000 {
            return Err("History traversal exceeded safety limit".to_string());
        }
    }
    ids.reverse();
    let commits = ids
        .into_iter()
        .map(|id| load_commit(conn, &id))
        .collect::<AppResult<Vec<_>>>()?;
    Ok(ChangeBundle {
        format: "dfir-investigator-changes".to_string(),
        format_version: 1,
        bundle_id: Uuid::new_v4().to_string(),
        case_id: case.id,
        base_commit_id: base,
        head_commit_id: head,
        exported_by: actor.name.clone(),
        exported_at: Utc::now().to_rfc3339(),
        commits,
    })
}

pub fn parse_change_bundle(json: &str) -> AppResult<ChangeBundle> {
    let bundle: ChangeBundle =
        serde_json::from_str(json).map_err(|e| format!("Invalid change bundle: {e}"))?;
    if bundle.format != "dfir-investigator-changes" || bundle.format_version != 1 {
        return Err("Unsupported change bundle format".to_string());
    }
    Ok(bundle)
}

#[derive(Clone)]
struct AggregatedChange {
    source_change_ids: Vec<String>,
    entity_type: String,
    entity_id: String,
    before: Option<Value>,
    after: Option<Value>,
    author_name: String,
    message: String,
    scope: Option<Value>,
}

pub fn preview_bundle(conn: &Connection, bundle: &ChangeBundle) -> AppResult<MergePreview> {
    let case = get_case(conn)?.ok_or_else(|| "Case metadata is missing".to_string())?;
    if case.id != bundle.case_id {
        return Err("Change bundle belongs to a different case".to_string());
    }
    let common_base: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM history_commits WHERE id=?1)",
            params![bundle.base_commit_id],
            |row| row.get::<_, i64>(0),
        )
        .map(|value| value != 0)
        .map_err(|e| e.to_string())?;

    let mut aggregated: BTreeMap<(String, String), AggregatedChange> = BTreeMap::new();
    for commit in &bundle.commits {
        for change in &commit.changes {
            let key = (change.entity_type.clone(), change.entity_id.clone());
            aggregated
                .entry(key)
                .and_modify(|entry| {
                    entry.after = change.after.clone();
                    entry.source_change_ids.push(change.id.clone());
                    entry.author_name = commit.author_name.clone();
                    entry.message = commit.message.clone();
                    entry.scope = commit.scope.clone();
                })
                .or_insert_with(|| AggregatedChange {
                    source_change_ids: vec![change.id.clone()],
                    entity_type: change.entity_type.clone(),
                    entity_id: change.entity_id.clone(),
                    before: change.before.clone(),
                    after: change.after.clone(),
                    author_name: commit.author_name.clone(),
                    message: commit.message.clone(),
                    scope: commit.scope.clone(),
                });
        }
    }

    let mut changes = Vec::new();
    for (_, change) in aggregated {
        let local = get_entity_json(conn, &change.entity_type, &change.entity_id)?;
        let operation = match (&change.before, &change.after) {
            (None, Some(_)) => "create",
            (Some(_), None) => "delete",
            _ => "update",
        }
        .to_string();
        let (mut classification, suggested, fields) =
            classify(&change.before, &local, &change.after);
        if !common_base && classification != "already_applied" {
            classification = "conflict".to_string();
        }
        changes.push(MergePreviewChange {
            id: format!("{}:{}", change.entity_type, change.entity_id),
            source_change_ids: change.source_change_ids,
            entity_type: change.entity_type,
            entity_id: change.entity_id,
            operation,
            classification,
            author_name: change.author_name,
            message: change.message,
            scope: change.scope,
            before: change.before,
            local,
            incoming: change.after,
            suggested,
            fields,
        });
    }
    Ok(MergePreview {
        bundle_id: bundle.bundle_id.clone(),
        case_id: bundle.case_id.clone(),
        base_commit_id: bundle.base_commit_id.clone(),
        head_commit_id: bundle.head_commit_id.clone(),
        exported_by: bundle.exported_by.clone(),
        exported_at: bundle.exported_at.clone(),
        common_base,
        changes,
    })
}

fn ignored_derived_field(field: &str) -> bool {
    matches!(
        field,
        "network_name" | "asset_name" | "source_network_name" | "target_network_name"
    )
}

fn classify(
    before: &Option<Value>,
    local: &Option<Value>,
    incoming: &Option<Value>,
) -> (String, Option<Value>, Vec<FieldDiff>) {
    if local == incoming {
        return (
            "already_applied".to_string(),
            local.clone(),
            field_diffs(before, local, incoming),
        );
    }
    match (before, local, incoming) {
        (None, None, Some(_)) => (
            "clean".to_string(),
            incoming.clone(),
            field_diffs(before, local, incoming),
        ),
        (None, Some(_), Some(_)) => (
            "conflict".to_string(),
            incoming.clone(),
            field_diffs(before, local, incoming),
        ),
        (Some(base), Some(current), Some(next)) if base == current => (
            "clean".to_string(),
            Some(next.clone()),
            field_diffs(before, local, incoming),
        ),
        (Some(_), None, Some(_)) => (
            "conflict".to_string(),
            incoming.clone(),
            field_diffs(before, local, incoming),
        ),
        (Some(base), Some(current), Some(next)) => {
            let (merged, conflicts) = three_way_object_merge(base, current, next);
            let classification = if conflicts.is_empty() {
                "auto_mergeable"
            } else {
                "conflict"
            };
            (
                classification.to_string(),
                Some(merged),
                field_diffs(before, local, incoming),
            )
        }
        (Some(base), Some(current), None) if base == current => (
            "clean".to_string(),
            None,
            field_diffs(before, local, incoming),
        ),
        (Some(_), None, None) => (
            "already_applied".to_string(),
            None,
            field_diffs(before, local, incoming),
        ),
        (Some(_), Some(_), None) => (
            "delete_conflict".to_string(),
            None,
            field_diffs(before, local, incoming),
        ),
        _ => (
            "conflict".to_string(),
            incoming.clone(),
            field_diffs(before, local, incoming),
        ),
    }
}

fn three_way_object_merge(base: &Value, local: &Value, incoming: &Value) -> (Value, Vec<String>) {
    let (Some(base), Some(local), Some(incoming)) =
        (base.as_object(), local.as_object(), incoming.as_object())
    else {
        return (incoming.clone(), vec!["value".to_string()]);
    };
    let mut merged = local.clone();
    let mut conflicts = Vec::new();
    let keys: HashSet<String> = base
        .keys()
        .chain(local.keys())
        .chain(incoming.keys())
        .cloned()
        .collect();
    for key in keys {
        if ignored_derived_field(&key) {
            continue;
        }
        let b = base.get(&key);
        let l = local.get(&key);
        let i = incoming.get(&key);
        let local_changed = l != b;
        let incoming_changed = i != b;
        if incoming_changed && !local_changed {
            match i {
                Some(value) => {
                    merged.insert(key, value.clone());
                }
                None => {
                    merged.remove(&key);
                }
            }
        } else if incoming_changed && local_changed && l != i {
            conflicts.push(key);
        }
    }
    (Value::Object(merged), conflicts)
}

fn field_diffs(
    before: &Option<Value>,
    local: &Option<Value>,
    incoming: &Option<Value>,
) -> Vec<FieldDiff> {
    let empty = Map::new();
    let base = before.as_ref().and_then(Value::as_object).unwrap_or(&empty);
    let local_obj = local.as_ref().and_then(Value::as_object).unwrap_or(&empty);
    let incoming_obj = incoming
        .as_ref()
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let mut keys: Vec<String> = base
        .keys()
        .chain(local_obj.keys())
        .chain(incoming_obj.keys())
        .filter(|key| !ignored_derived_field(key))
        .cloned()
        .collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter_map(|field| {
            let b = base.get(&field).cloned();
            let l = local_obj.get(&field).cloned();
            let i = incoming_obj.get(&field).cloned();
            if b == i && l == i {
                return None;
            }
            let conflict = l != b && i != b && l != i;
            Some(FieldDiff {
                field,
                base: b,
                local: l,
                incoming: i,
                conflict,
            })
        })
        .collect()
}

pub fn apply_bundle(
    conn: &mut Connection,
    actor: &ActorIdentity,
    bundle: &ChangeBundle,
    preview: &MergePreview,
    decisions: &[MergeDecision],
) -> AppResult<MergeApplySummary> {
    let decision_map: HashMap<&str, &MergeDecision> = decisions
        .iter()
        .map(|d| (d.change_id.as_str(), d))
        .collect();
    let mut selected: Vec<(&MergePreviewChange, Option<Value>)> = preview
        .changes
        .iter()
        .filter_map(|change| {
            let decision = decision_map.get(change.id.as_str())?;
            if !decision.selected || change.classification == "already_applied" {
                return None;
            }
            let resolved = if decision.resolved_after.is_some() {
                decision.resolved_after.clone()
            } else {
                change.suggested.clone()
            };
            Some((change, resolved))
        })
        .collect();
    selected.sort_by_key(|(change, after)| entity_order(&change.entity_type, after.is_none()));
    if selected.is_empty() {
        return Ok(MergeApplySummary {
            applied: 0,
            skipped: preview.changes.len(),
            merge_commit_id: None,
        });
    }
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut local_changes = Vec::new();
    let mut interface_asset_before: HashMap<String, Option<Value>> = HashMap::new();
    let mut interface_firewall_before: HashMap<String, Option<Value>> = HashMap::new();
    let mut applied_selected = 0usize;
    for (change, resolved) in selected {
        let current = get_entity_json(&tx, &change.entity_type, &change.entity_id)?;
        if current == resolved {
            continue;
        }
        if change.entity_type == "network_interface" {
            for asset_id in interface_asset_ids(&current, &resolved) {
                if !interface_asset_before.contains_key(&asset_id) {
                    let before = get_entity_json(&tx, "asset", &asset_id)?;
                    interface_asset_before.insert(asset_id, before);
                }
            }
        }
        if change.entity_type == "firewall_interface" {
            for firewall_id in interface_firewall_ids(&current, &resolved) {
                if !interface_firewall_before.contains_key(&firewall_id) {
                    let before = get_entity_json(&tx, "firewall", &firewall_id)?;
                    interface_firewall_before.insert(firewall_id, before);
                }
            }
        }
        if let Some(value) = &resolved {
            upsert_entity_json(&tx, &change.entity_type, value)?;
        } else {
            delete_entity_direct(&tx, &change.entity_type, &change.entity_id)?;
        }
        let after = get_entity_json(&tx, &change.entity_type, &change.entity_id)?;
        let operation = match (&current, &after) {
            (None, Some(_)) => "create",
            (Some(_), None) => "delete",
            _ => "update",
        };
        local_changes.push(EntityChangeInput {
            entity_type: change.entity_type.clone(),
            entity_id: change.entity_id.clone(),
            operation: operation.into(),
            before: current,
            after,
            source_change_id: Some(change.source_change_ids.join(",")),
        });
        applied_selected += 1;
    }
    for (asset_id, before) in interface_asset_before {
        reconcile_asset_primary_interface(&tx, &asset_id)?;
        let after = get_entity_json(&tx, "asset", &asset_id)?;
        if before == after {
            continue;
        }
        if let Some(existing) = local_changes
            .iter_mut()
            .find(|change| change.entity_type == "asset" && change.entity_id == asset_id)
        {
            existing.after = after;
            existing.operation = match (&existing.before, &existing.after) {
                (None, Some(_)) => "create",
                (Some(_), None) => "delete",
                _ => "update",
            }
            .into();
        } else {
            let operation = match (&before, &after) {
                (None, Some(_)) => "create",
                (Some(_), None) => "delete",
                _ => "update",
            };
            local_changes.push(EntityChangeInput {
                entity_type: "asset".into(),
                entity_id: asset_id,
                operation: operation.into(),
                before,
                after,
                source_change_id: None,
            });
        }
    }
    for (firewall_id, before) in interface_firewall_before {
        reconcile_firewall_primary_interface(&tx, &firewall_id)?;
        let after = get_entity_json(&tx, "firewall", &firewall_id)?;
        if before == after {
            continue;
        }
        if let Some(existing) = local_changes
            .iter_mut()
            .find(|change| change.entity_type == "firewall" && change.entity_id == firewall_id)
        {
            existing.after = after;
            existing.operation = "update".into();
        } else {
            local_changes.push(EntityChangeInput {
                entity_type: "firewall".into(),
                entity_id: firewall_id,
                operation: "update".into(),
                before,
                after,
                source_change_id: None,
            });
        }
    }
    if local_changes.is_empty() {
        tx.rollback().map_err(|e| e.to_string())?;
        return Ok(MergeApplySummary {
            applied: 0,
            skipped: preview.changes.len(),
            merge_commit_id: None,
        });
    }
    let commit_id = record_commit_tx(
        &tx,
        actor,
        &format!("Merged changes from {}", bundle.exported_by),
        local_changes,
        &[bundle.head_commit_id.clone()],
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(MergeApplySummary {
        applied: applied_selected,
        skipped: preview.changes.len().saturating_sub(applied_selected),
        merge_commit_id: Some(commit_id),
    })
}

fn interface_asset_ids(current: &Option<Value>, resolved: &Option<Value>) -> Vec<String> {
    let mut ids = Vec::new();
    for value in [current, resolved].into_iter().flatten() {
        if let Some(asset_id) = value.get("asset_id").and_then(Value::as_str) {
            if !ids.iter().any(|id| id == asset_id) {
                ids.push(asset_id.to_string());
            }
        }
    }
    ids
}

fn interface_firewall_ids(current: &Option<Value>, resolved: &Option<Value>) -> Vec<String> {
    let mut ids = Vec::new();
    for value in [current, resolved].into_iter().flatten() {
        if let Some(firewall_id) = value.get("firewall_id").and_then(Value::as_str) {
            if !ids.iter().any(|id| id == firewall_id) {
                ids.push(firewall_id.to_string());
            }
        }
    }
    ids
}

fn entity_order(entity_type: &str, deleting: bool) -> usize {
    let rank = match entity_type {
        "case" => 0,
        "network" => 1,
        "asset" => 2,
        "network_interface" => 3,
        "clock_profile" => 3,
        "firewall" => 3,
        "firewall_interface" => 4,
        "firewall_nat_rule" => 5,
        "network_connection" => 5,
        "timeline_event" => 6,
        "note" => 6,
        "ioc" => 6,
        _ => 9,
    };
    if deleting {
        100 - rank
    } else {
        rank
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        get_assets, get_network_interfaces, get_networks, init_database, initialize_history,
        update_network, update_network_interface,
    };

    fn actor(name: &str) -> ActorIdentity {
        ActorIdentity::new(
            name.to_string(),
            Some("Room 4 / DMZ".to_string()),
            vec!["network-1".to_string()],
        )
        .unwrap()
    }

    fn seeded_case() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_database(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO cases(id,name,description,client_name,investigator,status,created_at,updated_at,metadata)
             VALUES('case-shared','Case','','Client','Lead','active','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z',NULL);
             INSERT INTO networks(id,name,subnet,network_type,description,vlan_id,created_at)
             VALUES('network-1','Shared','10.0.0.0/24','LAN','Base description',NULL,'2025-01-01T00:00:00Z');",
        ).unwrap();
        initialize_history(&conn).unwrap();
        conn
    }

    fn seeded_asset_case() -> Connection {
        let conn = seeded_case();
        conn.execute_batch(
            "INSERT INTO networks(id,name,subnet,network_type,description,vlan_id,created_at)
             VALUES('network-2','DMZ','172.16.0.0/24','DMZ','',NULL,'2025-01-01T00:00:00Z');
             INSERT INTO assets(id,network_id,name,ip_address,mac_address,asset_type,os,user_name,suspicious,compromise_status,investigation_status,properties,scan_results,created_at)
             VALUES('asset-1','network-1','PC','10.0.0.5',NULL,'workstation',NULL,NULL,0,'unknown','not_started',NULL,NULL,'2025-01-01T00:00:00Z');
             INSERT INTO network_interfaces(id,asset_id,name,ip_address,mac_address,network_id,is_primary)
             VALUES('nic-1','asset-1','Ethernet','10.0.0.5',NULL,'network-1',1),
                   ('nic-2','asset-1','Ethernet 2','172.16.0.5',NULL,'network-2',0);",
        )
        .unwrap();
        initialize_history(&conn).unwrap();
        conn
    }

    #[test]
    fn non_overlapping_edits_are_auto_merged_with_attribution_and_two_parents() {
        let mut local = seeded_case();
        let mut incoming = seeded_case();
        let bob = actor("Bob");
        let alice = actor("Alice");
        update_network(
            &mut incoming,
            &bob,
            "network-1",
            "Renamed",
            "10.0.0.0/24",
            "LAN",
            "Base description",
            None,
        )
        .unwrap();
        let bundle = export_change_bundle(&incoming, &bob).unwrap();
        update_network(
            &mut local,
            &alice,
            "network-1",
            "Shared",
            "10.0.0.0/24",
            "LAN",
            "Local room finding",
            None,
        )
        .unwrap();

        let preview = preview_bundle(&local, &bundle).unwrap();
        assert!(preview.common_base);
        assert_eq!(preview.changes.len(), 1);
        assert_eq!(preview.changes[0].classification, "auto_mergeable");
        assert_eq!(preview.changes[0].author_name, "Bob");
        assert!(preview.changes[0].scope.is_some());
        let decision = MergeDecision {
            change_id: preview.changes[0].id.clone(),
            selected: true,
            resolved_after: None,
        };
        let summary = apply_bundle(&mut local, &alice, &bundle, &preview, &[decision]).unwrap();
        assert_eq!(summary.applied, 1);
        let merged = get_networks(&local).unwrap().pop().unwrap();
        assert_eq!(merged.name, "Renamed");
        assert_eq!(merged.description, "Local room finding");
        let history = get_history(&local, 10).unwrap();
        assert_eq!(history[0].author_name, "Alice");
        assert_eq!(history[0].parent_ids.len(), 2);
        assert_eq!(history[0].parent_ids[1], bundle.head_commit_id);
    }

    #[test]
    fn same_field_edits_require_an_explicit_resolution() {
        let mut local = seeded_case();
        let mut incoming = seeded_case();
        let bob = actor("Bob");
        let alice = actor("Alice");
        update_network(
            &mut incoming,
            &bob,
            "network-1",
            "Bob name",
            "10.0.0.0/24",
            "LAN",
            "Base description",
            None,
        )
        .unwrap();
        update_network(
            &mut local,
            &alice,
            "network-1",
            "Alice name",
            "10.0.0.0/24",
            "LAN",
            "Base description",
            None,
        )
        .unwrap();
        let bundle = export_change_bundle(&incoming, &bob).unwrap();
        let preview = preview_bundle(&local, &bundle).unwrap();
        let change = &preview.changes[0];
        assert_eq!(change.classification, "conflict");
        assert!(change
            .fields
            .iter()
            .any(|field| field.field == "name" && field.conflict));

        let mut resolved = change.suggested.clone().unwrap();
        resolved
            .as_object_mut()
            .unwrap()
            .insert("name".into(), Value::String("Team decision".into()));
        let decision = MergeDecision {
            change_id: change.id.clone(),
            selected: true,
            resolved_after: Some(resolved),
        };
        apply_bundle(&mut local, &alice, &bundle, &preview, &[decision]).unwrap();
        assert_eq!(get_networks(&local).unwrap()[0].name, "Team decision");
    }

    #[test]
    fn unknown_baseline_is_never_auto_applied_and_repeat_bundle_is_detected() {
        let mut local = seeded_case();
        let mut incoming = seeded_case();
        let bob = actor("Bob");
        let merger = actor("Merger");
        update_network(
            &mut incoming,
            &bob,
            "network-1",
            "Renamed",
            "10.0.0.0/24",
            "LAN",
            "Base description",
            None,
        )
        .unwrap();
        let bundle = export_change_bundle(&incoming, &bob).unwrap();
        let preview = preview_bundle(&local, &bundle).unwrap();
        let decision = MergeDecision {
            change_id: preview.changes[0].id.clone(),
            selected: true,
            resolved_after: None,
        };
        apply_bundle(&mut local, &merger, &bundle, &preview, &[decision]).unwrap();
        let repeated = preview_bundle(&local, &bundle).unwrap();
        assert_eq!(repeated.changes[0].classification, "already_applied");

        let mut unrelated = bundle.clone();
        unrelated.base_commit_id = "unrelated-base".into();
        let unrelated_preview = preview_bundle(&seeded_case(), &unrelated).unwrap();
        assert!(!unrelated_preview.common_base);
        assert_eq!(unrelated_preview.changes[0].classification, "conflict");
    }

    #[test]
    fn bundle_rejects_a_different_case() {
        let incoming = seeded_case();
        let bob = actor("Bob");
        let mut bundle = export_change_bundle(&incoming, &bob).unwrap();
        bundle.case_id = "other-case".into();
        assert!(preview_bundle(&seeded_case(), &bundle)
            .unwrap_err()
            .contains("different case"));
    }

    #[test]
    fn selectively_merging_a_primary_nic_still_reconciles_the_asset_projection() {
        let mut local = seeded_asset_case();
        let mut incoming = seeded_asset_case();
        let bob = actor("Bob");
        let merger = actor("Merger");
        update_network_interface(
            &mut incoming,
            &bob,
            "nic-2",
            "Ethernet 2",
            "172.16.0.8",
            None,
            Some("network-2"),
            true,
        )
        .unwrap();
        let bundle = export_change_bundle(&incoming, &bob).unwrap();
        let preview = preview_bundle(&local, &bundle).unwrap();
        let decisions: Vec<MergeDecision> = preview
            .changes
            .iter()
            .map(|change| MergeDecision {
                change_id: change.id.clone(),
                selected: change.entity_type == "network_interface" && change.entity_id == "nic-2",
                resolved_after: None,
            })
            .collect();
        apply_bundle(&mut local, &merger, &bundle, &preview, &decisions).unwrap();

        let interfaces = get_network_interfaces(&local, Some("asset-1")).unwrap();
        assert_eq!(
            interfaces.iter().filter(|value| value.is_primary).count(),
            1
        );
        assert!(interfaces
            .iter()
            .any(|value| value.id == "nic-2" && value.is_primary));
        let asset = &get_assets(&local).unwrap()[0];
        assert_eq!(asset.network_id.as_deref(), Some("network-2"));
        assert_eq!(asset.ip_address, "172.16.0.8");
        let latest = &get_history(&local, 1).unwrap()[0];
        assert!(latest
            .changes
            .iter()
            .any(|change| change.entity_type == "asset"));
    }
}
