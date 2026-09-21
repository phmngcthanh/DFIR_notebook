//! Dedicated event-log evidence store.
//!
//! Raw Windows and Unix events deliberately live outside the investigation
//! database. The sidecar is encrypted with the same case password and follows
//! the case connection's lifetime, but it has its own schema and no history
//! tables so high-volume evidence cannot inflate case snapshots or merges.
//! Investigators search the sidecar and promote the records that matter into
//! attributed timeline events; the raw evidence stays untouched.
//!
//! This module is part of the shared core: it must not reference `tauri` and
//! only reaches the rest of the core through `crate::db` / `crate::history`
//! / `crate::secure_db`.

use std::path::{Path, PathBuf};

use chrono::{Datelike, DateTime, Offset, Utc};
use rusqlite::{params, Connection};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::db::{create_timeline_event, fixed_offset, parse_log_timestamp, AppResult};
use crate::history::ActorIdentity;
use crate::secure_db::{create_encrypted_connection, open_encrypted_connection};

/// Sidecar file extension. Deliberately not `db` so the server's case listing
/// (which only exposes `*.db`) never mistakes an evidence store for a case.
pub const SIDECAR_EXTENSION: &str = "dfirlogs";

/// Records one `promote_records` call may create. Promotion writes a history
/// commit per event; keep selections reviewable.
const PROMOTE_LIMIT: usize = 500;

pub fn sidecar_path(case_path: &Path) -> PathBuf {
    case_path.with_extension(SIDECAR_EXTENSION)
}

// ---------------------------------------------------------------------------
// Store lifecycle
// ---------------------------------------------------------------------------

/// Open the sidecar for a case, creating and initializing it when absent.
/// The caller has already verified the password against the case database,
/// so a fresh sidecar can never be created with an unverified password.
pub fn open_store(case_path: &Path, password: &str) -> AppResult<Connection> {
    let sidecar = sidecar_path(case_path);
    let conn = if sidecar.exists() {
        open_encrypted_connection(&sidecar, password)
            .map_err(|error| format!("Could not open the event-log store: {error}"))?
    } else {
        create_encrypted_connection(&sidecar, password)
            .map_err(|error| format!("Could not create the event-log store: {error}"))?
    };
    init_schema(&conn)?;
    Ok(conn)
}

/// Create the sidecar schema when needed. `user_version` gates future
/// migrations the same way the case database's does.
fn init_schema(conn: &Connection) -> AppResult<()> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if version >= 1 {
        return Ok(());
    }
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;
         CREATE TABLE IF NOT EXISTS import_batches(
           id TEXT PRIMARY KEY,
           kind TEXT NOT NULL,
           file_name TEXT,
           host TEXT,
           timezone TEXT NOT NULL DEFAULT 'UTC',
           note TEXT,
           record_count INTEGER NOT NULL,
           skipped_count INTEGER NOT NULL,
           first_time_utc TEXT,
           last_time_utc TEXT,
           imported_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS event_records(
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           batch_id TEXT NOT NULL REFERENCES import_batches(id) ON DELETE CASCADE,
           ordinal INTEGER NOT NULL,
           event_time_utc TEXT,
           raw_time TEXT,
           host TEXT,
           provider TEXT,
           channel TEXT,
           event_id TEXT,
           level TEXT,
           message TEXT,
           details TEXT NOT NULL,
           UNIQUE(batch_id, ordinal)
         );
         CREATE INDEX IF NOT EXISTS idx_event_records_batch ON event_records(batch_id);
         CREATE INDEX IF NOT EXISTS idx_event_records_time ON event_records(event_time_utc);
         CREATE INDEX IF NOT EXISTS idx_event_records_host ON event_records(host);
         PRAGMA user_version = 1;",
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreCounts {
    pub batch_count: i64,
    pub record_count: i64,
}

pub fn store_counts(conn: &Connection) -> AppResult<StoreCounts> {
    let batch_count = conn
        .query_row("SELECT COUNT(*) FROM import_batches", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    let record_count = conn
        .query_row("SELECT COUNT(*) FROM event_records", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    Ok(StoreCounts {
        batch_count,
        record_count,
    })
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

struct NormalizedRecord {
    event_time_utc: Option<String>,
    raw_time: Option<String>,
    host: Option<String>,
    provider: Option<String>,
    channel: Option<String>,
    event_id: Option<String>,
    level: Option<String>,
    message: Option<String>,
    details: Value,
}

fn format_utc(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Resolve the import timezone once per batch: the same interpretations the
/// timeline accepts (UTC, fixed offset, IANA zone) are accepted here.
enum ImportZone {
    Utc,
    Fixed(chrono::FixedOffset),
    Named(chrono_tz::Tz),
}

fn resolve_zone(timezone: &str) -> AppResult<ImportZone> {
    let timezone = timezone.trim();
    if timezone.is_empty() || timezone.eq_ignore_ascii_case("UTC") || timezone == "Z" {
        return Ok(ImportZone::Utc);
    }
    if let Some(offset) = fixed_offset(timezone) {
        return offset.map(ImportZone::Fixed);
    }
    timezone
        .parse::<chrono_tz::Tz>()
        .map(ImportZone::Named)
        .map_err(|_| {
            format!(
                "Unknown timezone '{timezone}'. Use UTC, a fixed offset, or an IANA zone such as Asia/Ho_Chi_Minh"
            )
            .into()
        })
}

/// Resolve the import zone to the fixed offset the syslog parser applies to
/// RFC 3164 dates. A named zone contributes its *current* offset; records
/// spanning a DST change in that zone can be off by the shift for part of
/// the batch. Offsets embedded in RFC 5424 timestamps always win.
fn zone_fixed_offset(zone: &ImportZone) -> chrono::FixedOffset {
    match zone {
        ImportZone::Utc => chrono::FixedOffset::east_opt(0).expect("zero offset"),
        ImportZone::Fixed(offset) => *offset,
        ImportZone::Named(tz) => Utc::now().with_timezone(tz).offset().fix(),
    }
}

fn parse_syslog_line(line: &str, zone: Option<chrono::FixedOffset>) -> NormalizedRecord {
    let parsed = syslog_loose::parse_message_with_year_tz(
        line,
        |_| Utc::now().year(),
        zone,
        syslog_loose::Variant::Either,
    );
    let event_time_utc = parsed
        .timestamp
        .map(|timestamp| format_utc(timestamp.with_timezone(&Utc)));
    let level = parsed.severity.as_ref().map(|severity| match severity {
        syslog_loose::SyslogSeverity::SEV_EMERG
        | syslog_loose::SyslogSeverity::SEV_ALERT
        | syslog_loose::SyslogSeverity::SEV_CRIT => "critical",
        syslog_loose::SyslogSeverity::SEV_ERR => "high",
        syslog_loose::SyslogSeverity::SEV_WARNING => "medium",
        _ => "info",
    });
    NormalizedRecord {
        event_time_utc,
        raw_time: None,
        host: non_empty(parsed.hostname.map(|value| value.to_string())),
        provider: non_empty(parsed.appname.map(|value| value.to_string())),
        channel: parsed
            .facility
            .as_ref()
            .map(|facility| format!("{facility:?}")),
        event_id: None,
        level: level.map(String::from),
        message: non_empty(Some(parsed.msg.to_string())),
        details: json!({
            "raw": line,
            "protocol": format!("{:?}", parsed.protocol),
            "severity": parsed.severity.as_ref().map(|s| format!("{s:?}")),
            "facility": parsed.facility.as_ref().map(|f| format!("{f:?}")),
            "procid": parsed.procid.as_ref().map(|p| p.to_string()),
            "msgid": parsed.msgid.map(|value| value.to_string()),
        }),
    }
}

fn normalize_syslog(line: &str, zone: &ImportZone) -> NormalizedRecord {
    parse_syslog_line(line, Some(zone_fixed_offset(zone)))
}

/// Numeric Windows event levels: 0 LogAlways, 1 Critical, 2 Error,
/// 3 Warning, 4 Informational, 5 Verbose.
fn windows_level(level: Option<&str>, display: Option<&str>) -> Option<String> {
    if let Some(display) = display.filter(|value| !value.trim().is_empty()) {
        return Some(display.trim().to_string());
    }
    let value = level?;
    Some(
        match value.trim() {
            "1" => "Critical",
            "2" => "Error",
            "3" => "Warning",
            "5" => "Verbose",
            _ => "Information",
        }
        .to_string(),
    )
}

fn json_string(value: &Value, key: &str) -> Option<String> {
    non_empty(value.get(key).and_then(Value::as_str).map(String::from))
}

impl ImportZone {
    /// String form usable by `parse_log_timestamp` for values that carry no
    /// offset of their own.
    fn as_str(&self) -> std::borrow::Cow<'static, str> {
        match self {
            ImportZone::Utc => std::borrow::Cow::Borrowed("UTC"),
            ImportZone::Fixed(offset) => {
                let seconds = offset.local_minus_utc();
                let sign = if seconds < 0 { '-' } else { '+' };
                let seconds = seconds.abs();
                std::borrow::Cow::Owned(format!(
                    "{sign}{:02}:{:02}",
                    seconds / 3600,
                    (seconds % 3600) / 60
                ))
            }
            ImportZone::Named(tz) => std::borrow::Cow::Owned(tz.name().to_string()),
        }
    }
}

/// One `Get-WinEvent … | ConvertTo-Json` object.
fn normalize_windows_event(object: &Value, zone: &ImportZone) -> Option<NormalizedRecord> {
    if !object.is_object() {
        return None;
    }
    let raw_time = json_string(object, "TimeCreated");
    let event_time_utc = match &raw_time {
        Some(value) => parse_log_timestamp(value, &zone.as_str()).ok(),
        None => None,
    };
    let event_id = object
        .get("Id")
        .and_then(|value| {
            value.as_i64().map(|number| number.to_string()).or_else(|| {
                value.as_str().map(String::from)
            })
        });
    Some(NormalizedRecord {
        event_time_utc,
        raw_time,
        host: json_string(object, "MachineName"),
        provider: json_string(object, "ProviderName"),
        channel: json_string(object, "LogName"),
        event_id,
        level: windows_level(None, object.get("LevelDisplayName").and_then(Value::as_str)),
        message: json_string(object, "Message"),
        details: object.clone(),
    })
}

/// Render one XML-ish EVTX node's inner text: `#text` may be a string or a
/// number (EventID is commonly numeric), and plain string nodes appear too.
fn xml_text(value: &Value) -> Option<String> {
    let text = value.get("#text").or(Some(value)).filter(|node| !node.is_object())?;
    if let Some(text) = text.as_str() {
        return Some(text.to_string());
    }
    if let Some(number) = text.as_i64() {
        return Some(number.to_string());
    }
    text.as_f64().map(|number| number.to_string())
}

/// Extract the common `Event.System` fields from one parsed EVTX record.
fn normalize_evtx_record(data: &Value, raw_timestamp: Option<&str>) -> NormalizedRecord {
    let event = data.get("Event").unwrap_or(data);
    let system = event.get("System");
    let attribute = |value: &Value, key: &str| {
        value
            .get("#attributes")
            .and_then(|attributes| attributes.get(key))
            .and_then(Value::as_str)
            .map(String::from)
    };
    let text_of = xml_text;
    let system_value = |key: &str| system.and_then(|node| node.get(key));
    let provider = system_value("Provider").and_then(|node| attribute(&node, "Name"));
    let raw_time = system_value("TimeCreated").and_then(|node| attribute(&node, "SystemTime"));
    let event_time_utc = raw_timestamp
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|datetime| format_utc(datetime.with_timezone(&Utc)))
        .or_else(|| {
            raw_time
                .as_deref()
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .map(|datetime| format_utc(datetime.with_timezone(&Utc)))
        });
    let event_id = system_value("EventID").and_then(|node| text_of(&node));
    let host = system_value("Computer").and_then(|node| text_of(&node));
    let channel = system_value("Channel").and_then(|node| text_of(&node));
    let level = system_value("Level").and_then(|node| text_of(&node));
    let message = event
        .get("EventData")
        .and_then(|node| node.get("Data"))
        .map(|data| render_event_data(data));
    NormalizedRecord {
        event_time_utc,
        raw_time,
        host,
        provider,
        channel,
        event_id,
        level: windows_level(level.as_deref(), None),
        message: non_empty(message),
        details: data.clone(),
    }
}

/// Flatten `EventData.Data` name/value pairs into one readable line.
fn render_event_data(data: &Value) -> String {
    let pairs: Vec<String> = match data {
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => text.clone(),
                Value::Object(_) => {
                    let name = item
                        .get("Name")
                        .and_then(Value::as_str)
                        .unwrap_or("Value");
                    let value = item
                        .get("#text")
                        .or_else(|| item.get("#attributes").and_then(|a| a.get("#text")))
                        .map(|value| value.as_str().unwrap_or_default())
                        .unwrap_or("");
                    format!("{name}={value}")
                }
                other => other.to_string(),
            })
            .collect(),
        Value::String(text) => vec![text.clone()],
        other => vec![other.to_string()],
    };
    let joined = pairs.join("; ");
    if joined.chars().count() > 1000 {
        let truncated: String = joined.chars().take(1000).collect();
        format!("{truncated}…")
    } else {
        joined
    }
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ImportOptions {
    pub file_name: Option<String>,
    pub host_hint: Option<String>,
    pub timezone: String,
    pub note: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSummary {
    pub batch_id: String,
    pub kind: &'static str,
    pub imported: usize,
    pub skipped: usize,
    pub first_time_utc: Option<String>,
    pub last_time_utc: Option<String>,
}

/// Shared writer: one batch row plus its records inside one transaction, with
/// running first/last time so huge files never need to be buffered twice.
struct BatchWriter {
    batch_id: String,
    kind: &'static str,
    imported: usize,
    skipped: usize,
    first_time_utc: Option<String>,
    last_time_utc: Option<String>,
}

impl BatchWriter {
    fn new(kind: &'static str) -> Self {
        Self {
            batch_id: Uuid::new_v4().to_string(),
            kind,
            imported: 0,
            skipped: 0,
            first_time_utc: None,
            last_time_utc: None,
        }
    }

    /// Insert the batch row before its records so the foreign key holds.
    fn begin(&self, tx: &rusqlite::Transaction, options: &ImportOptions) -> AppResult<()> {
        let timezone = options.timezone.trim();
        let timezone = if timezone.is_empty() { "UTC" } else { timezone };
        tx.execute(
            "INSERT INTO import_batches(id,kind,file_name,host,timezone,note,record_count,skipped_count,first_time_utc,last_time_utc,imported_at)
             VALUES (?1,?2,?3,?4,?5,?6,0,0,NULL,NULL,?7)",
            params![
                self.batch_id,
                self.kind,
                options.file_name,
                options.host_hint,
                timezone,
                options.note,
                Utc::now().to_rfc3339(),
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn push(&mut self, tx: &rusqlite::Transaction, ordinal: i64, record: NormalizedRecord) -> AppResult<()> {
        if let Some(time) = &record.event_time_utc {
            let earlier = self
                .first_time_utc
                .as_ref()
                .map(|first| *time < *first)
                .unwrap_or(true);
            if earlier {
                self.first_time_utc = Some(time.clone());
            }
            let later = self
                .last_time_utc
                .as_ref()
                .map(|last| *time > *last)
                .unwrap_or(true);
            if later {
                self.last_time_utc = Some(time.clone());
            }
        }
        tx.execute(
            "INSERT INTO event_records(batch_id,ordinal,event_time_utc,raw_time,host,provider,channel,event_id,level,message,details)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                self.batch_id,
                ordinal,
                record.event_time_utc,
                record.raw_time,
                record.host,
                record.provider,
                record.channel,
                record.event_id,
                record.level,
                record.message,
                record.details.to_string(),
            ],
        )
        .map_err(|e| e.to_string())?;
        self.imported += 1;
        Ok(())
    }

    fn finish(self, tx: &rusqlite::Transaction) -> AppResult<BatchSummary> {
        tx.execute(
            "UPDATE import_batches SET record_count=?2, skipped_count=?3, first_time_utc=?4, last_time_utc=?5 WHERE id=?1",
            params![
                self.batch_id,
                self.imported as i64,
                self.skipped as i64,
                self.first_time_utc,
                self.last_time_utc,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(BatchSummary {
            batch_id: self.batch_id,
            kind: self.kind,
            imported: self.imported,
            skipped: self.skipped,
            first_time_utc: self.first_time_utc,
            last_time_utc: self.last_time_utc,
        })
    }
}

fn require_some_imported(summary: BatchSummary, kind: &str) -> AppResult<BatchSummary> {
    if summary.imported == 0 {
        return Err(format!(
            "No readable {kind} records were found in the supplied input ({} unreadable entries)",
            summary.skipped
        )
        .into());
    }
    Ok(summary)
}

pub fn import_syslog_text(
    conn: &mut Connection,
    options: &ImportOptions,
    text: &str,
) -> AppResult<BatchSummary> {
    let zone = resolve_zone(&options.timezone)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut writer = BatchWriter::new("syslog");
    writer.begin(&tx, &options)?;
    let mut ordinal = 0_i64;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        ordinal += 1;
        let record = normalize_syslog(line, &zone);
        if let Err(error) = writer.push(&tx, ordinal, record) {
            return Err(error);
        }
    }
    let summary = writer.finish(&tx)?;
    tx.commit().map_err(|e| e.to_string())?;
    require_some_imported(summary, "syslog")
}

pub fn import_windows_json_text(
    conn: &mut Connection,
    options: &ImportOptions,
    text: &str,
) -> AppResult<BatchSummary> {
    let zone = resolve_zone(&options.timezone)?;
    // Accept a JSON array, one object, or one JSON object per line.
    let values: Vec<Value> = if let Ok(parsed) = serde_json::from_str::<Value>(text) {
        match parsed {
            Value::Array(items) => items,
            object @ Value::Object(_) => vec![object],
            _ => Vec::new(),
        }
    } else {
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Value>(line))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Input is neither JSON nor JSON lines: {e}"))?
    };
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut writer = BatchWriter::new("windows-json");
    writer.begin(&tx, &options)?;
    for (index, value) in values.iter().enumerate() {
        match normalize_windows_event(value, &zone) {
            Some(record) => writer.push(&tx, index as i64 + 1, record)?,
            None => writer.skipped += 1,
        }
    }
    let summary = writer.finish(&tx)?;
    tx.commit().map_err(|e| e.to_string())?;
    require_some_imported(summary, "Windows event JSON")
}

pub fn import_evtx_file(
    conn: &mut Connection,
    options: &ImportOptions,
    path: &Path,
) -> AppResult<BatchSummary> {
    let mut parser = evtx::EvtxParser::from_path(path)
        .map_err(|error| format!("Could not open the EVTX file: {error}"))?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut writer = BatchWriter::new("evtx");
    writer.begin(&tx, &options)?;
    for record in parser.records() {
        let record = match record {
            Ok(record) => record,
            Err(_) => {
                writer.skipped += 1;
                continue;
            }
        };
        let data: Value = serde_json::from_str(&record.data)
            .map_err(|error| format!("Could not decode an EVTX record: {error}"))?;
        let timestamp = record.timestamp.to_string();
        let normalized = normalize_evtx_record(&data, Some(&timestamp));
        writer.push(&tx, record.event_record_id as i64, normalized)?;
    }
    let summary = writer.finish(&tx)?;
    tx.commit().map_err(|e| e.to_string())?;
    require_some_imported(summary, "EVTX")
}

// ---------------------------------------------------------------------------
// Browse and search
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogBatch {
    pub id: String,
    pub kind: String,
    pub file_name: Option<String>,
    pub host: Option<String>,
    pub timezone: String,
    pub note: Option<String>,
    pub record_count: i64,
    pub skipped_count: i64,
    pub first_time_utc: Option<String>,
    pub last_time_utc: Option<String>,
    pub imported_at: String,
}

pub fn list_batches(conn: &Connection) -> AppResult<Vec<EventLogBatch>> {
    let mut statement = conn
        .prepare(
            "SELECT id,kind,file_name,host,timezone,note,record_count,skipped_count,first_time_utc,last_time_utc,imported_at
             FROM import_batches ORDER BY imported_at DESC, id",
        )
        .map_err(|e| e.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok(EventLogBatch {
                id: row.get(0)?,
                kind: row.get(1)?,
                file_name: row.get(2)?,
                host: row.get(3)?,
                timezone: row.get(4)?,
                note: row.get(5)?,
                record_count: row.get(6)?,
                skipped_count: row.get(7)?,
                first_time_utc: row.get(8)?,
                last_time_utc: row.get(9)?,
                imported_at: row.get(10)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(rows)
}

#[derive(Default)]
pub struct EventLogSearchParams {
    pub query: Option<String>,
    pub batch_id: Option<String>,
    pub host: Option<String>,
    pub event_id: Option<String>,
    pub from_utc: Option<String>,
    pub to_utc: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogRecord {
    pub id: i64,
    pub batch_id: String,
    pub kind: String,
    pub event_time_utc: Option<String>,
    pub raw_time: Option<String>,
    pub host: Option<String>,
    pub provider: Option<String>,
    pub channel: Option<String>,
    pub event_id: Option<String>,
    pub level: Option<String>,
    pub message: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventLogSearchOutcome {
    pub rows: Vec<EventLogRecord>,
    pub total: i64,
}

fn escape_like(value: &str) -> String {
    value.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

pub fn search_event_logs(
    conn: &Connection,
    params: &EventLogSearchParams,
) -> AppResult<EventLogSearchOutcome> {
    let mut conditions: Vec<String> = Vec::new();
    let mut bindings: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(query) = params.query.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        conditions.push(
            "(r.message LIKE ?1 ESCAPE '\\' OR r.provider LIKE ?1 ESCAPE '\\' OR r.host LIKE ?1 ESCAPE '\\'
              OR r.channel LIKE ?1 ESCAPE '\\' OR r.event_id LIKE ?1 ESCAPE '\\' OR r.details LIKE ?1 ESCAPE '\\')".to_string(),
        );
        bindings.push(Box::new(format!("%{}%", escape_like(query))));
    }
    if let Some(batch) = params.batch_id.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        conditions.push("r.batch_id = ?".to_string());
        bindings.push(Box::new(batch.to_string()));
    }
    if let Some(host) = params.host.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        conditions.push("r.host LIKE ? ESCAPE '\\'".to_string());
        bindings.push(Box::new(format!("%{}%", escape_like(host))));
    }
    if let Some(event_id) = params.event_id.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        conditions.push("r.event_id = ?".to_string());
        bindings.push(Box::new(event_id.to_string()));
    }
    if let Some(from) = params.from_utc.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        conditions.push("r.event_time_utc >= ?".to_string());
        bindings.push(Box::new(from.to_string()));
    }
    if let Some(to) = params.to_utc.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        conditions.push("r.event_time_utc <= ?".to_string());
        bindings.push(Box::new(to.to_string()));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let total = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM event_records r JOIN import_batches b ON b.id = r.batch_id {where_clause}"
            ),
            rusqlite::params_from_iter(bindings.iter().map(|value| value.as_ref())),
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;

    let limit = params.limit.unwrap_or(100).clamp(1, 500);
    let offset = params.offset.unwrap_or(0).max(0);
    let mut statement = conn
        .prepare(&format!(
            "SELECT r.id,r.batch_id,b.kind,r.event_time_utc,r.raw_time,r.host,r.provider,r.channel,r.event_id,r.level,r.message
             FROM event_records r JOIN import_batches b ON b.id = r.batch_id {where_clause}
             ORDER BY r.event_time_utc IS NULL, r.event_time_utc DESC, r.id DESC
             LIMIT {limit} OFFSET {offset}"
        ))
        .map_err(|e| e.to_string())?;
    let rows = statement
        .query_map(
            rusqlite::params_from_iter(bindings.iter().map(|value| value.as_ref())),
            |row| {
                Ok(EventLogRecord {
                    id: row.get(0)?,
                    batch_id: row.get(1)?,
                    kind: row.get(2)?,
                    event_time_utc: row.get(3)?,
                    raw_time: row.get(4)?,
                    host: row.get(5)?,
                    provider: row.get(6)?,
                    channel: row.get(7)?,
                    event_id: row.get(8)?,
                    level: row.get(9)?,
                    message: row.get(10)?,
                })
            },
        )
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(EventLogSearchOutcome { rows, total })
}

pub fn delete_batch(conn: &mut Connection, batch_id: &str) -> AppResult<()> {
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let removed = tx
        .execute("DELETE FROM import_batches WHERE id = ?1", params![batch_id])
        .map_err(|e| e.to_string())?;
    if removed == 0 {
        return Err("That event-log batch was not found".into());
    }
    tx.commit().map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Promotion into the investigation timeline
// ---------------------------------------------------------------------------

pub struct PromoteOptions {
    pub asset_id: Option<String>,
    pub severity: String,
    pub event_type: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromoteSummary {
    pub created: usize,
    pub timeline_event_ids: Vec<String>,
}

/// Copy selected sidecar records into the case timeline. Each promoted record
/// becomes a normal attributed timeline event; the raw record is untouched.
pub fn promote_records(
    case_conn: &mut Connection,
    actor: &ActorIdentity,
    log_conn: &Connection,
    record_ids: &[i64],
    options: &PromoteOptions,
) -> AppResult<PromoteSummary> {
    if record_ids.is_empty() {
        return Err("Select at least one event-log record to promote".into());
    }
    if record_ids.len() > PROMOTE_LIMIT {
        return Err(format!(
            "Promote at most {PROMOTE_LIMIT} records at once (selected {})",
            record_ids.len()
        ));
    }
    let placeholders = record_ids
        .iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let mut statement = log_conn
        .prepare(&format!(
            "SELECT r.event_time_utc,b.kind,b.file_name,r.host,r.provider,r.channel,r.event_id,r.message
             FROM event_records r JOIN import_batches b ON b.id = r.batch_id
             WHERE r.id IN ({placeholders}) ORDER BY r.event_time_utc IS NULL, r.event_time_utc"
        ))
        .map_err(|e| e.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    if rows.len() != record_ids.len() {
        return Err("One or more selected records are no longer in the event-log store".into());
    }

    let mut created = Vec::new();
    for row in rows {
        let (event_time, kind, file_name, host, provider, channel, event_id, message) = row;
        let mut description = String::new();
        if let Some(channel) = channel.as_deref() {
            description.push('[');
            description.push_str(channel);
            description.push_str("] ");
        }
        if let Some(event_id) = event_id.as_deref() {
            description.push_str("Event ");
            description.push_str(event_id);
            description.push(' ');
        }
        if let Some(provider) = provider.as_deref() {
            description.push_str(provider);
            description.push(' ');
        }
        if let Some(host) = host.as_deref() {
            description.push_str("on ");
            description.push_str(host);
            description.push_str(": ");
        }
        if let Some(message) = message.as_deref() {
            let truncated: String = message.chars().take(280).collect();
            description.push_str(truncated.trim_end());
        }
        if description.trim().is_empty() {
            description = format!("Event-log record promoted from {kind} batch");
        }
        let source = match file_name.as_deref() {
            Some(name) => format!("Event log {kind}: {name}"),
            None => format!("Event log {kind}"),
        };
        let event = create_timeline_event(
            case_conn,
            actor,
            options.asset_id.as_deref(),
            event_time.as_deref(),
            Some("UTC"),
            None,
            None,
            None,
            options.event_type.trim(),
            description.trim(),
            options.severity.trim(),
            Some(&source),
            None,
            None,
        )?;
        created.push(event.id);
    }
    Ok(PromoteSummary {
        created: created.len(),
        timeline_event_ids: created,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::db::{create_case_record, get_timeline_events, init_database};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("dfir-event-logs-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn store(dir: &TempDir) -> Connection {
        open_store(&dir.path().join("case.db"), "testpassword").expect("sidecar opens")
    }

    fn options(timezone: &str) -> ImportOptions {
        ImportOptions {
            file_name: Some("security.json".to_string()),
            host_hint: None,
            timezone: timezone.to_string(),
            note: None,
        }
    }

    const SYSLOG: &str = "<86>Jul 19 14:25:30 fw-01 sshd[4321]: Accepted publickey for root from 10.0.0.8 port 51000 ssh2\n\
                          <86>Jul 19 14:26:02 fw-01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; COMMAND=/usr/bin/id\n\
                          <86>1 2026-07-19T14:26:40.512Z web-01 nginx - - - 10.0.0.8 - - 200 GET /index.html";

    #[test]
    fn syslog_import_normalizes_and_searches() {
        let dir = TempDir::new();
        let mut conn = store(&dir);
        let summary =
            import_syslog_text(&mut conn, &options("UTC"), SYSLOG).expect("syslog imports");
        assert_eq!(summary.imported, 3);
        assert_eq!(summary.skipped, 0);
        assert!(summary.first_time_utc.is_some());

        let outcome = search_event_logs(
            &conn,
            &EventLogSearchParams {
                query: Some("publickey".to_string()),
                ..Default::default()
            },
        )
        .expect("search works");
        assert_eq!(outcome.total, 1);
        let row = &outcome.rows[0];
        assert_eq!(row.provider.as_deref(), Some("sshd"));
        assert_eq!(row.level.as_deref(), Some("info"));
        // RFC 5424 line keeps its embedded offset interpretation.
        let nginx = search_event_logs(
            &conn,
            &EventLogSearchParams {
                query: Some("nginx".to_string()),
                ..Default::default()
            },
        )
        .expect("search works")
        .rows[0]
        .event_time_utc
        .clone();
        assert!(nginx.unwrap().starts_with("2026-07-19T14:26:40.512"));
    }

    #[test]
    fn windows_json_import_reports_skipped_records() {
        let dir = TempDir::new();
        let mut conn = store(&dir);
        let text = r#"[
            {"TimeCreated":"2026-07-19T09:00:01.500Z","Id":4624,"ProviderName":"Microsoft-Windows-Security-Auditing","LogName":"Security","LevelDisplayName":"Information","MachineName":"WS-204-07","Message":"An account was successfully logged on"},
            {"TimeCreated":"2026-07-19T09:05:12Z","Id":4672,"ProviderName":"Microsoft-Windows-Security-Auditing","LogName":"Security","MachineName":"WS-204-07","Message":"Special privileges assigned"},
            "not-an-object"
        ]"#;
        let summary = import_windows_json_text(&mut conn, &options("UTC"), text).expect("imports");
        assert_eq!(summary.imported, 2);
        assert_eq!(summary.skipped, 1);

        let outcome = search_event_logs(
            &conn,
            &EventLogSearchParams {
                event_id: Some("4624".to_string()),
                ..Default::default()
            },
        )
        .expect("search works");
        assert_eq!(outcome.total, 1);
        assert_eq!(
            outcome.rows[0].event_time_utc.as_deref(),
            Some("2026-07-19T09:00:01.500Z")
        );
    }

    #[test]
    fn deleting_a_batch_removes_its_records() {
        let dir = TempDir::new();
        let mut conn = store(&dir);
        let summary =
            import_syslog_text(&mut conn, &options("UTC"), SYSLOG).expect("syslog imports");
        delete_batch(&mut conn, &summary.batch_id).expect("batch deletes");
        let counts = store_counts(&conn).expect("counts");
        assert_eq!(counts.batch_count, 0);
        assert_eq!(counts.record_count, 0);
        assert!(delete_batch(&mut conn, &summary.batch_id).is_err());
    }

    #[test]
    fn promotion_creates_attributed_timeline_events() {
        let dir = TempDir::new();
        let mut case = crate::secure_db::create_encrypted_connection(
            &dir.path().join("case.db"),
            "testpassword",
        )
        .expect("case opens");
        init_database(&case).expect("case schema");
        create_case_record(&case, "Case", "", "Client", "Tester").expect("case record");
        let mut sidecar = open_store(&dir.path().join("case.db"), "testpassword").expect("sidecar");
        import_windows_json_text(
            &mut sidecar,
            &options("UTC"),
            r#"[{"TimeCreated":"2026-07-19T09:00:01.500Z","Id":4624,"ProviderName":"Microsoft-Windows-Security-Auditing","LogName":"Security","MachineName":"WS-204-07","Message":"An account was successfully logged on"}]"#,
        )
        .expect("imports");
        let actor =
            ActorIdentity::new("Tester".to_string(), None, Vec::new()).expect("actor");
        let row = search_event_logs(
            &sidecar,
            &EventLogSearchParams {
                event_id: Some("4624".to_string()),
                ..Default::default()
            },
        )
        .expect("search")
        .rows[0]
        .id;
        let summary = promote_records(
            &mut case,
            &actor,
            &sidecar,
            &[row],
            &PromoteOptions {
                asset_id: None,
                severity: "high".to_string(),
                event_type: "event_log".to_string(),
            },
        )
        .expect("promotion works");
        assert_eq!(summary.created, 1);
        let events = get_timeline_events(&case).expect("timeline");
        assert_eq!(events.len(), 1);
        assert!(events[0].description.contains("An account was successfully logged on"));
        assert_eq!(events[0].severity, "high");
    }

    #[test]
    fn evtx_normalizer_extracts_system_fields() {
        let data: Value = serde_json::from_str(
            r##"{"Event":{"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Security-Auditing"}},"EventID":{"#text":4624},"TimeCreated":{"#attributes":{"SystemTime":"2026-07-19T09:00:01.500421Z"}},"Computer":"WS-204-07","Channel":"Security","Level":0},"EventData":{"Data":[{"Name":"TargetUserName","#text":"alice"},{"Name":"LogonType","#text":"10"}]}}}"##,
        )
        .expect("fixture");
        let record = normalize_evtx_record(&data, Some("2026-07-19T09:00:01.500421Z"));
        assert_eq!(record.event_id.as_deref(), Some("4624"));
        assert_eq!(record.host.as_deref(), Some("WS-204-07"));
        assert_eq!(record.channel.as_deref(), Some("Security"));
        assert!(record
            .event_time_utc
            .as_deref()
            .unwrap()
            .starts_with("2026-07-19T09:00:01.500"));
        assert!(record.message.as_deref().unwrap().contains("TargetUserName=alice"));
    }

    #[test]
    fn sidecar_extension_is_not_a_case_extension() {
        assert_eq!(
            sidecar_path(Path::new("C:/cases/incident.db")),
            PathBuf::from("C:/cases/incident.dfirlogs")
        );
    }
}
