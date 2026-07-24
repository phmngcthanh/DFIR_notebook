//! IOC export to interchange formats.
//!
//! IR teams push the case's indicators *out* — into a SIEM lookup, an EDR block
//! list, a firewall deny rule, or a threat-intel platform. This turns the IOC
//! list into two portable artifacts:
//!
//! - **CSV** (RFC 4180) — ingestible by Excel, Splunk lookups, EDR/firewall imports.
//! - **STIX 2.1 bundle** — the standard TIP/TAXII interchange (MISP, OpenCTI, …).
//!
//! Both are pure functions over the shared `Ioc` core type, so they carry no
//! Tauri/HTTP/DB coupling and are unit-tested without a database.

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::db::Ioc;

/// Fixed namespace so a given IOC always yields the same STIX indicator id
/// across exports — a TIP/SIEM then de-duplicates re-ingested indicators
/// instead of accumulating a fresh copy on every push.
const STIX_NAMESPACE: Uuid = Uuid::from_u128(0x9a7b_3c1e_5d2f_4a6b_8c0d_1e2f_3a4b_5c6d);

const CSV_HEADER: &str = "id,type,value,threat_level,description,first_seen,last_seen,created_at";

/// Render the IOCs as RFC 4180 CSV (CRLF rows, quoted-and-escaped fields).
pub fn iocs_to_csv(iocs: &[Ioc]) -> String {
    let mut out = String::from(CSV_HEADER);
    out.push_str("\r\n");
    for ioc in iocs {
        let fields = [
            ioc.id.as_str(),
            ioc.ioc_type.as_str(),
            ioc.value.as_str(),
            ioc.threat_level.as_str(),
            ioc.description.as_str(),
            ioc.first_seen.as_deref().unwrap_or(""),
            ioc.last_seen.as_deref().unwrap_or(""),
            ioc.created_at.as_str(),
        ];
        let row: Vec<String> = fields.iter().map(|field| csv_field(field)).collect();
        out.push_str(&row.join(","));
        out.push_str("\r\n");
    }
    out
}

/// Quote a CSV field when it contains a delimiter, quote, or newline; double
/// any embedded quote.
fn csv_field(value: &str) -> String {
    if value.contains(['"', ',', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Render the IOCs as a STIX 2.1 bundle of `indicator` objects.
pub fn iocs_to_stix(iocs: &[Ioc]) -> Result<String, String> {
    let objects: Vec<Value> = iocs.iter().map(indicator).collect();
    let bundle = json!({
        "type": "bundle",
        "id": format!("bundle--{}", Uuid::new_v4()),
        "objects": objects,
    });
    serde_json::to_string_pretty(&bundle).map_err(|error| error.to_string())
}

fn indicator(ioc: &Ioc) -> Value {
    // created_at is machine-written and always parseable; the epoch is only a
    // defensive fallback so a corrupt value can never panic the export.
    let created = parse_ts(&ioc.created_at)
        .unwrap_or_else(|| DateTime::from_timestamp(0, 0).expect("epoch is valid"));
    let valid_from = ioc.first_seen.as_deref().and_then(parse_ts).unwrap_or(created);
    // STIX requires valid_until strictly after valid_from when present.
    let valid_until = ioc
        .last_seen
        .as_deref()
        .and_then(parse_ts)
        .filter(|until| *until > valid_from);

    let mut object = Map::new();
    object.insert("type".into(), json!("indicator"));
    object.insert("spec_version".into(), json!("2.1"));
    object.insert(
        "id".into(),
        json!(format!(
            "indicator--{}",
            Uuid::new_v5(&STIX_NAMESPACE, ioc.id.as_bytes())
        )),
    );
    object.insert("created".into(), json!(format_ts(created)));
    object.insert("modified".into(), json!(format_ts(created)));
    object.insert("name".into(), json!(indicator_name(ioc)));
    if !ioc.description.trim().is_empty() {
        object.insert("description".into(), json!(ioc.description));
    }
    object.insert("indicator_types".into(), json!(["malicious-activity"]));
    object.insert("pattern".into(), json!(stix_pattern(ioc)));
    object.insert("pattern_type".into(), json!("stix"));
    object.insert("valid_from".into(), json!(format_ts(valid_from)));
    if let Some(until) = valid_until {
        object.insert("valid_until".into(), json!(format_ts(until)));
    }
    if let Some(confidence) = confidence(&ioc.threat_level) {
        object.insert("confidence".into(), json!(confidence));
    }
    // Custom property (STIX requires the x_ prefix) carries the analyst's
    // qualitative rating alongside the numeric confidence.
    object.insert("x_dfir_threat_level".into(), json!(ioc.threat_level));
    Value::Object(object)
}

fn indicator_name(ioc: &Ioc) -> String {
    let value: String = ioc.value.trim().chars().take(120).collect();
    format!("{}: {}", ioc.ioc_type, value)
}

/// Map an IOC to a STIX pattern. The type vocabulary matches the app's own
/// (`IP`, `Hash`, `Domain`, `URL`, `Email`, `Registry`, `Mutex`).
fn stix_pattern(ioc: &Ioc) -> String {
    let value = escape_pattern(ioc.value.trim());
    match ioc.ioc_type.as_str() {
        "IP" if ioc.value.contains(':') => format!("[ipv6-addr:value = '{value}']"),
        "IP" => format!("[ipv4-addr:value = '{value}']"),
        "Hash" => format!(
            "[file:hashes.'{}' = '{value}']",
            hash_algorithm(ioc.value.trim())
        ),
        "Domain" => format!("[domain-name:value = '{value}']"),
        "URL" => format!("[url:value = '{value}']"),
        "Email" => format!("[email-addr:value = '{value}']"),
        "Registry" => format!("[windows-registry-key:key = '{value}']"),
        "Mutex" => format!("[mutex:name = '{value}']"),
        // Unknown types never validate at the create layer, but keep the export
        // total rather than dropping an indicator.
        _ => format!("[x-dfir-ioc:value = '{value}']"),
    }
}

/// Infer the hash algorithm from the hex length (standard digests only).
fn hash_algorithm(value: &str) -> &'static str {
    match value.len() {
        32 => "MD5",
        40 => "SHA-1",
        64 => "SHA-256",
        128 => "SHA-512",
        _ => "SHA-256",
    }
}

/// Escape a STIX string literal: backslash first, then single-quote.
fn escape_pattern(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

fn confidence(threat_level: &str) -> Option<u8> {
    match threat_level {
        "low" => Some(15),
        "medium" => Some(50),
        "high" => Some(75),
        "critical" => Some(95),
        _ => None,
    }
}

fn parse_ts(raw: &str) -> Option<DateTime<Utc>> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// STIX timestamps are RFC 3339, millisecond precision, `Z` suffix.
fn format_ts(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ioc(id: &str, ioc_type: &str, value: &str, threat: &str) -> Ioc {
        Ioc {
            id: id.to_string(),
            ioc_type: ioc_type.to_string(),
            value: value.to_string(),
            description: String::new(),
            threat_level: threat.to_string(),
            first_seen: None,
            last_seen: None,
            created_at: "2026-07-25T10:00:00Z".to_string(),
        }
    }

    fn sample() -> Vec<Ioc> {
        vec![
            ioc("i-ipv4", "IP", "10.0.0.9", "high"),
            ioc("i-ipv6", "IP", "2001:db8::1", "medium"),
            ioc("i-md5", "Hash", "d41d8cd98f00b204e9800998ecf8427e", "low"),
            ioc(
                "i-sha256",
                "Hash",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "critical",
            ),
            ioc("i-domain", "Domain", "evil.example", "high"),
            ioc("i-url", "URL", "https://evil.example/a", "high"),
            ioc("i-email", "Email", "attacker@evil.example", "medium"),
            ioc("i-reg", "Registry", "HKLM\\Software\\Evil", "low"),
            ioc("i-mutex", "Mutex", "Global\\EvilMutex", "medium"),
        ]
    }

    #[test]
    fn csv_has_header_and_one_row_per_ioc() {
        let iocs = sample();
        let csv = iocs_to_csv(&iocs);
        let lines: Vec<&str> = csv.trim_end_matches("\r\n").split("\r\n").collect();
        assert_eq!(lines[0], CSV_HEADER);
        assert_eq!(lines.len(), iocs.len() + 1);
        assert!(csv.contains("10.0.0.9"));
        assert!(csv.contains("attacker@evil.example"));
    }

    #[test]
    fn csv_escapes_delimiters_quotes_and_newlines() {
        let mut nasty = ioc("i-nasty", "Domain", "weird.example", "low");
        nasty.description = "a,b\"c\nd".to_string();
        let csv = iocs_to_csv(std::slice::from_ref(&nasty));
        // comma+quote+newline field becomes one quoted field with doubled quotes
        assert!(csv.contains("\"a,b\"\"c\nd\""));
        // exactly one field was quoted (the description)
        assert_eq!(csv.matches('"').count(), 4);
    }

    #[test]
    fn stix_bundle_shape_and_patterns() {
        let iocs = sample();
        let bundle: Value = serde_json::from_str(&iocs_to_stix(&iocs).unwrap()).unwrap();
        assert_eq!(bundle["type"], "bundle");
        assert!(bundle["id"].as_str().unwrap().starts_with("bundle--"));
        let objects = bundle["objects"].as_array().unwrap();
        assert_eq!(objects.len(), iocs.len());

        let pattern = |name_prefix: &str| -> String {
            objects
                .iter()
                .find(|o| o["name"].as_str().unwrap().starts_with(name_prefix))
                .unwrap()["pattern"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(pattern("IP: 10.0.0.9"), "[ipv4-addr:value = '10.0.0.9']");
        assert_eq!(pattern("IP: 2001:db8::1"), "[ipv6-addr:value = '2001:db8::1']");
        assert!(pattern("Hash: d41d8cd9").contains("file:hashes.'MD5'"));
        assert!(pattern("Hash: e3b0c442").contains("file:hashes.'SHA-256'"));
        assert_eq!(
            pattern("Domain"),
            "[domain-name:value = 'evil.example']"
        );
        assert_eq!(pattern("Registry"), "[windows-registry-key:key = 'HKLM\\\\Software\\\\Evil']");

        // every indicator carries a Z-terminated STIX timestamp and stix pattern_type
        for object in objects {
            assert_eq!(object["type"], "indicator");
            assert_eq!(object["spec_version"], "2.1");
            assert_eq!(object["pattern_type"], "stix");
            assert!(object["created"].as_str().unwrap().ends_with('Z'));
            assert!(object["valid_from"].as_str().unwrap().ends_with('Z'));
        }
    }

    #[test]
    fn confidence_reflects_threat_level() {
        let bundle: Value =
            serde_json::from_str(&iocs_to_stix(&[ioc("i", "Domain", "e.example", "critical")]).unwrap())
                .unwrap();
        assert_eq!(bundle["objects"][0]["confidence"], 95);
        assert_eq!(bundle["objects"][0]["x_dfir_threat_level"], "critical");
    }

    #[test]
    fn indicator_ids_are_deterministic_across_exports() {
        let iocs = sample();
        let first: Value = serde_json::from_str(&iocs_to_stix(&iocs).unwrap()).unwrap();
        let second: Value = serde_json::from_str(&iocs_to_stix(&iocs).unwrap()).unwrap();
        let ids = |b: &Value| -> Vec<String> {
            b["objects"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| o["id"].as_str().unwrap().to_string())
                .collect()
        };
        // same indicator ids both times; only the bundle wrapper id differs
        assert_eq!(ids(&first), ids(&second));
        assert_ne!(first["id"], second["id"]);
    }

    #[test]
    fn valid_until_is_omitted_unless_after_valid_from() {
        let mut same = ioc("i", "Domain", "e.example", "low");
        same.first_seen = Some("2026-07-25T10:00:00Z".to_string());
        same.last_seen = Some("2026-07-25T10:00:00Z".to_string()); // not strictly after
        let bundle: Value = serde_json::from_str(&iocs_to_stix(&[same]).unwrap()).unwrap();
        assert!(bundle["objects"][0].get("valid_until").is_none());
    }
}
