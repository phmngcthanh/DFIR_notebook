use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt::Write as _;
use zeroize::Zeroizing;

const ENCRYPTED_FORMAT: &str = "dfir-investigator-encrypted";
const ENCRYPTED_FORMAT_VERSION: u32 = 1;
const KDF_ALGORITHM: &str = "argon2id";
const KDF_VERSION: u32 = 19;
const KDF_MEMORY_KIB: u32 = 64 * 1024;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;
const CIPHER_ALGORITHM: &str = "aes-256-gcm";
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const KEY_BYTES: usize = 32;
const AUTH_TAG_BYTES: usize = 16;
const AAD: &[u8] = b"DFIR-Investigator portable export v1";
pub const MAX_PORTABLE_FILE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedEnvelope {
    format: String,
    format_version: u32,
    kdf: KdfMetadata,
    cipher: CipherMetadata,
    ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfMetadata {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CipherMetadata {
    algorithm: String,
    nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPortable {
    pub plaintext: String,
    pub encrypted: bool,
}

pub fn encode_portable_text(plaintext: &str, password: Option<&str>) -> Result<String, String> {
    match password.filter(|value| !value.is_empty()) {
        Some(password) => encrypt_portable_text(plaintext, password),
        None => Ok(plaintext.to_string()),
    }
}

pub fn decode_portable_text(
    input: &str,
    password: Option<&str>,
) -> Result<DecodedPortable, String> {
    if !is_encrypted_portable(input) {
        return Ok(DecodedPortable {
            plaintext: input.to_string(),
            encrypted: false,
        });
    }
    let password = password.filter(|value| !value.is_empty()).ok_or_else(|| {
        "This export is encrypted. Enter its export password and try again".to_string()
    })?;
    Ok(DecodedPortable {
        plaintext: decrypt_portable_text(input, password)?,
        encrypted: true,
    })
}

pub fn is_encrypted_portable(input: &str) -> bool {
    serde_json::from_str::<Value>(input)
        .ok()
        .and_then(|value| {
            value
                .get("format")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .as_deref()
        == Some(ENCRYPTED_FORMAT)
}

pub fn encrypt_portable_text(plaintext: &str, password: &str) -> Result<String, String> {
    validate_export_password(password)?;
    let mut salt = [0u8; SALT_BYTES];
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::getrandom(&mut salt)
        .map_err(|error| format!("Could not generate encryption salt: {error}"))?;
    getrandom::getrandom(&mut nonce)
        .map_err(|error| format!("Could not generate encryption nonce: {error}"))?;
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| "Could not initialize AES-256-GCM".to_string())?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: AAD,
            },
        )
        .map_err(|_| "Could not encrypt export".to_string())?;
    let envelope = EncryptedEnvelope {
        format: ENCRYPTED_FORMAT.to_string(),
        format_version: ENCRYPTED_FORMAT_VERSION,
        kdf: KdfMetadata {
            algorithm: KDF_ALGORITHM.to_string(),
            version: KDF_VERSION,
            memory_kib: KDF_MEMORY_KIB,
            iterations: KDF_ITERATIONS,
            parallelism: KDF_PARALLELISM,
            salt: BASE64.encode(salt),
        },
        cipher: CipherMetadata {
            algorithm: CIPHER_ALGORITHM.to_string(),
            nonce: BASE64.encode(nonce),
        },
        ciphertext: BASE64.encode(ciphertext),
    };
    serde_json::to_string_pretty(&envelope).map_err(|error| error.to_string())
}

pub fn decrypt_portable_text(input: &str, password: &str) -> Result<String, String> {
    let envelope: EncryptedEnvelope = serde_json::from_str(input)
        .map_err(|error| format!("Invalid encrypted export envelope: {error}"))?;
    validate_envelope(&envelope)?;
    let salt = BASE64
        .decode(&envelope.kdf.salt)
        .map_err(|_| "Encrypted export contains an invalid salt".to_string())?;
    let nonce = BASE64
        .decode(&envelope.cipher.nonce)
        .map_err(|_| "Encrypted export contains an invalid nonce".to_string())?;
    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|_| "Encrypted export contains invalid ciphertext".to_string())?;
    if salt.len() != SALT_BYTES || nonce.len() != NONCE_BYTES || ciphertext.len() < AUTH_TAG_BYTES {
        return Err("Encrypted export has invalid cryptographic field lengths".to_string());
    }
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| "Could not initialize AES-256-GCM".to_string())?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: AAD,
            },
        )
        .map_err(|_| {
            "Could not decrypt export: the password is wrong or the file was changed".to_string()
        })?;
    String::from_utf8(plaintext).map_err(|_| "Decrypted export is not valid UTF-8 JSON".to_string())
}

fn validate_export_password(password: &str) -> Result<(), String> {
    let length = password.chars().count();
    if length < 6 {
        return Err("Encrypted export passwords must contain at least 6 characters".to_string());
    }
    if length > 1024 {
        return Err("Encrypted export password is too long".to_string());
    }
    Ok(())
}

fn validate_envelope(envelope: &EncryptedEnvelope) -> Result<(), String> {
    if envelope.format != ENCRYPTED_FORMAT || envelope.format_version != ENCRYPTED_FORMAT_VERSION {
        return Err("Unsupported encrypted export format".to_string());
    }
    if envelope.kdf.algorithm != KDF_ALGORITHM
        || envelope.kdf.version != KDF_VERSION
        || envelope.kdf.memory_kib != KDF_MEMORY_KIB
        || envelope.kdf.iterations != KDF_ITERATIONS
        || envelope.kdf.parallelism != KDF_PARALLELISM
        || envelope.cipher.algorithm != CIPHER_ALGORITHM
    {
        return Err("Unsupported or unsafe encrypted export parameters".to_string());
    }
    Ok(())
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_BYTES]>, String> {
    let params = Params::new(
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        Some(KEY_BYTES),
    )
    .map_err(|error| format!("Invalid Argon2 parameters: {error}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|error| format!("Could not derive encryption key: {error}"))?;
    Ok(key)
}

pub fn render_export_text(json: &str) -> Result<String, String> {
    let root: Value =
        serde_json::from_str(json).map_err(|error| format!("Invalid export JSON: {error}"))?;
    if root.get("format").and_then(Value::as_str) == Some("dfir-investigator-changes") {
        render_change_bundle(&root)
    } else if root.get("case_info").is_some() {
        render_case_snapshot(&root)
    } else if root.get("format").and_then(Value::as_str) == Some(ENCRYPTED_FORMAT) {
        Err("Decrypt the export before rendering it as text".to_string())
    } else {
        Err("Unsupported DFIR export format".to_string())
    }
}

fn render_case_snapshot(root: &Value) -> Result<String, String> {
    let object = root
        .as_object()
        .ok_or_else(|| "Case snapshot must be a JSON object".to_string())?;
    let mut output = String::new();
    heading(&mut output, "DFIR CASE SNAPSHOT");
    scalar_line(&mut output, "Format version", object.get("format_version"));
    scalar_line(&mut output, "Exported at", object.get("exported_at"));
    if let Some(case) = object.get("case_info") {
        render_single_object(&mut output, "CASE INFORMATION", case)?;
    }
    for (field, title) in [
        ("networks", "NETWORK ZONES"),
        ("assets", "ASSETS / COMPUTERS"),
        ("network_interfaces", "NETWORK INTERFACES"),
        ("clock_profiles", "SERVER CLOCK PROFILES"),
        ("network_connections", "NETWORK CONNECTIONS"),
        ("firewalls", "FIREWALLS"),
        ("firewall_interfaces", "FIREWALL INTERFACES"),
        ("firewall_nat_rules", "FIREWALL NAT / VIP / PORT MAPPINGS"),
        ("timeline_events", "TIMELINE EVENTS"),
        ("iocs", "INDICATORS OF COMPROMISE"),
        ("ioc_sightings", "IOC SIGHTINGS"),
        ("attack_edges", "ATTACK PATHWAY"),
        ("notes", "NOTES"),
    ] {
        render_collection(&mut output, title, object.get(field))?;
    }
    // Saved views are presentation state: list them by name only.
    let views = object
        .get("investigation_views")
        .and_then(Value::as_array)
        .map(|views| {
            views
                .iter()
                .map(|view| {
                    let mut reduced = Map::new();
                    for field in ["name", "description", "updated_at"] {
                        if let Some(value) = view.get(field) {
                            reduced.insert(field.to_string(), value.clone());
                        }
                    }
                    Value::Object(reduced)
                })
                .collect::<Vec<_>>()
        });
    render_collection(
        &mut output,
        "SAVED INVESTIGATION VIEWS",
        views.map(Value::Array).as_ref(),
    )?;
    Ok(output)
}

fn render_change_bundle(root: &Value) -> Result<String, String> {
    let object = root
        .as_object()
        .ok_or_else(|| "Change bundle must be a JSON object".to_string())?;
    let mut output = String::new();
    heading(&mut output, "DFIR EXPERT CHANGE BUNDLE");
    for field in [
        "format_version",
        "bundle_id",
        "case_id",
        "base_commit_id",
        "head_commit_id",
        "exported_by",
        "exported_at",
    ] {
        scalar_line(&mut output, &human_label(field), object.get(field));
    }
    render_collection(&mut output, "COMMITS AND CHANGES", object.get("commits"))?;
    Ok(output)
}

fn render_single_object(output: &mut String, title: &str, value: &Value) -> Result<(), String> {
    section(output, title);
    let object = value
        .as_object()
        .ok_or_else(|| format!("{title} must be an object"))?;
    render_fields(output, object, "");
    Ok(())
}

fn render_collection(
    output: &mut String,
    title: &str,
    value: Option<&Value>,
) -> Result<(), String> {
    section(output, title);
    let values = match value {
        Some(Value::Array(values)) => values,
        Some(Value::Null) | None => {
            output.push_str("None\n");
            return Ok(());
        }
        Some(_) => return Err(format!("{title} must be an array")),
    };
    if values.is_empty() {
        output.push_str("None\n");
        return Ok(());
    }
    for (index, value) in values.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| format!("{title} entry {} must be an object", index + 1))?;
        let label = preferred_label(object).unwrap_or_else(|| format!("Record {}", index + 1));
        let _ = writeln!(output, "[{}] {}", index + 1, label);
        render_fields(output, object, "  ");
        output.push('\n');
    }
    Ok(())
}

fn render_fields(output: &mut String, object: &Map<String, Value>, indent: &str) {
    for (key, value) in object {
        // Retained in legacy snapshots for compatibility, but session expert
        // attribution supersedes this obsolete case-level label.
        if key == "investigator" {
            continue;
        }
        let label = human_label(key);
        match value {
            Value::String(text) if text.contains('\n') => {
                let _ = writeln!(output, "{indent}{label}:");
                for line in text.lines() {
                    let _ = writeln!(output, "{indent}  {line}");
                }
            }
            Value::Array(values) if values.iter().all(Value::is_object) => {
                let _ = writeln!(output, "{indent}{label}: {}", values.len());
                for (index, nested) in values.iter().enumerate() {
                    let _ = writeln!(output, "{indent}  [{}]", index + 1);
                    if let Some(nested) = nested.as_object() {
                        render_fields(output, nested, &format!("{indent}    "));
                    }
                }
            }
            _ => {
                let rendered = printable_value(value);
                if rendered.contains('\n') {
                    let _ = writeln!(output, "{indent}{label}:");
                    for line in rendered.lines() {
                        let _ = writeln!(output, "{indent}  {line}");
                    }
                } else {
                    let _ = writeln!(output, "{indent}{label}: {rendered}");
                }
            }
        }
    }
}

fn preferred_label(object: &Map<String, Value>) -> Option<String> {
    ["name", "title", "value", "description", "id"]
        .iter()
        .find_map(|key| {
            object
                .get(*key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
}

fn printable_value(value: &Value) -> String {
    match value {
        Value::Null => "-".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(_) | Value::Object(_) => {
            serde_json::to_string_pretty(value).unwrap_or_else(|_| "<unprintable>".to_string())
        }
    }
}

fn human_label(value: &str) -> String {
    let mut words = value.split('_').filter(|word| !word.is_empty());
    let first = words.next().unwrap_or_default();
    let mut result = String::new();
    if let Some(character) = first.chars().next() {
        result.extend(character.to_uppercase());
        result.push_str(&first[character.len_utf8()..]);
    }
    for word in words {
        result.push(' ');
        result.push_str(word);
    }
    result
}

fn heading(output: &mut String, title: &str) {
    let _ = writeln!(output, "{title}");
    let _ = writeln!(output, "{}\n", "=".repeat(title.len()));
}

fn section(output: &mut String, title: &str) {
    let _ = writeln!(output, "\n{title}");
    let _ = writeln!(output, "{}", "-".repeat(title.len()));
}

fn scalar_line(output: &mut String, label: &str, value: Option<&Value>) {
    let rendered = value
        .map(printable_value)
        .unwrap_or_else(|| "-".to_string());
    let _ = writeln!(output, "{label}: {rendered}");
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "portable-secret";

    #[test]
    fn export_password_minimum_is_six_characters() {
        assert!(validate_export_password("123456").is_ok());
        assert!(validate_export_password("12345")
            .unwrap_err()
            .contains("at least 6"));
    }

    #[test]
    fn encrypted_round_trip_preserves_the_exact_json_payload() {
        let json =
            r#"{"format_version":2,"case_info":{"id":"case-1","name":"Example"},"networks":[]}"#;
        let encrypted = encrypt_portable_text(json, PASSWORD).unwrap();
        assert!(is_encrypted_portable(&encrypted));
        assert!(!encrypted.contains("Example"));
        let decoded = decode_portable_text(&encrypted, Some(PASSWORD)).unwrap();
        assert!(decoded.encrypted);
        assert_eq!(decoded.plaintext, json);
    }

    #[test]
    fn wrong_password_and_tampering_are_rejected() {
        let encrypted = encrypt_portable_text("{\"case_info\":{}}", PASSWORD).unwrap();
        assert!(decrypt_portable_text(&encrypted, "wrong-password").is_err());
        let mut envelope: Value = serde_json::from_str(&encrypted).unwrap();
        envelope["ciphertext"] = Value::String(BASE64.encode([7u8; 32]));
        assert!(
            decrypt_portable_text(&serde_json::to_string(&envelope).unwrap(), PASSWORD).is_err()
        );
    }

    #[test]
    fn plaintext_is_unchanged_and_rendering_is_readable() {
        let json = r#"{"format_version":2,"exported_at":"2026-01-01T00:00:00Z","case_info":{"id":"case-1","name":"Example","investigator":"Lead B"},"networks":[{"id":"net-1","name":"DMZ"}],"assets":[],"network_interfaces":[],"network_connections":[],"firewalls":[],"timeline_events":[],"iocs":[],"notes":[]}"#;
        assert_eq!(encode_portable_text(json, None).unwrap(), json);
        let report = render_export_text(json).unwrap();
        assert!(report.contains("DFIR CASE SNAPSHOT"));
        assert!(!report.contains("Investigator:"));
        assert!(report.contains("[1] DMZ"));
    }
}
