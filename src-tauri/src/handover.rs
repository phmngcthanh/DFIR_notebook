//! Offline handover files: full case backups and the SHA-256 manifests that
//! travel with them.
//!
//! A full backup is a byte copy of the encrypted case file, plus its
//! event-log store when one exists, taken while the caller holds both
//! connections so no write can land mid-copy. The copy keeps the case
//! password, case id, history, and shared baseline, which makes it both the
//! backup and what a lead hands back to every expert after the daily merge.
//!
//! Every set gets a `<file>.sha256` manifest in `sha256sum` format, so it can
//! also be checked with `sha256sum -c` or `Get-FileHash` before it is opened.
//! Restore refuses a set that no longer matches its manifest.
//!
//! Desktop only (the server operator copies case files directly), but kept
//! free of `tauri` so it can be tested like the shared core.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::db::{get_case, AppResult};
use crate::event_logs::sidecar_path;
use crate::secure_db::{open_encrypted_connection, verify_cipher_integrity};

/// `<primary file name>.sha256`, next to the primary file.
pub fn manifest_path(primary: &Path) -> PathBuf {
    let mut name = primary
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_default();
    name.push(".sha256");
    primary.with_file_name(name)
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string_lossy().to_string())
}

pub fn sha256_file(path: &Path) -> AppResult<String> {
    let mut file = File::open(path)
        .map_err(|error| format!("Could not read {}: {error}", display_name(path)))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("Could not read {}: {error}", display_name(path)))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Write `<primary>.sha256` listing every file of the set by name. All files
/// sit in one folder, which is what `sha256sum -c` expects.
pub fn write_manifest(primary: &Path, files: &[PathBuf]) -> AppResult<PathBuf> {
    let mut text = String::new();
    for file in files {
        text.push_str(&format!("{}  {}\n", sha256_file(file)?, display_name(file)));
    }
    let path = manifest_path(primary);
    fs::write(&path, text)
        .map_err(|error| format!("Could not write {}: {error}", display_name(&path)))?;
    Ok(path)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ManifestCheck {
    /// "verified" when every listed file matched, "absent" when the set came
    /// without a manifest (and could not be checked).
    pub status: String,
    pub files: Vec<String>,
}

/// Check every file listed in `<primary>.sha256`. A missing manifest is
/// reported rather than refused; a listed file that is missing or differs is
/// an error.
pub fn verify_manifest(primary: &Path) -> AppResult<ManifestCheck> {
    let path = manifest_path(primary);
    if !path.exists() {
        return Ok(ManifestCheck {
            status: "absent".to_string(),
            files: Vec::new(),
        });
    }
    let manifest_name = display_name(&path);
    let text = fs::read_to_string(&path)
        .map_err(|error| format!("Could not read {manifest_name}: {error}"))?;
    let folder = primary.parent().unwrap_or_else(|| Path::new("."));
    let mut files = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (digest, name) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| format!("{manifest_name} has a malformed line"))?;
        // `sha256sum` marks binary mode with a leading '*'.
        let name = name.trim_start().trim_start_matches('*');
        if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
            return Err(format!(
                "{manifest_name} may only list files in its own folder"
            ));
        }
        let file = folder.join(name);
        if !file.is_file() {
            return Err(format!(
                "{name} is listed in {manifest_name} but is missing; copy the complete set"
            ));
        }
        if !sha256_file(&file)?.eq_ignore_ascii_case(digest) {
            return Err(format!(
                "{name} does not match its SHA-256 in {manifest_name}; the copy is incomplete or was altered"
            ));
        }
        files.push(name.to_string());
    }
    if files.is_empty() {
        return Err(format!("{manifest_name} lists no files"));
    }
    Ok(ManifestCheck {
        status: "verified".to_string(),
        files,
    })
}

/// Copy through ordinary file handles. `std::fs::copy` uses CopyFileEx on
/// Windows, which can refuse a file SQLite holds open for writing; Rust's own
/// `File::open` shares read and write access, so the open case copies fine.
fn copy_file(source: &Path, target: &Path) -> AppResult<u64> {
    let mut input = File::open(source)
        .map_err(|error| format!("Could not read {}: {error}", display_name(source)))?;
    let mut output = File::create(target)
        .map_err(|error| format!("Could not write {}: {error}", display_name(target)))?;
    let bytes = io::copy(&mut input, &mut output)
        .map_err(|error| format!("Could not copy {}: {error}", display_name(source)))?;
    output
        .flush()
        .and_then(|_| output.sync_all())
        .map_err(|error| format!("Could not finish writing {}: {error}", display_name(target)))?;
    Ok(bytes)
}

fn same_file(left: &Path, right: &Path) -> bool {
    matches!((fs::canonicalize(left), fs::canonicalize(right)), (Ok(a), Ok(b)) if a == b)
}

/// Open a copy read-only in practice (no writes are issued), prove the
/// password works, and run SQLCipher's page check on it and its store.
fn verify_set(path: &Path, password: &str, with_event_logs: bool) -> AppResult<String> {
    let conn = open_encrypted_connection(path, password)
        .map_err(|error| format!("{} could not be opened: {error}", display_name(path)))?;
    verify_cipher_integrity(&conn)?;
    let case = get_case(&conn)?
        .ok_or_else(|| format!("{} contains no case record", display_name(path)))?;
    if with_event_logs {
        let store_path = sidecar_path(path);
        let store = open_encrypted_connection(&store_path, password).map_err(|error| {
            format!("{} could not be opened: {error}", display_name(&store_path))
        })?;
        verify_cipher_integrity(&store)?;
    }
    Ok(case.name)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSummary {
    pub path: String,
    pub event_log_path: Option<String>,
    pub manifest_path: String,
    pub bytes: u64,
    pub event_log_bytes: Option<u64>,
    pub case_name: String,
}

/// Copy the open case (and its event-log store) to `target`, prove the copy
/// opens with `password` and passes the page check, then write the manifest.
/// The caller holds the case and store connections while this runs.
pub fn write_backup(case_path: &Path, target: &Path, password: &str) -> AppResult<BackupSummary> {
    let source_store = sidecar_path(case_path);
    let target_store = sidecar_path(target);
    if same_file(case_path, target) || same_file(&source_store, &target_store) {
        return Err("Choose another location: a backup cannot replace the open case".to_string());
    }
    let with_event_logs = source_store.is_file();
    if !with_event_logs && target_store.exists() {
        return Err(format!(
            "{} already exists next to the chosen name and belongs to another case; choose another name",
            display_name(&target_store)
        ));
    }
    let bytes = copy_file(case_path, target)?;
    let mut files = vec![target.to_path_buf()];
    let event_log_bytes = if with_event_logs {
        let copied = copy_file(&source_store, &target_store)?;
        files.push(target_store.clone());
        Some(copied)
    } else {
        None
    };
    let case_name = verify_set(target, password, with_event_logs)?;
    let manifest = write_manifest(target, &files)?;
    Ok(BackupSummary {
        path: target.to_string_lossy().to_string(),
        event_log_path: with_event_logs.then(|| target_store.to_string_lossy().to_string()),
        manifest_path: manifest.to_string_lossy().to_string(),
        bytes,
        event_log_bytes,
        case_name,
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreSummary {
    pub path: String,
    pub case_name: String,
    pub manifest: ManifestCheck,
    pub restored_event_logs: bool,
}

/// Check a backup set against its manifest and password, then copy it to
/// `target` as a new working case. Never overwrites an existing file, and
/// leaves the backup itself untouched.
pub fn restore_backup(source: &Path, target: &Path, password: &str) -> AppResult<RestoreSummary> {
    let manifest = verify_manifest(source)?;
    let source_store = sidecar_path(source);
    let with_event_logs = source_store.is_file();
    let case_name = verify_set(source, password, with_event_logs)?;
    let target_store = sidecar_path(target);
    if target.exists() || (with_event_logs && target_store.exists()) {
        return Err(
            "Restore never overwrites an existing case; choose a new file name".to_string(),
        );
    }
    copy_file(source, target)?;
    if with_event_logs {
        if let Err(error) = copy_file(&source_store, &target_store) {
            let _ = fs::remove_file(target);
            return Err(error);
        }
    }
    Ok(RestoreSummary {
        path: target.to_string_lossy().to_string(),
        case_name,
        manifest,
        restored_event_logs: with_event_logs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{create_case_record, init_database};
    use crate::secure_db::create_encrypted_connection;

    const PASSWORD: &str = "handover-test-pass";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("dfir-handover-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }
        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn make_case(path: &Path, with_store: bool) {
        let conn = create_encrypted_connection(path, PASSWORD).expect("case");
        init_database(&conn).expect("schema");
        create_case_record(&conn, "Handover case", "", "Client", "Alice").expect("record");
        drop(conn);
        if with_store {
            crate::event_logs::open_store(path, PASSWORD).expect("store");
        }
    }

    #[test]
    fn sha256_matches_the_standard_test_vector() {
        let dir = TempDir::new();
        let file = dir.join("abc.txt");
        fs::write(&file, "abc").unwrap();
        assert_eq!(
            sha256_file(&file).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn backup_copies_the_case_and_its_store_and_restore_checks_the_manifest() {
        let dir = TempDir::new();
        let case = dir.join("case.db");
        make_case(&case, true);

        let backup = dir.join("case-backup.db");
        let summary = write_backup(&case, &backup, PASSWORD).unwrap();
        assert_eq!(summary.case_name, "Handover case");
        assert!(summary.event_log_path.is_some());
        let manifest = fs::read_to_string(manifest_path(&backup)).unwrap();
        assert!(manifest.contains("  case-backup.db\n"));
        assert!(manifest.contains("  case-backup.dfirlogs\n"));

        let restored = dir.join("restored.db");
        let result = restore_backup(&backup, &restored, PASSWORD).unwrap();
        assert_eq!(result.manifest.status, "verified");
        assert_eq!(result.manifest.files.len(), 2);
        assert!(result.restored_event_logs);
        assert!(sidecar_path(&restored).is_file());
        // Never overwrite an existing case.
        assert!(restore_backup(&backup, &restored, PASSWORD)
            .unwrap_err()
            .contains("never overwrites"));
    }

    #[test]
    fn restore_refuses_an_altered_set_and_a_wrong_password() {
        let dir = TempDir::new();
        let case = dir.join("case.db");
        make_case(&case, false);
        let backup = dir.join("backup.db");
        write_backup(&case, &backup, PASSWORD).unwrap();

        assert!(restore_backup(&backup, &dir.join("a.db"), "wrong-password")
            .unwrap_err()
            .contains("could not be opened"));

        let mut bytes = fs::read(&backup).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&backup, bytes).unwrap();
        let error = restore_backup(&backup, &dir.join("b.db"), PASSWORD).unwrap_err();
        assert!(error.contains("does not match its SHA-256"), "{error}");
        assert!(!dir.join("b.db").exists());
    }

    #[test]
    fn a_set_without_a_manifest_restores_but_reports_it_unchecked() {
        let dir = TempDir::new();
        let case = dir.join("case.db");
        make_case(&case, false);
        let backup = dir.join("backup.db");
        write_backup(&case, &backup, PASSWORD).unwrap();
        fs::remove_file(manifest_path(&backup)).unwrap();
        let result = restore_backup(&backup, &dir.join("restored.db"), PASSWORD).unwrap();
        assert_eq!(result.manifest.status, "absent");
    }

    #[test]
    fn backup_refuses_to_replace_the_open_case_or_pair_with_a_foreign_store() {
        let dir = TempDir::new();
        let case = dir.join("case.db");
        make_case(&case, false);
        assert!(write_backup(&case, &case, PASSWORD)
            .unwrap_err()
            .contains("cannot replace the open case"));
        fs::write(dir.join("other.dfirlogs"), "not ours").unwrap();
        assert!(write_backup(&case, &dir.join("other.db"), PASSWORD)
            .unwrap_err()
            .contains("belongs to another case"));
    }

    #[test]
    fn manifests_only_name_files_in_their_own_folder() {
        let dir = TempDir::new();
        let file = dir.join("bundle.json");
        fs::write(&file, "{}").unwrap();
        fs::write(
            manifest_path(&file),
            format!("{}  ../secret.db\n", "0".repeat(64)),
        )
        .unwrap();
        assert!(verify_manifest(&file)
            .unwrap_err()
            .contains("only list files in its own folder"));
        write_manifest(&file, &[file.clone()]).unwrap();
        assert_eq!(verify_manifest(&file).unwrap().status, "verified");
    }
}
