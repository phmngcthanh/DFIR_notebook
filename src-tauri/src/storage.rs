use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tauri::Manager;

use crate::db::AppResult;

/// App-private storage layout used on Android (where native save dialogs do
/// not exist) and available on desktop for the same commands:
/// `<app_data_dir>/cases`   — active case databases
/// `<app_data_dir>/exports` — files written by export commands
/// `<app_data_dir>/inbox`   — files dropped in externally (e.g. `adb push`)
///   that import commands read from
fn private_dir(app_handle: &tauri::AppHandle, name: &str) -> AppResult<PathBuf> {
    let base = app_handle
        .path()
        .app_data_dir()
        .map_err(|error| format!("App data directory is unavailable: {error}"))?;
    let dir = base.join(name);
    fs::create_dir_all(&dir)
        .map_err(|error| format!("Could not create the {name} directory: {error}"))?;
    Ok(dir)
}

pub fn cases_dir(app_handle: &tauri::AppHandle) -> AppResult<PathBuf> {
    private_dir(app_handle, "cases")
}

pub fn exports_dir(app_handle: &tauri::AppHandle) -> AppResult<PathBuf> {
    private_dir(app_handle, "exports")
}

pub fn inbox_dir(app_handle: &tauri::AppHandle) -> AppResult<PathBuf> {
    private_dir(app_handle, "inbox")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCaseFile {
    pub file_name: String,
    pub size_bytes: u64,
    pub modified_at: Option<String>,
}

pub fn list_case_files(app_handle: &tauri::AppHandle) -> AppResult<Vec<LocalCaseFile>> {
    let dir = cases_dir(app_handle)?;
    let entries = fs::read_dir(&dir)
        .map_err(|error| format!("Could not read the cases directory: {error}"))?;
    let mut cases = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("db") {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        cases.push(LocalCaseFile {
            file_name: file_name.to_string(),
            size_bytes: metadata.len(),
            modified_at: metadata
                .modified()
                .ok()
                .map(|time| DateTime::<Utc>::from(time).to_rfc3339()),
        });
    }
    cases.sort_by(|a, b| b.modified_at.cmp(&a.modified_at));
    Ok(cases)
}

/// Resolve `file_name` inside `dir`, rejecting anything that could escape it.
pub fn safe_child_path(dir: &Path, file_name: &str) -> AppResult<PathBuf> {
    if file_name.is_empty()
        || file_name.contains('/')
        || file_name.contains('\\')
        || file_name.contains("..")
        || file_name.starts_with('.')
    {
        return Err("Invalid case file name".to_string());
    }
    Ok(dir.join(file_name))
}

/// `stem.ext`, or `stem-2.ext`, `stem-3.ext`, … if already taken.
pub fn unique_path(dir: &Path, stem: &str, extension: &str) -> PathBuf {
    let first = dir.join(format!("{stem}.{extension}"));
    if !first.exists() {
        return first;
    }
    let mut counter = 2u32;
    loop {
        let candidate = dir.join(format!("{stem}-{counter}.{extension}"));
        if !candidate.exists() {
            return candidate;
        }
        counter += 1;
    }
}

/// Newest regular file in `dir` whose extension matches one of `extensions`.
pub fn newest_file_with_extensions(
    dir: &Path,
    extensions: &[&str],
) -> AppResult<Option<PathBuf>> {
    let entries = fs::read_dir(dir)
        .map_err(|error| format!("Could not read the import inbox: {error}"))?;
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        let matches = path
            .extension()
            .and_then(|value| value.to_str())
            .map(|ext| extensions.iter().any(|candidate| candidate.eq_ignore_ascii_case(ext)))
            .unwrap_or(false);
        if !matches {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let modified = metadata
            .modified()
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        if newest
            .as_ref()
            .map(|(time, _)| modified > *time)
            .unwrap_or(true)
        {
            newest = Some((modified, path));
        }
    }
    Ok(newest.map(|(_, path)| path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dfir-storage-test-{tag}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn safe_child_path_rejects_traversal() {
        let dir = PathBuf::from("base");
        assert!(safe_child_path(&dir, "case.db").is_ok());
        assert!(safe_child_path(&dir, "../case.db").is_err());
        assert!(safe_child_path(&dir, "a/b.db").is_err());
        assert!(safe_child_path(&dir, "a\\b.db").is_err());
        assert!(safe_child_path(&dir, ".hidden").is_err());
        assert!(safe_child_path(&dir, "").is_err());
    }

    #[test]
    fn unique_path_appends_counter() {
        let dir = temp_dir("unique");
        let first = unique_path(&dir, "case", "db");
        assert_eq!(first.file_name().unwrap().to_str().unwrap(), "case.db");
        fs::write(&first, b"x").unwrap();
        let second = unique_path(&dir, "case", "db");
        assert_eq!(second.file_name().unwrap().to_str().unwrap(), "case-2.db");
        fs::write(&second, b"x").unwrap();
        let third = unique_path(&dir, "case", "db");
        assert_eq!(third.file_name().unwrap().to_str().unwrap(), "case-3.db");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn newest_file_prefers_recent_and_filters_extension() {
        let dir = temp_dir("newest");
        fs::write(dir.join("old.json"), b"old").unwrap();
        fs::write(dir.join("ignored.txt"), b"nope").unwrap();
        // Ensure a strictly newer mtime for the second file.
        std::thread::sleep(std::time::Duration::from_millis(30));
        fs::write(dir.join("new.dfirx"), b"new").unwrap();
        let newest = newest_file_with_extensions(&dir, &["json", "dfirx"])
            .unwrap()
            .expect("a file should match");
        assert_eq!(newest.file_name().unwrap().to_str().unwrap(), "new.dfirx");
        let none = newest_file_with_extensions(&dir, &["zip"]).unwrap();
        assert!(none.is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
