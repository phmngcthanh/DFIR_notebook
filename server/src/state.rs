//! Shared server state: open cases, sessions, and unlock throttling.
//!
//! Mirrors the desktop `DbState`, but keyed by case so one server instance can
//! host several case files at once. Everything lives in memory: no session
//! store, no user table, and no copy of any password.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rusqlite::Connection;
use serde::Serialize;

use crate::db::{validate_and_migrate_case, AppResult};
use crate::history::{ActorIdentity, ChangeBundle, MergePreview};
use crate::partial_import::PreparedPartialImport;
use crate::secure_db::{open_encrypted_connection, verify_cipher_integrity};

/// Failed unlocks tolerated from one address before it is locked out.
const MAX_UNLOCK_FAILURES: u32 = 5;
/// Window in which failures accumulate, and the lockout length once tripped.
const THROTTLE_WINDOW: Duration = Duration::from_secs(15 * 60);

/// Same envelope the desktop app returns from every `#[tauri::command]`, so the
/// frontend's `ApiResponse<T>` handling is unchanged.
#[derive(Serialize)]
pub struct Response<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> Response<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }

    pub fn from_result(result: AppResult<T>) -> Self {
        match result {
            Ok(value) => Self::ok(value),
            Err(error) => Self::err(error),
        }
    }
}

pub struct ServerConfig {
    pub cases_dir: PathBuf,
    pub allow_create: bool,
    pub session_timeout_secs: u64,
}

pub struct PendingBundle {
    pub bundle: ChangeBundle,
    pub preview: MergePreview,
}

/// One unlocked case file. Writes serialize on `conn`; `revision` is what
/// browsers poll to notice a teammate's edit.
pub struct OpenCase {
    pub id: String,
    pub path: PathBuf,
    pub conn: Mutex<Connection>,
    pub revision: AtomicU64,
    pub pending_bundles: Mutex<HashMap<String, PendingBundle>>,
    pub pending_partial_imports: Mutex<HashMap<String, PreparedPartialImport>>,
}

impl OpenCase {
    pub fn with_conn<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> AppResult<T>,
    ) -> AppResult<T> {
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| "Database lock poisoned".to_string())?;
        operation(&mut guard)
    }

    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }

    pub fn bump(&self) -> u64 {
        self.revision.fetch_add(1, Ordering::Relaxed) + 1
    }
}

#[derive(Clone)]
pub struct Session {
    pub case_id: String,
    pub actor: ActorIdentity,
    pub last_seen: SystemTime,
}

#[derive(Default)]
struct Failures {
    count: u32,
    first: Option<SystemTime>,
}

pub struct AppState {
    pub config: ServerConfig,
    cases: Mutex<HashMap<String, Arc<OpenCase>>>,
    sessions: Mutex<HashMap<String, Session>>,
    throttle: Mutex<HashMap<IpAddr, Failures>>,
}

impl AppState {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            cases: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            throttle: Mutex::new(HashMap::new()),
        }
    }

    // ---- case files -------------------------------------------------------

    /// Resolve a case id to a path inside the case directory.
    ///
    /// Ids come from the client, so only a conservative filename alphabet is
    /// accepted. That alone rules out traversal, but the resolved parent is
    /// checked as well.
    pub fn case_path(&self, id: &str) -> AppResult<PathBuf> {
        if id.is_empty() || id.len() > 128 {
            return Err("Invalid case identifier".to_string());
        }
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            || id.contains("..")
            || id.starts_with('.')
        {
            return Err("Invalid case identifier".to_string());
        }
        let path = self.config.cases_dir.join(format!("{id}.db"));
        if path.parent() != Some(self.config.cases_dir.as_path()) {
            return Err("Invalid case identifier".to_string());
        }
        Ok(path)
    }

    pub fn list_case_ids(&self) -> AppResult<Vec<String>> {
        let entries = std::fs::read_dir(&self.config.cases_dir)
            .map_err(|error| format!("Could not read the case directory: {error}"))?;
        let mut ids = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("db") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|value| value.to_str()) {
                if self.case_path(stem).is_ok() {
                    ids.push(stem.to_string());
                }
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// Unlock a case with a candidate password.
    ///
    /// The password check *is* the SQLCipher key check — nothing is stored to
    /// compare against. When the case is already open for other experts, a
    /// throwaway second connection verifies the candidate, exactly as the
    /// desktop `change_database_password` does before rekeying.
    pub fn unlock_case(&self, id: &str, password: &str) -> AppResult<Arc<OpenCase>> {
        let path = self.case_path(id)?;
        if !path.exists() {
            return Err("That case does not exist on this server".to_string());
        }

        if let Some(existing) = self.case(id) {
            open_encrypted_connection(&path, password)?;
            return Ok(existing);
        }

        let mut conn = open_encrypted_connection(&path, password)?;
        validate_and_migrate_case(&mut conn)?;
        verify_cipher_integrity(&conn)?;

        let mut guard = self
            .cases
            .lock()
            .map_err(|_| "Case registry lock poisoned".to_string())?;
        // Another request may have opened the same case while this one was
        // running the migration; keep the first connection that won.
        if let Some(existing) = guard.get(id) {
            return Ok(existing.clone());
        }
        let case = Arc::new(OpenCase {
            id: id.to_string(),
            path,
            conn: Mutex::new(conn),
            revision: AtomicU64::new(0),
            pending_bundles: Mutex::new(HashMap::new()),
            pending_partial_imports: Mutex::new(HashMap::new()),
        });
        guard.insert(id.to_string(), case.clone());
        Ok(case)
    }

    pub fn case(&self, id: &str) -> Option<Arc<OpenCase>> {
        self.cases.lock().ok()?.get(id).cloned()
    }

    /// Drop the connection once the last expert working on a case has gone,
    /// which is the server equivalent of "Lock / Close Case".
    fn close_case_if_idle(&self, id: &str) {
        let still_used = self
            .sessions
            .lock()
            .map(|guard| guard.values().any(|session| session.case_id == id))
            .unwrap_or(true);
        if still_used {
            return;
        }
        if let Ok(mut guard) = self.cases.lock() {
            guard.remove(id);
        }
    }

    // ---- sessions ---------------------------------------------------------

    pub fn create_session(&self, case_id: &str, actor: ActorIdentity) -> AppResult<String> {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|error| format!("Could not generate a session token: {error}"))?;
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let mut guard = self
            .sessions
            .lock()
            .map_err(|_| "Session lock poisoned".to_string())?;
        guard.insert(
            token.clone(),
            Session {
                case_id: case_id.to_string(),
                actor,
                last_seen: SystemTime::now(),
            },
        );
        Ok(token)
    }

    /// Look a session up and slide its idle timeout forward.
    pub fn touch_session(&self, token: &str) -> Option<Session> {
        self.sweep_sessions();
        let mut guard = self.sessions.lock().ok()?;
        let session = guard.get_mut(token)?;
        session.last_seen = SystemTime::now();
        Some(session.clone())
    }

    pub fn set_session_actor(&self, token: &str, actor: ActorIdentity) -> AppResult<()> {
        let mut guard = self
            .sessions
            .lock()
            .map_err(|_| "Session lock poisoned".to_string())?;
        let session = guard
            .get_mut(token)
            .ok_or_else(|| "This session has expired".to_string())?;
        session.actor = actor;
        Ok(())
    }

    pub fn end_session(&self, token: &str) {
        let case_id = match self.sessions.lock() {
            Ok(mut guard) => guard.remove(token).map(|session| session.case_id),
            Err(_) => None,
        };
        if let Some(case_id) = case_id {
            self.close_case_if_idle(&case_id);
        }
    }

    /// Used after a rekey: every other expert's token was issued against the
    /// old password and must stop working.
    pub fn end_other_sessions(&self, case_id: &str, keep: &str) {
        if let Ok(mut guard) = self.sessions.lock() {
            guard.retain(|token, session| session.case_id != case_id || token == keep);
        }
    }

    pub fn active_experts(&self, case_id: &str) -> Vec<String> {
        let mut names = match self.sessions.lock() {
            Ok(guard) => guard
                .values()
                .filter(|session| session.case_id == case_id)
                .map(|session| session.actor.name.clone())
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };
        names.sort();
        names.dedup();
        names
    }

    fn sweep_sessions(&self) {
        let timeout = Duration::from_secs(self.config.session_timeout_secs);
        let expired: Vec<String> = match self.sessions.lock() {
            Ok(mut guard) => {
                let now = SystemTime::now();
                let stale: Vec<String> = guard
                    .iter()
                    .filter(|(_, session)| {
                        now.duration_since(session.last_seen)
                            .map(|idle| idle > timeout)
                            .unwrap_or(false)
                    })
                    .map(|(token, _)| token.clone())
                    .collect();
                let mut cases = Vec::new();
                for token in &stale {
                    if let Some(session) = guard.remove(token) {
                        cases.push(session.case_id);
                    }
                }
                cases
            }
            Err(_) => Vec::new(),
        };
        for case_id in expired {
            self.close_case_if_idle(&case_id);
        }
    }

    // ---- unlock throttling ------------------------------------------------

    /// The case password is a six-character-minimum *presence* control offline.
    /// On a network it is reachable by anyone who can see the port, so repeated
    /// guesses from one address are cut off.
    pub fn check_throttle(&self, ip: IpAddr) -> AppResult<()> {
        let mut guard = self
            .throttle
            .lock()
            .map_err(|_| "Throttle lock poisoned".to_string())?;
        let entry = guard.entry(ip).or_default();
        if let Some(first) = entry.first {
            if SystemTime::now()
                .duration_since(first)
                .map(|elapsed| elapsed > THROTTLE_WINDOW)
                .unwrap_or(false)
            {
                *entry = Failures::default();
            }
        }
        if entry.count >= MAX_UNLOCK_FAILURES {
            return Err(
                "Too many failed unlock attempts from this address. Try again later".to_string(),
            );
        }
        Ok(())
    }

    pub fn record_unlock_failure(&self, ip: IpAddr) {
        if let Ok(mut guard) = self.throttle.lock() {
            let entry = guard.entry(ip).or_default();
            entry.count += 1;
            entry.first.get_or_insert_with(SystemTime::now);
        }
    }

    pub fn record_unlock_success(&self, ip: IpAddr) {
        if let Ok(mut guard) = self.throttle.lock() {
            guard.remove(&ip);
        }
    }
}

/// `.db` stem used for a newly created case, derived from the case name the
/// same way the desktop app derives its default filename.
pub fn case_id_from_name(name: &str, cases_dir: &Path) -> String {
    let base: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect();
    let base = base.trim_matches('-').to_lowercase();
    let base = if base.is_empty() {
        "case".to_string()
    } else {
        base.chars().take(64).collect()
    };
    if !cases_dir.join(format!("{base}.db")).exists() {
        return base;
    }
    for suffix in 2..1000 {
        let candidate = format!("{base}-{suffix}");
        if !cases_dir.join(format!("{candidate}.db")).exists() {
            return candidate;
        }
    }
    format!("{base}-{}", uuid::Uuid::new_v4())
}
