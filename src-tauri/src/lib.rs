mod db;
mod history;
mod partial_import;
mod portable_export;
mod secure_db;

use db::*;
use history::*;
use partial_import::*;
use portable_export::*;
use rusqlite::Connection;
use secure_db::*;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{Manager, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

struct PendingBundle {
    bundle: ChangeBundle,
    preview: MergePreview,
}

pub struct DbState {
    conn: Mutex<Option<Connection>>,
    db_path: Mutex<Option<PathBuf>>,
    actor: Mutex<Option<ActorIdentity>>,
    pending_bundles: Mutex<HashMap<String, PendingBundle>>,
    pending_partial_imports: Mutex<HashMap<String, PreparedPartialImport>>,
}

impl DbState {
    fn new() -> Self {
        Self {
            conn: Mutex::new(None),
            db_path: Mutex::new(None),
            actor: Mutex::new(None),
            pending_bundles: Mutex::new(HashMap::new()),
            pending_partial_imports: Mutex::new(HashMap::new()),
        }
    }
}

#[derive(Serialize)]
struct Response<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> Response<T> {
    fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

fn with_conn<T>(
    state: &State<DbState>,
    operation: impl FnOnce(&mut Connection) -> AppResult<T>,
) -> Response<T> {
    let mut guard = match state.conn.lock() {
        Ok(guard) => guard,
        Err(_) => return Response::err("Database lock poisoned"),
    };
    match guard.as_mut() {
        Some(conn) => match operation(conn) {
            Ok(value) => Response::ok(value),
            Err(error) => Response::err(error),
        },
        None => Response::err("No case is open"),
    }
}

fn current_actor(state: &State<DbState>) -> AppResult<ActorIdentity> {
    state
        .actor
        .lock()
        .map_err(|_| "Expert identity lock poisoned".to_string())?
        .clone()
        .ok_or_else(|| "Enter your expert name before changing the case".to_string())
}

fn with_actor_conn<T>(
    state: &State<DbState>,
    operation: impl FnOnce(&mut Connection, &ActorIdentity) -> AppResult<T>,
) -> Response<T> {
    let actor = match current_actor(state) {
        Ok(actor) => actor,
        Err(error) => return Response::err(error),
    };
    with_conn(state, |conn| operation(conn, &actor))
}

fn selected_path(file_path: tauri_plugin_dialog::FilePath) -> AppResult<PathBuf> {
    file_path
        .as_path()
        .map(PathBuf::from)
        .ok_or_else(|| "Selected location is not a local filesystem path".to_string())
}

fn ensure_extension(mut path: PathBuf, extension: &str) -> PathBuf {
    if path.extension().is_none() {
        path.set_extension(extension);
    }
    path
}

#[tauri::command]
fn set_current_expert(
    state: State<DbState>,
    name: String,
    scope_label: Option<String>,
    scope_network_ids: Vec<String>,
) -> Response<ActorIdentity> {
    match ActorIdentity::new(name, scope_label, scope_network_ids) {
        Ok(actor) => match state.actor.lock() {
            Ok(mut guard) => {
                *guard = Some(actor.clone());
                Response::ok(actor)
            }
            Err(_) => Response::err("Expert identity lock poisoned"),
        },
        Err(error) => Response::err(error),
    }
}

#[tauri::command]
fn get_current_expert(state: State<DbState>) -> Response<Option<ActorIdentity>> {
    match state.actor.lock() {
        Ok(guard) => Response::ok(guard.clone()),
        Err(_) => Response::err("Expert identity lock poisoned"),
    }
}

#[tauri::command]
fn create_new_case(
    app_handle: tauri::AppHandle,
    state: State<DbState>,
    name: String,
    description: String,
    client_name: String,
    expert_name: String,
    database_password: String,
) -> Response<String> {
    let database_password = Zeroizing::new(database_password);
    let actor = match ActorIdentity::new(expert_name.clone(), None, Vec::new()) {
        Ok(actor) => actor,
        Err(error) => return Response::err(error),
    };
    let selection = app_handle
        .dialog()
        .file()
        .set_file_name(format!("{}.db", sanitize_filename(&name)))
        .add_filter("DFIR Case", &["db"])
        .blocking_save_file();
    let path = match selection
        .and_then(|value| selected_path(value).ok())
        .map(|path| ensure_extension(path, "db"))
    {
        Some(path) => path,
        None => return Response::err("Case creation cancelled"),
    };
    if path.exists() {
        return Response::err("Refusing to overwrite an existing case file");
    }
    let mut conn = match create_encrypted_connection(&path, database_password.as_str()) {
        Ok(conn) => conn,
        Err(error) => return Response::err(format!("Failed to create case: {error}")),
    };
    if let Err(error) = init_database(&conn)
        .and_then(|_| {
            create_case_record(&conn, &name, &description, &client_name, &expert_name).map(|_| ())
        })
        .and_then(|_| validate_and_migrate_case(&mut conn))
        .and_then(|_| verify_cipher_integrity(&conn))
    {
        drop(conn);
        let _ = fs::remove_file(&path);
        return Response::err(error);
    }
    let case_id = match get_case(&conn) {
        Ok(Some(case)) => case.id,
        Ok(None) => return Response::err("Created case has no metadata"),
        Err(error) => return Response::err(error),
    };
    if let Ok(mut guard) = state.conn.lock() {
        *guard = Some(conn);
    } else {
        return Response::err("Database lock poisoned");
    }
    if let Ok(mut guard) = state.db_path.lock() {
        *guard = Some(path);
    } else {
        return Response::err("Database path lock poisoned");
    }
    if let Ok(mut guard) = state.actor.lock() {
        *guard = Some(actor);
    } else {
        return Response::err("Expert identity lock poisoned");
    }
    Response::ok(case_id)
}

#[tauri::command]
async fn open_existing_case(
    app_handle: tauri::AppHandle,
    database_password: String,
) -> Response<String> {
    let database_password = Zeroizing::new(database_password);
    let (sender, mut receiver) = tauri::async_runtime::channel(1);
    app_handle
        .dialog()
        .file()
        .add_filter("DFIR Case", &["db"])
        .pick_file(move |selection| {
            let _ = sender.try_send(selection);
        });
    let selection = receiver.recv().await.flatten();
    let path = match selection.and_then(|value| selected_path(value).ok()) {
        Some(path) => path,
        None => return Response::err("Open cancelled"),
    };
    let state = app_handle.state::<DbState>();
    let mut conn = match open_encrypted_connection(&path, database_password.as_str()) {
        Ok(conn) => conn,
        Err(error) => return Response::err(format!("Failed to open case: {error}")),
    };
    if let Err(error) =
        validate_and_migrate_case(&mut conn).and_then(|_| verify_cipher_integrity(&conn))
    {
        return Response::err(error);
    }
    if let Ok(mut guard) = state.conn.lock() {
        *guard = Some(conn);
    } else {
        return Response::err("Database lock poisoned");
    }
    if let Ok(mut guard) = state.db_path.lock() {
        *guard = Some(path);
    } else {
        return Response::err("Database path lock poisoned");
    }
    if let Ok(mut guard) = state.actor.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = state.pending_bundles.lock() {
        guard.clear();
    }
    if let Ok(mut guard) = state.pending_partial_imports.lock() {
        guard.clear();
    }
    Response::ok("Case opened".to_string())
}

#[tauri::command]
fn migrate_legacy_case(
    app_handle: tauri::AppHandle,
    state: State<DbState>,
    database_password: String,
) -> Response<String> {
    let database_password = Zeroizing::new(database_password);
    if let Err(error) = validate_database_password(database_password.as_str()) {
        return Response::err(error);
    }
    let source_selection = app_handle
        .dialog()
        .file()
        .add_filter("Legacy DFIR Case", &["db"])
        .blocking_pick_file();
    let source_path = match source_selection.and_then(|value| selected_path(value).ok()) {
        Some(path) => path,
        None => return Response::err("Legacy case selection cancelled"),
    };
    let default_name = source_path
        .file_stem()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}-encrypted.db"))
        .unwrap_or_else(|| "dfir-case-encrypted.db".to_string());
    let target_selection = app_handle
        .dialog()
        .file()
        .set_file_name(default_name)
        .add_filter("Encrypted DFIR Case", &["db"])
        .blocking_save_file();
    let target_path = match target_selection
        .and_then(|value| selected_path(value).ok())
        .map(|path| ensure_extension(path, "db"))
    {
        Some(path) => path,
        None => return Response::err("Encrypted copy location was not selected"),
    };

    if let Err(error) =
        migrate_plaintext_database(&source_path, &target_path, database_password.as_str())
    {
        return Response::err(error);
    }
    let mut conn = match open_encrypted_connection(&target_path, database_password.as_str()) {
        Ok(conn) => conn,
        Err(error) => {
            let _ = fs::remove_file(&target_path);
            return Response::err(format!("Encrypted copy could not be verified: {error}"));
        }
    };
    if let Err(error) =
        validate_and_migrate_case(&mut conn).and_then(|_| verify_cipher_integrity(&conn))
    {
        drop(conn);
        let _ = fs::remove_file(&target_path);
        return Response::err(format!("Encrypted copy could not be verified: {error}"));
    }
    if let Ok(mut guard) = state.conn.lock() {
        *guard = Some(conn);
    } else {
        return Response::err("Database lock poisoned");
    }
    if let Ok(mut guard) = state.db_path.lock() {
        *guard = Some(target_path.clone());
    } else {
        return Response::err("Database path lock poisoned");
    }
    if let Ok(mut guard) = state.actor.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = state.pending_bundles.lock() {
        guard.clear();
    }
    if let Ok(mut guard) = state.pending_partial_imports.lock() {
        guard.clear();
    }
    Response::ok(target_path.to_string_lossy().to_string())
}

#[tauri::command]
fn change_database_password(
    state: State<DbState>,
    current_password: String,
    new_password: String,
) -> Response<bool> {
    let current_password = Zeroizing::new(current_password);
    let new_password = Zeroizing::new(new_password);
    if let Err(error) = validate_database_password(new_password.as_str()) {
        return Response::err(error);
    }
    let path = match state.db_path.lock() {
        Ok(guard) => match guard.clone() {
            Some(path) => path,
            None => return Response::err("No case is open"),
        },
        Err(_) => return Response::err("Database path lock poisoned"),
    };
    if let Err(error) = open_encrypted_connection(&path, current_password.as_str()) {
        return Response::err(error);
    }
    let changed = with_conn(&state, |conn| {
        rekey_connection(conn, new_password.as_str())?;
        verify_cipher_integrity(conn)
    });
    if let Some(error) = changed.error {
        return Response::err(error);
    }
    match open_encrypted_connection(&path, new_password.as_str()) {
        Ok(conn) => match verify_cipher_integrity(&conn) {
            Ok(()) => Response::ok(true),
            Err(error) => Response::err(error),
        },
        Err(error) => Response::err(format!("Password changed but verification failed: {error}")),
    }
}

#[tauri::command]
fn close_current_case(state: State<DbState>) -> Response<bool> {
    if let Ok(mut guard) = state.conn.lock() {
        *guard = None;
    } else {
        return Response::err("Database lock poisoned");
    }
    if let Ok(mut guard) = state.db_path.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = state.actor.lock() {
        *guard = None;
    }
    if let Ok(mut guard) = state.pending_bundles.lock() {
        guard.clear();
    }
    if let Ok(mut guard) = state.pending_partial_imports.lock() {
        guard.clear();
    }
    Response::ok(true)
}

#[tauri::command]
fn get_current_case_info(state: State<DbState>) -> Response<Option<Case>> {
    with_conn(&state, |conn| get_case(conn))
}

#[tauri::command]
fn update_current_case(
    state: State<DbState>,
    name: String,
    description: String,
    client_name: String,
    status: String,
) -> Response<Case> {
    with_actor_conn(&state, |conn, actor| {
        update_case(conn, actor, &name, &description, &client_name, &status)
    })
}

#[tauri::command]
fn create_new_network(
    state: State<DbState>,
    name: String,
    subnet: String,
    network_type: String,
    description: String,
    vlan_id: Option<String>,
) -> Response<Network> {
    with_actor_conn(&state, |conn, actor| {
        create_network(
            conn,
            actor,
            &name,
            &subnet,
            &network_type,
            &description,
            vlan_id.as_deref(),
        )
    })
}
#[tauri::command]
fn update_existing_network(
    state: State<DbState>,
    id: String,
    name: String,
    subnet: String,
    network_type: String,
    description: String,
    vlan_id: Option<String>,
) -> Response<Network> {
    with_actor_conn(&state, |conn, actor| {
        update_network(
            conn,
            actor,
            &id,
            &name,
            &subnet,
            &network_type,
            &description,
            vlan_id.as_deref(),
        )
    })
}
#[tauri::command]
fn list_networks(state: State<DbState>) -> Response<Vec<Network>> {
    with_conn(&state, |conn| get_networks(conn))
}
#[tauri::command]
fn get_topology_view(state: State<DbState>, layout: String) -> Response<Option<TopologyViewState>> {
    with_conn(&state, |conn| db::get_topology_view(conn, &layout))
}
#[tauri::command]
fn save_topology_view(
    state: State<DbState>,
    layout: String,
    positions: Vec<TopologyNodePosition>,
    zoom: f64,
    pan_x: f64,
    pan_y: f64,
) -> Response<TopologyViewState> {
    with_conn(&state, |conn| {
        db::save_topology_view(conn, &layout, positions, zoom, pan_x, pan_y)
    })
}
#[tauri::command]
fn remove_network(state: State<DbState>, id: String) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        delete_network(conn, actor, &id).map(|_| true)
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_new_asset(
    state: State<DbState>,
    network_id: Option<String>,
    name: String,
    ip_address: String,
    mac_address: Option<String>,
    asset_type: String,
    os: Option<String>,
    user_name: Option<String>,
    compromise_status: String,
    investigation_status: String,
    properties: Option<String>,
    scan_results: Option<String>,
) -> Response<Asset> {
    with_actor_conn(&state, |conn, actor| {
        create_asset(
            conn,
            actor,
            network_id.as_deref(),
            &name,
            &ip_address,
            mac_address.as_deref(),
            &asset_type,
            os.as_deref(),
            user_name.as_deref(),
            &compromise_status,
            &investigation_status,
            properties.as_deref(),
            scan_results.as_deref(),
        )
    })
}
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_existing_asset(
    state: State<DbState>,
    id: String,
    network_id: Option<String>,
    name: String,
    ip_address: String,
    mac_address: Option<String>,
    asset_type: String,
    os: Option<String>,
    user_name: Option<String>,
    compromise_status: String,
    investigation_status: String,
    properties: Option<String>,
    scan_results: Option<String>,
) -> Response<Asset> {
    with_actor_conn(&state, |conn, actor| {
        update_asset(
            conn,
            actor,
            &id,
            network_id.as_deref(),
            &name,
            &ip_address,
            mac_address.as_deref(),
            &asset_type,
            os.as_deref(),
            user_name.as_deref(),
            &compromise_status,
            &investigation_status,
            properties.as_deref(),
            scan_results.as_deref(),
        )
    })
}
#[tauri::command]
fn list_assets(state: State<DbState>) -> Response<Vec<Asset>> {
    with_conn(&state, |conn| get_assets(conn))
}
#[tauri::command]
fn list_assets_by_network(state: State<DbState>, network_id: String) -> Response<Vec<Asset>> {
    with_conn(&state, |conn| get_assets_by_network(conn, &network_id))
}
#[tauri::command]
fn set_asset_suspicious(state: State<DbState>, id: String, suspicious: bool) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        update_asset_suspicious(conn, actor, &id, suspicious).map(|_| true)
    })
}
#[tauri::command]
fn remove_asset(state: State<DbState>, id: String) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        delete_asset(conn, actor, &id).map(|_| true)
    })
}

#[tauri::command]
fn list_network_interfaces(
    state: State<DbState>,
    asset_id: Option<String>,
) -> Response<Vec<NetworkInterface>> {
    with_conn(&state, |conn| {
        get_network_interfaces(conn, asset_id.as_deref())
    })
}
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_new_network_interface(
    state: State<DbState>,
    asset_id: String,
    name: String,
    ip_address: String,
    mac_address: Option<String>,
    network_id: Option<String>,
    is_primary: bool,
) -> Response<NetworkInterface> {
    with_actor_conn(&state, |conn, actor| {
        create_network_interface(
            conn,
            actor,
            &asset_id,
            &name,
            &ip_address,
            mac_address.as_deref(),
            network_id.as_deref(),
            is_primary,
        )
    })
}
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_existing_network_interface(
    state: State<DbState>,
    id: String,
    name: String,
    ip_address: String,
    mac_address: Option<String>,
    network_id: Option<String>,
    is_primary: bool,
) -> Response<NetworkInterface> {
    with_actor_conn(&state, |conn, actor| {
        update_network_interface(
            conn,
            actor,
            &id,
            &name,
            &ip_address,
            mac_address.as_deref(),
            network_id.as_deref(),
            is_primary,
        )
    })
}
#[tauri::command]
fn set_primary_network_interface(state: State<DbState>, id: String) -> Response<NetworkInterface> {
    with_actor_conn(&state, |conn, actor| {
        set_primary_interface(conn, actor, &id)
    })
}
#[tauri::command]
fn remove_network_interface(state: State<DbState>, id: String) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        delete_network_interface(conn, actor, &id).map(|_| true)
    })
}

#[tauri::command]
fn preview_timestamp(
    input: String,
    timezone: String,
    offset_ms: Option<i64>,
) -> Response<TimePreview> {
    match parse_timestamp_preview(&input, &timezone, offset_ms.unwrap_or(0)) {
        Ok(value) => Response::ok(value),
        Err(error) => Response::err(error),
    }
}

#[tauri::command]
fn list_clock_profiles(state: State<DbState>) -> Response<Vec<ClockProfile>> {
    with_conn(&state, |conn| get_clock_profiles(conn))
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_new_clock_profile(
    state: State<DbState>,
    name: String,
    description: String,
    server_reference_raw: String,
    server_timezone: String,
    correct_reference_raw: String,
    correct_timezone: String,
) -> Response<ClockProfile> {
    with_actor_conn(&state, |conn, actor| {
        create_clock_profile(
            conn,
            actor,
            &name,
            &description,
            &server_reference_raw,
            &server_timezone,
            &correct_reference_raw,
            &correct_timezone,
        )
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_existing_clock_profile(
    state: State<DbState>,
    id: String,
    name: String,
    description: String,
    server_reference_raw: String,
    server_timezone: String,
    correct_reference_raw: String,
    correct_timezone: String,
) -> Response<ClockProfile> {
    with_actor_conn(&state, |conn, actor| {
        update_clock_profile(
            conn,
            actor,
            &id,
            &name,
            &description,
            &server_reference_raw,
            &server_timezone,
            &correct_reference_raw,
            &correct_timezone,
        )
    })
}

#[tauri::command]
fn remove_clock_profile(state: State<DbState>, id: String) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        delete_clock_profile(conn, actor, &id).map(|_| true)
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_new_timeline_event(
    state: State<DbState>,
    asset_id: Option<String>,
    server_timestamp: Option<String>,
    server_timezone: Option<String>,
    correct_timestamp: Option<String>,
    correct_timezone: Option<String>,
    clock_profile_id: Option<String>,
    event_type: String,
    description: String,
    severity: String,
    source: Option<String>,
    mitre_tactic: Option<String>,
    mitre_technique: Option<String>,
) -> Response<TimelineEvent> {
    with_actor_conn(&state, |conn, actor| {
        create_timeline_event(
            conn,
            actor,
            asset_id.as_deref(),
            server_timestamp.as_deref(),
            server_timezone.as_deref(),
            correct_timestamp.as_deref(),
            correct_timezone.as_deref(),
            clock_profile_id.as_deref(),
            &event_type,
            &description,
            &severity,
            source.as_deref(),
            mitre_tactic.as_deref(),
            mitre_technique.as_deref(),
        )
    })
}
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_existing_timeline_event(
    state: State<DbState>,
    id: String,
    asset_id: Option<String>,
    server_timestamp: Option<String>,
    server_timezone: Option<String>,
    correct_timestamp: Option<String>,
    correct_timezone: Option<String>,
    clock_profile_id: Option<String>,
    event_type: String,
    description: String,
    severity: String,
    source: Option<String>,
    mitre_tactic: Option<String>,
    mitre_technique: Option<String>,
) -> Response<TimelineEvent> {
    with_actor_conn(&state, |conn, actor| {
        update_timeline_event(
            conn,
            actor,
            &id,
            asset_id.as_deref(),
            server_timestamp.as_deref(),
            server_timezone.as_deref(),
            correct_timestamp.as_deref(),
            correct_timezone.as_deref(),
            clock_profile_id.as_deref(),
            &event_type,
            &description,
            &severity,
            source.as_deref(),
            mitre_tactic.as_deref(),
            mitre_technique.as_deref(),
        )
    })
}
#[tauri::command]
fn list_timeline_events(state: State<DbState>) -> Response<Vec<TimelineEvent>> {
    with_conn(&state, |conn| get_timeline_events(conn))
}
#[tauri::command]
fn remove_timeline_event(state: State<DbState>, id: String) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        delete_timeline_event(conn, actor, &id).map(|_| true)
    })
}

#[tauri::command]
fn create_new_note(state: State<DbState>, title: String, content: String) -> Response<Note> {
    with_actor_conn(&state, |conn, actor| {
        create_note(conn, actor, &title, &content)
    })
}
#[tauri::command]
fn list_notes(state: State<DbState>) -> Response<Vec<Note>> {
    with_conn(&state, |conn| get_notes(conn))
}
#[tauri::command]
fn update_existing_note(
    state: State<DbState>,
    id: String,
    title: String,
    content: String,
) -> Response<Note> {
    with_actor_conn(&state, |conn, actor| {
        update_note(conn, actor, &id, &title, &content)
    })
}
#[tauri::command]
fn remove_note(state: State<DbState>, id: String) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        delete_note(conn, actor, &id).map(|_| true)
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_new_ioc(
    state: State<DbState>,
    ioc_type: String,
    value: String,
    description: String,
    threat_level: String,
    first_seen: Option<String>,
    last_seen: Option<String>,
) -> Response<Ioc> {
    with_actor_conn(&state, |conn, actor| {
        create_ioc(
            conn,
            actor,
            &ioc_type,
            &value,
            &description,
            &threat_level,
            first_seen.as_deref(),
            last_seen.as_deref(),
        )
    })
}
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_existing_ioc(
    state: State<DbState>,
    id: String,
    ioc_type: String,
    value: String,
    description: String,
    threat_level: String,
    first_seen: Option<String>,
    last_seen: Option<String>,
) -> Response<Ioc> {
    with_actor_conn(&state, |conn, actor| {
        update_ioc(
            conn,
            actor,
            &id,
            &ioc_type,
            &value,
            &description,
            &threat_level,
            first_seen.as_deref(),
            last_seen.as_deref(),
        )
    })
}
#[tauri::command]
fn list_iocs(state: State<DbState>) -> Response<Vec<Ioc>> {
    with_conn(&state, |conn| get_iocs(conn))
}
#[tauri::command]
fn remove_ioc(state: State<DbState>, id: String) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        delete_ioc(conn, actor, &id).map(|_| true)
    })
}

#[tauri::command]
fn list_ioc_sightings(
    state: State<DbState>,
    ioc_id: Option<String>,
    entity_kind: Option<String>,
    entity_id: Option<String>,
) -> Response<Vec<IocSighting>> {
    with_conn(&state, |conn| {
        get_ioc_sightings(
            conn,
            ioc_id.as_deref(),
            entity_kind.as_deref(),
            entity_id.as_deref(),
        )
    })
}
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_new_ioc_sighting(
    state: State<DbState>,
    ioc_id: String,
    entity_kind: String,
    entity_id: String,
    sighted_at: Option<String>,
    location: String,
    note: String,
    set_compromise_status: Option<String>,
) -> Response<IocSighting> {
    with_actor_conn(&state, |conn, actor| {
        create_ioc_sighting(
            conn,
            actor,
            &ioc_id,
            &entity_kind,
            &entity_id,
            sighted_at.as_deref(),
            &location,
            &note,
            set_compromise_status.as_deref(),
        )
    })
}
#[tauri::command]
fn update_existing_ioc_sighting(
    state: State<DbState>,
    id: String,
    sighted_at: Option<String>,
    location: String,
    note: String,
) -> Response<IocSighting> {
    with_actor_conn(&state, |conn, actor| {
        update_ioc_sighting(conn, actor, &id, sighted_at.as_deref(), &location, &note)
    })
}
#[tauri::command]
fn remove_ioc_sighting(state: State<DbState>, id: String) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        delete_ioc_sighting(conn, actor, &id).map(|_| true)
    })
}
#[tauri::command]
fn get_infection_summary(state: State<DbState>) -> Response<InfectionSummary> {
    with_conn(&state, |conn| db::get_infection_summary(conn))
}

#[tauri::command]
fn list_attack_edges(state: State<DbState>) -> Response<Vec<AttackEdge>> {
    with_conn(&state, |conn| get_attack_edges(conn))
}
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_new_attack_edge(
    state: State<DbState>,
    source_kind: String,
    source_id: String,
    target_kind: String,
    target_id: String,
    title: String,
    description: String,
    edge_type: String,
    confidence: String,
    mitre_tactic: Option<String>,
    mitre_technique: Option<String>,
    occurred_at: Option<String>,
    timeline_event_id: Option<String>,
    sequence: Option<i64>,
    ioc_ids: Vec<String>,
) -> Response<AttackEdge> {
    with_actor_conn(&state, |conn, actor| {
        create_attack_edge(
            conn,
            actor,
            &source_kind,
            &source_id,
            &target_kind,
            &target_id,
            &title,
            &description,
            &edge_type,
            &confidence,
            mitre_tactic.as_deref(),
            mitre_technique.as_deref(),
            occurred_at.as_deref(),
            timeline_event_id.as_deref(),
            sequence,
            ioc_ids,
        )
    })
}
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_existing_attack_edge(
    state: State<DbState>,
    id: String,
    source_kind: String,
    source_id: String,
    target_kind: String,
    target_id: String,
    title: String,
    description: String,
    edge_type: String,
    confidence: String,
    mitre_tactic: Option<String>,
    mitre_technique: Option<String>,
    occurred_at: Option<String>,
    timeline_event_id: Option<String>,
    sequence: i64,
    ioc_ids: Vec<String>,
) -> Response<AttackEdge> {
    with_actor_conn(&state, |conn, actor| {
        update_attack_edge(
            conn,
            actor,
            &id,
            &source_kind,
            &source_id,
            &target_kind,
            &target_id,
            &title,
            &description,
            &edge_type,
            &confidence,
            mitre_tactic.as_deref(),
            mitre_technique.as_deref(),
            occurred_at.as_deref(),
            timeline_event_id.as_deref(),
            sequence,
            ioc_ids,
        )
    })
}
#[tauri::command]
fn remove_attack_edge(state: State<DbState>, id: String) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        delete_attack_edge(conn, actor, &id).map(|_| true)
    })
}

#[tauri::command]
fn list_investigation_views(state: State<DbState>) -> Response<Vec<InvestigationViewSummary>> {
    with_conn(&state, |conn| get_investigation_views(conn))
}
#[tauri::command]
fn get_investigation_view(state: State<DbState>, id: String) -> Response<InvestigationView> {
    with_conn(&state, |conn| db::get_investigation_view(conn, &id))
}
#[tauri::command]
fn save_investigation_view(
    state: State<DbState>,
    id: Option<String>,
    name: String,
    description: String,
    view_state: serde_json::Value,
) -> Response<InvestigationView> {
    with_conn(&state, |conn| {
        db::save_investigation_view(conn, id.as_deref(), &name, &description, &view_state)
    })
}
#[tauri::command]
fn remove_investigation_view(state: State<DbState>, id: String) -> Response<bool> {
    with_conn(&state, |conn| {
        delete_investigation_view(conn, &id).map(|_| true)
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_new_firewall(
    state: State<DbState>,
    network_id: Option<String>,
    name: String,
    vendor: Option<String>,
    model: Option<String>,
    rules: Option<String>,
    config_text: Option<String>,
) -> Response<Firewall> {
    with_actor_conn(&state, |conn, actor| {
        create_firewall(
            conn,
            actor,
            network_id.as_deref(),
            &name,
            vendor.as_deref(),
            model.as_deref(),
            rules.as_deref(),
            config_text.as_deref(),
        )
    })
}
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_existing_firewall(
    state: State<DbState>,
    id: String,
    network_id: Option<String>,
    name: String,
    vendor: Option<String>,
    model: Option<String>,
    rules: Option<String>,
    config_text: Option<String>,
) -> Response<Firewall> {
    with_actor_conn(&state, |conn, actor| {
        update_firewall(
            conn,
            actor,
            &id,
            network_id.as_deref(),
            &name,
            vendor.as_deref(),
            model.as_deref(),
            rules.as_deref(),
            config_text.as_deref(),
        )
    })
}
#[tauri::command]
fn list_firewalls(state: State<DbState>) -> Response<Vec<Firewall>> {
    with_conn(&state, |conn| get_firewalls(conn))
}
#[tauri::command]
fn remove_firewall(state: State<DbState>, id: String) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        delete_firewall(conn, actor, &id).map(|_| true)
    })
}

#[tauri::command]
fn list_firewall_interfaces(
    state: State<DbState>,
    firewall_id: Option<String>,
) -> Response<Vec<FirewallInterface>> {
    with_conn(&state, |conn| {
        get_firewall_interfaces(conn, firewall_id.as_deref())
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_new_firewall_interface(
    state: State<DbState>,
    firewall_id: String,
    name: String,
    ip_addresses: Vec<String>,
    mac_address: Option<String>,
    network_id: Option<String>,
    vlan_id: Option<String>,
    role: String,
    is_primary: bool,
    description: String,
) -> Response<FirewallInterface> {
    with_actor_conn(&state, |conn, actor| {
        create_firewall_interface(
            conn,
            actor,
            &firewall_id,
            &name,
            ip_addresses,
            mac_address.as_deref(),
            network_id.as_deref(),
            vlan_id.as_deref(),
            &role,
            is_primary,
            &description,
        )
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_existing_firewall_interface(
    state: State<DbState>,
    id: String,
    name: String,
    ip_addresses: Vec<String>,
    mac_address: Option<String>,
    network_id: Option<String>,
    vlan_id: Option<String>,
    role: String,
    is_primary: bool,
    description: String,
) -> Response<FirewallInterface> {
    with_actor_conn(&state, |conn, actor| {
        update_firewall_interface(
            conn,
            actor,
            &id,
            &name,
            ip_addresses,
            mac_address.as_deref(),
            network_id.as_deref(),
            vlan_id.as_deref(),
            &role,
            is_primary,
            &description,
        )
    })
}

#[tauri::command]
fn remove_firewall_interface(state: State<DbState>, id: String) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        delete_firewall_interface(conn, actor, &id).map(|_| true)
    })
}

#[tauri::command]
fn list_firewall_nat_rules(
    state: State<DbState>,
    firewall_id: Option<String>,
) -> Response<Vec<FirewallNatRule>> {
    with_conn(&state, |conn| {
        get_firewall_nat_rules(conn, firewall_id.as_deref())
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_new_firewall_nat_rule(
    state: State<DbState>,
    firewall_id: String,
    name: String,
    nat_type: String,
    enabled: bool,
    protocol: String,
    source_cidr: Option<String>,
    original_destination: Option<String>,
    original_port: Option<String>,
    translated_source: Option<String>,
    translated_destination: Option<String>,
    translated_port: Option<String>,
    inbound_interface_id: Option<String>,
    outbound_interface_id: Option<String>,
    description: String,
) -> Response<FirewallNatRule> {
    with_actor_conn(&state, |conn, actor| {
        create_firewall_nat_rule(
            conn,
            actor,
            &firewall_id,
            &name,
            &nat_type,
            enabled,
            &protocol,
            source_cidr.as_deref(),
            original_destination.as_deref(),
            original_port.as_deref(),
            translated_source.as_deref(),
            translated_destination.as_deref(),
            translated_port.as_deref(),
            inbound_interface_id.as_deref(),
            outbound_interface_id.as_deref(),
            &description,
        )
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_existing_firewall_nat_rule(
    state: State<DbState>,
    id: String,
    name: String,
    nat_type: String,
    enabled: bool,
    protocol: String,
    source_cidr: Option<String>,
    original_destination: Option<String>,
    original_port: Option<String>,
    translated_source: Option<String>,
    translated_destination: Option<String>,
    translated_port: Option<String>,
    inbound_interface_id: Option<String>,
    outbound_interface_id: Option<String>,
    description: String,
) -> Response<FirewallNatRule> {
    with_actor_conn(&state, |conn, actor| {
        update_firewall_nat_rule(
            conn,
            actor,
            &id,
            &name,
            &nat_type,
            enabled,
            &protocol,
            source_cidr.as_deref(),
            original_destination.as_deref(),
            original_port.as_deref(),
            translated_source.as_deref(),
            translated_destination.as_deref(),
            translated_port.as_deref(),
            inbound_interface_id.as_deref(),
            outbound_interface_id.as_deref(),
            &description,
        )
    })
}

#[tauri::command]
fn remove_firewall_nat_rule(state: State<DbState>, id: String) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        delete_firewall_nat_rule(conn, actor, &id).map(|_| true)
    })
}

#[tauri::command]
fn create_new_network_connection(
    state: State<DbState>,
    source_network_id: String,
    target_network_id: String,
    connection_type: String,
    description: String,
    device_name: Option<String>,
) -> Response<NetworkConnection> {
    with_actor_conn(&state, |conn, actor| {
        create_network_connection(
            conn,
            actor,
            &source_network_id,
            &target_network_id,
            &connection_type,
            &description,
            device_name.as_deref(),
        )
    })
}
#[tauri::command]
fn update_existing_network_connection(
    state: State<DbState>,
    id: String,
    source_network_id: String,
    target_network_id: String,
    connection_type: String,
    description: String,
    device_name: Option<String>,
) -> Response<NetworkConnection> {
    with_actor_conn(&state, |conn, actor| {
        update_network_connection(
            conn,
            actor,
            &id,
            &source_network_id,
            &target_network_id,
            &connection_type,
            &description,
            device_name.as_deref(),
        )
    })
}
#[tauri::command]
fn list_network_connections(state: State<DbState>) -> Response<Vec<NetworkConnection>> {
    with_conn(&state, |conn| get_network_connections(conn))
}
#[tauri::command]
fn remove_network_connection(state: State<DbState>, id: String) -> Response<bool> {
    with_actor_conn(&state, |conn, actor| {
        delete_network_connection(conn, actor, &id).map(|_| true)
    })
}

fn protected_password(password: Option<String>) -> Option<Zeroizing<String>> {
    password
        .filter(|value| !value.is_empty())
        .map(Zeroizing::new)
}

fn password_ref(password: &Option<Zeroizing<String>>) -> Option<&str> {
    password.as_ref().map(|value| value.as_str())
}

fn parse_case_export(json: &str) -> AppResult<ExportData> {
    serde_json::from_str(json).map_err(|error| format!("Invalid case JSON: {error}"))
}

#[tauri::command]
fn export_case_json(state: State<DbState>, password: Option<String>) -> Response<String> {
    let password = protected_password(password);
    with_conn(&state, |conn| {
        let json =
            serde_json::to_string_pretty(&export_case_data(conn)?).map_err(|e| e.to_string())?;
        encode_portable_text(&json, password_ref(&password))
    })
}
#[tauri::command]
fn import_case_json(
    state: State<DbState>,
    json_data: String,
    password: Option<String>,
) -> Response<ImportSummary> {
    let password = protected_password(password);
    let decoded = match decode_portable_text(&json_data, password_ref(&password)) {
        Ok(decoded) => decoded,
        Err(error) => return Response::err(error),
    };
    let data: ExportData = match parse_case_export(&decoded.plaintext) {
        Ok(data) => data,
        Err(error) => return Response::err(error),
    };
    with_actor_conn(&state, |conn, actor| import_case_data(conn, actor, &data))
}
#[tauri::command]
fn save_export_to_file(
    app_handle: tauri::AppHandle,
    state: State<DbState>,
    password: Option<String>,
) -> Response<String> {
    let password = protected_password(password);
    let json = match with_conn(&state, |conn| {
        serde_json::to_string_pretty(&export_case_data(conn)?).map_err(|e| e.to_string())
    }) {
        Response {
            success: true,
            data: Some(json),
            ..
        } => json,
        Response {
            error: Some(error), ..
        } => return Response::err(error),
        _ => return Response::err("Export failed"),
    };
    let encoded = match encode_portable_text(&json, password_ref(&password)) {
        Ok(encoded) => encoded,
        Err(error) => return Response::err(error),
    };
    if password.is_some() {
        save_text_file(
            &app_handle,
            "case-backup.dfirx",
            "Encrypted DFIR Export",
            "dfirx",
            &encoded,
        )
    } else {
        save_text_file(
            &app_handle,
            "case-backup.json",
            "DFIR JSON",
            "json",
            &encoded,
        )
    }
}
#[tauri::command]
fn load_import_from_file(
    app_handle: tauri::AppHandle,
    state: State<DbState>,
    password: Option<String>,
) -> Response<ImportSummary> {
    let password = protected_password(password);
    let text = match pick_text_file(&app_handle, "DFIR Export", &["json", "dfirx"]) {
        Ok(text) => text,
        Err(error) => return Response::err(error),
    };
    let decoded = match decode_portable_text(&text, password_ref(&password)) {
        Ok(decoded) => decoded,
        Err(error) => return Response::err(error),
    };
    let data: ExportData = match parse_case_export(&decoded.plaintext) {
        Ok(data) => data,
        Err(error) => return Response::err(error),
    };
    with_actor_conn(&state, |conn, actor| import_case_data(conn, actor, &data))
}

fn stage_partial_import(state: &State<DbState>, input: &str) -> Response<PartialImportPreview> {
    let prepared = match with_conn(state, |conn| preview_partial_import(conn, input)) {
        Response {
            success: true,
            data: Some(prepared),
            ..
        } => prepared,
        Response {
            error: Some(error), ..
        } => return Response::err(error),
        _ => return Response::err("Partial-import preview failed"),
    };
    let preview = prepared.preview.clone();
    match state.pending_partial_imports.lock() {
        Ok(mut pending) => {
            pending.insert(preview.preview_id.clone(), prepared);
            Response::ok(preview)
        }
        Err(_) => Response::err("Pending partial-import lock poisoned"),
    }
}

#[tauri::command]
fn get_partial_import_template(state: State<DbState>) -> Response<String> {
    with_conn(&state, |conn| partial_import_template(conn))
}

#[tauri::command]
fn save_partial_import_template(
    app_handle: tauri::AppHandle,
    state: State<DbState>,
) -> Response<String> {
    let template = match with_conn(&state, |conn| partial_import_template(conn)) {
        Response {
            success: true,
            data: Some(template),
            ..
        } => template,
        Response {
            error: Some(error), ..
        } => return Response::err(error),
        _ => return Response::err("Could not generate partial-import template"),
    };
    save_text_file(
        &app_handle,
        "dfir-partial-import-template.json",
        "DFIR Partial Import",
        "json",
        &template,
    )
}

#[tauri::command]
fn preview_partial_import_text(
    state: State<DbState>,
    json_data: String,
) -> Response<PartialImportPreview> {
    stage_partial_import(&state, &json_data)
}

#[tauri::command]
fn load_partial_import_from_file(
    app_handle: tauri::AppHandle,
    state: State<DbState>,
) -> Response<PartialImportPreview> {
    let text = match pick_text_file(&app_handle, "Plain DFIR Partial Import", &["json"]) {
        Ok(text) => text,
        Err(error) => return Response::err(error),
    };
    stage_partial_import(&state, &text)
}

#[tauri::command]
fn validate_pending_partial_import(
    state: State<DbState>,
    preview_id: String,
    selected_change_ids: Vec<String>,
) -> Response<PartialSelectionValidation> {
    let pending = match state.pending_partial_imports.lock() {
        Ok(pending) => match pending.get(&preview_id) {
            Some(value) => value.clone(),
            None => return Response::err("Pending partial import was not found"),
        },
        Err(_) => return Response::err("Pending partial-import lock poisoned"),
    };
    with_conn(&state, |conn| {
        Ok(validate_partial_selection(
            conn,
            &pending,
            &selected_change_ids,
        ))
    })
}

#[tauri::command]
fn apply_pending_partial_import(
    state: State<DbState>,
    preview_id: String,
    selected_change_ids: Vec<String>,
) -> Response<PartialApplySummary> {
    let pending = match state.pending_partial_imports.lock() {
        Ok(pending) => match pending.get(&preview_id) {
            Some(value) => value.clone(),
            None => return Response::err("Pending partial import was not found"),
        },
        Err(_) => return Response::err("Pending partial-import lock poisoned"),
    };
    let result = with_actor_conn(&state, |conn, actor| {
        apply_partial_import(conn, actor, &pending, &selected_change_ids)
    });
    if result.success {
        if let Ok(mut pending) = state.pending_partial_imports.lock() {
            pending.remove(&preview_id);
        }
    }
    result
}

#[tauri::command]
fn discard_pending_partial_import(state: State<DbState>, preview_id: String) -> Response<bool> {
    match state.pending_partial_imports.lock() {
        Ok(mut pending) => Response::ok(pending.remove(&preview_id).is_some()),
        Err(_) => Response::err("Pending partial-import lock poisoned"),
    }
}

#[tauri::command]
fn save_export_as_text(app_handle: tauri::AppHandle, password: Option<String>) -> Response<String> {
    let password = protected_password(password);
    let text = match pick_text_file(&app_handle, "DFIR Export", &["json", "dfirx"]) {
        Ok(text) => text,
        Err(error) => return Response::err(error),
    };
    let decoded = match decode_portable_text(&text, password_ref(&password)) {
        Ok(decoded) => decoded,
        Err(error) => return Response::err(error),
    };
    let report = match render_export_text(&decoded.plaintext) {
        Ok(report) => report,
        Err(error) => return Response::err(error),
    };
    save_text_file(
        &app_handle,
        "dfir-export-report.txt",
        "Plain Text Report",
        "txt",
        &report,
    )
}

#[tauri::command]
fn mark_current_shared_baseline(state: State<DbState>) -> Response<String> {
    with_conn(&state, |conn| mark_shared_baseline(conn))
}
#[tauri::command]
fn list_case_history(state: State<DbState>, limit: Option<usize>) -> Response<Vec<HistoryCommit>> {
    with_conn(&state, |conn| {
        get_history(conn, limit.unwrap_or(100).min(1000))
    })
}
#[tauri::command]
fn save_change_bundle_to_file(
    app_handle: tauri::AppHandle,
    state: State<DbState>,
    password: Option<String>,
) -> Response<String> {
    let password = protected_password(password);
    let actor = match current_actor(&state) {
        Ok(actor) => actor,
        Err(error) => return Response::err(error),
    };
    let bundle = match with_conn(&state, |conn| export_change_bundle(conn, &actor)) {
        Response {
            success: true,
            data: Some(bundle),
            ..
        } => bundle,
        Response {
            error: Some(error), ..
        } => return Response::err(error),
        _ => return Response::err("Change export failed"),
    };
    let json = match serde_json::to_string_pretty(&bundle) {
        Ok(json) => json,
        Err(error) => return Response::err(error.to_string()),
    };
    let encoded = match encode_portable_text(&json, password_ref(&password)) {
        Ok(encoded) => encoded,
        Err(error) => return Response::err(error),
    };
    if password.is_some() {
        save_text_file(
            &app_handle,
            format!("changes-{}.dfirx", sanitize_filename(&actor.name)),
            "Encrypted DFIR Export",
            "dfirx",
            &encoded,
        )
    } else {
        save_text_file(
            &app_handle,
            format!(
                "changes-{}.dfir-changes.json",
                sanitize_filename(&actor.name)
            ),
            "DFIR Changes",
            "json",
            &encoded,
        )
    }
}
#[tauri::command]
fn load_change_bundle_from_file(
    app_handle: tauri::AppHandle,
    state: State<DbState>,
    password: Option<String>,
) -> Response<MergePreview> {
    let password = protected_password(password);
    let text = match pick_text_file(&app_handle, "DFIR Changes", &["json", "dfirx"]) {
        Ok(text) => text,
        Err(error) => return Response::err(error),
    };
    let decoded = match decode_portable_text(&text, password_ref(&password)) {
        Ok(decoded) => decoded,
        Err(error) => return Response::err(error),
    };
    let bundle = match parse_change_bundle(&decoded.plaintext) {
        Ok(bundle) => bundle,
        Err(error) => return Response::err(error),
    };
    let preview = match with_conn(&state, |conn| preview_bundle(conn, &bundle)) {
        Response {
            success: true,
            data: Some(preview),
            ..
        } => preview,
        Response {
            error: Some(error), ..
        } => return Response::err(error),
        _ => return Response::err("Change preview failed"),
    };
    match state.pending_bundles.lock() {
        Ok(mut pending) => {
            pending.insert(
                bundle.bundle_id.clone(),
                PendingBundle {
                    bundle,
                    preview: preview.clone(),
                },
            );
            Response::ok(preview)
        }
        Err(_) => Response::err("Pending merge lock poisoned"),
    }
}

#[tauri::command]
fn refresh_pending_change_bundle(
    state: State<DbState>,
    bundle_id: String,
) -> Response<MergePreview> {
    let bundle = match state.pending_bundles.lock() {
        Ok(pending) => match pending.get(&bundle_id) {
            Some(pending) => pending.bundle.clone(),
            None => return Response::err("Pending bundle was not found"),
        },
        Err(_) => return Response::err("Pending merge lock poisoned"),
    };
    let preview = match with_conn(&state, |conn| preview_bundle(conn, &bundle)) {
        Response {
            success: true,
            data: Some(preview),
            ..
        } => preview,
        Response {
            error: Some(error), ..
        } => return Response::err(error),
        _ => return Response::err("Change preview failed"),
    };
    match state.pending_bundles.lock() {
        Ok(mut pending) => {
            if let Some(item) = pending.get_mut(&bundle_id) {
                item.preview = preview.clone();
            }
            Response::ok(preview)
        }
        Err(_) => Response::err("Pending merge lock poisoned"),
    }
}
#[tauri::command]
fn apply_pending_change_bundle(
    state: State<DbState>,
    bundle_id: String,
    decisions: Vec<MergeDecision>,
) -> Response<MergeApplySummary> {
    let pending = match state.pending_bundles.lock() {
        Ok(pending) => match pending.get(&bundle_id) {
            Some(pending) => PendingBundle {
                bundle: pending.bundle.clone(),
                preview: pending.preview.clone(),
            },
            None => return Response::err("Pending bundle was not found"),
        },
        Err(_) => return Response::err("Pending merge lock poisoned"),
    };
    let result = with_actor_conn(&state, |conn, actor| {
        apply_bundle(conn, actor, &pending.bundle, &pending.preview, &decisions)
    });
    if result.success {
        if let Ok(mut guard) = state.pending_bundles.lock() {
            guard.remove(&bundle_id);
        }
    }
    result
}
#[tauri::command]
fn discard_pending_change_bundle(state: State<DbState>, bundle_id: String) -> Response<bool> {
    match state.pending_bundles.lock() {
        Ok(mut pending) => Response::ok(pending.remove(&bundle_id).is_some()),
        Err(_) => Response::err("Pending merge lock poisoned"),
    }
}

#[tauri::command]
fn get_db_path(state: State<DbState>) -> Response<Option<String>> {
    match state.db_path.lock() {
        Ok(path) => Response::ok(path.as_ref().map(|path| path.to_string_lossy().to_string())),
        Err(_) => Response::err("Database path lock poisoned"),
    }
}

fn save_text_file(
    app_handle: &tauri::AppHandle,
    default_name: impl AsRef<str>,
    label: &str,
    extension: &str,
    contents: &str,
) -> Response<String> {
    let selection = app_handle
        .dialog()
        .file()
        .set_file_name(default_name.as_ref())
        .add_filter(label, &[extension])
        .blocking_save_file();
    let path = match selection
        .and_then(|value| selected_path(value).ok())
        .map(|path| ensure_extension(path, extension))
    {
        Some(path) => path,
        None => return Response::err("Save cancelled"),
    };
    match fs::write(&path, contents) {
        Ok(()) => Response::ok(path.to_string_lossy().to_string()),
        Err(error) => Response::err(format!("Failed to write file: {error}")),
    }
}

fn pick_text_file(
    app_handle: &tauri::AppHandle,
    label: &str,
    extensions: &[&str],
) -> AppResult<String> {
    let selection = app_handle
        .dialog()
        .file()
        .add_filter(label, extensions)
        .blocking_pick_file()
        .ok_or_else(|| "Open cancelled".to_string())?;
    let path = selected_path(selection)?;
    let length = fs::metadata(&path)
        .map_err(|error| format!("Failed to inspect file: {error}"))?
        .len();
    if length > MAX_PORTABLE_FILE_BYTES {
        return Err(format!(
            "Refusing to open a portable file larger than {} MiB",
            MAX_PORTABLE_FILE_BYTES / 1024 / 1024
        ));
    }
    fs::read_to_string(path).map_err(|error| format!("Failed to read file: {error}"))
}

fn sanitize_filename(name: &str) -> String {
    let value: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect();
    if value.trim_matches('_').is_empty() {
        "dfir-case".to_string()
    } else {
        value
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(DbState::new())
        .invoke_handler(tauri::generate_handler![
            set_current_expert,
            get_current_expert,
            create_new_case,
            open_existing_case,
            migrate_legacy_case,
            change_database_password,
            close_current_case,
            get_current_case_info,
            update_current_case,
            create_new_network,
            update_existing_network,
            list_networks,
            get_topology_view,
            save_topology_view,
            remove_network,
            create_new_asset,
            update_existing_asset,
            list_assets,
            list_assets_by_network,
            set_asset_suspicious,
            remove_asset,
            list_network_interfaces,
            create_new_network_interface,
            update_existing_network_interface,
            set_primary_network_interface,
            remove_network_interface,
            preview_timestamp,
            list_clock_profiles,
            create_new_clock_profile,
            update_existing_clock_profile,
            remove_clock_profile,
            create_new_timeline_event,
            update_existing_timeline_event,
            list_timeline_events,
            remove_timeline_event,
            create_new_note,
            list_notes,
            update_existing_note,
            remove_note,
            create_new_ioc,
            update_existing_ioc,
            list_iocs,
            remove_ioc,
            list_ioc_sightings,
            create_new_ioc_sighting,
            update_existing_ioc_sighting,
            remove_ioc_sighting,
            get_infection_summary,
            list_attack_edges,
            create_new_attack_edge,
            update_existing_attack_edge,
            remove_attack_edge,
            list_investigation_views,
            get_investigation_view,
            save_investigation_view,
            remove_investigation_view,
            create_new_firewall,
            update_existing_firewall,
            list_firewalls,
            remove_firewall,
            list_firewall_interfaces,
            create_new_firewall_interface,
            update_existing_firewall_interface,
            remove_firewall_interface,
            list_firewall_nat_rules,
            create_new_firewall_nat_rule,
            update_existing_firewall_nat_rule,
            remove_firewall_nat_rule,
            create_new_network_connection,
            update_existing_network_connection,
            list_network_connections,
            remove_network_connection,
            export_case_json,
            import_case_json,
            save_export_to_file,
            load_import_from_file,
            get_partial_import_template,
            save_partial_import_template,
            preview_partial_import_text,
            load_partial_import_from_file,
            validate_pending_partial_import,
            apply_pending_partial_import,
            discard_pending_partial_import,
            save_export_as_text,
            mark_current_shared_baseline,
            list_case_history,
            save_change_bundle_to_file,
            load_change_bundle_from_file,
            refresh_pending_change_bundle,
            apply_pending_change_bundle,
            discard_pending_change_bundle,
            get_db_path,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
