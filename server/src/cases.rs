//! Case directory: what the login screen lists, and case creation.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::auth::SessionPayload;
use crate::db::{create_case_record, get_case, init_database, validate_and_migrate_case};
use crate::history::ActorIdentity;
use crate::secure_db::{
    create_encrypted_connection, validate_database_password, verify_cipher_integrity,
};
use crate::state::{case_id_from_name, AppState, Response};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseListing {
    pub cases: Vec<String>,
    pub allow_create: bool,
}

/// Unauthenticated: an expert has to see the list before they can pick which
/// case to unlock. Only the file stem is exposed — every byte inside the file
/// stays encrypted — but the stem is still visible to anyone who can reach the
/// port, so `docs/SERVER.md` tells operators to use neutral case filenames.
pub async fn list_cases(State(state): State<Arc<AppState>>) -> Json<Response<CaseListing>> {
    Json(match state.list_case_ids() {
        Ok(cases) => Response::ok(CaseListing {
            cases,
            allow_create: state.config.allow_create,
        }),
        Err(error) => Response::err(error),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCaseRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub client_name: String,
    pub expert_name: String,
    pub database_password: String,
}

/// Creates the encrypted case file and immediately starts a session on it, the
/// way `create_new_case` leaves the desktop app with an open case and an actor.
pub async fn create_case(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<CreateCaseRequest>,
) -> Json<Response<SessionPayload>> {
    Json(Response::from_result(create_case_inner(
        &state, peer, request,
    )))
}

pub(crate) fn create_case_inner(
    state: &Arc<AppState>,
    peer: SocketAddr,
    request: CreateCaseRequest,
) -> Result<SessionPayload, String> {
    if !state.config.allow_create {
        return Err(
            "This server does not accept new cases. Ask the operator to add the case file"
                .to_string(),
        );
    }
    state.check_throttle(peer.ip())?;

    let password = Zeroizing::new(request.database_password);
    validate_database_password(password.as_str())?;
    if request.name.trim().is_empty() {
        return Err("Case name is required".to_string());
    }
    let actor = ActorIdentity::new(request.expert_name, None, Vec::new())?;

    let case_id = case_id_from_name(&request.name, &state.config.cases_dir);
    let path = state.case_path(&case_id)?;
    if path.exists() {
        return Err("Refusing to overwrite an existing case file".to_string());
    }

    // Same construction sequence as the desktop `create_new_case`, including
    // removing a half-built file when any step fails.
    let build = (|| -> Result<(), String> {
        let mut conn = create_encrypted_connection(&path, password.as_str())?;
        init_database(&conn)?;
        create_case_record(
            &conn,
            request.name.trim(),
            request.description.trim(),
            request.client_name.trim(),
            &actor.name,
        )?;
        validate_and_migrate_case(&mut conn)?;
        verify_cipher_integrity(&conn)?;
        Ok(())
    })();
    if let Err(error) = build {
        let _ = std::fs::remove_file(&path);
        return Err(error);
    }

    let case = state.unlock_case(&case_id, password.as_str())?;
    let record = case.with_conn(|conn| get_case(conn))?;
    let token = state.create_session(&case.id, actor.clone())?;
    Ok(SessionPayload {
        token,
        case_id: case.id.clone(),
        case: record,
        expert: actor,
        revision: case.revision(),
    })
}
