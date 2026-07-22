//! Authentication.
//!
//! There is no user directory and no password hash on this server. Unlocking a
//! case *is* the login: SQLCipher either derives a working key from the
//! submitted password or it does not. The expert name accompanying the unlock
//! is self-declared attribution, exactly as in the offline app — it is never
//! checked against anything.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::db::{get_case, Case};
use crate::history::ActorIdentity;
use crate::state::{AppState, OpenCase, Response};

/// Unlock replies never resolve faster than this. It blunts timing differences
/// between "no such case", "wrong password", and "correct password", and caps
/// how fast an attacker can cycle guesses even before the lockout trips.
const MIN_UNLOCK_DURATION: Duration = Duration::from_millis(250);

/// A resolved session: which case this browser is working in, and as whom.
pub struct SessionContext {
    pub token: String,
    pub case: Arc<OpenCase>,
    pub actor: ActorIdentity,
}

impl FromRequestParts<Arc<AppState>> for SessionContext {
    type Rejection = (StatusCode, Json<Response<()>>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let reject = |message: &str| {
            (
                StatusCode::UNAUTHORIZED,
                Json(Response::<()>::err(message.to_string())),
            )
        };

        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(|value| value.trim().to_string())
            .ok_or_else(|| reject("Unlock a case before using it"))?;

        let session = state
            .touch_session(&token)
            .ok_or_else(|| reject("This session has expired. Unlock the case again"))?;

        let case = state
            .case(&session.case_id)
            .ok_or_else(|| reject("This case was closed. Unlock it again"))?;

        Ok(SessionContext {
            token,
            case,
            actor: session.actor,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockRequest {
    pub case_id: String,
    pub password: String,
    pub expert_name: String,
    #[serde(default)]
    pub scope_label: Option<String>,
    #[serde(default)]
    pub scope_network_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPayload {
    pub token: String,
    pub case_id: String,
    pub case: Option<Case>,
    pub expert: ActorIdentity,
    pub revision: u64,
}

pub async fn unlock(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<UnlockRequest>,
) -> Json<Response<SessionPayload>> {
    let started = Instant::now();
    let result = unlock_inner(&state, peer, request);
    if let Some(remaining) = MIN_UNLOCK_DURATION.checked_sub(started.elapsed()) {
        tokio::time::sleep(remaining).await;
    }
    Json(Response::from_result(result))
}

pub(crate) fn unlock_inner(
    state: &Arc<AppState>,
    peer: SocketAddr,
    request: UnlockRequest,
) -> Result<SessionPayload, String> {
    let password = Zeroizing::new(request.password);
    state.check_throttle(peer.ip())?;

    let actor = ActorIdentity::new(
        request.expert_name,
        request.scope_label,
        request.scope_network_ids,
    )?;

    let case = match state.unlock_case(&request.case_id, password.as_str()) {
        Ok(case) => {
            state.record_unlock_success(peer.ip());
            case
        }
        Err(error) => {
            state.record_unlock_failure(peer.ip());
            return Err(error);
        }
    };

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

pub async fn logout(
    State(state): State<Arc<AppState>>,
    session: SessionContext,
) -> Json<Response<bool>> {
    state.end_session(&session.token);
    Json(Response::ok(true))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatePayload {
    pub case_id: String,
    pub revision: u64,
    pub active_experts: Vec<String>,
}

/// Polled by every open browser, so it deliberately touches only in-memory
/// state — it must never queue behind a write on the case connection.
pub async fn server_state(
    State(state): State<Arc<AppState>>,
    session: SessionContext,
) -> Json<Response<ServerStatePayload>> {
    Json(Response::ok(ServerStatePayload {
        case_id: session.case.id.clone(),
        revision: session.case.revision(),
        active_experts: state.active_experts(&session.case.id),
    }))
}
