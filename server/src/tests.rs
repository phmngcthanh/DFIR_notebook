//! Server-level tests.
//!
//! The investigation logic itself is already covered by the `#[cfg(test)]`
//! modules inside the shared core files, which compile into this crate too.
//! What is tested here is only what the server adds: password-as-login,
//! throttling, session lifetime, and the command dispatcher.

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::json;
use uuid::Uuid;

use crate::auth::{unlock_inner, SessionContext, SessionPayload, UnlockRequest};
use crate::cases::{create_case_inner, CreateCaseRequest};
use crate::dispatch::run;
use crate::state::{AppState, ServerConfig};

struct TempServer {
    state: Arc<AppState>,
}

impl TempServer {
    fn new(allow_create: bool) -> Self {
        let cases_dir = std::env::temp_dir().join(format!("dfir-server-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&cases_dir).unwrap();
        Self {
            state: Arc::new(AppState::new(ServerConfig {
                cases_dir,
                allow_create,
                session_timeout_secs: 3600,
            })),
        }
    }
}

impl Drop for TempServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.state.config.cases_dir);
    }
}

fn peer() -> SocketAddr {
    "127.0.0.1:51000".parse().unwrap()
}

fn create(state: &Arc<AppState>, password: &str) -> Result<SessionPayload, String> {
    create_case_inner(
        state,
        peer(),
        CreateCaseRequest {
            name: "Incident 7".to_string(),
            description: String::new(),
            client_name: "ACME".to_string(),
            expert_name: "Expert A".to_string(),
            database_password: password.to_string(),
        },
    )
}

fn unlock(
    state: &Arc<AppState>,
    case_id: &str,
    password: &str,
    expert: &str,
) -> Result<SessionPayload, String> {
    unlock_inner(
        state,
        peer(),
        UnlockRequest {
            case_id: case_id.to_string(),
            password: password.to_string(),
            expert_name: expert.to_string(),
            scope_label: None,
            scope_network_ids: Vec::new(),
        },
    )
}

fn session(state: &Arc<AppState>, payload: &SessionPayload) -> SessionContext {
    SessionContext {
        token: payload.token.clone(),
        case: state.case(&payload.case_id).unwrap(),
        actor: payload.expert.clone(),
    }
}

#[test]
fn the_case_password_is_the_only_credential() {
    let server = TempServer::new(true);
    let created = create(&server.state, "correct-horse-battery").unwrap();

    // Any expert name is accepted — it is attribution, not identity.
    assert!(unlock(
        &server.state,
        &created.case_id,
        "correct-horse-battery",
        "Someone Else"
    )
    .is_ok());
    // The password alone decides.
    let refused = unlock(
        &server.state,
        &created.case_id,
        "wrong-password",
        "Expert A",
    )
    .unwrap_err();
    assert!(
        refused.contains("password is wrong") || refused.contains("unlock"),
        "{refused}"
    );
}

#[test]
fn case_creation_is_refused_unless_the_operator_enabled_it() {
    let server = TempServer::new(false);
    let error = create(&server.state, "correct-horse-battery").unwrap_err();
    assert!(error.contains("does not accept new cases"), "{error}");
}

#[test]
fn repeated_wrong_passwords_lock_the_address_out() {
    let server = TempServer::new(true);
    let created = create(&server.state, "correct-horse-battery").unwrap();

    for _ in 0..5 {
        assert!(unlock(&server.state, &created.case_id, "guess", "Expert A").is_err());
    }
    // The sixth attempt never reaches SQLCipher, and even the right password is
    // refused while the lockout stands.
    let blocked = unlock(
        &server.state,
        &created.case_id,
        "correct-horse-battery",
        "Expert A",
    )
    .unwrap_err();
    assert!(
        blocked.contains("Too many failed unlock attempts"),
        "{blocked}"
    );
}

#[test]
fn case_identifiers_cannot_escape_the_case_directory() {
    let server = TempServer::new(true);
    for id in ["../secrets", "..", ".hidden", "a/b", "with space", ""] {
        assert!(
            server.state.case_path(id).is_err(),
            "case id {id:?} should have been rejected"
        );
    }
    assert!(server.state.case_path("case-2026-07").is_ok());
}

#[test]
fn the_case_closes_when_the_last_expert_leaves() {
    let server = TempServer::new(true);
    let alice = create(&server.state, "correct-horse-battery").unwrap();
    let bob = unlock(
        &server.state,
        &alice.case_id,
        "correct-horse-battery",
        "Expert B",
    )
    .unwrap();

    assert_eq!(
        server.state.active_experts(&alice.case_id),
        vec!["Expert A".to_string(), "Expert B".to_string()]
    );

    server.state.end_session(&alice.token);
    assert!(
        server.state.case(&alice.case_id).is_some(),
        "Bob is still working"
    );

    server.state.end_session(&bob.token);
    assert!(
        server.state.case(&alice.case_id).is_none(),
        "no sessions left"
    );
}

#[test]
fn a_write_through_the_dispatcher_bumps_the_revision_every_browser_polls() {
    let server = TempServer::new(true);
    let payload = create(&server.state, "correct-horse-battery").unwrap();
    let context = session(&server.state, &payload);
    assert_eq!(context.case.revision(), 0);

    let created = run(
        &server.state,
        &context,
        "create_new_network",
        json!({
            "name": "Office LAN",
            "subnet": "10.0.0.0/24",
            "networkType": "LAN",
            "description": "",
            "vlanId": null
        }),
    )
    .unwrap();
    assert_eq!(created["name"], "Office LAN");
    assert_eq!(
        context.case.revision(),
        1,
        "writes must be visible to pollers"
    );

    let listed = run(&server.state, &context, "list_networks", json!({})).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(
        context.case.revision(),
        1,
        "reads must not wake up every other browser"
    );

    // The commit carries the self-declared expert name from this session.
    let history = run(&server.state, &context, "list_case_history", json!({})).unwrap();
    let authors: Vec<&str> = history
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|commit| commit["author_name"].as_str())
        .collect();
    assert!(authors.contains(&"Expert A"), "{authors:?}");
}

#[test]
fn iocs_export_to_csv_and_stix_through_the_dispatcher() {
    let server = TempServer::new(true);
    let payload = create(&server.state, "correct-horse-battery").unwrap();
    let context = session(&server.state, &payload);

    for (ty, value, threat) in [
        ("IP", "10.0.0.9", "high"),
        ("Domain", "evil.example", "critical"),
    ] {
        run(
            &server.state,
            &context,
            "create_new_ioc",
            json!({ "iocType": ty, "value": value, "description": "", "threatLevel": threat }),
        )
        .unwrap();
    }
    // Exporting is read-only — it must not bump the revision pollers watch.
    let before = context.case.revision();

    let csv = run(&server.state, &context, "export_iocs_csv", json!({})).unwrap();
    let csv = csv.as_str().unwrap();
    assert!(csv.starts_with("id,type,value,threat_level"));
    assert!(csv.contains("10.0.0.9") && csv.contains("evil.example"));

    let stix = run(&server.state, &context, "export_iocs_stix", json!({})).unwrap();
    let bundle: serde_json::Value = serde_json::from_str(stix.as_str().unwrap()).unwrap();
    assert_eq!(bundle["type"], "bundle");
    assert_eq!(bundle["objects"].as_array().unwrap().len(), 2);

    assert_eq!(context.case.revision(), before, "exports are read-only");

    // The optional id filter limits the export to a subset.
    let list = run(&server.state, &context, "list_iocs", json!({})).unwrap();
    let one_id = list[0]["id"].as_str().unwrap().to_string();
    let subset = run(
        &server.state,
        &context,
        "export_iocs_stix",
        json!({ "ids": [one_id] }),
    )
    .unwrap();
    let subset: serde_json::Value = serde_json::from_str(subset.as_str().unwrap()).unwrap();
    assert_eq!(subset["objects"].as_array().unwrap().len(), 1);
}

#[test]
fn unknown_commands_are_reported_rather_than_ignored() {
    let server = TempServer::new(true);
    let payload = create(&server.state, "correct-horse-battery").unwrap();
    let context = session(&server.state, &payload);
    let error = run(&server.state, &context, "drop_everything", json!({})).unwrap_err();
    assert!(error.contains("Unknown command"), "{error}");
}

#[test]
fn changing_the_password_signs_every_other_expert_out() {
    let server = TempServer::new(true);
    let alice = create(&server.state, "correct-horse-battery").unwrap();
    let bob = unlock(
        &server.state,
        &alice.case_id,
        "correct-horse-battery",
        "Expert B",
    )
    .unwrap();
    let context = session(&server.state, &alice);

    run(
        &server.state,
        &context,
        "change_database_password",
        json!({ "currentPassword": "correct-horse-battery", "newPassword": "a-longer-passphrase" }),
    )
    .unwrap();

    // Bob's token was issued against the old password.
    assert!(server.state.touch_session(&bob.token).is_none());
    assert!(server.state.touch_session(&alice.token).is_some());

    // And the file really is rekeyed.
    assert!(unlock(
        &server.state,
        &alice.case_id,
        "correct-horse-battery",
        "Expert B"
    )
    .is_err());
}

#[test]
fn a_wrong_current_password_cannot_rekey_the_case() {
    let server = TempServer::new(true);
    let alice = create(&server.state, "correct-horse-battery").unwrap();
    let context = session(&server.state, &alice);

    let error = run(
        &server.state,
        &context,
        "change_database_password",
        json!({ "currentPassword": "not-the-password", "newPassword": "a-longer-passphrase" }),
    )
    .unwrap_err();
    assert!(!error.is_empty());

    // The original password still opens the case.
    assert!(unlock(
        &server.state,
        &alice.case_id,
        "correct-horse-battery",
        "Expert B"
    )
    .is_ok());
}
