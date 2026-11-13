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
            team: None,
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
            team: None,
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

#[test]
fn captures_drafts_and_search_work_through_the_dispatcher() {
    let server = TempServer::new(true);
    let payload = create(&server.state, "correct-horse-battery").unwrap();
    let context = session(&server.state, &payload);

    // A capture is case content: other browsers must hear about it.
    let capture = run(
        &server.state,
        &context,
        "create_new_capture",
        json!({ "content": "APP01, 10.0.0.15. Finance owns it.", "source": "Interview" }),
    )
    .unwrap();
    assert_eq!(capture["captured_by"], "Expert A");
    assert_eq!(context.case.revision(), 1);

    // Drafts are one expert's working state: saving them must not wake others.
    run(
        &server.state,
        &context,
        "save_case_drafts",
        json!({ "drafts": { "notes.title": "Half written" } }),
    )
    .unwrap();
    assert_eq!(
        context.case.revision(),
        1,
        "drafts must not bump the revision"
    );
    let drafts = run(&server.state, &context, "load_case_drafts", json!({})).unwrap();
    assert_eq!(drafts["notes.title"], "Half written");

    let hits = run(
        &server.state,
        &context,
        "search_case_records",
        json!({ "query": "finance" }),
    )
    .unwrap();
    assert_eq!(hits[0]["entity_type"], "capture");
    let status = run(&server.state, &context, "get_handover_status", json!({})).unwrap();
    assert!(status["commits_since_base"].as_u64().unwrap() >= 1);
}

#[test]
fn sites_relations_and_asset_merges_work_through_the_dispatcher() {
    let server = TempServer::new(true);
    let payload = create(&server.state, "correct-horse-battery").unwrap();
    let context = session(&server.state, &payload);

    let site = run(
        &server.state,
        &context,
        "create_new_site",
        json!({ "name": "HQ", "location": "Berlin" }),
    )
    .unwrap();
    assert_eq!(site["name"], "HQ");
    let revision = context.case.revision();
    assert!(revision >= 1, "a site is case content");

    // The nested context object carries camelCase keys like every other argument.
    let network = run(
        &server.state,
        &context,
        "create_new_network",
        json!({
            "name": "Office", "subnet": "10.0.0.0/24", "networkType": "LAN", "description": "",
            "context": { "siteId": site["id"], "owner": "IT", "operator": "MSP" }
        }),
    )
    .unwrap();
    assert_eq!(network["site_id"], site["id"]);
    assert_eq!(network["operator"], "MSP");

    let asset_args = |name: &str, ip: &str, asset_type: &str, extra: serde_json::Value| {
        let mut args = json!({
            "name": name, "ipAddress": ip, "assetType": asset_type,
            "compromiseStatus": "unknown", "investigationStatus": "not_started"
        });
        args["context"] = extra;
        args
    };
    let host = run(
        &server.state,
        &context,
        "create_new_asset",
        asset_args(
            "ESX01",
            "10.0.0.10",
            "hypervisor",
            json!({ "origin": "client_inventory", "siteId": site["id"] }),
        ),
    )
    .unwrap();
    let vm = run(&server.state, &context, "create_new_asset", asset_args("APP01", "10.0.0.15", "vm", json!({ "origin": "discovered", "lastObserved": "2026-11-13T10:00:00Z", "owner": "Finance" }))).unwrap();
    let copy = run(
        &server.state,
        &context,
        "create_new_asset",
        asset_args("app01.corp.local", "10.0.0.15", "vm", json!({})),
    )
    .unwrap();
    assert_eq!(host["origin"], "client_inventory");
    assert_eq!(vm["last_observed"], "2026-11-13T10:00:00.000Z");
    assert_eq!(copy["origin"], "unknown");

    // An update without a context leaves the environment fields alone.
    let renamed = run(
        &server.state,
        &context,
        "update_existing_asset",
        json!({
            "id": vm["id"], "networkId": vm["network_id"], "name": "APP01", "ipAddress": "10.0.0.15",
            "assetType": "vm", "compromiseStatus": "unknown", "investigationStatus": "in_progress"
        }),
    )
    .unwrap();
    assert_eq!(renamed["owner"], "Finance");
    assert_eq!(renamed["origin"], "discovered");

    let link = run(
        &server.state,
        &context,
        "create_new_asset_relation",
        json!({ "sourceAssetId": vm["id"], "targetAssetId": host["id"], "relationType": "runs_on" }),
    )
    .unwrap();
    assert_eq!(link["target_name"], "ESX01");
    let duplicate = run(
        &server.state,
        &context,
        "create_new_asset_relation",
        json!({ "sourceAssetId": vm["id"], "targetAssetId": host["id"], "relationType": "runs_on" }),
    );
    assert!(duplicate.unwrap_err().contains("already related"));
    let listed = run(&server.state, &context, "list_asset_relations", json!({})).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);

    let before = context.case.revision();
    let merged = run(
        &server.state,
        &context,
        "merge_asset_records",
        json!({ "keepId": vm["id"], "removeId": copy["id"] }),
    )
    .unwrap();
    assert_eq!(merged["asset"]["id"], vm["id"]);
    assert!(
        context.case.revision() > before,
        "a merge is a write the other browsers must hear about"
    );
    let assets = run(&server.state, &context, "list_assets", json!({})).unwrap();
    assert_eq!(assets.as_array().unwrap().len(), 2);

    // A site cannot go while something is at it.
    let refused = run(
        &server.state,
        &context,
        "remove_site",
        json!({ "id": site["id"] }),
    );
    assert!(refused.unwrap_err().contains("still used"));
    let hits = run(
        &server.state,
        &context,
        "search_case_records",
        json!({ "query": "berlin" }),
    )
    .unwrap();
    assert_eq!(hits[0]["entity_type"], "site");
}

#[test]
fn the_expert_team_travels_with_the_session_into_history() {
    let server = TempServer::new(true);
    let created = create(&server.state, "correct-horse-battery").unwrap();
    let payload = unlock_inner(
        &server.state,
        peer(),
        UnlockRequest {
            case_id: created.case_id.clone(),
            password: "correct-horse-battery".to_string(),
            expert_name: "Expert B".to_string(),
            scope_label: None,
            scope_network_ids: Vec::new(),
            team: Some("Log analysis".to_string()),
        },
    )
    .unwrap();
    assert_eq!(payload.expert.team.as_deref(), Some("Log analysis"));
    let context = session(&server.state, &payload);
    run(
        &server.state,
        &context,
        "create_new_capture",
        json!({ "content": "Proxy logs show beaconing every 60s" }),
    )
    .unwrap();
    let history = run(
        &server.state,
        &context,
        "list_case_history",
        json!({ "limit": 1 }),
    )
    .unwrap();
    assert_eq!(history[0]["scope"]["team"], "Log analysis");
}
