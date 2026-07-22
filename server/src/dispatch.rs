//! The command surface.
//!
//! The desktop app exposes ~79 `#[tauri::command]` functions and the frontend
//! reaches them with `invoke(name, args)`. That maps onto HTTP without any
//! reshaping: `POST /api/cmd/{name}` with the same JSON argument object and the
//! same `{ success, data, error }` reply. Argument keys stay camelCase, which is
//! what Tauri's own serializer produced, so no call site in the frontend
//! changes.
//!
//! Commands that opened a native file dialog cannot exist here — see the
//! `render_export_report` / `load_change_bundle_text` arms for how those split
//! into "server returns the text, browser downloads it" and "browser reads the
//! file, server takes the text".

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::Json;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::auth::SessionContext;
use crate::db::{
    create_asset, create_clock_profile, create_firewall, create_firewall_interface,
    create_firewall_nat_rule, create_ioc, create_network, create_network_connection,
    create_network_interface, create_note, create_timeline_event, delete_asset,
    delete_clock_profile, delete_firewall, delete_firewall_interface, delete_firewall_nat_rule,
    delete_ioc, delete_network, delete_network_connection, delete_network_interface, delete_note,
    delete_timeline_event, export_case_data, get_assets, get_assets_by_network, get_case,
    get_clock_profiles, get_firewall_interfaces, get_firewall_nat_rules, get_firewalls, get_iocs,
    get_network_connections, get_network_interfaces, get_networks, get_notes, get_timeline_events,
    get_topology_view, import_case_data, parse_timestamp_preview, save_topology_view,
    set_primary_interface, update_asset, update_asset_suspicious, update_case, update_clock_profile,
    update_firewall, update_firewall_interface, update_firewall_nat_rule, update_ioc,
    update_network, update_network_connection, update_network_interface, update_note,
    update_timeline_event, ExportData, TopologyNodePosition,
};
use crate::history::{
    apply_bundle, get_history, parse_change_bundle, preview_bundle, ActorIdentity, MergeDecision,
};
use crate::partial_import::{
    apply_partial_import, partial_import_template, preview_partial_import,
    validate_partial_selection,
};
use crate::portable_export::{decode_portable_text, encode_portable_text, render_export_text};
use crate::secure_db::{
    open_encrypted_connection, rekey_connection, validate_database_password,
    verify_cipher_integrity,
};
use crate::state::{AppState, PendingBundle};

pub async fn dispatch(
    State(state): State<Arc<AppState>>,
    session: SessionContext,
    Path(command): Path<String>,
    body: Bytes,
) -> Json<Value> {
    let args = if body.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_slice::<Value>(&body)
            .map_err(|error| format!("Invalid request body: {error}"))
    };

    let outcome = args.and_then(|args| run(&state, &session, &command, args));
    Json(match outcome {
        Ok(data) => json!({ "success": true, "data": data, "error": Value::Null }),
        Err(error) => json!({ "success": false, "data": Value::Null, "error": error }),
    })
}

pub(crate) fn run(
    state: &Arc<AppState>,
    session: &SessionContext,
    command: &str,
    args: Value,
) -> Result<Value, String> {
    let case = &session.case;

    // Both macros are defined here rather than at module level on purpose:
    // `macro_rules!` locals are hygienic, so a macro body can only refer to
    // `case`, `args`, and `session` if those bindings are in scope where the
    // macro itself is written. Only one match arm ever runs, so each arm is
    // free to move `args`.

    // Read-only command: takes the case connection, returns JSON.
    macro_rules! read_cmd {
        ($params:ty, |$conn:ident, $p:ident| $body:expr) => {{
            let $p: $params = from_args(args)?;
            to_json(case.with_conn(|$conn| $body)?)
        }};
    }

    // Mutating command: same, plus the session's expert identity for history
    // attribution, and a revision bump so other browsers notice the change.
    macro_rules! write_cmd {
        ($params:ty, |$conn:ident, $actor:ident, $p:ident| $body:expr) => {{
            let $p: $params = from_args(args)?;
            let $actor: &ActorIdentity = &session.actor;
            let value = case.with_conn(|$conn| $body)?;
            case.bump();
            to_json(value)
        }};
    }

    match command {
        // ---- session and case -------------------------------------------
        "set_current_expert" => {
            let p: ExpertParams = from_args(args)?;
            let actor = ActorIdentity::new(p.name, p.scope_label, p.scope_network_ids)?;
            state.set_session_actor(&session.token, actor.clone())?;
            to_json(actor)
        }
        "get_current_expert" => to_json(Some(session.actor.clone())),
        "get_current_case_info" => read_cmd!(NoParams, |conn, _p| get_case(conn)),
        "update_current_case" => write_cmd!(CaseParams, |conn, actor, p| update_case(
            conn,
            actor,
            &p.name,
            &p.description,
            &p.client_name,
            &p.status
        )),
        // The browser equivalent of "Lock / Close Case": drop this session. The
        // connection itself closes once the last expert has left.
        "close_current_case" => {
            state.end_session(&session.token);
            to_json(true)
        }
        "get_db_path" => to_json(Some(case.id.clone())),
        "change_database_password" => {
            let p: ChangePasswordParams = from_args(args)?;
            let current = Zeroizing::new(p.current_password);
            let new = Zeroizing::new(p.new_password);
            validate_database_password(new.as_str())?;
            // Prove the caller knows the current password before rekeying.
            open_encrypted_connection(&case.path, current.as_str())?;
            case.with_conn(|conn| {
                rekey_connection(conn, new.as_str())?;
                verify_cipher_integrity(conn)
            })?;
            open_encrypted_connection(&case.path, new.as_str())
                .map_err(|error| format!("Password changed but verification failed: {error}"))?;
            // Every other token was issued against the old password.
            state.end_other_sessions(&case.id, &session.token);
            case.bump();
            to_json(true)
        }

        // ---- networks -----------------------------------------------------
        "create_new_network" => write_cmd!(NetworkParams, |conn, actor, p| create_network(
            conn,
            actor,
            &p.name,
            &p.subnet,
            &p.network_type,
            &p.description,
            p.vlan_id.as_deref()
        )),
        "update_existing_network" => write_cmd!(NetworkUpdateParams, |conn, actor, p| {
            update_network(
                conn,
                actor,
                &p.id,
                &p.name,
                &p.subnet,
                &p.network_type,
                &p.description,
                p.vlan_id.as_deref(),
            )
        }),
        "list_networks" => read_cmd!(NoParams, |conn, _p| get_networks(conn)),
        "remove_network" => write_cmd!(IdParams, |conn, actor, p| delete_network(
            conn, actor, &p.id
        )
        .map(|_| true)),
        "get_topology_view" => {
            read_cmd!(LayoutParams, |conn, p| get_topology_view(conn, &p.layout))
        }
        // Saved layouts are not history-tracked, but they are still a write the
        // other browsers should pick up.
        "save_topology_view" => {
            let p: TopologyViewParams = from_args(args)?;
            let view = case.with_conn(|conn| {
                save_topology_view(conn, &p.layout, p.positions, p.zoom, p.pan_x, p.pan_y)
            })?;
            case.bump();
            to_json(view)
        }

        // ---- assets -------------------------------------------------------
        "create_new_asset" => write_cmd!(AssetParams, |conn, actor, p| create_asset(
            conn,
            actor,
            p.network_id.as_deref(),
            &p.name,
            &p.ip_address,
            p.mac_address.as_deref(),
            &p.asset_type,
            p.os.as_deref(),
            p.user_name.as_deref(),
            &p.compromise_status,
            &p.investigation_status,
            p.properties.as_deref(),
            p.scan_results.as_deref()
        )),
        "update_existing_asset" => write_cmd!(AssetUpdateParams, |conn, actor, p| update_asset(
            conn,
            actor,
            &p.id,
            p.network_id.as_deref(),
            &p.name,
            &p.ip_address,
            p.mac_address.as_deref(),
            &p.asset_type,
            p.os.as_deref(),
            p.user_name.as_deref(),
            &p.compromise_status,
            &p.investigation_status,
            p.properties.as_deref(),
            p.scan_results.as_deref()
        )),
        "list_assets" => read_cmd!(NoParams, |conn, _p| get_assets(conn)),
        "list_assets_by_network" => read_cmd!(NetworkIdParams, |conn, p| get_assets_by_network(
            conn,
            &p.network_id
        )),
        "set_asset_suspicious" => write_cmd!(SuspiciousParams, |conn, actor, p| {
            update_asset_suspicious(conn, actor, &p.id, p.suspicious).map(|_| true)
        }),
        "remove_asset" => write_cmd!(IdParams, |conn, actor, p| delete_asset(conn, actor, &p.id)
            .map(|_| true)),

        // ---- network interfaces -------------------------------------------
        "list_network_interfaces" => read_cmd!(AssetFilterParams, |conn, p| {
            get_network_interfaces(conn, p.asset_id.as_deref())
        }),
        "create_new_network_interface" => {
            write_cmd!(InterfaceParams, |conn, actor, p| create_network_interface(
                conn,
                actor,
                &p.asset_id,
                &p.name,
                &p.ip_address,
                p.mac_address.as_deref(),
                p.network_id.as_deref(),
                p.is_primary
            ))
        }
        "update_existing_network_interface" => {
            write_cmd!(InterfaceUpdateParams, |conn, actor, p| {
                update_network_interface(
                    conn,
                    actor,
                    &p.id,
                    &p.name,
                    &p.ip_address,
                    p.mac_address.as_deref(),
                    p.network_id.as_deref(),
                    p.is_primary,
                )
            })
        }
        "set_primary_network_interface" => write_cmd!(IdParams, |conn, actor, p| {
            set_primary_interface(conn, actor, &p.id)
        }),
        "remove_network_interface" => write_cmd!(IdParams, |conn, actor, p| {
            delete_network_interface(conn, actor, &p.id).map(|_| true)
        }),

        // ---- clock correction ---------------------------------------------
        "preview_timestamp" => {
            let p: TimestampParams = from_args(args)?;
            to_json(parse_timestamp_preview(
                &p.input,
                &p.timezone,
                p.offset_ms.unwrap_or(0),
            )?)
        }
        "list_clock_profiles" => read_cmd!(NoParams, |conn, _p| get_clock_profiles(conn)),
        "create_new_clock_profile" => write_cmd!(ClockParams, |conn, actor, p| {
            create_clock_profile(
                conn,
                actor,
                &p.name,
                &p.description,
                &p.server_reference_raw,
                &p.server_timezone,
                &p.correct_reference_raw,
                &p.correct_timezone,
            )
        }),
        "update_existing_clock_profile" => write_cmd!(ClockUpdateParams, |conn, actor, p| {
            update_clock_profile(
                conn,
                actor,
                &p.id,
                &p.name,
                &p.description,
                &p.server_reference_raw,
                &p.server_timezone,
                &p.correct_reference_raw,
                &p.correct_timezone,
            )
        }),
        "remove_clock_profile" => write_cmd!(IdParams, |conn, actor, p| {
            delete_clock_profile(conn, actor, &p.id).map(|_| true)
        }),

        // ---- timeline ------------------------------------------------------
        "create_new_timeline_event" => write_cmd!(TimelineParams, |conn, actor, p| {
            create_timeline_event(
                conn,
                actor,
                p.asset_id.as_deref(),
                p.server_timestamp.as_deref(),
                p.server_timezone.as_deref(),
                p.correct_timestamp.as_deref(),
                p.correct_timezone.as_deref(),
                p.clock_profile_id.as_deref(),
                &p.event_type,
                &p.description,
                &p.severity,
                p.source.as_deref(),
                p.mitre_tactic.as_deref(),
                p.mitre_technique.as_deref(),
            )
        }),
        "update_existing_timeline_event" => write_cmd!(TimelineUpdateParams, |conn, actor, p| {
            update_timeline_event(
                conn,
                actor,
                &p.id,
                p.asset_id.as_deref(),
                p.server_timestamp.as_deref(),
                p.server_timezone.as_deref(),
                p.correct_timestamp.as_deref(),
                p.correct_timezone.as_deref(),
                p.clock_profile_id.as_deref(),
                &p.event_type,
                &p.description,
                &p.severity,
                p.source.as_deref(),
                p.mitre_tactic.as_deref(),
                p.mitre_technique.as_deref(),
            )
        }),
        "list_timeline_events" => read_cmd!(NoParams, |conn, _p| get_timeline_events(conn)),
        "remove_timeline_event" => write_cmd!(IdParams, |conn, actor, p| {
            delete_timeline_event(conn, actor, &p.id).map(|_| true)
        }),

        // ---- notes ---------------------------------------------------------
        "create_new_note" => write_cmd!(NoteParams, |conn, actor, p| create_note(
            conn,
            actor,
            &p.title,
            &p.content
        )),
        "list_notes" => read_cmd!(NoParams, |conn, _p| get_notes(conn)),
        "update_existing_note" => write_cmd!(NoteUpdateParams, |conn, actor, p| update_note(
            conn,
            actor,
            &p.id,
            &p.title,
            &p.content
        )),
        "remove_note" => write_cmd!(IdParams, |conn, actor, p| delete_note(conn, actor, &p.id)
            .map(|_| true)),

        // ---- IOCs ----------------------------------------------------------
        "create_new_ioc" => write_cmd!(IocParams, |conn, actor, p| create_ioc(
            conn,
            actor,
            &p.ioc_type,
            &p.value,
            &p.description,
            &p.threat_level,
            p.first_seen.as_deref(),
            p.last_seen.as_deref()
        )),
        "update_existing_ioc" => write_cmd!(IocUpdateParams, |conn, actor, p| update_ioc(
            conn,
            actor,
            &p.id,
            &p.ioc_type,
            &p.value,
            &p.description,
            &p.threat_level,
            p.first_seen.as_deref(),
            p.last_seen.as_deref()
        )),
        "list_iocs" => read_cmd!(NoParams, |conn, _p| get_iocs(conn)),
        "remove_ioc" => write_cmd!(IdParams, |conn, actor, p| delete_ioc(conn, actor, &p.id)
            .map(|_| true)),

        // ---- firewalls -----------------------------------------------------
        "create_new_firewall" => write_cmd!(FirewallParams, |conn, actor, p| create_firewall(
            conn,
            actor,
            p.network_id.as_deref(),
            &p.name,
            p.vendor.as_deref(),
            p.model.as_deref(),
            p.rules.as_deref(),
            p.config_text.as_deref()
        )),
        "update_existing_firewall" => write_cmd!(FirewallUpdateParams, |conn, actor, p| {
            update_firewall(
                conn,
                actor,
                &p.id,
                p.network_id.as_deref(),
                &p.name,
                p.vendor.as_deref(),
                p.model.as_deref(),
                p.rules.as_deref(),
                p.config_text.as_deref(),
            )
        }),
        "list_firewalls" => read_cmd!(NoParams, |conn, _p| get_firewalls(conn)),
        "remove_firewall" => write_cmd!(IdParams, |conn, actor, p| {
            delete_firewall(conn, actor, &p.id).map(|_| true)
        }),
        "list_firewall_interfaces" => read_cmd!(FirewallFilterParams, |conn, p| {
            get_firewall_interfaces(conn, p.firewall_id.as_deref())
        }),
        "create_new_firewall_interface" => write_cmd!(FirewallInterfaceParams, |conn, actor, p| {
            create_firewall_interface(
                conn,
                actor,
                &p.firewall_id,
                &p.name,
                p.ip_addresses,
                p.mac_address.as_deref(),
                p.network_id.as_deref(),
                p.vlan_id.as_deref(),
                &p.role,
                p.is_primary,
                &p.description,
            )
        }),
        "update_existing_firewall_interface" => {
            write_cmd!(FirewallInterfaceUpdateParams, |conn, actor, p| {
                update_firewall_interface(
                    conn,
                    actor,
                    &p.id,
                    &p.name,
                    p.ip_addresses,
                    p.mac_address.as_deref(),
                    p.network_id.as_deref(),
                    p.vlan_id.as_deref(),
                    &p.role,
                    p.is_primary,
                    &p.description,
                )
            })
        }
        "remove_firewall_interface" => write_cmd!(IdParams, |conn, actor, p| {
            delete_firewall_interface(conn, actor, &p.id).map(|_| true)
        }),
        "list_firewall_nat_rules" => read_cmd!(FirewallFilterParams, |conn, p| {
            get_firewall_nat_rules(conn, p.firewall_id.as_deref())
        }),
        "create_new_firewall_nat_rule" => write_cmd!(NatRuleParams, |conn, actor, p| {
            create_firewall_nat_rule(
                conn,
                actor,
                &p.firewall_id,
                &p.name,
                &p.nat_type,
                p.enabled,
                &p.protocol,
                p.source_cidr.as_deref(),
                p.original_destination.as_deref(),
                p.original_port.as_deref(),
                p.translated_source.as_deref(),
                p.translated_destination.as_deref(),
                p.translated_port.as_deref(),
                p.inbound_interface_id.as_deref(),
                p.outbound_interface_id.as_deref(),
                &p.description,
            )
        }),
        "update_existing_firewall_nat_rule" => write_cmd!(NatRuleUpdateParams, |conn, actor, p| {
            update_firewall_nat_rule(
                conn,
                actor,
                &p.id,
                &p.name,
                &p.nat_type,
                p.enabled,
                &p.protocol,
                p.source_cidr.as_deref(),
                p.original_destination.as_deref(),
                p.original_port.as_deref(),
                p.translated_source.as_deref(),
                p.translated_destination.as_deref(),
                p.translated_port.as_deref(),
                p.inbound_interface_id.as_deref(),
                p.outbound_interface_id.as_deref(),
                &p.description,
            )
        }),
        "remove_firewall_nat_rule" => write_cmd!(IdParams, |conn, actor, p| {
            delete_firewall_nat_rule(conn, actor, &p.id).map(|_| true)
        }),

        // ---- zone-to-zone connections --------------------------------------
        "create_new_network_connection" => write_cmd!(ConnectionParams, |conn, actor, p| {
            create_network_connection(
                conn,
                actor,
                &p.source_network_id,
                &p.target_network_id,
                &p.connection_type,
                &p.description,
                p.device_name.as_deref(),
            )
        }),
        "update_existing_network_connection" => {
            write_cmd!(ConnectionUpdateParams, |conn, actor, p| {
                update_network_connection(
                    conn,
                    actor,
                    &p.id,
                    &p.source_network_id,
                    &p.target_network_id,
                    &p.connection_type,
                    &p.description,
                    p.device_name.as_deref(),
                )
            })
        }
        "list_network_connections" => read_cmd!(NoParams, |conn, _p| get_network_connections(conn)),
        "remove_network_connection" => write_cmd!(IdParams, |conn, actor, p| {
            delete_network_connection(conn, actor, &p.id).map(|_| true)
        }),

        // ---- snapshots -----------------------------------------------------
        // The browser downloads what this returns; there is no server-side save
        // dialog. Encryption is untouched, so a `.dfirx` written here opens in
        // the desktop build and vice versa.
        "export_case_json" => {
            let p: PasswordParams = from_args(args)?;
            let password = optional_password(p.password);
            to_json(case.with_conn(|conn| {
                let json = serde_json::to_string_pretty(&export_case_data(conn)?)
                    .map_err(|error| error.to_string())?;
                encode_portable_text(&json, password_ref(&password))
            })?)
        }
        // Also the upload path: the browser reads the chosen file and posts its
        // text, which is what `load_import_from_file` used to read from disk.
        "import_case_json" => {
            let p: ImportParams = from_args(args)?;
            let password = optional_password(p.password);
            let decoded = decode_portable_text(&p.json_data, password_ref(&password))?;
            let data: ExportData = serde_json::from_str(&decoded.plaintext)
                .map_err(|error| format!("Invalid case JSON: {error}"))?;
            let actor = &session.actor;
            let summary = case.with_conn(|conn| import_case_data(conn, actor, &data))?;
            case.bump();
            to_json(summary)
        }
        // Read-only text rendering of an uploaded snapshot or bundle.
        "render_export_report" => {
            let p: ReportParams = from_args(args)?;
            let password = optional_password(p.password);
            let decoded = decode_portable_text(&p.contents, password_ref(&password))?;
            to_json(render_export_text(&decoded.plaintext)?)
        }

        // ---- partial import -------------------------------------------------
        "get_partial_import_template" => {
            read_cmd!(NoParams, |conn, _p| partial_import_template(conn))
        }
        "preview_partial_import_text" => {
            let p: PartialTextParams = from_args(args)?;
            let prepared = case.with_conn(|conn| preview_partial_import(conn, &p.json_data))?;
            let preview = prepared.preview.clone();
            case.pending_partial_imports
                .lock()
                .map_err(|_| "Pending partial-import lock poisoned".to_string())?
                .insert(preview.preview_id.clone(), prepared);
            to_json(preview)
        }
        "validate_pending_partial_import" => {
            let p: PartialSelectionParams = from_args(args)?;
            let pending = pending_partial(session, &p.preview_id)?;
            to_json(case.with_conn(|conn| {
                Ok(validate_partial_selection(
                    conn,
                    &pending,
                    &p.selected_change_ids,
                ))
            })?)
        }
        "apply_pending_partial_import" => {
            let p: PartialSelectionParams = from_args(args)?;
            let pending = pending_partial(session, &p.preview_id)?;
            let actor = &session.actor;
            let summary = case.with_conn(|conn| {
                apply_partial_import(conn, actor, &pending, &p.selected_change_ids)
            })?;
            if let Ok(mut guard) = case.pending_partial_imports.lock() {
                guard.remove(&p.preview_id);
            }
            case.bump();
            to_json(summary)
        }
        "discard_pending_partial_import" => {
            let p: PreviewIdParams = from_args(args)?;
            let removed = case
                .pending_partial_imports
                .lock()
                .map_err(|_| "Pending partial-import lock poisoned".to_string())?
                .remove(&p.preview_id)
                .is_some();
            to_json(removed)
        }

        // ---- history and offline expert bundles ------------------------------
        // Day-to-day merging is gone: everyone writes to this one case. What is
        // kept is the way back in for an expert who worked offline.
        "list_case_history" => read_cmd!(HistoryParams, |conn, p| get_history(
            conn,
            p.limit.unwrap_or(100).min(1000)
        )),
        "load_change_bundle_text" => {
            let p: ReportParams = from_args(args)?;
            let password = optional_password(p.password);
            let decoded = decode_portable_text(&p.contents, password_ref(&password))?;
            let bundle = parse_change_bundle(&decoded.plaintext)?;
            let preview = case.with_conn(|conn| preview_bundle(conn, &bundle))?;
            case.pending_bundles
                .lock()
                .map_err(|_| "Pending merge lock poisoned".to_string())?
                .insert(
                    bundle.bundle_id.clone(),
                    PendingBundle {
                        bundle,
                        preview: preview.clone(),
                    },
                );
            to_json(preview)
        }
        "refresh_pending_change_bundle" => {
            let p: BundleIdParams = from_args(args)?;
            let bundle = {
                let guard = case
                    .pending_bundles
                    .lock()
                    .map_err(|_| "Pending merge lock poisoned".to_string())?;
                guard
                    .get(&p.bundle_id)
                    .map(|pending| pending.bundle.clone())
                    .ok_or_else(|| "Pending bundle was not found".to_string())?
            };
            let preview = case.with_conn(|conn| preview_bundle(conn, &bundle))?;
            if let Ok(mut guard) = case.pending_bundles.lock() {
                if let Some(pending) = guard.get_mut(&p.bundle_id) {
                    pending.preview = preview.clone();
                }
            }
            to_json(preview)
        }
        "apply_pending_change_bundle" => {
            let p: ApplyBundleParams = from_args(args)?;
            let (bundle, preview) = {
                let guard = case
                    .pending_bundles
                    .lock()
                    .map_err(|_| "Pending merge lock poisoned".to_string())?;
                let pending = guard
                    .get(&p.bundle_id)
                    .ok_or_else(|| "Pending bundle was not found".to_string())?;
                (pending.bundle.clone(), pending.preview.clone())
            };
            let actor = &session.actor;
            let summary = case.with_conn(|conn| {
                apply_bundle(conn, actor, &bundle, &preview, &p.decisions)
            })?;
            if let Ok(mut guard) = case.pending_bundles.lock() {
                guard.remove(&p.bundle_id);
            }
            case.bump();
            to_json(summary)
        }
        "discard_pending_change_bundle" => {
            let p: BundleIdParams = from_args(args)?;
            let removed = case
                .pending_bundles
                .lock()
                .map_err(|_| "Pending merge lock poisoned".to_string())?
                .remove(&p.bundle_id)
                .is_some();
            to_json(removed)
        }

        other => Err(format!("Unknown command: {other}")),
    }
}

fn pending_partial(
    session: &SessionContext,
    preview_id: &str,
) -> Result<crate::partial_import::PreparedPartialImport, String> {
    session
        .case
        .pending_partial_imports
        .lock()
        .map_err(|_| "Pending partial-import lock poisoned".to_string())?
        .get(preview_id)
        .cloned()
        .ok_or_else(|| "Pending partial import was not found".to_string())
}

fn from_args<T: DeserializeOwned>(args: Value) -> Result<T, String> {
    serde_json::from_value(args).map_err(|error| format!("Invalid arguments: {error}"))
}

fn to_json<T: Serialize>(value: T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| error.to_string())
}

fn optional_password(password: Option<String>) -> Option<Zeroizing<String>> {
    password
        .filter(|value| !value.is_empty())
        .map(Zeroizing::new)
}

fn password_ref(password: &Option<Zeroizing<String>>) -> Option<&str> {
    password.as_ref().map(|value| value.as_str())
}

// ---- argument shapes -----------------------------------------------------
//
// One struct per command signature, camelCase to match what the frontend
// already sends. `#[serde(default)]` stands in for the desktop `Option<T>`
// parameters that Tauri filled in when the key was absent.

macro_rules! params {
    ($(
        $(#[$meta:meta])*
        struct $name:ident { $( $(#[$field_meta:meta])* $field:ident : $ty:ty ),* $(,)? }
    )*) => {
        $(
            $(#[$meta])*
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct $name { $( $(#[$field_meta])* #[allow(dead_code)] $field: $ty ),* }
        )*
    };
}

#[derive(Deserialize)]
struct NoParams {}

params! {
    struct IdParams { id: String }
    struct PreviewIdParams { preview_id: String }
    struct BundleIdParams { bundle_id: String }
    struct NetworkIdParams { network_id: String }
    struct LayoutParams { layout: String }
    struct ExpertParams {
        name: String,
        #[serde(default)] scope_label: Option<String>,
        #[serde(default)] scope_network_ids: Vec<String>,
    }
    struct CaseParams { name: String, description: String, client_name: String, status: String }
    struct ChangePasswordParams { current_password: String, new_password: String }
    struct PasswordParams { #[serde(default)] password: Option<String> }
    struct ImportParams { json_data: String, #[serde(default)] password: Option<String> }
    struct ReportParams { contents: String, #[serde(default)] password: Option<String> }
    struct PartialTextParams { json_data: String }
    struct PartialSelectionParams { preview_id: String, selected_change_ids: Vec<String> }
    struct HistoryParams { #[serde(default)] limit: Option<usize> }
    struct ApplyBundleParams { bundle_id: String, decisions: Vec<MergeDecision> }

    struct NetworkParams {
        name: String,
        subnet: String,
        network_type: String,
        description: String,
        #[serde(default)] vlan_id: Option<String>,
    }
    struct NetworkUpdateParams {
        id: String,
        name: String,
        subnet: String,
        network_type: String,
        description: String,
        #[serde(default)] vlan_id: Option<String>,
    }
    struct TopologyViewParams {
        layout: String,
        positions: Vec<TopologyNodePosition>,
        zoom: f64,
        pan_x: f64,
        pan_y: f64,
    }

    struct AssetParams {
        #[serde(default)] network_id: Option<String>,
        name: String,
        ip_address: String,
        #[serde(default)] mac_address: Option<String>,
        asset_type: String,
        #[serde(default)] os: Option<String>,
        #[serde(default)] user_name: Option<String>,
        compromise_status: String,
        investigation_status: String,
        #[serde(default)] properties: Option<String>,
        #[serde(default)] scan_results: Option<String>,
    }
    struct AssetUpdateParams {
        id: String,
        #[serde(default)] network_id: Option<String>,
        name: String,
        ip_address: String,
        #[serde(default)] mac_address: Option<String>,
        asset_type: String,
        #[serde(default)] os: Option<String>,
        #[serde(default)] user_name: Option<String>,
        compromise_status: String,
        investigation_status: String,
        #[serde(default)] properties: Option<String>,
        #[serde(default)] scan_results: Option<String>,
    }
    struct SuspiciousParams { id: String, suspicious: bool }
    struct AssetFilterParams { #[serde(default)] asset_id: Option<String> }

    struct InterfaceParams {
        asset_id: String,
        name: String,
        ip_address: String,
        #[serde(default)] mac_address: Option<String>,
        #[serde(default)] network_id: Option<String>,
        is_primary: bool,
    }
    struct InterfaceUpdateParams {
        id: String,
        name: String,
        ip_address: String,
        #[serde(default)] mac_address: Option<String>,
        #[serde(default)] network_id: Option<String>,
        is_primary: bool,
    }

    struct TimestampParams {
        input: String,
        timezone: String,
        #[serde(default)] offset_ms: Option<i64>,
    }
    struct ClockParams {
        name: String,
        description: String,
        server_reference_raw: String,
        server_timezone: String,
        correct_reference_raw: String,
        correct_timezone: String,
    }
    struct ClockUpdateParams {
        id: String,
        name: String,
        description: String,
        server_reference_raw: String,
        server_timezone: String,
        correct_reference_raw: String,
        correct_timezone: String,
    }

    struct TimelineParams {
        #[serde(default)] asset_id: Option<String>,
        #[serde(default)] server_timestamp: Option<String>,
        #[serde(default)] server_timezone: Option<String>,
        #[serde(default)] correct_timestamp: Option<String>,
        #[serde(default)] correct_timezone: Option<String>,
        #[serde(default)] clock_profile_id: Option<String>,
        event_type: String,
        description: String,
        severity: String,
        #[serde(default)] source: Option<String>,
        #[serde(default)] mitre_tactic: Option<String>,
        #[serde(default)] mitre_technique: Option<String>,
    }
    struct TimelineUpdateParams {
        id: String,
        #[serde(default)] asset_id: Option<String>,
        #[serde(default)] server_timestamp: Option<String>,
        #[serde(default)] server_timezone: Option<String>,
        #[serde(default)] correct_timestamp: Option<String>,
        #[serde(default)] correct_timezone: Option<String>,
        #[serde(default)] clock_profile_id: Option<String>,
        event_type: String,
        description: String,
        severity: String,
        #[serde(default)] source: Option<String>,
        #[serde(default)] mitre_tactic: Option<String>,
        #[serde(default)] mitre_technique: Option<String>,
    }

    struct NoteParams { title: String, content: String }
    struct NoteUpdateParams { id: String, title: String, content: String }

    struct IocParams {
        ioc_type: String,
        value: String,
        description: String,
        threat_level: String,
        #[serde(default)] first_seen: Option<String>,
        #[serde(default)] last_seen: Option<String>,
    }
    struct IocUpdateParams {
        id: String,
        ioc_type: String,
        value: String,
        description: String,
        threat_level: String,
        #[serde(default)] first_seen: Option<String>,
        #[serde(default)] last_seen: Option<String>,
    }

    struct FirewallParams {
        #[serde(default)] network_id: Option<String>,
        name: String,
        #[serde(default)] vendor: Option<String>,
        #[serde(default)] model: Option<String>,
        #[serde(default)] rules: Option<String>,
        #[serde(default)] config_text: Option<String>,
    }
    struct FirewallUpdateParams {
        id: String,
        #[serde(default)] network_id: Option<String>,
        name: String,
        #[serde(default)] vendor: Option<String>,
        #[serde(default)] model: Option<String>,
        #[serde(default)] rules: Option<String>,
        #[serde(default)] config_text: Option<String>,
    }
    struct FirewallFilterParams { #[serde(default)] firewall_id: Option<String> }
    struct FirewallInterfaceParams {
        firewall_id: String,
        name: String,
        ip_addresses: Vec<String>,
        #[serde(default)] mac_address: Option<String>,
        #[serde(default)] network_id: Option<String>,
        #[serde(default)] vlan_id: Option<String>,
        role: String,
        is_primary: bool,
        description: String,
    }
    struct FirewallInterfaceUpdateParams {
        id: String,
        name: String,
        ip_addresses: Vec<String>,
        #[serde(default)] mac_address: Option<String>,
        #[serde(default)] network_id: Option<String>,
        #[serde(default)] vlan_id: Option<String>,
        role: String,
        is_primary: bool,
        description: String,
    }
    struct NatRuleParams {
        firewall_id: String,
        name: String,
        nat_type: String,
        enabled: bool,
        protocol: String,
        #[serde(default)] source_cidr: Option<String>,
        #[serde(default)] original_destination: Option<String>,
        #[serde(default)] original_port: Option<String>,
        #[serde(default)] translated_source: Option<String>,
        #[serde(default)] translated_destination: Option<String>,
        #[serde(default)] translated_port: Option<String>,
        #[serde(default)] inbound_interface_id: Option<String>,
        #[serde(default)] outbound_interface_id: Option<String>,
        description: String,
    }
    struct NatRuleUpdateParams {
        id: String,
        name: String,
        nat_type: String,
        enabled: bool,
        protocol: String,
        #[serde(default)] source_cidr: Option<String>,
        #[serde(default)] original_destination: Option<String>,
        #[serde(default)] original_port: Option<String>,
        #[serde(default)] translated_source: Option<String>,
        #[serde(default)] translated_destination: Option<String>,
        #[serde(default)] translated_port: Option<String>,
        #[serde(default)] inbound_interface_id: Option<String>,
        #[serde(default)] outbound_interface_id: Option<String>,
        description: String,
    }

    struct ConnectionParams {
        source_network_id: String,
        target_network_id: String,
        connection_type: String,
        description: String,
        #[serde(default)] device_name: Option<String>,
    }
    struct ConnectionUpdateParams {
        id: String,
        source_network_id: String,
        target_network_id: String,
        connection_type: String,
        description: String,
        #[serde(default)] device_name: Option<String>,
    }
}
