//! DFIR Network Investigator — centralized case server.
//!
//! This binary is a second shell over the exact same investigation core that the
//! Tauri desktop app compiles. The five modules below are included by path from
//! `../src-tauri/src/`: nothing under `src-tauri/` is modified, so the desktop
//! build and this server can never drift apart.
//!
//! Authentication is the case database password. There are no user accounts:
//! unlocking a SQLCipher case file *is* the login, and the expert name stays
//! self-declared attribution exactly as it is offline.

// The core modules resolve each other through `crate::db` / `crate::history`, so
// they have to be declared at the crate root.
//
// `allow(dead_code)` because these files serve two shells and this one uses a
// subset: `export_change_bundle` and `mark_shared_baseline` are meaningless when
// everyone writes to the same case, and `migrate_plaintext_database` needs two
// local paths a browser cannot supply. All three stay available to the desktop
// build. Do not delete them, and do not edit anything under `src-tauri/`.
#[allow(dead_code)]
#[path = "../../src-tauri/src/db.rs"]
mod db;
#[allow(dead_code)]
#[path = "../../src-tauri/src/history.rs"]
mod history;
#[allow(dead_code)]
#[path = "../../src-tauri/src/partial_import.rs"]
mod partial_import;
#[allow(dead_code)]
#[path = "../../src-tauri/src/portable_export.rs"]
mod portable_export;
#[allow(dead_code)]
#[path = "../../src-tauri/src/secure_db.rs"]
mod secure_db;

mod auth;
mod cases;
mod dispatch;
mod state;
#[cfg(test)]
mod tests;
mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue};
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::state::{AppState, ServerConfig};

/// Content Security Policy for the browser build, adapted from the desktop
/// `tauri.conf.json`. Same local-only posture: no remote content of any kind.
const CSP: &str = "default-src 'self'; \
connect-src 'self'; \
img-src 'self' data: blob:; \
style-src 'self' 'unsafe-inline'; \
font-src 'self' data:; \
script-src 'self'; \
object-src 'none'; \
base-uri 'none'; \
form-action 'none'; \
frame-ancestors 'none'";

/// A snapshot or bundle upload arrives as a command argument, so the command
/// route accepts the same size the desktop app accepts from disk.
const MAX_COMMAND_BYTES: usize = portable_export::MAX_PORTABLE_FILE_BYTES as usize;
/// Unlock, logout, case listing, and case creation are all small.
const MAX_SESSION_BYTES: usize = 64 * 1024;

#[derive(Parser, Debug)]
#[command(name = "dfir-server", version, about = "Centralized DFIR case server")]
struct Cli {
    /// Directory holding the SQLCipher `.db` case files.
    #[arg(long, default_value = "./cases")]
    cases: PathBuf,

    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:8443")]
    bind: SocketAddr,

    /// Directory containing the built frontend (`npm run build` output).
    #[arg(long, default_value = "./dist")]
    web: PathBuf,

    /// TLS certificate chain in PEM format. Generated self-signed when omitted.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// TLS private key in PEM format.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// Serve plain HTTP instead of HTTPS. Development only.
    #[arg(long)]
    insecure: bool,

    /// Allow creating new case files over HTTP.
    #[arg(long)]
    allow_create: bool,

    /// Idle minutes before a session is dropped.
    #[arg(long, default_value_t = 480)]
    session_timeout: u64,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(error) = std::fs::create_dir_all(&cli.cases) {
        eprintln!("Could not create case directory {}: {error}", cli.cases.display());
        std::process::exit(1);
    }
    let cases_dir = match cli.cases.canonicalize() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("Could not resolve case directory: {error}");
            std::process::exit(1);
        }
    };

    let state = Arc::new(AppState::new(ServerConfig {
        cases_dir,
        allow_create: cli.allow_create,
        session_timeout_secs: cli.session_timeout.saturating_mul(60),
    }));

    // `.layer` only wraps routes registered before it, so the session routes
    // keep the small limit and the command route gets the upload-sized one.
    let api = Router::new()
        .route("/api/cases", get(cases::list_cases).post(cases::create_case))
        .route("/api/auth/unlock", post(auth::unlock))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/state", get(auth::server_state))
        .layer(DefaultBodyLimit::max(MAX_SESSION_BYTES))
        .route(
            "/api/cmd/{command}",
            post(dispatch::dispatch).layer(DefaultBodyLimit::max(MAX_COMMAND_BYTES)),
        )
        .with_state(state.clone());

    let index = cli.web.join("index.html");
    let web = Router::new().fallback_service(
        ServeDir::new(&cli.web).not_found_service(ServeFile::new(&index)),
    );

    let app = api
        .merge(web)
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ));

    if !index.exists() {
        eprintln!(
            "warning: {} does not exist — run `npm run build` before serving the web UI",
            index.display()
        );
    }
    println!("DFIR case server");
    println!("  cases      {}", state.config.cases_dir.display());
    println!("  web root   {}", cli.web.display());
    println!(
        "  creation   {}",
        if state.config.allow_create {
            "enabled (--allow-create)"
        } else {
            "disabled"
        }
    );

    let served = if cli.insecure {
        println!("  transport  PLAIN HTTP (--insecure)");
        println!();
        println!("!! --insecure sends case passwords and case data in clear text.");
        println!("!! Use it for local development only.");
        println!();
        println!("  listening  http://{}", cli.bind);
        axum_server::bind(cli.bind)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
    } else {
        let config = match tls::load_or_generate(cli.tls_cert.as_deref(), cli.tls_key.as_deref(), &state.config.cases_dir) {
            Ok(config) => config,
            Err(error) => {
                eprintln!("TLS setup failed: {error}");
                std::process::exit(1);
            }
        };
        println!("  transport  HTTPS");
        println!("  cert sha256 {}", config.fingerprint);
        println!();
        println!("  listening  https://{}", cli.bind);
        axum_server::bind_rustls(cli.bind, config.acceptor)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
    };

    if let Err(error) = served {
        eprintln!("Server stopped: {error}");
        std::process::exit(1);
    }
}
