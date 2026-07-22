//! HTTPS setup.
//!
//! An operator can supply a real certificate. Otherwise a self-signed one is
//! generated and *persisted* next to the case directory, so its fingerprint
//! stays the same across restarts and experts can verify it once. The
//! fingerprint is printed at startup for exactly that purpose.

use std::path::{Path, PathBuf};

use axum_server::tls_rustls::RustlsConfig;
use rcgen::CertifiedKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};

pub struct TlsSetup {
    pub acceptor: RustlsConfig,
    pub fingerprint: String,
}

pub fn load_or_generate(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    cases_dir: &Path,
) -> Result<TlsSetup, String> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "Could not install the TLS crypto provider".to_string())?;

    let (cert_pem, key_pem) = match (cert_path, key_path) {
        (Some(cert), Some(key)) => (read_pem(cert)?, read_pem(key)?),
        _ => self_signed(cases_dir)?,
    };

    let certs = parse_certs(&cert_pem)?;
    let fingerprint = fingerprint(certs.first().ok_or("The certificate chain is empty")?);
    let key = parse_key(&key_pem)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| format!("Certificate and key do not match: {error}"))?;

    Ok(TlsSetup {
        acceptor: RustlsConfig::from_config(std::sync::Arc::new(config)),
        fingerprint,
    })
}

fn read_pem(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|error| format!("Could not read {}: {error}", path.display()))
}

/// Generate once, reuse forever. Regenerating on every boot would train experts
/// to click through certificate warnings.
fn self_signed(cases_dir: &Path) -> Result<(String, String), String> {
    let cert_path: PathBuf = cases_dir.join("server-cert.pem");
    let key_path: PathBuf = cases_dir.join("server-key.pem");
    if cert_path.exists() && key_path.exists() {
        return Ok((read_pem(&cert_path)?, read_pem(&key_path)?));
    }

    let mut names = vec!["localhost".to_string()];
    if let Ok(host) = hostname() {
        if !host.is_empty() && host != "localhost" {
            names.push(host);
        }
    }
    names.push("127.0.0.1".to_string());

    let CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(names)
        .map_err(|error| format!("Could not generate a TLS certificate: {error}"))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    std::fs::write(&cert_path, &cert_pem)
        .map_err(|error| format!("Could not save the generated certificate: {error}"))?;
    std::fs::write(&key_path, &key_pem)
        .map_err(|error| format!("Could not save the generated key: {error}"))?;
    Ok((cert_pem, key_pem))
}

fn hostname() -> Result<String, String> {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .map_err(|_| "no hostname".to_string())
}

fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = rustls_pemfile_certs(pem)?;
    if certs.is_empty() {
        return Err("No CERTIFICATE block found in the certificate file".to_string());
    }
    Ok(certs)
}

fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>, String> {
    for (label, der) in pem_blocks(pem) {
        let key = match label.as_str() {
            "PRIVATE KEY" => PrivateKeyDer::Pkcs8(der.into()),
            "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(der.into()),
            "EC PRIVATE KEY" => PrivateKeyDer::Sec1(der.into()),
            _ => continue,
        };
        return Ok(key);
    }
    Err("No PRIVATE KEY block found in the key file".to_string())
}

fn rustls_pemfile_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    Ok(pem_blocks(pem)
        .into_iter()
        .filter(|(label, _)| label == "CERTIFICATE")
        .map(|(_, der)| CertificateDer::from(der))
        .collect())
}

/// Minimal PEM reader. Avoids a dependency for what is a dozen lines.
fn pem_blocks(pem: &str) -> Vec<(String, Vec<u8>)> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let mut blocks = Vec::new();
    let mut label: Option<String> = None;
    let mut body = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            label = rest.strip_suffix("-----").map(|value| value.to_string());
            body.clear();
        } else if line.starts_with("-----END ") {
            if let (Some(name), Ok(der)) = (label.take(), STANDARD.decode(&body)) {
                blocks.push((name, der));
            }
            body.clear();
        } else if label.is_some() {
            body.push_str(line);
        }
    }
    blocks
}

fn fingerprint(cert: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(cert.as_ref());
    digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
