use rusqlite::{ffi, Connection, OpenFlags};
use std::ffi::{c_void, CString};
use std::fs;
use std::io::Read;
use std::path::Path;

use crate::db::{configure_connection, AppResult};

pub const MIN_DATABASE_PASSWORD_CHARS: usize = 6;
const MAX_DATABASE_PASSWORD_CHARS: usize = 256;
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

pub fn validate_database_password(password: &str) -> AppResult<()> {
    let length = password.chars().count();
    if length < MIN_DATABASE_PASSWORD_CHARS {
        return Err(format!(
            "Database passwords must contain at least {MIN_DATABASE_PASSWORD_CHARS} characters"
        ));
    }
    if length > MAX_DATABASE_PASSWORD_CHARS {
        return Err(format!(
            "Database passwords cannot exceed {MAX_DATABASE_PASSWORD_CHARS} characters"
        ));
    }
    Ok(())
}

pub fn is_plaintext_sqlite(path: &Path) -> AppResult<bool> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("Failed to inspect case: {error}"))?;
    if metadata.len() < SQLITE_HEADER.len() as u64 {
        return Ok(false);
    }
    let mut file =
        fs::File::open(path).map_err(|error| format!("Failed to inspect case: {error}"))?;
    let mut header = [0_u8; SQLITE_HEADER.len()];
    file.read_exact(&mut header)
        .map_err(|error| format!("Failed to inspect case: {error}"))?;
    Ok(&header == SQLITE_HEADER)
}

fn cipher_version(conn: &Connection) -> AppResult<String> {
    conn.query_row("PRAGMA cipher_version", [], |row| row.get::<_, String>(0))
        .map_err(|error| format!("SQLCipher is unavailable: {error}"))
        .and_then(|version| {
            if version.trim().is_empty() {
                Err("SQLCipher is unavailable in this application build".to_string())
            } else {
                Ok(version)
            }
        })
}

fn apply_key(conn: &Connection, password: &str) -> AppResult<()> {
    let length = i32::try_from(password.len()).map_err(|_| "Database password is too long")?;
    // SAFETY: the connection handle is valid for the call and SQLCipher copies/derives
    // the supplied key bytes before returning. The password slice remains alive throughout.
    let result =
        unsafe { ffi::sqlite3_key(conn.handle(), password.as_ptr().cast::<c_void>(), length) };
    if result != ffi::SQLITE_OK {
        return Err("Could not apply the database password".to_string());
    }
    cipher_version(conn)?;
    conn.pragma_update(None, "cipher_memory_security", "ON")
        .map_err(|error| format!("Could not enable SQLCipher memory protection: {error}"))?;
    Ok(())
}

fn verify_unlocked(conn: &Connection) -> AppResult<()> {
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })
    .map(|_| ())
    .map_err(|_| {
        "Could not unlock this database: the password is wrong or the file is damaged".to_string()
    })
}

pub fn create_encrypted_connection(path: &Path, password: &str) -> AppResult<Connection> {
    validate_database_password(password)?;
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .map_err(|error| format!("Failed to create encrypted case: {error}"))?;
    apply_key(&conn, password)?;
    configure_connection(&conn)?;
    Ok(conn)
}

pub fn open_encrypted_connection(path: &Path, password: &str) -> AppResult<Connection> {
    if is_plaintext_sqlite(path)? {
        return Err(
            "This is an unencrypted legacy case. Use 'Convert legacy case' to create an encrypted copy"
                .to_string(),
        );
    }
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|error| format!("Failed to open case: {error}"))?;
    apply_key(&conn, password)?;
    verify_unlocked(&conn)?;
    configure_connection(&conn)?;
    Ok(conn)
}

pub fn rekey_connection(conn: &Connection, new_password: &str) -> AppResult<()> {
    validate_database_password(new_password)?;
    let length = i32::try_from(new_password.len()).map_err(|_| "Database password is too long")?;
    // SAFETY: equivalent to apply_key; SQLCipher re-encrypts the main database while the
    // connection and password bytes are valid for the complete call.
    let result = unsafe {
        ffi::sqlite3_rekey(
            conn.handle(),
            new_password.as_ptr().cast::<c_void>(),
            length,
        )
    };
    if result != ffi::SQLITE_OK {
        return Err("Could not change the database password".to_string());
    }
    verify_unlocked(conn)
}

pub fn verify_cipher_integrity(conn: &Connection) -> AppResult<()> {
    let mut statement = conn
        .prepare("PRAGMA cipher_integrity_check")
        .map_err(|error| format!("Could not start encrypted integrity check: {error}"))?;
    let failures = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| format!("Encrypted integrity check failed: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Encrypted integrity check failed: {error}"))?;
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Encrypted database integrity check found {} invalid page(s)",
            failures.len()
        ))
    }
}

pub fn migrate_plaintext_database(
    source_path: &Path,
    target_path: &Path,
    password: &str,
) -> AppResult<()> {
    validate_database_password(password)?;
    if !is_plaintext_sqlite(source_path)? {
        return Err("The selected source is not a plaintext SQLite case".to_string());
    }
    if target_path.exists() {
        return Err("Refusing to overwrite an existing migration target".to_string());
    }

    let source = Connection::open_with_flags(source_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|error| format!("Failed to open legacy case: {error}"))?;
    cipher_version(&source)?;
    source
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|error| format!("Failed to read legacy case: {error}"))?;

    fs::File::create(target_path)
        .map_err(|error| format!("Failed to create encrypted copy: {error}"))?;

    let migration = (|| -> AppResult<()> {
        source
            .execute(
                "ATTACH DATABASE ?1 AS encrypted",
                [target_path.to_string_lossy().as_ref()],
            )
            .map_err(|error| format!("Failed to attach encrypted copy: {error}"))?;

        let schema = CString::new("encrypted").map_err(|_| "Invalid migration schema name")?;
        let length = i32::try_from(password.len()).map_err(|_| "Database password is too long")?;
        // SAFETY: `encrypted` is attached on this live connection and SQLCipher consumes
        // the key bytes before returning.
        let key_result = unsafe {
            ffi::sqlite3_key_v2(
                source.handle(),
                schema.as_ptr(),
                password.as_ptr().cast::<c_void>(),
                length,
            )
        };
        if key_result != ffi::SQLITE_OK {
            return Err("Could not apply encryption to the migration target".to_string());
        }
        source
            .query_row("SELECT sqlcipher_export('encrypted')", [], |_| Ok(()))
            .map_err(|error| format!("Failed to encrypt legacy case: {error}"))?;
        source
            .execute_batch("DETACH DATABASE encrypted")
            .map_err(|error| format!("Failed to finalize encrypted copy: {error}"))?;
        Ok(())
    })();

    if let Err(error) = migration {
        let _ = source.execute_batch("DETACH DATABASE encrypted");
        drop(source);
        let _ = fs::remove_file(target_path);
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{create_case_record, get_case, init_database};
    use uuid::Uuid;

    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("dfir-{label}-{}.db", Uuid::new_v4()))
    }

    #[test]
    fn database_password_minimum_is_six_characters() {
        assert!(validate_database_password("123456").is_ok());
        assert!(validate_database_password("12345")
            .unwrap_err()
            .contains("at least 6"));
    }

    #[test]
    fn encrypted_database_requires_its_file_password_and_can_be_rekeyed() {
        let path = temp_path("encrypted");
        let first = "first-database-password";
        let second = "second-database-password";
        {
            let conn = create_encrypted_connection(&path, first).unwrap();
            init_database(&conn).unwrap();
            create_case_record(&conn, "Case", "", "", "Lead").unwrap();
            verify_cipher_integrity(&conn).unwrap();
            rekey_connection(&conn, second).unwrap();
        }
        assert!(!is_plaintext_sqlite(&path).unwrap());
        assert!(open_encrypted_connection(&path, first).is_err());
        let reopened = open_encrypted_connection(&path, second).unwrap();
        assert_eq!(get_case(&reopened).unwrap().unwrap().name, "Case");
        drop(reopened);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn legacy_migration_preserves_plain_source_and_creates_encrypted_copy() {
        let source_path = temp_path("plain");
        let target_path = temp_path("migrated");
        {
            let conn = Connection::open(&source_path).unwrap();
            init_database(&conn).unwrap();
            create_case_record(&conn, "Legacy", "", "", "Lead").unwrap();
        }
        migrate_plaintext_database(&source_path, &target_path, "migration-password").unwrap();
        assert!(is_plaintext_sqlite(&source_path).unwrap());
        assert!(!is_plaintext_sqlite(&target_path).unwrap());
        let encrypted = open_encrypted_connection(&target_path, "migration-password").unwrap();
        assert_eq!(get_case(&encrypted).unwrap().unwrap().name, "Legacy");
        drop(encrypted);
        fs::remove_file(source_path).unwrap();
        fs::remove_file(target_path).unwrap();
    }
}
