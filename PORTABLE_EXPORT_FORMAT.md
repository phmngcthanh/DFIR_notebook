# DFIR Investigator Portable Export Format

This document specifies encrypted `.dfirx` files so independent tools can decrypt them without running DFIR Investigator.

## Plain exports

An unencrypted export is formatted UTF-8 JSON using the application's existing structure:

- A full snapshot contains `format_version`, `exported_at`, `case_info`, `networks`, `assets`, `network_interfaces`, `clock_profiles`, `timeline_events`, `notes`, `iocs`, `firewalls`, and `network_connections`.
- An expert merge bundle contains `format: "dfir-investigator-changes"`, its version and case/baseline identifiers, exporter metadata, and `commits`.

No encryption wrapper is added to a plain export.

Plain structured partial intake (`format: "dfir-investigator-partial"`) is intentionally not wrapped by this application. See [docs/INPUT_FORMATS.md](docs/INPUT_FORMATS.md) for its complete field contract and merge behavior.

## Encrypted envelope version 1

An encrypted export is UTF-8 JSON with this shape:

```json
{
  "format": "dfir-investigator-encrypted",
  "format_version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "version": 19,
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 1,
    "salt": "BASE64"
  },
  "cipher": {
    "algorithm": "aes-256-gcm",
    "nonce": "BASE64"
  },
  "ciphertext": "BASE64"
}
```

All Base64 fields use the standard RFC 4648 alphabet with padding.

### Encryption procedure

1. Serialize the ordinary snapshot or change bundle as formatted UTF-8 JSON. These exact bytes are the plaintext payload.
2. Encode the password exactly as UTF-8 bytes. Do not trim, normalize, or bind it to an investigator, account, case, or machine.
3. Generate a new cryptographically random 16-byte salt.
4. Derive a 32-byte key with Argon2id version 19 using 65,536 KiB memory, 3 iterations, and parallelism 1.
5. Generate a new cryptographically random 12-byte AES-GCM nonce.
6. Encrypt with AES-256-GCM and the exact associated-data bytes `DFIR-Investigator portable export v1` (without quotes or a terminating null byte).
7. Store the AES-GCM ciphertext followed by its 16-byte authentication tag together in `ciphertext`.

The application requires at least six password characters when creating an encrypted export. Import treats every non-empty password as exact input so another compatible implementation is not forced to repeat that UI policy.

### Decryption procedure

1. Parse and validate the fixed format, version, KDF, and cipher fields before allocating KDF memory.
2. Base64-decode the salt, nonce, and combined ciphertext/tag.
3. Derive the same 32-byte key from the supplied password.
4. Authenticate and decrypt with AES-256-GCM and the fixed associated data.
5. Decode the plaintext as UTF-8 and parse the restored ordinary JSON structure.

Authentication failure means the password is wrong or the file was modified. A consumer must not import or print unauthenticated plaintext.

## Text rendering

The in-app **Text parser** is read-only. It selects a plain `.json` or encrypted `.dfirx`, decrypts when necessary, recognizes a snapshot or expert change bundle, and writes a human-readable `.txt` report. It never opens or mutates the SQLite case and its text result is not an import format.
