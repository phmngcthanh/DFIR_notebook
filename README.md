# DFIR Network Investigator — centralized server branch

Browser-based workbench for documenting a network investigation, backed by a small
Rust server that holds the SQLCipher case files. The team edits **one** case at
the same time instead of exchanging change bundles at a daily meeting.

> **This is the `server` branch.** [`main`](../../tree/main) is the offline Tauri
> desktop product. Both shells compile the same investigation core: `src-tauri/`
> is unmodified here, and the server includes its five core modules by path. The
> browser UI on this branch talks HTTP, so the desktop *bundle* is not a
> supported output — see [docs/SERVER.md](docs/SERVER.md).

There are still no user accounts. The case database password is the credential,
and the expert name beside it is self-declared attribution.

```bash
npm install && npm run build
npm run server-build -- --release
./dfir-server --cases ./cases --web ./dist
```

## Documentation

- [Running the case server](docs/SERVER.md)
- [Documentation index](docs/README.md)
- [Investigator user guide](docs/USER_GUIDE.md)
- [Running, development, and Windows/Linux/macOS release builds](docs/RUNNING_AND_BUILDING.md)
- [Accepted input/import formats and examples](docs/INPUT_FORMATS.md)
- [Current application and data architecture](docs/ARCHITECTURE.md)
- [Timeline and server clock correlation](docs/TIME_CORRELATION.md)
- [Plain structured partial import and LLM template](docs/PARTIAL_IMPORT.md)
- [Read-only text parser structure](docs/TEXT_PARSER.md)
- [Headquarters technical review](docs/TECHNICAL_REVIEW_HQ.md)
- [Current capability assessment and scenario fitness](docs/CAPABILITY_ASSESSMENT.md)
- [Portable encrypted export specification](PORTABLE_EXPORT_FORMAT.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## Implemented workflows

- Create a case at a user-selected `.db` location and reopen validated case files.
- Record network zones, network-to-network connections, and dedicated firewalls with multiple interfaces/IPs plus structured VIP, DNAT, SNAT, and port mappings.
- Track PCs and other assets, compromise state, investigation progress, custom JSON, and any number of NICs.
- Keep one primary NIC projection on the asset and show secondary network attachments in the topology.
- Create, edit, filter, and visualize timeline evidence with preserved raw server time, reusable clock correction, dual selected-zone/UTC display, stable asset IDs, and MITRE fields.
- Create, edit, search, and filter IOCs.
- Write versioned notes with a safe Markdown preview; embedded HTML is never executed.
- Export topology PNGs and full versioned snapshots as interoperable plain JSON or portable password-encrypted `.dfirx` files.
- Exchange plain or encrypted Git-like expert change bundles and review additions, edits, deletions, field conflicts, topology changes, timeline changes, author, and optional work scope before applying them.
- Generate a case-aware plain JSON template for an LLM/person, preview one or many partial sections, and choose add-only or incoming-overwrite behavior before transactional confirmation.
- Render either snapshot or change-bundle format as a read-only plain-text report for display or printing.

## Expert collaboration model

There are no user accounts, identity proof, roles, or per-expert permissions. Each case `.db` on the server has one shared database password. Unlocking a case with that password *is* the login; the expert then enters a self-declared name, and that name, session ID, timestamp, commit message, and optional assignment scope are stored with every change.

Scope can name a department, room, DMS/DMZ, or other assignment and can select network zones. It filters and labels the workspace but never prevents an expert from editing outside the scope.

The daily workflow is:

1. The lead puts the case `.db` in the server's case directory (or creates it from the browser when `--allow-create` is on).
2. Each expert opens the server in a browser, picks the case, enters the case password and their name, and optionally selects focus zones.
3. Everyone edits the same case. Each write is committed with its author, and every other open browser refreshes within about five seconds.
4. Writes serialize per case, so two experts editing the same record is last-write-wins with both edits attributed in the audit history.

**Case Transfer** keeps the way back in for an expert who worked offline: upload their change bundle, review clean edits, auto-mergeable edits, deletes, and same-field conflicts, then apply the selection as one SQLite transaction with a merge commit. Unknown baselines and different case IDs are not silently merged, and repeated bundles are detected. Full JSON snapshots remain available for backup and legacy transfer; add-only imports keep UUID skip-without-overwrite behavior and return per-entity inserted/skipped counts.

## Portable export protection

Every snapshot and expert change bundle can be saved in either mode:

- **Unencrypted:** ordinary formatted UTF-8 JSON. The existing snapshot or change-bundle structure is unchanged and can be parsed by other applications and languages.
- **Encrypted:** a `.dfirx` JSON envelope containing an AES-256-GCM ciphertext. The exact ordinary JSON export is the encrypted payload, so decrypting restores it without structural conversion.

The export password is independent of the active session expert. It is not stored in the case or export and has no dependency on the source or destination computer. Encrypted imports, merge previews, and the text parser accept the same portable password.

Encryption uses Argon2id with a fresh random salt and AES-256-GCM with a fresh random nonce for each file. Wrong passwords and modified files fail authenticated decryption. See [PORTABLE_EXPORT_FORMAT.md](PORTABLE_EXPORT_FORMAT.md) for the language-neutral envelope specification.

The database password and export password are separate controls. Changing one never changes the other. The database password applies only to that physical `.db` copy; a byte-for-byte copy initially has the same password, while independently rekeyed expert copies may use different passwords even when they share the same case UUID.

## Local data and safety

- A case is one SQLCipher-encrypted SQLite file in the server's `--cases` directory.
- Unlocking a case requires its database-file password. The password is never retained in server state, hashed, or bound to an expert name; SQLCipher deriving a working key *is* the check.
- **Dashboard → Database file security** changes the password for that case and signs every other expert on it out. **End Session** drops your token; the case connection closes once the last expert leaves.
- A legacy plaintext `.db` is converted with the desktop build; drop the encrypted result into the case directory.
- Every connection enables foreign keys and a five-second busy timeout.
- Opening a case validates required tables and the single case record, runs `PRAGMA user_version` migrations, repairs legacy orphan references, backfills primary interfaces, and runs integrity and foreign-key checks.
- Multi-table edits and imports are transactional.
- Networks cannot be deleted while assets, interfaces, firewalls, or connections reference them; the error includes dependency counts.
- Deleting an asset removes its interfaces but preserves timeline evidence with a null asset reference.
- SQLCipher encrypts and authenticates database pages at rest. Continue to use BitLocker, FileVault, or the site's approved device encryption because filenames, exports, process memory while unlocked, and endpoint activity remain outside that protection.

## Architecture

```text
Browser: React 19 + TypeScript + Vite
  ├─ Cytoscape.js topology
  ├─ Vis Timeline
  └─ src/lib/api.ts  →  POST /api/cmd/{command}   (Bearer token)
        ↓ HTTPS (rustls; --insecure for development)
     server/ — axum
        ├─ static dist/ + SPA fallback + strict CSP
        ├─ sessions: token → { case, expert }
        ├─ cases:    id → { connection, revision }
        └─ rusqlite + bundled SQLCipher/OpenSSL
             ├─ investigation tables
             └─ append-only commit/change history
```

The four core Rust modules are compiled straight out of `src-tauri/src/`, unmodified, so the server and the desktop app cannot drift apart. The server reads and writes only inside its case directory, and serves the UI with the same local-only CSP the desktop app uses.

## Quick start from source

- Node.js 20 or newer.
- Rust stable. Windows uses the MSVC host; Linux and macOS use their native stable host.
- Strawberry Perl on Windows only, build-time only, required to compile the vendored OpenSSL used by SQLCipher.

Install dependencies, build the UI, then start the server:

```bash
npm install
npm run build
npm run server-dev        # cargo run -- --cases ./cases --allow-create --insecure
```

`npm run dev` starts the Vite dev server and proxies `/api` to the running case server, so both can run side by side. See [docs/SERVER.md](docs/SERVER.md) for flags, TLS, and deployment.

## Development and release gates

```powershell
npm run lint
npm run build
npm test
npm run server-test

# The shared investigation core must still compile for the desktop shell.
cargo +stable-x86_64-pc-windows-msvc check --manifest-path src-tauri\Cargo.toml
```

`npm run server-*` selects the MSVC host of the toolchain pinned in `rust-toolchain.toml` and puts Strawberry Perl on `PATH`, which the vendored SQLCipher/OpenSSL build needs on Windows. See [INPUT_FORMATS.md](docs/INPUT_FORMATS.md) for the complete plain/encrypted snapshot, expert-bundle, and structured partial-import contracts.

## Deferred work

These are intentionally not implemented: PostgreSQL/Redis, identity authentication/RBAC beyond the case password, per-field locking or operational-transform live editing, tasks, automated log ingestion/parsing, YARA, STIX/OpenIOC export, attack-path algorithms, standardized PDF reporting, database-password recovery, and cryptographic identity signatures.

The files in `docs/archive/` (`dfir_network_investigation_platform.md`, `encryption_analysis.md`, and the design diagrams) are archived design research only and are not descriptions of the current application.

## License

DFIR Network Investigator is licensed under the [GNU Affero General Public License v3.0 only](LICENSE). Third-party components remain under their respective licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
