# DFIR Network Investigator

Lean, offline desktop workbench for documenting a network investigation. The application is React inside Tauri; Rust talks directly to an embedded SQLite case file. There is no web service, database server, account service, or cloud dependency.

## Documentation

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

There are no user accounts, identity proof, roles, or per-expert permissions. Each physical `.db` file has one shared database password that must unlock it when opened. After unlock, an expert enters a self-declared name; that name, session ID, timestamp, commit message, and optional assignment scope are stored with every local change.

Scope can name a department, room, DMS/DMZ, or other assignment and can select network zones. It filters and labels the workspace but never prevents an expert from editing outside the scope.

The recommended daily workflow is:

1. The lead distributes identical copies of the agreed master `.db` file.
2. Each expert enters their name, optionally selects focus zones, and works independently.
3. Each expert saves a change bundle from **Expert Merge**. It contains commits since the shared baseline, not a blind full-case overwrite.
4. At the meeting, the lead loads one or more bundles. Loading only creates previews.
5. The team reviews clean edits, auto-mergeable edits, deletes, and same-field conflicts. For a conflict, choose the master or incoming value per field, or leave the entity unselected.
6. Applying selected edits runs as one SQLite transaction and adds a merge commit with both history parents. Other loaded previews are recalculated against the new master.
7. After all accepted changes are applied, mark the current head as the next shared baseline and redistribute that database.

Unknown baselines and different case IDs are not silently merged. Repeated bundles are detected. A full JSON snapshot remains available for backup and legacy transfer; legacy imports keep UUID skip-without-overwrite behavior and return per-entity inserted/skipped counts.

## Portable export protection

Every snapshot and expert change bundle can be saved in either mode:

- **Unencrypted:** ordinary formatted UTF-8 JSON. The existing snapshot or change-bundle structure is unchanged and can be parsed by other applications and languages.
- **Encrypted:** a `.dfirx` JSON envelope containing an AES-256-GCM ciphertext. The exact ordinary JSON export is the encrypted payload, so decrypting restores it without structural conversion.

The export password is independent of the active session expert. It is not stored in the case or export and has no dependency on the source or destination computer. Encrypted imports, merge previews, and the text parser accept the same portable password.

Encryption uses Argon2id with a fresh random salt and AES-256-GCM with a fresh random nonce for each file. Wrong passwords and modified files fail authenticated decryption. See [PORTABLE_EXPORT_FORMAT.md](PORTABLE_EXPORT_FORMAT.md) for the language-neutral envelope specification.

The database password and export password are separate controls. Changing one never changes the other. The database password applies only to that physical `.db` copy; a byte-for-byte copy initially has the same password, while independently rekeyed expert copies may use different passwords even when they share the same case UUID.

## Local data and safety

- A case is one SQLCipher-encrypted SQLite file at the location selected in the native Save dialog.
- Creating and opening a case requires its database-file password. The password is never retained in application state or bound to an expert name.
- **Dashboard → Database file security** changes the password for only the open physical copy. **Lock / Close Case** drops the database connection and requires the password on the next open.
- A legacy plaintext `.db` can be converted to a newly selected encrypted copy; the source is left unchanged.
- Every connection enables foreign keys and a five-second busy timeout.
- Opening a case validates required tables and the single case record, runs `PRAGMA user_version` migrations, repairs legacy orphan references, backfills primary interfaces, and runs integrity and foreign-key checks.
- Multi-table edits and imports are transactional.
- Networks cannot be deleted while assets, interfaces, firewalls, or connections reference them; the error includes dependency counts.
- Deleting an asset removes its interfaces but preserves timeline evidence with a null asset reference.
- SQLCipher encrypts and authenticates database pages at rest. Continue to use BitLocker, FileVault, or the site's approved device encryption because filenames, exports, process memory while unlocked, and endpoint activity remain outside that protection.

## Architecture

```text
React 19 + TypeScript + Vite
  ├─ Cytoscape.js topology
  ├─ Vis Timeline
  └─ Tauri invoke (in-process IPC)
        └─ Rust commands
             └─ rusqlite + bundled SQLCipher/OpenSSL
                  ├─ investigation tables
                  └─ append-only commit/change history
```

Rust native file access is used only after a user selects a case, import, or export path. The unused frontend filesystem plugin and broad filesystem capabilities have been removed. Tauri uses a local-only CSP.

## Quick start from source

- Node.js 20 or newer.
- Rust stable. Windows releases use the MSVC host; Linux and macOS use their native stable host.
- Platform WebView/build prerequisites: WebView2 on Windows, WebKitGTK development packages on Ubuntu/Debian, and Xcode Command Line Tools on macOS.
- Strawberry Perl on Windows only, build-time only, required to compile the vendored OpenSSL used by SQLCipher.

Install dependencies, then start the complete desktop application:

```bash
npm install
npm run tauri-dev
```

`npm run dev` starts only the Vite frontend; native case files and Tauri commands require `npm run tauri-dev`. See [RUNNING_AND_BUILDING.md](docs/RUNNING_AND_BUILDING.md) for standalone/installer startup, prerequisites, build outputs, and troubleshooting.

## Development and release gates

```powershell
npm run dev
npm run lint
npm run build
npm test

cd src-tauri
cargo test
cd ..

npm run tauri-dev
npm run tauri-build:windows
```

On Windows machines whose default Rust host is GNU, run Rust checks with `cargo +stable-x86_64-pc-windows-msvc test --manifest-path src-tauri\Cargo.toml` or set the MSVC host as the default first.

Windows output is written to `src-tauri/target/release/bundle/nsis/`. Linux x86_64 builds use `npm run tauri-build:linux` on Ubuntu/Debian. macOS builds use `npm run tauri-build:mac-intel`, `npm run tauri-build:mac-apple`, or `npm run tauri-build:mac-universal` on macOS. See [RUNNING_AND_BUILDING.md](docs/RUNNING_AND_BUILDING.md) for platform prerequisites and artifact paths, and [INPUT_FORMATS.md](docs/INPUT_FORMATS.md) for the complete plain/encrypted snapshot, expert-bundle, and structured partial-import contracts.

## Deferred work

The lean MVP is manual DFIR documentation and visualization. These are intentionally not implemented: FastAPI or another HTTP backend, PostgreSQL/Redis, identity authentication/RBAC, live collaboration, tasks, automated log ingestion/parsing, YARA, STIX/OpenIOC export, attack-path algorithms, standardized PDF reporting, database-password recovery, and cryptographic identity signatures.

The files in `docs/archive/` (`dfir_network_investigation_platform.md`, `encryption_analysis.md`, and the design diagrams) are archived design research only and are not descriptions of the current application.

## License

DFIR Network Investigator is licensed under the [GNU Affero General Public License v3.0 only](LICENSE). Third-party components remain under their respective licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
