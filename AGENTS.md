# DFIR Network Investigator — Agent Guide

> Offline desktop workbench for DFIR (Digital Forensics and Incident Response) network investigation. **Tauri v2 (Rust + React 19)** with **SQLCipher-encrypted SQLite** case files. No server, no cloud, no accounts.

This file is a quick orientation for coding agents. The `docs/` folder is the authoritative documentation — when this file and `docs/` disagree, trust `docs/` and the code.

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — current application and data architecture
- [docs/RUNNING_AND_BUILDING.md](docs/RUNNING_AND_BUILDING.md) — dev/build/release per platform
- [docs/INPUT_FORMATS.md](docs/INPUT_FORMATS.md) — snapshot, expert-bundle, and partial-import contracts
- [PORTABLE_EXPORT_FORMAT.md](PORTABLE_EXPORT_FORMAT.md) — encrypted `.dfirx` envelope spec
- `dfir_network_investigation_platform.md`, `encryption_analysis.md`, `technology.md`, and the root PNGs are **archived design research**, not descriptions of the current app.

---

## Project Overview

A portable workbench for 3rd-party DFIR teams on client sites without SIEM access. Each investigator runs the app on their own laptop against one case file at a time. Collaboration is file-based: Git-like "expert change bundles" are exchanged and merged at a daily team meeting; full JSON snapshots exist for backup/legacy transfer.

### Key Features

- **Case files** — one SQLCipher-encrypted `.db` per case at a user-chosen path; password required to create/open; append-only commit history for every change.
- **Network topology** — zones, assets, multi-NIC interfaces, firewalls (interfaces, VIP/DNAT/SNAT/port NAT rules), zone-to-zone connections; Cytoscape.js graph with saved topology views and PNG export.
- **Timeline** — events with MITRE ATT&CK fields, preserved raw server time, reusable clock-correction profiles, dual zone/UTC display (vis-timeline).
- **IOCs, Notes** — searchable IOC list; versioned Markdown notes rendered via a safe React-only renderer (embedded HTML is never executed).
- **Expert Merge** — export/import change bundles (commits since a shared baseline), three-way preview with per-field conflict resolution, transactional apply, merge commits with two parents.
- **Partial import** — case-aware JSON template for LLM/human filling, previewed and applied transactionally with add-only or incoming-overwrite policy.
- **Portable exports** — every snapshot/bundle can be plain JSON or an encrypted `.dfirx` (Argon2id + AES-256-GCM) with an independent export password.

## Technology Stack

| Layer | Technology | Notes |
|---|---|---|
| Frontend | React 19 + TypeScript (strict) + Vite 7 | path alias `@/*` |
| UI | Tailwind CSS 3 + shadcn/ui (`src/components/ui/`) + lucide-react + sonner toasts | |
| Graph / timeline | Cytoscape.js + cytoscape-dagre; vis-timeline + vis-data | |
| Shell | Tauri 2 (`tauri-plugin-dialog` only) | |
| Backend | Rust, edition 2021; toolchain pinned in `rust-toolchain.toml` | |
| Database | `rusqlite` with **`bundled-sqlcipher-vendored-openssl`** — SQLCipher + OpenSSL are compiled from source (Strawberry Perl needed on Windows, build-time only) | |
| Crypto | `aes-gcm`, `argon2`, `getrandom`, `zeroize` for portable exports; SQLCipher for the DB at rest | |

There is **no** React Hook Form, Zod, HTTP client, or state-management library.

## Project Structure

```
src/                          # Frontend
├── components/               # Feature components (Dashboard, NetworkManager, AssetManager,
│   │                         #   NetworkTopology, TimelineView, IocManager, NoteManager,
│   │                         #   ExportImport, PartialImportPanel, CaseSetup, ExpertSetup,
│   │                         #   FirewallDetails, AboutPage)
│   └── ui/                   # Generated shadcn/ui components — avoid editing
├── lib/                      # utils.ts (cn), topology-layout.ts (+ tests)
├── config/branding.ts        # White-label strings
└── types/index.ts            # Shared TypeScript interfaces incl. ApiResponse<T>

src-tauri/src/
├── main.rs                   # Entry point (calls lib::run)
├── lib.rs                    # All #[tauri::command] handlers, shared state, with_conn helpers
├── db.rs                     # Schema DDL, migrations (PRAGMA user_version), CRUD, snapshot import/export
├── secure_db.rs              # SQLCipher key/rekey/legacy-migration via FFI
├── history.rs                # Commit history, change bundles, three-way merge preview/apply
├── portable_export.rs        # .dfirx envelope: Argon2id KDF + AES-256-GCM
└── partial_import.rs         # Template generation, preview, validated transactional apply
```

## Build, Run, Test

```bash
npm install
npm run tauri-dev        # full desktop app (required for any native/DB feature)
npm run dev              # Vite only — invoke() fails, UI shell only
npm run lint             # eslint
npm run build            # tsc -b && vite build
npm test                 # vitest run (tests in tests/ and co-located *.test.ts[x])
```

Rust tests (unit tests live in `#[cfg(test)]` modules inside each backend file):

```powershell
cargo +stable-x86_64-pc-windows-msvc test --manifest-path src-tauri\Cargo.toml
```

### Windows build rule for agents

Use the repository wrapper for the supported Windows/NSIS build:

```powershell
npm run tauri-build:windows
```

`scripts/tauri-build.mjs` selects the MSVC toolchain matching the channel pinned in `rust-toolchain.toml`, prepends Strawberry Perl to `PATH`, and invokes the project-local Tauri CLI. Do **not** treat a failure of plain `cargo check`/`cargo test` under a default GNU host (e.g. `dlltool.exe: program not found`) as a failure of the supported build — GNU dlltool is not part of the MSVC/NSIS workflow. Output: `src-tauri/target/release/bundle/nsis/` (see `tauri-build:linux` / `tauri-build:mac-*` for other platforms).

Clean builds are slow because SQLCipher + OpenSSL compile from C source. Avoid `cargo clean`; do not create extra `target-*` directories (each one recompiles OpenSSL from scratch).

## IPC Pattern

Every command returns `{ success, data, error }` (`ApiResponse<T>` on the frontend, `Response<T>` in Rust). Frontend calls use `invoke` from `@tauri-apps/api/core` wrapped in try/catch, surfacing errors with `toast.error`. The full command list (~60 commands) is registered in `lib.rs::run()`; groups:

- Case/session: `create_new_case`, `open_existing_case`, `migrate_legacy_case`, `change_database_password`, `close_current_case`, `get_current_case_info`, `update_current_case`, `set_current_expert`, `get_current_expert`, `get_db_path`
- Networks/assets/interfaces: `create_new_network`, `update_existing_network`, `list_networks`, `remove_network`, `list_assets*`, `set_asset_suspicious`, `remove_asset`, `list_network_interfaces`, `set_primary_network_interface`, …
- Topology views: `get_topology_view`, `save_topology_view`
- Timeline/clock: `list_timeline_events`, `preview_timestamp`, `list_clock_profiles`, …
- Notes/IOCs/firewalls/connections: CRUD + list commands per entity
- Snapshot export/import: `export_case_json`, `import_case_json`, `save_export_to_file`, `load_import_from_file`, `save_export_as_text`
- Partial import: `get_partial_import_template`, `preview_partial_import_text`, `validate_pending_partial_import`, `apply_pending_partial_import`, `discard_pending_partial_import`, …
- Expert merge/history: `save_change_bundle_to_file`, `load_change_bundle_from_file`, `refresh_pending_change_bundle`, `apply_pending_change_bundle`, `discard_pending_change_bundle`, `list_case_history`, `mark_current_shared_baseline`

## Database

All DDL and migrations live in `db.rs`; current schema version is tracked via `PRAGMA user_version` (see `validate_and_migrate_case`). Tables:

`cases`, `networks`, `assets`, `network_interfaces`, `network_connections`, `firewalls`, `firewall_interfaces`, `firewall_nat_rules`, `clock_profiles`, `timeline_events`, `notes`, `iocs`, `topology_views`, plus history tables (`history_commits`, `history_commit_parents`, `history_changes`, `history_entity_heads`, `history_state`).

- Case files live wherever the user chose in the native Save dialog (not a fixed app-data dir).
- `properties`/`scan_results`/`rules` are JSON strings in TEXT columns.
- UUIDs (`uuid::Uuid::new_v4()`) for all entity IDs, generated in Rust.
- Legacy snapshot import uses `INSERT OR IGNORE` (duplicate IDs skipped, never overwritten); expert-merge and partial-import paths are transactional with per-field conflict handling.
- Foreign keys and a 5-second busy timeout are enabled on every connection.

## Security Model (current, verified)

- **CSP is strict and local-only** (`tauri.conf.json`): `default-src 'self'`, `script-src 'self'`, `connect-src` limited to the Tauri IPC origin. Keep it that way — no remote content.
- **Capabilities are minimal** (`src-tauri/capabilities/default.json`): `core:default` + dialog open/save only. No fs, shell, http, or opener permissions. Do not add capabilities without a strong reason.
- **DB at rest:** SQLCipher; key applied via FFI in `secure_db.rs` with `cipher_memory_security = ON`. Passwords cross IPC wrapped in `Zeroizing` and are never stored, logged, or bound to the expert name.
- **Exports:** Argon2id (64 MiB, t=3, p=1) + AES-256-GCM, fresh random salt/nonce per file (`portable_export.rs`).
- **SQL:** always parameterized; table names only via hardcoded `match` arms. Keep it that way.
- **Frontend:** no `dangerouslySetInnerHTML`, no `console.*`. Markdown notes render through the React-only `SafeMarkdown` (NoteManager) that escapes HTML and allows only `http:`/`https:`/`mailto:` links. vis-timeline `content`/`title` strings rely on the library's built-in XSS filter — do not disable it or introduce custom `template` functions that return raw HTML.
- No accounts/RBAC by design: the expert name is self-declared attribution; the DB password is the access control for a physical file copy.

## Code Style

- **Frontend:** functional components, default exports for features; `@/` imports; Tailwind + `cn()`; local state via `useState`/`useEffect` with a `refreshTrigger` counter prop for re-fetch signaling; errors surfaced with sonner `toast.error`.
- **Backend:** `#[tauri::command]` snake_case handlers returning `Response<T>`; DB access only through the `with_conn`/`with_actor_conn` helpers on the shared `Mutex<Option<Connection>>`; no `unwrap()` in command paths; multi-step writes always inside `conn.transaction()` with a history commit recorded in the same transaction.

## Development Notes

- Single-case-at-a-time: one open connection in `DbState`; pending merge/import previews are cleared when a case is opened or closed.
- Deleting an asset preserves its timeline events (asset reference nulled); networks cannot be deleted while referenced.
- The Rust toolchain is pinned in `rust-toolchain.toml`; bump it deliberately (a channel change triggers a full rebuild including OpenSSL).
- CI (`.github/workflows/desktop-build.yml`) is `workflow_dispatch`-only with `Swatinem/rust-cache`.
