# DFIR Network Investigator — Agent Guide (`server` branch)

> Browser workbench for DFIR (Digital Forensics and Incident Response) network investigation, served by a small **axum** binary over **SQLCipher-encrypted SQLite** case files. Still no cloud and no user accounts: the case password is the login.

**Branch note.** `main` is the offline Tauri desktop product; this branch adds a centralized server. `src-tauri/` is **unmodified here on purpose** — the server compiles its five core modules by `#[path]`, so the two shells share one investigation core and merges from `main` stay clean. Do not restructure anything under `src-tauri/`. The browser UI here talks HTTP, so the desktop bundle is not a supported output of this branch.

This file is a quick orientation for coding agents. The `docs/` folder is the authoritative documentation — when this file and `docs/` disagree, trust `docs/` and the code.

- [docs/SERVER.md](docs/SERVER.md) — running, flags, TLS, and the server threat model
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — application and data architecture (desktop-era; the core is unchanged)
- [docs/RUNNING_AND_BUILDING.md](docs/RUNNING_AND_BUILDING.md) — dev/build/release per platform
- [docs/INPUT_FORMATS.md](docs/INPUT_FORMATS.md) — snapshot, expert-bundle, and partial-import contracts
- [PORTABLE_EXPORT_FORMAT.md](PORTABLE_EXPORT_FORMAT.md) — encrypted `.dfirx` envelope spec
- Everything under `docs/archive/` is **archived design research**, not a description of the current app. Root-level `technology.md` is current product/capability documentation.

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
│   │                         #   ActivityBoard, ExportImport, PartialImportPanel, CaseSetup,
│   │                         #   ExpertSetup, FirewallDetails, AboutPage)
│   └── ui/                   # Generated shadcn/ui components — avoid editing
├── lib/                      # utils.ts (cn), topology-layout.ts (+ tests)
├── config/branding.ts        # White-label strings
└── types/index.ts            # Shared TypeScript interfaces incl. ApiResponse<T>

src-tauri/src/                # UNMODIFIED on this branch — the shared core lives here
├── main.rs                   # Desktop entry point (calls lib::run)
├── lib.rs                    # Tauri command handlers — NOT used by the server
├── db.rs                     # Schema DDL, migrations (PRAGMA user_version), CRUD, snapshot import/export
├── secure_db.rs              # SQLCipher key/rekey/legacy-migration via FFI
├── history.rs                # Commit history, change bundles, three-way merge preview/apply
├── portable_export.rs        # .dfirx envelope: Argon2id KDF + AES-256-GCM
└── partial_import.rs         # Template generation, preview, validated transactional apply

server/src/
├── main.rs                   # #[path] includes of the five core modules, CLI, router, CSP headers
├── state.rs                  # Per-case OpenCase (connection, revision, pending previews), sessions, throttle
├── auth.rs                   # SessionContext extractor, unlock/logout, GET /api/state
├── cases.rs                  # Case listing and creation
├── dispatch.rs               # POST /api/cmd/{name} — the ported command surface
├── tls.rs                    # rustls setup; persisted self-signed cert + printed fingerprint
└── tests.rs                  # Auth, throttle, session lifetime, dispatcher round-trip
```

The five core modules contain **zero** `tauri` references and only reach each other through `crate::db` / `crate::history`, which is what makes the `#[path]` include work. Keep it that way: a `tauri::` import in any of them breaks the server build.

## Build, Run, Test

```bash
npm install
npm run build            # tsc -b && vite build — the server serves dist/
npm run server-dev       # cargo run -- --cases ./cases --allow-create --insecure
npm run dev              # Vite dev server; proxies /api to 127.0.0.1:8443
npm run lint             # eslint
npm test                 # vitest run (tests in tests/ and co-located *.test.ts[x])
npm run server-test      # cargo test — also runs the core modules' own suites
```

### Windows build rule for agents

Always go through `scripts/server.mjs` (`npm run server-*`). Like `scripts/tauri-build.mjs`, it selects the MSVC host of the channel pinned in `rust-toolchain.toml` and prepends Strawberry Perl to `PATH`. A bare `cargo build` picks up the default GNU host and Git-Bash's `/usr/bin/perl`, and the vendored OpenSSL configure step fails (`Can't locate Locale/Maketext/Simple.pm`). That is a wrong-environment failure, not a broken build.

`server/.cargo/config.toml` deliberately points the server's `target-dir` at `../src-tauri/target` so both crates share the compiled SQLCipher/OpenSSL artifacts. Avoid `cargo clean`; do not add extra target directories (each one recompiles OpenSSL from C source).

## Command surface

`POST /api/cmd/{name}` with a JSON argument object, replying `{ success, data, error }` — the same envelope and the same camelCase argument keys Tauri produced, which is why no frontend call site changed. `src/lib/api.ts` exports an `invoke(command, args)` with the desktop signature; components import it from `@/lib/api` and are otherwise untouched.

Commands live in one `match` in `dispatch.rs`, built from two macros: `read_cmd!` takes the case connection, `write_cmd!` also takes the session's `ActorIdentity` and bumps the case revision. Everything in `lib.rs`'s `generate_handler!` list is ported except:

- **Native-dialog commands, replaced.** `save_*_to_file` → commands that return the text for the browser to download (`export_case_json`, `get_partial_import_template`, `render_export_report`). `load_*_from_file` → commands that take the text the browser read (`import_case_json`, `load_change_bundle_text`, `preview_partial_import_text`).
- **Session commands, re-pointed.** `create_new_case`/`open_existing_case` became `POST /api/cases` and `POST /api/auth/unlock`; `close_current_case` ends the session; `get_db_path` returns the case *id*, never a server path.
- **Dropped.** `migrate_legacy_case` (needs two local paths — use the desktop build), plus `save_change_bundle_to_file` and `mark_current_shared_baseline`, which have no meaning when everyone writes to the same case.

Outside the command route: `GET /api/cases`, `POST /api/cases`, `POST /api/auth/unlock`, `POST /api/auth/logout`, `GET /api/state`.

## Database

All DDL and migrations live in `db.rs`; current schema version is tracked via `PRAGMA user_version` (see `validate_and_migrate_case`). Tables:

`cases`, `networks`, `assets`, `network_interfaces`, `network_connections`, `firewalls`, `firewall_interfaces`, `firewall_nat_rules`, `clock_profiles`, `timeline_events`, `notes`, `iocs`, `topology_views`, plus history tables (`history_commits`, `history_commit_parents`, `history_changes`, `history_entity_heads`, `history_state`).

- Case files live wherever the user chose in the native Save dialog (not a fixed app-data dir).
- `properties`/`scan_results`/`rules` are JSON strings in TEXT columns.
- UUIDs (`uuid::Uuid::new_v4()`) for all entity IDs, generated in Rust.
- Legacy snapshot import uses `INSERT OR IGNORE` (duplicate IDs skipped, never overwritten); expert-merge and partial-import paths are transactional with per-field conflict handling.
- Foreign keys and a 5-second busy timeout are enabled on every connection.

## Security Model (current, verified)

- **Auth is the case password, and nothing is stored to compare against.** `unlock_case` calls `open_encrypted_connection`; SQLCipher either derives a working key or it does not. An already-open case is verified with a throwaway second connection — the same trick `change_database_password` uses before a rekey. Never add a password hash, a user table, or a "remember me".
- **Online guessing is the new risk.** The 6-character minimum is a *presence* control from the offline threat model, not brute-force resistance. The server compensates with a per-IP lockout (5 failures / 15 min) and a 250 ms floor on unlock replies. Do not remove either.
- **Sessions:** 32 bytes from `getrandom`, in memory only, `Authorization: Bearer`, held in the browser's `sessionStorage`. No cookies, therefore no CSRF surface. A rekey ends every other session on that case.
- **Case ids from clients** are restricted to a filename alphabet and re-checked to resolve inside `--cases`. Never join a client string into a path without `AppState::case_path`.
- **CSP is strict and local-only** (`server/src/main.rs`, adapted from `tauri.conf.json`): `default-src 'self'`, `script-src 'self'`, `connect-src 'self'`. Keep it that way — no remote content.
- **DB at rest:** SQLCipher; key applied via FFI in `secure_db.rs` with `cipher_memory_security = ON`. Passwords are wrapped in `Zeroizing` and are never stored, logged, or bound to the expert name.
- **Exports:** Argon2id (64 MiB, t=3, p=1) + AES-256-GCM, fresh random salt/nonce per file (`portable_export.rs`). Unchanged, so `.dfirx` files move between the desktop build and the server.
- **SQL:** always parameterized; table names only via hardcoded `match` arms. Keep it that way.
- **Frontend:** no `dangerouslySetInnerHTML`, no `console.*`. Markdown notes render through the React-only `SafeMarkdown` (NoteManager) that escapes HTML and allows only `http:`/`https:`/`mailto:` links. vis-timeline `content`/`title` strings rely on the library's built-in XSS filter — do not disable it or introduce custom `template` functions that return raw HTML.
- No accounts/RBAC by design: the expert name is self-declared attribution; the case password is the access control.

## Code Style

- **Frontend:** functional components, default exports for features; `@/` imports; Tailwind + `cn()`; local state via `useState`/`useEffect` with a `refreshTrigger` counter prop for re-fetch signaling; errors surfaced with sonner `toast.error`.
- **Server:** snake_case command names matching the desktop ones; DB access only through `OpenCase::with_conn`; no `unwrap()` in request paths; multi-step writes always inside `conn.transaction()` with a history commit recorded in the same transaction. Adding a command means adding one `match` arm and one params struct with `#[serde(rename_all = "camelCase")]`.

## Development Notes

- **Live update:** every `write_cmd!` bumps `OpenCase::revision`; browsers poll `GET /api/state` every 5 s and, when it moves, bump `refreshTrigger`, which every feature component already re-fetches on. `/api/state` reads in-memory state only — never make it touch the case connection, or a few open browsers will queue behind writes.
- Writes serialize on one `Mutex<Connection>` per case, so concurrent edits to one record are last-write-wins with both attributed in history. Field-level locking is deliberately out of scope.
- A case's connection opens on first unlock and closes when its last session ends; pending merge/import previews live on the case, not the session.
- Deleting an asset preserves its timeline events (asset reference nulled); networks cannot be deleted while referenced.
- The Rust toolchain is pinned in `rust-toolchain.toml`; bump it deliberately (a channel change triggers a full rebuild including OpenSSL).
- CI (`.github/workflows/build-release.yml`) builds and releases every supported
  shell/platform after a manual dispatch or a push to `main` whose commit subject
  ends in `-v`. All required jobs must pass before the release job runs.
