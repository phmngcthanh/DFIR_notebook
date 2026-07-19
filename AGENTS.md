# DFIR Network Investigator — Agent Guide

> Desktop application for DFIR (Digital Forensics and Incident Response) network investigation. Built with **Tauri (Rust + React)** and **SQLite**.

---

## Project Overview

This is a **portable desktop workbench** for 3rd-party DFIR teams who work on client sites without access to the client's SIEM. Each investigator runs the app independently on their laptop, manages one case at a time, and exports/merges findings via JSON at the end of the day.

### Key Features

- **Case Management** — Create and open investigation cases stored as SQLite `.db` files.
- **Network Topology** — Visualize network zones and assets with interactive compound-node graphs (Cytoscape.js).
- **Asset Management** — Track VMs, workstations, and servers with IP, OS, MAC, user, and custom JSON properties.
- **Infection Timeline** — Document attack-chain events with MITRE ATT&CK tactic/technique mapping.
- **IOC Management** — Track indicators of compromise (IP, hash, domain, URL).
- **Notes** — Markdown notes for investigation findings.
- **Export / Merge** — Export a case to JSON; import/merge teammate exports (duplicate IDs are skipped, no overwrite).
- **Firewall & Network Connections** — Document firewall rules and inter-network links.

### Architecture

```
┌─────────────────────────────────────────┐
│  Frontend: React 19 + TypeScript + Vite │
│  UI: Tailwind CSS v3 + shadcn/ui        │
│  Visualization: Cytoscape.js + Vis.js   │
├─────────────────────────────────────────┤
│  Bridge: Tauri v2 (IPC invoke/commands) │
├─────────────────────────────────────────┤
│  Backend: Rust (Tauri runtime)          │
│  Database: SQLite via rusqlite          │
│  File dialogs: Tauri dialog plugin      │
└─────────────────────────────────────────┘
```

---

## Technology Stack

| Layer | Technology | Version / Notes |
|---|---|---|
| Frontend Framework | React | 19.2.0 |
| Build Tool | Vite | 7.2.4 |
| Language | TypeScript | ~5.9.3, strict mode enabled |
| Styling | Tailwind CSS | 3.4.19 |
| UI Components | shadcn/ui | `new-york` style, 40+ components in `src/components/ui/` |
| Icons | Lucide React | `lucide-react` |
| Desktop Shell | Tauri | 2.11.2 |
| Backend Language | Rust | Edition 2021, min 1.77.2 |
| Database | SQLite | `rusqlite` with `bundled`, `chrono`, `uuid`, `serde_json` |
| Network Graph | Cytoscape.js | `cytoscape` + `cytoscape-dagre` + `react-cytoscapejs` |
| Timeline | Vis.js | `vis-timeline` + `vis-data` |
| Forms | React Hook Form + Zod | `@hookform/resolvers` |

---

## Project Structure

```
.
├── src/                          # Frontend (React + TypeScript)
│   ├── components/
│   │   ├── ui/                   # shadcn/ui components (auto-generated)
│   │   ├── CaseSetup.tsx         # New / Open case dialog
│   │   ├── Dashboard.tsx         # Investigation stats & recent events
│   │   ├── NetworkManager.tsx    # CRUD for network zones
│   │   ├── AssetManager.tsx      # CRUD for assets
│   │   ├── NetworkTopology.tsx   # Cytoscape.js graph view
│   │   ├── TimelineView.tsx      # Vis.js timeline + event CRUD
│   │   ├── IocManager.tsx        # IOC management
│   │   ├── NoteManager.tsx       # Markdown notes CRUD
│   │   └── ExportImport.tsx      # Export case to JSON / import & merge
│   ├── hooks/
│   │   └── use-mobile.ts         # Mobile breakpoint detection
│   ├── lib/
│   │   └── utils.ts              # `cn()` Tailwind class merger
│   ├── pages/
│   │   └── Home.tsx              # Unused Vite starter page
│   ├── types/
│   │   ├── index.ts              # Core TypeScript interfaces
│   │   └── declarations.d.ts     # Module declarations
│   ├── App.tsx                   # Root layout (sidebar + view router)
│   ├── main.tsx                  # ReactDOM entry point
│   ├── index.css                 # Tailwind directives + CSS variables
│   └── App.css                   # App-specific styles
│
├── src-tauri/                    # Backend (Rust + Tauri)
│   ├── src/
│   │   ├── main.rs               # Entry point (calls lib::run)
│   │   ├── lib.rs                # Tauri command handlers + app setup
│   │   └── db.rs                 # SQLite schema + CRUD operations
│   ├── icons/                    # App icons (Windows, macOS, Linux)
│   ├── Cargo.toml                # Rust dependencies
│   ├── tauri.conf.json           # Tauri window, bundle, plugin config
│   └── build.rs                  # Tauri build script
│
├── package.json                  # Node scripts & dependencies
├── vite.config.ts                # Vite config (base: './', port 5173)
├── tailwind.config.js            # Tailwind theme + shadcn colors
├── tsconfig.app.json             # TS strict config, path alias `@/*`
├── eslint.config.js              # ESLint flat config (TS + React Hooks)
└── components.json               # shadcn/ui configuration
```

---

## Build and Run Commands

### Prerequisites

- [Node.js](https://nodejs.org/) 18+ (project uses Node 20)
- [Rust](https://rustup.rs/) latest stable
- Tauri CLI: `cargo install tauri-cli` (optional but recommended)

### Frontend Only

```bash
# Install dependencies
npm install

# Start Vite dev server
npm run dev

# Production build (outputs to `dist/`)
npm run build

# Preview production build
npm run preview

# Lint
npm run lint
```

### Full Desktop App (Tauri)

```bash
# Development mode (starts Vite + Tauri)
npm run tauri dev

# Production build (creates installers/binaries)
npm run tauri build
```

The built application bundles will be in `src-tauri/target/release/bundle/`.

---

## IPC Command Reference (Frontend ↔ Backend)

All commands return a standardized `Response<T>`:

```json
{ "success": true, "data": { ... }, "error": null }
```

| Command | Input | Output | Description |
|---|---|---|---|
| `create_new_case` | `name`, `description`, `clientName`, `investigator` | `caseId` | Creates `.db` in app data dir |
| `open_existing_case` | — | `"Case opened"` | File picker for `.db` files |
| `get_current_case_info` | — | `Case \| null` | Current case metadata |
| `create_new_network` | network fields | `Network` | Add network zone |
| `list_networks` | — | `Network[]` | |
| `remove_network` | `id` | `boolean` | |
| `create_new_asset` | asset fields | `Asset` | Add asset to a network |
| `list_assets` | — | `Asset[]` | |
| `list_assets_by_network` | `networkId` | `Asset[]` | |
| `set_asset_suspicious` | `id`, `suspicious` | `boolean` | Toggle suspicious flag |
| `remove_asset` | `id` | `boolean` | |
| `create_new_timeline_event` | event fields | `TimelineEvent` | |
| `list_timeline_events` | — | `TimelineEvent[]` | Sorted by timestamp |
| `remove_timeline_event` | `id` | `boolean` | |
| `create_new_note` | `title`, `content` | `Note` | |
| `list_notes` | — | `Note[]` | Sorted by `updated_at` DESC |
| `update_existing_note` | `id`, `title`, `content` | `boolean` | |
| `remove_note` | `id` | `boolean` | |
| `create_new_ioc` | IOC fields | `Ioc` | |
| `list_iocs` | — | `Ioc[]` | |
| `remove_ioc` | `id` | `boolean` | |
| `create_new_firewall` | firewall fields | `Firewall` | |
| `list_firewalls` | — | `Firewall[]` | |
| `remove_firewall` | `id` | `boolean` | |
| `create_new_network_connection` | connection fields | `NetworkConnection` | |
| `list_network_connections` | — | `NetworkConnection[]` | |
| `remove_network_connection` | `id` | `boolean` | |
| `export_case_json` | — | `JSON string` | Serialize entire case |
| `import_case_json` | `jsonData` | `boolean` | Merge into current case |
| `save_export_to_file` | — | `filePath` | Export + native save dialog |
| `load_import_from_file` | — | `boolean` | Native open dialog + merge |
| `get_db_path` | — | `string \| null` | Current DB file path |

---

## Database Schema

SQLite database managed entirely in `src-tauri/src/db.rs`.

| Table | Purpose |
|---|---|
| `cases` | Single case metadata (name, client, investigator, status) |
| `networks` | Network zones (subnet, VLAN, type) |
| `assets` | Machines in networks (IP, MAC, OS, user, properties JSON, scan_results JSON, suspicious flag) |
| `network_interfaces` | NICs per asset (multi-homed support) |
| `network_connections` | Links between network zones |
| `firewalls` | Firewall devices + rules JSON + config text |
| `timeline_events` | Events with MITRE tactic/technique |
| `notes` | Markdown notes |
| `iocs` | Indicators of compromise |

Indexes exist on foreign keys and frequently queried columns (`assets.network_id`, `timeline_events.asset_id`, `timeline_events.timestamp`, etc.).

### Data Storage Locations

SQLite `.db` files are stored per-platform:

- **Windows:** `%APPDATA%\DFIR-Investigator\<case-name>.db`
- **macOS:** `~/Library/Application Support/DFIR-Investigator/<case-name>.db`
- **Linux:** `~/.local/share/DFIR-Investigator/<case-name>.db`

---

## Code Style Guidelines

### Frontend (TypeScript / React)

- **Components:** Functional components, default exports for pages/features.
- **Imports:** Use path alias `@/` for project modules (e.g., `@/components/ui/button`, `@/types`).
- **Styling:** Tailwind utility classes. Use `cn()` from `@/lib/utils` for conditional class merging.
- **shadcn/ui:** Components live in `src/components/ui/`. Import them as needed; do not modify generated files unless necessary.
- **IPC Calls:** Use `invoke` from `@tauri-apps/api/core`. Wrap in `try/catch`. Type responses with `ApiResponse<T>`.
- **State:** `useState` + `useEffect` for local state. A `refreshTrigger` counter prop is used to signal child components to re-fetch data.
- **Naming:** PascalCase for components, camelCase for variables/functions, UPPER_SNAKE for constants.

### Backend (Rust)

- **Commands:** Marked with `#[tauri::command]`, snake_case naming.
- **Error Handling:** Commands return `Response<T>`; errors are converted to strings.
- **Database Access:** Use the `with_conn` helper to safely access the shared `DbState` mutex.
- **Schema:** All DDL lives in `db.rs::init_database()`. Use `INSERT OR IGNORE` for import/merge operations.

---

## Testing

**No automated tests are currently present** in this project. There are no unit tests, integration tests, or end-to-end tests.

If you add tests:

- **Frontend:** Consider [Vitest](https://vitest.dev/) (aligns with Vite) + React Testing Library.
- **Backend:** Use `cargo test` with temporary SQLite databases in memory (`:memory:`).

---

## Security Considerations

- **CSP is disabled** (`"csp": null` in `tauri.conf.json`). If you add remote content or external assets, configure a strict Content-Security-Policy.
- **Database paths** are resolved via `dirs::data_dir()`. Filenames are sanitized (`sanitize_filename`) to alphanumeric, hyphens, and underscores.
- **File dialogs** use Tauri's native dialog plugin (blocking API).
- **No authentication or RBAC** is implemented. The app is single-user, offline, and relies on physical access control.
- **Import merge behavior:** Duplicate IDs are skipped (`INSERT OR IGNORE`). This is intentional to prevent accidental overwrites during team collaboration, but it also means **updated records from a teammate will not overwrite local changes** if they share the same UUID.

---

## Development Notes

- The app is designed around a **single-case-at-a-time** model. The `DbState` holds one open connection in a `Mutex<Option<Connection>>`.
- `src/pages/Home.tsx` is leftover from the Vite starter template and is **not used** by the application.
- The sidebar in `App.tsx` acts as the main router; views are conditionally rendered based on `currentView` state.
- `properties` and `scan_results` on assets, as well as `rules` on firewalls, are stored as **JSON strings** in SQLite (not JSONB, since this is SQLite, not PostgreSQL).
- UUIDs are generated with `uuid::Uuid::new_v4()` on the Rust side for all entities.
- Timeline events are ordered by `timestamp` (string, RFC 3339 format).
