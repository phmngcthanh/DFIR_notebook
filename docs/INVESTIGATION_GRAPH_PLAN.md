# Investigation Graph — Implementation Plan

Document version: 1.1 (implemented — kept as the design rationale record)
Target application version: next minor release
Companion function reference: [INVESTIGATION_GRAPH_API.md](INVESTIGATION_GRAPH_API.md)

## 1. Feature summary

Add a second graph workspace — the **Investigation Graph** tab — next to the existing
Topology tab. Where Topology answers *"what does the environment look like?"*, the
Investigation Graph answers *"what did the attacker do, where, and in what order?"*.

The investigator can:

1. show/hide individual nodes and whole networks to reduce the graph to the entities
   that matter for the intrusion;
2. see IOC and infection state directly on the graph (badges, colors) and inspect the
   IOCs observed on a selected entity;
3. draw **attack edges** ("the attacker jumped from A to B") with time, MITRE context,
   confidence, and linked IOCs, producing a numbered intrusion pathway that can be
   stepped through chronologically;
4. save, load, and manage multiple named views (visibility set + filters + layout +
   camera); and
5. record **IOC sightings** that link an IOC to a concrete asset/network/firewall, so
   IOC data, infection status, and graph display stay synchronized.

## 2. Repository assessment (current state)

| Area | Finding | Consequence for this feature |
|---|---|---|
| Graph rendering | `src/components/NetworkTopology.tsx` renders Cytoscape from networks/assets/firewalls/connections/NICs; pure layout math lives in `src/lib/topology-layout.ts` with vitest coverage | The Investigation Graph reuses the same element-building approach and layout library; it must be a separate component because its element set, styling, and interactions differ |
| Saved view precedent | `topology_views` table stores one presentation row per layout (`db.rs` `get_topology_view`/`save_topology_view`, schema `user_version = 6`); excluded from history and export | Investigation views follow the same "presentation, not evidence" pattern but are **named and multiple**, and are worth sharing, so they join the plain snapshot (not history/merge) |
| IOC model | `iocs` table (`src/types/index.ts` `Ioc`, `IocManager.tsx`) has type/value/threat/first–last seen but **no relationship to assets or networks** | A new `ioc_sightings` link entity is required; this is the "sync IOC ↔ infection ↔ entity" gap |
| Infection state | `assets.compromise_status` (`unknown/clean/suspected/infected`) already drives topology node coloring | Sighting creation can optionally raise compromise status in the same transaction; the graph reads the existing field |
| Attacker movement | Nothing represents attacker movement. `timeline_events` hold chronology but no source→target relation; `network_connections` are legitimate infrastructure links | A new `attack_edges` evidence entity is required; it can optionally anchor to a `timeline_event` for corrected time |
| History / merge | Every evidence entity must appear in: `history.rs` `entity_order`, `db.rs` `get_entity_json` / `upsert_entity_json` / `delete_entity_direct`; changes are recorded per commit and three-way merged field-by-field | `ioc_sightings` and `attack_edges` must be wired into all of these; `investigation_views` deliberately must **not** be |
| Export formats | `ExportData` (db.rs) uses `#[serde(default)]` per collection, so adding collections is backward compatible; partial import (`partial_import.rs`) maps entity-kind aliases; the text renderer (`portable_export.rs`) prints per-entity sections | New collections are additive; `PORTABLE_EXPORT_FORMAT.md` and `INPUT_FORMATS.md` must be updated |
| Command surface | `lib.rs` registers commands in `generate_handler`; naming convention is `list_Xs` / `create_new_X` / `update_existing_X` / `remove_X`; all return the `ApiResponse` envelope | New commands follow the same names and envelope (see API doc) |
| Navigation | `App.tsx` `NAV_ITEMS` + `View` union in `src/types/index.ts` | Add `investigation` view |
| Non-goals honored | ARCHITECTURE.md §12 excludes *automated* attack-path computation | This feature stays manual/analyst-drawn; no pathfinding engine is added |

## 3. Requirements

### 3.1 Functional requirements

| ID | Requirement |
|---|---|
| FR-1 | A new "Investigation" tab renders a Cytoscape graph of networks (compound nodes), assets, and firewalls, using the same base data as Topology. |
| FR-2 | The investigator can hide/show any individual node; hiding a network hides its member nodes; a "hidden items" panel lists and restores hidden entities. |
| FR-3 | Quick filters: show only `suspected`/`infected` assets; show only entities with IOC sightings; filter by IOC threat level; optional time window applied to attack edges. |
| FR-4 | Nodes display infection overlay: color by `compromise_status` and an IOC badge with the sighting count; selecting a node shows its details, its IOC sightings, its timeline events, and its incident (attack) edges in a side panel. |
| FR-5 | An **IOC sighting** links one IOC to exactly one asset, network, or firewall, with optional sighting time, location (path/registry/log source), and note. |
| FR-6 | Creating a sighting on an asset can optionally set the asset `compromise_status` to `suspected` or `infected` in the same transaction (never silently — the UI asks; the backend only does it when the flag is passed). |
| FR-7 | IOC ↔ entity sync: the IOC list shows affected entities per IOC; the asset view shows IOCs seen on the asset; the graph badge/panel updates from the same data. Deleting an IOC deletes its sightings; deleting an entity deletes its sightings (both recorded in history). |
| FR-8 | An **attack edge** records analyst-asserted attacker movement: source and target (asset/network/firewall, or a named `external` origin such as "Internet"), label, description, edge type, MITRE tactic/technique, confidence, optional occurrence time, optional link to a timeline event, an explicit sequence number, and linked IOC ids. |
| FR-9 | Attack edges render as distinct directed edges with step numbers ordered by (`sequence`, then `occurred_at`); a playback slider highlights the pathway up to step *n* to visualize the intrusion timeline. |
| FR-10 | A **draw mode** lets the investigator click source node → target node to open a prefilled attack-edge form. |
| FR-11 | **Named saved views**: save/save-as/load/rename/delete multiple views capturing hidden ids, filters, display toggles, layout name, node positions, and camera. Loading a view restores all of it. |
| FR-12 | Sightings and attack edges are evidence: full history commits, expert change bundles, three-way merge, snapshot export/import, partial import, and text-report rendering. Saved views are presentation: excluded from history/merge, included in plain/encrypted snapshots. |
| FR-13 | Deleting a referenced entity behaves deterministically: entity delete removes its attack edges (endpoint is essential) and sightings; timeline-event delete nulls `timeline_event_id` on edges; IOC delete removes the id from edges' `ioc_ids` lists. All ripples are in the same transaction and recorded in the same history commit. |

### 3.2 Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-1 | Fully offline; no new network surface, dependency on remote services, or new heavyweight libraries (reuse Cytoscape, Dagre, existing UI kit). |
| NFR-2 | Backward compatibility: schema migration `user_version` 6 → 7 is additive; a v6 case opens cleanly; old snapshots import unchanged; new snapshot fields are `#[serde(default)]` so old files parse and old readers ignore unknown fields. |
| NFR-3 | Encryption model unchanged: SQLCipher for the case, Argon2id/AES-GCM for portable files; new data is inside the same envelopes. |
| NFR-4 | Backend validation authoritative (not UI-only): enum values, referenced-entity existence, RFC 3339 timestamps, exactly-one-target constraint on sightings, no self-loop attack edges (same kind+id source and target). |
| NFR-5 | Interactive at the scale the app targets (≈ 20 networks / 500 assets / 200 edges); visibility filtering is done via Cytoscape element display, not element rebuild, to keep interactions smooth. |
| NFR-6 | All multi-row mutations are transactional with history commits, per ARCHITECTURE.md §5.3. |
| NFR-7 | Tests: Rust unit tests for migration, CRUD, validation, cascades, merge ordering, export round-trip; vitest for the pure graph-building/visibility/ordering functions and a component smoke test. Release gates of RUNNING_AND_BUILDING.md pass. |

## 4. Data model

Three new tables (migration 6 → 7). UUID string ids, RFC 3339 UTC timestamps, matching existing conventions.

### 4.1 `ioc_sightings` — evidence, history-tracked

```sql
CREATE TABLE ioc_sightings (
    id          TEXT PRIMARY KEY,
    ioc_id      TEXT NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    asset_id    TEXT REFERENCES assets(id) ON DELETE CASCADE,
    network_id  TEXT REFERENCES networks(id) ON DELETE CASCADE,
    firewall_id TEXT REFERENCES firewalls(id) ON DELETE CASCADE,
    sighted_at  TEXT,            -- optional RFC 3339 UTC
    location    TEXT NOT NULL DEFAULT '',  -- file path, registry key, log source…
    note        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    CHECK ((asset_id IS NOT NULL) + (network_id IS NOT NULL) + (firewall_id IS NOT NULL) = 1)
);
CREATE INDEX idx_ioc_sightings_ioc ON ioc_sightings(ioc_id);
CREATE INDEX idx_ioc_sightings_asset ON ioc_sightings(asset_id);
```

Exactly one of the three entity columns is set (`entity_kind` is derived in the API as
`asset | network | firewall`). SQL-level `ON DELETE CASCADE` is a safety net only; the
application performs the deletes explicitly inside the transaction so each removal is
recorded in history (matching how asset deletion already unlinks timeline events).

### 4.2 `attack_edges` — evidence, history-tracked

```sql
CREATE TABLE attack_edges (
    id                TEXT PRIMARY KEY,
    source_kind       TEXT NOT NULL,  -- asset | network | firewall | external
    source_id         TEXT NOT NULL,  -- entity UUID, or free label when kind = external
    target_kind       TEXT NOT NULL,  -- asset | network | firewall
    target_id         TEXT NOT NULL,
    title             TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    edge_type         TEXT NOT NULL,  -- initial_access | lateral_movement | privilege_escalation | persistence | c2 | exfiltration | other
    confidence        TEXT NOT NULL,  -- confirmed | probable | suspected
    mitre_tactic      TEXT,
    mitre_technique   TEXT,
    occurred_at       TEXT,           -- optional RFC 3339 UTC
    timeline_event_id TEXT REFERENCES timeline_events(id) ON DELETE SET NULL,
    sequence          INTEGER NOT NULL DEFAULT 0,  -- analyst ordering when times are unknown
    ioc_ids           TEXT NOT NULL DEFAULT '[]',  -- JSON array of IOC UUIDs
    created_at        TEXT NOT NULL
);
CREATE INDEX idx_attack_edges_source ON attack_edges(source_kind, source_id);
CREATE INDEX idx_attack_edges_target ON attack_edges(target_kind, target_id);
```

Design notes:

- `external` source lets the analyst draw initial access from outside the environment;
  the graph materializes one synthetic node per distinct external label. `external` is
  not allowed as target kind (nothing in-case is "the internet").
- `ioc_ids` is a JSON array rather than a junction table so the whole edge stays one
  entity for field-level three-way merge (the same reason asset `properties` is JSON).
  Backend validates each id exists at write time; IOC deletion rewrites the arrays.
- `timeline_event_id` reuses the existing clock-corrected chronology instead of
  duplicating the clock-profile machinery; when set, the UI displays the event's
  corrected time next to the edge's own `occurred_at`.
- Ordering for display/playback: `sequence ASC, occurred_at ASC NULLS LAST, created_at ASC`.

### 4.3 `investigation_views` — presentation, NOT history-tracked

```sql
CREATE TABLE investigation_views (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    state_json  TEXT NOT NULL,   -- validated InvestigationViewState (see API doc §4)
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
```

`state_json` holds hidden ids, filters, display toggles, layout, positions, and camera
(full schema in the API doc). Views are included in plain/encrypted **snapshots** so a
team can share a curated picture, but excluded from history commits and expert change
bundles (merging two people's pan/zoom is meaningless; last-write-wins by name on
snapshot import: same-id rows are skipped like every other snapshot entity).

### 4.4 Entity classification summary

| Entity | History/merge | Change bundle | Snapshot | Partial import | Text report |
|---|---|---|---|---|---|
| `ioc_sightings` | yes | yes | yes | yes (`ioc_sighting`) | yes |
| `attack_edges` | yes | yes | yes | yes (`attack_edge`) | yes |
| `investigation_views` | no | no | yes | no (future option) | yes (summary only) |

## 5. Synchronization rules (IOC ↔ infection ↔ entities)

1. **Sighting → infection**: `create_ioc_sighting` accepts optional
   `set_compromise_status` (`suspected` or `infected`). When present and the target is
   an asset, the asset row is updated in the same transaction and both changes land in
   one history commit ("Recorded IOC sighting; escalated asset to infected"). It never
   downgrades: if the asset is already `infected`, passing `suspected` is a no-op on the
   asset. The UI asks the investigator explicitly (checkbox in the sighting form,
   defaulting per IOC threat level: `high`/`critical` → preselect `infected` prompt).
2. **IOC list ↔ entities**: `get_infection_summary` (API doc §2.5) is the single derived
   read used by the IOC table ("affected entities" column), the asset panel ("IOCs seen
   here"), and the graph overlay (badge counts, max threat per node). No cached copies.
3. **Deletes** (all transactional, all in history):
   - delete IOC → delete its sightings; remove its id from every `attack_edges.ioc_ids`.
   - delete asset/network/firewall → delete its sightings and every attack edge
     touching it (topology already blocks network deletion while dependents exist —
     the same dependency error lists sightings/edges so nothing disappears surprisingly;
     asset deletion follows its existing explicit-cascade style).
   - delete timeline event → `attack_edges.timeline_event_id` set to NULL (edge keeps
     its own `occurred_at` if any).
4. **Merge**: both new evidence entities take part in field-level three-way merge.
   `entity_order` ranks: `ioc_sighting` = 7 (after `ioc` = 6), `attack_edge` = 7
   (after assets/networks/firewalls/timeline events it references), reversed on delete
   as today.

## 6. UI design

### 6.1 New tab layout

```
┌────────────────────────────────────────────────────────────────────┐
│ Toolbar: [Saved view ▾] [Save] [Save as…] | [Layout ▾] [Fit] [PNG] │
│          [◇ Draw attack edge] [Filters ▾] [Hidden items (3) ▾]     │
├──────────────────────────────────────────────┬─────────────────────┤
│                                              │ Inspector panel     │
│              Cytoscape canvas                │ - entity details    │
│   (networks as compounds, assets, firewalls, │ - IOC sightings     │
│    synthetic external nodes, attack edges    │ - timeline events   │
│    numbered ①②③…)                            │ - attack edges      │
│                                              │ - hide this node    │
├──────────────────────────────────────────────┴─────────────────────┤
│ Pathway playback:  ◀ ─────●──────────── ▶   step 3 / 7  [clear]    │
└────────────────────────────────────────────────────────────────────┘
```

### 6.2 Components

| File | Responsibility |
|---|---|
| `src/components/InvestigationGraph.tsx` | Tab shell: data loading, Cytoscape wiring, toolbar, draw mode, playback state |
| `src/components/investigation/AttackEdgeForm.tsx` | Create/edit attack edge (also opened by draw mode with source/target prefilled) |
| `src/components/investigation/SightingForm.tsx` | Create/edit IOC sighting incl. the compromise-status escalation checkbox |
| `src/components/investigation/EntityInspector.tsx` | Side panel (FR-4) |
| `src/components/investigation/ViewManagerBar.tsx` | Saved-view dropdown + save/save-as/rename/delete |
| `src/lib/investigation-graph.ts` | Pure, unit-tested functions: `buildInvestigationElements`, `applyVisibility`, `computeInfectionOverlay`, `orderAttackPath`, `serializeViewState`/`parseViewState` (signatures in API doc §5) |
| `IocManager.tsx` (edit) | "Affected entities" column + "Record sighting" action |
| `AssetManager.tsx` (edit) | Sighting count surfaced per asset |
| `App.tsx`, `src/types/index.ts` (edit) | `investigation` view, nav item, new TS interfaces |

Visibility is implemented with `element.style('display','none')`/class toggles on the
existing Cytoscape instance (NFR-5); hidden state lives in React and is what gets
serialized into a saved view.

## 7. Implementation phases

Each phase ends green (`npm run lint`, `npm test`, `cargo fmt --check`, `cargo test`, `npm run build`).

### Phase 1 — Schema + IOC sightings backend
`db.rs`: migration v7, `IocSighting` struct, validation, CRUD, cascade rewrites in
`delete_ioc`/`delete_asset`/network/firewall deletion, `get_entity_json` /
`upsert_entity_json` / `delete_entity_direct` arms, `get_infection_summary`;
`history.rs`: `entity_order`; `lib.rs`: 5 commands. Rust tests: migration idempotence,
exactly-one-target check, escalation transaction, cascade + history recording.

### Phase 2 — Attack edges backend
`AttackEdge` struct, validation (kinds, enums, referenced ids, no self-loop, `ioc_ids`
existence, RFC 3339), CRUD, delete ripples (entity/timeline-event/IOC), entity JSON
arms, `entity_order`, 4 commands, tests incl. merge-order and ripple tests.

### Phase 3 — Views + portable formats
`investigation_views` CRUD with `state_json` validation, 4 commands; extend
`ExportData` (+3 collections, `#[serde(default)]`), snapshot import order
(iocs → sightings; edges after all endpoints; views last), partial-import kinds
`ioc_sighting`/`attack_edge`, text-renderer sections; update
`PORTABLE_EXPORT_FORMAT.md` + `INPUT_FORMATS.md`. Round-trip tests old→new and new→old.

### Phase 4 — Investigation Graph frontend
`src/lib/investigation-graph.ts` pure functions + vitest; `InvestigationGraph.tsx` and
sub-components; nav integration; PNG export reuse. Component smoke test.

### Phase 5 — Sync surfaces + docs + release
IocManager/AssetManager integration; ARCHITECTURE.md (§4 data model, §12 non-goals
wording: manual pathway ≠ automated attack-path computation), USER_GUIDE.md section;
full release gates incl. `npm run tauri-build:windows` and the `/verify` GUI pass.

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Merge conflicts on `ioc_ids` JSON arrays (both experts edit the same edge) | Field-level conflict is surfaced like any other field; document that linking IOCs to an edge is a per-edge decision. Acceptable for v1. |
| `state_json` referencing deleted nodes after merge/import | Loading a view ignores unknown ids (defensive parse); saving rewrites the cleaned set. |
| Graph clutter with both topology edges and attack edges | Display toggles (`show_topology_edges`, `show_attack_edges`) in filters; attack edges visually dominant (red, numbered), topology edges dimmed by default in this tab. |
| Scope creep toward automated path computation | Explicit non-goal retained; only analyst-drawn edges. |
| Schema bump breaks older builds opening newer cases | Same policy as previous bumps: older app refuses `user_version` > known; documented in USER_GUIDE. |
