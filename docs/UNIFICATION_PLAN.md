# Branch Unification — Conceptual Mitigation Plan

**Status:** proposal, not yet executed
**Direction:** fold `server` into `main`; `main` becomes the single ground truth for all builds
**Order:** `server` → `main` first; `android` rebases onto the unified `main` afterwards

---

## 1. Objective

Today three long-lived branches each build one shell of the same product:

| Branch | Shell | Ahead / behind `main` |
|---|---|---|
| `main` | Offline Tauri desktop (PC) | — |
| `server` | Browser UI + centralized axum case server | 5 ahead, **0 behind** |
| `android` | Offline Tauri mobile | 7 ahead, 4 behind |

The end state is **one trunk**. `main` holds every shell. Platform is selected at
build time, never by checking out a different branch. All three artifacts are
produced from the same commit by a CI matrix.

**Success is measured by three invariants**, not by a merge landing:

1. A feature written once appears in all three shells without a port.
2. Adding a case command requires editing **one** list, not two.
3. `git diff` between any two shells contains **no** duplicated business logic.

If the merge lands but any invariant fails, the divergence has moved from
branches into files and nothing has been fixed.

---

## 2. Why now

The window is unusually favourable and closes on its own:

- `server` is **0 commits behind `main`**. A merge today is a fast-forward of
  intent; every commit on `main` from here makes it worse.
- 17 commands' worth of feature work — the Investigation Graph, IOC sightings,
  attack edges, saved views, IOC export to CSV/STIX — exists only on `server`.
  Desktop and Android users cannot receive any of it while the branch stands.
- `main`'s last four commits are all *"Sync … from android branch"*. Trunk is
  already being used as a manual mirror for a CI file. That is the failure mode
  arriving early.

---

## 3. What actually differs

The branches do **not** differ by product. They differ along three axes, and
each axis needs a different mitigation. Conflating them is the main way this
migration goes wrong.

### Axis A — Transport (easy, already solved)

Desktop calls `invoke` over Tauri IPC. Browser calls `invoke` over
`POST /api/cmd/{name}`. `src/lib/api.ts` on `server` is already a **drop-in
replacement with identical semantics**: same command names, same camelCase
argument objects, same `{ success, data, error }` envelope.

The observable cost of this axis is ten components that differ by exactly one
line:

```
-import { invoke } from '@tauri-apps/api/core';
+import { invoke } from '@/lib/api';
```

This is not a real difference. It is a missing indirection.

### Axis B — Capabilities (medium)

Eleven registered desktop commands have no server counterpart, and all of them
are the same shape — they open a **native file dialog**:

```
create_new_case              open_existing_case        migrate_legacy_case
save_export_to_file          save_export_as_text       save_change_bundle_to_file
load_import_from_file        load_change_bundle_from_file
load_partial_import_from_file  save_partial_import_template
mark_current_shared_baseline
```

The browser cannot have these, and it does not need them: the server returns the
*text* and the browser downloads it; the browser reads the *file* and posts the
text. `downloadText()` and `pickTextFile()` in `api.ts` already implement this.

This is a genuine platform difference. It requires a declared capability model,
not a transport swap.

### Axis C — Session and concurrency model (hardest)

Desktop holds one case, one expert, in process-global state. The server holds
many cases, many sessions, bearer tokens, unlock throttling, and a monotonic
case revision that browsers poll to notice a teammate's write.

This axis is the one that leaks upward into `App.tsx` — login screens, session
restore, `SESSION_EXPIRED_EVENT`, the 5-second poll, the active-expert list.
It cannot be abstracted away and should not be. It is modelled explicitly.

### The debt underneath all three

`src-tauri/src/lib.rs` registers **79 commands** (1,991 lines).
`server/src/dispatch.rs` matches **85 commands** (1,221 lines).
**68 overlap.** Two hand-maintained command tables sit over one shared core,
which is reached today by `#[path = "../../src-tauri/src/db.rs"]`.

This duplication is the actual root cause. Merging the branches without
resolving it converts a branch-divergence problem into a file-divergence
problem — strictly worse, because the compiler still will not catch it.

---

## 4. Target architecture (conceptual)

```
                    ┌──────────────────────────────┐
                    │        dfir-core             │  ← all business logic
                    │  db · history · secure_db    │    lives here, once
                    │  partial_import · portable   │
                    │  commands (ONE table)        │
                    └───────────┬──────────────────┘
                                │  one command registry
             ┌──────────────────┼──────────────────┐
             │                  │                  │
      ┌──────┴──────┐   ┌───────┴──────┐   ┌───────┴──────┐
      │ desktop     │   │ server       │   │ mobile       │
      │ Tauri IPC   │   │ axum HTTP    │   │ Tauri IPC    │
      │ native fs   │   │ tokens/rev   │   │ app-private  │
      └─────────────┘   └──────────────┘   └──────────────┘
             ▲                  ▲                  ▲
             └──────── same React app ─────────────┘
                    seam: src/lib/api.ts
                    target chosen by build mode
```

Four concepts carry the design:

1. **One command registry.** `dfir-core` owns the canonical list. Each shell
   adapts it — Tauri generates handlers from it, axum routes into it. Neither
   shell restates it. Adding a command becomes a one-line change in one file.

2. **Capability tiers.** Every command declares what it needs: `Core` (pure,
   works everywhere), `LocalFs` (needs native dialogs — desktop and mobile
   only), `MultiUser` (needs sessions — server only). A shell refusing an
   unsupported command is a *typed* outcome, not a missing match arm.

3. **One frontend seam.** `@/lib/api` is the only module in `src/` that knows
   which shell it is running in. Every component imports `invoke` from it,
   including on desktop. Build target selects the implementation.

4. **Session model as an explicit interface**, not an `#ifdef`. Desktop and
   mobile supply a trivial single-user implementation; the server supplies the
   real one. `App.tsx` codes against the interface and stops caring.

---

## 5. Phases

Each phase is independently shippable and independently revertible. **No phase
depends on a later phase to be correct.** Stopping after any phase leaves the
repo in a better state than before it.

### Phase 0 — Freeze and baseline

Declare a change freeze on `server`. Land a CI workflow for the server build on
`main` (there is none today — `desktop-build.yml` and `android-build.yml` exist,
nothing builds or tests the server). Establish the green baseline: `npm test`,
`cargo test` for both crates, and one successful build of each of the three
artifacts, recorded.

*Exit:* every target has a known-good build and test run to compare against.

### Phase 1 — Close Axis A on `main` (branch by abstraction)

On `main`, introduce `src/lib/api.ts` that simply re-exports Tauri's `invoke`.
Convert every component to import from it. Zero behaviour change; the desktop
app is byte-identical in function.

*Why first:* this alone erases the ten one-line forks. After it, the `server`
diff shrinks to things that are genuinely about the server.

*Exit:* no file under `src/` imports `@tauri-apps/api/core` except `api.ts`.

### Phase 2 — Land the shared feature work

Split `server`'s ~10k lines. `src/lib/investigation-graph.ts` (426 lines) has
**zero platform imports** — it is pure domain logic. The graph UI, IOC
sightings, attack edges, saved views, and CSV/STIX export are likewise
platform-neutral; they are hostages of the transport change, not consequences
of it.

Merge these to `main` with desktop wiring. Desktop and (later) Android gain the
Investigation Graph. The `server` branch shrinks to genuinely server-shaped
change.

*Exit:* the Investigation Graph ships in the desktop build from `main`.

### Phase 3 — Extract `dfir-core` as a Cargo workspace

Replace the `#[path]` include with a real workspace: `dfir-core` as a library
crate, `apps/desktop` and `apps/server` depending on it. The comment already in
`server/Cargo.toml` — *"these versions must stay identical"* — becomes an
enforced `[workspace.dependencies]` block instead of a hope.

Pure refactor. No behaviour change. Both binaries build and pass their existing
tests.

*Exit:* `cargo build --workspace` produces both binaries; no `#[path]` remains.

### Phase 4 — Unify the command surface

Move the 68 shared commands into `dfir-core::commands` with capability tags.
Reduce `lib.rs` and `dispatch.rs` to thin adapters. Model the 11 dialog commands
as `LocalFs`-tier with an explicit browser split (server returns text / browser
downloads).

*This is the phase that satisfies invariant 2 and is the point of the exercise.*
It is also the riskiest; it should be its own PR with no other change in it.

*Exit:* adding a command requires editing exactly one list.

### Phase 5 — Land the server shell on `main`

What remains of `server` is now small and honestly server-shaped: `auth.rs`,
`state.rs`, `tls.rs`, `cases.rs`, the axum adapter, the Vite `/api` proxy, and
the session-model implementation. Merge it. Frontend target selection moves to a
Vite mode (`VITE_TARGET=desktop|server|mobile`).

*Exit:* `main` builds all three artifacts. `server` branch deleted.

### Phase 6 — Rebase `android`, then delete the long-lived branches

`android` is small — 1,768 lines, of which 868 are `mobile_device_plan.md`. Its
`use-platform.ts` hook is already the correct pattern and survives as-is. Its
`storage.rs` becomes a capability implementation.

Unify `AGENTS.md` and `docs/` into one set with platform sections, replacing
today's per-branch caveats. Collapse CI into one matrix over three targets.

*Exit:* one branch. Three artifacts. One doc set.

---

## 6. Risk register

| # | Risk | Likelihood | Mitigation |
|---|---|---|---|
| R1 | **`android` edits `src-tauri/src/lib.rs` (+179 lines); Phase 4 rewrites that file.** Direct collision. | High | Land Android's `storage.rs` + `lib.rs` hook **before** Phase 4, or freeze `android` and treat its diff as a patch to re-apply against the new structure. Decide before Phase 3 starts. |
| R2 | Merge stalls midway; repo left in a worse hybrid than three clean branches. | Medium | Every phase independently shippable and revertible. Never begin a phase without the previous one merged and green. |
| R3 | Silent regression in the encryption / SQLCipher path during the workspace extraction. | Medium | Phase 3 is a pure move: no logic edits allowed in the same commit. Full `cargo test` plus one real encrypted round-trip per shell before merge. |
| R4 | `src/types/index.ts` conflicts (`server` +116, `android` +13). | High | Trivially resolved if `server` lands first — Android's 13 lines then apply to a superset. This is a further argument for the chosen order. |
| R5 | Capability model under-specified; `LocalFs` commands silently no-op in the browser. | Medium | Unsupported capability must be a typed, user-visible error, never a silent success. Test explicitly per shell. |
| R6 | Desktop regression goes unnoticed because only the server is exercised. | Medium | Phase 0's CI must build **all three** from the start, not just the one being worked on. |
| R7 | Docs drift again during the migration. | Low | Doc unification is Phase 6 work, but each phase updates `AGENTS.md` in the same PR. |

---

## 7. Decisions needed from a human

These are not technical unknowns; they are product calls that change the plan:

1. **Does the desktop shell keep offline multi-expert bundle-merge**, or does
   the server become the only collaboration path? This determines whether
   `history.rs` bundle merge stays a first-class `Core` capability or degrades
   to a legacy import path.
2. **Does Android target the server, offline, or both?** If both, mobile needs
   the same seam as desktop and the capability model must handle it. If
   server-only, `storage.rs` may be retired instead of ported.
3. **Is there a deployed version in the field needing patches during the
   migration?** If yes, cut `release/1.0.x` from today's `main` at Phase 0 and
   cherry-pick into it. If no, skip release branches entirely.
4. **Freeze duration tolerable on `server`.** Phases 1–5 are the freeze window.
   If a feature must ship mid-migration, it lands on `main` and is picked up by
   the merge — not committed to `server`.

---

## 8. Explicitly out of scope

- No feature work during Phases 1, 3, and 4. Refactor and feature in one commit
  is how this kind of migration fails to be reviewable.
- No change to the `.dfirx` portable format, the SQLCipher schema, or the
  on-disk case layout. Data compatibility is invariant throughout.
- No change to the security model — session tokens, unlock throttling, and the
  password-as-presence-control design are ported as-is, not redesigned.
- No adoption of a monorepo tool, package manager change, or CI platform change.
