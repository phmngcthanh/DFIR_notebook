# DFIR Network Investigator — Mobile Tablet App Plan

> **Target Device**: Samsung Galaxy Tab S9 FE (10.9″, 1440×2304; ships Android 13, upgradeable — verify the demo unit's actual OS, anything ≥ 13 is fine)  
> **Strategy**: Extend the existing Tauri v2 codebase to produce an Android tablet build **from the same repo, on an `android` branch** — not a separate project, not a fork.  
> **Revision note (2026-07-20)**: adjusted after verification against the actual repo — corrected line counts (~2.7k frontend lines, not ~8.7k), corrected the "zero backend changes" claim (8 dialog-gated commands need Android paths), replaced the Windows-host Android build with a CI/WSL2 strategy, and added a Demo Track for a Tab S9 FE demo.

---

## 0. Demo Track — getting it on the Tab S9 FE fast

Read this before the full roadmap. The full plan below is a 12-week productization path; the demo needs only a vertical slice. Order of work is dictated by risk, not by feature value:

| Step | What | Why first | Est. |
|---|---|---|---|
| D1 | Add an `android-build.yml` GitHub Actions job (ubuntu runner) that runs `tauri android init` + `tauri android build --apk` and uploads the APK artifact | The single biggest risk is SQLCipher + vendored OpenSSL cross-compiling for `aarch64-linux-android`. Prove it in CI before touching any UI. The repo already has a `workflow_dispatch` CI pattern (`desktop-build.yml`) to copy. **Do not attempt this build on the Windows dev host** (see §9.1). | 1–2 days |
| D2 | Android-gate the 8 dialog-dependent commands (see §6.1): on Android, create/open cases in app-private storage instead of a native Save dialog; add a minimal `list_local_cases` command + a bare-bones case picker screen | `blocking_save_file` has no Android equivalent — case creation simply cannot work on the tablet without this. This is the only mandatory Rust work for the demo. | 2–3 days |
| D3 | Minimal UI triage, gated on platform (not window width): collapse the sidebar to an icon rail, make dialogs/sheets fit the viewport, bump touch targets on the main flows | Demo flows only: create case → expert → networks/assets → topology → timeline → IOC → Activity Board. Skip the Export/Import wizard rework; skip swipe gestures. | 2–3 days |
| D4 | Sideload and rehearse on the real device: `adb install`, walk the demo script, fix the top 5 usability breaks | WebView rendering and touch behavior on the actual device always surface surprises. | 1–2 days |

**Demo scope cuts**: no share-intent integration, no merge-conflict wizard, no `FLAG_SECURE`, no biometrics, no Case File Manager beyond a list+open+create screen. Expert Merge can be *shown* by pre-loading a bundle file via `adb push` if needed.

**Signing for sideload**: the debug keystore that `tauri android build --apk --debug` uses is enough for a demo install; a release APK needs a one-off self-signed keystore (`keytool -genkeypair`) wired into `gen/android` signing config — keep the keystore out of git.

---

## 0.5 Repository & Branch Strategy

The user question "other branch, other repo, or the same?" — recommendation: **same repo, `android` branch, merge early**.

- **Same repo** because the Rust backend, DB schema, history/merge engine, and TS types are shared byte-for-byte; a second repo forks them permanently and breaks the case-file/bundle interoperability guarantee the moment the schema moves.
- **A branch (`android`)** because `tauri android init` generates a sizeable `src-tauri/gen/android/` Gradle project that should land as one reviewable commit, and Phase-0 experimentation (NDK versions, gradle tweaks) shouldn't churn `main`.
- **Merge early, not late**: once CI proves the APK builds, merge to `main`. All mobile UI work is additive (platform-gated components, new hooks/layouts) and desktop behavior must be gated on **runtime platform detection, not viewport width** (see §5.5 warning) so `main` stays safe for desktop releases.
- A separate repo is justified only if a separate team owns mobile or license/distribution boundaries demand it (not the case here — single AGPL codebase).
- For the demo specifically: cut a `demo/tab-s9fe` branch off `android` for last-minute hacks; never demo from `main`.

---

## 0.7 Gap Analysis & P0–P4 Implementation Plan

### What actually stands between the current repo and "runs on the Tab S9 FE"

**Technical gaps** (backend/build):

| # | Gap | Blocking? | Where it can be closed |
|---|---|---|---|
| T1 | No platform detection anywhere (frontend or backend) | Yes | This machine, now |
| T2 | 10 dialog-gated commands cannot work on Android (no Save dialog; picks return `content://`): `create_new_case`, `open_existing_case`, `migrate_legacy_case`, plus everything funneling through `save_text_file`/`pick_text_file` (`save_export_to_file`, `save_export_as_text`, `save_change_bundle_to_file`, `load_import_from_file`, `load_change_bundle_from_file`, `save_partial_import_template`, `load_partial_import_from_file`) | Yes | This machine, now — the funnel helpers centralize most of it |
| T3 | No app-private case storage (list/create/open cases without a file dialog) | Yes | This machine, now |
| T4 | No Android project scaffold (`src-tauri/gen/android`) | Yes | Needs Android SDK/NDK host (`tauri android init`) |
| T5 | SQLCipher + vendored OpenSSL unproven for `aarch64-linux-android` | Yes | CI ubuntu runner (workflow can be written now, run on push) |
| T6 | No signing keystore | For release APK only | Later; debug signing fine for demo |
| T7 | Android lifecycle (WAL checkpoint on pause, state restore) | No (polish) | On-device phase |
| T8 | `content://` URI support for SAF interop | No (inbox/adb-push pattern covers demo) | Later, via `tauri-plugin-android-fs` after vetting |

**UI gaps** (frontend):

| # | Gap | Blocking? |
|---|---|---|
| U1 | Shell is desktop-only: fixed 240-px sidebar, no mobile navigation | Yes |
| U2 | Case open/create flow assumes file paths + native dialogs | Yes |
| U3 | Touch targets below 48 dp everywhere (`size="sm"` buttons ≈ 32 px, dense table rows) | Yes (usability) |
| U4 | Centered modals & nested dialogs (FirewallDetails) don't fit / stack badly on tablet | Partial |
| U5 | No orientation handling (landscape rail vs portrait bottom nav) | Partial |
| U6 | Topology/timeline toolbars sized for mouse | Partial |
| U7 | Soft-keyboard overlap on forms | On-device tuning |

### P0–P4 (status reflects what is implemented on the `android` branch)

| Phase | Scope | Status |
|---|---|---|
| **P0 — Platform foundation** | `android` branch; `isAndroid()`/`useIsAndroid()` detection with a dev override (`localStorage dfir-platform-override`) so the mobile UI is testable in the desktop build; mobile capability file; CI workflow file `android-build.yml` (dispatch-ready, unpushed) | ✅ done locally |
| **P1 — Android storage backend** (closes T1–T3) | New `storage.rs`: app-private `cases/`, `exports/`, `inbox/` dirs; `list_local_cases`, `open_local_case`, `get_platform_info` commands (work on all platforms); `#[cfg(target_os = "android")]` branches in `create_new_case`, `save_text_file` (→ exports dir), `pick_text_file` (→ newest inbox file, populated via `adb push`), `migrate_legacy_case` (desktop-only error). Desktop behavior byte-identical; new logic unit-tested on desktop | ✅ done locally |
| **P2 — Mobile shell & case flow UI** (closes U1–U2, U5) | `MobileShell` (top bar + landscape icon rail / portrait bottom nav), `CasePicker` (list/open/create local cases), platform-gated `App.tsx`, `touch-ui` CSS layer (U3 first pass); component tests | ✅ done locally |
| **P3 — Feature-surface touch adaptation** (U3–U6) | Sheet-style forms, FirewallDetails stacked nav, topology FABs, timeline item heights, Export/Import wizard | ◻ not started — needs on-device feedback to be worth doing |
| **P4 — Device enablement** (closes T4–T7) | `tauri android init` (SDK host), push branch → run `android-build.yml` → APK artifact, `adb install` on the Tab S9 FE, on-device fix round, keystore for release builds | ⛔ blocked here by design: requires Android SDK and a push, and this work is intentionally not pushed yet |

**Exit criteria for P4/demo**: APK installs on the Tab S9 FE; create case → expert → network → asset → topology → timeline event → IOC → Activity Board all work by touch; export writes to the app-private exports dir; a bundle pushed via `adb push` imports through Expert Merge.

---

## Table of Contents

0. [Demo Track — Tab S9 FE](#0-demo-track--getting-it-on-the-tab-s9-fe-fast) · [Repository & Branch Strategy](#05-repository--branch-strategy)
1. [Executive Summary](#1-executive-summary)
2. [Technology Strategy](#2-technology-strategy)
3. [Target Device Profile](#3-target-device-profile)
4. [Feature Analysis: Keep / Adapt / Remove](#4-feature-analysis-keep--adapt--remove)
5. [UI/UX Redesign for Tablet](#5-uiux-redesign-for-tablet)
6. [Backend & Database Considerations](#6-backend--database-considerations)
7. [Security Considerations](#7-security-considerations)
8. [File System & Storage](#8-file-system--storage)
9. [Build & Toolchain Setup](#9-build--toolchain-setup)
10. [Phased Implementation Roadmap](#10-phased-implementation-roadmap)
11. [Risk Assessment & Mitigations](#11-risk-assessment--mitigations)
12. [Testing Strategy](#12-testing-strategy)
13. [Open Questions for Decision](#13-open-questions-for-decision)

---

## 1. Executive Summary

The current DFIR Network Investigator is a **Tauri v2 desktop app** (Rust + React 19) with SQLCipher-encrypted case files, ~60 IPC commands, 14 feature components, and Git-like expert merge collaboration. The goal is to produce a **companion tablet app** for field investigators who need to input findings, view network topology, manage timelines, and exchange change bundles from a Samsung Galaxy Tab S9 FE — all while maintaining the same encrypted database format and security guarantees.

### Why Tauri v2 Mobile (Not a Rewrite)

Tauri v2 shipped stable Android/iOS support in October 2024. This means:

- **Same Rust backend** — all ~60 IPC commands, SQLCipher integration, history engine, merge logic, and portable export code compile for Android ARM64 without modification.
- **Same React frontend** — the UI runs in Android's system WebView (not bundled Chromium), so all React components, shadcn/ui, Tailwind CSS work as-is.
- **Single codebase** — desktop and mobile builds from one monorepo, sharing backend logic and most frontend code.
- **Small binary** — no bundled browser engine; relies on the system WebView.

The main work is **UI adaptation** (touch-friendly layouts for a 10.9″ screen) and **platform integration** (Android file access, storage permissions, lifecycle management).

---

## 2. Technology Strategy

### 2.1 Architecture: Shared Monorepo

```
web_dfir/                         # Existing monorepo
├── src/                          # Frontend (React 19 + TypeScript)
│   ├── components/               # Feature components (shared + mobile overrides)
│   │   ├── mobile/               # NEW: Mobile-specific layout wrappers
│   │   └── ui/                   # shadcn/ui (unchanged)
│   ├── hooks/                    # EXISTS: use-mobile.ts (shadcn useIsMobile) — extend with usePlatform()
│   ├── layouts/                  # NEW: Desktop vs tablet layout shells
│   ├── lib/                      # utils.ts, topology-layout.ts (unchanged)
│   ├── config/                   # branding.ts (unchanged)
│   └── types/                    # index.ts (unchanged)
├── src-tauri/
│   ├── src/                      # Rust backend (unchanged — compiles for all targets)
│   ├── gen/                      # NEW: Generated Android project files
│   │   └── android/              # Gradle project, AndroidManifest, Kotlin glue
│   ├── Cargo.toml                # Add Android targets + conditional deps
│   ├── tauri.conf.json           # Extend for mobile window/lifecycle config
│   └── capabilities/
│       ├── default.json          # Desktop capabilities (unchanged)
│       └── mobile.json           # NEW: Mobile-specific capabilities
├── scripts/
│   └── tauri-build.mjs           # Extend with Android build target
└── mobile_device_plan.md         # This file
```

### 2.2 Key Technology Decisions

| Decision | Choice | Rationale |
|---|---|---|
| **Framework** | Tauri v2 (same as desktop) | Code reuse, same Rust backend, proven stability |
| **Frontend** | React 19 + Tailwind CSS 3 + shadcn/ui | Already in use; responsive design via CSS media queries and layout components |
| **Database** | `rusqlite` + `bundled-sqlcipher-vendored-openssl` | Same crate, cross-compiles to ARM64 via Android NDK |
| **File Access** | `tauri-plugin-dialog` + `tauri-plugin-android-fs` | Official dialog's *pick* works on Android (returns `content://` URIs); **save dialogs do not exist on Android** — app-private storage replaces them (§6.1). `tauri-plugin-android-fs` is a **community plugin** (not tauri-apps org): pin the version, review its source and requested permissions before adopting — this is a security-sensitive AGPL project |
| **Graph Viz** | Cytoscape.js (same) | Has built-in touch gesture support (pinch-zoom, drag-pan) |
| **Timeline Viz** | vis-timeline (same) | Touch-compatible; needs performance tuning for mobile |
| **Crypto** | `aes-gcm`, `argon2`, `getrandom`, `zeroize` (same) | Pure Rust, cross-platform, no platform-specific deps |

### 2.3 What Changes vs What Stays

| Layer | Changes | Stays the Same |
|---|---|---|
| **Rust backend** | Add Android NDK build targets, `tauri-plugin-android-fs`, Android-aware file paths | All 60+ IPC commands, DB schema, SQLCipher, history/merge engine, portable export, crypto |
| **React frontend** | New mobile layout shell, responsive breakpoints, touch-optimized UI, swipe navigation | All TypeScript types, IPC call patterns (`invoke` + `ApiResponse`), business logic, Tailwind/shadcn |
| **Build system** | New `tauri-build:android` script, Android SDK/NDK setup, Gradle config | Existing desktop build scripts unchanged |
| **Config** | Mobile-specific Tauri capabilities, CSP adjustments for Android WebView | Desktop capabilities unchanged |

---

## 3. Target Device Profile

### Samsung Galaxy Tab S9 FE

| Spec | Value | Impact on App |
|---|---|---|
| **Display** | 10.9″ IPS LCD, 1440 × 2304 px | ~247 PPI — crisp text, but layout must account for ~10″ usable viewport |
| **Refresh Rate** | 90 Hz | Smooth animations; keep frame budget tight |
| **OS** | Ships Android 13 (One UI 5.1); Samsung promises upgrades to ~Android 17 — **check the actual demo unit** | Any Android 13+ WebView is fine; scoped storage fully enforced either way. Update Android System WebView from the Play Store on the demo unit beforehand |
| **RAM** | 6 GB (base) / 8 GB | Comfortable for SQLCipher + WebView + React; avoid excessive DOM nodes |
| **Storage** | 128 GB (base) + microSD | Ample for case files (typically < 50 MB each) |
| **Input** | Touch + optional S Pen + optional keyboard | Must support all three; touch is primary |
| **Orientation** | Landscape primary for field work | Design for landscape-first, support portrait as secondary |
| **Connectivity** | WiFi + optional 5G | App is offline-first; connectivity only needed for file exchange |

### Viewport Considerations

In **landscape orientation** on a 10.9″ 1440×2304 display:
- Effective CSS viewport: approximately **1138 × 720 dp** (at default Android scaling)
- This is comparable to a small laptop screen — the desktop layout mostly works, but needs denser spacing and touch-friendly targets
- Minimum touch target: **48 × 48 dp** (Android Material Design guideline)

---

## 4. Feature Analysis: Keep / Adapt / Remove

### 4.1 Feature-by-Feature Assessment

| # | Feature | Desktop Component | Lines | Decision | Tablet Notes |
|---|---|---|---|---|---|
| 1 | **Case Setup** (create/open) | `CaseSetup.tsx` | ~375 | ✅ **KEEP** (adapt) | Use Android file picker via `tauri-plugin-dialog`; simplify path display for `content://` URIs |
| 2 | **Expert Setup** | `ExpertSetup.tsx` | ~85 | ✅ **KEEP** (as-is) | Simple form; works perfectly on tablet |
| 3 | **Dashboard** (main shell) | `Dashboard.tsx` | ~560 | ✅ **KEEP** (major adapt) | Replace tab bar with bottom navigation or side rail; add hamburger menu for less-used features |
| 4 | **Network Manager** | `NetworkManager.tsx` | ~330 | ✅ **KEEP** (adapt) | Card-based list instead of dense table; larger touch targets for CRUD |
| 5 | **Asset Manager** | `AssetManager.tsx` | ~700 | ✅ **KEEP** (adapt) | Swipeable card list; detail panel as full-screen sheet instead of side panel |
| 6 | **Network Topology** | `NetworkTopology.tsx` | ~1150 | ✅ **KEEP** (adapt) | Cytoscape.js has touch support; enlarge node touch targets; simplify toolbar to floating action buttons; fullscreen mode |
| 7 | **Timeline View** | `TimelineView.tsx` | ~1200 | ✅ **KEEP** (adapt) | vis-timeline touch-compatible; larger item heights; simplified event creation form; bottom sheet for event details |
| 8 | **IOC Manager** | `IocManager.tsx` | ~450 | ✅ **KEEP** (adapt) | Card list with swipe actions; search bar always visible |
| 9 | **Note Manager** | `NoteManager.tsx` | ~600 | ✅ **KEEP** (adapt) | Split view: list left, content right (landscape); full-screen editor in portrait; keep SafeMarkdown renderer |
| 10 | **Firewall Details** | `FirewallDetails.tsx` | ~850 | ✅ **KEEP** (adapt) | Multi-level drill-down (firewall → interfaces → NAT rules) as stacked sheets instead of nested dialogs |
| 11 | **Activity Board** | `ActivityBoard.tsx` | ~720 | ✅ **KEEP** (adapt) | Scrollable activity feed optimized for touch; collapsible sections |
| 12 | **Export/Import** | `ExportImport.tsx` | ~1080 | ✅ **KEEP** (adapt) | Simplify to step-by-step wizard instead of multi-tab layout; share-intent integration for file exchange |
| 13 | **Partial Import** | `PartialImportPanel.tsx` | ~430 | ✅ **KEEP** (adapt) | Step-by-step wizard; better textarea for JSON on mobile (maybe file picker instead of paste) |
| 14 | **About Page** | `AboutPage.tsx` | ~145 | ✅ **KEEP** (as-is) | Static content; works as-is |

### 4.2 Summary: ALL Features Kept

> **Every feature is retained.** The investigator needs the same capabilities in the field. The work is entirely in **UI adaptation**, not feature removal.

### 4.3 Features That Need the Most Adaptation

| Priority | Feature | Reason |
|---|---|---|
| 🔴 Critical | **Dashboard** | Navigation paradigm must change from horizontal tabs to tablet-friendly navigation |
| 🔴 Critical | **Network Topology** | Canvas interaction needs touch optimization; floating toolbar |
| 🔴 Critical | **Timeline View** | Complex form + vis-timeline need responsive redesign |
| 🟡 High | **Export/Import** | Multi-tab layout with merge preview is too complex for touch; needs wizard flow |
| 🟡 High | **Firewall Details** | Deeply nested dialogs need stacked navigation |
| 🟡 High | **Asset Manager** | Dense table needs card-based alternative |
| 🟢 Medium | **Network/IOC/Note Managers** | Moderate table-to-card conversions |
| ⚪ Low | **Case/Expert Setup, About** | Work nearly as-is |

---

## 5. UI/UX Redesign for Tablet

### 5.1 Design Principles

1. **Eliminate Desktop Paradigms**: Remove wide, persistent sidebars (which waste precious horizontal space) and duplicate UI elements (like the double New/Open Case buttons on the welcome screen).
2. **Touch-First UI**: All interactive elements must be ≥ 48dp with generous padding. No hover-dependent interactions.
3. **Immersive Workspace**: Maximize the workspace area by hiding navigation when it's not actively being used, or condensing it into a minimal footprint.
4. **Familiar Mobile Patterns**: Adopt bottom navigation (portrait) or a collapsible mini-rail (landscape) rather than traditional desktop sidebars.
5. **Modal/Sheet Transitions**: Replace desktop popup `<Dialog>` components with mobile-friendly slide-up `<Sheet>` components or full-screen overlays.

### 5.2 Navigation Redesign (Addressing the Current Layout)

**The Problem with Current Desktop Layout:**
As seen in the current UI, the app uses a persistent, wide left sidebar that consumes ~20% of the screen width at all times. Additionally, the Welcome screen duplicates the "New Case" / "Open Case" buttons in both the sidebar and the center pane, confusing the visual hierarchy on a smaller screen.

**Tablet Solution:**
- **Welcome Screen**: Completely hide the sidebar when no case is loaded. Present a clean, centered interface with single, prominent "Create Case" and "Open Case" buttons.
- **In-Case Navigation (Landscape)**: Introduce a **collapsible mini-rail**. By default, it shows only icons (taking up minimal width). It can be expanded by tapping a hamburger menu.
- **In-Case Navigation (Portrait)**: Use a **bottom navigation bar** for the 4-5 most critical tools, with a "More" menu for the rest.

#### Tablet — Landscape Layout (Mini-rail)
```
┌──┬──────────────────────────────────────────────┐
│≡ │ [Case Name] • [Expert Name]                   │
├──┼──────────────────────────────────────────────┤
│🌐│                                              │
│💻│                                              │
│🗺️│         Primary Workspace Area               │
│⏱️│         (Takes up 95% of screen)             │
│🔍│                                              │
│≡ │                                              │
└──┴──────────────────────────────────────────────┘
```

#### Tablet — Portrait Layout (Bottom Nav)
```
┌─────────────────────────────────────────────────┐
│ ≡ [Case Name] • [Expert Name]                   │
├─────────────────────────────────────────────────┤
│                                                 │
│                                                 │
│         Primary Workspace Area                  │
│                                                 │
│                                                 │
│                                                 │
├─────────────────────────────────────────────────┤
│    🌐       💻       🗺️       ⏱️       🔍      │
│  Networks  Assets   Graph  Timeline   More      │
└─────────────────────────────────────────────────┘
```

### 5.3 Component-Level UI Adaptations

#### Case Setup (Welcome Screen)
- **Action**: Completely redesign `CaseSetup.tsx`.
- **Change**: Remove the sidebar wrapper entirely when in this view. Use a full-screen, clean layout with large touch targets for the two primary actions. Eliminate the redundant sidebar buttons shown in the desktop screenshot.

#### Tables → Cards
- All entity list views (networks, assets, IOCs, notes, firewalls) get a **card variant**
- Use a `useIsMobile()` hook to switch between `<Table>` and card list
- Cards: title, key fields, status badge, swipe-right to edit, swipe-left to delete
- Search/filter bar stays at top, always visible

#### Dialogs → Bottom Sheets
- Desktop `<Dialog>` (centered modal) → tablet `<Sheet side="bottom">` (slide-up panel)
- Full-screen sheet for complex forms (asset creation, timeline event, firewall NAT rule)
- Half-screen sheet for simple forms (network creation, IOC entry)
- Keep existing `<Sheet>` component from shadcn/ui — just change the `side` prop

#### Network Topology (Cytoscape.js)
- **Fullscreen mode**: hide nav, maximize canvas with a floating toolbar
- **Touch targets**: increase node size from current to ≥ 48dp tap area
- **Floating Action Buttons (FAB)**:
  - Fit-to-screen, Zoom in/out, Layout toggle, Save view, Export PNG
  - Positioned bottom-right, collapsible
- **Context menu**: long-press on node/edge → action sheet (instead of right-click menu)
- **Pinch-to-zoom and drag-to-pan**: already native in Cytoscape.js
- **Performance**: use `cy.batch()` for updates; limit visible labels at low zoom levels

#### Timeline View (vis-timeline)
- **Landscape**: timeline widget takes full width; event detail panel slides up from bottom
- **Touch scrolling**: vis-timeline handles touch natively; increase item height to 48dp+
- **Event creation**: FAB "+" button → full-screen form sheet
- **Simplified form**: group MITRE ATT&CK fields into collapsible sections
- **Performance**: set `autoResize: false`; batch updates; simplify item CSS

#### Export/Import
- Replace 3-tab layout with a **step-by-step wizard**:
  1. Choose operation (Snapshot / Expert Merge / Partial Import)
  2. Choose direction (Export / Import)
  3. Execute + review (for imports: preview → resolve conflicts → apply)
- Use Android **share intent** for file exchange (send/receive `.json` / `.dfirx` files)
- File picker instead of textarea paste for JSON input

#### Firewall Details
- Replace nested `Dialog` hierarchy with **stacked navigation**:
  - Level 1: Firewall list (cards)
  - Level 2: Firewall detail → interface list
  - Level 3: Interface detail → NAT rule list
  - Level 4: NAT rule form
- Each level is a full-screen view with a back button
- Breadcrumb trail at top: `Firewalls > PaloAlto-01 > eth0 > NAT Rules`

### 5.4 Touch Interaction Patterns

| Desktop Pattern | Tablet Replacement |
|---|---|
| Right-click context menu | Long-press → action sheet |
| Hover tooltip | Tap-and-hold → tooltip; or inline labels |
| Drag-and-drop (rare) | Touch drag (Cytoscape handles this) |
| Keyboard shortcuts | FABs + gesture shortcuts |
| Resize panels | Fixed layout ratios or swipe to toggle |
| Small icon buttons | Minimum 48dp touch targets |
| Dense table rows | Card list or expanded table rows (56dp+ height) |
| Multi-select checkbox | Touch multi-select with selection bar |

### 5.5 Responsive Breakpoints

```css
/* Existing desktop styles are the default */

/* Tablet landscape (primary target) */
@media (max-width: 1200px) and (min-width: 768px) and (orientation: landscape) {
  /* Side rail navigation, two-column layouts */
}

/* Tablet portrait */
@media (max-width: 768px), (orientation: portrait) {
  /* Bottom nav, single-column, stacked layouts */
}
```

> [!WARNING]
> **Do not gate the mobile layout on viewport width alone.** The desktop window is resizable down to 1024×768 (`tauri.conf.json` minWidth/minHeight), which falls inside the `max-width: 1200px` tablet breakpoint above — a desktop user shrinking the window would suddenly get the tablet shell. Gate the layout switch on **runtime platform** (Tauri `@tauri-apps/api/core` → `platform()`, or `navigator.userAgent`), and use width breakpoints only for orientation/density decisions *within* the mobile shell.

The existing `useIsMobile()` hook (`src/hooks/use-mobile.ts`, 768px matchMedia) is a width check only — add a separate `usePlatform()` hook for the Android gate.

---

## 6. Backend & Database Considerations

### 6.1 Rust Backend: Business Logic Unchanged — but 8 Commands Are Dialog-Gated

The business logic (DB, history/merge, crypto, partial import) compiles for Android ARM64 without changes. However, the original claim of "zero backend changes" is **wrong**: eight commands call native file dialogs, and Android has no blocking Save dialog at all:

| Command | Dialog use | Android adaptation |
|---|---|---|
| `create_new_case` | `blocking_save_file` to choose the `.db` path | Create in app-private storage; name derived from case name; no dialog |
| `open_existing_case` | file pick | Pick works but returns `content://` — copy-to-private first, or list app-private cases instead |
| `migrate_legacy_case` | pick + save | Same combination of the two patterns |
| `save_export_to_file`, `save_export_as_text`, `save_change_bundle_to_file` | `blocking_save_file` | Write to app-private export dir, then share intent / SAF `createDocument` via `tauri-plugin-android-fs` |
| `load_import_from_file`, `load_change_bundle_from_file` | file pick | Read through `content://` (plugin) or copy-to-private |

Pattern: `#[cfg(target_os = "android")]` branches inside these handlers (or a small `storage` module with desktop/android implementations). Everything else:

- **The remaining ~50 IPC commands**: same function signatures, same `Response<T>` return type
- **SQLCipher**: `bundled-sqlcipher-vendored-openssl` cross-compiles via the Android NDK's Clang/LLVM toolchain
- **Crypto**: `aes-gcm`, `argon2`, `getrandom`, `zeroize` are pure Rust or have Android support
- **UUID generation**: `uuid` crate works on all platforms
- **Serialization**: `serde` + `serde_json` are platform-independent

### 6.2 Database Schema: Identical

No schema changes. The same `.db` file format works on both desktop and tablet:

| Aspect | Desktop | Tablet |
|---|---|---|
| Schema | Same DDL, same `PRAGMA user_version` | Identical |
| Encryption | SQLCipher + PBKDF2 key derivation | Identical |
| Data types | All TEXT/INTEGER/REAL, JSON in TEXT columns | Identical |
| Foreign keys | Enabled on every connection | Identical |
| Migrations | `validate_and_migrate_case()` runs on open | Identical |

### 6.3 File Interoperability

Case files (`.db`) and export files (`.json`, `.dfirx`) are **fully interoperable** between desktop and tablet:

- A case created on desktop can be opened on tablet and vice versa
- Change bundles exported from desktop can be imported on tablet
- Portable `.dfirx` exports use the same Argon2id + AES-256-GCM on both platforms

### 6.4 Android-Specific Database Concerns

| Concern | Mitigation |
|---|---|
| **Storage location** | Use app-private internal storage (`/data/data/<pkg>/databases/`) for active case files; export to shared storage via `tauri-plugin-android-fs` |
| **File URIs** | Android returns `content://` URIs from file picker; need adapter layer to copy selected file to app-private storage before opening with `rusqlite` |
| **WAL mode** | SQLite WAL works on Android; no changes needed |
| **Concurrent access** | Still single-case-at-a-time; `Mutex<Option<Connection>>` works on Android |
| **App lifecycle** | Handle `onPause`/`onStop` — may need to checkpoint WAL and release file locks |

### 6.5 Content URI Adapter Pattern

```
User selects file via Android picker
        ↓
    content://... URI returned
        ↓
    Copy file to app-private storage
        ↓
    Open copy with rusqlite + SQLCipher
        ↓
    On save/close: offer to export back to original location
```

This is necessary because `rusqlite` requires a filesystem path, not a content URI.

---

## 7. Security Considerations

### 7.1 Security Parity with Desktop

| Security Feature | Desktop | Tablet | Notes |
|---|---|---|---|
| **DB encryption** | SQLCipher | SQLCipher (same) | Same crate, same crypto |
| **Memory zeroization** | `Zeroizing<String>` | Same | Rust memory model is platform-independent |
| **Portable exports** | Argon2id + AES-256-GCM | Same | Same Rust code |
| **CSP** | Strict, local-only | Strict, local-only | Same `tauri.conf.json` settings apply to Android WebView |
| **Capabilities** | Minimal (core + dialog) | Minimal + android-fs | One additional plugin for Android file access |
| **SQL injection** | Parameterized queries only | Same | Same Rust code |
| **XSS** | No dangerouslySetInnerHTML | Same | Same React components |
| **No remote content** | CSP blocks all remote | Same | Android WebView respects CSP |

### 7.2 Additional Mobile Security Measures

| Measure | Implementation |
|---|---|
| **Screen lock integration** | Require device PIN/biometric to open the app (optional, via Android Keyguard API) |
| **Screenshot prevention** | Set `FLAG_SECURE` on the Android activity to block screenshots and screen recording |
| **App-private storage** | All case files stored in app-private directory; not accessible to other apps without root |
| **Clipboard hygiene** | Clear clipboard of passwords after a timeout |
| **Background protection** | Show blank/branded screen in app switcher to prevent data leakage |

### 7.3 New Capability Requirements

```json
{
  "identifier": "mobile",
  "description": "mobile-specific capabilities",
  "permissions": [
    "core:default",
    "dialog:default",
    "android-fs:default"
  ]
}
```

---

## 8. File System & Storage

### 8.1 Android Storage Model

Android enforces **scoped storage** (since Android 10, fully enforced on Android 13+):

| Storage Type | Access | Use Case |
|---|---|---|
| **App-private internal** (`/data/data/<pkg>/`) | App only | Active case files, temp files |
| **App-private external** (`/sdcard/Android/data/<pkg>/`) | App only (no SAF needed) | Case file backups, large exports |
| **Shared storage** (via SAF/MediaStore) | User-granted | Exchanging `.dfirx` / `.json` files with other apps |

### 8.2 File Flow for Tablet

```
┌──────────────────────────────────────────────────┐
│                  File Operations                  │
├──────────────────────────────────────────────────┤
│                                                   │
│  CREATE CASE                                      │
│  ┌─────────────┐    ┌──────────────────┐         │
│  │ User enters │───→│ Create .db in    │         │
│  │ name + pass │    │ app-private dir  │         │
│  └─────────────┘    └──────────────────┘         │
│                                                   │
│  OPEN CASE                                        │
│  ┌─────────────┐    ┌──────────────────┐         │
│  │ Android file│───→│ Copy to app-     │         │
│  │ picker      │    │ private, open    │         │
│  └─────────────┘    └──────────────────┘         │
│                                                   │
│  EXPORT                                           │
│  ┌─────────────┐    ┌──────────────────┐         │
│  │ Export data  │───→│ Save to shared   │         │
│  │ as .json/   │    │ storage via SAF   │         │
│  │ .dfirx      │    │ or share intent  │         │
│  └─────────────┘    └──────────────────┘         │
│                                                   │
│  IMPORT                                           │
│  ┌─────────────┐    ┌──────────────────┐         │
│  │ Pick file   │───→│ Read from        │         │
│  │ via SAF     │    │ content:// URI   │         │
│  └─────────────┘    └──────────────────┘         │
│                                                   │
└──────────────────────────────────────────────────┘
```

### 8.3 Case File Manager (New Feature for Tablet)

Since Android doesn't have a natural "choose any path" model like desktop, add a **Case File Manager** screen:

- Lists all case files in app-private storage with metadata (name, last opened, size)
- Actions: Open, Export Copy, Delete, Import from External
- Replaces the desktop file-path-based case open flow
- This is the only genuinely **new feature** for mobile

---

## 9. Build & Toolchain Setup

### 9.1 Build Host Strategy — the Windows problem

> [!IMPORTANT]
> **The current dev machine is Windows, and that is the wrong host for this Android build.** `bundled-sqlcipher-vendored-openssl` compiles OpenSSL from source via `openssl-src`, whose Android configure/make path assumes a Unix-ish host (Perl + make + NDK clang). Cross-compiling OpenSSL for `aarch64-linux-android` from a Windows host is notoriously fragile — this repo already fights a milder version of this on desktop (Strawberry Perl, MSVC-vs-GNU dlltool trap in `scripts/tauri-build.mjs`).

Host options, in order of preference:

| Host | Use for | Notes |
|---|---|---|
| **GitHub Actions `ubuntu-latest`** (primary) | Release/demo APKs | Copy the `desktop-build.yml` pattern (`workflow_dispatch`, `Swatinem/rust-cache`). Install: JDK 17, Android SDK + NDK (`android-actions/setup-android` or preinstalled runner SDK), Rust target `aarch64-linux-android`. Upload the APK as an artifact; `adb install` it from anywhere |
| **WSL2 (Ubuntu) on the dev machine** (secondary) | Local iteration on Rust/Android glue | Same toolchain as CI. For `tauri android dev` against a USB device, forward adb: run `adb` server on Windows, point WSL's adb at it (`ADB_SERVER_SOCKET=tcp:...`) or use `adb tcpip 5555` + Wi-Fi |
| **Native Windows host** (avoid) | Last resort | If forced: Strawberry Perl already present, NDK clang via `cargo-ndk`; expect openssl-src path/quoting failures. Time spent here is better spent on the CI job |

Frontend dev iteration (React layout work) does not need any of this — it stays on Windows with `npm run dev` + browser devtools in tablet-viewport mode; only the on-device loop needs an APK.

### 9.2 Prerequisites (CI image or WSL2)

| Requirement | Version | Purpose |
|---|---|---|
| Android SDK | API 34+ platform + build-tools | Target/compile SDK |
| Android NDK | r26+ (r27 recommended) | Cross-compile Rust + C (SQLCipher/OpenSSL) |
| Rust target | `aarch64-linux-android` **only** | Tab S9 FE (Exynos 1380) is ARM64. Skip `armv7` — no target device needs it, and it doubles the OpenSSL build time |
| JDK | 17+ | Gradle build |

No manual `.cargo/config.toml` linker entries are needed — the Tauri v2 CLI (`cargo-mobile2`) sets up the NDK toolchain env itself when you run `tauri android init` / `build`. (The original plan's §9.2 linker config is obsolete.)

### 9.3 Build Commands

```bash
# One-time: generate src-tauri/gen/android (commit this on the `android` branch)
npx tauri android init
npx tauri icon path/to/icon.png   # generates Android mipmap densities too

# Development (device via USB, or emulator; needs Vite reachable from device)
npx tauri android dev --host

# Demo/sideload build
npx tauri android build --apk --target aarch64
adb install -r src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk
```

`tauri.conf.json` identifier `com.dfir.investigator` is a valid Android applicationId and carries over as-is.

### 9.4 CI Workflow (`.github/workflows/android-build.yml`)

Pattern it on `desktop-build.yml` (`workflow_dispatch`, optional `release_tag` input):

```yaml
jobs:
  android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4        # JDK 17
      - uses: android-actions/setup-android@v3
      - run: sdkmanager "ndk;27.0.12077973"
      - uses: dtolnay/rust-toolchain@stable # match rust-toolchain.toml channel
        with: { targets: aarch64-linux-android }
      - uses: Swatinem/rust-cache@v2       # OpenSSL compile is the slow step; cache hard
      - run: npm ci
      - run: npx tauri android build --apk --target aarch64
        env: { NDK_HOME: ... , ANDROID_HOME: ... }
      - uses: actions/upload-artifact@v4
        with: { name: android-apk, path: src-tauri/gen/android/app/build/outputs/apk/**/*.apk }
```

Release signing: generate a keystore once (`keytool -genkeypair`), store as repo secrets (`ANDROID_KEYSTORE_B64`, passwords), decode in CI, reference from `gen/android` signing config. Debug-signed APKs are fine for the demo.

### 9.5 Tauri Mobile Configuration

In `tauri.conf.json`, the mobile config is set under `app.mobile` or via `tauri.android.conf.json`:

```json
{
  "app": {
    "withGlobalTauri": false
  },
  "bundle": {
    "android": {
      "minSdkVersion": 28,
      "targetSdkVersion": 34
    }
  }
}
```

---

## 10. Phased Implementation Roadmap

### Phase 0: Foundation (Week 1-2)

> **Goal**: Get the app compiling and running on Android with the existing UI. (Overlaps with Demo Track D1–D2 — if the demo happened first, Phase 0 is mostly done.)

- [ ] Create the `android` branch; set up WSL2 toolchain for local iteration (§9.1)
- [ ] Run `npx tauri android init` to generate Android project scaffold; commit `gen/android`
- [ ] Stand up `android-build.yml` CI job (ubuntu) — this is the canonical build host, not Windows
- [ ] Verify `bundled-sqlcipher-vendored-openssl` compiles for `aarch64-linux-android` in CI (highest-risk item; do first)
- [ ] Add Android storage branches for the 8 dialog-gated commands (§6.1)
- [ ] Run existing app on Android emulator (accept broken layouts)
- [ ] Test core flow: create case → enter expert → see dashboard
- [ ] Fix any runtime crashes or WebView incompatibilities
- [ ] Verify SQLCipher encryption works on Android

### Phase 1: Navigation & Layout Shell (Week 3-4)

> **Goal**: Tablet-friendly navigation and responsive layout infrastructure.

- [ ] Create `useIsMobile()` / `usePlatform()` hooks
- [ ] Create `MobileLayout.tsx` with side rail (landscape) + bottom nav (portrait)
- [ ] Create responsive breakpoint CSS utilities
- [ ] Implement platform detection (Tauri `platform()` API or user agent)
- [ ] Convert `Dashboard.tsx` to use adaptive layout (desktop tabs vs mobile nav)
- [ ] Test on Samsung Tab S9 FE (or equivalent emulator resolution)
- [ ] Verify orientation changes work smoothly

### Phase 2: Core Feature Adaptation (Week 5-8)

> **Goal**: All features usable on tablet with touch-friendly UI.

#### Sprint 2A (Week 5-6): Data Entry Features
- [ ] **Case Setup**: Adapt file picker for Android `content://` URIs
- [ ] **Case File Manager**: New component for listing/managing local case files
- [ ] **Network Manager**: Card-based list with touch CRUD
- [ ] **Asset Manager**: Card list + full-screen detail sheet
- [ ] **IOC Manager**: Card list with swipe actions
- [ ] **Note Manager**: Split view (landscape) / full-screen (portrait)

#### Sprint 2B (Week 7-8): Complex Visualizations
- [ ] **Network Topology**: Floating toolbar, enlarged touch targets, long-press context menu, fullscreen mode
- [ ] **Timeline View**: Responsive vis-timeline, FAB for event creation, bottom sheet for details
- [ ] **Firewall Details**: Stacked navigation (drill-down levels)
- [ ] **Activity Board**: Touch-optimized scrollable feed

### Phase 3: Export/Import & Collaboration (Week 9-10)

> **Goal**: Full export/import workflow optimized for tablet, including file exchange.

- [ ] **Export/Import wizard**: Step-by-step flow replacing multi-tab layout
- [ ] **Android Share Intent**: Register app as handler for `.dfirx` and `.json` files
- [ ] **File exchange flow**: Export → Share → (transfer via Bluetooth/Wi-Fi Direct/USB) → Import
- [ ] **Partial Import**: File picker for JSON instead of paste
- [ ] **Change Bundle merge**: Touch-friendly conflict resolution UI
- [ ] **Portable export**: Same crypto, tested on Android

### Phase 4: Polish & Platform Integration (Week 11-12)

> **Goal**: Production-ready tablet experience.

- [ ] **Performance optimization**: Cytoscape.js batch rendering, vis-timeline `autoResize: false`, DOM reduction
- [ ] **Android lifecycle**: Handle pause/resume, WAL checkpoint on background
- [ ] **Security hardening**: `FLAG_SECURE`, background screen blanking
- [ ] **Accessibility**: Screen reader labels, focus management, high-contrast support
- [ ] **Error handling**: Graceful degradation for WebView quirks
- [ ] **Icon & splash screen**: App icon, launch screen, status bar theming
- [ ] **Testing**: Full regression on Samsung Tab S9 FE hardware
- [ ] **Build pipeline**: Add Android to CI workflow

---

## 11. Risk Assessment & Mitigations

### 11.1 Technical Risks

| Risk | Severity | Likelihood | Mitigation |
|---|---|---|---|
| **SQLCipher fails to cross-compile for ARM64** | 🔴 Critical | Low | `bundled-sqlcipher-vendored-openssl` is designed for this; prove it in CI as step D1, before any other work |
| **OpenSSL vendored build fails with Android NDK** | 🔴 Critical | Medium | Build on Linux (CI/WSL2); may need a specific NDK version or `CC`/`AR` env vars |
| **Attempting the Android build on the Windows host** | 🔴 Critical | High (if attempted) | Don't. openssl-src's Android path assumes a Unix host. Use the CI ubuntu runner or WSL2 (§9.1) |
| **Dialog-gated commands break on Android** | 🔴 Critical | Certain (known) | 8 commands need `#[cfg(target_os = "android")]` storage branches (§6.1); scheduled as demo step D2 |
| **WebView performance issues with Cytoscape.js** | 🟡 High | Medium | Profile early; use `cy.batch()`, reduce label rendering at low zoom; consider WebGL renderer if needed |
| **vis-timeline touch responsiveness** | 🟡 High | Medium | Set `autoResize: false`; simplify item CSS; increase item heights |
| **Android `content://` URI handling breaks file flow** | 🟡 High | Medium | `tauri-plugin-android-fs` handles URIs; copy-to-private pattern as fallback |
| **App size too large (SQLCipher + OpenSSL)** | 🟢 Medium | Low | Tauri apps are typically < 20 MB; SQLCipher adds ~3 MB; acceptable |
| **Android WebView version inconsistency** | 🟢 Medium | Low | Tab S9 FE ships with modern WebView; set `minSdkVersion: 28` to ensure baseline |
| **Keyboard overlap with input fields** | 🟢 Medium | High | Use `windowSoftInputMode: adjustResize` in AndroidManifest; scroll form into view |

### 11.2 UX Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **Too many features for mobile navigation** | 🟡 High | Group into primary/secondary; overflow menu for less-used features |
| **Complex forms hard to fill on touch** | 🟡 High | Progressive disclosure; collapsible sections; smart defaults |
| **Merge conflict resolution too complex on tablet** | 🟡 High | Simplify diff view; use clear accept/reject buttons instead of checkboxes |
| **Investigators prefer laptop over tablet** | 🟢 Medium | Position as companion, not replacement; focus on field data entry use case |

---

## 12. Testing Strategy

### 12.1 Test Matrix

| Test Type | Tool | Coverage |
|---|---|---|
| **Unit tests (frontend)** | Vitest (existing) | Types, utilities, topology layout |
| **Unit tests (backend)** | `cargo test` (existing) | DB operations, crypto, merge logic |
| **Component tests** | Vitest + Testing Library | Mobile-specific layout components |
| **Integration tests** | Android emulator + Tauri | Full IPC flow on Android |
| **Device testing** | Samsung Tab S9 FE hardware | Touch interactions, performance, orientation |
| **Performance profiling** | Chrome DevTools remote | Canvas rendering, memory usage, frame rate |

### 12.2 Device Test Checklist

- [ ] Case creation and opening works
- [ ] SQLCipher encryption/decryption works
- [ ] All CRUD operations for all entity types
- [ ] Network topology renders and responds to touch
- [ ] Timeline events render and scroll smoothly
- [ ] File export/import via Android share intent
- [ ] Portable `.dfirx` export/import works
- [ ] Change bundle merge with conflict resolution
- [ ] Orientation changes don't lose state
- [ ] Background/foreground transitions don't lose data
- [ ] Soft keyboard doesn't obscure input fields
- [ ] App survives low-memory kill and restart
- [ ] Screenshot prevention works (`FLAG_SECURE`)

---

## 13. Open Questions for Decision

### 13.1 Distribution

> [!IMPORTANT]
> **How will the tablet app be distributed?** — **Resolved for the demo: sideloaded APK** (built by CI, installed via `adb install`). This matches the offline-first philosophy and needs no store account. Play Store remains a later option:
> - **Option A**: Sideload APK only (matches the desktop's offline-first philosophy; no app store review) ← demo choice
> - **Option B**: Private Play Store listing (easier updates; requires Google Play Console account)
> - **Option C**: Both (APK for air-gapped environments; Play Store for convenience)

### 13.2 Case File Transfer

> [!IMPORTANT]
> **How will case files move between desktop and tablet?**
> - **Option A**: USB cable + file transfer (most secure, offline)
> - **Option B**: Wi-Fi Direct / Bluetooth (device-to-device, no internet)
> - **Option C**: Shared folder (e.g., USB drive, network share)
> - **Option D**: All of the above (app doesn't care — it just imports/exports files)
>
> The app itself is agnostic — it exports to / imports from the Android storage. The transfer mechanism is external.

### 13.3 Biometric Lock

> [!NOTE]
> **Should the app require biometric/PIN authentication on open?**
> This is an additional security layer beyond the case file password. It could be implemented via the Android Keyguard API. Recommendation: make it optional (configurable in settings).

### 13.4 S Pen Support

> [!NOTE]
> **The Tab S9 FE supports S Pen. Should the app have S Pen-specific features?**
> - Hover preview (S Pen hover detection for tooltips without touching)
> - Handwriting-to-text in note fields
> - Precision tap for small topology nodes
> 
> Recommendation: Phase 4+ enhancement. Basic S Pen input works as touch by default.

### 13.5 Offline Map / Site Photo Integration

> [!NOTE]
> **Should the tablet app add field-specific features the desktop doesn't have?**
> - Camera integration for photographing server rooms / labels
> - Offline map for marking physical asset locations
> - Voice-to-text for quick note entry
>
> Recommendation: Out of scope for initial release. Can be added as tablet-exclusive features later.

---

## Appendix A: Component Inventory (Current Desktop)

| Component | Lines (actual, `wc -l` 2026-07-20) | Touch Complexity | Adaptation Effort |
|---|---|---|---|
| `AboutPage.tsx` | 33 | ⚪ None | Trivial |
| `ActivityBoard.tsx` | 299 | 🟢 Low | Low — already a scrollable card board |
| `AssetManager.tsx` | 192 | 🟡 Medium | Medium — table → cards, detail sheet |
| `CaseSetup.tsx` | 180 | 🟡 Medium | Medium — Android storage flow (no save dialog) |
| `Dashboard.tsx` | 99 | 🔴 High | High — navigation paradigm change (nav actually lives in `App.tsx`) |
| `ExpertSetup.tsx` | 105 | ⚪ None | Trivial |
| `ExportImport.tsx` | 341 | 🔴 High | High — wizard flow, share intent |
| `FirewallDetails.tsx` | 135 | 🔴 High | Medium — stacked navigation |
| `IocManager.tsx` | 91 | 🟢 Low | Low — card list |
| `NetworkManager.tsx` | 176 | 🟢 Low | Low — card list |
| `NetworkTopology.tsx` | 257 | 🔴 High | High — touch targets, floating toolbar |
| `NoteManager.tsx` | 95 | 🟡 Medium | Medium — split/full view |
| `PartialImportPanel.tsx` | 191 | 🟡 Medium | Medium — wizard steps |
| `TimelineView.tsx` | 384 | 🔴 High | High — responsive timeline, form |

**Total frontend feature-component lines**: ~2,600 (the original plan's ~8,675 estimate was off by 3×; the codebase is much smaller than assumed)  
**Estimated new/modified lines for mobile**: ~1,500–2,500 including the mobile shell, hooks, and Rust storage branches — roughly a rewrite-sized effort relative to the existing UI, which argues for the platform-gated-overrides approach rather than forking components

## Appendix B: IPC Command Compatibility

The `invoke()` bridge works identically on mobile, and ~50 commands carry over unchanged — but **8 dialog-gated commands need Android storage branches** (see §6.1 for the list). The additions are:

| New Command | Purpose |
|---|---|
| `list_local_cases` | List case files in app-private storage |
| `copy_file_to_private` | Copy a `content://` URI file to app-private storage |
| `export_file_to_shared` | Export a file to shared storage or trigger share intent |
| `get_platform_info` | Return platform (desktop/android), storage paths, device info |

## Appendix C: Dependency Compatibility

| Dependency | Android Compatible | Notes |
|---|---|---|
| `rusqlite` + `bundled-sqlcipher-vendored-openssl` | ✅ Yes | Cross-compiles with NDK; tested by community |
| `aes-gcm` | ✅ Yes | Pure Rust |
| `argon2` | ✅ Yes | Pure Rust |
| `getrandom` | ✅ Yes | Uses Android's `/dev/urandom` |
| `zeroize` | ✅ Yes | Pure Rust |
| `uuid` | ✅ Yes | Pure Rust |
| `chrono` | ✅ Yes | Pure Rust |
| `serde` / `serde_json` | ✅ Yes | Pure Rust |
| `tauri` v2 | ✅ Yes | Official Android support |
| `tauri-plugin-dialog` | ✅ Yes | Official mobile support |
| React 19 | ✅ Yes | Runs in WebView |
| Tailwind CSS 3 | ✅ Yes | Pure CSS, WebView-compatible |
| shadcn/ui (Radix) | ✅ Yes | Pure React, runs in WebView |
| Cytoscape.js | ✅ Yes | Canvas-based, touch support built in |
| vis-timeline | ✅ Yes | DOM-based, touch support via Hammer.js |
| lucide-react | ✅ Yes | SVG icons, no platform deps |
| sonner | ✅ Yes | Pure React toast library |
| moment (via vis-timeline) | ✅ Yes | Pure JS (the repo does not use date-fns — the original table listed a dependency that doesn't exist) |
| xss | ✅ Yes | Pure JS |

**All dependencies are Android-compatible.** No substitutions needed.
