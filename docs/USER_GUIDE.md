# DFIR Network Investigator User Guide

Document version: 1.0  
Application version: 0.1.0  
Last reviewed: 2026-07-19

## 1. Purpose

DFIR Network Investigator is an offline desktop workbench for manually documenting a network incident when responders do not have a shared SIEM or dependable access to the client environment. It keeps the developing network picture, computer status, interfaces, findings, timeline, IOCs, and notes in one local SQLite case file.

The application is designed to answer six early-response questions quickly:

1. What network zones have been identified?
2. What computers and devices exist in each zone?
3. How are those zones and devices connected, including secondary NICs?
4. Which systems are clean, suspected, infected, or still not examined?
5. What happened, in what order, and what evidence supports it?
6. What did each expert add, change, or remove?

It is a documentation and coordination tool. It does not collect evidence automatically, scan endpoints, parse logs, prove expert identity, or replace forensic acquisition tools.

## 2. Installation and startup

Use the package built for your operating system. The verified Windows setup executable is:

- `src-tauri/target/release/bundle/nsis/DFIR-Investigator_0.1.0_x64-setup.exe`

The standalone release executable is `src-tauri/target/release/dfir-investigator.exe`. It is a GUI application, so it normally prints nothing in a terminal; it should open a window titled **DFIR Network Investigator**.

Windows requires Microsoft Edge WebView2 Runtime, which is normally present on supported Windows systems. Linux requires the normal WebKitGTK desktop runtime packages for the distribution. macOS uses the system WebKit framework; unsigned local builds may be blocked by Gatekeeper policy.

For development, use:

```powershell
npm install
npm run tauri-dev
```

`npm run dev` starts only the web frontend and cannot provide native dialogs, SQLite case access, encryption, or other Tauri operations. Full prerequisites, build gates, artifact paths, and `dlltool.exe` troubleshooting are in [RUNNING_AND_BUILDING.md](RUNNING_AND_BUILDING.md).

## 3. Case and identity concepts

### 3.1 Case file

A case is one SQLCipher-encrypted `.db` file selected by the user. It contains the investigation data and local change history. The application opens one case at a time and requires that file's shared database password whenever it is opened.

The database password belongs to the physical file copy, not to a username, machine, or logical case UUID. A direct copy initially accepts the same password. If machine A and machine B each rekey their own copies, the copies may use different passwords while still representing the same merge-compatible case.

Keep the case file on a local or organization-approved protected location. Do not allow two running application instances to edit the same file over an unreliable network share.

### 3.2 Session expert

The **active expert** is the name attributed to changes made during the current application session. It is not an account and is never checked against either password. Names are self-declared operational attribution, not cryptographic proof of identity.

When opening an existing case, enter:

- expert name;
- optional assignment label, such as `Room 204`, `Finance`, or `DMZ`; and
- optional focus network zones.

The focus is advisory. It filters and highlights relevant work but does not prevent an expert from editing outside the assignment. The application asks for confirmation when an asset or interface is saved outside selected focus zones.

Click the expert name in the left sidebar to change the active session identity or focus.

## 4. Create and open a case

### Create

1. Select **New Case**.
2. Enter the case name and expert name for this first work session. Client and description are optional.
3. Enter and confirm a database-file password of at least 6 characters.
4. Select **Create Case** and choose the `.db` file location in the native Save dialog.

The application appends `.db` when needed and refuses to overwrite an existing file.

### Open

1. Select **Open Case**.
2. Enter the database-file password and select the `.db` file.
3. After it unlocks, enter the active expert name and optional focus.

Before using the file, the application authenticates and decrypts its SQLCipher pages, validates the expected schema and single case record, runs required migrations, repairs supported legacy references, checks encrypted-page integrity, checks SQLite integrity, and checks foreign-key consistency.

Use **Lock / Close Case** in the sidebar when handing over or leaving the workstation. It drops the open connection and requires the database password to reopen the file. It does not depend on the expert name.

### Change the database password

Open **Dashboard → Database file security**, enter the current password, then enter and confirm the new password. This re-encrypts only the open physical copy. It does not change the expert name, case UUID, exported files, or passwords on other database copies. There is no password recovery.

### Convert an older unencrypted case

From **Open Case**, select **Convert a legacy unencrypted case**, enter and confirm a new password, choose the old `.db`, and choose where to save the encrypted copy. The app preserves the old plaintext source and opens the validated encrypted copy. Dispose of the plaintext source only under the site's approved data-handling procedure.

## 5. Recommended first-response workflow

Use the following sequence to reduce early uncertainty and repeated movement between computers.

### Step 1: Establish zones

Open **Networks → Zones** and record each known LAN, DMZ/DMS, WAN, guest, management, or other segment. Add the CIDR subnet, VLAN when known, and a concise description.

Do not wait for the map to be complete. Record confirmed information first and revise it as the team learns more.

### Step 2: Record connections and firewalls

Use **Networks → Connections** to record links between zones and **Networks → Firewalls** for dedicated firewall devices. Select the interface/NAT button beside a firewall to manage its structured details.

For each firewall:

- add every WAN, LAN, DMZ, management, HA, VPN, or other interface;
- attach each interface to a zone and record any number of IPv4/IPv6 addresses or CIDRs;
- optionally record MAC, VLAN, role, and description;
- choose one primary/home interface, which controls where the firewall node sits in topology; and
- add enabled or disabled VIP, DNAT, SNAT, and port-mapping records with protocol, source, original/translated address and ports, and optional inbound/outbound interfaces.

Addresses are evidence records, not globally unique keys. Overlapping subnets and repeated addresses in isolated zones remain valid.

This makes assumptions about routing and control points visible to the team rather than leaving them in individual notebooks.

### Step 3: Register computers and their current status

Open **Assets** and add each workstation, server, VM, appliance, or other system. Record:

- primary network, IP, and MAC;
- operating system and observed user;
- compromise status: `unknown`, `clean`, `suspected`, or `infected`;
- investigation status: `not started`, `in progress`, or `completed`;
- optional JSON properties and scan results.

Use the status filters to identify systems that have not been started or completed. This list should drive physical or remote responder assignments and reduce duplicate visits.

### Step 4: Add every NIC

Expand an asset to manage network interfaces. Create, edit, delete, or select the primary interface.

Rules:

- an asset can have multiple interfaces;
- at most one interface is primary;
- the asset's main network/IP/MAC fields mirror the primary interface; and
- secondary interfaces create explicit cross-zone edges in the topology.

Multi-homed systems are important because they may explain unexpected paths, routing, bridging, management access, or movement between network zones.

### Step 5: Review the topology

Open **Topology**. The asset is shown once inside its primary network. Purple dotted edges show secondary asset NIC attachments, amber dotted edges show additional firewall interfaces, network connections are dashed links, and dedicated firewalls are separate nodes.

Available layouts:

- Hierarchical;
- Grid;
- Circle;
- Concentric; and
- Breadth-first.

Use zoom, fit, refresh, and PNG export controls. Select a node to inspect its fields.

The topology is a working operational picture, not a packet-derived proof of connectivity. Mark uncertain information clearly in descriptions or notes.

### Step 6: Build the timeline continuously

Open **Timeline** and add evidence events as they are confirmed. Record:

- event time;
- related asset when known;
- event type and severity;
- evidence source;
- description; and
- optional MITRE tactic and technique.

Use 24-hour `DD-MM-YYYY HH:mm:ss.SSS`, an ISO/RFC 3339 UTC value, or a Unix epoch. Time is optional after the date; omitted hour, minute, second, and millisecond fields become `00`. Select `UTC`, a fixed offset, or an IANA timezone. The table always shows the selected zone beside UTC (or local workstation time when UTC is selected).

When adding or editing an event, server/evidence time and known real/correct time are independent and optional. Enter both to calculate a direct per-event correction, enter only what is known, or leave both unknown and add them later. The preview and table normalize server and corrected values into the selected workstation/display zone plus UTC. Alternatively, open **Server clocks** and create a reusable profile from a server reading and known-correct reference observed at the same instant. A saved profile requires server time and is used instead of directly entered correct time.

Use separate profiles if a clock changed or drifted during the incident. See [TIME_CORRELATION.md](TIME_CORRELATION.md) for accepted syntax and forensic boundaries.

Use table or timeline view. Search and filter by time range, asset, severity, event type, source, description, and MITRE values. Asset grouping uses stable IDs, so two computers with the same name do not collapse into one group.

### Step 7: Record IOCs and findings

Use **IOCs** for indicators such as IP addresses, hashes, domains, and URLs. Record threat level, description, and first/last-seen times when known.

Use **Notes** for findings, hypotheses, evidence references, decisions, and handover information. Notes support a safe Markdown subset. Raw HTML is displayed as text rather than executed.

### Step 8: Use the dashboard as the coverage board

The **Dashboard** shows full-case counts, including:

- networks and assets;
- suspected/infected assets;
- assets not completed;
- timeline and critical-event counts;
- IOCs, notes, and firewalls; and
- recent evidence events.

During coordination meetings, use the dashboard and filtered asset list to decide where responders should go next.

## 6. Editing and deletion behavior

Core case, network, asset, interface, timeline, IOC, note, firewall, and connection records can be edited.

Important safeguards:

- A network cannot be deleted while assets, interfaces, firewalls, or network connections reference it. The error reports dependency counts.
- Deleting an asset removes its interfaces but keeps timeline evidence and clears the event's asset link.
- Updates or deletes that match no record return an error.
- Multi-table changes and imports use SQLite transactions.

## 7. Daily expert collaboration and merge

### Structured information and LLM-assisted intake

Use **Expert Merge → Plain structured partial import** when information comes from prose, another team's notes, a script, or an LLM rather than a shared-baseline expert bundle.

1. Load or save the case-aware template.
2. Give only the required template/context to an approved person or model.
3. Paste the returned JSON or open a plain `.json` file.
4. Select **Parse, verify, and preview**.
5. Review invalid, unchanged, new, and matching-update records.
6. For each section choose Skip, Add missing only, or Use incoming versions; individual records remain selectable.
7. Select **Validate and confirm** and check the final create/update count.

Add-only retains current notes/timeline records and adds expert records with different UUIDs. Use incoming versions also updates matching UUIDs but never deletes unrelated local records. See [INPUT_FORMATS.md](INPUT_FORMATS.md) for the complete field contract and examples, and [PARTIAL_IMPORT.md](PARTIAL_IMPORT.md) for the review workflow.

### 7.1 Prepare a shared baseline

1. The merge lead opens the agreed master case.
2. Resolve existing work.
3. Open **Expert Merge**.
4. Select **Mark current head** under Shared baseline.
5. Distribute identical copies of that `.db` file to experts.

### 7.2 Expert work

Each expert:

1. opens their copy;
2. enters their own active expert name and optional focus;
3. records network, asset/NIC, status, timeline, IOC, note, firewall, and connection changes; and
4. selects **Save change bundle** at the end of the work period.

The bundle contains attributed commits since the shared baseline, not a replacement database.

### 7.3 Team review

On the master case, the merge lead:

1. selects **Load for review**;
2. chooses an expert bundle;
3. reviews topology/PC configuration and timeline changes;
4. accepts or rejects each entity change;
5. resolves same-field conflicts by choosing current master or incoming value; and
6. selects **Apply selected**.

Loading a bundle creates an in-memory preview only. Applying accepted changes is one transaction and adds a merge commit with the local and incoming history parents.

Classifications include:

- **clean**: incoming change can be applied directly;
- **auto mergeable**: local and incoming work changed different fields;
- **conflict**: both sides changed the same field differently;
- **delete conflict**: a deletion conflicts with local edits; and
- **already applied**: the imported source change was previously merged.

Bundles from another case ID are rejected. Unknown baselines require explicit review. After all agreed work is applied, mark the new shared baseline and redistribute the new master.

## 8. Snapshot backup and legacy import

**Save snapshot** exports the complete case structure. **Import snapshot** accepts only a matching case ID, inserts missing UUID records, and skips existing UUIDs without overwriting them. The result shows inserted/skipped counts by entity.

Snapshot import is not the preferred way to reconcile concurrent edits. Use expert change bundles for field-level review and merge.

## 9. Plain and encrypted portable files

### Unencrypted mode

Leave **Encrypt new snapshots and change bundles** unchecked.

Outputs are formatted UTF-8 JSON that can be opened as text and parsed by other software or programming languages. No wrapper changes the data structure.

### Encrypted mode

1. Check **Encrypt new snapshots and change bundles**.
2. Enter and confirm an export password of at least 6 characters.
3. Save the snapshot or change bundle.

The output uses the `.dfirx` extension. The original JSON bytes are encrypted inside a portable, versioned envelope. The password:

- is independent of session expert names;
- is independent of the source and destination computer;
- is not written to the database or export; and
- cannot be recovered by the application.

To import or review an encrypted file, enter the password in **Import / decrypt password** before selecting the action. The field is cleared after a successful operation.

Wrong passwords and changed files fail authenticated decryption. Share the password through a separate approved channel rather than in the same message or storage location as the file.

See `PORTABLE_EXPORT_FORMAT.md` for implementation details needed by another language.

## 10. Text parser

The **Text parser** converts either a snapshot or expert change bundle into a human-readable `.txt` report.

1. For an encrypted input, enter its password under **Import / decrypt password**. Leave blank for plain JSON.
2. Select **Create text report**.
3. Choose the `.json` or `.dfirx` input.
4. Choose the `.txt` output location.

The parser does not open or modify a case database. The output text is display-only and cannot be imported back into the application.

Important: the `.txt` result is unencrypted and can contain the full sensitive investigation content. Generate, display, transmit, and dispose of it according to the site's information-handling rules.

## 11. Data-at-rest handling

| Material | Built-in application encryption | Required handling |
|---|---|---|
| Live `.db` case | Yes; SQLCipher page encryption and authentication | Keep a recoverable password copy under approved procedure; also use endpoint/full-disk controls |
| Plain `.json` export | No | Use only where interoperability or inspection is required; protect externally |
| Encrypted `.dfirx` export | Yes; password-derived authenticated encryption | Protect password separately; retain backups because there is no recovery |
| Text-parser `.txt` | No | Treat as sensitive plain text |
| Topology `.png` | No | Treat as sensitive plain image |

The database password and optional export password are independent. Neither authenticates an expert's identity. Expert names are audit labels, not digital signatures. SQLCipher protects the closed database contents, but not an unlocked process, screenshots, filenames, plain JSON/text/PNG output, or a compromised endpoint.

## 12. Troubleshooting

### Application exits immediately

Use the current rebuilt executable or installer. Ensure WebView2 Runtime is installed.

### Development build reports `dlltool.exe` missing

The GNU Rust target was selected on Windows. Install and select MSVC:

```powershell
rustup toolchain install stable-x86_64-pc-windows-msvc
rustup default stable-x86_64-pc-windows-msvc
npm run tauri-dev
```

### Import says the case is different

The snapshot or change bundle belongs to another case UUID. Open the correct master case; do not bypass this control.

### Encrypted file will not open

Confirm the exact password, including spaces and character case. Failure also occurs if the file was changed or truncated.

For a `.db`, use the database-file password. For a `.dfirx`, use the independent export password selected when that file was created. Changing the database password does not re-encrypt existing exports.

### Network cannot be deleted

Review the dependency counts in the error. Deliberately reassign or delete referenced assets, interfaces, firewalls, and connections before trying again.

### Timeline evidence remains after deleting an asset

This is intentional. The event remains as evidence but becomes unassigned.

## 13. Recommended end-of-day checklist

1. Filter assets to **not started** and **in progress**; record the next assignment.
2. Check suspected/infected systems and confirm supporting timeline entries.
3. Review secondary NIC edges and unexpected cross-zone connections.
4. Add unresolved assumptions and handover notes.
5. Save an encrypted snapshot when handling rules require it.
6. Each expert saves a change bundle.
7. The team reviews and applies agreed changes on the master.
8. Mark the new shared baseline.
9. Lock the master, back it up, and redistribute the same new master database under approved data-at-rest protection. Direct copies initially have the master's database password; each expert may rekey their own copy if procedure requires it.
