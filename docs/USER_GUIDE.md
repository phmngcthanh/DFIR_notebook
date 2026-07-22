# DFIR Network Investigator User Guide

Document version: 1.0  
Application version: 1.0.20
Last reviewed: 2026-07-19

## 1. Purpose

DFIR Network Investigator is a browser workbench for manually documenting a network incident when responders do not have a shared SIEM or dependable access to the client environment. It keeps the developing network picture, computer status, interfaces, findings, timeline, IOCs, and notes in one encrypted SQLite case file held by a case server the team shares.

The application is designed to answer six early-response questions quickly:

1. What network zones have been identified?
2. What computers and devices exist in each zone?
3. How are those zones and devices connected, including secondary NICs?
4. Which systems are clean, suspected, infected, or still not examined?
5. What happened, in what order, and what evidence supports it?
6. What did each expert add, change, or remove?

It is a documentation and coordination tool. It does not collect evidence automatically, scan endpoints, parse logs, prove expert identity, or replace forensic acquisition tools.

## 2. Installation and startup

Open the address your operator gives you in a normal browser — there is nothing to install on your machine. The first time you connect over HTTPS with a self-signed certificate, compare the fingerprint the browser shows against the one the operator read out at startup, then accept it once.

Operators: see [SERVER.md](SERVER.md) for running the server, its flags, TLS, and the case directory.

Because your work now lives on the server rather than on your laptop, two habits change: closing the tab ends your session, and **End Session** in the sidebar is what you use when leaving the workstation.

## 3. Case and identity concepts

### 3.1 Case file

A case is one SQLCipher-encrypted `.db` file in the server's case directory. It contains the investigation data and the change history. Unlocking it requires that case's shared password, and that password is the only credential — there are no user accounts.

The password belongs to the file, not to a username, machine, or logical case UUID. A copy taken elsewhere initially accepts the same password; a copy that is independently rekeyed may use a different password while still representing the same merge-compatible case.

Everyone unlocking the same case on the server works on the same file at the same time. Your session ends when you close the tab, select **End Session**, or stay idle past the operator's timeout.

### 3.2 Session expert

The **active expert** is the name attributed to changes made during the current session. It is not an account and is never checked against either password. Names are self-declared operational attribution, not cryptographic proof of identity.

When unlocking a case, enter:

- expert name;
- optional assignment label, such as `Room 204`, `Finance`, or `DMZ`; and
- optional focus network zones.

The focus is advisory. It filters and highlights relevant work but does not prevent an expert from editing outside the assignment. The application asks for confirmation when an asset or interface is saved outside selected focus zones.

Click the expert name in the left sidebar to change the active session identity or focus.

## 4. Create and open a case

### Create

Only available when the operator started the server with `--allow-create`; otherwise they add case files for you.

1. Select **Create a new case on this server**.
2. Enter the case name and your expert name. Client and description are optional.
3. Enter and confirm the case password.
4. Select **Create Case**.

The password now travels over the network, so use a long passphrase rather than the six-character minimum. Everyone who will work on this case needs it.

### Unlock

1. Pick the case from the list.
2. Enter your expert name and the case password.
3. Select **Unlock Case**.

Before using the file, the server authenticates and decrypts its SQLCipher pages, validates the expected schema and single case record, runs required migrations, repairs supported legacy references, checks encrypted-page integrity, checks SQLite integrity, and checks foreign-key consistency.

Repeated wrong passwords from one address are locked out for a while, so if you are locked out, wait rather than retrying.

Use **End Session** in the sidebar when handing over or leaving the workstation. It drops your token; the case password is required to get back in. It does not depend on the expert name.

### Change the case password

Open **Dashboard → Database file security**, enter the current password, then enter and confirm the new password. Everyone else working on that case is signed out immediately, because their access was granted against the old password — tell the team before you do it. This does not change the expert name, case UUID, or exported files. There is no password recovery.

### Convert an older unencrypted case

Not available in the browser, because it needs two local file paths. Convert with the desktop build, then ask the operator to put the encrypted copy in the server's case directory. Dispose of the plaintext source only under the site's approved data-handling procedure.

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

## 7. Working alongside the rest of the team

Everyone unlocking this case on the server is editing the same file. There is no
daily merge for ordinary work:

1. Each expert unlocks the case, enters their own name, and optionally sets a focus scope.
2. Everyone records network, asset/NIC, status, timeline, IOC, note, firewall, and connection changes as they go.
3. Every change is committed with its author and shows up in **Activity Board** and the audit history.
4. Other open browsers pick up your edits within about five seconds and show a "case was updated" notice. The sidebar shows how many experts are working right now.

Two people editing the same record at the same moment is last-write-wins — the
last save is what remains, and both edits stay visible in the history. Split work
by zone, department, or room the way you would offline, and use the focus scope
to label it.

### Bringing in an expert who worked offline

Someone who worked in the desktop app can still hand their work over. On the
server, open **Case Transfer** and:

1. select **Load for review** and choose their bundle file;
2. review topology/PC configuration and timeline changes;
3. accept or reject each entity change;
4. resolve same-field conflicts by choosing current or incoming value; and
5. select **Apply selected**.

Loading a bundle creates an in-memory preview only. Applying accepted changes is
one transaction and adds a merge commit with both history parents.

Classifications include:

- **clean**: incoming change can be applied directly;
- **auto mergeable**: local and incoming work changed different fields;
- **conflict**: both sides changed the same field differently;
- **delete conflict**: a deletion conflicts with local edits; and
- **already applied**: the imported source change was previously merged.

Bundles from another case ID are rejected. Unknown baselines require explicit review.

### Structured information and LLM-assisted intake

Use **Case Transfer → Plain structured partial import** when information comes from prose, another team's notes, a script, or an LLM.

1. Load or save the case-aware template.
2. Give only the required template/context to an approved person or model.
3. Paste the returned JSON or open a plain `.json` file.
4. Select **Parse, verify, and preview**.
5. Review invalid, unchanged, new, and matching-update records.
6. For each section choose Skip, Add missing only, or Use incoming versions; individual records remain selectable.
7. Select **Validate and confirm** and check the final create/update count.

Add-only retains current notes/timeline records and adds expert records with different UUIDs. Use incoming versions also updates matching UUIDs but never deletes unrelated local records. See [INPUT_FORMATS.md](INPUT_FORMATS.md) for the complete field contract and examples, and [PARTIAL_IMPORT.md](PARTIAL_IMPORT.md) for the review workflow.

## 8. Snapshot backup and add-only import

**Download snapshot** exports the complete case structure to your browser's downloads. **Import add-only** accepts only a matching case ID, inserts missing UUID records, and skips existing UUIDs without overwriting them. The result shows inserted/skipped counts by entity.

The authoritative backup is the `.db` file itself, which the operator copies from the server's case directory.


## 9. Plain and encrypted portable files

### Unencrypted mode

Leave **Encrypt downloaded snapshots** unchecked.

Outputs are formatted UTF-8 JSON that can be opened as text and parsed by other software or programming languages. No wrapper changes the data structure.

### Encrypted mode

1. Check **Encrypt downloaded snapshots**.
2. Enter and confirm an export password of at least 6 characters.
3. Download the snapshot.

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
3. Choose the `.json` or `.dfirx` input. Your browser saves the `.txt` report to its downloads folder.

The parser does not open or modify a case database. The output text is display-only and cannot be imported back into the application.

Important: the `.txt` result is unencrypted and can contain the full sensitive investigation content. Generate, display, transmit, and dispose of it according to the site's information-handling rules.

## 11. Data-at-rest handling

| Material | Built-in application encryption | Required handling |
|---|---|---|
| Live `.db` case on the server | Yes; SQLCipher page encryption and authentication | Keep a recoverable password copy under approved procedure; also use full-disk controls on the server |
| Plain `.json` export | No | Use only where interoperability or inspection is required; protect externally |
| Encrypted `.dfirx` export | Yes; password-derived authenticated encryption | Protect password separately; retain backups because there is no recovery |
| Text-parser `.txt` | No | Treat as sensitive plain text |
| Topology `.png` | No | Treat as sensitive plain image |

The case password and optional export password are independent. Neither authenticates an expert's identity. Expert names are audit labels, not digital signatures. SQLCipher protects the closed database contents, but not an unlocked case in the server's memory, screenshots, case filenames, plain JSON/text/PNG output, or a compromised endpoint. Because the case password now travels over the network, use a long passphrase and keep the server on HTTPS.

## 12. Troubleshooting

### The page will not load, or the browser warns about the certificate

Confirm the address with the operator, and compare the certificate fingerprint the browser shows against the one printed when the server started. Do not accept a fingerprint that does not match.

### "Too many failed unlock attempts from this address"

Five wrong passwords within fifteen minutes locks your address out. Wait it out and confirm the password rather than retrying.

### "This session has expired. Unlock the case again"

Your session was idle past the operator's timeout, someone changed the case password, or the last expert left and the case closed. Unlock again.

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
5. Download an encrypted snapshot when handling rules require it.
6. Review the day's work in **Activity Board** and the audit history.
7. Select **End Session** before leaving the workstation.
8. Operator: back up the `.db` files from the case directory under approved data-at-rest protection. A copy initially accepts the same case password.
