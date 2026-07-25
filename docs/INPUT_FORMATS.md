# Input and Import Formats

Document version: 1.0  
Application version: 1.0.20
Last reviewed: 2026-07-19

## 1. Format selection

| Input | Typical extension | Encryption | Purpose | Changes the open case? |
|---|---|---|---|---|
| SQLite case | `.db` | SQLCipher; database-file password required | Open a complete working case | Opens that database after unlock/validation |
| Full snapshot | `.json` | No | Backup/legacy add-only transfer | Yes, after same-case validation |
| Encrypted snapshot | `.dfirx` | AES-256-GCM envelope | Protected backup/transfer | Yes, after password and validation |
| Expert change bundle | `.json` | No | Git-like attributed review/merge | Only after review and confirmation |
| Encrypted expert bundle | `.dfirx` | AES-256-GCM envelope | Protected attributed review/merge | Only after password, review, and confirmation |
| Structured partial import | `.json` or pasted JSON | No, deliberately | One-field, multi-section, script/LLM-assisted intake | Only after preview, selection, and confirmation |
| Text report | `.txt` | No | Display/print output | Never; not importable |

Use a shared-baseline expert bundle for end-of-day expert reconciliation. Use structured partial import for information extracted from prose, another tool, an LLM, or a team that did not work from the shared database baseline.

Encrypted `.dfirx` is supported for full snapshots and expert bundles. Structured partial import is plain JSON only; if its contents require protected transport, use an approved encrypted container/channel outside the application.

The `.db` password and `.dfirx` password are independent. A case database cannot be opened as JSON and an encrypted export cannot be used to unlock a database. Plain `.json` remains the interoperable format for other applications and programming languages. Legacy plaintext `.db` files must be converted from the **Open Case** screen into a new encrypted copy before use.

## 2. Structured partial-import envelope

The canonical version 1 root is:

```json
{
  "format": "dfir-investigator-partial",
  "format_version": 1,
  "case_id": "OPEN-CASE-UUID",
  "source": "Expert B or extraction process",
  "changes": []
}
```

Rules:

- Canonical generators must emit `format`, `format_version`, and `changes`. For legacy tolerance, the parser defaults an omitted version to `1` and an omitted `changes` value to an empty list.
- `case_id` should be copied from the in-app case-aware template. A different case ID is rejected.
- `source` is a human-readable attribution/context label.
- JSON must be UTF-8 and the root must be an object.
- A Markdown fenced `json` block is accepted when pasted into the editor.
- Unknown/deletion operations are rejected.
- One document may contain one record, several sections, or all supported sections.
- The same entity UUID may appear only once in one partial document.

Each change has this shape:

```json
{
  "change_id": "human-readable-unique-label",
  "entity_type": "asset",
  "operation": "update",
  "target_id": "EXISTING-ASSET-UUID",
  "values": {
    "compromise_status": "infected"
  }
}
```

`entityType`, `targetId`, and `data` are accepted compatibility aliases, but generators should emit the canonical snake-case names above.

## 3. Operations and identity

| Operation | Required identity | Behavior |
|---|---|---|
| `create` | Optional `values.id`; otherwise the app generates a UUID | Fails if that UUID already exists |
| `update` | `target_id` | Patches only supplied fields; fails if the UUID does not exist |
| `upsert` | `target_id` or `values.id` | Creates an absent UUID or patches an existing UUID |

Case metadata supports update/upsert against the open case only; creating a second case record is rejected.

Identity is exact UUID identity. The importer never assumes that matching names, IP addresses, subnets, note titles, or timestamps are the same record. This matters because network zones may legitimately have overlapping CIDRs.

When several new records refer to each other, assign UUIDs in `values.id` and use those UUIDs in relationship fields. A UUID should use the normal form `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`.

## 4. Supported entities and fields

Fields listed as required are required when creating a record. Updates may contain only the fields being changed.

| `entity_type` | Required create fields | Optional/update fields and accepted values |
|---|---|---|
| `case` | Update only | `name`, `description`, `client_name`, `status` (`active`, `closed`, `archived`), `metadata`; legacy `investigator` values are preserved but ignored |
| `network` | `name`, `subnet` | `network_type` (`LAN`, `DMZ`, `DMS`, `WAN`, `GUEST`, `MANAGEMENT`, `OTHER`), `description`, `vlan_id` |
| `asset` | `name`, `ip_address` | `network_id`, `mac_address`, `asset_type` (`workstation`, `server`, `vm`, `laptop`, `router`, `switch`, `other`), `os`, `user_name`, `compromise_status` (`unknown`, `clean`, `suspected`, `infected`), `investigation_status` (`not_started`, `in_progress`, `completed`), `properties`, `scan_results` |
| `network_interface` | `asset_id`, `name`, `ip_address` | `network_id`, `mac_address`, `is_primary`; at most one primary NIC per asset |
| `clock_profile` | `name`, `server_reference_raw`, `correct_reference_raw` | `description`, `server_timezone`, `correct_timezone`; UTC values and offset are derived by the app |
| `firewall` | `name` | `network_id`, `vendor`, `model`, `rules`, `config_text` |
| `firewall_interface` | `firewall_id`, `name` | `ip_addresses` array (IPv4/IPv6 addresses or CIDRs), `mac_address`, `network_id`, `vlan_id`, `role` (`wan`, `lan`, `dmz`, `management`, `ha`, `vpn`, `other`), `is_primary`, `description` |
| `firewall_nat_rule` | `firewall_id`, `name`, `nat_type` | `enabled`, `protocol`, `source_cidr`, `original_destination`, `original_port`, `translated_source`, `translated_destination`, `translated_port`, `inbound_interface_id`, `outbound_interface_id`, `description`; types: `vip`, `dnat`, `snat`, `port_mapping` |
| `network_connection` | `source_network_id`, `target_network_id`, `connection_type` | `description`, `device_name`; source and target must differ |
| `timeline_event` | `raw_timestamp` or `timestamp`, `description` | `raw_timezone`, `clock_profile_id`, `asset_id`, `event_type`, `severity` (`info`, `low`, `medium`, `high`, `critical`), `source`, `mitre_tactic`, `mitre_technique` |
| `ioc` | `ioc_type`, `value` | `description`, `threat_level` (`low`, `medium`, `high`, `critical`), `first_seen`, `last_seen`; types: `IP`, `Hash`, `Domain`, `URL`, `Email`, `Registry`, `Mutex` |
| `ioc_sighting` | `ioc_id`, `entity_kind` (`asset`, `network`, `firewall`), `entity_id` | `sighted_at`, `location`, `note`; the IOC and target entity must exist |
| `attack_edge` | `source_kind` (`asset`, `network`, `firewall`, `external`), `source_id`, `target_kind` (`asset`, `network`, `firewall`), `target_id`, `title` | `description`, `edge_type` (`initial_access`, `lateral_movement`, `privilege_escalation`, `persistence`, `c2`, `exfiltration`, `other`), `confidence` (`confirmed`, `probable`, `suspected`), `mitre_tactic`, `mitre_technique`, `occurred_at`, `timeline_event_id`, `sequence`, `ioc_ids` (array of existing IOC UUIDs); for `external` sources `source_id` is a free origin label; source and target must differ |
| `note` | `title` | `content` (safe Markdown when displayed) |

Entity aliases accepted by the parser include common singular/plural forms, `nic` for `network_interface`, `firewall_nic` for `firewall_interface`, and `nat` for `firewall_nat_rule`; canonical generators should use the names in the table.

`properties`, `scan_results`, and firewall `rules` may be supplied as JSON objects/arrays or as valid JSON strings. The app stores them as JSON text in SQLite without losing their nested structure.

## 5. Time input

Timeline and IOC time values accept:

- `DD-MM-YYYY HH:mm:ss.SSS` in 24-hour form;
- ISO/RFC 3339, such as `2026-07-19T14:25:30.123Z`;
- Unix seconds;
- Unix milliseconds; and
- partial date/time values, where omitted time, seconds, or milliseconds become zero.

For a wall-clock value without an embedded offset, provide `raw_timezone` as `UTC`, a fixed offset such as `+07:00`, or an IANA zone such as `Asia/Novosibirsk`. The app normalizes the stored event instant to UTC and preserves the raw value and zone. A referenced `clock_profile_id` applies the profile's measured correction.

See [TIME_CORRELATION.md](TIME_CORRELATION.md) for ambiguity, daylight-saving, precision, and clock-correction rules.

## 6. Copy-ready examples

### Update one existing asset

```json
{
  "format": "dfir-investigator-partial",
  "format_version": 1,
  "case_id": "OPEN-CASE-UUID",
  "source": "Expert B endpoint review",
  "changes": [
    {
      "change_id": "asset-23-status",
      "entity_type": "asset",
      "operation": "update",
      "target_id": "EXISTING-ASSET-UUID",
      "values": {
        "compromise_status": "infected",
        "investigation_status": "in_progress"
      }
    }
  ]
}
```

### Create a network, asset, NIC, timeline event, and expert note together

```json
{
  "format": "dfir-investigator-partial",
  "format_version": 1,
  "case_id": "OPEN-CASE-UUID",
  "source": "Room 204 triage worksheet",
  "changes": [
    {
      "change_id": "room-network",
      "entity_type": "network",
      "operation": "create",
      "values": {
        "id": "11111111-1111-4111-8111-111111111111",
        "name": "Room 204 isolated LAN",
        "subnet": "10.10.10.0/24",
        "network_type": "LAN",
        "description": "May overlap another isolated zone"
      }
    },
    {
      "change_id": "room-host",
      "entity_type": "asset",
      "operation": "create",
      "values": {
        "id": "22222222-2222-4222-8222-222222222222",
        "network_id": "11111111-1111-4111-8111-111111111111",
        "name": "WS-204-07",
        "ip_address": "10.10.10.27",
        "asset_type": "workstation",
        "compromise_status": "suspected",
        "investigation_status": "in_progress"
      }
    },
    {
      "change_id": "room-host-primary-nic",
      "entity_type": "network_interface",
      "operation": "create",
      "values": {
        "id": "33333333-3333-4333-8333-333333333333",
        "asset_id": "22222222-2222-4222-8222-222222222222",
        "network_id": "11111111-1111-4111-8111-111111111111",
        "name": "Ethernet 1",
        "ip_address": "10.10.10.27",
        "is_primary": true
      }
    },
    {
      "change_id": "room-host-event",
      "entity_type": "timeline_event",
      "operation": "create",
      "values": {
        "asset_id": "22222222-2222-4222-8222-222222222222",
        "raw_timestamp": "19-07-2026 14:25:30.125",
        "raw_timezone": "+07:00",
        "event_type": "triage",
        "description": "Responder observed an active suspicious session",
        "severity": "high",
        "source": "Console observation"
      }
    },
    {
      "change_id": "room-host-note",
      "entity_type": "note",
      "operation": "create",
      "values": {
        "title": "WS-204-07 expert note",
        "content": "Preserve volatile evidence before shutdown."
      }
    }
  ]
}
```

## 7. Review and merge behavior

Opening or pasting partial input does not mutate SQLite. The workflow is:

1. parse and case-check;
2. run all proposed changes in a rollback-only transaction;
3. show invalid, unchanged, create, and update records with field differences;
4. select individual records or a section policy;
5. dry-run the exact selection again;
6. show final create/update totals; and
7. apply all selected records in one audited transaction after confirmation.

Section policies are:

- **Skip section / Keep current only**: import nothing from that section;
- **Add missing only / Add expert records**: create new UUIDs and retain matching local records; and
- **Use incoming versions**: create new UUIDs and patch/overwrite reviewed matching UUIDs.

For Notes and Timeline, using incoming versions does not delete unrelated local records. Deletions are unsupported in partial JSON and are never bulk-selected in expert-bundle section shortcuts. Timeline patches may provide `raw_timestamp` plus `raw_timezone` for the server clock, `correct_timestamp_raw` plus `correct_timezone` for directly known real time, or `clock_profile_id` to apply a saved correction. Server and correct timestamps are independently optional and may both be added later.

## 8. Full snapshot structure

A plain snapshot is formatted UTF-8 JSON with this root structure:

```json
{
  "format_version": 4,
  "exported_at": "2026-07-19T14:25:30.125Z",
  "case_info": {},
  "networks": [],
  "assets": [],
  "network_interfaces": [],
  "clock_profiles": [],
  "network_connections": [],
  "firewalls": [],
  "firewall_interfaces": [],
  "firewall_nat_rules": [],
  "timeline_events": [],
  "iocs": [],
  "ioc_sightings": [],
  "attack_edges": [],
  "investigation_views": [],
  "notes": []
}
```

`ioc_sightings` and `attack_edges` are evidence entities and take part in history, expert bundles, and partial import. `investigation_views` are named saved Investigation Graph views (presentation state): imported by snapshot for convenience but excluded from history, expert bundles, and partial import. Snapshots written before these arrays existed remain valid; each missing array defaults to empty.

Snapshot import requires the same `case_info.id`, inserts missing UUIDs, skips existing UUIDs, and never overwrites open-case metadata. A plain snapshot can also be loaded into the partial-import reviewer; there it is converted to reviewed upserts so the operator can explicitly select incoming updates.

## 9. Expert bundle and encrypted envelope

An expert bundle has `format: "dfir-investigator-changes"` and contains attributed commits from a shared baseline. Do not hand-author it; generate it through **Expert Merge → Save change bundle**.

An encrypted file has `format: "dfir-investigator-encrypted"`. Its authenticated ciphertext contains the exact ordinary snapshot or expert-bundle JSON bytes. The portable password is independent of session expert names and machines.

See [../PORTABLE_EXPORT_FORMAT.md](../PORTABLE_EXPORT_FORMAT.md) for the language-neutral Argon2id/AES-256-GCM envelope and [PARTIAL_IMPORT.md](PARTIAL_IMPORT.md) for the operator-focused partial review process.

## 10. LLM preparation guidance

Use **Expert Merge → Plain structured partial import → Save template file**. The generated template includes the exact open case UUID, supported fields, examples, and an ID reference catalog. Instruct the model to:

1. return one JSON object only;
2. keep the supplied `format`, version, and case ID;
3. place actual proposals only in `changes`;
4. use reference-catalog UUIDs for updates and relationships;
5. create explicit UUIDs when new records refer to one another;
6. never invent missing facts—omit unknown optional fields; and
7. never request deletion.

The generated catalog can contain sensitive hostnames, IP addresses, evidence descriptions, and UUIDs. Sending it to an external model is a data-disclosure decision. Use an approved local/private model when required.
