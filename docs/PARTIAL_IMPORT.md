# Plain Structured Partial Import

## Purpose

The structured partial-import workflow converts information prepared by an investigator, script, another team, or an LLM into reviewed application records. It can propose one field update, several entity sections, or a complete plain snapshot. Parsing and preview are read-only. The case changes only after selection validation and explicit confirmation.

This workflow is intentionally unencrypted and interoperable. Encrypted snapshots and expert bundles continue through their existing password-aware workflows.

For the complete entity field table, enum values, time syntax, full-snapshot root, and copy-ready multi-entity example, see [INPUT_FORMATS.md](INPUT_FORMATS.md).

## Case-aware template

In **Expert Merge → Plain structured partial import**, choose **Load template into editor** or **Save template file**. The generated JSON contains:

- the fixed format and version;
- the open case ID;
- supported operations and entity types;
- field guidance;
- a compact reference catalog of current UUIDs and human labels; and
- examples outside the active `changes` array.

The reference catalog lets a person or LLM target an existing record precisely. It may contain sensitive host names, IP addresses, evidence descriptions, and identifiers. Sending it to an external LLM is a disclosure decision made outside this offline application. Use an approved local/private model when the case requires it.

## Document structure

```json
{
  "format": "dfir-investigator-partial",
  "format_version": 1,
  "case_id": "OPEN-CASE-UUID",
  "source": "Analyst B extraction from supplied notes",
  "changes": [
    {
      "change_id": "finding-note",
      "entity_type": "note",
      "operation": "create",
      "values": {
        "title": "Credential theft finding",
        "content": "Markdown content"
      }
    },
    {
      "change_id": "asset-status",
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

The parser also accepts a Markdown fenced JSON block, which is common LLM output.

JSON files must be UTF-8. Canonical keys use `entity_type`, `target_id`, and `values`; compatibility aliases `entityType`, `targetId`, and `data` are also accepted.

## Operations

| Operation | Behavior |
|---|---|
| `create` | Creates a new record. `values.id` is optional unless another new record must reference it. |
| `update` | Applies only supplied fields to the exact `target_id`; fails if it does not exist. |
| `upsert` | Creates when the UUID is absent and updates when it exists. Plain snapshots are converted to upserts. |

Deletion is deliberately unsupported. Imports never replace a record by matching its name, IP address, title, or timestamp. Updates/overwrites require the same UUID.

Supported entities are case metadata, networks, assets, NICs, server-clock profiles, firewalls, network connections, timeline events, IOCs, and notes.

For multiple newly created related records, provide UUIDs in `values.id` and use those UUIDs in foreign-key fields such as `network_id`, `asset_id`, `source_network_id`, or `target_network_id`.

## Review policies

Each section offers:

- **Skip section** — no records in that section are imported;
- **Add missing only** — selects only records whose UUID does not exist; and
- **Use incoming versions** — selects new records and partial/full updates to matching UUIDs.

For notes and timeline evidence, **Add missing only** keeps the local records and adds differently identified expert records. **Use incoming versions** also overwrites matching UUIDs with reviewed incoming fields. It does not remove other local notes or events.

Every record can be expanded to compare current and incoming field values and can be selected individually.

## Validation and transaction sequence

1. Parse JSON and verify format/case ID.
2. Normalize supported aliases and default fields for new records.
3. Apply every proposal inside a rollback-only SQLite transaction using the normal backend validators.
4. Show create, update, unchanged, and invalid records with field differences.
5. Let the investigator select records or section policies.
6. Dry-run the exact selected subset again, including relationship and foreign-key checks.
7. Show the create/update totals and request confirmation.
8. Apply all selected records in one transaction and write one attributed audit-history commit.

If one selected record is invalid, references an unselected dependency, or changed after preview, the complete import is rejected without partial mutation.

## Expert change bundles

Git-like expert bundle review remains the preferred path when experts began from a shared case baseline because it preserves authorship, ancestry, and field-conflict information. Its Timeline and Notes sections now have the same intent controls:

- **Keep current only**;
- **Add expert records**; and
- **Use expert versions**.

Incoming deletion remains an individual explicit decision and is never selected by these section shortcuts.
