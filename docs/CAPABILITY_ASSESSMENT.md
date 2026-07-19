# Capability Assessment

Assessment date: 2026-07-19  
Application version: 1.0.20, schema version 6
Assessment basis: implemented source, automated tests, production build, and the supplied 30-machine/two-perimeter-firewall scenario

## 1. Conclusion

DFIR Network Investigator can represent and coordinate the supplied scenario as a manual offline investigation workspace. It can hold the complete 30-machine inventory, four internal zones, two ISP edges, two perimeter firewalls, firewall interfaces and addresses, structured address translation, stated connectivity, independent clock corrections, findings, uncertainty, and Alex's pending review note.

The application is suitable for building a common operating picture and reconciling work performed by several experts. It is not a network-policy simulator, vulnerability scanner, log parser, automatic asset-discovery system, task manager, or proof that a suspected exploit path occurred.

Overall assessment: **operationally capable with explicit evidence and automation boundaries**.

## 2. Current capability assessment

| Area | Status | What is implemented | Boundary |
|---|---|---|---|
| Offline case storage | Implemented | One user-selected SQLCipher/SQLite database per case; no service or database server | One case is open at a time |
| Local access password | Implemented | A password protects each physical database file and can be changed | It is shared file access, not user authentication |
| Expert attribution | Implemented | Self-declared expert name, session, time, scope, and before/after change history | It does not prove identity or enforce authorization |
| Network zones | Implemented | LAN/DMZ/WAN/etc. zones, overlapping CIDRs, VLAN and descriptions | No automatic network discovery |
| Assets and coverage | Implemented | Workstations/servers, IP/MAC/OS/user, compromise state, investigation progress and JSON details | Observations are manually entered |
| Asset NICs | Implemented | Multiple NICs, one primary projection, secondary topology edges | No live interface enumeration |
| Dedicated firewalls | Implemented | Vendor/model/configuration plus multiple named interfaces | No configuration-file vendor parser |
| Firewall addressing | Implemented | Multiple IPv4/IPv6 addresses or CIDRs per interface, zone, VLAN, MAC, role and primary/home interface | Address ownership is asserted by the investigator |
| NAT and VIP | Implemented | VIP, DNAT, SNAT and port mappings with protocol, source, original/translated addresses and ports, ingress/egress interfaces and enabled state | It does not calculate rule order, shadowing or effective policy |
| Reachability documentation | Partially implemented | Zone links, firewall interface edges, descriptions and JSON policy observations | Links document the asserted design; they do not simulate ACLs or prove reachability |
| Topology | Implemented | Zones, assets, dedicated firewalls, asset NIC edges, firewall interface edges, layouts and PNG export | The graph is a documented operational model, not packet-derived truth |
| Timeline | Implemented | Independently optional raw server time and correct time, reusable clock profiles, RFC 3339 UTC storage, selected-zone/UTC display and filters | Clock stability between measurements is not proven |
| Independent findings | Implemented | Events may be months apart and unrelated; neither chronology nor causality is inferred merely from their presence | Investigators must state relationships or uncertainty themselves |
| Notes and hypotheses | Implemented | Safe Markdown notes preserve analysis, assignments and caveats | There is no structured task/due-date workflow |
| Expert merge | Implemented | Git-like baseline bundles, attributed field diffs, conflict review and transactional selective apply | No live collaboration or central repository |
| Partial/LLM intake | Implemented | Plain JSON template, validation, preview, selective confirmation and transactional import | It never treats generated text as verified evidence |
| Export protection | Implemented | Interoperable plain JSON and independent password-encrypted Argon2id/AES-256-GCM export | Export encryption does not replace evidence-handling procedure |
| Reporting | Partially implemented | Read-only text rendering and topology PNG | No formatted PDF/final-report generator |

## 3. Fit against the supplied scenario

The import fixture represents:

- 22 Windows 11 Pro workstations: 12 in Department 1 and 10 in Department 2;
- eight servers: four DMZ and four LocalServer systems;
- four internal zones plus two ISP-edge abstractions;
- a DMZ perimeter firewall using `203.0.113.4` and a Department perimeter firewall using `203.0.113.5`;
- separate firewall interfaces for ISP, DMZ, both departments and LocalServer;
- Department 1 and Department 2 outbound SNAT through `203.0.113.5`;
- DMZ outbound SNAT and four inbound DNAT findings through `203.0.113.4`;
- allowed Department/DMZ paths and LocalServer-to-department paths, with no LocalServer-to-DMZ link;
- the Exchange traversal/credential-download log finding;
- the Department 2 User-3 malware execution finding; and
- an unconfirmed perimeter-firewall zero-day hypothesis assigned to Alex for log review.

The supplied DMZ and LocalServer CIDRs were unspecified. The fixture therefore uses documentation-range placeholders `10.20.0.0/24` and `10.10.10.0/24`, clearly marked for replacement. Exact DMZ public port numbers were also unspecified. The fixture creates four DNAT records with the correct public/internal addresses and an explicit â€œport not yet confirmedâ€ description; it does not fabricate port evidence.

## 4. Timeline re-assessment

The two timeline records are valid independent findings. The application must not reject or imply a causal chain merely because January precedes June.

### Exchange finding

- preserved server/log value: `23-06-2026 12:23:45`, declared by the log/server as UTC;
- known correct local reference: `23-06-2026 15:23:45` at UTC+7;
- normalized server interpretation: `23-06-2026 12:23:45 UTC`;
- corrected incident instant: `23-06-2026 08:23:45 UTC` / `23-06-2026 15:23:45 UTC+7`; and
- applied correction: `-04:00:00`.

This unusual negative four-hour correction is correct for the stated observation: a value labelled UTC was actually three hours behind the UTC+7 local clock.

### User-3 finding

- preserved workstation value: `23-01-2026 07:01:25` at UTC+7;
- measured clock error: one day, three hours and 24 minutes slow;
- corrected incident instant: `24-01-2026 03:25:25 UTC` / `24-01-2026 10:25:25 UTC+7`; and
- applied correction: `+27:24:00`.

The records are stored separately. Their descriptions explicitly state that no relationship to one another has been established.

## 5. Old assessment disposition

The earlier assessment should no longer be used without these corrections:

| Earlier conclusion | Current disposition |
|---|---|
| Dedicated firewalls cannot have multiple NICs/IPs | Resolved. Firewall interfaces are normalized records and each may contain multiple IPv4/IPv6 addresses or CIDRs. |
| NAT/VIP/DNAT/SNAT/port mapping is only unstructured text | Resolved. These are structured, validated, editable, versioned and mergeable records. |
| Firewall topology is represented only by one home network | Resolved for documentation. One primary interface places the node; additional interfaces draw explicit zone edges. |
| The January/June sequence makes the timeline invalid | Incorrect. They are independent findings unless evidence establishes a relationship. Chronological distance is not a validation error. |
| Connectivity records enforce or prove policy | Still not true. They document asserted links and observations; the application does not execute a policy engine. |
| Alex's work can be managed as a task | Not implemented as a structured task. It can be preserved in an attributed note and later updated/merged. |
| Reported zero-day information proves this intrusion path | Not true. It remains an explicitly unconfirmed hypothesis until log/evidence review supports it. |

## 6. Acceptance judgment

For this scenario the application can answer the coordination questions it is designed for:

- Which 30 machines exist, where are they, and which remain uninvestigated?
- Which perimeter device and public IP govern each traffic path?
- Which NAT findings are known, and which ports are still unknown?
- Which zones are asserted to communicate and which path is intentionally absent?
- What raw time did each source report, what correction was applied, and what is the normalized UTC instant?
- Which finding came from which expert session, and what changed during merge?
- What must Alex review next, and why is the zero-day theory still unconfirmed?

It cannot independently answer whether the firewall zero-day was exploited, whether a documented rule was effective at the event time, or whether the workstation malware and Exchange traversal are related. Those remain investigation questions rather than software-generated conclusions.
