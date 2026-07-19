# DFIR Network Investigator Documentation

This directory documents the implemented desktop application as of 2026-07-19, application version 0.1.0.

| Document | Audience | Purpose |
|---|---|---|
| [USER_GUIDE.md](USER_GUIDE.md) | Investigators and merge leads | Daily operating instructions, collaboration, encryption, and troubleshooting |
| [RUNNING_AND_BUILDING.md](RUNNING_AND_BUILDING.md) | Operators, developers, and release engineers | Installed/standalone startup, platform prerequisites, development commands, Windows/Linux/macOS release packaging, and build troubleshooting |
| [WHITE_LABELING.md](WHITE_LABELING.md) | Product owners and release engineers | Editable About-page branding and native package identity |
| [INPUT_FORMATS.md](INPUT_FORMATS.md) | Investigators, LLM/script integrators, and reviewers | Accepted case/snapshot/bundle/partial formats, complete partial field reference, examples, and merge semantics |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Engineers, security reviewers, and maintainers | Application structure, data model, trust boundaries, history model, and deployment |
| [TIME_CORRELATION.md](TIME_CORRELATION.md) | Investigators and forensic reviewers | Flexible timestamp syntax, dual-zone display, Unix epochs, and reusable server-clock correction |
| [PARTIAL_IMPORT.md](PARTIAL_IMPORT.md) | Investigators, integrators, and reviewers | Case-aware LLM template, plain partial imports, validation preview, section policies, and transactional confirmation |
| [TEXT_PARSER.md](TEXT_PARSER.md) | Operators and integrators | Read-only export-to-text pipeline, accepted inputs, output structure, and safeguards |
| [TECHNICAL_REVIEW_HQ.md](TECHNICAL_REVIEW_HQ.md) | Headquarters, technical authorities, and program owners | Executive assessment, operational value, security posture, limitations, risks, and recommendation |
| [CAPABILITY_ASSESSMENT.md](CAPABILITY_ASSESSMENT.md) | Headquarters, investigators, and acceptance reviewers | Current implementation assessment, corrected old conclusions, and fitness against the 30-machine scenario |
| [../PORTABLE_EXPORT_FORMAT.md](../PORTABLE_EXPORT_FORMAT.md) | Integrators | Language-neutral `.dfirx` encryption envelope specification |
| [../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) | Operators and legal/security reviewers | SQLCipher Community Edition and OpenSSL attribution and license notices |

The root-level `architecture_diagram.png`, `database_schema.png`, `dfir_network_investigation_platform.md`, and `encryption_analysis.md` are archived design material. They describe server-side or proposed components that are not authoritative for the current application.
