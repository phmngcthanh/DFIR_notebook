# White-label configuration

Application version: 1.0.20
Last reviewed: 2026-07-19

## In-application identity

Edit `src/config/branding.ts` to change the product name, short sidebar name, tagline, organization, About description, support address, website, version text, and legal notice. These values drive the sidebar, welcome screen, and About page. Rebuild after editing.

The About page is deliberately available before a case is opened, so an organization can display ownership and support information without exposing case data.

## Native package identity

The frontend branding file does not rename Windows artifacts. For a full rebrand, also update these fields in `src-tauri/tauri.conf.json`:

- `productName` — installed application and window-facing product name;
- `identifier` — reverse-domain package identifier; use an identifier owned by the organization;
- `version` — packaged application version;
- window `title`; and
- bundle icons under `src-tauri/icons`.

Keep `package.json` and the displayed version in `src/config/branding.ts` aligned with the Tauri version. Changing the SQLite/export format identifiers is not branding and would break interoperability; do not rename those identifiers.

## Build the branded release

Run all quality gates, then build the NSIS installer:

```powershell
npm run lint
npm run build
npm test
cargo test --manifest-path src-tauri\Cargo.toml
npm run tauri-build:windows
```

Verify the About page, executable properties, installer name, icons, window title, and uninstall entry on a clean test workstation before distribution.
