# Centralized case server

This branch adds a second shell over the same investigation core the desktop app
uses: a small Rust HTTP server that holds the SQLCipher case files, and the same
React UI running in a browser instead of a Tauri window.

The point is to remove the file-exchange ceremony. On `main`, every expert holds
their own copy of the `.db` and the team merges change bundles at a meeting. Here
everyone edits **one** case file at the same time, so an edit is simply a write,
and every other open browser picks it up within seconds.

What does *not* change: there are still no user accounts. The case database
password is the credential, the expert name beside it is self-declared
attribution, and every write is still recorded in the append-only commit history.

---

## Running it

```bash
npm install
npm run build                     # builds the browser UI into dist/
npm run server-build -- --release # builds the server binary
```

Development, with the UI served by Vite and the API proxied to the server:

```bash
npm run server-dev                # cargo run -- --cases ./cases --allow-create --insecure
npm run dev                       # separate terminal; proxies /api to 127.0.0.1:8443
```

Production-ish, one process serving both:

```bash
./dfir-server --cases /srv/dfir/cases --web ./dist --bind 0.0.0.0:8443
```

`npm run server-*` wraps `cargo` the same way `npm run tauri-build:windows`
wraps the Tauri CLI: it selects the MSVC host of the toolchain pinned in
`rust-toolchain.toml` and puts Strawberry Perl on `PATH`, both of which the
vendored SQLCipher/OpenSSL build needs on Windows.

### Options

| Flag | Default | Meaning |
|---|---|---|
| `--cases <dir>` | `./cases` | Directory of `.db` case files. Created if missing. |
| `--web <dir>` | `./dist` | Built frontend to serve. |
| `--bind <addr:port>` | `0.0.0.0:8443` | Listen address. |
| `--tls-cert` / `--tls-key` | — | PEM certificate and key. Both or neither. |
| `--insecure` | off | Serve plain HTTP. Development only. |
| `--allow-create` | off | Permit creating case files over HTTP. |
| `--session-timeout <min>` | `480` | Idle minutes before a session is dropped. |

### TLS

With no `--tls-cert`, the server generates a self-signed certificate once and
stores it as `server-cert.pem` / `server-key.pem` in the case directory, so its
fingerprint is stable across restarts. Startup prints:

```
  cert sha256 A1:B2:...:9F
```

Have each expert compare that against what their browser shows the first time
they connect, then accept it. Regenerating on every boot would train the team to
click through certificate warnings, which is why the certificate is persisted.

`--insecure` exists so you can check the app works before dealing with
certificates. It sends case passwords and case contents in clear text; the
server prints a warning on every start while it is enabled.

---

## Cases

One server instance serves any number of cases. Each `.db` in `--cases` appears
in the login picker under its filename stem, and each has its own password.

- **Case filenames are visible without authenticating.** They have to be — an
  expert must pick a case before they can unlock it. The contents stay
  encrypted, but the name does not, so use neutral names like `case-2026-07`
  rather than the client's name.
- `--allow-create` is off by default so that anyone who can reach the port
  cannot fill the disk with case files. Turn it on when the team needs to create
  cases from the browser; otherwise drop `.db` files into the directory yourself.
- A case's connection opens on the first successful unlock and closes when the
  last expert working on it logs out or times out.
- The `.db` files are the backup. Copy them while no one is editing, or use
  **Case Transfer → Download snapshot**.
- Converting a legacy unencrypted `.db` is not exposed over HTTP because it
  needs two local paths. Use the desktop build for that, then drop the encrypted
  result into the case directory.

---

## Security model

The offline threat model treats the six-character password minimum as a
*presence* control — enough to stop someone editing the case while an expert is
away from their laptop, not a defense against offline cracking. **Putting the
case on a network changes that**: the password is now reachable by anyone who can
see the port. Two consequences:

- Choose a real passphrase for a server case, not six characters. The old
  minimum is still enforced for compatibility, and the create screen says so.
- The server locks an address out after 5 failed unlocks in 15 minutes, and no
  unlock reply resolves in under 250 ms.

Everything else follows the desktop posture:

- No password is stored or hashed anywhere. Unlocking calls
  `open_encrypted_connection`, and SQLCipher either derives a working key or it
  does not. Verifying an already-open case opens a throwaway second connection —
  the same trick the desktop app uses before a rekey.
- Session tokens are 32 random bytes, held in memory only, sent as
  `Authorization: Bearer`, and kept in the browser's `sessionStorage` so closing
  the tab ends the session. Nothing is stored in a cookie, so there is no CSRF
  surface.
- Changing a case password signs every other expert on that case out, because
  their tokens were issued against the old password.
- Case identifiers from the client are restricted to a filename alphabet and
  resolved inside the case directory, so no request can reach another path.
- The same strict CSP the desktop app uses is served with the UI:
  `default-src 'self'`, no remote content of any kind.
- Portable `.dfirx` exports are unchanged, so files move between the desktop
  build and the server in both directions.

Bind to `127.0.0.1` and put the server behind an existing reverse proxy if you
would rather manage certificates there. Disk encryption still matters: SQLCipher
protects the case file at rest, not the server's memory while a case is unlocked.

---

## How the browser stays current

Every mutating command bumps an in-memory revision counter for its case. Each
browser polls `GET /api/state` every five seconds and, when the number moves,
re-fetches the view it is showing. That endpoint reads server memory only — it
never queues behind a write on the case connection.

Writes serialize on a single connection per case, so two experts editing the
same record is last-write-wins, with both edits attributed in the history. There
is no field-level locking; the team is expected to split work by zone or
department the way the offline workflow already does.

---

## Relationship to the desktop app

`src-tauri/` is **unmodified** on this branch. The server includes the five core
modules (`db`, `history`, `partial_import`, `portable_export`, `secure_db`)
straight from `src-tauri/src/` with `#[path]`, so:

- the investigation logic, schema, migrations, and crypto cannot drift between
  the two shells;
- merges from `main` land cleanly, because no existing file was restructured;
- `cargo test` on the server crate also runs the core modules' own test suites.

The browser UI on this branch talks HTTP, so it is not a working Tauri frontend —
the desktop *bundle* is not a supported output here. Use `main` for the offline
desktop product. What is preserved is the shared core, which
`cargo check --manifest-path src-tauri/Cargo.toml` verifies.
