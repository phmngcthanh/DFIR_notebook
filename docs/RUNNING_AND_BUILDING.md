# Running and Building DFIR Network Investigator

Document version: 1.0  
Application version: 0.1.0  
Last reviewed: 2026-07-19

## 1. Runtime model

DFIR Network Investigator is a local desktop application for Windows, Linux x86_64, and macOS on Intel or Apple Silicon. React is hosted inside the platform WebView through Tauri, Rust runs in the same desktop process, and each case is a SQLCipher-encrypted SQLite `.db` file.

Running the application does **not** require FastAPI, Node.js, a database server, a web server, an account service, or Internet access. Node.js and Rust are development/build requirements only.

Do not open the same case file for writing from two application instances, especially across a network share. Give each expert a copy and reconcile work with Expert Merge.

## 2. Run an installed or packaged release

### Windows

Recommended installer:

```text
src-tauri\target\release\bundle\nsis\DFIR-Investigator_0.1.0_x64-setup.exe
```

Install the application and launch **DFIR-Investigator** from Windows. Microsoft Edge WebView2 Runtime must be installed; it is normally already present on supported Windows releases.

### Standalone executable

The release executable can also be started directly:

```powershell
.\src-tauri\target\release\dfir-investigator.exe
```

The executable is a GUI program, so a terminal prompt returning without printed output is normal. A current build should open a window titled **DFIR Network Investigator**. If no window appears, see [Troubleshooting](#7-troubleshooting).

The verified installer for this release is NSIS. An MSI is optional and should only be documented or distributed when an MSI file was actually produced and tested in the target environment.

The package also installs `THIRD_PARTY_NOTICES.md` as an application resource for the bundled SQLCipher Community Edition and OpenSSL components.

### Linux

Linux builds produce Debian and AppImage artifacts when built on a compatible Linux host:

```text
src-tauri/target/release/bundle/deb/*.deb
src-tauri/target/release/bundle/appimage/*.AppImage
```

For Ubuntu/Debian x86_64, prefer the `.deb` package when the target machine is managed through apt. Use the AppImage for a more portable field copy, but expect the target system to provide the normal desktop WebKit/GTK runtime libraries.

### macOS

macOS builds produce `.app` and `.dmg` artifacts when built on macOS:

```text
src-tauri/target/release/bundle/macos/*.app
src-tauri/target/release/bundle/dmg/*.dmg
```

Use the universal macOS build when one download must run on both Intel and Apple Silicon. Use the single-architecture commands only when you intentionally want a smaller architecture-specific package.

## 3. Platform build rule

Build each desktop release on that operating system:

| Target users | Build host | Command |
|---|---|---|
| Windows x86_64 | Windows x86_64 with MSVC host installed | `npm run tauri-build:windows` |
| Ubuntu/Debian x86_64 | Ubuntu/Debian x86_64 | `npm run tauri-build:linux` |
| macOS Intel | macOS Intel or Apple Silicon with Intel target installed | `npm run tauri-build:mac-intel` |
| macOS Apple Silicon | macOS Apple Silicon | `npm run tauri-build:mac-apple` |
| macOS Intel + Apple Silicon | macOS, preferably Apple Silicon | `npm run tauri-build:mac-universal` |

Do not plan on producing macOS release artifacts from Windows. Tauri applications use Apple's native SDK, bundle tools, signing/notarization path, and WebKit framework assumptions. Linux should also be built on Linux because its WebKitGTK/AppIndicator packaging dependencies are distro-native.

The repository uses `rust-toolchain.toml` with `channel = "stable"` so Linux and macOS builders are not forced into a Windows-only Rust host. `npm run tauri-build` runs through `scripts/tauri-build.mjs`; on Windows that wrapper sets `RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-msvc`, prepends the common Strawberry Perl path, and defaults the Tauri target to `x86_64-pc-windows-msvc` so Cargo host build-dependencies do not fall back to GNU.

## 4. Windows development prerequisites

Install:

- Node.js 20 or newer, including npm;
- Rust through `rustup`;
- Visual Studio 2022 Build Tools with **Desktop development with C++**;
- a current Windows SDK; and
- Microsoft Edge WebView2 Runtime; and
- Strawberry Perl, used only while compiling the vendored OpenSSL dependency required by SQLCipher.

Install Strawberry Perl from its official installer or with:

```powershell
winget install --id StrawberryPerl.StrawberryPerl -e
```

Open a new terminal after installation. The `npm run tauri-build:windows` script also prepends the common `C:\Strawberry\perl\bin` location for release builds. If Perl was installed elsewhere and is not yet on that terminal's `PATH`, prefix build commands in the current PowerShell session with:

```powershell
$env:PATH = 'C:\Strawberry\perl\bin;' + $env:PATH
```

Install the Windows MSVC Rust host once:

```powershell
rustup toolchain install stable-x86_64-pc-windows-msvc
rustup default stable-x86_64-pc-windows-msvc
```

Verify that the active host is MSVC, not GNU:

```powershell
rustup show active-toolchain
rustc -vV
node --version
npm --version
```

`rustc -vV` should report `host: x86_64-pc-windows-msvc`.

## 5. Linux x86_64 prerequisites

On Ubuntu/Debian x86_64, install Node.js 20+, Rust stable, and Tauri's desktop build libraries. A typical package set is:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  curl \
  file \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  patchelf \
  perl \
  pkg-config \
  webkit2gtk-4.1-dev
```

Then install Rust if needed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
```

Some older Debian/Ubuntu releases package WebKitGTK under `webkit2gtk-4.0-dev` instead of `webkit2gtk-4.1-dev`. Use the package name available for the target build distribution.

## 6. macOS prerequisites

On macOS Intel or Apple Silicon:

```bash
xcode-select --install
rustup default stable
npm install
```

For Intel-only builds on Apple Silicon, install the Intel Rust target:

```bash
rustup target add x86_64-apple-darwin
```

For Apple Silicon builds on Intel macOS, install the Apple Silicon target:

```bash
rustup target add aarch64-apple-darwin
```

For universal builds:

```bash
rustup target add x86_64-apple-darwin aarch64-apple-darwin
```

Distribution outside a controlled lab may require Apple Developer signing and notarization. The unsigned `.app`/`.dmg` produced by a local build may be blocked by Gatekeeper depending on the target Mac policy.

## 7. First source setup

From the repository root:

```bash
npm install
```

The Tauri CLI is already a project development dependency. A global Tauri installation is not required.

## 8. Development modes

### Debug versus release

| | Debug (`npm run tauri-dev`) | Release (`npm run tauri-build:windows`, `npm run tauri-build:linux`, or `npm run tauri-build:mac-universal`) |
|---|---|---|
| Purpose | Development, diagnostics, rapid iteration | Distribution and operational use |
| Frontend | Vite development server with hot reload | Prebuilt `dist` assets embedded in the desktop package |
| Rust | Unoptimized debug executable with symbols | Optimized release executable |
| Location | `src-tauri\target\debug` | `src-tauri\target\release` and `release\bundle\nsis` |
| Performance/size | Starts and runs more slowly; larger diagnostics footprint | Faster/smaller runtime; initial release compilation can take longer |
| Error visibility | Build/runtime diagnostics remain in the development terminal | GUI application normally prints nothing to a terminal |

A debug build is not a substitute for testing the packaged release: bundling, embedded assets, CSP, installer resources, and target paths differ. A release build does not provide Vite hot reload.

### Full desktop application

Use this for normal feature development and case-file testing:

```bash
npm run tauri-dev
```

This starts Vite and then compiles/runs the Rust desktop shell. The first Rust build can take substantially longer because SQLCipher and vendored OpenSSL are compiled locally. Keep the command running while using the application.

The equivalent forwarding form is `npm run tauri dev`, but `npm run tauri-dev` is the documented command.

### Frontend only

```bash
npm run dev
```

This starts Vite at `http://localhost:5173`. It is useful for frontend compilation and limited layout work. Native dialogs, SQLite access, encryption, and Tauri commands require the full desktop mode and will not work as a normal browser-only application.

## 9. Test and build commands

### Quality gates

Run from the repository root:

```bash
npm run lint
npm run build
npm test
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo test --manifest-path src-tauri/Cargo.toml
```

On Windows, if the system default Rust host is GNU, run Rust tests with the MSVC toolchain explicitly:

```powershell
cargo +stable-x86_64-pc-windows-msvc test --manifest-path src-tauri\Cargo.toml
```

`npm run build` produces only the compiled web frontend in `dist`. It does not produce a Windows desktop executable.

### Windows release and installer

Build the verified NSIS package:

```powershell
npm run tauri-build:windows
```

Important outputs:

```text
src-tauri\target\release\dfir-investigator.exe
src-tauri\target\release\bundle\nsis\DFIR-Investigator_0.1.0_x64-setup.exe
```

To request every bundle target configured in `tauri.conf.json`, use:

```powershell
npm run tauri-build
```

To use the forwarding form, this also works on Windows:

```powershell
npm run tauri-build -- --bundles nsis
```

Building all targets can require additional Windows packaging tools such as WiX. A failure in optional MSI packaging does not invalidate a successfully produced NSIS installer, but release records must state which artifact was actually tested.

Do not distribute an older executable merely because it exists in `target/release`; confirm its modification time after the build.

For organization names, support details, About text, native product identity, and icons, follow [WHITE_LABELING.md](WHITE_LABELING.md) before the release build.

### Linux x86_64 release

Build on Ubuntu/Debian x86_64:

```bash
npm run tauri-build:linux
```

Expected outputs:

```text
src-tauri/target/release/dfir-investigator
src-tauri/target/release/bundle/deb/*.deb
src-tauri/target/release/bundle/appimage/*.AppImage
```

Smoke-test the package on a clean target similar to the field machines, not only on the build host.

### macOS release

Build a universal package for Intel and Apple Silicon:

```bash
npm run tauri-build:mac-universal
```

Architecture-specific builds:

```bash
npm run tauri-build:mac-intel
npm run tauri-build:mac-apple
```

Expected outputs:

```text
src-tauri/target/release/bundle/macos/*.app
src-tauri/target/release/bundle/dmg/*.dmg
```

Smoke-test on both an Intel Mac and an Apple Silicon Mac when distributing the universal package.

### GitHub Actions cross-platform builds

`.github/workflows/desktop-build.yml` builds the native packages on GitHub-hosted Windows, Ubuntu 22.04, and macOS runners. It runs for pushes and pull requests targeting `main`, version tags matching `v*`, and manual `workflow_dispatch` runs.

Every successful job stores its packages as downloadable workflow artifacts. Release publishing is intentionally separate, so this build workflow only needs read access to repository contents.

The macOS CI package is built as a universal Intel/Apple Silicon application. Without Apple Developer secrets it is not notarized for general distribution; configure the repository's Apple signing and notarization secrets before treating it as a public macOS release.

## 10. Troubleshooting

### `dlltool.exe`: program not found

The GNU Windows target is active. Windows builds use MSVC. Run:

```powershell
rustup toolchain install stable-x86_64-pc-windows-msvc
rustup default stable-x86_64-pc-windows-msvc
rustup show active-toolchain
rustc -vV
npm run tauri-dev
```

If the active host is still GNU, use `npm run tauri-build:windows` or `npm run tauri-build -- --bundles nsis`; both commands route the build through the MSVC toolchain wrapper.

### Linux build cannot find WebKitGTK or AppIndicator

Install the native desktop packages for the build distro. On Ubuntu/Debian this normally means `webkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, `pkg-config`, and `patchelf`. If the distro does not provide WebKitGTK 4.1 development headers, use its equivalent WebKitGTK package.

### macOS build fails for `x86_64-apple-darwin` or `aarch64-apple-darwin`

Install the missing Rust target:

```bash
rustup target add x86_64-apple-darwin aarch64-apple-darwin
```

Also confirm that Xcode Command Line Tools are installed with `xcode-select --install`.

### macOS app is blocked on another machine

Unsigned or unnotarized local builds can be blocked by Gatekeeper. For broad distribution, use the organization's Apple Developer signing and notarization process.

### `Blocking waiting for file lock on artifact directory`

Another Cargo/Tauri build is using `src-tauri/target`. Allow that build to finish or close the other development instance before starting another build. Do not delete the target directory while Cargo is running.

### OpenSSL build reports a Perl module or `Configure` error

Install full Strawberry Perl and start a new terminal. Git for Windows includes a limited Perl distribution that is not sufficient for the vendored OpenSSL build. Confirm:

```powershell
perl -MLocale::Maketext::Simple -e "print 'Perl OK'"
```

### Executable returns to the prompt and no window appears

1. Confirm that WebView2 Runtime is installed.
2. Rebuild or reinstall the current NSIS package.
3. Confirm that the executable timestamp matches the latest build.
4. Run `npm run tauri-dev` to see compilation/startup errors.
5. Check Windows endpoint controls or Event Viewer if the packaged executable is being blocked.

### Development port 5173 is already in use

Close the previous Vite/Tauri development process and rerun `npm run tauri-dev`. The configured development URL is fixed at `http://localhost:5173`.
