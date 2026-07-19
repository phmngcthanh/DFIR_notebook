---
name: verify
description: Build, launch, and drive the DFIR Network Investigator desktop app on Windows to verify changes at the real GUI surface.
---

# Verifying changes in the running desktop app (Windows)

## Launch with CDP debugging

```powershell
$env:RUSTUP_TOOLCHAIN='1.97.1-x86_64-pc-windows-msvc'   # match rust-toolchain.toml channel + MSVC host
if (Test-Path 'C:\Strawberry\perl\bin\perl.exe') { $env:PATH = 'C:\Strawberry\perl\bin;' + $env:PATH }
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS='--remote-debugging-port=9333'
npm run tauri-dev
```

- Plain `npm run tauri-dev` under the default GNU host fails with `dlltool.exe: program not found` — always set `RUSTUP_TOOLCHAIN` to the MSVC triple (same trick as `scripts/tauri-build.mjs`).
- Wait for `http://127.0.0.1:9333/json` to answer; the page target is the Vite URL (port 5173).
- If the app window opens but no `msedgewebview2.exe` children spawn and CDP never comes up, the WebView2 runtime may be auto-updating; kill the app and relaunch a minute later.

## Drive it over CDP

Node 22+ has a global `WebSocket` — a ~40-line script connecting to the CDP target covers everything:

- `Runtime.evaluate` (with `awaitPromise`, `returnByValue`) to click buttons and fill React inputs. React-controlled inputs need the native setter trick: `Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el, v); el.dispatchEvent(new Event('input',{bubbles:true}))`.
- `Page.captureScreenshot` returns blank unless you call `Page.bringToFront` first and wait ~500 ms. Note bringToFront also dismisses open Radix popovers — query the DOM instead of screenshotting when a dropdown must stay open.
- Radix UI selects/popovers ignore synthetic `dispatchEvent` clicks; use trusted input via `Input.dispatchMouseEvent` (mousePressed + mouseReleased) at coordinates from `getBoundingClientRect`.

## Native file dialogs

`create_new_case` / open / export commands block on a native Save/Open dialog that CDP cannot reach. Answer it with SendKeys ~3 s after triggering:

```powershell
Add-Type -AssemblyName Microsoft.VisualBasic; Add-Type -AssemblyName System.Windows.Forms
[Microsoft.VisualBasic.Interaction]::AppActivate((Get-Process dfir-investigator).Id)
[System.Windows.Forms.SendKeys]::SendWait('C:\full\path\case.db'); Start-Sleep -m 500
[System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
```

## Useful flows

- New case: welcome → New Case → labels `Case name *`, `Session expert name *`, `Database file password *`, `Confirm password *` → Create Case → native dialog.
- Switch expert (new session id): click the expert button in the sidebar → `#expert-name` → "Start session".
- Every entity edit lands in `list_case_history`; the Activity Board tab visualizes it per expert/session.
- Clean up: kill `dfir-investigator`, delete the throwaway `.db`.
