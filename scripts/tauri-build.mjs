import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const env = { ...process.env };

if (process.platform === 'win32') {
  // Use the channel pinned in rust-toolchain.toml, but with the MSVC host
  // (the toolchain file alone would resolve to the machine's default host).
  const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  let channel = 'stable';
  try {
    channel = readFileSync(path.join(repoRoot, 'rust-toolchain.toml'), 'utf8')
      .match(/channel\s*=\s*"([^"]+)"/)?.[1] ?? 'stable';
  } catch {}
  env.RUSTUP_TOOLCHAIN ||= `${channel}-x86_64-pc-windows-msvc`;

  const strawberryPerl = 'C:\\Strawberry\\perl\\bin';
  if (existsSync(path.join(strawberryPerl, 'perl.exe'))) {
    const pathKey = Object.keys(env).find((key) => key.toLowerCase() === 'path') ?? 'PATH';
    env[pathKey] = `${strawberryPerl};${env[pathKey] ?? ''}`;
  }

  const hasExplicitTarget = args.some((arg) => arg === '--target' || arg.startsWith('--target='));
  if (!hasExplicitTarget) {
    args.unshift('x86_64-pc-windows-msvc');
    args.unshift('--target');
  }
}

// Invoke the project-local CLI through Node instead of relying on a global
// `tauri` command or platform-specific node_modules/.bin shims.
const require = createRequire(import.meta.url);
const tauriCli = require.resolve('@tauri-apps/cli/tauri.js');
const result = spawnSync(process.execPath, [tauriCli, 'build', ...args], {
  env,
  stdio: 'inherit',
});

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}

process.exit(result.status ?? 1);
