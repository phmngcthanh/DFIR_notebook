// Cargo wrapper for the case server, mirroring scripts/tauri-build.mjs.
//
// The server links the same vendored SQLCipher/OpenSSL as the desktop crate, so
// it needs the same Windows environment: the MSVC host of the pinned toolchain,
// and Strawberry Perl on PATH to configure OpenSSL. Building it through this
// wrapper keeps `npm run server-*` working on a machine whose default Rust host
// is GNU.
//
//   node scripts/server.mjs run -- --cases ./cases --insecure
//   node scripts/server.mjs build --release
//   node scripts/server.mjs test
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const serverDir = path.join(repoRoot, 'server');
const manifest = path.join(serverDir, 'Cargo.toml');
const [subcommand = 'build', ...rest] = process.argv.slice(2);
const env = { ...process.env };
const args = [subcommand, '--manifest-path', manifest];

if (process.platform === 'win32') {
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

  if (!rest.some((arg) => arg === '--target' || arg.startsWith('--target='))) {
    args.push('--target', 'x86_64-pc-windows-msvc');
  }
}

args.push(...rest);

// Cargo discovers .cargo/config.toml by walking up from its working directory,
// not from --manifest-path. Run inside server/ so its shared target-dir setting
// is honored instead of compiling SQLCipher/OpenSSL again in server/target.
const result = spawnSync('cargo', args, {
  cwd: serverDir,
  env,
  stdio: 'inherit',
  shell: process.platform === 'win32',
});
if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);
