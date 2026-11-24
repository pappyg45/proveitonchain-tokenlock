// 0.4.5 RC5 deep review (item a): pages-router getServerSideProps pages are also served as JSON at
// /_next/data/<buildId>/<path>.json (and /<basePath>/_next/data/..., /_next/data/<id>/<locale>/...). Real Next.js apps (next
// build + next start): those URLs must be gated like the page, with and without the x-nextjs-data header. Passed on first
// run (Next hands middleware the normalized URL); kept as a regression test. TL_CI=1: a missing dependency fails.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, symlinkSync, readFileSync, mkdtempSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path'; import os from 'node:os'; import net from 'node:net';
const ROOT = path.resolve(process.env.TL_PKG_ROOT || new URL('../', import.meta.url).pathname); const HERE = new URL('../', import.meta.url).pathname;
const req = createRequire(HERE + 'package.json'); const dep = (m) => { try { return path.dirname(req.resolve(m + '/package.json')); } catch { return null; } };
const deps = { next: dep('next'), react: dep('react'), 'react-dom': dep('react-dom') };
const missing = Object.entries(deps).filter(([, v]) => !v).map(([k]) => k);
if (missing.length && process.env.TL_CI === '1') throw new Error('next-data-routes: missing ' + missing.join(', ') + '; TL_CI=1 refuses to skip');
const tmp = mkdtempSync(path.join(os.tmpdir(), 'tl-next-data-'));
const freePort = () => new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const nap = (ms) => new Promise((r) => setTimeout(r, ms));
async function run(name, config, urls) {
  const d = path.join(tmp, name); mkdirSync(path.join(d, 'pages/members'), { recursive: true }); mkdirSync(path.join(d, 'node_modules/@tokenlock'), { recursive: true });
  for (const [m, p] of Object.entries(deps)) symlinkSync(p, path.join(d, 'node_modules', m));
  symlinkSync(ROOT, path.join(d, 'node_modules/@tokenlock/sdk'));
  writeFileSync(path.join(d, 'package.json'), '{"name":"x","private":true}');
  writeFileSync(path.join(d, 'next.config.js'), `module.exports = ${JSON.stringify(config)};`);
  writeFileSync(path.join(d, 'middleware.js'), "import { tokenlock } from '@tokenlock/sdk/next';\nexport default tokenlock({ protect: ['/members', '/members/:path*'], signInPage: '/signin', secretKey: 'sk_' + 'x'.repeat(30) });\nexport const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };\n");
  const ssp = (f, secret) => writeFileSync(path.join(d, 'pages', f), `export async function getServerSideProps() { return { props: { s: ${JSON.stringify(secret)} } }; }\nexport default function P({ s }) { return s; }\n`);
  ssp('index.js', 'home'); ssp('signin.js', 'signin'); ssp('members/index.js', 'MEMBERS-SECRET'); ssp('members/x.js', 'MEMBERS-SECRET-X');
  const b = spawnSync(process.execPath, [path.join(deps.next, 'dist/bin/next'), 'build'], { cwd: d, encoding: 'utf8', env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1' } });
  assert.equal(b.status, 0, 'next build failed:\n' + (b.stdout + b.stderr).slice(-3000));
  const id = readFileSync(path.join(d, '.next/BUILD_ID'), 'utf8').trim();
  const port = await freePort();
  const p = spawn(process.execPath, [path.join(deps.next, 'dist/bin/next'), 'start', '-p', String(port), '-H', '127.0.0.1'], { cwd: d, env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1' }, stdio: 'ignore' });
  for (let i = 0; i < 120; i++) { try { await fetch(`http://127.0.0.1:${port}/`); break; } catch { await nap(250); } }
  try {
    for (const [u0, open] of urls) for (const headers of [{ 'x-nextjs-data': '1' }, {}]) {
      const u = u0.replace('ID', id);
      const r = await fetch(`http://127.0.0.1:${port}${u}`, { redirect: 'manual', headers }); const t = await r.text();
      if (open) { assert.equal(r.status, 200, `${u} ${JSON.stringify(headers)}: open data route ${r.status}`); continue; }
      assert.ok(!/MEMBERS-SECRET/.test(t), `${u} ${JSON.stringify(headers)}: protected props served (status ${r.status})`);
      assert.ok([307, 308, 401, 403].includes(r.status), `${u} ${JSON.stringify(headers)}: status ${r.status}`);
    }
  } finally { p.kill('SIGTERM'); }
}
const APPS = [
  ['plain', {}, [['/members/x'], ['/_next/data/ID/members/x.json'], ['/_next/data/ID/members.json'], ['/_next/data/ID/MEMBERS/x.json'], ['/_next/data/ID/index.json', true]]],
  ['i18n', { i18n: { locales: ['en', 'fr'], defaultLocale: 'en' } }, [['/fr/members/x'], ['/_next/data/ID/fr/members/x.json'], ['/_next/data/ID/en/members.json'], ['/_next/data/ID/FR/members.json'], ['/_next/data/ID/fr/signin.json', true]]],
  ['basepath', { basePath: '/docs' }, [['/docs/members/x'], ['/docs/_next/data/ID/members/x.json'], ['/docs/_next/data/ID/members.json'], ['/docs/_next/data/ID/index.json', true]]],
];
for (const [name, config, urls] of APPS) test(`real Next app (${name}): getServerSideProps data routes /_next/data/<buildId>/... are gated like the page`, { skip: missing.length ? 'missing ' + missing.join(', ') : false, timeout: 400000 }, () => run(name, config, urls));
