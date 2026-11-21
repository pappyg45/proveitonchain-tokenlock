// 0.4.5 RC5 (RC3 review: "Next.js basePath and i18n gating (src/next.ts:31-35) still untested"). Builds REAL
// Next.js apps (pages router, `next build` + `next start`) with the package under test as middleware and requests them over
// HTTP. Next routes /fr/members (i18n locale prefix) and /docs/members (basePath) to pages/members, and its own matcher
// patterns are written without basePath / locale, so `protect: ['/members/:path*']` must lock them too. Failing first on
// RC4: the middleware matched the raw path and served the protected page. Needs next, react, react-dom (devDependencies).
// TL_PKG_ROOT = package root under test (dist/ is used). TL_CI=1: a missing dependency fails instead of skipping.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, symlinkSync, rmSync, existsSync, mkdtempSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path'; import os from 'node:os'; import net from 'node:net';
const ROOT = path.resolve(process.env.TL_PKG_ROOT || new URL('../', import.meta.url).pathname);
const HERE = new URL('../', import.meta.url).pathname; const req = createRequire(HERE + 'package.json');
const dep = (m) => { try { return path.dirname(req.resolve(m + '/package.json')); } catch { return null; } };
const deps = { next: dep('next'), react: dep('react'), 'react-dom': dep('react-dom') };
const missing = Object.entries(deps).filter(([, v]) => !v).map(([k]) => k);
if (missing.length && process.env.TL_CI === '1') throw new Error('next-real-app: missing ' + missing.join(', ') + ' (npm install the devDependencies); TL_CI=1 refuses to skip');
const freePort = () => new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const nap = (ms) => new Promise((r) => setTimeout(r, ms));
const tmp = mkdtempSync(path.join(os.tmpdir(), 'tl-next-real-'));
function scaffold(name, config) {
  const d = path.join(tmp, name); mkdirSync(path.join(d, 'pages/members'), { recursive: true }); mkdirSync(path.join(d, 'node_modules/@proveitonchain'), { recursive: true });
  for (const [m, p] of Object.entries(deps)) symlinkSync(p, path.join(d, 'node_modules', m));
  symlinkSync(ROOT, path.join(d, 'node_modules/@proveitonchain/tokenlock'));
  writeFileSync(path.join(d, 'package.json'), '{"name":"tl-next-real","private":true}');
  writeFileSync(path.join(d, 'next.config.js'), `module.exports = ${JSON.stringify(config)};`);
  writeFileSync(path.join(d, 'middleware.js'), "import { tokenlock } from '@proveitonchain/tokenlock/next';\nexport default tokenlock({ protect: ['/members', '/members/:path*'], publicPaths: ['/members/open'], signInPage: '/signin', secretKey: 'sk_' + 'x'.repeat(30) });\nexport const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };\n");
  const page = (f, body) => writeFileSync(path.join(d, 'pages', f), `export default function P() { return ${JSON.stringify(body)}; }\n`);
  page('index.js', 'home'); page('signin.js', 'signin page'); page('members/index.js', 'MEMBERS-SECRET'); page('members/x.js', 'MEMBERS-SECRET-X'); page('members/open.js', 'members open page');
  const b = spawnSync(process.execPath, [path.join(deps.next, 'dist/bin/next'), 'build'], { cwd: d, encoding: 'utf8', env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1' }, timeout: 300000 });
  assert.equal(b.status, 0, 'next build failed:\n' + (b.stdout + b.stderr).slice(-3000));
  return d;
}
async function serve(d) {
  const port = await freePort();
  const p = spawn(process.execPath, [path.join(deps.next, 'dist/bin/next'), 'start', '-p', String(port), '-H', '127.0.0.1'], { cwd: d, env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1' }, stdio: 'ignore' });
  for (let i = 0; i < 120; i++) { try { await fetch(`http://127.0.0.1:${port}/`, { redirect: 'manual' }); break; } catch { await nap(250); } }
  return { port, stop: () => p.kill('SIGTERM') };
}
const get1 = async (port, u) => { const r = await fetch(`http://127.0.0.1:${port}${u}`, { redirect: 'manual' }); const body = await r.text(); return { status: r.status, location: r.headers.get('location'), body }; };
// Next's own normalization redirects (308 trailing slash) are followed; a redirect to the sign-in page is not.
const get = async (port, u) => { let r = await get1(port, u); for (let i = 0; i < 3 && r.status === 308 && r.location && !/\/signin(\?|$)/.test(new URL(r.location, 'http://x').pathname + '?'); i++) r = await get1(port, new URL(r.location, 'http://x').pathname + new URL(r.location, 'http://x').search); return r; };
// A protected URL must not serve the page: a redirect to the sign-in page (under the basePath) or a 401/403 JSON answer.
function assertGated(r, u, base) {
  assert.ok(!r.body.includes('MEMBERS-SECRET'), `${u}: protected page served (status ${r.status})`);
  assert.ok([307, 308, 401, 403].includes(r.status), `${u}: status ${r.status}`);
  if (r.status === 307 || r.status === 308) assert.equal(new URL(r.location, 'http://x').pathname.replace(/\/(en|fr)(?=\/)/i, ''), base + '/signin', `${u}: redirect ${r.location}`);
}
const APPS = [
  { name: 'i18n', config: { i18n: { locales: ['en', 'fr'], defaultLocale: 'en' } }, base: '',
    gated: ['/members', '/members/x', '/fr/members', '/fr/members/x', '/FR/members', '/fr/MEMBERS/x', '/fr/members/'], open: ['/', '/fr', '/fr/signin', '/signin', '/fr/members/open'] },
  { name: 'basepath', config: { basePath: '/docs' }, base: '/docs',
    gated: ['/docs/members', '/docs/members/x', '/docs/MEMBERS/x'], open: ['/docs', '/docs/signin', '/docs/members/open'] },
  { name: 'basepath-i18n', config: { basePath: '/docs', i18n: { locales: ['en', 'fr'], defaultLocale: 'en' } }, base: '/docs',
    gated: ['/docs/members', '/docs/fr/members', '/docs/fr/members/x', '/docs/FR/members'], open: ['/docs', '/docs/fr', '/docs/fr/signin', '/docs/fr/members/open'] },
];
for (const app of APPS) {
  test(`real Next app (${app.name}): protect ['/members/:path*'] locks every route Next serves from pages/members`, { skip: missing.length ? 'missing ' + missing.join(', ') : false, timeout: 400000 }, async () => {
    const d = scaffold(app.name, app.config); const s = await serve(d);
    try {
      for (const u of app.gated) assertGated(await get(s.port, u), u, app.base);
      for (const u of app.open) { const r = await get(s.port, u); assert.equal(r.status, 200, `${u}: control should be served (status ${r.status} ${r.location || ''})`); assert.ok(!r.body.includes('MEMBERS-SECRET'), u); }
    } finally { s.stop(); }
  });
}
test.after(() => rmSync(tmp, { recursive: true, force: true }));
