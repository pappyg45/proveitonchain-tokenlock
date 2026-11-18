// App-level integration tests (path rules v1.1). Real apps, real routing, raw request paths (no client-side URL
// normalization): Express 4 and Express 5 routers, a Next.js app (app router + middleware, `next build` + `next start`),
// the PHP built-in server with a simple front-controller router, and the Cloudflare worker example running in Miniflare
// (workerd). Every alternate form of a protected URL must either be rejected with 400 or be decided on the SAME route
// the app actually serves; nothing protected is ever served without a pass the API allowed for that route.
//
// Run: cd test/integration && npm install && npm test        (Next build takes ~1 min; SKIP_NEXT=1 to skip it)
// What this does NOT show: the security of the hosted verification service or isolation between tenants. These are
// client-side adapter tests against a local mock of the API.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, symlinkSync, existsSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SDK = process.env.TOKENLOCK_SDK_DIR ? path.resolve(process.env.TOKENLOCK_SDK_DIR) : path.resolve(HERE, '../..');
// The PHP drop-in: php/ in this repo, else a sibling tokenlock-php checkout.
const PHP_FILE = process.env.TOKENLOCK_PHP_FILE || [path.join(SDK, 'php/tokenlock/tokenlock.php'), path.resolve(SDK, '../tokenlock-php/tokenlock/tokenlock.php')].find((f) => existsSync(f)) || 'missing';
const core = await import(path.join(SDK, 'dist/index.js'));
const ex = await import(path.join(SDK, 'dist/express.js'));
const SK = 'sk_' + 'i'.repeat(43);
const MEMBER = 'pp1.' + 'M'.repeat(40) + '.' + 'Q'.repeat(43); // a key allowed GET /members/* only
const OTHER = 'pp1.' + 'O'.repeat(40) + '.' + 'Q'.repeat(43);  // a key allowed GET /public/* only

// ---- mock of the hosted verify API (registered keys; case-insensitive routes; v1.1 path rules; echoes the resource)
let calls = [];
const mock = http.createServer((req, res) => {
  let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => {
    const j = b ? JSON.parse(b) : {};
    calls.push(j);
    const send = (o) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (req.headers.authorization !== 'Bearer ' + SK) return send({ valid: false, code: 'bad_key' });
    const routes = j.pass === MEMBER ? ['/members'] : j.pass === OTHER ? ['/public'] : null;
    if (!routes) return send({ valid: false, code: 'bad_pass', reason: 'Not a valid pass.' });
    const resource = { path: j.path ?? null, method: j.method ?? null, environment: j.environment ?? null };
    const base = { address: 'bc1qholder', site_id: 'site1', expires_at: new Date(Date.now() + 3600e3).toISOString(), cache_max_s: 5, resource };
    const access = (allowed, reason) => ({ mode: 'registered_keys', allowed, reason, resource });
    if (j.path != null && core.canonicalPath(j.path) === null) return send({ valid: false, allowed: false, code: 'bad_path', reason: 'Not a valid path.', ...base, access: access(false, 'bad_path') });
    const p = String(j.path || '').toLowerCase();
    if (j.path != null && !routes.some((r) => p === r || p.startsWith(r + '/'))) return send({ valid: false, allowed: false, code: 'route_not_allowed', reason: 'route_not_allowed', ...base, access: access(false, 'route_not_allowed') });
    if (j.method && j.method !== 'GET' && j.method !== 'HEAD') return send({ valid: false, allowed: false, code: 'method_not_allowed', reason: 'method_not_allowed', ...base, access: access(false, 'method_not_allowed') });
    send({ valid: true, allowed: true, ...base, access: access(true, 'ok') });
  });
});
await new Promise((r) => mock.listen(0, '127.0.0.1', r));
const API = 'http://127.0.0.1:' + mock.address().port;
const procs = []; const servers = [mock]; const dirs = [];
after(async () => { for (const p of procs) p.kill('SIGTERM'); for (const s of servers) s.close(); for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const raw = (port, p, headers = {}, method = 'GET') => new Promise((ok, no) => {
  const q = http.request({ host: '127.0.0.1', port, path: p, method, headers }, (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => ok({ status: res.statusCode, headers: res.headers, body: d })); });
  q.on('error', no); q.setTimeout(20000, () => q.destroy(new Error('timeout ' + p))); q.end();
});
const waitUp = async (port, p = '/', tries = 300) => { for (let i = 0; i < tries; i++) { try { await raw(port, p); return; } catch { await new Promise((r) => setTimeout(r, 200)); } } throw new Error('server did not start on ' + port); };
const freePort = () => new Promise((ok) => { const s = http.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => ok(p)); }); });

// ---- the forms. Every one is sent byte-for-byte as written.
const FORMS = [
  '/admin', '/ADMIN', '/Admin/x', '/admin/', '//admin', '///admin/x', '/%61dmin', '/%41DMIN/x', '/admin;x', '/admin;x/y', '/admin/x;y',
  '/./admin', '/x/../admin', '/admin/..', '/admin/.', '/admin/x/..', '/admin/x/../..', '/members/../admin', '/members/..%2fadmin',
  '/members/%2e%2e/admin', '/members/.%2e/admin', '/members/%2E%2E/admin', '/members%2f..%2fadmin', '/admin%2fx', '/admin%2Fx', '/admin%5cx',
  '/admin\\x', '/members\\..\\admin', '/%2561dmin', '/members/..;/admin', '/admin/..;/', '/admin%00', '/admin%00/x', '/admin/%2e', '/admin/%2e%2e',
  '/ADMIN%2F', '/admin?x=1', '/admin#x', '/admin%3bx', '/admin%09', '/admin%20', '/admin%20/x', '/admin.', '/admin..', '/admin...', '/admin/~',
  '/admin%2e', '/admin/x/', '/admin//x', '/members/x', '/MEMBERS/X', '/Members/', '/members/x/../../admin', '/members/./x', '/public/../admin',
  '/public/..%5cadmin', '/public/%2e%2e/admin', '/public/x', '/PUBLIC/x', '/public/..', '/%2e/admin', '/%2e%2e/admin', '/../admin', '/admin/%252e%252e',
  '/admin%u002f', '/admin%c0%af', '/admin%e2%80%a8', '/members/x?next=//evil.com', '/', '/nothing', '/members/%2e', '/members/;/x',
];
const family = (p) => (String(p || '').toLowerCase().split('/').filter(Boolean)[0] || 'home');
const PROTECTED = ['admin', 'members'];
// Ask one app for one form with one credential; check the invariant; return a short label for the summary.
async function check(app, port, form, pass) {
  calls = [];
  const r = await raw(port, form, { accept: 'application/json', ...(pass ? { cookie: 'tokenlock_pass=' + pass } : {}) });
  const m = r.body.match(/ROUTE:(\w+)/);
  const where = `${app} ${JSON.stringify(form)} pass=${pass === MEMBER ? 'member' : pass === OTHER ? 'other' : 'none'} → ${r.status} ${m ? m[0] : r.body.slice(0, 80)}`;
  if (r.status === 400) return 'rejected';
  if (!m || r.status >= 300) {
    // the guard answered (sign-in, 401/403, or the platform refused the URL): nothing from the app was served
    assert.ok([301, 302, 303, 307, 308, 400, 401, 403, 404, 503].includes(r.status), where);
    assert.ok(!/ROUTE:(admin|members)/.test(r.body), where);
    return 'guarded ' + r.status;
  }
  const served = m[1];
  if (PROTECTED.includes(served)) {
    assert.notEqual(served, 'admin', 'nobody may reach /admin: ' + where);
    assert.equal(pass, MEMBER, 'members content needs the member pass: ' + where);
    // the decision was made by the API for the same route the app served
    assert.ok(calls.length >= 1, 'served protected content without asking the API: ' + where);
    assert.equal(family(calls.at(-1).path), served, `guard asked about ${calls.at(-1).path} but the app served ${served}: ` + where);
    assert.equal(calls.at(-1).path, calls.at(-1).path.toLowerCase(), 'resource is lowercased: ' + where);
  } else if (calls.length) {
    // unprotected route served; if the guard asked, it must have asked about that route family too
    assert.ok(!PROTECTED.includes(family(calls.at(-1).path)) || false, `guard decided on ${calls.at(-1).path} but app served ${served}: ` + where);
  }
  return 'served ' + served;
}
async function matrix(app, port, { normalizes = false, caseSensitiveRoutes = false } = {}) {
  const out = {};
  for (const form of FORMS) for (const pass of [null, MEMBER, OTHER]) out[`${form} ${pass === MEMBER ? 'M' : pass === OTHER ? 'O' : '-'}`] = await check(app, port, form, pass);
  // positives: the real routes work
  assert.match(out['/members/x M'], /served members/, app + ' members');
  // the guard is case-insensitive everywhere; Next's own routes are case-sensitive, so /MEMBERS/X is its 404 there
  assert.match(out['/MEMBERS/X M'], caseSensitiveRoutes ? /served members|guarded 404/ : /served members/, app + ' members (case)');
  assert.match(out['/MEMBERS/X -'], /guarded 401/, app + ' members (case) without a pass');
  assert.match(out['/public/x -'], /served public/, app + ' public');
  assert.match(out['/admin M'], /guarded 403/, app + ' /admin with member pass');
  assert.match(out['/admin -'], /guarded 401/, app + ' /admin no pass');
  // '/admin/..': 400 (v1.1). Platforms that hand the app a WHATWG-normalized URL (workerd, Next) resolve it to '/'
  // before either the guard or the app sees it, so both decide on '/' (the origin gets '/' too).
  // (Next's own server answers 404 for it before routing.)
  if (normalizes) assert.ok(['rejected', 'served home', 'guarded 404'].includes(out['/admin/.. M']), app + ' /admin/..: ' + out['/admin/.. M']);
  else assert.equal(out['/admin/.. M'], 'rejected', app + ' /admin/.. must be 400 (v1.1)');
  return out;
}
const counts = {};
const tally = (app, out) => { counts[app] = { forms: FORMS.length, requests: Object.keys(out).length, rejected: Object.values(out).filter((v) => v === 'rejected').length }; };

// ---- origin app used by the Cloudflare worker (and as a plain Node router)
const originRoute = (p) => { p = decodeURIComponent(p).toLowerCase(); return /^\/admin(\/|$)/.test(p) ? 'admin' : /^\/members(\/|$)/.test(p) ? 'members' : /^\/public(\/|$)/.test(p) ? 'public' : p === '/' ? 'home' : 'none'; };

test('Express 4: real app routing (app.use(tokenlock) + app.get routes)', async () => {
  const express = (await import('express')).default;
  const app = express();
  app.use(ex.tokenlock({ protect: ['/admin/:path*', '/members/:path*'], signInPage: '/signin', secretKey: SK, apiBase: API, environment: 'production' }));
  app.get(['/admin', '/admin/*'], (q, s) => s.send('ROUTE:admin'));
  app.get(['/members', '/members/*'], (q, s) => s.send('ROUTE:members'));
  app.get('/public/*', (q, s) => s.send('ROUTE:public'));
  app.get('/', (q, s) => s.send('ROUTE:home'));
  app.use((q, s) => s.status(404).send('ROUTE:none'));
  const srv = app.listen(0, '127.0.0.1'); servers.push(srv); await new Promise((r) => srv.once('listening', r));
  tally('express4', await matrix('express4', srv.address().port));
});

test('Express 5: real app routing (path-to-regexp v8 wildcards)', async () => {
  const express = (await import('express5')).default;
  const app = express();
  app.use(ex.tokenlock({ protect: ['/admin/:path*', '/members/:path*'], signInPage: '/signin', secretKey: SK, apiBase: API, environment: 'production' }));
  app.get(['/admin', '/admin/*rest'], (q, s) => s.send('ROUTE:admin'));
  app.get(['/members', '/members/*rest'], (q, s) => s.send('ROUTE:members'));
  app.get('/public/*rest', (q, s) => s.send('ROUTE:public'));
  app.get('/', (q, s) => s.send('ROUTE:home'));
  app.use((q, s) => s.status(404).send('ROUTE:none'));
  const srv = app.listen(0, '127.0.0.1'); servers.push(srv); await new Promise((r) => srv.once('listening', r));
  tally('express5', await matrix('express5', srv.address().port));
});

test('PHP built-in server + simple front-controller router', { skip: (() => { try { execFileSync('php', ['-v']); return !existsSync(PHP_FILE) && 'PHP drop-in not found'; } catch { return 'php not installed'; } })() }, async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'tl-int-php-')); dirs.push(dir);
  const port = await freePort();
  const p = spawn('php', ['-S', '127.0.0.1:' + port, path.join(HERE, 'apps/php/router.php')], { cwd: dir, stdio: 'ignore',
    env: { ...process.env, TOKENLOCK_PHP_FILE: PHP_FILE, TOKENLOCK_API: API, TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_SITE_KEY: 'pk_x', TOKENLOCK_ENVIRONMENT: 'production', TOKENLOCK_CACHE_DIR: dir } });
  procs.push(p); await waitUp(port);
  tally('php', await matrix('php', port));
});

test('Cloudflare worker example in Miniflare (workerd) in front of an origin', async () => {
  const { Miniflare } = await import('miniflare');
  const mf = new Miniflare({
    modules: true, script: readFileSync(path.join(SDK, 'examples/cloudflare-worker/worker.js'), 'utf8'), compatibilityDate: '2025-01-01',
    bindings: { TOKENLOCK_API: API, TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_SITE_KEY: 'pk_x', TOKENLOCK_ENVIRONMENT: 'production', TOKENLOCK_PROTECT: '/admin,/members' },
    // Outbound fetches: the verify API goes to the mock; everything else is the origin (routes on the URL it is given).
    outboundService: async (req) => {
      const u = new URL(req.url);
      if (u.origin === API) { const r = await fetch(req.url, { method: req.method, headers: Object.fromEntries(req.headers), body: await req.text() }); return new Response(await r.text(), { status: r.status, headers: { 'content-type': 'application/json' } }); }
      const route = originRoute(u.pathname);
      return new Response('ROUTE:' + route, { status: route === 'none' ? 404 : 200 });
    },
  });
  try { const u = await mf.ready; tally('cloudflare', await matrix('cloudflare', Number(u.port), { normalizes: true })); } finally { await mf.dispose(); }
});

test('Next.js 15 app (app router + middleware): next build && next start', { skip: process.env.SKIP_NEXT ? 'SKIP_NEXT set' : false, timeout: 600000 }, async () => {
  const src = path.join(HERE, 'apps/next');
  const nm = path.join(src, 'node_modules');
  mkdirSync(path.join(nm, '@proveitonchain'), { recursive: true });
  const link = (to, from) => { if (!existsSync(from)) symlinkSync(to, from, 'dir'); };
  link(SDK, path.join(nm, '@proveitonchain/tokenlock'));
  for (const m of ['next', 'react', 'react-dom']) link(path.join(SDK, 'node_modules', m), path.join(nm, m));
  const env = { ...process.env, NEXT_TELEMETRY_DISABLED: '1', TOKENLOCK_API: API, TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_SITE_KEY: 'pk_x' };
  const nextBin = path.join(SDK, 'node_modules/next/dist/bin/next');
  execFileSync(process.execPath, [nextBin, 'build'], { cwd: src, env, stdio: process.env.VERBOSE ? 'inherit' : 'pipe', timeout: 480000 });
  const port = await freePort();
  const p = spawn(process.execPath, [nextBin, 'start', '-p', String(port), '-H', '127.0.0.1'], { cwd: src, env, stdio: 'ignore' }); procs.push(p);
  await waitUp(port, '/public/x');
  tally('next', await matrix('next', port, { normalizes: true, caseSensitiveRoutes: true }));
});

test('summary', () => { console.log('integration matrix:', JSON.stringify(counts)); });
