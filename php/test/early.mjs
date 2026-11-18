// Early block (tokenlock/early.php) over real HTTP: php -S with auto_prepend_file, a mock TOKENLOCK API, a test app.
import http from 'node:http';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { writeFileSync, rmSync, mkdirSync, mkdtempSync, symlinkSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PHP = process.env.PHP || 'php';
const SK = 'sk_' + 'a'.repeat(43), PK = 'pk_' + 'b'.repeat(43);
const GOOD = 'pp1.' + 'Z'.repeat(40) + '.' + 'Q'.repeat(43);
const DOWN = 'pp1.' + 'D'.repeat(40) + '.' + 'Q'.repeat(43);
const future = () => new Date(Date.now() + 3600e3).toISOString();
let pass = 0, fail = 0;
async function step(name, fn) { try { await fn(); pass++; console.log('  ✔', name); } catch (e) { fail++; console.log('  ✖', name, '-', e.message); } }

const mock = http.createServer((req, res) => {
  const chunks = []; req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const j = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
    const send = (o, s = 200) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (!req.url.endsWith('/api/v1/gate/verify')) return send({ error: 'no' }, 404);
    if (req.headers.authorization !== 'Bearer ' + SK) return send({ valid: false, code: 'bad_secret_key' }, 401);
    if (j.pass === DOWN) return send({ error: 'busy', code: 'kv_unavailable' }, 503);
    const echo = { allowed: true, resource: { path: j.path ?? null, method: j.method ?? null, environment: j.environment ?? null } };
    if (j.pass === GOOD) return send({ valid: true, address: 'bc1qtest', assets_held: ['TOKENLOCK'], site_id: 's1', origin: 'http://localhost', expires_at: future(), ...echo });
    return send({ valid: false, code: 'bad_pass', reason: 'Not a valid pass.' });
  });
});
await new Promise((r) => mock.listen(0, '127.0.0.1', r));
const API = `http://127.0.0.1:${mock.address().port}`;

// A throwaway web root that looks like a real site: index.php front controller, a WordPress-style login file,
// and the real tokenlock/ folder. The "app" says APP BOOTED only if the early block let the request through.
const DOC = mkdtempSync(path.join(os.tmpdir(), 'tokenlock-early-'));
const APP = `<?php if (getenv('EARLY_MODE') === 'include') { require ${JSON.stringify(path.join(root, 'test/fixtures/early-prepend.php'))}; }
header('Content-Type: text/plain'); echo 'APP BOOTED ' . parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) . ' early=' . (defined('TOKENLOCK_EARLY_RAN') ? 'ran' : 'no');\n`;
writeFileSync(path.join(DOC, 'index.php'), APP);
writeFileSync(path.join(DOC, 'wp-login.php'), APP);
mkdirSync(path.join(DOC, 'wp-admin')); writeFileSync(path.join(DOC, 'wp-admin', 'options.php'), APP);
symlinkSync(path.join(root, 'tokenlock'), path.join(DOC, 'tokenlock'));
const servers = [];
async function server(early, env = {}) {
  const port = 19000 + Math.floor(Math.random() * 900) + servers.length;
  const prepend = env.EARLY_MODE === 'include' ? [] : ['-d', 'auto_prepend_file=' + path.join(root, 'test/fixtures/early-prepend.php')];
  const p = spawn(PHP, ['-d', 'display_errors=0', '-d', 'log_errors=0', ...prepend, '-S', `127.0.0.1:${port}`, '-t', DOC], {
    cwd: root, stdio: 'ignore',
    env: { ...process.env, TOKENLOCK_API: API, TOKENLOCK_SITE_KEY: PK, TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_CACHE_DIR: path.join(root, 'tokenlock', 'cache'), TOKENLOCK_TEST_EARLY: JSON.stringify(early), TOKENLOCK_TEST_API_PATHS: '/api', ...env },
  });
  servers.push(p);
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 60; i++) { try { await fetch(base + '/tokenlock/signin.php'); return base; } catch { await new Promise((r) => setTimeout(r, 50)); } }
  throw new Error('php -S did not start');
}
const get = (base, p, headers = {}) => fetch(base + p, { redirect: 'manual', headers });
// Byte-for-byte request path (fetch would resolve dot segments first).
const rawGet = (base, p, headers = {}) => new Promise((ok, no) => { const u = new URL(base); http.get({ host: u.hostname, port: u.port, path: p, headers }, (res) => { let b = ''; res.setEncoding('utf8'); res.on('data', (c) => { b += c; }); res.on('end', () => ok({ status: res.statusCode, headers: res.headers, body: b })); }).on('error', no); });
const ck = (v) => ({ cookie: 'tokenlock_pass=' + v });
const OFF = path.join(root, 'tokenlock', 'early.off');

const EARLY = { protect: ['/members/*', '/api/*'], public: ['/members/join'], exclude_paths: ['/wp-admin/*', '/wp-login.php'], admin_ips: ['203.0.113.0/24', '2001:db8::/32'], deny_ips: ['198.51.100.0/24'], trusted_proxies: ['127.0.0.1'] };
try {
  const A = await server(EARLY);
  console.log('early block (auto_prepend_file)');
  await step('unprotected page: app boots, no pass needed', async () => { const r = await get(A, '/about'); assert.equal(r.status, 200); assert.match(await r.text(), /APP BOOTED \/about early=ran/); });
  await step('protected, no pass: 302 to sign-in, app never boots', async () => {
    const r = await get(A, '/members/area?x=1'); assert.equal(r.status, 302);
    assert.equal(r.headers.get('location'), '/tokenlock/signin.php?next=' + encodeURIComponent('/members/area?x=1')); assert.doesNotMatch(await r.text(), /APP BOOTED/);
  });
  await step('protected, alternate spellings (/MEMBERS, //members, /x/../members) are still protected', async () => {
    for (const p of ['/MEMBERS/area', '//members/area', '/x/../members/area']) { const r = await get(A, p); assert.equal(r.status, 302, p); }
    // path rules v1.1: ';params' and dot segments are rejected outright
    for (const p of ['/members;a=b/area', '/members/area/..', '/members/%2e%2e/x', '/members/./area', '/members/..', '/x/%2e%2e/members/area', '/MEMBERS%2farea', '/members\\area', '/api;x/data']) { const r = await rawGet(A, p); assert.equal(r.status, 400, p); }
  });
  await step('malformed paths outside protect are left to the app (no 400 from the early block)', async () => {
    for (const p of ['/about;x=1', '/blog/../about', '/blog/%2e%2e/about', '/files/%2fa', '/members-old/..', '/blog\\x']) {
      const r = await rawGet(A, p); assert.notEqual(r.status, 400, p); assert.notEqual(r.headers['x-tokenlock-early'], 'bad_path', p); assert.match(r.body, /APP BOOTED/, p);
    }
  });
  await step('protected, valid pass: app boots', async () => { const r = await get(A, '/members/area', ck(GOOD)); assert.equal(r.status, 200); assert.match(await r.text(), /APP BOOTED/); });
  await step('public carve-out inside protect', async () => { assert.equal((await get(A, '/members/join')).status, 200); });
  await step('API path, no pass: JSON 401 (no redirect)', async () => {
    const r = await get(A, '/api/data', { accept: 'application/json' }); assert.equal(r.status, 401); const j = await r.json(); assert.equal(j.code, 'signin_required');
  });
  await step('malformed path (%2f): 400 bad_path before the app', async () => { const r = await get(A, '/members%2f..%2fx'); assert.equal(r.status, 400); assert.equal((await r.json()).code, 'bad_path'); });
  await step('exclude_paths: admin login keeps working without a pass (no self-lockout)', async () => {
    for (const p of ['/wp-login.php', '/wp-admin/options.php']) { const r = await get(A, p); assert.equal(r.status, 200, p); assert.match(await r.text(), /APP BOOTED/); }
  });
  await step('TOKENLOCK pages always reachable (sign-in / session / sign-out)', async () => { const r = await get(A, '/tokenlock/signin.php'); assert.equal(r.status, 200); assert.match(await r.text(), /Sign in with your Token/); });
  await step('admin_ips (via trusted proxy X-Forwarded-For, IPv4 and IPv6): allowed without a pass', async () => {
    for (const ip of ['203.0.113.9', '2001:db8::5']) { const r = await get(A, '/members/area', { 'x-forwarded-for': `9.9.9.9, ${ip}` }); assert.equal(r.status, 200, ip); assert.equal(r.headers.get('x-tokenlock-early'), 'admin'); }
  });
  await step('deny_ips: 403 even with a valid pass; spoofed left-most XFF hop is ignored', async () => {
    const r = await get(A, '/members/area', { ...ck(GOOD), 'x-forwarded-for': '198.51.100.7' }); assert.equal(r.status, 403); assert.doesNotMatch(await r.text(), /APP BOOTED/);
    const s = await get(A, '/members/area', { 'x-forwarded-for': '203.0.113.9, 198.51.100.7' }); assert.equal(s.status, 403, 'right-most untrusted hop decides');
  });
  await step('verification service down: fail closed (503), app never boots', async () => {
    const r = await get(A, '/members/area', ck(DOWN)); assert.equal(r.status, 503); assert.doesNotMatch(await r.text(), /APP BOOTED/);
  });
  await step('kill switch: tokenlock/early.off turns the early block off', async () => {
    writeFileSync(OFF, ''); try { const r = await get(A, '/members/area'); assert.equal(r.status, 200); assert.match(await r.text(), /APP BOOTED/); } finally { rmSync(OFF, { force: true }); }
    assert.equal((await get(A, '/members/area')).status, 302, 'back on after removing the file');
  });

  console.log('lockout and failure policy');
  const B = await server({ protect: ['/*'] });
  await step("protect '/*': the sign-in page is still reachable (built-in exclusion)", async () => {
    assert.equal((await get(B, '/tokenlock/signin.php')).status, 200); assert.equal((await get(B, '/anything')).status, 302);
  });
  const C = await server(EARLY, { TOKENLOCK_SECRET_KEY: '' });
  await step('misconfigured (no secret key): protected paths fail closed 503, other pages work', async () => {
    const r = await get(C, '/members/area', ck(GOOD)); assert.equal(r.status, 503); assert.doesNotMatch(await r.text(), /APP BOOTED/);
    assert.equal((await get(C, '/about')).status, 200);
  });
  const D = await server(EARLY, { TOKENLOCK_FAIL_OPEN: '1' });
  await step('fail_open on (strict off): outage lets the pass holder in, marked fail-open; a "no" still blocks', async () => {
    const r = await get(D, '/members/area', ck(DOWN)); assert.equal(r.status, 200); assert.equal(r.headers.get('x-tokenlock'), 'fail-open');
    assert.equal((await get(D, '/members/area', ck('pp1.' + 'Y'.repeat(40) + '.' + 'Q'.repeat(43)))).status, 302);
  });
  const E = await server(EARLY, { TOKENLOCK_FAIL_OPEN: '1', TOKENLOCK_STRICT: '1' });
  await step('strict on + fail_open = configuration error: fails closed (503), never open', async () => {
    const r = await get(E, '/members/area', ck(DOWN)); assert.equal(r.status, 503); assert.doesNotMatch(await r.text(), /APP BOOTED/);
  });
  console.log('top-of-index include mode');
  const G = await server(EARLY, { EARLY_MODE: 'include' });
  await step('require at the top of index.php: same decisions', async () => {
    assert.equal((await get(G, '/members/area')).status, 302);
    const r = await get(G, '/members/area', ck(GOOD)); assert.equal(r.status, 200); assert.match(await r.text(), /early=ran/);
    assert.equal((await get(G, '/about')).status, 200);
  });
  const F = await server({});
  await step('no early settings: does nothing', async () => { assert.equal((await get(F, '/members/area')).status, 200); });
} finally {
  for (const s of servers) s.kill(); mock.close(); rmSync(OFF, { force: true }); rmSync(DOC, { recursive: true, force: true });
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
