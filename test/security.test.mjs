// 0.2.1 security patch: canonical paths, case-insensitive matching, strict mode, per-pass cache clearing, cache:false,
// API mode JSON 401/403, authorize(), config-time checks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import * as core from '../dist/index.js';
import * as ex from '../dist/express.js';
import * as nx from '../dist/next.js';

const V = JSON.parse(readFileSync(new URL('./fixtures/path-vectors.json', import.meta.url), 'utf8'));
const SK = 'sk_' + 'a'.repeat(43);
const P = 'pp1.' + 'E'.repeat(40) + '.' + 'Q'.repeat(43);
const P2 = 'pp1.' + 'F'.repeat(40) + '.' + 'Q'.repeat(43);
const future = () => new Date(Date.now() + 3600e3).toISOString();
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });
// Agent key allowed GET /admin/* in production; mirrors the hosted API (canonical path echo, case-insensitive routes).
function api(calls = [], st = {}) {
  return async (url, init = {}) => {
    const b = JSON.parse(init.body || '{}'); calls.push(b);
    if (st.down) throw new TypeError('fetch failed');
    const resource = { path: b.path ?? null, method: b.method ?? null, environment: b.environment ?? null };
    const base = { address: 'bc1qagent', assets_held: ['TOKENLOCK'], site_id: 's1', origin: 'https://example.com', expires_at: future(), correlation_id: 'cid' };
    if (st.answer) return J(st.answer(base, resource));
    const access = (allowed, reason) => ({ mode: 'registered_keys', allowed, reason, key: { id: 'k1' }, permissions: {}, key_expires_at: null, resource });
    const no = (code) => J({ valid: false, allowed: false, code, reason: code, ...base, access: access(false, code), resource, cache_max_s: 0 });
    if (st.revoked) return no('key_revoked');
    const p = String(b.path || '').toLowerCase();
    if (b.path && !(p === '/admin' || p.startsWith('/admin/'))) return no('route_not_allowed');
    if (b.method && b.method !== 'GET') return no('method_not_allowed');
    if (b.environment && b.environment !== 'production') return no('environment_not_allowed');
    return J({ valid: true, allowed: true, ...base, access: access(true, 'ok'), resource, cache_max_s: 5 });
  };
}
async function withServer(mw, fn) {
  const s = http.createServer((req, res) => mw(req, res, (e) => { if (e) { res.statusCode = 500; return res.end(String(e)); } res.end('SECRET ' + req.url); }));
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  try { return await fn('http://127.0.0.1:' + s.address().port); } finally { s.close(); }
}
const raw = (base, path, headers = {}) => new Promise((ok, no) => {
  const u = new URL(base);
  const r = http.request({ host: u.hostname, port: u.port, path, method: headers.method || 'GET', headers }, (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => ok({ status: res.statusCode, headers: res.headers, body: d })); });
  r.on('error', no); r.end();
});

test('canonicalPath: shared vectors', () => {
  for (const [i, want] of V.vectors) assert.equal(core.canonicalPath(i), want, JSON.stringify(i));
});
test('matcher: case-insensitive by default; every alternate form of /admin is protected', () => {
  const m = core.createMatcher(V.protected_case.protect);
  for (const p of V.protected_case.must_be_protected_or_rejected) assert.equal(m(p), true, p);
  for (const p of V.protected_case.not_protected) assert.equal(m(p), false, p);
  assert.equal(core.createMatcher('/admin/*', { caseSensitive: true })('/ADMIN'), false);
});
test('express: no alternate URL form reaches protected content without a pass', async () => {
  core.clearCache();
  const mw = ex.tokenlock({ protect: ['/admin/:path*'], signInPage: '/signin', secretKey: SK, fetch: api() });
  await withServer(mw, async (b) => {
    for (const p of V.protected_case.must_be_protected_or_rejected) {
      const r = await raw(b, p);
      assert.notEqual(r.status, 200, p); assert.ok([302, 400].includes(r.status), p + ' ' + r.status);
    }
    assert.equal((await raw(b, '/public')).status, 200);
  });
});
test('express: alternate forms are checked as the canonical route (a key for /admin/* gets /ADMIN/x; not /PUBLIC-ish tricks)', async () => {
  core.clearCache(); const calls = [];
  const mw = ex.tokenlock({ protect: ['/:path*'], publicPaths: ['/signin'], signInPage: '/signin', secretKey: SK, fetch: api(calls), environment: 'production' });
  await withServer(mw, async (b) => {
    const c = { cookie: 'tokenlock_pass=' + P };
    assert.equal((await raw(b, '/ADMIN/x', c)).status, 200);
    assert.equal(calls.at(-1).path, '/ADMIN/x');
    assert.equal((await raw(b, '/x/../admin/y', c)).status, 200); assert.equal(calls.at(-1).path, '/admin/y');
    assert.equal((await raw(b, '/admin%2f..%2fbilling', c)).status, 400);
    assert.equal((await raw(b, '/billing', c)).status, 403);
    assert.equal((await raw(b, '/admin/x', { ...c, method: 'POST' })).status, 403);
  });
});
test('strict: valid:true with missing allowed / resource echo / mismatched echo / unknown mode is denied', async () => {
  const cases = {
    no_allowed: (b) => ({ valid: true, ...b }),
    no_echo: (b) => ({ valid: true, allowed: true, ...b }),
    mismatch: (b, r) => ({ valid: true, allowed: true, ...b, resource: { ...r, path: '/admin/other' } }),
    unknown_mode: (b, r) => ({ valid: true, allowed: true, ...b, resource: r, access: { mode: 'future_mode', allowed: true } }),
    access_missing_allowed: (b, r) => ({ valid: true, allowed: true, ...b, resource: r, access: { mode: 'registered_keys' } }),
    no_address: (b, r) => ({ valid: true, allowed: true, ...b, address: '', resource: r }),
    expired: (b, r) => ({ valid: true, allowed: true, ...b, expires_at: new Date(Date.now() - 1000).toISOString(), resource: r }),
  };
  for (const [name, answer] of Object.entries(cases)) {
    core.clearCache();
    const c = new core.TokenlockClient({ secretKey: SK, fetch: api([], { answer }) });
    const r = await c.verifyPass(P, { path: '/admin/x', method: 'GET' });
    assert.equal(r.valid, false, name); assert.equal(r.allowed, false, name);
  }
  // the same incomplete answer is accepted only when strict is explicitly off (0.2.0 behaviour)
  core.clearCache();
  const loose = new core.TokenlockClient({ secretKey: SK, fetch: api([], { answer: cases.no_echo }), strict: false });
  assert.equal((await loose.verifyPass(P, { path: '/admin/x', method: 'GET' })).valid, true);
});
test('clearCache(pass) drops every resource entry for that pass only; cache:false always asks', async () => {
  core.clearCache(); const calls = [];
  const c = new core.TokenlockClient({ secretKey: SK, fetch: api(calls), strict: false });
  for (const p of ['/admin/a', '/admin/b']) { await c.verifyPass(P, { path: p, method: 'GET' }); await c.verifyPass(P2, { path: p, method: 'GET' }); }
  assert.equal(calls.length, 4);
  for (const p of ['/admin/a', '/admin/b']) { await c.verifyPass(P, { path: p, method: 'GET' }); await c.verifyPass(P2, { path: p, method: 'GET' }); }
  assert.equal(calls.length, 4, 'all cached');
  core.clearCache(P);
  for (const p of ['/admin/a', '/admin/b']) { await c.verifyPass(P, { path: p, method: 'GET' }); await c.verifyPass(P2, { path: p, method: 'GET' }); }
  assert.equal(calls.length, 6, 'both of P\'s entries refetched, P2 still cached');
  await c.verifyPass(P2, { path: '/admin/a', method: 'GET' }, { cache: false });
  assert.equal(calls.length, 7);
  const nc = new core.TokenlockClient({ secretKey: SK, fetch: api(calls), cache: false });
  await nc.verifyPass(P2); await nc.verifyPass(P2); assert.equal(calls.length, 9);
});
test('strict: a revoked registered key is denied on the very next request (no cache)', async () => {
  core.clearCache(); const st = {};
  const mw = ex.tokenlock({ protect: ['/admin/:path*'], signInPage: '/signin', secretKey: SK, fetch: api([], st) });
  await withServer(mw, async (b) => {
    const c = { cookie: 'tokenlock_pass=' + P };
    assert.equal((await raw(b, '/admin/x', c)).status, 200);
    st.revoked = true;
    assert.equal((await raw(b, '/admin/x', { ...c, accept: 'application/json' })).status, 403);
  });
});
test('API mode: JSON 401/403 with a reason for every denial (Accept: application/json or apiPaths)', async () => {
  core.clearCache(); const st = {};
  const mw = ex.tokenlock({ protect: ['/:path*'], publicPaths: ['/signin'], signInPage: '/signin', apiPaths: ['/admin/api/:path*'], secretKey: SK, fetch: api([], st), environment: 'production' });
  await withServer(mw, async (b) => {
    let r = await raw(b, '/admin/api/x'); assert.equal(r.status, 401); assert.equal(JSON.parse(r.body).code, 'signin_required');
    r = await raw(b, '/admin/x', { accept: 'application/json' }); assert.equal(r.status, 401);
    r = await raw(b, '/admin/x', { accept: 'application/json', cookie: 'tokenlock_pass=bad' }); assert.equal(r.status, 401); assert.equal(JSON.parse(r.body).code, 'bad_pass'); assert.ok(r.headers['set-cookie']);
    r = await raw(b, '/billing', { accept: 'application/json', cookie: 'tokenlock_pass=' + P }); assert.equal(r.status, 403); const j = JSON.parse(r.body); assert.equal(j.code, 'route_not_allowed'); assert.ok(j.reason);
    st.revoked = true;
    r = await raw(b, '/admin/api/x', { cookie: 'tokenlock_pass=' + P }); assert.equal(r.status, 403); assert.equal(JSON.parse(r.body).code, 'key_revoked');
    st.revoked = false; st.down = true;
    r = await raw(b, '/admin/api/x', { cookie: 'tokenlock_pass=' + P }); assert.equal(r.status, 503); assert.equal(JSON.parse(r.body).code, 'tokenlock_unavailable');
    r = await raw(b, '/admin/x', { accept: 'text/html' }); assert.equal(r.status, 302, 'browsers still get the sign-in redirect');
  });
});
test('config: strict:true with failOpen or checkResource:false throws; without strict it warns and turns strict off', () => {
  assert.throws(() => ex.tokenlock({ protect: '/a', signInPage: '/s', secretKey: SK, strict: true, failOpen: true }), /failOpen/);
  assert.throws(() => nx.tokenlock({ protect: '/a', signInPage: '/s', secretKey: SK, strict: true, checkResource: false }), /checkResource/);
  const warn = console.warn; const seen = []; console.warn = (m) => seen.push(m);
  try { ex.tokenlock({ protect: '/a', signInPage: '/s', secretKey: SK, failOpen: true }); } finally { console.warn = warn; }
  assert.match(seen.join('\n'), /strict mode is OFF.*UNVERIFIED/);
});
test('next: getPass forwards a resource; authorize() is strict + uncached; middleware sees raw encoded paths', async () => {
  core.clearCache(); const calls = [];
  const req = (p, h = {}) => ({ url: 'https://example.com' + p, nextUrl: new URL('https://example.com' + p), method: 'GET', headers: new Headers({ cookie: 'tokenlock_pass=' + P, ...h }) });
  const g = await nx.getPass(req('/x'), { secretKey: SK, fetch: api(calls), path: '/billing', method: 'GET' });
  assert.equal(g, null); assert.equal(calls.at(-1).path, '/billing');
  const a1 = await nx.authorize(req('/x'), { path: '/admin/x', method: 'GET' }, { secretKey: SK, fetch: api(calls) });
  const a2 = await nx.authorize(req('/x'), { path: '/admin/x', method: 'GET' }, { secretKey: SK, fetch: api(calls) });
  assert.equal(a1.valid, true); assert.equal(a2.valid, true); assert.equal(calls.length, 3, 'not cached');
  await assert.rejects(nx.authorize(req('/x'), {}, { secretKey: SK }), /path, method/);
  const mw = nx.tokenlock({ protect: ['/admin/:path*'], signInPage: '/signin', secretKey: SK, fetch: api(calls) });
  assert.equal((await mw(req('/ADMIN', { cookie: '' }))).status, 307);
  assert.equal((await mw(req('/admin%2f..'))).status, 400);
});
