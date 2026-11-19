// AI-assisted review findings and regression fixes (0.2.1 / 0.2.2): cache key collision across path case, open redirects through ?next=, Cloudflare
// denial mapping, and path rules v1.1 (ambiguous forms rejected).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as core from '../dist/index.js';
import * as cf from '../examples/cloudflare-worker/worker.js';

const V = JSON.parse(readFileSync(new URL('./fixtures/path-vectors.json', import.meta.url), 'utf8'));
const N = JSON.parse(readFileSync(new URL('./fixtures/next-vectors.json', import.meta.url), 'utf8'));
const SK = 'sk_' + 'b'.repeat(43);
const SK2 = 'sk_' + 'c'.repeat(43);
const P = 'pp1.' + 'G'.repeat(40) + '.' + 'Q'.repeat(43);
const future = () => new Date(Date.now() + 3600e3).toISOString();
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });
// A token-only site (no registered keys): the API echoes exactly the resource it was sent, no `access` block, so
// strict answers ARE cached. Only /admin is allowed (case-insensitive, like the hosted API).
function tokenOnly(calls, { echo } = {}) {
  return async (url, init = {}) => {
    const b = JSON.parse(init.body || '{}'); calls.push(b);
    const resource = { path: b.path ?? null, method: b.method ?? null, environment: b.environment ?? null };
    const base = { valid: true, address: 'bc1qholder', assets_held: ['TOKENLOCK'], site_id: 's1', expires_at: future(), cache_max_s: 60 };
    return J({ ...base, allowed: true, resource: echo ? echo(resource) : resource });
  };
}

test('resourcePath: shared vectors (canonical, lowercased)', () => {
  for (const [i, want] of V.resource_vectors.vectors) assert.equal(core.resourcePath(i), want, i);
});

test('cache key collision (repro): /Admin then /admin answer for the same lowercased resource, with a matching echo', async () => {
  core.clearCache(); const calls = [];
  const c = new core.TokenlockClient({ secretKey: SK, fetch: tokenOnly(calls) });
  const a = await c.verifyPass(P, { path: '/Admin', method: 'GET' });
  const b = await c.verifyPass(P, { path: '/admin', method: 'GET' });
  assert.equal(a.valid, true); assert.equal(b.valid, true);
  assert.equal(calls.length, 1, 'one canonical resource → one cache entry');
  assert.equal(calls[0].path, '/admin', 'the API is asked about the canonical lowercased path');
  // 0.2.1 returned the cached /Admin answer (echo "/Admin") for /admin; the echo now always matches the request.
  assert.equal(b.resource.path, '/admin');
});

test('cache hits are revalidated against the request: a hit that no longer matches is dropped and asked again', async () => {
  core.clearCache(); const calls = [];
  const c = new core.TokenlockClient({ secretKey: SK, fetch: tokenOnly(calls) });
  const a = await c.verifyPass(P, { path: '/admin/x', method: 'GET' });
  assert.equal(a.valid, true);
  a.resource.path = '/admin/other'; // the cached object no longer describes this request
  const b = await c.verifyPass(P, { path: '/admin/x', method: 'GET' });
  assert.equal(b.valid, true); assert.equal(calls.length, 2, 'the bad hit was not used');
  assert.equal(b.resource.path, '/admin/x');
  // an expired cached answer is never used either
  b.expires_at = new Date(Date.now() - 1000).toISOString();
  await c.verifyPass(P, { path: '/admin/x', method: 'GET' }); assert.equal(calls.length, 3);
});

test('cache key includes secret key (site), method, environment and mode', async () => {
  core.clearCache(); const calls = [];
  const f = tokenOnly(calls);
  const one = new core.TokenlockClient({ secretKey: SK, fetch: f });
  const two = new core.TokenlockClient({ secretKey: SK2, fetch: f });
  await one.verifyPass(P, { path: '/admin', method: 'GET', environment: 'production' });
  await two.verifyPass(P, { path: '/admin', method: 'GET', environment: 'production' }); assert.equal(calls.length, 2, 'site');
  await one.verifyPass(P, { path: '/admin', method: 'POST', environment: 'production' }); assert.equal(calls.length, 3, 'method');
  await one.verifyPass(P, { path: '/admin', method: 'GET', environment: 'staging' }); assert.equal(calls.length, 4, 'environment');
  await one.verifyPass(P, { path: '/admin', method: 'GET', environment: 'production' }, { strict: false }); assert.equal(calls.length, 5, 'mode');
  await one.verifyPass(P, { path: '/ADMIN/', method: 'get', environment: 'production' }); assert.equal(calls.length, 5, 'same canonical resource is a hit');
});

test('an echo for another path is refused in strict AND loose mode (never cached)', async () => {
  for (const strict of [true, false]) {
    core.clearCache(); const calls = [];
    const c = new core.TokenlockClient({ secretKey: SK, strict, fetch: tokenOnly(calls, { echo: (r) => ({ ...r, path: '/public' }) }) });
    const r = await c.verifyPass(P, { path: '/admin', method: 'GET' });
    assert.equal(r.valid, false, 'strict=' + strict); assert.equal(r.code, 'resource_mismatch');
    await c.verifyPass(P, { path: '/admin', method: 'GET' }); assert.equal(calls.length, 2);
  }
  // an upper-case echo of the same path is the same resource
  core.clearCache();
  const c = new core.TokenlockClient({ secretKey: SK, fetch: tokenOnly([], { echo: (r) => ({ ...r, path: '/ADMIN' }) }) });
  assert.equal((await c.verifyPass(P, { path: '/admin', method: 'GET' })).valid, true);
});

test('safeNext: shared vectors (only same-site relative paths)', () => {
  for (const v of N.allowed) assert.equal(core.safeNext(v), v, JSON.stringify(v));
  for (const v of N.rejected) assert.equal(core.safeNext(v), '/', JSON.stringify(v));
  assert.equal(core.safeNext('//evil.com', '/home'), '/home');
  assert.equal(core.safeNext(undefined), '/'); assert.equal(core.safeNext('/' + 'a'.repeat(2001)), '/');
});

test('Cloudflare sign-in page: the browser redirect goes through the same safeNext (no open redirect)', async () => {
  const res = await cf.default.fetch(new Request('https://site.example/signin?next=//evil.com'), { TOKENLOCK_SITE_KEY: 'pk_x', TOKENLOCK_SECRET_KEY: SK });
  const html = await res.text();
  assert.ok(!/location\.href\s*=/.test(html), 'no raw location.href assignment');
  assert.match(html, /location\.assign\(tlSafeNext\(/);
  const script = html.slice(html.lastIndexOf('<script>') + 8, html.lastIndexOf('</script>'));
  const fn = new Function('ProveItGate', 'fetch', 'location', 'go', script.replace(/go\.onclick=/, 'go.onclick=') + ';return tlSafeNext;');
  const tl = fn({}, () => {}, {}, {});
  for (const v of N.allowed) assert.equal(tl(v), v, 'cf browser ' + JSON.stringify(v));
  for (const v of N.rejected) assert.equal(tl(v), '/', 'cf browser ' + JSON.stringify(v));
  for (const v of N.rejected) assert.equal(cf.safeNext(v), '/', 'cf server ' + JSON.stringify(v));
  // end to end: the page sends the visitor to the fallback, not to evil.com
  let went = null;
  const go = {}; const loc = { search: '?next=' + encodeURIComponent('/%2f%2fevil.com'), assign: (u) => (went = u) };
  new Function('ProveItGate', 'fetch', 'location', 'go', 'URLSearchParams', script)({ signIn: async () => ({ pass: P }) }, async () => ({ ok: true }), loc, go, URLSearchParams);
  await go.onclick(); assert.equal(went, '/');
});

test('Express example sign-in page: browser redirect uses safeNext', () => {
  const src = readFileSync(new URL('../examples/express/server.js', import.meta.url), 'utf8');
  assert.ok(!/location\.href\s*=/.test(src)); assert.match(src, /location\.assign\(tlSafeNext\(/); assert.match(src, /const tlSafeNext = \$\{safeNext\.toString\(\)\}/);
  // what the page ships: the built safeNext, stringified
  const tl = new Function('return (' + core.safeNext.toString() + ')')();
  for (const v of N.rejected) assert.equal(tl(v), '/', JSON.stringify(v));
  for (const v of N.allowed) assert.equal(tl(v), v, JSON.stringify(v));
});

test('Cloudflare: authorization denials keep their reason (403), only malformed answers are incomplete_answer', () => {
  const res = { path: '/admin', method: 'GET', environment: null };
  const base = { valid: true, address: 'bc1q', site_id: 's1', expires_at: future() };
  const acc = (allowed, reason) => ({ mode: 'registered_keys', allowed, reason, resource: res });
  const cases = [
    [{ ...base, allowed: false, access: acc(false, 'route_not_allowed') }, 'route_not_allowed'],
    [{ ...base, allowed: false, access: acc(false, 'method_not_allowed') }, 'method_not_allowed'],
    [{ ...base, allowed: true, access: acc(false, 'key_revoked') }, 'key_revoked'],
    [{ valid: false, code: 'environment_not_allowed', access: acc(false, 'environment_not_allowed') }, 'environment_not_allowed'],
    [{ ...base, allowed: false }, 'not_allowed'],
    [{ ...base, allowed: true }, 'incomplete_answer'],
    [{ ...base, address: '', allowed: true, resource: res }, 'incomplete_answer'],
    [{ ...base, allowed: true, resource: { ...res, path: '/public' } }, 'resource_mismatch'],
    [{ ...base, allowed: true, resource: res, access: { mode: 'future', allowed: true } }, 'not_allowed'],
    [{ ...base, expires_at: new Date(Date.now() - 1).toISOString(), allowed: true, resource: res }, 'expired'],
    [null, 'bad_answer'],
  ];
  for (const [v, want] of cases) assert.deepEqual(cf.strictCheck(v, res), { ok: false, code: want }, JSON.stringify(v));
  assert.deepEqual(cf.strictCheck({ ...base, allowed: true, resource: { ...res, path: '/ADMIN' } }, res), { ok: true });
});

test('Cloudflare worker end to end: route_not_allowed with valid:true → 403 route_not_allowed (was 401 incomplete_answer)', async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const u = String(input?.url || input);
    if (u.endsWith('/api/v1/gate/verify')) { const b = JSON.parse(init.body); return J({ valid: true, address: 'bc1q', site_id: 's1', expires_at: future(), allowed: false, access: { mode: 'registered_keys', allowed: false, reason: 'route_not_allowed', resource: { path: b.path, method: b.method, environment: b.environment } } }); }
    return new Response('ORIGIN');
  };
  try {
    const env = { TOKENLOCK_API: 'https://api.example', TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_PROTECT: '/admin' };
    const r = await cf.default.fetch(new Request('https://site.example/Admin/x', { headers: { accept: 'application/json', cookie: 'tokenlock_pass=' + P } }), env);
    assert.equal(r.status, 403); const j = await r.json(); assert.equal(j.code, 'route_not_allowed');
    const h = await cf.default.fetch(new Request('https://site.example/admin/x', { headers: { cookie: 'tokenlock_pass=' + P } }), env);
    assert.equal(h.status, 403, 'browser requests: forbidden, not a sign-in loop');
  } finally { globalThis.fetch = realFetch; }
});

test('path rules v1.1: ambiguous forms are rejected by the SDK and the Cloudflare example alike', () => {
  for (const [i, want] of V.vectors) assert.equal(cf.canonicalPath(i), want, 'cf ' + JSON.stringify(i));
  for (const p of ['/admin/..', '/admin/.', '/x/..', '/admin;x', '/admin/%2e%2e', '/a/.%2e/b', '/admin%3b']) {
    assert.equal(core.canonicalPath(p), null, p);
    assert.equal(core.createMatcher('/admin/*')(p), true, 'treated as locked: ' + p);
  }
});
