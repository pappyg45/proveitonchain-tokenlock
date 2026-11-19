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
// 0.4.0: a resource is granted only by a route policy, so these cache tests use a registered-keys site whose key may
// do anything; non-strict clients cache its answers for cache_max_s. The API echoes exactly the resource it was sent.
// (Until 0.3.x they used a token-only answer with no access block; that answer is now policy_required, never cached.)
function tokenOnly(calls, { echo, legacy } = {}) {
  return async (url, init = {}) => {
    const b = JSON.parse(init.body || '{}'); calls.push(b);
    const resource = { path: b.path ?? null, method: b.method ?? null, environment: b.environment ?? null };
    const r = echo ? echo(resource) : resource;
    const base = { valid: true, address: 'bc1qholder', assets_held: ['TOKENLOCK'], site_id: 's1', expires_at: future(), cache_max_s: 60 };
    if (legacy) return J({ ...base, allowed: true, resource: r });
    return J({ ...base, allowed: true, resource: r, access: { mode: 'registered_keys', allowed: true, reason: 'ok', key: { id: 'k1' }, permissions: {}, key_expires_at: null, resource: r } });
  };
}

test('resourcePath: shared vectors (canonical, lowercased)', () => {
  for (const [i, want] of V.resource_vectors.vectors) assert.equal(core.resourcePath(i), want, i);
});

test('cache key collision (repro): /Admin then /admin are the same canonical resource; 0.4.2 never caches resource answers', async () => {
  core.clearCache(); const calls = [];
  const c = new core.TokenlockClient({ secretKey: SK, fetch: tokenOnly(calls) });
  const a = await c.verifyPass(P, { path: '/Admin', method: 'GET' });
  const b = await c.verifyPass(P, { path: '/admin', method: 'GET' });
  assert.equal(a.valid, true); assert.equal(b.valid, true);
  assert.equal(calls.length, 2, '0.4.2 (always strict): registered-key resource answers are asked every time');
  assert.deepEqual(calls.map((x) => x.path), ['/admin', '/admin'], 'the API is asked about the canonical lowercased path');
  assert.equal(b.resource.path, '/admin');
  assert.throws(() => new core.TokenlockClient({ secretKey: SK, strict: false, fetch: tokenOnly(calls) }), (e) => e.code === 'bad_config', 'loose mode removed');
});

test('cache hits are revalidated against the request: a hit that no longer matches (expired) is dropped and asked again', async () => {
  core.clearCache(); const calls = [];
  const c = new core.TokenlockClient({ secretKey: SK, fetch: async (u, init) => { calls.push(1); return J({ valid: true, address: 'bc1qholder', assets_held: ['TOKENLOCK'], site_id: 's1', expires_at: future(), cache_max_s: 60 }); } });
  const a = await c.verifyPass(P, { identityOnly: true }); assert.equal(a.valid, true);
  await c.verifyPass(P, { identityOnly: true }); assert.equal(calls.length, 1, 'identity answer cached');
  a.expires_at = new Date(Date.now() - 1000).toISOString(); // the cached object no longer holds
  const b = await c.verifyPass(P, { identityOnly: true }); assert.equal(b.valid, true); assert.equal(calls.length, 2, 'the bad hit was not used');
  a.resource = { path: '/admin', method: 'GET', environment: null }; b.resource = { path: '/admin', method: 'GET', environment: null };
  await c.verifyPass(P, { identityOnly: true }); assert.equal(calls.length, 3, 'a cached identity answer that suddenly names a resource is not used');
});

test('cache key includes secret key (site): identity answers of one site never answer for another', async () => {
  core.clearCache(); const calls = [];
  const f = async () => { calls.push(1); return J({ valid: true, address: 'bc1qholder', assets_held: ['TOKENLOCK'], site_id: 's1', expires_at: future(), cache_max_s: 60 }); };
  const one = new core.TokenlockClient({ secretKey: SK, fetch: f });
  const two = new core.TokenlockClient({ secretKey: SK2, fetch: f });
  await one.verifyPass(P, { identityOnly: true }); await two.verifyPass(P, { identityOnly: true }); assert.equal(calls.length, 2, 'site');
  await one.verifyPass(P, { identityOnly: true }); await two.verifyPass(P, { identityOnly: true }); assert.equal(calls.length, 2, 'each site hit its own entry');
  // resource checks (method/environment variations included) always ask
  const k = new core.TokenlockClient({ secretKey: SK, fetch: tokenOnly([]) });
  const kc = []; const k2 = new core.TokenlockClient({ secretKey: SK, fetch: tokenOnly(kc) });
  for (const [m, e] of [['GET', 'production'], ['POST', 'production'], ['GET', 'staging'], ['GET', 'production']]) await k2.verifyPass(P, { path: '/admin', method: m, environment: e });
  assert.equal(kc.length, 4); void k;
});

test('an echo for another path is refused (never cached); strict:false is a config error', async () => {
  core.clearCache(); const calls = [];
  const c = new core.TokenlockClient({ secretKey: SK, fetch: tokenOnly(calls, { echo: (r) => ({ ...r, path: '/public' }) }) });
  const r = await c.verifyPass(P, { path: '/admin', method: 'GET' });
  assert.equal(r.valid, false); assert.equal(r.code, 'resource_mismatch');
  await c.verifyPass(P, { path: '/admin', method: 'GET' }); assert.equal(calls.length, 2);
  assert.throws(() => new core.TokenlockClient({ secretKey: SK, strict: false, fetch: tokenOnly([]) }), (e) => e.code === 'bad_config');
  // an upper-case echo of the same path is the same resource
  core.clearCache();
  const u = new core.TokenlockClient({ secretKey: SK, fetch: tokenOnly([], { echo: (r) => ({ ...r, path: '/ADMIN' }) }) });
  assert.equal((await u.verifyPass(P, { path: '/admin', method: 'GET' })).valid, true);
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
    [{ ...base, allowed: false }, 'policy_required'], // 0.4.0: no route policy (token-only) → policy_required
    [{ ...base, allowed: true }, 'policy_required'],
    [{ ...base, allowed: false, access: acc(true, 'ok') }, 'not_allowed'],
    [{ ...base, allowed: true, access: { ...acc(true, 'ok'), resource: undefined } }, 'incomplete_answer'],
    [{ ...base, address: '', allowed: true, resource: res }, 'incomplete_answer'],
    [{ ...base, allowed: true, resource: { ...res, path: '/public' }, access: acc(true, 'ok') }, 'resource_mismatch'],
    [{ ...base, allowed: true, resource: res, access: { mode: 'future', allowed: true } }, 'not_allowed'],
    [{ ...base, expires_at: new Date(Date.now() - 1).toISOString(), allowed: true, resource: res }, 'expired'],
    [null, 'bad_answer'],
  ];
  for (const [v, want] of cases) assert.deepEqual(cf.strictCheck(v, res), { ok: false, code: want }, JSON.stringify(v));
  assert.deepEqual(cf.strictCheck({ ...base, allowed: true, resource: { ...res, path: '/ADMIN' }, access: acc(true, 'ok') }, res), { ok: true });
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

test('0.4.0: a valid answer with a resource but no route policy (token-only) is policy_required (0.4.2: always strict), never cached', async () => {
  for (const strict of [true, undefined]) {
    core.clearCache(); const calls = [];
    const c = new core.TokenlockClient({ secretKey: SK, ...(strict === undefined ? {} : { strict }), fetch: tokenOnly(calls, { legacy: true }) });
    const r = await c.verifyPass(P, { path: '/admin', method: 'GET' });
    assert.equal(r.valid, false, 'strict=' + strict); assert.equal(r.allowed, false); assert.equal(r.code, 'policy_required'); assert.equal(r.identity_valid, true);
    await c.verifyPass(P, { path: '/admin', method: 'GET' }); assert.equal(calls.length, 2, 'not cached');
    const id = await c.verifyPass(P, { identityOnly: true }); assert.equal(id.valid, true, 'identity-only still valid');
  }
  assert.ok(core.FORBIDDEN_CODES.includes('policy_required'));
});
