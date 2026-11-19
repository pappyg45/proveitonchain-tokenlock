import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createRequire } from 'node:module';
import * as core from '../dist/index.js';
import * as ex from '../dist/express.js';
import * as nx from '../dist/next.js';

const require = createRequire(import.meta.url);
const SK = 'sk_' + 'a'.repeat(43);
const GOOD = 'pp1.' + 'Z'.repeat(40) + '.' + 'Q'.repeat(43);
const FORGED = 'pp1.' + 'Y'.repeat(40) + '.' + 'Q'.repeat(43);
const future = () => new Date(Date.now() + 3600e3).toISOString();

// Mock API: records calls; GOOD is a valid pass for site s1, everything else is bad.
function mockFetch(calls = []) {
  return async (url, init = {}) => {
    const body = init.body ? JSON.parse(init.body) : {};
    calls.push({ url, method: init.method, auth: init.headers?.authorization, body });
    const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });
    if (url.endsWith('/api/v1/gate/verify')) {
      if (init.headers?.authorization !== 'Bearer ' + SK) return J({ valid: false, code: 'bad_secret_key' });
      const echo = body.path || body.method || body.environment ? { allowed: true, resource: { path: body.path ?? null, method: body.method ?? null, environment: body.environment ?? null } } : {};
      if (body.pass === GOOD) return J({ valid: true, address: 'bc1qtest', assets_held: ['TOKENLOCK'], site_id: 's1', origin: 'https://example.com', expires_at: future(), ...echo });
      return J({ valid: false, code: 'bad_pass', reason: 'Not a valid pass.' });
    }
    if (url.endsWith('/api/v1/gate/challenge')) {
      if (body.site_key !== 'pk_good') return J({ error: 'Unknown site key.', code: 'bad_site_key', status: 401 }, 401);
      return J({ challenge_id: 'pg1.x.y', message: 'Sign in…', assets: ['TOKENLOCK'], any_name: false, origin: body.origin, site_id: 's1' });
    }
    if (url.endsWith('/api/v1/gate/signin')) return J({ valid: false, code: 'bad_signature' });
    return J({ error: 'no' }, 404);
  };
}

test('verifyPass: good pass, Bearer secret key sent, result cached', async () => {
  core.clearCache();
  const calls = [];
  const c = new core.TokenlockClient({ secretKey: SK, fetch: mockFetch(calls) });
  const v = await c.verifyPass(GOOD, { identityOnly: true });
  assert.equal(v.valid, true); assert.equal(v.address, 'bc1qtest');
  assert.equal(calls[0].auth, 'Bearer ' + SK); assert.equal(calls[0].method, 'POST');
  await c.verifyPass(GOOD, { identityOnly: true });
  assert.equal(calls.length, 1, 'second check served from cache');
});
test('verifyPass: forged / malformed / missing pass rejected', async () => {
  const c = new core.TokenlockClient({ secretKey: SK, fetch: mockFetch() });
  assert.equal((await c.verifyPass(FORGED, { identityOnly: true })).valid, false);
  assert.equal((await c.verifyPass('not-a-pass', { identityOnly: true })).code, 'bad_pass');
  assert.equal((await c.verifyPass(null, { identityOnly: true })).valid, false);
});
test('verifyPass: wrong secret key is never valid; missing key throws', async () => {
  core.clearCache();
  const c = new core.TokenlockClient({ secretKey: 'sk_' + 'b'.repeat(43), fetch: mockFetch() });
  assert.equal((await c.verifyPass(GOOD, { identityOnly: true })).valid, false);
  const saved = process.env.TOKENLOCK_SECRET_KEY; delete process.env.TOKENLOCK_SECRET_KEY;
  await assert.rejects(new core.TokenlockClient({ fetch: mockFetch() }).verifyPass(GOOD, { identityOnly: true }), /secret key/);
  if (saved) process.env.TOKENLOCK_SECRET_KEY = saved;
});
test('verifyPass: a "valid" answer without site_id is treated as invalid', async () => {
  core.clearCache();
  const f = async () => new Response(JSON.stringify({ valid: true, address: 'x' }), { status: 200 });
  assert.equal((await new core.TokenlockClient({ secretKey: SK, fetch: f }).verifyPass(GOOD, { identityOnly: true })).valid, false);
});
test('network failure → TokenlockError(network)', async () => {
  core.clearCache();
  const f = async () => { throw new TypeError('fetch failed'); };
  await assert.rejects(new core.TokenlockClient({ secretKey: SK, fetch: f }).verifyPass(GOOD, { identityOnly: true }), (e) => e.code === 'network');
});
test('createChallenge sends site key + origin; bad key → 401 error', async () => {
  const calls = [];
  const ch = await core.createChallenge({ siteKey: 'pk_good', origin: 'https://example.com', fetch: mockFetch(calls) });
  assert.equal(ch.site_id, 's1'); assert.equal(calls[0].body.site_key, 'pk_good'); assert.equal(calls[0].body.origin, 'https://example.com');
  await assert.rejects(core.createChallenge({ siteKey: 'pk_bad', fetch: mockFetch() }), (e) => e.status === 401 && e.code === 'bad_site_key');
});
test('matchers', () => {
  const m = core.createMatcher(['/members/:path*', '/admin', /^\/secret-/]);
  for (const p of ['/members', '/members/', '/members/a/b', '/admin', '/admin/', '/secret-x']) assert.ok(m(p), p);
  for (const p of ['/', '/membersx', '/admin/x', '/public']) assert.ok(!m(p), p);
  assert.ok(core.createMatcher('/docs/:slug')('/docs/a')); assert.ok(!core.createMatcher('/docs/:slug')('/docs/a/b'));
});
test('safeNext blocks open redirects', () => {
  assert.equal(core.safeNext('/members?x=1'), '/members?x=1');
  for (const v of ['//evil.com', 'https://evil.com', '/\\evil.com', '', null]) assert.equal(core.safeNext(v), '/');
});
test('cookies: HttpOnly, Secure, SameSite=Lax, ends with the pass; insecure only on http://localhost', () => {
  const c = core.passCookie(GOOD, { valid: true, expires_at: new Date(Date.now() + 600e3).toISOString() });
  assert.match(c, /^tokenlock_pass=pp1\./); assert.match(c, /HttpOnly/); assert.match(c, /Secure/); assert.match(c, /SameSite=Lax/);
  const age = Number(c.match(/Max-Age=(\d+)/)[1]); assert.ok(age > 590 && age <= 600);
  assert.equal(core.wantsSecure('http://localhost:3000/x'), false); assert.equal(core.wantsSecure('https://a.com'), true); assert.equal(core.wantsSecure('http://a.com'), true);
  assert.match(core.clearPassCookie(), /Max-Age=0/);
});
test('readPass / getPass from Node req, Fetch Request and cookie jar', async () => {
  core.clearCache();
  assert.equal(core.readPass({ headers: { cookie: 'a=1; tokenlock_pass=' + GOOD } }), GOOD);
  assert.equal(core.readPass(new Request('https://x', { headers: { cookie: 'tokenlock_pass=' + GOOD } })), GOOD);
  assert.equal(core.readPass({ headers: {}, cookies: { get: () => ({ value: GOOD }) } }), GOOD);
  const p = await core.getPass({ headers: { cookie: 'tokenlock_pass=' + GOOD } }, { secretKey: SK, fetch: mockFetch(), identityOnly: true });
  assert.equal(p.address, 'bc1qtest');
  assert.equal(await core.getPass({ headers: { cookie: 'tokenlock_pass=' + FORGED } }, { secretKey: SK, fetch: mockFetch(), identityOnly: true }), null);
  assert.equal(await core.getPass({ headers: {} }, { secretKey: SK, fetch: mockFetch(), identityOnly: true }), null);
});
test('CJS build loads', () => {
  const c = require('../dist/index.cjs'); assert.equal(typeof c.verifyPass, 'function');
  assert.equal(typeof require('../dist/express.cjs').tokenlock, 'function');
});

// ------------------------------------------------ Express middleware (real http server)
async function withServer(mw, fn) {
  const srv = http.createServer((req, res) => mw(req, res, () => { res.statusCode = 200; res.end('SECRET CONTENT ' + (req.tokenlock?.address || '')); }));
  await new Promise((r) => srv.listen(0, r));
  const base = 'http://localhost:' + srv.address().port;
  try { await fn(base); } finally { srv.close(); }
}
test('express: no pass → 302 to sign-in with next; good pass → content; forged → redirect + cookie cleared', async () => {
  core.clearCache();
  const mw = ex.tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', secretKey: SK, fetch: mockFetch(), tokenOnly: true });
  await withServer(mw, async (b) => {
    let r = await fetch(b + '/members/x?y=1', { redirect: 'manual' });
    assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/signin?next=%2Fmembers%2Fx%3Fy%3D1');
    r = await fetch(b + '/public'); assert.equal(r.status, 200);
    r = await fetch(b + '/members/x', { headers: { cookie: 'tokenlock_pass=' + GOOD } });
    assert.equal(r.status, 200); assert.match(await r.text(), /SECRET CONTENT bc1qtest/);
    r = await fetch(b + '/members/x', { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + FORGED } });
    assert.equal(r.status, 302); assert.match(r.headers.get('set-cookie'), /Max-Age=0/);
  });
});
test('express: session exchange sets cookie; forged pass 401; foreign origin 403; sign-out clears', async () => {
  core.clearCache();
  const mw = ex.tokenlock({ protect: '/members/:path*', signInPage: '/signin', secretKey: SK, fetch: mockFetch(), tokenOnly: true });
  await withServer(mw, async (b) => {
    const post = (pass, origin) => fetch(b + '/api/tokenlock/session', { method: 'POST', headers: { 'content-type': 'application/json', ...(origin ? { origin } : {}) }, body: JSON.stringify({ pass }) });
    let r = await post(GOOD, b);
    assert.equal(r.status, 200); const sc = r.headers.get('set-cookie');
    assert.match(sc, /tokenlock_pass=pp1\./); assert.match(sc, /HttpOnly/); assert.doesNotMatch(sc, /Secure/, 'http://localhost dev cookie');
    assert.equal((await post(FORGED, b)).status, 401);
    assert.equal((await post(GOOD, 'https://evil.example')).status, 403);
    r = await fetch(b + '/api/tokenlock/signout', { redirect: 'manual' });
    assert.equal(r.status, 303); assert.match(r.headers.get('set-cookie'), /Max-Age=0/);
  });
});

// ------------------------------------------------ Next.js middleware + route handlers
test('next: middleware redirects without pass, passes with good pass, clears forged', async () => {
  core.clearCache();
  const { NextRequest } = await import('next/server.js');
  const mw = nx.tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', secretKey: SK, fetch: mockFetch(), tokenOnly: true });
  let r = await mw(new NextRequest('https://example.com/members/a?b=2'));
  assert.equal(r.status, 307); assert.equal(r.headers.get('location'), 'https://example.com/signin?next=%2Fmembers%2Fa%3Fb%3D2');
  r = await mw(new NextRequest('https://example.com/members/a', { headers: { cookie: 'tokenlock_pass=' + GOOD } }));
  assert.equal(r.headers.get('x-middleware-next'), '1');
  r = await mw(new NextRequest('https://example.com/members/a', { headers: { cookie: 'tokenlock_pass=' + FORGED } }));
  assert.equal(r.status, 307); assert.match(r.headers.get('set-cookie'), /Max-Age=0/);
  r = await mw(new NextRequest('https://example.com/signin'));
  assert.equal(r.headers.get('x-middleware-next'), '1');
});
test('next: route handlers exchange pass and sign out', async () => {
  core.clearCache();
  const { GET, POST } = nx.tokenlockRoutes({ secretKey: SK, fetch: mockFetch() });
  const mk = (pass, origin = 'https://example.com') => new Request('https://example.com/api/tokenlock/session', { method: 'POST', headers: { 'content-type': 'application/json', origin }, body: JSON.stringify({ pass }) });
  let r = await POST(mk(GOOD)); assert.equal(r.status, 200); assert.match(r.headers.get('set-cookie'), /HttpOnly; Secure; SameSite=Lax/);
  assert.equal((await POST(mk(FORGED))).status, 401);
  assert.equal((await POST(mk(GOOD, 'https://evil.example'))).status, 403);
  r = await GET(new Request('https://example.com/api/tokenlock/signout')); assert.equal(r.status, 303); assert.match(r.headers.get('set-cookie'), /Max-Age=0/);
  const g = await nx.getPass(new Request('https://example.com/x', { headers: { cookie: 'tokenlock_pass=' + GOOD } }), { secretKey: SK, fetch: mockFetch(), identityOnly: true });
  assert.equal(g.address, 'bc1qtest');
});
test('react: renders a button with the default label', async () => {
  const React = await import('react');
  const { renderToStaticMarkup } = await import('react-dom/server');
  const { SignInWithBitcoin } = await import('../dist/react.js');
  const html = renderToStaticMarkup(React.createElement(SignInWithBitcoin, { siteKey: 'pk_x' }));
  assert.match(html, /<button[^>]*>Sign in with your Token<\/button>/);
});

// ------------------------------------------------ 0.2.0: enterprise access controls
const ENT_PASS = 'pp1.' + 'E'.repeat(40) + '.' + 'Q'.repeat(43);
function accessFetch(calls = [], state = { revoked: false }) {
  return async (url, init = {}) => {
    const body = init.body ? JSON.parse(init.body) : {};
    calls.push({ url, body, sdk: init.headers?.['x-tokenlock-sdk'] });
    const J = (o) => new Response(JSON.stringify(o), { status: 200, headers: { 'content-type': 'application/json' } });
    const base = { address: 'bc1qagent', assets_held: ['TOKENLOCK'], site_id: 's1', origin: 'https://example.com', expires_at: future(), correlation_id: 'c0ffee' };
    const resource = { path: body.path ?? null, method: body.method ?? null, environment: body.environment ?? null };
    const access = (allowed, reason) => ({ mode: 'registered_keys', allowed, reason, key: { id: 'key_1', label: 'bot', owner_type: 'agent', owner_name: 'Ops', org_id: null }, permissions: { routes: ['/api/*'], methods: ['GET'], environments: [] }, key_expires_at: null, resource });
    if (state.revoked) return J({ valid: false, allowed: false, code: 'key_revoked', reason: 'This key was revoked by the site admin.', ...base, access: access(false, 'key_revoked'), cache_max_s: 0 });
    if (body.path && !body.path.startsWith('/api/')) return J({ valid: false, allowed: false, code: 'route_not_allowed', reason: 'This key is not allowed on this route.', ...base, access: access(false, 'route_not_allowed'), cache_max_s: 0 });
    if (state.noEcho) return J({ valid: true, allowed: true, ...base, access: { ...access(true, 'ok'), resource: undefined }, cache_max_s: 5 });
    if (state.lie) return J({ valid: true, allowed: true, ...base, access: { ...access(true, 'ok'), resource: { ...resource, path: '/api/other' } }, resource: { ...resource, path: '/api/other' }, cache_max_s: 5 });
    return J({ valid: true, allowed: true, ...base, access: access(true, 'ok'), resource, cache_max_s: 5 });
  };
}
test('0.2.0 verifyPass: sends path/method/environment + SDK header; returns access; cache keyed by resource', async () => {
  core.clearCache(); const calls = [];
  const c = new core.TokenlockClient({ secretKey: SK, fetch: accessFetch(calls) });
  const a = await c.verifyPass(ENT_PASS, { path: '/api/x?q=1', method: 'get', environment: 'production' });
  assert.equal(a.valid, true); assert.equal(a.access.key.owner_type, 'agent'); assert.equal(a.correlation_id, 'c0ffee');
  assert.deepEqual({ path: calls[0].body.path, method: calls[0].body.method, environment: calls[0].body.environment }, { path: '/api/x', method: 'GET', environment: 'production' });
  assert.equal(calls[0].sdk, 'js/' + core.VERSION);
  const d = await c.verifyPass(ENT_PASS, { path: '/admin', method: 'GET' });
  assert.equal(d.valid, false); assert.equal(d.code, 'route_not_allowed');
  assert.equal(calls.length, 2, 'a different resource is not served from cache');
  await c.verifyPass(ENT_PASS, { path: '/api/x', method: 'GET', environment: 'production' });
  assert.equal(calls.length, 3, 'strict (default with a resource): registered-key answers are never cached');
  // 0.4.2: loose mode (strict: false) was removed; it is a configuration error, never a cached/looser answer
  assert.throws(() => new core.TokenlockClient({ secretKey: SK, fetch: accessFetch(calls), strict: false }), (e) => e.code === 'bad_config');
});
test('0.2.0 revocation (0.4.2: always strict): a revoked key fails on the very next check, registered-key answers are never cached', async () => {
  core.clearCache(); const calls = []; const st = { revoked: false };
  const c = new core.TokenlockClient({ secretKey: SK, fetch: accessFetch(calls, st) });
  assert.equal((await c.verifyPass(ENT_PASS, { path: '/api/x', method: 'GET' })).valid, true);
  st.revoked = true;
  const r = await c.verifyPass(ENT_PASS, { path: '/api/x', method: 'GET' }); assert.equal(r.valid, false); assert.equal(r.code, 'key_revoked');
  assert.equal(calls.length, 2);
});
test('0.2.0 functional verifyPass(pass, { secretKey, path, method }) and allowed:false is never valid', async () => {
  core.clearCache(); const calls = [];
  const r = await core.verifyPass(ENT_PASS, { secretKey: SK, fetch: accessFetch(calls), path: '/nope', method: 'POST' });
  assert.equal(r.valid, false); assert.equal(calls[0].body.method, 'POST');
});
test('0.2.0 express: path + method sent; out-of-scope route → 403 JSON (no redirect, cookie kept)', async () => {
  core.clearCache(); const calls = [];
  const mw = ex.tokenlock({ protect: ['/:path*'], publicPaths: ['/signin'], signInPage: '/signin', secretKey: SK, fetch: accessFetch(calls), environment: 'production' });
  await withServer(mw, async (b) => {
    let r = await fetch(b + '/api/data', { headers: { cookie: 'tokenlock_pass=' + ENT_PASS } });
    assert.equal(r.status, 200);
    assert.equal(calls.at(-1).body.path, '/api/data'); assert.equal(calls.at(-1).body.method, 'GET'); assert.equal(calls.at(-1).body.environment, 'production');
    r = await fetch(b + '/admin', { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + ENT_PASS } });
    assert.equal(r.status, 403); assert.equal(r.headers.get('set-cookie'), null);
    const j = await r.json(); assert.equal(j.code, 'route_not_allowed'); assert.equal(j.correlation_id, 'c0ffee');
  });
});
test('0.4.0 token-only answers: identity-only checks behave like 0.1.x; a resource check is policy_required', async () => {
  core.clearCache(); const calls = [];
  const c = new core.TokenlockClient({ secretKey: SK, fetch: mockFetch(calls) });
  const r = await c.verifyPass(GOOD, { identityOnly: true });
  assert.equal(r.valid, true); assert.equal(r.access, undefined);
  await c.verifyPass(GOOD, { identityOnly: true }); assert.equal(calls.length, 1, 'token-only identity answers: 60 s cache when the server sends no cache_max_s');
  await c.verifyPass(GOOD, { identityOnly: true }, { cache: false }); assert.equal(calls.length, 2, 'cache: false → always asks');
  const x = await c.verifyPass(GOOD, { path: '/members', method: 'GET' });
  assert.equal(x.valid, false); assert.equal(x.allowed, false); assert.equal(x.code, 'policy_required'); assert.equal(x.identity_valid, true);
  assert.equal(calls.at(-1).body.path, '/members');
});
test('0.4.0 middleware: token-only site without tokenOnly → 403 policy_required (warned once); with tokenOnly → identity check, no resource sent', async () => {
  core.clearCache(); const calls = []; const warns = []; const w = console.warn; console.warn = (m) => warns.push(String(m));
  try {
    const mw = ex.tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', secretKey: SK, fetch: mockFetch(calls) });
    await withServer(mw, async (b) => {
      const r = await fetch(b + '/members/x', { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + GOOD } });
      assert.equal(r.status, 403); assert.equal((await r.json()).code, 'policy_required');
      await fetch(b + '/members/y', { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + GOOD } });
    });
    assert.equal(warns.filter((m) => /tokenOnly: true/.test(m)).length, 1);
  } finally { console.warn = w; }
  core.clearCache(); const c2 = [];
  const mw2 = ex.tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', secretKey: SK, fetch: mockFetch(c2), tokenOnly: true });
  await withServer(mw2, async (b) => {
    const r = await fetch(b + '/members/x', { headers: { cookie: 'tokenlock_pass=' + GOOD } });
    assert.equal(r.status, 200);
  });
  assert.ok(c2.every((c) => c.body.path === undefined), 'tokenOnly: identity-only check (no resource sent)');
});
test('0.4.0 middleware: tokenOnly on a registered-keys site still enforces routes (no bypass)', async () => {
  core.clearCache(); const calls = [];
  const mw = ex.tokenlock({ protect: ['/:path*'], publicPaths: ['/signin'], signInPage: '/signin', secretKey: SK, fetch: accessFetch(calls), environment: 'production', tokenOnly: true });
  await withServer(mw, async (b) => {
    let r = await fetch(b + '/api/data', { headers: { cookie: 'tokenlock_pass=' + ENT_PASS } });
    assert.equal(r.status, 200);
    r = await fetch(b + '/admin', { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + ENT_PASS } });
    assert.equal(r.status, 403); assert.equal((await r.json()).code, 'route_not_allowed');
  });
});
const DOWN = 'pp1.' + 'D'.repeat(40) + '.' + 'Q'.repeat(43);
test('0.2.0 availability: API down → express fails closed with 503 + Retry-After, cookie kept; failOpen is a config error (0.4.2)', async () => {
  core.clearCache();
  const down = async () => { throw new TypeError('fetch failed'); };
  const mw = ex.tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', secretKey: SK, fetch: down });
  await withServer(mw, async (b) => {
    const r = await fetch(b + '/members/x', { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + DOWN } });
    assert.equal(r.status, 503); assert.equal(r.headers.get('retry-after'), '15'); assert.equal(r.headers.get('set-cookie'), null);
    assert.equal((await r.json()).code, 'tokenlock_unavailable');
    const n = await fetch(b + '/members/x', { redirect: 'manual' }); assert.equal(n.status, 302, 'no pass → still sign-in');
  });
  // 0.4.2: failOpen was removed; passing it (any value) is a configuration error
  for (const v of [true, false]) assert.throws(() => ex.tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', secretKey: SK, fetch: down, failOpen: v }), (e) => e.code === 'bad_config');
  // a 5xx from the API counts as unavailable; a "no" (valid:false) never fails open
  const five = async () => new Response('{"error":"busy","code":"kv_unavailable"}', { status: 503, headers: { 'content-type': 'application/json' } });
  assert.equal(core.isUnavailable(await new core.TokenlockClient({ secretKey: SK, fetch: five }).verifyPass(DOWN, { identityOnly: true }).catch((e) => e)), true);
  const mw2 = ex.tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', secretKey: SK, fetch: mockFetch(), tokenOnly: true });
  await withServer(mw2, async (b) => { const r = await fetch(b + '/members/x', { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + FORGED } }); assert.equal(r.status, 302); });
});
test('0.2.0 availability: next middleware 503 when API down; failOpen is a config error (0.4.2)', async () => {
  core.clearCache();
  const down = async () => { throw new TypeError('fetch failed'); };
  const req = (p) => { const u = new URL('https://example.com' + p); return { url: u.toString(), nextUrl: u, method: 'GET', headers: new Headers({ cookie: 'tokenlock_pass=' + DOWN }), cookies: { get: (n) => (n === 'tokenlock_pass' ? { value: DOWN } : undefined) } }; };
  const r = await nx.tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', secretKey: SK, fetch: down })(req('/members/a'));
  assert.equal(r.status, 503);
  assert.throws(() => nx.tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', secretKey: SK, fetch: down, failOpen: true }), (e) => e.code === 'bad_config');
});
