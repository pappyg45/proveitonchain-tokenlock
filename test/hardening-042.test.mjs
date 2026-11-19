// 0.4.2 security-hardening regression tests. Written BEFORE the fixes: against 0.4.1 the "cannot grant access" tests
// show the removed opt-outs letting requests through, and the denial-matrix tests show each malformed, conflicting,
// stale or invalid input that was accepted. Every test asserts the 0.4.2 contract: protected content is never served,
// removed or unknown options are a startup (config) error, and any ambiguity is a denial.
// Throwaway keys only. No network: every API answer is a local stub.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1.js';
import * as core from '../dist/index.js';
import * as ex from '../dist/express.js';
import * as nx from '../dist/next.js';
import * as sv from '../dist/self-verify.js';
import * as cf from '../examples/cloudflare-worker/worker.js';

const SK = 'sk_' + 'h'.repeat(43);
const PASS = 'pp1.' + 'H'.repeat(40) + '.' + 'Q'.repeat(43);
const future = (ms = 3600e3) => new Date(Date.now() + ms).toISOString();
const J = (o, s = 200) => new Response(typeof o === 'string' ? o : JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });
const base = () => ({ address: 'bc1qagent', assets_held: ['TOKENLOCK'], site_id: 's1', origin: 'https://example.com', expires_at: future(), correlation_id: 'cid' });
const echo = (b) => ({ path: b.path ?? null, method: b.method ?? null, environment: b.environment ?? null });
const accessOk = (b, extra = {}) => ({ mode: 'registered_keys', allowed: true, reason: 'ok', key: { id: 'k1', label: 'k', owner_type: 'agent', owner_name: null, org_id: null }, permissions: { routes: ['/members/*'], methods: ['GET'], environments: ['production'] }, key_expires_at: null, ...(b.path || b.method || b.environment ? { resource: echo(b) } : {}), ...extra });
// Registered-keys site: the key may GET /members/* in production. Identity checks (no resource) are allowed.
function registered(b) {
  const deny = (code) => ({ valid: false, allowed: false, code, reason: code, ...base(), access: { ...accessOk(b), allowed: false, reason: code }, resource: echo(b), cache_max_s: 0 });
  if (!b.path && !b.method && !b.environment) return { valid: true, allowed: true, ...base(), access: accessOk(b), cache_max_s: 5 };
  const p = String(b.path || '').toLowerCase();
  if (b.path && !(p === '/members' || p.startsWith('/members/'))) return deny('route_not_allowed');
  if (b.method && b.method !== 'GET') return deny('method_not_allowed');
  if (b.environment && b.environment !== 'production') return deny('environment_not_allowed');
  return { valid: true, allowed: true, ...base(), access: accessOk(b), resource: echo(b), cache_max_s: 5 };
}
const tokenOnlySite = (b) => (b.path || b.method || b.environment
  ? { valid: false, allowed: false, identity_valid: true, code: 'policy_required', reason: 'no policy', ...base(), access: { mode: 'token', allowed: false, reason: 'policy_required' }, resource: echo(b), cache_max_s: 0 }
  : { valid: true, ...base() });
// fetch stub: answer(b) → object (JSON) | Response | 'down' | 'hang'
function stub(answer, calls = []) {
  return async (url, init = {}) => {
    const b = JSON.parse(init.body || '{}'); calls.push(b);
    const a = answer(b);
    if (a === 'down') throw new TypeError('fetch failed');
    if (a === 'hang') return new Promise((_, no) => init.signal?.addEventListener('abort', () => no(Object.assign(new Error('aborted'), { name: 'AbortError' }))));
    return a instanceof Response ? a : J(a);
  };
}
async function withServer(mw, fn) {
  const s = http.createServer((req, res) => mw(req, res, (e) => { if (e) { res.statusCode = 500; return res.end('ERROR ' + (e.code || '')); } res.end('SECRET ' + req.url); }));
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  try { return await fn('http://127.0.0.1:' + s.address().port); } finally { s.close(); }
}
const get = async (b, p) => { const r = await fetch(b + p, { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + PASS, accept: 'application/json' } }); return { status: r.status, text: await r.text() }; };
const served = (r) => r.status === 200 && r.text.startsWith('SECRET');
const nreq = (p, method = 'GET') => { const u = new URL('https://example.com' + p); return { url: u.toString(), nextUrl: u, method, headers: new Headers({ cookie: 'tokenlock_pass=' + PASS, accept: 'application/json' }), cookies: { get: (n) => (n === 'tokenlock_pass' ? { value: PASS } : undefined) } }; };
const nextServed = (r) => r.headers.get('x-middleware-next') === '1';
const attempt = (f) => { try { return { v: f() }; } catch (e) { return { e }; } };
const isConfigError = (r, re) => r.e && r.e.code === 'bad_config' && (!re || re.test(r.e.message));
const quiet = async (f) => { const w = console.warn; console.warn = () => {}; try { return await f(); } finally { console.warn = w; } };
const G = (o = {}) => ({ protect: ['/members/:path*', '/private/:path*'], signInPage: '/signin', secretKey: SK, ...o });

// ============================================================ (a) failOpen
test('(a) failOpen cannot grant access when the API is down (Express)', async () => {
  core.clearCache();
  const r = await quiet(() => attempt(() => ex.tokenlock(G({ fetch: stub(() => 'down'), failOpen: true }))));
  if (r.e) return assert.ok(isConfigError(r, /failOpen/), 'rejected with bad_config');
  await withServer(r.v, async (b) => { const g = await get(b, '/members/x'); assert.ok(!served(g), `failOpen served protected content during an outage: ${g.status} ${g.text.slice(0, 40)}`); });
});
test('(a) failOpen cannot grant access when the API is down (Next.js)', async () => {
  core.clearCache();
  const r = await quiet(() => attempt(() => nx.tokenlock(G({ fetch: stub(() => 'down'), failOpen: true }))));
  if (r.e) return assert.ok(isConfigError(r, /failOpen/));
  const res = await r.v(nreq('/members/x'));
  assert.ok(!nextServed(res), `failOpen let the request through: x-tokenlock=${res.headers.get('x-tokenlock')}`);
});
test('(a) failOpen is a removed option: any value is a startup error (Express, Next.js, client)', async () => {
  for (const v of [true, false, 'true', 1]) {
    assert.ok(isConfigError(await quiet(() => attempt(() => ex.tokenlock(G({ failOpen: v })))), /failOpen/), 'express failOpen=' + JSON.stringify(v));
    assert.ok(isConfigError(await quiet(() => attempt(() => nx.tokenlock(G({ failOpen: v })))), /failOpen/), 'next failOpen=' + JSON.stringify(v));
  }
  assert.ok(isConfigError(attempt(() => new core.TokenlockClient({ secretKey: SK, failOpen: true })), /failOpen/), 'client');
});

// ============================================================ (b) checkResource:false (and loose mode)
test('(b) checkResource:false cannot skip the route check on a registered-keys site (Express)', async () => {
  core.clearCache();
  const r = await quiet(() => attempt(() => ex.tokenlock(G({ fetch: stub(registered), checkResource: false }))));
  if (r.e) return assert.ok(isConfigError(r, /checkResource/));
  await withServer(r.v, async (b) => { const g = await get(b, '/private/payroll'); assert.ok(!served(g), `checkResource:false served a route the key is not allowed on: ${g.status} ${g.text.slice(0, 40)}`); });
});
test('(b) checkResource:false cannot skip the route check (Next.js)', async () => {
  core.clearCache();
  const r = await quiet(() => attempt(() => nx.tokenlock(G({ fetch: stub(registered), checkResource: false }))));
  if (r.e) return assert.ok(isConfigError(r, /checkResource/));
  const res = await r.v(nreq('/private/payroll'));
  assert.ok(!nextServed(res), 'checkResource:false let /private/payroll through');
});
test('(b) checkResource is a removed option: any value is a startup error', async () => {
  for (const v of [false, true, 'false', 0]) {
    assert.ok(isConfigError(await quiet(() => attempt(() => ex.tokenlock(G({ checkResource: v })))), /checkResource/), 'express checkResource=' + JSON.stringify(v));
    assert.ok(isConfigError(await quiet(() => attempt(() => nx.tokenlock(G({ checkResource: v })))), /checkResource/), 'next checkResource=' + JSON.stringify(v));
  }
});
test('(b) strict:false (loose mode) is removed: middleware and client refuse it at startup', async () => {
  assert.ok(isConfigError(await quiet(() => attempt(() => ex.tokenlock(G({ strict: false })))), /strict/));
  assert.ok(isConfigError(await quiet(() => attempt(() => nx.tokenlock(G({ strict: false })))), /strict/));
  assert.ok(isConfigError(attempt(() => new core.TokenlockClient({ secretKey: SK, strict: false })), /strict/));
});
test('(b) loose mode cannot accept an answer with no resource echo for a resource check', async () => {
  core.clearCache();
  const answer = (b) => ({ valid: true, allowed: true, ...base(), access: { mode: 'registered_keys', allowed: true, reason: 'ok' } }); // no echo
  const c = attempt(() => new core.TokenlockClient({ secretKey: SK, fetch: stub(answer), strict: false }));
  if (c.e) return assert.ok(isConfigError(c));
  const v = await c.v.verifyPass(PASS, { path: '/private/x', method: 'GET' }).catch((e) => e);
  assert.notEqual(v?.valid, true, 'loose mode accepted a resource answer that never named the resource');
  const v2 = await core.verifyPass(PASS, { secretKey: SK, fetch: stub(answer), path: '/private/x', method: 'GET', strict: false }).catch((e) => e);
  assert.notEqual(v2?.valid, true, 'verifyPass({ strict:false }) accepted it');
});

// ============================================================ invalid configuration
test('config: a missing or malformed secret key is a startup error', async () => {
  const saved = process.env.TOKENLOCK_SECRET_KEY; delete process.env.TOKENLOCK_SECRET_KEY;
  try {
    assert.ok(isConfigError(attempt(() => ex.tokenlock(G({ secretKey: undefined })))), 'missing');
    for (const k of ['', 'pk_' + 'a'.repeat(43), 'sk_short', 'Bearer sk_' + 'a'.repeat(43), 123]) assert.ok(isConfigError(attempt(() => ex.tokenlock(G({ secretKey: k })))), 'bad key ' + JSON.stringify(k));
    assert.ok(isConfigError(attempt(() => new core.TokenlockClient({ secretKey: 'pk_' + 'a'.repeat(43) }))), 'client');
  } finally { if (saved !== undefined) process.env.TOKENLOCK_SECRET_KEY = saved; }
});
test('config: unknown options (typos) are a startup error, never silently ignored', async () => {
  for (const o of [{ tokenonly: true }, { failopen: true }, { checkresource: false }, { bypass: true }, { protected: ['/x'] }, { publicPath: ['/members'] }]) {
    assert.ok(isConfigError(attempt(() => ex.tokenlock(G(o)))), 'express ' + JSON.stringify(o));
    assert.ok(isConfigError(attempt(() => nx.tokenlock(G(o)))), 'next ' + JSON.stringify(o));
  }
});
test('config: wrong types are a startup error (tokenOnly:"false" must not turn token-only mode on)', async () => {
  core.clearCache();
  // On a token-only site, tokenOnly:'false' (a string) was truthy in 0.4.1 and let every holder in.
  const r = attempt(() => ex.tokenlock(G({ fetch: stub(tokenOnlySite), tokenOnly: 'false' })));
  if (!r.e) await withServer(r.v, async (b) => { const g = await get(b, '/members/x'); assert.ok(!served(g), `tokenOnly:'false' served protected content: ${g.status}`); });
  else assert.ok(isConfigError(r));
  for (const o of [{ tokenOnly: 'yes' }, { tokenOnly: 1 }, { caseSensitive: 'no' }, { strict: 'true' }, { cache: 'off' }, { environment: 7 }, { timeoutMs: -1 }, { timeoutMs: 'fast' }, { timeoutMs: Infinity }, { apiBase: 'ftp://example.com' }, { apiBase: 'not a url' }, { signInPage: 42 }, { signInPage: '' }]) {
    assert.ok(isConfigError(attempt(() => ex.tokenlock(G(o)))), 'express ' + JSON.stringify(o));
  }
});
test('config: protect must name at least one path; a missing protect list is a startup error, not "nothing is locked"', async () => {
  for (const p of [undefined, [], '', [''], [null], 5]) assert.ok(isConfigError(attempt(() => ex.tokenlock(G({ protect: p })))), 'protect=' + JSON.stringify(p));
  assert.ok(isConfigError(attempt(() => ex.tokenlock(G({ signInPage: undefined })))), 'signInPage missing');
});
test('config: verifyPass / getPass / authorize refuse removed options and strict:false', async () => {
  core.clearCache();
  const f = stub(registered);
  for (const o of [{ strict: false }, { failOpen: true }, { checkResource: false }]) {
    const r = await core.verifyPass(PASS, { secretKey: SK, fetch: f, path: '/private/x', method: 'GET', ...o }).then((v) => ({ v }), (e) => ({ e }));
    assert.ok((r.e && r.e.code === 'bad_config') || r.v?.valid === false, 'verifyPass ' + JSON.stringify(o));
    assert.ok(r.e && r.e.code === 'bad_config', 'verifyPass rejects ' + JSON.stringify(o) + ' as bad_config');
  }
});

// ============================================================ malformed backend responses
const MALFORMED = {
  'valid:"true" (string)': (b) => ({ ...registered(b), valid: 'true' }),
  'allowed:"true" (string)': (b) => ({ ...registered(b), allowed: 'true' }),
  'access.allowed:1': (b) => ({ ...registered(b), access: { ...accessOk(b), allowed: 1 } }),
  'access.mode missing': (b) => ({ ...registered(b), access: { ...accessOk(b), mode: undefined } }),
  'access:null': (b) => ({ ...registered(b), access: null }),
  'access:[] (array)': (b) => ({ ...registered(b), access: [] }),
  'missing address': (b) => { const x = registered(b); delete x.address; return x; },
  'address is a number': (b) => ({ ...registered(b), address: 12345 }),
  'missing site_id': (b) => { const x = registered(b); delete x.site_id; return x; },
  'missing expires_at': (b) => { const x = registered(b); delete x.expires_at; return x; },
  'expires_at garbage': (b) => ({ ...registered(b), expires_at: 'tomorrow' }),
  'expires_at in the past': (b) => ({ ...registered(b), expires_at: new Date(Date.now() - 1000).toISOString() }),
  'missing resource echo': (b) => { const x = registered(b); delete x.resource; delete x.access.resource; return x; },
  'resource echo not an object': (b) => ({ ...registered(b), resource: '/members/x', access: { ...accessOk(b), resource: '/members/x' } }),
  'extra fields claiming allowed on a deny': (b) => ({ valid: false, allowed: true, authorized: true, granted: true, ...base(), access: { ...accessOk(b), allowed: true }, resource: echo(b) }),
  'JSON array': () => [registered({})],
  'JSON null': () => J('null'),
  'JSON string': () => J('"valid"'),
  'non-JSON 200': () => J('<html>ok</html>'),
  'empty 200': () => J(''),
  'oversized 200 (1 MiB, otherwise valid)': (b) => J(JSON.stringify({ ...registered(b), pad: 'x'.repeat(1 << 20) })),
};
const CONFLICTING = {
  'valid:true with code key_revoked': (b) => ({ ...registered(b), code: 'key_revoked' }),
  'valid:true allowed:true with code policy_required': (b) => ({ ...registered(b), code: 'policy_required' }),
  'valid:true with error': (b) => ({ ...registered(b), error: 'Unknown secret key.' }),
  'valid:true with identity_valid:false': (b) => ({ ...registered(b), identity_valid: false }),
  'allowed:true but access.allowed:false': (b) => ({ ...registered(b), access: { ...accessOk(b), allowed: false, reason: 'key_revoked' } }),
  'access.allowed:true but allowed:false': (b) => ({ ...registered(b), allowed: false }),
  'access.reason route_not_allowed with allowed:true': (b) => ({ ...registered(b), access: { ...accessOk(b), reason: 'route_not_allowed' } }),
  'top echo matches, access echo names another path': (b) => ({ ...registered(b), access: { ...accessOk(b), resource: { ...echo(b), path: '/members' } } }),
  'access echo matches, top echo names another method': (b) => ({ ...registered(b), resource: { ...echo(b), method: 'POST' } }),
  'hosted echoes a different path than Node asked (Node vs hosted disagreement)': (b) => ({ ...registered(b), resource: { ...echo(b), path: '/members' }, access: { ...accessOk(b), resource: { ...echo(b), path: '/members' } } }),
  'hosted echoes a different environment': (b) => ({ ...registered(b), resource: { ...echo(b), environment: 'staging' }, access: { ...accessOk(b), resource: { ...echo(b), environment: 'staging' } } }),
  'access.mode token with allowed:true': (b) => ({ ...registered(b), access: { ...accessOk(b), mode: 'token' } }),
};
for (const [group, table] of [['malformed', MALFORMED], ['conflicting', CONFLICTING]]) {
  test(`${group} backend answers are denied by the client (resource check)`, async () => {
    const bad = [];
    for (const [name, fn] of Object.entries(table)) {
      core.clearCache();
      const c = new core.TokenlockClient({ secretKey: SK, fetch: stub(fn), cache: false });
      const v = await c.verifyPass(PASS, { path: '/members/x', method: 'GET', environment: 'production' }).catch((e) => ({ thrown: e.code || e.message }));
      if (v.valid === true) bad.push(name);
    }
    assert.deepEqual(bad, [], 'accepted: ' + bad.join(' | '));
  });
  test(`${group} backend answers never serve protected content (Express)`, async () => {
    const bad = [];
    for (const [name, fn] of Object.entries(table)) {
      core.clearCache();
      const mw = ex.tokenlock(G({ fetch: stub(fn), environment: 'production', cache: false }));
      await withServer(mw, async (b) => { const g = await get(b, '/members/x'); if (served(g)) bad.push(name); });
    }
    assert.deepEqual(bad, [], 'served: ' + bad.join(' | '));
  });
  test(`${group} backend answers never reach the origin (Cloudflare worker)`, async () => {
    const bad = [];
    for (const [name, fn] of Object.entries(table)) {
      const r = await cfRun(fn, '/members/x');
      if (r.origin) bad.push(name);
    }
    assert.deepEqual(bad, [], 'origin reached: ' + bad.join(' | '));
  });
}
test('malformed identity answers are denied too (identity-only check and tokenOnly middleware)', async () => {
  const cases = {
    'allowed:"false" (string) on an identity check': () => ({ valid: true, allowed: 'false', ...base() }),
    'allowed:0 on an identity check': () => ({ valid: true, allowed: 0, ...base() }),
    'valid:true with code not_holder': () => ({ valid: true, code: 'not_holder', ...base() }),
    'valid:1': () => ({ valid: 1, ...base() }),
    'expires_at garbage': () => ({ valid: true, ...base(), expires_at: 'soon' }),
    'missing expires_at': () => { const x = { valid: true, ...base() }; delete x.expires_at; return x; },
  };
  const bad = [];
  for (const [name, fn] of Object.entries(cases)) {
    core.clearCache();
    const v = await new core.TokenlockClient({ secretKey: SK, fetch: stub(fn), cache: false }).verifyPass(PASS).catch(() => ({}));
    if (v.valid === true) bad.push('client: ' + name);
    const mw = ex.tokenlock(G({ fetch: stub(fn), tokenOnly: true, cache: false }));
    await withServer(mw, async (b) => { if (served(await get(b, '/members/x'))) bad.push('express tokenOnly: ' + name); });
    const r = await cfRun(fn, '/members/x', { TOKENLOCK_TOKEN_ONLY: '1' });
    if (r.origin) bad.push('cf tokenOnly: ' + name);
  }
  assert.deepEqual(bad, [], 'accepted: ' + bad.join(' | '));
});
test('conflicting decisions: identity allowed but route denied → denied (tokenOnly on a registered-keys site)', async () => {
  core.clearCache();
  const mw = ex.tokenlock(G({ fetch: stub(registered), tokenOnly: true, environment: 'production' }));
  await withServer(mw, async (b) => {
    const g = await get(b, '/private/payroll'); assert.ok(!served(g)); assert.equal(g.status, 403); assert.equal(JSON.parse(g.text).code, 'route_not_allowed');
    assert.ok(served(await get(b, '/members/ok')), 'a permitted route still works');
  });
  const r = await cfRun(registered, '/private/payroll', { TOKENLOCK_TOKEN_ONLY: '1', TOKENLOCK_PROTECT: '/members,/private' });
  assert.equal(r.origin, false); assert.equal(r.status, 403);
});

// ============================================================ Cloudflare worker: config + outage
const CF_ENV = { TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_SITE_KEY: 'pk_x', TOKENLOCK_API: 'https://api.test', TOKENLOCK_ENVIRONMENT: 'production', TOKENLOCK_PROTECT: '/members,/private' };
async function cfRun(answer, path, envExtra = {}, { timeoutMs = 4000 } = {}) {
  const env = { ...CF_ENV, ...envExtra };
  for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
  let origin = false; const real = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = String(input?.url || input);
    if (url.startsWith('https://api.test')) { const b = JSON.parse(init.body || '{}'); const a = answer(b); if (a === 'down') throw new TypeError('fetch failed'); if (a === 'hang') return new Promise((_, no) => init.signal?.addEventListener('abort', () => no(Object.assign(new Error('The operation was aborted'), { name: 'TimeoutError' })))); return a instanceof Response ? a : J(a); }
    origin = true; return new Response('ORIGIN SECRET');
  };
  try {
    const req = new Request('https://site.example' + path, { headers: { cookie: 'tokenlock_pass=' + PASS, accept: 'application/json' } });
    const res = await Promise.race([cf.default.fetch(req, env), new Promise((r) => setTimeout(() => r('HUNG'), timeoutMs))]);
    if (res === 'HUNG') return { hung: true, origin, status: 0 };
    return { origin, status: res.status, body: await res.text() };
  } finally { globalThis.fetch = real; }
}
test('Cloudflare worker: removed / unknown / invalid settings are a configuration error (500), origin never reached', async () => {
  const bad = [];
  for (const e of [{ TOKENLOCK_FAIL_OPEN: '1' }, { TOKENLOCK_FAIL_OPEN: '0' }, { TOKENLOCK_CHECK_RESOURCE: '0' }, { TOKENLOCK_STRICT: '0' }, { TOKENLOCK_SECRET_KEY: undefined }, { TOKENLOCK_SECRET_KEY: 'pk_' + 'a'.repeat(43) }, { TOKENLOCK_TOKEN_ONLY: 'true' }, { TOKENLOCK_TOKEN_ONLY: 'yes' }, { TOKENLOCK_TIMEOUT_MS: 'fast' }, { TOKENLOCK_TIMEOUT_MS: '0' }, { TOKENLOCK_API: 'ftp://x' }]) {
    const r = await cfRun(registered, '/members/x', e);
    if (r.origin || r.status !== 500) bad.push(JSON.stringify(e) + ' → ' + r.status + (r.origin ? ' ORIGIN' : ''));
  }
  assert.deepEqual(bad, [], bad.join(' | '));
  const ok = await cfRun(registered, '/members/x');
  assert.equal(ok.origin, true, 'a valid configuration still works');
});
test('Cloudflare worker: a hung API is cut off by a fetch timeout and answered 503 (no hang, nothing served)', async () => {
  const r = await cfRun(() => 'hang', '/members/x', { TOKENLOCK_TIMEOUT_MS: '300' }, { timeoutMs: 3000 });
  assert.equal(r.hung, undefined, 'the worker hung waiting for the API');
  assert.equal(r.origin, false); assert.equal(r.status, 503);
});
test('Cloudflare worker: API down / 5xx / 4xx → denied, origin never reached', async () => {
  for (const a of ['down', J({ error: 'x' }, 500), J({ error: 'x' }, 503), J({ error: 'x', code: 'rate_limited' }, 429), J({ valid: false, code: 'bad_secret_key' }, 401)]) {
    const r = await cfRun(() => a, '/members/x');
    assert.equal(r.origin, false); assert.ok(r.status >= 400);
  }
});

// ============================================================ self-verify: stale, rolled-back and malformed policies
const PRIV = randomBytes(32); const PUB = Buffer.from(schnorr.getPublicKey(PRIV)).toString('hex');
const sha = (b) => createHash('sha256').update(b).digest();
const tagged = (tag, msg) => { const t = sha(Buffer.from(tag)); return sha(Buffer.concat([t, t, msg])); };
const bundle = (p) => { const bytes = Buffer.from(JSON.stringify(p)); return { v: 1, typ: 'tokenlock.policy-bundle', alg: 'BIP340', kid: 'k1', payload: bytes.toString('base64url'), sig: Buffer.from(schnorr.sign(tagged('TOKENLOCK/policy/v1', bytes), PRIV)).toString('hex') }; };
const ADDR = 'bc1qagentaddressxxxxxxxxxxxxxxxxxxxxxxxx';
const KEY = (o = {}) => ({ id: 'key_a', address: ADDR, status: 'active', owner_type: 'agent', org_id: null, assets: [], permissions: { routes: ['/members/*'], methods: ['GET'], environments: ['production'] }, expires_at: null, pass_ttl_s: null, ...o });
const POL = (o = {}) => ({ v: 1, typ: 'tokenlock.policy', site_id: 'site1', seq: 1, issued_at: new Date(Date.now() - 1000).toISOString(), expires_at: future(600e3), mode: 'registered_keys', orgs: [], revoked_assets: [], keys: [KEY()], ...o });
const PASS_SECRET = randomBytes(32).toString('hex');
const localPass = (o = {}) => { const p = { sub: ADDR, h: ['TOKENLOCK'], k: 'key_a', n: 'n1', s: 'https://site1', i: Date.now(), e: Date.now() + 600e3, ...o }; const m = Buffer.from(JSON.stringify(p)).toString('base64url'); return 'tl3.' + m + '.' + createHmac('sha256', PASS_SECRET).update('tl3.' + m).digest('base64url'); };
const RES = { path: '/members/x', method: 'GET', environment: 'production' };
const vlp = (policy, resource = RES) => sv.verifyLocalPass(localPass(), { passSecret: PASS_SECRET, policy, resource }).catch((e) => ({ valid: false, thrown: e.code || String(e) }));

test('self-verify: a rolled-back policy bundle (lower seq) never replaces a newer one (revocation stays)', async () => {
  const seqs = [POL({ seq: 5, keys: [KEY({ status: 'revoked' })] }), POL({ seq: 3 })];
  let i = 0;
  const src = sv.signedPolicy({ siteId: 'site1', secretKey: SK, publicKeys: { k1: PUB }, refreshSeconds: 0, retryMinSeconds: 0.1, load: async () => bundle(seqs[Math.min(i++, 1)]) });
  const first = await vlp(src); assert.equal(first.code, 'key_revoked');
  await new Promise((r) => setTimeout(r, 150));
  const second = await vlp(src); assert.notEqual(second.valid, true, 'rolled-back bundle re-granted a revoked key'); assert.equal(src.status().seq, 5);
  assert.throws(() => sv.verifyPolicyBundle(bundle(POL({ seq: 3 })), { publicKeys: { k1: PUB }, siteId: 'site1', minSeq: 5 }), (e) => e.code === 'policy_rollback');
});
test('self-verify: stale and expired policies deny', async () => {
  assert.throws(() => sv.verifyPolicyBundle(bundle(POL({ expires_at: new Date(Date.now() - 1).toISOString() })), { publicKeys: { k1: PUB }, siteId: 'site1' }), (e) => e.code === 'policy_expired');
  assert.throws(() => sv.verifyPolicyBundle(bundle(POL({ issued_at: new Date(Date.now() - 7200e3).toISOString() })), { publicKeys: { k1: PUB }, siteId: 'site1', maxAgeSeconds: 3600 }), (e) => e.code === 'policy_stale');
  let n = 0;
  const src = sv.signedPolicy({ siteId: 'site1', secretKey: SK, publicKeys: { k1: PUB }, refreshSeconds: 0, retryMinSeconds: 0.05, load: async () => { if (n++ === 0) return bundle(POL({ expires_at: future(300) })); throw new Error('down'); } });
  assert.equal((await vlp(src)).valid, true, 'fresh bundle works');
  await new Promise((r) => setTimeout(r, 400));
  const v = await vlp(src); assert.equal(v.valid, false); assert.equal(v.code, 'policy_expired', 'cached bundle past expiry with the endpoint down');
});
test('self-verify: malformed policy bundles are rejected (policy_invalid), never evaluated', async () => {
  const bad = [];
  const cases = {
    'seq is a string': POL({ seq: '9' }), 'seq negative': POL({ seq: -1 }), 'seq fractional': POL({ seq: 1.5 }),
    'issued_at in the future': POL({ issued_at: future(3600e3) }), 'issued_at garbage': POL({ issued_at: 'yesterday' }),
    'expires before issued': POL({ issued_at: future(1000), expires_at: future(500) }),
    'mode typo': POL({ mode: 'registered-keys' }), 'mode missing': POL({ mode: undefined }),
    'keys not an array': POL({ keys: { a: KEY() } }), 'key permissions.routes is a string': POL({ keys: [KEY({ permissions: { routes: '/members/*', methods: ['GET'] } })] }),
    'key permissions.methods is a string': POL({ keys: [KEY({ permissions: { routes: ['/members/*'], methods: 'GET,POST' } })] }),
    'key expires_at garbage': POL({ keys: [KEY({ expires_at: 'never' })] }), 'key status unknown': POL({ keys: [KEY({ status: 'enabled' })] }),
    'revoked_assets not an array': POL({ revoked_assets: 'TOKENLOCK' }), 'orgs not an array': POL({ orgs: null }),
  };
  for (const [name, p] of Object.entries(cases)) {
    let threw = null; try { sv.verifyPolicyBundle(bundle(p), { publicKeys: { k1: PUB }, siteId: 'site1' }); } catch (e) { threw = e.code; }
    if (!threw) bad.push(name);
  }
  assert.deepEqual(bad, [], 'accepted: ' + bad.join(' | '));
});
test('self-verify: a malformed local policy denies (no typo, wrong type or bad date can grant access)', async () => {
  const bad = [];
  const cases = {
    'mode typo (would read as token mode)': { mode: 'registered-keys', keys: [KEY({ status: 'revoked' })] },
    'key expires_at garbage': { keys: [KEY({ expires_at: 'never' })] },
    'methods as a string (substring match)': { keys: [KEY({ permissions: { routes: ['/members/*'], methods: 'GETPOST', environments: ['production'] } })] },
    'routes as a string': { keys: [KEY({ permissions: { routes: '/members/*', methods: ['GET'], environments: ['production'] } })] },
    'environments as a string': { keys: [KEY({ permissions: { routes: ['/members/*'], methods: ['GET'], environments: 'productionx' } })] },
    'keys not an array': { keys: { 0: KEY() } },
  };
  for (const [name, p] of Object.entries(cases)) {
    const res = name.startsWith('methods') ? { ...RES, method: 'POST' } : RES;
    const v = await vlp(sv.localPolicy(p), res);
    if (v.allowed === true) bad.push(name); // resource check: `allowed` is the grant (`valid` alone = identity)
    const id = await vlp(sv.localPolicy(p), null);
    if (id.valid === true) bad.push(name + ' (identity)');
  }
  assert.deepEqual(bad, [], 'granted: ' + bad.join(' | '));
});
test('self-verify: malformed holdings answers fail closed (held must be the boolean true)', async () => {
  const bad = [];
  for (const [name, h] of Object.entries({ 'held:"false"': { held: 'false' }, 'held:1': { held: 1 }, 'held:"yes"': { held: 'yes' }, 'entry missing': undefined, 'entry is a string': 'held' })) {
    const p = sv.proveitonchainProvider({ api: 'https://api.test', fetch: async () => J({ holdings: h === undefined ? {} : { TOKENLOCK: h } }) });
    const r = await p.holdings(ADDR, ['TOKENLOCK']).catch((e) => ({ error: e.code }));
    if (r.TOKENLOCK?.held === true) bad.push(name);
  }
  assert.deepEqual(bad, [], 'read as held: ' + bad.join(' | '));
  // agreement compares the boolean, so "false" (string) vs false can't count as agreement on true
  const a = sv.staticProvider({ [ADDR]: ['TOKENLOCK'] });
  const b = { name: 'weird', async holdings() { return { TOKENLOCK: { held: 'false' } }; } };
  const r = await sv.requireAgreement([a, b]).holdings(ADDR, ['TOKENLOCK']).then(() => 'agreed', (e) => e.code);
  assert.notEqual(r, 'agreed', 'a malformed held value was treated as agreement');
});
test('self-verify: conflicting / rolled-back pass binding denies', async () => {
  const p = sv.localPolicy({ keys: [KEY({ id: 'key_b' })] });
  const v = await sv.verifyLocalPass(localPass({ k: 'key_a' }), { passSecret: PASS_SECRET, policy: p, resource: RES });
  assert.equal(v.valid, false); assert.equal(v.code, 'not_registered');
});
