// 0.4.3 security correction: strict authorization-request schema. Written BEFORE the fix; it fails against 0.4.2.
// A malformed authorization request (unknown field, wrong type, empty / whitespace-only / null value, malformed path,
// partial route/method) must be refused (bad_resource / bad_path) and must NEVER silently become an identity-only check.
// Identity-only verification stays supported, but only as an explicit request ({ identityOnly: true }).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import * as core from '../dist/index.js';
import * as ex from '../dist/express.js';
import * as nx from '../dist/next.js';
import * as sv from '../dist/self-verify.js';
import cfDefault from '../examples/cloudflare-worker/worker.js';

const SK = 'sk_' + 'h'.repeat(43);
const PASS = 'pp1.' + 'H'.repeat(40) + '.' + 'Q'.repeat(43);
const future = (ms = 3600e3) => new Date(Date.now() + ms).toISOString();
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });
const base = () => ({ address: 'bc1qagent', assets_held: ['TOKENLOCK'], site_id: 's1', origin: 'https://example.com', expires_at: future(), correlation_id: 'cid' });
const echo = (b) => ({ path: b.path ?? null, method: b.method ?? null, environment: b.environment ?? null });
const accessOk = (b) => ({ mode: 'registered_keys', allowed: true, reason: 'ok', key: { id: 'k1' }, permissions: { routes: ['/members/*'], methods: ['GET'], environments: ['production'] }, ...(b.path || b.method || b.environment ? { resource: echo(b) } : {}) });
// Registered-keys site (key may GET /members/* in production). An identity check (no route fields) is answered valid,
// so any client that downgrades a malformed request to identity-only shows up as valid:true.
function registered(b) {
  const deny = (code) => ({ valid: false, allowed: false, code, reason: code, ...base(), access: { ...accessOk(b), allowed: false, reason: code }, resource: echo(b) });
  if (b.path === undefined && b.method === undefined && b.environment === undefined) return { valid: true, allowed: true, ...base(), access: accessOk(b) };
  const p = String(b.path || '').toLowerCase();
  if (!(p === '/members' || p.startsWith('/members/'))) return deny('route_not_allowed');
  if (b.method !== 'GET') return deny('method_not_allowed');
  if (b.environment && b.environment !== 'production') return deny('environment_not_allowed');
  return { valid: true, allowed: true, ...base(), access: accessOk(b), resource: echo(b) };
}
function stub(calls = []) { return async (url, init = {}) => { const b = JSON.parse(init.body || '{}'); calls.push(b); return J(registered(b)); }; }
const OK = { path: '/members/x', method: 'GET', environment: 'production' };
// Malformed authorization requests (item 2) and inconsistent route/method combinations (item 3).
const MALFORMED = {
  'unknown field (typo pth)': { pth: '/members/x', method: 'GET' },
  'unknown field next to a valid resource': { ...OK, rout: '/admin' },
  'path array': { path: ['/members/x'], method: 'GET' },
  'path number': { path: 5, method: 'GET' },
  'path object': { path: { toString: () => '/members/x' }, method: 'GET' },
  'path empty string': { path: '', method: 'GET' },
  'path whitespace-only': { path: '   ', method: 'GET' },
  'path null': { path: null, method: 'GET' },
  'path undefined (key present)': { path: undefined, method: 'GET' },
  'path padded with spaces': { path: ' /members/x ', method: 'GET' },
  'path relative': { path: 'members/x', method: 'GET' },
  'method empty': { path: '/members/x', method: '' },
  'method whitespace-only': { path: '/members/x', method: '  ' },
  'method null': { path: '/members/x', method: null },
  'method array': { path: '/members/x', method: ['GET'] },
  'method padded': { path: '/members/x', method: ' GET' },
  'method too long (was silently truncated)': { path: '/members/x', method: 'GETXXXXXXXXXX' },
  'method with symbols': { path: '/members/x', method: 'GET;POST' },
  'environment empty': { ...OK, environment: '' },
  'environment whitespace-only': { ...OK, environment: '   ' },
  'environment null': { ...OK, environment: null },
  'environment number': { ...OK, environment: 1 },
  'environment too long (was silently truncated)': { ...OK, environment: 'production' + 'x'.repeat(40) },
  'empty resource object': {},
  'path without method': { path: '/members/x' },
  'method without path': { method: 'GET' },
  'environment only': { environment: 'production' },
  'identityOnly false': { identityOnly: false },
  'identityOnly string': { identityOnly: 'true' },
  'identityOnly together with a route': { identityOnly: true, ...OK },
};
// Malformed / ambiguous paths (item 3): encoded separators, double encoding, traversal, path parameters, control bytes.
const BAD_PATHS = ['/members/../admin', '/members/./x', '/members/%2e%2e/admin', '/members/%2E%2E/admin', '/members/%252e%252e/admin', '/members/%252fadmin',
  '/members/%2fadmin', '/members/%5cadmin', '/members\\admin', '/members/x;jsessionid=1', '/members/%00', '/members/%3b', '/members/%25', '/members/\u0000x', '/members/\tx', '/members/%E0%A4%A'];
const isRefusal = (r) => r && r.valid !== true && ['bad_resource', 'bad_path'].includes(r.code);
const run = async (f) => { try { return await f(); } catch (e) { return { valid: false, thrown: true, code: e?.code ?? String(e) }; } };
const req = () => ({ headers: { cookie: 'tokenlock_pass=' + PASS } });

test('every public client entry point refuses malformed authorization requests (never valid, never sent as identity-only)', async () => {
  const bad = [];
  for (const [name, r] of Object.entries(MALFORMED)) {
    const entry = {
      'verifyPass()': (f) => core.verifyPass(PASS, { secretKey: SK, fetch: f, cache: false, ...r }),
      'TokenlockClient.verifyPass()': (f) => new core.TokenlockClient({ secretKey: SK, fetch: f, cache: false }).verifyPass(PASS, r),
      'getPass()': (f) => core.getPass(req(), { secretKey: SK, fetch: f, cache: false, ...r }).then((v) => v || { valid: false, code: 'null' }),
      'authorize()': (f) => core.authorize(req(), r, { secretKey: SK, fetch: f }),
      'next getPass()': (f) => nx.getPass(req(), { secretKey: SK, fetch: f, cache: false, ...r }).then((v) => v || { valid: false, code: 'null' }),
      'next authorize()': (f) => nx.authorize(req(), r, { secretKey: SK, fetch: f }),
    };
    for (const [ep, call] of Object.entries(entry)) {
      core.clearCache();
      const calls = [];
      const v = await run(() => call(stub(calls)));
      const downgraded = calls.some((b) => b.path === undefined && b.method === undefined && b.environment === undefined);
      if (!isRefusal(v) || downgraded) bad.push(`${ep} ${name} → ${JSON.stringify({ valid: v.valid, code: v.code })}${downgraded ? ' (sent as identity-only)' : ''}`);
    }
  }
  assert.deepEqual(bad, [], bad.join('\n'));
});
test('a missing route is not an identity check: verifyPass / getPass / TokenlockClient need a route or an explicit identityOnly: true', async () => {
  const bad = [];
  const cases = {
    'verifyPass(pass, { secretKey })': (f) => core.verifyPass(PASS, { secretKey: SK, fetch: f, cache: false }),
    'TokenlockClient.verifyPass(pass)': (f) => new core.TokenlockClient({ secretKey: SK, fetch: f, cache: false }).verifyPass(PASS),
    'TokenlockClient.verifyPass(pass, null)': (f) => new core.TokenlockClient({ secretKey: SK, fetch: f, cache: false }).verifyPass(PASS, null),
    'getPass(req, { secretKey })': (f) => core.getPass(req(), { secretKey: SK, fetch: f, cache: false }).then((v) => v || { valid: false, code: 'null' }),
    'next getPass(req, { secretKey })': (f) => nx.getPass(req(), { secretKey: SK, fetch: f, cache: false }).then((v) => v || { valid: false, code: 'null' }),
  };
  for (const [name, call] of Object.entries(cases)) { core.clearCache(); const calls = []; const v = await run(() => call(stub(calls))); if (!isRefusal(v) || calls.length) bad.push(`${name} → ${JSON.stringify(v)} calls=${calls.length}`); }
  assert.deepEqual(bad, [], bad.join('\n'));
});
test('identity-only verification stays supported as an explicit request (item 5)', async () => {
  const calls = [];
  const a = await core.verifyPass(PASS, { secretKey: SK, fetch: stub(calls), cache: false, identityOnly: true });
  assert.equal(a.valid, true); assert.equal(calls.at(-1).path, undefined); assert.equal(calls.at(-1).identity_only, true, 'explicit identity_only sent to the API');
  const c = await new core.TokenlockClient({ secretKey: SK, fetch: stub(calls), cache: false }).verifyPass(PASS, { identityOnly: true });
  assert.equal(c.valid, true);
  const g = await core.getPass(req(), { secretKey: SK, fetch: stub(calls), cache: false, identityOnly: true });
  assert.equal(g?.valid, true);
  const n = await nx.getPass(req(), { secretKey: SK, fetch: stub(calls), cache: false, identityOnly: true });
  assert.equal(n?.valid, true);
  // an explicit identity answer that echoes a route is contradictory → denied
  const echoing = async () => J({ valid: true, ...base(), resource: { path: '/members/x', method: 'GET', environment: null } });
  const d = await run(() => core.verifyPass(PASS, { secretKey: SK, fetch: echoing, cache: false, identityOnly: true }));
  assert.notEqual(d.valid, true);
});
test('malformed and ambiguous paths are refused everywhere; canonical forms are sent (item 3)', async () => {
  const bad = [];
  for (const p of BAD_PATHS) {
    core.clearCache(); const calls = [];
    const v = await run(() => new core.TokenlockClient({ secretKey: SK, fetch: stub(calls), cache: false }).verifyPass(PASS, { path: p, method: 'GET' }));
    if (!isRefusal(v) || calls.length) bad.push(`${JSON.stringify(p)} → ${JSON.stringify(v)}`);
  }
  assert.deepEqual(bad, [], bad.join('\n'));
  const calls = [];
  const v = await new core.TokenlockClient({ secretKey: SK, fetch: stub(calls), cache: false }).verifyPass(PASS, { path: '/Members//%41/', method: 'get', environment: 'production' });
  assert.equal(v.valid, true); assert.equal(calls[0].path, '/members/a'); assert.equal(calls[0].method, 'GET');
  // path rules v1.1: a query or fragment is not part of the route and is dropped before matching (never a downgrade)
  const q = []; await new core.TokenlockClient({ secretKey: SK, fetch: stub(q), cache: false }).verifyPass(PASS, { path: '/members/x?role=admin#f', method: 'GET' });
  assert.equal(q[0].path, '/members/x');
});
test('inconsistent route / method combinations deny (item 3)', async () => {
  const c = new core.TokenlockClient({ secretKey: SK, fetch: stub(), cache: false });
  assert.equal((await c.verifyPass(PASS, { path: '/members/x', method: 'POST', environment: 'production' })).code, 'method_not_allowed');
  assert.equal((await c.verifyPass(PASS, { path: '/admin', method: 'GET', environment: 'production' })).code, 'route_not_allowed');
  assert.equal((await c.verifyPass(PASS, { path: '/members/x', method: 'GET', environment: 'staging' })).code, 'environment_not_allowed');
});
test('middleware and worker settings: empty / whitespace-only environment is a configuration error', async () => {
  for (const environment of ['', '   ', ' production']) {
    let err = null; try { ex.tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', secretKey: SK, environment }); } catch (e) { err = e; }
    assert.equal(err?.code, 'bad_config', `express environment ${JSON.stringify(environment)}`);
    let err2 = null; try { nx.tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', secretKey: SK, environment }); } catch (e) { err2 = e; }
    assert.equal(err2?.code, 'bad_config', `next environment ${JSON.stringify(environment)}`);
    const r = await cfDefault.fetch(new Request('https://site.test/members/x', { headers: { cookie: 'tokenlock_pass=' + PASS } }), { TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_SITE_KEY: 'pk_x', TOKENLOCK_API: 'https://api.invalid', TOKENLOCK_ENVIRONMENT: environment, TOKENLOCK_PROTECT: '/members' });
    assert.equal(r.status, 500, `worker environment ${JSON.stringify(environment)}`);
  }
});

// ---------------------------------------------------------------- self-verify (Node)
const ADDR = 'bc1qagentaddressxxxxxxxxxxxxxxxxxxxxxxxx';
const KEY = { id: 'key_a', address: ADDR, status: 'active', owner_type: 'agent', org_id: null, assets: [], permissions: { routes: ['/members/*'], methods: ['GET'], environments: ['production'] }, expires_at: null, pass_ttl_s: null };
const POL = { v: 1, typ: 'tokenlock.policy', site_id: 'site1', seq: 1, issued_at: new Date(Date.now() - 1000).toISOString(), expires_at: future(600e3), mode: 'registered_keys', orgs: [], revoked_assets: [], keys: [KEY] };
const PASS_SECRET = randomBytes(32).toString('hex');
const localPass = () => { const p = { sub: ADDR, h: ['TOKENLOCK'], k: 'key_a', n: 'n1', s: 'https://site1', i: Date.now(), e: Date.now() + 600e3 }; const m = Buffer.from(JSON.stringify(p)).toString('base64url'); return 'tl3.' + m + '.' + createHmac('sha256', PASS_SECRET).update('tl3.' + m).digest('base64url'); };
test('self-verify verifyLocalPass refuses malformed authorization requests and never downgrades them (registered-keys policy)', async () => {
  const policy = sv.localPolicy(POL); const bad = [];
  for (const [name, r] of Object.entries(MALFORMED)) {
    const v = await run(() => sv.verifyLocalPass(localPass(), { passSecret: PASS_SECRET, policy, resource: r }));
    if (v.allowed === true || !['bad_resource', 'bad_path'].includes(v.code)) bad.push(`${name} → ${JSON.stringify({ allowed: v.allowed, code: v.code })}`);
  }
  for (const p of BAD_PATHS) { const v = await run(() => sv.verifyLocalPass(localPass(), { passSecret: PASS_SECRET, policy, resource: { path: p, method: 'GET' } })); if (v.allowed === true || !['bad_resource', 'bad_path'].includes(v.code)) bad.push(`path ${JSON.stringify(p)} → ${v.code}`); }
  assert.deepEqual(bad, [], bad.join('\n'));
  const none = await run(() => sv.verifyLocalPass(localPass(), { passSecret: PASS_SECRET, policy }));
  assert.equal(none.allowed, false, 'no resource and no identityOnly is not an identity check'); assert.equal(none.code, 'bad_resource');
  const ok = await sv.verifyLocalPass(localPass(), { passSecret: PASS_SECRET, policy, identityOnly: true });
  assert.equal(ok.allowed, true, 'explicit identity-only still works');
  const both = await run(() => sv.verifyLocalPass(localPass(), { passSecret: PASS_SECRET, policy, identityOnly: true, resource: OK }));
  assert.equal(both.allowed, false);
  const route = await sv.verifyLocalPass(localPass(), { passSecret: PASS_SECRET, policy, resource: OK });
  assert.equal(route.allowed, true);
});
test('self-verify evaluate() refuses a malformed resource instead of skipping the route rules', () => {
  const bad = [];
  for (const [name, r] of Object.entries(MALFORMED)) {
    if (name.startsWith('identityOnly')) continue;
    let v; try { v = sv.evaluate(POL, { address: ADDR, held: ['TOKENLOCK'], resource: r }); } catch (e) { v = { allowed: false, reason: e.code }; }
    if (v.allowed === true) bad.push(name);
  }
  assert.deepEqual(bad, [], bad.join(' | '));
});

// Found by the 0.4.3 interface audit (written before the fix): a Cloudflare TOKENLOCK_PROTECT / TOKENLOCK_API_PATHS
// entry that is not a plain path prefix (e.g. "/api/*", "api", "/api/:path*") matched nothing, so the paths it was meant
// to protect were served unprotected. Since 0.4.3 it is a configuration error: protected paths answer 500 bad_config.
test('cloudflare: a TOKENLOCK_PROTECT entry that is not a plain path prefix is bad_config, never silently unprotected', async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input) => { const u = String(input?.url || input); if (u.startsWith('https://origin.example/')) return new Response('SECRET', { status: 200 }); throw new Error('no API in this test'); };
  try {
    for (const protect of ['/api/*', 'api', '/api/:path*', '/api,/admin/*', '/api/**', '/api,admin']) {
      const envX = { TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_SITE_KEY: 'pk_x', TOKENLOCK_PROTECT: protect };
      const res = await cfDefault.fetch(new Request('https://origin.example/api/x', { headers: { accept: 'application/json' } }), envX);
      const body = await res.text();
      assert.ok(!body.includes('SECRET'), `${JSON.stringify(protect)}: /api/x must not be served (status ${res.status})`);
      assert.equal(res.status, 500, `${JSON.stringify(protect)}: expected 500 bad_config, got ${res.status} ${body.slice(0, 120)}`);
    }
    const okEnv = { TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_SITE_KEY: 'pk_x', TOKENLOCK_PROTECT: '/api,/admin' };
    const res = await cfDefault.fetch(new Request('https://origin.example/api/x', { headers: { accept: 'application/json' } }), okEnv);
    assert.equal(res.status, 401, 'control: a plain prefix list protects /api/x');
  } finally { globalThis.fetch = realFetch; }
});
