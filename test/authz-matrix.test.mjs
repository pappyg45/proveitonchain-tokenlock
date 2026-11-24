// Shared authorization matrix (test/fixtures/authz-matrix.json) for Node self-verify. The PHP drop-in runs the same
// fixture (php/test/authz-matrix.php) and the hosted API runs it in the site repo (tests/tokenlock-access.test.mjs),
// through the raw API, this SDK's hosted client and the PHP hosted client.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import * as SV from '../dist/self-verify.js';

const M = JSON.parse(readFileSync(new URL('./fixtures/authz-matrix.json', import.meta.url), 'utf8'));
const PKG_VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const SECRET = 'm'.repeat(40);
const ADDR = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq';
const NOW = Date.parse('2026-11-18T18:00:00.000Z');
export const norm = (v) => { const allow = v.valid === true && v.allowed !== false; return { allow, code: allow ? 'ok' : v.code }; };

function setup(c) {
  const k = c.policy === 'registered_keys' ? 'key_1' : null;
  let pass = SV.issuePass({ sub: ADDR, h: ['TOKENLOCK'], k, n: 'a'.repeat(32), s: 'https://app.example', i: NOW - 1000, e: c.pass === 'expired' ? NOW - 1 : NOW + 900e3 }, SECRET);
  if (c.pass === 'forged') pass = pass.slice(0, -4) + (pass.endsWith('AAAA') ? 'BBBB' : 'AAAA');
  let policy;
  if (c.policy === 'registered_keys') policy = SV.localPolicy({ keys: [{ id: 'key_1', address: ADDR, status: c.key === 'revoked' ? 'revoked' : 'active', permissions: { routes: M.key.routes, methods: M.key.methods, environments: M.key.environments } }] });
  if (c.policy === 'token') policy = SV.localPolicy({ mode: 'token' });
  return { pass, policy };
}

test('authz matrix: Node self-verify matches every expected allow/deny and code', async () => {
  const out = {};
  for (const c of M.cases) {
    const { pass, policy } = setup(c);
    const v = await SV.verifyLocalPass(pass, { passSecret: SECRET, policy, ...(c.resource === null ? { identityOnly: true } : { resource: c.resource }), now: NOW });
    out[c.id] = norm(v);
    assert.deepEqual(out[c.id], c.expect, c.id);
  }
  if (process.env.AUTHZ_MATRIX_OUT) writeFileSync(process.env.AUTHZ_MATRIX_OUT, JSON.stringify({ integration: 'node-self-verify', results: out }, null, 1));
});

test('policy_required answers say whether the pass itself is good (identity_valid), and never allow', async () => {
  for (const c of M.cases.filter((x) => x.expect.code === 'policy_required')) {
    const { pass, policy } = setup(c);
    for (const resource of [c.resource, { path: '/x', method: 'GET' }, { path: '/x', method: 'DELETE' }, { path: '/x', method: 'GET', environment: 'production' }]) {
      const v = await SV.verifyLocalPass(pass, { passSecret: SECRET, policy, resource, now: NOW });
      assert.equal(v.valid, false); assert.equal(v.allowed, false); assert.equal(v.code, 'policy_required'); assert.equal(v.identity_valid, true);
      assert.equal(v.address, ADDR);
    }
  }
  const { pass } = setup({ policy: 'none', pass: 'forged' });
  assert.equal((await SV.verifyLocalPass(pass, { passSecret: SECRET, resource: { path: '/x', method: 'GET' }, now: NOW })).code, 'bad_pass', 'a forged pass is never reported as policy_required');
});

test('Cloudflare worker 0.4.0: token-only site needs TOKENLOCK_TOKEN_ONLY=1; it cannot bypass a route policy', async () => {
  const cf = await import('../examples/cloudflare-worker/worker.js');
  const P = 'pp1.' + 'a'.repeat(40) + '.' + 'b'.repeat(43);
  const realFetch = globalThis.fetch;
  let registered = false; const sent = [];
  const J = (o) => new Response(JSON.stringify(o), { headers: { 'content-type': 'application/json' } });
  globalThis.fetch = async (input, init) => {
    const u = String(input?.url || input);
    if (!u.endsWith('/api/v1/gate/verify')) return new Response('ORIGIN');
    const b = JSON.parse(init.body); sent.push({ ...b, client: init.headers['x-tokenlock-sdk'] });
    const base = { address: ADDR, site_id: 's1', expires_at: new Date(Date.now() + 600e3).toISOString() };
    const res = b.path ? { path: b.path, method: b.method, environment: b.environment ?? null } : undefined;
    if (!registered) return J(res ? { valid: false, allowed: false, identity_valid: true, code: 'policy_required', reason: 'no policy', ...base, access: { mode: 'token', allowed: false, reason: 'policy_required' }, resource: res } : { valid: true, ...base });
    const ok = !b.path || b.path.startsWith('/members');
    return J({ valid: true, allowed: ok, ...(ok ? {} : { code: 'route_not_allowed' }), ...base, access: { mode: 'registered_keys', allowed: ok, reason: ok ? 'ok' : 'route_not_allowed' }, ...(res ? { resource: res } : {}) });
  };
  try {
    const env = { TOKENLOCK_API: 'https://api.example', TOKENLOCK_SECRET_KEY: 'sk_' + 'x'.repeat(40), TOKENLOCK_PROTECT: '/members,/admin' };
    const get = (p, e) => cf.default.fetch(new Request('https://site.example' + p, { headers: { accept: 'application/json', cookie: 'tokenlock_pass=' + P } }), e);
    let r = await get('/members/x', env);
    assert.equal(r.status, 403); assert.equal((await r.json()).code, 'policy_required', 'token-only site without TOKENLOCK_TOKEN_ONLY: denied');
    r = await get('/members/x', { ...env, TOKENLOCK_TOKEN_ONLY: '1' });
    assert.equal(r.status, 200); assert.equal(await r.text(), 'ORIGIN', 'with TOKENLOCK_TOKEN_ONLY=1: holder reaches the origin');
    assert.ok(sent.every((s) => s.client === 'cf-worker/' + PKG_VERSION));
    registered = true;
    r = await get('/admin/x', { ...env, TOKENLOCK_TOKEN_ONLY: '1' });
    assert.equal(r.status, 403, 'registered keys: TOKENLOCK_TOKEN_ONLY cannot bypass the route policy'); assert.equal((await r.json()).code, 'route_not_allowed');
    r = await get('/members/x', { ...env, TOKENLOCK_TOKEN_ONLY: '1' });
    assert.equal(r.status, 200);
  } finally { globalThis.fetch = realFetch; }
});
