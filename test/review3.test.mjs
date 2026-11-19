// 0.3.3 review fixes: self-verify resource without a policy, signedPolicy retry backoff, verifyPass exceptions.
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import * as SV from '../dist/self-verify.js';
import { TokenlockClient, TokenlockError, verifyPass, isUnavailable, VERSION } from '../dist/index.js';

const sha = (b) => createHash('sha256').update(b).digest();
const SECRET = 'z'.repeat(40);
const ADDR = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq';
const NOW = Date.parse('2026-11-18T18:00:00.000Z');
const pass = (k = null) => SV.issuePass({ sub: ADDR, h: ['TOKENLOCK'], k, n: 'a'.repeat(32), s: 'https://app.example', i: NOW, e: NOW + 900e3 }, SECRET);

function signedBundle({ seq = 1, now = Date.now(), ttlMs = 600e3 } = {}) {
  const sk = secp256k1.utils.randomSecretKey(); const pk = Buffer.from(schnorr.getPublicKey(sk)).toString('hex');
  const payload = { v: 1, typ: 'tokenlock.policy', site_id: 's1', seq, issued_at: new Date(now).toISOString(), expires_at: new Date(now + ttlMs).toISOString(), mode: 'token', orgs: [], revoked_assets: [], keys: [] };
  const bytes = Buffer.from(JSON.stringify(payload));
  const tag = sha(Buffer.from('TOKENLOCK/policy/v1')); const msg = sha(Buffer.concat([tag, tag, bytes]));
  return { pk, bundle: { v: 1, typ: 'tokenlock.policy-bundle', alg: 'BIP340', kid: 'k1', payload: bytes.toString('base64url'), sig: Buffer.from(schnorr.sign(msg, sk)).toString('hex') } };
}

// ---------------------------------------------------------------- finding 1 (high)
test('0.3.3 verifyLocalPass: resource without a policy is a configuration error, never allowed', async () => {
  const p = pass();
  for (const resource of [{ path: '/admin', method: 'POST', environment: 'production' }, { path: '/api/x' }, { method: 'DELETE' }, { environment: 'production' }, {}]) {
    const v = await SV.verifyLocalPass(p, { passSecret: SECRET, resource, now: NOW });
    assert.equal(v.allowed, false, `allowed must be false for ${JSON.stringify(resource)}`);
    assert.equal(v.valid, false);
    assert.equal(v.code, 'policy_required');
    assert.match(v.reason, /no policy/i);
    assert.equal(v.address, ADDR, 'identity is still reported for logs');
  }
});

test('0.3.3 verifyLocalPass: identity-only check (no resource) still works without a policy', async () => {
  const p = pass();
  for (const o of [{}, { resource: undefined }, { resource: null }]) {
    const v = await SV.verifyLocalPass(p, { passSecret: SECRET, now: NOW, ...o });
    assert.equal(v.valid, true); assert.equal(v.allowed, true); assert.equal(v.code, 'ok');
  }
  // bad and expired passes are still reported as such, before the policy check
  assert.equal((await SV.verifyLocalPass(p.slice(0, -2) + 'AA', { passSecret: SECRET, resource: { path: '/a' }, now: NOW })).code, 'bad_pass');
  assert.equal((await SV.verifyLocalPass(p, { passSecret: SECRET, resource: { path: '/a' }, now: NOW + 901e3 })).code, 'expired');
});

test('0.3.3 verifyLocalPass: resource + policy evaluates route, method and environment', async () => {
  const policy = SV.localPolicy({ keys: [{ id: 'key_1', address: ADDR, status: 'active', permissions: { routes: ['/api/*'], methods: ['GET'], environments: ['production'] } }] });
  const p = pass('key_1');
  const lp = (resource) => SV.verifyLocalPass(p, { passSecret: SECRET, policy, resource, now: NOW });
  assert.equal((await lp({ path: '/api/reports', method: 'GET', environment: 'production' })).allowed, true);
  assert.equal((await lp({ path: '/admin', method: 'GET', environment: 'production' })).code, 'route_not_allowed');
  assert.equal((await lp({ path: '/api/reports', method: 'POST', environment: 'production' })).code, 'method_not_allowed');
  assert.equal((await lp({ path: '/api/reports', method: 'GET', environment: 'staging' })).code, 'environment_not_allowed');
});

// ---------------------------------------------------------------- finding 3 (medium)
test('0.3.3 signedPolicy: 3 immediate calls during an initial outage make 1 load attempt (sequential)', async () => {
  let loads = 0;
  const src = SV.signedPolicy({ siteId: 's1', secretKey: 'sk_x', publicKeys: ['11'.repeat(32)], load: async () => { loads++; throw new Error('down'); } });
  for (let i = 0; i < 3; i++) await assert.rejects(src.get(), (e) => e.code === 'policy_unavailable');
  assert.equal(loads, 1);
  const st = src.status();
  assert.equal(st.failures, 1); assert.equal(st.last_error, 'policy_unavailable'); assert.ok(st.next_retry_at > Date.now());
});

test('0.3.3 signedPolicy: concurrent calls share one in-flight load', async () => {
  let loads = 0;
  const src = SV.signedPolicy({ siteId: 's1', secretKey: 'sk_x', publicKeys: ['11'.repeat(32)], load: async () => { loads++; await new Promise((r) => setTimeout(r, 20)); throw new Error('down'); } });
  const rs = await Promise.allSettled([src.get(), src.get(), src.get()]);
  assert.ok(rs.every((r) => r.status === 'rejected' && r.reason.code === 'policy_unavailable'));
  assert.equal(loads, 1);
});

test('0.3.3 signedPolicy: exponential backoff (5 s, 10 s, 20 s … capped at refreshSeconds), success resets it', async () => {
  mock.timers.enable({ apis: ['Date'], now: Date.now() });
  try {
    let up = false, loads = 0;
    const { pk, bundle } = signedBundle({ now: Date.now() });
    const src = SV.signedPolicy({ siteId: 's1', secretKey: 'sk_x', publicKeys: { k1: pk }, refreshSeconds: 30, load: async () => { loads++; if (!up) throw new Error('down'); return bundle; } });
    await assert.rejects(src.get()); assert.equal(loads, 1);
    mock.timers.tick(4_900); await assert.rejects(src.get()); assert.equal(loads, 1, 'inside the 5 s window: no load');
    mock.timers.tick(200); await assert.rejects(src.get()); assert.equal(loads, 2, 'after 5 s: one retry');
    mock.timers.tick(9_900); await assert.rejects(src.get()); assert.equal(loads, 2, 'second window is 10 s');
    mock.timers.tick(200); await assert.rejects(src.get()); assert.equal(loads, 3);
    mock.timers.tick(20_100); await assert.rejects(src.get()); assert.equal(loads, 4);
    mock.timers.tick(30_100); await assert.rejects(src.get()); assert.equal(loads, 5, 'capped at refreshSeconds (30 s), not 40 s');
    assert.equal(src.status().failures, 4 + 1);
    up = true;
    mock.timers.tick(30_100);
    assert.equal((await src.get()).seq, 1); assert.equal(loads, 6);
    const st = src.status(); assert.equal(st.failures, 0); assert.equal(st.last_error, null); assert.equal(st.next_retry_at, null);
    await src.get(); assert.equal(loads, 6, 'fresh bundle: no load');
  } finally { mock.timers.reset(); }
});

test('0.3.3 signedPolicy: failed refresh with a cached bundle backs off and serves the cache without waiting', async () => {
  mock.timers.enable({ apis: ['Date'], now: Date.now() });
  try {
    let up = true, loads = 0;
    const { pk, bundle } = signedBundle({ now: Date.now(), ttlMs: 600e3 });
    const src = SV.signedPolicy({ siteId: 's1', secretKey: 'sk_x', publicKeys: { k1: pk }, load: async () => { loads++; if (!up) throw new Error('down'); return bundle; } });
    assert.equal((await src.get()).seq, 1); assert.equal(loads, 1);
    up = false; mock.timers.tick(61_000);
    assert.equal((await src.get()).seq, 1, 'refresh failed: cached bundle used'); assert.equal(loads, 2);
    for (let i = 0; i < 5; i++) assert.equal((await src.get()).seq, 1);
    assert.equal(loads, 2, 'no fetch on every call during the outage');
    mock.timers.tick(600e3);
    await assert.rejects(src.get(), (e) => e.code === 'policy_expired');
  } finally { mock.timers.reset(); }
});

test('0.3.3 signedPolicy: a bad bundle (wrong key) also backs off and keeps its own error code', async () => {
  let loads = 0;
  const { bundle } = signedBundle();
  const src = SV.signedPolicy({ siteId: 's1', secretKey: 'sk_x', publicKeys: { k1: '22'.repeat(32) }, load: async () => { loads++; return bundle; } });
  for (let i = 0; i < 3; i++) await assert.rejects(src.get(), (e) => e.code === 'policy_bad_signature');
  assert.equal(loads, 1);
});

// ---------------------------------------------------------------- finding 4 (low): documented exceptions
test('0.3.3 verifyPass throws TokenlockError: missing secret key, non-2xx HTTP, network; a bad pass is an answer', async () => {
  assert.equal(VERSION, '0.3.3');
  const PASS = 'pp1.' + 'a'.repeat(20) + '.' + 'b'.repeat(20);
  const saved = process.env.TOKENLOCK_SECRET_KEY; delete process.env.TOKENLOCK_SECRET_KEY;
  try {
    await assert.rejects(new TokenlockClient({ fetch: async () => { throw new Error('unused'); } }).verifyPass(PASS), (e) => e instanceof TokenlockError && e.code === 'no_secret_key' && e.status === 0 && !isUnavailable(e));
  } finally { if (saved !== undefined) process.env.TOKENLOCK_SECRET_KEY = saved; }
  const res = (status, body) => async () => ({ ok: status >= 200 && status < 300, status, json: async () => body });
  await assert.rejects(verifyPass(PASS, { secretKey: 'sk_test', fetch: res(429, { error: 'Too many requests.', code: 'rate_limited' }) }), (e) => e instanceof TokenlockError && e.status === 429 && e.code === 'rate_limited' && !isUnavailable(e));
  await assert.rejects(verifyPass(PASS, { secretKey: 'sk_test', fetch: res(503, null) }), (e) => e instanceof TokenlockError && e.status === 503 && isUnavailable(e));
  await assert.rejects(verifyPass(PASS, { secretKey: 'sk_test', fetch: async () => { throw new TypeError('fetch failed'); } }), (e) => e instanceof TokenlockError && e.code === 'network' && e.status === 0 && isUnavailable(e));
  const bad = await verifyPass('not-a-pass', { secretKey: 'sk_test', fetch: async () => { throw new Error('not called'); } });
  assert.equal(bad.valid, false); assert.equal(bad.code, 'bad_pass');
  const answered = await verifyPass(PASS, { secretKey: 'sk_test', fetch: res(200, { valid: false, code: 'bad_secret_key', reason: 'Unknown secret key.' }) });
  assert.equal(answered.valid, false); assert.equal(answered.code, 'bad_secret_key');
});
