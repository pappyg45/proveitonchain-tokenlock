// 0.4.5 security patch. Written BEFORE the fix; it fails against 0.4.4 (local dist and the registry package).
// External review (19 Nov 2026):
//  F1  self-verify turned missing permissions into wildcard access: for an active registered key, no `permissions`,
//      `permissions: null`, `permissions: {}` and `{ routes: null, methods: null }` all allowed DELETE /private/admin,
//      because missing/null routes and methods defaulted to ['*']. Explicit [] already denied.
//      Fixed rule: routes and methods must each be an explicit list. Missing, null, undefined or not a list → the key is
//      refused with policy_invalid for any resource. [] grants nothing. Only an explicit '*' is a wildcard.
//  F2  examples/self-verify-enterprise.mjs checkPass(pass, { path, method }) answered bad_resource because it always sent
//      `environment: undefined`; environment must be included only when supplied.
// Run against another copy of the package with TL_PKG_ROOT=/path/to/package (root that contains dist/ and examples/).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { schnorr } from '@noble/curves/secp256k1.js';

const ROOT = process.env.TL_PKG_ROOT ? pathToFileURL(process.env.TL_PKG_ROOT.replace(/\/?$/, '/')) : new URL('../', import.meta.url);
const SV = await import(new URL('dist/self-verify.js', ROOT));
const EXAMPLE = await import(new URL('examples/self-verify-enterprise.mjs', ROOT));

const SECRET = 'x'.repeat(40);
const A = 'bc1qreviewer0000000000000000000000000000';
const B = 'bc1qsecondkey00000000000000000000000000000';
const RES = { path: '/private/admin', method: 'DELETE' };
const future = (ms = 3600e3) => new Date(Date.now() + ms).toISOString();
const policy = (keys) => ({ v: 1, typ: 'tokenlock.policy', site_id: 'local', seq: 1, issued_at: new Date(Date.now() - 60e3).toISOString(), expires_at: future(), mode: 'registered_keys', orgs: [], revoked_assets: [], keys });
const key = (extra, address = A, id = 'k1') => ({ id, address, status: 'active', ...extra });
const ev = (pol, resource = RES, address = A) => SV.evaluate(pol, { address, held: ['GOTPROOF'], resource });
const pass = (k = 'k1', sub = A) => SV.issuePass({ sub, h: ['GOTPROOF'], k, n: 'n1', s: 'https://shop.example', i: Date.now(), e: Date.now() + 3600e3 }, SECRET);
const lp = (keys, resource = RES, p = pass()) => SV.verifyLocalPass(p, { passSecret: SECRET, policy: SV.localPolicy(policy(keys)), resource });

// Missing / null / undefined / empty-object permission shapes: the reviewer's four plus variants.
const MISSING = {
  'no permissions field': {},
  'permissions: null': { permissions: null },
  'permissions: undefined': { permissions: undefined },
  'permissions: {}': { permissions: {} },
  'routes: null, methods: null': { permissions: { routes: null, methods: null } },
  'routes: undefined, methods: undefined': { permissions: { routes: undefined, methods: undefined } },
  'routes missing (methods ["*"])': { permissions: { methods: ['*'] } },
  'methods missing (routes ["/*"])': { permissions: { routes: ['/*'] } },
  'routes null (methods ["*"])': { permissions: { routes: null, methods: ['*'] } },
  'methods null (routes ["/*"])': { permissions: { routes: ['/*'], methods: null } },
  'only environments given': { permissions: { environments: ['production'] } },
};
// Not-a-list values (0.4.4 already refused these as a malformed policy; still policy_invalid).
const NOT_LIST = {
  'routes: "*" (string)': { permissions: { routes: '*', methods: ['*'] } },
  'methods: "DELETE" (string)': { permissions: { routes: ['/*'], methods: 'DELETE' } },
  'routes: {} (object)': { permissions: { routes: {}, methods: ['*'] } },
  'routes: 5': { permissions: { routes: 5, methods: ['*'] } },
  'permissions: [] (array)': { permissions: [] },
  'permissions: "all" (string)': { permissions: 'all' },
};

test('F1 evaluate(): missing/null/undefined/{} routes or methods never grant a route (policy_invalid)', () => {
  const got = {};
  for (const [name, extra] of Object.entries(MISSING)) got[name] = ev(policy([key(extra)]));
  for (const [name, r] of Object.entries(got)) {
    assert.equal(r.allowed, false, `${name}: must not be allowed (got ${JSON.stringify({ allowed: r.allowed, reason: r.reason })})`);
    assert.equal(r.reason, 'policy_invalid', `${name}: reason`);
  }
});
test('F1 evaluate(): permissions that are not lists are refused (policy_invalid)', () => {
  for (const [name, extra] of Object.entries(NOT_LIST)) {
    const r = ev(policy([key(extra)]));
    assert.equal(r.allowed, false, name); assert.equal(r.reason, 'policy_invalid', name);
  }
});
test('F1 evaluate(): explicit grants still work; [] grants nothing; "*" only when explicit', () => {
  assert.equal(ev(policy([key({ permissions: { routes: ['*'], methods: ['*'], environments: ['*'] } })])).allowed, true, 'explicit "*" / "*"');
  assert.equal(ev(policy([key({ permissions: { routes: ['/private/*'], methods: ['DELETE'], environments: ['*'] } })])).allowed, true, 'explicit route + method');
  assert.equal(ev(policy([key({ permissions: { routes: [], methods: ['*'], environments: ['*'] } })])).reason, 'route_not_allowed', 'routes []');
  assert.equal(ev(policy([key({ permissions: { routes: ['/*'], methods: [], environments: ['*'] } })])).reason, 'method_not_allowed', 'methods []');
  assert.equal(ev(policy([key({ permissions: { routes: [], methods: [], environments: ['*'] } })])).allowed, false, 'both []');
  assert.equal(ev(policy([key({ permissions: { routes: ['/public/*'], methods: ['*'], environments: ['*'] } })])).reason, 'route_not_allowed', 'other route');
});
test('F1 evaluate(): mixed keys: an incomplete key is refused, a complete key in the same policy still works', () => {
  const pol = policy([key({ permissions: {} }), key({ permissions: { routes: ['/private/*'], methods: ['DELETE'], environments: ['*'] } }, B, 'k2')]);
  assert.equal(ev(pol, RES, A).reason, 'policy_invalid', 'key with permissions {}');
  assert.equal(ev(pol, RES, B).allowed, true, 'complete key');
  const pol2 = policy([key({}), key({ permissions: null }, B, 'k2')]);
  assert.equal(ev(pol2, RES, A).allowed, false); assert.equal(ev(pol2, RES, B).allowed, false);
});
test('F1 evaluate(): identity-only checks do not read route permissions (unchanged)', () => {
  assert.equal(SV.evaluate(policy([key({})]), { address: A, held: ['GOTPROOF'], identityOnly: true }).allowed, true);
});
test('F1 verifyLocalPass(): the reviewer\'s four shapes deny DELETE /private/admin (policy_invalid)', async () => {
  for (const [name, extra] of Object.entries(MISSING)) {
    const r = await lp([key(extra)]);
    assert.equal(r.allowed, false, `${name}: allowed must be false (got ${JSON.stringify({ valid: r.valid, allowed: r.allowed, code: r.code })})`);
    assert.equal(r.valid, false, `${name}: valid must be false`);
    assert.equal(r.code, 'policy_invalid', `${name}: code`);
  }
  const ok = await lp([key({ permissions: { routes: ['/private/*'], methods: ['DELETE'], environments: ['*'] } })]);
  assert.equal(ok.valid && ok.allowed, true, 'explicit grant still allowed');
});

// ---------------------------------------------------------------- F2: enterprise example, optional environment
const sha = (b) => createHash('sha256').update(b).digest();
function signBundle(sk, payload) {
  const bytes = Buffer.from(JSON.stringify(payload)); const tag = sha(Buffer.from('TOKENLOCK/policy/v1'));
  return { v: 1, typ: 'tokenlock.policy-bundle', alg: 'BIP340', kid: 'k1', payload: bytes.toString('base64url'), sig: Buffer.from(schnorr.sign(sha(Buffer.concat([tag, tag, bytes])), sk)).toString('hex') };
}
function verifier(permissions) {
  const sk = schnorr.utils.randomSecretKey(); const pub = Buffer.from(schnorr.getPublicKey(sk)).toString('hex');
  const now = Date.now();
  const payload = { ...policy([{ id: 'k1', address: A, status: 'active', permissions }]), site_id: 'site_ent', issued_at: new Date(now).toISOString(), expires_at: new Date(now + 600e3).toISOString() };
  return EXAMPLE.createEnterpriseVerifier({ siteId: 'site_ent', publicKeys: { k1: pub }, passSecret: SECRET, store: { async put() { return true; }, async take() { return null; } }, holdings: { name: 'unused', async holdings() { return {}; } }, load: async () => signBundle(sk, payload) });
}
test('F2 enterprise example checkPass(pass, { path, method }) works without an environment', async () => {
  // 0.4.5 RC3 (contract 1.1, U1): a key for any environment is ['*']; [] grants no environment (RC2 read [] as any).
  const v = verifier({ routes: ['/api/reports/*'], methods: ['GET'], environments: ['*'] });
  const r = await v.checkPass(pass(), { path: '/api/reports/q3', method: 'GET' });
  assert.equal(r.code, 'ok', JSON.stringify({ ok: r.ok, code: r.code })); assert.equal(r.ok, true);
  const none = await verifier({ routes: ['/api/reports/*'], methods: ['GET'], environments: [] }).checkPass(pass(), { path: '/api/reports/q3', method: 'GET' });
  assert.equal(none.ok, false); assert.equal(none.code, 'environment_not_allowed');
});
test('F2 enterprise example: environment is sent when supplied and still enforced', async () => {
  const v = verifier({ routes: ['/api/reports/*'], methods: ['GET'], environments: ['production'] });
  assert.equal((await v.checkPass(pass(), { path: '/api/reports/q3', method: 'GET', environment: 'production' })).ok, true, 'production');
  const s = await v.checkPass(pass(), { path: '/api/reports/q3', method: 'GET', environment: 'staging' });
  assert.equal(s.ok, false); assert.equal(s.code, 'environment_not_allowed');
  const w = await v.checkPass(pass(), { path: '/api/admin', method: 'GET', environment: 'production' });
  assert.equal(w.ok, false); assert.equal(w.code, 'route_not_allowed');
});
test('F2 enterprise example: a key with missing permissions is refused through the example too', async () => {
  const v = verifier(undefined);
  const r = await v.checkPass(pass(), { path: '/api/reports/q3', method: 'GET' });
  assert.equal(r.ok, false); assert.equal(r.code, 'policy_invalid');
});
