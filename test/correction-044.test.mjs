// 0.4.4 security correction. Written BEFORE the fix; it fails against 0.4.3 (local dist and the registry package).
// Reproduces the external review (19 Nov 2026) exactly, plus the gaps the widened 0.4.4 audit found:
//  G1  evaluate(): the token-mode branch returned before the resource was validated, so a normal resource, a misspelled
//      { pth: '/private' } and an array-valued path were all allowed: true.
//  G2  an explicitly expired localPolicy() (January 2020) still authorized a currently valid local pass.
//  G3  both starter projects depend on ^0.1.0, omit tokenOnly: true, and the Next members page calls bare getPass().
//  G4  README / error docs describe older behavior.
//  A1  verifyLocalPass() never checked passSecret: an empty secret verifies a pass anyone can forge (HMAC with '').
//  A2  evaluate() with held: null skipped the holdings check (token mode: allowed with no token at all).
//  A3  the Cloudflare worker's exported strictCheck(answer, resource) never validated `resource`.
//  A5  a policy "issued" in the future (not yet valid) was only refused for signed bundles.
// Run against another copy of the package with TL_PKG_ROOT=/path/to/package (root that contains dist/ and examples/).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { createHash } from 'node:crypto';

const ROOT = process.env.TL_PKG_ROOT ? pathToFileURL(process.env.TL_PKG_ROOT.replace(/\/?$/, '/')) : new URL('../', import.meta.url);
const SV = await import(new URL('dist/self-verify.js', ROOT));
const EX = await import(new URL('dist/express.js', ROOT));
const NX = await import(new URL('dist/next.js', ROOT));
const CF = await import(new URL('examples/cloudflare-worker/worker.js', ROOT));
const read = (p) => readFileSync(new URL(p, ROOT), 'utf8');
const VERSION = JSON.parse(read('package.json')).version;

const SECRET = 'x'.repeat(40);
const A = 'bc1qreviewer0000000000000000000000000000';
const future = (ms = 3600e3) => new Date(Date.now() + ms).toISOString();
const policyBase = (o = {}) => ({ v: 1, typ: 'tokenlock.policy', site_id: 'local', seq: 1, issued_at: new Date(Date.now() - 60e3).toISOString(), expires_at: future(), orgs: [], revoked_assets: [], keys: [], ...o });
const TOKEN = policyBase({ mode: 'token', assets: ['GOTPROOF'] });
const KEY = { id: 'k1', address: A, status: 'active', permissions: { routes: ['/*'], methods: ['*'], environments: ['*'] } };
const REG = policyBase({ mode: 'registered_keys', keys: [KEY] });
const pass = (o = {}) => SV.issuePass({ sub: A, h: ['GOTPROOF'], k: null, n: 'n1', s: 'https://shop.example', i: Date.now(), e: Date.now() + 3600e3, ...o }, SECRET);
const isAllowed = (r) => !!r && (r.allowed === true || r.valid === true);

// ---------------------------------------------------------------- G1: evaluate() validates the resource before any mode branch
test('G1 evaluate(): token-mode policy never authorizes a resource (normal, misspelled pth, array path)', () => {
  const cases = {
    'normal resource': [{ path: '/private', method: 'GET' }, 'policy_required'],
    'misspelled { pth: "/private" }': [{ pth: '/private' }, 'bad_resource'],
    'array-valued path { path: ["/private"] }': [{ path: ['/private'] }, 'bad_resource'],
    'array-valued path with method': [{ path: ['/private'], method: 'GET' }, 'bad_resource'],
    'relative path': [{ path: 'private', method: 'GET' }, 'bad_path'],
    'traversal': [{ path: '/public/../private', method: 'GET' }, 'bad_path'],
  };
  const got = {};
  for (const [name, [resource]] of Object.entries(cases)) got[name] = SV.evaluate(TOKEN, { address: A, held: ['GOTPROOF'], resource });
  for (const [name, [, code]] of Object.entries(cases)) {
    assert.equal(got[name].allowed, false, `${name}: must not be allowed (got ${JSON.stringify(got[name])})`);
    assert.equal(got[name].reason, code, `${name}: reason`);
  }
});
test('G1 evaluate(): malformed resources are refused before the mode branch in registered-keys mode too', () => {
  for (const resource of [{ pth: '/private' }, { path: ['/private'], method: 'GET' }, { path: '/x' }, { path: '/x', method: 'GET', extra: 1 }, 'path=/x', 7]) {
    const r = SV.evaluate(REG, { address: A, held: ['GOTPROOF'], resource });
    assert.equal(r.allowed, false, JSON.stringify(resource));
  }
  assert.equal(SV.evaluate(REG, { address: A, held: ['GOTPROOF'], resource: { path: '/private', method: 'GET' } }).allowed, true, 'a granted route is still allowed');
});
test('G1 evaluate(): identity-only must be explicit; { identityOnly: true } still works', () => {
  assert.equal(SV.evaluate(TOKEN, { address: A, held: ['GOTPROOF'], identityOnly: true }).allowed, true, 'explicit identity-only (token mode)');
  assert.equal(SV.evaluate(REG, { address: A, held: ['GOTPROOF'], identityOnly: true }).allowed, true, 'explicit identity-only (registered keys)');
  for (const [name, o] of Object.entries({
    'no resource and no identityOnly': { address: A, held: ['GOTPROOF'] },
    'resource: null': { address: A, held: ['GOTPROOF'], resource: null },
    'resource: undefined': { address: A, held: ['GOTPROOF'], resource: undefined },
    'identityOnly: "true"': { address: A, held: ['GOTPROOF'], identityOnly: 'true' },
    'identityOnly with a resource': { address: A, held: ['GOTPROOF'], identityOnly: true, resource: { path: '/x', method: 'GET' } },
    'unknown option': { address: A, held: ['GOTPROOF'], identityOnly: true, rsource: { path: '/x', method: 'GET' } },
  })) {
    const r = SV.evaluate(TOKEN, o);
    assert.equal(r.allowed, false, `${name}: token mode`);
    assert.equal(r.reason, 'bad_resource', `${name}: reason`);
    assert.equal(SV.evaluate(REG, o).allowed, false, `${name}: registered keys`);
  }
});
test('A2 evaluate(): held must be a list of asset names (null no longer skips the holdings check)', () => {
  for (const held of [null, undefined, 'GOTPROOF', [1], {}]) {
    assert.equal(SV.evaluate(TOKEN, { address: A, held, identityOnly: true }).allowed, false, `token mode held=${JSON.stringify(held)}`);
    assert.equal(SV.evaluate(REG, { address: A, held, identityOnly: true }).allowed, false, `registered held=${JSON.stringify(held)}`);
  }
  assert.equal(SV.evaluate(TOKEN, { address: A, held: [], identityOnly: true }).reason, 'not_holder');
});

// ---------------------------------------------------------------- G2 / A5: policy validity window enforced wherever a policy is used
const EXPIRED = { mode: 'registered_keys', issued_at: '2020-01-01T00:00:00.000Z', expires_at: '2020-01-31T00:00:00.000Z', keys: [KEY] };
test('G2 an explicitly expired localPolicy() (January 2020) never authorizes a currently valid local pass', async () => {
  const policy = SV.localPolicy(EXPIRED);
  const p = pass({ k: 'k1' });
  const id = await SV.verifyLocalPass(p, { passSecret: SECRET, policy, identityOnly: true });
  assert.deepEqual([id.valid, id.allowed, id.code], [false, false, 'policy_expired'], 'identity-only: ' + JSON.stringify(id));
  const res = await SV.verifyLocalPass(p, { passSecret: SECRET, policy, resource: { path: '/private', method: 'GET' } });
  assert.deepEqual([res.valid, res.allowed, res.code], [false, false, 'policy_expired'], 'resource: ' + JSON.stringify(res));
  const tok = await SV.verifyLocalPass(pass(), { passSecret: SECRET, policy: SV.localPolicy({ ...EXPIRED, mode: 'token', keys: [] }), identityOnly: true });
  assert.deepEqual([tok.valid, tok.allowed, tok.code], [false, false, 'policy_expired'], 'token mode: ' + JSON.stringify(tok));
  await assert.rejects(policy.get(), (e) => e.code === 'policy_expired', 'localPolicy().get() refuses an expired policy');
});
test('G2 expiry is enforced on every path: evaluate(), a custom PolicySource, verifySignIn()', async () => {
  const exp = policyBase({ ...EXPIRED });
  assert.equal(SV.evaluate(exp, { address: A, held: ['GOTPROOF'], identityOnly: true }).reason, 'policy_expired');
  assert.equal(SV.evaluate(exp, { address: A, held: ['GOTPROOF'], resource: { path: '/private', method: 'GET' } }).reason, 'policy_expired');
  assert.equal(SV.evaluate({ ...exp, mode: 'token', keys: [] }, { address: A, held: ['GOTPROOF'], identityOnly: true }).reason, 'policy_expired');
  const custom = { async get() { return exp; } };
  const r = await SV.verifyLocalPass(pass({ k: 'k1' }), { passSecret: SECRET, policy: custom, identityOnly: true });
  assert.deepEqual([r.valid, r.allowed, r.code], [false, false, 'policy_expired'], 'custom source: ' + JSON.stringify(r));
  // sign-in with an expired local policy
  const priv = secp256k1.utils.randomSecretKey();
  const addr = SV._addr.p2wpkh(secp256k1.getPublicKey(priv, true));
  const store = SV.memoryNonceStore();
  const ch = await SV.createChallenge({ site: 'https://shop.example', assets: ['GOTPROOF'], store });
  const s = await SV.verifySignIn({ challenge_id: ch.challenge_id, address: addr, signature: signLegacy(priv, ch.message) },
    { store, holdings: SV.staticProvider({ [addr]: ['GOTPROOF'] }), passSecret: SECRET, policy: SV.localPolicy({ ...EXPIRED, mode: 'token', keys: [] }) });
  assert.deepEqual([s.valid, s.code, s.pass], [false, 'policy_expired', undefined], 'sign-in: ' + JSON.stringify(s));
});
test('A5 a policy issued in the future (not yet valid) is refused on every path, local or signed', async () => {
  const later = { mode: 'token', keys: [], issued_at: future(86400e3), expires_at: future(2 * 86400e3) };
  const r = await SV.verifyLocalPass(pass(), { passSecret: SECRET, policy: SV.localPolicy(later), identityOnly: true });
  assert.equal(r.allowed, false, JSON.stringify(r));
  assert.equal(SV.evaluate(policyBase(later), { address: A, held: ['GOTPROOF'], identityOnly: true }).allowed, false);
});
test('G2 a valid local policy still works (no regression)', async () => {
  const ok = await SV.verifyLocalPass(pass({ k: 'k1' }), { passSecret: SECRET, policy: SV.localPolicy({ mode: 'registered_keys', keys: [KEY] }), resource: { path: '/private', method: 'GET' } });
  assert.deepEqual([ok.valid, ok.allowed, ok.code], [true, true, 'ok']);
});

// ---------------------------------------------------------------- A1: passSecret is checked on verify, not only on issue
test('A1 verifyLocalPass(): an empty or short passSecret is a config error, never a valid pass', async () => {
  const body = Buffer.from(JSON.stringify({ v: 1, sub: A, h: ['GOTPROOF'], k: null, n: 'x', s: 'https://shop.example', i: Date.now(), e: Date.now() + 3600e3 })).toString('base64url');
  for (const secret of ['', 'short']) {
    const forged = `tl3.${body}.${createHmac('sha256', secret).update('tl3.' + body).digest('base64url')}`;
    const r = await SV.verifyLocalPass(forged, { passSecret: secret, identityOnly: true });
    assert.equal(isAllowed(r), false, `passSecret ${JSON.stringify(secret)}: ${JSON.stringify(r)}`);
    assert.equal(r.code, 'bad_secret');
  }
  const u = await SV.verifyLocalPass(pass(), { passSecret: undefined, identityOnly: true });
  assert.equal(u.code, 'bad_secret', 'missing passSecret answers bad_secret instead of throwing');
});

// ---------------------------------------------------------------- A6: found by the widened audit (fuzz-exports): early bad_path answered valid: true
test('A6 verifyLocalPass(): a malformed path never answers valid: true (the pass was not even checked)', async () => {
  for (const token of ['garbage', pass()]) for (const path of ['/a/../admin', 'admin', '/%2e%2e/admin', '/a%2fb', '/a\\b']) {
    const r = await SV.verifyLocalPass(token, { passSecret: SECRET, resource: { path, method: 'GET' } });
    assert.deepEqual([r.valid, r.allowed, r.code], [false, false, 'bad_path'], `${token.slice(0, 8)} ${path}: ${JSON.stringify(r)}`);
  }
  const r = await SV.verifyLocalPass('garbage', { passSecret: SECRET, resource: { pth: '/admin' } });
  assert.deepEqual([r.valid, r.allowed], [false, false]);
});

// ---------------------------------------------------------------- A3: Cloudflare strictCheck validates the resource it is given
test('A3 cf-worker strictCheck(answer, resource): a malformed resource is refused, not compared field by field', () => {
  const answer = { valid: true, allowed: true, address: A, site_id: 's1', expires_at: future(), access: { mode: 'registered_keys', allowed: true, reason: 'ok' }, resource: { path: null, method: null, environment: null } };
  for (const resource of [{ pth: '/private' }, { path: ['/private'], method: 'GET' }, { method: 'GET' }, 'path=/private', 1, []]) {
    const r = CF.strictCheck(answer, resource);
    assert.equal(r.ok, false, `${JSON.stringify(resource)}: ${JSON.stringify(r)}`);
  }
  const good = { ...answer, resource: { path: '/private', method: 'GET', environment: null } };
  assert.equal(CF.strictCheck(good, { path: '/private', method: 'GET' }).ok, true, 'a matching answer is still accepted');
  assert.equal(CF.strictCheck({ ...answer, resource: undefined }, null).ok, true, 'identity answer still accepted');
});

// ---------------------------------------------------------------- G3: starters usable with the current release
test('G3 starters: depend on the current release, tokenOnly: true, members page asks for identity explicitly', async () => {
  const [maj, min, pat] = VERSION.split('.').map(Number);
  for (const dir of ['express', 'next-app']) {
    const range = JSON.parse(read(`examples/${dir}/package.json`)).dependencies['@proveitonchain/tokenlock'];
    const m = /^\^(\d+)\.(\d+)\.(\d+)$/.exec(range || '');
    // 0.5.0 RC7 (disclosed U25): "at least 0.4.4" compared as a version, not as patch >= 4 (which only held on 0.4.x);
    // still the current release line (same major.minor, patch not above the current one).
    const atLeast044 = m && (+m[1] > 0 || +m[2] > 4 || (+m[2] === 4 && +m[3] >= 4));
    assert.ok(m && +m[1] === maj && +m[2] === min && +m[3] <= pat && atLeast044, `${dir}: dependency ${range} must be ^0.4.4 or later within ${VERSION}`);
  }
  assert.ok(/tokenOnly:\s*true/.test(read('examples/express/server.js')), 'express starter: tokenOnly: true');
  assert.ok(/tokenOnly:\s*true/.test(read('examples/next-app/middleware.ts')), 'next starter: tokenOnly: true');
  const members = read('examples/next-app/app/members/page.tsx');
  assert.ok(!/getPass\(\s*\)/.test(members), 'next members page: no bare getPass()');
  assert.ok(/getPass\([^)]*identityOnly:\s*true/.test(members), 'next members page: explicit identityOnly');
  await assert.rejects(NX.getPass(undefined, {}), (e) => e.code === 'bad_resource', 'bare getPass() is still refused (bad_resource)');
  assert.doesNotThrow(() => EX.tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', tokenOnly: true, secretKey: 'sk_' + 'a'.repeat(30) }));
});

// ---------------------------------------------------------------- G4: docs match the implementation
test('G4 README and error docs describe current behavior', async () => {
  const readme = read('README.md');
  assert.ok(!/resource_required/.test(readme), 'README: authorize() without a resource is bad_resource, not resource_required');
  const err = await EX.authorize({ headers: {} }, undefined, { secretKey: 'sk_' + 'a'.repeat(30) }).catch((e) => e);
  assert.deepEqual([err.code, err.status], ['bad_resource', 400], 'implementation: bad_resource / 400');
  const row = readme.split('\n').find((l) => /`authorize\(\)` without/.test(l)) || '';
  assert.match(row, /400/, 'README errors table: status 400'); assert.match(row, /bad_resource/);
  assert.ok(!/current 0\.4\.2/.test(readme), 'README: PHP current version');
  for (const l of readme.split('\n').filter((x) => /drop the resource|drop `resource`/.test(x))) assert.match(l, /identityOnly/, 'README: identity-only guidance names identityOnly: true: ' + l);
  const r = await SV.verifyLocalPass(pass(), { passSecret: SECRET, resource: { path: '/x', method: 'GET' } });
  assert.doesNotMatch(r.reason, /drop `resource`/, 'policy_required reason names { identityOnly: true }');
  assert.match(r.reason, /identityOnly/);
});

function signLegacy(priv, message, base = 39) {
  const sha = (b) => createHash('sha256').update(b).digest();
  const m = Buffer.from(message, 'utf8');
  const len = m.length < 253 ? Buffer.from([m.length]) : Buffer.from([253, m.length & 255, m.length >> 8]);
  const h = sha(sha(Buffer.concat([Buffer.from('\x18Bitcoin Signed Message:\n'), len, m])));
  const s = secp256k1.sign(h, priv, { prehash: false, format: 'recovered' });
  return Buffer.concat([Buffer.from([base + s[0]]), Buffer.from(s.slice(1))]).toString('base64');
}
