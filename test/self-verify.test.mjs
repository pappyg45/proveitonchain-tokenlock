// Self-verify (0.3.0): local signature check (same answers as the hosted check), customer nonce store (replay),
// expiry, holdings providers (fail closed), signed policy bundles (pinned key, tamper, site, expiry, rollback),
// local passes and the access rule.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import * as SV from '../dist/self-verify.js';

const VEC = JSON.parse(readFileSync(new URL('./fixtures/sig-vectors.json', import.meta.url), 'utf8'));
const PB = JSON.parse(readFileSync(new URL('./fixtures/policy-bundle.json', import.meta.url), 'utf8'));
const sha = (b) => createHash('sha256').update(b).digest();
function signLegacy(priv, message, base = 39) {
  const m = Buffer.from(message, 'utf8');
  const len = m.length < 253 ? Buffer.from([m.length]) : Buffer.from([253, m.length & 255, m.length >> 8]);
  const h = sha(sha(Buffer.concat([Buffer.from('\x18Bitcoin Signed Message:\n'), len, m])));
  const s = secp256k1.sign(h, priv, { prehash: false, format: 'recovered' });
  return Buffer.concat([Buffer.from([base + s[0]]), Buffer.from(s.slice(1))]).toString('base64');
}
const wallet = () => { const priv = secp256k1.utils.randomSecretKey(); return { priv, address: SV._addr.p2wpkh(secp256k1.getPublicKey(priv, true)) }; };
const SECRET = 'x'.repeat(40);

test('signatures: every shared vector gives the same answer as the hosted check', () => {
  let bad = [];
  for (const v of VEC.vectors) if (SV.verifyMessageSignature(v.address, v.message, v.signature) !== v.valid) bad.push(v.kind);
  assert.deepEqual(bad, []);
  assert.ok(VEC.vectors.length > 300 && VEC.vectors.filter((v) => v.valid).length > 100);
  for (const k of ['bip322-p2wpkh', 'bip322-p2sh', 'bip322-p2tr', 'legacy-p2pkh-h31', 'legacy-p2sh-h35', 'legacy-p2wpkh-h39', 'legacy-p2tr-h31']) assert.ok(VEC.vectors.some((v) => v.kind === k && v.valid), k);
});

test('challenge + sign-in: valid once; replay, tamper, expiry and wrong address are refused', async () => {
  const store = SV.memoryNonceStore(); const w = wallet();
  const cfg = { store, holdings: SV.staticProvider({ [w.address]: ['GOTPROOF'] }), passSecret: SECRET };
  const ch = await SV.createChallenge({ site: 'https://shop.example/x', assets: ['gotproof'], store });
  assert.match(ch.message, /^Sign in with your Token\nSite: https:\/\/shop\.example\nRequires: GOTPROOF\nVia: self-verify\nNonce: [0-9a-f]{32}\n/);
  const sig = signLegacy(w.priv, ch.message);
  const r = await SV.verifySignIn({ challenge_id: ch.challenge_id, address: w.address, signature: sig }, cfg);
  assert.equal(r.valid, true, JSON.stringify(r)); assert.match(r.pass, /^tl3\./); assert.deepEqual(r.assets_held, ['GOTPROOF']);
  assert.equal((await SV.verifySignIn({ challenge_id: ch.challenge_id, address: w.address, signature: sig }, cfg)).code, 'unknown_challenge', 'replay');
  const ch2 = await SV.createChallenge({ site: 'https://shop.example', assets: ['GOTPROOF'], store });
  assert.equal((await SV.verifySignIn({ challenge_id: ch2.challenge_id, address: w.address, signature: signLegacy(w.priv, ch2.message + ' ') }, cfg)).code, 'bad_signature');
  assert.equal((await SV.verifySignIn({ challenge_id: ch2.challenge_id, address: w.address, signature: sig }, cfg)).code, 'unknown_challenge', 'a failed try still burns the nonce');
  const ch3 = await SV.createChallenge({ site: 'https://shop.example', assets: ['GOTPROOF'], store, ttlSeconds: 60 });
  assert.equal((await SV.verifySignIn({ challenge_id: ch3.challenge_id, address: w.address, signature: signLegacy(w.priv, ch3.message) }, cfg, Date.now() + 61_000)).code, 'expired');
  const other = wallet(); const ch4 = await SV.createChallenge({ site: 'https://shop.example', assets: ['GOTPROOF'], store });
  assert.equal((await SV.verifySignIn({ challenge_id: ch4.challenge_id, address: other.address, signature: signLegacy(w.priv, ch4.message) }, cfg)).code, 'bad_signature');
  const ch5 = await SV.createChallenge({ site: 'https://shop.example', assets: ['GOTPROOF'], store });
  assert.equal((await SV.verifySignIn({ challenge_id: ch5.challenge_id, address: other.address, signature: signLegacy(other.priv, ch5.message) }, cfg)).code, 'not_holder');
});

test('file nonce store: single use across two "servers" sharing a folder', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'tl-nonce-'));
  try {
    const a = SV.fileNonceStore(dir), b = SV.fileNonceStore(dir);
    const ch = await SV.createChallenge({ site: 'https://shop.example', assets: ['GOTPROOF'], store: a });
    const [x, y] = await Promise.all([a.take(ch.challenge_id), b.take(ch.challenge_id)]);
    assert.equal([x, y].filter(Boolean).length, 1);
    assert.equal(await a.take('../../etc/passwd'), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('providers: tokenscan, httpJson and ours parse answers; any failure fails closed', async () => {
  const J = (o, s = 200) => ({ ok: s < 400, status: s, json: async () => o });
  const ts = SV.tokenscanProvider({ fetch: async (u) => u.includes('/asset/GOTPROOF') ? J({ asset: 'GOTPROOF', owner: 'bc1qowner' }) : u.includes('/asset/NOPE') ? J({ error: 'Asset not found' }, 404) : u.includes('/balances/bc1qme/1/') ? J({ data: [{ asset: 'GOTPROOF', quantity: '3' }] }) : J({}, 500) });
  assert.deepEqual(await ts.holdings('bc1qme', ['GOTPROOF', 'NOPE']), { GOTPROOF: { held: true, how: 'balance', quantity: '3', exists: true }, NOPE: { held: false, how: null, exists: false } });
  assert.equal((await ts.holdings('bc1qowner', ['GOTPROOF'])).GOTPROOF.how, 'owner');
  const down = SV.tokenscanProvider({ fetch: async () => { throw new Error('down'); } });
  await assert.rejects(down.holdings('bc1qme', ['GOTPROOF']), (e) => e.code === 'lookup_failed');
  const hj = SV.httpJsonProvider({ url: 'https://node.example/bal/{address}/{asset}', quantity: (b) => b.qty, fetch: async (u) => J({ qty: u.endsWith('/GOTPROOF') ? 1 : 0 }) });
  assert.deepEqual(await hj.holdings('bc1qme', ['GOTPROOF', 'OTHER']), { GOTPROOF: { held: true, how: 'balance', quantity: '1' }, OTHER: { held: false, how: null } });
  const junk = SV.httpJsonProvider({ url: 'https://n/{address}', quantity: (b) => b.nope, fetch: async () => J({}) });
  await assert.rejects(junk.holdings('bc1qme', ['GOTPROOF']), (e) => e.code === 'lookup_failed', 'unreadable answer fails closed');
  const ours = SV.proveitonchainProvider({ fetch: async (u) => { assert.match(u, /\/api\/v1\/tokenlock\/holdings\?address=bc1qme&assets=GOTPROOF/); return J({ holdings: { GOTPROOF: { held: true, how: 'balance' } } }); } });
  assert.equal((await ours.holdings('bc1qme', ['GOTPROOF'])).GOTPROOF.held, true);
  assert.equal((await SV.firstAvailable([down, hj]).holdings('bc1qme', ['GOTPROOF'])).GOTPROOF.held, true);
  await assert.rejects(SV.firstAvailable([down, down]).holdings('bc1qme', ['GOTPROOF']), (e) => e.code === 'lookup_failed');
  const no = SV.staticProvider({});
  await assert.rejects(SV.requireAgreement([hj, no]).holdings('bc1qme', ['GOTPROOF']), (e) => e.code === 'lookup_disagreement');
  // a sign-in with a failing provider is refused (fail closed)
  const store = SV.memoryNonceStore(); const w = wallet();
  const ch = await SV.createChallenge({ site: 'https://shop.example', assets: ['GOTPROOF'], store });
  const r = await SV.verifySignIn({ challenge_id: ch.challenge_id, address: w.address, signature: signLegacy(w.priv, ch.message) }, { store, holdings: down, passSecret: SECRET });
  assert.equal(r.valid, false); assert.equal(r.code, 'lookup_failed'); assert.equal(r.pass, undefined);
});

test('policy bundle: pinned key verifies; tamper, unknown key, wrong site, expiry, staleness and rollback are refused', () => {
  const opts = { publicKeys: { [PB.kid]: PB.public_key }, siteId: 'site_fixture', now: PB.now + 1000 };
  const p = SV.verifyPolicyBundle(PB.bundle, opts);
  assert.equal(p.seq, 7); assert.equal(p.mode, 'registered_keys');
  const code = (b, o = opts) => { try { SV.verifyPolicyBundle(b, o); return 'ok'; } catch (e) { return e.code; } };
  const flip = PB.bundle.payload.slice(0, 20) + (PB.bundle.payload[20] === 'A' ? 'B' : 'A') + PB.bundle.payload.slice(21);
  assert.equal(code({ ...PB.bundle, payload: flip }), 'policy_bad_signature');
  assert.equal(code({ ...PB.bundle, sig: '00'.repeat(64) }), 'policy_bad_signature');
  assert.equal(code(PB.bundle, { ...opts, publicKeys: { other: PB.public_key } }), 'policy_untrusted_key');
  assert.equal(code(PB.bundle, { ...opts, publicKeys: ['11'.repeat(32)] }), 'policy_bad_signature');
  assert.equal(code(PB.bundle, { ...opts, siteId: 'site_other' }), 'policy_wrong_site');
  assert.equal(code(PB.bundle, { ...opts, now: PB.now + 11 * 60e3 }), 'policy_expired');
  assert.equal(code(PB.bundle, { ...opts, maxAgeSeconds: 0.5 }), 'policy_stale');
  assert.equal(code(PB.bundle, { ...opts, minSeq: 8 }), 'policy_rollback');
});

test('signedPolicy: refreshes, keeps the last good bundle while fresh, then fails closed', async () => {
  // a bundle signed here with a throwaway key, valid for 2 s
  const sk = secp256k1.utils.randomSecretKey(); const pk = Buffer.from(schnorr.getPublicKey(sk)).toString('hex');
  const now = Date.now();
  const payload = { v: 1, typ: 'tokenlock.policy', site_id: 's1', seq: 1, issued_at: new Date(now).toISOString(), expires_at: new Date(now + 2000).toISOString(), mode: 'token', orgs: [], revoked_assets: [], keys: [] };
  const bytes = Buffer.from(JSON.stringify(payload));
  const tag = sha(Buffer.from('TOKENLOCK/policy/v1')); const msg = sha(Buffer.concat([tag, tag, bytes]));
  const bundle = { v: 1, typ: 'tokenlock.policy-bundle', alg: 'BIP340', kid: 'k1', payload: bytes.toString('base64url'), sig: Buffer.from(schnorr.sign(msg, sk)).toString('hex') };
  let up = true, loads = 0;
  const src = SV.signedPolicy({ siteId: 's1', secretKey: 'sk_x', publicKeys: { k1: pk }, refreshSeconds: 0, load: async () => { loads++; if (!up) throw new Error('down'); return bundle; } });
  assert.equal((await src.get()).seq, 1);
  up = false;
  assert.equal((await src.get()).seq, 1, 'outage: cached bundle still used before it expires');
  await new Promise((r) => setTimeout(r, 2100));
  await assert.rejects(src.get(), (e) => e.code === 'policy_expired');
  assert.ok(loads >= 2, "a refresh was attempted during the outage");
});

test('access rule + local pass: registered key routes (canonical, case-insensitive), revocation, org, expiry', async () => {
  const pol = SV.verifyPolicyBundle(PB.bundle, { publicKeys: { [PB.kid]: PB.public_key }, siteId: 'site_fixture', now: PB.now });
  // 0.4.4: identity is explicit (resource null → identityOnly: true).
  const ev = (address, resource, held = ['GOTPROOF']) => SV.evaluate(pol, resource === null ? { address, held, identityOnly: true, now: PB.now } : { address, held, resource, now: PB.now }).reason;
  assert.equal(ev('bc1qfixtureaddressa', { path: '/api/x', method: 'GET', environment: 'production' }), 'ok');
  assert.equal(ev('bc1qfixtureaddressa', { path: '/API//x/', method: 'get', environment: 'production' }), 'ok');
  assert.equal(ev('bc1qfixtureaddressa', { path: '/admin', method: 'GET', environment: 'production' }), 'route_not_allowed');
  assert.equal(ev('bc1qfixtureaddressa', { path: '/api/x', method: 'POST', environment: 'production' }), 'method_not_allowed');
  assert.equal(ev('bc1qfixtureaddressa', { path: '/api/x', method: 'GET', environment: 'staging' }), 'environment_not_allowed');
  assert.equal(ev('bc1qfixtureaddressa', { path: '/api%2f..%2fadmin', method: 'GET' }), 'bad_path');
  assert.equal(ev('bc1qfixtureaddressa', { path: '/api/x', method: 'GET' }, ['OLDTOKEN']), 'entitlement_revoked');
  assert.equal(ev('bc1qfixtureaddressr', null), 'key_revoked');
  assert.equal(ev('bc1qnobody', null), 'not_registered');
  // 0.4.4: localPolicy().get() checks the validity window against the real clock, and the decision checks it against
  // `now` (PB.now here): the fixture policy expired by the real clock, so its window is widened for this local copy.
  const win = { issued_at: new Date(PB.now - 60e3).toISOString(), expires_at: new Date(Date.now() + 10 * 365 * 86400e3).toISOString() };
  const policy = SV.localPolicy({ ...pol, ...win });
  const pass = SV.issuePass({ sub: 'bc1qfixtureaddressa', h: ['GOTPROOF'], k: 'key_a', n: 'c', s: 'https://shop.example', i: Date.now(), e: Date.now() + 60e3 }, SECRET);
  const lp = (o) => SV.verifyLocalPass(pass, { passSecret: SECRET, policy, now: PB.now, ...o });
  assert.equal((await lp({ resource: { path: '/api/x', method: 'GET', environment: 'production' } })).allowed, true);
  const d = await lp({ resource: { path: '/admin', method: 'GET', environment: 'production' } });
  assert.equal(d.valid, true); assert.equal(d.allowed, false); assert.equal(d.code, 'route_not_allowed');
  assert.equal((await SV.verifyLocalPass(pass.slice(0, -2) + 'AA', { passSecret: SECRET, identityOnly: true })).code, 'bad_pass');
  assert.equal((await SV.verifyLocalPass(pass, { passSecret: 'y'.repeat(40), identityOnly: true })).code, 'bad_pass');
  const revoked = SV.localPolicy({ ...pol, ...win, keys: pol.keys.map((k) => ({ ...k, status: 'revoked' })) });
  assert.equal((await SV.verifyLocalPass(pass, { passSecret: SECRET, policy: revoked, now: PB.now, identityOnly: true })).code, 'key_revoked', 'revocation applies to existing passes at the next policy refresh');
  const broken = { async get() { throw new SV.SelfVerifyError('policy_expired', 'x', 503); } };
  assert.equal((await SV.verifyLocalPass(pass, { passSecret: SECRET, policy: broken, identityOnly: true })).allowed, false, 'policy outage fails closed');
});
