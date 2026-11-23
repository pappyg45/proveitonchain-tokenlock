// 0.4.5 RC5 (RC3 review): failing first.
//   H1 (client side): a signed-policy source never accepts a bundle that drops registered-keys mode unless the bundle's
//      state_version is higher than the one it replaces (a hosted store loss signed mode=token, keys=[], state_version 0).
//   S2: a policy with two keys for one address (or one id) is ambiguous: policy_invalid, never "first one wins".
//   S3: verifySignIn answers { code: 'bad_asset' } for a malformed name (Node threw; PHP already answered bad_asset).
// Adapted from the review's poc4-sdk.mjs (S2, S3) and poc1 (H1). TL_PKG_ROOT selects the package under test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
const ROOT = process.env.TL_PKG_ROOT ? process.env.TL_PKG_ROOT.replace(/\/?$/, '/') : new URL('../', import.meta.url).pathname;
const SV = await import(ROOT + 'dist/self-verify.js');
const F = JSON.parse(readFileSync(new URL('../php/test/fixtures/rc5-bundles.json', import.meta.url), 'utf8'));
const B = F.bundles, PK = F.public_keys, ADDR = F.address;
const RES = { path: '/members/x', method: 'GET', environment: 'production' };

function source(seqOfBundles) {
  let i = 0;
  return SV.signedPolicy({ siteId: 'site1', secretKey: 'sk_' + 'f'.repeat(40), publicKeys: PK, refreshSeconds: 0, retryMinSeconds: 0.01, load: async () => seqOfBundles[Math.min(i++, seqOfBundles.length - 1)] });
}
const nap = (ms) => new Promise((r) => setTimeout(r, ms));
async function get(src) { try { return await src.get(); } catch (e) { return { thrown: e.code }; } }

test('H1 client: after a registered policy (state_version 7), a token bundle with state_version 0 (store-loss shape) is refused; the revoked key and unregistered holders stay denied', async () => {
  const src = source([B.registered_v7_revoked, B.token_v0_after_loss]);
  const p1 = await get(src); assert.equal(p1.mode, 'registered_keys');
  await nap(30); const p2 = await get(src);
  assert.equal(p2.mode, 'registered_keys', 'downgraded policy accepted');
  assert.equal(SV.evaluate(p2, { address: ADDR, held: ['CLUB'], identityOnly: true }).reason, 'key_revoked');
  assert.equal(SV.evaluate(p2, { address: 'bc1qattacker', held: ['CLUB'], identityOnly: true }).allowed, false);
  assert.match(String(src.status().last_error), /policy_downgrade/);
});
test('H1 client: a token bundle at the SAME state_version, or without one, is refused too', async () => {
  for (const b of [B.token_v7_same_version, B.token_no_version]) {
    const src = source([B.registered_v7_revoked, b]); await get(src); await nap(30);
    assert.equal((await get(src)).mode, 'registered_keys');
  }
});
test('H1 client: verifyPolicyBundle({ previous }) refuses the downgrade with policy_downgrade', () => {
  const prev = SV.verifyPolicyBundle(B.registered_v7_revoked, { publicKeys: PK, siteId: 'site1' });
  assert.throws(() => SV.verifyPolicyBundle(B.token_v0_after_loss, { publicKeys: PK, siteId: 'site1', previous: prev }), (e) => e.code === 'policy_downgrade');
});
test('H1 client control: a legitimate turn-off (token bundle with a higher state_version) is accepted, and turning back on works', async () => {
  const src = source([B.registered_v7_revoked, B.token_v8_turned_off, B.registered_v9_back_on]);
  assert.equal((await get(src)).mode, 'registered_keys'); await nap(30);
  assert.equal((await get(src)).mode, 'token'); await nap(30);
  assert.equal((await get(src)).mode, 'registered_keys');
});

const KP = { routes: ['*'], methods: ['*'], environments: ['*'] };
test('S2: duplicate address entries (active then revoked) are policy_invalid, never first-one-wins (poc4)', async () => {
  const base = { mode: 'registered_keys', keys: [{ id: 'k1', address: ADDR, status: 'active', permissions: KP }, { id: 'k2', address: ADDR, status: 'revoked', permissions: KP }] };
  let pol = null; try { pol = await SV.localPolicy(base).get(); } catch (e) { assert.equal(e.code, 'policy_invalid'); }
  if (pol) { const r = SV.evaluate(pol, { address: ADDR, held: ['CLUB'], resource: { path: '/admin', method: 'POST' } }); assert.equal(r.allowed, false); assert.equal(r.reason, 'policy_invalid'); }
  assert.throws(() => SV.validatePolicy({ v: 1, typ: 'tokenlock.policy', site_id: 's', seq: 1, issued_at: new Date(Date.now() - 1000).toISOString(), expires_at: new Date(Date.now() + 60000).toISOString(), orgs: [], revoked_assets: [], ...base }), (e) => e.code === 'policy_invalid');
});
test('S2: duplicate key ids are policy_invalid; also when the duplicate address differs only in case', () => {
  const P = (keys) => ({ v: 1, typ: 'tokenlock.policy', site_id: 's', seq: 1, issued_at: new Date(Date.now() - 1000).toISOString(), expires_at: new Date(Date.now() + 60000).toISOString(), orgs: [], revoked_assets: [], mode: 'registered_keys', keys });
  assert.throws(() => SV.validatePolicy(P([{ id: 'k1', address: 'bc1qa', status: 'active', permissions: KP }, { id: 'k1', address: 'bc1qb', status: 'active', permissions: KP }])), (e) => e.code === 'policy_invalid');
  assert.throws(() => SV.validatePolicy(P([{ id: 'k1', address: 'bc1qabc', status: 'active', permissions: KP }, { id: 'k2', address: 'BC1QABC', status: 'revoked', permissions: KP }])), (e) => e.code === 'policy_invalid');
  SV.validatePolicy(P([{ id: 'k1', address: 'bc1qa', status: 'active', permissions: KP }, { id: 'k2', address: 'bc1qb', status: 'revoked', permissions: KP }]));
});

const priv = secp256k1.utils.randomSecretKey(); const address = SV._addr.p2wpkh(secp256k1.getPublicKey(priv, true));
const sign = (message) => { const sha = (b) => createHash('sha256').update(b).digest(); const m = Buffer.from(message); const len = m.length < 253 ? Buffer.from([m.length]) : Buffer.from([253, m.length & 255, m.length >> 8]); const s = secp256k1.sign(sha(sha(Buffer.concat([Buffer.from('\x18Bitcoin Signed Message:\n'), len, m]))), priv, { prehash: false, format: 'recovered' }); return Buffer.concat([Buffer.from([39 + s[0]]), Buffer.from(s.slice(1))]).toString('base64'); };
// RC6 (S1 option A, U16): a name that is not a registered name now answers bad_name (as hosted sign-in does); it still never throws.
test('S3: verifySignIn with a malformed name answers bad_name (does not throw), for several malformed names (poc4)', async () => {
  for (const name of ['not a name!', '', 'A1', '1ABC', 'x'.repeat(300), 42, null, {}, []]) {
    const store = SV.memoryNonceStore();
    const cfg = { store, holdings: SV.staticProvider({ [address]: ['PEPECASH'] }), passSecret: randomBytes(32).toString('hex') };
    const ch = await SV.createChallenge({ site: 'https://club.example', anyName: true, store });
    let r; try { r = await SV.verifySignIn({ challenge_id: ch.challenge_id, address, signature: sign(ch.message), name }, cfg); } catch (e) { r = { thrown: e.code || String(e) }; }
    assert.ok(!r.thrown, `name ${JSON.stringify(name)}: threw ${r.thrown}`);
    assert.equal(r.valid === true, false, `name ${JSON.stringify(name)}: accepted`);
    if (typeof name === 'string' && name) assert.equal(r.code, 'bad_name', `name ${JSON.stringify(name)}: ${r.code}`);
  }
});
// RC6 (S1 option A, U16): the name must be OWNED (how: 'owner'), so the control's provider now reports ownership.
test('S3 control: a well-formed owned name still signs in', async () => {
  const store = SV.memoryNonceStore();
  const cfg = { store, holdings: SV.staticProvider({}, { [address]: ['PEPECASH'] }), passSecret: randomBytes(32).toString('hex') };
  const ch = await SV.createChallenge({ site: 'https://club.example', anyName: true, store });
  const r = await SV.verifySignIn({ challenge_id: ch.challenge_id, address, signature: sign(ch.message), name: 'PEPECASH' }, cfg);
  assert.equal(r.code, 'ok');
});

// RC5 deep review: seq and state_version validation is identical in Node and PHP (php/test/rc5-045.php has the same table).
test('parity: seq and state_version accept an integer 0 .. 2^53-1 (also 1e0) and nothing else', async () => {
  const PV = { '0': true, '-0': true, '1e0': true, '9007199254740991': true, '9007199254740992': false, '9223372036854775807': false, '-1': false, '1.5': false, '"3"': false, 'true': false, 'null': false, '1e20': false };
  for (const field of ['seq', 'state_version']) {
    const bad = [];
    for (const [raw, want] of Object.entries(PV)) {
      const pol = { v: 1, typ: 'tokenlock.policy', site_id: 's', seq: 1, issued_at: '2026-01-01T00:00:00.000Z', expires_at: '2099-01-01T00:00:00.000Z', mode: 'registered_keys', orgs: [], revoked_assets: [], keys: [] };
      pol[field] = JSON.parse(raw);
      let ok = true; try { await SV.localPolicy(pol).get(); } catch { ok = false; }
      if (ok !== want) bad.push(`${raw}: ${ok ? 'accepted' : 'refused'}`);
    }
    assert.deepEqual(bad, [], field);
  }
});

// RC5 deep review: asset names normalize the same way in Node, PHP and hosted (challenges.js): a string, ASCII whitespace
// trimmed, ASCII letters uppercased. Node and hosted uppercased Unicode (pepeca\u017fh -> PEPECASH, stra\u00dfe -> STRASSE),
// trimmed NBSP/BOM and String()-ed non-strings (true -> TRUE, ['PEPECASH'] -> PEPECASH); PHP refused those and trimmed NUL.
export const NAME_TABLE = {"pepecash":"PEPECASH"," PEPECASH\t\n":"PEPECASH","PEPECASH\u000b":"PEPECASH","pepecash.Sub":"PEPECASH.Sub","a123456789012":"A123456789012","pepeca\u017fh":null,"p\u0131zza":null,"stra\u00dfe":null,"PEPECASH\u00a0":null,"\ufeffPEPECASH":null,"PEPECASH\u0000":null,"pepecash.\u017fub":null};
test('parity: normalizeAsset is ASCII-only and string-only (same table as PHP and hosted)', () => {
  const bad = [];
  for (const [raw, want] of Object.entries(NAME_TABLE)) { let got; try { got = SV.normalizeAsset(raw); } catch (e) { got = e.code === 'bad_asset' ? null : 'threw ' + e.code; } if (got !== want) bad.push(`${JSON.stringify(raw)} -> ${JSON.stringify(got)}`); }
  for (const raw of [true, ["PEPECASH"], 42, {}, null, ""]) { let got; try { got = SV.normalizeAsset(raw); } catch (e) { got = e.code === 'bad_asset' ? null : 'threw ' + e.code; } if (got !== null) bad.push(`${JSON.stringify(raw)} -> ${JSON.stringify(got)}`); }
  assert.deepEqual(bad, []);
});
