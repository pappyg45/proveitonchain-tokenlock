// 0.4.5 RC6 (RC5 review and the second reviewer's findings), Node, failing first on 10cfc26:
//   S1 option A: self-verify "any name on Bitcoin" means a registered name (4-12 letters A-Z, not starting with A) that the
//      address OWNS, as on hosted sign-in. RC5 accepted a numeric asset (free to issue) and any positive balance.
//   Site binding: verifyLocalPass({ site }) refuses a pass issued for another site (wrong_site). RC5 had no site check, so
//      two sites sharing a passSecret accepted each other's passes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
const ROOT = process.env.TL_PKG_ROOT ? process.env.TL_PKG_ROOT.replace(/\/?$/, '/') : new URL('../', import.meta.url).pathname;
const SV = await import(ROOT + 'dist/self-verify.js');

const priv = secp256k1.utils.randomSecretKey(); const address = SV._addr.p2wpkh(secp256k1.getPublicKey(priv, true));
const sign = (message) => { const sha = (b) => createHash('sha256').update(b).digest(); const m = Buffer.from(message); const len = m.length < 253 ? Buffer.from([m.length]) : Buffer.from([253, m.length & 255, m.length >> 8]); const s = secp256k1.sign(sha(sha(Buffer.concat([Buffer.from('\x18Bitcoin Signed Message:\n'), len, m]))), priv, { prehash: false, format: 'recovered' }); return Buffer.concat([Buffer.from([39 + s[0]]), Buffer.from(s.slice(1))]).toString('base64'); };
const NUMERIC = 'A' + '1'.repeat(17), SUBASSET = 'PEPECASH.club';
const signIn = async ({ holdings, assets, name, site = 'https://club.example' }) => {
  const store = SV.memoryNonceStore(); const passSecret = 'p'.repeat(40);
  const ch = await SV.createChallenge({ site, anyName: true, ...(assets ? { assets } : {}), store });
  try { return await SV.verifySignIn({ challenge_id: ch.challenge_id, address, signature: sign(ch.message), name }, { store, holdings, passSecret }); } catch (e) { return { thrown: e.code || String(e) }; }
};

test('S1: a numeric asset (free to issue) is not "any name": bad_name, even when the wallet owns it (poc4)', async () => {
  const r = await signIn({ holdings: SV.staticProvider({ [address]: [NUMERIC] }, { [address]: [NUMERIC] }), name: NUMERIC });
  assert.equal(r.code, 'bad_name', JSON.stringify(r));
});
test('S1: a subasset is not "any name": bad_name', async () => {
  const r = await signIn({ holdings: SV.staticProvider({}, { [address]: [SUBASSET] }), name: SUBASSET });
  assert.equal(r.code, 'bad_name', JSON.stringify(r));
});
test('S1: a balance of a registered name the wallet does not own is not enough: not_holder', async () => {
  const r = await signIn({ holdings: SV.staticProvider({ [address]: ['PEPECASH'] }), name: 'PEPECASH' });
  assert.equal(r.code, 'not_holder', JSON.stringify(r));
  assert.equal(r.valid, false);
});
test('S1: the owner of a registered name signs in (any case, ASCII whitespace trimmed)', async () => {
  for (const name of ['PEPECASH', 'pepecash', ' PepeCash\t']) {
    const r = await signIn({ holdings: SV.staticProvider({}, { [address]: ['PEPECASH'] }), name });
    assert.equal(r.code, 'ok', `${JSON.stringify(name)}: ${JSON.stringify(r)}`);
    assert.deepEqual(r.assets_held, ['PEPECASH']);
  }
});
test('S1: names the hosted rule refuses are refused (bad_name), never thrown', async () => {
  for (const name of ['ABCD', 'BCD', 'BCDEFGHIJKLMN', 'B1CD', 'pepecaſh', 'PEPE CASH', 42, true, {}, []]) {
    const r = await signIn({ holdings: SV.staticProvider({}, { [address]: ['PEPECASH', 'ABCD'] }), name });
    assert.ok(!r.thrown, `${JSON.stringify(name)} threw ${r.thrown}`);
    assert.equal(r.code, 'bad_name', `${JSON.stringify(name)}: ${JSON.stringify(r)}`);
  }
});
test('S1 control: a site-listed asset still counts with a positive balance, and "any name" stays optional when assets are listed', async () => {
  const holdings = SV.staticProvider({ [address]: ['GOTPROOF'] });
  assert.equal((await signIn({ holdings, assets: ['GOTPROOF'] })).code, 'ok');
  assert.equal((await signIn({ holdings, assets: ['GOTPROOF'], name: 'PEPECASH' })).code, 'ok', 'the listed asset is held; the unowned name is simply not counted');
});
test('S1 control: the tokenscan-style provider reports ownership as how: "owner"; httpJsonProvider too', async () => {
  const fetch = async (url) => ({ ok: true, status: 200, json: async () => ({ owner: address, divisible: false }) });
  const p = SV.httpJsonProvider({ url: 'https://x.example/{asset}?a={address}', quantity: () => 1, owner: (b) => b.owner, fetch });
  const h = await p.holdings(address, ['PEPECASH']);
  assert.equal(h.PEPECASH.how, 'owner');
});

const passFor = async (site) => {
  const store = SV.memoryNonceStore(); const passSecret = 's'.repeat(40);
  const ch = await SV.createChallenge({ site, assets: ['GOTPROOF'], store });
  const r = await SV.verifySignIn({ challenge_id: ch.challenge_id, address, signature: sign(ch.message) }, { store, holdings: SV.staticProvider({ [address]: ['GOTPROOF'] }), passSecret });
  assert.equal(r.code, 'ok'); return { pass: r.pass, passSecret };
};
test('site binding: a pass issued for site A is refused at site B that shares the passSecret (wrong_site, never valid)', async () => {
  const { pass, passSecret } = await passFor('https://a.example');
  const r = await SV.verifyLocalPass(pass, { passSecret, identityOnly: true, site: 'https://b.example' });
  assert.equal(r.code, 'wrong_site'); assert.equal(r.valid, false); assert.equal(r.allowed, false);
});
test('site binding: the issuing site accepts its own pass (origin compared after normalization)', async () => {
  const { pass, passSecret } = await passFor('https://Club.Example:443/members');
  for (const site of ['https://club.example', 'https://CLUB.example/', 'https://club.example:443/x?y=1']) {
    const r = await SV.verifyLocalPass(pass, { passSecret, identityOnly: true, site });
    assert.equal(r.code, 'ok', `${site}: ${JSON.stringify(r)}`); assert.equal(r.valid, true);
  }
});
test('site binding: a malformed site option is refused (bad_site); omitting it keeps RC5 behavior', async () => {
  const { pass, passSecret } = await passFor('https://a.example');
  for (const site of ['', 'not a url', 42, null, 'ftp://a.example', 'ws://a.example', 'file:///etc', 'https://']) assert.equal((await SV.verifyLocalPass(pass, { passSecret, identityOnly: true, site })).code, 'bad_site', JSON.stringify(site));
  assert.equal((await SV.verifyLocalPass(pass, { passSecret, identityOnly: true })).code, 'ok');
});

test('site option and createChallenge accept only http(s) origins, like PHP (bad_site for ftp:, ws:, file:)', async () => {
  for (const site of ['ftp://a.example', 'ws://a.example', 'file:///etc', 'javascript:alert(1)']) {
    await assert.rejects(SV.createChallenge({ site, assets: ['GOTPROOF'], store: SV.memoryNonceStore() }), (e) => e.code === 'bad_site', site);
  }
  assert.ok((await SV.createChallenge({ site: 'http://localhost:3000', assets: ['GOTPROOF'], store: SV.memoryNonceStore() })).challenge_id);
});
