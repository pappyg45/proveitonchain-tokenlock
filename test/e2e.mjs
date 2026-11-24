// End-to-end against production (https://tokenlock.ai). Creates a throwaway account + test site through the
// dashboard API, runs the failure paths through the real SDK and a local Express-style server, then deletes the site.
// No funds, no transactions: the account key is random and lives only in memory.
import http from 'node:http';
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import * as core from '../dist/index.js';
import { tokenlock } from '../dist/express.js';

const API = process.env.TOKENLOCK_API || 'https://tokenlock.ai';
const A = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ123456789'.split('').sort((a, b) => '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.indexOf(a) - '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.indexOf(b)).join('');
function b58check(payload) {
  const full = new Uint8Array([...payload, ...sha256(sha256(payload)).slice(0, 4)]);
  let n = BigInt('0x' + Buffer.from(full).toString('hex')); let s = '';
  while (n > 0n) { s = A[Number(n % 58n)] + s; n /= 58n; }
  for (const b of full) { if (b === 0) s = '1' + s; else break; }
  return s;
}
const priv = secp256k1.utils.randomSecretKey();
const address = b58check(new Uint8Array([0, ...ripemd160(sha256(secp256k1.getPublicKey(priv, true)))]));
function sign(msg) {
  const m = Buffer.from(msg); const pre = Buffer.from('\x18Bitcoin Signed Message:\n');
  const len = m.length < 253 ? Buffer.from([m.length]) : Buffer.from([253, m.length & 255, m.length >> 8]);
  const s = secp256k1.sign(sha256(sha256(Buffer.concat([pre, len, m]))), priv, { prehash: false, format: 'recovered' });
  return Buffer.concat([Buffer.from([31 + s[0]]), Buffer.from(s.slice(1))]).toString('base64');
}

let cookie = '';
async function dash(method, path, body) {
  const r = await fetch(API + '/api/v1/tokenlock/' + path, { method, headers: { origin: API, 'content-type': 'application/json', cookie }, body: body ? JSON.stringify(body) : undefined });
  const sc = r.headers.get('set-cookie'); if (sc && sc.startsWith('tl_session=')) cookie = sc.split(';')[0];
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(`${path}: ${r.status} ${j?.code}`);
  return j;
}

const results = [];
async function step(name, fn) {
  try { await fn(); results.push(['PASS', name]); console.log('  ✔', name); }
  catch (e) { results.push(['FAIL', name, e.message]); console.log('  ✖', name, '-', e.message); }
}

const srv = http.createServer();
await new Promise((r) => srv.listen(0, '127.0.0.1', r));
const port = srv.address().port;
const LOCAL = `http://localhost:${port}`;
let site, sk;
try {
  console.log('setup: dashboard sign-in and test site');
  const ch = await dash('POST', 'auth/challenge', {});
  await dash('POST', 'auth/verify', { challenge_id: ch.challenge_id, address, signature: sign(ch.message) });
  const made = await dash('POST', 'sites', { name: 'SDK e2e test (auto-deleted)', origins: LOCAL, assets: 'TOKENLOCK' });
  site = made.site; sk = made.secret_key;
  console.log('  site', site.id, 'origin', LOCAL, 'tokens', site.assets.join(','));

  const mw = tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', secretKey: sk, apiBase: API });
  srv.on('request', (req, res) => mw(req, res, () => { res.end('SECRET ' + (req.tokenlock?.address || '')); }));

  await step('no pass → 302 to sign-in page with ?next', async () => {
    const r = await fetch(LOCAL + '/members/area?x=1', { redirect: 'manual' });
    assert.equal(r.status, 302); assert.equal(r.headers.get('location'), '/signin?next=%2Fmembers%2Farea%3Fx%3D1');
    assert.doesNotMatch(await r.text(), /SECRET/);
  });
  await step('forged pass cookie → 302 and cookie cleared (checked by production API)', async () => {
    const forged = 'pp1.eyJ2IjoxLCJzdWIiOiIxQSIsImgiOlsiVE9LRU5MT0NLIl0sInMiOiJodHRwOi8vbG9jYWxob3N0Iiwic3QiOiJ4IiwiaSI6MSwiZSI6OTk5OTk5OTk5OTk5OX0.' + 'A'.repeat(43);
    const r = await fetch(LOCAL + '/members/area', { redirect: 'manual', headers: { cookie: 'tokenlock_pass=' + forged } });
    assert.equal(r.status, 302); assert.match(r.headers.get('set-cookie') || '', /tokenlock_pass=; .*Max-Age=0/);
  });
  await step('forged pass → verifyPass(pass, { secretKey }) is invalid', async () => {
    const v = await core.verifyPass('pp1.' + 'e'.repeat(60) + '.' + 'A'.repeat(43), { secretKey: sk, apiBase: API });
    assert.equal(v.valid, false); assert.equal(v.code, 'bad_pass');
  });
  await step('forged pass → POST /api/tokenlock/session is 401, no cookie', async () => {
    const r = await fetch(LOCAL + '/api/tokenlock/session', { method: 'POST', headers: { 'content-type': 'application/json', origin: LOCAL }, body: JSON.stringify({ pass: 'pp1.' + 'e'.repeat(60) + '.' + 'A'.repeat(43) }) });
    assert.equal(r.status, 401); assert.equal(r.headers.get('set-cookie'), null);
  });
  await step('session exchange from another site → 403', async () => {
    const r = await fetch(LOCAL + '/api/tokenlock/session', { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://evil.example' }, body: JSON.stringify({ pass: 'x' }) });
    assert.equal(r.status, 403);
  });
  await step('wrong origin → createChallenge refused (403 origin_not_allowed)', async () => {
    await assert.rejects(core.createChallenge({ siteKey: site.publishable_key, origin: 'https://evil.example', apiBase: API }), (e) => e.status === 403 && e.code === 'origin_not_allowed');
  });
  await step('right origin → challenge uses the dashboard token choice (TOKENLOCK), not code', async () => {
    const c = new core.TokenlockClient({ siteKey: site.publishable_key, apiBase: API });
    const ch = await c.createChallenge({ origin: LOCAL });
    assert.deepEqual(ch.assets, ['TOKENLOCK']); assert.equal(ch.site_id, site.id);
    const r = await c.signIn({ challengeId: ch.challenge_id, address, signature: sign(ch.message) });
    assert.equal(r.valid, false); assert.equal(r.code, 'not_holder');
  });
  await step('unknown secret key → never valid', async () => {
    const v = await core.verifyPass('pp1.' + 'e'.repeat(60) + '.' + 'A'.repeat(43), { secretKey: 'sk_' + 'Z'.repeat(43), apiBase: API });
    assert.equal(v.valid, false);
  });
  await step('dashboard attempt log recorded the failures', async () => {
    await new Promise((r) => setTimeout(r, 1500));
    const a = await dash('GET', `sites/${site.id}/attempts`);
    const codes = a.attempts.map((x) => x.code);
    assert.ok(codes.includes('origin_mismatch') && codes.includes('not_holder'), codes.join(','));
  });
} finally {
  if (site) { try { await dash('POST', `sites/${site.id}/delete`, {}); console.log('cleanup: test site deleted'); } catch (e) { console.log('cleanup FAILED', e.message); } }
  try { await dash('POST', 'auth/logout', {}); } catch {}
  srv.close();
}
const failed = results.filter((r) => r[0] === 'FAIL').length;
console.log(`\n${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
