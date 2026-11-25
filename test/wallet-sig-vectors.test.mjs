// 0.5.4: wallet signature compatibility. The shared vector file (test/fixtures/wallet-sig-vectors.json) is the same file
// the hosted TOKENLOCK check and the PHP drop-in are tested against: every non-slot vector must give the same answer here.
// Covers the Freewallet CRLF retry, BIP-137 header bands 27-42, Electrum-style segwit headers, BIP-322 simple and full,
// whitespace inside the signature, hex signatures, low-S, and the fail-closed negatives. Offline, throwaway keys only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as SV from '../dist/self-verify.js';

const RAW = readFileSync(new URL('./fixtures/wallet-sig-vectors.json', import.meta.url), 'utf8');
const DOC = JSON.parse(RAW);
const real = DOC.vectors.filter((v) => v.source !== 'slot');
const FW_ADDR = '13Hnmhs5gy2yXKVBx4wSM5HCBdKnaSBZJH';
const FW_SIG = 'H+Xyciqy//n27mlTymwBBeFz5wNeTqZKNhqW9ASfcSNqS5FXUn/4D0tJ2m9HHRxOtVZrbJ3gWNn8S6KAoZOtXQs=';
const FW_LINES = ['Sign in with your Token', 'Site: https://pepeproject.com', 'Requires: TOKENLOCK', 'Via: tokenlock.ai', 'Nonce: 396555173588b1f81ef0a69a2af927f7',
  'Issued: 2026-11-25T15:10:10.816Z', 'Expires: 2026-11-25T15:20:10.816Z', 'Signing proves you control this address. It moves no funds.'];

test('the shared vector file: version 1, the real Freewallet vector, reserved Electrum and Sparrow slots (skipped until filled)', () => {
  assert.equal(DOC.version, 1);
  assert.equal(new Set(DOC.vectors.map((v) => v.id)).size, DOC.vectors.length);
  const fw = DOC.vectors.find((v) => v.id === 'freewallet-crlf-p2pkh-h31');
  assert.deepEqual([fw.source, fw.valid, fw.address, fw.signature, fw.header, fw.message], ['real', true, FW_ADDR, FW_SIG, 31, FW_LINES.join('\n')]);
  for (const id of ['slot-electrum-real', 'slot-sparrow-real']) {
    const s = DOC.vectors.find((v) => v.id === id);
    assert.deepEqual([s.source, s.valid, s.address, s.message, s.signature], ['slot', null, '', '', '']);
  }
  assert.doesNotMatch(RAW, /"(?:wif|priv(?:ate)?(?:_?key)?|seed|secret)"\s*:/i);
  assert.ok(real.length >= 80);
});

test('verifyMessageSignature agrees with every non-slot vector', () => {
  const wrong = real.filter((v) => SV.verifyMessageSignature(v.address, v.message, v.signature) !== v.valid).map((v) => `${v.id} (want ${v.valid})`);
  assert.deepEqual(wrong, []);
});

test('Freewallet: LF and CRLF forms verify; trailing whitespace, altered fields and wrong address do not', () => {
  const LF = FW_LINES.join('\n'), CRLF = FW_LINES.join('\r\n');
  assert.equal(SV.verifyMessageSignature(FW_ADDR, LF, FW_SIG), true);
  assert.equal(SV.verifyMessageSignature(FW_ADDR, CRLF, FW_SIG), true);
  for (const [a, m, s] of [[FW_ADDR, LF + '\n', FW_SIG], [FW_ADDR, LF + ' ', FW_SIG], [FW_ADDR, LF.replace('396555', '396556'), FW_SIG], [FW_ADDR, LF.replace('pepeproject.com', 'example.com'), FW_SIG],
    [FW_ADDR, LF.replace('TOKENLOCK', 'TOKENLOCKX'), FW_SIG], ['1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH', LF, FW_SIG], [FW_ADDR, null, FW_SIG], [FW_ADDR, LF, ''], [FW_ADDR, LF, null]]) {
    assert.equal(SV.verifyMessageSignature(a, m, s), false);
  }
});

test('the same signature as hex, 0x-hex and wrapped base64 verifies; header bytes outside 27-42 never do', () => {
  const LF = FW_LINES.join('\n'), b = Buffer.from(FW_SIG, 'base64');
  assert.equal(SV.verifyMessageSignature(FW_ADDR, LF, b.toString('hex')), true);
  assert.equal(SV.verifyMessageSignature(FW_ADDR, LF, '0x' + b.toString('hex').toUpperCase()), true);
  assert.equal(SV.verifyMessageSignature(FW_ADDR, LF, FW_SIG.match(/.{1,20}/g).join('\r\n')), true);
  for (let h = 0; h < 256; h++) { if (h >= 27 && h <= 42) continue; const x = Buffer.from(b); x[0] = h; assert.equal(SV.verifyMessageSignature(FW_ADDR, LF, x.toString('base64')), false, String(h)); }
});

test('never throws on hostile input and stays fast', () => {
  for (const [a, m, s] of [[undefined, undefined, undefined], [{}, [], 5], [FW_ADDR, 'x', 'A'.repeat(200000)], [FW_ADDR, 'x', 'ab'.repeat(100000)], [FW_ADDR, 'x', Buffer.alloc(400).toString('base64')]]) {
    const t0 = Date.now(); assert.equal(SV.verifyMessageSignature(a, m, s), false); assert.ok(Date.now() - t0 < 2000);
  }
});

test('signatureFormatProblem names exactly the expected format problem for every vector (null when well formed)', () => {
  const wrong = real.filter((v) => SV.signatureFormatProblem(v.address, v.signature) !== v.format).map((v) => `${v.id}: got ${SV.signatureFormatProblem(v.address, v.signature)} want ${v.format}`);
  assert.deepEqual(wrong, []);
  for (const code of Object.keys(SV.FORMAT_PROBLEMS)) assert.ok(real.some((v) => v.format === code), code);
});

test('the real Freewallet signature passes the strict rules (standard padded base64; LF, CRLF, hex, wrapped); its lenient variants are named', () => {
  const by = (id) => DOC.vectors.find((v) => v.id === id);
  assert.match(by('freewallet-crlf-p2pkh-h31').signature, /^[A-Za-z0-9+/]{86}[A-Za-z0-9+/=]=$/);
  for (const id of ['freewallet-crlf-p2pkh-h31', 'freewallet-crlf-p2pkh-h31-given-crlf', 'freewallet-strict-hex', 'freewallet-strict-wrapped']) {
    const v = by(id); assert.equal(v.valid, true); assert.equal(SV.verifyMessageSignature(v.address, v.message, v.signature), true, id); assert.equal(SV.signatureFormatProblem(v.address, v.signature), null, id);
  }
  for (const id of ['freewallet-unpadded', 'freewallet-urlsafe']) { const v = by(id); assert.equal(SV.verifyMessageSignature(v.address, v.message, v.signature), false); assert.equal(SV.signatureFormatProblem(v.address, v.signature), 'base64_variant'); }
});

test('verifySignIn: a format refusal carries signature_format and says so; a wrong-key signature keeps the plain reason', async () => {
  const { secp256k1 } = await import('@noble/curves/secp256k1.js');
  const { createHash } = await import('node:crypto');
  const sha = (b) => createHash('sha256').update(b).digest();
  const sign = (priv, message) => { const m = Buffer.from(message, 'utf8'); const h = sha(sha(Buffer.concat([Buffer.from('\x18Bitcoin Signed Message:\n'), (m.length < 253 ? Buffer.from([m.length]) : Buffer.from([253, m.length & 255, m.length >> 8])), m]))); const s = secp256k1.sign(h, priv, { prehash: false, format: 'recovered' }); return Buffer.concat([Buffer.from([39 + s[0]]), Buffer.from(s.slice(1))]).toString('base64'); };
  const priv = secp256k1.utils.randomSecretKey(), other = secp256k1.utils.randomSecretKey();
  const address = SV._addr.p2wpkh(secp256k1.getPublicKey(priv, true));
  const store = SV.memoryNonceStore(); const cfg = { store, holdings: SV.staticProvider({ [address]: ['GOTPROOF'] }), passSecret: 'x'.repeat(40) };
  let ch = await SV.createChallenge({ site: 'https://shop.example', assets: ['GOTPROOF'], store });
  let r = await SV.verifySignIn({ challenge_id: ch.challenge_id, address, signature: sign(priv, ch.message).replace(/=+$/, '') }, cfg);
  assert.equal(r.code, 'bad_signature'); assert.equal(r.signature_format, 'base64_variant'); assert.match(r.reason, /^Unsupported signature format: The signature uses a base64 variant/);
  ch = await SV.createChallenge({ site: 'https://shop.example', assets: ['GOTPROOF'], store });
  r = await SV.verifySignIn({ challenge_id: ch.challenge_id, address, signature: sign(other, ch.message) }, cfg);
  assert.equal(r.code, 'bad_signature'); assert.equal(r.signature_format, undefined); assert.equal(r.reason, 'The signature does not match this address and message.');
  ch = await SV.createChallenge({ site: 'https://shop.example', assets: ['GOTPROOF'], store });
  assert.equal((await SV.verifySignIn({ challenge_id: ch.challenge_id, address, signature: sign(priv, ch.message) }, cfg)).code, 'ok');
});
