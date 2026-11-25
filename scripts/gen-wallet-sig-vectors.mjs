// Dev only: regenerate test/fixtures/wallet-sig-vectors.json, the wallet-format vectors shared by every TOKENLOCK
// message-signature verifier (hosted tokenlock.ai, the shared site, this SDK in TypeScript and PHP).
//
//   HOSTED_VERIFIER=/path/to/server/vendor-bip322.mjs node scripts/gen-wallet-sig-vectors.mjs
//
// Keys are THROWAWAY: fixed 32-byte seeds below, never funded, never used anywhere else. Signatures are produced
// with @noble/curves (whatever build is installed: its ECDSA nonces decide the exact bytes, so regenerating with a
// different build changes signatures but not which vectors are valid). Every base signature (legacy BIP-137 and
// BIP-322 simple witness) is cross-checked against the hosted verifier bundle (bip322-js), an independent
// implementation; the script refuses to write the file if it disagrees. The format variants built on top (BIP-322
// full, hex, whitespace, headers outside 27-42, tampered templates) follow the rules in docs/self-verify-spec.md.
import { writeFileSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';

const OUT = new URL('../test/fixtures/wallet-sig-vectors.json', import.meta.url);
const { Verifier } = await import(process.env.HOSTED_VERIFIER || '../../server/vendor-bip322.mjs');

// ---------------------------------------------------------------- small helpers (no SDK imports: independent)
const sha = (b) => createHash('sha256').update(b).digest();
const dsha = (b) => sha(sha(b));
const h160 = (b) => createHash('ripemd160').update(sha(b)).digest();
const tagged = (tag, ...m) => { const t = sha(Buffer.from(tag)); return sha(Buffer.concat([t, t, ...m])); };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const varint = (n) => (n < 0xfd ? Buffer.from([n]) : Buffer.from([0xfd, n & 255, n >> 8]));
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const b2n = (b) => BigInt('0x' + Buffer.from(b).toString('hex'));
const n2b = (n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58check(body) {
  const b = Buffer.concat([body, dsha(body).subarray(0, 4)]); let n = b2n(b), s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const x of b) { if (x === 0) s = '1' + s; else break; }
  return s;
}
const BECH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function polymod(v) { const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; let c = 1; for (const x of v) { const t = c >>> 25; c = ((c & 0x1ffffff) << 5) ^ x; for (let i = 0; i < 5; i++) if ((t >>> i) & 1) c ^= G[i]; } return c >>> 0; }
function segwit(hrp, ver, prog) {
  let acc = 0, bits = 0; const d = [ver];
  for (const x of prog) { acc = (acc << 8) | x; bits += 8; while (bits >= 5) { bits -= 5; d.push((acc >> bits) & 31); } }
  if (bits) d.push((acc << (5 - bits)) & 31);
  const he = [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];
  const pm = polymod([...he, ...d, 0, 0, 0, 0, 0, 0]) ^ (ver === 0 ? 1 : 0x2bc830a3);
  return hrp + '1' + [...d, ...[0, 1, 2, 3, 4, 5].map((i) => (pm >> (5 * (5 - i))) & 31)].map((x) => BECH[x]).join('');
}
const P = secp256k1.Point;
function tapTweakPub(comp) { const x = comp.subarray(1); const t = b2n(tagged('TapTweak', x)); return Buffer.from(P.fromBytes(Buffer.concat([Buffer.from([2]), x])).add(P.BASE.multiply(t)).toBytes(true)).subarray(1); }
function tapTweakPriv(d, comp) { let k = b2n(d); if (comp[0] === 3) k = N - k; return n2b((k + b2n(tagged('TapTweak', comp.subarray(1)))) % N); }

function key(seedHex) {
  const d = Buffer.from(seedHex.repeat(32), 'hex');
  const comp = Buffer.from(secp256k1.getPublicKey(d, true)), uncomp = Buffer.from(secp256k1.getPublicKey(d, false));
  const pkh = h160(comp), redeem = Buffer.concat([Buffer.from([0x00, 0x14]), pkh]), q = tapTweakPub(comp);
  return {
    d, comp, uncomp, pkh, redeem,
    p2pkh: b58check(Buffer.concat([Buffer.from([0]), pkh])), p2pkhU: b58check(Buffer.concat([Buffer.from([0]), h160(uncomp)])),
    p2sh: b58check(Buffer.concat([Buffer.from([5]), h160(redeem)])), p2wpkh: segwit('bc', 0, pkh), p2tr: segwit('bc', 1, q),
    spk: {
      p2wpkh: Buffer.concat([Buffer.from([0x00, 0x14]), pkh]), p2sh: Buffer.concat([Buffer.from([0xa9, 0x14]), h160(redeem), Buffer.from([0x87])]),
      p2tr: Buffer.concat([Buffer.from([0x51, 0x20]), q]),
    },
  };
}

// ---------------------------------------------------------------- legacy (BIP-137) and BIP-322
const magic = (m) => { const b = Buffer.from(m, 'utf8'); return dsha(Buffer.concat([Buffer.from('\x18Bitcoin Signed Message:\n'), varint(b.length), b])); };
function legacy(k, m, base) { const s = secp256k1.sign(magic(m), k.d, { prehash: false, format: 'recovered' }); return Buffer.concat([Buffer.from([base + s[0]]), Buffer.from(s.subarray(1))]); }

function toSpendTxid(m, spk) {
  const ss = Buffer.concat([Buffer.from([0x00, 0x20]), tagged('BIP0322-signed-message', Buffer.from(m, 'utf8'))]);
  return dsha(Buffer.concat([u32(0), Buffer.from([1]), Buffer.alloc(32), Buffer.from('ffffffff', 'hex'), varint(ss.length), ss, u32(0),
    Buffer.from([1]), Buffer.alloc(8), varint(spk.length), spk, u32(0)]));
}
const OPRET = Buffer.concat([Buffer.alloc(8), Buffer.from([1, 0x6a])]);
function sighash143(txid, pkh) {
  const op = Buffer.concat([txid, u32(0)]);
  const code = Buffer.concat([Buffer.from([0x19, 0x76, 0xa9, 0x14]), pkh, Buffer.from([0x88, 0xac])]);
  return dsha(Buffer.concat([u32(0), dsha(op), dsha(u32(0)), op, code, Buffer.alloc(8), u32(0), dsha(OPRET), u32(0), u32(1)]));
}
function sighash341(txid, spk, ht = 0x00) {
  const op = Buffer.concat([txid, u32(0)]);
  return tagged('TapSighash', Buffer.concat([Buffer.from([0x00, ht]), u32(0), u32(0), sha(op), sha(Buffer.alloc(8)), sha(Buffer.concat([varint(spk.length), spk])),
    sha(u32(0)), sha(OPRET), Buffer.from([0x00]), u32(0)]));
}
function der(rs, highS = false) {
  let r = b2n(rs.subarray(0, 32)), s = b2n(rs.subarray(32)); if (highS) s = N - s;
  const enc = (n) => { let b = Buffer.from(n.toString(16).padStart(64, '0'), 'hex'); while (b.length > 1 && b[0] === 0 && b[1] < 0x80) b = b.subarray(1); return b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b; };
  const R = enc(r), S = enc(s);
  return Buffer.concat([Buffer.from([0x30, R.length + S.length + 4, 0x02, R.length]), R, Buffer.from([0x02, S.length]), S]);
}
const witness = (items) => Buffer.concat([varint(items.length), ...items.flatMap((x) => [varint(x.length), x])]);
/** BIP-322 simple signature (the to_sign witness stack) for k's `type` address. */
function bip322Items(k, type, m, { highS = false } = {}) {
  const txid = toSpendTxid(m, k.spk[type]);
  if (type === 'p2tr') return [Buffer.from(schnorr.sign(sighash341(txid, k.spk.p2tr), tapTweakPriv(k.d, k.comp), Buffer.alloc(32)))];
  const rs = Buffer.from(secp256k1.sign(sighash143(txid, k.pkh), k.d, { prehash: false }));
  return [Buffer.concat([der(rs, highS), Buffer.from([0x01])]), k.comp];
}
/** BIP-322 full signature: the whole serialized to_sign transaction (BIP-144 segwit serialization). */
function fullTx(k, type, m, items, o = {}) {
  const txid = o.txid || toSpendTxid(m, k.spk[type]);
  const scriptSig = o.scriptSig ?? (type === 'p2sh' ? Buffer.concat([Buffer.from([0x16]), k.redeem]) : Buffer.alloc(0));
  const ins = o.inputs ?? 1, outs = o.outputs ?? [OPRET];
  const input = Buffer.concat([txid, u32(o.vout ?? 0), varint(scriptSig.length), scriptSig, u32(o.sequence ?? 0)]);
  const wit = Buffer.concat(Array.from({ length: ins }, () => witness(items)));
  return Buffer.concat([u32(o.version ?? 0), Buffer.from([0x00, 0x01]), varint(ins), ...Array(ins).fill(input), varint(outs.length), ...outs, wit, u32(o.locktime ?? 0), o.trailing || Buffer.alloc(0)]);
}

// ---------------------------------------------------------------- the vectors
const LINES = (site, nonce) => ['Sign in with your Token', `Site: ${site}`, 'Requires: TOKENLOCK', 'Via: tokenlock.ai', `Nonce: ${nonce}`,
  'Issued: 2026-11-25T15:10:10.816Z', 'Expires: 2026-11-25T15:20:10.816Z', 'Signing proves you control this address. It moves no funds.'];
const M = LINES('https://shop.example', '00112233445566778899aabbccddeeff').join('\n');
const M_CRLF = M.replace(/\n/g, '\r\n');
const M_OTHER = LINES('https://shop.example', 'ffeeddccbbaa99887766554433221100').join('\n');
const A = key('11'), B = key('22');

const FW = {
  address: '13Hnmhs5gy2yXKVBx4wSM5HCBdKnaSBZJH',
  signature: 'H+Xyciqy//n27mlTymwBBeFz5wNeTqZKNhqW9ASfcSNqS5FXUn/4D0tJ2m9HHRxOtVZrbJ3gWNn8S6KAoZOtXQs=',
  message: ['Sign in with your Token', 'Site: https://pepeproject.com', 'Requires: TOKENLOCK', 'Via: tokenlock.ai', 'Nonce: 396555173588b1f81ef0a69a2af927f7',
    'Issued: 2026-11-25T15:10:10.816Z', 'Expires: 2026-11-25T15:20:10.816Z', 'Signing proves you control this address. It moves no funds.'].join('\n'),
};

const V = [];
const b64 = (b) => Buffer.from(b).toString('base64');
const hex = (b) => Buffer.from(b).toString('hex');
let checks = 0;
/** Cross-check a base signature (base64, canonical form) against the hosted bundle. */
function hosted(address, message, sigB64, want) {
  let got; try { got = !!Verifier.verifySignature(address, message, sigB64); } catch { got = false; }
  checks++;
  if (got !== want) throw new Error(`hosted bundle disagrees on base signature for ${address} (${want ? 'expected valid' : 'expected invalid'})`);
}
// Expected signatureFormatProblem(address, signature) for invalid vectors whose format is the reason they fail (codes in
// docs/self-verify-spec.md §2). Every other vector has format null: well formed, so a failure means wrong key or message.
const FORMAT = {
  'freewallet-empty-signature': 'encoding', 'freewallet-unpadded': 'base64_variant', 'freewallet-urlsafe': 'base64_variant',
  'bip322-full-p2wpkh-version-2': 'bip322_witness_shape', 'bip322-full-p2wpkh-locktime': 'bip322_full_template', 'bip322-full-p2wpkh-sequence': 'bip322_full_template',
  'bip322-full-p2wpkh-vout-1': 'bip322_full_template', 'bip322-full-p2wpkh-two-inputs': 'bip322_full_template', 'bip322-full-p2wpkh-extra-output': 'bip322_full_template',
  'bip322-full-p2wpkh-value-output': 'bip322_full_template', 'bip322-full-p2wpkh-script-output': 'bip322_full_template', 'bip322-full-p2wpkh-scriptsig': 'bip322_full_template',
  'bip322-full-p2wpkh-trailing-bytes': 'bip322_full_template', 'bip322-full-p2sh-empty-scriptsig': 'bip322_full_template',
  'bip322-full-p2tr-script-path': 'bip322_witness_shape', 'bip322-simple-p2tr-script-path': 'bip322_witness_shape', 'bip322-full-arbitrary-tx': 'bip322_witness_shape',
  'bip322-simple-p2pkh-unsupported': 'legacy_length', 'bip322-simple-p2wpkh-high-s': 'bip322_witness_shape', 'bip322-simple-p2wpkh-hashtype-00': 'bip322_witness_shape',
  'bip322-simple-p2wpkh-hashtype-02': 'bip322_witness_shape', 'bip322-simple-p2wpkh-hashtype-81': 'bip322_witness_shape', 'bip322-simple-p2wpkh-der-nonminimal': 'bip322_witness_shape',
  'bip322-simple-p2wpkh-der-trailing': 'bip322_witness_shape', 'bip322-simple-p2tr-65-hashtype-00': 'bip322_witness_shape',
  'address-leading-space': 'address_format', 'address-uppercase-bech32': 'address_format', 'address-too-long': 'address_format', 'bad-address': 'address_format',
  'enc-ws-nbsp': 'base64_variant', 'enc-b64-unpadded': 'base64_variant', 'enc-b64-urlsafe': 'base64_variant', 'enc-hex-odd-length': 'encoding', 'enc-hex-truncated': 'legacy_length',
  'enc-hex-bad-char': 'encoding', 'enc-hex-0x-only': 'encoding', 'enc-too-long': 'encoding', 'enc-ws-u0085': 'base64_variant', 'enc-ws-u180e': 'base64_variant', 'enc-ws-ufeff': 'base64_variant', 'enc-b64-garbage': 'bip137_header', 'enc-b64-short': 'bip322_witness_shape', 'enc-ws-only': 'encoding',
};
function add(v) {
  const format = /^bip137-header-\d+$/.test(v.id) ? 'bip137_header' : FORMAT[v.id] ?? null;
  if (v.valid && format) throw new Error('a valid vector cannot have a format problem: ' + v.id);
  const e = { id: v.id, kind: v.kind, wallets: v.wallets || [], source: v.source || 'generated', valid: v.valid, format, address: v.address, message: v.message,
    signature: v.signature, encoding: v.encoding || 'base64' };
  if (v.header !== undefined) e.header = v.header;
  e.notes = v.notes;
  if (V.some((x) => x.id === e.id)) throw new Error('duplicate id ' + e.id);
  V.push(e);
}

// Freewallet: the real Nov 25 2026 sign-in (header 31, compressed P2PKH). Freewallet signed the CRLF form.
hosted(FW.address, FW.message.replace(/\n/g, '\r\n'), FW.signature, true);
add({ id: 'freewallet-crlf-p2pkh-h31', kind: 'legacy-p2pkh-crlf', wallets: ['Freewallet'], source: 'real', valid: true, ...FW, header: 31,
  notes: 'Real Freewallet.io signature (Nov 25 2026) over the CRLF form of this LF challenge. Verifiers try the exact message, then only its LF<->CRLF equivalent.' });
add({ id: 'freewallet-crlf-p2pkh-h31-given-crlf', kind: 'legacy-p2pkh-crlf', wallets: ['Freewallet'], source: 'real', valid: true, ...FW, message: FW.message.replace(/\n/g, '\r\n'), header: 31,
  notes: 'Same real signature, message given in the CRLF form Freewallet signed (exact match on the first try).' });
add({ id: 'freewallet-wrong-address', kind: 'negative-wrong-address', wallets: ['Freewallet'], source: 'real', valid: false, ...FW, address: A.p2pkh, header: 31, notes: 'Real signature, different address.' });
add({ id: 'freewallet-altered-nonce', kind: 'negative-tampered-message', wallets: ['Freewallet'], source: 'real', valid: false, ...FW, message: FW.message.replace('396555173588', '396555173589'), header: 31, notes: 'Nonce changed by one digit.' });
add({ id: 'freewallet-altered-site', kind: 'negative-tampered-message', wallets: ['Freewallet'], source: 'real', valid: false, ...FW, message: FW.message.replace('pepeproject.com', 'pepeproject.co'), header: 31, notes: 'Site changed.' });
add({ id: 'freewallet-altered-requires', kind: 'negative-tampered-message', wallets: ['Freewallet'], source: 'real', valid: false, ...FW, message: FW.message.replace('Requires: TOKENLOCK', 'Requires: TOKENL0CK'), header: 31, notes: 'Required Token name changed.' });
add({ id: 'freewallet-trailing-newline', kind: 'negative-message-whitespace', wallets: ['Freewallet'], source: 'real', valid: false, ...FW, message: FW.message + '\n', header: 31, notes: 'Trailing LF on the message: messages are never trimmed.' });
add({ id: 'freewallet-trailing-space', kind: 'negative-message-whitespace', wallets: ['Freewallet'], source: 'real', valid: false, ...FW, message: FW.message + ' ', header: 31, notes: 'Trailing space on the message.' });
add({ id: 'freewallet-crlf-trailing-crlf', kind: 'negative-message-whitespace', wallets: ['Freewallet'], source: 'real', valid: false, ...FW, message: FW.message.replace(/\n/g, '\r\n') + '\r\n', header: 31, notes: 'CRLF form plus a trailing CRLF.' });
add({ id: 'freewallet-mixed-endings', kind: 'negative-message-whitespace', wallets: ['Freewallet'], source: 'real', valid: false, ...FW, message: FW.message.replace('\n', '\n\n'), header: 31, notes: 'An extra blank line: only the exact LF<->CRLF equivalent is tried, nothing else is normalized.' });
add({ id: 'freewallet-null-message', kind: 'negative-malformed', wallets: ['Freewallet'], source: 'real', valid: false, ...FW, message: null, header: 31, notes: 'null message.' });
// The real Freewallet signature is standard padded base64, so it passes the strict rules in every form a wallet or a
// paste box can produce; only lenient-decoder variants (which no wallet sends) are refused, and named as a format problem.
add({ id: 'freewallet-strict-hex', kind: 'hex-signature', wallets: ['Freewallet'], source: 'real', valid: true, ...FW, signature: Buffer.from(FW.signature, 'base64').toString('hex'), encoding: 'hex', header: 31,
  notes: 'The real signature as hex: still verifies under the strict rules.' });
add({ id: 'freewallet-strict-wrapped', kind: 'signature-whitespace', wallets: ['Freewallet'], source: 'real', valid: true, ...FW, signature: FW.signature.match(/.{1,40}/g).join('\r\n'), header: 31,
  notes: 'The real signature wrapped with CRLF: still verifies.' });
add({ id: 'freewallet-unpadded', kind: 'negative-signature-encoding', wallets: ['Freewallet'], source: 'real', valid: false, ...FW, signature: FW.signature.replace(/=+$/, ''), header: 31,
  notes: 'The real signature with its = padding removed: refused, reported as base64_variant.' });
add({ id: 'freewallet-urlsafe', kind: 'negative-signature-encoding', wallets: ['Freewallet'], source: 'real', valid: false, ...FW, signature: FW.signature.replace(/\+/g, '-').replace(/\//g, '_'), header: 31,
  notes: 'The real signature in the URL-safe alphabet: refused, reported as base64_variant.' });
add({ id: 'freewallet-empty-signature', kind: 'negative-malformed', wallets: ['Freewallet'], source: 'real', valid: false, ...FW, signature: '', notes: 'Empty signature.' });

// BIP-137 header bands. Validity = the recovered key derives the given address; the band's type flag is ignored.
const bands = [
  ['p2pkh-uncompressed', 27, A.p2pkhU, ['Bitcoin Core (uncompressed key)', 'old wallets']],
  ['p2pkh', 31, A.p2pkh, ['Bitcoin Core', 'Freewallet', 'XCP Wallet']],
  ['p2sh-p2wpkh', 35, A.p2sh, ['Trezor', 'Ledger (BIP-137 segwit)']],
  ['p2wpkh', 39, A.p2wpkh, ['Trezor', 'Ledger (BIP-137 segwit)']],
];
for (const [name, base, addr, wallets] of bands) {
  const s = legacy(A, M, base); hosted(addr, M, b64(s), true);
  add({ id: `bip137-${name}-h${s[0]}`, kind: `bip137-${name}`, wallets, valid: true, address: addr, message: M, signature: b64(s), header: s[0], notes: `Header band ${base}-${base + 3}.` });
}
// Electrum (and some Trezor flows): segwit addresses signed with the compressed-P2PKH band 31-34.
for (const [name, addr] of [['p2wpkh', A.p2wpkh], ['p2sh-p2wpkh', A.p2sh]]) {
  const s = legacy(A, M, 31); hosted(addr, M, b64(s), true);
  add({ id: `electrum-style-${name}-h${s[0]}`, kind: 'bip137-electrum-segwit', wallets: ['Electrum', 'Trezor (some flows)'], valid: true, address: addr, message: M, signature: b64(s), header: s[0],
    notes: `${name} address signed with header ${s[0]} (compressed-P2PKH band). Accepted because the recovered key derives the address.` });
  hosted(name === 'p2wpkh' ? B.p2wpkh : B.p2sh, M, b64(s), false);
  add({ id: `electrum-style-${name}-wrong-key`, kind: 'negative-wrong-address', wallets: ['Electrum'], valid: false, address: name === 'p2wpkh' ? B.p2wpkh : B.p2sh, message: M, signature: b64(s), header: s[0],
    notes: 'Header-31 signature by key A for key B\'s segwit address: the header band never stands in for the key check.' });
}
{ const s = legacy(A, M, 31); hosted(A.p2tr, M, b64(s), true);
  add({ id: `bip137-p2tr-keypath-h${s[0]}`, kind: 'bip137-p2tr', wallets: ['legacy signmessage on a key-path Taproot address'], valid: true, address: A.p2tr, message: M, signature: b64(s), header: s[0], notes: 'Recovered key, BIP-86 tweak, equals the P2TR output key.' }); }
// Headers outside 27-42 fail closed, even when the r/s/recovery would recover the right key.
{ const s = legacy(A, M, 31); const rec = s[0] - 31;
  for (const h of [26, 43 + rec, 46]) { const x = Buffer.from(s); x[0] = h;
    add({ id: `bip137-header-${h}`, kind: 'negative-bip137-header', valid: false, address: A.p2pkh, message: M, signature: b64(x), header: h, notes: `Header ${h} is outside 27-42: rejected before any key recovery (BIP-137 defines 27-42 only).` }); } }
add({ id: 'bip137-wrong-address', kind: 'negative-wrong-address', valid: false, address: B.p2pkh, message: M, signature: b64(legacy(A, M, 31)), header: legacy(A, M, 31)[0], notes: 'Valid signature by key A, address of key B.' });
add({ id: 'bip137-tampered-message', kind: 'negative-tampered-message', valid: false, address: A.p2pkh, message: M_OTHER, signature: b64(legacy(A, M, 31)), header: legacy(A, M, 31)[0], notes: 'Signature for a different nonce.' });

// CRLF-signed synthetic vectors (Freewallet-style) for the other formats.
{ const s = legacy(A, M_CRLF, 39); hosted(A.p2wpkh, M_CRLF, b64(s), true);
  add({ id: 'crlf-signed-bip137-p2wpkh', kind: 'legacy-p2wpkh-crlf', wallets: ['CRLF wallets'], valid: true, address: A.p2wpkh, message: M, signature: b64(s), header: s[0], notes: 'Signed over the CRLF form; LF message given.' }); }
{ const w = witness(bip322Items(A, 'p2wpkh', M_CRLF)); hosted(A.p2wpkh, M_CRLF, b64(w), true);
  add({ id: 'crlf-signed-bip322-simple-p2wpkh', kind: 'bip322-simple-crlf', wallets: ['CRLF wallets'], valid: true, address: A.p2wpkh, message: M, signature: b64(w), notes: 'BIP-322 simple over the CRLF form; LF message given.' });
  add({ id: 'lf-signed-bip322-given-crlf', kind: 'bip322-simple-crlf', valid: true, address: A.p2wpkh, message: M_CRLF, signature: b64(witness(bip322Items(A, 'p2wpkh', M))), notes: 'Signed over LF; CRLF message given.' }); }

// BIP-322 simple and full for bc1q / 3 / bc1p.
const WALLETS = { p2wpkh: ['XCP Wallet', 'Unisat', 'Xverse', 'Leather', 'Sparrow'], p2sh: ['Xverse', 'Leather', 'Sparrow'], p2tr: ['Unisat', 'Xverse', 'Leather', 'Sparrow'] };
const NAME = { p2wpkh: 'p2wpkh', p2sh: 'p2sh-p2wpkh', p2tr: 'p2tr' };
const full = {};
for (const t of ['p2wpkh', 'p2sh', 'p2tr']) {
  const addr = A[t], items = bip322Items(A, t, M), w = witness(items);
  hosted(addr, M, b64(w), true);
  hosted(B[t], M, b64(w), false);
  add({ id: `bip322-simple-${NAME[t]}`, kind: `bip322-simple-${NAME[t]}`, wallets: WALLETS[t], valid: true, address: addr, message: M, signature: b64(w), notes: 'BIP-322 simple: base64 of the to_sign witness stack.' });
  const f = fullTx(A, t, M, items); full[t] = { f, items };
  add({ id: `bip322-full-${NAME[t]}`, kind: `bip322-full-${NAME[t]}`, wallets: ['Sparrow', 'BIP-322 full signers'], valid: true, address: addr, message: M, signature: b64(f),
    notes: 'BIP-322 full: base64 of the whole to_sign transaction (version 0, one input spending to_spend:0 with sequence 0, one OP_RETURN output of 0, locktime 0). Witness verified like simple.' });
  add({ id: `bip322-simple-${NAME[t]}-wrong-address`, kind: 'negative-wrong-address', valid: false, address: B[t], message: M, signature: b64(w), notes: 'Key A\'s witness, key B\'s address.' });
  add({ id: `bip322-full-${NAME[t]}-wrong-prevout`, kind: 'negative-bip322-full', valid: false, address: addr, message: M, signature: b64(fullTx(A, t, M, items, { txid: toSpendTxid(M_OTHER, A.spk[t]) })), notes: 'Full tx whose input spends the to_spend of a different message.' });
}
{ const { items } = full.p2wpkh, a = A.p2wpkh;
  const bad = [
    ['version-2', { version: 2 }, 'nVersion 2 (only 0 is accepted).'],
    ['locktime', { locktime: 1 }, 'nLockTime 1 (only 0 is accepted).'],
    ['sequence', { sequence: 0xffffffff }, 'Input sequence not 0.'],
    ['vout-1', { vout: 1 }, 'Prevout index 1.'],
    ['two-inputs', { inputs: 2 }, 'Two inputs.'],
    ['extra-output', { outputs: [OPRET, OPRET] }, 'Two outputs.'],
    ['value-output', { outputs: [Buffer.concat([Buffer.from('e803000000000000', 'hex'), Buffer.from([1, 0x6a])])] }, 'Output value 1000 sats.'],
    ['script-output', { outputs: [Buffer.concat([Buffer.alloc(8), Buffer.from([2, 0x6a, 0x00])])] }, 'Output script is not a bare OP_RETURN.'],
    ['scriptsig', { scriptSig: Buffer.from([0x51]) }, 'Non-empty scriptSig on a native segwit input.'],
    ['trailing-bytes', { trailing: Buffer.from([0]) }, 'Extra byte after nLockTime.'],
  ];
  for (const [n, o, note] of bad) add({ id: `bip322-full-p2wpkh-${n}`, kind: 'negative-bip322-full', valid: false, address: a, message: M, signature: b64(fullTx(A, 'p2wpkh', M, items, o)), notes: note });
  add({ id: 'bip322-full-p2sh-wrong-scriptsig', kind: 'negative-bip322-full', valid: false, address: A.p2sh, message: M, signature: b64(fullTx(A, 'p2sh', M, full.p2sh.items, { scriptSig: Buffer.concat([Buffer.from([0x16]), B.redeem]) })), notes: 'P2SH-P2WPKH full tx whose scriptSig pushes another key\'s redeem script: rejected; its format is fine, so it reads as a wrong key.' });
  add({ id: 'bip322-full-p2sh-empty-scriptsig', kind: 'negative-bip322-full', valid: false, address: A.p2sh, message: M, signature: b64(fullTx(A, 'p2sh', M, full.p2sh.items, { scriptSig: Buffer.alloc(0) })), notes: 'P2SH-P2WPKH full tx without the redeem-script push.' });
  add({ id: 'bip322-full-p2tr-script-path', kind: 'negative-bip322-full', valid: false, address: A.p2tr, message: M, signature: b64(fullTx(A, 'p2tr', M, [full.p2tr.items[0], Buffer.from([0x51]), Buffer.concat([Buffer.from([0xc0]), A.comp.subarray(1)])])), notes: 'Script-path Taproot spend (3 witness items): unsupported, rejected.' });
  add({ id: 'bip322-simple-p2tr-script-path', kind: 'negative-bip322-simple', valid: false, address: A.p2tr, message: M, signature: b64(witness([full.p2tr.items[0], Buffer.from([0x51]), Buffer.concat([Buffer.from([0xc0]), A.comp.subarray(1)])])), notes: 'Script-path Taproot witness in simple form.' });
  add({ id: 'bip322-full-arbitrary-tx', kind: 'negative-bip322-full', valid: false, address: a, message: M, signature: b64(Buffer.concat([u32(2), Buffer.from([0, 1, 1]), Buffer.alloc(32, 7), u32(0), Buffer.from([0]), u32(0xffffffff), Buffer.from([1]), Buffer.from('1027000000000000', 'hex'), Buffer.from([0x16]), A.spk.p2wpkh, Buffer.from([2, 0]), Buffer.from([0]), u32(0)])), notes: 'An unrelated transaction.' });
  const w = witness(bip322Items(A, 'p2wpkh', M)); // a valid P2WPKH witness for the same key, offered for its 1... address
  add({ id: 'bip322-simple-p2pkh-unsupported', kind: 'negative-bip322-simple', valid: false, address: A.p2pkh, message: M, signature: b64(w), notes: 'BIP-322 for a P2PKH (1...) address is not supported (no wallet in our list needs it); legacy signmessage is.' });
  const hi = witness(bip322Items(A, 'p2wpkh', M, { highS: true }));
  let hostedHi; try { hostedHi = !!Verifier.verifySignature(A.p2wpkh, M, b64(hi)); } catch { hostedHi = false; }
  add({ id: 'bip322-simple-p2wpkh-high-s', kind: 'negative-bip322-simple', valid: hostedHi, address: A.p2wpkh, message: M, signature: b64(hi),
    notes: `Same signature with S replaced by n-S (high-S). Validity is what the hosted bundle answers (${hostedHi ? 'accepts' : 'rejects'}); all verifiers must match it.` });
}

// Witness shape: SIGHASH_ALL only, strict DER, BIP-341 hash types (the bundle alone is looser on the first and last).
{ const [sigAll, pub] = bip322Items(A, 'p2wpkh', M); const der0 = sigAll.subarray(0, -1);
  for (const ht of [0x00, 0x02, 0x81]) add({ id: `bip322-simple-p2wpkh-hashtype-${ht.toString(16).padStart(2, '0')}`, kind: 'negative-bip322-simple', valid: false, address: A.p2wpkh, message: M,
    signature: b64(witness([Buffer.concat([der0, Buffer.from([ht])]), pub])), notes: `ECDSA witness signed for SIGHASH_ALL but labelled hash type 0x${ht.toString(16).padStart(2, '0')}: only 0x01 is accepted.` });
  const rl = der0[3], R = der0.subarray(4, 4 + rl), S = der0.subarray(4 + rl);
  const nonMin = Buffer.concat([Buffer.from([0x30, der0[1] + 1, 0x02, rl + 1, 0x00]), R, S]);
  add({ id: 'bip322-simple-p2wpkh-der-nonminimal', kind: 'negative-bip322-simple', valid: false, address: A.p2wpkh, message: M, signature: b64(witness([Buffer.concat([nonMin, Buffer.from([1])]), pub])), notes: 'DER R with a needless leading zero byte (not strict DER).' });
  const trail = Buffer.concat([Buffer.from([0x30, der0[1] + 1]), der0.subarray(2), Buffer.from([0x00])]);
  add({ id: 'bip322-simple-p2wpkh-der-trailing', kind: 'negative-bip322-simple', valid: false, address: A.p2wpkh, message: M, signature: b64(witness([Buffer.concat([trail, Buffer.from([1])]), pub])), notes: 'DER sequence with a trailing byte (not strict DER).' });
  const txid = toSpendTxid(M, A.spk.p2tr), dk = tapTweakPriv(A.d, A.comp);
  const s1 = Buffer.from(schnorr.sign(sighash341(txid, A.spk.p2tr, 0x01), dk, Buffer.alloc(32)));
  hosted(A.p2tr, M, b64(witness([Buffer.concat([s1, Buffer.from([0x01])])])), true);
  add({ id: 'bip322-simple-p2tr-sighash-all-65', kind: 'bip322-simple-p2tr', wallets: ['Taproot signers using explicit SIGHASH_ALL'], valid: true, address: A.p2tr, message: M, signature: b64(witness([Buffer.concat([s1, Buffer.from([0x01])])])), notes: '65-byte Taproot signature with explicit SIGHASH_ALL (0x01).' });
  const s0 = Buffer.from(schnorr.sign(sighash341(txid, A.spk.p2tr, 0x00), dk, Buffer.alloc(32)));
  add({ id: 'bip322-simple-p2tr-65-hashtype-00', kind: 'negative-bip322-simple', valid: false, address: A.p2tr, message: M, signature: b64(witness([Buffer.concat([s0, Buffer.from([0x00])])])), notes: '65-byte Taproot signature ending in 0x00: invalid under BIP-341 (0x00 must be the 64-byte form).' });
  const good = b64(witness(bip322Items(A, 'p2wpkh', M)));
  add({ id: 'address-leading-space', kind: 'negative-malformed', valid: false, address: ' ' + A.p2wpkh, message: M, signature: good, notes: 'The address is not trimmed.' });
  add({ id: 'address-uppercase-bech32', kind: 'negative-malformed', valid: false, address: A.p2wpkh.toUpperCase(), message: M, signature: good, notes: 'Upper-case bech32 is refused (the hosted check requires lower case).' });
  add({ id: 'address-too-long', kind: 'negative-malformed', valid: false, address: '3' + 'z'.repeat(150), message: M, signature: b64(fullTx(A, 'p2sh', M, full.p2sh.items)), notes: 'Addresses over 100 characters are refused before decoding.' });
}

// Signature encodings: whitespace inside the signature (never the message), hex, and strict base64.
{ const s = b64(legacy(A, M, 31)), w = b64(witness(bip322Items(A, 'p2wpkh', M))), fw = b64(full.p2wpkh.f);
  const wrap = (x, n, sep) => x.match(new RegExp(`.{1,${n}}`, 'g')).join(sep);
  const enc = [
    ['ws-leading-trailing', ` ${s} `, A.p2pkh, true, 'Leading and trailing spaces around the signature.'],
    ['ws-tab', `\t${s}\t`, A.p2pkh, true, 'Tabs around the signature.'],
    ['ws-lf-wrap', wrap(s, 64, '\n'), A.p2pkh, true, 'Base64 wrapped at 64 characters with LF (PEM-style).'],
    ['ws-crlf-wrap', wrap(w, 32, '\r\n'), A.p2wpkh, true, 'BIP-322 witness wrapped with CRLF.'],
    ['ws-mid-space', s.slice(0, 40) + ' ' + s.slice(40), A.p2pkh, true, 'A space in the middle of the base64.'],
    ['ws-nbsp', s.slice(0, 40) + ' ' + s.slice(40), A.p2pkh, false, 'A no-break space (U+00A0) is not whitespace for signatures: only space, tab, CR, LF, FF, VT are stripped.'],
    ['b64-unpadded', s.replace(/=+$/, ''), A.p2pkh, false, 'Base64 without its = padding: rejected (strict base64).'],
    ['b64-urlsafe', w.replace(/\+/g, '-').replace(/\//g, '_'), A.p2wpkh, false, 'URL-safe base64 alphabet: rejected (strict base64).'],
    ['hex-bip137', hex(Buffer.from(s, 'base64')), A.p2pkh, true, '65-byte BIP-137 signature as 130 hex characters.'],
    ['hex-bip137-0x', '0x' + hex(Buffer.from(s, 'base64')), A.p2pkh, true, 'Same with a 0x prefix.'],
    ['hex-bip137-upper', hex(Buffer.from(s, 'base64')).toUpperCase(), A.p2pkh, true, 'Upper-case hex.'],
    ['hex-bip322-simple', hex(Buffer.from(w, 'base64')), A.p2wpkh, true, 'BIP-322 simple witness as hex.'],
    ['hex-bip322-full', '0x' + hex(Buffer.from(fw, 'base64')), A.p2wpkh, true, 'BIP-322 full transaction as 0x hex.'],
    ['hex-wrapped', wrap(hex(Buffer.from(s, 'base64')), 40, '\n'), A.p2pkh, true, 'Hex wrapped over lines.'],
    ['hex-odd-length', hex(Buffer.from(s, 'base64')).slice(0, -1), A.p2pkh, false, 'Odd-length hex.'],
    ['hex-truncated', hex(Buffer.from(s, 'base64')).slice(0, 128), A.p2pkh, false, '64 bytes of hex (one byte short).'],
    ['hex-bad-char', hex(Buffer.from(s, 'base64')).slice(0, -2) + 'zz', A.p2pkh, false, 'Not clean hex.'],
    ['hex-0x-only', '0x', A.p2pkh, false, 'Prefix with nothing after it.'],
    ['hex-other-message', hex(legacy(A, M_OTHER, 31)), A.p2pkh, false, 'Hex of a signature over a different nonce.'],
    ['b64-garbage', b64(Buffer.alloc(65, 0x41)), A.p2pkh, false, '65 bytes that are not a signature.'],
    ['b64-short', b64(Buffer.alloc(10, 1)), A.p2wpkh, false, 'Ten random-looking bytes.'],
    ['ws-only', ' \n\t ', A.p2pkh, false, 'Whitespace only.'],
    ['too-long', s + ' '.repeat(4096 - s.length + 1), A.p2pkh, false, 'Over 4096 characters (here: a valid signature plus spaces): refused without decoding.'],
    ['ws-u0085', s.slice(0, 40) + '\u0085' + s.slice(40), A.p2pkh, false, 'U+0085 (NEL) inside the signature: not whitespace for signatures; named as a base64 variant.'],
    ['ws-u180e', s.slice(0, 40) + '\u180e' + s.slice(40), A.p2pkh, false, 'U+180E inside the signature: refused; named as a base64 variant.'],
    ['ws-ufeff', '\ufeff' + s, A.p2pkh, false, 'A byte-order mark before the signature: refused; named as a base64 variant.'],
  ];
  for (const [n, sig, addr, valid, note] of enc) add({ id: `enc-${n}`, kind: n.startsWith('hex') ? (valid ? 'hex-signature' : 'negative-hex') : n.startsWith('ws') ? (valid ? 'signature-whitespace' : 'negative-signature-encoding') : 'negative-signature-encoding',
    valid, address: addr, message: M, signature: sig, encoding: n.startsWith('hex') ? 'hex' : 'base64', notes: note });
}
add({ id: 'bad-address', kind: 'negative-malformed', valid: false, address: 'bc1qnotanaddress', message: M, signature: b64(legacy(A, M, 31)), notes: 'Unparseable address.' });

// Reserved slots for real wallet captures (Garrett fills these; tests skip them until then).
for (const [id, w, note] of [
  ['slot-electrum-real', ['Electrum'], 'Reserved: a real Electrum signature (likely a segwit address with header 31-34). Fill address/message/signature/valid and set source to "real".'],
  ['slot-sparrow-real', ['Sparrow'], 'Reserved: a real Sparrow signature (BIP-322 simple and/or full, or legacy if that is what its UI emits). Fill and set source to "real".'],
]) V.push({ id, kind: 'slot', wallets: w, source: 'slot', valid: null, format: null, address: '', message: '', signature: '', encoding: 'base64', notes: note });

for (const id of Object.keys(FORMAT)) if (!V.some((v) => v.id === id)) throw new Error('FORMAT names an unknown vector: ' + id);
const doc = { version: 1, generated_by: 'scripts/gen-wallet-sig-vectors.mjs',
  notes: 'Shared across tokenlock.ai, the shared site, @tokenlock/sdk (TypeScript) and the PHP drop-in; copy it byte-for-byte. valid=true must verify and valid=false must not; format is the expected signature-format problem (null when the format is fine). source=slot entries are reserved and skipped until filled. Generated vectors use throwaway keys only.',
  vectors: V };
const text = JSON.stringify(doc, null, 2) + '\n';
if (process.argv.includes('--check')) { if (readFileSync(OUT, 'utf8') !== text) throw new Error('wallet-sig-vectors.json is stale'); }
else writeFileSync(OUT, text);
console.log(`${V.length} vectors (${V.filter((v) => v.source === 'slot').length} slots), ${checks} base signatures cross-checked against the hosted bundle`);
