// Dev only: regenerate test/fixtures/sig-vectors.json. Needs bip322-js and the hosted verifier bundle:
//   npm i --no-save bip322-js@4 && HOSTED_VERIFIER=/path/to/server/vendor-bip322.mjs node scripts/gen-sig-vectors.mjs
// Every vector's `valid` is what the hosted TOKENLOCK check (server Verifier) answers, so the local verifiers
// (Node and PHP) are tested to give the same answer as the hosted check.
import { writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(process.env.BIP_NODE_MODULES || import.meta.url);
const { Signer } = require('bip322-js');
const { ECPairFactory } = require('ecpair');
const ecc = require('@bitcoinerlab/secp256k1');
const bitcoin = require('bitcoinjs-lib');
bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const { Verifier } = await import(process.env.HOSTED_VERIFIER);
const { secp256k1 } = await import('@noble/curves/secp256k1.js');
const { sha256 } = await import('@noble/hashes/sha2.js');

const msgHash = (m) => { const p = Buffer.from('\x18Bitcoin Signed Message:\n'); const b = Buffer.from(m, 'utf8'); const l = b.length < 253 ? Buffer.from([b.length]) : Buffer.from([253, b.length & 255, b.length >> 8]); return Buffer.from(sha256(sha256(Buffer.concat([p, l, b])))); };
const legacy = (priv, m, base) => { const s = secp256k1.sign(msgHash(m), priv, { prehash: false, format: 'recovered' }); return Buffer.concat([Buffer.from([base + s[0]]), Buffer.from(s.slice(1))]).toString('base64'); };
const seeds = ['01', '02', '7f', 'c3', 'e9'].map((x) => Buffer.from(x.repeat(32), 'hex'));
const MESSAGES = [
  ['gate', 'Sign in with your Token\nSite: https://shop.example\nRequires: GOTPROOF\nVia: self-verify\nNonce: 00112233445566778899aabbccddeeff\nIssued: 2026-11-18T18:00:00.000Z\nExpires: 2026-11-18T18:10:00.000Z\nSigning proves you control this address. It moves no funds.'],
  ['unicode', 'Sign in with your Token\nSite: https://ünïcode.example\nRequires: A12345678901234567 or any name on Bitcoin\nVia: self-verify\nNonce: ffeeddccbbaa99887766554433221100\nIssued: 2026-11-18T18:00:00.000Z\nExpires: 2026-11-18T18:10:00.000Z\nSigning proves you control this address. It moves no funds.'],
  ['long', 'x'.repeat(300)],
];
const out = [];
const add = (v) => { let hosted; try { hosted = !!Verifier.verifySignature(v.address, v.message, v.signature); } catch { hosted = false; } out.push({ ...v, valid: hosted }); };
for (const [si, seed] of seeds.entries()) {
  const kp = ECPair.fromPrivateKey(seed, { compressed: true });
  const wif = kp.toWIF(); const pub = Buffer.from(kp.publicKey);
  const ukp = ECPair.fromPrivateKey(seed, { compressed: false });
  const A = {
    p2wpkh: bitcoin.payments.p2wpkh({ pubkey: pub }).address,
    p2sh: bitcoin.payments.p2sh({ redeem: bitcoin.payments.p2wpkh({ pubkey: pub }) }).address,
    p2tr: bitcoin.payments.p2tr({ internalPubkey: pub.subarray(1) }).address,
    p2pkh: bitcoin.payments.p2pkh({ pubkey: pub }).address,
    p2pkh_u: bitcoin.payments.p2pkh({ pubkey: Buffer.from(ukp.publicKey) }).address,
  };
  const other = ECPair.fromPrivateKey(Buffer.from('55'.repeat(31) + String(si).padStart(2, '0'), 'hex'));
  const otherA = bitcoin.payments.p2wpkh({ pubkey: Buffer.from(other.publicKey) }).address;
  for (const [mk, m] of MESSAGES) {
    // BIP-322 simple: Xverse, Leather, Unisat (bip322-simple), XCP Wallet and Horizon for segwit/taproot addresses
    for (const t of ['p2wpkh', 'p2sh', 'p2tr']) {
      const sig = Signer.sign(wif, A[t], m).toString('base64');
      add({ kind: `bip322-${t}`, wallets: t === 'p2tr' ? 'Xverse, Leather, Unisat (taproot)' : 'XCP Wallet, Horizon, Unisat, Xverse, Leather', msg: mk, address: A[t], message: m, signature: sig });
      add({ kind: `bip322-${t}-tampered-message`, msg: mk, address: A[t], message: m + ' ', signature: sig });
      add({ kind: `bip322-${t}-wrong-address`, msg: mk, address: otherA, message: m, signature: sig });
    }
    // legacy "sign message" (BIP-137 / Electrum): P2PKH wallets, Unisat ecdsa mode, older XCP Wallet / Horizon builds
    for (const [t, base] of [['p2pkh', 31], ['p2pkh_u', 27], ['p2wpkh', 39], ['p2wpkh', 31], ['p2sh', 35], ['p2sh', 31], ['p2tr', 31], ['p2wpkh', 27]]) {
      const sig = legacy(seed, m, base);
      add({ kind: `legacy-${t}-h${base}`, wallets: 'legacy sign message', msg: mk, address: A[t], message: m, signature: sig });
      add({ kind: `legacy-${t}-h${base}-tampered`, msg: mk, address: A[t], message: m.slice(0, -1), signature: sig });
    }
    add({ kind: 'legacy-wrong-key', msg: mk, address: A.p2wpkh, message: m, signature: legacy(Buffer.from('66'.repeat(32), 'hex'), m, 39) });
  }
}
// malformed
const any = out[0];
for (const [k, s] of [['empty', ''], ['not-base64', '!!!!'], ['short', 'AAAA'], ['truncated', any.signature.slice(0, 40)], ['junk-65', Buffer.alloc(65, 7).toString('base64')]]) add({ kind: 'malformed-' + k, address: any.address, message: any.message, signature: s });
add({ kind: 'bad-address', address: 'bc1qnotanaddress', message: any.message, signature: any.signature });
writeFileSync(new URL('../test/fixtures/sig-vectors.json', import.meta.url), JSON.stringify({ generated_by: 'scripts/gen-sig-vectors.mjs', valid_is: 'answer of the hosted TOKENLOCK verifier', vectors: out }, null, 1) + '\n');
console.log('vectors', out.length, 'valid', out.filter((v) => v.valid).length);
