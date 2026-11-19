// Local Bitcoin message-signature verification for TOKENLOCK self-verify (spec v1, docs/self-verify-spec.md).
// No network calls. Accepts what the hosted TOKENLOCK check accepts:
//   - BIP-322 "simple" signatures (base64 witness) for P2WPKH (bc1q…), P2SH-P2WPKH (3…) and single-key P2TR (bc1p…)
//   - legacy "Bitcoin Signed Message" signatures (BIP-137 / Electrum, 65 bytes) for P2PKH (1…), P2SH-P2WPKH, P2WPKH and
//     P2TR (key-path, BIP-86 tweak of the recovered key). The header's address-type flag is ignored, like the hosted check.
// Mainnet (bc/1/3) and testnet/signet (tb/m/n/2) addresses.
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';

const te = new TextEncoder();
const cat = (...a: Uint8Array[]) => { const n = a.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
const dsha = (b: Uint8Array) => sha256(sha256(b));
const hash160 = (b: Uint8Array) => ripemd160(sha256(b));
const u32le = (n: number) => { const o = new Uint8Array(4); new DataView(o.buffer).setUint32(0, n >>> 0, true); return o; };
const u64zero = () => new Uint8Array(8);
function varint(n: number) {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 255, n >> 8);
  return cat(Uint8Array.of(0xfe), u32le(n));
}
export function taggedHash(tag: string, ...msgs: Uint8Array[]) { const t = sha256(te.encode(tag)); return sha256(cat(t, t, ...msgs)); }

// ---------------------------------------------------------------- encodings
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
export function b64decode(s: string): Uint8Array | null {
  s = String(s || '').trim().replace(/[\r\n\s]/g, '');
  if (!s || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  const pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
  const out = new Uint8Array((s.length / 4) * 3 - pad);
  let o = 0;
  for (let i = 0; i < s.length; i += 4) {
    const n = (B64.indexOf(s[i]) << 18) | (B64.indexOf(s[i + 1]) << 12) | ((s[i + 2] === '=' ? 0 : B64.indexOf(s[i + 2])) << 6) | (s[i + 3] === '=' ? 0 : B64.indexOf(s[i + 3]));
    if (o < out.length) out[o++] = (n >> 16) & 255;
    if (o < out.length) out[o++] = (n >> 8) & 255;
    if (o < out.length) out[o++] = n & 255;
  }
  return out;
}
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58checkDecode(s: string): Uint8Array | null {
  let n = 0n;
  for (const c of s) { const v = B58.indexOf(c); if (v < 0) return null; n = n * 58n + BigInt(v); }
  const bytes: number[] = [];
  while (n > 0n) { bytes.unshift(Number(n & 255n)); n >>= 8n; }
  for (const c of s) { if (c === '1') bytes.unshift(0); else break; }
  const b = Uint8Array.from(bytes);
  if (b.length < 5) return null;
  const body = b.slice(0, -4), sum = b.slice(-4);
  return eq(dsha(body).slice(0, 4), sum) ? body : null;
}
function b58checkEncode(body: Uint8Array) {
  const b = cat(body, dsha(body).slice(0, 4));
  let n = 0n; for (const x of b) n = (n << 8n) | BigInt(x);
  let s = ''; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const x of b) { if (x === 0) s = '1' + s; else break; }
  return s;
}
const BECH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function polymod(values: number[]) {
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) { const top = chk >>> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= G[i]; }
  return chk >>> 0;
}
const hrpExpand = (h: string) => [...[...h].map((c) => c.charCodeAt(0) >> 5), 0, ...[...h].map((c) => c.charCodeAt(0) & 31)];
function convertBits(data: number[], from: number, to: number, pad: boolean) {
  let acc = 0, bits = 0; const out: number[] = []; const maxv = (1 << to) - 1;
  for (const v of data) { acc = (acc << from) | v; bits += from; while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); } }
  if (pad) { if (bits) out.push((acc << (to - bits)) & maxv); } else if (bits >= from || ((acc << (to - bits)) & maxv)) return null;
  return out;
}
function segwitDecode(addr: string): { hrp: string; version: number; program: Uint8Array } | null {
  if (addr !== addr.toLowerCase() && addr !== addr.toUpperCase()) return null;
  const a = addr.toLowerCase(); const pos = a.lastIndexOf('1');
  if (pos < 1 || pos + 7 > a.length || a.length > 90) return null;
  const hrp = a.slice(0, pos); const data: number[] = [];
  for (const c of a.slice(pos + 1)) { const v = BECH.indexOf(c); if (v < 0) return null; data.push(v); }
  const pm = polymod([...hrpExpand(hrp), ...data]);
  const version = data[0];
  if (!(version === 0 ? pm === 1 : pm === 0x2bc830a3)) return null;
  const prog = convertBits(data.slice(1, -6), 5, 8, false);
  if (!prog || prog.length < 2 || prog.length > 40 || version > 16) return null;
  if (version === 0 && prog.length !== 20 && prog.length !== 32) return null;
  return { hrp, version, program: Uint8Array.from(prog) };
}
function segwitEncode(hrp: string, version: number, program: Uint8Array) {
  const data = [version, ...(convertBits([...program], 8, 5, true) as number[])];
  const c = version === 0 ? 1 : 0x2bc830a3;
  const pm = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ c;
  const chk = [0, 1, 2, 3, 4, 5].map((i) => (pm >> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...chk].map((v) => BECH[v]).join('');
}

export type AddressType = 'p2pkh' | 'p2sh' | 'p2wpkh' | 'p2tr';
export interface DecodedAddress { type: AddressType; hash: Uint8Array; script: Uint8Array; network: 'mainnet' | 'testnet' }
/** Decode a Bitcoin address into its type and scriptPubKey. null if not a supported address. */
export function decodeAddress(address: string): DecodedAddress | null {
  const a = String(address || '').trim();
  if (/^(bc|tb|bcrt)1/i.test(a)) {
    const d = segwitDecode(a); if (!d) return null;
    const network = d.hrp === 'bc' ? 'mainnet' : 'testnet';
    if (d.version === 0 && d.program.length === 20) return { type: 'p2wpkh', hash: d.program, script: cat(Uint8Array.of(0x00, 0x14), d.program), network };
    if (d.version === 1 && d.program.length === 32) return { type: 'p2tr', hash: d.program, script: cat(Uint8Array.of(0x51, 0x20), d.program), network };
    return null;
  }
  const b = b58checkDecode(a); if (!b || b.length !== 21) return null;
  const v = b[0], h = b.slice(1);
  if (v === 0x00 || v === 0x6f) return { type: 'p2pkh', hash: h, script: cat(Uint8Array.of(0x76, 0xa9, 0x14), h, Uint8Array.of(0x88, 0xac)), network: v ? 'testnet' : 'mainnet' };
  if (v === 0x05 || v === 0xc4) return { type: 'p2sh', hash: h, script: cat(Uint8Array.of(0xa9, 0x14), h, Uint8Array.of(0x87)), network: v === 0xc4 ? 'testnet' : 'mainnet' };
  return null;
}

// ---------------------------------------------------------------- BIP-322 simple
function toSpendTxid(message: string, script: Uint8Array) {
  const mh = taggedHash('BIP0322-signed-message', te.encode(message));
  const scriptSig = cat(Uint8Array.of(0x00, 0x20), mh);
  const tx = cat(u32le(0), Uint8Array.of(1), new Uint8Array(32), Uint8Array.of(0xff, 0xff, 0xff, 0xff), varint(scriptSig.length), scriptSig, u32le(0),
    Uint8Array.of(1), u64zero(), varint(script.length), script, u32le(0));
  return dsha(tx); // internal byte order
}
const OP_RETURN_OUT = cat(u64zero(), Uint8Array.of(1, 0x6a));
function bip143Sighash(txid: Uint8Array, pkh: Uint8Array) {
  const outpoint = cat(txid, u32le(0));
  const scriptCode = cat(Uint8Array.of(0x19, 0x76, 0xa9, 0x14), pkh, Uint8Array.of(0x88, 0xac));
  const pre = cat(u32le(0), dsha(outpoint), dsha(u32le(0)), outpoint, scriptCode, u64zero(), u32le(0), dsha(OP_RETURN_OUT), u32le(0), u32le(1));
  return dsha(pre);
}
function bip341Sighash(txid: Uint8Array, script: Uint8Array, hashType: number) {
  const outpoint = cat(txid, u32le(0));
  const msg = cat(Uint8Array.of(0x00, hashType), u32le(0), u32le(0), sha256(outpoint), sha256(u64zero()), sha256(cat(varint(script.length), script)), sha256(u32le(0)),
    sha256(OP_RETURN_OUT), Uint8Array.of(0x00), u32le(0));
  return taggedHash('TapSighash', msg);
}
function parseWitness(b: Uint8Array): Uint8Array[] | null {
  let i = 0;
  const rd = () => { if (i >= b.length) throw 0; const f = b[i++]; if (f < 0xfd) return f; if (f === 0xfd) { const v = b[i] | (b[i + 1] << 8); i += 2; return v; } throw 0; };
  try {
    const n = rd(); if (n < 1 || n > 10) return null;
    const items: Uint8Array[] = [];
    for (let k = 0; k < n; k++) { const len = rd(); if (i + len > b.length) return null; items.push(b.slice(i, i + len)); i += len; }
    return i === b.length ? items : null;
  } catch { return null; }
}
function verifyBip322(addr: DecodedAddress, message: string, sig: Uint8Array): boolean {
  const w = parseWitness(sig); if (!w) return false;
  const txid = toSpendTxid(message, addr.script);
  if (addr.type === 'p2wpkh' || addr.type === 'p2sh') {
    if (w.length !== 2 || w[1].length !== 33) return false;
    const pub = w[1], pkh = hash160(pub);
    if (addr.type === 'p2wpkh' && !eq(pkh, addr.hash)) return false;
    if (addr.type === 'p2sh' && !eq(hash160(cat(Uint8Array.of(0x00, 0x14), pkh)), addr.hash)) return false;
    const der = w[0].slice(0, -1); if (der.length < 8) return false;
    try { return secp256k1.verify(der, bip143Sighash(txid, pkh), pub, { prehash: false, lowS: false, format: 'der' }); } catch { return false; }
  }
  if (addr.type === 'p2tr') {
    if (w.length !== 1) return false;
    const s = w[0]; let ht = 0x00, raw = s;
    if (s.length === 65) { ht = s[64]; raw = s.slice(0, 64); if (ht !== 0x01) return false; } else if (s.length !== 64) return false;
    try { return schnorr.verify(raw, bip341Sighash(txid, addr.script, ht), addr.hash); } catch { return false; }
  }
  return false;
}

// ---------------------------------------------------------------- legacy (BIP-137 / Electrum)
export function legacyMessageHash(message: string) {
  const prefix = te.encode('\x18Bitcoin Signed Message:\n'); const m = te.encode(message);
  return dsha(cat(prefix, varint(m.length), m));
}
const P = secp256k1.Point;
function tweakTaproot(xonly: Uint8Array): Uint8Array | null {
  try {
    const t = taggedHash('TapTweak', xonly);
    const n = P.Fn.ORDER; let tn = 0n; for (const x of t) tn = (tn << 8n) | BigInt(x);
    if (tn >= n) return null;
    const pt = P.fromBytes(cat(Uint8Array.of(0x02), xonly)).add(P.BASE.multiply(tn));
    return pt.toBytes(true).slice(1);
  } catch { return null; }
}
function verifyLegacy(addr: DecodedAddress, message: string, sig: Uint8Array): boolean {
  if (sig.length !== 65) return false;
  const h = sig[0]; if (h < 27 || h > 42) return false;
  const recid = (h - 27) & 3;
  let pt;
  try { pt = P.fromBytes(secp256k1.recoverPublicKey(cat(Uint8Array.of(recid), sig.slice(1)), legacyMessageHash(message), { prehash: false })); } catch { return false; }
  const comp = pt.toBytes(true), uncomp = pt.toBytes(false);
  switch (addr.type) {
    case 'p2pkh': return eq(hash160(comp), addr.hash) || eq(hash160(uncomp), addr.hash);
    case 'p2wpkh': return eq(hash160(comp), addr.hash);
    case 'p2sh': return eq(hash160(cat(Uint8Array.of(0x00, 0x14), hash160(comp))), addr.hash);
    case 'p2tr': { const q = tweakTaproot(comp.slice(1)); return !!q && eq(q, addr.hash); }
  }
  return false;
}

/** Does `signature` (base64) prove `address` signed exactly `message`? Never throws. */
export function verifyMessageSignature(address: string, message: string, signature: string): boolean {
  const addr = decodeAddress(address); if (!addr) return false;
  const sig = b64decode(signature); if (!sig) return false;
  if (addr.type === 'p2pkh' || (sig.length === 65 && sig[0] >= 27 && sig[0] <= 42)) return verifyLegacy(addr, message, sig);
  return verifyBip322(addr, message, sig);
}

/** Address helpers for tests and tooling. */
export const _addr = {
  p2wpkh: (pub33: Uint8Array, hrp = 'bc') => segwitEncode(hrp, 0, hash160(pub33)),
  p2tr: (pub33: Uint8Array, hrp = 'bc') => segwitEncode(hrp, 1, tweakTaproot(pub33.slice(1)) as Uint8Array),
  p2pkh: (pub: Uint8Array) => b58checkEncode(cat(Uint8Array.of(0), hash160(pub))),
  p2sh: (pub33: Uint8Array) => b58checkEncode(cat(Uint8Array.of(5), hash160(cat(Uint8Array.of(0x00, 0x14), hash160(pub33))))),
};
export const _internal = { toSpendTxid, bip143Sighash, bip341Sighash, hash160, dsha, cat, sha256 };
