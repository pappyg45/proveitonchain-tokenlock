// Local Bitcoin message-signature verification for TOKENLOCK self-verify (spec v1, docs/self-verify-spec.md).
// No network calls. Accepts what the hosted TOKENLOCK check accepts (shared vectors: test/fixtures/wallet-sig-vectors.json):
//   - BIP-322 "simple" (the to_sign witness stack) and "full" (the whole to_sign transaction, accepted only when it is
//     exactly the BIP-322 template for this address and message) for P2WPKH (bc1q…), P2SH-P2WPKH (3…) and single-key
//     P2TR (bc1p…). ECDSA witnesses must be low-S, as on the hosted check.
//   - legacy "Bitcoin Signed Message" signatures (BIP-137 / Electrum, 65 bytes, header 27-42) for P2PKH (1…),
//     P2SH-P2WPKH, P2WPKH and P2TR (key-path, BIP-86 tweak of the recovered key). The header's address-type flag is
//     ignored, like the hosted check: the recovered key must derive the address.
//   - the exact message first, then only its LF<->CRLF equivalent (Freewallet signs the CRLF form of an LF challenge).
//   - signature encodings: ASCII whitespace removed, then strict base64, else even-length hex with an optional 0x.
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
/** Strict base64 (standard alphabet, padded). ASCII whitespace (space, tab, CR, LF, FF, VT) is ignored; nothing else is. */
export function b64decode(s: string): Uint8Array | null {
  s = String(s || '').replace(/[ \t\r\n\f\v]+/g, '');
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
/** Even-length hex with an optional 0x prefix; ASCII whitespace ignored. */
export function hexdecode(s: string): Uint8Array | null {
  const h = String(s || '').replace(/[ \t\r\n\f\v]+/g, '').replace(/^0x/i, '');
  if (!h || h.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(h)) return null;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
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
/**
 * BIP-322 ECDSA witnesses: strict DER (minimal, positive integers, no trailing bytes) and low-S (S <= n/2), like the hosted
 * check. Checked here explicitly, whatever the curve library's defaults.
 */
function derStrictLowS(der: Uint8Array): boolean {
  if (der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) return false;
  let i = 2; const ints: bigint[] = [];
  for (let k = 0; k < 2; k++) {
    if (i + 2 > der.length || der[i] !== 0x02) return false;
    const len = der[i + 1]; i += 2;
    if (len < 1 || len > 33 || i + len > der.length) return false;
    const v = der.slice(i, i + len);
    if (v[0] & 0x80) return false; // negative
    if (len > 1 && v[0] === 0 && !(v[1] & 0x80)) return false; // not minimal
    let n = 0n; for (const x of v) n = (n << 8n) | BigInt(x);
    ints.push(n); i += len;
  }
  if (i !== der.length) return false;
  const N = P.Fn.ORDER as bigint;
  return ints[0] > 0n && ints[0] < N && ints[1] > 0n && ints[1] <= N >> 1n;
}
function verifyBip322(addr: DecodedAddress, message: string, sig: Uint8Array): boolean {
  const w = parseWitness(sig); if (!w) return false;
  const txid = toSpendTxid(message, addr.script);
  if (addr.type === 'p2wpkh' || addr.type === 'p2sh') {
    if (w.length !== 2 || w[1].length !== 33) return false;
    const pub = w[1], pkh = hash160(pub);
    if (addr.type === 'p2wpkh' && !eq(pkh, addr.hash)) return false;
    if (addr.type === 'p2sh' && !eq(hash160(cat(Uint8Array.of(0x00, 0x14), pkh)), addr.hash)) return false;
    if (w[0][w[0].length - 1] !== 0x01) return false; // hash type must be SIGHASH_ALL
    const der = w[0].slice(0, -1); if (!derStrictLowS(der)) return false;
    try { return secp256k1.verify(der, bip143Sighash(txid, pkh), pub, { prehash: false, lowS: true, format: 'der' }); } catch { return false; }
  }
  if (addr.type === 'p2tr') {
    if (w.length !== 1) return false;
    const s = w[0]; let ht = 0x00, raw = s;
    if (s.length === 65) { ht = s[64]; raw = s.slice(0, 64); if (ht !== 0x01) return false; } else if (s.length !== 64) return false;
    try { return schnorr.verify(raw, bip341Sighash(txid, addr.script, ht), addr.hash); } catch { return false; }
  }
  return false;
}

// ---------------------------------------------------------------- BIP-322 full
interface FullSig { txid: Uint8Array; scriptSig: Uint8Array; items: Uint8Array[] }
function reader(b: Uint8Array) {
  let i = 0;
  const take = (n: number) => { if (n < 0 || i + n > b.length) throw 0; const x = b.slice(i, i + n); i += n; return x; };
  const vi = () => { const f = take(1)[0]; if (f < 0xfd) return f; if (f === 0xfd) { const x = take(2); return x[0] | (x[1] << 8); } if (f === 0xfe) { const x = take(4); return (x[0] | (x[1] << 8) | (x[2] << 16)) + x[3] * 0x1000000; } throw 0; };
  const u32 = () => { const x = take(4); return (x[0] | (x[1] << 8) | (x[2] << 16)) + x[3] * 0x1000000; };
  return { take, vi, u32, done: () => i === b.length };
}
/**
 * Structure of a BIP-322 full signature, independent of the message: nVersion 0 + segwit marker, one input at index 0
 * with sequence 0, one OP_RETURN output of 0, locktime 0, nothing after it. undefined = not "nVersion 0 + marker" (treat
 * as simple: a simple witness starts with its item count, never 0); null = such a transaction but not the to_sign shape.
 */
function parseFull(b: Uint8Array): FullSig | null | undefined {
  if (b.length < 10 || b[0] | b[1] | b[2] | b[3] || b[4] !== 0x00 || b[5] !== 0x01) return undefined;
  try {
    const r = reader(b); r.take(6);
    if (r.vi() !== 1) return null;
    const txid = r.take(32), vout = r.u32(), scriptSig = r.take(r.vi()), seq = r.u32();
    if (r.vi() !== 1) return null;
    const value = r.take(8), outScript = r.take(r.vi());
    const n = r.vi(); if (n < 1 || n > 16) return null;
    const items: Uint8Array[] = []; for (let k = 0; k < n; k++) items.push(r.take(r.vi()));
    const lock = r.u32();
    if (!r.done() || lock !== 0 || seq !== 0 || vout !== 0) return null;
    if (value.some((x) => x !== 0) || !eq(outScript, Uint8Array.of(0x6a))) return null;
    return { txid, scriptSig, items };
  } catch { return null; }
}
/** The scriptSig a to_sign input carries: empty, or (P2SH-P2WPKH) one push of 0014<hash160(key)> hashing to the address. */
function scriptSigOk(addr: DecodedAddress, ss: Uint8Array): boolean {
  if (addr.type !== 'p2sh') return ss.length === 0;
  return ss.length === 23 && ss[0] === 0x16 && ss[1] === 0x00 && ss[2] === 0x14 && eq(hash160(ss.slice(1)), addr.hash);
}
const encodeWitness = (items: Uint8Array[]) => cat(varint(items.length), ...items.flatMap((x) => [varint(x.length), x]));
/**
 * If `b` is a BIP-322 full signature, check it is the to_sign transaction for (addr, message) and return its witness
 * re-encoded as a simple signature. undefined = not a full signature (try it as simple); null = one that does not match.
 */
function fullToSimple(addr: DecodedAddress, message: string, b: Uint8Array): Uint8Array | null | undefined {
  const f = parseFull(b);
  if (f === undefined) return undefined;
  if (!f || addr.type === 'p2pkh' || !scriptSigOk(addr, f.scriptSig) || !eq(f.txid, toSpendTxid(message, addr.script))) return null;
  return encodeWitness(f.items);
}
/** Witness stack items (1-16) of a simple signature, or null. */
function witnessItems(b: Uint8Array): Uint8Array[] | null {
  try { const r = reader(b); const n = r.vi(); if (n < 1 || n > 16) return null; const items: Uint8Array[] = []; for (let k = 0; k < n; k++) items.push(r.take(r.vi())); return r.done() ? items : null; } catch { return null; }
}
/** The witness shapes every TOKENLOCK verifier accepts (same rule as the hosted check). */
function witnessShapeOk(type: AddressType, items: Uint8Array[] | null): boolean {
  if (!items) return false;
  if (type === 'p2wpkh' || type === 'p2sh') { const s = items[0]; return items.length === 2 && items[1].length === 33 && s.length >= 9 && s[s.length - 1] === 0x01 && derStrictLowS(s.slice(0, -1)); }
  if (type === 'p2tr') return items.length === 1 && (items[0].length === 64 || (items[0].length === 65 && items[0][64] === 0x01));
  return false;
}

// ---------------------------------------------------------------- format problems (named in errors)
/** Why a signature cannot be checked as written (the same codes and texts as the hosted check). */
export const FORMAT_PROBLEMS: Record<string, string> = {
  address_format: 'The address is not a supported Bitcoin address as written (exact text, lower-case bech32, at most 100 characters).',
  encoding: 'The signature is not base64 or hex.',
  base64_variant: 'The signature uses a base64 variant we do not accept (URL-safe characters, missing = padding, or non-ASCII spaces). Send standard padded base64.',
  bip137_header: 'The legacy signature has a header byte outside 27-42.',
  legacy_length: 'A signature for a 1... address must be a 65-byte legacy (BIP-137) signature; BIP-322 is not supported for these addresses.',
  bip322_full_template: 'The BIP-322 full signature is not the standard to_sign transaction for this address.',
  bip322_witness_shape: 'The BIP-322 signature is not a supported single-key witness (strict DER, low-S, SIGHASH_ALL; Taproot key-path only).',
};
function addressAsWritten(address: unknown): DecodedAddress | null {
  if (typeof address !== 'string' || address.length > 100 || address !== address.trim()) return null;
  if (/^(bc|tb|bcrt)1/i.test(address) && address !== address.toLowerCase()) return null;
  return decodeAddress(address);
}
// Shape only: a P2SH-P2WPKH redeem push for the wrong key is a wrong key, not a format problem.
const scriptSigShapeOk = (addr: DecodedAddress, ss: Uint8Array) => (addr.type !== 'p2sh' ? ss.length === 0 : ss.length === 23 && ss[0] === 0x16 && ss[1] === 0x00 && ss[2] === 0x14);
// Unicode whitespace a lenient decoder might skip (explicit, so every implementation agrees).
const LOOSE_WS = /[\t\n\v\f\r \u0085\u00a0\u1680\u180e\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/g;
/** Signatures longer than this (characters) are refused without decoding; real ones are under 1,000. */
export const MAX_SIGNATURE_LENGTH = 4096;
function bytesProblem(addr: DecodedAddress, b: Uint8Array): string | null {
  if (b.length === 65) return b[0] >= 27 && b[0] <= 42 ? null : 'bip137_header';
  if (addr.type === 'p2pkh') return 'legacy_length';
  const f = parseFull(b);
  if (f === null || (f && !scriptSigShapeOk(addr, f.scriptSig))) return 'bip322_full_template';
  return witnessShapeOk(addr.type, f ? f.items : witnessItems(b)) ? null : 'bip322_witness_shape';
}
/**
 * Why `signature` (for `address`) cannot be checked at all, independent of the message: a key of FORMAT_PROBLEMS, or
 * null when it is well formed (then a failure means the wrong key or message). Never throws.
 */
export function signatureFormatProblem(address: string, signature: string): string | null {
  try {
    const addr = addressAsWritten(address); if (!addr) return 'address_format';
    if (typeof signature !== 'string' || signature.length > MAX_SIGNATURE_LENGTH) return 'encoding';
    const s = signature.replace(/[ \t\r\n\f\v]+/g, ''), h = s.replace(/^0x/i, '');
    const isHex = h !== '' && /^[0-9a-fA-F]+$/.test(h) && h.length % 2 === 0;
    const isB64 = s !== '' && s.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(s);
    if (isHex) {
      const hp = bytesProblem(addr, hexdecode(h) as Uint8Array);
      if (!hp || !isB64) return hp;
      return bytesProblem(addr, b64decode(s) as Uint8Array) ? hp : null;
    }
    if (isB64) return bytesProblem(addr, b64decode(s) as Uint8Array);
    let loose = signature.replace(LOOSE_WS, '').replace(/-/g, '+').replace(/_/g, '/');
    let end = loose.length; while (end > 0 && loose.charCodeAt(end - 1) === 61) end--; loose = loose.slice(0, end); // trailing '=' (linear)
    if (loose && /^[A-Za-z0-9+/]+$/.test(loose) && loose.length % 4 !== 1) {
      const b = b64decode(loose + '='.repeat((4 - (loose.length % 4)) % 4));
      if (b && !bytesProblem(addr, b)) return 'base64_variant';
    }
    return 'encoding';
  } catch { return 'encoding'; }
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

/** The exact message first, then only its LF<->CRLF equivalent (when different). Never trimmed or otherwise normalized. */
export function messageCandidates(message: string): string[] {
  const out = [message];
  const lf = message.replace(/\r\n/g, '\n'); if (lf !== message) out.push(lf);
  const crlf = lf.replace(/\n/g, '\r\n'); if (crlf !== message) out.push(crlf);
  return out;
}
function verifyBytes(addr: DecodedAddress, message: string, sig: Uint8Array): boolean {
  if (sig.length === 65) return sig[0] >= 27 && sig[0] <= 42 && verifyLegacy(addr, message, sig);
  if (addr.type === 'p2pkh') return false; // BIP-322 for 1… addresses is not supported
  const simple = fullToSimple(addr, message, sig);
  if (simple === null) return false;
  return verifyBip322(addr, message, simple || sig);
}
/**
 * Does `signature` prove `address` signed exactly `message` (or its LF<->CRLF equivalent)? `signature` is base64, or hex
 * (optional 0x) as a fallback; whitespace inside it is ignored. Never throws.
 */
export function verifyMessageSignature(address: string, message: string, signature: string): boolean {
  try {
    if (typeof address !== 'string' || typeof message !== 'string' || typeof signature !== 'string' || signature.length > 4096) return false;
    // Same address strictness as the hosted check: at most 100 characters, no surrounding whitespace, lower-case bech32.
    if (address.length > 100 || address !== address.trim() || (/^(bc|tb|bcrt)1/i.test(address) && address !== address.toLowerCase())) return false;
    const addr = decodeAddress(address); if (!addr) return false;
    const sigs = [b64decode(signature), hexdecode(signature)].filter((x): x is Uint8Array => !!x && x.length > 0);
    if (!sigs.length) return false;
    for (const m of messageCandidates(message)) for (const sig of sigs) if (verifyBytes(addr, m, sig)) return true;
    return false;
  } catch { return false; }
}

/** Address helpers for tests and tooling. */
export const _addr = {
  p2wpkh: (pub33: Uint8Array, hrp = 'bc') => segwitEncode(hrp, 0, hash160(pub33)),
  p2tr: (pub33: Uint8Array, hrp = 'bc') => segwitEncode(hrp, 1, tweakTaproot(pub33.slice(1)) as Uint8Array),
  p2pkh: (pub: Uint8Array) => b58checkEncode(cat(Uint8Array.of(0), hash160(pub))),
  p2sh: (pub33: Uint8Array) => b58checkEncode(cat(Uint8Array.of(5), hash160(cat(Uint8Array.of(0x00, 0x14), hash160(pub33))))),
};
export const _internal = { toSpendTxid, bip143Sighash, bip341Sighash, hash160, dsha, cat, sha256, fullToSimple };
