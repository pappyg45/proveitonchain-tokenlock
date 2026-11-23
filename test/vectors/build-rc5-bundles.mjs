// RC5: signed policy bundles for the PHP tests of the mode-downgrade guard (H1 client side). Deterministic test-only key
// (sha256('tokenlock rc5 test fixture')); far-future expiry. Run: node test/vectors/build-rc5-bundles.mjs
import { schnorr } from '@noble/curves/secp256k1.js';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const sha = (b) => createHash('sha256').update(b).digest();
const tagged = (tag, msg) => { const t = sha(Buffer.from(tag)); return sha(Buffer.concat([t, t, msg])); };
const PRIV = sha(Buffer.from('tokenlock rc5 test fixture'));
const PUB = Buffer.from(schnorr.getPublicKey(PRIV)).toString('hex');
const bundle = (p) => { const bytes = Buffer.from(JSON.stringify(p)); return { v: 1, typ: 'tokenlock.policy-bundle', alg: 'BIP340', kid: 'k1', payload: bytes.toString('base64url'), sig: Buffer.from(schnorr.sign(tagged('TOKENLOCK/policy/v1', bytes), PRIV, new Uint8Array(32))).toString('hex') }; };
const ADDR = 'bc1qagentaddressxxxxxxxxxxxxxxxxxxxxxxxx';
const KEY = (o = {}) => ({ id: 'key_a', address: ADDR, status: 'active', owner_type: 'agent', org_id: null, assets: [], permissions: { routes: ['/members/*'], methods: ['GET'], environments: ['production'] }, expires_at: null, pass_ttl_s: null, ...o });
const POL = (o = {}) => ({ v: 1, typ: 'tokenlock.policy', site_id: 'site1', seq: 1, state_version: 7, issued_at: '2026-11-19T00:00:00.000Z', expires_at: '2099-01-01T00:00:00.000Z', mode: 'registered_keys', orgs: [], revoked_assets: [], keys: [KEY({ status: 'revoked' })], ...o });
const out = { public_keys: { k1: PUB }, address: ADDR, bundles: {
  registered_v7_revoked: bundle(POL({ seq: 10 })),
  token_v0_after_loss: bundle(POL({ seq: 20, state_version: 0, mode: 'token', keys: [] })),
  token_v7_same_version: bundle(POL({ seq: 21, mode: 'token', keys: [] })),
  token_no_version: bundle((() => { const p = POL({ seq: 22, mode: 'token', keys: [] }); delete p.state_version; return p; })()),
  token_v8_turned_off: bundle(POL({ seq: 30, state_version: 8, mode: 'token', keys: [] })),
  registered_v9_back_on: bundle(POL({ seq: 40, state_version: 9 })),
} };
writeFileSync(new URL('../../php/test/fixtures/rc5-bundles.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log('wrote php/test/fixtures/rc5-bundles.json', PUB);
