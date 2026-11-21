// RC6: signed policy bundles for the PHP policy-cache tests (overlapping refreshes, cache write failure). Same deterministic
// test-only key as build-rc5-bundles.mjs; far-future expiry. Run: node test/vectors/build-rc6-bundles.mjs
import { schnorr } from '@noble/curves/secp256k1.js';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const sha = (b) => createHash('sha256').update(b).digest();
const tagged = (tag, msg) => { const t = sha(Buffer.from(tag)); return sha(Buffer.concat([t, t, msg])); };
const PRIV = sha(Buffer.from('tokenlock rc5 test fixture'));
const PUB = Buffer.from(schnorr.getPublicKey(PRIV)).toString('hex');
const AUX = new Uint8Array(32); // deterministic signatures, so the fixture file is reproducible
const bundle = (p) => { const bytes = Buffer.from(JSON.stringify(p)); return { v: 1, typ: 'tokenlock.policy-bundle', alg: 'BIP340', kid: 'k1', payload: bytes.toString('base64url'), sig: Buffer.from(schnorr.sign(tagged('TOKENLOCK/policy/v1', bytes), PRIV, AUX)).toString('hex') }; };
const ADDR = 'bc1qagentaddressxxxxxxxxxxxxxxxxxxxxxxxx';
const KEY = (status) => ({ id: 'key_a', address: ADDR, status, owner_type: 'agent', org_id: null, assets: [], permissions: { routes: ['/members/*'], methods: ['GET'], environments: ['production'] }, expires_at: null, pass_ttl_s: null });
const POL = (seq, status) => ({ v: 1, typ: 'tokenlock.policy', site_id: 'site1', seq, state_version: seq, issued_at: '2026-11-19T00:00:00.000Z', expires_at: '2099-01-01T00:00:00.000Z', mode: 'registered_keys', orgs: [], revoked_assets: [], keys: [KEY(status)] });
const out = { public_keys: { k1: PUB }, address: ADDR, bundles: { active_1000: bundle(POL(1000, 'active')), active_2000: bundle(POL(2000, 'active')), active_2500: bundle(POL(2500, 'active')), revoked_3000: bundle(POL(3000, 'revoked')) } };
writeFileSync(new URL('../../php/test/fixtures/rc6-bundles.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log('wrote php/test/fixtures/rc6-bundles.json', PUB);
