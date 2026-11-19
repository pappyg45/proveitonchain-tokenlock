// Exercises examples/self-verify-enterprise.mjs against the real 0.3.x self-verify API:
// pinned policy key, signed policy source, path/method/environment, valid && allowed,
// expired policy bundle, unavailable holdings provider.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import * as SV from '../dist/self-verify.js';
import { createEnterpriseVerifier, POLICY_REFRESH_SECONDS, POLICY_BUNDLE_TTL_SECONDS } from '../examples/self-verify-enterprise.mjs';

const sha = (b) => createHash('sha256').update(b).digest();
const SECRET = 'y'.repeat(40);
const SITE = 'https://app.example';
const ADDR = 'bc1qenterpriseexampleaddress0000000000000'; // replaced by a real P2WPKH below

function signBundle(sk, payload) {
  const bytes = Buffer.from(JSON.stringify(payload));
  const tag = sha(Buffer.from('TOKENLOCK/policy/v1'));
  const msg = sha(Buffer.concat([tag, tag, bytes]));
  return {
    v: 1, typ: 'tokenlock.policy-bundle', alg: 'BIP340', kid: 'k1',
    payload: bytes.toString('base64url'),
    sig: Buffer.from(schnorr.sign(msg, sk)).toString('hex'),
  };
}

function policyPayload({ now, ttlS = POLICY_BUNDLE_TTL_SECONDS, seq = 1, keys, expiresAt }) {
  return {
    v: 1, typ: 'tokenlock.policy', site_id: 'site_ent', seq,
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(expiresAt ?? (now + ttlS * 1000)).toISOString(),
    mode: 'registered_keys',
    settings: { require_org: false },
    orgs: [{ id: 'org_1', status: 'approved' }],
    revoked_assets: [],
    keys: keys || [{
      id: 'key_agent', address: ADDR, status: 'active', owner_type: 'agent', org_id: 'org_1',
      permissions: { routes: ['/api/reports/*'], methods: ['GET'], environments: ['production'] },
      expires_at: null, pass_ttl_s: 900,
    }],
  };
}

const wallet = () => {
  const priv = secp256k1.utils.randomSecretKey();
  return { priv, address: SV._addr.p2wpkh(secp256k1.getPublicKey(priv, true)) };
};

function signLegacy(priv, message) {
  const m = Buffer.from(message, 'utf8');
  const len = m.length < 253 ? Buffer.from([m.length]) : Buffer.from([253, m.length & 255, m.length >> 8]);
  const h = sha(sha(Buffer.concat([Buffer.from('\x18Bitcoin Signed Message:\n'), len, m])));
  const s = secp256k1.sign(h, priv, { prehash: false, format: 'recovered' });
  return Buffer.concat([Buffer.from([39 + s[0]]), Buffer.from(s.slice(1))]).toString('base64');
}

test('enterprise self-verify example: defaults match the 0.3.0 API', () => {
  assert.equal(POLICY_REFRESH_SECONDS, 60);
  assert.equal(POLICY_BUNDLE_TTL_SECONDS, 600);
});

test('enterprise self-verify example: pin key, allow and deny a resource, fail closed on expiry and holdings outage', async () => {
  const w = wallet();
  const now = Date.now();
  const sk = secp256k1.utils.randomSecretKey();
  const pk = Buffer.from(schnorr.getPublicKey(sk)).toString('hex');
  const keys = [{
    id: 'key_agent', address: w.address, status: 'active', owner_type: 'agent', org_id: 'org_1',
    permissions: { routes: ['/api/reports/*'], methods: ['GET'], environments: ['production'] },
    expires_at: null, pass_ttl_s: 900,
  }];
  const bundle = signBundle(sk, policyPayload({ now, keys }));
  const store = SV.memoryNonceStore();
  const holdings = SV.staticProvider({ [w.address]: ['TOKENLOCK'] });
  const verifier = createEnterpriseVerifier({
    siteId: 'site_ent',
    publicKeys: { k1: pk },
    passSecret: SECRET,
    store,
    holdings,
    load: async () => bundle,
  });

  const c = await SV.createChallenge({ site: SITE, assets: ['TOKENLOCK'], store });
  const signed = signLegacy(w.priv, c.message);
  const signedIn = await verifier.signIn({ challenge_id: c.challenge_id, address: w.address, signature: signed });
  assert.equal(signedIn.valid, true, signedIn.code);
  assert.ok(signedIn.pass);

  const allowed = await verifier.checkPass(signedIn.pass, { path: '/api/reports/q3', method: 'GET', environment: 'production' });
  assert.equal(allowed.ok, true);
  assert.equal(allowed.valid, true);
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.code, 'ok');

  const denied = await verifier.checkPass(signedIn.pass, { path: '/api/admin/users', method: 'GET', environment: 'production' });
  assert.equal(denied.ok, false);
  assert.equal(denied.valid, true);           // pass is authentic
  assert.equal(denied.allowed, false);        // but this resource is not in scope
  assert.equal(denied.code, 'route_not_allowed');

  const method = await verifier.checkPass(signedIn.pass, { path: '/api/reports/q3', method: 'POST', environment: 'production' });
  assert.equal(method.ok, false);
  assert.equal(method.code, 'method_not_allowed');

  const env = await verifier.checkPass(signedIn.pass, { path: '/api/reports/q3', method: 'GET', environment: 'staging' });
  assert.equal(env.ok, false);
  assert.equal(env.code, 'environment_not_allowed');

  // Expired policy bundle + refresh failure → fail closed (policy_expired).
  const expired = signBundle(sk, policyPayload({ now: now - 1200e3, keys, expiresAt: now - 1000 }));
  // First successful load is already expired; refresh cannot save it.
  const dead = createEnterpriseVerifier({
    siteId: 'site_ent', publicKeys: { k1: pk }, passSecret: SECRET, store: SV.memoryNonceStore(),
    holdings, refreshSeconds: 0, load: async () => expired,
  });
  const expiredCheck = await dead.checkPass(signedIn.pass, { path: '/api/reports/q3', method: 'GET', environment: 'production' });
  assert.equal(expiredCheck.ok, false);
  assert.equal(expiredCheck.allowed, false);
  assert.equal(expiredCheck.code, 'policy_expired');

  // Unavailable holdings provider at sign-in → lookup_failed, no pass.
  const down = { async holdings() { throw Object.assign(new Error('down'), { code: 'lookup_failed' }); } };
  const store2 = SV.memoryNonceStore();
  const outage = createEnterpriseVerifier({
    siteId: 'site_ent', publicKeys: { k1: pk }, passSecret: SECRET, store: store2,
    holdings: down, load: async () => bundle,
  });
  const c2 = await SV.createChallenge({ site: SITE, assets: ['TOKENLOCK'], store: store2 });
  const s2 = await outage.signIn({ challenge_id: c2.challenge_id, address: w.address, signature: signLegacy(w.priv, c2.message) });
  assert.equal(s2.valid, false);
  assert.equal(s2.code, 'lookup_failed');
  assert.equal(s2.pass, undefined);

});
