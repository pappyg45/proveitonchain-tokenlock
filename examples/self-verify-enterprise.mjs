/**
 * Complete enterprise self-verify flow (SDK 0.3.3 docs/examples).
 *
 * In an app, import from '@proveitonchain/tokenlock/self-verify'. This file
 * imports the built package in this repo so tests can run the same logic.
 *
 * Shows: a pinned policy-signing key, a configured signed policy source,
 * path/method/environment on every check, enforcement of both `valid` and
 * `allowed`, and fail-closed handling when the policy bundle has expired or
 * the holdings provider is unavailable.
 */
import * as SV from '../dist/self-verify.js';

/**
 * Default refresh and bundle lifetime, matching signedPolicy() and the hosted policy API. A failed load is
 * retried with backoff (5 s, doubling, max refreshSeconds), not on every call; policy.status() shows the state.
 */
export const POLICY_REFRESH_SECONDS = 60;
export const POLICY_BUNDLE_TTL_SECONDS = 600;

/**
 * @param {object} o
 * @param {string} o.siteId
 * @param {Record<string, string>} o.publicKeys  kid → hex BIP-340 public key (pin from /.well-known/tokenlock-policy-keys.json)
 * @param {string} o.passSecret
 * @param {string} [o.secretKey]  site secret, used to fetch GET /api/v1/tokenlock/access/policy
 * @param {SV.NonceStore} o.store
 * @param {SV.HoldingsProvider} o.holdings
 * @param {() => Promise<any>} [o.load]  test/override: return a policy bundle instead of calling the API
 * @param {number} [o.refreshSeconds]
 * @param {string} [o.api]
 */
export function createEnterpriseVerifier(o) {
  if (!o?.publicKeys || !Object.keys(o.publicKeys).length) {
    throw new Error('Pin at least one policy-signing public key.');
  }
  const policy = SV.signedPolicy({
    siteId: o.siteId,
    secretKey: o.secretKey || 'sk_unused',
    publicKeys: o.publicKeys,
    refreshSeconds: o.refreshSeconds ?? POLICY_REFRESH_SECONDS,
    ttlSeconds: o.ttlSeconds ?? POLICY_BUNDLE_TTL_SECONDS,
    load: o.load,
    api: o.api,
  });
  const cfg = { store: o.store, holdings: o.holdings, passSecret: o.passSecret, policy };

  return {
    policy,
    /** Sign-in: signature, holdings, and (when configured) the policy. Fails closed on provider/policy errors. */
    async signIn({ challenge_id, address, signature, name } = {}) {
      return SV.verifySignIn({ challenge_id, address, signature, name }, cfg);
    },
    /**
     * Check a local pass for one resource. Callers must require both `valid` and `allowed`.
     * `policy_expired` / `policy_unavailable` if the bundle cannot be used.
     */
    async checkPass(pass, { path, method, environment } = {}) {
      const v = await SV.verifyLocalPass(pass, {
        passSecret: o.passSecret,
        policy,
        resource: { path, method, environment },
      });
      return { ok: !!(v.valid && v.allowed), ...v };
    },
  };
}

export { SV };
