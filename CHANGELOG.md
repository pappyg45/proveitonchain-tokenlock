# Changelog

## 0.3.0 (preview: self-verify)

- **New entry `@proveitonchain/tokenlock/self-verify`** (spec v1, `docs/self-verify-spec.md`): `createChallenge`, `verifySignIn`, `issuePass` / `verifyLocalPass` (`tl3.` passes keyed by your secret).
- **Local signature check** `verifyMessageSignature`: BIP-322 simple (P2WPKH, P2SH-P2WPKH, P2TR) and legacy BIP-137 / Electrum (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR). It matches the hosted check on 396 shared vectors.
- **Nonce stores**: `memoryNonceStore`, `fileNonceStore` (atomic rename), `redisNonceStore` (SET NX PX + GETDEL). Each nonce works once, even when a sign-in fails.
- **Holdings providers**: `proveitonchainProvider`, `tokenscanProvider`, `httpJsonProvider`, `staticProvider`, `firstAvailable`, `requireAgreement`. All fail closed.
- **Signed policy bundles**: `verifyPolicyBundle` (BIP-340, pinned `kid`, site, expiry, rollback), `signedPolicy` (refresh 60 s, cached until expiry, then fail closed), `localPolicy`, `evaluate` (same rules as the hosted API, path rules v1).
- Shared fixtures for Node and PHP: `test/fixtures/sig-vectors.json`, `policy-bundle.json`, `signin-vectors.json`.
- Known limit: while the policy endpoint is down, `signedPolicy` retries on every call after the refresh interval, with no backoff.


## 0.2.1 (security)

- **Paths are matched in canonical form, case-insensitively** (Express, Next.js, Cloudflare example, PHP and the API). `/ADMIN`, `/admin/`, `//admin`, `/%61dmin`, `/admin;x`, `/./admin` all match `/admin`; encoded slashes/backslashes/NUL/`%25`, raw backslashes and `..` above the root are rejected with 400. New `canonicalPath()`; `createMatcher(…, { caseSensitive })`.
- **Strict mode, on by default**: an answer counts only if complete and `allowed: true` for exactly the requested path, method and environment (echoed by the API). `strict: true` with `failOpen` or `checkResource: false` throws at startup; those options without `strict` turn it off with a warning.
- **No caching of registered-key answers in strict mode** (revocation window 0). New `cache: false` option. `clearCache(pass)` now clears every route cached for that pass.
- **API mode**: `Accept: application/json` or `apiPaths` get JSON `401`/`403`/`400`/`503` with `{ error, code, reason, correlation_id }` for every denial.
- **Next.js**: `getPass()` forwards `{ path, method, environment }`; new `authorize()` (strict, uncached). Example middleware uses a broad matcher.
- **Cloudflare example** sends path, method and environment and checks `allowed` and the echoed resource; fails closed with 503.
- Docs: bearer-pass session model, exact revocation window, path rules.
