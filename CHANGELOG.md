# Changelog

## 0.4.0 (security, breaking: explicit route authorization)

Fixes [security advisory 2026-11-18](https://proveitonchain.com/security/advisories/2026-11-18). No route, method or
environment is authorized unless a policy explicitly permits it, in the hosted client, the middleware, self-verify and
the Cloudflare worker example. Identity-only checks are unchanged. See "Upgrading to 0.4.0" in the README.

- **Hosted verification:** a resource on a token-only site (no registered keys, so no route policy) now answers
  `{ valid: false, allowed: false, code: 'policy_required', identity_valid: true }`. 0.3.x accepted the API's
  `allowed: true` answer, so `verifyPass(pass, { path })`, `getPass(req, { path })` and `authorize(...)` reported a route
  as authorized when nothing had checked it. The SDK enforces this itself (strict and loose), and the hosted API now
  answers the same way to 0.4.0 clients and direct calls.
- **Middleware (Next, Express):** new `tokenOnly` option. **Breaking:** without it, a token-only site answers
  `403 policy_required` on protected paths (logged once). With `tokenOnly: true` the middleware checks identity and
  token; if the site has registered keys it still checks the route.
- **Self-verify:** a token-mode policy with a `resource` answers `policy_required` (0.3.3 and earlier: `allowed: true`).
  Results carry `identity_valid`.
- **Cloudflare worker example:** same rules; `TOKENLOCK_TOKEN_ONLY = "1"` for token-only sites. Client header `cf-worker/0.4.0`.
- Strict checks no longer report `code: 'ok'` on an answer with `allowed: false` (now `not_allowed`).
- Tests: shared authorization matrix `test/fixtures/authz-matrix.json` (11 cases), run by Node self-verify,
  PHP self-verify, and the hosted API through the raw API, this SDK's client and the PHP client.

## 0.3.3 (fixes from external review)

- **Self-verify: a `resource` now requires a `policy`.** `verifyLocalPass(pass, { passSecret, resource })` with no `policy` returned `allowed: true` in 0.3.2, which could be read as "route, method and environment were checked". It now returns `{ valid: false, allowed: false, code: 'policy_required' }` (a configuration error, never an allow). Identity-only checks (no `resource`) still work without a policy.
- **`signedPolicy` retry backoff.** After a failed load, the next attempt waits 5 s, doubling up to `refreshSeconds` (options `retryMinSeconds`, `retryMaxSeconds`); calls in between answer at once from the cached bundle or with the last error, and concurrent calls share one in-flight load. Three immediate calls during an initial outage now make one load attempt (0.3.2: three). New `status()` reports `failures`, `last_error` and `next_retry_at`. Fixes the 0.3.0 known limit below.
- Docs: the revocation table is split into key revocation, permission changes and holdings changes. Only admin changes to registered keys are 0 s on hosted strict / `cache: false`; token transfers follow the hosted `recheck_holdings_s` (300 s default) even with `cache: false`, and self-verify passes keep their holdings until they expire.
- Docs: the enterprise self-verify example comment no longer says failed refreshes retry every 60 s.
- Docs: `verifyPass` lists every `TokenlockError` (missing configuration, non-2xx HTTP responses, network errors and timeouts), with a custom-server error-handling example.
- Tests: `test/review3.test.mjs` (9 tests) reproduces each finding against 0.3.2 and covers the fixes.

## 0.3.2 (docs)

- Docs: corrected strict-mode logging wording.

## 0.3.1 (docs and examples)

- Next.js quickstart `config.matcher` is now the broad pattern already used in the shipped example (`/((?!_next/static|_next/image|favicon.ico).*)`). TOKENLOCK's `protect` option decides which application paths are locked. A narrow, case-sensitive Next matcher such as `['/members/:path*']` is no longer shown as a copy-and-paste default.
- README documents hosted decision-log coverage, including authorized `pass_check` rows, cache hits (not hosted-logged), self-verify (not hosted-logged; no `onDecision` hook yet), and logging-failure behavior (access still proceeds; webhook is one POST, 3 s, no retries).
- New complete enterprise self-verify example (`examples/self-verify-enterprise.mjs`) with a pinned policy-signing key, signed policy source, path/method/environment, enforcement of both `valid` and `allowed`, and fail-closed handling for an expired policy bundle and an unavailable holdings provider.
- Revocation timing table now labels the zero-cache strict row as hosted verification and lists self-verify refresh (60 s default) and bundle expiry (600 s default) separately.
- Changelog 0.2.2 wording: "AI-assisted review findings and regression fixes." Trust table: `localPolicy` + your node does not require TOKENLOCK-hosted verification or an external holdings provider; you still depend on your own software and node infrastructure.

## 0.3.0 (preview: self-verify)

- **New entry `@proveitonchain/tokenlock/self-verify`** (spec v1, `docs/self-verify-spec.md`): `createChallenge`, `verifySignIn`, `issuePass` / `verifyLocalPass` (`tl3.` passes keyed by your secret).
- **Local signature check** `verifyMessageSignature`: BIP-322 simple (P2WPKH, P2SH-P2WPKH, P2TR) and legacy BIP-137 / Electrum (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR). It matches the hosted check on 396 shared vectors.
- **Nonce stores**: `memoryNonceStore`, `fileNonceStore` (atomic rename), `redisNonceStore` (SET NX PX + GETDEL). Each nonce works once, even when a sign-in fails.
- **Holdings providers**: `proveitonchainProvider`, `tokenscanProvider`, `httpJsonProvider`, `staticProvider`, `firstAvailable`, `requireAgreement`. All fail closed.
- **Signed policy bundles**: `verifyPolicyBundle` (BIP-340, pinned `kid`, site, expiry, rollback), `signedPolicy` (refresh 60 s, cached until expiry, then fail closed), `localPolicy`, `evaluate` (same rules as the hosted API, path rules v1.1).
- Shared fixtures for Node and PHP: `test/fixtures/sig-vectors.json`, `policy-bundle.json`, `signin-vectors.json`.
- Includes every 0.2.2 security fix (below).
- **PHP early block** (`tokenlock/early.php`): a malformed or ambiguous path gets 400 only if some reading of it could reach a protected path; other malformed URLs are left to your app. Protected paths keep the strict 0.2.2 rules.
- Known limit: while the policy endpoint is down, `signedPolicy` retries on every call after the refresh interval, with no backoff.


## 0.2.2 (security: AI-assisted review findings and regression fixes)

- **Path rules v1.1: ambiguous paths are rejected with 400 `bad_path`**, not resolved: any `;` (path parameters), any `.` or `..` segment, and encoded dots or semicolons (`%2e`, `%3b`). In 0.2.1, `/admin/..` was resolved to `/` (unprotected) while Express and PHP routers served it as `/admin`, so a protected prefix could be reached without a pass. Same rules in Express, Next.js, the Cloudflare example, the PHP drop-in and the API.
- **Cache key collision fixed**: the resource sent to the API, the cache key and the answer check all use one form, the canonical path lowercased (`resourcePath()`). The key also includes the secret key and API (site), method, environment and mode. Every cache hit is checked again against the request; a hit that doesn't match is dropped. Loose mode now refuses an answer that echoes a different resource.
- **Open redirects through `?next=` fixed**: `safeNext()` allows only a relative path with a single leading `/`; it refuses `//`, `/\`, any backslash, control characters, schemes and encoded variants (decoded up to three times). The Cloudflare and Express example sign-in pages now check `next` in the browser with the same function; the PHP sign-in page and `tokenlock_safe_next()` use the same rules.
- **Cloudflare example: denials keep their reason** (`route_not_allowed`, `key_revoked`, …) and answer 403, the same as the Node adapters. Only a malformed answer is `incomplete_answer`.
- Tests: shared `next-vectors.json`; equivalence matrix compares denial reasons, not just status; app-level integration matrix (`test/integration/`: Express 4 and 5, Next.js app router + middleware, PHP built-in server, Cloudflare worker in Miniflare).
- Docs: proxy/CDN guidance, and what these client-side tests don't establish (hosted-service security, tenant isolation).

## 0.2.1 (security)

- **Paths are matched in canonical form, case-insensitively** (Express, Next.js, Cloudflare example, PHP and the API). `/ADMIN`, `/admin/`, `//admin`, `/%61dmin`, `/admin;x`, `/./admin` all match `/admin`; encoded slashes/backslashes/NUL/`%25`, raw backslashes and `..` above the root are rejected with 400. New `canonicalPath()`; `createMatcher(…, { caseSensitive })`.
- **Strict mode, on by default**: an answer counts only if complete and `allowed: true` for exactly the requested path, method and environment (echoed by the API). `strict: true` with `failOpen` or `checkResource: false` throws at startup; those options without `strict` turn it off with a warning.
- **No caching of registered-key answers in strict mode** (revocation window 0). New `cache: false` option. `clearCache(pass)` now clears every route cached for that pass.
- **API mode**: `Accept: application/json` or `apiPaths` get JSON `401`/`403`/`400`/`503` with `{ error, code, reason, correlation_id }` for every denial.
- **Next.js**: `getPass()` forwards `{ path, method, environment }`; new `authorize()` (strict, uncached). Example middleware uses a broad matcher.
- **Cloudflare example** sends path, method and environment and checks `allowed` and the echoed resource; fails closed with 503.
- Docs: bearer-pass session model, exact revocation window, path rules.
