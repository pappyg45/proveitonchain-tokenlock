# Changelog

## 0.4.4 (security correction)

No new features. Corrects validation gaps reported by an external reviewer and found by a widened audit that enumerates
every exported function (Node SDK, PHP drop-in, Cloudflare worker, hosted API) and fuzzes each one. 0.4.3 is deprecated
on npm. Regression tests were written first and failed against npm 0.4.3 (`test/correction-044.test.mjs`: 11 of 13
failed; `php/test/correction-044.php`: 31 of 45 failed; `test/fuzz-exports.test.mjs`: 332 findings; all pass on 0.4.4).
Advisory: https://proveitonchain.com/security/advisories/2026-11-18#correction-044

- **Self-verify `evaluate()` validates before any mode branch** (external review). 0.4.3 returned `allowed: true` from
  the token-mode branch before looking at the resource (a normal resource, `{ pth: '/private' }` or an array path).
  Now: the request is checked first (exactly one of a valid `resource` or `identityOnly: true`; unknown options,
  `null` or a missing resource are `bad_resource`), then `held` (must be a list of strings, else `bad_input`; `null` no
  longer skips the holdings check), then the policy, then the mode: a token-mode policy with a resource is
  `policy_required`.
- **Policy validity window enforced everywhere** (external review). An explicitly expired `localPolicy()` still
  authorized in 0.4.3 (only the signed-bundle path checked expiry). `validatePolicy()` now refuses `expires_at <= now`
  (`policy_expired`) and an `issued_at` more than 5 minutes ahead (`policy_invalid`, previously signed bundles only), and
  it runs on every use: `localPolicy().get()`, custom sources, `evaluate()`, `verifyLocalPass()`, `verifySignIn()`.
- **`verifyLocalPass()` checks `passSecret`** (widened audit): a missing, empty or short secret is `bad_secret`. 0.4.3
  verified passes forged with an empty HMAC key when `passSecret` was `''` (for example an unset environment variable).
- **`verifyLocalPass()` never answers `valid: true` before the pass is verified** (widened audit): a malformed path is
  checked first, and 0.4.3 answered `{ valid: true, allowed: false, code: 'bad_path' }` for any token, even garbage.
- **Cloudflare worker:** `strictCheck(answer, resource)` validates `resource` (a misspelled `{ pth }` matched an answer
  naming no path); `verify()` accepts only plain objects with own fields (inherited fields skipped the type checks).
- **`validateResource()`** reads own fields only.
- **Starters** (`examples/express`, `examples/next-app`): depend on `^0.4.4` (they said `^0.1.0`, which excludes 0.4.x),
  set `tokenOnly: true` (holder sites), and the Next members page calls `getPass(undefined, { identityOnly: true })`.
- **Docs:** `authorize()` without a resource is `bad_resource` with status 400 (the README said `resource_required`,
  status 0); PHP current version; identity-only guidance names `identityOnly: true`; the `policy_required` reason says
  to pass `{ identityOnly: true }` instead of "drop `resource`".

## 0.4.3 (security correction, breaking: explicit identity-only)

No new features. Corrects a fail-open found by the 0.4.2 production regression run: in 0.4.2 an unknown, mistyped,
empty, `null` or non-string resource field (for example `{ pth: '/admin' }` or `{ path: '' }`) was dropped and the call
became an identity-only check, which can answer `valid: true` for a protected resource. 0.4.2 is deprecated on npm.
Regression tests were written first and failed against 0.4.2 (`test/correction-043.test.mjs`: 6 of 8 failed on 0.4.2;
all pass on 0.4.3). Advisory: https://proveitonchain.com/security/advisories/2026-11-18#correction-043

- **One strict schema** (`validateResource`) for every authorization entry point: `verifyPass`, `getPass`, `authorize`,
  `TokenlockClient.verifyPass`, the Next.js helpers, the Express/Next middleware, the Cloudflare worker and
  `verifyLocalPass`/`evaluate`. Allowed fields: `path`, `method`, `environment`, `identityOnly`.
- **Refused (`TokenlockError` `code: 'bad_resource'`, before any network call):** unknown fields or options, a request
  that is not a plain object, a path without a method or a method without a path, values that are not strings, empty,
  whitespace-only or padded, `null`/`undefined` values, a method that is not 1–10 letters, an environment that is not
  1–30 of `A-Z a-z 0-9 _ . -`. Values are never truncated. A relative path or one that fails the canonical path rules
  answers `{ valid: false, code: 'bad_path' }`. A query string or fragment is dropped (path rules v1.1, unchanged).
- **Breaking: identity-only is explicit.** `verifyPass(pass, { secretKey, identityOnly: true })`,
  `getPass(req, { identityOnly: true })`, `client.verifyPass(pass, { identityOnly: true })`,
  `verifyLocalPass(pass, { passSecret, identityOnly: true })`. Calling these with no resource now throws
  `bad_resource` (self-verify answers `bad_resource`) instead of silently doing an identity check. `identityOnly` must
  be exactly `true` and alone. `authorize()` always needs `{ path, method }`. On the wire an identity check sends
  `identity_only: true`.
- **Middleware / worker:** the resource is built from the request; an unset environment is omitted (never sent as
  `null` or `''`); an invalid `environment` option or `TOKENLOCK_ENVIRONMENT` is `bad_config`. A request whose method
  is not a plain HTTP method name is denied.
- **Interface audit fixes (path patterns):** an Express/Next `protect`, `publicPaths` or `apiPaths` string without a
  leading `/` (e.g. `'api/*'`) matched nothing and silently left those paths unprotected; it is now `bad_config` at
  startup. In the Cloudflare worker, a `TOKENLOCK_PROTECT` / `TOKENLOCK_API_PATHS` entry that is not a plain path prefix
  (`/api/*`, `/api/:path*`, `api`) is `bad_config` and every request is refused (500) until fixed.
- **Docs:** 0.4.2 said "unknown options are refused"; that held for the middleware only. Since 0.4.3 it holds for every
  authorization call.

## 0.4.2 (security hardening, breaking: removed options)

No new features. Removes every configuration that could weaken fail-closed behavior and adds denial checks for
invalid configuration, stale or malformed policies, malformed backend answers and conflicting decisions. Regression
tests were written first and failed against 0.4.1 (`test/hardening-042.test.mjs`: 26 of 30 failed on 0.4.1, 30 of 30
pass on 0.4.2).

- **Breaking, removed:** `failOpen` and `checkResource` (any value) and `strict: false` (loose mode) are configuration
  errors (`TokenlockError`, `code: 'bad_config'`) on `TokenlockClient`, `verifyPass`, `getPass`, `authorize` and the
  Express/Next middleware. The `x-tokenlock: fail-open` header is gone. The path, method and environment are always sent.
- **Configuration validation:** the middleware refuses unknown options (typos), wrong types (`tokenOnly: 'false'` was
  truthy in 0.4.1), a missing or malformed secret key, an empty `protect` and a missing `signInPage`. The client checks
  `timeoutMs`, `cache`, `apiBase`, `fetch` and the secret key format.
- **Answers:** capped at 64 KiB; a 2xx answer that is not a JSON object is `bad_answer` (502 → protected requests get
  503). Identity checks are strict too. New denials: `valid: true` with a `code`, `error` or `identity_valid` other than
  true; `allowed` present and not `true`; `access.reason` other than `ok`; non-ISO `expires_at`; `assets_held` not a list;
  any resource echo that is not an object or names another resource (both echoes are checked); an identity answer that
  names a resource. Registered-key answers are never cached.
- **Self-verify:** `validatePolicy` (signed bundles and `localPolicy`): integer `seq` ≥ 0, ISO `issued_at`/`expires_at`,
  `issued_at` at most 5 min in the future, `mode` `token`|`registered_keys`, list-typed `orgs`/`revoked_assets`/`keys`
  and permissions, known key status, parseable key expiry. Malformed → `policy_invalid`. `evaluate` denies malformed
  input; an unparseable key expiry is `key_expired`. The hosted holdings provider requires a boolean `held`;
  `requireAgreement` refuses non-boolean answers.
- **Cloudflare worker example:** `TOKENLOCK_FAIL_OPEN`, `TOKENLOCK_CHECK_RESOURCE`, `TOKENLOCK_STRICT` (any value), a
  missing or non-`sk_` secret, invalid `TOKENLOCK_TOKEN_ONLY`/`TOKENLOCK_TIMEOUT_MS`/`TOKENLOCK_API` → `500 bad_config`
  on protected paths and the session endpoint. Fail-closed fetch timeout (`TOKENLOCK_TIMEOUT_MS`, default 8000) → `503`.
  Same answer checks as the SDK. Client header `cf-worker/0.4.2`.
- **Hosted API (deployed with this release):** a storage error reading a site's settings is `503` and is not cached
  (0.4.1 cached it as "no site", which with the Redis access state also missing produced a token-only answer for a
  registered-keys site); access decisions use the site document just loaded for the secret key; malformed access state
  or key records deny; the `TOKENLOCK_LEGACY_RESOURCE_COMPAT` emergency switch was removed.
- PHP drop-in 0.4.2 ships the same changes.

## 0.4.1 (documentation only)

No code changes from 0.4.0: same authorization logic, same tests. Only the version string (`VERSION`, client header
`js/0.4.1`) and the documents changed. 0.4.1 is the stable security baseline.

- README: the hosted API answers `policy_required` to every client version, SDK and PHP 0.2.x/0.3.x included (since
  18 Nov 2026, 9:03 PM PT). The 0.4.0 package still said legacy clients got the old answer.
- README: new "Fail-closed guarantee" section listing what denies by default (no policy, legacy clients, `tokenOnly`
  on a registered-keys site, API unreachable / 5xx / timeout, policy or holdings lookup failures) and the explicit
  opt-outs that weaken it (`failOpen: true`, `checkResource: false`, the hosted holdings re-check grace window).
- PHP drop-in 0.4.1 ships the same way: documentation and version string only.

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
