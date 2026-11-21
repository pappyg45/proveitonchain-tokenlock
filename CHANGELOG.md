# Changelog

## 0.5.0 (security release; behavior changes)

> **Behavior change: read this before upgrading.** 0.5.0 is the security release prepared as 0.4.5 (0.4.5 was never
> published) plus fixes from later reviews (RC6, RC7). It is a minor version because it **denies inputs that 0.4.4
> accepted** and adds options. If you use **`anyName` / `any_name`** ("any name on Bitcoin"): numeric assets (`A…`, free
> to issue), subassets (`NAME.sub`) and a balance of a name the wallet does not own are now **rejected** (`bad_name` /
> `not_holder`); only a registered name (4–12 letters A–Z, not starting with A) that the wallet owns counts. More inputs
> are denied: `bad_name` (malformed names), `wrong_site` (a pass issued for another site, with the new `site` option),
> `bad_site` (a `site` option or challenge site that is not an `http(s)` origin, now the same in Node and PHP). Hosted:
> an entitlement revocation on a token-mode site now denies sign-in and verify (`entitlement_revoked`), as self-verify
> already did (contract 1.2.0). Dependencies on `^0.4.x` do not pick up 0.5.0: change them to `^0.5.0`.

Released as 0.5.0 instead of 0.4.5 (20 Nov 2026). The rest of this entry is the 0.4.5 security patch as reviewed:
no new features in it. Fixes one fail-open and one broken example reported by an external reviewer (19 Nov 2026). Regression
tests were written first and failed against npm 0.4.4 (`test/correction-045.test.mjs`: 5 of 9 failed;
`php/test/correction-045.php`: 19 of 33 failed; hosted `tests/tokenlock-correction-045.test.mjs`: 25 of 32 failed).

- **Missing permissions no longer grant every route** (external review). In 0.4.4 a registered key with no
  `permissions`, `permissions: null`, `permissions: {}` or `{ routes: null, methods: null }` (or just one of `routes` /
  `methods` missing or `null`) was read as `routes: ['*']`, `methods: ['*']`, so self-verify `evaluate()` /
  `verifyLocalPass()` (Node and PHP) and the hosted access check allowed, for example, `DELETE /private/admin`. Now a
  key's `routes` and `methods` must each be an explicit list of strings; otherwise any request with a resource is refused
  with `policy_invalid` for that key (other keys in the policy are unaffected). `[]` grants nothing, and `'*'` is a
  wildcard only when it is written explicitly. Identity-only checks do not read route permissions and are unchanged.
  (`environments`: see contract v1 below.) The Cloudflare worker does not interpret permissions (it enforces the hosted
  answer); only its version changes.
- **Enterprise example** (`examples/self-verify-enterprise.mjs`): `checkPass(pass, { path, method })` answered
  `bad_resource` because it always sent `environment: undefined`. It now sends `environment` only when one is given.
- Starter projects depend on `^0.5.0`.

### RC7 corrections (reviews of RC6)

- **`site` must be an `http(s)` origin in Node too** (auditor). Node's `createChallenge({ site })` and
  `verifyLocalPass({ site })` took the origin of any URL, so `ftp://`, `ws://`, `file:` or `javascript:` sites were accepted
  (a later mismatch answered `wrong_site`); PHP already refused them. Both now answer `bad_site`. Every case was denied
  before; this aligns the codes (12-input comparison: 0 differences).
- **Hosted: entitlement revocations on token-mode sites are enforced** (review finding Q1). The hosted
  service answered `200` to the revocation and then ignored it on verify and sign-in for token-mode sites, while signed
  self-verify policies carried it. Now hosted verify and gate sign-in deny a wallet whose every held token is revoked
  (`entitlement_revoked`); a path/method request on a token-mode site is still `policy_required`. Authorization contract
  1.2.0, vectors T01–T08.

### RC8 corrections (review of RC7)

- **Hosted: Redis-down 503 scoped to sites with access state.** In
  RC7, every token-mode site answered `503` on verify and sign-in while the access store (Redis) could not be read. Now a
  site gets a permanent flag on its site record the first time it has any access state (keys, revocations, settings,
  requests or durable backups; the flag is written before that state and is never removed). A flagged site still fails
  closed (`503`) during an outage; a site that never had access state is answered on its token rules alone, as before
  RC7. With the store up, every token-mode site's revocations are read and enforced, flagged or not. The SDK code,
  self-verify and the authorization contract are unchanged.
- Thanks to the external reviewer and the auditor for their reviews of this release.

### RC6 corrections (reviews of RC5)

- **"Any name on Bitcoin" means a registered name the wallet owns** (S1). Self-verify (Node and PHP) accepted
  any asset name with any positive balance, including numeric `A…` assets that anyone can issue for the network fee.
  Now, as on hosted sign-in, the name must be 4–12 letters A–Z, not starting with A, and the holdings provider must
  report ownership (`how: 'owner'`). Anything else answers `bad_name`; a balance of a name the wallet does not own answers
  `not_holder`. Assets the site lists still count with any positive balance. `staticProvider(map, owners)` /
  `tokenlock_sv_static_provider($map, $owners)` take an optional second argument for owned names.
- **`verifyLocalPass({ site })` / `tokenlock_sv_verify_local_pass(array('site' => …))`**: optional. A pass issued for
  another site (possible only when two sites share a `passSecret`) answers `wrong_site` and is never valid. Use one
  `passSecret` per site.
- **PHP policy cache** (`tokenlock_sv_signed_policy`): updates are serialized with a file lock and the bundle with the
  higher `seq` wins, so overlapping refreshes can no longer leave an older bundle on disk; a failed cache write removes
  the old record (or fails closed with `policy_cache_failed`), and the cached bundle is used as an outage fallback only
  while the cache directory is writable. In RC5 a revoked key could be allowed again from the older bundle.

### Identity selector (0.4.5 RC4)

- **`evaluate()` no longer reads `{ resource: { identityOnly: true } }` as an identity-only check** (external review of
  RC3). Node self-verify `evaluate()` took that malformed request as identity-only, so an active key with empty
  `routes`, `methods` and `environments` was allowed (token-mode and registered-key policies). It is now `bad_resource`.
  Identity-only is selected only by the top-level `identityOnly: true` with no `resource` (contract §2 step 1, now stated
  explicitly). `verifyLocalPass()`, the PHP drop-in, the Cloudflare worker and the hosted API already refused it.
  Contract vectors: new group I (54 vectors).

### Authorization contract 1.1 (added in 0.4.5 RC3)

Release candidate 3 closes two gaps found while reviewing RC2, before 0.4.5 is published. Contract:
[AUTHORIZATION-CONTRACT.md](AUTHORIZATION-CONTRACT.md) 1.1.0; upgrade checklist: [UPGRADE-0.4.5.md](UPGRADE-0.4.5.md).

- **Reactivating a key requires explicit grants (hosted).** Approving a revoked key now requires `routes`, `methods`,
  `environments` and `expires_at` (ISO date or `null`) in the request (`400 permissions_required` / `expiry_required`).
  RC2 reactivated it with its previous grants and expiry. The previous grants stay visible in the dashboard, for
  reference only; every input starts empty. No other path turns a revoked key active.
- **A successful change survives recovery (hosted).** A change answers `200` only when the journal, the snapshot and a
  separate revocation ledger all hold it;
  otherwise `503 not_durable` (the change is in effect now; repeat it until it answers `200`). When the live store is
  restored and the latest state cannot be established, every key that is not revoked is held (`pending_approval`) until
  an administrator re-approves it with explicit grants. A revoked key stays revoked through every recovery path.
- **An older backup cannot bring back revoked access (hosted).** The revocation ledger is kept apart from the backups;
  a restore that finds a key changed after the restored copy revokes it again (or holds it), and a lost site-wide
  change holds every key. A missing or unreadable ledger holds every key.
- **Concurrent changes cannot undo a revocation or a narrowing (hosted).** Changes for a site are serialized and
  version-checked (`409 site_busy` / `key_changed` / `state_changed`; nothing changed, retry). An admin change on a
  lost live store restores first instead of starting an empty state.
- **Unknown permission fields deny (Node, PHP, hosted).** `permissions` may contain only `routes`, `methods` and
  `environments`; any other field makes the key invalid (it was ignored, keeping the other grants). The hosted API also
  refuses a malformed `expires_at` (`400 bad_expiry`) or `assets` (`400 bad_assets`; it was dropped, removing the
  restriction).
- **`environments: []` grants no environment** (Node, PHP, hosted). It was the deprecated "any environment" form; write
  `['*']` for any environment. The hosted API has not created `[]` since RC2.

Tests were written first and failed against the frozen RC2 artifacts: contract vectors E07/E08 (Node, PHP and hosted) and
2,458 property violations in Node and PHP; hosted lifecycle tests (`tests/tokenlock-correction-045-rc3.test.mjs`) 28 of
34; hosted lifecycle properties (`tests/tokenlock-lifecycle-properties.test.mjs`) 242 violations. Further tests for the
durability, recovery, concurrency and field requirements were added first as well: unknown-field vectors F01-F04 (Node,
PHP and hosted allowed them), durability / termination / concurrency tests
(`tests/tokenlock-correction-045-rc3-durability.test.mjs`, 22 of 29 failing on RC2) and randomized recovery over six
recorded seeds (`tests/tokenlock-recovery-random.test.mjs`). Contract vectors: 111.

### Authorization contract v1 (added in 0.4.5 RC2)

The remaining implicit authorization defaults are removed, and one written rule now covers every integration:
[AUTHORIZATION-CONTRACT.md](AUTHORIZATION-CONTRACT.md) (normative, version 1.0.0). It comes with 89 shared test vectors
(`docs/authorization-vectors-v1.json`, run by Node, PHP, the Cloudflare worker and the hosted API) and seeded property
tests: removing, corrupting or narrowing authorization data never allows more. 1,952,768 evaluations per platform, same
input and decision digests in Node and PHP.

Tests were written first and failed against the frozen RC1 artifacts:
- Contract vectors: 5 of 89 failed in Node, PHP and hosted alike (G10, M06, M09, E02, E11).
- Property violations: 2,350 in Node and PHP, 6,324 hosted.
- Hosted RC2 regressions (`tests/tokenlock-correction-045-rc2.test.mjs`): 35 of 58 failed.

Changes:
- **`environments` is required** like `routes` and `methods`. Missing or `null` is `policy_invalid` (RC1 read it as any
  environment). `['*']` is any environment.
- **A restricted key denies a request with no environment** (`environment_not_allowed`). RC1 skipped the check when
  the request named none, so a key limited to `staging` worked anywhere the environment was left out.
- **A trailing slash is an exact route.** `'/api/'` matches only `/api`; RC1 read it as `/api/*`.
- **Hosted API:**
  - Resource checks need the site's secret key (`secret_key_required`). RC1 answered them for anyone with a pass, and
    took the environment from the caller.
  - Stored `expires_at` must be ISO 8601. A corrupted `99999` or `'2999'` no longer revives an expired key.
  - The admin API no longer fills in wildcards on create, update, rotate or request approval (`permissions_required` /
    `bad_permissions`).
  - Rotation requires an active key.
  - A request approval never revives a revoked key.
  - The signed policy carries stored values as-is.
  - The dashboard no longer prefills `*` and asks for grants when approving a request.

**MIGRATION.** Stored data is never rewritten. A read-only review of production found 15 keys, with no wildcard, no
`[]`, no missing field and no trailing-slash route. Check your own setup:
- **A key restricted to environments:** make sure every check names the environment. Set it in the guard
  (`environment`), the PHP drop-in (`'environment'` / `TOKENLOCK_ENVIRONMENT`) or the worker (`TOKENLOCK_ENVIRONMENT`).
- **`environments: []`:** grants no environment since RC3. Write `['*']` or a list of environments.
- **A hand-written policy key without `environments`:** add it.
- **A route written as `'/x/'` that was meant as a prefix:** write `'/x/*'`.
- **Code calling the hosted verify endpoint directly with path or method:** send `Authorization: Bearer sk_…` from your
  server.

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
