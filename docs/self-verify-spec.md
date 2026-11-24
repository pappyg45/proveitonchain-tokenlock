# TOKENLOCK self-verify, spec v1

Status: preview (SDK 0.5.0, self-verify since 0.3.0; PHP drop-in 0.5.0; 0.4.2 adds policy validation: malformed policies are `policy_invalid`; 0.4.3 adds the strict request schema: malformed `resource` or unknown options are `bad_resource`, identity-only is explicit; 0.4.4 enforces every policy's validity window wherever it is used and validates `evaluate()` input before any mode branch; 0.4.5 requires explicit `routes` and `methods` on every registered key). Enterprise. Web version: https://tokenlock.ai/docs/self-verify

Self-verify lets **your server** run "Sign in with your Token" from start to finish. You issue the challenge and keep
the nonce. You check the wallet signature locally, and you read holdings from a source you pick. For the sign-in itself,
nothing has to call our API. Our API is only involved if you choose our holdings provider or pull a signed policy
bundle for registered keys.

A pass proves a wallet signed a claim and held a token at sign-in time. It does not prove legal ownership of anything.

## 1. Modes and what you still trust

| Mode | Who checks the signature | Who reads holdings | Who decides access (keys, revocation) | What you trust us for |
|---|---|---|---|---|
| Hosted (default) | our API | our API | our API, live on every verify | signature check, holdings, policy, uptime |
| Self-verify + our holdings | your server | our `/holdings` endpoint | your policy, or our signed bundle | the holdings reading only (plus the bundle, if used) |
| Self-verify + tokenscan / your node | your server | tokenscan.io, your node, or any HTTP JSON source | your policy, or our signed bundle | nothing, or the bundle signer (if used) |
| Self-verify + `localPolicy` + your node | your server | your node/indexer | you | nothing |

Whatever mode you use, you also trust:
- **The holdings source** you pick. A wrong balance means a wrong decision. `requireAgreement([a, b])` asks two
  independent sources and fails closed if they disagree.
- **Your nonce store.** Replay protection is yours (§3).
- **Your pass secret.** Anyone holding it can mint passes (§6).
- **The code**: this SDK (MIT) and the noble cryptography libraries bundled in it (Node), or the GMP-based verifier
  (PHP). Both are tested against the same 396 signature vectors, whose expected answers come from the hosted check.

## 2. Challenge message

```
Sign in with your Token
Site: <origin>
Requires: <ASSET1 or ASSET2 …>[ or any name on Bitcoin]
Via: self-verify
Nonce: <32 lowercase hex>
Issued: <ISO-8601 UTC, milliseconds>
Expires: <ISO-8601 UTC, milliseconds>
Signing proves you control this address. It moves no funds.
```

`any name on Bitcoin` (0.5.0, same as hosted): the visitor names a registered name (`^[B-Z][A-Z]{3,11}$` after ASCII
trim and uppercase) and the holdings source must report that the address OWNS it (`how: "owner"`). Other names answer
`bad_name`; a balance without ownership answers `not_holder`. Listed assets count with any positive balance.

Lines are joined with `\n` and there is no trailing newline. `Site` is the origin only: scheme, host and a port only if it
is non-default. `Via: self-verify` keeps a self-verify signature from being replayed against the hosted check, and the other
way round. Lifetime is 60 s to 30 min (default 10 min).

Accepted signatures are the same as the hosted check:
- **BIP-322 "simple"** (a base64 witness) for P2WPKH (`bc1q…`), P2SH-P2WPKH (`3…`) and single-key P2TR (`bc1p…`).
- **Legacy "Bitcoin Signed Message"** (BIP-137 / Electrum, 65 bytes) for P2PKH (`1…`), P2SH-P2WPKH, P2WPKH and P2TR
  (BIP-86 tweak of the recovered key). The address-type flag in the header byte is ignored, like the hosted check.

Wallets tested: XCP Wallet, Horizon, Unisat, Xverse and Leather. Testnet and signet addresses (`tb1…`, `m/n/2…`) are also accepted.

## 3. Nonce store (replay)

A store has `put(nonce, record, expiresAtMs)` and `take(nonce)`. `take` must be **atomic fetch-and-delete**, and must
return null when the nonce is unknown or already taken. The nonce is taken before anything else is checked, so a
failed attempt still uses it up.

Built in: `memoryNonceStore` (one process only), `fileNonceStore(dir)` (atomic rename; safe for servers that share
a folder), and `redisNonceStore(client)` (`SET NX PX` + `GETDEL`). PHP has `tokenlock_sv_file_store`, `tokenlock_sv_redis_store`
and `tokenlock_sv_memory_store`. If you run more than one server, use a shared store.

## 4. Holdings providers

A provider is `holdings(address, assets) → { [asset]: { held, how?, quantity?, exists? } }`. It throws on any
error, and a throw is always read as "deny" (`lookup_failed`).

- `proveitonchainProvider()`: `GET /api/v1/tokenlock/holdings?address=&assets=` (public, rate-limited).
- `tokenscanProvider()`: the public tokenscan.io API (asset owner first, then balances).
- `httpJsonProvider({ url, quantity, owner?, notFound? })`: your node, your indexer or another explorer.
- `staticProvider(map)`, `firstAvailable([…])` (the first source that answers wins), and `requireAgreement([…])` (every source must answer and agree).

## 5. Policy bundles (registered keys)

You need this only if you use registered keys: per-wallet permissions, orgs and revocation.

```
bundle  = { v:1, typ:"tokenlock.policy-bundle", alg:"BIP340", kid, payload, sig }
payload = base64url(JSON policy)          sig = hex(BIP-340 Schnorr over taggedHash("TOKENLOCK/policy/v1", payload bytes))
policy  = { v:1, typ:"tokenlock.policy", site_id, seq, state_version, issued_at, expires_at, mode, assets, any_name,
            origins, settings, orgs:[{id,status}], revoked_assets, keys:[{id,address,status,owner_type,org_id,assets,
            permissions:{routes,methods,environments}, expires_at, pass_ttl_s}] }
```

- **Key permissions (0.4.5):** `routes` and `methods` must each be an explicit list of strings. If `permissions` is missing,
  `null` or not an object, or `routes` / `methods` is missing, `null` or not a list, a request with a resource for that key
  is `policy_invalid` (0.4.4 read missing or `null` as `['*']`). `[]` grants nothing; `'*'` is a wildcard only when written.
  `environments` is required the same way (missing or `null`: `policy_invalid`); `['*']` is any environment; `[]` grants no
  environment (contract 1.1; RC2 read it as any). A list without `'*'` denies a request that names no environment
  (`environment_not_allowed`). A route with a trailing slash is exact (`'/api/'` = `/api`); only `/*` makes a prefix.
  `permissions` is a closed object: any other field (e.g. a misspelled `route`) makes the key `policy_invalid` (RC3).
  Identity-only checks do not read permissions. Normative rule: `AUTHORIZATION-CONTRACT.md` (contract 1.1).

- Get it with `GET /api/v1/tokenlock/access/policy?ttl=60..3600` (default 600) and `Authorization: Bearer sk_…`.
  It needs Enterprise or a pilot; otherwise the answer is 402 `plan_required`.
- Public keys are at `/.well-known/tokenlock-policy-keys.json` (also `/api/v1/tokenlock/policy-keys`). **Pin** the key in
  your config rather than fetching it at runtime.
- The bundle has no owner names or emails in it.
- Checks: the signature is by a pinned `kid`, `site_id` matches, `expires_at` is in the future, and `seq` is not lower than
  the last one seen (rollback protection). `seq` is the issue time in ms, so it always goes up.
- `localPolicy(obj | fn)`: the same shape, but you are the source, so it needs no signature. Left-out `issued_at` /
  `expires_at` default to 1970 / 9999 (no expiry); a set `expires_at` is enforced on every use.
- **Validity window (0.4.4, every policy: signed, local, custom source, or passed to `evaluate()`):** `expires_at <= now`
  is `policy_expired`; `issued_at` more than 5 minutes after `now` is `policy_invalid`. `now` is the decision's time
  (the current time unless a test passes one).
- `evaluate(policy, { address, held, resource | identityOnly: true, now? })` checks, in order: the request (exactly one
  of a valid `resource` or `identityOnly: true`, else `bad_resource` / `bad_path`), `held` (a list of asset names, else
  `bad_input`), the policy (shape and window), then the mode (token mode + resource = `policy_required`).

### Revocation freshness

A revocation reaches your server on its **next successful refresh**.

| Setting | Default | Effect |
|---|---|---|
| `refreshSeconds` (`refresh_seconds`) | 60 | How often a fresh bundle is pulled. This is the normal worst case for key revocation and permission changes. |
| `retryMinSeconds` / `retryMaxSeconds` | 5 / `refreshSeconds` | After a failed load, the next attempt waits 5 s, then 10 s, 20 s … up to the max. Calls in between don't hit the network; concurrent calls share one in-flight load. A success resets the backoff. |
| bundle `ttl` | 600 s (60–3600) | If refreshes fail, the cached bundle is used until it expires. This is the worst case during an outage. |
| after expiry | — | Every sign-in and pass check fails closed (`policy_expired`) until a refresh works. |

Holdings changes (a token transferred away) are a separate clock: holdings are read at sign-in, and `verifyLocalPass`
does not re-read them, so an existing pass keeps working until it expires (`pass_ttl_s`, default 900 s). The bundle
carries key status, not live holdings, and the hosted `recheck_holdings_s` re-check does not apply to self-verify.

The hosted mode checks revocation on every verify. Self-verify trades that for not depending on us; choose `ttl`
to match how quickly a revoked key must stop working.

## 6. Local passes

`tl3.<base64url(JSON {v,sub,h,k,n,s,i,e})>.<base64url(HMAC-SHA256(passSecret, "tl3." + body))>`

The pass secret is yours: at least 32 characters, and never sent to us. A pass is a bearer token, so send it over HTTPS
in an HttpOnly cookie or an Authorization header. Lifetime is the challenge's `pass_ttl_s` (default 900 s), capped by
the key's `pass_ttl_s` and the agent/default TTLs in the policy, and by the key's `expires_at`.
`verifyLocalPass(token, { passSecret, policy?, resource | identityOnly: true, site? })` (`site` since 0.5.0: a pass whose `s` is another origin answers `wrong_site`, never valid) gives one of these results (0.4.3: exactly one of `resource` or `identityOnly: true`):
- `valid:false, code:"bad_secret"`: `passSecret` missing or shorter than 32 characters (0.4.4).
- `valid:false, code:"bad_resource"`: unknown option, no `resource` and no `identityOnly`, or a malformed `resource` (unknown field, path without method, empty/whitespace/padded/`null`/non-string value). Never treated as identity-only. `bad_path` for a relative or non-canonical path (always `valid:false`: the pass was not checked; 0.4.3 answered `valid:true` here).
- `valid:false`: forged, expired, revoked, or the policy is unavailable, expired or not yet valid. Answer 401.
- `valid:false, allowed:false, code:"policy_required"`: a `resource` was given without a `policy`, or with a
  token-mode policy (no route rules). This is a configuration error (answer 500, or 403 in middleware, and fix the
  config): route, method and environment rules live in a registered-keys policy. `identity_valid` is `true` when the
  pass itself is authentic and unexpired. For an identity-only check pass `identityOnly: true` (no `resource`), which needs no policy.
  (No policy: Node SDK 0.3.3+, PHP 0.4.0+. Token-mode policy: Node SDK 0.4.0+, PHP 0.4.0+. Earlier versions answered
  `allowed: true`; see advisory 2026-11-18.)
- `valid:true, allowed:false`: authentic but outside this route, method or environment (`route_not_allowed`, …). Answer 403.
- `valid:true, allowed:true`: allow.

In `registered_keys` mode a pass is bound to its key id, so re-registering the same address under a new key does not
bring an old pass back to life. Passes are the same in Node and PHP: one side can verify what the other issued.

## 7. Paths

Resources use TOKENLOCK path rules v1.1, the same as the hosted API and every adapter:
- `?` and `#` are stripped.
- These are rejected: backslash, control bytes, any `;`, `%2f`, `%5c`, `%00`, `%25`, `%2e` and `%3b`.
- The path is decoded once and empty segments are dropped. Any `.` or `..` segment is rejected (not resolved).
- Matching ignores case; the resource is compared in lowercase.

The shared test vectors are in `test/fixtures/path-vectors.json`.

## 8. Fail closed

Every one of these means **deny**: an unknown or reused nonce, an expired challenge, a bad signature, an unsupported
address, any holdings error or disagreement, a policy that is unavailable or expired, a bad bundle signature, an
unknown `kid`, the wrong site, a rollback, a bad path, a bad pass, or a resource check with no policy configured. No option turns any of these into "allow".

## 9. Test vectors

- `test/fixtures/sig-vectors.json`: 396 signatures (BIP-322 and legacy, valid and tampered), labeled with what the hosted check answers.
- `test/fixtures/policy-bundle.json`: a bundle signed by the server code (`site_fixture`, seq 7).
- `test/fixtures/signin-vectors.json`: a fixed challenge, its signatures and a Node-issued pass (used by the PHP tests).
