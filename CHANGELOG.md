# Changelog

## 0.2.1 (security)

- **Paths are matched in canonical form, case-insensitively** (Express, Next.js, Cloudflare example, PHP and the API). `/ADMIN`, `/admin/`, `//admin`, `/%61dmin`, `/admin;x`, `/./admin` all match `/admin`; encoded slashes/backslashes/NUL/`%25`, raw backslashes and `..` above the root are rejected with 400. New `canonicalPath()`; `createMatcher(…, { caseSensitive })`.
- **Strict mode, on by default**: an answer counts only if complete and `allowed: true` for exactly the requested path, method and environment (echoed by the API). `strict: true` with `failOpen` or `checkResource: false` throws at startup; those options without `strict` turn it off with a warning.
- **No caching of registered-key answers in strict mode** (revocation window 0). New `cache: false` option. `clearCache(pass)` now clears every route cached for that pass.
- **API mode**: `Accept: application/json` or `apiPaths` get JSON `401`/`403`/`400`/`503` with `{ error, code, reason, correlation_id }` for every denial.
- **Next.js**: `getPass()` forwards `{ path, method, environment }`; new `authorize()` (strict, uncached). Example middleware uses a broad matcher.
- **Cloudflare example** sends path, method and environment and checks `allowed` and the echoed resource; fails closed with 503.
- Docs: bearer-pass session model, exact revocation window, path rules.
