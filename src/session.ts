import { TokenlockClient, passCookie, clearPassCookie, wantsSecure, safeNext, DEFAULT_COOKIE, type ClientOptions, type PassInfo } from './core.js';

export interface SessionOptions extends ClientOptions {
  /** Cookie name. Default tokenlock_pass */
  cookieName?: string;
  /** Cookie path. Default '/' so every protected path sees it. */
  cookiePath?: string;
  /** Longest a sign-in lasts, in seconds (also capped by the pass). Default 86400. */
  maxAgeSeconds?: number;
  /** Where sign-out sends people. Default '/' */
  afterSignOut?: string;
}

/** Shared pass → cookie exchange. Returns status, JSON body and Set-Cookie. */
export async function exchangePass(client: TokenlockClient, o: SessionOptions, input: { pass: unknown; requestUrl: string; originHeader?: string | null }) {
  // Only accept the exchange from your own pages (stops other sites from planting a pass).
  const self = new URL(input.requestUrl).origin;
  if (input.originHeader && input.originHeader !== self) return { status: 403, body: { ok: false, code: 'bad_origin', error: 'Wrong site.' } };
  const pass = typeof input.pass === 'string' ? input.pass : '';
  let info: PassInfo;
  try { info = await client.verifyPass(pass); }
  catch (e: any) { return { status: 503, body: { ok: false, code: e?.code || 'unavailable', error: 'Could not check the pass right now. Try again.' } }; }
  if (!info.valid) return { status: 401, body: { ok: false, code: info.code || 'bad_pass', error: info.reason || 'Not signed in.' } };
  const cookie = passCookie(pass, info, { name: o.cookieName || DEFAULT_COOKIE, path: o.cookiePath, maxAgeSeconds: o.maxAgeSeconds, secure: wantsSecure(input.requestUrl) });
  return { status: 200, body: { ok: true, address: info.address, assets_held: info.assets_held, expires_at: info.expires_at }, cookie };
}

export function signOutCookie(o: SessionOptions, requestUrl: string) {
  return clearPassCookie({ name: o.cookieName || DEFAULT_COOKIE, path: o.cookiePath, secure: wantsSecure(requestUrl) });
}

export function signInRedirect(signInPage: string, requestUrl: string, path: string, search = '') {
  const u = new URL(signInPage, requestUrl);
  u.searchParams.set('next', safeNext(path + search));
  return u;
}
