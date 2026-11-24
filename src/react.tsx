import * as React from 'react';
import { DEFAULT_API, safeNext } from './core.js';

declare global {
  interface Window { ProveItGate?: { signIn(o: { siteKey?: string; passTtlSeconds?: number; title?: string }): Promise<{ pass: string; address: string; assets_held: string[] }> } }
}

export interface SignInWithBitcoinProps {
  /** pk_… from your TOKENLOCK dashboard. Which tokens unlock your site is set there. */
  siteKey: string;
  /** Where to go after sign-in. Default: the ?next= path, else '/'. */
  redirectTo?: string;
  /** Your pass → cookie endpoint. Default '/api/tokenlock/session' */
  sessionUrl?: string;
  /** Button text. Default 'Sign in with your Token' */
  label?: React.ReactNode;
  /** Title of the sign-in window. */
  title?: string;
  /** How long the sign-in lasts, 60–86400 seconds. Default 3600. */
  passTtlSeconds?: number;
  /** API origin. Default https://tokenlock.ai */
  apiBase?: string;
  className?: string;
  style?: React.CSSProperties;
  disabled?: boolean;
  /** Called after the cookie is set, before redirecting. Return false to stay on the page. */
  onSignedIn?: (r: { address: string; assets_held: string[] }) => void | boolean | Promise<void | boolean>;
  onError?: (e: Error) => void;
}

let loading: Promise<void> | null = null;
/** Load gate.js once. It shows the wallet picker (browser wallets plus a paste-a-signature fallback). */
export function loadGate(apiBase = DEFAULT_API, siteKey?: string): Promise<void> {
  if (typeof window === 'undefined') return Promise.reject(new Error('Browser only'));
  if (window.ProveItGate) return Promise.resolve();
  return (loading ||= new Promise<void>((ok, fail) => {
    const s = document.createElement('script');
    s.src = apiBase.replace(/\/+$/, '') + '/gate.js';
    s.async = true;
    if (siteKey) s.setAttribute('data-site-key', siteKey);
    s.onload = () => (window.ProveItGate ? ok() : fail(new Error('Sign-in script did not load.')));
    s.onerror = () => { loading = null; fail(new Error('Could not load the sign-in script.')); };
    document.head.appendChild(s);
  }));
}

/**
 * <SignInWithBitcoin siteKey="pk_…" redirectTo="/members" />
 * Opens the wallet sign-in, sends the pass to your server (which sets an HttpOnly cookie), then redirects.
 */
export function SignInWithBitcoin(props: SignInWithBitcoinProps) {
  const { siteKey, sessionUrl = '/api/tokenlock/session', apiBase = DEFAULT_API, passTtlSeconds = 3600 } = props;
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);
  React.useEffect(() => { loadGate(apiBase, siteKey).catch(() => {}); }, [apiBase, siteKey]);

  async function go() {
    setErr(null); setBusy(true);
    try {
      await loadGate(apiBase, siteKey);
      const r = await window.ProveItGate!.signIn({ siteKey, passTtlSeconds, title: props.title });
      const res = await fetch(sessionUrl, { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pass: r.pass }) });
      const j = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(j.error || 'Sign-in failed. Try again.');
      const stay = props.onSignedIn ? (await props.onSignedIn({ address: r.address, assets_held: r.assets_held })) === false : false;
      if (!stay) {
        const next = new URLSearchParams(window.location.search).get('next');
        window.location.assign(safeNext(props.redirectTo ?? next, '/'));
      }
    } catch (e: any) {
      if (e && e.message !== 'closed') { setErr(e.message || String(e)); props.onError?.(e); }
    } finally { setBusy(false); }
  }

  return (
    <span className="tokenlock-signin">
      <button type="button" onClick={go} disabled={busy || props.disabled} className={props.className} style={props.style} aria-busy={busy}>
        {busy ? 'Waiting for your wallet…' : (props.label ?? 'Sign in with your Token')}
      </button>
      {err ? <span role="alert" className="tokenlock-error" style={{ display: 'block', color: '#d33', fontSize: 14, marginTop: 6 }}>{err}</span> : null}
    </span>
  );
}

/** Sign-out link that clears the cookie. */
export function SignOutLink({ href = '/api/tokenlock/signout', children = 'Sign out', className }: { href?: string; children?: React.ReactNode; className?: string }) {
  return <a href={href} className={className}>{children}</a>;
}

export const SignInWithToken = SignInWithBitcoin;
