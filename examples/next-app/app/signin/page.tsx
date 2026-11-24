import { SignInWithBitcoin } from '@tokenlock/sdk/react';

export default function SignIn() {
  return (
    <main style={{ maxWidth: 480, margin: '80px auto', fontFamily: 'system-ui', textAlign: 'center' }}>
      <h1>Members only</h1>
      <p>Sign in with the wallet that holds our token.</p>
      <SignInWithBitcoin siteKey={process.env.NEXT_PUBLIC_TOKENLOCK_SITE_KEY!} redirectTo="/members" />
    </main>
  );
}
