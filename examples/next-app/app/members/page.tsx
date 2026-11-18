import { getPass } from '@proveitonchain/tokenlock/next';

export const dynamic = 'force-dynamic';

export default async function Members() {
  const pass = await getPass(); // { address, assets_held, … } or null
  return (
    <main style={{ maxWidth: 560, margin: '80px auto', fontFamily: 'system-ui' }}>
      <h1>Welcome in</h1>
      <p>Signed in as <code>{pass?.address}</code>, holding {pass?.assets_held?.join(', ')}.</p>
      <p><a href="/api/tokenlock/signout">Sign out</a></p>
    </main>
  );
}
