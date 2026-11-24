import { getPass } from '@tokenlock/sdk/next';

export const dynamic = 'force-dynamic';

export default async function Members() {
  // Identity check for the signed-in wallet. Since 0.4.3 the request is explicit: { identityOnly: true } here, or a
  // route ({ path, method }) to authorize one; with neither, getPass throws bad_resource. The middleware already locked /members.
  const pass = await getPass(undefined, { identityOnly: true }); // { address, assets_held, … } or null
  return (
    <main style={{ maxWidth: 560, margin: '80px auto', fontFamily: 'system-ui' }}>
      <h1>Welcome in</h1>
      <p>Signed in as <code>{pass?.address}</code>, holding {pass?.assets_held?.join(', ')}.</p>
      <p><a href="/api/tokenlock/signout">Sign out</a></p>
    </main>
  );
}
