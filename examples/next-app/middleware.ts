import { tokenlock } from '@proveitonchain/tokenlock/next';

// Everything under /members needs a pass. Which tokens unlock it is set in your TOKENLOCK dashboard.
export default tokenlock({
  protect: ['/members/:path*'],
  signInPage: '/signin',
});

export const config = { matcher: ['/members/:path*'] };
