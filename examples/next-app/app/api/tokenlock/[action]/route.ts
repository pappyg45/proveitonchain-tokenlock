import { tokenlockRoutes } from '@proveitonchain/tokenlock/next';

// POST /api/tokenlock/session { pass } sets the HttpOnly cookie. GET /api/tokenlock/signout clears it.
export const { GET, POST } = tokenlockRoutes();
