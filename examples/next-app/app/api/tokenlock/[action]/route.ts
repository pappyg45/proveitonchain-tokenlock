import { tokenlockRoutes } from '@tokenlock/sdk/next';

// POST /api/tokenlock/session { pass } sets the HttpOnly cookie. GET /api/tokenlock/signout clears it.
export const { GET, POST } = tokenlockRoutes();
