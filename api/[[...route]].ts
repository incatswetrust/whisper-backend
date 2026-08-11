import { handle } from 'hono/vercel';
import { app } from '../src/app.js';

// Node.js runtime, not Edge: password hashing uses node:crypto's scryptSync,
// which Edge's Web Crypto subset doesn't provide.
export const config = { runtime: 'nodejs' };

export default handle(app);
