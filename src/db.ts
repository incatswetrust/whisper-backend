import { neon } from '@neondatabase/serverless';

const connectionString = process.env.DATABASE_URL ?? process.env.POSTGRES_URL;
if (!connectionString) {
  throw new Error('DATABASE_URL (or POSTGRES_URL) is not set — connect a Neon database via env vars');
}

export const sql = neon(connectionString);
