import { Pool } from "pg";

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error("Missing DATABASE_URL in environment.");
}

const isProduction = process.env.NODE_ENV === "production";
const isNeonConnection = connectionString.includes("neon.tech");

function normalizeConnectionStringForSsl(input: string): string {
  const replacedByRegex = input.replace(
    /([?&])sslmode=(require|prefer|verify-ca)(?=(&|$))/gi,
    "$1sslmode=verify-full",
  );

  try {
    const url = new URL(replacedByRegex);
    const sslMode = url.searchParams.get("sslmode");
    if (sslMode && sslMode !== "verify-full") {
      url.searchParams.set("sslmode", "verify-full");
    }
    return url.toString();
  } catch {
    return replacedByRegex;
  }
}

const normalizedConnectionString = normalizeConnectionStringForSsl(connectionString);

export const db = new Pool({
  connectionString: normalizedConnectionString,
  ssl: isProduction || isNeonConnection ? { rejectUnauthorized: true } : undefined,
});

export async function initDb(appBaseUrl: string): Promise<void> {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      github_id BIGINT UNIQUE NOT NULL,
      login TEXT NOT NULL,
      name TEXT,
      email TEXT,
      avatar_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await db.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS avatar_url TEXT;
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS oauth_clients (
      client_id TEXT PRIMARY KEY,
      client_secret TEXT,
      redirect_uri TEXT NOT NULL,
      is_confidential BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS authorization_codes (
      code TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
      redirect_uri TEXT NOT NULL,
      scope TEXT NOT NULL,
      code_challenge TEXT,
      code_challenge_method TEXT,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS access_tokens (
      token TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
      scope TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      token TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
      scope TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      revoked_at TIMESTAMPTZ,
      replaced_by_token TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS auth_events (
      id BIGSERIAL PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      event_type TEXT NOT NULL,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await db.query(
    `
      INSERT INTO oauth_clients (client_id, client_secret, redirect_uri, is_confidential)
      VALUES ($1, NULL, $2, FALSE)
      ON CONFLICT (client_id) DO UPDATE
      SET redirect_uri = EXCLUDED.redirect_uri;
    `,
    ["demo-client", `${appBaseUrl}/client/callback`],
  );
}
