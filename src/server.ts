import crypto from "node:crypto";
import fs from "node:fs";
import type { Server } from "node:http";
import path from "node:path";
import compression from "compression";
import dotenv from "dotenv";
import express from "express";
import rateLimit from "express-rate-limit";
import session from "express-session";
import helmet from "helmet";
import { z } from "zod";
import { db, initDb } from "./db";

dotenv.config();

const envSchema = z.object({
  PORT: z.string().default("3000"),
  APP_BASE_URL: z.string().url(),
  ACCESS_TOKEN_AUDIENCE: z.string().default("oauth2-demo-resource"),
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  TRUST_PROXY: z.coerce.number().int().min(0).default(1),
  SESSION_SECURE_COOKIE: z
    .string()
    .optional()
    .transform((value) => (value ? value === "true" : undefined)),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60_000),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().int().positive().default(60),
  SESSION_SECRET: z.string().min(16),
  GITHUB_CLIENT_ID: z.string().min(1),
  GITHUB_CLIENT_SECRET: z.string().min(1),
});

const inferredAppBaseUrl =
  process.env.APP_BASE_URL ??
  (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : undefined);

const env = envSchema.parse({
  ...process.env,
  APP_BASE_URL: inferredAppBaseUrl,
});
const isProduction = env.NODE_ENV === "production";
const sessionSecureCookie = env.SESSION_SECURE_COOKIE ?? isProduction;

declare module "express-session" {
  interface SessionData {
    userId?: string;
    githubOAuthState?: string;
    githubRedirectUri?: string;
    pendingAuthQuery?: string;
    latestAccessToken?: string;
    latestAccessTokenExpiresAt?: string;
    latestRefreshToken?: string;
    latestRefreshTokenExpiresAt?: string;
  }
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", env.TRUST_PROXY);
let signingPrivateKey: CryptoKey | undefined;
let signingPublicKey: CryptoKey | undefined;
let signingPublicJwk:
  | ({
      kty: string;
      crv?: string;
      x?: string;
      y?: string;
      e?: string;
      n?: string;
    } & { kid: string; alg: "ES256"; use: "sig" })
  | undefined;

async function ensureSigningKeys(): Promise<void> {
  if (signingPrivateKey && signingPublicKey && signingPublicJwk) {
    return;
  }

  const { generateKeyPair, exportJWK } = await import("jose");
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const publicJwk = (await exportJWK(publicKey)) as {
    kty: string;
    crv?: string;
    x?: string;
    y?: string;
    e?: string;
    n?: string;
  };
  signingPrivateKey = privateKey;
  signingPublicKey = publicKey;
  signingPublicJwk = {
    ...publicJwk,
    kid: crypto.randomUUID(),
    alg: "ES256",
    use: "sig",
  };
}

const oauthRateLimit = rateLimit({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  max: env.RATE_LIMIT_MAX_REQUESTS,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));
app.use(
  session({
    secret: env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: sessionSecureCookie,
      maxAge: 1000 * 60 * 60 * 12,
    },
  }),
);

const authorizeQuerySchema = z.object({
  response_type: z.literal("code"),
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  scope: z.string().default("read:profile"),
  state: z.string().optional(),
  code_challenge: z.string().min(10),
  code_challenge_method: z.enum(["plain", "S256"]).default("S256"),
});

const authorizationCodeTokenSchema = z.object({
  grant_type: z.literal("authorization_code"),
  code: z.string().min(1),
  redirect_uri: z.string().url(),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
  code_verifier: z.string().min(10),
});

const refreshTokenGrantSchema = z.object({
  grant_type: z.literal("refresh_token"),
  refresh_token: z.string().min(1),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
});

const tokenBodySchema = z.discriminatedUnion("grant_type", [
  authorizationCodeTokenSchema,
  refreshTokenGrantSchema,
]);

function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

function sha256Base64Url(value: string): string {
  return crypto.createHash("sha256").update(value).digest("base64url");
}

async function upsertGithubUser(input: {
  githubId: number;
  login: string;
  name: string | null;
  email: string | null;
  avatarUrl: string | null;
}): Promise<string> {
  const userId = crypto.randomUUID();
  const { rows } = await db.query<{ id: string }>(
    `
      INSERT INTO users (id, github_id, login, name, email, avatar_url)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (github_id) DO UPDATE
      SET login = EXCLUDED.login,
          name = EXCLUDED.name,
          email = COALESCE(EXCLUDED.email, users.email),
          avatar_url = COALESCE(EXCLUDED.avatar_url, users.avatar_url)
      RETURNING id;
    `,
    [userId, input.githubId, input.login, input.name, input.email, input.avatarUrl],
  );

  return rows[0].id;
}

async function exchangeGithubCodeForToken(code: string): Promise<string> {
  const redirectUri = `${env.APP_BASE_URL}/auth/github/callback`;
  return exchangeGithubCodeForTokenWithRedirect(code, redirectUri);
}

async function exchangeGithubCodeForTokenWithRedirect(
  code: string,
  redirectUri: string,
): Promise<string> {
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: redirectUri,
    }),
  });

  if (!response.ok) {
    throw new Error(`GitHub token exchange failed with status ${response.status}`);
  }

  const data = (await response.json()) as { access_token?: string };
  if (!data.access_token) {
    throw new Error("GitHub token exchange returned no access token.");
  }

  return data.access_token;
}

function getRequestBaseUrl(req: express.Request): string {
  const forwardedProto = req.get("x-forwarded-proto")?.split(",")[0]?.trim();
  const forwardedHost = req.get("x-forwarded-host")?.split(",")[0]?.trim();
  const proto = forwardedProto || req.protocol;
  const host = forwardedHost || req.get("host");

  if (!host) {
    return env.APP_BASE_URL;
  }

  return `${proto}://${host}`;
}

async function fetchGithubIdentity(accessToken: string): Promise<{
  id: number;
  login: string;
  name: string | null;
  email: string | null;
  avatarUrl: string | null;
}> {
  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "oauth2-demo-app",
    },
  });

  if (!userResponse.ok) {
    throw new Error(`GitHub user request failed with status ${userResponse.status}`);
  }

  const userData = (await userResponse.json()) as {
    id: number;
    login: string;
    name: string | null;
    email: string | null;
    avatar_url?: string | null;
  };

  let email = userData.email;
  if (!email) {
    const emailsResponse = await fetch("https://api.github.com/user/emails", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "oauth2-demo-app",
      },
    });

    if (emailsResponse.ok) {
      const emails = (await emailsResponse.json()) as Array<{
        email: string;
        primary: boolean;
        verified: boolean;
      }>;
      email = emails.find((item) => item.primary && item.verified)?.email ?? null;
    }
  }

  return {
    id: userData.id,
    login: userData.login,
    name: userData.name,
    email,
    avatarUrl: userData.avatar_url ?? null,
  };
}

async function logAuthEvent(
  userId: string | null,
  eventType: string,
  details: Record<string, unknown> = {},
): Promise<void> {
  await db.query(
    `
      INSERT INTO auth_events (user_id, event_type, details)
      VALUES ($1, $2, $3::jsonb);
    `,
    [userId, eventType, JSON.stringify(details)],
  );
}

async function issueAuthorizationCode(params: {
  userId: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string;
  codeChallengeMethod: "plain" | "S256";
}): Promise<string> {
  const code = randomToken(32);
  const expiresAt = new Date(Date.now() + 1000 * 60 * 5);
  await db.query(
    `
      INSERT INTO authorization_codes
      (code, user_id, client_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
    `,
    [
      code,
      params.userId,
      params.clientId,
      params.redirectUri,
      params.scope,
      params.codeChallenge,
      params.codeChallengeMethod,
      expiresAt.toISOString(),
    ],
  );
  return code;
}

async function issueTokenPair(params: {
  userId: string;
  clientId: string;
  scope: string;
}): Promise<{
  accessToken: string;
  accessExpiresAt: Date;
  accessExpiresInSeconds: number;
  refreshToken: string;
  refreshExpiresAt: Date;
  refreshExpiresInSeconds: number;
}> {
  const accessExpiresInSeconds = 3600;
  const accessExpiresAt = new Date(Date.now() + accessExpiresInSeconds * 1000);
  await ensureSigningKeys();
  const { SignJWT } = await import("jose");
  const accessToken = await new SignJWT({
    scope: params.scope,
    client_id: params.clientId,
  })
    .setProtectedHeader({
      alg: "ES256",
      kid: signingPublicJwk!.kid,
      typ: "at+jwt",
    })
    .setIssuer(env.APP_BASE_URL)
    .setAudience(env.ACCESS_TOKEN_AUDIENCE)
    .setSubject(params.userId)
    .setJti(randomToken(12))
    .setIssuedAt()
    .setExpirationTime(`${accessExpiresInSeconds}s`)
    .sign(signingPrivateKey!);

  const refreshToken = randomToken(48);
  const refreshExpiresInSeconds = 60 * 60 * 24 * 7;
  const refreshExpiresAt = new Date(Date.now() + refreshExpiresInSeconds * 1000);

  await db.query(
    `
      INSERT INTO access_tokens (token, user_id, client_id, scope, expires_at)
      VALUES ($1, $2, $3, $4, $5);
    `,
    [
      accessToken,
      params.userId,
      params.clientId,
      params.scope,
      accessExpiresAt.toISOString(),
    ],
  );

  await db.query(
    `
      INSERT INTO refresh_tokens (token, user_id, client_id, scope, expires_at)
      VALUES ($1, $2, $3, $4, $5);
    `,
    [
      refreshToken,
      params.userId,
      params.clientId,
      params.scope,
      refreshExpiresAt.toISOString(),
    ],
  );

  return {
    accessToken,
    accessExpiresAt,
    accessExpiresInSeconds,
    refreshToken,
    refreshExpiresAt,
    refreshExpiresInSeconds,
  };
}

async function revokeTokenFamily(params: {
  userId: string;
  clientId: string;
  reason: string;
  triggerToken: string;
}): Promise<{ revokedRefresh: number; revokedAccess: number }> {
  const refreshResult = await db.query(
    `
      UPDATE refresh_tokens
      SET revoked_at = NOW()
      WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL;
    `,
    [params.userId, params.clientId],
  );

  const accessResult = await db.query(
    `
      DELETE FROM access_tokens
      WHERE user_id = $1 AND client_id = $2;
    `,
    [params.userId, params.clientId],
  );

  await logAuthEvent(params.userId, "refresh_token_reuse_detected", {
    reason: params.reason,
    triggerTokenPreview: `${params.triggerToken.slice(0, 8)}...${params.triggerToken.slice(-6)}`,
    revokedRefreshTokens: refreshResult.rowCount ?? 0,
    revokedAccessTokens: accessResult.rowCount ?? 0,
  });

  return {
    revokedRefresh: refreshResult.rowCount ?? 0,
    revokedAccess: accessResult.rowCount ?? 0,
  };
}

const frontendDistDir = path.join(__dirname, "..", "frontend", "dist");
const frontendEntryFile = path.join(frontendDistDir, "index.html");
app.use(express.static(frontendDistDir, { index: false }));

function serveFrontend(res: express.Response): void {
  if (!fs.existsSync(frontendEntryFile)) {
    res.status(503).type("text/plain").send(
      "Frontend build not found. Run `npm run build:frontend` (or `npm run build`) and retry.",
    );
    return;
  }
  res.sendFile(frontendEntryFile);
}

app.get("/", (_req, res) => {
  res.redirect("/app");
});

app.get("/app", (_req, res) => {
  serveFrontend(res);
});

app.get("/healthz", (_req, res) => {
  res.json({ ok: true, uptimeSeconds: Math.floor(process.uptime()) });
});

app.get("/readyz", async (_req, res) => {
  try {
    await ensureSigningKeys();
    await db.query("SELECT 1;");
    res.json({ ready: true });
  } catch (error) {
    res.status(503).json({
      ready: false,
      error: error instanceof Error ? error.message : "unknown",
    });
  }
});

app.get("/dashboard/data", async (req, res) => {
  const sessionIssuedAt = req.session.cookie?.originalMaxAge
    ? new Date(Date.now() - (1000 * 60 * 60 * 12 - req.session.cookie.maxAge!)).toISOString()
    : new Date().toISOString();

  if (!req.session.userId) {
    res.json({
      signedIn: false,
      appBaseUrl: env.APP_BASE_URL,
      sessionIssuedAt,
      latestToken: null,
      latestRefreshToken: null,
      events: [],
    });
    return;
  }

  const { rows: users } = await db.query<{
    login: string;
    email: string | null;
    avatar_url: string | null;
  }>("SELECT login, email, avatar_url FROM users WHERE id = $1;", [req.session.userId]);

  const { rows: tokens } = await db.query<{
    token: string;
    scope: string;
    expires_at: Date;
  }>(
    `
      SELECT token, scope, expires_at
      FROM access_tokens
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 1;
    `,
    [req.session.userId],
  );

  const { rows: refreshTokens } = await db.query<{
    token: string;
    scope: string;
    expires_at: Date;
  }>(
    `
      SELECT token, scope, expires_at
      FROM refresh_tokens
      WHERE user_id = $1 AND revoked_at IS NULL
      ORDER BY created_at DESC
      LIMIT 1;
    `,
    [req.session.userId],
  );

  const { rows: events } = await db.query<{
    event_type: string;
    details: Record<string, unknown>;
    created_at: Date;
  }>(
    `
      SELECT event_type, details, created_at
      FROM auth_events
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 20;
    `,
    [req.session.userId],
  );

  const latest = tokens[0];
  const latestRefresh = refreshTokens[0];
  req.session.latestAccessToken = latest?.token;
  req.session.latestAccessTokenExpiresAt = latest?.expires_at.toISOString();
  req.session.latestRefreshToken = latestRefresh?.token;
  req.session.latestRefreshTokenExpiresAt = latestRefresh?.expires_at.toISOString();

  res.json({
    signedIn: true,
    appBaseUrl: env.APP_BASE_URL,
    sessionIssuedAt,
    user: {
      login: users[0]?.login ?? "unknown",
      email: users[0]?.email ?? null,
      avatarUrl: users[0]?.avatar_url ?? null,
    },
    latestToken: latest
      ? {
          value: latest.token,
          preview: `${latest.token.slice(0, 8)}...${latest.token.slice(-6)}`,
          scope: latest.scope,
          expiresAt: latest.expires_at.toISOString(),
        }
      : null,
    latestRefreshToken: latestRefresh
      ? {
          value: latestRefresh.token,
          preview: `${latestRefresh.token.slice(0, 8)}...${latestRefresh.token.slice(-6)}`,
          scope: latestRefresh.scope,
          expiresAt: latestRefresh.expires_at.toISOString(),
        }
      : null,
    events: events.map((event) => ({
      type: event.event_type,
      details: event.details,
      createdAt: event.created_at.toISOString(),
    })),
  });
});

app.get("/client/callback", (_req, res) => {
  serveFrontend(res);
});

app.get("/.well-known/jwks.json", async (_req, res) => {
  await ensureSigningKeys();
  res.json({
    keys: [signingPublicJwk],
  });
});

app.get("/.well-known/openid-configuration", (_req, res) => {
  res.json({
    issuer: env.APP_BASE_URL,
    authorization_endpoint: `${env.APP_BASE_URL}/oauth/authorize`,
    token_endpoint: `${env.APP_BASE_URL}/oauth/token`,
    jwks_uri: `${env.APP_BASE_URL}/.well-known/jwks.json`,
    revocation_endpoint: `${env.APP_BASE_URL}/oauth/revoke-latest`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    code_challenge_methods_supported: ["S256", "plain"],
    scopes_supported: ["read:profile"],
  });
});

app.get("/login/github", oauthRateLimit, (req, res) => {
  const state = randomToken(24);
  req.session.githubOAuthState = state;
  const redirectUri = `${getRequestBaseUrl(req)}/auth/github/callback`;
  req.session.githubRedirectUri = redirectUri;
  void logAuthEvent(req.session.userId ?? null, "github_login_started", {
    hasSessionUser: Boolean(req.session.userId),
    redirectUri,
  });

  const params = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: "read:user user:email",
    state,
  });
  res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
});

app.get("/auth/github/callback", async (req, res) => {
  try {
    const code = z.string().min(1).parse(req.query.code);
    const state = z.string().min(1).parse(req.query.state);

    if (!req.session.githubOAuthState || req.session.githubOAuthState !== state) {
      res.status(400).json({ error: "invalid_state" });
      return;
    }

    const redirectUri = req.session.githubRedirectUri ?? `${env.APP_BASE_URL}/auth/github/callback`;
    const githubAccessToken = await exchangeGithubCodeForTokenWithRedirect(code, redirectUri);
    const githubIdentity = await fetchGithubIdentity(githubAccessToken);
    const userId = await upsertGithubUser({
      githubId: githubIdentity.id,
      login: githubIdentity.login,
      name: githubIdentity.name,
      email: githubIdentity.email,
      avatarUrl: githubIdentity.avatarUrl,
    });

    req.session.userId = userId;
    req.session.githubOAuthState = undefined;
    req.session.githubRedirectUri = undefined;
    await logAuthEvent(userId, "github_login_completed", {
      githubLogin: githubIdentity.login,
    });

    const pending = req.session.pendingAuthQuery;
    req.session.pendingAuthQuery = undefined;
    if (pending) {
      res.redirect(pending);
      return;
    }

    res.redirect("/app");
  } catch (error) {
    await logAuthEvent(req.session.userId ?? null, "github_login_failed", {
      message: error instanceof Error ? error.message : "Unknown error",
    });
    res.status(400).json({
      error: "github_callback_failed",
      message: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.get("/oauth/authorize", oauthRateLimit, async (req, res) => {
  try {
    const authRequest = authorizeQuerySchema.parse(req.query);
    const { rows: clients } = await db.query<{
      client_id: string;
      redirect_uri: string;
    }>(
      "SELECT client_id, redirect_uri FROM oauth_clients WHERE client_id = $1;",
      [authRequest.client_id],
    );

    const client = clients[0];
    if (!client || client.redirect_uri !== authRequest.redirect_uri) {
      res.status(400).json({ error: "invalid_client_or_redirect_uri" });
      return;
    }

    if (!req.session.userId) {
      req.session.pendingAuthQuery = req.originalUrl;
      res.redirect("/login/github");
      return;
    }

    const code = await issueAuthorizationCode({
      userId: req.session.userId,
      clientId: authRequest.client_id,
      redirectUri: authRequest.redirect_uri,
      scope: authRequest.scope,
      codeChallenge: authRequest.code_challenge,
      codeChallengeMethod: authRequest.code_challenge_method,
    });
    await logAuthEvent(req.session.userId, "authorization_code_issued", {
      clientId: authRequest.client_id,
      scope: authRequest.scope,
    });

    const redirect = new URL(authRequest.redirect_uri);
    redirect.searchParams.set("code", code);
    if (authRequest.state) {
      redirect.searchParams.set("state", authRequest.state);
    }
    res.redirect(redirect.toString());
  } catch (error) {
    res.status(400).json({
      error: "invalid_authorization_request",
      message: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.post("/oauth/token", oauthRateLimit, async (req, res) => {
  try {
    const tokenRequest = tokenBodySchema.parse(req.body);
    const { rows: clients } = await db.query<{
      client_id: string;
      client_secret: string | null;
      is_confidential: boolean;
      redirect_uri: string;
    }>(
      `
        SELECT client_id, client_secret, is_confidential, redirect_uri
        FROM oauth_clients
        WHERE client_id = $1;
      `,
      [tokenRequest.client_id],
    );

    const client = clients[0];
    if (!client) {
      res.status(400).json({ error: "invalid_client" });
      return;
    }

    if (client.is_confidential && client.client_secret !== tokenRequest.client_secret) {
      res.status(401).json({ error: "invalid_client_secret" });
      return;
    }

    if (tokenRequest.grant_type === "authorization_code") {
      if (client.redirect_uri !== tokenRequest.redirect_uri) {
        res.status(400).json({ error: "invalid_client" });
        return;
      }

      const { rows: codes } = await db.query<{
        code: string;
        user_id: string;
        client_id: string;
        redirect_uri: string;
        scope: string;
        code_challenge: string | null;
        code_challenge_method: "plain" | "S256" | null;
        expires_at: Date;
        used_at: Date | null;
      }>(
        `
          SELECT code, user_id, client_id, redirect_uri, scope,
                 code_challenge, code_challenge_method, expires_at, used_at
          FROM authorization_codes
          WHERE code = $1;
        `,
        [tokenRequest.code],
      );

      const authCode = codes[0];
      if (!authCode) {
        res.status(400).json({ error: "invalid_grant" });
        return;
      }

      if (authCode.used_at || authCode.expires_at.getTime() < Date.now()) {
        res.status(400).json({ error: "invalid_or_expired_code" });
        return;
      }

      if (
        authCode.client_id !== tokenRequest.client_id ||
        authCode.redirect_uri !== tokenRequest.redirect_uri
      ) {
        res.status(400).json({ error: "grant_client_mismatch" });
        return;
      }

      if (!authCode.code_challenge || !authCode.code_challenge_method) {
        res.status(400).json({ error: "missing_pkce_challenge" });
        return;
      }

      const expectedChallenge =
        authCode.code_challenge_method === "S256"
          ? sha256Base64Url(tokenRequest.code_verifier)
          : tokenRequest.code_verifier;

      if (expectedChallenge !== authCode.code_challenge) {
        res.status(400).json({ error: "invalid_code_verifier" });
        return;
      }

      const { rowCount } = await db.query(
        `
          UPDATE authorization_codes
          SET used_at = NOW()
          WHERE code = $1 AND used_at IS NULL;
        `,
        [authCode.code],
      );

      if (!rowCount) {
        res.status(400).json({ error: "authorization_code_already_used" });
        return;
      }

      const issued = await issueTokenPair({
        userId: authCode.user_id,
        clientId: tokenRequest.client_id,
        scope: authCode.scope,
      });

      await logAuthEvent(authCode.user_id, "access_token_issued", {
        clientId: tokenRequest.client_id,
        scope: authCode.scope,
        expiresInSeconds: issued.accessExpiresInSeconds,
        source: "authorization_code",
      });
      await logAuthEvent(authCode.user_id, "refresh_token_issued", {
        clientId: tokenRequest.client_id,
        scope: authCode.scope,
        expiresInSeconds: issued.refreshExpiresInSeconds,
        source: "authorization_code",
      });

      if (req.session.userId === authCode.user_id) {
        req.session.latestAccessToken = issued.accessToken;
        req.session.latestAccessTokenExpiresAt = issued.accessExpiresAt.toISOString();
        req.session.latestRefreshToken = issued.refreshToken;
        req.session.latestRefreshTokenExpiresAt = issued.refreshExpiresAt.toISOString();
      }

      res.json({
        access_token: issued.accessToken,
        token_type: "Bearer",
        expires_in: issued.accessExpiresInSeconds,
        scope: authCode.scope,
        refresh_token: issued.refreshToken,
        refresh_token_expires_in: issued.refreshExpiresInSeconds,
      });
      return;
    }

    const { rows: refreshRows } = await db.query<{
      token: string;
      user_id: string;
      client_id: string;
      scope: string;
      expires_at: Date;
      used_at: Date | null;
      revoked_at: Date | null;
    }>(
      `
        SELECT token, user_id, client_id, scope, expires_at, used_at, revoked_at
        FROM refresh_tokens
        WHERE token = $1;
      `,
      [tokenRequest.refresh_token],
    );

    const refreshRecord = refreshRows[0];
    if (!refreshRecord) {
      res.status(400).json({ error: "invalid_grant" });
      return;
    }

    if (refreshRecord.client_id !== tokenRequest.client_id) {
      res.status(400).json({ error: "grant_client_mismatch" });
      return;
    }

    if (refreshRecord.used_at) {
      const family = await revokeTokenFamily({
        userId: refreshRecord.user_id,
        clientId: refreshRecord.client_id,
        reason: "used_refresh_token_replayed",
        triggerToken: refreshRecord.token,
      });

      if (req.session.userId === refreshRecord.user_id) {
        req.session.latestAccessToken = undefined;
        req.session.latestAccessTokenExpiresAt = undefined;
        req.session.latestRefreshToken = undefined;
        req.session.latestRefreshTokenExpiresAt = undefined;
      }

      res.status(401).json({
        error: "refresh_token_reuse_detected",
        message: "Refresh token replay detected; token family revoked.",
        revoked_access_tokens: family.revokedAccess,
        revoked_refresh_tokens: family.revokedRefresh,
      });
      return;
    }

    if (refreshRecord.revoked_at || refreshRecord.expires_at.getTime() < Date.now()) {
      res.status(400).json({ error: "invalid_or_expired_refresh_token" });
      return;
    }

    const rotationUpdate = await db.query(
      `
        UPDATE refresh_tokens
        SET used_at = NOW()
        WHERE token = $1 AND used_at IS NULL AND revoked_at IS NULL;
      `,
      [refreshRecord.token],
    );

    if (!rotationUpdate.rowCount) {
      const family = await revokeTokenFamily({
        userId: refreshRecord.user_id,
        clientId: refreshRecord.client_id,
        reason: "rotation_race_refresh_replayed",
        triggerToken: refreshRecord.token,
      });
      if (req.session.userId === refreshRecord.user_id) {
        req.session.latestAccessToken = undefined;
        req.session.latestAccessTokenExpiresAt = undefined;
        req.session.latestRefreshToken = undefined;
        req.session.latestRefreshTokenExpiresAt = undefined;
      }
      res.status(401).json({
        error: "refresh_token_reuse_detected",
        message: "Refresh token replay detected during rotation; token family revoked.",
        revoked_access_tokens: family.revokedAccess,
        revoked_refresh_tokens: family.revokedRefresh,
      });
      return;
    }

    const issued = await issueTokenPair({
      userId: refreshRecord.user_id,
      clientId: refreshRecord.client_id,
      scope: refreshRecord.scope,
    });

    await db.query(
      `
        UPDATE refresh_tokens
        SET replaced_by_token = $2
        WHERE token = $1;
      `,
      [refreshRecord.token, issued.refreshToken],
    );

    await logAuthEvent(refreshRecord.user_id, "refresh_token_rotated", {
      clientId: refreshRecord.client_id,
      scope: refreshRecord.scope,
      accessExpiresInSeconds: issued.accessExpiresInSeconds,
      refreshExpiresInSeconds: issued.refreshExpiresInSeconds,
    });

    if (req.session.userId === refreshRecord.user_id) {
      req.session.latestAccessToken = issued.accessToken;
      req.session.latestAccessTokenExpiresAt = issued.accessExpiresAt.toISOString();
      req.session.latestRefreshToken = issued.refreshToken;
      req.session.latestRefreshTokenExpiresAt = issued.refreshExpiresAt.toISOString();
    }

    res.json({
      access_token: issued.accessToken,
      token_type: "Bearer",
      expires_in: issued.accessExpiresInSeconds,
      scope: refreshRecord.scope,
      refresh_token: issued.refreshToken,
      refresh_token_expires_in: issued.refreshExpiresInSeconds,
    });
  } catch (error) {
    res.status(400).json({
      error: "invalid_token_request",
      message: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("Unhandled request error:", error);
  if (res.headersSent) {
    return;
  }
  res.status(500).json({
    error: "internal_server_error",
    message: isProduction ? "Unexpected server error." : error instanceof Error ? error.message : "Unknown error",
  });
});

app.get("/api/resource", async (req, res) => {
  const authorization = req.get("authorization");
  if (!authorization?.startsWith("Bearer ")) {
    await logAuthEvent(req.session.userId ?? null, "resource_access_denied", {
      reason: "missing_bearer_token",
    });
    res.status(401).json({ error: "missing_bearer_token" });
    return;
  }

  const token = authorization.slice("Bearer ".length);
  try {
    await ensureSigningKeys();
    const { jwtVerify } = await import("jose");
    await jwtVerify(token, signingPublicKey!, {
      issuer: env.APP_BASE_URL,
      audience: env.ACCESS_TOKEN_AUDIENCE,
    });
  } catch {
    await logAuthEvent(req.session.userId ?? null, "resource_access_denied", {
      reason: "invalid_jwt_signature_or_claims",
    });
    res.status(401).json({ error: "invalid_or_expired_token" });
    return;
  }

  const { rows } = await db.query<{
    token: string;
    scope: string;
    expires_at: Date;
    login: string;
    email: string | null;
  }>(
    `
      SELECT at.token, at.scope, at.expires_at, u.login, u.email
      FROM access_tokens at
      JOIN users u ON u.id = at.user_id
      WHERE at.token = $1;
    `,
    [token],
  );

  const record = rows[0];
  if (!record || record.expires_at.getTime() < Date.now()) {
    await logAuthEvent(req.session.userId ?? null, "resource_access_denied", {
      reason: "invalid_or_expired_token",
    });
    res.status(401).json({ error: "invalid_or_expired_token" });
    return;
  }

  await logAuthEvent(req.session.userId ?? null, "resource_access_granted", {
    scope: record.scope,
    login: record.login,
  });

  res.json({
    message: "Protected resource granted.",
    user: {
      login: record.login,
      email: record.email,
    },
    scope: record.scope,
  });
});

app.post("/oauth/revoke-latest", async (req, res) => {
  if (!req.session.userId) {
    res.status(401).json({ error: "not_signed_in" });
    return;
  }

  const accessToken = req.session.latestAccessToken;
  const refreshToken = req.session.latestRefreshToken;
  if (!accessToken && !refreshToken) {
    res.status(400).json({ error: "no_token_to_revoke" });
    return;
  }

  const accessResult = accessToken
    ? await db.query("DELETE FROM access_tokens WHERE token = $1 AND user_id = $2;", [
        accessToken,
        req.session.userId,
      ])
    : { rowCount: 0 };

  const refreshResult = refreshToken
    ? await db.query(
        `
          UPDATE refresh_tokens
          SET revoked_at = NOW()
          WHERE token = $1 AND user_id = $2 AND revoked_at IS NULL;
        `,
        [refreshToken, req.session.userId],
      )
    : { rowCount: 0 };

  req.session.latestAccessToken = undefined;
  req.session.latestAccessTokenExpiresAt = undefined;
  req.session.latestRefreshToken = undefined;
  req.session.latestRefreshTokenExpiresAt = undefined;
  await logAuthEvent(req.session.userId, "token_revoked", {
    accessRevoked: accessResult.rowCount ?? 0,
    refreshRevoked: refreshResult.rowCount ?? 0,
  });

  res.json({
    revoked: Boolean((accessResult.rowCount ?? 0) + (refreshResult.rowCount ?? 0)),
    accessRevoked: accessResult.rowCount ?? 0,
    refreshRevoked: refreshResult.rowCount ?? 0,
  });
});

app.get("/logout", (req, res) => {
  const userId = req.session.userId ?? null;
  req.session.destroy(() => {
    void logAuthEvent(userId, "session_logout", {});
    res.redirect("/app");
  });
});

async function start(): Promise<void> {
  await ensureSigningKeys();
  const maxAttempts = 20;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await initDb(env.APP_BASE_URL);
      break;
    } catch (error) {
      if (attempt === maxAttempts) {
        throw error;
      }
      console.warn(
        `Database not ready (attempt ${attempt}/${maxAttempts}), retrying in 2s...`,
      );
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
  const port = Number(env.PORT);
  const server: Server = app.listen(port, () => {
    console.log(`OAuth2 demo running on ${env.APP_BASE_URL}`);
  });

  const shutdown = async (signal: string): Promise<void> => {
    console.log(`Received ${signal}, shutting down...`);
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
    await db.end();
    process.exit(0);
  };

  process.on("SIGINT", () => {
    void shutdown("SIGINT");
  });
  process.on("SIGTERM", () => {
    void shutdown("SIGTERM");
  });
}

if (require.main === module) {
  start().catch((error) => {
    console.error("Failed to start app:", error);
    process.exit(1);
  });
}

export { app, start };
