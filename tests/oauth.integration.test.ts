import crypto from "node:crypto";
import request from "supertest";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

process.env.PORT = process.env.PORT ?? "3000";
process.env.APP_BASE_URL = process.env.APP_BASE_URL ?? "http://localhost:3000";
process.env.ACCESS_TOKEN_AUDIENCE =
  process.env.ACCESS_TOKEN_AUDIENCE ?? "oauth2-demo-resource";
process.env.SESSION_SECRET =
  process.env.SESSION_SECRET ?? "integration-test-session-secret";
process.env.GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID ?? "test-client-id";
process.env.GITHUB_CLIENT_SECRET =
  process.env.GITHUB_CLIENT_SECRET ?? "test-client-secret";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/oauth2_demo";

describe("OAuth integration", () => {
  let app: import("express").Express;
  let db: { query: (sql: string, values?: unknown[]) => Promise<{ rowCount?: number }> };
  let initDbFn: (appBaseUrl: string) => Promise<void>;

  beforeAll(async () => {
    const serverModule = await import("../src/server");
    const dbModule = await import("../src/db");
    app = serverModule.app;
    db = dbModule.db as unknown as {
      query: (sql: string, values?: unknown[]) => Promise<{ rowCount?: number }>;
    };
    initDbFn = dbModule.initDb;
    await initDbFn(process.env.APP_BASE_URL!);
  });

  beforeEach(async () => {
    await db.query("DELETE FROM access_tokens;");
    await db.query("DELETE FROM refresh_tokens;");
    await db.query("DELETE FROM authorization_codes;");
    await db.query("DELETE FROM auth_events;");
    await db.query("DELETE FROM users;");
  });

  it("serves discovery and jwks endpoints", async () => {
    const discovery = await request(app).get("/.well-known/openid-configuration");
    expect(discovery.status).toBe(200);
    expect(discovery.body.issuer).toBe(process.env.APP_BASE_URL);
    expect(discovery.body.jwks_uri).toContain("/.well-known/jwks.json");

    const jwks = await request(app).get("/.well-known/jwks.json");
    expect(jwks.status).toBe(200);
    expect(Array.isArray(jwks.body.keys)).toBe(true);
    expect(jwks.body.keys[0].alg).toBe("ES256");
  });

  it("issues tokens, rotates refresh token, and detects replay", async () => {
    const userId = crypto.randomUUID();
    const code = "test-auth-code";
    const verifier = "very-long-test-verifier-1234567890";
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");

    await db.query(
      `
        INSERT INTO users (id, github_id, login, name, email, avatar_url)
        VALUES ($1, $2, $3, $4, $5, $6);
      `,
      [userId, 1001, "integration-user", "Integration User", "test@example.com", null],
    );

    await db.query(
      `
        INSERT INTO authorization_codes
        (code, user_id, client_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() + INTERVAL '5 minutes');
      `,
      [
        code,
        userId,
        "demo-client",
        `${process.env.APP_BASE_URL}/client/callback`,
        "read:profile",
        challenge,
        "S256",
      ],
    );

    const tokenResponse = await request(app)
      .post("/oauth/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: `${process.env.APP_BASE_URL}/client/callback`,
        client_id: "demo-client",
        code_verifier: verifier,
      });

    expect(tokenResponse.status).toBe(200);
    expect(typeof tokenResponse.body.access_token).toBe("string");
    expect(tokenResponse.body.access_token.split(".")).toHaveLength(3);
    expect(typeof tokenResponse.body.refresh_token).toBe("string");

    const apiResponse = await request(app)
      .get("/api/resource")
      .set("Authorization", `Bearer ${tokenResponse.body.access_token as string}`);
    expect(apiResponse.status).toBe(200);

    const rotated = await request(app)
      .post("/oauth/token")
      .type("form")
      .send({
        grant_type: "refresh_token",
        refresh_token: tokenResponse.body.refresh_token,
        client_id: "demo-client",
      });
    expect(rotated.status).toBe(200);
    expect(rotated.body.refresh_token).not.toBe(tokenResponse.body.refresh_token);

    const replay = await request(app)
      .post("/oauth/token")
      .type("form")
      .send({
        grant_type: "refresh_token",
        refresh_token: tokenResponse.body.refresh_token,
        client_id: "demo-client",
      });
    expect(replay.status).toBe(401);
    expect(replay.body.error).toBe("refresh_token_reuse_detected");

    const afterFamilyRevoke = await request(app)
      .post("/oauth/token")
      .type("form")
      .send({
        grant_type: "refresh_token",
        refresh_token: rotated.body.refresh_token,
        client_id: "demo-client",
      });
    expect(afterFamilyRevoke.status).toBe(400);
    expect(afterFamilyRevoke.body.error).toBe("invalid_or_expired_refresh_token");
  });
});
