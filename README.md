# OAuth2 End-to-End Demo (Node + TypeScript)

This project includes:

- OAuth2 authorization server (`/oauth/authorize`, `/oauth/token`)
- React + Vite security dashboard UI (`/app`, `/client/callback`)
- Protected resource API (`/api/resource`)
- Refresh token grant with token rotation
- Refresh token reuse detection with token-family revocation
- JWT access tokens signed with ES256
- JWKS and OAuth discovery metadata endpoints
- Production middleware (Helmet, compression, rate limiting)
- Health/readiness probes for orchestrators (`/healthz`, `/readyz`)
- GitHub login as external identity provider
- Postgres persistence for users, codes, tokens, and clients

## 1) Prerequisites

- Node.js 20+
- Postgres running locally
- A GitHub OAuth App

## 2) GitHub OAuth App setup

Create an OAuth App in GitHub with:

- Homepage URL: `http://localhost:3000`
- Authorization callback URL: `http://localhost:3000/auth/github/callback`

Copy the generated client ID and client secret.

## 3) Configure environment

```bash
cp .env.example .env
```

Update `.env` values:

- `SESSION_SECRET`: at least 16 chars
- `DATABASE_URL`: local Postgres connection string
- `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`: from GitHub OAuth App
- `APP_BASE_URL`: public base URL for OAuth callbacks
- `ACCESS_TOKEN_AUDIENCE`: resource audience for JWT verification

## 4) Install and run (local Node + built frontend)

```bash
npm install
npm --prefix frontend install
npm run build:frontend
npm run dev
```

Open `http://localhost:3000/app`.

## 5) Frontend development mode (optional)

If you want to iterate on React UI with Vite:

```bash
# terminal 1
npm run dev

# terminal 2
npm run dev:frontend
```

Open `http://localhost:5173/app`.

Before using Vite mode, set `APP_BASE_URL=http://localhost:5173` in `.env` so OAuth
redirects match the frontend origin.

## 6) Run with Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

Open `http://localhost:3000/app`.

Notes:

- Compose starts two services: `app` and `db`.
- In Docker, `DATABASE_URL` is automatically overridden to use host `db`.
- To stop:

```bash
docker compose down
```

- To stop and remove Postgres data volume:

```bash
docker compose down -v
```

## 7) OAuth2 flow in this demo

1. Client page generates PKCE verifier/challenge.
2. Browser redirects to `/oauth/authorize`.
3. If not logged in, user is redirected to GitHub login.
4. After callback, app issues an authorization code.
5. Client exchanges code at `/oauth/token` with PKCE verifier.
6. Client calls `/api/resource` using bearer token.

## Notes

- The seeded OAuth2 client is:
  - `client_id`: `demo-client`
  - `redirect_uri`: `${APP_BASE_URL}/client/callback`
- Tokens expire in 1 hour and auth codes in 5 minutes.
- Discovery endpoints:
  - `/.well-known/openid-configuration`
  - `/.well-known/jwks.json`
- Health endpoints:
  - `/healthz`
  - `/readyz`

## 8) Testing and CI

Run integration tests locally:

```bash
npm test
```

CI is configured in `.github/workflows/ci.yml` and runs:

- backend/frontend install
- typecheck
- integration tests (with Postgres service)
- full build

## 9) Deployment

### Vercel + Neon (recommended)

This repo is configured for Vercel serverless hosting with Neon Postgres:

- `api/index.ts` exports the Express app for Vercel.
- `vercel.json` routes all traffic to the serverless function.
- Frontend assets from `frontend/dist` are included in the function bundle.
- Neon SSL is auto-enabled in production and for Neon connection strings.

Steps:

1. Create a Neon project and copy the pooled connection string.
2. Create a Vercel project and connect this repository.
3. Set these Vercel environment variables:
   - `NODE_ENV=production`
   - `PORT=3000`
   - `APP_BASE_URL=https://<your-vercel-domain>`
   - `DATABASE_URL=<your-neon-connection-string>`
   - `ACCESS_TOKEN_AUDIENCE=oauth2-demo-resource`
   - `SESSION_SECRET=<long-random-secret>`
   - `SESSION_SECURE_COOKIE=true`
   - `TRUST_PROXY=1`
   - `RATE_LIMIT_WINDOW_MS=60000`
   - `RATE_LIMIT_MAX_REQUESTS=120`
   - `GITHUB_CLIENT_ID=<your-github-client-id>`
   - `GITHUB_CLIENT_SECRET=<your-github-client-secret>`
4. In GitHub OAuth App settings, set callback URL to:
   - `https://<your-vercel-domain>/auth/github/callback`
5. Deploy.

Post-deploy checks:

- `GET /healthz`
- `GET /readyz`
- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`

Smoke test helper:

```bash
./scripts/deploy-smoke.sh --base-url https://your-app.vercel.app
```

Optional authenticated resource check:

```bash
./scripts/deploy-smoke.sh --base-url https://your-app.vercel.app --bearer-token "<access-token>"
```

### Docker deployment (alternative)

This repository is also production container ready:

- `Dockerfile` uses a multi-stage build and runs as a non-root user.
- `.dockerignore` keeps image context small.
- Container healthcheck targets `/healthz`.

Build and run manually:

```bash
docker build -t oauth2-demo .
docker run --rm -p 3000:3000 --env-file .env oauth2-demo
```
