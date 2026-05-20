import { useEffect, useMemo, useState } from 'react'

type DashboardEvent = {
  type: string
  details: Record<string, unknown>
  createdAt: string
}

type DashboardData = {
  signedIn: boolean
  appBaseUrl: string
  sessionIssuedAt: string
  user?: {
    login: string
    email: string | null
    avatarUrl: string | null
  }
  latestToken: {
    value: string
    preview: string
    scope: string
    expiresAt: string
  } | null
  latestRefreshToken: {
    value: string
    preview: string
    scope: string
    expiresAt: string
  } | null
  events: DashboardEvent[]
}

function App() {
  const [dashboard, setDashboard] = useState<DashboardData | null>(null)
  const [apiOutput, setApiOutput] = useState('No API call yet.')
  const [busy, setBusy] = useState(false)
  const [mode, setMode] = useState<'dashboard' | 'callback'>(
    window.location.pathname === '/client/callback' ? 'callback' : 'dashboard',
  )

  const latestToken = useMemo(() => dashboard?.latestToken?.value ?? null, [dashboard])
  const latestRefreshToken = useMemo(
    () => dashboard?.latestRefreshToken?.value ?? null,
    [dashboard],
  )

  async function refreshDashboard() {
    const response = await fetch('/dashboard/data', {
      cache: 'no-store',
      credentials: 'include',
    })
    if (!response.ok) {
      throw new Error(`Failed to load dashboard data (${response.status})`)
    }
    const data = (await response.json()) as DashboardData
    setDashboard(data)
    return data
  }

  async function createPkce() {
    const random = crypto.getRandomValues(new Uint8Array(64))
    const verifier = base64Url(random.buffer)
    const hash = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(verifier),
    )
    const challenge = base64Url(hash)
    return { verifier, challenge }
  }

  function base64Url(buffer: ArrayBuffer) {
    const bytes = Array.from(new Uint8Array(buffer))
    const b64 = btoa(String.fromCharCode(...bytes))
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }

  async function startOAuthFlow() {
    const appBaseUrl = dashboard?.appBaseUrl ?? window.location.origin
    const { verifier, challenge } = await createPkce()
    const state = crypto.randomUUID()
    sessionStorage.setItem('pkce_verifier', verifier)
    sessionStorage.setItem('oauth_state', state)
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: 'demo-client',
      redirect_uri: `${appBaseUrl}/client/callback`,
      scope: 'read:profile',
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    })
    window.location.href = `/oauth/authorize?${params.toString()}`
  }

  async function handleCallback() {
    try {
      setBusy(true)
      const bootstrap = await refreshDashboard()
      const appBaseUrl = bootstrap.appBaseUrl
      const url = new URL(window.location.href)
      const code = url.searchParams.get('code')
      const state = url.searchParams.get('state')
      const expectedState = sessionStorage.getItem('oauth_state')
      const verifier = sessionStorage.getItem('pkce_verifier')

      if (!code || !state || !verifier || expectedState !== state) {
        setApiOutput('Missing or invalid callback values.')
        return
      }

      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${appBaseUrl}/client/callback`,
        client_id: 'demo-client',
        code_verifier: verifier,
      })

      const tokenResponse = await fetch('/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const tokenData = await tokenResponse.json()
      if (!tokenResponse.ok) {
        setApiOutput(`Token exchange failed: ${JSON.stringify(tokenData, null, 2)}`)
        return
      }

      const resourceResponse = await fetch('/api/resource', {
        headers: { Authorization: `Bearer ${tokenData.access_token as string}` },
      })
      const resourceData = await resourceResponse.json()

      setApiOutput(
        JSON.stringify(
          {
            token: tokenData,
            resource: resourceData,
          },
          null,
          2,
        ),
      )

      window.history.replaceState({}, '', '/app')
      setMode('dashboard')
      await refreshDashboard()
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown callback error'
      setApiOutput(message)
    } finally {
      setBusy(false)
    }
  }

  async function callApiResource() {
    if (!latestToken) {
      setApiOutput('No token available. Run OAuth2 flow first.')
      return
    }
    const response = await fetch('/api/resource', {
      headers: { Authorization: `Bearer ${latestToken}` },
    })
    const data = await response.json()
    setApiOutput(JSON.stringify(data, null, 2))
    await refreshDashboard()
  }

  async function revokeLatestToken() {
    const response = await fetch('/oauth/revoke-latest', { method: 'POST' })
    const data = await response.json()
    setApiOutput(JSON.stringify(data, null, 2))
    await refreshDashboard()
  }

  async function rotateRefreshToken() {
    if (!latestRefreshToken) {
      setApiOutput('No refresh token available. Run OAuth2 flow first.')
      return
    }

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: latestRefreshToken,
      client_id: 'demo-client',
    })

    const response = await fetch('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    const data = await response.json()
    setApiOutput(JSON.stringify(data, null, 2))
    await refreshDashboard()
  }

  useEffect(() => {
    if (mode === 'callback') {
      void handleCallback()
      return
    }
    void refreshDashboard().catch((error) => {
      const message = error instanceof Error ? error.message : 'Dashboard load failed'
      setDashboard(null)
      setApiOutput(message)
    })
  }, [mode])

  return (
    <main className="container">
      <nav className="top-nav">
        <span className="brand">OAuth2 Portfolio Project</span>
        <div className="nav-links">
          <a href="#highlights">Highlights</a>
          <a href="#runtime">Runtime</a>
          <a href="#events">Audit Trail</a>
        </div>
      </nav>

      <header>
        <h1>Developer Security Dashboard</h1>
        <p className="muted">
          OAuth2 Authorization Code + PKCE with GitHub identity and Postgres audit
          events.
        </p>
      </header>

      <section className="grid">
        <article className="card full" id="highlights">
          <h2>Project Highlights (Recruiter View)</h2>
          <div className="highlights">
            <div className="highlight-item">
              <h3>Security</h3>
              <p>Authorization Code + PKCE, rotating refresh tokens, scoped bearer tokens.</p>
            </div>
            <div className="highlight-item">
              <h3>Architecture</h3>
              <p>React frontend, Express OAuth server, protected API, Postgres persistence.</p>
            </div>
            <div className="highlight-item">
              <h3>Operational Readiness</h3>
              <p>Dockerized stack, DB health checks, startup retry, build/typecheck automation.</p>
            </div>
            <div className="highlight-item">
              <h3>Observability</h3>
              <p>Auth event ledger for login, token issuance/revocation, and resource access.</p>
            </div>
          </div>
        </article>

        <article className="card">
          <h2>Identity</h2>
          {!dashboard?.signedIn ? (
            <>
              <p>Not signed in yet.</p>
              <a className="btn" href="/login/github">
                Sign in with GitHub
              </a>
            </>
          ) : (
            <div className="identity">
              {dashboard.user?.avatarUrl ? (
                <img src={dashboard.user.avatarUrl} alt="GitHub avatar" />
              ) : (
                <div className="avatar-fallback" />
              )}
              <div>
                <p>
                  <strong>{dashboard.user?.login}</strong>
                </p>
                <p className="muted">{dashboard.user?.email ?? 'No public email'}</p>
                <p className="muted">Provider: GitHub</p>
                <p className="muted">
                  Session started: {new Date(dashboard.sessionIssuedAt).toLocaleString()}
                </p>
              </div>
            </div>
          )}
        </article>

        <article className="card">
          <h2>Token Details</h2>
          {!dashboard?.latestToken ? (
            <p>No token issued in this session.</p>
          ) : (
            <>
              <p>
                <strong>Type:</strong> Bearer
              </p>
              <p>
                <strong>Scope:</strong> {dashboard.latestToken.scope}
              </p>
              <p>
                <strong>Expires:</strong>{' '}
                {new Date(dashboard.latestToken.expiresAt).toLocaleString()}
              </p>
              <p>
                <strong>Preview:</strong> <code>{dashboard.latestToken.preview}</code>
              </p>
              <p>
                <strong>Refresh:</strong>{' '}
                {dashboard.latestRefreshToken
                  ? `Ready (expires ${new Date(dashboard.latestRefreshToken.expiresAt).toLocaleString()})`
                  : 'Not issued'}
              </p>
            </>
          )}
        </article>

        <article className="card">
          <h2>Controls</h2>
          <button className="btn" onClick={() => void startOAuthFlow()} disabled={busy}>
            Run OAuth2 Flow
          </button>
          <button className="btn secondary" onClick={() => void callApiResource()}>
            Call Protected API
          </button>
          <button className="btn secondary" onClick={() => void rotateRefreshToken()}>
            Rotate Refresh Token
          </button>
          <button className="btn secondary" onClick={() => void revokeLatestToken()}>
            Revoke Latest Token
          </button>
          <a className="btn secondary" href="/logout">
            Logout
          </a>
        </article>

        <article className="card wide" id="runtime">
          <h2>Live API Tester</h2>
          <p className="muted">
            Calls <code>/api/resource</code> with the latest token.
          </p>
          <pre>{apiOutput}</pre>
        </article>

        <article className="card">
          <h2>Architecture</h2>
          <pre>{`Browser Client -> /oauth/authorize
GitHub Identity -> /auth/github/callback
OAuth2 Server -> /oauth/token
Resource API -> /api/resource
Postgres -> users/tokens/events`}</pre>
        </article>

        <article className="card full" id="events">
          <h2>Recent Auth Events</h2>
          {!dashboard?.events?.length ? (
            <p className="muted">No events yet.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Event</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {dashboard.events.map((event) => (
                  <tr key={`${event.type}-${event.createdAt}`}>
                    <td>{new Date(event.createdAt).toLocaleTimeString()}</td>
                    <td>{event.type}</td>
                    <td>
                      <code>{JSON.stringify(event.details)}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </article>
      </section>
    </main>
  )
}

export default App
