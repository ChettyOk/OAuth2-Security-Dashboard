#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Smoke test a deployed OAuth2 app.

Usage:
  ./scripts/deploy-smoke.sh --base-url https://your-app.vercel.app [--bearer-token TOKEN]

Checks:
  - GET /healthz
  - GET /readyz
  - GET /.well-known/openid-configuration
  - GET /.well-known/jwks.json
  - GET /app
  - (optional) GET /api/resource with bearer token
EOF
}

BASE_URL=""
BEARER_TOKEN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url)
      BASE_URL="${2:-}"
      shift 2
      ;;
    --bearer-token)
      BEARER_TOKEN="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$BASE_URL" ]]; then
  echo "Missing required --base-url" >&2
  usage
  exit 1
fi

BASE_URL="${BASE_URL%/}"

require_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "This script requires jq. Install jq and retry." >&2
    exit 1
  fi
}

request_json() {
  local path="$1"
  local expected_status="${2:-200}"
  local url="${BASE_URL}${path}"
  local body_file
  body_file="$(mktemp)"

  local status
  status="$(curl -sS -o "$body_file" -w "%{http_code}" "$url")"

  if [[ "$status" != "$expected_status" ]]; then
    echo "FAIL ${path} expected ${expected_status}, got ${status}"
    echo "Body:"
    cat "$body_file"
    rm -f "$body_file"
    exit 1
  fi

  echo "PASS ${path} (${status})"
  cat "$body_file"
  rm -f "$body_file"
}

request_html() {
  local path="$1"
  local expected_status="${2:-200}"
  local url="${BASE_URL}${path}"
  local status
  status="$(curl -sS -o /dev/null -w "%{http_code}" "$url")"

  if [[ "$status" != "$expected_status" ]]; then
    echo "FAIL ${path} expected ${expected_status}, got ${status}"
    exit 1
  fi
  echo "PASS ${path} (${status})"
}

echo "Running deploy smoke tests for: ${BASE_URL}"
echo

require_jq

health_json="$(request_json "/healthz")"
echo "$health_json" | jq -e '.ok == true' >/dev/null

ready_json="$(request_json "/readyz")"
echo "$ready_json" | jq -e '.ready == true' >/dev/null

discovery_json="$(request_json "/.well-known/openid-configuration")"
echo "$discovery_json" | jq -e --arg issuer "$BASE_URL" '.issuer == $issuer' >/dev/null

jwks_json="$(request_json "/.well-known/jwks.json")"
echo "$jwks_json" | jq -e '.keys | type == "array" and length > 0' >/dev/null
echo "$jwks_json" | jq -e '.keys[0].kid != null and .keys[0].alg == "ES256"' >/dev/null

request_html "/app"

if [[ -n "$BEARER_TOKEN" ]]; then
  api_status="$(curl -sS -o /tmp/oauth2_smoke_api.json -w "%{http_code}" \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    "${BASE_URL}/api/resource")"
  if [[ "$api_status" != "200" ]]; then
    echo "FAIL /api/resource expected 200 with provided token, got ${api_status}"
    cat /tmp/oauth2_smoke_api.json
    rm -f /tmp/oauth2_smoke_api.json
    exit 1
  fi
  echo "PASS /api/resource (200)"
  cat /tmp/oauth2_smoke_api.json | jq .
  rm -f /tmp/oauth2_smoke_api.json
else
  echo "SKIP /api/resource (no --bearer-token provided)"
fi

echo
echo "All smoke checks passed."
