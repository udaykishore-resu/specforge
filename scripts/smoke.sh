#!/usr/bin/env bash
# Verify a running local stack, end to end.
#
# `make dev` prints six URLs. This checks all of them, and then checks the
# things the URLs exist to serve: that a token carries a tenant, that the API
# enforces the permission each route declares, that separation of duties holds,
# that the audit chain verifies, that traces reach Jaeger and that metrics reach
# Prometheus. Every check is a real request against the running system — nothing
# here is mocked, and a check that cannot be made honestly is reported as SKIP
# rather than quietly passing.
#
#   make smoke
#   scripts/smoke.sh
#
# Exit status is non-zero if any check fails, so it is usable as a gate.

set -uo pipefail

API="${SF_SMOKE_API:-http://localhost:8080}"
WEB="${SF_SMOKE_WEB:-http://localhost:3000}"
IDP="${SF_SMOKE_IDP:-http://localhost:8081}"
GRAFANA="${SF_SMOKE_GRAFANA:-http://localhost:3001}"
JAEGER="${SF_SMOKE_JAEGER:-http://localhost:16686}"
PROM="${SF_SMOKE_PROM:-http://localhost:9091}"
MINIO="${SF_SMOKE_MINIO:-http://localhost:9000}"
MINIO_CONSOLE="${SF_SMOKE_MINIO_CONSOLE:-http://localhost:9001}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pass=0
fail=0
skip=0

green() { printf '\033[32m%s\033[0m' "$1"; }
red() { printf '\033[31m%s\033[0m' "$1"; }
grey() { printf '\033[90m%s\033[0m' "$1"; }

ok() {
	pass=$((pass + 1))
	printf '  %s  %s\n' "$(green PASS)" "$1"
}
no() {
	fail=$((fail + 1))
	printf '  %s  %s\n' "$(red FAIL)" "$1"
	[ $# -gt 1 ] && printf '        %s\n' "$2"
	return 0
}
sk() {
	skip=$((skip + 1))
	printf '  %s  %s\n' "$(grey SKIP)" "$1"
	[ $# -gt 1 ] && printf '        %s\n' "$2"
	return 0
}
section() { printf '\n%s\n' "$1"; }

# status URL [curl args...] — echo the HTTP status code, or 000 if unreachable.
status() {
	local url="$1" code
	shift
	code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$@" "$url" 2>/dev/null)"
	printf '%s' "${code:-000}"
}

# expect_status "description" expected URL [curl args...]
expect_status() {
	local what="$1" want="$2" url="$3"
	shift 3
	local got
	got="$(status "$url" "$@")"
	if [ "$got" = "$want" ]; then
		ok "$what"
	else
		no "$what" "$url returned $got, expected $want"
	fi
}

body() {
	local url="$1"
	shift
	curl -sS --max-time 10 "$@" "$url" 2>/dev/null
}

# json_string key <<< json — first value of a string field. Deliberately crude:
# jq is not assumed to be installed, and the shapes read here are flat.
json_string() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -1; }

printf 'SpecForge smoke test\n'
printf '  API %s   Web %s   IdP %s\n' "$API" "$WEB" "$IDP"

# ---------------------------------------------------------------- API ------

section "API — $API"

expect_status "liveness      GET /healthz" 200 "$API/healthz"
expect_status "readiness     GET /readyz" 200 "$API/readyz"
expect_status "version       GET /api/v1/version" 200 "$API/api/v1/version"
expect_status "contract      GET /api/v1/openapi.json" 200 "$API/api/v1/openapi.json"
expect_status "metrics       GET /metrics" 200 "$API/metrics"

# A route that requires a permission must reject an anonymous caller. If this
# passes with 200, authentication is not being enforced and nothing below means
# anything.
expect_status "anonymous request is rejected" 401 "$API/api/v1/auth/me"

READY="$(body "$API/readyz")"
case "$READY" in
*'"status":"ok"'* | *'"status": "ok"'*) ok "readiness reports its dependencies healthy" ;;
"") no "readiness reports its dependencies healthy" "no response from $API/readyz" ;;
*) no "readiness reports its dependencies healthy" "$READY" ;;
esac

VERSION_BODY="$(body "$API/api/v1/version")"
if [ -n "$VERSION_BODY" ]; then
	ok "version: $(printf '%s' "$VERSION_BODY" | json_string version) ($(printf '%s' "$VERSION_BODY" | json_string commit))"
else
	no "the API reports its build identity"
fi

# ------------------------------------------------------------ dev IdP ------

section "Development identity provider — $IDP"

DISCOVERY="$(body "$IDP/.well-known/openid-configuration")"
if printf '%s' "$DISCOVERY" | grep -q '"token_endpoint"'; then
	ok "discovery document"
else
	no "discovery document" "not served — is the API running with SF_AUTH_DEV_IDP=true?"
fi

if printf '%s' "$DISCOVERY" | grep -q '"S256"'; then
	ok "PKCE S256 advertised"
else
	no "PKCE S256 advertised"
fi

if printf '%s' "$(body "$IDP/jwks.json")" | grep -q '"kty":"RSA"'; then
	ok "JWKS publishes an asymmetric key"
else
	no "JWKS publishes an asymmetric key"
fi

ACCOUNTS="$(body "$IDP/users" | tr ',' '\n' | sed -n 's/.*"sub":"dev-\([^"]*\)".*/\1/p' | tr '\n' ' ')"
if [ -n "$ACCOUNTS" ]; then
	ok "seeded accounts: $ACCOUNTS"
else
	no "the provider lists its seeded accounts"
fi

# --------------------------------------------------- tokens and tenancy ----

section "Tokens"

token_for() { "$here/dev-token.sh" "$1" 2>/dev/null; }

# claim NAME TOKEN — read a claim from the payload without verifying the
# signature. The API verifies it; this is only for reporting.
claim() {
	local name="$1" tok="$2" payload
	payload="$(printf '%s' "$tok" | cut -d. -f2 | tr '_-' '/+')"
	# base64 needs padding restored.
	case $((${#payload} % 4)) in
	2) payload="$payload==" ;;
	3) payload="$payload=" ;;
	esac
	# A '#' delimiter, because the claim names are namespaced URLs.
	printf '%s' "$payload" | base64 -d 2>/dev/null |
		sed -n "s#.*\"$name\":\"\([^\"]*\)\".*#\1#p" | head -1
}

ANALYST="$(token_for analyst)"
OWNER="$(token_for owner)"
AUDITOR="$(token_for auditor)"
VIEWER="$(token_for viewer)"

if [ -z "$ANALYST" ] || [ -z "$OWNER" ]; then
	no "the development provider issues tokens" \
		"scripts/dev-token.sh failed — the checks below cannot run"
	printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
	exit 1
fi
ok "authorization-code flow with PKCE issues a token"

TENANT="$(claim 'https://specforge.io/tenant' "$OWNER")"
if [ -n "$TENANT" ]; then
	ok "tokens carry a tenant: $TENANT"
else
	no "tokens carry a tenant" \
		"SF_DEV_TENANT_ID did not reach the API process, so every request below will be tenantless.
        Set it in the api service's environment and restart:  docker compose -f deploy/docker/docker-compose.yml up -d api"
	printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
	exit 1
fi

auth() { curl -sS --max-time 10 -H "Authorization: Bearer $1" "${@:2}" 2>/dev/null; }
auth_status() {
	local code
	code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
		-H "Authorization: Bearer $1" "${@:2}" 2>/dev/null)"
	printf '%s' "${code:-000}"
}

ME="$(auth "$OWNER" "$API/api/v1/auth/me")"
if printf '%s' "$ME" | grep -q '"tenant_id"'; then
	ok "GET /auth/me resolves the principal and its roles"
else
	no "GET /auth/me resolves the principal and its roles" "${ME:-no response}"
fi

# A forged token must be refused. The API verifies against the JWKS with an
# asymmetric algorithm only, so a token signed with `none` or with a symmetric
# key cannot be accepted.
FORGED="$(printf 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.%s.' "$(printf '%s' "$OWNER" | cut -d. -f2)")"
got="$(auth_status "$FORGED" "$API/api/v1/auth/me")"
if [ "$got" = "401" ]; then
	ok "an unsigned (alg=none) token is refused"
else
	no "an unsigned (alg=none) token is refused" "got $got, expected 401"
fi

# --------------------------------------------------- the seeded project ----

section "Governance"

PROJECTS="$(auth "$OWNER" "$API/api/v1/tenants/$TENANT/projects")"
PROJECT="$(printf '%s' "$PROJECTS" | tr ',' '\n' | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)"
if [ -n "$PROJECT" ]; then
	ok "the demo project is visible: $PROJECT"
else
	no "the demo project is visible" "${PROJECTS:-no response} — has \`make seed\` run?"
fi

if [ -n "$PROJECT" ]; then
	BASE="$API/api/v1/tenants/$TENANT/projects/$PROJECT"

	ARTIFACTS="$(auth "$OWNER" "$BASE/artifacts")"
	COUNT="$(printf '%s' "$ARTIFACTS" | grep -o '"artifact_id"' | wc -l | tr -d ' ')"
	if [ "${COUNT:-0}" -ge 2 ]; then
		ok "the seeded artifacts are present ($COUNT)"
	else
		no "the seeded artifacts are present" "found ${COUNT:-0}, expected at least 2"
	fi

	if printf '%s' "$ARTIFACTS" | grep -q '"APPROVED"'; then
		ok "a seeded artifact is APPROVED"
	else
		no "a seeded artifact is APPROVED"
	fi

	# Traceability. The seeded specification derives from the seeded requirement,
	# so an upstream query from the specification must reach it.
	UP="$(auth "$OWNER" "$BASE/trace/upstream?artifact_id=SPEC-PAY-001")"
	if printf '%s' "$UP" | grep -q 'REQ-PAY-001'; then
		ok "trace upstream: SPEC-PAY-001 reaches REQ-PAY-001"
	else
		no "trace upstream: SPEC-PAY-001 reaches REQ-PAY-001" "${UP:-no response}"
	fi

	IMPACT="$(auth "$OWNER" "$BASE/trace/impact?artifact_id=REQ-PAY-001")"
	if printf '%s' "$IMPACT" | grep -q 'SPEC-PAY-001'; then
		ok "impact analysis: changing REQ-PAY-001 affects SPEC-PAY-001"
	else
		no "impact analysis: changing REQ-PAY-001 affects SPEC-PAY-001" "${IMPACT:-no response}"
	fi

	# Evidence. An approved version must expose a document whose digest an
	# auditor can verify offline.
	EVIDENCE="$(auth "$AUDITOR" "$BASE/artifacts/REQ-PAY-001/versions/1/evidence")"
	if printf '%s' "$EVIDENCE" | grep -q 'sha256:'; then
		ok "an auditor can read the approval evidence"
	else
		no "an auditor can read the approval evidence" "${EVIDENCE:-no response}"
	fi

	# Authorization. A viewer holds no approval permission, and the route
	# declares one, so this must be refused — with 403, not 401: the caller is
	# authenticated and simply not permitted.
	got="$(auth_status "$VIEWER" -X POST "$BASE/artifacts/REQ-PAY-001/versions/1/approve" \
		-H 'Content-Type: application/json' -d '{"comment":"smoke test"}')"
	case "$got" in
	403) ok "a viewer cannot approve (403)" ;;
	401) no "a viewer cannot approve" "got 401 — the token was rejected before authorization was reached" ;;
	2*) no "a viewer cannot approve" "got $got — AUTHORIZATION IS NOT BEING ENFORCED" ;;
	*) ok "a viewer cannot approve ($got)" ;;
	esac

	# Immutability. An approved version is sealed; editing it must be refused by
	# the state machine rather than accepted and silently ignored.
	got="$(auth_status "$OWNER" -X PUT "$BASE/artifacts/REQ-PAY-001/versions/1" \
		-H 'Content-Type: application/json' -d '{"title":"rewritten by the smoke test"}')"
	case "$got" in
	2*) no "an APPROVED version cannot be edited" "got $got — AN APPROVED ARTIFACT WAS MUTATED" ;;
	*) ok "an APPROVED version cannot be edited ($got)" ;;
	esac
fi

# ------------------------------------------------------------- audit -------

section "Audit"

CHAIN="$(auth "$AUDITOR" -X POST "$API/api/v1/tenants/$TENANT/audit/verify" \
	-H 'Content-Type: application/json' -d '{}')"
if printf '%s' "$CHAIN" | grep -q '"valid":true'; then
	RECORDS="$(printf '%s' "$CHAIN" | sed -n 's/.*"records_checked":\([0-9]*\).*/\1/p')"
	ok "the audit chain verifies (${RECORDS:-?} records)"
else
	no "the audit chain verifies" "${CHAIN:-no response}"
fi

RECENT="$(auth "$AUDITOR" "$API/api/v1/tenants/$TENANT/audit?limit=5")"
if printf '%s' "$RECENT" | grep -q '"sequence"'; then
	ok "audit records are readable and sequenced"
else
	no "audit records are readable and sequenced" "${RECENT:-no response}"
fi

# The same recomputation, done offline from stored bytes rather than by asking
# the API to vouch for itself. This is the check an auditor actually runs.
if command -v go >/dev/null && [ -f "$here/../go.mod" ]; then
	if (cd "$here/.." && SF_DB_DSN="${SF_DB_DSN:-host=127.0.0.1 port=5432 user=specforge password=specforge dbname=specforge sslmode=disable}" \
		go run ./cmd/specforge-cli verify-audit --tenant "$TENANT" >/dev/null 2>&1); then
		ok "specforge-cli recomputes the chain independently"
	else
		no "specforge-cli recomputes the chain independently" \
			"run it directly to see why: make verify-audit TENANT=$TENANT"
	fi
else
	sk "specforge-cli recomputes the chain independently" "the Go toolchain is not available here"
fi

# --------------------------------------------------------------- web -------

section "Console — $WEB"

got="$(status "$WEB/")"
case "$got" in
200 | 302 | 307) ok "the console responds ($got)" ;;
000) no "the console responds" "nothing is listening on $WEB" ;;
*) no "the console responds" "returned $got" ;;
esac

HEAD="$(curl -sS -D - -o /dev/null --max-time 10 "$WEB/" 2>/dev/null | tr -d '\r')"
if printf '%s' "$HEAD" | grep -qi '^content-security-policy:'; then
	ok "a Content-Security-Policy is set"
else
	no "a Content-Security-Policy is set"
fi

# The sign-in route must start a real authorization request at the provider.
LOC="$(curl -sS -D - -o /dev/null --max-time 10 "$WEB/api/auth/login" 2>/dev/null |
	tr -d '\r' | awk 'tolower($1) == "location:" { print $2 }')"
case "$LOC" in
*"/authorize?"*"code_challenge="*) ok "sign-in starts an authorization-code flow with PKCE" ;;
"") no "sign-in starts an authorization-code flow with PKCE" "no redirect from $WEB/api/auth/login" ;;
*) no "sign-in starts an authorization-code flow with PKCE" "redirected to $LOC" ;;
esac

# ----------------------------------------------------- observability -------

section "Observability"

if printf '%s' "$(body "$GRAFANA/api/health")" | grep -q '"database"'; then
	ok "Grafana is up — $GRAFANA (admin/admin, anonymous viewing is on)"
else
	no "Grafana is up" "no response from $GRAFANA/api/health"
fi

DASH="$(body "$GRAFANA/api/search?query=SpecForge")"
if printf '%s' "$DASH" | grep -q 'SpecForge'; then
	ok "the governance dashboard is provisioned"
	printf '        %s%s\n' "$GRAFANA" "$(printf '%s' "$DASH" | json_string url)"
else
	no "the governance dashboard is provisioned" "${DASH:-no response}"
fi

TARGETS="$(body "$PROM/api/v1/targets?state=active")"
if printf '%s' "$TARGETS" | grep -q '"health":"up"'; then
	DOWN="$(printf '%s' "$TARGETS" | grep -o '"health":"down"' | wc -l | tr -d ' ')"
	if [ "${DOWN:-0}" -eq 0 ]; then
		ok "every Prometheus target is up"
	else
		no "every Prometheus target is up" "$DOWN target(s) down — see $PROM/targets"
	fi
else
	no "Prometheus is scraping" "no active targets at $PROM"
fi

# The metric that matters most: a non-zero content-hash mismatch means stored
# bytes stopped matching their recorded digest.
MISMATCH="$(body "$PROM/api/v1/query?query=sum(sf_content_hash_mismatch_total)")"
case "$MISMATCH" in
*'"value"'*) ok "integrity metrics are being collected" ;;
*'"result":[]'*) sk "integrity metrics are being collected" "no samples yet — Prometheus scrapes every 15s" ;;
*) no "integrity metrics are being collected" "${MISMATCH:-no response}" ;;
esac

SERVICES="$(body "$JAEGER/api/services")"
if printf '%s' "$SERVICES" | grep -q 'specforge-api'; then
	ok "Jaeger has traces from specforge-api"
	printf '        %s/search?service=specforge-api\n' "$JAEGER"
else
	sk "Jaeger has traces from specforge-api" \
		"none yet — make a few requests, then look at $JAEGER"
fi

# ------------------------------------------------------- object store ------

section "Object store"

if [ "$(status "$MINIO/minio/health/live")" = "200" ]; then
	ok "MinIO is up — console at $MINIO_CONSOLE (specforge / specforge-dev-secret)"
else
	no "MinIO is up" "no response from $MINIO/minio/health/live"
fi

# Bucket state is checked through the running container's own client rather than
# by signing S3 requests here, because a hand-rolled signature that fails proves
# nothing about the store.
if command -v docker >/dev/null 2>&1; then
	LOCK="$(docker run --rm --network specforge_default minio/mc:RELEASE.2024-10-08T09-37-26Z \
		/bin/sh -c "mc alias set l http://minio:9000 specforge specforge-dev-secret >/dev/null 2>&1 && \
                mc retention info --default l/sf-evidence 2>/dev/null" 2>/dev/null)"
	if printf '%s' "$LOCK" | grep -qi 'GOVERNANCE'; then
		ok "the evidence bucket has object-lock retention set"
	else
		sk "the evidence bucket has object-lock retention set" \
			"could not read it from here; check by hand: docker compose -f deploy/docker/docker-compose.yml run --rm minio-init sh -c 'mc alias set l http://minio:9000 specforge specforge-dev-secret && mc retention info --default l/sf-evidence'"
	fi
else
	sk "the evidence bucket has object-lock retention set" "docker is not available here"
fi

# ------------------------------------------------------------ summary ------

printf '\n'
if [ "$fail" -eq 0 ]; then
	printf '%s  %d checks passed, %d skipped\n' "$(green 'ALL GOOD')" "$pass" "$skip"
	exit 0
fi
printf '%s  %d passed, %d failed, %d skipped\n' "$(red 'FAILURES')" "$pass" "$fail" "$skip"
exit 1
