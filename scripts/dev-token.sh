#!/usr/bin/env bash
# Obtain an access token from the development identity provider.
#
# This walks the same authorization-code flow with PKCE that the console walks
# in a browser — nothing is stubbed, and no shortcut endpoint exists to be
# accidentally shipped. It is here so that `curl` against the API is as easy as
# clicking through the console, because a check that is hard to run is a check
# nobody runs.
#
#   TOKEN=$(scripts/dev-token.sh analyst)
#   curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/auth/me
#
# The role names are the suffixes of the seeded accounts: admin, owner, analyst,
# architect, dev, qa, ops, sec, compliance, auditor, viewer, platform.
#
# Requires curl and openssl. Refuses to run against anything but a loopback
# issuer: this provider is a development component and must never be reachable,
# or usable, anywhere else.

set -euo pipefail

ROLE="${1:-owner}"
ISSUER="${SF_DEV_IDP_URL:-http://localhost:8081}"
REDIRECT="${SF_DEV_REDIRECT_URL:-http://localhost:3000/api/auth/callback}"
CLIENT_ID="${SF_DEV_CLIENT_ID:-specforge-web}"
WHICH="${SF_DEV_TOKEN_KIND:-access_token}" # or id_token

case "$ISSUER" in
http://localhost:* | http://127.0.0.1:*) ;;
*)
	echo "dev-token: refusing a non-loopback issuer: $ISSUER" >&2
	echo "The development identity provider is not a production component." >&2
	exit 2
	;;
esac

for tool in curl openssl; do
	command -v "$tool" >/dev/null || {
		echo "dev-token: $tool is required" >&2
		exit 2
	}
done

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# PKCE. The verifier never leaves this process until the token exchange, and the
# provider rejects the code without it.
VERIFIER="$(openssl rand 48 | b64url)"
CHALLENGE="$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | b64url)"
STATE="$(openssl rand 12 | b64url)"
NONCE="$(openssl rand 12 | b64url)"

# Step 1: authorize. login_hint picks the seeded account without the chooser.
HEADERS="$(
	curl -sS -o /dev/null -D - -G "$ISSUER/authorize" \
		--data-urlencode "client_id=$CLIENT_ID" \
		--data-urlencode "redirect_uri=$REDIRECT" \
		--data-urlencode "response_type=code" \
		--data-urlencode "scope=openid profile email" \
		--data-urlencode "state=$STATE" \
		--data-urlencode "nonce=$NONCE" \
		--data-urlencode "code_challenge=$CHALLENGE" \
		--data-urlencode "code_challenge_method=S256" \
		--data-urlencode "login_hint=dev-$ROLE" | tr -d '\r'
)"
STATUS="$(printf '%s' "$HEADERS" | awk 'NR == 1 { print $2 }')"
LOCATION="$(printf '%s' "$HEADERS" | awk 'tolower($1) == "location:" { print $2 }')"

if [ -z "$LOCATION" ]; then
	case "$STATUS" in
	200)
		# The provider fell back to the account chooser, which it does when the
		# requested subject does not exist.
		echo "dev-token: no account named 'dev-$ROLE'." >&2
		echo "Available accounts: $(curl -sS "$ISSUER/users" |
			tr ',' '\n' | sed -n 's/.*"sub":"dev-\([^"]*\)".*/\1/p' | tr '\n' ' ')" >&2
		;;
	*)
		echo "dev-token: the provider did not issue a redirect (HTTP ${STATUS:-none})." >&2
		echo "Is the API running with SF_AUTH_DEV_IDP=true? Check: curl $ISSUER/.well-known/openid-configuration" >&2
		;;
	esac
	exit 1
fi

case "$LOCATION" in
*"error="*)
	echo "dev-token: the authorization request was rejected: $LOCATION" >&2
	exit 1
	;;
esac

CODE="$(printf '%s' "$LOCATION" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')"
GOT_STATE="$(printf '%s' "$LOCATION" | sed -n 's/.*[?&]state=\([^&]*\).*/\1/p')"

if [ -z "$CODE" ]; then
	echo "dev-token: no authorization code in the redirect: $LOCATION" >&2
	echo "The account 'dev-$ROLE' may not exist. Try: curl $ISSUER/users" >&2
	exit 1
fi
# The provider percent-encodes the echoed state; compare against the same form.
if [ "$GOT_STATE" != "$(printf '%s' "$STATE" | sed 's/=/%3D/g')" ] && [ "$GOT_STATE" != "$STATE" ]; then
	echo "dev-token: state was not echoed back unchanged — refusing the code." >&2
	exit 1
fi

# Step 2: exchange the single-use code. Replaying it invalidates the grant.
RESPONSE="$(
	curl -sS -X POST "$ISSUER/token" \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		--data-urlencode "grant_type=authorization_code" \
		--data-urlencode "code=$CODE" \
		--data-urlencode "redirect_uri=$REDIRECT" \
		--data-urlencode "client_id=$CLIENT_ID" \
		--data-urlencode "code_verifier=$VERIFIER"
)"

TOKEN="$(printf '%s' "$RESPONSE" | sed -n "s/.*\"$WHICH\":\"\([^\"]*\)\".*/\1/p")"
if [ -z "$TOKEN" ]; then
	echo "dev-token: the token exchange failed: $RESPONSE" >&2
	exit 1
fi

printf '%s\n' "$TOKEN"
