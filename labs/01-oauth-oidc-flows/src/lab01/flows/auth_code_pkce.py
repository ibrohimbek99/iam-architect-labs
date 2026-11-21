"""Authorization code + PKCE for a public client, then refresh-token rotation.

1. Opens your browser at Keycloak's login (sign in as `alice`; the password is in .env.example).
2. Receives the code on a loopback redirect (http://127.0.0.1:8765/callback) and checks `state`.
3. Redeems the code with the PKCE verifier. A stolen code is useless without it.
4. Refreshes once, then shows that **reusing the old refresh token fails**: rotation
   with reuse detection (the realm sets revokeRefreshToken=true, maxReuse=0).

Run: `uv run python -m lab01.flows.auth_code_pkce`
"""

from __future__ import annotations

import http.server
import os
import threading
import urllib.parse
import webbrowser
from typing import Any

from lab01.flows.common import TokenEndpointError, call_api, peek_claims, post_token, show
from lab01.pkce import code_challenge_s256, new_code_verifier, new_nonce, new_state
from lab01.settings import Settings

CLIENT_ID = "contoso-cli"
REDIRECT_PORT = 8765
REDIRECT_URI = f"http://127.0.0.1:{REDIRECT_PORT}/callback"


def _wait_for_callback() -> dict[str, str]:
    result: dict[str, str] = {}
    done = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - name required by BaseHTTPRequestHandler
            query = urllib.parse.urlparse(self.path).query
            result.update({k: v[0] for k, v in urllib.parse.parse_qs(query).items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Login complete. You can close this tab.")
            done.set()

        def log_message(self, *args: Any) -> None:  # keep the code out of the console
            return

    # Bind to the loopback interface only (RFC 8252 §7.3), never 0.0.0.0.
    server = http.server.HTTPServer(("127.0.0.1", REDIRECT_PORT), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    if not done.wait(timeout=180):
        server.shutdown()
        raise SystemExit("Timed out waiting for the browser login.")
    server.shutdown()
    return result


def main() -> None:
    settings = Settings.from_env()
    verifier, state, nonce = new_code_verifier(), new_state(), new_nonce()
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid accounts:read",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge_s256(verifier),
        "code_challenge_method": "S256",
    }
    url = f"{settings.authorization_endpoint}?{urllib.parse.urlencode(params)}"
    print(f"Log in at:\n{url}", flush=True)
    if not os.environ.get("LAB01_NO_BROWSER"):  # set it to drive the login from another browser
        webbrowser.open(url)

    callback = _wait_for_callback()
    if callback.get("state") != state:  # CSRF / login-injection check
        raise SystemExit("state mismatch: refusing the response")
    # RFC 9207: Keycloak names itself in the redirect. Checking it defeats IdP mix-up attacks
    # when a client trusts more than one authorization server.
    if "iss" in callback and callback["iss"] != settings.issuer:
        raise SystemExit(f"unexpected issuer {callback['iss']!r}: refusing the response")
    if "error" in callback:
        raise SystemExit(f"login failed: {callback['error']}")

    tokens = post_token(
        settings,
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": callback["code"],
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
    )
    show("authorization_code + PKCE as alice", tokens)
    if peek_claims(tokens["id_token"]).get("nonce") != nonce:
        raise SystemExit("nonce mismatch in ID token: refusing it")
    call_api(settings, "/accounts/summary", tokens["access_token"])

    old_refresh = tokens["refresh_token"]
    rotated = post_token(
        settings,
        {"grant_type": "refresh_token", "client_id": CLIENT_ID, "refresh_token": old_refresh},
    )
    print("\n== refresh #1 succeeded; a NEW refresh token was issued:", "refresh_token" in rotated)

    try:
        post_token(
            settings,
            {"grant_type": "refresh_token", "client_id": CLIENT_ID, "refresh_token": old_refresh},
        )
        print("!! reuse of the old refresh token was accepted: rotation is NOT enforced")
    except TokenEndpointError as exc:
        print(f"== reuse of the old refresh token was rejected, as it should be: {exc}")


if __name__ == "__main__":
    main()
