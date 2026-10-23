import base64
import contextlib
import hashlib
import http.server
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from support import NULARA

from nulara.core.config import ProductConfig, Surface
from nulara.core.errors import AuthenticationError, CliError
from nulara.core.oauth import (
    await_authorization_code,
    bind_loopback_callback,
    build_authorize_url,
    client_id_for,
    exchange_code,
    fetch_metadata,
    pkce_pair,
    run_browser_login,
)

LOCAL_CONFIG = ProductConfig(
    product=NULARA,
    surface=Surface.DEVELOPMENT,
    base_url="http://localhost:5710/v1/app",
    token_env="NULARA_API_TOKEN",
    keyring_service="nulara-cli",
)
REMOTE_CONFIG = ProductConfig(
    product=NULARA,
    surface=Surface.DEVELOPMENT,
    base_url="https://api.example.test/v1/app",
    token_env="NULARA_API_TOKEN",
    keyring_service="nulara-cli",
)


def metadata_payload(
    *,
    token_endpoint: str = "http://localhost:5710/v1/app/auth/cli/token",
    authorization_endpoint: str = "http://localhost:5800/cli/authorize",
) -> dict[str, object]:
    return {
        "issuer": "http://localhost:5710/v1/app",
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code"],
        "scopes_supported": ["read", "write"],
    }


def metadata_transport(payload: object, status: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/auth/cli/metadata")
        return httpx.Response(status, json=payload)

    return httpx.MockTransport(handler)


def test_pkce_pair_is_s256_of_the_verifier() -> None:
    verifier, challenge = pkce_pair()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    assert challenge == expected
    assert 43 <= len(verifier) <= 128
    assert "=" not in verifier and "=" not in challenge
    assert pkce_pair()[0] != verifier


def test_authorize_url_carries_the_pkce_parameters() -> None:
    url = build_authorize_url(
        "http://localhost:5800/cli/authorize",
        client_id=client_id_for(LOCAL_CONFIG),
        redirect_uri="http://127.0.0.1:41234/callback",
        code_challenge="challenge",
        state="state-value",
    )
    query = parse_qs(urlsplit(url).query)
    # RFC 6749 §4.1.1 lists response_type as REQUIRED on the authorization request.
    assert query["response_type"] == ["code"]
    assert query["client_id"] == ["nulara-cli"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["redirect_uri"] == ["http://127.0.0.1:41234/callback"]
    assert query["state"] == ["state-value"]

    with_query = build_authorize_url(
        "http://localhost:5800/cli/authorize?next=1",
        client_id="nulara-cli",
        redirect_uri="http://127.0.0.1:1/callback",
        code_challenge="c",
        state="s",
    )
    assert with_query.count("?") == 1


def test_metadata_requires_the_token_endpoint_to_match_the_api_origin() -> None:
    payload = metadata_payload(token_endpoint="https://evil.test/v1/app/auth/cli/token")
    with pytest.raises(AuthenticationError, match="must match the API origin"):
        fetch_metadata(LOCAL_CONFIG, transport=metadata_transport(payload))


def test_metadata_rejects_a_plain_http_consent_page_off_loopback() -> None:
    payload = metadata_payload(
        token_endpoint="https://api.example.test/v1/app/auth/cli/token",
        authorization_endpoint="http://app.example.test/cli/authorize",
    )
    with pytest.raises(AuthenticationError, match="plain HTTP"):
        fetch_metadata(REMOTE_CONFIG, transport=metadata_transport(payload))

    relative = metadata_payload(
        token_endpoint="https://api.example.test/v1/app/auth/cli/token",
        authorization_endpoint="/cli/authorize",
    )
    with pytest.raises(AuthenticationError, match="absolute http"):
        fetch_metadata(REMOTE_CONFIG, transport=metadata_transport(relative))


def test_metadata_reports_unusable_documents() -> None:
    with pytest.raises(CliError, match="metadata unavailable"):
        fetch_metadata(LOCAL_CONFIG, transport=metadata_transport({}, status=404))
    with pytest.raises(CliError, match="missing `token_endpoint`"):
        fetch_metadata(
            LOCAL_CONFIG,
            transport=metadata_transport(
                {"authorization_endpoint": "http://localhost:5800/cli/authorize"}
            ),
        )
    with pytest.raises(CliError, match="Invalid CLI login metadata"):
        fetch_metadata(LOCAL_CONFIG, transport=metadata_transport(["not", "a", "map"]))

    def broken(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    with pytest.raises(CliError, match="Cannot reach"):
        fetch_metadata(LOCAL_CONFIG, transport=httpx.MockTransport(broken))


def test_metadata_rejects_a_non_json_body() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>proxy</html>")

    with pytest.raises(CliError, match="Invalid CLI login metadata"):
        fetch_metadata(LOCAL_CONFIG, transport=httpx.MockTransport(handler))


def test_exchange_posts_form_encoded_parameters() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"
        form = parse_qs(request.read().decode("utf-8"))
        assert form["grant_type"] == ["authorization_code"]
        assert form["client_id"] == ["nulara-cli"]
        assert form["code"] == ["auth-code"]
        assert form["code_verifier"] == ["verifier"]
        assert form["redirect_uri"] == ["http://127.0.0.1:41234/callback"]
        return httpx.Response(
            200,
            json={
                "access_token": "nulara_sk_live",
                "token_type": "Bearer",
                "expires_in": 7776000,
                "scopes": ["read", "write"],
                "token_prefix": "nulara_sk_live_prefix",
                "workspace_id": "01a061db-5513-70f1-8f7e-000000000001",
            },
        )

    result = exchange_code(
        LOCAL_CONFIG,
        token_endpoint="http://localhost:5710/v1/app/auth/cli/token",
        code="auth-code",
        code_verifier="verifier",
        redirect_uri="http://127.0.0.1:41234/callback",
        transport=httpx.MockTransport(handler),
    )
    assert result.token == "nulara_sk_live"
    assert result.scopes == ["read", "write"]
    assert result.expires_in == 7776000


def test_exchange_surfaces_rejections_and_bad_payloads() -> None:
    rejected = httpx.MockTransport(
        lambda _request: httpx.Response(400, json={"detail": "CLI_AUTH_GRANT_INVALID"})
    )
    with pytest.raises(AuthenticationError, match="CLI_AUTH_GRANT_INVALID"):
        exchange_code(
            LOCAL_CONFIG,
            token_endpoint="http://localhost:5710/v1/app/auth/cli/token",
            code="c",
            code_verifier="v",
            redirect_uri="http://127.0.0.1:1/callback",
            transport=rejected,
        )

    empty = httpx.MockTransport(lambda _request: httpx.Response(200, json={}))
    with pytest.raises(AuthenticationError, match="Unexpected token exchange"):
        exchange_code(
            LOCAL_CONFIG,
            token_endpoint="http://localhost:5710/v1/app/auth/cli/token",
            code="c",
            code_verifier="v",
            redirect_uri="http://127.0.0.1:1/callback",
            transport=empty,
        )

    def broken(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    with pytest.raises(CliError, match="Token exchange failed"):
        exchange_code(
            LOCAL_CONFIG,
            token_endpoint="http://localhost:5710/v1/app/auth/cli/token",
            code="c",
            code_verifier="v",
            redirect_uri="http://127.0.0.1:1/callback",
            transport=httpx.MockTransport(broken),
        )


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(400, text="proxy blocked"), "proxy blocked"),
        (httpx.Response(400, json=["unexpected"]), "unexpected"),
    ],
)
def test_exchange_reports_non_detail_error_bodies(
    response: httpx.Response, message: str
) -> None:
    with pytest.raises(AuthenticationError, match=message):
        exchange_code(
            LOCAL_CONFIG,
            token_endpoint="http://localhost:5710/v1/app/auth/cli/token",
            code="c",
            code_verifier="v",
            redirect_uri="http://127.0.0.1:1/callback",
            transport=httpx.MockTransport(lambda _request: response),
        )


captured_bounces: list[tuple[int, str]] = []


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Capture the bounce instead of following it to the (absent) app."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        captured_bounces.append((code, newurl))
        return None


def _drive_callback(query: str) -> Callable[[str], None]:
    """Complete the loopback redirect the way the browser would."""

    def visit(url: str) -> None:
        parsed = parse_qs(urlsplit(url).query)
        redirect_uri = parsed["redirect_uri"][0]
        state = parsed.get("state", [""])[0]
        target = f"{redirect_uri}?{query.format(state=state)}"
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(target, timeout=5) as response:  # noqa: S310
                response.read()
        except urllib.error.HTTPError as exc:
            exc.close()

    return visit


def test_await_authorization_code_accepts_the_matching_state() -> None:
    captured_bounces.clear()
    codes: dict[str, str] = {}

    def announce(url: str) -> None:
        threading.Thread(
            target=_drive_callback("code=granted&state={state}"),
            args=(url,),
            daemon=True,
        ).start()

    code, redirect_uri = await_authorization_code(
        "http://localhost:5800/cli/authorize",
        client_id="nulara-cli",
        code_challenge="challenge",
        open_browser=False,
        timeout_seconds=15,
        announce=announce,
    )
    codes["code"] = code
    assert codes["code"] == "granted"
    assert redirect_uri.startswith("http://127.0.0.1:")
    assert redirect_uri.endswith("/callback")
    # The browser is bounced back to the product page, never left on loopback.
    assert captured_bounces == [
        (302, "http://localhost:5800/cli/authorize?result=granted")
    ]


@pytest.mark.parametrize(
    ("query", "message", "bounce_result"),
    [
        ("code=granted&state=wrong-state", "state_mismatch", "failed"),
        ("error=access_denied&state={state}", "access_denied", "denied"),
        ("error=server_error&state={state}", "server_error", "failed"),
        ("state={state}", "missing_code", "failed"),
    ],
)
def test_await_authorization_code_rejects_bad_redirects(
    query: str, message: str, bounce_result: str
) -> None:
    captured_bounces.clear()

    def announce(url: str) -> None:
        threading.Thread(
            target=_drive_callback(query), args=(url,), daemon=True
        ).start()

    with pytest.raises(AuthenticationError, match=message):
        await_authorization_code(
            "http://localhost:5800/cli/authorize",
            client_id="nulara-cli",
            code_challenge="challenge",
            open_browser=False,
            timeout_seconds=15,
            announce=announce,
        )

    bounced_to = f"http://localhost:5800/cli/authorize?result={bounce_result}"
    assert captured_bounces == [(302, bounced_to)]


def test_await_authorization_code_ignores_unrelated_paths_and_times_out() -> None:
    def announce(url: str) -> None:
        def visit() -> None:
            redirect_uri = parse_qs(urlsplit(url).query)["redirect_uri"][0]
            root = redirect_uri.replace("/callback", "/favicon.ico")
            with contextlib.suppress(urllib.error.HTTPError):
                urllib.request.urlopen(root, timeout=5)  # noqa: S310

        threading.Thread(target=visit, daemon=True).start()

    with pytest.raises(AuthenticationError, match="Timed out"):
        await_authorization_code(
            "http://localhost:5800/cli/authorize",
            client_id="nulara-cli",
            code_challenge="challenge",
            open_browser=False,
            timeout_seconds=1.5,
            announce=announce,
        )


def test_await_authorization_code_times_out_despite_an_idle_connection() -> None:
    # A connection that never sends a request line (a browser preconnect, a port
    # scanner) must not pin the single-threaded server past the login timeout.
    idle: list[socket.socket] = []

    def announce(url: str) -> None:
        redirect = urlsplit(parse_qs(urlsplit(url).query)["redirect_uri"][0])
        idle.append(socket.create_connection((redirect.hostname, redirect.port)))

    outcome: list[BaseException] = []

    def login() -> None:
        try:
            await_authorization_code(
                "http://localhost:5800/cli/authorize",
                client_id="nulara-cli",
                code_challenge="challenge",
                open_browser=False,
                timeout_seconds=0.5,
                announce=announce,
            )
        except BaseException as exc:  # noqa: BLE001 — handed to the assertion
            outcome.append(exc)

    worker = threading.Thread(target=login, daemon=True)
    worker.start()
    try:
        worker.join(timeout=20)
        assert not worker.is_alive(), "login ignored its timeout"
    finally:
        for connection in idle:
            connection.close()
    assert len(outcome) == 1
    assert isinstance(outcome[0], AuthenticationError)
    assert "Timed out" in str(outcome[0])


def test_bind_loopback_callback_serves_on_a_loopback_literal() -> None:
    server, redirect_uri = bind_loopback_callback(http.server.BaseHTTPRequestHandler)
    try:
        host, port = server.server_address[0], server.server_address[1]
    finally:
        server.server_close()
    assert host in {"127.0.0.1", "::1"}
    assert 1024 < port < 65536
    # RFC 8252 §7.3: the IP literal, IPv6 in brackets, and always an explicit port.
    assert redirect_uri in {
        f"http://127.0.0.1:{port}/callback",
        f"http://[::1]:{port}/callback",
    }


def test_metadata_rejects_a_consent_page_on_an_unrelated_domain() -> None:
    payload = metadata_payload(
        token_endpoint="https://api.example.test/v1/app/auth/cli/token",
        authorization_endpoint="https://phishing.evil.test/cli/authorize",
    )
    with pytest.raises(AuthenticationError, match="same domain as the API"):
        fetch_metadata(REMOTE_CONFIG, transport=metadata_transport(payload))


def test_metadata_accepts_a_sibling_consent_host() -> None:
    payload = metadata_payload(
        token_endpoint="https://api.example.test/v1/app/auth/cli/token",
        authorization_endpoint="https://app.example.test/cli/authorize",
    )
    assert fetch_metadata(REMOTE_CONFIG, transport=metadata_transport(payload))


def test_run_browser_login_drives_the_full_flow(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/auth/cli/metadata"):
            return httpx.Response(200, json=metadata_payload())
        form = parse_qs(request.read().decode("utf-8"))
        assert form["code"] == ["granted"]
        assert len(form["code_verifier"][0]) >= 43
        return httpx.Response(
            200,
            json={
                "access_token": "nulara_sk_flow",
                "expires_in": 60,
                "scopes": ["read"],
                "token_prefix": "nulara_sk_flow_prefix",
                "workspace_id": "01a061db-5513-70f1-8f7e-000000000001",
            },
        )

    opened: list[str] = []

    def fake_open(url: str) -> bool:
        opened.append(url)
        threading.Thread(
            target=_drive_callback("code=granted&state={state}"),
            args=(url,),
            daemon=True,
        ).start()
        return True

    monkeypatch.setattr("nulara.core.oauth.webbrowser.open", fake_open)

    result = run_browser_login(
        LOCAL_CONFIG,
        timeout_seconds=15,
        transport=httpx.MockTransport(handler),
    )
    assert result.token == "nulara_sk_flow"
    assert opened and "code_challenge_method=S256" in opened[0]


def test_client_id_names_the_product_not_the_package() -> None:
    assert client_id_for(LOCAL_CONFIG) == "nulara-cli"
    assert client_id_for(REMOTE_CONFIG) == "nulara-cli"


def test_token_response_without_a_workspace_is_refused() -> None:
    # The workspace decides which keyring slot the token is filed under, so a
    # response that omits it cannot be stored — better a named error than a
    # credential saved under the wrong workspace.
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "access_token": "nulara_sk_live",
                "expires_in": 60,
                "scopes": ["read"],
                "token_prefix": "nulara_sk_live_prefix",
            },
        )

    transport = httpx.MockTransport(handler)
    with pytest.raises(AuthenticationError, match="did not name a workspace"):
        exchange_code(
            LOCAL_CONFIG,
            token_endpoint="http://localhost:5710/v1/app/auth/cli/token",
            code="auth-code",
            code_verifier="verifier",
            redirect_uri="http://127.0.0.1:41234/callback",
            transport=transport,
        )
