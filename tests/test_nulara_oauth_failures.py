"""Nulara OAuth discovery and terminal device-grant failures."""

import base64
import hashlib
import io
import socket as socket_module
import socketserver
from dataclasses import replace
from typing import cast
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from support import NULARA_DEV

from nulara.core import oauth as o
from nulara.core.config import Surface, product_config
from nulara.core.errors import AuthenticationError, CliError


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return product_config(
        NULARA_DEV,
        surface=Surface.DEVELOPMENT,
        api_url="https://api.nulara.example/v1/app",
    )


def metadata(config):
    return {
        "authorization_endpoint": "https://app.nulara.example/cli/authorize",
        "token_endpoint": config.base_url + "/auth/cli/token",
        "device_authorization_endpoint": config.base_url + "/auth/cli/device",
    }


def token():
    return {
        "access_token": "synthetic-token",
        "workspace_id": "one",
        "scopes": ["read"],
        "expires_in": 600,
    }


def authorization():
    return o.DeviceAuthorization(
        "synthetic-device",
        "BCDF-GHJK",
        "https://app.nulara.example/cli/device",
        "https://app.nulara.example/cli/device?user_code=BCDF-GHJK",
        600,
        1,
    )


def test_pkce_verifier_matches_public_challenge_and_query():
    verifier, challenge = o.pkce_pair()
    assert challenge == base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    assert len(verifier) >= 43
    url = o.build_authorize_url(
        "https://app.nulara.example/cli/authorize?locale=en",
        client_id="nulara-cli",
        redirect_uri="http://127.0.0.1:49152/callback",
        code_challenge=challenge,
        state="synthetic-state",
    )
    params = parse_qs(urlsplit(url).query)
    assert params["locale"] == ["en"]
    assert params["response_type"] == ["code"]
    assert params["code_challenge_method"] == ["S256"]
    assert verifier not in url


@pytest.mark.parametrize(
    "body",
    [[], {}, {"authorization_endpoint": "https://app.nulara.example/cli/authorize"}],
)
def test_unusable_discovery_document(config, body):
    with pytest.raises(CliError, match="metadata"):
        o.fetch_metadata(
            config,
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body)),
        )


@pytest.mark.parametrize("status,body", [(503, "unavailable"), (200, "{broken")])
def test_discovery_http_and_json_failures(config, status, body):
    with pytest.raises(CliError, match="metadata"):
        o.fetch_metadata(
            config,
            transport=httpx.MockTransport(lambda _: httpx.Response(status, text=body)),
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("token_endpoint", "https://foreign.example/token"),
        ("authorization_endpoint", "https://foreign.example/authorize"),
        ("authorization_endpoint", "http://app.nulara.example/authorize"),
        (
            "authorization_endpoint",
            "https://user:synthetic@app.nulara.example/authorize",
        ),
        ("authorization_endpoint", "https://[broken"),
        ("authorization_endpoint", "https://app.nulara.example:0/authorize"),
        ("authorization_endpoint", "https://app.nulara.example/with\ncontrol"),
    ],
)
def test_discovery_rejects_untrusted_endpoints(config, field, value):
    with pytest.raises(AuthenticationError):
        o.fetch_metadata(
            config,
            transport=httpx.MockTransport(
                lambda _: httpx.Response(200, json=metadata(config) | {field: value})
            ),
        )


@pytest.mark.parametrize("value", [None, "", "https://foreign.example/device"])
def test_device_endpoint_missing_or_foreign(config, value):
    with pytest.raises(CliError):
        o.device_authorization_endpoint(
            config, {"device_authorization_endpoint": value}
        )


@pytest.mark.parametrize("call", ["metadata", "exchange", "device", "poll"])
def test_oauth_transport_failures_are_typed(config, call):
    def denied(request):
        raise httpx.ConnectError("synthetic unavailable", request=request)

    transport = httpx.MockTransport(denied)
    with pytest.raises(CliError):
        if call == "metadata":
            o.fetch_metadata(config, transport=transport)
        elif call == "exchange":
            o.exchange_code(
                config,
                token_endpoint=metadata(config)["token_endpoint"],
                code="synthetic",
                code_verifier="synthetic",
                redirect_uri="http://127.0.0.1:49152/callback",
                transport=transport,
            )
        elif call == "device":
            o.request_device_authorization(
                config,
                endpoint=metadata(config)["device_authorization_endpoint"],
                transport=transport,
            )
        else:
            o.poll_device_token(
                config,
                token_endpoint=metadata(config)["token_endpoint"],
                authorization=authorization(),
                transport=transport,
                sleep=lambda _: None,
            )


@pytest.mark.parametrize(
    "body", [b"", b"invalid", b"[]", b'{"detail":"synthetic denied"}']
)
@pytest.mark.parametrize("call", ["exchange", "device"])
def test_oauth_rejection_body_is_actionable(config, body, call):
    transport = httpx.MockTransport(lambda _: httpx.Response(400, content=body))
    with pytest.raises(AuthenticationError, match="rejected"):
        if call == "exchange":
            o.exchange_code(
                config,
                token_endpoint=metadata(config)["token_endpoint"],
                code="synthetic",
                code_verifier="synthetic",
                redirect_uri="http://127.0.0.1:49152/callback",
                transport=transport,
            )
        else:
            o.request_device_authorization(
                config,
                endpoint=metadata(config)["device_authorization_endpoint"],
                transport=transport,
            )


@pytest.mark.parametrize("body", [[], {}, {"access_token": "synthetic-token"}])
def test_token_response_requires_object_token_and_workspace(config, body):
    with pytest.raises(AuthenticationError):
        o.exchange_code(
            config,
            token_endpoint=metadata(config)["token_endpoint"],
            code="synthetic",
            code_verifier="synthetic",
            redirect_uri="http://127.0.0.1:49152/callback",
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body)),
        )


@pytest.mark.parametrize("missing", ["device_code", "user_code", "verification_uri"])
def test_device_response_requires_all_codes_and_page(config, missing):
    body = {
        "device_code": "synthetic-device",
        "user_code": "BCDF-GHJK",
        "verification_uri": "https://app.nulara.example/cli/device",
    }
    del body[missing]
    with pytest.raises(AuthenticationError, match=missing):
        o.request_device_authorization(
            config,
            endpoint=metadata(config)["device_authorization_endpoint"],
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body)),
        )


@pytest.mark.parametrize(
    "detail,match",
    [
        (o.DEVICE_DENIED_DETAIL, "access_denied"),
        (o.DEVICE_EXPIRED_DETAIL, "expired"),
        ("unexpected", "rejected"),
    ],
)
def test_polling_stops_on_terminal_errors(config, detail, match):
    with pytest.raises(AuthenticationError, match=match):
        o.poll_device_token(
            config,
            token_endpoint=metadata(config)["token_endpoint"],
            authorization=authorization(),
            transport=httpx.MockTransport(
                lambda _: httpx.Response(400, json={"detail": detail})
            ),
            sleep=lambda _: None,
        )


def test_expired_device_code_is_never_polled(config):
    with pytest.raises(AuthenticationError, match="expired"):
        o.poll_device_token(
            config,
            token_endpoint=metadata(config)["token_endpoint"],
            authorization=replace(authorization(), expires_in=0),
            transport=httpx.MockTransport(
                lambda _: pytest.fail("expired code must not be sent")
            ),
            sleep=lambda _: None,
        )


def test_rate_limited_device_flow_can_complete_without_launching_real_browser(
    config, monkeypatch
):
    calls, opened, waited = [], [], []

    def handle(request):
        calls.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=metadata(config))
        assert parse_qs(request.content.decode())["client_id"] == ["nulara-cli"]
        if request.url.path.endswith("/device"):
            return httpx.Response(
                200,
                json={
                    "device_code": "synthetic-device",
                    "user_code": "BCDF-GHJK",
                    "verification_uri": "https://app.nulara.example/cli/device",
                    "verification_uri_complete": "https://app.nulara.example/cli/device?user_code=BCDF-GHJK",
                },
            )
        return (
            httpx.Response(429, json={"detail": "rate limit"})
            if len(calls) == 3
            else httpx.Response(200, json=token())
        )

    monkeypatch.setattr(o.webbrowser, "open", opened.append)
    result = o.run_device_login(
        config, transport=httpx.MockTransport(handle), sleep=waited.append
    )
    assert result.workspace_id == "one"
    assert waited == [5, 5]
    assert opened == ["https://app.nulara.example/cli/device?user_code=BCDF-GHJK"]


@pytest.mark.parametrize("available", [False, True])
def test_browser_detection_handles_missing_controller(monkeypatch, available):
    def get():
        if not available:
            raise o.webbrowser.Error("synthetic no browser")
        return object()

    monkeypatch.setattr(o.webbrowser, "get", get)
    assert o.browser_is_available() is available


def test_browser_login_redeems_matching_pkce_verifier(config, monkeypatch):
    challenge = []

    def consent(endpoint, **kwargs):
        challenge.append(kwargs["code_challenge"])
        assert kwargs["client_id"] == "nulara-cli"
        assert kwargs["open_browser"] is False
        return "synthetic-code", "http://127.0.0.1:49152/callback"

    def handle(request):
        if request.method == "GET":
            return httpx.Response(200, json=metadata(config))
        fields = parse_qs(request.content.decode())
        verifier = fields["code_verifier"][0]
        assert challenge == [
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        ]
        assert fields["code"] == ["synthetic-code"]
        return httpx.Response(200, json=token())

    monkeypatch.setattr(o, "await_authorization_code", consent)
    assert (
        o.run_browser_login(
            config, open_browser=False, transport=httpx.MockTransport(handle)
        ).workspace_id
        == "one"
    )


@pytest.mark.parametrize(
    "query,result",
    [
        ("state=expected&code=synthetic-code", {"code": "synthetic-code"}),
        ("state=wrong&code=synthetic-code", {"error": "state_mismatch"}),
        ("state=expected&error=access_denied", {"error": "access_denied"}),
        ("state=expected&error=other", {"error": "other"}),
        ("state=expected", {"error": "missing_code"}),
        ("state=%C3%BC&code=synthetic-code", {"error": "state_mismatch"}),
    ],
)
def test_callback_http_request_returns_consent_result(query, result):
    class Socket:
        def __init__(self):
            self.output = bytearray()

        def makefile(self, *args):
            return io.BytesIO(
                f"GET /callback?{query} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n".encode()
            )

        def sendall(self, data):
            self.output.extend(data)

        def settimeout(self, value):
            self.timeout = value

    state = {}
    handler = type(
        "NularaCallback",
        (o._CallbackHandler,),
        {
            "expected_state": "expected",
            "consent_url": "https://app.nulara.example/cli/authorize?locale=en",
            "result": state,
        },
    )
    socket = Socket()
    handler(
        cast(socket_module.socket, socket),
        ("127.0.0.1", 49152),
        cast(socketserver.BaseServer, object()),
    )
    assert state == result
    assert b"302 Found" in socket.output
    assert b"locale=en&result=" in socket.output
    assert b"synthetic-code" not in socket.output


def test_callback_ignores_unrelated_paths():
    class Socket:
        def __init__(self):
            self.output = bytearray()

        def makefile(self, *args):
            return io.BytesIO(b"GET /favicon.ico HTTP/1.0\r\n\r\n")

        def sendall(self, data):
            self.output.extend(data)

        def settimeout(self, value):
            self.timeout = value

    state = {}
    handler = type("NularaCallback", (o._CallbackHandler,), {"result": state})
    socket = Socket()
    handler(
        cast(socket_module.socket, socket),
        ("127.0.0.1", 49152),
        cast(socketserver.BaseServer, object()),
    )
    assert state == {}
    assert b"404 Not Found" in socket.output


def test_loopback_binding_reports_failure_after_both_families(monkeypatch):
    attempts = []

    def unavailable(self, address, handler):
        attempts.append(address)
        raise OSError("synthetic no local socket")

    monkeypatch.setattr(o.http.server.HTTPServer, "__init__", unavailable)
    with pytest.raises(CliError, match="Could not open a loopback port"):
        o.bind_loopback_callback(o._CallbackHandler)
    assert attempts == [("127.0.0.1", 0), ("::1", 0)]


@pytest.mark.parametrize("outcome", ["success", "denied", "timeout"])
def test_browser_callback_wait_closes_listener_on_every_outcome(monkeypatch, outcome):
    class Listener:
        def __init__(self):
            self.closed = []

        def serve_forever(self):
            pass

        def shutdown(self):
            self.closed.append("shutdown")

        def server_close(self):
            self.closed.append("close")

    listener = Listener()
    handlers, opened, announced = [], [], []

    def bind(handler):
        handlers.append(handler)
        return listener, "http://127.0.0.1:49152/callback"

    def announce(url):
        announced.append(url)
        params = parse_qs(urlsplit(url).query)
        assert params["client_id"] == ["nulara-cli"]
        assert handlers[0].expected_state == params["state"][0]
        if outcome != "timeout":
            handlers[0].result.update(
                {"code": "synthetic-code"}
                if outcome == "success"
                else {"error": "access_denied"}
            )

    monkeypatch.setattr(o, "bind_loopback_callback", bind)
    monkeypatch.setattr(o.webbrowser, "open", opened.append)
    if outcome == "success":
        assert o.await_authorization_code(
            "https://app.nulara.example/cli/authorize",
            client_id="nulara-cli",
            code_challenge="synthetic-challenge",
            announce=announce,
        ) == ("synthetic-code", "http://127.0.0.1:49152/callback")
    else:
        with pytest.raises(
            AuthenticationError,
            match="Timed out" if outcome == "timeout" else "not granted",
        ):
            o.await_authorization_code(
                "https://app.nulara.example/cli/authorize",
                client_id="nulara-cli",
                code_challenge="synthetic-challenge",
                announce=announce,
                open_browser=False,
                timeout_seconds=0 if outcome == "timeout" else 1,
            )
    assert listener.closed == ["shutdown", "close"]
    assert bool(opened) == (outcome == "success")
    assert len(announced) == 1
