import httpx
import pytest
from support import NULARA

from nulara.core.config import ProductConfig, Surface
from nulara.core.errors import AuthenticationError, CliError
from nulara.core.oauth import (
    DEVICE_DEFAULT_INTERVAL,
    DEVICE_GRANT_TYPE,
    DeviceAuthorization,
    browser_is_available,
    device_authorization_endpoint,
    poll_device_token,
    request_device_authorization,
    run_device_login,
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
DEVICE_ENDPOINT = "http://localhost:5710/v1/app/auth/cli/device-authorization"
TOKEN_ENDPOINT = "http://localhost:5710/v1/app/auth/cli/token"


def device_payload(**overrides: object) -> dict[str, object]:
    return {
        "device_code": "device-secret",
        "user_code": "BCDF-GHJK",
        "verification_uri": "http://localhost:5800/cli/device",
        "verification_uri_complete": (
            "http://localhost:5800/cli/device?user_code=BCDF-GHJK"
        ),
        "expires_in": 600,
        "interval": 5,
        **overrides,
    }


def metadata_payload(**overrides: object) -> dict[str, object]:
    return {
        "issuer": "http://localhost:5710/v1/app",
        "authorization_endpoint": "http://localhost:5800/cli/authorize",
        "device_authorization_endpoint": DEVICE_ENDPOINT,
        "token_endpoint": TOKEN_ENDPOINT,
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", DEVICE_GRANT_TYPE],
        "scopes_supported": ["read", "write"],
        **overrides,
    }


def authorization(**overrides: object) -> DeviceAuthorization:
    values: dict[str, object] = {
        "device_code": "device-secret",
        "user_code": "BCDF-GHJK",
        "verification_uri": "http://localhost:5800/cli/device",
        "verification_uri_complete": "http://localhost:5800/cli/device?user_code=X",
        "expires_in": 600,
        "interval": 1,
        **overrides,
    }
    return DeviceAuthorization(**values)  # type: ignore[arg-type]


def test_device_endpoint_must_come_from_the_document_and_match_the_api_origin() -> None:
    assert (
        device_authorization_endpoint(LOCAL_CONFIG, metadata_payload())
        == DEVICE_ENDPOINT
    )

    with pytest.raises(CliError, match="does not offer device login"):
        device_authorization_endpoint(
            LOCAL_CONFIG, metadata_payload(device_authorization_endpoint=None)
        )
    with pytest.raises(AuthenticationError, match="must match the API origin"):
        device_authorization_endpoint(
            LOCAL_CONFIG,
            metadata_payload(device_authorization_endpoint="https://evil.test/device"),
        )


def test_request_device_authorization_sends_the_client_id_and_reads_the_codes() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = request.content.decode()
        return httpx.Response(201, json=device_payload())

    result = request_device_authorization(
        LOCAL_CONFIG,
        endpoint=DEVICE_ENDPOINT,
        transport=httpx.MockTransport(handler),
    )

    assert seen["url"] == DEVICE_ENDPOINT
    assert "client_id=nulara-cli" in str(seen["body"])
    assert result.device_code == "device-secret"
    assert result.user_code == "BCDF-GHJK"
    assert result.interval == 5
    assert result.expires_in == 600


def test_request_device_authorization_defaults_a_missing_interval() -> None:
    payload = device_payload()
    del payload["interval"]
    del payload["expires_in"]
    del payload["verification_uri_complete"]

    result = request_device_authorization(
        LOCAL_CONFIG,
        endpoint=DEVICE_ENDPOINT,
        transport=httpx.MockTransport(lambda _: httpx.Response(201, json=payload)),
    )

    assert result.interval == int(DEVICE_DEFAULT_INTERVAL)
    assert result.expires_in == 600
    # Without the convenience URL the plain verification page is what we show.
    assert result.verification_uri_complete == result.verification_uri


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        ({"device_code": ""}, "missing `device_code`"),
        ({"user_code": None}, "missing `user_code`"),
        ({"verification_uri": ""}, "missing `verification_uri`"),
    ],
)
def test_request_device_authorization_rejects_an_incomplete_response(
    payload: dict[str, object], match: str
) -> None:
    with pytest.raises(AuthenticationError, match=match):
        request_device_authorization(
            LOCAL_CONFIG,
            endpoint=DEVICE_ENDPOINT,
            transport=httpx.MockTransport(
                lambda _: httpx.Response(201, json=device_payload(**payload))
            ),
        )


def test_request_device_authorization_refuses_a_foreign_verification_page() -> None:
    # A tampered response must not be able to send the user to a look-alike
    # sign-in page: the page has to belong to the API's own domain.
    with pytest.raises(AuthenticationError, match="same domain as the API"):
        request_device_authorization(
            REMOTE_CONFIG,
            endpoint="https://api.example.test/v1/app/auth/cli/device-authorization",
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    201,
                    json=device_payload(
                        verification_uri="https://evil.test/cli/device"
                    ),
                )
            ),
        )


def test_request_device_authorization_refuses_a_plain_http_page_off_loopback() -> None:
    with pytest.raises(AuthenticationError, match="plain-HTTP page"):
        request_device_authorization(
            REMOTE_CONFIG,
            endpoint="https://api.example.test/v1/app/auth/cli/device-authorization",
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    201,
                    json=device_payload(
                        verification_uri="http://api.example.test/cli/device"
                    ),
                )
            ),
        )


def test_request_device_authorization_surfaces_a_rejection() -> None:
    with pytest.raises(AuthenticationError, match="Device login rejected"):
        request_device_authorization(
            LOCAL_CONFIG,
            endpoint=DEVICE_ENDPOINT,
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    400, json={"detail": "CLI_AUTH_CLIENT_UNKNOWN"}
                )
            ),
        )


def test_request_device_authorization_reports_an_unusable_body() -> None:
    with pytest.raises(AuthenticationError, match="Unexpected device authorization"):
        request_device_authorization(
            LOCAL_CONFIG,
            endpoint=DEVICE_ENDPOINT,
            transport=httpx.MockTransport(lambda _: httpx.Response(201, json=[1, 2])),
        )


def test_request_device_authorization_wraps_a_transport_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(CliError, match="could not be started"):
        request_device_authorization(
            LOCAL_CONFIG,
            endpoint=DEVICE_ENDPOINT,
            transport=httpx.MockTransport(handler),
        )


def test_polling_keeps_going_while_pending_then_returns_the_token() -> None:
    answers = [
        httpx.Response(400, json={"detail": "CLI_AUTH_DEVICE_PENDING"}),
        httpx.Response(429, json={"detail": "RATE_LIMITED"}),
        httpx.Response(
            200,
            json={
                "access_token": "nulara_sk_device",
                "token_prefix": "nulara_sk_abc",
                "scopes": ["read", "write"],
                "expires_in": 7776000,
                "workspace_id": "01a061db-5513-70f1-8f7e-000000000001",
            },
        ),
    ]
    forms: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        forms.append(request.content.decode())
        return answers.pop(0)

    result = poll_device_token(
        LOCAL_CONFIG,
        token_endpoint=TOKEN_ENDPOINT,
        authorization=authorization(),
        transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
    )

    assert result.token == "nulara_sk_device"
    assert result.scopes == ["read", "write"]
    assert len(forms) == 3
    assert f"grant_type={DEVICE_GRANT_TYPE.replace(':', '%3A')}" in forms[0]
    assert "device_code=device-secret" in forms[0]


def test_slow_down_widens_the_interval_the_client_waits() -> None:
    # RFC 8628 §3.5: the client obeys the widened interval rather than hammering.
    answers = [
        httpx.Response(400, json={"detail": "CLI_AUTH_DEVICE_SLOW_DOWN"}),
        httpx.Response(
            200,
            json={
                "access_token": "nulara_sk_ok",
                "workspace_id": "01a061db-5513-70f1-8f7e-000000000001",
            },
        ),
    ]
    waits: list[float] = []

    result = poll_device_token(
        LOCAL_CONFIG,
        token_endpoint=TOKEN_ENDPOINT,
        authorization=authorization(interval=5),
        transport=httpx.MockTransport(lambda _: answers.pop(0)),
        sleep=waits.append,
    )

    assert result.token == "nulara_sk_ok"
    assert waits == [5.0, 10.0]


@pytest.mark.parametrize(
    ("detail", "match"),
    [
        ("CLI_AUTH_DEVICE_DENIED", "not granted"),
        ("CLI_AUTH_DEVICE_EXPIRED", "expired"),
        ("CLI_AUTH_GRANT_INVALID", "Device login rejected"),
    ],
)
def test_polling_stops_on_a_terminal_answer(detail: str, match: str) -> None:
    with pytest.raises(AuthenticationError, match=match):
        poll_device_token(
            LOCAL_CONFIG,
            token_endpoint=TOKEN_ENDPOINT,
            authorization=authorization(),
            transport=httpx.MockTransport(
                lambda _: httpx.Response(400, json={"detail": detail})
            ),
            sleep=lambda _: None,
        )


def test_polling_gives_up_when_the_code_lifetime_is_over() -> None:
    with pytest.raises(AuthenticationError, match="expired before it was approved"):
        poll_device_token(
            LOCAL_CONFIG,
            token_endpoint=TOKEN_ENDPOINT,
            authorization=authorization(expires_in=0),
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    400, json={"detail": "CLI_AUTH_DEVICE_PENDING"}
                )
            ),
            sleep=lambda _: None,
        )


def test_polling_wraps_a_transport_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(CliError, match="Device login failed"):
        poll_device_token(
            LOCAL_CONFIG,
            token_endpoint=TOKEN_ENDPOINT,
            authorization=authorization(),
            transport=httpx.MockTransport(handler),
            sleep=lambda _: None,
        )


def test_run_device_login_discovers_announces_and_polls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[str] = []
    monkeypatch.setattr(
        "nulara.core.oauth.webbrowser.open", lambda url: opened.append(url) or True
    )
    announced: list[DeviceAuthorization] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/auth/cli/metadata"):
            return httpx.Response(200, json=metadata_payload())
        if request.url.path.endswith("/auth/cli/device-authorization"):
            return httpx.Response(201, json=device_payload())
        return httpx.Response(
            200,
            json={
                "access_token": "nulara_sk_device",
                "workspace_id": "01a061db-5513-70f1-8f7e-000000000001",
            },
        )

    result = run_device_login(
        LOCAL_CONFIG,
        transport=httpx.MockTransport(handler),
        announce=announced.append,
        sleep=lambda _: None,
    )

    assert result.token == "nulara_sk_device"
    assert [a.user_code for a in announced] == ["BCDF-GHJK"]
    assert opened == ["http://localhost:5800/cli/device?user_code=BCDF-GHJK"]


def test_run_device_login_can_keep_its_hands_off_the_browser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "nulara.core.oauth.webbrowser.open",
        lambda url: pytest.fail("must not open a browser"),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/auth/cli/metadata"):
            return httpx.Response(200, json=metadata_payload())
        if request.url.path.endswith("/auth/cli/device-authorization"):
            return httpx.Response(201, json=device_payload())
        return httpx.Response(
            200,
            json={
                "access_token": "nulara_sk_device",
                "workspace_id": "01a061db-5513-70f1-8f7e-000000000001",
            },
        )

    result = run_device_login(
        LOCAL_CONFIG,
        open_browser=False,
        transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
    )

    assert result.token == "nulara_sk_device"


def test_browser_availability_decides_which_flow_fits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import webbrowser

    monkeypatch.setattr("nulara.core.oauth.webbrowser.get", lambda: object())
    assert browser_is_available() is True

    def raise_error() -> None:
        raise webbrowser.Error("no browser on a remote shell")

    monkeypatch.setattr("nulara.core.oauth.webbrowser.get", raise_error)
    assert browser_is_available() is False
