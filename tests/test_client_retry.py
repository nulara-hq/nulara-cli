"""Retries only what is safe to send again, and honours the server's pause."""

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path

import httpx
import pytest
from support import NULARA

from nulara.core import client as client_module
from nulara.core.client import MAX_RETRIES, ApiClient
from nulara.core.config import DEFAULT_TIMEOUT, ProductConfig, Surface, product_config
from nulara.core.errors import (
    ApiError,
    ConfigurationError,
    NetworkError,
    RateLimitError,
)

CONFIG = ProductConfig(
    product=NULARA,
    surface=Surface.DEVELOPMENT,
    base_url="https://api.example.test/v1/app",
    token_env="NULARA_API_TOKEN",
    keyring_service="nulara-cli",
)


def scripted(
    *answers: httpx.Response | Exception,
) -> tuple[Callable[[httpx.Request], httpx.Response], list[httpx.Request]]:
    """A transport handler that answers each request with the next entry."""
    sent: list[httpx.Request] = []
    remaining = list(answers)

    def handler(request: httpx.Request) -> httpx.Response:
        request.read()
        sent.append(request)
        answer = remaining.pop(0) if len(remaining) > 1 else remaining[0]
        if isinstance(answer, Exception):
            raise answer
        return answer

    return handler, sent


def client(handler: Callable[[httpx.Request], httpx.Response]) -> ApiClient:
    return ApiClient(CONFIG, "token", transport=httpx.MockTransport(handler))


def test_a_get_is_retried_through_transient_server_errors(retry_pauses) -> None:
    handler, sent = scripted(
        httpx.Response(503), httpx.Response(502), httpx.Response(200, json={"ok": 1})
    )
    with client(handler) as api:
        assert api.request("GET", "/passports") == {"ok": 1}
    assert len(sent) == 3
    assert len(retry_pauses) == 2
    assert all(0 <= pause <= client_module.RETRY_MAX_SECONDS for pause in retry_pauses)


def test_a_post_is_not_sent_twice_on_a_server_error(retry_pauses) -> None:
    handler, sent = scripted(httpx.Response(503, json={"detail": "BUSY"}))
    with client(handler) as api, pytest.raises(ApiError) as raised:
        api.request("POST", "/products", json={"name": "Bottle"})
    assert len(sent) == 1
    assert retry_pauses == []
    assert raised.value.code == "BUSY"


def test_a_rate_limited_post_waits_the_servers_pause(retry_pauses) -> None:
    handler, sent = scripted(
        httpx.Response(429, headers={"Retry-After": "2"}, json={"detail": "x"}),
        httpx.Response(201, json={"id": "product-1"}),
    )
    with client(handler) as api:
        assert api.request("POST", "/products", json={"name": "Bottle"}) == {
            "id": "product-1"
        }
    assert [request.content for request in sent] == [b'{"name":"Bottle"}'] * 2
    assert retry_pauses == [2.0]


def test_a_lasting_rate_limit_exits_with_its_own_code(retry_pauses) -> None:
    handler, sent = scripted(
        httpx.Response(
            429, headers={"Retry-After": "1"}, json={"detail": "RATE_LIMITED"}
        )
    )
    with client(handler) as api, pytest.raises(RateLimitError) as raised:
        api.request("GET", "/passports")
    assert len(sent) == MAX_RETRIES + 1
    assert retry_pauses == [1.0] * MAX_RETRIES
    assert raised.value.exit_code == 11
    assert raised.value.as_payload() == {
        "error": "rate_limit_error",
        "message": "API rate limit reached (429: RATE_LIMITED)",
        "exit_code": 11,
        "status_code": 429,
        "code": "RATE_LIMITED",
        "detail": "RATE_LIMITED",
        "retry_after": 1.0,
    }


def test_a_long_server_pause_is_reported_instead_of_waited_out(retry_pauses) -> None:
    handler, sent = scripted(
        httpx.Response(
            429, headers={"Retry-After": "120"}, json={"detail": "RATE_LIMITED"}
        )
    )
    with client(handler) as api, pytest.raises(RateLimitError) as raised:
        api.request("GET", "/passports")
    assert len(sent) == 1
    assert retry_pauses == []
    assert raised.value.retry_after == 120.0


def test_retry_after_accepts_an_http_date_and_ignores_garbage() -> None:
    later = datetime.now(UTC) + timedelta(seconds=30)
    seconds = client_module._retry_after_seconds(
        {"retry-after": format_datetime(later, usegmt=True)}
    )
    assert seconds is not None and 25 <= seconds <= 30
    past = datetime.now(UTC) - timedelta(seconds=30)
    assert (
        client_module._retry_after_seconds(
            {"retry-after": format_datetime(past, usegmt=True)}
        )
        == 0.0
    )
    naive = "Wed, 21 Oct 2015 07:28:00 -0000"
    assert client_module._retry_after_seconds({"retry-after": naive}) == 0.0
    assert client_module._retry_after_seconds({"retry-after": "soon"}) is None
    assert client_module._retry_after_seconds({}) is None


def test_garbage_retry_after_falls_back_to_backoff(retry_pauses) -> None:
    handler, _sent = scripted(
        httpx.Response(429, headers={"Retry-After": "soon"}),
        httpx.Response(200, json=[]),
    )
    with client(handler) as api:
        assert api.request("GET", "/passports") == []
    assert len(retry_pauses) == 1
    assert retry_pauses[0] <= client_module.RETRY_BASE_SECONDS


def test_a_dropped_connection_is_retried_only_for_reads(retry_pauses) -> None:
    handler, sent = scripted(
        httpx.ConnectError("synthetic refused"),
        httpx.Response(200, json=[]),
    )
    with client(handler) as api:
        assert api.request("GET", "/passports") == []
    assert len(sent) == 2

    handler, sent = scripted(httpx.ConnectError("synthetic refused"))
    with client(handler) as api, pytest.raises(NetworkError) as raised:
        api.request("POST", "/products", json={})
    assert len(sent) == 1
    assert raised.value.exit_code == 10
    assert raised.value.as_payload()["error"] == "network_error"


def test_a_lasting_network_failure_exits_with_its_own_code(retry_pauses) -> None:
    handler, sent = scripted(httpx.ReadTimeout("synthetic slow"))
    with client(handler) as api, pytest.raises(NetworkError, match="Request failed"):
        api.request("GET", "/passports")
    assert len(sent) == MAX_RETRIES + 1


def test_a_streamed_body_is_never_replayed(retry_pauses) -> None:
    handler, sent = scripted(httpx.Response(429, json={"detail": "RATE_LIMITED"}))
    with client(handler) as api, pytest.raises(RateLimitError):
        api.request("POST", "/uploads", content=iter([b"one", b"two"]))
    assert len(sent) == 1
    assert retry_pauses == []


def test_an_upload_is_rewound_before_it_is_sent_again(
    tmp_path: Path, retry_pauses
) -> None:
    source = tmp_path / "label.png"
    source.write_bytes(b"synthetic image bytes")
    handler, sent = scripted(
        httpx.Response(429, headers={"Retry-After": "0"}),
        httpx.Response(201, json={"id": "upload-1"}),
    )
    with source.open("rb") as handle, client(handler) as api:
        api.request(
            "POST", "/uploads", files=[("file", ("label.png", handle, "image/png"))]
        )
        api.request("POST", "/uploads", files={"file": handle})
    assert len(sent) == 3
    assert all(b"synthetic image bytes" in request.content for request in sent)


def test_a_download_is_retried_before_the_file_is_created(
    tmp_path: Path, retry_pauses
) -> None:
    handler, _sent = scripted(httpx.Response(504), httpx.Response(200, content=b"png"))
    output = tmp_path / "qr.png"
    with client(handler) as api:
        result = api.request_to_file("GET", "/qr-code", output)
    assert output.read_bytes() == b"png"
    assert result.bytes_written == 3


def test_the_request_timeout_comes_from_option_environment_or_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NULARA_TIMEOUT", raising=False)
    assert product_config(NULARA, surface=Surface.CUSTOMER).timeout == DEFAULT_TIMEOUT
    monkeypatch.setenv("NULARA_TIMEOUT", "40")
    assert product_config(NULARA, surface=Surface.CUSTOMER).timeout == 40.0
    assert product_config(NULARA, surface=Surface.CUSTOMER, timeout=2.5).timeout == 2.5
    monkeypatch.setenv("NULARA_TIMEOUT", "slow")
    with pytest.raises(ConfigurationError, match="NULARA_TIMEOUT must be a number"):
        product_config(NULARA, surface=Surface.CUSTOMER)
    monkeypatch.setenv("NULARA_TIMEOUT", "0")
    with pytest.raises(ConfigurationError, match="positive"):
        product_config(NULARA, surface=Surface.CUSTOMER)
    with pytest.raises(ConfigurationError, match="--request-timeout"):
        product_config(NULARA, surface=Surface.CUSTOMER, timeout=float("inf"))

    with ApiClient(replace(CONFIG, timeout=2.0), "token") as api:
        timeout = api._client.timeout
    assert (timeout.read, timeout.connect) == (2.0, 2.0)
