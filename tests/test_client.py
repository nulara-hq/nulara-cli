from pathlib import Path

import httpx
import pytest
from support import NULARA

from nulara.core import client as client_module
from nulara.core.client import ApiClient, ApiDownloadResult, ApiResult
from nulara.core.config import ProductConfig, Surface
from nulara.core.errors import (
    ApiError,
    AuthenticationError,
    AuthorizationError,
    CliError,
    ThreadProtocolError,
)

CONFIG = ProductConfig(
    product=NULARA,
    surface=Surface.DEVELOPMENT,
    base_url="https://api.example.test/v1/app",
    token_env="NULARA_API_TOKEN",
    keyring_service="nulara-cli",
)


def test_client_sends_bearer_and_reads_current_key() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer nulara_sk_test_secret"
        assert request.url.path == "/v1/app/me/api-keys/current"
        return httpx.Response(200, json={"token_prefix": "nulara_sk_test"})

    with ApiClient(
        CONFIG,
        "nulara_sk_test_secret",
        transport=httpx.MockTransport(handler),
    ) as client:
        result = client.current_api_key()

    assert result["token_prefix"] == "nulara_sk_test"


@pytest.mark.parametrize(
    ("status", "error"),
    [(401, AuthenticationError), (403, AuthorizationError)],
)
def test_client_maps_auth_errors(status: int, error: type[CliError]) -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(status, json={"detail": "UNAUTHORIZED"})
    )
    with (
        ApiClient(CONFIG, "bad", transport=transport) as client,
        pytest.raises(error, match="UNAUTHORIZED") as raised,
    ):
        client.current_api_key()
    assert raised.value.status_code == status
    assert raised.value.detail == "UNAUTHORIZED"


def test_client_requests_and_streams_sse() -> None:
    streamed_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/agent-operations"):
            return httpx.Response(200, json={"operations": []})
        if request.method == "POST":
            streamed_paths.append(request.url.path)
            assert request.headers["Accept"] == "text/event-stream"
            if request.url.path.endswith("/threads/chat") and request.headers.get(
                "X-Test-Run-ID"
            ):
                assert request.headers["X-Test-Run-ID"] == "test-run"
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream; charset=utf-8"},
                text='data: {"type":"COMPLETE","thread_id":"thread-1"}\n\n',
            )
        return httpx.Response(200, json={"interactions": []})

    with ApiClient(CONFIG, "token", transport=httpx.MockTransport(handler)) as client:
        assert client.operation_catalog() == {"operations": []}
        assert list(
            client.stream_thread({"message": "hi"}, test_run_id="test-run")
        ) == [{"type": "COMPLETE", "thread_id": "thread-1"}]
        assert list(client.stream_agent({"message": "hi"})) == [
            {"type": "COMPLETE", "thread_id": "thread-1"}
        ]
        assert list(
            client.resume_agent(
                "thread-1",
                {"decisions": [{"type": "approve"}]},
            )
        ) == [{"type": "COMPLETE", "thread_id": "thread-1"}]
        assert client.thread_interactions("thread-1") == {"interactions": []}
    assert streamed_paths == [
        "/v1/app/threads/chat",
        "/v1/app/threads/chat",
        "/v1/app/threads/thread-1/resume",
    ]


@pytest.mark.parametrize("status", [401, 500])
def test_stream_maps_http_errors(status: int) -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(status, json={"detail": "BROKEN"})
    )
    error = AuthenticationError if status == 401 else CliError
    with (
        ApiClient(CONFIG, "token", transport=transport) as client,
        pytest.raises(error, match="BROKEN"),
    ):
        list(client.stream_thread({"message": "hi"}, test_run_id="run"))


def test_stream_rejects_non_sse_response() -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200, headers={"content-type": "application/json"}, json={}
        )
    )
    with (
        ApiClient(CONFIG, "token", transport=transport) as client,
        pytest.raises(ThreadProtocolError, match="Expected text/event-stream"),
    ):
        list(client.stream_thread({"message": "hi"}, test_run_id="run"))


def test_stream_maps_transport_errors() -> None:
    def broken(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("stream offline")

    with (
        ApiClient(CONFIG, "token", transport=httpx.MockTransport(broken)) as client,
        pytest.raises(CliError, match="stream offline"),
    ):
        list(client.stream_thread({"message": "hi"}, test_run_id="run"))


def test_client_maps_transport_and_generic_http_errors() -> None:
    def broken(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    with (
        ApiClient(CONFIG, "token", transport=httpx.MockTransport(broken)) as client,
        pytest.raises(CliError, match="offline"),
    ):
        client.request("GET", "/anything")

    transport = httpx.MockTransport(
        lambda _request: httpx.Response(500, text="failure")
    )
    with (
        ApiClient(CONFIG, "token", transport=transport) as client,
        pytest.raises(ApiError, match="failure") as raised,
    ):
        client.request("GET", "/anything")
    assert raised.value.status_code == 500

    transport = httpx.MockTransport(
        lambda _request: httpx.Response(500, json=["structured", "failure"])
    )
    with (
        ApiClient(CONFIG, "token", transport=transport) as client,
        pytest.raises(CliError, match="structured"),
    ):
        client.request("GET", "/anything")


def test_client_reports_the_server_error_code_as_its_own_field() -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(404, json={"detail": "MAIL_ACCOUNT_NOT_FOUND"})
    )
    with (
        ApiClient(CONFIG, "token", transport=transport) as client,
        pytest.raises(ApiError) as raised,
    ):
        client.request("POST", "/mail/send")
    assert raised.value.as_payload() == {
        "error": "api_error",
        "message": "API request failed (404: MAIL_ACCOUNT_NOT_FOUND)",
        "exit_code": 5,
        "status_code": 404,
        "code": "MAIL_ACCOUNT_NOT_FOUND",
        "detail": "MAIL_ACCOUNT_NOT_FOUND",
    }


def test_client_keeps_a_long_error_detail_whole() -> None:
    message = "synthetic " * 60
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(500, json={"detail": message})
    )
    with (
        ApiClient(CONFIG, "token", transport=transport) as client,
        pytest.raises(ApiError) as raised,
    ):
        client.request("GET", "/anything")
    assert raised.value.detail == message
    assert raised.value.code is None


def test_client_redacts_validation_inputs_and_sensitive_error_echoes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "body-secret-value"
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            422,
            json={
                "detail": [
                    {
                        "type": "string_too_short",
                        "loc": ["body", "token"],
                        "msg": f"invalid value {secret}",
                        "input": secret,
                    }
                ]
            },
        )
    )
    with (
        ApiClient(CONFIG, "token", transport=transport) as client,
        pytest.raises(ApiError) as raised,
    ):
        client.request(
            "POST",
            "/secrets",
            json={"token": secret},
            redact_values=[secret],
        )
    assert secret not in str(raised.value)
    assert secret not in str(raised.value.as_payload())
    # The detail stays JSON a script can index, not a Python repr.
    assert raised.value.detail == [
        {
            "type": "string_too_short",
            "loc": ["body", "token"],
            "msg": "invalid value <redacted>",
            "input": "<redacted>",
        }
    ]
    assert raised.value.code is None

    monkeypatch.setattr(client_module, "MAX_ERROR_RESPONSE_BYTES", 4)
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(500, text="unbounded error")
    )
    with (
        ApiClient(CONFIG, "token", transport=transport) as client,
        pytest.raises(ApiError, match="unbo…") as truncated,
    ):
        client.request("GET", "/anything")
    assert truncated.value.detail == "unbo…"


def test_client_handles_empty_and_unexpected_responses() -> None:
    transport = httpx.MockTransport(lambda _request: httpx.Response(204))
    with ApiClient(CONFIG, "token", transport=transport) as client:
        assert client.request("DELETE", "/anything") is None

    transport = httpx.MockTransport(lambda _request: httpx.Response(200, json=[]))
    with ApiClient(CONFIG, "token", transport=transport) as client:
        with pytest.raises(CliError, match="API key status"):
            client.current_api_key()
        with pytest.raises(CliError, match="operation catalog"):
            client.operation_catalog()
        with pytest.raises(CliError, match="interactions"):
            client.thread_interactions("thread")


def test_api_result_rejects_invalid_json_and_sanitizes_filenames() -> None:
    with pytest.raises(CliError, match="invalid JSON"):
        ApiResult(200, "application/json", b"invalid", {}).payload()
    assert ApiResult(200, "application/octet-stream", b"x", {}).filename is None
    assert (
        ApiResult(
            200,
            "application/octet-stream",
            b"x",
            {"content-disposition": "attachment"},
        ).filename
        is None
    )
    assert (
        ApiResult(
            200,
            "application/octet-stream",
            b"x",
            {"content-disposition": 'attachment; filename="../safe.txt"'},
        ).filename
        == "safe.txt"
    )
    assert ApiResult(200, "", b"raw", {}).payload() == b"raw"
    assert (
        ApiDownloadResult(
            200,
            "application/octet-stream",
            {"content-disposition": 'attachment; filename="report.pdf"'},
            10,
            Path("report.pdf"),
        ).filename
        == "report.pdf"
    )


def test_binary_responses_are_not_buffered_without_output() -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            headers={"content-type": "application/pdf"},
            content=b"large binary placeholder",
        )
    )
    with ApiClient(CONFIG, "token", transport=transport) as client:
        result = client.request_result("GET", "/report")
    assert result.is_binary is True
    assert result.content == b""


def test_download_streams_and_installs_output_atomically(tmp_path: Path) -> None:
    payload = b"invalid json"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=payload,
        )

    output = tmp_path / "response.json"
    with ApiClient(CONFIG, "token", transport=httpx.MockTransport(handler)) as client:
        result = client.request_to_file("GET", "/export", output)
    assert result.bytes_written == len(payload)
    assert output.read_bytes() == payload
    assert not list(tmp_path.glob("*.part"))

    output.write_bytes(b"preserve")
    with (
        ApiClient(CONFIG, "token", transport=httpx.MockTransport(handler)) as client,
        pytest.raises(CliError, match="already exists"),
    ):
        client.request_to_file("GET", "/export", output)
    assert output.read_bytes() == b"preserve"

    with ApiClient(CONFIG, "token", transport=httpx.MockTransport(handler)) as client:
        client.request_to_file("GET", "/export", output, overwrite=True)
    assert output.read_bytes() == payload


def test_download_wraps_invalid_output_paths(tmp_path: Path) -> None:
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, content=b"x"))
    output = tmp_path / "missing" / "result.bin"
    with (
        ApiClient(CONFIG, "token", transport=transport) as client,
        pytest.raises(CliError, match="Could not write output file"),
    ):
        client.request_to_file("GET", "/export", output)


def test_download_maps_http_and_transport_errors(tmp_path: Path) -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(500, json={"detail": "BROKEN"})
    )
    with (
        ApiClient(CONFIG, "token", transport=transport) as client,
        pytest.raises(ApiError, match="BROKEN"),
    ):
        client.request_to_file("GET", "/export", tmp_path / "error.bin")

    def broken(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("download offline")

    with (
        ApiClient(CONFIG, "token", transport=httpx.MockTransport(broken)) as client,
        pytest.raises(CliError, match="download offline"),
    ):
        client.request_to_file("GET", "/export", tmp_path / "offline.bin")

    assert CliError("plain").as_payload() == {
        "error": "runtime_error",
        "message": "plain",
        "exit_code": 1,
    }


def test_buffered_responses_have_a_hard_memory_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_module, "MAX_BUFFERED_RESPONSE_BYTES", 3)
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200, headers={"content-type": "text/plain"}, content=b"four"
        )
    )
    with (
        ApiClient(CONFIG, "token", transport=transport) as client,
        pytest.raises(CliError, match="in-memory output limit"),
    ):
        client.request_result("GET", "/large")
