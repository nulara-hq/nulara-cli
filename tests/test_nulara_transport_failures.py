"""Nulara HTTP and stream failures preserve local files and typed errors."""

import httpx
import pytest
from support import NULARA_DEV

from nulara.core import client as c
from nulara.core.config import Surface, product_config
from nulara.core.errors import (
    ApiError,
    AuthenticationError,
    AuthorizationError,
    CliError,
    ThreadProtocolError,
)


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return product_config(
        NULARA_DEV,
        surface=Surface.DEVELOPMENT,
        api_url="http://127.0.0.1:5710/v1/app",
    )


def client(config, handler):
    return c.ApiClient(
        config, "synthetic-token", transport=httpx.MockTransport(handler)
    )


@pytest.mark.parametrize(
    "method",
    ["current_api_key", "list_workspaces", "operation_catalog", "thread_interactions"],
)
def test_metadata_response_shape_is_checked(config, method):
    with (
        client(config, lambda _: httpx.Response(200, json="invalid shape")) as api,
        pytest.raises(CliError, match="Unexpected"),
    ):
        getattr(api, method)(*(["one"] if method == "thread_interactions" else []))


def test_workspace_list_filters_unusable_entries(config):
    with client(config, lambda _: httpx.Response(200, json=[{}, None, 5])) as api:
        assert api.list_workspaces() == [{}]


@pytest.mark.parametrize(
    "method",
    ["request", "request_to_file", "stream_agent", "resume_agent", "stream_thread"],
)
def test_transport_errors_become_cli_errors(config, tmp_path, method):
    def unavailable(request):
        raise httpx.ConnectError("synthetic refused", request=request)

    with (
        client(config, unavailable) as api,
        pytest.raises(CliError, match="Request failed"),
    ):
        if method == "request":
            api.request("GET", "/locations")
        elif method == "request_to_file":
            api.request_to_file("GET", "/export", tmp_path / "output")
        elif method == "resume_agent":
            list(api.resume_agent("one", {"decisions": []}))
        elif method == "stream_thread":
            list(
                api.stream_thread({"message": "synthetic"}, test_run_id="synthetic-run")
            )
        else:
            list(api.stream_agent({"message": "synthetic"}))
    assert not list(tmp_path.glob("*.part"))


@pytest.mark.parametrize("method", ["request", "request_to_file", "stream_agent"])
@pytest.mark.parametrize(
    "status,error",
    [(401, AuthenticationError), (403, AuthorizationError), (503, ApiError)],
)
def test_http_errors_are_typed_and_do_not_write_files(
    config, tmp_path, method, status, error
):
    with client(
        config, lambda _: httpx.Response(status, json={"detail": "synthetic rejected"})
    ) as api:
        with pytest.raises(error) as raised:
            if method == "request":
                api.request("GET", "/locations")
            elif method == "request_to_file":
                api.request_to_file("GET", "/export", tmp_path / "output")
            else:
                list(api.stream_agent({"message": "synthetic"}))
        assert raised.value.status_code == status
    assert not (tmp_path / "output").exists()


def test_download_disk_failure_cleans_partial(config, tmp_path, monkeypatch):
    target = tmp_path / "output"

    def denied(*args):
        raise OSError("synthetic disk full")

    monkeypatch.setattr(c.os, "fsync", denied)
    with (
        client(config, lambda _: httpx.Response(200, content=b"synthetic file")) as api,
        pytest.raises(CliError, match="Could not write output"),
    ):
        api.request_to_file("GET", "/export", target)
    assert not target.exists()
    assert not list(tmp_path.glob(".*.part"))


def test_download_preserves_existing_file_and_allows_explicit_overwrite(
    config, tmp_path
):
    target = tmp_path / "output"
    target.write_bytes(b"existing")

    def response(_):
        return httpx.Response(
            200,
            content=b"new",
            headers={"Content-Disposition": 'attachment; filename="../export.bin"'},
        )

    with client(config, response) as api:
        with pytest.raises(CliError, match="already exists"):
            api.request_to_file("GET", "/export", target)
        assert target.read_bytes() == b"existing"
        result = api.request_to_file("GET", "/export", target, overwrite=True)
    assert target.read_bytes() == b"new"
    assert result.filename == "export.bin"
    assert result.bytes_written == 3
    assert not list(tmp_path.glob(".*.part"))


@pytest.mark.parametrize(
    "content_type", ["application/json", "application/problem+json"]
)
def test_malformed_json_is_not_printed_as_success(config, content_type):
    with (
        client(
            config,
            lambda _: httpx.Response(
                200, content=b"{broken", headers={"Content-Type": content_type}
            ),
        ) as api,
        pytest.raises(CliError, match="invalid JSON"),
    ):
        api.request("GET", "/locations")


def test_response_memory_limit_is_enforced(config, monkeypatch):
    monkeypatch.setattr(c, "MAX_BUFFERED_RESPONSE_BYTES", 4)
    with (
        client(config, lambda _: httpx.Response(200, text="too long")) as api,
        pytest.raises(CliError, match="in-memory output limit"),
    ):
        api.request("GET", "/export")


def test_error_redaction_and_truncation(config, monkeypatch):
    monkeypatch.setattr(c, "MAX_ERROR_RESPONSE_BYTES", 32)
    with (
        client(
            config, lambda _: httpx.Response(400, text="synthetic-secret " * 20)
        ) as api,
        pytest.raises(ApiError) as raised,
    ):
        api.request(
            "POST", "/locations", redact_values=["synthetic-secret", "", "synthetic"]
        )
    assert "synthetic-secret" not in str(raised.value)
    assert "<redacted>" in str(raised.value)
    assert raised.value.detail is not None
    assert raised.value.detail.endswith("…")


@pytest.mark.parametrize("content", [b"", b"\xff", b"[]"])
def test_error_body_without_detail_is_still_reported(config, content):
    with (
        client(config, lambda _: httpx.Response(502, content=content)) as api,
        pytest.raises(ApiError) as raised,
    ):
        api.request("GET", "/locations")
    assert str(raised.value) != "API request failed (502: )"


@pytest.mark.parametrize("content_type", ["application/json", ""])
def test_sse_rejects_wrong_content_type(config, content_type):
    with (
        client(
            config,
            lambda _: httpx.Response(
                200, content=b"{}", headers={"Content-Type": content_type}
            ),
        ) as api,
        pytest.raises(ThreadProtocolError, match="Expected text/event-stream"),
    ):
        list(api.stream_agent({"message": "synthetic"}))


@pytest.mark.parametrize("method", ["stream_thread", "resume_agent"])
def test_nulara_stream_request_contract(config, method):
    def handle(request):
        assert request.headers["accept"] == "text/event-stream"
        assert request.headers["authorization"] == "Bearer synthetic-token"
        assert request.url.path == (
            "/v1/app/threads/chat"
            if method == "stream_thread"
            else "/v1/app/threads/one/resume"
        )
        assert request.headers.get("X-Test-Run-ID") == (
            "synthetic-run" if method == "stream_thread" else None
        )
        return httpx.Response(
            200,
            text='data: {"type":"COMPLETE","thread_id":"one"}\n\n',
            headers={"Content-Type": "text/event-stream; charset=utf-8"},
        )

    with client(config, handle) as api:
        events = list(
            api.stream_thread({}, test_run_id="synthetic-run")
            if method == "stream_thread"
            else api.resume_agent("one", {"decisions": []})
        )
    assert events == [{"type": "COMPLETE", "thread_id": "one"}]


def test_raw_binary_result_and_unnamed_disposition():
    assert (
        c.ApiResult(200, "application/octet-stream", b"data", {}).payload() == b"data"
    )
    assert (
        c.ApiResult(
            200, "text/plain", b"hello", {"content-disposition": "attachment"}
        ).filename
        is None
    )
