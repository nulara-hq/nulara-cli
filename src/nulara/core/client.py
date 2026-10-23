import json as json_module
import os
import tempfile
from collections.abc import Iterable, Iterator, Mapping
from contextlib import suppress
from dataclasses import dataclass
from email.message import Message
from pathlib import Path
from typing import Any

import httpx

from nulara.core.config import ProductConfig
from nulara.core.errors import (
    ApiError,
    AuthenticationError,
    AuthorizationError,
    CliError,
    ThreadProtocolError,
)
from nulara.core.thread import parse_sse

MAX_BUFFERED_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_ERROR_RESPONSE_BYTES = 64 * 1024


@dataclass(frozen=True)
class ApiResult:
    status_code: int
    content_type: str
    content: bytes
    headers: Mapping[str, str]

    def payload(self) -> Any:
        if not self.content:
            return None
        if self.content_type == "application/json" or self.content_type.endswith(
            "+json"
        ):
            try:
                return json_module.loads(self.content)
            except ValueError as exc:
                raise CliError("API returned invalid JSON") from exc
        if self.content_type.startswith("text/"):
            return self.content.decode("utf-8", errors="replace")
        return self.content

    @property
    def is_binary(self) -> bool:
        return bool(self.content_type) and not (
            self.content_type == "application/json"
            or self.content_type.endswith("+json")
            or self.content_type.startswith("text/")
        )

    @property
    def filename(self) -> str | None:
        return _response_filename(self.headers)


@dataclass(frozen=True)
class ApiDownloadResult:
    status_code: int
    content_type: str
    headers: Mapping[str, str]
    bytes_written: int
    output: Path

    @property
    def filename(self) -> str | None:
        return _response_filename(self.headers)


class ApiClient:
    def __init__(
        self,
        config: ProductConfig,
        token: str,
        *,
        transport: httpx.BaseTransport | None = None,
    ):
        self._client = httpx.Client(
            base_url=config.base_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": config.user_agent,
            },
            timeout=httpx.Timeout(15.0, connect=5.0),
            transport=transport,
        )

    def __enter__(self):
        self._client.__enter__()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._client.__exit__(exc_type, exc, traceback)

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | list[tuple[str, Any]] | None = None,
        json: Any = None,
        data: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | list[tuple[str, Any]] | None = None,
        headers: Mapping[str, str] | None = None,
        content: bytes | Iterable[bytes] | None = None,
        redact_values: Iterable[str] = (),
    ) -> Any:
        return self.request_result(
            method,
            path,
            params=params,
            json=json,
            data=data,
            files=files,
            headers=headers,
            content=content,
            redact_values=redact_values,
        ).payload()

    def request_result(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | list[tuple[str, Any]] | None = None,
        json: Any = None,
        data: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | list[tuple[str, Any]] | None = None,
        headers: Mapping[str, str] | None = None,
        content: bytes | Iterable[bytes] | None = None,
        redact_values: Iterable[str] = (),
    ) -> ApiResult:
        try:
            with self._client.stream(
                method,
                path,
                params=params,
                json=json,
                data=data,
                files=files,
                headers=headers,
                content=content,
            ) as response:
                if response.is_error:
                    _raise_for_response(response, redact_values=redact_values)
                content_type = _content_type(response)
                response_headers = dict(response.headers)
                if _is_binary_content_type(content_type):
                    return ApiResult(
                        status_code=response.status_code,
                        content_type=content_type,
                        content=b"",
                        headers=response_headers,
                    )
                buffered = bytearray()
                for chunk in response.iter_bytes():
                    buffered.extend(chunk)
                    if len(buffered) > MAX_BUFFERED_RESPONSE_BYTES:
                        raise CliError(
                            "API response exceeds the in-memory output limit; "
                            "use --output to stream it to a file"
                        )
                return ApiResult(
                    status_code=response.status_code,
                    content_type=content_type,
                    content=bytes(buffered),
                    headers=response_headers,
                )
        except httpx.RequestError as exc:
            raise CliError(f"Request failed: {exc}") from exc

    def request_to_file(
        self,
        method: str,
        path: str,
        output: Path,
        *,
        overwrite: bool = False,
        params: Mapping[str, Any] | list[tuple[str, Any]] | None = None,
        json: Any = None,
        data: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | list[tuple[str, Any]] | None = None,
        headers: Mapping[str, str] | None = None,
        content: bytes | Iterable[bytes] | None = None,
        redact_values: Iterable[str] = (),
    ) -> ApiDownloadResult:
        temporary: Path | None = None
        try:
            with self._client.stream(
                method,
                path,
                params=params,
                json=json,
                data=data,
                files=files,
                headers=headers,
                content=content,
            ) as response:
                if response.is_error:
                    _raise_for_response(response, redact_values=redact_values)
                descriptor, temporary_name = tempfile.mkstemp(
                    prefix=f".{output.name}.",
                    suffix=".part",
                    dir=output.parent,
                )
                temporary = Path(temporary_name)
                bytes_written = 0
                with os.fdopen(descriptor, "wb") as target:
                    for chunk in response.iter_bytes():
                        target.write(chunk)
                        bytes_written += len(chunk)
                    target.flush()
                    os.fsync(target.fileno())
                if overwrite:
                    os.replace(temporary, output)
                else:
                    os.link(temporary, output)
                    temporary.unlink()
                temporary = None
                return ApiDownloadResult(
                    status_code=response.status_code,
                    content_type=_content_type(response),
                    headers=dict(response.headers),
                    bytes_written=bytes_written,
                    output=output,
                )
        except FileExistsError as exc:
            raise CliError(
                f"Output file already exists: {output}; pass --overwrite to replace it"
            ) from exc
        except httpx.RequestError as exc:
            raise CliError(f"Request failed: {exc}") from exc
        except OSError as exc:
            raise CliError(f"Could not write output file {output}: {exc}") from exc
        finally:
            if temporary is not None:
                with suppress(OSError):
                    temporary.unlink(missing_ok=True)

    def current_api_key(self) -> dict[str, Any]:
        result = self.request("GET", "/me/api-keys/current")
        if not isinstance(result, dict):
            raise CliError("Unexpected API key status response")
        return result

    def list_workspaces(self) -> list[dict[str, Any]]:
        """Workspaces the token's user belongs to, used to name the local slot."""
        result = self.request("GET", "/workspace")
        if not isinstance(result, list):
            raise CliError("Unexpected workspace list response")
        return [entry for entry in result if isinstance(entry, dict)]

    def stream_thread(
        self, payload: Mapping[str, Any], *, test_run_id: str
    ) -> Iterator[dict[str, Any]]:
        yield from self._stream_sse(
            "/threads/chat",
            payload,
            headers={"X-Test-Run-ID": test_run_id},
        )

    def stream_agent(self, payload: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
        """Start a customer-facing agent turn without test-only headers."""
        yield from self._stream_sse("/threads/chat", payload)

    def resume_agent(
        self, thread_id: str, payload: Mapping[str, Any]
    ) -> Iterator[dict[str, Any]]:
        """Resume one interrupted turn with explicit human decisions."""
        yield from self._stream_sse(f"/threads/{thread_id}/resume", payload)

    def _stream_sse(
        self,
        path: str,
        payload: Mapping[str, Any],
        *,
        headers: Mapping[str, str] | None = None,
    ) -> Iterator[dict[str, Any]]:
        stream_headers = {"Accept": "text/event-stream", **(headers or {})}
        try:
            with self._client.stream(
                "POST",
                path,
                json=payload,
                headers=stream_headers,
                timeout=httpx.Timeout(300.0, connect=5.0),
            ) as response:
                if response.is_error:
                    _raise_for_response(response)
                content_type = response.headers.get("content-type", "")
                if content_type.split(";", 1)[0].strip().lower() != "text/event-stream":
                    raise ThreadProtocolError(
                        f"Expected text/event-stream, received {content_type or 'no content type'}"
                    )
                yield from parse_sse(response.iter_lines())
        except httpx.RequestError as exc:
            raise CliError(f"Request failed: {exc}") from exc

    def thread_interactions(self, thread_id: str) -> dict[str, Any]:
        result = self.request("GET", f"/threads/{thread_id}/interactions")
        if not isinstance(result, dict):
            raise CliError("Unexpected thread interactions response")
        return result

    def operation_catalog(self) -> dict[str, Any]:
        result = self.request("GET", "/agent-operations")
        if not isinstance(result, dict):
            raise CliError("Unexpected operation catalog response")
        return result


def _response_detail(
    response: httpx.Response,
    content: bytes,
    *,
    truncated: bool,
    redact_values: Iterable[str],
) -> str:
    try:
        payload = json_module.loads(content)
    except (UnicodeDecodeError, ValueError):
        rendered = content.decode("utf-8", errors="replace")
    else:
        detail = payload.get("detail") if isinstance(payload, dict) else payload
        rendered = str(_redact_error_inputs(detail))
    rendered = _redact_text(rendered, redact_values)[:200]
    if truncated:
        rendered = f"{rendered}…"
    return rendered or response.reason_phrase


def _redact_error_inputs(value: Any) -> Any:
    if isinstance(value, list):
        return [_redact_error_inputs(item) for item in value]
    if isinstance(value, dict):
        return {
            key: (
                "<redacted>"
                if str(key).lower() == "input"
                else _redact_error_inputs(item)
            )
            for key, item in value.items()
        }
    return value


def _redact_text(value: str, redact_values: Iterable[str]) -> str:
    rendered = value
    candidates = sorted(
        {candidate for candidate in redact_values if candidate},
        key=len,
        reverse=True,
    )
    for candidate in candidates:
        rendered = rendered.replace(candidate, "<redacted>")
    return rendered


def _read_error_content(response: httpx.Response) -> tuple[bytes, bool]:
    content = bytearray()
    for chunk in response.iter_bytes():
        remaining = MAX_ERROR_RESPONSE_BYTES + 1 - len(content)
        content.extend(chunk[:remaining])
        if len(content) > MAX_ERROR_RESPONSE_BYTES:
            return bytes(content[:MAX_ERROR_RESPONSE_BYTES]), True
    return bytes(content), False


def _raise_for_response(
    response: httpx.Response, *, redact_values: Iterable[str] = ()
) -> None:
    content, truncated = _read_error_content(response)
    detail = _response_detail(
        response,
        content,
        truncated=truncated,
        redact_values=redact_values,
    )
    if response.status_code == 401:
        raise AuthenticationError(
            f"API rejected authentication ({response.status_code}: {detail})",
            status_code=response.status_code,
            detail=detail,
        )
    if response.status_code == 403:
        raise AuthorizationError(
            f"API denied this operation ({response.status_code}: {detail})",
            status_code=response.status_code,
            detail=detail,
        )
    if response.is_error:
        raise ApiError(
            f"API request failed ({response.status_code}: {detail})",
            status_code=response.status_code,
            detail=detail,
        )


def _content_type(response: httpx.Response) -> str:
    return response.headers.get("content-type", "").split(";", 1)[0].strip().lower()


def _is_binary_content_type(content_type: str) -> bool:
    return bool(content_type) and not (
        content_type == "application/json"
        or content_type.endswith("+json")
        or content_type.startswith("text/")
    )


def _response_filename(headers: Mapping[str, str]) -> str | None:
    disposition = headers.get("content-disposition")
    if not disposition:
        return None
    message = Message()
    message["content-disposition"] = disposition
    filename = message.get_filename()
    return Path(filename).name if filename else None
