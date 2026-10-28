import json as json_module
import os
import random
import re
import tempfile
import time
from collections.abc import Iterable, Iterator, Mapping
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import Message
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import httpx

from nulara.core.config import ProductConfig
from nulara.core.errors import (
    ApiError,
    AuthenticationError,
    AuthorizationError,
    CliError,
    NetworkError,
    RateLimitError,
    ThreadProtocolError,
)
from nulara.core.thread import parse_sse

MAX_BUFFERED_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_ERROR_RESPONSE_BYTES = 64 * 1024
# The server answers a refusal with `{"detail": "MAIL_ACCOUNT_NOT_FOUND"}`.
ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]*")
# Retries after the first attempt. A GET or HEAD is retried on a dropped
# connection or a transient 5xx; any method on a 429, which the rate limiter
# answers before the route runs. Nothing else is retried, so a POST that may
# have reached the server is never sent twice.
MAX_RETRIES = 3
RETRY_BASE_SECONDS = 0.5
RETRY_MAX_SECONDS = 8.0
# A server asking for a longer pause than this is reported, not waited out.
MAX_RETRY_AFTER_SECONDS = 60.0
IDEMPOTENT_METHODS = frozenset({"GET", "HEAD"})
TRANSIENT_SERVER_STATUSES = frozenset({500, 502, 503, 504})


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
            timeout=httpx.Timeout(config.timeout, connect=min(5.0, config.timeout)),
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
            with self._send(
                method,
                path,
                params=params,
                json=json,
                data=data,
                files=files,
                headers=headers,
                content=content,
                redact_values=redact_values,
            ) as response:
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
            raise NetworkError(f"Request failed: {exc}") from exc

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
            with self._send(
                method,
                path,
                params=params,
                json=json,
                data=data,
                files=files,
                headers=headers,
                content=content,
                redact_values=redact_values,
            ) as response:
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
            raise NetworkError(f"Request failed: {exc}") from exc
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
            with self._send(
                "POST",
                path,
                json=payload,
                headers=stream_headers,
                timeout=httpx.Timeout(300.0, connect=5.0),
            ) as response:
                content_type = response.headers.get("content-type", "")
                if content_type.split(";", 1)[0].strip().lower() != "text/event-stream":
                    raise ThreadProtocolError(
                        f"Expected text/event-stream, received {content_type or 'no content type'}"
                    )
                yield from parse_sse(response.iter_lines())
        except httpx.RequestError as exc:
            raise NetworkError(f"Request failed: {exc}") from exc

    @contextmanager
    def _send(
        self,
        method: str,
        path: str,
        *,
        files: Mapping[str, Any] | list[tuple[str, Any]] | None = None,
        content: bytes | Iterable[bytes] | None = None,
        redact_values: Iterable[str] = (),
        **arguments: Any,
    ) -> Iterator[httpx.Response]:
        """Open a successful response, retrying what is safe to send again.

        A streamed `content` body cannot be replayed, so it is sent once.
        """
        replayable = (content is None or isinstance(content, bytes)) and _rewindable(
            files
        )
        attempt = 0
        while True:
            _rewind(files)
            with ExitStack() as stack:
                try:
                    response = stack.enter_context(
                        self._client.stream(
                            method, path, files=files, content=content, **arguments
                        )
                    )
                except httpx.TransportError:
                    if not (
                        replayable
                        and method in IDEMPOTENT_METHODS
                        and attempt < MAX_RETRIES
                    ):
                        raise
                    _pause(_backoff(attempt))
                    attempt += 1
                    continue
                delay = _retry_delay(method, response, attempt) if replayable else None
                if delay is not None:
                    stack.close()
                    _pause(delay)
                    attempt += 1
                    continue
                if response.is_error:
                    _raise_for_response(response, redact_values=redact_values)
                yield response
                return

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


def _rewindable(files: Mapping[str, Any] | list[tuple[str, Any]] | None) -> bool:
    return all(
        _file_handle(entry) is None or _file_handle(entry).seekable()
        for entry in _file_entries(files)
    )


def _rewind(files: Mapping[str, Any] | list[tuple[str, Any]] | None) -> None:
    for entry in _file_entries(files):
        handle = _file_handle(entry)
        if handle is not None:
            handle.seek(0)


def _file_entries(files: Mapping[str, Any] | list[tuple[str, Any]] | None) -> list:
    if files is None:
        return []
    return list(
        files.values() if isinstance(files, Mapping) else (v for _k, v in files)
    )


def _file_handle(entry: Any) -> Any:
    handle = entry[1] if isinstance(entry, tuple) else entry
    return handle if hasattr(handle, "seek") and hasattr(handle, "seekable") else None


def _pause(seconds: float) -> None:
    time.sleep(seconds)


def _backoff(attempt: int) -> float:
    """Full jitter: a random pause up to the doubled base, capped."""
    return random.uniform(0, min(RETRY_MAX_SECONDS, RETRY_BASE_SECONDS * 2**attempt))


def _retry_delay(method: str, response: httpx.Response, attempt: int) -> float | None:
    status = response.status_code
    transient = status in TRANSIENT_SERVER_STATUSES and method in IDEMPOTENT_METHODS
    if attempt >= MAX_RETRIES or not (status == 429 or transient):
        return None
    retry_after = _retry_after_seconds(response.headers)
    if retry_after is None:
        return _backoff(attempt)
    return retry_after if retry_after <= MAX_RETRY_AFTER_SECONDS else None


def _retry_after_seconds(headers: Mapping[str, str]) -> float | None:
    """`Retry-After` as seconds: delay-seconds or an HTTP-date (RFC 9110 10.2.3)."""
    value = headers.get("retry-after", "").strip()
    if not value:
        return None
    if value.isdigit():
        return float(value)
    try:
        moment = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return max(0.0, (moment - datetime.now(UTC)).total_seconds())


def _response_detail(
    content: bytes,
    *,
    truncated: bool,
    redact_values: Iterable[str],
) -> tuple[str | None, Any]:
    """The server's error code and its redacted `detail`, kept as JSON.

    A body that is not JSON, or was cut at the error-size limit, stays text.
    """
    try:
        payload = json_module.loads(content)
    except (UnicodeDecodeError, ValueError):
        rendered = _redact_text(
            content.decode("utf-8", errors="replace"), redact_values
        )
        return None, f"{rendered}…" if truncated else rendered or None
    detail = payload.get("detail") if isinstance(payload, dict) else payload
    detail = _redact_strings(_redact_error_inputs(detail), redact_values)
    code = detail if isinstance(detail, str) and ERROR_CODE.fullmatch(detail) else None
    return code, detail


def _redact_strings(value: Any, redact_values: Iterable[str]) -> Any:
    candidates = list(redact_values)
    if isinstance(value, str):
        return _redact_text(value, candidates)
    if isinstance(value, list):
        return [_redact_strings(item, candidates) for item in value]
    if isinstance(value, dict):
        # Keys too: a validation error can echo a submitted value as a key.
        return {
            _redact_text(str(key), candidates): _redact_strings(item, candidates)
            for key, item in value.items()
        }
    return value


def _summary(detail: Any) -> str | None:
    if detail is None or isinstance(detail, str):
        return detail or None
    return json_module.dumps(detail, ensure_ascii=False, default=str)


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
    code, detail = _response_detail(
        content,
        truncated=truncated,
        redact_values=redact_values,
    )
    summary = f"{response.status_code}: {_summary(detail) or response.reason_phrase}"
    error_fields: dict[str, Any] = {
        "status_code": response.status_code,
        "code": code,
        "detail": detail,
    }
    if response.status_code == 401:
        raise AuthenticationError(
            f"API rejected authentication ({summary})", **error_fields
        )
    if response.status_code == 403:
        raise AuthorizationError(
            f"API denied this operation ({summary})", **error_fields
        )
    if response.status_code == 429:
        raise RateLimitError(
            f"API rate limit reached ({summary})",
            retry_after=_retry_after_seconds(response.headers),
            **error_fields,
        )
    if response.is_error:
        raise ApiError(f"API request failed ({summary})", **error_fields)


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
