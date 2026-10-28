from typing import Any


class CliError(Exception):
    """A failure the CLI reports instead of a traceback.

    `code` is the server's error code (`MAIL_ACCOUNT_NOT_FOUND`), `detail` the
    server's redacted `detail` as JSON, so a script branches on either without
    parsing the message.
    """

    error_type = "runtime_error"
    exit_code = 1

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        detail: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.detail = detail

    def as_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "error": self.error_type,
            "message": str(self),
            "exit_code": self.exit_code,
        }
        if self.status_code is not None:
            payload["status_code"] = self.status_code
        if self.code is not None:
            payload["code"] = self.code
        if self.detail is not None:
            payload["detail"] = self.detail
        return payload


class ConfigurationError(CliError):
    error_type = "configuration_error"
    exit_code = 2


class AuthenticationError(CliError):
    error_type = "authentication_error"
    exit_code = 3


class AuthorizationError(CliError):
    error_type = "authorization_error"
    exit_code = 4


class ApiError(CliError):
    error_type = "api_error"
    exit_code = 5


class RateLimitError(ApiError):
    """A 429 that outlasted the retries; `retry_after` is the server's pause."""

    error_type = "rate_limit_error"
    exit_code = 11

    def __init__(
        self, message: str, *, retry_after: float | None = None, **fields: Any
    ) -> None:
        super().__init__(message, **fields)
        self.retry_after = retry_after

    def as_payload(self) -> dict[str, object]:
        payload = super().as_payload()
        if self.retry_after is not None:
            payload["retry_after"] = self.retry_after
        return payload


class OperationError(CliError):
    error_type = "operation_error"
    exit_code = 6


class ThreadProtocolError(CliError):
    error_type = "thread_protocol_error"
    exit_code = 7


class ThreadExpectationError(CliError):
    error_type = "thread_expectation_error"
    exit_code = 8


class UsageError(CliError):
    """The command line itself did not parse: unknown option, missing argument."""

    error_type = "usage_error"
    exit_code = 9


class NetworkError(CliError):
    """The API could not be reached or the connection broke off."""

    error_type = "network_error"
    exit_code = 10
