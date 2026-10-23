class CliError(Exception):
    error_type = "runtime_error"
    exit_code = 1

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail

    def as_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "error": self.error_type,
            "message": str(self),
            "exit_code": self.exit_code,
        }
        if self.status_code is not None:
            payload["status_code"] = self.status_code
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


class OperationError(CliError):
    error_type = "operation_error"
    exit_code = 6


class ThreadProtocolError(CliError):
    error_type = "thread_protocol_error"
    exit_code = 7


class ThreadExpectationError(CliError):
    error_type = "thread_expectation_error"
    exit_code = 8
