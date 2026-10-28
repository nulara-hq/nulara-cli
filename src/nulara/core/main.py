import getpass
import json
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

from cyclopts import App, CycloptsError, Group, Parameter
from rich.console import Console
from rich.markup import escape
from rich.prompt import Confirm

from nulara.core.client import ApiClient
from nulara.core.config import (
    Product,
    ProductConfig,
    Surface,
    WorkspaceRef,
    delete_token,
    forget_workspace,
    known_workspaces,
    match_workspace,
    product_config,
    remember_workspace,
    require_explicit_secret_endpoint,
    resolve_workspace,
    set_active_workspace,
    store_token,
)
from nulara.core.direct import (
    HTTP_METHODS,
    JSON_HELP,
    register_module_commands,
    run_raw_api,
)
from nulara.core.engine import parse_catalog, select_read_operation
from nulara.core.errors import CliError, UsageError
from nulara.core.oauth import (
    DEFAULT_LOGIN_TIMEOUT,
    browser_is_available,
    run_browser_login,
    run_device_login,
)
from nulara.core.render import render_json, render_rows
from nulara.core.thread import (
    assert_expectations,
    assistant_text,
    latest_interrupt,
    summarize_run,
    write_artifacts,
)
from nulara.core.tokens import get_token

console = Console()
error_console = Console(stderr=True)
JsonOption = Annotated[bool, Parameter(name="--json", help=JSON_HELP)]
YesOption = Annotated[
    bool,
    Parameter(
        name="--yes",
        negative=(),
        help="Skip the confirmation prompt for non-interactive automation.",
    ),
]
DryRunOption = Annotated[
    bool,
    Parameter(
        name="--dry-run",
        negative=(),
        help="Show the local operation without changing state.",
    ),
]
connection_options = Group("Connection options", sort_key=0)


@Parameter(name="*", group=connection_options)
@dataclass(frozen=True)
class ConnectionOptions:
    """Connection settings shared only by commands that call the product API."""

    api_url: Annotated[
        str | None,
        Parameter(help="Override the product API URL for this invocation."),
    ] = None
    config_file: Annotated[
        Path | None,
        Parameter(
            name="--config",
            help=(
                "Use this TOML project config instead of searching for the "
                "product's project file."
            ),
        ),
    ] = None
    workspace: Annotated[
        str | None,
        Parameter(
            name="--workspace",
            help=(
                "Act as this workspace (name or id) for this invocation, "
                "overriding the one `workspace use` selected."
            ),
        ),
    ] = None

    def resolve(self, product: Product, surface: Surface) -> ProductConfig:
        return product_config(
            product,
            surface=surface,
            api_url=self.api_url,
            config_file=self.config_file,
            workspace=self.workspace,
        )


DEFAULT_CONNECTION_OPTIONS = ConnectionOptions()


def build_app(product: Product, surface: Surface) -> App:
    app = App(
        name=_entrypoint_name(product, surface),
        help=_entrypoint_help(product, surface),
        version=product.version,
    )
    _register_api_commands(app, product, surface)
    module_apps = register_module_commands(
        app,
        product,
        surface,
        connection_type=ConnectionOptions,
        default_connection=DEFAULT_CONNECTION_OPTIONS,
    )
    _register_workspace_selection(app, module_apps, product, surface)
    return app


def _entrypoint_name(product: Product, surface: Surface) -> str:
    if surface is Surface.DEVELOPMENT:
        return f"{product.name}-dev"
    return product.name


def _entrypoint_help(product: Product, surface: Surface) -> str:
    if surface is Surface.DEVELOPMENT:
        return (
            f"{product.display_name} development CLI, defaulting to the local backend."
        )
    return (
        f"{product.display_name} command-line access, defaulting to the production API."
    )


def _register_api_commands(app: App, product: Product, surface: Surface) -> None:
    """Commands that talk to the product API; shipped on both entrypoints."""
    auth = app.command(App(name="auth", help="Manage PAT authentication."))
    operations = app.command(
        App(name="operations", help="Inspect agent-approved operations.")
    )
    resource = app.command(
        App(name="resource", help="Run agent-approved resource reads.")
    )
    agent = app.command(
        App(name="agent", help="Run the workspace agent from the terminal.")
    )
    app.register_install_completion_command(
        help="Install shell completion for the current shell."
    )

    @app.command
    def login(
        *,
        connection: ConnectionOptions = DEFAULT_CONNECTION_OPTIONS,
        open_browser: bool = True,
        device: bool | None = None,
        timeout: float = DEFAULT_LOGIN_TIMEOUT,
    ) -> None:
        """Sign in through the browser consent page and store the token.

        Uses the loopback flow when a browser can reach this machine and the
        device flow (RFC 8628) when it cannot — on a remote shell the redirect
        would land on a port only this host can see. `--device` forces the second
        one, `--no-device` insists on the first.
        """
        _config = connection.resolve(product, surface)
        require_explicit_secret_endpoint(_config, "the browser login")
        use_device = not browser_is_available() if device is None else device
        if use_device:
            result = run_device_login(
                _config,
                open_browser=open_browser,
                announce=lambda authorization: console.print(
                    f"Open [cyan]{authorization.verification_uri}[/cyan] and enter "
                    f"the code [bold]{authorization.user_code}[/bold]\n"
                    "Waiting for approval…"
                ),
            )
        else:
            result = run_browser_login(
                _config,
                open_browser=open_browser,
                timeout_seconds=timeout,
                announce=lambda url: console.print(
                    f"Opening the consent page:\n[cyan]{url}[/cyan]"
                    if open_browser
                    else f"Open the consent page:\n[cyan]{url}[/cyan]"
                ),
            )
        store_token(
            _config,
            result.token,
            result.workspace_id,
            refresh_token=result.refresh_token,
            access_expires_at=(
                time.time() + result.expires_in
                if result.refresh_token is not None
                else None
            ),
        )
        with ApiClient(_config, result.token) as client:
            metadata = client.current_api_key()
            workspace = _workspace_ref(client, result.workspace_id)
        # Recorded after the token is stored, so the state file never advertises
        # a workspace whose credential is not actually in the keyring.
        remember_workspace(_config, workspace)
        console.print(
            f"[green]Authenticated[/green] as {metadata['token_prefix']} "
            f"in {workspace.name} (expires {metadata['expires_at']})."
        )

    @auth.command(name="login")
    def auth_login(
        *, connection: ConnectionOptions = DEFAULT_CONNECTION_OPTIONS
    ) -> None:
        """Verify and store a PAT pasted from the app's API-keys settings."""
        _config = connection.resolve(product, surface)
        require_explicit_secret_endpoint(_config, "a pasted PAT")
        token = getpass.getpass(f"{product.name} PAT: ").strip()
        if not token:
            raise CliError("No token provided")
        with ApiClient(_config, token) as client:
            metadata = client.current_api_key()
            workspace_id = str(metadata.get("workspace_id") or "")
            if not workspace_id:
                raise CliError("API key status did not name a workspace")
            workspace = _workspace_ref(client, workspace_id)
        store_token(_config, token, workspace_id)
        remember_workspace(_config, workspace)
        console.print(
            f"[green]Authenticated[/green] as {metadata['token_prefix']} "
            f"in {workspace.name} (expires {metadata['expires_at']})."
        )

    @auth.command
    def status(
        *,
        connection: ConnectionOptions = DEFAULT_CONNECTION_OPTIONS,
        json_output: JsonOption = False,
    ) -> None:
        """Verify the active token and list every workspace signed in here.

        Only the active workspace's token is verified against the API; the
        others are listed from local state, so the command stays one request.
        """
        _config = connection.resolve(product, surface)
        token, source = get_token(_config)
        active = resolve_workspace(_config)
        with ApiClient(_config, token) as client:
            metadata = client.current_api_key()
        metadata["credential_source"] = source
        metadata["base_url"] = _config.base_url
        metadata["base_url_source"] = _config.base_url_source
        metadata["workspace_source"] = _config.workspace_source
        if active is not None:
            metadata["workspace_name"] = active.name
        metadata["workspaces"] = [
            {
                "id": entry.id,
                "name": entry.name,
                "active": active is not None and entry.id == active.id,
            }
            for entry in known_workspaces(_config)
        ]
        if json_output:
            render_json(metadata)
        else:
            workspace_lines = "\n".join(
                f"  {'*' if entry['active'] else ' '} {entry['name']} ({entry['id']})"
                for entry in metadata["workspaces"]
            )
            console.print(
                f"[green]Authenticated[/green] {metadata['token_prefix']}\n"
                f"Workspace: {metadata.get('workspace_name', metadata['workspace_id'])}"
                f" (from {_config.workspace_source})\n"
                f"Scopes: {', '.join(metadata['scopes'])}\n"
                f"Expires: {metadata['expires_at']}\n"
                f"Source: {source}\n"
                f"API: {_config.base_url}"
                + (f"\nWorkspaces:\n{workspace_lines}" if workspace_lines else "")
            )

    @auth.command
    def logout(
        *,
        connection: ConnectionOptions = DEFAULT_CONNECTION_OPTIONS,
        all_workspaces: Annotated[
            bool,
            Parameter(
                name="--all",
                help="Sign out of every workspace, not just the active one.",
            ),
        ] = False,
    ) -> None:
        """Remove a saved token from the operating-system keyring.

        Signs out of the active workspace only, so a second workspace stays
        usable — that is the point of holding one token per workspace.
        """
        _config = connection.resolve(product, surface)
        if all_workspaces:
            targets = known_workspaces(_config)
        else:
            active = resolve_workspace(_config)
            targets = [active] if active is not None else []
        if not targets:
            console.print("No saved OS-keyring token found.")
            return
        removed: list[WorkspaceRef] = []
        for workspace in targets:
            if delete_token(_config, workspace.id):
                removed.append(workspace)
            # Dropped from state either way: an entry whose token is already
            # gone is stale and would only mislead `auth status`.
            forget_workspace(_config, workspace.id)
        if removed:
            names = ", ".join(workspace.name for workspace in removed)
            console.print(f"[green]Token removed from OS keyring:[/green] {names}")
        else:
            console.print("No saved OS-keyring token found.")

    @operations.command(name="list")
    def list_operations(
        *,
        connection: ConnectionOptions = DEFAULT_CONNECTION_OPTIONS,
        json_output: JsonOption = False,
    ) -> None:
        """List operations allowed by the server for this token."""
        _config = connection.resolve(product, surface)
        token, _source = get_token(_config)
        with ApiClient(_config, token) as client:
            payload = client.operation_catalog()
        parsed = parse_catalog(payload)
        rows = [operation.__dict__ for operation in parsed]
        render_json(rows) if json_output else render_rows(rows)

    @resource.command(name="list")
    def list_resource(
        resource_name: str,
        *,
        connection: ConnectionOptions = DEFAULT_CONNECTION_OPTIONS,
        param: list[str] | None = None,
        json_output: JsonOption = False,
    ) -> None:
        """Run the catalog-approved read operation for a resource."""
        _config = connection.resolve(product, surface)
        token, _source = get_token(_config)
        with ApiClient(_config, token) as client:
            catalog = parse_catalog(client.operation_catalog())
            operation = select_read_operation(catalog, resource_name)
            params = _resource_params(param or [])
            payload = client.request(
                operation.method,
                operation.path,
                params=params,
            )
        render_json(payload) if json_output else render_rows(payload)

    @app.command
    def api(
        endpoint: Annotated[
            str,
            Parameter(
                help="Relative app API path; absolute URLs are rejected.",
            ),
        ],
        *,
        method: HTTP_METHODS = "GET",
        field: Annotated[
            list[str] | None,
            Parameter(
                name="--field",
                help="Add a typed JSON body field as key=value; repeatable.",
            ),
        ] = None,
        raw_field: Annotated[
            list[str] | None,
            Parameter(
                name="--raw-field",
                help="Add a string JSON body field as key=value; repeatable.",
            ),
        ] = None,
        param: Annotated[
            list[str] | None,
            Parameter(
                help="Add a typed query parameter as key=value; repeatable.",
            ),
        ] = None,
        input_file: Annotated[
            str | None,
            Parameter(
                name="--input",
                help="Read the request body from FILE; use - for stdin.",
            ),
        ] = None,
        content_type: Annotated[
            str,
            Parameter(help="Content type used with a non-JSON --input body."),
        ] = "application/json",
        output: Annotated[
            Path | None,
            Parameter(help="Write the raw response body to FILE."),
        ] = None,
        overwrite: Annotated[
            bool,
            Parameter(negative=(), help="Replace an existing --output file."),
        ] = False,
        yes: YesOption = False,
        dry_run: DryRunOption = False,
        json_output: JsonOption = False,
        connection: ConnectionOptions = DEFAULT_CONNECTION_OPTIONS,
    ) -> None:
        """Call a PAT-protected app API route not yet covered by a typed command."""
        run_raw_api(
            endpoint=endpoint,
            method=method,
            fields=field or [],
            raw_fields=raw_field or [],
            params=param or [],
            input_file=input_file,
            content_type=content_type,
            output=output,
            overwrite=overwrite,
            yes=yes,
            dry_run=dry_run,
            json_output=json_output,
            connection=connection,
            product=product,
            surface=surface,
        )

    @agent.command(name="run")
    def run_agent(
        message: str,
        *,
        connection: ConnectionOptions = DEFAULT_CONNECTION_OPTIONS,
        thread_id: str | None = None,
        model: str | None = None,
        json_output: JsonOption = False,
    ) -> None:
        """Run an agent turn; approve every requested write explicitly.

        Human-readable mode prompts once per pending tool call and can continue
        through chained approval rounds. JSON mode never prompts or approves: an
        interrupted result returns the pending actions for safe automation.
        """
        _config = connection.resolve(product, surface)
        token, _source = get_token(_config)
        client_message_id = str(uuid4())
        payload = {
            "message": message,
            "client_message_id": client_message_id,
            **({"thread_id": thread_id} if thread_id else {}),
            **({"model": model} if model else {}),
        }
        events: list[dict[str, Any]] = []
        active_thread_id = thread_id
        first_stream = True

        with ApiClient(_config, token) as client:
            while True:
                batch = list(
                    client.stream_agent(payload)
                    if first_stream
                    else client.resume_agent(active_thread_id or "", payload)
                )
                first_stream = False
                events.extend(batch)
                for event in batch:
                    if not json_output and event.get("type") == "MESSAGE_DELTA":
                        console.print(
                            str(event.get("delta", "")),
                            end="",
                            markup=False,
                            emoji=False,
                            highlight=False,
                        )

                summary = summarize_run(events, client_message_id)
                active_thread_id = summary.thread_id or active_thread_id
                interrupt = latest_interrupt(batch)
                if interrupt is None:
                    break
                if not active_thread_id:
                    raise CliError("Agent approval cannot continue without a thread ID")
                if json_output:
                    break
                payload = _prompt_agent_decisions(interrupt)

        summary = summarize_run(events, client_message_id)
        interrupt = (
            latest_interrupt(events) if summary.status == "interrupted" else None
        )
        result = {
            "status": summary.status,
            "terminal_type": summary.terminal_type,
            "thread_id": summary.thread_id or active_thread_id,
            "message": assistant_text(events),
            "pending_actions": (
                interrupt.get("action_requests", []) if interrupt else []
            ),
        }
        if summary.status in {"error", "incomplete"}:
            raise CliError(
                f"Agent run ended with status {summary.status} "
                f"({summary.terminal_type or 'no terminal event'})"
            )
        if json_output:
            render_json(result)
        elif not result["message"]:
            console.print(f"[green]{summary.status.title()}[/green]")
        else:
            console.print()

    if surface is Surface.DEVELOPMENT:
        _register_thread_harness(app, product, surface)

    @app.command
    def doctor(
        *,
        connection: ConnectionOptions = DEFAULT_CONNECTION_OPTIONS,
        json_output: JsonOption = False,
    ) -> None:
        """Verify API reachability, token validity, and operation discovery."""
        _config = connection.resolve(product, surface)
        token, credential_source = get_token(_config)
        with ApiClient(_config, token) as client:
            metadata = client.current_api_key()
            operation_count = len(parse_catalog(client.operation_catalog()))
        result = {
            "status": "ok",
            "product": product.name,
            "surface": surface.value,
            "version": product.version,
            "base_url": _config.base_url,
            "base_url_source": _config.base_url_source,
            "credential_source": credential_source,
            "token_prefix": metadata.get("token_prefix"),
            "expires_at": metadata.get("expires_at"),
            "scopes": metadata.get("scopes", []),
            "operation_count": operation_count,
        }
        if json_output:
            render_json(result)
        else:
            console.print(
                f"[green]Ready[/green] {product.name} {product.version}\n"
                f"API: {_config.base_url} ({_config.base_url_source})\n"
                f"Credential: {credential_source}\n"
                f"Operations: {operation_count}"
            )


def _workspace_ref(client: ApiClient, workspace_id: str) -> WorkspaceRef:
    """Name the workspace a freshly minted token is bound to.

    The token response carries only the id, and `workspace use <name>` has to
    resolve a name without a server call, so the name is looked up once at login
    and kept in local state afterwards.
    """
    for workspace in client.list_workspaces():
        if str(workspace.get("id")) == workspace_id:
            name = workspace.get("name")
            if isinstance(name, str) and name:
                return WorkspaceRef(id=workspace_id, name=name)
    return WorkspaceRef(id=workspace_id, name=workspace_id)


def _register_workspace_selection(
    app: App,
    module_apps: dict[str, App],
    product: Product,
    surface: Surface,
) -> None:
    """Add the local workspace switch to the generated `workspace` group.

    `use` has no operation in the manifest to be generated from: it changes only
    which stored credential later commands pick up.
    """
    workspace_app = module_apps.get("workspace")
    if workspace_app is None:
        workspace_app = app.command(
            App(name="workspace", help="Workspace selection for this machine.")
        )

    @workspace_app.command(name="use")
    def use_workspace(
        selector: str,
        /,
        *,
        connection: ConnectionOptions = DEFAULT_CONNECTION_OPTIONS,
    ) -> None:
        """Switch which workspace later commands act as, by name or id.

        Purely local, like `stripe switch context` or `gh auth switch`: the
        token for that workspace is already in the keyring, so this needs
        neither a server call nor a re-login.
        """
        _config = connection.resolve(product, surface)
        workspace = match_workspace(_config, selector)
        set_active_workspace(_config, workspace.id)
        console.print(f"[green]Now using[/green] {workspace.name} ({workspace.id}).")


def _register_thread_harness(app: App, product: Product, surface: Surface) -> None:
    """The thread verification harness: assertions and artifacts, not a chat UI."""
    thread = app.command(
        App(name="thread", help="Run and verify thread streams with test artifacts.")
    )

    @thread.command(name="run")
    def run_thread(
        message: str,
        *,
        connection: ConnectionOptions = DEFAULT_CONNECTION_OPTIONS,
        thread_id: str | None = None,
        model: str | None = None,
        artifact_dir: Path | None = None,
        expect_terminal: str | None = None,
        require_event: list[str] | None = None,
        forbid_event: list[str] | None = None,
        require_tool: list[str] | None = None,
        require_persisted_interactions: bool = True,
        json_output: JsonOption = False,
    ) -> None:
        """Run a live thread stream and fail when structural expectations fail."""
        _config = connection.resolve(product, surface)
        token, _source = get_token(_config)
        test_run_id = str(uuid4())
        output_dir = artifact_dir or Path("test-results/thread-runs") / test_run_id
        payload = {
            "message": message,
            "client_message_id": test_run_id,
            **({"thread_id": thread_id} if thread_id else {}),
            **({"model": model} if model else {}),
        }
        events: list[dict[str, Any]] = []
        interactions = None
        stream_error: CliError | None = None
        interaction_error: CliError | None = None
        with ApiClient(_config, token) as client:
            try:
                events.extend(client.stream_thread(payload, test_run_id=test_run_id))
            except CliError as exc:
                stream_error = exc
            summary = summarize_run(events, test_run_id)
            if summary.thread_id:
                try:
                    interactions = client.thread_interactions(summary.thread_id)
                except CliError as exc:
                    interaction_error = exc
            write_artifacts(output_dir, events, summary, interactions)
        if stream_error:
            raise stream_error
        if interaction_error:
            raise interaction_error
        assert_expectations(
            summary,
            terminal_type=expect_terminal,
            required_event_types=require_event or (),
            forbidden_event_types=forbid_event or (),
            required_tools=require_tool or (),
            require_persisted_interactions=require_persisted_interactions,
            interactions=interactions,
        )
        result = {**summary.to_dict(), "artifact_dir": str(output_dir.resolve())}
        if json_output:
            render_json(result)
        else:
            console.print(
                f"[green]{summary.status.title()}[/green] "
                f"({summary.event_count} events)\nArtifacts: {output_dir.resolve()}"
            )


def _prompt_agent_decisions(interrupt: dict[str, Any]) -> dict[str, Any]:
    decisions: list[dict[str, str]] = []
    for request in interrupt.get("action_requests", []):
        if not isinstance(request, dict):
            raise CliError("Agent returned an invalid approval request")
        action_id = request.get("id")
        action_name = request.get("name")
        if not isinstance(action_id, str) or not isinstance(action_name, str):
            raise CliError("Agent approval request is missing id or name")
        console.print(
            f"\n[bold]Pending action:[/bold] {escape(action_name)}\n"
            f"{escape(json.dumps(request.get('args', {}), ensure_ascii=False, indent=2))}"
        )
        approved = Confirm.ask("Approve this action?", default=False)
        decisions.append(
            {
                "type": "approve" if approved else "reject",
                "action_request_id": action_id,
            }
        )
    # Only the decisions: the server reads the pending requests, the stopped
    # turn's steps and its time from where the run stored them.
    return {"decisions": decisions}


def _parse_params(values: list[str]) -> list[tuple[str, object]]:
    parsed: list[tuple[str, object]] = []
    for value in values:
        key, separator, raw = value.partition("=")
        if not separator or not key:
            raise CliError(f"Invalid --param `{value}`; expected key=value")
        try:
            parsed_value = json.loads(raw)
        except json.JSONDecodeError:
            parsed_value = raw
        parsed.append((key, parsed_value))
    return parsed


def _resource_params(values: list[str]) -> list[tuple[str, object]]:
    parsed = _parse_params(values)
    if not any(key == "limit" for key, _value in parsed):
        parsed.append(("limit", 100))
    return parsed


def run(build: Callable[[], App]) -> None:
    """Build and run an entrypoint's app, reporting a CLI error, not a traceback.

    Building is inside the guard because it already reads the product's
    command manifest, which can fail.
    """
    json_output = "--json" in sys.argv[1:]
    try:
        try:
            # A parse error gets its own exit code and, under --json, the same
            # one-object stderr shape as any other failure, not a Rich panel.
            build()(exit_on_error=False, print_error=not json_output)
        except CycloptsError as exc:
            raise UsageError(str(exc).strip() or type(exc).__name__) from exc
    except CliError as exc:
        if json_output:
            sys.stderr.write(
                json.dumps(
                    exc.as_payload(), ensure_ascii=False, sort_keys=True, default=str
                )
                + "\n"
            )
        elif not isinstance(exc, UsageError):
            error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise SystemExit(exc.exit_code) from exc
