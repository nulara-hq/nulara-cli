# Nulara CLI

Command-line access to Nulara: sign in, call the product modules and the API,
and run the workspace agent.

Documentation: <https://nulara.de/cli>

## Install

```console
uv tool install nulara
```

The CLI needs Python 3.14; [uv](https://docs.astral.sh/uv/) downloads it when
the machine does not have it. With pipx, name the interpreter yourself:
`pipx install --python 3.14 nulara`. Update with `uv tool upgrade nulara`.
The CLI runs on macOS and Linux.

## Use

```console
nulara login
nulara doctor
nulara agent run "Summarize my open tasks"
nulara --help
```

The CLI talks to the production API (`https://api.nulara.de/v1/app`) unless
`--api-url`, `NULARA_API_URL` or the nearest `.nulara.toml`
(`api_url = "…"`) names another one.

`nulara login` opens the browser for consent, or prints a code to approve on
another device when no browser can be opened here. It stores an hour-long token
and its refresh token in the operating-system keyring (service `nulara-cli`)
and renews it automatically. For automation, set `NULARA_API_TOKEN` to a
personal access token from the app's API key settings instead. Which workspace
a command acts as is kept in `~/.config/nulara/state.json`
(`$XDG_CONFIG_HOME/nulara/` when that is set); the file holds no secrets.

## Layout

`nulara.core` holds everything that does not depend on the product: an
entrypoint builds a `nulara.core.config.Product` (name, API, OAuth client,
command manifest) and hands it to `nulara.core.main.build_app`. `nulara`
itself is that entrypoint, and `src/nulara/spec.json` is its command manifest,
generated from the app API's OpenAPI document; it is never edited by hand.

## Development

```console
uv sync --locked
uv run pytest --cov=nulara
uv run ruff check && uv run ruff format --check && uv run pyright
```

A release is a GitHub release whose tag is `v<version>` from `pyproject.toml`;
`.github/workflows/publish.yml` builds, verifies and publishes it to PyPI with
an attestation.

## License

[Apache-2.0](LICENSE)
