---
name: nulara
description: Work in a Nulara workspace through the `nulara` command-line tool. Use when the user asks to create or change products, items, records or other Nulara data, publish a digital product passport, fetch a passport's QR code, or read anything from their Nulara workspace.
---

# Nulara CLI

`nulara` calls the Nulara API for the workspace the user signed in to. Every
product module is a command group (`nulara products …`,
`nulara passport-publications …`) whose commands mirror the API one to one.

## Rules

- Pass `--json` to every command. Data goes to stdout as one JSON document; a
  failure is one JSON object on stderr and a non-zero exit code. Never parse
  the human output.
- A command that changes data refuses to run without `--yes` outside a
  terminal. Before the first change, show the user what you will do; run the
  same command with `--dry-run` to print the request without sending it.
- Never guess a command or option. Ask the CLI:
  - `nulara describe` lists the modules and their commands,
  - `nulara describe <module>` lists one module's commands,
  - `nulara describe <module> <command>` prints arguments, options, the
    request schema, required fields and an example command line.
- A list that pages takes `--all` and then prints `{"items": […], "total": n}`;
  add `--max-items N` to stop early. Without `--all` you get one page.
- A field whose value is JSON, or a whole body, can be passed as a file with
  `--input body.json` (or `--input -` for stdin) instead of single options.
- A command that returns a file (an image, a PDF, an export) needs
  `--output <path>`; with `--json` it reports where the file went.

## Sign in

Check first: `nulara doctor --json`. Exit 0 means ready. Exit 3 means the user
has to sign in; ask them to run `nulara login` themselves (it opens a browser
for their consent). In CI the environment variable `NULARA_API_TOKEN` holds an
API key instead. `nulara workspace use <name>` switches between workspaces the
user signed in to; `--workspace <name>` overrides it for one command.

## Exit codes

| Exit | `error`                    | What to do                                      |
| ---- | -------------------------- | ----------------------------------------------- |
| 0    |                            | Success                                         |
| 1    | `runtime_error`            | Read `message`; often a missing `--yes`         |
| 2    | `configuration_error`      | Configuration or workspace selection is wrong   |
| 3    | `authentication_error`     | Ask the user to run `nulara login`              |
| 4    | `authorization_error`      | The user or key lacks the right; tell the user  |
| 5    | `api_error`                | The API refused; `code` names why, `detail` has the fields |
| 6    | `operation_error`          | The operation catalog is unusable               |
| 7, 8 | `thread_*`                 | The workspace agent's stream failed             |
| 9    | `usage_error`              | The command line was wrong; check `describe`    |
| 10   | `network_error`            | The API was unreachable; retry later            |
| 11   | `rate_limit_error`         | Wait `retry_after` seconds, then retry          |

Reads are retried on network errors and server errors already, and every
request on a rate limit, so do not wrap commands in your own retry loop.
A 422 `api_error` lists the invalid fields in `detail`; fix them and send the
command again.

## Digital product passport with QR code

1. Create the product (or find it with
   `nulara products list --search "<name>" --json`):

   ```console
   nulara products create --name "Steel bottle 0.75 l" --inventory-mode fungible --yes --json
   ```

   Keep the `id` of the result.

2. Ask what is still missing before publishing:

   ```console
   nulara passport-publications evaluate-readiness --subject-level product --product-id <product-id> --json
   ```

   `is_publishable` must be `true`; otherwise each entry of `findings` names
   what to fill in first. Tell the user, fill it in, evaluate again.

3. Publish. This signs the passport and makes it public, so confirm with the
   user first:

   ```console
   nulara passport-publications publish-passport --subject-level product --product-id <product-id> --yes --json
   ```

   The result holds the publication `id` and the public page in `viewer_url`.

4. Download the QR code that opens `viewer_url`:

   ```console
   nulara passport-publications get-qr-code <publication-id> --output passport-qr.png --json
   ```

   `--format svg` gives a vector file. The code is for sharing the passport
   page; it is not the regulated GS1 data carrier. An `api_error` with `code`
   `PASSPORT_NOT_PUBLISHED` means the passport is not public (yet or any more).

The CLI cannot send email. To send the QR code or the link, use the user's own
mail tool and attach the PNG.
