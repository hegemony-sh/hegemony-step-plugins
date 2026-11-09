<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-step-sdk

Public SDK for Hegemony step-handler plugins.

A step handler implements the work one flow step performs. A plugin wheel
subclasses `BaseHandler`, declares a pydantic `config_model` plus editor
metadata, and exposes a `register(registry)` callable under the
`hegemony.step_handlers` entry-point group:

```python
from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    InvalidConfigError,
    StepKind,
)


class HttpRequestConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    url: str = Field(title="URL")
    timeout_seconds: int = Field(default=30, ge=1, title="Timeout (seconds)")


class HttpRequestHandler(BaseHandler):
    handler_id = "http.request"
    supported_kinds = [StepKind.ACTION]
    display_name = "HTTP Request"
    config_model = HttpRequestConfig
    run_timeout_field = "timeout_seconds"

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        try:
            config = self.parse_config(ctx.config, HttpRequestConfig)
        except InvalidConfigError as exc:
            return exc.result()
        ...


def register(registry) -> None:
    registry.register_handler_type(HttpRequestHandler)
```

Read the step's settings through `parse_config`, not `ctx.config.get`. It
runs `validate_config` and returns the parsed model, so the handler gets the
model's defaults (the ones the editor and the reference docs show), values
converted to the field's type (a rendered `{{ }}` template is a string), and a
renamed field's old name, which the field keeps accepting:

```python
from pydantic import AliasChoices, Field

...
    duration_seconds: int = Field(
        default=30,
        validation_alias=AliasChoices("duration_seconds", "seconds"),
        json_schema_extra={"x_legacy_keys": ["seconds"]},
    )
```

`x_legacy_keys` tells the editor to show a step saved under the old name in
the new field.

A handler that enforces a time limit of its own for the whole step names its
field in `run_timeout_field`. The host then gives the step at least that long
plus `run_timeout_margin_seconds` (60 by default), so the handler stops first
and its output is kept. An older host ignores the attribute, so check the time
left against `ctx.timeout_seconds` too.

`supported_kinds` is informational: the platform lists it as the plugin's
capabilities, and neither the engine nor the editor reads it. A step's `kind`
tag changes nothing about how the step runs.

Handlers reach every platform facility — device transports, secret/template
resolution, the internal API, notifications — through `ctx.services`
(`HandlerServices`); plugin code never imports Hegemony internals.

A device transport that checks SSH host keys sets
`supports_host_key_verifier = True` and takes a `host_key_verifier`
(`HostKeyVerifier`) at construction. Before it dials a hop it asks
`trusted_keys(host, port)` and connects accepting only those keys: None means
no check, an empty tuple means first contact (fetch the key without logging
in, then `learn` it). A host that presents another key is reported with
`rejected(...)`, and the transport raises the `HostKeyRejectedError` it
returns. Without a verifier such a transport refuses to connect; only a
verifier that answers None (checks switched off) lets it connect unchecked.

A device transport that reports what each SSH hop agreed on sets
`supports_ssh_algorithm_recorder = True` and takes an
`ssh_algorithm_recorder` (`SshAlgorithmRecorder`). Once a hop is logged in,
the jump host first, it calls `record(host, port, algorithms)` with the
`SshAlgorithms` (key exchange, host key, cipher and MAC) the hop agreed on.
`SshAlgorithms.from_kexinit` works them out from the two sides' KEXINIT
messages by the rule both sides follow (RFC 4253 §7.1), so a transport only
has to keep those messages. A failure to record never fails the connection.

Legacy SSH algorithms are off by default; a step turns them on with the
`allow_legacy_ssh` setting (`SshSecurityConfig`). A transport that honours it
also has a static `ssh_algorithm_lists(allow_legacy=False)`, the exact
algorithms its connections offer by kind (`kex`, `host_key`, `cipher`, `mac`),
built with `hegemony_step_sdk.ssh.asyncssh_algorithm_lists` or
`paramiko_algorithm_lists`. Comparing the two calls shows what the opt-in
adds. `legacy_algorithms(agreed, secure)` names the algorithms a connection
agreed on that only the opt-in allowed. The field's JSON schema carries
`"x-hegemony-help": "legacy-ssh-algorithms"`, the help topic a host links the
setting to.

The step's own `key=value` tags arrive as `ctx.tags` (`env=prod`,
`risk=high`, `phase=VERIFY` ...), so a handler can vary its behaviour per
tag. `phase` and `kind` are ordinary keys of that map, nothing more:
`ctx.tags.get("phase", "")` is `""` when the step carries no such tag.

A handler that stores values in the run organization's secret store
declares `writes_secrets = True` and calls `services.read_secret`,
`write_secret` and `delete_secret` with a path relative to the
organization's own secret root (`certs/web`). The host decides where that
path lives, refuses what the organization's administrators have not allowed,
registers the values for redaction and audits each call; `write_secret`
returns a `SecretWriteResult` naming the stored keys and the reference later
steps read them through, never the values. A write or delete that raises may
still have been applied, so read the secret back to learn what it holds. On a
store that keeps versions, the host leaves no replaced or deleted value
readable through the store's history, and `read_secret` treats a soft-deleted
secret as absent. Hosts older than these services lack the methods, so check
for them with `getattr` and fail clearly.

A handler that starts inventory syncs declares `syncs_inventory = True` and
calls `services.sync_inventory(provider, max_age_seconds=...)` with one of
the run organization's inventory providers, by id or by name. The host runs
the sync only for a provider an administrator has opened to flows, and
answers `fresh` (none ran: the last one is recent enough) or `busy` (another
sync is running) instead of syncing when it should not. Check for the method
with `getattr` too.

A handler that verifies TLS trusts the worker's system store plus the run
organization's trusted CAs, which administrators keep under Settings, Trusted
CAs. `services.trusted_ca_certificates()` returns that list as PEM text (`""`
for none). It is the run organization's own list: for a flow shared from the
platform's shared organization, the list of the organization that runs it;
two organizations' lists are never combined. `hegemony_step_sdk.trust` wraps
it: `org_trusted_ca_pem(services)` returns None on a host without the
service, and `add_trusted_cas(context, pem)` adds the certificates to an
`ssl` context. A `ca_bundle` a step sets still replaces both (it pins those
CAs).

## API reference

Import public handler contracts from `hegemony_step_sdk`. The SDK exposes
Python interfaces; individual step configuration and output contracts are
documented by each plugin's README and packaged handler documentation.

| Interface | Inputs | Result and calling convention |
| --- | --- | --- |
| `StepHandlerRegistry.register_handler_type` | Handler class | Synchronous registration; returns `None` |
| `BaseHandler.execute` | `HandlerContext` | Async; await for a `HandlerResult` |
| `BaseHandler.validate_config` | Configuration dictionary | Synchronous; list of validation errors (empty when valid) |
| `BaseHandler.parse_config` | Configuration mapping and Pydantic model class | Synchronous; parsed model or `InvalidConfigError` |
| `BaseHandler.template_errors` | Configuration dictionary | Synchronous; list of template-validation errors |
| `HandlerContext.require_services` | No arguments | Synchronous; `HandlerServices` or an exception if absent |
| `HandlerContext.get_target_devices` | No arguments | Synchronous; selected device dictionaries |
| `HandlerContext.get_target_ips` | No arguments | Synchronous; selected IP strings |
| `HandlerContext.emit_progress` / `emit_output` | Progress/output arguments described in the signatures | Async; await delivery to the host callback |

`HandlerContext` carries run/flow/step identifiers, target selections, config,
parameters, previous outputs, timeout, attempt number, tags and optional host
services. `HandlerResult` carries success, summary, metrics, evidence, error and
output. `InvalidConfigError.result()` turns invalid configuration into a failed
result. Keep resolved credentials out of results and logs.

Host services include secret resolution and storage, transport access, internal
API access, child runs, notifications, probes, containers and artifacts.
Methods declared `async` must be awaited, for example
`await ctx.require_services().render_template(template)`.
Some methods return resources synchronously: `connect(...)` returns a
`Transport`; `open_state_backend(...)` returns an async context manager
to use with `async with`. `open_api_client(...)` returns an `httpx.AsyncClient` which
also needs to be closed, normally with `async with`.
`validate_secret_ref`, `contains_template`, `container_runtime` and
`is_check_registered` are synchronous. See the service reference for each
method's exact arguments and result.

From the repository root, render the complete signatures, fields and docstrings:

```bash
uv sync --frozen --all-packages
uv run python -m pydoc hegemony_step_sdk
uv run python -m pydoc hegemony_step_sdk.contract
uv run python -m pydoc hegemony_step_sdk.registry
uv run python -m pydoc hegemony_step_sdk.services
uv run python -m pydoc hegemony_step_sdk.transports
uv run python -m pydoc hegemony_step_sdk.probes
uv run python -m pydoc hegemony_step_sdk.trust
uv run python -m pydoc hegemony_step_sdk.docs
uv run python -m pydoc hegemony_step_sdk.concurrency
uv run python -m pydoc hegemony_step_sdk.enums
```

For local HTML browsing, run `uv run python -m pydoc -b`, open the SDK module,
and follow its class/module links; stop the server when finished. With an
installed SDK, omit `uv run`.
