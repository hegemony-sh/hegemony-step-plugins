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
