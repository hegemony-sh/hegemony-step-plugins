<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

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

The step's own `key=value` tags arrive as `ctx.tags` (`env=prod`,
`risk=high`, `phase=VERIFY` ...), so a handler can vary its behaviour per
tag. `phase` and `kind` are ordinary keys of that map, nothing more:
`ctx.tags.get("phase", "")` is `""` when the step carries no such tag.
