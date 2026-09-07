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
from hegemony_step_sdk import BaseHandler, HandlerContext, HandlerResult, StepKind


class HttpRequestHandler(BaseHandler):
    handler_id = "http.request"
    supported_kinds = [StepKind.ACTION]
    display_name = "HTTP Request"

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        ...


def register(registry) -> None:
    registry.register_handler_type(HttpRequestHandler)
```

Handlers reach every platform facility — device transports, secret/template
resolution, the internal API, notifications — through `ctx.services`
(`HandlerServices`); plugin code never imports Hegemony internals.

The step's own `key=value` tags arrive as `ctx.tags` (`env=prod`,
`risk=high`, `phase=VERIFY` ...), so a handler can vary its behaviour per
tag. `phase` and `kind` are ordinary keys of that map, nothing more:
`ctx.tags.get("phase", "")` is `""` when the step carries no such tag.
