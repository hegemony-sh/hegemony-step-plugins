<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# NETCONF RPC

`netconf.rpc` sends one NETCONF operation of your choosing to each target
device and keeps the reply: a vendor RPC, a YANG action, or a standard
operation the other netconf steps do not cover.

## Using It

Operation is the XML that goes inside `<rpc>`: exactly one element, with its
namespace. Templates are filled in before the step runs. For example, to
save the running configuration on IOS XE:

```xml
<save-config xmlns="http://cisco.com/yang/cisco-ia"/>
```

Escape every template value you place in the XML with the `e` filter:
`{{ inputs.description | e }}`. It turns `<`, `>`, `&`, `'` and `"` into XML
entities. Without it, a value such as `x</description><shutdown/><description>`
closes the element it belongs in and adds a `<shutdown/>` node to the
operation. Write `| e` on every value, also ones you expect to be plain,
such as a hostname.

`hello`, `close-session` and `kill-session` are refused: the step manages
its session itself. The operation runs as written, with no lock, diff or
rollback; use `netconf.edit_config` for configuration changes. Max Parallel
Devices defaults to 1. Port, timeouts and Allow legacy SSH work as in
`netconf.get`.

## Output

The summary reads `netconf <operation>: N/M devices`. Each device adds one
`cli_output` evidence record named `<device>:netconf <operation>` with the
reply.

- `steps.NODE_ID.output.devices`: each device's result by name: `ok`,
  `error`, `reply` (the content of `<rpc-reply>`, `<ok/>` for a plain
  success) and `warnings` (`rpc-error`s of severity warning).
- `steps.NODE_ID.output.truncated`: replies cut short in the output (16 KiB
  a device, 64 KiB the step); the evidence keeps them whole.

## When It Fails

The step fails without connecting when Operation is empty, not well-formed
XML, more than one element, or a refused operation. A device fails when it
cannot be reached and when it answers with an `rpc-error` of severity
error, which the step error quotes.
