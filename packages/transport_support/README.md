<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-transport-support

Internal code shared by the built-in device transports of
[Hegemony](https://github.com/hegemony-sh/hegemony):
`hegemony-transport-netmiko`, `hegemony-transport-scrapli` and
`hegemony-transport-asyncssh`.

**Internal, no stability promise.** This package is not part of the SDK's
public surface. Its API can change in any release. Step plugins and
third-party transports must not depend on it; build on
`hegemony-step-sdk` instead.

It is released in lockstep with the SDK and the transports (same version),
and the transports pin it exactly.

## Contents

- `hegemony_transport_support.ssh` applies the SDK's SSH policy
  (`hegemony_step_sdk.ssh`: weak algorithms, weak keys, the legacy opt-in) to
  each SSH library's own options: `configure_paramiko` and
  `paramiko_algorithm_lists` for Paramiko, and `asyncssh_algorithms`,
  `asyncssh_algorithm_lists`, `asyncssh_security_options` and
  `validate_asyncssh_client_key` for AsyncSSH. It imports no SSH library;
  callers pass theirs in.

## Dependency direction

```
steps → hegemony-step-sdk ← hegemony-transport-support ← transports
```

The SDK never imports this package, and no step plugin does. A test in the
monorepo (`tests/test_package_architecture.py`) enforces both.
