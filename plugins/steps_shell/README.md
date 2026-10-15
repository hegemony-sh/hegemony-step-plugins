<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-shell

Remote shell execution for Hegemony flows — the `shell.` namespace.

Handlers: `shell.execute` — run commands on Linux/Unix hosts with exec-channel
semantics (meaningful exit codes, separate stdout/stderr), optionally wrapped
in `sh`/`bash`/`pwsh`. The transport (SSH today, WinRM planned) is resolved
from `device.access_config` via the platform's `open_shell` service; per
CONVENTIONS.md, neither transport nor interpreter ever appears in handler ids.

**In the platform's images**: the handler is in every instance's flow editor,
and a deployment that must not run commands on hosts leaves the wheel out. It
reaches only devices whose access config holds SSH credentials. This wheel
doubles as the reference for out-of-tree handler plugins.
