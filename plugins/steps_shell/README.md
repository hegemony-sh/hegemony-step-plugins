<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-shell

Remote shell execution for Hegemony flows — the `shell.` namespace.

Handlers: `shell.execute` — run commands on Linux/Unix hosts with exec-channel
semantics (meaningful exit codes, separate stdout/stderr), optionally wrapped
in `sh`/`bash`/`pwsh`; `shell.file_download` — have each host download a
file-repository file with `curl` through a short-lived link, and verify its
SHA-256. The file is picked in the editor or comes from a "Repository file"
run-form field (`file: "{{ inputs.package }}"`); the step's output carries a
reference to it (`{{ steps.<id>.output.file }}`, looked up again by path;
`output.file_id` names the exact file; on an older platform a download named
by id has no `output.file`, so pass `output.file_id` through `file_ids`) for
later steps; `shell.wait_for` — run one command again and again, on one
connection per host, until its output matches (or stops matching) a regular
expression, for the time after a reboot or an install. The transport (SSH today, WinRM planned) is resolved
from `device.access_config` via the platform's `open_shell` service; per
CONVENTIONS.md, neither transport nor interpreter ever appears in handler ids.

**In the platform's images**: the handlers are in every instance's flow editor,
and a deployment that must not run commands on hosts builds its api and worker
images without the wheel (`uv pip uninstall hegemony-steps-shell` in a derived
image). It reaches only devices whose access config holds SSH credentials. This wheel
doubles as the reference for out-of-tree handler plugins.
