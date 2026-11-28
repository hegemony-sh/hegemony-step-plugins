<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-transport-napalm

NAPALM device transport for
[Hegemony](https://github.com/hegemony-sh/hegemony).

Registers the `napalm` transport under the `hegemony.device_transports`
entry-point group. It does two things:

- **Network CLI.** It is the netmiko transport with one addition, so a
  device whose `access_config.ssh.transport` is `napalm` runs `netcli.*`
  steps exactly as it would with `netmiko`.
- **NAPALM sessions.** `open_napalm()` returns a NAPALM driver session (the
  SDK's `NapalmSession`), which the platform hands to `napalm.*` steps
  through `services.open_napalm`.

## How the session is secured

NAPALM's SSH drivers run every operation on one netmiko connection. This
wheel gives the driver the connection the netmiko transport's own login
opens, instead of letting the driver open one. So a NAPALM session has the
same protections as a CLI step: the organization's trusted SSH host keys on
the device and its jump host, the SSH algorithm policy, the record of the
algorithms agreed, and cancellation when the run is cancelled. The driver is
never given the password.

Nothing opens a second SSH connection. netmiko's SCP would, without the
trusted keys and without the jump host, so IOS candidates go through the
session's TCL shell and NX-OS replace (SCP only) is refused.

Getter results never carry credentials: `config` is read with NAPALM's
sanitizing, which masks passwords, keys and community strings, and fields
such as `authentication_key` (BGP neighbor passwords) are dropped from every
result.

This is why the wheel depends on `hegemony-transport-netmiko` at the same
version. It is the one transport allowed to build on another
(`tests/test_package_architecture.py`, `BUILT_ON`).

## Supported platforms

| Device platform | NAPALM driver | Notes |
| --- | --- | --- |
| `ios-xe`, `ios` | `ios` | Loading a candidate sends it through the session with the device's TCL shell (`tclsh`), not SCP. Commit with automatic rollback needs the `archive` feature. NAPALM turns on `file prompt quiet` for the session and turns it off again when it closes. |
| `eos` | `eos` (over SSH) | Uses EOS configuration sessions. The eAPI (HTTPS) mode is never used. |
| `nxos` | `nxos_ssh` | Merge only: replace copies the file with SCP and is refused. No commit with automatic rollback. |

It logs in with paramiko, as the netmiko transport does, so a device that
offers only the oldest SSH key exchanges (an old IOS router that needs
`diffie-hellman-group1-sha1`) cannot be reached with it even with legacy SSH
allowed.

Other platforms are refused with a clear error. Junos is not offered: its
NAPALM driver connects through PyEZ, which skips SSH host-key checks unless
told otherwise, and NAPALM gives no way to tell it. The eAPI, NX-API and
IOS-XR drivers are not offered either: they connect outside the SSH trust
model.
