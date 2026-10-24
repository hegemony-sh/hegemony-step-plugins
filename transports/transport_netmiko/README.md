<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-transport-netmiko

Netmiko network-CLI device transport for
[Hegemony](https://github.com/hegemony-sh/hegemony).

Registers the `netmiko` transport under the `hegemony.device_transports`
entry-point group — the concrete device-connection library behind the SDK
`Transport` I/O surface (`execute_command(s)`, `execute_command_timing`,
`scp_put`, `http_transfer`) for IOS-XE and other netmiko-supported platforms.

The transport is **not** named in handler ids: `netcli.*`, `shell.*`, and
other credentialed handlers reach it through `ctx.services.connect()`, and which
transport runs is resolved host-side from `device.access_config`. The host
resolves credentials into a `DeviceConnectionSpec` and injects its cancellation
registry, so this wheel never imports the platform's secret pipeline or settings.

## Host keys

When the host passes a `host_key_verifier` (hosts that check SSH host keys
do; the transport advertises `supports_host_key_verifier`), each hop, the
jump host first and then the device, accepts only the keys the verifier
trusts for it. A host that presents another key fails the connection during
the key exchange, before a password or private key is sent, and the
transport reports the key it saw to the verifier. On first contact the
transport fetches the host's key without logging in, has the verifier record
it, and then logs in accepting only that key. Without a verifier the
transport refuses to connect: it never connects without checking. Checks
switched off for a host (the verifier answers None) are the only way to
connect unchecked.

Netmiko takes host keys only from a file, so the device hop writes the
trusted keys to a private temporary `known_hosts` file and removes it once
the session is open.

## Agreed algorithms

When the host passes an `ssh_algorithm_recorder` (the transport advertises
`supports_ssh_algorithm_recorder`), each hop, the jump host first and then
the device, reports the key exchange, host key, cipher and MAC it agreed on
once it is logged in. paramiko drops both sides' KEXINIT messages after the
key exchange, so the transport connects through a paramiko transport that
keeps them (paramiko 3.2 or later), and the agreement is worked out from
them. paramiko 5.1.0 and later offer the post-quantum
`mlkem768x25519-sha256` key exchange first when `cryptography` supports
ML-KEM; an older paramiko records a classical one even when the device
offers more. A failure to record is logged and never fails the connection.
