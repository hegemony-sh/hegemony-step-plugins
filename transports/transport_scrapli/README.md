<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-transport-scrapli

Scrapli network-CLI device transport for
[Hegemony](https://github.com/hegemony-sh/hegemony).

Registers the `scrapli` transport under the `hegemony.device_transports`
entry-point group — an alternative to the default netmiko transport for the
scrapli core platforms (IOS-XE, IOS-XR, NX-OS, EOS, Junos), running
`AsyncScrapli` over scrapli's asyncssh transport plugin (natively async, no
paramiko in the dependency tree). Implements the SDK `Transport` command
surface (`execute_command(s)`, `execute_command_timing`); file staging
(`scp_put`, `http_transfer`) is not supported by this transport and raises
`NotImplementedError` — use the netmiko transport for staging steps.

The transport is **not** named in handler ids: `netcli.*` and other
credentialed handlers reach it through `ctx.services.connect()`, and which
transport runs is resolved host-side from `device.access_config`
(`access_config.ssh.transport: "scrapli"`). The host resolves credentials into
a `DeviceConnectionSpec` and injects its cancellation registry, so this wheel
never imports the platform's secret pipeline or settings.

## Host keys

When the host passes a `host_key_verifier` (hosts that check SSH host keys
do; the transport advertises `supports_host_key_verifier`), each hop, the
jump host first and then the device, accepts only the keys the verifier
trusts for it. A host that presents another key fails the connection during
the key exchange, before a password or private key is sent, and the
transport reports the key it saw to the verifier. On first contact the
transport fetches the host's key without logging in, has the verifier record
it, and then logs in accepting only that key. Without a verifier, any host
key is accepted, as before.
