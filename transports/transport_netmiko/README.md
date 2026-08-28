<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-transport-netmiko

Netmiko network-CLI device transport for
[Hegemony](https://github.com/hegemony-sh/hegemony).

Registers the `netmiko` transport under the `hegemony.device_transports`
entry-point group — the concrete device-connection library behind the SDK
`Transport` I/O surface (`execute_command(s)`, `execute_command_timing`,
`scp_put`, `http_transfer`) for IOS-XE and other netmiko-supported platforms.

The transport is **not** named in handler ids: `netcli.*`, `cisco.iosxe.*`, and
other credentialed handlers reach it through `ctx.services.connect()`, and which
transport runs is resolved host-side from `device.access_config`. The host
resolves credentials into a `DeviceConnectionSpec` and injects its cancellation
registry, so this wheel never imports the platform's secret pipeline or settings.
