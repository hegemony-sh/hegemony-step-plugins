<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-transport-asyncssh

AsyncSSH exec-channel device transport for
[Hegemony](https://github.com/hegemony-sh/hegemony).

Registers the `asyncssh` transport under the `hegemony.device_transports`
entry-point group — for server-like devices (Linux hosts, whitebox NOS,
appliances with a real shell) where commands run on SSH **exec channels** with
genuine exit codes, instead of the prompt-scraping network-CLI model netmiko
and scrapli implement. Runs natively async (no thread pool). Implements the
full SDK `Transport` surface: `execute_command(s)` via exec channels,
`execute_command_timing` via a PTY session, `scp_put` via SFTP, and
`http_transfer` by running `curl` on the remote host.

The transport is **not** named in handler ids: `netcli.*` and other
credentialed handlers reach it through `ctx.services.connect()`, and which
transport runs is resolved host-side from `device.access_config`
(`access_config.ssh.transport: "asyncssh"`). The host resolves credentials into
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
it, and then logs in accepting only that key. Without a verifier the
transport refuses to connect: it never connects without checking. Checks
switched off for a host (the verifier answers None) are the only way to
connect unchecked.

## Agreed algorithms

When the host passes an `ssh_algorithm_recorder` (the transport advertises
`supports_ssh_algorithm_recorder`), each hop, the jump host first and then
the device, reports the key exchange, host key, cipher and MAC it agreed on
once it is logged in. asyncssh keeps both sides' KEXINIT messages, and the
agreement is worked out from them. A failure to record is logged and never
fails the connection.
