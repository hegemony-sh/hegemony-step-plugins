<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-netcli

Network-device CLI paradigm: execute command lines and collect outputs as
evidence. Vendor-neutral by design — platform
dialects and transports (netmiko/scrapli, ssh) are resolved beneath the
handler layer from device access config.

Handlers: `netcli.execute`, `netcli.collect_evidence`.

Namespace prefix (= entry-point name): `netcli.` — see the repo-level
`CONVENTIONS.md` for the naming rules.

## SSH security

The built-in AsyncSSH, Scrapli and Netmiko device transports use the SSH
library's own default algorithms, minus the ones known to be weak: SHA-1 key
exchange, CBC/3DES/Blowfish/CAST/RC4 encryption, SHA-1/MD5 and truncated
(96-bit) MACs, and DSA or SHA-1 signatures (`ssh-rsa`). The policy lists only
these weak families, so strong algorithms a library adds later, such as new
post-quantum key exchanges or Ed448, are used without a policy change. RSA
host keys must be at least 2048 bits and DSA host keys are refused. The policy
applies to the device and its jump host, including first-contact key
discovery. A failed secure negotiation never retries with weaker settings.

For an older device, enable **Allow legacy SSH algorithms**
(`allow_legacy_ssh: true`) in the `netcli.execute` or
`netcli.collect_evidence` step. This offers every algorithm the installed SSH
library still implements, weak ones included (for example CBC/3DES, SHA-1/MD5
MACs and SHA-1 key exchange/signatures), and permits smaller host or login
keys. Use it only on trusted networks while upgrading the device; these
choices weaken confidentiality or authentication. The override affects both
hops of that step and leaves host-key identity verification in place. It does
not change other steps or organizations.

Libraries cannot negotiate algorithms they have removed. Current Paramiko
does not implement SHA-1 key exchange or SHA-1 RSA host signatures; use the
AsyncSSH or Scrapli transport for a legacy peer which requires it. A transport
without policy-setting support rejects a requested legacy override rather than
silently ignoring it.

This setting governs the built-in device transports used by the netcli steps.
It does not configure the host's `shell.execute` implementation or external
Ansible/OpenSSH clients. Login identities must also meet the minimum key size.
Explicit jump-host keys and Netmiko authentication keys are validated. AsyncSSH
and Scrapli check automatically loaded file, agent, and PKCS#11 identities
before offering them to the server. Weak discovered identities are skipped, with
a logged warning naming the key and the reason, so a later strong key
or password can still authenticate; an explicitly configured weak jump-host key
is rejected. RSA user keys and OpenSSH certificate signing keys must be at
least 2048 bits, and X.509 identities are checked by their subject key.
Ed25519, Ed448, ECDSA and hardware-backed Ed25519/P-256 identities remain
supported. The explicit legacy override also permits smaller login keys.
