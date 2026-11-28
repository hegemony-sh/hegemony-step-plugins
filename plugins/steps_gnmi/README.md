<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-gnmi

gNMI (gRPC Network Management Interface) for Hegemony flows — the `gnmi.`
namespace. Vendor-neutral: openconfig gNMI 0.10 over gRPC with TLS, with the
encodings each device supports read from its Capabilities answer.

Handlers:

- `gnmi.get` — read configuration and state data (Get) for a list of
  paths, as JSON values per path.
- `gnmi.set` — change configuration as one transaction (Set): deletes,
  replaces and updates, with a dry run and the values before and after.

The platform has no gNMI channel to hand out, so this wheel dials the device
itself (`hegemony_steps_gnmi.client`, on `grpc.aio`) and applies what the
platform applies to its own connections: the flow's egress policy for the
device's name and every address it resolves to
(`services.enforce_egress`), the refusal of loopback, link-local,
unspecified and multicast addresses, TLS verified against the system store
and the organization's trusted CAs (`services.trusted_ca_certificates`), and
the device's SSH login (`services.resolve_device_credentials`) sent as call
metadata. Devices behind a jump host are refused.

The protocol's messages come from openconfig's `gnmi.proto` and
`gnmi_ext.proto` (`src/hegemony_steps_gnmi/proto/`, Apache-2.0, unchanged),
loaded from their compiled descriptors (`_descriptors.py`) into a private
descriptor pool (`hegemony_steps_gnmi.messages`): no generated `_pb2` code
and no exact protobuf version. `scripts/gen_gnmi_descriptors.py` rebuilds
the descriptors after the `.proto` files are replaced.

Namespace prefix (= entry-point name): `gnmi.` — see the repo-level
`CONVENTIONS.md` for the naming rules. Each handler has its page under
`src/hegemony_steps_gnmi/docs/`.
