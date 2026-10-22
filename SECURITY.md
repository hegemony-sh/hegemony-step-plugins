<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Security Policy

Security reports are handled privately. Please do not open a public GitHub issue for vulnerabilities, suspected vulnerabilities, leaked secrets, or exploit details.

This policy covers what this repository publishes: the step-handler SDK, the step-handler, device-transport and probe wheels, the `ansible-runner` and `opentofu-runner` images, and the build and release workflows. A vulnerability in the Hegemony platform itself is reported the same way; its own policy is in the [platform's SECURITY.md](https://github.com/hegemony-sh/hegemony/blob/develop/SECURITY.md).

## Supported versions

Releases are cut from `main` only, and a release is immutable. A security fix is therefore published as a new release of the newest line (the version in the [Releases](https://github.com/hegemony-sh/hegemony-step-plugins/releases) list) and is not backported to older releases of this repository.

Which Hegemony platform versions are supported, and for how long, is set by the platform's [support policy](https://github.com/hegemony-sh/hegemony/blob/develop/SECURITY.md#supported-versions). The platform picks up a fix from this repository by pinning the new release, so a platform fix release may be needed before a deployment receives it.

## Reporting a vulnerability

Report vulnerabilities privately by emailing [security@hegemony.sh](mailto:security@hegemony.sh).

Please include as much detail as you can safely share:

- Affected component (a wheel such as `hegemony-steps-http`, the SDK, a runner image, or a workflow) and the handler id, if one is involved.
- Impact and attack scenario.
- Reproduction steps or proof-of-concept details.
- Affected versions, commits, configuration, and how the wheel is deployed (platform version, or standalone).
- Whether the issue is already public or under active exploitation.
- A safe way to contact you for follow-up.

Do not include production secrets, customer data, private keys, or exploit traffic from systems you do not own or have permission to test.

## Response targets

Maintainers aim to follow this timeline:

| Stage | Target |
| --- | --- |
| Acknowledge receipt | 48 hours |
| Initial triage and severity assessment | 7 days |
| Coordinated fix and disclosure target | 90 days |

These targets may vary based on severity, complexity, affected dependencies, maintainer availability, and responsible-disclosure coordination.

## Disclosure process

1. Maintainers acknowledge the report and establish a private coordination channel.
2. Maintainers validate the report, assess severity, and identify affected versions.
3. A fix, mitigation, or advisory is prepared privately.
4. Disclosure timing is coordinated with the reporter when possible.
5. Public details are published after a fix or mitigation is available, or after the coordinated disclosure window expires.

Each vulnerability is published as an advisory on this repository's [Security tab](https://github.com/hegemony-sh/hegemony-step-plugins/security/advisories), with the affected and fixed versions, and the release that carries the fix links it in its notes. A fix that also needs a platform release is announced as described in the platform's policy.

## Safe harbor

Security research conducted in good faith is welcome. Please avoid privacy violations, service disruption, data destruction, persistence, social engineering, spam, and testing against systems you do not own or do not have permission to test.

## Secrets

If you believe a secret was committed or exposed, report it privately. Do not rotate, use, or test credentials unless they belong to you and you are authorized to do so.
