# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Code shared by Hegemony's built-in device transports.

Internal: this package has no stability promise. It is for the built-in
transports in this monorepo only (``hegemony-transport-netmiko``,
``-scrapli``, ``-asyncssh``) and is not part of the SDK's public surface.
Its API can change in any release; it is released in lockstep with the SDK
and the transports, which pin it exactly. Step plugins and third-party
transports must not import it: the contract they build on is
``hegemony-step-sdk``.

It depends on the SDK for the contract and policy; the SDK never depends on
it.
"""
