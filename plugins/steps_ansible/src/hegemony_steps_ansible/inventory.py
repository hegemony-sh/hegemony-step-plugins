# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Build an Ansible inventory from Hegemony's inventory.

Every inventory source — the local inventory, Git, NetBox — is synced into the
platform's device table, and a run's targets are rows of it. So a step's target
devices are all a playbook needs: this module turns them into an inventory in
Ansible's YAML-plugin structure (written as JSON, which that plugin reads), with
groups derived from the flow's roles and the devices' platform, site, tags, and
inventory provider.

Pure functions only — no I/O, no secrets. Credentials are added separately as
``host_vars`` files (see :func:`credential_host_vars`), so the inventory file
itself never holds a secret.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

GroupDimension = Literal["role", "platform", "site", "tag", "provider"]

#: Group dimensions a step can derive groups from.
GROUP_DIMENSIONS: tuple[GroupDimension, ...] = ("role", "platform", "site", "tag", "provider")

#: Characters Ansible accepts in a group name (``^[A-Za-z_][A-Za-z0-9_]*$``);
#: anything else warns or is replaced depending on the controller setting.
_INVALID_GROUP_CHARS = re.compile(r"[^A-Za-z0-9_]")
#: Host names double as ``host_vars/<name>.json`` file names, so they are kept
#: to a file-safe set (``:`` would also read as a port to the YAML plugin).
_INVALID_HOST_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")

#: Device attribute whose mapping is merged into the host's variables, so
#: inventory owners (NetBox custom fields, Git device files) can tune Ansible
#: per device — ``ansible_python_interpreter``, the network OS, playbook data.
ANSIBLE_VARS_ATTRIBUTE = "ansible_vars"

#: The only ``ansible_*`` variables that attribute may set. Inventory editors
#: are not necessarily flow authors: connection, login, become, ssh-argument,
#: proxy-command and executable variables would let them run commands in the
#: step container (``ansible_connection: local``) or at connect time, with
#: every credential of the run staged beside them. Those come from Hegemony
#: only; any other ``ansible_*`` key in the attribute is ignored.
DEVICE_ANSIBLE_VARS_ALLOWED = frozenset(
    {
        "ansible_python_interpreter",
        "ansible_network_os",
        "ansible_network_cli_ssh_type",
        "ansible_connect_timeout",
        "ansible_command_timeout",
    }
)


#: Where a Jinja expression, statement or comment starts. Ansible templates
#: every string it reads from inventory, host_vars, group_vars and ``-e @file``
#: files, so text from device records or secrets that contains one would run.
_TEMPLATE_START_RE = re.compile(r"\{[{%#]")


def has_template(value: Any) -> bool:
    """Whether ``value`` (strings inside mappings and lists too) holds template syntax."""
    if isinstance(value, str):
        return bool(_TEMPLATE_START_RE.search(value))
    if isinstance(value, Mapping):
        return any(has_template(key) or has_template(item) for key, item in value.items())
    if isinstance(value, list | tuple):
        return any(has_template(item) for item in value)
    return False


def literal(value: Any) -> Any:
    """``value`` with every template start escaped, so Ansible renders it as written.

    ``{{`` becomes ``{{ '{{' }}`` (and likewise ``{%`` and ``{#``), which Jinja
    renders back to exactly ``{{``: the value is kept, and nothing in it runs.
    Text from device records and secrets goes through this before Ansible
    reads it; a password with braces in it then also works.
    """
    if isinstance(value, str):
        return _TEMPLATE_START_RE.sub(lambda match: "{{ '" + match.group(0) + "' }}", value)
    if isinstance(value, Mapping):
        return {literal(key): literal(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [literal(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class PlatformConnection:
    """How Ansible reaches a device of one platform."""

    connection: str
    network_os: str | None = None

    @property
    def is_network_cli(self) -> bool:
        return self.connection == "ansible.netcommon.network_cli"


_NETWORK_CLI = "ansible.netcommon.network_cli"
_NETCONF = "ansible.netcommon.netconf"
_SSH = PlatformConnection(connection="ssh")

#: Hegemony platform strings (normalized: lowercase, no separators) mapped to
#: Ansible's network OS and connection. Unknown platforms are servers over SSH.
_PLATFORMS: dict[str, PlatformConnection] = {
    "ios": PlatformConnection(_NETWORK_CLI, "cisco.ios.ios"),
    "iosxe": PlatformConnection(_NETWORK_CLI, "cisco.ios.ios"),
    "ciscoios": PlatformConnection(_NETWORK_CLI, "cisco.ios.ios"),
    "ciscoiosxe": PlatformConnection(_NETWORK_CLI, "cisco.ios.ios"),
    "nxos": PlatformConnection(_NETWORK_CLI, "cisco.nxos.nxos"),
    "cisconxos": PlatformConnection(_NETWORK_CLI, "cisco.nxos.nxos"),
    "iosxr": PlatformConnection(_NETWORK_CLI, "cisco.iosxr.iosxr"),
    "ciscoxr": PlatformConnection(_NETWORK_CLI, "cisco.iosxr.iosxr"),
    "ciscoiosxr": PlatformConnection(_NETWORK_CLI, "cisco.iosxr.iosxr"),
    "eos": PlatformConnection(_NETWORK_CLI, "arista.eos.eos"),
    "aristaeos": PlatformConnection(_NETWORK_CLI, "arista.eos.eos"),
    # Most Junos modules speak NETCONF; network_cli covers only a few.
    "junos": PlatformConnection(_NETCONF, "junipernetworks.junos.junos"),
    "juniperjunos": PlatformConnection(_NETCONF, "junipernetworks.junos.junos"),
}


def platform_connection(platform: object) -> PlatformConnection:
    """Ansible connection settings for a Hegemony platform string."""
    if not isinstance(platform, str):
        return _SSH
    key = re.sub(r"[^a-z0-9]", "", platform.lower())
    return _PLATFORMS.get(key, _SSH)


def group_name(prefix: str, value: str) -> str:
    """A valid Ansible group name for ``value`` under ``prefix`` (may be empty)."""
    raw = f"{prefix}_{value}" if prefix else value
    name = _INVALID_GROUP_CHARS.sub("_", raw.strip()).strip("_").lower()
    name = re.sub(r"_+", "_", name)
    if not name:
        name = "_"
    if name[0].isdigit():
        name = "_" + name
    return name


@dataclass
class InventoryHost:
    """One inventory host and the Hegemony device behind it."""

    name: str
    device: dict[str, Any]
    groups: set[str] = field(default_factory=set)
    variables: dict[str, Any] = field(default_factory=dict)
    # Keys of the device's ``ansible_vars`` attribute that were not applied.
    ignored_vars: list[str] = field(default_factory=list)
    # The flow roles the device is in the inventory for (unsanitized).
    roles: set[str] = field(default_factory=set)

    @property
    def device_id(self) -> str | None:
        value = self.device.get("id")
        return str(value) if value else None


@dataclass
class Inventory:
    """A built inventory: the document plus the host → device mapping."""

    hosts: list[InventoryHost]
    # group name -> child group names (site hierarchy)
    children: dict[str, set[str]]

    def host_by_name(self) -> dict[str, InventoryHost]:
        return {host.name: host for host in self.hosts}

    def without(self, names: set[str]) -> Inventory:
        """This inventory minus the hosts named, and the groups left empty."""
        hosts = [host for host in self.hosts if host.name not in names]
        alive = {group for host in hosts for group in host.groups}
        changed = True
        while changed:
            changed = False
            for parent, kids in self.children.items():
                if parent not in alive and kids & alive:
                    alive.add(parent)
                    changed = True
        children = {
            parent: kids & alive for parent, kids in self.children.items() if parent in alive
        }
        return Inventory(hosts=hosts, children=children)

    def document(self) -> dict[str, Any]:
        """The inventory in Ansible's YAML-plugin structure (JSON-serializable).

        Every host is listed once under ``all.hosts`` with its variables;
        groups list member hosts with no variables (the YAML plugin merges
        them), and the site hierarchy is expressed as ``children``.
        """
        groups: dict[str, dict[str, Any]] = {}
        for host in self.hosts:
            for name in host.groups:
                groups.setdefault(name, {"hosts": {}})["hosts"][host.name] = None
        for parent, kids in self.children.items():
            entry = groups.setdefault(parent, {})
            entry.setdefault("children", {})
            for kid in sorted(kids):
                entry["children"][kid] = groups.setdefault(kid, {})
        top_level = {
            name: groups[name]
            for name in sorted(groups)
            if not any(name in kids for kids in self.children.values())
        }
        return {
            "all": {
                "hosts": {host.name: host.variables for host in self.hosts},
                "children": top_level,
            }
        }


def _host_name(device: Mapping[str, Any], used: set[str]) -> str:
    raw = str(device.get("name") or device.get("hostname") or device.get("mgmt_host") or "host")
    base = _INVALID_HOST_CHARS.sub("_", raw.strip()).lstrip(".") or "host"
    name = base
    suffix = 2
    while name in used:
        name = f"{base}__{suffix}"
        suffix += 1
    used.add(name)
    return name


def _site_groups(site: object) -> list[str]:
    """``site_emea``, ``site_emea_nl``, ``site_emea_nl_ams01`` for ``emea/nl/ams01``."""
    if not isinstance(site, Mapping):
        return []
    path = site.get("path") or site.get("name")
    if not isinstance(path, str) or not path.strip():
        return []
    parts = [part for part in path.split("/") if part.strip()]
    return [group_name("site", "_".join(parts[: index + 1])) for index in range(len(parts))]


def _device_var_allowed(key: str) -> bool:
    if key == "hegemony":
        return False
    if key.lower().startswith("ansible_"):
        return key in DEVICE_ANSIBLE_VARS_ALLOWED
    return True


def _host_variables(
    device: Mapping[str, Any], connection: PlatformConnection
) -> tuple[dict[str, Any], list[str]]:
    """The host's inventory variables, and the attribute keys left out."""
    variables: dict[str, Any] = {}
    if device.get("mgmt_host"):
        variables["ansible_host"] = literal(device["mgmt_host"])
    port = device.get("mgmt_port")
    if isinstance(port, int) and not isinstance(port, bool) and port > 0:
        variables["ansible_port"] = port
    variables["ansible_connection"] = connection.connection
    if connection.network_os:
        variables["ansible_network_os"] = connection.network_os
    if connection.is_network_cli:
        # paramiko is deprecated in ansible-core 2.19 and removed in 2.21.
        variables["ansible_network_cli_ssh_type"] = "libssh"
    site = device.get("site")
    # Device records are data, never templates (see literal()).
    variables["hegemony"] = literal(
        {
            "id": device.get("id"),
            "name": device.get("name"),
            "display_name": device.get("display_name"),
            "platform": device.get("platform"),
            "provider_id": device.get("provider_id"),
            "external_id": device.get("external_id"),
            "site": site.get("path") if isinstance(site, Mapping) else None,
            "mgmt_ips": device.get("mgmt_ips") or [],
            "tags": dict(device.get("tags") or {}),
            "attributes": dict(device.get("attributes") or {}),
        }
    )
    attributes = device.get("attributes")
    overrides = attributes.get(ANSIBLE_VARS_ATTRIBUTE) if isinstance(attributes, Mapping) else None
    ignored: list[str] = []
    if isinstance(overrides, Mapping):
        for key, value in overrides.items():
            # A template in a value would run in the step's container when the
            # play reads the variable, with the run's credentials beside it.
            if _device_var_allowed(str(key)) and not has_template(value):
                variables[str(key)] = value
            else:
                ignored.append(str(key))
    return variables, sorted(ignored)


def build_inventory(
    devices_by_role: Mapping[str, Iterable[Mapping[str, Any]]],
    *,
    group_by: Iterable[str] = GROUP_DIMENSIONS,
) -> Inventory:
    """Build the inventory for the given role → devices mapping.

    A device targeted under several roles is one host in several role groups.
    Role groups keep the flow author's own names (sanitized); every other
    derived group carries a prefix — ``platform_``, ``site_``, ``tag_``,
    ``provider_``. A role whose group name would be one of Ansible's own
    groups (``all``, ``ungrouped``) or carry the prefix of a derived group
    being built would silently merge with it, so it is refused.

    Host names are the device name made file-safe (runs of anything but
    letters, digits, ``_ . -`` become ``_``, leading dots are dropped), with
    ``__2``, ``__3`` … appended to repeats.

    Raises ``ValueError`` for a role whose group name is reserved.
    """
    dimensions = set(group_by)
    if "role" in dimensions:
        for role in devices_by_role:
            if role:
                _check_role_group(role, dimensions)
    hosts: list[InventoryHost] = []
    by_identity: dict[str, InventoryHost] = {}
    used_names: set[str] = set()
    children: dict[str, set[str]] = {}

    for role, devices in devices_by_role.items():
        for device in devices:
            identity = str(
                device.get("id")
                or (
                    f"{device.get('provider_id')}:{device.get('external_id')}"
                    if device.get("external_id")
                    else device.get("name")
                )
            )
            host = by_identity.get(identity)
            if host is None:
                connection = platform_connection(device.get("platform"))
                variables, ignored_vars = _host_variables(device, connection)
                host = InventoryHost(
                    name=_host_name(device, used_names),
                    device=dict(device),
                    variables=variables,
                    ignored_vars=ignored_vars,
                )
                by_identity[identity] = host
                hosts.append(host)
                _add_derived_groups(host, dimensions, children)
            host.roles.add(role)
            if "role" in dimensions and role:
                host.groups.add(group_name("", role))

    return Inventory(hosts=hosts, children=children)


#: Groups Ansible defines itself.
RESERVED_GROUPS = frozenset({"all", "ungrouped"})


def _check_role_group(role: str, dimensions: set[str]) -> None:
    name = group_name("", role)
    if name in RESERVED_GROUPS:
        raise ValueError(
            f"role {role!r} would be the inventory group {name!r}, which Ansible "
            "reserves; rename the role"
        )
    for dimension in ("platform", "site", "tag", "provider"):
        if dimension in dimensions and (name == dimension or name.startswith(f"{dimension}_")):
            raise ValueError(
                f"role {role!r} would be the inventory group {name!r}, which the "
                f"{dimension} groups use; rename the role or leave {dimension} out of "
                "Inventory groups"
            )


def _add_derived_groups(
    host: InventoryHost, dimensions: set[str], children: dict[str, set[str]]
) -> None:
    device = host.device
    if "platform" in dimensions and isinstance(device.get("platform"), str):
        host.groups.add(group_name("platform", device["platform"]))
    if "provider" in dimensions and isinstance(device.get("provider_id"), str):
        host.groups.add(group_name("provider", device["provider_id"]))
    if "tag" in dimensions:
        tags = device.get("tags")
        if isinstance(tags, Mapping):
            for key, value in tags.items():
                host.groups.add(group_name("tag", f"{key}_{value}"))
    if "site" in dimensions:
        chain = _site_groups(device.get("site"))
        if chain:
            host.groups.add(chain[-1])
            for parent, kid in zip(chain, chain[1:], strict=False):
                children.setdefault(parent, set()).add(kid)
