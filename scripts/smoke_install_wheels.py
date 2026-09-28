# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Install built wheels in a clean virtualenv and verify imports, entry points, and docs.

The docs half is the only mechanical proof that a plugin's documentation
bundle left git and entered the built artifact: it loads every step-handler
package's bundle from the *installed* wheel and asserts one page per
registered handler id.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import tomllib
import venv
from pathlib import Path

from package_paths import PACKAGE_DIRS, ROOT

EXPECTED_MODULES = (
    "hegemony_step_sdk",
    "hegemony_steps_general",
    "hegemony_steps_probe",
    "hegemony_steps_netcli",
    "hegemony_steps_evidence",
    "hegemony_steps_container",
    "hegemony_steps_flow",
    "hegemony_steps_cisco_iosxe",
    "hegemony_steps_shell",
    "hegemony_steps_monitor",
    "hegemony_steps_ansible",
    "hegemony_steps_tf",
    "hegemony_probe_net",
    "hegemony_transport_netmiko",
    "hegemony_transport_scrapli",
    "hegemony_transport_asyncssh",
)

# Entry-point names under hegemony.step_handlers (claimed handler-id namespaces).
EXPECTED_ENTRY_POINTS = {
    "general",
    "probe",
    "netcli",
    "evidence",
    "container",
    "flow",
    "cisco.iosxe",
    "shell",
    "monitor",
    "ansible",
    "tf",
}

# Entry-point names under hegemony.probes (probe wheels).
EXPECTED_PROBE_ENTRY_POINTS = {
    "net",
}

# Entry-point names under hegemony.device_transports (transport wheels).
EXPECTED_TRANSPORT_ENTRY_POINTS = {
    "netmiko",
    "scrapli",
    "asyncssh",
}


_EXPECTED_BY_GROUP = {
    "hegemony.step_handlers": EXPECTED_ENTRY_POINTS,
    "hegemony.probes": EXPECTED_PROBE_ENTRY_POINTS,
    "hegemony.device_transports": EXPECTED_TRANSPORT_ENTRY_POINTS,
}


def source_gaps() -> list[str]:
    """Modules and entry points the source packages declare but the lists above lack.

    The lists are written out rather than read from the built wheels, so a
    wheel that lost its entry point fails the smoke test; this check makes
    sure a new package cannot be left out of them.
    """
    gaps: list[str] = []
    for package_dir in PACKAGE_DIRS:
        for module_dir in sorted((package_dir / "src").iterdir()):
            if (module_dir / "__init__.py").is_file() and module_dir.name not in EXPECTED_MODULES:
                gaps.append(f"EXPECTED_MODULES lacks {module_dir.name}")
        with (package_dir / "pyproject.toml").open("rb") as fh:
            project = tomllib.load(fh).get("project", {})
        for group, entries in project.get("entry-points", {}).items():
            expected = _EXPECTED_BY_GROUP.get(group)
            if expected is None:
                continue
            gaps.extend(
                f"expected entry points of {group} lack {name!r}"
                for name in sorted(entries)
                if name not in expected
            )
    return gaps


def _python_bin(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts" if sys.platform == "win32" else "bin") / "python"


def main() -> None:
    gaps = source_gaps()
    if gaps:
        raise SystemExit("Update the smoke test's expectations: " + "; ".join(gaps))
    wheels = sorted((ROOT / "dist").glob("*.whl"))
    if len(wheels) != len(PACKAGE_DIRS):
        raise SystemExit(f"Expected {len(PACKAGE_DIRS)} wheels in dist/, found {len(wheels)}")

    tmp = Path(tempfile.mkdtemp(prefix="hegemony-step-wheel-smoke-"))
    try:
        venv_dir = tmp / "venv"
        venv.EnvBuilder(with_pip=True).create(venv_dir)
        python = _python_bin(venv_dir)
        subprocess.run(
            ["uv", "pip", "install", "--python", str(python), *map(str, wheels)],
            cwd=ROOT,
            check=True,
        )
        code = f"""
from importlib import import_module
from importlib.metadata import entry_points

modules = {EXPECTED_MODULES!r}
for module in modules:
    import_module(module)

entries = entry_points(group="hegemony.step_handlers")
names = {{entry.name for entry in entries}}
expected = {EXPECTED_ENTRY_POINTS!r}
missing = expected - names
assert not missing, missing

probe_entries = entry_points(group="hegemony.probes")
probe_names = {{entry.name for entry in probe_entries}}
probe_expected = {EXPECTED_PROBE_ENTRY_POINTS!r}
probe_missing = probe_expected - probe_names
assert not probe_missing, probe_missing

transport_entries = entry_points(group="hegemony.device_transports")
transport_names = {{entry.name for entry in transport_entries}}
transport_expected = {EXPECTED_TRANSPORT_ENTRY_POINTS!r}
transport_missing = transport_expected - transport_names
assert not transport_missing, transport_missing

# Plugin-owned docs: every step-handler wheel ships one page per registered
# handler id, readable through the SDK loader from the installed package.
from hegemony_step_sdk.docs import load_docs_bundle

class _Reg:
    api_version = 1
    def __init__(self):
        self.handlers = []
    def register_handler_type(self, cls):
        self.handlers.append(cls)

for entry in entries:
    reg = _Reg()
    entry.load()(reg)
    package = entry.value.split(":", 1)[0].split(".", 1)[0]
    bundle = load_docs_bundle(package)
    registered = {{cls.handler_id for cls in reg.handlers}}
    assert registered == set(bundle), (
        package,
        sorted(registered - set(bundle)),
        sorted(set(bundle) - registered),
    )
"""
        subprocess.run([str(python), "-c", code], check=True)
    finally:
        shutil.rmtree(tmp)


if __name__ == "__main__":
    main()
