# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""secret.write: files and values into the organization's secret store, swap, delete.

The host's secret store services are faked in memory (recording every call),
the run's shared workspace is a temporary directory, and every result is
checked for the values it must never carry.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from hegemony_step_sdk import (
    ContainerRuntime,
    HandlerContext,
    HandlerResult,
    HandlerServices,
    SecretWriteResult,
)
from hegemony_step_sdk.docs import check_page, load_docs_bundle
from hegemony_steps_secret import ALL_HANDLERS, register
from hegemony_steps_secret.workspace import (
    MAX_FILE_BYTES,
    MAX_TOTAL_BYTES,
    read_source_files,
    scrub_source_files,
)
from hegemony_steps_secret.write import SecretWriteConfig, WriteSecretHandler

RUN_ID = "0b4f6a52-run"
REFERENCE_ROOT = "vault://orgs/acme/secrets"

CERT_PEM = (
    "-----BEGIN CERTIFICATE-----\nMIIBcertBODYsecretPART0001\nMIIBcertBODYsecretPART0002\n"
    "-----END CERTIFICATE-----\n"
)
KEY_PEM = "-----BEGIN TEST KEY-----\nMIIEkeyBODYsecretPART0003\n-----END TEST KEY-----\n"
DB_PASSWORD = "resolved-db-password-VALUE-0004"
API_TOKEN = "resolved-api-token-VALUE-0005"
LITERAL = "literal-user-VALUE-0006"
OLD_VALUE = "previous-stored-VALUE-0007"

#: What the fake resolver knows: the exact text it is asked to render -> value.
BACKEND = {
    "{{ secret('vault://orgs/acme/secrets/db/password') }}": DB_PASSWORD,
    "{{ secret('vault://orgs/acme/secrets/api/token') }}": API_TOKEN,
}


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


#: Every value a result could leak, in every form it is stored in.
SECRETS = [
    CERT_PEM,
    _b64(CERT_PEM),
    "MIIBcertBODYsecretPART0001",
    KEY_PEM,
    _b64(KEY_PEM),
    "MIIEkeyBODYsecretPART0003",
    DB_PASSWORD,
    API_TOKEN,
    LITERAL,
    OLD_VALUE,
]


class _Store:
    """The host's secret store services, in memory, recording every call."""

    def __init__(self, shared_root: Path, *, shared_enabled: bool = True) -> None:
        self.shared_root = shared_root
        self.shared_enabled = shared_enabled
        self.secrets: dict[str, dict[str, str]] = {}
        self.calls: list[tuple[Any, ...]] = []
        self.resolved: list[str] = []
        # path -> outcomes of successive writes: None succeeds, an exception is raised.
        self.write_outcomes: dict[str, list[BaseException | None]] = {}
        self.read_error: BaseException | None = None
        self.delete_error: BaseException | None = None

    async def read_secret(self, path: str) -> dict[str, str] | None:
        self.calls.append(("read", path))
        if self.read_error is not None:
            raise self.read_error
        held = self.secrets.get(path)
        return dict(held) if held is not None else None

    async def write_secret(
        self, path: str, values: dict[str, str], *, merge: bool = False
    ) -> SecretWriteResult:
        self.calls.append(("write", path, tuple(sorted(values)), merge))
        outcomes = self.write_outcomes.get(path)
        if outcomes:
            outcome = outcomes.pop(0)
            if outcome is not None:
                raise outcome
        created = path not in self.secrets
        stored = {**self.secrets.get(path, {}), **values} if merge else dict(values)
        self.secrets[path] = stored
        return SecretWriteResult(
            path=path,
            reference=f"{REFERENCE_ROOT}/{path}",
            keys=tuple(sorted(stored)),
            created=created,
        )

    async def delete_secret(self, path: str) -> bool:
        self.calls.append(("delete", path))
        if self.delete_error is not None:
            raise self.delete_error
        return self.secrets.pop(path, None) is not None

    def container_runtime(self) -> ContainerRuntime:
        return ContainerRuntime(
            docker_bin="docker",
            shared_workspaces_enabled=self.shared_enabled,
            shared_workspace_root=str(self.shared_root),
            shared_workspace_volume="hegemony-shared",
            docker_host="tcp://dind:2375",
        )

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        assert ref is not None
        self.resolved.append(ref)
        return BACKEND.get(ref)

    @property
    def store_calls(self) -> list[tuple[Any, ...]]:
        return [call for call in self.calls if call[0] in ("read", "write", "delete")]


class _OldHost:
    """A host older than the secret store services: everything else, none of them."""

    def container_runtime(self) -> ContainerRuntime:  # pragma: no cover - not reached
        raise AssertionError("not reached")

    async def resolve_secret_ref(self, ref, *, source):  # pragma: no cover - not reached
        raise AssertionError("not reached")


@pytest.fixture
def shared_root(tmp_path: Path) -> Path:
    root = tmp_path / "shared"
    (root / RUN_ID).mkdir(parents=True)
    return root


@pytest.fixture
def workspace(shared_root: Path) -> Path:
    """The run's shared workspace: what a step container sees at /shared."""
    return shared_root / RUN_ID


@pytest.fixture
def store(shared_root: Path) -> _Store:
    return _Store(shared_root)


def _put(workspace: Path, rel: str, content: str | bytes) -> Path:
    path = workspace / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)
    return path


def _ctx(config: dict[str, Any], services: Any, *, shared: bool = True) -> HandlerContext:
    return HandlerContext(
        run_id=RUN_ID,
        flow_id="flow-1",
        step_run_id="step-run-1",
        step_id="store_cert",
        config=config,
        shared_workspace=shared,
        services=cast(HandlerServices, services),
    )


async def _run(config: dict[str, Any], services: Any, *, shared: bool = True) -> HandlerResult:
    return await WriteSecretHandler().execute(_ctx(config, services, shared=shared))


def _assert_no_values(result: HandlerResult) -> str:
    """Serialize the whole result and check no value, in any stored form, is in it."""
    text = json.dumps(dataclasses.asdict(result), default=str, sort_keys=True)
    for secret in SECRETS:
        assert secret not in text, secret
    return text


# ── metadata ────────────────────────────────────────────────────────────────


def test_handler_metadata():
    handler = WriteSecretHandler()
    assert handler.handler_id == "secret.write"
    assert handler.display_name == "Write Secret"
    assert handler.category == "Actions"
    assert handler.writes_secrets is True
    assert handler.container_backed is False
    assert handler.targeting.roles is False and handler.targeting.ips is False
    assert handler.raw_config_keys == frozenset({"values"})
    assert list(ALL_HANDLERS) == [WriteSecretHandler]

    registered: list[type] = []

    class _Registry:
        api_version = 1

        def register_handler_type(self, handler_class: type) -> None:
            registered.append(handler_class)

    register(_Registry())
    assert registered == [WriteSecretHandler]


def test_config_schema_defaults():
    config = SecretWriteConfig.model_validate({"path": "certs/web"})
    assert config.operation == "write"
    assert config.encoding == "base64"
    assert config.merge is False
    assert config.delete_source_files is True
    assert config.missing_ok is True
    assert config.keep_previous_at == ""
    schema = SecretWriteConfig.model_json_schema()
    assert schema["required"] == ["path"]
    assert schema["properties"]["files"]["x_show_when"] == {"field": "operation", "value": "write"}
    assert schema["properties"]["swap_with"]["x_show_when"] == {
        "field": "operation",
        "value": "swap",
    }


def test_docs_page_satisfies_the_contract():
    bundle = load_docs_bundle("hegemony_steps_secret")
    assert set(bundle) == {"secret.write"}
    assert check_page("secret.write", bundle["secret.write"]) == []
    page = bundle["secret.write"]
    for section in ("## Using It", "## Output", "## Security", "## When It Fails"):
        assert section in page, section
    readme = (
        Path(__file__).resolve().parents[1] / "plugins" / "steps_secret" / "README.md"
    ).read_text(encoding="utf-8")
    assert "`secret.write`" in readme


# ── validate_config ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("path", "fragment"),
    [
        ("../x", "'..'"),
        ("a/../b", "'..'"),
        ("/abs", "leading '/'"),
        ("a//b", "empty segments"),
        ("a/b/", "empty segments"),
        (".hidden", "must not start with '.'"),
        ("certs/.hidden", "must not start with '.'"),
        ("vault://orgs/acme/secrets/x", "not a secret reference"),
        ("a b", "only letters"),
        ("a\\b", "only letters"),
        ("x" * 257, "at most 256"),
    ],
)
async def test_malformed_paths_are_refused_before_the_host_is_asked(store, path, fragment):
    config = {"path": path, "values": {"user": LITERAL}}
    errors = WriteSecretHandler().validate_config(config)
    assert any(fragment in error for error in errors), errors

    result = await _run(config, store)
    assert result.success is False
    assert result.summary == "Config validation failed"
    assert store.calls == []
    _assert_no_values(result)


@pytest.mark.parametrize("field", ["keep_previous_at", "swap_with"])
@pytest.mark.parametrize("path", ["../x", "/abs", "a//b", ".hidden"])
def test_the_second_path_follows_the_same_rules(field, path):
    operation = "swap" if field == "swap_with" else "write"
    config = {"operation": operation, "path": "certs/web", "values": {"k": "v"}, field: path}
    errors = WriteSecretHandler().validate_config(config)
    assert any(f"'{field}'" in error for error in errors), errors


@pytest.mark.parametrize(
    ("config", "fragment"),
    [
        ({"path": "certs/web"}, "at least one key"),
        ({"path": "certs/web", "files": {}, "values": {}}, "at least one key"),
        (
            {"path": "certs/web", "files": {"cert": "out/c.pem"}, "values": {"cert": "x"}},
            "set in both 'files' and 'values'",
        ),
        ({"path": "certs/web", "values": {"1bad": "x"}}, "must start with a letter"),
        ({"path": "certs/web", "files": {"bad key": "out/c.pem"}}, "must start with a letter"),
        ({"path": "certs/web", "values": {"k" * 129: "x"}}, "max 128"),
        ({"path": "certs/web", "values": {"user": "  "}}, "non-empty string"),
        ({"path": "certs/web", "files": {"cert": "/etc/passwd"}}, "under /shared/"),
        ({"path": "certs/web", "files": {"cert": "/shared/../etc/passwd"}}, "'..'"),
        ({"path": "certs/web", "files": {"cert": "../x.pem"}}, "'..'"),
        ({"path": "certs/web", "files": {"cert": "out//c.pem"}}, "empty segments"),
        ({"path": "certs/web", "files": {"cert": "/shared"}}, "workspace itself"),
        (
            {"path": "certs/web", "values": {"k": "v"}, "keep_previous_at": " certs/web "},
            "must differ from 'path'",
        ),
        ({"operation": "swap", "path": "certs/web"}, "needs 'swap_with'"),
        (
            {"operation": "swap", "path": "certs/web", "swap_with": "certs/web"},
            "must differ from 'path'",
        ),
        ({"operation": "rotate", "path": "certs/web"}, "operation"),
        ({"path": "certs/web", "values": {"k": "v"}, "encoding": "hex"}, "encoding"),
        ({"values": {"k": "v"}}, "path"),
    ],
)
def test_validate_config_errors(config, fragment):
    errors = WriteSecretHandler().validate_config(config)
    assert any(fragment in error for error in errors), errors


def test_validate_config_accepts_templated_paths_and_checks_them_once_rendered():
    handler = WriteSecretHandler()
    templated = {
        "path": "certs/{{ inputs.site }}",
        "keep_previous_at": "certs/{{ inputs.site }}-previous",
        "files": {"cert": "/shared/{{ inputs.dir }}/cert.pem"},
    }
    assert handler.validate_config(templated) == []
    assert handler.validate_config({"path": "certs/web", "values": {"k": "v"}}) == []
    assert handler.validate_config({"operation": "delete", "path": "certs/web"}) == []
    assert (
        handler.validate_config(
            {"operation": "swap", "path": "certs/web", "swap_with": "certs/web-previous"}
        )
        == []
    )


async def test_a_path_rendered_badly_is_refused_at_run_time(store):
    # The host rendered the template into something that is not a secret path.
    result = await _run({"path": "certs/../other-org", "values": {"user": LITERAL}}, store)
    assert result.success is False
    assert "'..'" in (result.error or "")
    assert store.calls == []


# ── write: files ────────────────────────────────────────────────────────────


async def test_write_from_files_stores_base64_and_deletes_the_sources(store, workspace):
    cert = _put(workspace, "out/cert.pem", CERT_PEM)
    key = _put(workspace, "out/key.pem", KEY_PEM)

    result = await _run(
        {"path": "certs/web", "files": {"cert": "/shared/out/cert.pem", "key": "out/key.pem"}},
        store,
    )

    assert result.success is True, result.error
    assert store.secrets["certs/web"] == {"cert": _b64(CERT_PEM), "key": _b64(KEY_PEM)}
    assert store.store_calls == [("write", "certs/web", ("cert", "key"), False)]
    assert result.output == {
        "operation": "write",
        "path": "certs/web",
        "reference": f"{REFERENCE_ROOT}/certs/web",
        "keys": ["cert", "key"],
        "created": True,
        "previous_path": None,
        "swapped_with": None,
        "deleted": False,
    }
    assert result.summary == "wrote 2 keys to certs/web"
    assert result.metrics == {"keys": 2, "source_files": 2, "source_files_deleted": 2}
    (evidence,) = result.evidence
    assert evidence["kind"] == "step_result"
    assert evidence["name"] == "secret_write_store_cert"
    assert evidence["content_json"]["reference"] == f"{REFERENCE_ROOT}/certs/web"
    assert evidence["content_json"]["keys_from_files"] == ["cert", "key"]
    assert evidence["content_json"]["encoding"] == "base64"
    assert evidence["content_json"]["source_files_deleted"] == ["out/cert.pem", "out/key.pem"]
    assert not cert.exists() and not key.exists()
    # The stored base64 decodes to the exact bytes, line breaks included.
    assert base64.b64decode(store.secrets["certs/web"]["cert"]).decode() == CERT_PEM
    _assert_no_values(result)


async def test_write_text_encoding_stores_the_file_as_it_is(store, workspace):
    _put(workspace, "out/cert.pem", CERT_PEM)
    result = await _run(
        {"path": "certs/web", "files": {"cert": "out/cert.pem"}, "encoding": "text"}, store
    )
    assert result.success is True, result.error
    assert store.secrets["certs/web"] == {"cert": CERT_PEM}
    _assert_no_values(result)


async def test_text_encoding_refuses_a_file_that_is_not_utf8(store, workspace):
    source = _put(workspace, "out/key.der", b"\x30\x82\xff\xfe\x00binary")
    result = await _run(
        {"path": "certs/web", "files": {"key": "out/key.der"}, "encoding": "text"}, store
    )
    assert result.success is False
    assert "not UTF-8" in (result.error or "") and "base64" in (result.error or "")
    assert store.calls == []
    assert source.exists()


async def test_delete_source_files_off_keeps_the_files(store, workspace):
    cert = _put(workspace, "out/cert.pem", CERT_PEM)
    result = await _run(
        {"path": "certs/web", "files": {"cert": "out/cert.pem"}, "delete_source_files": False},
        store,
    )
    assert result.success is True, result.error
    assert cert.read_text(encoding="utf-8") == CERT_PEM
    assert result.metrics == {"keys": 1, "source_files": 1, "source_files_deleted": 0}
    assert result.evidence[0]["content_json"]["source_files_deleted"] == []


async def test_source_files_are_overwritten_with_zeros_before_unlinking(
    store, workspace, monkeypatch
):
    cert = _put(workspace, "out/cert.pem", CERT_PEM)
    unlinked: list[str] = []
    monkeypatch.setattr(
        "hegemony_steps_secret.workspace.os.unlink",
        lambda name, *, dir_fd=None: unlinked.append(name),
    )
    result = await _run({"path": "certs/web", "files": {"cert": "out/cert.pem"}}, store)
    assert result.success is True, result.error
    assert unlinked == ["cert.pem"]
    assert cert.read_bytes() == bytes(len(CERT_PEM.encode()))


async def test_a_source_file_that_cannot_be_deleted_does_not_fail_the_step(
    store, workspace, monkeypatch
):
    _put(workspace, "out/cert.pem", CERT_PEM)

    def refuse(name, *, dir_fd=None):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("hegemony_steps_secret.workspace.os.unlink", refuse)
    result = await _run({"path": "certs/web", "files": {"cert": "out/cert.pem"}}, store)
    assert result.success is True
    assert result.summary == "wrote 1 key to certs/web (1 source file not deleted)"
    not_deleted = result.evidence[0]["content_json"]["source_files_not_deleted"]
    assert list(not_deleted) == ["out/cert.pem"]
    assert "Permission denied" in not_deleted["out/cert.pem"]
    assert result.metrics["source_files_deleted"] == 0


def test_scrub_leaves_a_file_replaced_since_it_was_read(workspace):
    _put(workspace, "out/cert.pem", CERT_PEM)
    (source,) = read_source_files(str(workspace), {"cert": "out/cert.pem"})
    os.unlink(workspace / "out" / "cert.pem")
    replacement = _put(workspace, "out/cert.pem", "someone else's file")

    failures = scrub_source_files(str(workspace), [source])
    assert "changed since it was read" in failures["out/cert.pem"]
    assert replacement.read_text(encoding="utf-8") == "someone else's file"


def test_scrub_unlinks_a_hard_linked_file_without_overwriting_it(workspace, tmp_path):
    cert = _put(workspace, "out/cert.pem", CERT_PEM)
    other_name = workspace / "other.pem"
    os.link(cert, other_name)
    sources = read_source_files(str(workspace), {"cert": "out/cert.pem"})

    assert scrub_source_files(str(workspace), sources) == {}
    assert not cert.exists()
    assert other_name.read_text(encoding="utf-8") == CERT_PEM


# ── write: refused files ────────────────────────────────────────────────────


async def test_a_symlinked_file_escaping_the_workspace_is_refused(store, workspace, tmp_path):
    outside = tmp_path / "worker-secret.txt"
    outside.write_text("worker-only content", encoding="utf-8")
    (workspace / "out").mkdir()
    (workspace / "out" / "cert.pem").symlink_to(outside)

    result = await _run({"path": "certs/web", "files": {"cert": "/shared/out/cert.pem"}}, store)
    assert result.success is False
    assert "outside the run's shared workspace" in (result.error or "")
    assert "worker-only content" not in (result.error or "")
    assert store.calls == []
    assert outside.read_text(encoding="utf-8") == "worker-only content"


async def test_a_symlinked_directory_escaping_the_workspace_is_refused(store, workspace, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "cert.pem").write_text("worker-only content", encoding="utf-8")
    (workspace / "out").symlink_to(elsewhere, target_is_directory=True)

    result = await _run({"path": "certs/web", "files": {"cert": "out/cert.pem"}}, store)
    assert result.success is False
    assert "outside the run's shared workspace" in (result.error or "")
    assert store.calls == []
    assert (elsewhere / "cert.pem").exists()


async def test_a_symlink_inside_the_workspace_is_refused_too(store, workspace):
    _put(workspace, "real/cert.pem", CERT_PEM)
    (workspace / "linked").symlink_to(workspace / "real", target_is_directory=True)
    (workspace / "cert-link.pem").symlink_to(workspace / "real" / "cert.pem")

    for written in ("linked/cert.pem", "cert-link.pem"):
        result = await _run({"path": "certs/web", "files": {"cert": written}}, store)
        assert result.success is False, written
        assert "symbolic link" in (result.error or ""), result.error
    assert store.calls == []


def test_a_symlink_swapped_in_after_the_realpath_check_is_still_refused(
    workspace, tmp_path, monkeypatch
):
    """The open itself follows no link: the realpath check is only the clear message."""
    outside = tmp_path / "worker-secret.txt"
    outside.write_text("worker-only content", encoding="utf-8")
    (workspace / "out").mkdir()
    (workspace / "out" / "cert.pem").symlink_to(outside)
    monkeypatch.setattr(
        "hegemony_steps_secret.workspace._check_inside", lambda root, rel, label: None
    )
    with pytest.raises(ValueError, match="symbolic link"):
        read_source_files(str(workspace), {"cert": "out/cert.pem"})


async def test_non_regular_files_are_refused(store, workspace):
    (workspace / "out" / "cert.pem").mkdir(parents=True)
    result = await _run({"path": "certs/web", "files": {"cert": "out/cert.pem"}}, store)
    assert result.success is False
    assert "not a regular file" in (result.error or "")

    fifo = workspace / "pipe"
    os.mkfifo(fifo)
    result = await _run({"path": "certs/web", "files": {"cert": "pipe"}}, store)
    assert result.success is False
    assert "not a regular file" in (result.error or "")
    assert store.calls == []


async def test_missing_and_empty_files_are_refused(store, workspace):
    result = await _run({"path": "certs/web", "files": {"cert": "out/cert.pem"}}, store)
    assert result.success is False
    assert "does not exist" in (result.error or "")

    _put(workspace, "out/cert.pem", "")
    result = await _run({"path": "certs/web", "files": {"cert": "out/cert.pem"}}, store)
    assert result.success is False
    assert "is empty" in (result.error or "")
    assert store.calls == []


async def test_a_file_over_the_cap_is_refused(store, workspace):
    _put(workspace, "out/big.bin", b"x" * (MAX_FILE_BYTES + 1))
    _put(workspace, "out/max.bin", b"x" * MAX_FILE_BYTES)

    result = await _run({"path": "certs/web", "files": {"big": "out/big.bin"}}, store)
    assert result.success is False
    assert f"larger than {MAX_FILE_BYTES} bytes" in (result.error or "")

    result = await _run({"path": "certs/web", "files": {"max": "out/max.bin"}}, store)
    assert result.success is True, result.error


async def test_files_over_the_total_cap_are_refused(store, workspace):
    count = MAX_TOTAL_BYTES // MAX_FILE_BYTES + 1
    files = {}
    for index in range(count):
        _put(workspace, f"out/part{index}.bin", b"y" * MAX_FILE_BYTES)
        files[f"part{index}"] = f"out/part{index}.bin"
    result = await _run({"path": "certs/web", "files": files}, store)
    assert result.success is False
    assert f"larger than {MAX_TOTAL_BYTES} bytes" in (result.error or "")
    assert store.calls == []
    assert (workspace / "out" / "part0.bin").exists()


async def test_files_need_the_runs_shared_workspace(store, workspace):
    _put(workspace, "out/cert.pem", CERT_PEM)
    config = {"path": "certs/web", "files": {"cert": "out/cert.pem"}}

    result = await _run(config, store, shared=False)
    assert result.success is False
    assert result.summary == "Shared workspace unavailable"
    assert "shared (or explicit) execution affinity" in (result.error or "")
    assert "this step has no shared workspace" in (result.error or "")

    store.shared_enabled = False
    result = await _run(config, store)
    assert result.success is False
    assert "shared workspaces disabled" in (result.error or "")
    assert store.calls == []

    # Values alone need no workspace.
    result = await _run({"path": "app/login", "values": {"user": LITERAL}}, store, shared=False)
    assert result.success is True, result.error


async def test_a_workspace_no_step_wrote_is_reported(store, shared_root):
    os.rmdir(shared_root / RUN_ID)
    result = await _run({"path": "certs/web", "files": {"cert": "out/cert.pem"}}, store)
    assert result.success is False
    assert "does not exist on this worker" in (result.error or "")


# ── write: values ───────────────────────────────────────────────────────────


async def test_write_from_values_resolves_references_and_templates(store):
    result = await _run(
        {
            "path": "app/login",
            "values": {
                "password": "vault://orgs/acme/secrets/db/password",
                "token": "{{ secret('vault://orgs/acme/secrets/api/token') }}",
                "user": LITERAL,
            },
        },
        store,
    )
    assert result.success is True, result.error
    assert store.secrets["app/login"] == {
        "password": DB_PASSWORD,
        "token": API_TOKEN,
        "user": LITERAL,
    }
    # The bare reference is resolved as a secret() template; the literal is not resolved.
    assert store.resolved == [
        "{{ secret('vault://orgs/acme/secrets/db/password') }}",
        "{{ secret('vault://orgs/acme/secrets/api/token') }}",
    ]
    assert result.output["keys"] == ["password", "token", "user"]
    assert result.summary == "wrote 3 keys to app/login"
    assert result.metrics == {"keys": 3}
    assert result.evidence[0]["content_json"]["keys_from_values"] == ["password", "token", "user"]
    _assert_no_values(result)


async def test_files_and_values_together(store, workspace):
    _put(workspace, "out/cert.pem", CERT_PEM)
    result = await _run(
        {
            "path": "certs/web",
            "files": {"cert": "out/cert.pem"},
            "values": {"passphrase": "vault://orgs/acme/secrets/db/password"},
        },
        store,
    )
    assert result.success is True, result.error
    assert store.secrets["certs/web"] == {"cert": _b64(CERT_PEM), "passphrase": DB_PASSWORD}
    _assert_no_values(result)


async def test_a_reference_resolving_to_nothing_fails_before_any_write(store, workspace):
    source = _put(workspace, "out/cert.pem", CERT_PEM)
    result = await _run(
        {
            "path": "certs/web",
            "files": {"cert": "out/cert.pem"},
            "values": {"password": "vault://orgs/acme/secrets/missing/key"},
        },
        store,
    )
    assert result.success is False
    assert result.summary == "Secret value not resolved"
    assert "'values.password'" in (result.error or "") and "'vault'" in (result.error or "")
    assert store.store_calls == []
    assert source.exists()
    _assert_no_values(result)


# ── write: replace, merge, keep previous ────────────────────────────────────


async def test_replace_removes_keys_not_written(store):
    store.secrets["app/login"] = {"user": OLD_VALUE, "stale": OLD_VALUE}
    result = await _run({"path": "app/login", "values": {"user": LITERAL}}, store)
    assert result.success is True, result.error
    assert store.secrets["app/login"] == {"user": LITERAL}
    assert result.output["keys"] == ["user"]
    assert result.output["created"] is False
    assert store.store_calls == [("write", "app/login", ("user",), False)]
    _assert_no_values(result)


async def test_merge_keeps_keys_not_written(store):
    store.secrets["app/login"] = {"user": OLD_VALUE, "kept": OLD_VALUE}
    result = await _run({"path": "app/login", "values": {"user": LITERAL}, "merge": True}, store)
    assert result.success is True, result.error
    assert store.secrets["app/login"] == {"user": LITERAL, "kept": OLD_VALUE}
    assert result.output["keys"] == ["kept", "user"]
    assert result.summary == "wrote 1 key to app/login (merged, 2 keys stored)"
    assert store.store_calls == [("write", "app/login", ("user",), True)]
    _assert_no_values(result)


async def test_keep_previous_at_copies_the_current_keys_first(store, workspace):
    store.secrets["certs/web"] = {"cert": OLD_VALUE, "chain": OLD_VALUE}
    store.secrets["certs/web-previous"] = {"something": OLD_VALUE}
    _put(workspace, "out/cert.pem", CERT_PEM)

    result = await _run(
        {
            "path": "certs/web",
            "files": {"cert": "out/cert.pem"},
            "keep_previous_at": "certs/web-previous",
        },
        store,
    )

    assert result.success is True, result.error
    assert store.store_calls == [
        ("read", "certs/web"),
        ("write", "certs/web-previous", ("cert", "chain"), False),
        ("write", "certs/web", ("cert",), False),
    ]
    assert store.secrets["certs/web-previous"] == {"cert": OLD_VALUE, "chain": OLD_VALUE}
    assert store.secrets["certs/web"] == {"cert": _b64(CERT_PEM)}
    assert result.output["previous_path"] == "certs/web-previous"
    assert result.summary == "wrote 1 key to certs/web (previous kept at certs/web-previous)"
    _assert_no_values(result)


async def test_keep_previous_at_with_nothing_to_keep(store):
    result = await _run(
        {"path": "app/login", "values": {"user": LITERAL}, "keep_previous_at": "app/login-old"},
        store,
    )
    assert result.success is True, result.error
    assert store.store_calls == [
        ("read", "app/login"),
        ("write", "app/login", ("user",), False),
    ]
    assert "app/login-old" not in store.secrets
    assert result.output["previous_path"] is None
    assert result.output["created"] is True
    assert (
        result.summary == "wrote 1 key to app/login (no previous secret to keep at app/login-old)"
    )


async def test_a_failed_write_after_keeping_says_the_copy_was_made(store, workspace):
    store.secrets["certs/web"] = {"cert": OLD_VALUE}
    store.write_outcomes["certs/web"] = [RuntimeError("secret backend 'vault' is unreachable")]
    source = _put(workspace, "out/cert.pem", CERT_PEM)

    result = await _run(
        {
            "path": "certs/web",
            "files": {"cert": "out/cert.pem"},
            "keep_previous_at": "certs/web-previous",
        },
        store,
    )
    assert result.success is False
    assert result.summary == "Secret store unavailable"
    assert "secret backend 'vault' is unreachable" in (result.error or "")
    assert "already copied to certs/web-previous" in (result.error or "")
    assert store.secrets["certs/web"] == {"cert": OLD_VALUE}
    # Nothing was stored from the file, so it is kept for another attempt.
    assert source.exists()
    _assert_no_values(result)


# ── host errors ─────────────────────────────────────────────────────────────


async def test_a_host_without_the_secret_services_fails_clearly():
    result = await _run({"path": "app/login", "values": {"user": LITERAL}}, _OldHost())
    assert result.success is False
    assert "this platform does not provide secret writes to steps" in (result.error or "")
    assert "read_secret, write_secret, delete_secret" in (result.error or "")
    _assert_no_values(result)


@pytest.mark.parametrize(
    ("error", "summary"),
    [
        (
            PermissionError("secret writes by steps are not enabled for organization acme"),
            "Refused by the platform",
        ),
        (
            PermissionError("path 'app/login' is outside the prefixes steps may write"),
            "Refused by the platform",
        ),
        (ValueError("path 'app/login' is not a valid secret path"), "Rejected by the platform"),
        (RuntimeError("no writable secret backend is configured"), "Secret store unavailable"),
    ],
)
async def test_host_errors_become_failed_results_with_the_hosts_message(store, error, summary):
    store.write_outcomes["app/login"] = [error]
    result = await _run({"path": "app/login", "values": {"user": LITERAL}}, store)
    assert result.success is False
    assert result.summary == summary
    assert str(error) in (result.error or "")
    assert "app/login" in (result.error or "")
    _assert_no_values(result)


async def test_an_unexpected_host_error_reports_only_its_type(store):
    store.write_outcomes["app/login"] = [KeyError(f"request body had {LITERAL}")]
    result = await _run({"path": "app/login", "values": {"user": LITERAL}}, store)
    assert result.success is False
    assert "unexpected KeyError" in (result.error or "")
    _assert_no_values(result)


async def test_a_refused_read_for_keep_previous_writes_nothing(store):
    store.read_error = PermissionError("path 'app/login' is outside the prefixes steps may write")
    result = await _run(
        {"path": "app/login", "values": {"user": LITERAL}, "keep_previous_at": "app/old"}, store
    )
    assert result.success is False
    assert result.summary == "Refused by the platform"
    assert [call for call in store.store_calls if call[0] == "write"] == []


# ── swap ────────────────────────────────────────────────────────────────────


async def test_swap_exchanges_the_keys_of_two_secrets(store):
    store.secrets["certs/web"] = {"cert": CERT_PEM}
    store.secrets["certs/web-previous"] = {"cert": OLD_VALUE, "chain": OLD_VALUE}

    result = await _run(
        {"operation": "swap", "path": "certs/web", "swap_with": "certs/web-previous"}, store
    )

    assert result.success is True, result.error
    assert store.secrets["certs/web"] == {"cert": OLD_VALUE, "chain": OLD_VALUE}
    assert store.secrets["certs/web-previous"] == {"cert": CERT_PEM}
    assert result.output == {
        "operation": "swap",
        "path": "certs/web",
        "reference": f"{REFERENCE_ROOT}/certs/web",
        "keys": ["cert", "chain"],
        "created": False,
        "previous_path": None,
        "swapped_with": "certs/web-previous",
        "deleted": False,
    }
    assert result.summary == "swapped certs/web and certs/web-previous"
    details = result.evidence[0]["content_json"]
    assert details["swapped_with_reference"] == f"{REFERENCE_ROOT}/certs/web-previous"
    assert details["swapped_with_keys"] == ["cert"]
    _assert_no_values(result)


async def test_swap_needs_both_secrets(store):
    store.secrets["certs/web"] = {"cert": CERT_PEM}
    result = await _run(
        {"operation": "swap", "path": "certs/web", "swap_with": "certs/web-previous"}, store
    )
    assert result.success is False
    assert "no secret exists at certs/web-previous" in (result.error or "")
    assert [call for call in store.store_calls if call[0] == "write"] == []
    _assert_no_values(result)


async def test_swap_restores_the_first_secret_when_the_second_write_fails(store):
    store.secrets["certs/web"] = {"cert": CERT_PEM}
    store.secrets["certs/web-previous"] = {"cert": OLD_VALUE}
    store.write_outcomes["certs/web-previous"] = [RuntimeError("backend timed out")]

    result = await _run(
        {"operation": "swap", "path": "certs/web", "swap_with": "certs/web-previous"}, store
    )

    assert result.success is False
    assert result.summary == "Swap failed, restored"
    assert "backend timed out" in (result.error or "")
    assert "certs/web was restored" in (result.error or "")
    assert store.secrets == {
        "certs/web": {"cert": CERT_PEM},
        "certs/web-previous": {"cert": OLD_VALUE},
    }
    assert [call[1] for call in store.store_calls if call[0] == "write"] == [
        "certs/web",
        "certs/web-previous",
        "certs/web",
    ]
    _assert_no_values(result)


async def test_swap_reports_a_failed_restore(store):
    store.secrets["certs/web"] = {"cert": CERT_PEM}
    store.secrets["certs/web-previous"] = {"cert": OLD_VALUE}
    store.write_outcomes["certs/web-previous"] = [RuntimeError("backend timed out")]
    store.write_outcomes["certs/web"] = [None, RuntimeError("backend still down")]

    result = await _run(
        {"operation": "swap", "path": "certs/web", "swap_with": "certs/web-previous"}, store
    )

    assert result.success is False
    assert result.summary == "Swap failed half-way"
    error = result.error or ""
    assert "certs/web now holds the keys certs/web-previous held" in error
    assert "backend timed out" in error and "backend still down" in error
    assert "by hand" in error
    _assert_no_values(result)


# ── delete ──────────────────────────────────────────────────────────────────


async def test_delete_removes_the_secret(store):
    store.secrets["certs/web-previous"] = {"cert": OLD_VALUE}
    result = await _run({"operation": "delete", "path": "certs/web-previous"}, store)
    assert result.success is True, result.error
    assert "certs/web-previous" not in store.secrets
    assert result.output["deleted"] is True
    assert result.output["reference"] is None
    assert result.summary == "deleted certs/web-previous"
    _assert_no_values(result)


async def test_delete_of_a_missing_secret(store):
    result = await _run({"operation": "delete", "path": "certs/gone"}, store)
    assert result.success is True
    assert result.output["deleted"] is False
    assert result.summary == "no secret at certs/gone; nothing deleted"

    result = await _run({"operation": "delete", "path": "certs/gone", "missing_ok": False}, store)
    assert result.success is False
    assert result.summary == "Secret not found"
    assert result.output["deleted"] is False


async def test_a_refused_delete(store):
    store.delete_error = PermissionError("secrets backend 'vault' is read-only")
    result = await _run({"operation": "delete", "path": "certs/web"}, store)
    assert result.success is False
    assert result.summary == "Refused by the platform"
    assert "read-only" in (result.error or "")
