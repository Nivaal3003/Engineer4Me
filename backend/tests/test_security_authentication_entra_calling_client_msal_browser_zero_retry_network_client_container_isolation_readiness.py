from __future__ import annotations

import ast
import hashlib
import json
from builtins import BaseExceptionGroup
from dataclasses import fields
from pathlib import Path

import pytest

import app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_container_isolation_readiness as module
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_execution_probe import (
    DOCUMENT_TYPE as STEP228_DOCUMENT_TYPE,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_execution_probe import (
    HARNESS_FILE_NAME,
    NODE_VERSION,
    RUNNER_FILE_NAME,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_execution_probe import (
    PROFILE as STEP228_PROFILE,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_execution_probe import (
    SOURCE as STEP228_SOURCE,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_implementation_readiness import (
    ADAPTER_SHA256,
    STEP226_PACKAGE_MANIFEST_SHA256,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_implementation_readiness import (
    DOCUMENT_TYPE as STEP227_DOCUMENT_TYPE,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_implementation_readiness import (
    PROFILE as STEP227_PROFILE,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_implementation_readiness import (
    SOURCE as STEP227_SOURCE,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_readiness import (
    DOCUMENT_TYPE as STEP226_DOCUMENT_TYPE,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_readiness import (
    PROFILE as STEP226_PROFILE,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_readiness import (
    SOURCE as STEP226_SOURCE,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_readiness import (
    STEP225_PACKAGE_MANIFEST_SHA256,
)

SECURITY = Path(__file__).parents[1] / "app/security"
ADAPTER_FILE = (
    SECURITY
    / "authentication_entra_calling_client_msal_browser_zero_retry_network_client.mjs"
)
HARNESS_FILE = SECURITY / HARNESS_FILE_NAME
RUNNER_FILE = SECURITY / RUNNER_FILE_NAME
NODE_SHA256 = "1" * 64
IMAGE_ID = "sha256:" + "2" * 64


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _step226_document() -> bytes:
    return _canonical(
        {
            "document_type": STEP226_DOCUMENT_TYPE,
            "schema_version": 1,
            "source": STEP226_SOURCE,
            "approved_step225_package_manifest_sha256": (
                STEP225_PACKAGE_MANIFEST_SHA256
            ),
            "override_profile": STEP226_PROFILE,
        }
    )


def _step227_document() -> bytes:
    return _canonical(
        {
            "document_type": STEP227_DOCUMENT_TYPE,
            "schema_version": 1,
            "source": STEP227_SOURCE,
            "approved_step226_package_manifest_sha256": (
                STEP226_PACKAGE_MANIFEST_SHA256
            ),
            "approved_adapter_sha256": ADAPTER_SHA256,
            "implementation_profile": STEP227_PROFILE,
        }
    )


def _step228_document(**updates: object) -> bytes:
    value: dict[str, object] = {
        "document_type": STEP228_DOCUMENT_TYPE,
        "schema_version": 1,
        "source": STEP228_SOURCE,
        "approved_step227_implementation_document_sha256": hashlib.sha256(
            _step227_document()
        ).hexdigest(),
        "expected_node_version": NODE_VERSION,
        "approved_node_executable_sha256": NODE_SHA256,
        "execution_profile": STEP228_PROFILE,
    }
    value.update(updates)
    return _canonical(value)


def _document(**updates: object) -> bytes:
    value: dict[str, object] = {
        "document_type": module.DOCUMENT_TYPE,
        "schema_version": 1,
        "source": module.SOURCE,
        "approved_step228_package_manifest_sha256": (
            module.STEP228_PACKAGE_MANIFEST_SHA256
        ),
        "approved_step228_execution_document_sha256": hashlib.sha256(
            _step228_document()
        ).hexdigest(),
        "approved_container_image_id": IMAGE_ID,
        "expected_container_operating_system": module.CONTAINER_OPERATING_SYSTEM,
        "expected_container_architecture": module.CONTAINER_ARCHITECTURE,
        "expected_node_path": module.CONTAINER_NODE_PATH,
        "isolation_profile": module.PROFILE,
    }
    value.update(updates)
    return _canonical(value)


def _adapter() -> bytes:
    return ADAPTER_FILE.read_bytes()


def _harness() -> bytes:
    return HARNESS_FILE.read_bytes()


def _runner() -> bytes:
    return RUNNER_FILE.read_bytes()


def _load(**updates: object):
    values: dict[str, object] = {
        "document_bytes": _document(),
        "step228_execution_document_bytes": _step228_document(),
        "step227_document_bytes": _step227_document(),
        "step226_document_bytes": _step226_document(),
        "adapter_bytes": _adapter(),
        "harness_bytes": _harness(),
        "runner_bytes": _runner(),
    }
    values.update(updates)
    return (
        module.load_entra_calling_client_msal_zero_retry_container_isolation_readiness(
            **values
        )
    )


def _unsafe_clone(receipt: object, name: str, value: object):
    clone = object.__new__(type(receipt))
    for field in fields(receipt):
        object.__setattr__(
            clone,
            field.name,
            value if field.name == name else getattr(receipt, field.name),
        )
    return clone


def test_valid_offline_container_isolation_readiness() -> None:
    receipt = _load()
    assert receipt.container_runtime == "docker"
    assert receipt.container_network_mode == "none"
    assert receipt.approved_container_image_id == IMAGE_ID
    assert receipt.step228_source_chain_rerun is True
    assert receipt.offline_container_isolation_readiness_validated is True
    assert receipt.docker_none_network_required is True
    assert receipt.image_pull_forbidden is True
    assert receipt.container_created is False
    assert receipt.os_network_isolation_dynamically_verified is False
    assert receipt.candidate_docker_daemon_accessed is False
    assert receipt.package_selection_approved is False


def test_step228_prerequisite_runs_before_current_document_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False
    original = (
        module.prove_entra_calling_client_msal_zero_retry_network_client_execution
    )

    def wrapped(**values: object):
        nonlocal called
        called = True
        return original(**values)

    monkeypatch.setattr(
        module,
        "prove_entra_calling_client_msal_zero_retry_network_client_execution",
        wrapped,
    )
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerIsolationReadinessError
    ):
        _load(document_bytes=b"not-json")
    assert called


def test_step228_rerun_is_synthetic_and_performs_no_sealed_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    original = (
        module.prove_entra_calling_client_msal_zero_retry_network_client_execution
    )

    def wrapped(**values: object):
        captured.update(values)
        return original(**values)

    monkeypatch.setattr(
        module,
        "prove_entra_calling_client_msal_zero_retry_network_client_execution",
        wrapped,
    )
    _load()
    assert "node_executable_path" not in captured
    assert callable(captured["execution_transport"])


@pytest.mark.parametrize(
    "updates",
    [
        {"document_type": "wrong"},
        {"schema_version": True},
        {"source": "wrong"},
        {"approved_step228_package_manifest_sha256": "0" * 64},
        {"approved_step228_execution_document_sha256": "0" * 64},
        {"approved_container_image_id": "node:24.19.0"},
        {"approved_container_image_id": "sha256:" + "A" * 64},
        {"expected_container_operating_system": "windows"},
        {"expected_container_architecture": "arm64"},
        {"expected_node_path": "/bin/node"},
        {"isolation_profile": "wrong"},
        {"extra": False},
    ],
)
def test_document_tampering_fails(updates: dict[str, object]) -> None:
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerIsolationReadinessError
    ):
        _load(document_bytes=_document(**updates))


def test_document_must_be_canonical() -> None:
    raw = json.loads(_document())
    noncanonical = json.dumps(raw, indent=2).encode()
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerIsolationReadinessError
    ):
        _load(document_bytes=noncanonical)


@pytest.mark.parametrize(
    "name",
    [
        "step228_execution_document_bytes",
        "step227_document_bytes",
        "step226_document_bytes",
        "adapter_bytes",
        "harness_bytes",
        "runner_bytes",
    ],
)
def test_every_prerequisite_source_tamper_fails(name: str) -> None:
    source = {
        "step228_execution_document_bytes": _step228_document(),
        "step227_document_bytes": _step227_document(),
        "step226_document_bytes": _step226_document(),
        "adapter_bytes": _adapter(),
        "harness_bytes": _harness(),
        "runner_bytes": _runner(),
    }[name]
    changed = bytearray(source)
    changed[-1] ^= 1
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerIsolationReadinessError
    ):
        _load(**{name: bytes(changed)})


def test_reblessed_invalid_step228_document_still_fails() -> None:
    step228 = _step228_document(expected_node_version="v0.0.0")
    current = _document(
        approved_step228_execution_document_sha256=hashlib.sha256(step228).hexdigest()
    )
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerIsolationReadinessError
    ):
        _load(
            document_bytes=current,
            step228_execution_document_bytes=step228,
        )


@pytest.mark.parametrize(
    "name",
    [
        "document_bytes",
        "step228_execution_document_bytes",
        "step227_document_bytes",
        "step226_document_bytes",
        "adapter_bytes",
        "harness_bytes",
        "runner_bytes",
    ],
)
def test_public_input_types_are_exact(name: str) -> None:
    with pytest.raises(TypeError):
        _load(**{name: bytearray(b"not-exact-bytes")})


def test_input_byte_objects_must_be_distinct() -> None:
    shared = _step226_document()
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerIsolationReadinessError
    ):
        _load(
            document_bytes=shared,
            step226_document_bytes=shared,
        )


def test_profiles_bind_exact_isolation_and_lifecycle() -> None:
    receipt = _load()
    expected = module._profiles(
        image_id=IMAGE_ID,
        node_executable_sha256=NODE_SHA256,
    )
    for name, digest in expected.items():
        assert getattr(receipt, name) == digest
    assert len(expected) == 7
    source = Path(module.__file__).read_text()
    for value in (
        '"network": CONTAINER_NETWORK_MODE',
        '"read_only_root": True',
        '"cap_drop": ["ALL"]',
        '"no_new_privileges": True',
        '"seccomp": "builtin"',
        '"docker_socket_mount": False',
        '"healthcheck_disabled": True',
        '"log_driver": "none"',
        '"pull": "never"',
        '"create_retries": 0',
        '"start_retries": 0',
    ):
        assert value in source


def test_module_has_no_io_capable_import_or_process_call() -> None:
    tree = ast.parse(Path(module.__file__).read_text())
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert not imported.intersection(
        {"asyncio", "http", "requests", "socket", "ssl", "subprocess", "urllib"}
    )


def test_every_receipt_field_is_guarded() -> None:
    receipt = _load()
    flexible = {
        "isolation_document_sha256",
        "step228_execution_document_sha256",
        "step228_receipt_sha256",
        "approved_container_image_id",
        "approved_node_executable_sha256",
    }
    for field in fields(receipt):
        current = getattr(receipt, field.name)
        if field.name == "approved_container_image_id":
            invalid: object = "not-an-image-id"
        elif field.name in flexible:
            invalid = "x"
        elif type(current) is bool:
            invalid = not current
        elif type(current) is int:
            invalid = True
        else:
            invalid = "0" * 64 if current != "0" * 64 else "1" * 64
        clone = _unsafe_clone(receipt, field.name, invalid)
        with pytest.raises(ValueError):
            clone.__post_init__()


def test_renderer_is_canonical_and_exact_type_only() -> None:
    receipt = _load()
    rendered = module.render_entra_calling_client_msal_zero_retry_container_isolation_readiness_receipt(
        receipt
    )
    assert rendered == json.dumps(
        json.loads(rendered), sort_keys=True, separators=(",", ":")
    )
    assert set(json.loads(rendered)) == set(receipt.__dataclass_fields__)
    with pytest.raises(TypeError):
        module.render_entra_calling_client_msal_zero_retry_container_isolation_readiness_receipt(
            object()  # type: ignore[arg-type]
        )


def test_nested_control_flow_is_sanitized_and_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = ValueError("private-container-marker")
    group = BaseExceptionGroup(
        "private-group-marker",
        [SystemExit("private-exit"), KeyboardInterrupt("private-interrupt"), child],
    )

    def fail(*_values: object) -> None:
        raise group

    monkeypatch.setattr(module, "_load_internal", fail)
    with pytest.raises(KeyboardInterrupt) as caught:
        _load()
    assert "private" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert child.args == ()
    assert child.__traceback__ is None


def test_public_export_set_is_exact_and_unique() -> None:
    assert len(module.__all__) == len(set(module.__all__))
    assert set(module.__all__) == {
        "CONTAINER_ARCHITECTURE",
        "CONTAINER_NETWORK_MODE",
        "CONTAINER_OPERATING_SYSTEM",
        "CONTAINER_RUNTIME",
        "DOCUMENT_TYPE",
        "EntraCallingClientMSALZeroRetryContainerIsolationReadinessError",
        "EntraCallingClientMSALZeroRetryContainerIsolationReadinessReceipt",
        "PROFILE",
        "RECEIPT_TYPE",
        "SOURCE",
        "STATUS",
        "STEP228_PACKAGE_MANIFEST_SHA256",
        "load_entra_calling_client_msal_zero_retry_container_isolation_readiness",
        "render_entra_calling_client_msal_zero_retry_container_isolation_readiness_receipt",
    }
