from __future__ import annotations

import ast
import hashlib
import json
from builtins import BaseExceptionGroup
from dataclasses import fields
from pathlib import Path

import pytest

import app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_container_execution_loader as loader
import app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_container_execution_probe as module
import app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_container_isolation_readiness as step229
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
ADAPTER = (
    SECURITY
    / "authentication_entra_calling_client_msal_browser_zero_retry_network_client.mjs"
)
HARNESS = SECURITY / HARNESS_FILE_NAME
RUNNER = SECURITY / RUNNER_FILE_NAME
IMAGE_ID = "sha256:" + "2" * 64
DOCKER_SHA256 = "3" * 64
NODE_SHA256 = "1" * 64
CONTAINER_ID = "4" * 64


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


def _step229_document(**updates: object) -> bytes:
    value: dict[str, object] = {
        "document_type": step229.DOCUMENT_TYPE,
        "schema_version": 1,
        "source": step229.SOURCE,
        "approved_step228_package_manifest_sha256": (
            step229.STEP228_PACKAGE_MANIFEST_SHA256
        ),
        "approved_step228_execution_document_sha256": hashlib.sha256(
            _step228_document()
        ).hexdigest(),
        "approved_container_image_id": IMAGE_ID,
        "expected_container_operating_system": step229.CONTAINER_OPERATING_SYSTEM,
        "expected_container_architecture": step229.CONTAINER_ARCHITECTURE,
        "expected_node_path": step229.CONTAINER_NODE_PATH,
        "isolation_profile": step229.PROFILE,
    }
    value.update(updates)
    return _canonical(value)


def _document(**updates: object) -> bytes:
    value: dict[str, object] = {
        "document_type": module.DOCUMENT_TYPE,
        "schema_version": 1,
        "source": module.SOURCE,
        "approved_step229_package_manifest_sha256": (
            module.STEP229_PACKAGE_MANIFEST_SHA256
        ),
        "approved_step229_isolation_document_sha256": hashlib.sha256(
            _step229_document()
        ).hexdigest(),
        "approved_docker_executable_sha256": DOCKER_SHA256,
        "execution_profile": module.PROFILE,
    }
    value.update(updates)
    return _canonical(value)


def _version() -> bytes:
    return _canonical(
        {"ApiVersion": "1.53", "Arch": "amd64", "Os": "linux", "Version": "29.6.1"}
    )


def _image() -> bytes:
    return _canonical(
        {
            "Id": IMAGE_ID,
            "Os": "linux",
            "Architecture": "amd64",
            "Size": 100_000_000,
            "Config": {
                "Env": [
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "NODE_VERSION=24.19.0",
                    "YARN_VERSION=1.22.22",
                ],
                "Volumes": None,
                "ExposedPorts": None,
                "Healthcheck": None,
                "OnBuild": None,
            },
            "RootFS": {"Type": "layers", "Layers": ["sha256:" + "5" * 64]},
        }
    )


def _container(exited: bool) -> bytes:
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "NODE_VERSION": "24.19.0",
        "YARN_VERSION": "1.22.22",
        **loader._environment_overrides(),
    }
    return _canonical(
        {
            "Id": CONTAINER_ID,
            "Image": IMAGE_ID,
            "Path": step229.CONTAINER_NODE_PATH,
            "Args": list(loader._container_arguments()),
            "Config": {
                "Image": IMAGE_ID,
                "User": step229.CONTAINER_USER,
                "WorkingDir": step229.CONTAINER_WORKDIR,
                "Entrypoint": [step229.CONTAINER_NODE_PATH],
                "Cmd": list(loader._container_arguments()),
                "Env": [
                    f"{name}={value}" for name, value in sorted(environment.items())
                ],
                "Healthcheck": {"Test": ["NONE"]},
            },
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapDrop": ["ALL"],
                "PidsLimit": 32,
                "Memory": 268_435_456,
                "MemorySwap": 268_435_456,
                "NanoCpus": 1_000_000_000,
                "ShmSize": 16_777_216,
                "AutoRemove": False,
                "PublishAllPorts": False,
                "PortBindings": {},
                "Devices": [],
                "Binds": None,
                "Tmpfs": {},
                "VolumesFrom": None,
                "Links": None,
                "ExtraHosts": None,
                "Dns": [],
                "DnsOptions": [],
                "DnsSearch": [],
                "PidMode": "private",
                "IpcMode": "private",
                "UTSMode": "private",
                "CgroupnsMode": "private",
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "LogConfig": {"Type": "none", "Config": {}},
                "SecurityOpt": ["no-new-privileges=true", "seccomp=builtin"],
            },
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": "/host/ephemeral/work",
                    "Destination": "/work",
                    "RW": False,
                }
            ],
            "NetworkSettings": {
                "Networks": {
                    "none": {
                        "Gateway": "",
                        "IPAddress": "",
                        "GlobalIPv6Address": "",
                    }
                },
                "Ports": {},
            },
            "State": (
                {
                    "Running": False,
                    "Status": "exited",
                    "ExitCode": 0,
                    "StartedAt": "2026-08-17T00:00:00Z",
                    "FinishedAt": "2026-08-17T00:00:01Z",
                }
                if exited
                else {"Running": False, "Status": "created", "ExitCode": 0}
            ),
        }
    )


def _evidence(**updates: object):
    values: dict[str, object] = {
        "docker_cli_sha256": DOCKER_SHA256,
        "image_id": IMAGE_ID,
        "docker_version_document": _version(),
        "image_inspect_document": _image(),
        "container_inspect_before_start_document": _container(False),
        "container_inspect_after_exit_document": _container(True),
        "node_executable_sha256": NODE_SHA256,
        "stdout": step229._step228_synthetic_stdout(),
        "stderr": b"",
        "exit_code": 0,
        "command_sequence": loader.COMMAND_SEQUENCE,
        "cleanup_succeeded": True,
    }
    values.update(updates)
    return loader.EntraCallingClientMSALZeroRetryContainerExecutionEvidence(**values)


def _load(**updates: object):
    values: dict[str, object] = {
        "document": _document(),
        "step229_document": _step229_document(),
        "step228_document": _step228_document(),
        "step227_document": _step227_document(),
        "step226_document": _step226_document(),
        "adapter": ADAPTER.read_bytes(),
        "harness": HARNESS.read_bytes(),
        "runner": RUNNER.read_bytes(),
        "execution_transport": lambda _request: _evidence(),
    }
    values.update(updates)
    return module.prove_entra_calling_client_msal_zero_retry_container_execution(
        **values
    )


def _unsafe_clone(receipt: object, name: str, replacement: object):
    clone = object.__new__(type(receipt))
    for item in fields(receipt):
        object.__setattr__(
            clone,
            item.name,
            replacement if item.name == name else getattr(receipt, item.name),
        )
    return clone


def test_valid_synthetic_container_execution_proof() -> None:
    receipt = _load()
    assert receipt.synthetic_container_execution_evidence is True
    assert receipt.sealed_docker_execution_performed is False
    assert receipt.sealed_docker_command_count == 0
    assert receipt.planned_docker_command_count == 8
    assert receipt.exact_step228_zero_retry_stdout_validated is True
    assert receipt.sealed_docker_none_network_applied is False
    assert receipt.active_in_container_tcp_denial_checked is False
    assert receipt.package_selection_approved is False


def test_step229_prerequisite_runs_before_current_document_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False
    original = (
        module.load_entra_calling_client_msal_zero_retry_container_isolation_readiness
    )

    def wrapped(*values: object):
        nonlocal called
        called = True
        return original(*values)

    monkeypatch.setattr(
        module,
        "load_entra_calling_client_msal_zero_retry_container_isolation_readiness",
        wrapped,
    )
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerExecutionProbeError
    ):
        _load(document=b"not-json")
    assert called


@pytest.mark.parametrize(
    "updates",
    [
        {"document_type": "wrong"},
        {"schema_version": True},
        {"source": "wrong"},
        {"approved_step229_package_manifest_sha256": "0" * 64},
        {"approved_step229_isolation_document_sha256": "0" * 64},
        {"approved_docker_executable_sha256": "x"},
        {"execution_profile": "wrong"},
        {"extra": False},
    ],
)
def test_document_tampering_fails(updates: dict[str, object]) -> None:
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerExecutionProbeError
    ):
        _load(document=_document(**updates))


def test_document_must_be_canonical() -> None:
    value = json.loads(_document())
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerExecutionProbeError
    ):
        _load(document=json.dumps(value, indent=2).encode())


@pytest.mark.parametrize(
    "name",
    [
        "step229_document",
        "step228_document",
        "step227_document",
        "step226_document",
        "adapter",
        "harness",
        "runner",
    ],
)
def test_every_prerequisite_source_tamper_fails(name: str) -> None:
    source = {
        "step229_document": _step229_document(),
        "step228_document": _step228_document(),
        "step227_document": _step227_document(),
        "step226_document": _step226_document(),
        "adapter": ADAPTER.read_bytes(),
        "harness": HARNESS.read_bytes(),
        "runner": RUNNER.read_bytes(),
    }[name]
    changed = bytearray(source)
    changed[-1] ^= 1
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerExecutionProbeError
    ):
        _load(**{name: bytes(changed)})


def test_reblessed_invalid_step229_document_fails() -> None:
    step229_document = _step229_document(expected_container_architecture="arm64")
    current = _document(
        approved_step229_isolation_document_sha256=hashlib.sha256(
            step229_document
        ).hexdigest()
    )
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerExecutionProbeError
    ):
        _load(document=current, step229_document=step229_document)


@pytest.mark.parametrize(
    "name",
    [
        "document",
        "step229_document",
        "step228_document",
        "step227_document",
        "step226_document",
        "adapter",
        "harness",
        "runner",
    ],
)
def test_public_source_types_are_exact(name: str) -> None:
    with pytest.raises(TypeError):
        _load(**{name: bytearray(b"not-exact")})


def test_public_source_byte_objects_must_be_distinct() -> None:
    shared = _step226_document()
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerExecutionProbeError
    ):
        _load(document=shared, step226_document=shared)


@pytest.mark.parametrize(
    "updates",
    [
        {"docker_cli_sha256": "0" * 64},
        {"image_id": "sha256:" + "0" * 64},
        {"node_executable_sha256": "0" * 64},
        {"stdout": b"{}\n{}\n"},
        {"stderr": b"private"},
        {"cleanup_succeeded": False},
    ],
)
def test_evidence_identity_or_stdout_tampering_fails(
    updates: dict[str, object],
) -> None:
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryContainerExecutionProbeError
    ):
        _load(execution_transport=lambda _request: _evidence(**updates))


def test_modes_are_mutually_exclusive() -> None:
    with pytest.raises(TypeError):
        _load(docker_executable_path="/docker")
    with pytest.raises(TypeError):
        module.prove_entra_calling_client_msal_zero_retry_container_execution(
            document=_document(),
            step229_document=_step229_document(),
            step228_document=_step228_document(),
            step227_document=_step227_document(),
            step226_document=_step226_document(),
            adapter=ADAPTER.read_bytes(),
            harness=HARNESS.read_bytes(),
            runner=RUNNER.read_bytes(),
            docker_executable_path="/docker",
            execution_transport=lambda _request: _evidence(),
        )


def test_valid_live_receipt_partition_is_constructible() -> None:
    receipt = _load()
    live_names = {
        "sealed_docker_execution_performed",
        "sealed_candidate_docker_daemon_accessed",
        "sealed_local_image_inspected",
        "sealed_container_created",
        "sealed_container_configuration_reinspected",
        "sealed_node_binary_attested",
        "sealed_container_started_once",
        "sealed_container_removed",
        "sealed_docker_none_network_applied",
        "sealed_zero_retry_matrix_observed_in_container",
        "sealed_temporary_filesystem_io_performed",
        "sealed_local_container_process_performed",
    }
    clone = object.__new__(type(receipt))
    for item in fields(receipt):
        value = getattr(receipt, item.name)
        if item.name == "synthetic_container_execution_evidence":
            value = False
        elif item.name == "sealed_docker_command_count":
            value = 8
        elif item.name in live_names:
            value = True
        object.__setattr__(clone, item.name, value)
    clone.__post_init__()


def test_every_receipt_field_is_guarded() -> None:
    receipt = _load()
    flexible = {
        "execution_document_sha256",
        "step229_isolation_document_sha256",
        "step229_receipt_sha256",
        "docker_cli_sha256",
        "approved_container_image_id",
        "approved_node_executable_sha256",
        "docker_evidence_projection_sha256",
        "public_identity_summary_sha256",
        "image_projection_sha256",
        "container_before_projection_sha256",
        "container_after_projection_sha256",
        "command_sequence_sha256",
        "execution_stdout_sha256",
        "step228_execution_receipt_sha256",
        "docker_server_version",
        "docker_server_api_version",
    }
    for item in fields(receipt):
        current = getattr(receipt, item.name)
        if item.name == "approved_container_image_id":
            replacement: object = "not-image"
        elif item.name in flexible:
            replacement = "x"
        elif type(current) is bool:
            replacement = not current
        elif type(current) is int:
            replacement = True
        else:
            replacement = "x"
        clone = _unsafe_clone(receipt, item.name, replacement)
        with pytest.raises(ValueError):
            clone.__post_init__()


def test_receipt_source_has_no_duplicate_field_declarations() -> None:
    tree = ast.parse(Path(module.__file__).read_text())
    receipt = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "EntraCallingClientMSALZeroRetryContainerExecutionProofReceipt"
    )
    names = [
        node.target.id
        for node in receipt.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    ]
    assert len(names) == len(set(names))


def test_renderer_is_canonical_and_exact_type_only() -> None:
    receipt = _load()
    rendered = (
        module.render_entra_calling_client_msal_zero_retry_container_execution_receipt(
            receipt
        )
    )
    assert rendered == json.dumps(
        json.loads(rendered), sort_keys=True, separators=(",", ":")
    )
    assert set(json.loads(rendered)) == set(receipt.__dataclass_fields__)
    with pytest.raises(TypeError):
        module.render_entra_calling_client_msal_zero_retry_container_execution_receipt(
            object()  # type: ignore[arg-type]
        )


def test_nested_control_flow_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    child = ValueError("private-container-marker")
    group = BaseExceptionGroup(
        "private-group-marker",
        [SystemExit("private-exit"), KeyboardInterrupt("private-interrupt"), child],
    )

    def fail(**_values: object) -> None:
        raise group

    monkeypatch.setattr(module, "_load_internal", fail)
    with pytest.raises(KeyboardInterrupt) as caught:
        _load()
    assert "private" not in str(caught.value)
    assert caught.value.__context__ is None
    assert child.args == ()


def test_probe_has_no_direct_process_or_network_import() -> None:
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
    assert not imported.intersection({"socket", "ssl", "subprocess", "urllib"})


def test_public_export_set_is_exact() -> None:
    assert len(module.__all__) == len(set(module.__all__))
    assert set(module.__all__) == {
        "DOCUMENT_TYPE",
        "EntraCallingClientMSALZeroRetryContainerExecutionProbeError",
        "EntraCallingClientMSALZeroRetryContainerExecutionProofReceipt",
        "PROFILE",
        "RECEIPT_TYPE",
        "SOURCE",
        "STATUS",
        "STEP229_PACKAGE_MANIFEST_SHA256",
        "prove_entra_calling_client_msal_zero_retry_container_execution",
        "render_entra_calling_client_msal_zero_retry_container_execution_receipt",
    }
