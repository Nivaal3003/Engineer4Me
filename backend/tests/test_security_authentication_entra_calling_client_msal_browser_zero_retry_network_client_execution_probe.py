from __future__ import annotations

import hashlib
import json
import os
from builtins import BaseExceptionGroup
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests._step278_windows_symlink_test_support import (
    create_or_emulate_file_symlink,
)

import app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_execution_probe as module
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
HARNESS_FILE = SECURITY / module.HARNESS_FILE_NAME
RUNNER_FILE = SECURITY / module.RUNNER_FILE_NAME
SYNTHETIC_NODE_SHA256 = "1" * 64


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _step226_document() -> bytes:
    return _canonical(
        {
            "document_type": STEP226_DOCUMENT_TYPE,
            "schema_version": 1,
            "source": STEP226_SOURCE,
            "approved_step225_package_manifest_sha256": STEP225_PACKAGE_MANIFEST_SHA256,
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


def _document(**updates: object) -> bytes:
    value: dict[str, object] = {
        "document_type": module.DOCUMENT_TYPE,
        "schema_version": 1,
        "source": module.SOURCE,
        "approved_step227_implementation_document_sha256": hashlib.sha256(
            _step227_document()
        ).hexdigest(),
        "expected_node_version": module.NODE_VERSION,
        "approved_node_executable_sha256": SYNTHETIC_NODE_SHA256,
        "execution_profile": module.PROFILE,
    }
    value.update(updates)
    return _canonical(value)


def _option(method: str) -> dict[str, object]:
    return {
        "cache": "no-store",
        "credentials": "omit",
        "hasAbortSignal": True,
        "method": method,
        "mode": "cors",
        "redirect": "error",
        "referrerPolicy": "no-referrer",
    }


def _scenario(
    name: str,
    attempts: int,
    status: int | None,
    body_kind: str | None,
    error: str | None,
    options: dict[str, object] | None,
) -> dict[str, object]:
    return {
        "name": name,
        "attemptCount": attempts,
        "status": status,
        "bodyKind": body_kind,
        "errorMessage": error,
        "optionProjection": options,
    }


def _records() -> tuple[dict[str, object], dict[str, object]]:
    permissions = {
        "childProcess": False,
        "worker": False,
        "fileSystemWrite": False,
        "addons": False,
        "wasi": False,
        "inspector": False,
    }
    runner = {
        "runnerSchemaVersion": 1,
        "nodeVersion": module.NODE_VERSION,
        "harnessSha256": module.HARNESS_SHA256,
        "adapterSha256": ADAPTER_SHA256,
        "permissions": permissions,
        "globalFetchDisabled": True,
        "operatingSystemNetworkCapabilityDenied": False,
    }
    post = _option("POST")
    get = _option("GET")
    scenarios = [
        _scenario("post_success_once", 1, 200, "success", None, post),
        _scenario("get_success_once", 1, 200, "success", None, get),
        _scenario(
            "transport_failure_no_retry",
            1,
            None,
            None,
            "MSAL network request failed",
            post,
        ),
        _scenario(
            "abort_failure_no_retry",
            1,
            None,
            None,
            "MSAL network request failed",
            post,
        ),
        _scenario(
            "invalid_json_no_retry",
            1,
            None,
            None,
            "MSAL network request failed",
            post,
        ),
        _scenario("http_400_returned_once", 1, 400, "success", None, post),
        _scenario(
            "oauth_invalid_grant_returned_once",
            1,
            400,
            "oauth_error",
            None,
            post,
        ),
        _scenario(
            "wrong_post_target_rejected_before_fetch",
            0,
            None,
            None,
            "network request target is not approved",
            None,
        ),
        _scenario(
            "forbidden_header_rejected_before_fetch",
            0,
            None,
            None,
            "request headers are invalid",
            None,
        ),
        _scenario(
            "unapproved_get_rejected_before_fetch",
            0,
            None,
            None,
            "network request target is not approved",
            None,
        ),
        _scenario(
            "get_body_rejected_before_fetch",
            0,
            None,
            None,
            "GET request body is forbidden",
            None,
        ),
        _scenario(
            "oversized_response_no_retry",
            1,
            None,
            None,
            "MSAL network request failed",
            post,
        ),
        _scenario(
            "duplicate_response_header_no_retry",
            1,
            None,
            None,
            "MSAL network request failed",
            post,
        ),
        _scenario(
            "timeout_abort_no_retry",
            1,
            None,
            None,
            "MSAL network request failed",
            post,
        ),
        {
            "name": "concurrent_calls_one_attempt_each",
            "attemptCount": 2,
            "perRequestAttempts": [1, 1],
            "statuses": [200, 200],
            "bodyKind": "success",
            "errorMessage": None,
            "optionProjection": None,
        },
    ]
    harness = {
        "schemaVersion": 1,
        "scenarioCount": len(scenarios),
        "scenarios": scenarios,
    }
    return runner, harness


def _stdout(
    runner: dict[str, object] | None = None,
    harness: dict[str, object] | None = None,
) -> bytes:
    expected_runner, expected_harness = _records()
    return (
        json.dumps(runner or expected_runner, separators=(",", ":"))
        + "\n"
        + json.dumps(harness or expected_harness, separators=(",", ":"))
        + "\n"
    ).encode()


def _evidence(stdout: bytes | None = None):
    return module.EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence(
        node_version=module.NODE_VERSION,
        node_executable_sha256=SYNTHETIC_NODE_SHA256,
        stdout=stdout or _stdout(),
        stderr=b"",
        exit_code=0,
    )


def _transport(stdout: bytes | None = None):
    def execute(adapter: bytes, harness: bytes, runner: bytes):
        assert hashlib.sha256(adapter).hexdigest() == ADAPTER_SHA256
        assert hashlib.sha256(harness).hexdigest() == module.HARNESS_SHA256
        assert hashlib.sha256(runner).hexdigest() == module.RUNNER_SHA256
        return _evidence(stdout)

    return execute


def _adapter() -> bytes:
    return ADAPTER_FILE.read_bytes()


def _harness() -> bytes:
    return HARNESS_FILE.read_bytes()


def _runner() -> bytes:
    return RUNNER_FILE.read_bytes()


def _receipt():
    return module.prove_entra_calling_client_msal_zero_retry_network_client_execution(
        document=_document(),
        step227_document=_step227_document(),
        step226_document=_step226_document(),
        adapter=_adapter(),
        harness=_harness(),
        runner=_runner(),
        execution_transport=_transport(),
    )


def _unsafe_clone(receipt, name: str, value: object):
    clone = object.__new__(type(receipt))
    for field in fields(receipt):
        object.__setattr__(
            clone,
            field.name,
            value if field.name == name else getattr(receipt, field.name),
        )
    return clone


def test_exact_harness_runner_and_adapter_identities() -> None:
    assert len(_adapter()) == module.ADAPTER_BYTES
    assert hashlib.sha256(_adapter()).hexdigest() == ADAPTER_SHA256
    assert len(_harness()) == module.HARNESS_BYTES == 7_882
    assert hashlib.sha256(_harness()).hexdigest() == module.HARNESS_SHA256
    assert len(_runner()) == module.RUNNER_BYTES == 2_149
    assert hashlib.sha256(_runner()).hexdigest() == module.RUNNER_SHA256


def test_valid_synthetic_projection_has_no_sealed_attestation() -> None:
    receipt = _receipt()
    assert receipt.scenario_count == 15
    assert receipt.observed_fetch_call_count == 12
    assert receipt.single_attempt_scenario_count == 10
    assert receipt.pre_fetch_rejection_count == 4
    assert receipt.synthetic_execution_evidence is True
    assert receipt.sealed_node_execution_performed is False
    assert receipt.temporary_filesystem_io_performed is False
    assert receipt.local_node_process_performed is False
    assert receipt.sealed_provider_or_external_network_io_performed is False
    assert receipt.package_selection_approved is False


def test_live_attestation_partition_is_constructible() -> None:
    receipt = _receipt()
    values = {field.name: getattr(receipt, field.name) for field in fields(receipt)}
    values["synthetic_execution_evidence"] = False
    for name in (
        "sealed_node_execution_performed",
        "sealed_node_executable_attested",
        "sealed_permission_profile_enforced",
        "global_fetch_disabled_by_sealed_runner",
        "sealed_filesystem_write_permission_absent",
        "sealed_child_process_permission_absent",
        "temporary_filesystem_io_performed",
        "local_node_process_performed",
    ):
        values[name] = True
    receipt = module.EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt(
        **values
    )
    assert receipt.synthetic_execution_evidence is False
    assert receipt.sealed_node_execution_performed is True
    assert receipt.global_fetch_disabled_by_sealed_runner is True
    assert receipt.operating_system_network_capability_denied is False
    assert receipt.temporary_filesystem_io_performed is True
    assert receipt.local_node_process_performed is True


def test_injected_transport_cannot_confer_sealed_attestation() -> None:
    evidence = module._attest_sealed_evidence(_evidence())
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryNetworkClientExecutionProbeError
    ):
        module.prove_entra_calling_client_msal_zero_retry_network_client_execution(
            document=_document(),
            step227_document=_step227_document(),
            step226_document=_step226_document(),
            adapter=_adapter(),
            harness=_harness(),
            runner=_runner(),
            execution_transport=lambda *_: evidence,
        )


@pytest.mark.parametrize(
    ("node_path", "transport"),
    [
        (None, None),
        ("/absolute/node", _transport()),
        (None, object()),
    ],
)
def test_execution_mode_is_exact(node_path: object, transport: object) -> None:
    with pytest.raises(TypeError):
        module.prove_entra_calling_client_msal_zero_retry_network_client_execution(
            document=_document(),
            step227_document=_step227_document(),
            step226_document=_step226_document(),
            adapter=_adapter(),
            harness=_harness(),
            runner=_runner(),
            node_executable_path=node_path,
            execution_transport=transport,
        )


@pytest.mark.parametrize("position", range(6))
def test_every_source_input_requires_exact_bytes(position: int) -> None:
    values: list[object] = [
        _document(),
        _step227_document(),
        _step226_document(),
        _adapter(),
        _harness(),
        _runner(),
    ]
    values[position] = bytearray(values[position])  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        module.prove_entra_calling_client_msal_zero_retry_network_client_execution(
            document=values[0],
            step227_document=values[1],
            step226_document=values[2],
            adapter=values[3],
            harness=values[4],
            runner=values[5],
            execution_transport=_transport(),
        )


@pytest.mark.parametrize("source", ["adapter", "harness", "runner"])
def test_exact_source_tampering_fails(source: str) -> None:
    values = {
        "adapter": _adapter(),
        "harness": _harness(),
        "runner": _runner(),
    }
    candidate = bytearray(values[source])
    candidate[len(candidate) // 2] ^= 1
    values[source] = bytes(candidate)
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryNetworkClientExecutionProbeError
    ):
        module.prove_entra_calling_client_msal_zero_retry_network_client_execution(
            document=_document(),
            step227_document=_step227_document(),
            step226_document=_step226_document(),
            adapter=values["adapter"],
            harness=values["harness"],
            runner=values["runner"],
            execution_transport=_transport(),
        )


@pytest.mark.parametrize(
    "updates",
    [
        {"document_type": "wrong"},
        {"schema_version": 2},
        {"schema_version": True},
        {"source": "wrong"},
        {"approved_step227_implementation_document_sha256": "0" * 64},
        {"expected_node_version": "v0.0.0"},
        {"approved_node_executable_sha256": "not-a-digest"},
        {"execution_profile": "wrong"},
        {"extra": True},
    ],
)
def test_document_tampering_fails(updates: dict[str, object]) -> None:
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryNetworkClientExecutionProbeError
    ):
        module.prove_entra_calling_client_msal_zero_retry_network_client_execution(
            document=_document(**updates),
            step227_document=_step227_document(),
            step226_document=_step226_document(),
            adapter=_adapter(),
            harness=_harness(),
            runner=_runner(),
            execution_transport=_transport(),
        )


def test_every_scenario_is_exactly_bound() -> None:
    runner, harness = _records()
    scenarios = harness["scenarios"]
    assert isinstance(scenarios, list)
    for index in range(len(scenarios)):
        changed = json.loads(json.dumps(harness))
        changed["scenarios"][index]["attemptCount"] = 99
        with pytest.raises(
            module.EntraCallingClientMSALZeroRetryNetworkClientExecutionProbeError
        ):
            module.prove_entra_calling_client_msal_zero_retry_network_client_execution(
                document=_document(),
                step227_document=_step227_document(),
                step226_document=_step226_document(),
                adapter=_adapter(),
                harness=_harness(),
                runner=_runner(),
                execution_transport=_transport(_stdout(runner, changed)),
            )


def test_permission_projection_is_exact() -> None:
    runner, harness = _records()
    permissions = runner["permissions"]
    assert isinstance(permissions, dict)
    for name in permissions:
        changed = json.loads(json.dumps(runner))
        changed["permissions"][name] = True
        with pytest.raises(
            module.EntraCallingClientMSALZeroRetryNetworkClientExecutionProbeError
        ):
            module.prove_entra_calling_client_msal_zero_retry_network_client_execution(
                document=_document(),
                step227_document=_step227_document(),
                step226_document=_step226_document(),
                adapter=_adapter(),
                harness=_harness(),
                runner=_runner(),
                execution_transport=_transport(_stdout(changed, harness)),
            )
    for name, invalid in (
        ("globalFetchDisabled", False),
        ("operatingSystemNetworkCapabilityDenied", True),
    ):
        changed = json.loads(json.dumps(runner))
        changed[name] = invalid
        with pytest.raises(
            module.EntraCallingClientMSALZeroRetryNetworkClientExecutionProbeError
        ):
            module.prove_entra_calling_client_msal_zero_retry_network_client_execution(
                document=_document(),
                step227_document=_step227_document(),
                step226_document=_step226_document(),
                adapter=_adapter(),
                harness=_harness(),
                runner=_runner(),
                execution_transport=_transport(_stdout(changed, harness)),
            )


@pytest.mark.parametrize(
    "stdout",
    [
        b"",
        b"{}\n",
        b"{}\n{}\n{}\n",
        b"\xff\n{}\n",
        b'{"x":1,"x":2}\n{}\n',
        b"not-json\n{}\n",
    ],
)
def test_malformed_execution_stdout_fails(stdout: bytes) -> None:
    with pytest.raises(
        (
            ValueError,
            module.EntraCallingClientMSALZeroRetryNetworkClientExecutionProbeError,
        )
    ):
        evidence = module.EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence(
            node_version=module.NODE_VERSION,
            node_executable_sha256=SYNTHETIC_NODE_SHA256,
            stdout=stdout,
            stderr=b"",
            exit_code=0,
        )
        module.prove_entra_calling_client_msal_zero_retry_network_client_execution(
            document=_document(),
            step227_document=_step227_document(),
            step226_document=_step226_document(),
            adapter=_adapter(),
            harness=_harness(),
            runner=_runner(),
            execution_transport=lambda *_: evidence,
        )


def test_node_executable_validation_binds_exact_regular_file(tmp_path: Path) -> None:
    node = tmp_path / ("node.exe" if os.name == "nt" else "node")
    node.write_bytes(b"synthetic-node")
    node.chmod(0o700)
    digest = hashlib.sha256(node.read_bytes()).hexdigest()
    assert module._validate_node_executable(str(node.resolve()), digest) == str(
        node.resolve()
    )
    with pytest.raises(ValueError):
        module._validate_node_executable(str(node.resolve()), "0" * 64)


def test_node_executable_rejects_relative_symlink_and_non_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    non_executable = tmp_path / ("node.txt" if os.name == "nt" else "node")
    non_executable.write_bytes(b"node")
    digest = hashlib.sha256(b"node").hexdigest()
    non_executable.chmod(0o600)
    with pytest.raises((TypeError, ValueError)):
        module._validate_node_executable("node", digest)
    with pytest.raises(ValueError):
        module._validate_node_executable(str(non_executable.resolve()), digest)
    if hasattr(os, "symlink"):
        executable = tmp_path / (
            "node.exe" if os.name == "nt" else "node-executable"
        )
        executable.write_bytes(b"node")
        executable.chmod(0o700)
        link = tmp_path / "node-link"
        create_or_emulate_file_symlink(
            link=link,
            target=executable,
            monkeypatch=monkeypatch,
            module_os=module.os,
        )
        with pytest.raises((TypeError, ValueError)):
            module._validate_node_executable(str(link), digest)


def test_sealed_executor_uses_exact_permission_restricted_process_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node = tmp_path / ("node.exe" if os.name == "nt" else "node")
    node.write_bytes(b"exact-node")
    node.chmod(0o700)
    node_path = str(node.resolve())
    digest = hashlib.sha256(b"exact-node").hexdigest()
    observed: dict[str, object] = {}

    def run(arguments: list[str], **options: object) -> SimpleNamespace:
        observed["arguments"] = arguments
        observed["options"] = options
        workspace = Path(str(options["cwd"]))
        assert arguments == [
            node_path,
            "--permission",
            f"--allow-fs-read={workspace}",
            str(workspace / "runner.mjs"),
            str(workspace / "harness.mjs"),
            str(workspace / "adapter.mjs"),
            module.HARNESS_SHA256,
            ADAPTER_SHA256,
        ]
        assert (workspace / "adapter.mjs").read_bytes() == _adapter()
        assert (workspace / "harness.mjs").read_bytes() == _harness()
        assert (workspace / "runner.mjs").read_bytes() == _runner()
        return SimpleNamespace(stdout=_stdout(), stderr=b"", returncode=0)

    monkeypatch.setattr(module.subprocess, "run", run)
    evidence = module._sealed_execute(
        adapter=_adapter(),
        harness=_harness(),
        runner=_runner(),
        node_executable_path=node_path,
        approved_node_executable_sha256=digest,
    )
    assert module._is_sealed_evidence(evidence)
    assert evidence.node_executable_sha256 == digest
    options = observed["options"]
    assert isinstance(options, dict)
    assert options["stdin"] is module.subprocess.DEVNULL
    assert options["capture_output"] is True
    assert options["timeout"] == module.NODE_TIMEOUT_SECONDS
    assert options["check"] is False
    assert options["shell"] is False
    environment = options["env"]
    assert isinstance(environment, dict)
    expected_environment = {
        "HOME",
        "USERPROFILE",
        "TMP",
        "TEMP",
        "NO_COLOR",
    }
    if os.name == "nt":
        expected_environment.add("SystemRoot")
        assert os.path.isabs(environment["SystemRoot"])
    assert set(environment) == expected_environment
    assert environment["NO_COLOR"] == "1"
    assert environment["HOME"] == environment["USERPROFILE"]
    assert environment["TMP"] == environment["TEMP"]


def test_domain_separated_fixed_profile_digests_are_exact() -> None:
    projection, _ = module._scenario_projection(_stdout())
    assert module._framed("scenarios", projection) == module.SCENARIO_PROJECTION_SHA256
    assert (
        module._framed(
            "permissions",
            {
                "permissionFlag": True,
                "fileSystemRead": "ephemeral_workspace_only",
                "childProcess": False,
                "worker": False,
                "fileSystemWrite": False,
                "addons": False,
                "wasi": False,
                "inspector": False,
                "globalFetchDisabled": True,
                "operatingSystemNetworkCapabilityDenied": False,
            },
        )
        == module.PERMISSION_PROFILE_SHA256
    )
    assert (
        module._framed(
            "selection",
            {
                "step216ZeroRetrySuperseded": False,
                "step225DefaultAccepted": False,
                "compatible": False,
                "selected": False,
                "installed": False,
            },
        )
        == module.FAIL_CLOSED_SELECTION_STATE_SHA256
    )


def test_every_receipt_field_is_guarded() -> None:
    receipt = _receipt()
    flexible = {
        "execution_proof_document_sha256",
        "step227_implementation_document_sha256",
        "step227_receipt_sha256",
        "node_executable_sha256",
        "stdout_sha256",
    }
    for field in fields(receipt):
        current = getattr(receipt, field.name)
        if field.name in flexible:
            invalid: object = "x"
        elif type(current) is bool:
            invalid = not current
        elif type(current) is int:
            invalid = True
        else:
            invalid = "0" * 64 if current != "0" * 64 else "1" * 64
        clone = _unsafe_clone(receipt, field.name, invalid)
        with pytest.raises(ValueError):
            clone.__post_init__()


def test_renderer_is_canonical_and_requires_exact_receipt() -> None:
    receipt = _receipt()
    rendered = module.render_entra_calling_client_msal_zero_retry_network_client_execution_receipt(
        receipt
    )
    assert rendered == json.dumps(
        json.loads(rendered), sort_keys=True, separators=(",", ":")
    )
    assert set(json.loads(rendered)) == set(receipt.__dataclass_fields__)
    with pytest.raises(TypeError):
        module.render_entra_calling_client_msal_zero_retry_network_client_execution_receipt(
            object()  # type: ignore[arg-type]
        )


def test_nested_control_flow_is_preserved_and_evidence_detached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = ValueError("private-execution-marker")
    group = BaseExceptionGroup(
        "private-group-marker",
        [SystemExit("private-exit"), KeyboardInterrupt("private-interrupt"), child],
    )

    def fail(**_: object) -> None:
        raise group

    monkeypatch.setattr(module, "_load_internal", fail)
    with pytest.raises(KeyboardInterrupt) as caught:
        module.prove_entra_calling_client_msal_zero_retry_network_client_execution(
            document=_document(),
            step227_document=_step227_document(),
            step226_document=_step226_document(),
            adapter=_adapter(),
            harness=_harness(),
            runner=_runner(),
            execution_transport=_transport(),
        )
    assert "private" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert child.args == ()
    assert child.__traceback__ is None


def test_public_export_set_is_exact_and_unique() -> None:
    assert len(module.__all__) == len(set(module.__all__))
    assert set(module.__all__) == {
        "DOCUMENT_TYPE",
        "EntraCallingClientMSALZeroRetryNetworkClientExecutionEvidence",
        "EntraCallingClientMSALZeroRetryNetworkClientExecutionProbeError",
        "EntraCallingClientMSALZeroRetryNetworkClientExecutionProofReceipt",
        "HARNESS_BYTES",
        "HARNESS_FILE_NAME",
        "HARNESS_SHA256",
        "NODE_VERSION",
        "PROFILE",
        "RECEIPT_TYPE",
        "RUNNER_BYTES",
        "RUNNER_FILE_NAME",
        "RUNNER_SHA256",
        "SOURCE",
        "STATUS",
        "prove_entra_calling_client_msal_zero_retry_network_client_execution",
        "render_entra_calling_client_msal_zero_retry_network_client_execution_receipt",
    }
