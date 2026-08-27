"""Tests for the Step 223 dual-artifact sealed execution proof."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
from builtins import BaseExceptionGroup
from dataclasses import fields
from pathlib import Path

import pytest

from tests._step278_windows_symlink_test_support import (
    create_or_emulate_file_symlink,
)

import app.security.authentication_entra_calling_client_msal_browser_compiled_retry_execution_probe as module
from app.security.authentication_entra_calling_client_msal_browser_compiled_retry_execution_probe import (
    DOCUMENT_TYPE,
    NODE_VERSION,
    PROFILE,
    RECEIPT_TYPE,
    RUNNER_BYTES,
    RUNNER_FILE_NAME,
    RUNNER_SHA256,
    SOURCE,
    STATUS,
    EntraCallingClientMSALCompiledRetryArtifactEvidence,
    EntraCallingClientMSALCompiledRetryExecutionEvidence,
    EntraCallingClientMSALCompiledRetryExecutionProbeError,
    load_entra_calling_client_msal_compiled_retry_execution_proof,
    render_entra_calling_client_msal_compiled_retry_execution_proof_receipt,
)
from tests import (
    test_security_authentication_entra_calling_client_msal_browser_compiled_retry_harness_readiness as step222,
)

RUNNER_PATH = Path(module.__file__).with_name(RUNNER_FILE_NAME)
RUNNER = RUNNER_PATH.read_bytes()
NODE_SHA256 = "a" * 64


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def prerequisites():
    prior = step222.prerequisites()
    prior_document = json.dumps(step222.values(prior), separators=(",", ":")).encode()
    prior_receipt = step222.load(step222.values(prior), prior)
    return {
        **prior,
        "harness_readiness_document": prior_document,
        "approved_harness_readiness_document_sha256": (
            prior_receipt.harness_readiness_document_sha256
        ),
    }


def values(prior=None, node_sha256=NODE_SHA256):
    prior = prior or prerequisites()
    return {
        "document_type": DOCUMENT_TYPE,
        "schema_version": 1,
        "source": SOURCE,
        "approved_harness_readiness_document_sha256": prior[
            "approved_harness_readiness_document_sha256"
        ],
        "expected_node_version": NODE_VERSION,
        "approved_node_executable_sha256": node_sha256,
        "execution_profile": PROFILE,
    }


def artifact_evidence():
    return EntraCallingClientMSALCompiledRetryArtifactEvidence(
        browser_tarball_sha256=module.BROWSER_TARBALL_SHA256,
        browser_tarball_bytes=module.BROWSER_TARBALL_BYTES,
        browser_archive_member_count=module.BROWSER_ARCHIVE_MEMBER_COUNT,
        browser_archive_uncompressed_bytes=module.BROWSER_ARCHIVE_UNCOMPRESSED_BYTES,
        browser_package_json_sha256=module.BROWSER_PACKAGE_JSON_SHA256,
        common_tarball_sha256=module.COMMON_TARBALL_SHA256,
        common_tarball_bytes=module.COMMON_TARBALL_BYTES,
        common_archive_member_count=module.COMMON_ARCHIVE_MEMBER_COUNT,
        common_archive_uncompressed_bytes=module.COMMON_ARCHIVE_UNCOMPRESSED_BYTES,
        common_package_json_sha256=module.COMMON_PACKAGE_JSON_SHA256,
        compiled_retry_entry_sha256=module.COMPILED_RETRY_ENTRY_SHA256,
        compiled_retry_entry_bytes=module.COMPILED_RETRY_ENTRY_BYTES,
        browser_metadata_response_sha256="b" * 64,
        common_metadata_response_sha256="c" * 64,
    )


def harness_record():
    telemetry = [
        {
            "value": {"fetchRetryCount": 1},
            "correlationId": "00000000-0000-4000-8000-000000000222",
        }
    ]

    def standard(name, attempts, elapsed, status, error, retry_telemetry):
        return {
            "name": name,
            "attemptCount": attempts,
            "elapsedBetweenAttemptsMilliseconds": elapsed,
            "requestEquivalent": True,
            "status": status,
            "errorName": error,
            "telemetry": telemetry if retry_telemetry else [],
        }

    scenarios = [
        standard("transport_failure_then_success", 2, 100, 200, None, True),
        standard("two_transport_failures", 2, 100, None, "NetworkError", True),
        standard("http_400_no_retry", 1, None, 400, None, False),
        standard("http_429_no_retry", 1, None, 429, None, False),
        standard("http_500_no_retry", 1, None, 500, None, False),
        standard("oauth_error_no_retry", 1, None, 400, None, False),
        standard("abort_no_retry", 1, None, None, "NetworkError", False),
        standard("non_token_transport_failure", 2, 100, 200, None, True),
        {
            "name": "concurrent_isolation",
            "attemptCount": 4,
            "perRequestAttempts": [2, 2],
            "elapsedMilliseconds": 100,
            "statuses": [200, 200],
        },
        {
            "name": "telemetry_and_request_equivalence",
            "attemptCount": 2,
            "requestEquivalent": True,
            "telemetry": telemetry,
        },
    ]
    return {"schemaVersion": 1, "scenarioCount": 10, "scenarios": scenarios}


def stdout_bytes(record=None):
    runner = {
        "runnerSchemaVersion": 1,
        "nodeVersion": NODE_VERSION,
        "harnessSha256": module.HARNESS_SHA256,
        "permissions": {
            "network": False,
            "childProcess": False,
            "worker": False,
            "fileSystemWrite": False,
            "addons": False,
            "wasi": False,
            "inspector": False,
            "ffi": False,
        },
    }
    return canonical(runner) + b"\n" + canonical(record or harness_record()) + b"\n"


def execution_evidence(stdout=None, node_sha256=NODE_SHA256):
    return EntraCallingClientMSALCompiledRetryExecutionEvidence(
        node_version=NODE_VERSION,
        node_executable_sha256=node_sha256,
        stdout=stdout or stdout_bytes(),
        stderr=b"",
        exit_code=0,
    )


def load(value=None, prior=None, *, artifact_transport=None, execution_transport=None):
    prior = prior or prerequisites()
    body = values(prior) if value is None else value
    artifact_transport = artifact_transport or artifact_evidence
    execution_transport = execution_transport or (
        lambda _artifacts, _harness, _runner: execution_evidence()
    )
    return load_entra_calling_client_msal_compiled_retry_execution_proof(
        document=json.dumps(body, separators=(",", ":")).encode(),
        harness=step222.HARNESS,
        runner=RUNNER,
        artifact_transport=artifact_transport,
        execution_transport=execution_transport,
        **prior,
    )


def unsafe_replace(receipt, **changes):
    clone = object.__new__(type(receipt))
    for field in fields(receipt):
        object.__setattr__(
            clone,
            field.name,
            changes.get(field.name, getattr(receipt, field.name)),
        )
    return clone


def exception_material(error):
    material = []
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        material.extend((repr(current), *(repr(item) for item in current.args)))
        pending.extend(
            item
            for item in (current.__context__, current.__cause__)
            if isinstance(item, BaseException)
        )
        pending.extend(getattr(current, "exceptions", ()))
        traceback = current.__traceback__
        while traceback:
            if traceback.tb_frame.f_globals.get("__name__") == module.__name__:
                material.extend(
                    repr(item) for item in traceback.tb_frame.f_locals.values()
                )
            traceback = traceback.tb_next
    return "\n".join(material)


def test_valid_synthetic_receipt_is_exact_and_fail_closed():
    receipt = load()
    assert receipt.receipt_type == RECEIPT_TYPE
    assert receipt.proof_status == STATUS
    assert receipt.synthetic_evidence_used is True
    assert receipt.live_proof_complete is False
    assert receipt.sealed_registry_request_count == 0
    assert receipt.sealed_node_process_count == 0
    assert all(getattr(receipt, name) is True for name in module._TRUE_FIELDS)
    assert all(getattr(receipt, name) is False for name in module._FALSE_FIELDS)
    assert all(getattr(receipt, name) is False for name in module._LIVE_FIELDS)
    assert receipt.conditional_exception_approved is False
    assert receipt.step216_zero_retry_superseded is False
    assert receipt.candidate_compatible is False
    assert receipt.candidate_selected is False


def test_runner_and_harness_bytes_are_exactly_bound():
    receipt = load()
    assert RUNNER_PATH.name == RUNNER_FILE_NAME
    assert len(RUNNER) == RUNNER_BYTES
    assert hashlib.sha256(RUNNER).hexdigest() == RUNNER_SHA256
    assert receipt.runner_sha256 == RUNNER_SHA256
    assert len(step222.HARNESS) == module.HARNESS_BYTES
    assert hashlib.sha256(step222.HARNESS).hexdigest() == module.HARNESS_SHA256


def test_transports_receive_only_exact_synthetic_evidence():
    calls = []
    artifacts = artifact_evidence()

    def artifact_transport():
        calls.append("artifact")
        return artifacts

    def execution_transport(actual, harness, runner):
        calls.append("execution")
        assert actual is artifacts
        assert harness == step222.HARNESS
        assert runner == RUNNER
        return execution_evidence()

    load(artifact_transport=artifact_transport, execution_transport=execution_transport)
    assert calls == ["artifact", "execution"]


def test_step222_is_rerun_before_document_or_transport(monkeypatch):
    calls = []

    def fail(**_kwargs):
        calls.append("step222")
        raise ValueError("prior-secret")

    monkeypatch.setattr(
        module,
        "load_entra_calling_client_msal_compiled_retry_harness_readiness",
        fail,
    )
    with pytest.raises(EntraCallingClientMSALCompiledRetryExecutionProbeError):
        load_entra_calling_client_msal_compiled_retry_execution_proof(
            document=b"not-json",
            harness=step222.HARNESS,
            runner=RUNNER,
            artifact_transport=lambda: calls.append("artifact"),
            execution_transport=lambda *_args: calls.append("execution"),
            **prerequisites(),
        )
    assert calls == ["step222"]


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("document_type", "wrong"),
        ("schema_version", True),
        ("source", "wrong"),
        ("approved_harness_readiness_document_sha256", "0" * 64),
        ("expected_node_version", "v0.0.0"),
        ("approved_node_executable_sha256", "A" * 64),
        ("execution_profile", "wrong"),
    ],
)
def test_document_literals_and_digests_are_exact(field, invalid):
    prior = prerequisites()
    value = values(prior)
    value[field] = invalid
    with pytest.raises(EntraCallingClientMSALCompiledRetryExecutionProbeError):
        load(value, prior)


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not-json",
        b'{"document_type":"x","document_type":"y"}',
        b'{"x":1e999}',
        b"[]",
        b"{}",
    ],
)
def test_malformed_duplicate_and_nonfinite_documents_fail_closed(body):
    with pytest.raises(EntraCallingClientMSALCompiledRetryExecutionProbeError):
        load_entra_calling_client_msal_compiled_retry_execution_proof(
            document=body,
            harness=step222.HARNESS,
            runner=RUNNER,
            artifact_transport=artifact_evidence,
            execution_transport=lambda *_args: execution_evidence(),
            **prerequisites(),
        )


def test_extra_and_missing_document_keys_fail_closed():
    prior = prerequisites()
    extra = values(prior) | {"extra": True}
    missing = values(prior)
    missing.pop("execution_profile")
    for value in (extra, missing):
        with pytest.raises(EntraCallingClientMSALCompiledRetryExecutionProbeError):
            load(value, prior)


@pytest.mark.parametrize(
    "changes",
    [
        {"document": "not-bytes"},
        {"harness": "not-bytes"},
        {"runner": "not-bytes"},
        {"artifact_transport": object()},
        {"execution_transport": object()},
    ],
)
def test_public_misuse_is_a_sanitized_type_error(changes):
    prior = prerequisites()
    arguments = {
        "document": json.dumps(values(prior), separators=(",", ":")).encode(),
        "harness": step222.HARNESS,
        "runner": RUNNER,
        "artifact_transport": artifact_evidence,
        "execution_transport": lambda *_args: execution_evidence(),
        **prior,
        **changes,
    }
    with pytest.raises(TypeError) as caught:
        load_entra_calling_client_msal_compiled_retry_execution_proof(**arguments)
    assert caught.value.__context__ is None


def test_partial_injection_and_synthetic_node_path_fail_before_side_effects():
    prior = prerequisites()
    base = {
        "document": json.dumps(values(prior), separators=(",", ":")).encode(),
        "harness": step222.HARNESS,
        "runner": RUNNER,
        **prior,
    }
    for additions in (
        {"artifact_transport": artifact_evidence},
        {"execution_transport": lambda *_args: execution_evidence()},
        {
            "artifact_transport": artifact_evidence,
            "execution_transport": lambda *_args: execution_evidence(),
            "node_executable_path": "/forbidden",
        },
    ):
        with pytest.raises(TypeError):
            load_entra_calling_client_msal_compiled_retry_execution_proof(
                **base, **additions
            )


def test_node_path_is_prevalidated_before_registry_transport(monkeypatch):
    prior = prerequisites()
    calls = []

    class Loader:
        def load(self, _plan):
            calls.append("registry")
            raise AssertionError

    monkeypatch.setattr(
        module,
        "BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader",
        Loader,
    )
    with pytest.raises(EntraCallingClientMSALCompiledRetryExecutionProbeError):
        load_entra_calling_client_msal_compiled_retry_execution_proof(
            document=json.dumps(values(prior), separators=(",", ":")).encode(),
            harness=step222.HARNESS,
            runner=RUNNER,
            node_executable_path="/definitely/missing/node",
            **prior,
        )
    assert calls == []


def test_node_executable_validation_is_bounded_canonical_and_hash_bound(
    tmp_path, monkeypatch
):
    node = tmp_path / ("node.exe" if os.name == "nt" else "node")
    node.write_bytes(b"node-fixture")
    node.chmod(0o700)
    digest = hashlib.sha256(node.read_bytes()).hexdigest()
    assert module._validate_node_executable(str(node), digest) == str(node)
    with pytest.raises(ValueError):
        module._validate_node_executable(str(node), "0" * 64)
    link = tmp_path / "node-link"
    create_or_emulate_file_symlink(
        link=link, target=node, monkeypatch=monkeypatch, module_os=module.os
    )
    with pytest.raises((TypeError, ValueError)):
        module._validate_node_executable(str(link), digest)


@pytest.mark.parametrize(
    ("scenario", "field", "invalid"),
    [
        ("transport_failure_then_success", "attemptCount", 1),
        ("transport_failure_then_success", "elapsedBetweenAttemptsMilliseconds", 89),
        ("two_transport_failures", "errorName", "TypeError"),
        ("http_400_no_retry", "requestEquivalent", False),
        ("http_429_no_retry", "telemetry", [{}]),
        ("abort_no_retry", "status", 200),
        ("non_token_transport_failure", "attemptCount", 1),
        ("concurrent_isolation", "perRequestAttempts", [1, 3]),
        ("concurrent_isolation", "elapsedMilliseconds", 89),
        ("telemetry_and_request_equivalence", "requestEquivalent", False),
    ],
)
def test_every_execution_behavior_boundary_is_fail_closed(scenario, field, invalid):
    record = harness_record()
    selected = next(item for item in record["scenarios"] if item["name"] == scenario)
    selected[field] = invalid

    def execute(_artifacts, _harness, _runner):
        return execution_evidence(stdout_bytes(record))

    with pytest.raises(EntraCallingClientMSALCompiledRetryExecutionProbeError):
        load(execution_transport=execute)


def test_scenario_schema_rejects_extra_missing_duplicate_and_permission_changes():
    changes = []
    extra = harness_record()
    extra["scenarios"][0]["extra"] = True
    changes.append(stdout_bytes(extra))
    missing = harness_record()
    missing["scenarios"].pop()
    missing["scenarioCount"] = 9
    changes.append(stdout_bytes(missing))
    duplicate = harness_record()
    duplicate["scenarios"][1]["name"] = duplicate["scenarios"][0]["name"]
    changes.append(stdout_bytes(duplicate))
    lines = stdout_bytes().splitlines()
    runner = json.loads(lines[0])
    runner["permissions"]["network"] = True
    changes.append(canonical(runner) + b"\n" + lines[1] + b"\n")
    for stdout in changes:
        with pytest.raises(EntraCallingClientMSALCompiledRetryExecutionProbeError):
            load(
                execution_transport=lambda *_args, output=stdout: execution_evidence(
                    output
                )
            )


def test_receipt_fields_are_complete_disjoint_and_exactly_typed():
    receipt = load()
    field_names = {field.name for field in fields(receipt)}
    bool_fields = {
        field.name for field in fields(receipt) if field.type in (bool, "bool")
    }
    partitions = [
        set(module._TRUE_FIELDS),
        set(module._FALSE_FIELDS),
        set(module._DYNAMIC_FIELDS),
    ]
    assert set.union(*partitions) == bool_fields
    assert all(
        left.isdisjoint(right)
        for index, left in enumerate(partitions)
        for right in partitions[index + 1 :]
    )
    assert len(field_names) == len(fields(receipt))
    for name in module._TRUE_FIELDS:
        with pytest.raises(ValueError):
            unsafe_replace(receipt, **{name: False}).__post_init__()
    for name in module._FALSE_FIELDS:
        with pytest.raises(ValueError):
            unsafe_replace(receipt, **{name: True}).__post_init__()
    for name in module._COUNT_FIELDS:
        with pytest.raises(ValueError):
            unsafe_replace(receipt, **{name: True}).__post_init__()


def test_live_receipt_partition_is_constructible_and_correlated():
    receipt = load()
    changes = {
        "synthetic_evidence_used": False,
        "sealed_registry_request_count": 4,
        "sealed_node_process_count": 1,
        **{name: True for name in module._LIVE_FIELDS},
    }
    live = unsafe_replace(receipt, **changes)
    live.__post_init__()
    with pytest.raises(ValueError):
        unsafe_replace(live, sealed_registry_request_count=0).__post_init__()
    with pytest.raises(ValueError):
        unsafe_replace(live, live_retry_count_checked=False).__post_init__()


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("receipt_type", "wrong"),
        ("source", "wrong"),
        ("validation_scope", "wrong"),
        ("execution_profile", "wrong"),
        ("proof_status", "wrong"),
        ("node_version", "wrong"),
        ("browser_package_name", "wrong"),
        ("browser_version", "wrong"),
        ("common_package_name", "wrong"),
        ("common_version", "wrong"),
        ("registry_origin", "wrong"),
        ("compiled_scope_finding", "wrong"),
        ("browser_tarball_sha256", "0" * 64),
        ("common_tarball_sha256", "0" * 64),
        ("compiled_retry_entry_sha256", "0" * 64),
        ("harness_sha256", "0" * 64),
        ("runner_sha256", "0" * 64),
    ],
)
def test_receipt_public_constants_and_frozen_hashes_are_exact(field, invalid):
    with pytest.raises(ValueError):
        unsafe_replace(load(), **{field: invalid}).__post_init__()


def test_renderer_is_canonical_and_revalidates_receipt():
    receipt = load()
    rendered = render_entra_calling_client_msal_compiled_retry_execution_proof_receipt(
        receipt
    )
    assert rendered.encode() == canonical(json.loads(rendered))
    with pytest.raises(TypeError):
        render_entra_calling_client_msal_compiled_retry_execution_proof_receipt(
            object()
        )
    with pytest.raises(ValueError):
        render_entra_calling_client_msal_compiled_retry_execution_proof_receipt(
            unsafe_replace(receipt, candidate_selected=True)
        )


@pytest.mark.parametrize("control", [KeyboardInterrupt, SystemExit])
def test_nested_control_flow_is_sanitized_and_preserved(control):
    secret = "execution-control-secret"

    def fail():
        raise BaseExceptionGroup("secret-group", [control(secret)])

    with pytest.raises(control) as caught:
        load(artifact_transport=fail)
    assert secret not in exception_material(caught.value)


def test_generic_exception_graph_is_detached_and_secret_free():
    secret = "execution-generic-secret"

    def fail():
        raise BaseExceptionGroup("secret-group", [ValueError(secret)])

    with pytest.raises(
        EntraCallingClientMSALCompiledRetryExecutionProbeError
    ) as caught:
        load(artifact_transport=fail)
    assert secret not in exception_material(caught.value)


def test_runner_uses_one_permission_restricted_process_and_no_network_grant():
    source = RUNNER.decode()
    assert 'process.permission.has("net")' in source
    assert 'process.permission.has("child")' in source
    assert 'process.permission.has("worker")' in source
    assert 'process.permission.has("fs.write")' in source
    assert 'process.permission.has("addons")' in source
    assert 'process.permission.has("wasi")' in source
    assert 'process.permission.has("inspector")' in source
    assert 'process.permission.has("ffi")' in source
    assert "node:http" not in source
    assert "node:https" not in source
    assert "child_process" not in source


def test_module_has_safe_imports_unique_fields_and_no_configuration_writes():
    source = inspect.getsource(module)
    tree = ast.parse(source)
    receipt = module.EntraCallingClientMSALCompiledRetryExecutionProofReceipt
    assert len(receipt.__dataclass_fields__) == len(set(receipt.__dataclass_fields__))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "requests" not in imported
    assert "httpx" not in imported
    assert "socket" not in imported
    assert "browser_oauth_provider_io_performed" in source
    assert "conditional_exception_approved" in source
    assert "candidate_selected" in source
    assert "--allow-net" not in source
    assert "--allow-child-process" not in source
    assert "npm install" not in source
    assert "configuration_mutation" not in source


def test_public_exports_are_exact_and_unique():
    assert len(module.__all__) == len(set(module.__all__))
    assert set(module.__all__) == {
        "DOCUMENT_TYPE",
        "NODE_VERSION",
        "PROFILE",
        "RECEIPT_TYPE",
        "RUNNER_BYTES",
        "RUNNER_FILE_NAME",
        "RUNNER_SHA256",
        "SOURCE",
        "STATUS",
        "EntraCallingClientMSALCompiledRetryArtifactEvidence",
        "EntraCallingClientMSALCompiledRetryArtifactTransport",
        "EntraCallingClientMSALCompiledRetryExecutionDocument",
        "EntraCallingClientMSALCompiledRetryExecutionEvidence",
        "EntraCallingClientMSALCompiledRetryExecutionProbeError",
        "EntraCallingClientMSALCompiledRetryExecutionProofReceipt",
        "EntraCallingClientMSALCompiledRetryExecutionTransport",
        "load_entra_calling_client_msal_compiled_retry_execution_proof",
        "render_entra_calling_client_msal_compiled_retry_execution_proof_receipt",
    }
