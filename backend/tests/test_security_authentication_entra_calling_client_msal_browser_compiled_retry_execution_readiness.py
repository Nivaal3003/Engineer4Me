"""Tests for offline MSAL compiled retry execution readiness."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from builtins import BaseExceptionGroup
from dataclasses import fields
from pathlib import Path

import pytest

import app.security.authentication_entra_calling_client_msal_browser_compiled_retry_execution_readiness as module
from app.security.authentication_entra_calling_client_msal_browser_compiled_retry_execution_readiness import (
    BEHAVIOR_SCENARIO_COUNT,
    BROWSER_ARCHIVE_MEMBER_COUNT,
    BROWSER_PACKAGE_NAME,
    BROWSER_TARBALL_SHA256,
    BROWSER_VERSION,
    COMMON_ARCHIVE_MEMBER_COUNT,
    COMMON_PACKAGE_NAME,
    COMMON_TARBALL_SHA256,
    COMMON_VERSION,
    COMPILED_RETRY_ENTRY_PATH,
    COMPILED_RETRY_ENTRY_SHA256,
    DOCUMENT_TYPE,
    EXECUTION_PROFILE,
    READINESS_STATUS,
    RECEIPT_TYPE,
    SOURCE,
    VALIDATION_SCOPE,
    EntraCallingClientMSALCompiledRetryExecutionReadinessError,
    load_entra_calling_client_msal_compiled_retry_execution_readiness,
    render_entra_calling_client_msal_compiled_retry_execution_readiness_receipt,
)
from app.security.authentication_entra_calling_client_msal_browser_current_version_readiness import (
    load_entra_calling_client_msal_current_version_readiness,
)
from tests import (
    test_security_authentication_entra_calling_client_msal_browser_current_version_readiness as step220,
)


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def prerequisites(
    redirect_uris=(step220.step218.step217.step216.step214.REDIRECT_URI,),
):
    prior = step220.prerequisites(redirect_uris)
    current_document = json.dumps(step220.values(prior), separators=(",", ":")).encode()
    receipt = load_entra_calling_client_msal_current_version_readiness(
        document=current_document,
        **prior,
    )
    return {
        **prior,
        "current_version_readiness_document": current_document,
        "approved_current_version_readiness_document_sha256": (
            receipt.current_version_readiness_document_sha256
        ),
    }


def values(prior=None):
    prior = prior or prerequisites()
    return {
        "document_type": DOCUMENT_TYPE,
        "schema_version": 1,
        "source": SOURCE,
        "approved_current_version_readiness_document_sha256": prior[
            "approved_current_version_readiness_document_sha256"
        ],
        "execution_profile": EXECUTION_PROFILE,
    }


def load(value=None, prior=None):
    prior = prior or prerequisites()
    body = values(prior) if value is None else value
    return load_entra_calling_client_msal_compiled_retry_execution_readiness(
        document=json.dumps(body, separators=(",", ":")).encode(),
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


def framed(label, value):
    digest = hashlib.sha256()
    for part in ("engineer4me-step221-v1", label, canonical(value)):
        encoded = part if isinstance(part, bytes) else part.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def exception_material(error):
    material = []
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        material.extend((repr(current), *(repr(x) for x in current.args)))
        pending.extend(
            x
            for x in (current.__context__, current.__cause__)
            if isinstance(x, BaseException)
        )
        pending.extend(getattr(current, "exceptions", ()))
        traceback = current.__traceback__
        while traceback:
            if traceback.tb_frame.f_globals.get("__name__") == module.__name__:
                material.extend(repr(x) for x in traceback.tb_frame.f_locals.values())
            traceback = traceback.tb_next
    return "\n".join(material)


def test_valid_receipt_is_exact_and_fully_fail_closed():
    receipt = load()
    assert receipt.receipt_type == RECEIPT_TYPE
    assert receipt.validation_scope == VALIDATION_SCOPE
    assert receipt.readiness_status == READINESS_STATUS
    assert receipt.artifact_count == 2
    assert receipt.behavior_scenario_count == BEHAVIOR_SCENARIO_COUNT == 10
    assert all(getattr(receipt, name) is True for name in module._TRUE_FIELDS)
    assert all(getattr(receipt, name) is False for name in module._FALSE_FIELDS)


def test_exact_reviewed_artifact_constants_are_bound():
    receipt = load()
    assert (receipt.browser_package_name, receipt.browser_version) == (
        BROWSER_PACKAGE_NAME,
        BROWSER_VERSION,
    )
    assert (receipt.common_package_name, receipt.common_version) == (
        COMMON_PACKAGE_NAME,
        COMMON_VERSION,
    )
    assert receipt.browser_tarball_sha256 == BROWSER_TARBALL_SHA256
    assert receipt.common_tarball_sha256 == COMMON_TARBALL_SHA256
    assert receipt.browser_archive_member_count == BROWSER_ARCHIVE_MEMBER_COUNT
    assert receipt.common_archive_member_count == COMMON_ARCHIVE_MEMBER_COUNT
    assert receipt.compiled_retry_entry_path == COMPILED_RETRY_ENTRY_PATH
    assert receipt.compiled_retry_entry_sha256 == COMPILED_RETRY_ENTRY_SHA256


def test_dual_artifact_profile_hash_is_independently_recomputed():
    receipt = load()
    artifacts = [
        {
            "name": module.BROWSER_PACKAGE_NAME,
            "version": module.BROWSER_VERSION,
            "tarball": module.BROWSER_TARBALL_URL,
            "sri": module.BROWSER_SRI,
            "shasum": module.BROWSER_SHASUM,
            "sha256": module.BROWSER_TARBALL_SHA256,
            "bytes": module.BROWSER_TARBALL_BYTES,
            "members": module.BROWSER_ARCHIVE_MEMBER_COUNT,
            "uncompressedBytes": module.BROWSER_ARCHIVE_UNCOMPRESSED_BYTES,
            "packageJsonSha256": module.BROWSER_PACKAGE_JSON_SHA256,
        },
        {
            "name": module.COMMON_PACKAGE_NAME,
            "version": module.COMMON_VERSION,
            "tarball": module.COMMON_TARBALL_URL,
            "sri": module.COMMON_SRI,
            "shasum": module.COMMON_SHASUM,
            "sha256": module.COMMON_TARBALL_SHA256,
            "bytes": module.COMMON_TARBALL_BYTES,
            "members": module.COMMON_ARCHIVE_MEMBER_COUNT,
            "uncompressedBytes": module.COMMON_ARCHIVE_UNCOMPRESSED_BYTES,
            "packageJsonSha256": module.COMMON_PACKAGE_JSON_SHA256,
        },
    ]
    assert receipt.reviewed_dual_artifact_profile_sha256 == framed(
        "artifacts", artifacts
    )


def test_execution_and_behavior_hashes_are_independently_recomputed():
    receipt = load()
    execution = {
        "entry": module.COMPILED_RETRY_ENTRY_PATH,
        "entrySha256": module.COMPILED_RETRY_ENTRY_SHA256,
        "entryBytes": module.COMPILED_RETRY_ENTRY_BYTES,
        "nodeIdentity": "exact_and_receipt_bound",
        "workspace": "ephemeral_bounded",
        "network": "disabled_before_import",
        "processes": 1,
        "fetch": "controlled_fake_only",
        "realOAuthInputs": False,
    }
    scenarios = [
        "transport_failure_then_success",
        "two_transport_failures",
        "http_400_no_retry",
        "http_429_no_retry",
        "http_500_no_retry",
        "oauth_error_no_retry",
        "abort_no_retry",
        "non_token_request_no_retry",
        "concurrent_isolation",
        "telemetry_and_request_equivalence",
    ]
    assert receipt.compiled_execution_profile_sha256 == framed("execution", execution)
    assert receipt.compiled_behavior_matrix_sha256 == framed("scenarios", scenarios)


def test_selection_hash_preserves_step216_and_rejects_approval():
    receipt = load()
    state = {
        "step216ZeroRetrySuperseded": False,
        "exceptionApproved": False,
        "compatible": False,
        "selected": False,
    }
    assert receipt.fail_closed_selection_state_sha256 == framed("selection", state)
    assert receipt.step216_zero_retry_superseded is False
    assert receipt.conditional_exception_approved is False
    assert receipt.current_candidate_selected is False


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("document_type", "wrong"),
        ("schema_version", True),
        ("source", "wrong"),
        (
            "approved_current_version_readiness_document_sha256",
            "0" * 64,
        ),
        ("execution_profile", "wrong"),
    ],
)
def test_document_literals_and_approved_digest_are_exact(field, invalid):
    prior = prerequisites()
    value = values(prior)
    value[field] = invalid
    with pytest.raises(EntraCallingClientMSALCompiledRetryExecutionReadinessError):
        load(value, prior)


def test_document_rejects_extra_missing_duplicate_and_malformed_json():
    prior = prerequisites()
    value = values(prior)
    for body in (
        {**value, "extra": True},
        {key: item for key, item in value.items() if key != "source"},
    ):
        with pytest.raises(EntraCallingClientMSALCompiledRetryExecutionReadinessError):
            load(body, prior)
    duplicate = (
        b'{"document_type":"'
        + DOCUMENT_TYPE.encode()
        + b'","document_type":"'
        + DOCUMENT_TYPE.encode()
        + b'","schema_version":1,"source":"'
        + SOURCE.encode()
        + b'","approved_current_version_readiness_document_sha256":"'
        + prior["approved_current_version_readiness_document_sha256"].encode()
        + b'","execution_profile":"'
        + EXECUTION_PROFILE.encode()
        + b'"}'
    )
    with pytest.raises(EntraCallingClientMSALCompiledRetryExecutionReadinessError):
        load_entra_calling_client_msal_compiled_retry_execution_readiness(
            document=duplicate,
            **prior,
        )
    for malformed in (b"", b"{", b"\xff", b"[]", b"NaN"):
        with pytest.raises(
            (
                TypeError,
                EntraCallingClientMSALCompiledRetryExecutionReadinessError,
            )
        ):
            load_entra_calling_client_msal_compiled_retry_execution_readiness(
                document=malformed,
                **prior,
            )


@pytest.mark.parametrize("invalid", [None, "x", bytearray(b"x"), memoryview(b"x")])
def test_public_documents_require_exact_bytes(invalid):
    prior = prerequisites()
    with pytest.raises(TypeError):
        load_entra_calling_client_msal_compiled_retry_execution_readiness(
            document=invalid,
            **prior,
        )


def test_step220_rerun_precedes_step221_document_parse(monkeypatch):
    prior = prerequisites()
    called = []

    def fail(**arguments):
        del arguments
        called.append(True)
        raise ValueError("step220-secret")

    monkeypatch.setattr(
        module, "load_entra_calling_client_msal_current_version_readiness", fail
    )
    with pytest.raises(EntraCallingClientMSALCompiledRetryExecutionReadinessError):
        load_entra_calling_client_msal_compiled_retry_execution_readiness(
            document=b"{",
            **prior,
        )
    assert called == [True]


def test_schema_valid_reblessed_step220_approval_is_rejected(monkeypatch):
    prior = prerequisites()
    original = module.load_entra_calling_client_msal_current_version_readiness

    def reblessed(**arguments):
        receipt = original(**arguments)
        clone = step220.unsafe_replace(
            receipt,
            conditional_exception_approved=True,
            current_candidate_selected=True,
        )
        return clone

    monkeypatch.setattr(
        module, "load_entra_calling_client_msal_current_version_readiness", reblessed
    )
    monkeypatch.setattr(
        module,
        "render_entra_calling_client_msal_current_version_readiness_receipt",
        lambda receipt: json.dumps(
            {field.name: getattr(receipt, field.name) for field in fields(receipt)},
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    with pytest.raises(EntraCallingClientMSALCompiledRetryExecutionReadinessError):
        load(prior=prior)


@pytest.mark.parametrize(
    "failure",
    [
        ValueError("secret-value"),
        KeyboardInterrupt("secret-interrupt"),
        SystemExit("secret-exit"),
        BaseExceptionGroup("secret-group", [ValueError("secret-child")]),
    ],
)
def test_nested_control_flow_and_exception_graph_are_sanitized(monkeypatch, failure):
    prior = prerequisites()

    def fail(**arguments):
        del arguments
        raise failure

    monkeypatch.setattr(
        module, "load_entra_calling_client_msal_current_version_readiness", fail
    )
    expected = (
        KeyboardInterrupt
        if isinstance(failure, KeyboardInterrupt)
        else SystemExit
        if isinstance(failure, SystemExit)
        else EntraCallingClientMSALCompiledRetryExecutionReadinessError
    )
    with pytest.raises(expected) as caught:
        load(prior=prior)
    material = exception_material(caught.value)
    assert "secret" not in material
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_every_boolean_is_partitioned_and_enforced():
    receipt = load()
    names = {
        field.name
        for field in fields(receipt)
        if type(getattr(receipt, field.name)) is bool
    }
    expected = {*module._TRUE_FIELDS, *module._FALSE_FIELDS}
    assert names == expected
    assert not set(module._TRUE_FIELDS) & set(module._FALSE_FIELDS)
    for name in names:
        with pytest.raises(ValueError):
            unsafe_replace(
                receipt, **{name: not getattr(receipt, name)}
            ).__post_init__()


@pytest.mark.parametrize("invalid", [True, 0.0, "1", None, [], {}])
def test_every_count_requires_exact_integer_type(invalid):
    receipt = load()
    for name in module._COUNT_FIELDS:
        with pytest.raises(ValueError):
            unsafe_replace(receipt, **{name: invalid}).__post_init__()


def test_every_string_and_digest_is_validated():
    receipt = load()
    for field in fields(receipt):
        if field.name in module._STRING_FIELDS or field.name.endswith("_sha256"):
            with pytest.raises(ValueError):
                unsafe_replace(receipt, **{field.name: "invalid"}).__post_init__()


def test_renderer_is_canonical_and_revalidates():
    receipt = load()
    rendered = (
        render_entra_calling_client_msal_compiled_retry_execution_readiness_receipt(
            receipt
        )
    )
    assert rendered == json.dumps(
        {field.name: getattr(receipt, field.name) for field in fields(receipt)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    with pytest.raises(ValueError):
        render_entra_calling_client_msal_compiled_retry_execution_readiness_receipt(
            unsafe_replace(receipt, activation_ready=True)
        )


def test_public_signature_has_no_artifact_or_process_injection():
    signature = inspect.signature(
        load_entra_calling_client_msal_compiled_retry_execution_readiness
    )
    assert tuple(signature.parameters) == ("arguments",)
    source = inspect.getsource(module._load_internal)
    assert "step219_receipt" not in source
    assert "subprocess" not in source


def test_source_ast_has_no_io_imports_and_receipt_fields_are_unique():
    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not imports & {
        "asyncio",
        "http",
        "os",
        "pathlib",
        "requests",
        "shutil",
        "socket",
        "ssl",
        "subprocess",
        "tarfile",
        "tempfile",
        "urllib",
    }
    receipt_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "EntraCallingClientMSALCompiledRetryExecutionReadinessReceipt"
    )
    declared = [
        node.target.id
        for node in receipt_class.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    ]
    assert len(declared) == len(set(declared))
