"""Tests for offline MSAL Browser current-version transition readiness."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from builtins import BaseExceptionGroup
from dataclasses import fields
from pathlib import Path

import pytest

import app.security.authentication_entra_calling_client_msal_browser_current_version_readiness as module
from app.security.authentication_entra_calling_client_msal_browser_current_version_readiness import (
    CURRENT_VERSION_ARTIFACT_COUNT,
    CURRENT_VERSION_BEHAVIOR_SCENARIO_COUNT,
    CURRENT_VERSION_RETRY_BACKOFF_MILLISECONDS,
    CURRENT_VERSION_TOKEN_POST_ATTEMPT_COUNT,
    CURRENT_VERSION_TOKEN_POST_RETRY_COUNT,
    ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_DOCUMENT_TYPE,
    ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_PROFILE,
    ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_RECEIPT_TYPE,
    ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SCOPE,
    ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SOURCE,
    ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_STATUS,
    MSAL_BROWSER_CURRENT_CANDIDATE_VERSION,
    MSAL_BROWSER_CURRENT_RELEASE_COMMIT,
    MSAL_BROWSER_CURRENT_RELEASE_DATE,
    MSAL_BROWSER_CURRENT_RELEASE_TAG,
    MSAL_BROWSER_PREVIOUS_REVIEWED_VERSION,
    MSAL_COMMON_CURRENT_DEPENDENCY_VERSION,
    EntraCallingClientMSALCurrentVersionReadinessError,
    load_entra_calling_client_msal_current_version_readiness,
    render_entra_calling_client_msal_current_version_readiness_receipt,
)
from app.security.authentication_entra_calling_client_msal_browser_retry_reconciliation_readiness import (
    load_entra_calling_client_msal_retry_reconciliation_readiness,
)
from tests import (
    test_security_authentication_entra_calling_client_msal_browser_retry_reconciliation_readiness as step218,
)


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def prerequisites(redirect_uris=(step218.step217.step216.step214.REDIRECT_URI,)):
    prior = step218.prerequisites(redirect_uris)
    retry_document = json.dumps(step218.values(prior), separators=(",", ":")).encode()
    receipt = load_entra_calling_client_msal_retry_reconciliation_readiness(
        document=retry_document,
        **prior,
    )
    return {
        **prior,
        "retry_reconciliation_document": retry_document,
        "approved_retry_reconciliation_document_sha256": (
            receipt.retry_reconciliation_document_sha256
        ),
    }


def values(prior=None):
    prior = prior or prerequisites()
    return {
        "document_type": ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_DOCUMENT_TYPE,
        "schema_version": 1,
        "source": ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SOURCE,
        "approved_retry_reconciliation_document_sha256": prior[
            "approved_retry_reconciliation_document_sha256"
        ],
        "transition_profile": ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_PROFILE,
    }


def load(value=None, prior=None):
    prior = prior or prerequisites()
    body = values(prior) if value is None else value
    return load_entra_calling_client_msal_current_version_readiness(
        document=json.dumps(body, separators=(",", ":")).encode(),
        **prior,
    )


def unsafe_replace(receipt, **changes):
    clone = object.__new__(type(receipt))
    for field in fields(receipt):
        object.__setattr__(
            clone, field.name, changes.get(field.name, getattr(receipt, field.name))
        )
    return clone


def framed(label, *values_value):
    digest = hashlib.sha256()
    for value in (
        "engineer4me-step220-v1",
        label,
        str(len(values_value)),
        *values_value,
    ):
        encoded = value if isinstance(value, bytes) else value.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def production_exception_material(error):
    material = []
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        material.extend((repr(current), *(repr(value) for value in current.args)))
        pending.extend(
            linked
            for linked in (current.__context__, current.__cause__)
            if isinstance(linked, BaseException)
        )
        pending.extend(getattr(current, "exceptions", ()))
        traceback = current.__traceback__
        while traceback is not None:
            if traceback.tb_frame.f_globals.get("__name__") == module.__name__:
                material.extend(
                    repr(value) for value in traceback.tb_frame.f_locals.values()
                )
            traceback = traceback.tb_next
    return "\n".join(material)


def test_valid_readiness_is_current_but_fully_fail_closed():
    receipt = load()
    assert (
        receipt.receipt_type == ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_RECEIPT_TYPE
    )
    assert receipt.validation_scope == ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_SCOPE
    assert receipt.readiness_status == ENTRA_CALLING_CLIENT_MSAL_CURRENT_VERSION_STATUS
    assert receipt.previous_reviewed_browser_version == "5.17.3"
    assert receipt.current_candidate_browser_version == "5.18.0"
    assert receipt.current_common_dependency_version == "16.12.0"
    assert receipt.artifact_count == 2
    assert receipt.behavior_scenario_count == 10
    assert all(
        getattr(receipt, name) is True for name in module._STRUCTURAL_TRUE_FIELDS
    )
    assert all(
        getattr(receipt, name) is False for name in module._DEFERRED_FALSE_FIELDS
    )
    assert receipt.registry_metadata_checked is False
    assert receipt.compiled_retry_path_inspected is False
    assert receipt.conditional_exception_approved is False
    assert receipt.step216_zero_retry_superseded is False
    assert receipt.current_candidate_selected is False
    assert receipt.activation_ready is False


def test_public_current_release_constants_are_exact():
    assert MSAL_BROWSER_PREVIOUS_REVIEWED_VERSION == "5.17.3"
    assert MSAL_BROWSER_CURRENT_CANDIDATE_VERSION == "5.18.0"
    assert MSAL_COMMON_CURRENT_DEPENDENCY_VERSION == "16.12.0"
    assert MSAL_BROWSER_CURRENT_RELEASE_TAG == "msal-browser-v5.18.0"
    assert MSAL_BROWSER_CURRENT_RELEASE_DATE == "2026-08-04"
    assert MSAL_BROWSER_CURRENT_RELEASE_COMMIT == "5c53ac6"
    assert CURRENT_VERSION_ARTIFACT_COUNT == 2
    assert CURRENT_VERSION_BEHAVIOR_SCENARIO_COUNT == 10
    assert CURRENT_VERSION_TOKEN_POST_RETRY_COUNT == 1
    assert CURRENT_VERSION_TOKEN_POST_ATTEMPT_COUNT == 2
    assert CURRENT_VERSION_RETRY_BACKOFF_MILLISECONDS == 100


def test_two_artifact_plan_is_independently_bound():
    receipt = load()
    expected = {
        "packages": [
            ["@azure/msal-browser", "5.18.0"],
            ["@azure/msal-common", "16.12.0"],
        ],
        "registry": "https://registry.npmjs.org",
        "proof": [
            "exact_version_metadata",
            "sha512_sri",
            "tarball_sha256_sha512",
            "safe_archive",
            "package_json_identity",
            "exact_dependency_edge",
            "compiled_entrypoint_closure",
        ],
    }
    assert receipt.two_artifact_proof_plan_sha256 == framed(
        "two_artifact_proof_plan", canonical(expected)
    )


def test_isolated_runtime_profile_is_independently_bound():
    receipt = load()
    expected = {
        "node": "exact_supported_binary_identity_required",
        "networkAfterAcquisition": "disabled",
        "filesystem": "ephemeral_bounded_workspace_only",
        "lifecycleScripts": "forbidden",
        "harnessChildProcesses": "forbidden",
        "transport": "controlled_fake_token_transport",
        "realOAuthInputs": "forbidden",
    }
    assert receipt.isolated_runtime_profile_sha256 == framed(
        "isolated_runtime_profile", canonical(expected)
    )


def test_all_ten_compiled_behavior_scenarios_are_exact():
    receipt = load()
    expected = [
        "transport_failure_then_success_one_retry_after_100ms",
        "two_transport_failures_two_attempts_then_failure",
        "http_400_response_no_retry",
        "http_429_response_no_retry",
        "http_500_response_no_retry",
        "oauth_error_response_no_retry",
        "abort_or_cancellation_no_retry",
        "non_token_request_no_retry",
        "concurrent_calls_no_cross_talk_or_parallel_retry",
        "retry_telemetry_and_request_equivalence_exact",
    ]
    assert receipt.compiled_behavior_scenario_plan_sha256 == framed(
        "compiled_behavior_scenarios", canonical(expected)
    )


def test_selection_state_preserves_step216_and_refuses_approval():
    receipt = load()
    expected = {
        "candidate": "5.18.0",
        "artifactProofComplete": False,
        "compiledBehaviorProofComplete": False,
        "conditionalExceptionApproved": False,
        "step216ZeroRetrySuperseded": False,
        "selected": False,
    }
    assert receipt.current_candidate_selection_state_sha256 == framed(
        "current_candidate_selection", canonical(expected)
    )


def test_three_redirects_remain_private_and_only_change_count():
    prior = prerequisites(
        (
            "https://app.engineer4me.invalid/auth/callback",
            "https://app.engineer4me.invalid/auth/complete",
            "https://app.engineer4me.invalid/auth/return",
        )
    )
    receipt = load(prior=prior)
    rendered = render_entra_calling_client_msal_current_version_readiness_receipt(
        receipt
    )
    assert receipt.desired_redirect_endpoint_count == 3
    for secret in ("/auth/callback", "/auth/complete", "/auth/return"):
        assert secret not in rendered


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("document_type", "other"),
        ("schema_version", True),
        ("schema_version", 2),
        ("source", "other"),
        ("transition_profile", "other"),
        ("approved_retry_reconciliation_document_sha256", "0" * 64),
    ],
)
def test_document_literals_and_digest_are_exact(field, invalid):
    prior = prerequisites()
    value = values(prior)
    value[field] = invalid
    with pytest.raises(EntraCallingClientMSALCurrentVersionReadinessError):
        load(value, prior)


def test_document_rejects_extra_missing_duplicate_and_malformed_json():
    prior = prerequisites()
    valid = values(prior)
    for value in (
        {**valid, "extra": True},
        {key: item for key, item in valid.items() if key != "source"},
    ):
        with pytest.raises(EntraCallingClientMSALCurrentVersionReadinessError):
            load(value, prior)
    duplicate = (
        b'{"document_type":"x","document_type":"y","schema_version":1,'
        b'"source":"x","approved_retry_reconciliation_document_sha256":"'
        + b"0" * 64
        + b'","transition_profile":"x"}'
    )
    with pytest.raises(EntraCallingClientMSALCurrentVersionReadinessError):
        load_entra_calling_client_msal_current_version_readiness(
            document=duplicate,
            **prior,
        )


@pytest.mark.parametrize(
    "argument",
    [
        "document",
        "retry_reconciliation_document",
        "msal_browser_control_document",
        "pkce_runtime_control_document",
        "redirect_endpoint_control_document",
        "api_registration_document",
        "calling_client_registration_document",
        "inventory_document",
    ],
)
def test_document_arguments_require_exact_bytes(argument):
    prior = prerequisites()
    arguments = {
        "document": canonical(values(prior)),
        **prior,
    }
    arguments[argument] = bytearray(arguments[argument])
    with pytest.raises(TypeError):
        load_entra_calling_client_msal_current_version_readiness(**arguments)


def test_step218_rerun_precedes_step220_document_parsing(monkeypatch):
    calls = []

    def fail(**_arguments):
        calls.append("step218")
        raise ValueError("secret-prerequisite")

    monkeypatch.setattr(
        module,
        "load_entra_calling_client_msal_retry_reconciliation_readiness",
        fail,
    )
    prior = prerequisites()
    with pytest.raises(EntraCallingClientMSALCurrentVersionReadinessError):
        load_entra_calling_client_msal_current_version_readiness(
            document=b"malformed",
            **prior,
        )
    assert calls == ["step218"]


def test_schema_valid_reblessed_step218_approval_is_rejected(monkeypatch):
    prior = prerequisites()
    valid_prior = load_entra_calling_client_msal_retry_reconciliation_readiness(
        document=prior["retry_reconciliation_document"],
        msal_browser_control_document=prior["msal_browser_control_document"],
        approved_msal_browser_control_document_sha256=prior[
            "approved_msal_browser_control_document_sha256"
        ],
        pkce_runtime_control_document=prior["pkce_runtime_control_document"],
        approved_pkce_runtime_control_document_sha256=prior[
            "approved_pkce_runtime_control_document_sha256"
        ],
        redirect_endpoint_control_document=prior["redirect_endpoint_control_document"],
        approved_redirect_endpoint_control_document_sha256=prior[
            "approved_redirect_endpoint_control_document_sha256"
        ],
        authentication_preview=prior["authentication_preview"],
        api_registration_document=prior["api_registration_document"],
        accepted_api_registration_document_sha256=prior[
            "accepted_api_registration_document_sha256"
        ],
        calling_client_registration_document=prior[
            "calling_client_registration_document"
        ],
        accepted_calling_client_registration_document_sha256=prior[
            "accepted_calling_client_registration_document_sha256"
        ],
        inventory_document=prior["inventory_document"],
        approved_inventory_document_sha256=prior["approved_inventory_document_sha256"],
    )
    monkeypatch.setattr(
        module,
        "load_entra_calling_client_msal_retry_reconciliation_readiness",
        lambda **_arguments: unsafe_replace(
            valid_prior,
            conditional_exception_approved=True,
        ),
    )
    with pytest.raises(EntraCallingClientMSALCurrentVersionReadinessError):
        load(prior=prior)


@pytest.mark.parametrize(
    "failure",
    [
        ValueError("secret"),
        KeyboardInterrupt("secret"),
        SystemExit("secret"),
        BaseExceptionGroup("secret-group", [ValueError("child-secret")]),
    ],
)
def test_nested_control_flow_and_exception_privacy(monkeypatch, failure):
    def fail(**_arguments):
        raise failure

    monkeypatch.setattr(
        module,
        "load_entra_calling_client_msal_retry_reconciliation_readiness",
        fail,
    )
    prior = prerequisites()
    expected = (
        type(failure)
        if isinstance(failure, (KeyboardInterrupt, SystemExit))
        else EntraCallingClientMSALCurrentVersionReadinessError
    )
    with pytest.raises(expected) as caught:
        load_entra_calling_client_msal_current_version_readiness(
            document=canonical(values(prior)),
            **prior,
        )
    assert "secret" not in production_exception_material(caught.value)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_every_receipt_boolean_is_exhaustively_partitioned_and_enforced():
    receipt = load()
    boolean_fields = {
        field.name
        for field in fields(receipt)
        if type(getattr(receipt, field.name)) is bool
    }
    expected = {*module._STRUCTURAL_TRUE_FIELDS, *module._DEFERRED_FALSE_FIELDS}
    assert boolean_fields == expected
    assert not set(module._STRUCTURAL_TRUE_FIELDS) & set(module._DEFERRED_FALSE_FIELDS)
    for name in boolean_fields:
        tampered = unsafe_replace(receipt, **{name: not getattr(receipt, name)})
        with pytest.raises(ValueError):
            tampered.__post_init__()


@pytest.mark.parametrize("invalid", [True, 0.0, "1", None, [], {}])
def test_every_receipt_count_requires_exact_integer_type(invalid):
    receipt = load()
    for name in module._COUNT_FIELDS:
        with pytest.raises(ValueError):
            unsafe_replace(receipt, **{name: invalid}).__post_init__()


def test_every_public_string_and_digest_has_integrity_validation():
    receipt = load()
    for field in fields(receipt):
        if field.name in module._PUBLIC_STRING_FIELDS or field.name.endswith("_sha256"):
            with pytest.raises(ValueError):
                unsafe_replace(receipt, **{field.name: "invalid"}).__post_init__()


@pytest.mark.parametrize(
    ("approved", "observed"),
    [
        ("approved_inventory_document_sha256", "inventory_document_sha256"),
        (
            "approved_redirect_endpoint_control_document_sha256",
            "redirect_endpoint_control_document_sha256",
        ),
        (
            "approved_pkce_runtime_control_document_sha256",
            "pkce_runtime_control_document_sha256",
        ),
        (
            "approved_msal_browser_control_document_sha256",
            "msal_browser_control_document_sha256",
        ),
        (
            "approved_retry_reconciliation_document_sha256",
            "retry_reconciliation_document_sha256",
        ),
    ],
)
def test_paired_source_digests_must_match(approved, observed):
    receipt = load()
    replacement = "0" * 64
    if getattr(receipt, observed) == replacement:
        replacement = "1" * 64
    with pytest.raises(ValueError):
        unsafe_replace(receipt, **{observed: replacement}).__post_init__()


def test_renderer_is_canonical_and_revalidates_receipt():
    receipt = load()
    rendered = render_entra_calling_client_msal_current_version_readiness_receipt(
        receipt
    )
    assert rendered == json.dumps(
        {field.name: getattr(receipt, field.name) for field in fields(receipt)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    with pytest.raises(ValueError):
        render_entra_calling_client_msal_current_version_readiness_receipt(
            unsafe_replace(receipt, activation_ready=True)
        )


def test_no_step219_receipt_or_artifact_bytes_are_accepted_as_inputs():
    signature = inspect.signature(
        load_entra_calling_client_msal_current_version_readiness
    )
    source = inspect.getsource(module._load_internal)
    assert "step219_receipt" not in source
    assert "npm_artifact" not in source
    assert tuple(signature.parameters) == ("arguments",)


def test_source_ast_has_no_io_imports_and_receipt_fields_are_unique():
    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    receipt_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "EntraCallingClientMSALCurrentVersionReadinessReceipt"
    )
    declared = [
        node.target.id
        for node in receipt_class.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    ]
    assert len(declared) == len(set(declared))
    imports = {
        alias.name.split(".")[0]
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imports.isdisjoint(
        {
            "builtins",
            "os",
            "pathlib",
            "socket",
            "ssl",
            "subprocess",
            "urllib",
            "tarfile",
            "tempfile",
        }
    )
    assert "open(" not in source
    assert "__import__" not in source
    assert "eval(" not in source
    assert "exec(" not in source
