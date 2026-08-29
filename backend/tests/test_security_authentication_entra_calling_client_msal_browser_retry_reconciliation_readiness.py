"""Tests for offline MSAL Browser retry reconciliation readiness."""

from __future__ import annotations

import ast
import builtins
import hashlib
import inspect
import json
import os
import socket
import ssl
import urllib.request
from dataclasses import fields
from pathlib import Path

import pytest

import app.security.authentication_entra_calling_client_msal_browser_retry_reconciliation_readiness as module
from app.security.authentication_entra_calling_client_msal_browser_readiness import (
    load_entra_calling_client_msal_browser_readiness,
)
from app.security.authentication_entra_calling_client_msal_browser_retry_reconciliation_readiness import (
    ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_DOCUMENT_TYPE,
    ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_PROFILE,
    ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_RECEIPT_TYPE,
    ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SCOPE,
    ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SOURCE,
    MAX_ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_DOCUMENT_BYTES,
    RECONCILIATION_ARTIFACT_PROOF,
    RECONCILIATION_FIXED_BACKOFF_MILLISECONDS,
    RECONCILIATION_HTTP_RESPONSE_RETRY_COUNT,
    RECONCILIATION_MAXIMUM_TOKEN_POST_ATTEMPT_COUNT,
    RECONCILIATION_MAXIMUM_TOKEN_POST_RETRY_COUNT,
    RECONCILIATION_OAUTH_ERROR_RETRY_COUNT,
    RECONCILIATION_POLICY_STATUS,
    RECONCILIATION_RESPONSE_AMBIGUITY,
    RECONCILIATION_RETRY_BACKOFF,
    RECONCILIATION_RETRY_EXECUTION,
    RECONCILIATION_RETRY_TRIGGER,
    STEP216_REQUIRED_TOKEN_POST_RETRY_COUNT,
    EntraCallingClientMSALRetryReconciliationReadinessError,
    load_entra_calling_client_msal_retry_reconciliation_readiness,
    render_entra_calling_client_msal_retry_reconciliation_readiness_receipt,
)
from tests import (
    test_security_authentication_entra_calling_client_msal_browser_readiness as step217,
)


def prerequisites(redirect_uris=(step217.step216.step214.REDIRECT_URI,)):
    prior = step217.prerequisites(redirect_uris)
    msal_document = json.dumps(step217.values(prior), separators=(",", ":")).encode()
    msal_receipt = load_entra_calling_client_msal_browser_readiness(
        document=msal_document,
        **prior,
    )
    return {
        **prior,
        "msal_browser_control_document": msal_document,
        "approved_msal_browser_control_document_sha256": (
            msal_receipt.msal_browser_control_document_sha256
        ),
    }


def values(prerequisite=None):
    prerequisite = prerequisite or prerequisites()
    return {
        "document_type": ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_DOCUMENT_TYPE,
        "schema_version": 1,
        "source": ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SOURCE,
        "approved_msal_browser_control_document_sha256": prerequisite[
            "approved_msal_browser_control_document_sha256"
        ],
        "reconciliation_profile": ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_PROFILE,
    }


def load(value=None, prerequisite=None):
    prerequisite = prerequisite or prerequisites()
    body = values(prerequisite) if value is None else value
    return load_entra_calling_client_msal_retry_reconciliation_readiness(
        document=json.dumps(body, separators=(",", ":")).encode(),
        **prerequisite,
    )


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def framed(label, *values):
    digest = hashlib.sha256()
    for value in ("engineer4me-step218-v1", label, str(len(values)), *values):
        encoded = value if isinstance(value, bytes) else value.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def unsafe_replace(receipt, **changes):
    clone = object.__new__(type(receipt))
    for field in fields(receipt):
        object.__setattr__(
            clone, field.name, changes.get(field.name, getattr(receipt, field.name))
        )
    return clone


def exception_material(error):
    values = []
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        values.append(repr(current))
        values.extend(repr(value) for value in current.args)
        for linked in (current.__context__, current.__cause__):
            if isinstance(linked, BaseException):
                pending.append(linked)
        children = getattr(current, "exceptions", ())
        if isinstance(children, tuple):
            pending.extend(children)
        traceback = current.__traceback__
        while traceback is not None:
            if traceback.tb_frame.f_globals.get("__name__") == module.__name__:
                values.extend(
                    repr(value) for value in traceback.tb_frame.f_locals.values()
                )
            traceback = traceback.tb_next
    return "\n".join(values)


def test_valid_reconciliation_preserves_blocker_and_stays_offline():
    receipt = load()
    assert (
        receipt.receipt_type
        == ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_RECEIPT_TYPE
    )
    assert (
        receipt.validation_scope == ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_SCOPE
    )
    assert (
        receipt.reconciliation_profile
        == ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_PROFILE
    )
    assert all(
        getattr(receipt, name) is True for name in module._STRUCTURAL_TRUE_FIELDS
    )
    assert all(
        getattr(receipt, name) is False for name in module._DEFERRED_FALSE_FIELDS
    )
    assert receipt.conditional_exception_approved is False
    assert receipt.step216_zero_retry_superseded is False
    assert receipt.package_selection_ready is False
    assert receipt.activation_ready is False


def test_public_retry_reconciliation_constants_are_exact():
    receipt = load()
    assert receipt.package_name == "@azure/msal-browser"
    assert receipt.reviewed_package_version == "5.17.3"
    assert (
        receipt.retry_trigger
        == RECONCILIATION_RETRY_TRIGGER
        == "token_post_transport_failure_only"
    )
    assert (
        receipt.retry_execution
        == RECONCILIATION_RETRY_EXECUTION
        == "single_sequential_retry"
    )
    assert (
        receipt.retry_backoff
        == RECONCILIATION_RETRY_BACKOFF
        == "fixed_100_milliseconds"
    )
    assert receipt.response_ambiguity == RECONCILIATION_RESPONSE_AMBIGUITY
    assert (
        receipt.policy_status
        == RECONCILIATION_POLICY_STATUS
        == "conditional_exception_not_approved"
    )
    assert (
        receipt.artifact_proof
        == RECONCILIATION_ARTIFACT_PROOF
        == "exact_distribution_artifact_required"
    )
    assert (
        receipt.step216_required_token_post_retry_count
        == STEP216_REQUIRED_TOKEN_POST_RETRY_COUNT
        == 0
    )
    assert receipt.reviewed_candidate_token_post_retry_count == 1
    assert (
        receipt.conditional_maximum_token_post_retry_count
        == RECONCILIATION_MAXIMUM_TOKEN_POST_RETRY_COUNT
        == 1
    )
    assert (
        receipt.conditional_maximum_token_post_attempt_count
        == RECONCILIATION_MAXIMUM_TOKEN_POST_ATTEMPT_COUNT
        == 2
    )
    assert (
        receipt.conditional_fixed_backoff_milliseconds
        == RECONCILIATION_FIXED_BACKOFF_MILLISECONDS
        == 100
    )
    assert (
        receipt.conditional_http_response_retry_count
        == RECONCILIATION_HTTP_RESPONSE_RETRY_COUNT
        == 0
    )
    assert (
        receipt.conditional_oauth_error_retry_count
        == RECONCILIATION_OAUTH_ERROR_RETRY_COUNT
        == 0
    )


def test_conditional_exception_profile_is_independently_bound():
    expected = canonical(
        {
            "status": "conditional_exception_not_approved",
            "step216RequiredRetryCount": 0,
            "conditionalMaximumRetryCount": 1,
            "conditionalMaximumAttemptCount": 2,
            "trigger": "token_post_transport_failure_only",
            "execution": "single_sequential_retry",
            "backoffMilliseconds": 100,
            "httpResponseRetryCount": 0,
            "oauthErrorRetryCount": 0,
            "parallelRetryAllowed": False,
            "recursiveRetryAllowed": False,
            "retryAfterAbortOrCancellationAllowed": False,
            "sameNormalizedTokenRequestRequired": True,
            "allOtherStep216ControlsPreserved": True,
            "approved": False,
        }
    )
    assert load().conditional_retry_exception_profile_sha256 == framed(
        "conditional_retry_exception_profile", expected
    )


def test_artifact_verification_plan_is_independently_bound():
    expected = canonical(
        {
            "package": "@azure/msal-browser",
            "version": "5.17.3",
            "exactRegistryMetadataRequired": True,
            "exactTarballRequired": True,
            "registryIntegrityRequired": True,
            "packageJsonRequired": True,
            "exportsRequired": True,
            "redirectBridgeExportRequired": True,
            "compiledRetryPathInspectionRequired": True,
            "adversarialTransportFailureTestsRequired": True,
            "httpAndOauthErrorNoRetryTestsRequired": True,
            "abortAndCancellationNoRetryTestsRequired": True,
            "responseLossAmbiguityTestRequired": True,
            "providerIoPerformed": False,
            "approved": False,
        }
    )
    assert load().distribution_artifact_verification_plan_sha256 == framed(
        "distribution_artifact_verification_plan", expected
    )


def test_response_loss_risk_and_package_selection_profiles_are_exact():
    risk = canonical(
        {
            "ambiguity": "first_response_loss_may_consume_single_use_code",
            "firstRequestMayReachTokenEndpoint": True,
            "firstResponseMayBeUnavailableToBrowser": True,
            "authorizationCodeMayAlreadyBeConsumed": True,
            "retryMayReturnInvalidGrant": True,
            "automaticSuccessGuaranteed": False,
            "credentialReplaySafetyEstablished": False,
            "userReauthenticationMayBeRequired": True,
            "riskAccepted": False,
        }
    )
    selection = canonical(
        {
            "package": "@azure/msal-browser",
            "reviewedCandidateVersion": "5.17.3",
            "downgradeAllowedWithoutReview": False,
            "currentReleaseRevalidationRequired": True,
            "artifactProofRequired": True,
            "conditionalExceptionApproved": False,
            "step216Superseded": False,
            "compatible": False,
            "selectionReady": False,
        }
    )
    receipt = load()
    assert receipt.response_loss_risk_profile_sha256 == framed(
        "response_loss_risk_profile", risk
    )
    assert receipt.package_selection_state_sha256 == framed(
        "package_selection_state", selection
    )


def test_three_redirects_preserve_privacy_and_change_count():
    step214 = step217.step216.step214
    prerequisite = prerequisites(
        (step214.REDIRECT_URI, step214.REDIRECT_URI_2, step214.REDIRECT_URI_3)
    )
    receipt = load(prerequisite=prerequisite)
    rendered = render_entra_calling_client_msal_retry_reconciliation_readiness_receipt(
        receipt
    )
    assert receipt.desired_redirect_endpoint_count == 3
    forbidden = {
        step214.TENANT_ID,
        step214.API_APPLICATION_ID,
        step214.API_APPLICATION_OBJECT_ID,
        step214.API_SERVICE_PRINCIPAL_OBJECT_ID,
        step214.API_SCOPE_ID,
        step214.CALLING_CLIENT_APPLICATION_ID,
        step214.CALLING_CLIENT_OBJECT_ID,
        step214.CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
        step214.OWNER_ID,
        step214.OWNER_ID_2,
        step214.REDIRECT_URI,
        step214.REDIRECT_URI_2,
        step214.REDIRECT_URI_3,
        "synthetic.ciamlogin.com",
    }
    assert all(value not in rendered for value in forbidden)
    for key in (
        "api_registration_document",
        "calling_client_registration_document",
        "inventory_document",
        "redirect_endpoint_control_document",
        "pkce_runtime_control_document",
        "msal_browser_control_document",
    ):
        assert prerequisite[key].decode() not in rendered


def test_step217_safe_hashes_and_approved_digest_are_preserved():
    prerequisite = prerequisites()
    prior = load_entra_calling_client_msal_browser_readiness(
        document=prerequisite["msal_browser_control_document"],
        **{
            key: value
            for key, value in prerequisite.items()
            if key
            not in {
                "msal_browser_control_document",
                "approved_msal_browser_control_document_sha256",
            }
        },
    )
    receipt = load(prerequisite=prerequisite)
    for name in (
        "configuration_sha256",
        "api_registration_document_sha256",
        "calling_client_registration_document_sha256",
        "tenant_id_sha256",
        "calling_client_application_id_sha256",
        "calling_client_application_object_id_sha256",
        "api_application_id_sha256",
        "api_delegated_scope_id_sha256",
        "spa_redirect_uris_sha256",
        "authority_origin_sha256",
        "authority_sha256",
        "known_authorities_sha256",
    ):
        assert getattr(receipt, name) == getattr(prior, name)
    assert (
        receipt.msal_browser_control_document_sha256
        == prerequisite["approved_msal_browser_control_document_sha256"]
    )


@pytest.mark.parametrize("field", ["document_type", "source", "reconciliation_profile"])
def test_document_literals_are_exact(field):
    body = values()
    body[field] = str(body[field]) + "-wrong"
    with pytest.raises(EntraCallingClientMSALRetryReconciliationReadinessError):
        load(body)


@pytest.mark.parametrize("invalid", [True, False, 0, 2, 1.0, "1", None, [], {}])
def test_schema_version_requires_exact_integer_one(invalid):
    body = values()
    body["schema_version"] = invalid
    with pytest.raises(EntraCallingClientMSALRetryReconciliationReadinessError):
        load(body)


def test_document_rejects_extra_missing_root_and_nested_duplicates():
    prerequisite = prerequisites()
    body = values(prerequisite)
    cases = [
        b"[]",
        json.dumps({**body, "extra": True}).encode(),
        json.dumps(
            {key: value for key, value in body.items() if key != "source"}
        ).encode(),
        b'{"document_type":"x","document_type":"y"}',
        b'{"document_type":"x","nested":{"a":1,"a":2}}',
    ]
    for document in cases:
        with pytest.raises(EntraCallingClientMSALRetryReconciliationReadinessError):
            load_entra_calling_client_msal_retry_reconciliation_readiness(
                document=document, **prerequisite
            )


@pytest.mark.parametrize(
    "document",
    [b"", b"{", b'"scalar"', b"\xff", b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}'],
)
def test_malformed_documents_fail_with_context_free_error(document):
    with pytest.raises(
        EntraCallingClientMSALRetryReconciliationReadinessError
    ) as caught:
        load_entra_calling_client_msal_retry_reconciliation_readiness(
            document=document, **prerequisites()
        )
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_document_size_depth_and_container_limits_fail_closed():
    prerequisite = prerequisites()
    cases = (
        b" " * (MAX_ENTRA_CALLING_CLIENT_MSAL_RETRY_RECONCILIATION_DOCUMENT_BYTES + 1),
        b'{"a":{"b":{"c":{"d":1}}}}',
        json.dumps({str(index): [] for index in range(9)}).encode(),
    )
    for document in cases:
        with pytest.raises(EntraCallingClientMSALRetryReconciliationReadinessError):
            load_entra_calling_client_msal_retry_reconciliation_readiness(
                document=document, **prerequisite
            )


def test_step217_rerun_precedes_step218_document_parsing(monkeypatch):
    def fail(**kwargs):
        del kwargs
        raise KeyboardInterrupt("step217-first-secret")

    monkeypatch.setattr(
        module, "load_entra_calling_client_msal_browser_readiness", fail
    )
    with pytest.raises(KeyboardInterrupt, match="reconciliation interrupted"):
        load_entra_calling_client_msal_retry_reconciliation_readiness(
            document=b"not-json", **prerequisites()
        )


def test_independently_approved_msal_control_digest_is_required():
    prerequisite = prerequisites()
    prerequisite["approved_msal_browser_control_document_sha256"] = "0" * 64
    body = values(prerequisite)
    body["approved_msal_browser_control_document_sha256"] = "0" * 64
    with pytest.raises(EntraCallingClientMSALRetryReconciliationReadinessError):
        load(body, prerequisite)


def test_schema_valid_reblessed_step217_tamper_is_rejected():
    prerequisite = prerequisites()
    parsed = json.loads(prerequisite["msal_browser_control_document"])
    parsed["source"] = parsed["source"] + "-wrong"
    tampered = json.dumps(parsed, separators=(",", ":")).encode()
    prerequisite["msal_browser_control_document"] = tampered
    prerequisite["approved_msal_browser_control_document_sha256"] = hashlib.sha256(
        tampered
    ).hexdigest()
    with pytest.raises(EntraCallingClientMSALRetryReconciliationReadinessError):
        load(values(prerequisite), prerequisite)


@pytest.mark.parametrize(
    "argument",
    [
        "document",
        "msal_browser_control_document",
        "pkce_runtime_control_document",
        "redirect_endpoint_control_document",
        "api_registration_document",
        "calling_client_registration_document",
        "inventory_document",
    ],
)
def test_document_arguments_require_exact_bytes(argument):
    prerequisite = prerequisites()
    kwargs = {"document": json.dumps(values(prerequisite)).encode(), **prerequisite}
    kwargs[argument] = bytearray(kwargs[argument])
    with pytest.raises(TypeError, match="inputs are invalid"):
        load_entra_calling_client_msal_retry_reconciliation_readiness(**kwargs)


@pytest.mark.parametrize(
    "argument",
    [
        "approved_msal_browser_control_document_sha256",
        "approved_pkce_runtime_control_document_sha256",
        "approved_redirect_endpoint_control_document_sha256",
        "accepted_api_registration_document_sha256",
        "accepted_calling_client_registration_document_sha256",
        "approved_inventory_document_sha256",
    ],
)
@pytest.mark.parametrize("invalid", ["0" * 63, "0" * 65, "A" * 64, 0, True, None])
def test_digest_arguments_require_exact_lower_sha256(argument, invalid):
    prerequisite = prerequisites()
    kwargs = {"document": json.dumps(values(prerequisite)).encode(), **prerequisite}
    kwargs[argument] = invalid
    with pytest.raises(TypeError, match="inputs are invalid"):
        load_entra_calling_client_msal_retry_reconciliation_readiness(**kwargs)


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (BaseExceptionGroup("outer", [SystemExit("secret")]), SystemExit),
        (
            BaseExceptionGroup(
                "outer", [SystemExit("secret"), KeyboardInterrupt("secret")]
            ),
            KeyboardInterrupt,
        ),
    ],
)
def test_nested_keyboard_interrupt_and_system_exit_are_preserved(
    monkeypatch, error, expected
):
    def fail(**kwargs):
        del kwargs
        raise error

    monkeypatch.setattr(
        module, "load_entra_calling_client_msal_browser_readiness", fail
    )
    with pytest.raises(expected) as caught:
        load_entra_calling_client_msal_retry_reconciliation_readiness(
            document=b"secret-step218", **prerequisites()
        )
    assert "secret" not in exception_material(caught.value)


def test_public_error_graph_and_production_frames_omit_untrusted_values(monkeypatch):
    secret = "secret-step218-evidence"

    def fail(**kwargs):
        del kwargs
        raise ExceptionGroup(secret, [ValueError(secret)])

    monkeypatch.setattr(
        module, "load_entra_calling_client_msal_browser_readiness", fail
    )
    with pytest.raises(
        EntraCallingClientMSALRetryReconciliationReadinessError
    ) as caught:
        load_entra_calling_client_msal_retry_reconciliation_readiness(
            document=secret.encode(), **prerequisites()
        )
    assert secret not in exception_material(caught.value)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_every_receipt_boolean_is_exhaustively_integrity_enforced():
    receipt = load()
    bool_fields = [field.name for field in fields(receipt) if field.type == "bool"]
    assert set(bool_fields) == set(module._STRUCTURAL_TRUE_FIELDS) | set(
        module._DEFERRED_FALSE_FIELDS
    )
    assert set(module._STRUCTURAL_TRUE_FIELDS).isdisjoint(module._DEFERRED_FALSE_FIELDS)
    for name in bool_fields:
        forged = unsafe_replace(receipt, **{name: not getattr(receipt, name)})
        with pytest.raises(ValueError):
            forged.__post_init__()
        with pytest.raises(ValueError):
            render_entra_calling_client_msal_retry_reconciliation_readiness_receipt(
                forged
            )


@pytest.mark.parametrize("invalid", [True, False, 0.0, "1", None, [], {}])
def test_every_receipt_count_rejects_wrong_exact_type(invalid):
    receipt = load()
    for name in module._COUNT_FIELDS:
        with pytest.raises(ValueError):
            unsafe_replace(receipt, **{name: invalid}).__post_init__()


def test_every_exact_count_rejects_a_different_integer():
    receipt = load()
    for name in module._COUNT_FIELDS[:-1]:
        with pytest.raises(ValueError):
            unsafe_replace(
                receipt, **{name: getattr(receipt, name) + 1}
            ).__post_init__()


def test_every_public_string_and_digest_is_integrity_enforced():
    receipt = load()
    for name in module._PUBLIC_STRING_FIELDS:
        with pytest.raises(ValueError):
            unsafe_replace(
                receipt, **{name: getattr(receipt, name) + "-wrong"}
            ).__post_init__()
    for field in fields(receipt):
        if field.name.endswith("_sha256"):
            for invalid in ("0" * 63, "A" * 64, 0, True, None):
                with pytest.raises(ValueError):
                    unsafe_replace(receipt, **{field.name: invalid}).__post_init__()


@pytest.mark.parametrize(
    "field",
    [
        "approved_inventory_document_sha256",
        "approved_redirect_endpoint_control_document_sha256",
        "approved_pkce_runtime_control_document_sha256",
        "approved_msal_browser_control_document_sha256",
    ],
)
def test_paired_source_digests_reject_valid_shape_mismatch(field):
    with pytest.raises(ValueError):
        unsafe_replace(load(), **{field: "0" * 64}).__post_init__()


def test_renderer_is_canonical_and_revalidates_receipt():
    receipt = load()
    rendered = render_entra_calling_client_msal_retry_reconciliation_readiness_receipt(
        receipt
    )
    assert rendered == json.dumps(
        json.loads(rendered), sort_keys=True, separators=(",", ":")
    )
    with pytest.raises(TypeError):
        render_entra_calling_client_msal_retry_reconciliation_readiness_receipt({})
    with pytest.raises(ValueError):
        render_entra_calling_client_msal_retry_reconciliation_readiness_receipt(
            unsafe_replace(receipt, activation_ready=True)
        )


def test_no_io_occurs_during_offline_reconciliation(monkeypatch):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("I/O was attempted")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(ssl, "create_default_context", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    receipt = load()
    assert receipt.provider_io_performed is False
    assert receipt.network_io_performed is False
    assert receipt.filesystem_io_performed is False
    assert receipt.package_manager_process_performed is False


def test_source_ast_has_no_io_imports_and_receipt_fields_are_unique():
    tree = ast.parse(inspect.getsource(module))
    forbidden_roots = {"subprocess", "http", "requests", "socket", "ssl", "urllib"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported.isdisjoint(forbidden_roots)
    receipt_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "EntraCallingClientMSALRetryReconciliationReadinessReceipt"
    )
    names = [
        node.target.id
        for node in receipt_class.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    ]
    assert len(names) == len(set(names)) == len(fields(load()))


def test_reconciliation_never_claims_known_behavior_or_policy_approval():
    receipt = load()
    must_remain_false = {
        "compiled_distribution_artifact_inspected",
        "exact_retry_trigger_checked",
        "exact_retry_count_checked",
        "exact_retry_backoff_checked",
        "retry_request_equivalence_checked",
        "response_loss_behavior_checked",
        "conditional_exception_approved",
        "step216_zero_retry_superseded",
        "reviewed_candidate_compatible_with_successor_policy",
        "package_selection_ready",
        "package_installed",
        "runtime_pkce_s256_checked",
        "activation_ready",
    }
    assert must_remain_false.issubset(module._DEFERRED_FALSE_FIELDS)
    assert all(getattr(receipt, name) is False for name in must_remain_false)
