"""Tests for offline MSAL compiled retry harness readiness."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from builtins import BaseExceptionGroup
from dataclasses import fields
from pathlib import Path

import pytest

import app.security.authentication_entra_calling_client_msal_browser_compiled_retry_harness_readiness as module
from app.security.authentication_entra_calling_client_msal_browser_compiled_retry_execution_readiness import (
    load_entra_calling_client_msal_compiled_retry_execution_readiness,
)
from app.security.authentication_entra_calling_client_msal_browser_compiled_retry_harness_readiness import (
    DOCUMENT_TYPE,
    HARNESS_BYTES,
    HARNESS_FILE_NAME,
    HARNESS_SCENARIO_COUNT,
    HARNESS_SHA256,
    PROFILE,
    RECEIPT_TYPE,
    REVIEWED_NON_TOKEN_POST_ATTEMPTS,
    SOURCE,
    STATUS,
    EntraCallingClientMSALCompiledRetryHarnessReadinessError,
    load_entra_calling_client_msal_compiled_retry_harness_readiness,
    render_entra_calling_client_msal_compiled_retry_harness_readiness_receipt,
)
from tests import (
    test_security_authentication_entra_calling_client_msal_browser_compiled_retry_execution_readiness as step221,
)

HARNESS_PATH = Path(module.__file__).with_name(HARNESS_FILE_NAME)
HARNESS = HARNESS_PATH.read_bytes()


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def prerequisites():
    prior = step221.prerequisites()
    prior_document = json.dumps(step221.values(prior), separators=(",", ":")).encode()
    receipt = load_entra_calling_client_msal_compiled_retry_execution_readiness(
        document=prior_document,
        **prior,
    )
    return {
        **prior,
        "compiled_retry_execution_readiness_document": prior_document,
        "approved_compiled_retry_execution_readiness_document_sha256": (
            receipt.compiled_execution_readiness_document_sha256
        ),
    }


def values(prior=None):
    prior = prior or prerequisites()
    return {
        "document_type": DOCUMENT_TYPE,
        "schema_version": 1,
        "source": SOURCE,
        "approved_compiled_retry_execution_readiness_document_sha256": prior[
            "approved_compiled_retry_execution_readiness_document_sha256"
        ],
        "harness_profile": PROFILE,
    }


def load(value=None, prior=None, harness=HARNESS):
    prior = prior or prerequisites()
    body = values(prior) if value is None else value
    return load_entra_calling_client_msal_compiled_retry_harness_readiness(
        document=json.dumps(body, separators=(",", ":")).encode(),
        harness=harness,
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
    for part in ("engineer4me-step222-v1", label, canonical(value)):
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


def test_valid_receipt_is_exact_and_fully_fail_closed():
    receipt = load()
    assert receipt.receipt_type == RECEIPT_TYPE
    assert receipt.validation_scope == module.SCOPE
    assert receipt.readiness_status == STATUS
    assert receipt.harness_bytes == HARNESS_BYTES
    assert receipt.harness_scenario_count == HARNESS_SCENARIO_COUNT == 10
    assert (
        receipt.reviewed_non_token_post_attempts
        == REVIEWED_NON_TOKEN_POST_ATTEMPTS
        == 2
    )
    assert all(getattr(receipt, name) is True for name in module._TRUE_FIELDS)
    assert all(getattr(receipt, name) is False for name in module._FALSE_FIELDS)


def test_exact_harness_bytes_and_identity_are_bound():
    receipt = load()
    assert HARNESS_PATH.name == HARNESS_FILE_NAME
    assert len(HARNESS) == HARNESS_BYTES
    assert hashlib.sha256(HARNESS).hexdigest() == HARNESS_SHA256
    assert receipt.harness_sha256 == HARNESS_SHA256
    assert receipt.harness_file_name == HARNESS_FILE_NAME


def test_execution_scope_conflict_and_selection_hashes_are_independent():
    receipt = load()
    execution = {
        "harnessSha256": HARNESS_SHA256,
        "scenarioCount": 10,
        "node": "exact_identity_required",
        "workspace": "ephemeral",
        "networkBeforeImport": "disabled",
        "fetch": "fake_only",
        "oauthInputs": "synthetic_only",
    }
    conflict = {
        "compiledEntrySha256": module.COMPILED_RETRY_ENTRY_SHA256,
        "method": "sendPostRequestAsync",
        "guard": "non_abort_transport_failure_and_online",
        "urlTokenRestrictionPresent": False,
        "reviewedNonTokenAttempts": 2,
    }
    selection = {
        "step216ZeroRetrySuperseded": False,
        "exceptionApproved": False,
        "compatible": False,
        "selected": False,
    }
    assert receipt.harness_execution_plan_sha256 == framed("execution", execution)
    assert receipt.reviewed_scope_conflict_sha256 == framed("scope_conflict", conflict)
    assert receipt.selection_state_sha256 == framed("selection", selection)


def test_non_token_scope_conflict_does_not_approve_candidate():
    receipt = load()
    assert receipt.compiled_scope_finding == (
        "sendPostRequestAsync_retries_non_abort_transport_failure_for_any_post_url"
    )
    assert receipt.non_token_post_retry_scope_conflict_recorded is True
    assert receipt.step216_zero_retry_requirement_preserved is True
    assert receipt.conditional_exception_remains_unapproved is True
    assert receipt.non_token_exclusion_runtime_checked is False
    assert receipt.conditional_exception_approved is False
    assert receipt.step216_zero_retry_superseded is False
    assert receipt.candidate_compatible is False
    assert receipt.candidate_selected is False


def test_step221_is_rerun_and_rendered_receipt_is_not_provenance(monkeypatch):
    calls = []
    original = module.load_entra_calling_client_msal_compiled_retry_execution_readiness

    def wrapped(**kwargs):
        calls.append("step221")
        return original(**kwargs)

    monkeypatch.setattr(
        module,
        "load_entra_calling_client_msal_compiled_retry_execution_readiness",
        wrapped,
    )
    load()
    assert calls == ["step221"]


def test_step221_runs_before_step222_document_parse(monkeypatch):
    def fail(**_kwargs):
        raise ValueError("prior-first-secret")

    monkeypatch.setattr(
        module,
        "load_entra_calling_client_msal_compiled_retry_execution_readiness",
        fail,
    )
    with pytest.raises(EntraCallingClientMSALCompiledRetryHarnessReadinessError):
        load_entra_calling_client_msal_compiled_retry_harness_readiness(
            document=b"not-json",
            harness=HARNESS,
            **prerequisites(),
        )


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("document_type", "wrong"),
        ("schema_version", True),
        ("source", "wrong"),
        ("approved_compiled_retry_execution_readiness_document_sha256", "0" * 64),
        ("harness_profile", "wrong"),
    ],
)
def test_document_literals_and_approved_digest_are_exact(field, invalid):
    prior = prerequisites()
    value = values(prior)
    value[field] = invalid
    with pytest.raises(EntraCallingClientMSALCompiledRetryHarnessReadinessError):
        load(value, prior)


@pytest.mark.parametrize(
    "body",
    [
        b"{}",
        b'{"document_type":"x","document_type":"y"}',
        b'{"schema_version":NaN}',
        b"\xff",
        b"[1]",
        b"null",
    ],
)
def test_malformed_noncanonical_and_duplicate_documents_fail_closed(body):
    with pytest.raises(EntraCallingClientMSALCompiledRetryHarnessReadinessError):
        load_entra_calling_client_msal_compiled_retry_harness_readiness(
            document=body,
            harness=HARNESS,
            **prerequisites(),
        )


def test_extra_and_missing_document_keys_fail_closed():
    prior = prerequisites()
    extra = values(prior) | {"extra": False}
    missing = values(prior)
    missing.pop("harness_profile")
    for value in (extra, missing):
        with pytest.raises(EntraCallingClientMSALCompiledRetryHarnessReadinessError):
            load(value, prior)


@pytest.mark.parametrize(
    ("document", "harness"),
    [("not-bytes", HARNESS), (b"{}", "not-bytes"), (None, HARNESS)],
)
def test_public_input_type_errors_are_sanitized_type_errors(document, harness):
    with pytest.raises(TypeError, match="inputs are invalid") as caught:
        load_entra_calling_client_msal_compiled_retry_harness_readiness(
            document=document,
            harness=harness,
            **prerequisites(),
        )
    assert caught.value.__context__ is None


def test_one_byte_harness_tamper_and_wrong_length_are_rejected():
    changed = bytearray(HARNESS)
    changed[-2] ^= 1
    for harness in (bytes(changed), HARNESS[:-1], HARNESS + b"\n"):
        with pytest.raises(EntraCallingClientMSALCompiledRetryHarnessReadinessError):
            load(harness=harness)


def test_reblessed_step221_approval_is_rejected(monkeypatch):
    original = module.load_entra_calling_client_msal_compiled_retry_execution_readiness

    def forged(**kwargs):
        receipt = original(**kwargs)
        return step221.unsafe_replace(receipt, conditional_exception_approved=True)

    monkeypatch.setattr(
        module,
        "load_entra_calling_client_msal_compiled_retry_execution_readiness",
        forged,
    )
    with pytest.raises(EntraCallingClientMSALCompiledRetryHarnessReadinessError):
        load()


def test_receipt_digests_bind_canonical_documents_and_step221_receipt():
    prior = prerequisites()
    receipt = load(prior=prior)
    expected_document = canonical(values(prior))
    prior_receipt = load_entra_calling_client_msal_compiled_retry_execution_readiness(
        document=prior["compiled_retry_execution_readiness_document"],
        **{
            key: value
            for key, value in prior.items()
            if key
            not in {
                "compiled_retry_execution_readiness_document",
                "approved_compiled_retry_execution_readiness_document_sha256",
            }
        },
    )
    rendered = step221.render_entra_calling_client_msal_compiled_retry_execution_readiness_receipt(
        prior_receipt
    )
    assert (
        receipt.harness_readiness_document_sha256
        == hashlib.sha256(expected_document).hexdigest()
    )
    assert (
        receipt.compiled_retry_execution_readiness_receipt_sha256
        == hashlib.sha256(rendered.encode()).hexdigest()
    )


def test_all_receipt_fields_are_exhaustively_partitioned_and_tamper_checked():
    receipt = load()
    names = {field.name for field in fields(receipt)}
    bool_names = {
        field.name
        for field in fields(receipt)
        if type(getattr(receipt, field.name)) is bool
    }
    assert set(module._TRUE_FIELDS).isdisjoint(module._FALSE_FIELDS)
    assert set(module._TRUE_FIELDS) | set(module._FALSE_FIELDS) == bool_names
    assert set(module._STRING_FIELDS) <= names
    assert set(module._COUNT_FIELDS) <= names
    for name in module._TRUE_FIELDS:
        with pytest.raises(ValueError):
            unsafe_replace(receipt, **{name: False}).__post_init__()
    for name in module._FALSE_FIELDS:
        with pytest.raises(ValueError):
            unsafe_replace(receipt, **{name: True}).__post_init__()


@pytest.mark.parametrize("name", module._COUNT_FIELDS)
def test_counts_require_exact_int_and_exact_value(name):
    receipt = load()
    for invalid in (True, -1, getattr(receipt, name) + 1):
        with pytest.raises(ValueError):
            unsafe_replace(receipt, **{name: invalid}).__post_init__()


def test_all_digest_fields_require_lowercase_sha256():
    receipt = load()
    digest_names = [
        field.name for field in fields(receipt) if field.name.endswith("_sha256")
    ]
    assert len(digest_names) >= 10
    for name in digest_names:
        with pytest.raises(ValueError):
            unsafe_replace(receipt, **{name: "G" * 64}).__post_init__()


@pytest.mark.parametrize(
    ("name", "invalid"),
    [
        ("receipt_type", "wrong"),
        ("source", "wrong"),
        ("validation_scope", "wrong"),
        ("harness_profile", "wrong"),
        ("readiness_status", "wrong"),
        ("harness_file_name", "wrong"),
        ("compiled_scope_finding", "wrong"),
        ("schema_version", True),
    ],
)
def test_receipt_public_constants_are_exact(name, invalid):
    receipt = load()
    with pytest.raises(ValueError):
        unsafe_replace(receipt, **{name: invalid}).__post_init__()


def test_renderer_is_canonical_and_revalidates_receipt():
    receipt = load()
    rendered = (
        render_entra_calling_client_msal_compiled_retry_harness_readiness_receipt(
            receipt
        )
    )
    assert rendered == json.dumps(
        json.loads(rendered), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    with pytest.raises(TypeError):
        render_entra_calling_client_msal_compiled_retry_harness_readiness_receipt({})
    with pytest.raises(ValueError):
        render_entra_calling_client_msal_compiled_retry_harness_readiness_receipt(
            unsafe_replace(receipt, candidate_selected=True)
        )


@pytest.mark.parametrize("control", [KeyboardInterrupt, SystemExit])
def test_control_flow_is_sanitized_and_preserved(monkeypatch, control):
    def fail(**_kwargs):
        raise BaseExceptionGroup(
            "group-secret",
            [ValueError("child-secret"), control("control-secret")],
        )

    monkeypatch.setattr(
        module,
        "load_entra_calling_client_msal_compiled_retry_execution_readiness",
        fail,
    )
    with pytest.raises(control) as caught:
        load()
    material = exception_material(caught.value)
    assert "group-secret" not in material
    assert "child-secret" not in material
    assert "control-secret" not in material


def test_generic_exception_graph_is_detached_and_secret_free(monkeypatch):
    secret = "sensitive-step222-evidence"

    def fail(**_kwargs):
        try:
            raise ValueError(secret)
        except ValueError as inner:
            raise RuntimeError(secret) from inner

    monkeypatch.setattr(
        module,
        "load_entra_calling_client_msal_compiled_retry_execution_readiness",
        fail,
    )
    with pytest.raises(
        EntraCallingClientMSALCompiledRetryHarnessReadinessError
    ) as caught:
        load()
    assert secret not in exception_material(caught.value)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_harness_has_exact_frozen_scenario_matrix_and_no_real_target():
    text = HARNESS.decode()
    literal_scenarios = {
        "transport_failure_then_success",
        "two_transport_failures",
        "oauth_error_no_retry",
        "abort_no_retry",
        "non_token_transport_failure",
        "concurrent_isolation",
        "telemetry_and_request_equivalence",
    }
    assert {
        name for name in literal_scenarios if f'"{name}"' in text
    } == literal_scenarios
    assert "for (const status of [400, 429, 500])" in text
    assert "`http_${status}_no_retry`" in text
    assert "login.microsoftonline.com" not in text
    assert "graph.microsoft.com" not in text
    assert "example.com" not in text
    assert ".invalid" in text
    assert "child_process" not in text
    assert "node:net" not in text
    assert "node:https" not in text


def test_module_has_unique_fields_safe_imports_and_no_io_primitives():
    source = inspect.getsource(module)
    tree = ast.parse(source)
    receipt = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "EntraCallingClientMSALCompiledRetryHarnessReadinessReceipt"
    )
    names = [
        node.target.id
        for node in receipt.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    ]
    assert len(names) == len(set(names)) == len(fields(load()))
    imports = {
        alias.name.split(".")[0]
        for node in tree.body
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert imports <= {"hashlib", "json"}
    forbidden = {
        "open(",
        "Path(",
        "socket",
        "requests",
        "urllib",
        "subprocess",
        "os.environ",
    }
    assert not any(item in source for item in forbidden)
