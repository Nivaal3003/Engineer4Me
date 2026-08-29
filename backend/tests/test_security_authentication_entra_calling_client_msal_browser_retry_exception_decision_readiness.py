from __future__ import annotations

import json
from builtins import BaseExceptionGroup
from dataclasses import fields, replace

import pytest

import app.security.authentication_entra_calling_client_msal_browser_retry_exception_decision_readiness as module
from app.security.authentication_entra_calling_client_msal_browser_retry_exception_decision_readiness import (
    EntraCallingClientMSALRetryExceptionDecisionReadinessError,
    EntraCallingClientMSALRetryExceptionDecisionReadinessReceipt,
    load_entra_calling_client_msal_retry_exception_decision_readiness,
    render_entra_calling_client_msal_retry_exception_decision_readiness_receipt,
)


def _document(**updates: object) -> bytes:
    value: dict[str, object] = {
        "document_type": module.DOCUMENT_TYPE,
        "schema_version": 1,
        "source": module.SOURCE,
        "approved_step223_package_manifest_sha256": module.STEP223_PACKAGE_MANIFEST_SHA256,
        "decision_profile": module.PROFILE,
    }
    value.update(updates)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _receipt() -> EntraCallingClientMSALRetryExceptionDecisionReadinessReceipt:
    return load_entra_calling_client_msal_retry_exception_decision_readiness(
        _document()
    )


def test_valid_document_returns_fail_closed_receipt() -> None:
    receipt = _receipt()
    assert receipt.readiness_status == module.STATUS
    assert receipt.compiled_occurrence_file_count == 4
    assert receipt.compiled_real_invocation_count == 1
    assert receipt.compiled_implementation_count == 1
    assert receipt.compiled_stub_count == 1
    assert receipt.compiled_interface_count == 1
    assert receipt.real_invocation_uses_token_endpoint_parameter_declared is True
    assert receipt.implementation_remains_url_agnostic is True
    assert receipt.retry_exception_approved is False
    assert receipt.library_compatibility_approved is False
    assert receipt.package_selection_approved is False


def test_exact_reviewed_compiled_identities_are_bound() -> None:
    receipt = _receipt()
    assert (
        receipt.fetch_client_sha256
        == "abf75690801b45b64347873bb5483774aab1b70f1cf261021aa4e6b5181e9704"
    )
    assert (
        receipt.token_call_site_sha256
        == "fbfdf312c1553f87e721fd444814fe81640774b0b0ffa71f607d31c158072b63"
    )
    assert (
        receipt.client_configuration_stub_sha256
        == "ee30e9c1c7d4e3fe92c76eb35364f45ecb6f257c3f01c058e81c9748a28eba19"
    )
    assert (
        receipt.network_interface_sha256
        == "24f42ae4d9ebe378d695531822ff50806be7f5bba27359760b73ab6f4cf083e1"
    )
    assert receipt.fetch_client_bytes == 5_560
    assert receipt.token_call_site_bytes == 6_019
    assert receipt.client_configuration_stub_bytes == 4_404
    assert receipt.network_interface_bytes == 743


def test_retry_and_response_loss_boundaries_remain_exact() -> None:
    receipt = _receipt()
    assert receipt.maximum_retry_count == 1
    assert receipt.maximum_attempt_count == 2
    assert receipt.backoff_milliseconds == 100
    assert receipt.step216_zero_retry_requirement_preserved is True
    assert receipt.lost_response_code_consumption_ambiguity_preserved is True
    assert receipt.explicit_risk_decision_required is True


def test_no_live_or_application_claim_is_made() -> None:
    receipt = _receipt()
    names = (
        "step223_rendered_receipt_accepted_as_provenance",
        "artifact_bytes_loaded_or_scanned",
        "registry_or_network_io_performed",
        "browser_or_node_execution_performed",
        "real_oauth_values_processed",
        "application_integration_import_graph_checked",
        "application_network_client_override_checked",
        "source_to_distribution_reproducibility_checked",
        "package_advisories_checked",
        "registry_freshness_checked",
        "retry_exception_approved",
        "library_compatibility_approved",
        "package_selection_approved",
        "dependency_installed_or_locked",
        "application_configuration_mutation_performed",
        "application_activation_performed",
        "runtime_pkce_or_token_exchange_executed",
    )
    assert all(getattr(receipt, name) is False for name in names)


def test_document_digest_is_canonical_and_not_raw_format_dependent() -> None:
    pretty = json.dumps(json.loads(_document()), indent=2).encode()
    assert (
        load_entra_calling_client_msal_retry_exception_decision_readiness(
            pretty
        ).decision_document_sha256
        == _receipt().decision_document_sha256
    )


def test_domain_hashes_are_unique_lowercase_sha256() -> None:
    receipt = _receipt()
    values = {
        receipt.call_site_inventory_sha256,
        receipt.confinement_finding_sha256,
        receipt.response_loss_risk_sha256,
        receipt.fail_closed_decision_sha256,
    }
    assert len(values) == 4
    assert all(len(value) == 64 and value == value.lower() for value in values)


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"document_type": "wrong"}, "validation failed"),
        ({"schema_version": 2}, "validation failed"),
        ({"source": "wrong"}, "validation failed"),
        ({"decision_profile": "wrong"}, "validation failed"),
        ({"approved_step223_package_manifest_sha256": "0" * 64}, "validation failed"),
        ({"extra": True}, "validation failed"),
    ],
)
def test_document_semantic_tampering_is_rejected(
    update: dict[str, object], message: str
) -> None:
    with pytest.raises(
        EntraCallingClientMSALRetryExceptionDecisionReadinessError, match=message
    ):
        load_entra_calling_client_msal_retry_exception_decision_readiness(
            _document(**update)
        )


@pytest.mark.parametrize("value", [None, "text", bytearray(b"{}"), memoryview(b"{}")])
def test_public_input_requires_exact_bytes(value: object) -> None:
    with pytest.raises(TypeError, match="input is invalid"):
        load_entra_calling_client_msal_retry_exception_decision_readiness(value)


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b"{",
        b"[]",
        b"\xff",
        b'{"schema_version":1,"schema_version":1}',
        b"{" + (b" " * module.MAX_DOCUMENT_BYTES) + b"}",
    ],
)
def test_malformed_documents_are_sanitized(value: bytes) -> None:
    with pytest.raises(
        EntraCallingClientMSALRetryExceptionDecisionReadinessError,
        match="validation failed",
    ) as caught:
        load_entra_calling_client_msal_retry_exception_decision_readiness(value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    decoded = value.decode("utf-8", errors="ignore")
    if decoded:
        assert decoded not in repr(caught.value)


def test_excessive_json_depth_is_rejected() -> None:
    value = b"[" * 17 + b"0" + b"]" * 17
    with pytest.raises(EntraCallingClientMSALRetryExceptionDecisionReadinessError):
        load_entra_calling_client_msal_retry_exception_decision_readiness(value)


def test_keyboard_interrupt_and_system_exit_are_preserved_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for error_type, expected in (
        (KeyboardInterrupt, "interrupted"),
        (SystemExit, "terminated"),
    ):

        def fail(_: object, exception: type[BaseException] = error_type) -> object:
            raise exception("secret-value")

        monkeypatch.setattr(module, "_load_internal", fail)
        with pytest.raises(error_type, match=expected) as caught:
            load_entra_calling_client_msal_retry_exception_decision_readiness(
                b"secret-document"
            )
        assert "secret" not in repr(caught.value)


def test_exception_group_control_flow_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_: object) -> object:
        raise BaseExceptionGroup(
            "secret-group",
            [SystemExit("secret-exit"), KeyboardInterrupt("secret-interrupt")],
        )

    monkeypatch.setattr(module, "_load_internal", fail)
    with pytest.raises(KeyboardInterrupt, match="interrupted") as caught:
        load_entra_calling_client_msal_retry_exception_decision_readiness(
            b"secret-document"
        )
    assert "secret" not in repr(caught.value)


def test_renderer_is_canonical_and_complete() -> None:
    receipt = _receipt()
    rendered = (
        render_entra_calling_client_msal_retry_exception_decision_readiness_receipt(
            receipt
        )
    )
    value = json.loads(rendered)
    assert list(value) == sorted(value)
    assert set(value) == {field.name for field in fields(receipt)}
    assert " " not in rendered
    assert "\n" not in rendered


@pytest.mark.parametrize("value", [None, {}, object()])
def test_renderer_requires_exact_receipt(value: object) -> None:
    with pytest.raises(TypeError, match="exact MSAL retry decision"):
        render_entra_calling_client_msal_retry_exception_decision_readiness_receipt(
            value
        )  # type: ignore[arg-type]


def _invalid_for(name: str, value: object) -> object:
    if type(value) is bool:
        return not value
    if type(value) is int:
        return True
    if name.endswith("sha256"):
        return "z" * 64
    return "tampered"


def test_every_receipt_field_is_guarded_by_post_init() -> None:
    receipt = _receipt()
    for field in fields(receipt):
        tampered = object.__new__(type(receipt))
        for candidate in fields(receipt):
            value = getattr(receipt, candidate.name)
            if candidate.name == field.name:
                value = _invalid_for(candidate.name, value)
            object.__setattr__(tampered, candidate.name, value)
        with pytest.raises(ValueError):
            tampered.__post_init__()


def test_renderer_revalidates_receipt() -> None:
    receipt = _receipt()
    with pytest.raises(ValueError):
        render_entra_calling_client_msal_retry_exception_decision_readiness_receipt(
            replace(receipt, retry_exception_approved=True)
        )
