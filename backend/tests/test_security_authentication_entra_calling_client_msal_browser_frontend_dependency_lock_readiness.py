from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest
from pydantic import ValidationError

from app.security.authentication_entra_calling_client_msal_browser_frontend_dependency_lock_readiness import (
    DOCUMENT_TYPE,
    INSTALL_COMMAND,
    LOCKFILE_NAME,
    LOCKFILE_VERSION,
    MSAL_BROWSER_PACKAGE,
    MSAL_BROWSER_VERSION,
    MSAL_COMMON_PACKAGE,
    MSAL_COMMON_VERSION,
    NETWORK_CLIENT_CONFIGURATION_SEAM,
    PACKAGE_MANAGER,
    RECEIPT_TYPE,
    SCHEMA_VERSION,
    SOURCE,
    STATUS,
    STEP230_PACKAGE_MANIFEST_SHA256,
    ZERO_RETRY_NETWORK_CLIENT_SHA256,
    EntraCallingClientMSALFrontendDependencyLockReadinessDocument,
    EntraCallingClientMSALFrontendDependencyLockReadinessError,
    EntraCallingClientMSALFrontendDependencyLockReadinessReceipt,
    load_entra_calling_client_msal_frontend_dependency_lock_readiness,
    render_entra_calling_client_msal_frontend_dependency_lock_readiness_receipt,
)


def _mapping() -> dict[str, object]:
    return {
        "document_type": DOCUMENT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE,
        "approved_step230_package_manifest_sha256": STEP230_PACKAGE_MANIFEST_SHA256,
        "approved_zero_retry_network_client_sha256": ZERO_RETRY_NETWORK_CLIENT_SHA256,
        "package_manager": PACKAGE_MANAGER,
        "lockfile_name": LOCKFILE_NAME,
        "lockfile_version": LOCKFILE_VERSION,
        "install_mode": INSTALL_COMMAND,
    }


def _document(mapping: dict[str, object] | None = None) -> bytes:
    return json.dumps(
        _mapping() if mapping is None else mapping,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _receipt() -> EntraCallingClientMSALFrontendDependencyLockReadinessReceipt:
    return load_entra_calling_client_msal_frontend_dependency_lock_readiness(_document())


def test_constants_are_exact() -> None:
    assert DOCUMENT_TYPE.endswith("frontend_dependency_lock_readiness")
    assert RECEIPT_TYPE == DOCUMENT_TYPE + "_receipt"
    assert SCHEMA_VERSION == 1
    assert PACKAGE_MANAGER == "npm"
    assert LOCKFILE_NAME == "package-lock.json"
    assert LOCKFILE_VERSION == 3
    assert INSTALL_COMMAND == (
        "npm ci --ignore-scripts --audit=false --fund=false --prefer-offline=false"
    )
    assert (MSAL_BROWSER_PACKAGE, MSAL_BROWSER_VERSION) == (
        "@azure/msal-browser",
        "5.18.0",
    )
    assert (MSAL_COMMON_PACKAGE, MSAL_COMMON_VERSION) == (
        "@azure/msal-common",
        "16.12.0",
    )
    assert NETWORK_CLIENT_CONFIGURATION_SEAM == "system.networkClient"
    assert len(STEP230_PACKAGE_MANIFEST_SHA256) == 64
    assert len(ZERO_RETRY_NETWORK_CLIENT_SHA256) == 64


def test_exact_document_model_accepts_only_the_approved_contract() -> None:
    model = EntraCallingClientMSALFrontendDependencyLockReadinessDocument.model_validate(
        _mapping()
    )
    assert model.model_dump(mode="json") == _mapping()


@pytest.mark.parametrize("value", [None, [], "x", 1, True])
def test_document_model_rejects_non_object(value: object) -> None:
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendDependencyLockReadinessDocument.model_validate(value)


@pytest.mark.parametrize("name", sorted(_mapping()))
def test_document_model_rejects_missing_key(name: str) -> None:
    value = _mapping()
    del value[name]
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendDependencyLockReadinessDocument.model_validate(value)


def test_document_model_rejects_extra_key() -> None:
    value = _mapping()
    value["unexpected"] = False
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendDependencyLockReadinessDocument.model_validate(value)


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        ("document_type", 1),
        ("schema_version", True),
        ("source", None),
        ("approved_step230_package_manifest_sha256", b"x" * 64),
        ("approved_zero_retry_network_client_sha256", ["x"]),
        ("package_manager", 1),
        ("lockfile_name", False),
        ("lockfile_version", "3"),
        ("install_mode", 1),
    ],
)
def test_document_model_rejects_wrong_exact_wire_type(
    name: str, replacement: object
) -> None:
    value = _mapping()
    value[name] = replacement
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendDependencyLockReadinessDocument.model_validate(value)


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        ("document_type", DOCUMENT_TYPE + "_other"),
        ("schema_version", 2),
        ("source", SOURCE + "_other"),
        ("approved_step230_package_manifest_sha256", "0" * 64),
        ("approved_zero_retry_network_client_sha256", "0" * 64),
        ("package_manager", "pnpm"),
        ("lockfile_name", "npm-shrinkwrap.json"),
        ("lockfile_version", 2),
        ("install_mode", "npm install"),
    ],
)
def test_document_model_rejects_wrong_exact_value(
    name: str, replacement: object
) -> None:
    value = _mapping()
    value[name] = replacement
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendDependencyLockReadinessDocument.model_validate(value)


def test_loader_returns_frozen_slotted_receipt() -> None:
    receipt = _receipt()
    assert dataclasses.is_dataclass(receipt)
    assert receipt.__dataclass_params__.frozen is True
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        receipt.package_selected = True  # type: ignore[misc]
    assert not hasattr(receipt, "__dict__")


def test_loader_binds_exact_dependency_plan() -> None:
    receipt = _receipt()
    assert receipt.receipt_type == RECEIPT_TYPE
    assert receipt.readiness_status == STATUS
    assert receipt.package_manager == PACKAGE_MANAGER
    assert receipt.lockfile_name == LOCKFILE_NAME
    assert receipt.lockfile_version == LOCKFILE_VERSION
    assert receipt.install_command == INSTALL_COMMAND
    assert receipt.msal_browser_package == MSAL_BROWSER_PACKAGE
    assert receipt.msal_browser_version == MSAL_BROWSER_VERSION
    assert receipt.msal_common_package == MSAL_COMMON_PACKAGE
    assert receipt.msal_common_version == MSAL_COMMON_VERSION
    assert receipt.approved_step230_package_manifest_sha256 == (
        STEP230_PACKAGE_MANIFEST_SHA256
    )


def test_loader_binds_exact_zero_retry_integration_plan() -> None:
    receipt = _receipt()
    assert receipt.network_client_configuration_seam == (
        NETWORK_CLIENT_CONFIGURATION_SEAM
    )
    assert receipt.approved_zero_retry_network_client_sha256 == (
        ZERO_RETRY_NETWORK_CLIENT_SHA256
    )
    assert receipt.zero_retry_network_client_digest_bound is True
    assert receipt.custom_network_client_configuration_required is True
    assert receipt.default_msal_network_client_forbidden is True
    assert receipt.exactly_one_network_client_instance_required is True
    assert receipt.token_endpoint_post_retry_forbidden is True


def test_loader_keeps_all_selection_install_and_activation_facts_false() -> None:
    receipt = _receipt()
    names = (
        "real_oauth_values_processed",
        "registry_access_performed",
        "package_selected",
        "dependency_installed",
        "lockfile_created_or_modified",
        "frontend_source_modified",
        "browser_bundle_built",
        "browser_runtime_executed",
        "application_configuration_modified",
        "application_activated",
        "operational_write_performed",
    )
    assert all(getattr(receipt, name) is False for name in names)


def test_loader_requires_successor_browser_proofs() -> None:
    receipt = _receipt()
    assert receipt.browser_bundle_import_graph_proof_required is True
    assert receipt.browser_cors_proof_required is True
    assert receipt.pkce_and_callback_journey_proof_required is True
    assert receipt.step216_zero_retry_policy_preserved is True
    assert receipt.step225_default_retry_rejection_preserved is True
    assert receipt.step230_container_proof_boundary_preserved is True


def test_document_digest_is_canonical_and_input_whitespace_independent() -> None:
    compact = _receipt()
    pretty = load_entra_calling_client_msal_frontend_dependency_lock_readiness(
        json.dumps(_mapping(), indent=2).encode()
    )
    canonical = json.dumps(
        _mapping(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert compact.readiness_document_sha256 == hashlib.sha256(canonical).hexdigest()
    assert pretty.readiness_document_sha256 == compact.readiness_document_sha256


def test_plan_digests_are_domain_separated() -> None:
    receipt = _receipt()
    assert receipt.dependency_plan_sha256 != receipt.integration_plan_sha256
    assert receipt.dependency_plan_sha256 != receipt.readiness_document_sha256
    assert receipt.integration_plan_sha256 != receipt.readiness_document_sha256


@pytest.mark.parametrize("value", [None, "x", bytearray(b"{}"), memoryview(b"{}")])
def test_loader_rejects_non_exact_bytes(value: object) -> None:
    with pytest.raises(
        EntraCallingClientMSALFrontendDependencyLockReadinessError,
        match="frontend dependency-lock readiness validation failed",
    ):
        load_entra_calling_client_msal_frontend_dependency_lock_readiness(value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [b"", b"{", b"[]", b"null", b"true"])
def test_loader_rejects_invalid_or_non_object_json(value: bytes) -> None:
    with pytest.raises(EntraCallingClientMSALFrontendDependencyLockReadinessError):
        load_entra_calling_client_msal_frontend_dependency_lock_readiness(value)


def test_loader_rejects_oversized_document() -> None:
    with pytest.raises(EntraCallingClientMSALFrontendDependencyLockReadinessError):
        load_entra_calling_client_msal_frontend_dependency_lock_readiness(
            b" " * 4097
        )


def test_loader_rejects_duplicate_json_key() -> None:
    duplicate = _document()[:-1] + b',"package_manager":"npm"}'
    with pytest.raises(EntraCallingClientMSALFrontendDependencyLockReadinessError):
        load_entra_calling_client_msal_frontend_dependency_lock_readiness(duplicate)


def test_loader_error_is_sanitized_and_preserves_cause() -> None:
    value = _mapping()
    value["approved_step230_package_manifest_sha256"] = "secret-non-digest"
    with pytest.raises(
        EntraCallingClientMSALFrontendDependencyLockReadinessError
    ) as captured:
        load_entra_calling_client_msal_frontend_dependency_lock_readiness(
            _document(value)
        )
    assert str(captured.value) == (
        "frontend dependency-lock readiness validation failed"
    )
    assert captured.value.__cause__ is not None
    assert "secret-non-digest" not in str(captured.value)


def test_renderer_is_canonical_deterministic_and_round_trippable() -> None:
    receipt = _receipt()
    first = render_entra_calling_client_msal_frontend_dependency_lock_readiness_receipt(
        receipt
    )
    second = render_entra_calling_client_msal_frontend_dependency_lock_readiness_receipt(
        receipt
    )
    assert first == second
    assert first == json.dumps(
        json.loads(first),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    assert json.loads(first)["package_selected"] is False
    assert json.loads(first)["default_msal_network_client_forbidden"] is True


@pytest.mark.parametrize("value", [None, {}, object()])
def test_renderer_rejects_non_exact_receipt(value: object) -> None:
    with pytest.raises(TypeError, match="exact frontend dependency-lock receipt"):
        render_entra_calling_client_msal_frontend_dependency_lock_readiness_receipt(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("receipt_type", "wrong"),
        ("package_manager", "pnpm"),
        ("lockfile_version", 2),
        ("msal_browser_version", "5.18.1"),
        ("approved_zero_retry_network_client_sha256", "0" * 64),
        ("dependency_plan_sha256", "x"),
        ("exact_versions_required", False),
        ("package_selected", True),
        ("application_activated", True),
    ],
)
def test_receipt_rejects_constant_digest_or_boolean_tampering(
    field: str, replacement: object
) -> None:
    values = {
        item.name: getattr(_receipt(), item.name)
        for item in dataclasses.fields(
            EntraCallingClientMSALFrontendDependencyLockReadinessReceipt
        )
    }
    values[field] = replacement
    with pytest.raises(ValueError):
        EntraCallingClientMSALFrontendDependencyLockReadinessReceipt(**values)


def test_rendered_receipt_contains_only_declared_fields() -> None:
    receipt = _receipt()
    rendered = json.loads(
        render_entra_calling_client_msal_frontend_dependency_lock_readiness_receipt(
            receipt
        )
    )
    assert set(rendered) == {
        field.name
        for field in dataclasses.fields(
            EntraCallingClientMSALFrontendDependencyLockReadinessReceipt
        )
    }
    serialized = json.dumps(rendered)
    for forbidden in ("client_secret", "access_token", "refresh_token", "authorization_code"):
        assert forbidden not in serialized
