from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest
from pydantic import ValidationError

from app.security.authentication_entra_calling_client_msal_browser_frontend_host_inventory_loader import (
    APPROVED_BRANCH,
    APPROVED_HEAD,
    EVIDENCE_PROVENANCE,
    EVIDENCE_TYPE,
    SCHEMA_VERSION as EVIDENCE_SCHEMA_VERSION,
    EntraCallingClientMSALFrontendHostInventoryEvidence,
    EntraCallingClientMSALFrontendHostInventoryFileEvidence,
)
from app.security.authentication_entra_calling_client_msal_browser_frontend_host_inventory_probe import (
    DOCUMENT_TYPE,
    MAX_DOCUMENT_BYTES,
    PROFILE,
    RECEIPT_TYPE,
    SCHEMA_VERSION,
    SCOPE,
    SOURCE,
    STATUS,
    STEP231_ACCEPTED_STATE_MANIFEST_SHA256,
    STEP231_DEPENDENCY_LOCK_READINESS_SHA256,
    STEP231_PACKAGE_MANIFEST_SHA256,
    ZERO_RETRY_NETWORK_CLIENT_SHA256,
    EntraCallingClientMSALFrontendHostInventoryProbeError,
    EntraCallingClientMSALFrontendHostInventoryProofDocument,
    EntraCallingClientMSALFrontendHostInventoryProofReceipt,
    prove_entra_calling_client_msal_frontend_host_inventory,
    render_entra_calling_client_msal_frontend_host_inventory_receipt,
)


def _mapping() -> dict[str, object]:
    return {
        "document_type": DOCUMENT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE,
        "approved_step231_package_manifest_sha256": (
            STEP231_PACKAGE_MANIFEST_SHA256
        ),
        "approved_step231_dependency_lock_readiness_sha256": (
            STEP231_DEPENDENCY_LOCK_READINESS_SHA256
        ),
        "approved_step231_accepted_state_manifest_sha256": (
            STEP231_ACCEPTED_STATE_MANIFEST_SHA256
        ),
        "approved_zero_retry_network_client_sha256": (
            ZERO_RETRY_NETWORK_CLIENT_SHA256
        ),
        "approved_branch": APPROVED_BRANCH,
        "approved_head": APPROVED_HEAD,
        "inventory_profile": PROFILE,
    }


def _document(mapping: dict[str, object] | None = None) -> bytes:
    return json.dumps(
        _mapping() if mapping is None else mapping,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _file(
    path: str,
    role: str,
    size_bytes: int,
    sha256: str,
) -> EntraCallingClientMSALFrontendHostInventoryFileEvidence:
    return EntraCallingClientMSALFrontendHostInventoryFileEvidence(
        path=path,
        role=role,  # type: ignore[arg-type]
        size_bytes=size_bytes,
        sha256=sha256,
    )


def _evidence(
    *, host: bool = False
) -> EntraCallingClientMSALFrontendHostInventoryEvidence:
    roots = ("frontend",) if host else ()
    files = (
        (
            _file("frontend/package.json", "package_manifest", 120, "1" * 64),
            _file(
                "frontend/package-lock.json",
                "dependency_lock",
                240,
                "2" * 64,
            ),
        )
        if host
        else ()
    )
    return EntraCallingClientMSALFrontendHostInventoryEvidence(
        evidence_type=EVIDENCE_TYPE,
        schema_version=EVIDENCE_SCHEMA_VERSION,
        provenance=EVIDENCE_PROVENANCE,
        branch=APPROVED_BRANCH,
        head=APPROVED_HEAD,
        repository_root_sha256="3" * 64,
        tracked_path_count=300,
        candidate_roots=roots,
        package_manager="npm" if host else "none",
        lockfile_kind="package-lock.json" if host else "none",
        files=files,
        git_tracked_projection_complete=True,
        untracked_content_included=False,
        symlink_or_reparse_point_observed=False,
        submodule_observed=False,
        nested_repository_observed=False,
        git_worktree_indirection_observed=False,
        case_collision_observed=False,
        environment_file_content_read=False,
        secret_value_collected=False,
        live_repository_accessed=False,
        filesystem_io_performed=False,
        git_process_started=False,
        package_manager_process_started=False,
        network_io_performed=False,
        repository_mutation_performed=False,
    )


def _receipt(
    *, host: bool = False
) -> EntraCallingClientMSALFrontendHostInventoryProofReceipt:
    return prove_entra_calling_client_msal_frontend_host_inventory(
        _document(), _evidence(host=host)
    )


def test_constants_bind_exact_step231_and_zero_retry_identities() -> None:
    assert DOCUMENT_TYPE.endswith("frontend_host_inventory_proof")
    assert RECEIPT_TYPE == DOCUMENT_TYPE + "_receipt"
    assert SCOPE == "exact_step231_state_and_bounded_synthetic_frontend_host_inventory"
    assert STATUS == "synthetic_inventory_validated_live_frontend_host_undetermined"
    assert STEP231_PACKAGE_MANIFEST_SHA256 == (
        "d23f9bb5b1ee336403251404c65c57b5d854c889f5368a1a460e88139a5c8873"
    )
    assert STEP231_DEPENDENCY_LOCK_READINESS_SHA256 == (
        "25a22ccba2a5aa6f656fb7a3629d81173af5f7ecfe9daecefec2581cde0b8119"
    )
    assert STEP231_ACCEPTED_STATE_MANIFEST_SHA256 == (
        "9ef658e4a2af573ff0a6e42118ec9313686f3abb7e847efdb43df8598bc186ba"
    )
    assert ZERO_RETRY_NETWORK_CLIENT_SHA256 == (
        "c36e718f4893959be94e4b51f6cfa76e0ac34da7c310151d23e446a3794f7a73"
    )


def test_exact_document_model_accepts_only_approved_mapping() -> None:
    model = EntraCallingClientMSALFrontendHostInventoryProofDocument.model_validate(
        _mapping()
    )
    assert model.model_dump(mode="json") == _mapping()


@pytest.mark.parametrize("value", [None, [], "x", 1, True])
def test_document_model_rejects_non_object(value: object) -> None:
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendHostInventoryProofDocument.model_validate(value)


@pytest.mark.parametrize("name", sorted(_mapping()))
def test_document_model_rejects_missing_key(name: str) -> None:
    value = _mapping()
    del value[name]
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendHostInventoryProofDocument.model_validate(value)


def test_document_model_rejects_extra_key() -> None:
    value = _mapping()
    value["unexpected"] = False
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendHostInventoryProofDocument.model_validate(value)


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        ("document_type", 1),
        ("schema_version", True),
        ("source", None),
        ("approved_step231_package_manifest_sha256", b"x"),
        ("approved_step231_dependency_lock_readiness_sha256", []),
        ("approved_step231_accepted_state_manifest_sha256", 1),
        ("approved_zero_retry_network_client_sha256", False),
        ("approved_branch", 1),
        ("approved_head", None),
        ("inventory_profile", 1),
    ],
)
def test_document_model_rejects_wrong_wire_type(
    name: str, replacement: object
) -> None:
    value = _mapping()
    value[name] = replacement
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendHostInventoryProofDocument.model_validate(value)


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        ("document_type", DOCUMENT_TYPE + "_other"),
        ("schema_version", 2),
        ("source", SOURCE + "_other"),
        ("approved_step231_package_manifest_sha256", "0" * 64),
        ("approved_step231_dependency_lock_readiness_sha256", "0" * 64),
        ("approved_step231_accepted_state_manifest_sha256", "0" * 64),
        ("approved_zero_retry_network_client_sha256", "0" * 64),
        ("approved_branch", "main"),
        ("approved_head", "0" * 40),
        ("inventory_profile", PROFILE + "_other"),
    ],
)
def test_document_model_rejects_wrong_exact_value(
    name: str, replacement: object
) -> None:
    value = _mapping()
    value[name] = replacement
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendHostInventoryProofDocument.model_validate(value)


def test_probe_validates_synthetic_absent_candidate_without_live_claim() -> None:
    receipt = _receipt()
    assert receipt.proof_status == STATUS
    assert receipt.synthetic_candidate_root_count == 0
    assert receipt.synthetic_inventory_file_count == 0
    assert receipt.synthetic_package_manager == "none"
    assert receipt.synthetic_lockfile_kind == "none"
    assert receipt.synthetic_evidence_validated is True
    assert receipt.live_repository_inventory_performed is False
    assert receipt.live_frontend_host_status_determined is False
    assert receipt.live_candidate_frontend_host_detected is False


def test_probe_accepts_synthetic_candidate_for_classification_only() -> None:
    receipt = _receipt(host=True)
    assert receipt.synthetic_candidate_root_count == 1
    assert receipt.synthetic_inventory_file_count == 2
    assert receipt.synthetic_inventory_total_bytes == 360
    assert receipt.synthetic_package_manager == "npm"
    assert receipt.synthetic_lockfile_kind == "package-lock.json"
    assert receipt.live_frontend_host_status_determined is False
    assert receipt.candidate_frontend_host_selected is False


def test_probe_binds_all_required_upstream_identities() -> None:
    receipt = _receipt()
    assert receipt.approved_branch == APPROVED_BRANCH
    assert receipt.approved_head == APPROVED_HEAD
    assert receipt.approved_step231_package_manifest_sha256 == (
        STEP231_PACKAGE_MANIFEST_SHA256
    )
    assert receipt.approved_step231_dependency_lock_readiness_sha256 == (
        STEP231_DEPENDENCY_LOCK_READINESS_SHA256
    )
    assert receipt.approved_step231_accepted_state_manifest_sha256 == (
        STEP231_ACCEPTED_STATE_MANIFEST_SHA256
    )
    assert receipt.approved_zero_retry_network_client_sha256 == (
        ZERO_RETRY_NETWORK_CLIENT_SHA256
    )


def test_probe_keeps_every_mutation_network_and_runtime_fact_false() -> None:
    receipt = _receipt(host=True)
    names = (
        "candidate_frontend_host_selected",
        "package_manager_selected",
        "package_manager_executed",
        "registry_access_performed",
        "package_manifest_created_or_modified",
        "lockfile_created_or_modified",
        "dependency_installed",
        "frontend_source_modified",
        "browser_bundle_built",
        "browser_runtime_executed",
        "real_oauth_values_processed",
        "application_configuration_modified",
        "application_activated",
        "operational_write_performed",
    )
    assert all(getattr(receipt, name) is False for name in names)


def test_probe_preserves_prior_policy_boundaries() -> None:
    receipt = _receipt()
    assert receipt.step216_zero_retry_policy_preserved is True
    assert receipt.step225_default_retry_rejection_preserved is True
    assert receipt.step230_container_proof_boundary_preserved is True
    assert receipt.step231_dependency_lock_plan_preserved is True
    assert receipt.successor_live_inventory_required is True
    assert receipt.rendered_receipt_accepted_as_live_provenance is False


def test_document_digest_is_canonical_and_whitespace_independent() -> None:
    compact = _receipt()
    pretty = prove_entra_calling_client_msal_frontend_host_inventory(
        json.dumps(_mapping(), indent=2).encode(), _evidence()
    )
    canonical = json.dumps(
        _mapping(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert compact.proof_document_sha256 == hashlib.sha256(canonical).hexdigest()
    assert pretty.proof_document_sha256 == compact.proof_document_sha256


def test_projection_digests_are_deterministic_and_domain_separated() -> None:
    first = _receipt(host=True)
    second = _receipt(host=True)
    names = (
        "evidence_projection_sha256",
        "repository_identity_projection_sha256",
        "candidate_projection_sha256",
        "file_inventory_projection_sha256",
        "policy_limits_sha256",
    )
    assert all(getattr(first, name) == getattr(second, name) for name in names)
    assert len({getattr(first, name) for name in names}) == len(names)


@pytest.mark.parametrize("value", [None, "x", bytearray(b"{}"), memoryview(b"{}")])
def test_probe_rejects_non_exact_document_bytes(value: object) -> None:
    with pytest.raises(
        EntraCallingClientMSALFrontendHostInventoryProbeError,
        match="frontend-host inventory proof validation failed",
    ):
        prove_entra_calling_client_msal_frontend_host_inventory(value, _evidence())  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [b"", b"{", b"[]", b"null", b"true"])
def test_probe_rejects_invalid_or_non_object_json(value: bytes) -> None:
    with pytest.raises(EntraCallingClientMSALFrontendHostInventoryProbeError):
        prove_entra_calling_client_msal_frontend_host_inventory(value, _evidence())


def test_probe_rejects_oversized_document() -> None:
    with pytest.raises(EntraCallingClientMSALFrontendHostInventoryProbeError):
        prove_entra_calling_client_msal_frontend_host_inventory(
            b" " * (MAX_DOCUMENT_BYTES + 1), _evidence()
        )


def test_probe_rejects_duplicate_json_key() -> None:
    duplicate = _document()[:-1] + b',"approved_branch":"feature/phase-8"}'
    with pytest.raises(EntraCallingClientMSALFrontendHostInventoryProbeError):
        prove_entra_calling_client_msal_frontend_host_inventory(
            duplicate, _evidence()
        )


def test_probe_resanitizes_invalid_or_tampered_evidence() -> None:
    evidence = _evidence()
    object.__setattr__(evidence, "secret_value_collected", True)
    with pytest.raises(
        EntraCallingClientMSALFrontendHostInventoryProbeError,
        match="frontend-host inventory proof validation failed",
    ) as captured:
        prove_entra_calling_client_msal_frontend_host_inventory(
            _document(), evidence
        )
    assert captured.value.__cause__ is not None
    assert "secret" not in str(captured.value)


def test_receipt_is_frozen_and_slotted() -> None:
    receipt = _receipt()
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        receipt.application_activated = True  # type: ignore[misc]
    assert not hasattr(receipt, "__dict__")


def test_renderer_is_canonical_deterministic_and_declared_only() -> None:
    receipt = _receipt(host=True)
    first = render_entra_calling_client_msal_frontend_host_inventory_receipt(receipt)
    second = render_entra_calling_client_msal_frontend_host_inventory_receipt(receipt)
    assert first == second
    parsed = json.loads(first)
    assert first == json.dumps(
        parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert set(parsed) == {
        field.name
        for field in dataclasses.fields(
            EntraCallingClientMSALFrontendHostInventoryProofReceipt
        )
    }
    assert "frontend/package.json" not in first.decode()


@pytest.mark.parametrize("value", [None, {}, object()])
def test_renderer_rejects_non_exact_receipt(value: object) -> None:
    with pytest.raises(TypeError, match="exact frontend-host inventory proof receipt"):
        render_entra_calling_client_msal_frontend_host_inventory_receipt(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("receipt_type", "wrong"),
        ("approved_branch", "main"),
        ("approved_step231_package_manifest_sha256", "0" * 64),
        ("evidence_projection_sha256", "x"),
        ("synthetic_candidate_root_count", -1),
        ("synthetic_evidence_validated", False),
        ("live_repository_inventory_performed", True),
        ("candidate_frontend_host_selected", True),
        ("application_activated", True),
    ],
)
def test_receipt_rejects_constant_digest_count_or_boolean_tampering(
    field: str, replacement: object
) -> None:
    receipt = _receipt()
    values = {item.name: getattr(receipt, item.name) for item in dataclasses.fields(receipt)}
    values[field] = replacement
    with pytest.raises(ValueError):
        EntraCallingClientMSALFrontendHostInventoryProofReceipt(**values)


def test_rendered_receipt_omits_raw_paths_secrets_and_oauth_values() -> None:
    rendered = render_entra_calling_client_msal_frontend_host_inventory_receipt(
        _receipt(host=True)
    ).decode()
    for forbidden in (
        "frontend/package.json",
        "C:\\Users",
        "client_secret",
        "access_token",
        "refresh_token",
        "authorization_code",
    ):
        assert forbidden not in rendered
