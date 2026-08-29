from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest
from pydantic import ValidationError

from app.security.authentication_entra_calling_client_msal_browser_frontend_host_live_inventory_loader import (
    ACCEPTED_OVERLAY_PATH_COUNT,
    APPROVED_BRANCH,
    APPROVED_HEAD,
    EVIDENCE_PROVENANCE,
    EVIDENCE_TYPE,
    SCHEMA_VERSION as EVIDENCE_SCHEMA_VERSION,
    STEP232_ACCEPTED_STATE_MANIFEST_SHA256,
    STEP232_INVENTORY_LOADER_SHA256,
    STEP232_INVENTORY_PROBE_SHA256,
    STEP232_PACKAGE_MANIFEST_SHA256,
)
from app.security.authentication_entra_calling_client_msal_browser_frontend_host_live_inventory_probe import (
    DOCUMENT_TYPE,
    MAX_PROOF_DOCUMENT_BYTES,
    PROFILE,
    RECEIPT_TYPE,
    SCHEMA_VERSION,
    SCOPE,
    SOURCE,
    STATUS_NO_CANDIDATE,
    STATUS_SINGLE_CANDIDATE,
    EntraCallingClientMSALFrontendHostLiveInventoryProbeError,
    EntraCallingClientMSALFrontendHostLiveInventoryProofDocument,
    EntraCallingClientMSALFrontendHostLiveInventoryProofReceipt,
    prove_entra_calling_client_msal_frontend_host_live_inventory,
    render_entra_calling_client_msal_frontend_host_live_inventory_receipt,
)


def _proof_mapping() -> dict[str, object]:
    return {
        "document_type": DOCUMENT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE,
        "approved_step232_package_manifest_sha256": STEP232_PACKAGE_MANIFEST_SHA256,
        "approved_step232_accepted_state_manifest_sha256": (
            STEP232_ACCEPTED_STATE_MANIFEST_SHA256
        ),
        "approved_step232_inventory_loader_sha256": STEP232_INVENTORY_LOADER_SHA256,
        "approved_step232_inventory_probe_sha256": STEP232_INVENTORY_PROBE_SHA256,
        "approved_branch": APPROVED_BRANCH,
        "approved_head": APPROVED_HEAD,
        "inventory_profile": PROFILE,
    }


def _proof_document(mapping: dict[str, object] | None = None) -> bytes:
    return json.dumps(
        _proof_mapping() if mapping is None else mapping,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _evidence_mapping(*, host: bool = False) -> dict[str, object]:
    head_path = "frontend/package.json" if host else "README.md"
    return {
        "evidence_type": EVIDENCE_TYPE,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "provenance": EVIDENCE_PROVENANCE,
        "branch": APPROVED_BRANCH,
        "head": APPROVED_HEAD,
        "head_tree_object_id": "1" * 40,
        "step232_package_manifest_sha256": STEP232_PACKAGE_MANIFEST_SHA256,
        "accepted_step232_state_manifest_sha256": (
            STEP232_ACCEPTED_STATE_MANIFEST_SHA256
        ),
        "step232_inventory_loader_sha256": STEP232_INVENTORY_LOADER_SHA256,
        "step232_inventory_probe_sha256": STEP232_INVENTORY_PROBE_SHA256,
        "git_executable_sha256": "2" * 64,
        "working_tree_status_before_sha256": "3" * 64,
        "working_tree_status_after_sha256": "3" * 64,
        "accepted_overlay_path_count": ACCEPTED_OVERLAY_PATH_COUNT,
        "accepted_overlay_projection_sha256": (
            STEP232_ACCEPTED_STATE_MANIFEST_SHA256
        ),
        "accepted_overlay_paths_overlapping_head": 0,
        "combined_source_path_count": ACCEPTED_OVERLAY_PATH_COUNT + 1,
        "installer_asserted_combined_source_path_projection_sha256": "4" * 64,
        "head_entries": [
            {
                "mode": "100644",
                "object_type": "blob",
                "object_id": "5" * 40,
                "path": head_path,
            }
        ],
        "markers": (
            [
                {
                    "source_domain": "git_head",
                    "path": "frontend/package.json",
                    "role": "package_manifest",
                    "size_bytes": 120,
                    "sha256": "6" * 64,
                    "object_id": "5" * 40,
                }
            ]
            if host
            else []
        ),
        "live_repository_accessed": True,
        "filesystem_io_performed": True,
        "git_process_started": True,
        "git_head_projection_complete": True,
        "accepted_overlay_projection_complete": True,
        "before_after_accepted_source_projection_identical": True,
        "git_object_bytes_read_only_for_allowlisted_markers": True,
        "git_status_worktree_enumeration_performed": True,
        "working_tree_marker_content_read": False,
        "tracked_git_symlink_or_gitlink_observed": False,
        "package_manager_process_started": False,
        "remote_git_or_package_network_operation_requested": False,
        "inventory_accepted_source_projection_changed": False,
    }


def _evidence_document(*, host: bool = False) -> bytes:
    return json.dumps(
        _evidence_mapping(host=host), sort_keys=True, separators=(",", ":")
    ).encode()


def _receipt(
    *, host: bool = False
) -> EntraCallingClientMSALFrontendHostLiveInventoryProofReceipt:
    return prove_entra_calling_client_msal_frontend_host_live_inventory(
        _proof_document(), _evidence_document(host=host)
    )


def test_constants_and_document_bind_exact_step232_identities() -> None:
    assert DOCUMENT_TYPE.endswith("frontend_host_live_inventory_proof")
    assert RECEIPT_TYPE == DOCUMENT_TYPE + "_receipt"
    assert SCOPE == "exact_step232_state_plus_accepted_head_git_object_inventory"
    assert STATUS_NO_CANDIDATE.endswith("no_package_manifest_candidate_in_accepted_source")
    assert STATUS_SINGLE_CANDIDATE.endswith("single_unselected_package_manifest_candidate")
    assert PROFILE == "engineer4me_frontend_host_live_git_inventory_v2"
    model = EntraCallingClientMSALFrontendHostLiveInventoryProofDocument.model_validate(
        _proof_mapping()
    )
    assert model.model_dump(mode="json") == _proof_mapping()


@pytest.mark.parametrize("value", [None, [], "x", 1, True])
def test_document_rejects_non_object(value: object) -> None:
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendHostLiveInventoryProofDocument.model_validate(
            value
        )


@pytest.mark.parametrize("name", sorted(_proof_mapping()))
def test_document_rejects_missing_key(name: str) -> None:
    value = _proof_mapping()
    del value[name]
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendHostLiveInventoryProofDocument.model_validate(
            value
        )


def test_document_rejects_extra_key_and_wrong_exact_types() -> None:
    extra = _proof_mapping()
    extra["unexpected"] = False
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendHostLiveInventoryProofDocument.model_validate(
            extra
        )
    for name, replacement in (
        ("schema_version", True),
        ("approved_step232_package_manifest_sha256", b"x"),
        ("approved_branch", 1),
    ):
        value = _proof_mapping()
        value[name] = replacement
        with pytest.raises(ValidationError):
            EntraCallingClientMSALFrontendHostLiveInventoryProofDocument.model_validate(
                value
            )


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        ("document_type", DOCUMENT_TYPE + "_other"),
        ("schema_version", 2),
        ("source", SOURCE + "_other"),
        ("approved_step232_package_manifest_sha256", "0" * 64),
        ("approved_step232_accepted_state_manifest_sha256", "0" * 64),
        ("approved_step232_inventory_loader_sha256", "0" * 64),
        ("approved_step232_inventory_probe_sha256", "0" * 64),
        ("approved_branch", "main"),
        ("approved_head", "0" * 40),
        ("inventory_profile", PROFILE + "_other"),
    ],
)
def test_document_rejects_wrong_exact_value(name: str, replacement: object) -> None:
    value = _proof_mapping()
    value[name] = replacement
    with pytest.raises(ValidationError):
        EntraCallingClientMSALFrontendHostLiveInventoryProofDocument.model_validate(
            value
        )


def test_probe_accepts_zero_candidate_live_inventory() -> None:
    receipt = _receipt()
    assert receipt.proof_status == STATUS_NO_CANDIDATE
    assert receipt.candidate_root_count == 0
    assert receipt.no_package_manifest_candidate_identified is True
    assert receipt.single_unselected_package_manifest_candidate_detected is False
    assert receipt.live_repository_inventory_performed is True
    assert receipt.live_package_manifest_candidate_status_determined is True
    assert receipt.qualifying_browser_frontend_host_confirmed is False


def test_probe_accepts_one_candidate_without_selecting_or_qualifying_it() -> None:
    receipt = _receipt(host=True)
    assert receipt.proof_status == STATUS_SINGLE_CANDIDATE
    assert receipt.candidate_root_count == 1
    assert receipt.package_manifest_count == 1
    assert receipt.single_unselected_package_manifest_candidate_detected is True
    assert receipt.qualifying_browser_frontend_host_confirmed is False
    assert receipt.candidate_frontend_host_selected is False
    assert receipt.host_decision_or_scaffold_required is True


def test_probe_accepts_spaced_candidate_but_keeps_receipt_path_free() -> None:
    root = "web app & admin #1"
    evidence = _evidence_mapping(host=True)
    evidence["head_entries"] = [
        {
            "mode": "100644",
            "object_type": "blob",
            "object_id": "5" * 40,
            "path": f"{root}/package.json",
        }
    ]
    evidence["markers"] = [
        {
            "source_domain": "git_head",
            "path": f"{root}/package.json",
            "role": "package_manifest",
            "size_bytes": 120,
            "sha256": "6" * 64,
            "object_id": "5" * 40,
        }
    ]
    receipt = prove_entra_calling_client_msal_frontend_host_live_inventory(
        _proof_document(),
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode(),
    )
    rendered = render_entra_calling_client_msal_frontend_host_live_inventory_receipt(
        receipt
    )
    assert receipt.proof_status == STATUS_SINGLE_CANDIDATE
    assert root.encode() not in rendered


def test_probe_preserves_all_network_mutation_runtime_and_activation_boundaries() -> None:
    receipt = _receipt(host=True)
    assert receipt.git_status_worktree_enumeration_performed is True
    false_fields = (
        "working_tree_marker_content_read",
        "tracked_git_symlink_or_gitlink_observed",
        "raw_path_or_file_content_emitted",
        "rendered_receipt_is_independent_live_provenance",
        "qualifying_browser_frontend_host_confirmed",
        "candidate_frontend_host_selected",
        "package_manager_selected",
        "package_manager_executed",
        "remote_git_or_registry_operation_requested",
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
    assert all(getattr(receipt, name) is False for name in false_fields)


def test_probe_preserves_prior_step_boundaries_and_provenance_separation() -> None:
    receipt = _receipt()
    assert receipt.step216_zero_retry_policy_preserved is True
    assert receipt.step225_default_retry_rejection_preserved is True
    assert receipt.step230_container_proof_boundary_preserved is True
    assert receipt.step231_dependency_lock_plan_preserved is True
    assert receipt.step232_synthetic_live_provenance_separation_preserved is True
    assert receipt.rendered_receipt_is_independent_live_provenance is False


def test_proof_document_digest_is_canonical_and_whitespace_independent() -> None:
    compact = _receipt()
    pretty = prove_entra_calling_client_msal_frontend_host_live_inventory(
        json.dumps(_proof_mapping(), indent=2).encode(), _evidence_document()
    )
    canonical = json.dumps(
        _proof_mapping(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert compact.proof_document_sha256 == hashlib.sha256(canonical).hexdigest()
    assert pretty.proof_document_sha256 == compact.proof_document_sha256


@pytest.mark.parametrize("value", [None, "x", bytearray(b"{}"), memoryview(b"{}")])
def test_probe_rejects_non_exact_document_bytes(value: object) -> None:
    with pytest.raises(
        EntraCallingClientMSALFrontendHostLiveInventoryProbeError,
        match="controlled local frontend-host live inventory proof failed",
    ):
        prove_entra_calling_client_msal_frontend_host_live_inventory(
            value, _evidence_document()  # type: ignore[arg-type]
        )


def test_probe_rejects_oversized_duplicate_and_tampered_documents() -> None:
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryProbeError):
        prove_entra_calling_client_msal_frontend_host_live_inventory(
            b" " * (MAX_PROOF_DOCUMENT_BYTES + 1), _evidence_document()
        )
    duplicate = _proof_document()[:-1] + b',"approved_branch":"feature/phase-8"}'
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryProbeError):
        prove_entra_calling_client_msal_frontend_host_live_inventory(
            duplicate, _evidence_document()
        )
    tampered = _evidence_mapping()
    tampered["remote_git_or_package_network_operation_requested"] = True
    with pytest.raises(EntraCallingClientMSALFrontendHostLiveInventoryProbeError) as captured:
        prove_entra_calling_client_msal_frontend_host_live_inventory(
            _proof_document(),
            json.dumps(tampered, separators=(",", ":")).encode(),
        )
    assert captured.value.__cause__ is not None


def test_receipt_is_frozen_and_slotted() -> None:
    receipt = _receipt()
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        receipt.application_activated = True  # type: ignore[misc]
    assert not hasattr(receipt, "__dict__")


def test_renderer_is_canonical_declared_only_and_path_free() -> None:
    receipt = _receipt(host=True)
    rendered = render_entra_calling_client_msal_frontend_host_live_inventory_receipt(
        receipt
    )
    parsed = json.loads(rendered)
    assert rendered == json.dumps(
        parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert set(parsed) == {
        field.name
        for field in dataclasses.fields(
            EntraCallingClientMSALFrontendHostLiveInventoryProofReceipt
        )
    }
    for forbidden in (
        "frontend/package.json",
        "C:\\Users",
        "client_secret",
        "access_token",
        "refresh_token",
        "authorization_code",
    ):
        assert forbidden not in rendered.decode()


@pytest.mark.parametrize("value", [None, {}, object()])
def test_renderer_rejects_non_exact_receipt(value: object) -> None:
    with pytest.raises(TypeError, match="exact frontend-host live inventory receipt"):
        render_entra_calling_client_msal_frontend_host_live_inventory_receipt(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("receipt_type", "wrong"),
        ("schema_version", True),
        ("proof_status", "wrong"),
        ("approved_branch", "main"),
        ("evidence_document_sha256", "x"),
        ("candidate_root_count", 2),
        ("dependency_lock_count", 1),
        ("no_package_manifest_candidate_identified", 1),
        ("single_unselected_package_manifest_candidate_detected", 0),
        ("max_candidate_roots", True),
        ("observed_package_manager", "totally-invalid"),
        ("observed_lockfile_kind", "also-invalid"),
        ("live_repository_inventory_performed", False),
        ("candidate_frontend_host_selected", True),
        ("application_activated", True),
    ],
)
def test_receipt_rejects_constant_digest_count_or_boolean_tampering(
    field: str, replacement: object
) -> None:
    receipt = _receipt()
    values = {
        item.name: getattr(receipt, item.name) for item in dataclasses.fields(receipt)
    }
    values[field] = replacement
    with pytest.raises(ValueError):
        EntraCallingClientMSALFrontendHostLiveInventoryProofReceipt(**values)
