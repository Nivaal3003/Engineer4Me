"""Step 231 fail-closed frontend dependency-lock readiness contract.

This module records the exact dependency and integration controls that must be
satisfied before the reviewed MSAL Browser candidate may be selected, installed,
locked, imported, or activated.  It performs no filesystem or network I/O.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import model_validator

from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_browser_"
    "frontend_dependency_lock_readiness"
)
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_offline_frontend_dependency_lock_readiness"
SCOPE = "exact_msal_versions_lock_install_and_zero_retry_integration_plan"
STATUS = "frontend_dependency_lock_plan_validated_selection_remains_blocked"

STEP230_PACKAGE_MANIFEST_SHA256 = (
    "71f07fcf6dcc99e66ba0cfebd53ac5af3e699464998a60f5cabd8a99a8ecbd7e"
)
ZERO_RETRY_NETWORK_CLIENT_SHA256 = (
    "c36e718f4893959be94e4b51f6cfa76e0ac34da7c310151d23e446a3794f7a73"
)
MSAL_BROWSER_PACKAGE = "@azure/msal-browser"
MSAL_BROWSER_VERSION = "5.18.0"
MSAL_COMMON_PACKAGE = "@azure/msal-common"
MSAL_COMMON_VERSION = "16.12.0"
PACKAGE_MANAGER = "npm"
LOCKFILE_NAME = "package-lock.json"
LOCKFILE_VERSION = 3
INSTALL_COMMAND = (
    "npm ci --ignore-scripts --audit=false --fund=false --prefer-offline=false"
)
NETWORK_CLIENT_CONFIGURATION_SEAM = "system.networkClient"
MAX_DOCUMENT_BYTES = 4096


class EntraCallingClientMSALFrontendDependencyLockReadinessError(ValueError):
    """Sanitized Step 231 readiness failure."""


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _framed(domain: str, value: object) -> str:
    return hashlib.sha256(
        b"Engineer4Me-Step231-v1\x00" + domain.encode("ascii") + b"\x00" + _canonical(value)
    ).hexdigest()


class EntraCallingClientMSALFrontendDependencyLockReadinessDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_dependency_lock_readiness"
    ]
    schema_version: Literal[1]
    source: Literal["engineer4me_offline_frontend_dependency_lock_readiness"]
    approved_step230_package_manifest_sha256: str
    approved_zero_retry_network_client_sha256: str
    package_manager: Literal["npm"]
    lockfile_name: Literal["package-lock.json"]
    lockfile_version: Literal[3]
    install_mode: Literal[
        "npm ci --ignore-scripts --audit=false --fund=false --prefer-offline=false"
    ]

    @model_validator(mode="before")
    @classmethod
    def validate_exact_wire_contract(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError("dependency-lock document must be an exact object")
        expected = {
            "document_type": str,
            "schema_version": int,
            "source": str,
            "approved_step230_package_manifest_sha256": str,
            "approved_zero_retry_network_client_sha256": str,
            "package_manager": str,
            "lockfile_name": str,
            "lockfile_version": int,
            "install_mode": str,
        }
        if set(value) != set(expected):
            raise ValueError("dependency-lock document keys are not exact")
        if any(type(value[name]) is not expected_type for name, expected_type in expected.items()):
            raise ValueError("dependency-lock document types are not exact")
        return value

    @model_validator(mode="after")
    def validate_approved_identities(
        self,
    ) -> EntraCallingClientMSALFrontendDependencyLockReadinessDocument:
        if (
            not _is_sha256(self.approved_step230_package_manifest_sha256)
            or self.approved_step230_package_manifest_sha256
            != STEP230_PACKAGE_MANIFEST_SHA256
            or not _is_sha256(self.approved_zero_retry_network_client_sha256)
            or self.approved_zero_retry_network_client_sha256
            != ZERO_RETRY_NETWORK_CLIENT_SHA256
        ):
            raise ValueError("dependency-lock approved identities are invalid")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendDependencyLockReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    readiness_status: str
    package_manager: str
    lockfile_name: str
    lockfile_version: int
    install_command: str
    msal_browser_package: str
    msal_browser_version: str
    msal_common_package: str
    msal_common_version: str
    network_client_configuration_seam: str
    approved_step230_package_manifest_sha256: str
    approved_zero_retry_network_client_sha256: str
    readiness_document_sha256: str
    dependency_plan_sha256: str
    integration_plan_sha256: str
    exact_versions_required: bool
    semver_ranges_forbidden: bool
    alternate_msal_versions_forbidden: bool
    single_package_manager_required: bool
    exact_lockfile_name_and_version_required: bool
    frozen_lockfile_required: bool
    deterministic_clean_install_required: bool
    lifecycle_scripts_disabled_during_install: bool
    dependency_tree_must_match_lockfile: bool
    package_tarball_integrities_must_match_prior_proof: bool
    zero_retry_network_client_digest_bound: bool
    custom_network_client_configuration_required: bool
    default_msal_network_client_forbidden: bool
    exactly_one_network_client_instance_required: bool
    token_endpoint_post_retry_forbidden: bool
    dependency_confusion_controls_required: bool
    browser_bundle_import_graph_proof_required: bool
    browser_cors_proof_required: bool
    pkce_and_callback_journey_proof_required: bool
    real_oauth_values_processed: bool
    registry_access_performed: bool
    package_selected: bool
    dependency_installed: bool
    lockfile_created_or_modified: bool
    frontend_source_modified: bool
    browser_bundle_built: bool
    browser_runtime_executed: bool
    application_configuration_modified: bool
    application_activated: bool
    operational_write_performed: bool
    step216_zero_retry_policy_preserved: bool
    step225_default_retry_rejection_preserved: bool
    step230_container_proof_boundary_preserved: bool

    def __post_init__(self) -> None:
        constants = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "readiness_status": STATUS,
            "package_manager": PACKAGE_MANAGER,
            "lockfile_name": LOCKFILE_NAME,
            "lockfile_version": LOCKFILE_VERSION,
            "install_command": INSTALL_COMMAND,
            "msal_browser_package": MSAL_BROWSER_PACKAGE,
            "msal_browser_version": MSAL_BROWSER_VERSION,
            "msal_common_package": MSAL_COMMON_PACKAGE,
            "msal_common_version": MSAL_COMMON_VERSION,
            "network_client_configuration_seam": NETWORK_CLIENT_CONFIGURATION_SEAM,
            "approved_step230_package_manifest_sha256": STEP230_PACKAGE_MANIFEST_SHA256,
            "approved_zero_retry_network_client_sha256": ZERO_RETRY_NETWORK_CLIENT_SHA256,
        }
        if any(getattr(self, name) != expected for name, expected in constants.items()):
            raise ValueError("dependency-lock receipt constant is invalid")
        for name in (
            "readiness_document_sha256",
            "dependency_plan_sha256",
            "integration_plan_sha256",
        ):
            if not _is_sha256(getattr(self, name)):
                raise ValueError("dependency-lock receipt digest is invalid")

        required_true = (
            "exact_versions_required",
            "semver_ranges_forbidden",
            "alternate_msal_versions_forbidden",
            "single_package_manager_required",
            "exact_lockfile_name_and_version_required",
            "frozen_lockfile_required",
            "deterministic_clean_install_required",
            "lifecycle_scripts_disabled_during_install",
            "dependency_tree_must_match_lockfile",
            "package_tarball_integrities_must_match_prior_proof",
            "zero_retry_network_client_digest_bound",
            "custom_network_client_configuration_required",
            "default_msal_network_client_forbidden",
            "exactly_one_network_client_instance_required",
            "token_endpoint_post_retry_forbidden",
            "dependency_confusion_controls_required",
            "browser_bundle_import_graph_proof_required",
            "browser_cors_proof_required",
            "pkce_and_callback_journey_proof_required",
            "step216_zero_retry_policy_preserved",
            "step225_default_retry_rejection_preserved",
            "step230_container_proof_boundary_preserved",
        )
        required_false = (
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
        if any(type(getattr(self, name)) is not bool or not getattr(self, name) for name in required_true):
            raise ValueError("dependency-lock required control is not true")
        if any(type(getattr(self, name)) is not bool or getattr(self, name) for name in required_false):
            raise ValueError("dependency-lock deferred or mutation control is not false")


def load_entra_calling_client_msal_frontend_dependency_lock_readiness(
    document: bytes,
) -> EntraCallingClientMSALFrontendDependencyLockReadinessReceipt:
    """Validate one exact offline Step 231 document and return a bounded receipt."""

    try:
        if type(document) is not bytes:
            raise TypeError("document must be exact bytes")
        if not document or len(document) > MAX_DOCUMENT_BYTES:
            raise ValueError("dependency-lock document size is invalid")
        parsed = json.loads(document, object_pairs_hook=_pairs)
        model = EntraCallingClientMSALFrontendDependencyLockReadinessDocument.model_validate(parsed)
        canonical_document = _canonical(model.model_dump(mode="json"))
        dependency_plan = {
            "package_manager": PACKAGE_MANAGER,
            "lockfile": LOCKFILE_NAME,
            "lockfile_version": LOCKFILE_VERSION,
            "install_command": INSTALL_COMMAND,
            "dependencies": {
                MSAL_BROWSER_PACKAGE: MSAL_BROWSER_VERSION,
                MSAL_COMMON_PACKAGE: MSAL_COMMON_VERSION,
            },
            "semver_ranges_forbidden": True,
            "frozen_lockfile_required": True,
            "lifecycle_scripts_disabled": True,
        }
        integration_plan = {
            "configuration_seam": NETWORK_CLIENT_CONFIGURATION_SEAM,
            "network_client_sha256": ZERO_RETRY_NETWORK_CLIENT_SHA256,
            "default_network_client_forbidden": True,
            "network_client_instances": 1,
            "token_endpoint_post_retries": 0,
            "browser_import_graph_proof_required": True,
            "cors_proof_required": True,
            "pkce_callback_journey_proof_required": True,
        }
        return EntraCallingClientMSALFrontendDependencyLockReadinessReceipt(
            receipt_type=RECEIPT_TYPE,
            schema_version=SCHEMA_VERSION,
            source=SOURCE,
            validation_scope=SCOPE,
            readiness_status=STATUS,
            package_manager=PACKAGE_MANAGER,
            lockfile_name=LOCKFILE_NAME,
            lockfile_version=LOCKFILE_VERSION,
            install_command=INSTALL_COMMAND,
            msal_browser_package=MSAL_BROWSER_PACKAGE,
            msal_browser_version=MSAL_BROWSER_VERSION,
            msal_common_package=MSAL_COMMON_PACKAGE,
            msal_common_version=MSAL_COMMON_VERSION,
            network_client_configuration_seam=NETWORK_CLIENT_CONFIGURATION_SEAM,
            approved_step230_package_manifest_sha256=(STEP230_PACKAGE_MANIFEST_SHA256),
            approved_zero_retry_network_client_sha256=(ZERO_RETRY_NETWORK_CLIENT_SHA256),
            readiness_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
            dependency_plan_sha256=_framed("dependency-plan", dependency_plan),
            integration_plan_sha256=_framed("integration-plan", integration_plan),
            exact_versions_required=True,
            semver_ranges_forbidden=True,
            alternate_msal_versions_forbidden=True,
            single_package_manager_required=True,
            exact_lockfile_name_and_version_required=True,
            frozen_lockfile_required=True,
            deterministic_clean_install_required=True,
            lifecycle_scripts_disabled_during_install=True,
            dependency_tree_must_match_lockfile=True,
            package_tarball_integrities_must_match_prior_proof=True,
            zero_retry_network_client_digest_bound=True,
            custom_network_client_configuration_required=True,
            default_msal_network_client_forbidden=True,
            exactly_one_network_client_instance_required=True,
            token_endpoint_post_retry_forbidden=True,
            dependency_confusion_controls_required=True,
            browser_bundle_import_graph_proof_required=True,
            browser_cors_proof_required=True,
            pkce_and_callback_journey_proof_required=True,
            real_oauth_values_processed=False,
            registry_access_performed=False,
            package_selected=False,
            dependency_installed=False,
            lockfile_created_or_modified=False,
            frontend_source_modified=False,
            browser_bundle_built=False,
            browser_runtime_executed=False,
            application_configuration_modified=False,
            application_activated=False,
            operational_write_performed=False,
            step216_zero_retry_policy_preserved=True,
            step225_default_retry_rejection_preserved=True,
            step230_container_proof_boundary_preserved=True,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise EntraCallingClientMSALFrontendDependencyLockReadinessError(
            "frontend dependency-lock readiness validation failed"
        ) from error


def render_entra_calling_client_msal_frontend_dependency_lock_readiness_receipt(
    receipt: EntraCallingClientMSALFrontendDependencyLockReadinessReceipt,
) -> bytes:
    """Render only the exact validated receipt as canonical UTF-8 JSON."""

    if type(receipt) is not EntraCallingClientMSALFrontendDependencyLockReadinessReceipt:
        raise TypeError("exact frontend dependency-lock receipt is required")
    receipt.__post_init__()
    return _canonical(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__}
    )


__all__ = [
    "DOCUMENT_TYPE",
    "INSTALL_COMMAND",
    "LOCKFILE_NAME",
    "LOCKFILE_VERSION",
    "MSAL_BROWSER_PACKAGE",
    "MSAL_BROWSER_VERSION",
    "MSAL_COMMON_PACKAGE",
    "MSAL_COMMON_VERSION",
    "NETWORK_CLIENT_CONFIGURATION_SEAM",
    "PACKAGE_MANAGER",
    "RECEIPT_TYPE",
    "SCHEMA_VERSION",
    "SOURCE",
    "STATUS",
    "STEP230_PACKAGE_MANIFEST_SHA256",
    "ZERO_RETRY_NETWORK_CLIENT_SHA256",
    "EntraCallingClientMSALFrontendDependencyLockReadinessDocument",
    "EntraCallingClientMSALFrontendDependencyLockReadinessError",
    "EntraCallingClientMSALFrontendDependencyLockReadinessReceipt",
    "load_entra_calling_client_msal_frontend_dependency_lock_readiness",
    "render_entra_calling_client_msal_frontend_dependency_lock_readiness_receipt",
]
