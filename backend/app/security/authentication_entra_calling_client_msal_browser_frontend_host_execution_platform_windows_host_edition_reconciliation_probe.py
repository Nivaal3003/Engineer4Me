"""Pure Step 241 Windows host Professional-composition reconciliation proof.

The closed-package installer performs the narrowly scoped Registry64, CIM,
and SoftwareLicensingProduct reads and sends one canonical JSON envelope to
this module.  This module only validates and classifies those supplied bytes.
It has no filesystem, environment, network, subprocess, registry, CIM, WMI,
Node.js, npm, package-manager, or operational capability.

The selected Windows 10 22H2 client build reached the end of its Microsoft
base lifecycle on 2025-10-14.  A commercial ESU license is classified only as
a security-updates entitlement: it never overrides Node.js's documented rule
that a vendor-EOL operating system is unsupported.  Consequently every
receipt remains fail-closed and Windows Node.js execution stays unauthorized.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from typing import Any

_CANONICAL_MODULE_NAME = (
    "app.security."
    "authentication_entra_calling_client_msal_browser_frontend_host_"
    "execution_platform_windows_host_edition_reconciliation_probe"
)
if __name__ == "__main__":
    _canonical_name = getattr(__spec__, "name", None)
    _current_module = sys.modules.get(__name__)
    _existing_module = (
        sys.modules.get(_canonical_name)
        if type(_canonical_name) is str
        else None
    )
    if (
        _canonical_name != _CANONICAL_MODULE_NAME
        or _current_module is None
        or (
            _existing_module is not None
            and _existing_module is not _current_module
        )
    ):
        raise RuntimeError("Step 241 CLI module identity cannot be bound safely")
    sys.modules[_CANONICAL_MODULE_NAME] = _current_module


AUTHORIZATION_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_"
    "execution_platform_windows_host_professional_composition_reconciliation_authorization"
)
EVIDENCE_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_"
    "execution_platform_windows_host_professional_composition_reconciliation_evidence"
)
RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_"
    "execution_platform_windows_host_professional_composition_reconciliation_receipt"
)
SCHEMA_VERSION = 1
AUTHORIZATION_SOURCE = "engineer4me_step241_closed_package_installer"
EVIDENCE_SOURCE = (
    "engineer4me_step241_closed_package_installer_read_only_windows_host_inventory"
)
SOURCE = "engineer4me_pure_windows_host_professional_composition_reconciliation_probe"
SCOPE = (
    "exact_step240_chain_plus_read_only_registry64_cim_and_commercial_esu_"
    "windows_host_professional_composition_reconciliation"
)
POLICY_AS_OF = "2026-08-20"

STATUS_WINDOWS_10_22H2_VENDOR_EOL = (
    "windows_10_22h2_base_lifecycle_ended_node_vendor_eol_execution_blocked"
)
STATUS_IDENTITY_NOT_CREDIBLE = (
    "windows_host_identity_not_credible_execution_blocked"
)
STATUS_LIFECYCLE_MAPPING_UNSELECTED = (
    "windows_host_lifecycle_mapping_unselected_execution_blocked"
)

IDENTITY_WINDOWS_10_22H2 = "credible_windows_10_22h2_build_19045_client"
IDENTITY_CREDIBLE_UNSELECTED = "credible_windows_client_lifecycle_mapping_unselected"
IDENTITY_NOT_CREDIBLE = "windows_client_identity_not_credible"

ESU_LICENSED_SECURITY_UPDATES_ONLY = "licensed_security_updates_only"
ESU_PRESENT_NOT_LICENSED = "present_not_licensed"
ESU_NOT_FOUND = "not_found"
ESU_QUERY_UNAVAILABLE = "query_unavailable"
CONSUMER_ESU_DISPOSITION = "not_machine_proven_by_selected_official_interface"
COMMERCIAL_ESU_CURRENT_PERIOD_YEAR = 1

STEP240_ACCEPTED_STATE_MANIFEST_SHA256 = (
    "bd382feb228394939a2343f731e36c52a7712c1ad578ef6f606f41d867dca067"
)
STEP240_PACKAGE_MANIFEST_SHA256 = (
    "ab2805047b5583a8e8550e8d27e002923a8c962fb325eb5c1624afe9e5732b6f"
)
STEP240_CANONICAL_RECEIPT_SHA256 = (
    "d32f3069da64c6b485489b75f84fc4a99646350e790bd8682239ead72fa991e0"
)
STEP240_READINESS_STATUS = "windows_host_identity_not_credible_execution_blocked"
RECONCILIATION_RULE = (
    "registry_edition_professional_composition_enterprise_cim_sku_48_only"
)
OBSERVED_STEP240_REGISTRY_EDITION_ID = "Professional"
OBSERVED_STEP240_REGISTRY_COMPOSITION_EDITION_ID = "Enterprise"
OBSERVED_STEP240_CIM_OPERATING_SYSTEM_SKU = 48
NODE_VERSION_TAG = "v24.19.0"
NODE_BUILDING_COMMIT = "cdc1b38d40cb567b7ad0b39c86addf830a0af0ae"
NODE_BUILDING_PATH = "BUILDING.md"
NODE_BUILDING_BYTES = 38_739
NODE_BUILDING_SHA256 = (
    "f77e6a28ffd03ff93f05c116fc70a795ff348f7ef4ad4669abcdf7d97e310a1c"
)
MICROSOFT_WINDOWS_10_22H2_BASE_LIFECYCLE_END_DATE = "2025-10-14"

REGISTRY_VIEW = "Registry64"
REGISTRY_ACCESS_MODE = "read_only"
CIM_CLASS = "Win32_OperatingSystem"
MAX_CLI_ENVELOPE_BYTES = 16_384

ESU_ACTIVATION_IDS = (
    "f520e45e-7413-4a34-a497-d2765967d094",
    "1043add5-23b1-4afb-9a0f-64343c8f3f8d",
    "83d49986-add3-41d7-ba33-87c7bfb5c0fb",
)
ESU_QUERY_STATES = frozenset(("found", "not_found", "query_unavailable"))

# Exact registry-edition/CIM-SKU correlations already accepted as ordinary
# Windows client editions by Step 240.  LTSC/LTSB, IoT, Server, evaluation,
# Cloud, and virtual-edition mappings remain intentionally absent.
_CLIENT_EDITION_SKU = {
    ("Core", "Core", 101): "home",
    ("CoreCountrySpecific", "CoreCountrySpecific", 99): "home_country_specific",
    ("CoreN", "CoreN", 98): "home_n",
    ("CoreSingleLanguage", "CoreSingleLanguage", 100): "home_single_language",
    ("Education", "Education", 121): "education",
    ("EducationN", "EducationN", 122): "education_n",
    ("Enterprise", "Enterprise", 4): "enterprise",
    ("EnterpriseN", "EnterpriseN", 27): "enterprise_n",
    ("Professional", "Professional", 48): "professional",
    ("ProfessionalEducation", "ProfessionalEducation", 164): "professional_education",
    ("ProfessionalEducationN", "ProfessionalEducationN", 165): "professional_education_n",
    ("ProfessionalN", "ProfessionalN", 49): "professional_n",
    ("ProfessionalWorkstation", "ProfessionalWorkstation", 161): "professional_workstation",
    ("ProfessionalWorkstationN", "ProfessionalWorkstationN", 162): "professional_workstation_n",
}

# One exact observed-host exception.  This is not a generalized composition
# rule and no other mixed edition/composition/SKU tuple is authorized.
_OBSERVED_EDITION_SKU_RECONCILIATION = {
    (
        OBSERVED_STEP240_REGISTRY_EDITION_ID,
        OBSERVED_STEP240_REGISTRY_COMPOSITION_EDITION_ID,
        OBSERVED_STEP240_CIM_OPERATING_SYSTEM_SKU,
    ): "professional",
}

_AUTHORIZATION_KEYS = frozenset(
    (
        "approved_step240_accepted_state_manifest_sha256",
        "approved_step240_canonical_receipt_sha256",
        "approved_step240_package_manifest_sha256",
        "approved_step240_readiness_status",
        "document_type",
        "node_building_bytes",
        "node_building_commit",
        "node_building_path",
        "node_building_sha256",
        "node_version_tag",
        "observed_step240_cim_operating_system_sku",
        "observed_step240_registry_composition_edition_id",
        "observed_step240_registry_edition_id",
        "policy_as_of",
        "reconciliation_rule",
        "schema_version",
        "source",
    )
)
_EVIDENCE_KEYS = frozenset(
    (
        "cim",
        "cim_class",
        "commercial_esu_activation_ids",
        "evidence_type",
        "registry64",
        "registry_access_mode",
        "registry_view",
        "schema_version",
        "source",
    )
)
_REGISTRY_KEYS = frozenset(
    (
        "CompositionEditionID",
        "CurrentBuildNumber",
        "CurrentMajorVersionNumber",
        "CurrentMinorVersionNumber",
        "DisplayVersion",
        "EditionID",
        "InstallationType",
        "ProductName",
        "UBR",
    )
)
_CIM_KEYS = frozenset(("BuildNumber", "OperatingSystemSKU", "ProductType", "Version"))
_ESU_KEYS = frozenset(("activation_id", "license_status", "program_year", "query_state"))


class WindowsHostProfessionalCompositionReconciliationError(ValueError):
    """Sanitized Step 241 proof failure."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(unused: str) -> None:
    raise ValueError("non-finite JSON number")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _load_canonical_json(document: bytes) -> dict[str, Any]:
    if type(document) is not bytes or not document or len(document) > MAX_CLI_ENVELOPE_BYTES:
        raise ValueError("Step 241 envelope size is invalid")
    value = json.loads(
        document,
        object_pairs_hook=_pairs,
        parse_constant=_reject_constant,
    )
    if type(value) is not dict or _canonical(value) != document:
        raise ValueError("Step 241 envelope is not exact canonical JSON")
    return value


def _exact_object(value: object, keys: frozenset[str], description: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != keys:
        raise ValueError(f"{description} is not an exact object")
    return value


def _plain_string(value: object, *, maximum: int = 128) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= maximum
        and all(0x20 <= ord(character) <= 0x7E for character in value)
    )


def _validate_authorization(value: object) -> dict[str, Any]:
    authorization = _exact_object(value, _AUTHORIZATION_KEYS, "Step 241 authorization")
    expected: dict[str, object] = {
        "approved_step240_accepted_state_manifest_sha256": STEP240_ACCEPTED_STATE_MANIFEST_SHA256,
        "approved_step240_canonical_receipt_sha256": STEP240_CANONICAL_RECEIPT_SHA256,
        "approved_step240_package_manifest_sha256": STEP240_PACKAGE_MANIFEST_SHA256,
        "approved_step240_readiness_status": STEP240_READINESS_STATUS,
        "document_type": AUTHORIZATION_TYPE,
        "node_building_bytes": NODE_BUILDING_BYTES,
        "node_building_commit": NODE_BUILDING_COMMIT,
        "node_building_path": NODE_BUILDING_PATH,
        "node_building_sha256": NODE_BUILDING_SHA256,
        "node_version_tag": NODE_VERSION_TAG,
        "observed_step240_cim_operating_system_sku": OBSERVED_STEP240_CIM_OPERATING_SYSTEM_SKU,
        "observed_step240_registry_composition_edition_id": (
            OBSERVED_STEP240_REGISTRY_COMPOSITION_EDITION_ID
        ),
        "observed_step240_registry_edition_id": OBSERVED_STEP240_REGISTRY_EDITION_ID,
        "policy_as_of": POLICY_AS_OF,
        "reconciliation_rule": RECONCILIATION_RULE,
        "schema_version": SCHEMA_VERSION,
        "source": AUTHORIZATION_SOURCE,
    }
    for name, expected_value in expected.items():
        actual = authorization[name]
        if type(actual) is not type(expected_value) or actual != expected_value:
            raise ValueError("Step 241 authorization binding is invalid")
    return authorization


def _validate_registry(value: object) -> dict[str, Any]:
    registry = _exact_object(value, _REGISTRY_KEYS, "Registry64 evidence")
    for name in (
        "CompositionEditionID",
        "CurrentBuildNumber",
        "DisplayVersion",
        "EditionID",
        "InstallationType",
        "ProductName",
    ):
        if not _plain_string(registry[name]):
            raise ValueError("Registry64 string evidence is invalid")
    if not re.fullmatch(r"[1-9][0-9]{3,5}", registry["CurrentBuildNumber"]):
        raise ValueError("Registry64 build number is invalid")
    if not re.fullmatch(r"[0-9]{2}H[12]", registry["DisplayVersion"]):
        raise ValueError("Registry64 display version is invalid")
    for name, maximum in (
        ("CurrentMajorVersionNumber", 100),
        ("CurrentMinorVersionNumber", 100),
        ("UBR", 10_000_000),
    ):
        if type(registry[name]) is not int or not 0 <= registry[name] <= maximum:
            raise ValueError("Registry64 integer evidence is invalid")
    return registry


def _validate_cim(value: object) -> dict[str, Any]:
    cim = _exact_object(value, _CIM_KEYS, "CIM evidence")
    if (
        not _plain_string(cim["BuildNumber"])
        or not re.fullmatch(r"[1-9][0-9]{3,5}", cim["BuildNumber"])
        or not _plain_string(cim["Version"])
        or not re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[1-9][0-9]{3,5}", cim["Version"])
    ):
        raise ValueError("CIM version evidence is invalid")
    if (
        type(cim["OperatingSystemSKU"]) is not int
        or not 0 <= cim["OperatingSystemSKU"] <= 1_000
        or type(cim["ProductType"]) is not int
        or cim["ProductType"] not in (1, 2, 3)
    ):
        raise ValueError("CIM integer evidence is invalid")
    return cim


def _validate_esu(value: object) -> tuple[dict[str, Any], ...]:
    if type(value) is not list or len(value) != len(ESU_ACTIVATION_IDS):
        raise ValueError("commercial ESU evidence inventory is invalid")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        entry = _exact_object(item, _ESU_KEYS, "commercial ESU evidence entry")
        expected_year = index + 1
        if (
            type(entry["activation_id"]) is not str
            or entry["activation_id"] != ESU_ACTIVATION_IDS[index]
            or type(entry["program_year"]) is not int
            or entry["program_year"] != expected_year
            or type(entry["query_state"]) is not str
            or entry["query_state"] not in ESU_QUERY_STATES
        ):
            raise ValueError("commercial ESU evidence identity is invalid")
        license_status = entry["license_status"]
        if entry["query_state"] == "found":
            if type(license_status) is not int or not 0 <= license_status <= 6:
                raise ValueError("commercial ESU license status is invalid")
        elif license_status is not None:
            raise ValueError("commercial ESU unavailable license status must be null")
        result.append(entry)
    return tuple(result)


def _validate_evidence(value: object) -> tuple[dict[str, Any], dict[str, Any], tuple[dict[str, Any], ...]]:
    evidence = _exact_object(value, _EVIDENCE_KEYS, "Step 241 evidence")
    constants: dict[str, object] = {
        "cim_class": CIM_CLASS,
        "evidence_type": EVIDENCE_TYPE,
        "registry_access_mode": REGISTRY_ACCESS_MODE,
        "registry_view": REGISTRY_VIEW,
        "schema_version": SCHEMA_VERSION,
        "source": EVIDENCE_SOURCE,
    }
    for name, expected in constants.items():
        actual = evidence[name]
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError("Step 241 evidence binding is invalid")
    return (
        _validate_registry(evidence["registry64"]),
        _validate_cim(evidence["cim"]),
        _validate_esu(evidence["commercial_esu_activation_ids"]),
    )


def _esu_disposition(
    entries: tuple[dict[str, Any], ...]
) -> tuple[str, bool, bool, bool]:
    any_licensed = any(
        entry["query_state"] == "found" and entry["license_status"] == 1
        for entry in entries
    )
    query_complete = all(entry["query_state"] != "query_unavailable" for entry in entries)
    current = entries[COMMERCIAL_ESU_CURRENT_PERIOD_YEAR - 1]
    current_licensed = (
        current["query_state"] == "found" and current["license_status"] == 1
    )
    if current_licensed:
        disposition = ESU_LICENSED_SECURITY_UPDATES_ONLY
    elif current["query_state"] == "query_unavailable":
        disposition = ESU_QUERY_UNAVAILABLE
    elif current["query_state"] == "found":
        disposition = ESU_PRESENT_NOT_LICENSED
    else:
        disposition = ESU_NOT_FOUND
    return disposition, any_licensed, query_complete, current_licensed


def _edition_disposition(
    edition_key: tuple[str, str, int],
) -> tuple[str, bool, bool]:
    ordinary_family = _CLIENT_EDITION_SKU.get(edition_key)
    reconciled_family = _OBSERVED_EDITION_SKU_RECONCILIATION.get(edition_key)
    exact_tuple_matched = reconciled_family is not None
    reconciliation_applied = ordinary_family is None and exact_tuple_matched
    if ordinary_family is not None:
        family = ordinary_family
    elif reconciled_family is not None:
        family = reconciled_family
    else:
        family = "unselected"
    return family, exact_tuple_matched, reconciliation_applied


@dataclass(frozen=True, slots=True)
class WindowsHostProfessionalCompositionReconciliationReceipt:
    receipt_type: str
    schema_version: int
    source: str
    scope: str
    status: str
    policy_as_of: str
    approved_step240_accepted_state_manifest_sha256: str
    approved_step240_package_manifest_sha256: str
    approved_step240_canonical_receipt_sha256: str
    approved_step240_readiness_status: str
    authorization_document_sha256: str
    evidence_document_sha256: str
    node_version_tag: str
    node_building_commit: str
    node_building_path: str
    node_building_bytes: int
    node_building_sha256: str
    registry_view: str
    registry_access_mode: str
    cim_class: str
    registry_edition_id: str
    registry_composition_edition_id: str
    registry_installation_type: str
    registry_display_version: str
    registry_current_build_number: str
    registry_ubr: int
    registry_current_major_version_number: int
    registry_current_minor_version_number: int
    registry_product_name_display_only: str
    cim_version: str
    cim_build_number: str
    cim_operating_system_sku: int
    cim_product_type: int
    esu_year1_activation_id: str
    esu_year1_query_state: str
    esu_year1_license_status: int | None
    esu_year2_activation_id: str
    esu_year2_query_state: str
    esu_year2_license_status: int | None
    esu_year3_activation_id: str
    esu_year3_query_state: str
    esu_year3_license_status: int | None
    host_edition_family: str
    host_identity_disposition: str
    edition_sku_reconciliation_rule: str
    commercial_esu_disposition: str
    commercial_esu_current_period_year: int
    consumer_esu_disposition: str
    microsoft_base_lifecycle_end_date: str
    exact_step240_chain_bound: bool
    exact_node_building_policy_bound: bool
    host_inventory_read_only: bool
    commercial_esu_query_read_only: bool
    registry64_inventory_validated: bool
    cim_inventory_validated: bool
    registry_cim_build_crosscheck_passed: bool
    registry_cim_version_crosscheck_passed: bool
    windows_client_type_crosscheck_passed: bool
    edition_sku_mapping_credible: bool
    edition_sku_reconciliation_exact_tuple_matched: bool
    edition_sku_reconciliation_applied: bool
    other_mixed_edition_sku_tuple_authorized: bool
    windows_client_identity_credible: bool
    windows_10_22h2_build_19045_classified: bool
    registry_product_name_used_for_decision: bool
    node_documented_windows_x64_platform_floor_met: bool
    microsoft_base_lifecycle_supported: bool
    commercial_esu_query_complete: bool
    commercial_esu_any_licensed: bool
    commercial_esu_current_period_licensed: bool
    commercial_esu_security_updates_only: bool
    commercial_esu_overrides_node_vendor_eol_rule: bool
    consumer_esu_machine_verification_interface_selected: bool
    host_support_disposition_verified: bool
    node_vendor_supported_operating_system: bool
    host_execution_platform_supported: bool
    windows_node_execution_authorized: bool
    probe_network_request_performed: bool
    probe_subprocess_or_shell_executed: bool
    probe_environment_read_or_mutated: bool
    probe_filesystem_read_or_written: bool
    node_or_npm_executed: bool
    package_manager_executed: bool
    lock_generation_authorized_or_performed: bool
    frontend_materialized: bool
    operational_write_performed: bool
    git_staging_commit_or_push_performed: bool
    application_activation_performed: bool


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_receipt(receipt: WindowsHostProfessionalCompositionReconciliationReceipt) -> None:
    constants: dict[str, object] = {
        "receipt_type": RECEIPT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE,
        "scope": SCOPE,
        "policy_as_of": POLICY_AS_OF,
        "approved_step240_accepted_state_manifest_sha256": STEP240_ACCEPTED_STATE_MANIFEST_SHA256,
        "approved_step240_package_manifest_sha256": STEP240_PACKAGE_MANIFEST_SHA256,
        "approved_step240_canonical_receipt_sha256": STEP240_CANONICAL_RECEIPT_SHA256,
        "approved_step240_readiness_status": STEP240_READINESS_STATUS,
        "edition_sku_reconciliation_rule": RECONCILIATION_RULE,
        "node_version_tag": NODE_VERSION_TAG,
        "node_building_commit": NODE_BUILDING_COMMIT,
        "node_building_path": NODE_BUILDING_PATH,
        "node_building_bytes": NODE_BUILDING_BYTES,
        "node_building_sha256": NODE_BUILDING_SHA256,
        "registry_view": REGISTRY_VIEW,
        "registry_access_mode": REGISTRY_ACCESS_MODE,
        "cim_class": CIM_CLASS,
        "commercial_esu_current_period_year": COMMERCIAL_ESU_CURRENT_PERIOD_YEAR,
        "consumer_esu_disposition": CONSUMER_ESU_DISPOSITION,
        "esu_year1_activation_id": ESU_ACTIVATION_IDS[0],
        "esu_year2_activation_id": ESU_ACTIVATION_IDS[1],
        "esu_year3_activation_id": ESU_ACTIVATION_IDS[2],
    }
    for name, expected in constants.items():
        actual = getattr(receipt, name)
        if type(actual) is not type(expected) or actual != expected:
            raise WindowsHostProfessionalCompositionReconciliationError("Step 241 receipt constant is invalid")
    if not _is_sha256(receipt.authorization_document_sha256) or not _is_sha256(
        receipt.evidence_document_sha256
    ):
        raise WindowsHostProfessionalCompositionReconciliationError("Step 241 receipt digest is invalid")
    authorization_projection: dict[str, object] = {
        "approved_step240_accepted_state_manifest_sha256": STEP240_ACCEPTED_STATE_MANIFEST_SHA256,
        "approved_step240_canonical_receipt_sha256": STEP240_CANONICAL_RECEIPT_SHA256,
        "approved_step240_package_manifest_sha256": STEP240_PACKAGE_MANIFEST_SHA256,
        "approved_step240_readiness_status": STEP240_READINESS_STATUS,
        "document_type": AUTHORIZATION_TYPE,
        "node_building_bytes": NODE_BUILDING_BYTES,
        "node_building_commit": NODE_BUILDING_COMMIT,
        "node_building_path": NODE_BUILDING_PATH,
        "node_building_sha256": NODE_BUILDING_SHA256,
        "node_version_tag": NODE_VERSION_TAG,
        "observed_step240_cim_operating_system_sku": OBSERVED_STEP240_CIM_OPERATING_SYSTEM_SKU,
        "observed_step240_registry_composition_edition_id": (
            OBSERVED_STEP240_REGISTRY_COMPOSITION_EDITION_ID
        ),
        "observed_step240_registry_edition_id": OBSERVED_STEP240_REGISTRY_EDITION_ID,
        "policy_as_of": POLICY_AS_OF,
        "reconciliation_rule": RECONCILIATION_RULE,
        "schema_version": SCHEMA_VERSION,
        "source": AUTHORIZATION_SOURCE,
    }
    if receipt.authorization_document_sha256 != hashlib.sha256(
        _canonical(authorization_projection)
    ).hexdigest():
        raise WindowsHostProfessionalCompositionReconciliationError(
            "Step 241 authorization receipt digest is invalid"
        )
    registry_projection: dict[str, Any] = {
        "CompositionEditionID": receipt.registry_composition_edition_id,
        "CurrentBuildNumber": receipt.registry_current_build_number,
        "CurrentMajorVersionNumber": receipt.registry_current_major_version_number,
        "CurrentMinorVersionNumber": receipt.registry_current_minor_version_number,
        "DisplayVersion": receipt.registry_display_version,
        "EditionID": receipt.registry_edition_id,
        "InstallationType": receipt.registry_installation_type,
        "ProductName": receipt.registry_product_name_display_only,
        "UBR": receipt.registry_ubr,
    }
    cim_projection: dict[str, Any] = {
        "BuildNumber": receipt.cim_build_number,
        "OperatingSystemSKU": receipt.cim_operating_system_sku,
        "ProductType": receipt.cim_product_type,
        "Version": receipt.cim_version,
    }
    esu_projection: list[dict[str, Any]] = [
        {
            "activation_id": activation_id,
            "license_status": license_status,
            "program_year": year,
            "query_state": query_state,
        }
        for year, activation_id, query_state, license_status in (
            (
                1,
                receipt.esu_year1_activation_id,
                receipt.esu_year1_query_state,
                receipt.esu_year1_license_status,
            ),
            (
                2,
                receipt.esu_year2_activation_id,
                receipt.esu_year2_query_state,
                receipt.esu_year2_license_status,
            ),
            (
                3,
                receipt.esu_year3_activation_id,
                receipt.esu_year3_query_state,
                receipt.esu_year3_license_status,
            ),
        )
    ]
    try:
        registry_projection = _validate_registry(registry_projection)
        cim_projection = _validate_cim(cim_projection)
        validated_esu_projection = _validate_esu(esu_projection)
    except (KeyError, TypeError, ValueError) as error:
        raise WindowsHostProfessionalCompositionReconciliationError(
            "Step 241 receipt inventory is invalid"
        ) from error
    evidence_projection: dict[str, object] = {
        "cim": cim_projection,
        "cim_class": CIM_CLASS,
        "commercial_esu_activation_ids": esu_projection,
        "evidence_type": EVIDENCE_TYPE,
        "registry64": registry_projection,
        "registry_access_mode": REGISTRY_ACCESS_MODE,
        "registry_view": REGISTRY_VIEW,
        "schema_version": SCHEMA_VERSION,
        "source": EVIDENCE_SOURCE,
    }
    if receipt.evidence_document_sha256 != hashlib.sha256(
        _canonical(evidence_projection)
    ).hexdigest():
        raise WindowsHostProfessionalCompositionReconciliationError(
            "Step 241 evidence receipt digest is invalid"
        )
    required_true = (
        "exact_step240_chain_bound",
        "exact_node_building_policy_bound",
        "host_inventory_read_only",
        "commercial_esu_query_read_only",
        "registry64_inventory_validated",
        "cim_inventory_validated",
    )
    required_false = (
        "registry_product_name_used_for_decision",
        "microsoft_base_lifecycle_supported",
        "commercial_esu_overrides_node_vendor_eol_rule",
        "consumer_esu_machine_verification_interface_selected",
        "node_vendor_supported_operating_system",
        "host_execution_platform_supported",
        "windows_node_execution_authorized",
        "probe_network_request_performed",
        "probe_subprocess_or_shell_executed",
        "probe_environment_read_or_mutated",
        "probe_filesystem_read_or_written",
        "node_or_npm_executed",
        "package_manager_executed",
        "lock_generation_authorized_or_performed",
        "frontend_materialized",
        "operational_write_performed",
        "git_staging_commit_or_push_performed",
        "application_activation_performed",
        "other_mixed_edition_sku_tuple_authorized",
    )
    if any(type(getattr(receipt, name)) is not bool or not getattr(receipt, name) for name in required_true):
        raise WindowsHostProfessionalCompositionReconciliationError("Step 241 required receipt control is invalid")
    if any(type(getattr(receipt, name)) is not bool or getattr(receipt, name) for name in required_false):
        raise WindowsHostProfessionalCompositionReconciliationError("Step 241 fail-closed receipt control is invalid")
    dynamic_booleans = (
        "registry_cim_build_crosscheck_passed",
        "registry_cim_version_crosscheck_passed",
        "windows_client_type_crosscheck_passed",
        "edition_sku_mapping_credible",
        "edition_sku_reconciliation_exact_tuple_matched",
        "edition_sku_reconciliation_applied",
        "windows_client_identity_credible",
        "windows_10_22h2_build_19045_classified",
        "node_documented_windows_x64_platform_floor_met",
        "commercial_esu_query_complete",
        "commercial_esu_any_licensed",
        "commercial_esu_current_period_licensed",
        "commercial_esu_security_updates_only",
        "host_support_disposition_verified",
    )
    if any(type(getattr(receipt, name)) is not bool for name in dynamic_booleans):
        raise WindowsHostProfessionalCompositionReconciliationError("Step 241 receipt Boolean type is invalid")
    if receipt.commercial_esu_security_updates_only != receipt.commercial_esu_any_licensed:
        raise WindowsHostProfessionalCompositionReconciliationError("Step 241 ESU receipt correlation is invalid")
    expected_esu, expected_licensed, expected_complete, expected_current_licensed = _esu_disposition(
        validated_esu_projection
    )
    if (
        receipt.commercial_esu_disposition != expected_esu
        or receipt.commercial_esu_any_licensed != expected_licensed
        or receipt.commercial_esu_query_complete != expected_complete
        or receipt.commercial_esu_current_period_licensed
        != expected_current_licensed
    ):
        raise WindowsHostProfessionalCompositionReconciliationError("Step 241 ESU disposition is invalid")
    version_parts = receipt.cim_version.split(".")
    expected_build_crosscheck = (
        receipt.registry_current_build_number
        == receipt.cim_build_number
        == version_parts[2]
    )
    expected_version_crosscheck = (
        receipt.registry_current_major_version_number == int(version_parts[0])
        and receipt.registry_current_minor_version_number == int(version_parts[1])
    )
    expected_client_type_crosscheck = (
        receipt.registry_installation_type == "Client"
        and receipt.cim_product_type == 1
    )
    (
        expected_edition_family,
        expected_reconciliation_exact_tuple_matched,
        expected_reconciliation_applied,
    ) = _edition_disposition(
        (
            receipt.registry_edition_id,
            receipt.registry_composition_edition_id,
            receipt.cim_operating_system_sku,
        )
    )
    expected_edition_credible = expected_edition_family != "unselected"
    expected_identity_credible = (
        expected_build_crosscheck
        and expected_version_crosscheck
        and expected_client_type_crosscheck
        and expected_edition_credible
    )
    expected_known = (
        expected_identity_credible
        and receipt.registry_current_build_number == "19045"
        and receipt.registry_display_version == "22H2"
        and receipt.cim_version == "10.0.19045"
    )
    expected_node_floor = (
        expected_identity_credible and int(version_parts[0]) >= 10
    )
    if (
        receipt.registry_cim_build_crosscheck_passed
        != expected_build_crosscheck
        or receipt.registry_cim_version_crosscheck_passed
        != expected_version_crosscheck
        or receipt.windows_client_type_crosscheck_passed
        != expected_client_type_crosscheck
        or receipt.host_edition_family != expected_edition_family
        or receipt.edition_sku_mapping_credible != expected_edition_credible
        or receipt.edition_sku_reconciliation_exact_tuple_matched
        != expected_reconciliation_exact_tuple_matched
        or receipt.edition_sku_reconciliation_applied
        != expected_reconciliation_applied
        or receipt.other_mixed_edition_sku_tuple_authorized
        or receipt.windows_client_identity_credible != expected_identity_credible
        or receipt.windows_10_22h2_build_19045_classified != expected_known
        or receipt.node_documented_windows_x64_platform_floor_met
        != expected_node_floor
    ):
        raise WindowsHostProfessionalCompositionReconciliationError(
            "Step 241 host-identity receipt correlation is invalid"
        )
    known = receipt.windows_10_22h2_build_19045_classified
    if known:
        if (
            receipt.status != STATUS_WINDOWS_10_22H2_VENDOR_EOL
            or receipt.host_identity_disposition != IDENTITY_WINDOWS_10_22H2
            or receipt.microsoft_base_lifecycle_end_date
            != MICROSOFT_WINDOWS_10_22H2_BASE_LIFECYCLE_END_DATE
            or not receipt.windows_client_identity_credible
            or not receipt.host_support_disposition_verified
            or not receipt.node_documented_windows_x64_platform_floor_met
        ):
            raise WindowsHostProfessionalCompositionReconciliationError("Step 241 known-host receipt is invalid")
    elif receipt.windows_client_identity_credible:
        if (
            receipt.status != STATUS_LIFECYCLE_MAPPING_UNSELECTED
            or receipt.host_identity_disposition != IDENTITY_CREDIBLE_UNSELECTED
            or receipt.microsoft_base_lifecycle_end_date != "unselected"
            or receipt.host_support_disposition_verified
        ):
            raise WindowsHostProfessionalCompositionReconciliationError("Step 241 unselected-host receipt is invalid")
    elif (
        receipt.status != STATUS_IDENTITY_NOT_CREDIBLE
        or receipt.host_identity_disposition != IDENTITY_NOT_CREDIBLE
        or receipt.microsoft_base_lifecycle_end_date != "unselected"
        or receipt.host_support_disposition_verified
        or receipt.node_documented_windows_x64_platform_floor_met
    ):
        raise WindowsHostProfessionalCompositionReconciliationError("Step 241 uncredible-host receipt is invalid")


def prove_windows_host_professional_composition_reconciliation(
    envelope_document: bytes,
) -> WindowsHostProfessionalCompositionReconciliationReceipt:
    """Validate one exact canonical installer envelope and classify it."""

    try:
        envelope = _load_canonical_json(envelope_document)
        if frozenset(envelope) != frozenset(("authorization", "evidence")):
            raise ValueError("Step 241 envelope keys are invalid")
        authorization = _validate_authorization(envelope["authorization"])
        evidence = _exact_object(envelope["evidence"], _EVIDENCE_KEYS, "Step 241 evidence")
        registry, cim, esu_entries = _validate_evidence(evidence)

        registry_build = registry["CurrentBuildNumber"]
        cim_build = cim["BuildNumber"]
        version_parts = cim["Version"].split(".")
        build_crosscheck = registry_build == cim_build == version_parts[2]
        version_crosscheck = (
            registry["CurrentMajorVersionNumber"] == int(version_parts[0])
            and registry["CurrentMinorVersionNumber"] == int(version_parts[1])
        )
        client_type_crosscheck = (
            registry["InstallationType"] == "Client" and cim["ProductType"] == 1
        )
        edition_key = (
            registry["EditionID"],
            registry["CompositionEditionID"],
            cim["OperatingSystemSKU"],
        )
        (
            edition_family,
            reconciliation_exact_tuple_matched,
            reconciliation_applied,
        ) = _edition_disposition(edition_key)
        edition_credible = edition_family != "unselected"
        identity_credible = (
            build_crosscheck
            and version_crosscheck
            and client_type_crosscheck
            and edition_credible
        )
        known_target = (
            identity_credible
            and registry_build == "19045"
            and registry["DisplayVersion"] == "22H2"
            and cim["Version"] == "10.0.19045"
        )
        node_floor = (
            identity_credible
            and int(version_parts[0]) >= 10
        )

        if known_target:
            status = STATUS_WINDOWS_10_22H2_VENDOR_EOL
            identity_disposition = IDENTITY_WINDOWS_10_22H2
            lifecycle_end = MICROSOFT_WINDOWS_10_22H2_BASE_LIFECYCLE_END_DATE
        elif identity_credible:
            status = STATUS_LIFECYCLE_MAPPING_UNSELECTED
            identity_disposition = IDENTITY_CREDIBLE_UNSELECTED
            lifecycle_end = "unselected"
        else:
            status = STATUS_IDENTITY_NOT_CREDIBLE
            identity_disposition = IDENTITY_NOT_CREDIBLE
            lifecycle_end = "unselected"

        (
            esu_disposition,
            any_licensed,
            query_complete,
            current_period_licensed,
        ) = _esu_disposition(esu_entries)
        receipt = WindowsHostProfessionalCompositionReconciliationReceipt(
            receipt_type=RECEIPT_TYPE,
            schema_version=SCHEMA_VERSION,
            source=SOURCE,
            scope=SCOPE,
            status=status,
            policy_as_of=POLICY_AS_OF,
            approved_step240_accepted_state_manifest_sha256=(
                authorization["approved_step240_accepted_state_manifest_sha256"]
            ),
            approved_step240_package_manifest_sha256=(
                authorization["approved_step240_package_manifest_sha256"]
            ),
            approved_step240_canonical_receipt_sha256=(
                authorization["approved_step240_canonical_receipt_sha256"]
            ),
            approved_step240_readiness_status=(
                authorization["approved_step240_readiness_status"]
            ),
            authorization_document_sha256=hashlib.sha256(_canonical(authorization)).hexdigest(),
            evidence_document_sha256=hashlib.sha256(_canonical(evidence)).hexdigest(),
            node_version_tag=NODE_VERSION_TAG,
            node_building_commit=NODE_BUILDING_COMMIT,
            node_building_path=NODE_BUILDING_PATH,
            node_building_bytes=NODE_BUILDING_BYTES,
            node_building_sha256=NODE_BUILDING_SHA256,
            registry_view=REGISTRY_VIEW,
            registry_access_mode=REGISTRY_ACCESS_MODE,
            cim_class=CIM_CLASS,
            registry_edition_id=registry["EditionID"],
            registry_composition_edition_id=registry["CompositionEditionID"],
            registry_installation_type=registry["InstallationType"],
            registry_display_version=registry["DisplayVersion"],
            registry_current_build_number=registry_build,
            registry_ubr=registry["UBR"],
            registry_current_major_version_number=registry["CurrentMajorVersionNumber"],
            registry_current_minor_version_number=registry["CurrentMinorVersionNumber"],
            registry_product_name_display_only=registry["ProductName"],
            cim_version=cim["Version"],
            cim_build_number=cim_build,
            cim_operating_system_sku=cim["OperatingSystemSKU"],
            cim_product_type=cim["ProductType"],
            esu_year1_activation_id=esu_entries[0]["activation_id"],
            esu_year1_query_state=esu_entries[0]["query_state"],
            esu_year1_license_status=esu_entries[0]["license_status"],
            esu_year2_activation_id=esu_entries[1]["activation_id"],
            esu_year2_query_state=esu_entries[1]["query_state"],
            esu_year2_license_status=esu_entries[1]["license_status"],
            esu_year3_activation_id=esu_entries[2]["activation_id"],
            esu_year3_query_state=esu_entries[2]["query_state"],
            esu_year3_license_status=esu_entries[2]["license_status"],
            host_edition_family=edition_family,
            host_identity_disposition=identity_disposition,
            edition_sku_reconciliation_rule=RECONCILIATION_RULE,
            commercial_esu_disposition=esu_disposition,
            commercial_esu_current_period_year=COMMERCIAL_ESU_CURRENT_PERIOD_YEAR,
            consumer_esu_disposition=CONSUMER_ESU_DISPOSITION,
            microsoft_base_lifecycle_end_date=lifecycle_end,
            exact_step240_chain_bound=True,
            exact_node_building_policy_bound=True,
            host_inventory_read_only=True,
            commercial_esu_query_read_only=True,
            registry64_inventory_validated=True,
            cim_inventory_validated=True,
            registry_cim_build_crosscheck_passed=build_crosscheck,
            registry_cim_version_crosscheck_passed=version_crosscheck,
            windows_client_type_crosscheck_passed=client_type_crosscheck,
            edition_sku_mapping_credible=edition_credible,
            edition_sku_reconciliation_exact_tuple_matched=(
                reconciliation_exact_tuple_matched
            ),
            edition_sku_reconciliation_applied=reconciliation_applied,
            other_mixed_edition_sku_tuple_authorized=False,
            windows_client_identity_credible=identity_credible,
            windows_10_22h2_build_19045_classified=known_target,
            registry_product_name_used_for_decision=False,
            node_documented_windows_x64_platform_floor_met=node_floor,
            microsoft_base_lifecycle_supported=False,
            commercial_esu_query_complete=query_complete,
            commercial_esu_any_licensed=any_licensed,
            commercial_esu_current_period_licensed=current_period_licensed,
            commercial_esu_security_updates_only=any_licensed,
            commercial_esu_overrides_node_vendor_eol_rule=False,
            consumer_esu_machine_verification_interface_selected=False,
            host_support_disposition_verified=known_target,
            node_vendor_supported_operating_system=False,
            host_execution_platform_supported=False,
            windows_node_execution_authorized=False,
            probe_network_request_performed=False,
            probe_subprocess_or_shell_executed=False,
            probe_environment_read_or_mutated=False,
            probe_filesystem_read_or_written=False,
            node_or_npm_executed=False,
            package_manager_executed=False,
            lock_generation_authorized_or_performed=False,
            frontend_materialized=False,
            operational_write_performed=False,
            git_staging_commit_or_push_performed=False,
            application_activation_performed=False,
        )
        _validate_receipt(receipt)
        return receipt
    except WindowsHostProfessionalCompositionReconciliationError:
        raise
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise WindowsHostProfessionalCompositionReconciliationError(
            "Step 241 Windows host Professional-composition reconciliation proof failed"
        ) from error


def render_windows_host_professional_composition_reconciliation_receipt(
    receipt: WindowsHostProfessionalCompositionReconciliationReceipt,
) -> bytes:
    """Render one exact receipt as a canonical ASCII JSON object."""

    if type(receipt) is not WindowsHostProfessionalCompositionReconciliationReceipt:
        raise TypeError("exact Step 241 Windows host-support receipt is required")
    _validate_receipt(receipt)
    return _canonical(dataclasses.asdict(receipt))


def main() -> int:
    """Read one canonical envelope and emit exactly one canonical receipt line."""

    try:
        envelope = sys.stdin.buffer.read(MAX_CLI_ENVELOPE_BYTES + 1)
        receipt = prove_windows_host_professional_composition_reconciliation(envelope)
        sys.stdout.buffer.write(render_windows_host_professional_composition_reconciliation_receipt(receipt) + b"\n")
        return 0
    except Exception:
        sys.stderr.buffer.write(
            b"Step 241 Windows host Professional-composition reconciliation proof failed.\n"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AUTHORIZATION_SOURCE",
    "AUTHORIZATION_TYPE",
    "CIM_CLASS",
    "COMMERCIAL_ESU_CURRENT_PERIOD_YEAR",
    "CONSUMER_ESU_DISPOSITION",
    "ESU_ACTIVATION_IDS",
    "ESU_LICENSED_SECURITY_UPDATES_ONLY",
    "ESU_NOT_FOUND",
    "ESU_PRESENT_NOT_LICENSED",
    "ESU_QUERY_UNAVAILABLE",
    "EVIDENCE_SOURCE",
    "EVIDENCE_TYPE",
    "MAX_CLI_ENVELOPE_BYTES",
    "MICROSOFT_WINDOWS_10_22H2_BASE_LIFECYCLE_END_DATE",
    "NODE_BUILDING_BYTES",
    "NODE_BUILDING_COMMIT",
    "NODE_BUILDING_PATH",
    "NODE_BUILDING_SHA256",
    "NODE_VERSION_TAG",
    "POLICY_AS_OF",
    "RECONCILIATION_RULE",
    "RECEIPT_TYPE",
    "REGISTRY_ACCESS_MODE",
    "REGISTRY_VIEW",
    "SCHEMA_VERSION",
    "SCOPE",
    "SOURCE",
    "STATUS_IDENTITY_NOT_CREDIBLE",
    "STATUS_LIFECYCLE_MAPPING_UNSELECTED",
    "STATUS_WINDOWS_10_22H2_VENDOR_EOL",
    "STEP240_ACCEPTED_STATE_MANIFEST_SHA256",
    "STEP240_CANONICAL_RECEIPT_SHA256",
    "STEP240_PACKAGE_MANIFEST_SHA256",
    "STEP240_READINESS_STATUS",
    "OBSERVED_STEP240_CIM_OPERATING_SYSTEM_SKU",
    "OBSERVED_STEP240_REGISTRY_COMPOSITION_EDITION_ID",
    "OBSERVED_STEP240_REGISTRY_EDITION_ID",
    "WindowsHostProfessionalCompositionReconciliationError",
    "WindowsHostProfessionalCompositionReconciliationReceipt",
    "main",
    "prove_windows_host_professional_composition_reconciliation",
    "render_windows_host_professional_composition_reconciliation_receipt",
]
