from __future__ import annotations

import ast
import builtins
import copy
import dataclasses
import hashlib
import inspect
import io
import json
import os
import runpy
import socket
import subprocess
import sys
import urllib.request
import warnings
from dataclasses import replace

import pytest

import app.security.authentication_entra_calling_client_msal_browser_frontend_host_execution_platform_windows_host_edition_reconciliation_probe as probe


def _authorization() -> dict[str, object]:
    return {
        "approved_step240_accepted_state_manifest_sha256": (
            probe.STEP240_ACCEPTED_STATE_MANIFEST_SHA256
        ),
        "approved_step240_canonical_receipt_sha256": (
            probe.STEP240_CANONICAL_RECEIPT_SHA256
        ),
        "approved_step240_package_manifest_sha256": (
            probe.STEP240_PACKAGE_MANIFEST_SHA256
        ),
        "approved_step240_readiness_status": probe.STEP240_READINESS_STATUS,
        "document_type": probe.AUTHORIZATION_TYPE,
        "node_building_bytes": probe.NODE_BUILDING_BYTES,
        "node_building_commit": probe.NODE_BUILDING_COMMIT,
        "node_building_path": probe.NODE_BUILDING_PATH,
        "node_building_sha256": probe.NODE_BUILDING_SHA256,
        "node_version_tag": probe.NODE_VERSION_TAG,
        "observed_step240_cim_operating_system_sku": (
            probe.OBSERVED_STEP240_CIM_OPERATING_SYSTEM_SKU
        ),
        "observed_step240_registry_composition_edition_id": (
            probe.OBSERVED_STEP240_REGISTRY_COMPOSITION_EDITION_ID
        ),
        "observed_step240_registry_edition_id": (
            probe.OBSERVED_STEP240_REGISTRY_EDITION_ID
        ),
        "policy_as_of": probe.POLICY_AS_OF,
        "reconciliation_rule": probe.RECONCILIATION_RULE,
        "schema_version": probe.SCHEMA_VERSION,
        "source": probe.AUTHORIZATION_SOURCE,
    }


def _esu(
    states: tuple[str, str, str] = ("not_found", "not_found", "not_found"),
    statuses: tuple[int | None, int | None, int | None] = (None, None, None),
) -> list[dict[str, object]]:
    return [
        {
            "activation_id": activation_id,
            "license_status": statuses[index],
            "program_year": index + 1,
            "query_state": states[index],
        }
        for index, activation_id in enumerate(probe.ESU_ACTIVATION_IDS)
    ]


def _evidence() -> dict[str, object]:
    return {
        "cim": {
            "BuildNumber": "19045",
            "OperatingSystemSKU": 48,
            "ProductType": 1,
            "Version": "10.0.19045",
        },
        "cim_class": probe.CIM_CLASS,
        "commercial_esu_activation_ids": _esu(),
        "evidence_type": probe.EVIDENCE_TYPE,
        "registry64": {
            "CompositionEditionID": "Enterprise",
            "CurrentBuildNumber": "19045",
            "CurrentMajorVersionNumber": 10,
            "CurrentMinorVersionNumber": 0,
            "DisplayVersion": "22H2",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "ProductName": "Windows 10 Pro",
            "UBR": 6216,
        },
        "registry_access_mode": probe.REGISTRY_ACCESS_MODE,
        "registry_view": probe.REGISTRY_VIEW,
        "schema_version": probe.SCHEMA_VERSION,
        "source": probe.EVIDENCE_SOURCE,
    }


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _envelope(
    *,
    authorization: dict[str, object] | None = None,
    evidence: dict[str, object] | None = None,
) -> bytes:
    return _canonical(
        {
            "authorization": _authorization() if authorization is None else authorization,
            "evidence": _evidence() if evidence is None else evidence,
        }
    )


def _prove(evidence: dict[str, object] | None = None) -> probe.WindowsHostProfessionalCompositionReconciliationReceipt:
    return probe.prove_windows_host_professional_composition_reconciliation(_envelope(evidence=evidence))


def test_exact_public_policy_and_predecessor_constants() -> None:
    assert probe.POLICY_AS_OF == "2026-08-20"
    assert probe.NODE_VERSION_TAG == "v24.19.0"
    assert probe.NODE_BUILDING_COMMIT == "cdc1b38d40cb567b7ad0b39c86addf830a0af0ae"
    assert probe.NODE_BUILDING_PATH == "BUILDING.md"
    assert probe.NODE_BUILDING_BYTES == 38_739
    assert probe.NODE_BUILDING_SHA256 == (
        "f77e6a28ffd03ff93f05c116fc70a795ff348f7ef4ad4669abcdf7d97e310a1c"
    )
    assert probe.STEP240_ACCEPTED_STATE_MANIFEST_SHA256 == (
        "bd382feb228394939a2343f731e36c52a7712c1ad578ef6f606f41d867dca067"
    )
    assert probe.STEP240_PACKAGE_MANIFEST_SHA256 == (
        "ab2805047b5583a8e8550e8d27e002923a8c962fb325eb5c1624afe9e5732b6f"
    )
    assert probe.STEP240_CANONICAL_RECEIPT_SHA256 == (
        "d32f3069da64c6b485489b75f84fc4a99646350e790bd8682239ead72fa991e0"
    )
    assert probe.STEP240_READINESS_STATUS == (
        "windows_host_identity_not_credible_execution_blocked"
    )
    assert probe.RECONCILIATION_RULE == (
        "registry_edition_professional_composition_enterprise_cim_sku_48_only"
    )
    assert probe.ESU_ACTIVATION_IDS == (
        "f520e45e-7413-4a34-a497-d2765967d094",
        "1043add5-23b1-4afb-9a0f-64343c8f3f8d",
        "83d49986-add3-41d7-ba33-87c7bfb5c0fb",
    )


def test_exact_windows_10_22h2_professional_disposition_is_unsupported() -> None:
    receipt = _prove()
    assert receipt.status == probe.STATUS_WINDOWS_10_22H2_VENDOR_EOL
    assert receipt.host_identity_disposition == probe.IDENTITY_WINDOWS_10_22H2
    assert receipt.host_edition_family == "professional"
    assert receipt.microsoft_base_lifecycle_end_date == "2025-10-14"
    assert receipt.registry_cim_build_crosscheck_passed is True
    assert receipt.registry_cim_version_crosscheck_passed is True
    assert receipt.windows_client_type_crosscheck_passed is True
    assert receipt.edition_sku_mapping_credible is True
    assert receipt.edition_sku_reconciliation_exact_tuple_matched is True
    assert receipt.edition_sku_reconciliation_applied is True
    assert receipt.other_mixed_edition_sku_tuple_authorized is False
    assert receipt.windows_client_identity_credible is True
    assert receipt.windows_10_22h2_build_19045_classified is True
    assert receipt.node_documented_windows_x64_platform_floor_met is True
    assert receipt.host_support_disposition_verified is True
    assert receipt.microsoft_base_lifecycle_supported is False
    assert receipt.node_vendor_supported_operating_system is False
    assert receipt.host_execution_platform_supported is False
    assert receipt.windows_node_execution_authorized is False


def test_only_exact_observed_professional_enterprise_48_tuple_is_reconciled() -> None:
    evidence = _evidence()
    registry = evidence["registry64"]
    cim = evidence["cim"]
    assert type(registry) is dict and type(cim) is dict
    receipt = _prove(evidence)
    assert receipt.host_edition_family == "professional"
    assert receipt.edition_sku_reconciliation_rule == probe.RECONCILIATION_RULE
    assert receipt.edition_sku_reconciliation_exact_tuple_matched is True
    assert receipt.edition_sku_reconciliation_applied is True
    assert receipt.other_mixed_edition_sku_tuple_authorized is False
    assert receipt.windows_client_identity_credible is True
    assert receipt.status == probe.STATUS_WINDOWS_10_22H2_VENDOR_EOL
    assert receipt.windows_node_execution_authorized is False


@pytest.mark.parametrize(
    ("edition_id", "composition_id", "sku", "family"),
    [
        ("Core", "Core", 101, "home"),
        ("CoreCountrySpecific", "CoreCountrySpecific", 99, "home_country_specific"),
        ("CoreN", "CoreN", 98, "home_n"),
        ("CoreSingleLanguage", "CoreSingleLanguage", 100, "home_single_language"),
        ("Education", "Education", 121, "education"),
        ("EducationN", "EducationN", 122, "education_n"),
        ("Enterprise", "Enterprise", 4, "enterprise"),
        ("EnterpriseN", "EnterpriseN", 27, "enterprise_n"),
        ("Professional", "Professional", 48, "professional"),
        ("ProfessionalEducation", "ProfessionalEducation", 164, "professional_education"),
        ("ProfessionalEducationN", "ProfessionalEducationN", 165, "professional_education_n"),
        ("ProfessionalN", "ProfessionalN", 49, "professional_n"),
        ("ProfessionalWorkstation", "ProfessionalWorkstation", 161, "professional_workstation"),
        ("ProfessionalWorkstationN", "ProfessionalWorkstationN", 162, "professional_workstation_n"),
    ],
)
def test_ordinary_client_mappings_do_not_use_reconciliation(
    edition_id: str, composition_id: str, sku: int, family: str
) -> None:
    evidence = _evidence()
    registry = evidence["registry64"]
    cim = evidence["cim"]
    assert type(registry) is dict and type(cim) is dict
    registry["EditionID"] = edition_id
    registry["CompositionEditionID"] = composition_id
    cim["OperatingSystemSKU"] = sku
    receipt = _prove(evidence)
    assert receipt.host_edition_family == family
    assert receipt.edition_sku_reconciliation_exact_tuple_matched is False
    assert receipt.edition_sku_reconciliation_applied is False
    assert receipt.other_mixed_edition_sku_tuple_authorized is False
    assert receipt.windows_client_identity_credible is True
    assert receipt.windows_node_execution_authorized is False


@pytest.mark.parametrize(
    ("edition_id", "composition_id", "sku"),
    [
        ("Professional", "EnterpriseN", 48),
        ("ProfessionalN", "Enterprise", 48),
        ("Professional", "Enterprise", 49),
        ("Enterprise", "Professional", 48),
        ("Professional", "Core", 48),
        ("Professional", "Enterprise", 4),
        ("ProfessionalEducation", "Enterprise", 164),
    ],
)
def test_every_nearby_mixed_tuple_remains_unselected(
    edition_id: str, composition_id: str, sku: int
) -> None:
    evidence = _evidence()
    registry = evidence["registry64"]
    cim = evidence["cim"]
    assert type(registry) is dict and type(cim) is dict
    registry["EditionID"] = edition_id
    registry["CompositionEditionID"] = composition_id
    cim["OperatingSystemSKU"] = sku
    receipt = _prove(evidence)
    assert receipt.host_edition_family == "unselected"
    assert receipt.edition_sku_mapping_credible is False
    assert receipt.edition_sku_reconciliation_exact_tuple_matched is False
    assert receipt.edition_sku_reconciliation_applied is False
    assert receipt.other_mixed_edition_sku_tuple_authorized is False
    assert receipt.status == probe.STATUS_IDENTITY_NOT_CREDIBLE
    assert receipt.windows_node_execution_authorized is False


@pytest.mark.parametrize(
    (
        "states",
        "statuses",
        "disposition",
        "any_licensed",
        "current_licensed",
        "complete",
    ),
    [
        (("found", "not_found", "not_found"), (1, None, None), probe.ESU_LICENSED_SECURITY_UPDATES_ONLY, True, True, True),
        (("not_found", "found", "not_found"), (None, 1, None), probe.ESU_NOT_FOUND, True, False, True),
        (("not_found", "not_found", "found"), (None, None, 1), probe.ESU_NOT_FOUND, True, False, True),
        (("found", "not_found", "not_found"), (0, None, None), probe.ESU_PRESENT_NOT_LICENSED, False, False, True),
        (("query_unavailable", "not_found", "not_found"), (None, None, None), probe.ESU_QUERY_UNAVAILABLE, False, False, False),
        (("query_unavailable", "found", "not_found"), (None, 1, None), probe.ESU_QUERY_UNAVAILABLE, True, False, False),
        (("not_found", "not_found", "not_found"), (None, None, None), probe.ESU_NOT_FOUND, False, False, True),
    ],
)
def test_esu_dispositions_never_override_node_vendor_eol(
    states: tuple[str, str, str],
    statuses: tuple[int | None, int | None, int | None],
    disposition: str,
    any_licensed: bool,
    current_licensed: bool,
    complete: bool,
) -> None:
    evidence = _evidence()
    evidence["commercial_esu_activation_ids"] = _esu(states, statuses)
    receipt = _prove(evidence)
    assert receipt.commercial_esu_disposition == disposition
    assert receipt.commercial_esu_current_period_year == 1
    assert receipt.commercial_esu_any_licensed is any_licensed
    assert receipt.commercial_esu_current_period_licensed is current_licensed
    assert receipt.commercial_esu_security_updates_only is any_licensed
    assert receipt.commercial_esu_query_complete is complete
    assert receipt.consumer_esu_disposition == (
        "not_machine_proven_by_selected_official_interface"
    )
    assert receipt.consumer_esu_machine_verification_interface_selected is False
    assert receipt.commercial_esu_overrides_node_vendor_eol_rule is False
    assert receipt.node_vendor_supported_operating_system is False
    assert receipt.windows_node_execution_authorized is False


@pytest.mark.parametrize(
    ("section", "name", "value", "flag"),
    [
        ("registry64", "CurrentBuildNumber", "19044", "registry_cim_build_crosscheck_passed"),
        ("cim", "BuildNumber", "19044", "registry_cim_build_crosscheck_passed"),
        ("cim", "Version", "10.0.19044", "registry_cim_build_crosscheck_passed"),
        ("registry64", "CurrentMajorVersionNumber", 11, "registry_cim_version_crosscheck_passed"),
        ("registry64", "CurrentMinorVersionNumber", 1, "registry_cim_version_crosscheck_passed"),
        ("registry64", "InstallationType", "Server", "windows_client_type_crosscheck_passed"),
        ("cim", "ProductType", 2, "windows_client_type_crosscheck_passed"),
        ("registry64", "CompositionEditionID", "EnterpriseN", "edition_sku_mapping_credible"),
        ("registry64", "EditionID", "EnterpriseS", "edition_sku_mapping_credible"),
        ("cim", "OperatingSystemSKU", 125, "edition_sku_mapping_credible"),
    ],
)
def test_identity_crosscheck_failures_return_fail_closed_receipt(
    section: str, name: str, value: object, flag: str
) -> None:
    evidence = _evidence()
    target = evidence[section]
    assert type(target) is dict
    target[name] = value
    receipt = _prove(evidence)
    assert getattr(receipt, flag) is False
    assert receipt.windows_client_identity_credible is False
    assert receipt.windows_10_22h2_build_19045_classified is False
    assert receipt.status == probe.STATUS_IDENTITY_NOT_CREDIBLE
    assert receipt.host_support_disposition_verified is False
    assert receipt.windows_node_execution_authorized is False


def test_credible_other_build_is_unselected_and_fail_closed() -> None:
    evidence = _evidence()
    registry = evidence["registry64"]
    cim = evidence["cim"]
    assert type(registry) is dict and type(cim) is dict
    registry["CurrentBuildNumber"] = "22631"
    registry["DisplayVersion"] = "23H2"
    cim["BuildNumber"] = "22631"
    cim["Version"] = "10.0.22631"
    receipt = _prove(evidence)
    assert receipt.windows_client_identity_credible is True
    assert receipt.node_documented_windows_x64_platform_floor_met is True
    assert receipt.windows_10_22h2_build_19045_classified is False
    assert receipt.status == probe.STATUS_LIFECYCLE_MAPPING_UNSELECTED
    assert receipt.microsoft_base_lifecycle_end_date == "unselected"
    assert receipt.host_support_disposition_verified is False
    assert receipt.windows_node_execution_authorized is False


@pytest.mark.parametrize(
    "product_name",
    ["Windows 10 Pro", "misleading server label", "X"],
)
def test_product_name_is_display_only_and_never_decides(product_name: str) -> None:
    evidence = _evidence()
    registry = evidence["registry64"]
    assert type(registry) is dict
    registry["ProductName"] = product_name
    receipt = _prove(evidence)
    assert receipt.registry_product_name_display_only == product_name
    assert receipt.registry_product_name_used_for_decision is False
    assert receipt.status == probe.STATUS_WINDOWS_10_22H2_VENDOR_EOL


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update({"unexpected": False}),
        lambda value: value.pop("policy_as_of"),
        lambda value: value.__setitem__("policy_as_of", "2026-08-21"),
        lambda value: value.__setitem__("schema_version", True),
        lambda value: value.__setitem__("node_building_bytes", 38_738),
        lambda value: value.__setitem__("node_building_sha256", "0" * 64),
        lambda value: value.__setitem__("approved_step240_accepted_state_manifest_sha256", "0" * 64),
        lambda value: value.__setitem__("approved_step240_package_manifest_sha256", "0" * 64),
        lambda value: value.__setitem__("approved_step240_canonical_receipt_sha256", "0" * 64),
        lambda value: value.__setitem__("approved_step240_readiness_status", "accepted"),
        lambda value: value.__setitem__("observed_step240_cim_operating_system_sku", 49),
        lambda value: value.__setitem__("observed_step240_registry_composition_edition_id", "Professional"),
        lambda value: value.__setitem__("observed_step240_registry_edition_id", "Enterprise"),
        lambda value: value.__setitem__("reconciliation_rule", "widened"),
        lambda value: value.__setitem__("source", probe.EVIDENCE_SOURCE),
    ],
)
def test_every_authorization_binding_is_closed_against_tamper(mutate: object) -> None:
    authorization = _authorization()
    mutate(authorization)  # type: ignore[operator]
    with pytest.raises(probe.WindowsHostProfessionalCompositionReconciliationError):
        probe.prove_windows_host_professional_composition_reconciliation(_envelope(authorization=authorization))


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("registry_view", "Default"),
        ("registry_access_mode", "read_write"),
        ("cim_class", "Win32_ComputerSystem"),
        ("evidence_type", probe.AUTHORIZATION_TYPE),
        ("schema_version", True),
        ("source", probe.AUTHORIZATION_SOURCE),
    ],
)
def test_evidence_source_and_acquisition_contract_is_exact(name: str, value: object) -> None:
    evidence = _evidence()
    evidence[name] = value
    with pytest.raises(probe.WindowsHostProfessionalCompositionReconciliationError):
        _prove(evidence)


@pytest.mark.parametrize(
    ("section", "name", "value"),
    [
        ("registry64", "CurrentBuildNumber", 19045),
        ("registry64", "CurrentBuildNumber", "019045"),
        ("registry64", "DisplayVersion", "22H3"),
        ("registry64", "UBR", True),
        ("registry64", "UBR", -1),
        ("registry64", "CurrentMajorVersionNumber", "10"),
        ("registry64", "ProductName", "Windows\n10"),
        ("registry64", "ProductName", "Windows 10 Pro™"),
        ("registry64", "EditionID", ""),
        ("cim", "Version", "10.0"),
        ("cim", "BuildNumber", 19045),
        ("cim", "OperatingSystemSKU", True),
        ("cim", "OperatingSystemSKU", -1),
        ("cim", "ProductType", 4),
    ],
)
def test_registry_and_cim_wire_types_ranges_and_ascii_are_strict(
    section: str, name: str, value: object
) -> None:
    evidence = _evidence()
    target = evidence[section]
    assert type(target) is dict
    target[name] = value
    with pytest.raises(probe.WindowsHostProfessionalCompositionReconciliationError):
        _prove(evidence)


@pytest.mark.parametrize(
    "mutation",
    [
        "short",
        "extra",
        "wrong_id",
        "wrong_year",
        "wrong_state",
        "found_null",
        "found_bool",
        "found_out_of_range",
        "not_found_status",
        "unavailable_status",
        "extra_key",
        "missing_key",
    ],
)
def test_commercial_esu_inventory_is_exact_and_correlated(mutation: str) -> None:
    evidence = _evidence()
    entries = _esu()
    if mutation == "short":
        entries.pop()
    elif mutation == "extra":
        entries.append(copy.deepcopy(entries[-1]))
    elif mutation == "wrong_id":
        entries[0]["activation_id"] = probe.ESU_ACTIVATION_IDS[1]
    elif mutation == "wrong_year":
        entries[0]["program_year"] = 2
    elif mutation == "wrong_state":
        entries[0]["query_state"] = "unknown"
    elif mutation == "found_null":
        entries[0]["query_state"] = "found"
    elif mutation == "found_bool":
        entries[0]["query_state"] = "found"
        entries[0]["license_status"] = True
    elif mutation == "found_out_of_range":
        entries[0]["query_state"] = "found"
        entries[0]["license_status"] = 7
    elif mutation == "not_found_status":
        entries[0]["license_status"] = 1
    elif mutation == "unavailable_status":
        entries[0]["query_state"] = "query_unavailable"
        entries[0]["license_status"] = 1
    elif mutation == "extra_key":
        entries[0]["name"] = "secret"
    elif mutation == "missing_key":
        entries[0].pop("license_status")
    evidence["commercial_esu_activation_ids"] = entries
    with pytest.raises(probe.WindowsHostProfessionalCompositionReconciliationError):
        _prove(evidence)


def test_strict_canonical_envelope_rejects_alternate_encodings_and_duplicates() -> None:
    canonical = _envelope()
    variants = (
        b" " + canonical,
        canonical + b"\n",
        b"\xef\xbb\xbf" + canonical,
        json.dumps(json.loads(canonical), indent=2).encode("ascii"),
        canonical.replace(b'"authorization":', b'"authorization":null,"authorization":', 1),
        b'{"authorization":NaN,"evidence":null}',
        b"{}",
        b"[]",
        b"null",
    )
    for value in variants:
        with pytest.raises(probe.WindowsHostProfessionalCompositionReconciliationError):
            probe.prove_windows_host_professional_composition_reconciliation(value)


def test_envelope_rejects_empty_oversize_extra_and_missing_top_level_keys() -> None:
    for value in (b"", b"{" + b"x" * probe.MAX_CLI_ENVELOPE_BYTES + b"}"):
        with pytest.raises(probe.WindowsHostProfessionalCompositionReconciliationError):
            probe.prove_windows_host_professional_composition_reconciliation(value)
    for object_value in (
        {"authorization": _authorization()},
        {"evidence": _evidence()},
        {"authorization": _authorization(), "evidence": _evidence(), "extra": False},
    ):
        with pytest.raises(probe.WindowsHostProfessionalCompositionReconciliationError):
            probe.prove_windows_host_professional_composition_reconciliation(_canonical(object_value))


def test_authorization_and_evidence_digests_bind_canonical_subdocuments() -> None:
    receipt = _prove()
    assert receipt.authorization_document_sha256 == hashlib.sha256(
        _canonical(_authorization())
    ).hexdigest()
    assert receipt.evidence_document_sha256 == hashlib.sha256(
        _canonical(_evidence())
    ).hexdigest()


def test_receipt_is_frozen_slotted_exact_and_canonical() -> None:
    receipt = _prove()
    assert len(dataclasses.fields(type(receipt))) == 88
    with pytest.raises(dataclasses.FrozenInstanceError):
        receipt.status = "tampered"  # type: ignore[misc]
    assert not hasattr(receipt, "__dict__")
    rendered = probe.render_windows_host_professional_composition_reconciliation_receipt(receipt)
    value = json.loads(rendered)
    assert rendered == _canonical(value)
    assert set(value) == {field.name for field in dataclasses.fields(type(receipt))}
    assert b"\n" not in rendered


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("windows_node_execution_authorized", True),
        ("node_vendor_supported_operating_system", True),
        ("commercial_esu_overrides_node_vendor_eol_rule", True),
        ("consumer_esu_machine_verification_interface_selected", True),
        ("probe_network_request_performed", True),
        ("probe_subprocess_or_shell_executed", True),
        ("probe_environment_read_or_mutated", True),
        ("probe_filesystem_read_or_written", True),
        ("node_or_npm_executed", True),
        ("package_manager_executed", True),
        ("lock_generation_authorized_or_performed", True),
        ("frontend_materialized", True),
        ("operational_write_performed", True),
        ("git_staging_commit_or_push_performed", True),
        ("application_activation_performed", True),
        ("exact_step240_chain_bound", False),
        ("exact_node_building_policy_bound", False),
        ("registry_product_name_used_for_decision", True),
        ("commercial_esu_security_updates_only", True),
    ],
)
def test_renderer_rejects_tampered_receipt_controls(field: str, value: object) -> None:
    with pytest.raises(probe.WindowsHostProfessionalCompositionReconciliationError):
        probe.render_windows_host_professional_composition_reconciliation_receipt(
            replace(_prove(), **{field: value})
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorization_document_sha256", "0" * 64),
        ("evidence_document_sha256", "0" * 64),
        ("registry_ubr", 6217),
        ("registry_current_build_number", "19044"),
        ("cim_version", "10.0.19044"),
        ("esu_year1_query_state", "query_unavailable"),
        ("host_edition_family", "enterprise"),
        ("registry_cim_build_crosscheck_passed", False),
        ("windows_client_identity_credible", False),
        ("windows_10_22h2_build_19045_classified", False),
        ("commercial_esu_current_period_year", 2),
        ("consumer_esu_disposition", "proven"),
        ("status", probe.STATUS_LIFECYCLE_MAPPING_UNSELECTED),
        ("approved_step240_readiness_status", "accepted"),
        ("edition_sku_reconciliation_rule", "widened"),
        ("edition_sku_reconciliation_exact_tuple_matched", False),
        ("edition_sku_reconciliation_applied", False),
        ("other_mixed_edition_sku_tuple_authorized", True),
    ],
)
def test_renderer_rejects_tampered_inventory_digest_and_disposition(
    field: str, value: object
) -> None:
    with pytest.raises(probe.WindowsHostProfessionalCompositionReconciliationError):
        probe.render_windows_host_professional_composition_reconciliation_receipt(
            replace(_prove(), **{field: value})
        )


def test_renderer_rejects_wrong_receipt_type() -> None:
    with pytest.raises(TypeError):
        probe.render_windows_host_professional_composition_reconciliation_receipt(object())  # type: ignore[arg-type]


def test_proof_uses_no_prohibited_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    def prohibited(*unused_args: object, **unused_kwargs: object) -> object:
        raise AssertionError("prohibited capability used")

    with monkeypatch.context() as scoped:
        scoped.setattr(builtins, "open", prohibited)
        scoped.setattr(os, "getenv", prohibited)
        scoped.setattr(os, "putenv", prohibited)
        scoped.setattr(socket, "socket", prohibited)
        scoped.setattr(subprocess, "Popen", prohibited)
        scoped.setattr(subprocess, "run", prohibited)
        scoped.setattr(urllib.request, "urlopen", prohibited)
        receipt = _prove()
        rendered = probe.render_windows_host_professional_composition_reconciliation_receipt(receipt)
    assert rendered.startswith(b"{") and rendered.endswith(b"}")


def test_probe_source_import_and_escape_inventory_is_capability_minimal() -> None:
    source = inspect.getsource(probe)
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module.split(".")[0])
    assert imported <= {
        "__future__",
        "dataclasses",
        "hashlib",
        "json",
        "re",
        "sys",
        "typing",
    }
    for forbidden in (
        "open(",
        "os.",
        "pathlib.",
        "socket.",
        "subprocess.",
        "urllib.",
        "requests",
        "httpx",
        "winreg",
        "wmi",
        "powershell",
        "shell=True",
        "eval(",
        "exec(",
        "compile(",
        "__import__(",
    ):
        assert forbidden not in source


def _text_stream(initial: bytes = b"") -> tuple[io.TextIOWrapper, io.BytesIO]:
    buffer = io.BytesIO(initial)
    return io.TextIOWrapper(buffer, encoding="ascii"), buffer


def test_main_emits_one_canonical_receipt_line(monkeypatch: pytest.MonkeyPatch) -> None:
    stdin, _ = _text_stream(_envelope())
    stdout, stdout_bytes = _text_stream()
    stderr, stderr_bytes = _text_stream()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)
    assert probe.main() == 0
    stdout.flush()
    stderr.flush()
    output = stdout_bytes.getvalue()
    assert output == probe.render_windows_host_professional_composition_reconciliation_receipt(_prove()) + b"\n"
    assert output.count(b"\n") == 1
    assert stderr_bytes.getvalue() == b""


def test_main_failure_is_sanitized_and_emits_no_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    stdin, _ = _text_stream(b"{}")
    stdout, stdout_bytes = _text_stream()
    stderr, stderr_bytes = _text_stream()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)
    assert probe.main() == 1
    stdout.flush()
    stderr.flush()
    assert stdout_bytes.getvalue() == b""
    assert stderr_bytes.getvalue() == (
        b"Step 241 Windows host Professional-composition reconciliation proof failed.\n"
    )


def test_true_python_m_module_alias_guard_and_cli_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = probe.__name__
    expected = probe.render_windows_host_professional_composition_reconciliation_receipt(_prove()) + b"\n"
    stdin, _ = _text_stream(_envelope())
    stdout, stdout_bytes = _text_stream()
    stderr, stderr_bytes = _text_stream()
    original_module = sys.modules.pop(module_name)
    executed_module = None
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(sys, "stdin", stdin)
            scoped.setattr(sys, "stdout", stdout)
            scoped.setattr(sys, "stderr", stderr)
            with pytest.raises(SystemExit) as exited:
                runpy.run_module(module_name, run_name="__main__", alter_sys=True)
            stdout.flush()
            stderr.flush()
            executed_module = sys.modules.get(module_name)
    finally:
        sys.modules[module_name] = original_module
    assert exited.value.code == 0
    assert executed_module is not None and executed_module is not original_module
    assert stdout_bytes.getvalue() == expected
    assert stderr_bytes.getvalue() == b""


def test_python_m_alias_guard_rejects_preexisting_distinct_canonical_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = probe.__name__
    stdin, _ = _text_stream(_envelope())
    stdout, _ = _text_stream()
    stderr, _ = _text_stream()
    with monkeypatch.context() as scoped:
        scoped.setattr(sys, "stdin", stdin)
        scoped.setattr(sys, "stdout", stdout)
        scoped.setattr(sys, "stderr", stderr)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            with pytest.raises(RuntimeError, match="module identity cannot be bound safely"):
                runpy.run_module(module_name, run_name="__main__", alter_sys=True)
