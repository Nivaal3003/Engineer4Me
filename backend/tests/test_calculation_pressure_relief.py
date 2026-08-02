"""Phase 7 Step 103 pressure-relief readiness and hard-safety tests."""

from __future__ import annotations

import ast
import inspect
from math import inf, nan
from types import MappingProxyType

import pytest
from pydantic import ValidationError

from app.engineering import calculations
from app.engineering.calculations import pressure_relief as relief
from app.engineering.calculations.models import (
    CalculationStatus,
    FindingSeverity,
    MethodLifecycleStatus,
)


def flow_basis() -> relief.PressureReliefFlowBasis:
    return relief.PressureReliefFlowBasis(
        required_relieving_mass_flow_kg_s=4.25,
        load_determination_reference="CALC-RELIEF-LOAD-001",
        load_determination_basis=(
            "Required mass flow supplied by the separately reviewed scenario study."
        ),
        supplied_by="Process engineering",
    )


def scenario(
    *,
    scenario_id: str = "blocked-outlet-1",
    protected_equipment_reference: str = "V-101",
    flow: relief.PressureReliefFlowBasis | None = None,
    credible: bool = True,
) -> relief.PressureReliefScenarioBasis:
    return relief.PressureReliefScenarioBasis(
        scenario_id=scenario_id,
        scenario_kind=relief.PressureReliefScenarioKind.BLOCKED_OUTLET,
        title="Documented blocked-outlet case",
        protected_equipment_reference=protected_equipment_reference,
        scenario_description=(
            "The process study identifies a credible blocked outlet while feed "
            "continues at the reviewed relieving condition."
        ),
        credibility_confirmed=credible,
        credibility_basis_reference="HAZOP-REV-C-NODE-14" if credible else None,
        flow_basis=flow_basis() if flow is None else flow,
    )


def pressure_basis(
    *,
    basis_kind: relief.PressureReliefPressureBasisKind = (
        relief.PressureReliefPressureBasisKind.ABSOLUTE
    ),
    atmosphere: float | None = None,
) -> relief.PressureReliefPressureBasis:
    return relief.PressureReliefPressureBasis(
        basis_kind=basis_kind,
        set_pressure_pa=1_000_000.0,
        maximum_allowable_working_pressure_pa=1_100_000.0,
        relieving_pressure_pa=1_100_000.0,
        total_backpressure_pa=120_000.0,
        atmospheric_pressure_absolute_pa=atmosphere,
        pressure_source_reference="V-101-DESIGN-DATA-REV-B",
    )


def jurisdiction_basis(
    *,
    family: relief.PressureReliefStandardsFamily = (
        relief.PressureReliefStandardsFamily.API_520_521
    ),
) -> relief.PressureReliefJurisdictionBasis:
    return relief.PressureReliefJurisdictionBasis(
        jurisdiction_id="ZA-project-jurisdiction",
        authority_having_jurisdiction="Project pressure-equipment authority",
        applicable_design_code_reference="PROJECT-DESIGN-CODE-REV-D",
        standards_family=family,
        exact_edition_and_amendment_reference="CONTROLLED-STANDARD-REGISTER-REV-F",
        jurisdiction_source_reference="PROJECT-CODE-BASIS-REV-D",
    )


def fluid_properties(
    phase: relief.PressureReliefFluidPhase,
) -> relief.PressureReliefFluidProperties:
    common = {
        "phase": phase,
        "relieving_temperature_k": 410.0,
        "property_source_reference": "PROCESS-DATASHEET-REV-E",
        "condition_basis": (
            "Properties evaluated at the documented relieving pressure and temperature."
        ),
    }
    if phase is relief.PressureReliefFluidPhase.LIQUID:
        return relief.PressureReliefFluidProperties(
            **common,
            liquid_density_kg_m3=825.0,
        )
    if phase is relief.PressureReliefFluidPhase.GAS_VAPOUR:
        return relief.PressureReliefFluidProperties(
            **common,
            gas_molar_mass_kg_kmol=44.0,
            compressibility_factor=0.92,
            isentropic_exponent=1.28,
        )
    return relief.PressureReliefFluidProperties(
        **common,
        steam_specific_volume_m3_kg=0.18,
        dry_or_superheated_steam_confirmed=True,
    )


def complete_request(
    phase: relief.PressureReliefFluidPhase = relief.PressureReliefFluidPhase.LIQUID,
) -> relief.PressureReliefReadinessRequest:
    return relief.PressureReliefReadinessRequest(
        request_id=f"readiness-{phase.value}",
        scenarios=(scenario(),),
        pressure_basis=pressure_basis(),
        jurisdiction_basis=jurisdiction_basis(),
        fluid_properties=fluid_properties(phase),
        selected_standards_pack_id=relief.API_520_521_STANDARDS_PACK_ID,
        selected_standards_pack_version=relief.PRESSURE_RELIEF_STANDARDS_PACK_VERSION,
        competency_requirement_acknowledged=True,
        proposed_reviewer_evidence_reference="REVIEW-ASSIGNMENT-PRV-001",
    )


def finding_ids(
    result: relief.PressureReliefSafetyGateResult,
) -> tuple[str, ...]:
    return tuple(finding.finding_id for finding in result.blocking_findings)


def test_versions_and_non_calculation_boundary_are_exact() -> None:
    assert relief.PRESSURE_RELIEF_FOUNDATION_VERSION == "1.0.0"
    assert relief.PRESSURE_RELIEF_STANDARDS_PACK_VERSION == "1.0.0"
    assert not hasattr(relief, "PRESSURE_RELIEF_CALCULATORS_VERSION")
    assert not hasattr(relief, "PRESSURE_RELIEF_METHOD_VERSION")
    assert calculations.FOUNDATION_VERSION == "0.6.0"


def test_standards_pack_registry_is_exact_and_immutable() -> None:
    expected_keys = (
        (relief.API_520_521_STANDARDS_PACK_ID, "1.0.0"),
        (relief.ISO_4126_STANDARDS_PACK_ID, "1.0.0"),
    )
    assert isinstance(relief.PRESSURE_RELIEF_STANDARDS_PACK_REGISTRY, MappingProxyType)
    assert tuple(relief.PRESSURE_RELIEF_STANDARDS_PACK_REGISTRY) == expected_keys
    assert relief.PRESSURE_RELIEF_DISCOVERY_ENTRIES == (
        relief.API_520_521_STANDARDS_PACK,
        relief.ISO_4126_STANDARDS_PACK,
    )
    with pytest.raises(TypeError):
        relief.PRESSURE_RELIEF_STANDARDS_PACK_REGISTRY[expected_keys[0]] = (  # type: ignore[index]
            relief.ISO_4126_STANDARDS_PACK
        )


@pytest.mark.parametrize("entry", relief.PRESSURE_RELIEF_DISCOVERY_ENTRIES)
def test_standards_entries_are_inert_review_metadata(
    entry: relief.PressureReliefStandardsPackMetadata,
) -> None:
    assert entry.lifecycle_status is MethodLifecycleStatus.STANDARDS_REVIEW
    assert entry.executable is False
    assert entry.conformity_claimed is False
    assert entry.protected_content_embedded is False
    assert entry.exact_edition_selection_required is True
    assert entry.independent_review_required is True
    assert all(url.startswith("https://") for url in entry.official_catalog_urls)


def test_all_pressure_relief_execution_collections_are_empty_and_immutable() -> None:
    assert relief.PRESSURE_RELIEF_EXECUTABLE_ADAPTERS == ()
    assert isinstance(relief.PRESSURE_RELIEF_METHOD_REGISTRY, MappingProxyType)
    assert isinstance(relief.PRESSURE_RELIEF_METHOD_IMPLEMENTATIONS, MappingProxyType)
    assert dict(relief.PRESSURE_RELIEF_METHOD_REGISTRY) == {}
    assert dict(relief.PRESSURE_RELIEF_METHOD_IMPLEMENTATIONS) == {}
    with pytest.raises(TypeError):
        relief.PRESSURE_RELIEF_METHOD_REGISTRY["method"] = object()  # type: ignore[index]


@pytest.mark.parametrize("phase", tuple(relief.PressureReliefFluidPhase))
def test_complete_evidence_still_blocks_unapproved_method(
    phase: relief.PressureReliefFluidPhase,
) -> None:
    result = relief.assess_pressure_relief_readiness(complete_request(phase))
    assert result.status is CalculationStatus.BLOCKED
    assert finding_ids(result) == (
        relief.PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID,
    )
    assert result.ready_for_sizing is False
    assert result.calculation_performed is False
    assert result.device_selected is False
    assert result.standards_conformity_claimed is False
    assert result.preliminary_engineering_decision_support is True
    assert result.independent_review_required is True


@pytest.mark.parametrize("phase", tuple(relief.PressureReliefFluidPhase))
def test_readiness_result_and_fingerprints_are_deterministic(
    phase: relief.PressureReliefFluidPhase,
) -> None:
    first = relief.assess_pressure_relief_readiness(complete_request(phase))
    second = relief.assess_pressure_relief_readiness(complete_request(phase))
    assert first == second
    assert first.request_fingerprint == second.request_fingerprint
    assert first.result_fingerprint == second.result_fingerprint
    assert first.request_fingerprint != first.result_fingerprint


def test_empty_request_returns_all_blocks_in_safety_order() -> None:
    result = relief.assess_pressure_relief_readiness(
        relief.PressureReliefReadinessRequest(request_id="empty-request")
    )
    assert finding_ids(result) == (
        relief.PRESSURE_RELIEF_MISSING_SCENARIO_FINDING_ID,
        relief.PRESSURE_RELIEF_MISSING_FLOW_BASIS_FINDING_ID,
        relief.PRESSURE_RELIEF_MISSING_PRESSURE_BASIS_FINDING_ID,
        relief.PRESSURE_RELIEF_MISSING_JURISDICTION_FINDING_ID,
        relief.PRESSURE_RELIEF_MISSING_PROPERTIES_FINDING_ID,
        relief.PRESSURE_RELIEF_MISSING_COMPETENCY_FINDING_ID,
        relief.PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID,
    )
    assert all(finding.blocking for finding in result.blocking_findings)
    assert all(
        finding.severity is FindingSeverity.CRITICAL
        for finding in result.blocking_findings
    )


@pytest.mark.parametrize(
    ("update", "expected_finding"),
    (
        (
            {"scenarios": (scenario(credible=False),)},
            relief.PRESSURE_RELIEF_MISSING_SCENARIO_FINDING_ID,
        ),
        (
            {
                "scenarios": (
                    scenario(
                        flow=relief.PressureReliefFlowBasis(
                            required_relieving_mass_flow_kg_s=None
                        )
                    ),
                )
            },
            relief.PRESSURE_RELIEF_MISSING_FLOW_BASIS_FINDING_ID,
        ),
        (
            {"pressure_basis": None},
            relief.PRESSURE_RELIEF_MISSING_PRESSURE_BASIS_FINDING_ID,
        ),
        (
            {"jurisdiction_basis": None},
            relief.PRESSURE_RELIEF_MISSING_JURISDICTION_FINDING_ID,
        ),
        (
            {"fluid_properties": None},
            relief.PRESSURE_RELIEF_MISSING_PROPERTIES_FINDING_ID,
        ),
        (
            {
                "competency_requirement_acknowledged": False,
                "proposed_reviewer_evidence_reference": None,
            },
            relief.PRESSURE_RELIEF_MISSING_COMPETENCY_FINDING_ID,
        ),
    ),
)
def test_each_critical_omission_produces_its_named_block(
    update: dict[str, object],
    expected_finding: str,
) -> None:
    request = complete_request().model_copy(update=update)
    result = relief.assess_pressure_relief_readiness(request)
    assert expected_finding in finding_ids(result)
    assert finding_ids(result)[-1] == relief.PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID


@pytest.mark.parametrize(
    "update",
    (
        {"relieving_temperature_k": None},
        {"property_source_reference": None},
        {"condition_basis": None},
        {"liquid_density_kg_m3": None},
    ),
)
def test_each_liquid_property_omission_blocks(update: dict[str, object]) -> None:
    properties = fluid_properties(relief.PressureReliefFluidPhase.LIQUID).model_copy(
        update=update
    )
    request = complete_request().model_copy(update={"fluid_properties": properties})
    assert relief.PRESSURE_RELIEF_MISSING_PROPERTIES_FINDING_ID in finding_ids(
        relief.assess_pressure_relief_readiness(request)
    )


@pytest.mark.parametrize(
    "update",
    (
        {"gas_molar_mass_kg_kmol": None},
        {"compressibility_factor": None},
        {"isentropic_exponent": None},
    ),
)
def test_each_gas_property_omission_blocks(update: dict[str, object]) -> None:
    properties = fluid_properties(
        relief.PressureReliefFluidPhase.GAS_VAPOUR
    ).model_copy(update=update)
    request = complete_request(
        relief.PressureReliefFluidPhase.GAS_VAPOUR
    ).model_copy(update={"fluid_properties": properties})
    assert relief.PRESSURE_RELIEF_MISSING_PROPERTIES_FINDING_ID in finding_ids(
        relief.assess_pressure_relief_readiness(request)
    )


@pytest.mark.parametrize(
    "update",
    (
        {"steam_specific_volume_m3_kg": None},
        {"dry_or_superheated_steam_confirmed": False},
        {"dry_or_superheated_steam_confirmed": None},
    ),
)
def test_each_steam_property_omission_blocks(update: dict[str, object]) -> None:
    properties = fluid_properties(relief.PressureReliefFluidPhase.STEAM).model_copy(
        update=update
    )
    request = complete_request(relief.PressureReliefFluidPhase.STEAM).model_copy(
        update={"fluid_properties": properties}
    )
    assert relief.PRESSURE_RELIEF_MISSING_PROPERTIES_FINDING_ID in finding_ids(
        relief.assess_pressure_relief_readiness(request)
    )


@pytest.mark.parametrize("value", (True, False, "1.0", nan, inf, -inf, 0.0, -1.0, 1.1e9))
def test_required_flow_rejects_invalid_or_unbounded_values(value: object) -> None:
    with pytest.raises((ValidationError, TypeError)):
        relief.PressureReliefFlowBasis(
            required_relieving_mass_flow_kg_s=value,
        )


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("set_pressure_pa", True),
        ("set_pressure_pa", nan),
        ("set_pressure_pa", 0.0),
        ("set_pressure_pa", -1.0),
        ("set_pressure_pa", 1.1e12),
        ("total_backpressure_pa", -1.0),
        ("total_backpressure_pa", inf),
    ),
)
def test_pressure_basis_rejects_invalid_values(
    field_name: str,
    value: object,
) -> None:
    values = pressure_basis().model_dump(mode="python", round_trip=True)
    values[field_name] = value
    with pytest.raises((ValidationError, TypeError)):
        relief.PressureReliefPressureBasis(**values)


@pytest.mark.parametrize(
    "update",
    (
        {
            "set_pressure_pa": 1_200_000.0,
            "maximum_allowable_working_pressure_pa": 1_100_000.0,
        },
        {
            "set_pressure_pa": 1_000_000.0,
            "relieving_pressure_pa": 900_000.0,
        },
        {
            "relieving_pressure_pa": 1_100_000.0,
            "total_backpressure_pa": 1_100_000.0,
        },
    ),
)
def test_pressure_basis_rejects_incoherent_pressure_states(
    update: dict[str, float],
) -> None:
    values = pressure_basis().model_dump(mode="python", round_trip=True)
    values.update(update)
    with pytest.raises(ValidationError):
        relief.PressureReliefPressureBasis(**values)


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("relieving_temperature_k", 0.0),
        ("relieving_temperature_k", True),
        ("liquid_density_kg_m3", -1.0),
        ("liquid_density_kg_m3", nan),
        ("liquid_density_kg_m3", 1.1e7),
        ("compressibility_factor", 0.0),
        ("compressibility_factor", 10.1),
        ("isentropic_exponent", 1.0),
        ("isentropic_exponent", inf),
    ),
)
def test_fluid_properties_reject_invalid_values(
    field_name: str,
    value: object,
) -> None:
    values: dict[str, object] = {
        "phase": relief.PressureReliefFluidPhase.LIQUID,
        "relieving_temperature_k": 400.0,
        "liquid_density_kg_m3": 800.0,
        "property_source_reference": "PROPERTY-SOURCE",
        "condition_basis": "Documented relieving-condition property basis.",
    }
    if field_name in {"compressibility_factor", "isentropic_exponent"}:
        values = {
            "phase": relief.PressureReliefFluidPhase.GAS_VAPOUR,
            "relieving_temperature_k": 400.0,
            "gas_molar_mass_kg_kmol": 30.0,
            "compressibility_factor": 0.9,
            "isentropic_exponent": 1.3,
            "property_source_reference": "PROPERTY-SOURCE",
            "condition_basis": "Documented relieving-condition property basis.",
        }
    values[field_name] = value
    with pytest.raises((ValidationError, TypeError)):
        relief.PressureReliefFluidProperties(**values)


@pytest.mark.parametrize(
    "values",
    (
        {
            "phase": relief.PressureReliefFluidPhase.LIQUID,
            "liquid_density_kg_m3": 800.0,
            "compressibility_factor": 0.9,
        },
        {
            "phase": relief.PressureReliefFluidPhase.LIQUID,
            "liquid_density_kg_m3": 800.0,
            "steam_specific_volume_m3_kg": 0.2,
        },
        {
            "phase": relief.PressureReliefFluidPhase.GAS_VAPOUR,
            "gas_molar_mass_kg_kmol": 30.0,
            "liquid_density_kg_m3": 800.0,
        },
        {
            "phase": relief.PressureReliefFluidPhase.GAS_VAPOUR,
            "compressibility_factor": 0.9,
            "dry_or_superheated_steam_confirmed": True,
        },
        {
            "phase": relief.PressureReliefFluidPhase.STEAM,
            "steam_specific_volume_m3_kg": 0.2,
            "liquid_density_kg_m3": 800.0,
        },
        {
            "phase": relief.PressureReliefFluidPhase.STEAM,
            "steam_specific_volume_m3_kg": 0.2,
            "isentropic_exponent": 1.3,
        },
    ),
)
def test_phase_incompatible_property_combinations_are_rejected(
    values: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        relief.PressureReliefFluidProperties(**values)


@pytest.mark.parametrize(
    ("factory", "field_name"),
    (
        (lambda: flow_basis(), "load_determination_reference"),
        (lambda: flow_basis(), "load_determination_basis"),
        (lambda: scenario(), "title"),
        (lambda: scenario(), "credibility_basis_reference"),
        (lambda: pressure_basis(), "pressure_source_reference"),
        (lambda: jurisdiction_basis(), "jurisdiction_source_reference"),
        (
            lambda: fluid_properties(relief.PressureReliefFluidPhase.LIQUID),
            "property_source_reference",
        ),
        (lambda: complete_request(), "proposed_reviewer_evidence_reference"),
    ),
)
def test_provenance_rejects_surrounding_whitespace(
    factory,
    field_name: str,
) -> None:
    model = factory()
    values = model.model_dump(mode="python", round_trip=True)
    values[field_name] = f" {values[field_name]} "
    with pytest.raises((ValidationError, TypeError)):
        type(model)(**values)


def test_duplicate_and_case_conflicting_scenario_ids_are_rejected() -> None:
    for second_id in ("blocked-outlet-1", "BLOCKED-OUTLET-1"):
        with pytest.raises(ValidationError):
            complete_request().model_copy(
                update={
                    "scenarios": (
                        scenario(scenario_id="blocked-outlet-1"),
                        scenario(scenario_id=second_id),
                    )
                }
            )


def test_one_request_cannot_mix_protected_equipment_references() -> None:
    with pytest.raises(ValidationError, match="same protected equipment"):
        complete_request().model_copy(
            update={
                "scenarios": (
                    scenario(
                        scenario_id="blocked-outlet-1",
                        protected_equipment_reference="V-101",
                    ),
                    scenario(
                        scenario_id="external-fire-1",
                        protected_equipment_reference="V-102",
                    ),
                )
            }
        )


def test_pack_id_and_version_must_be_supplied_together() -> None:
    with pytest.raises(ValidationError):
        relief.PressureReliefReadinessRequest(
            request_id="partial-pack",
            selected_standards_pack_id=relief.API_520_521_STANDARDS_PACK_ID,
        )
    with pytest.raises(ValidationError):
        relief.PressureReliefReadinessRequest(
            request_id="partial-pack",
            selected_standards_pack_version="1.0.0",
        )


def test_selected_standards_pack_must_resolve_and_match_jurisdiction() -> None:
    with pytest.raises(ValidationError, match="resolve exactly"):
        complete_request().model_copy(
            update={
                "selected_standards_pack_id": "pressure-relief.unknown.discovery",
            }
        )

    with pytest.raises(ValidationError, match="match the jurisdiction"):
        complete_request().model_copy(
            update={
                "jurisdiction_basis": jurisdiction_basis(
                    family=relief.PressureReliefStandardsFamily.ISO_4126
                )
            }
        )


def test_reviewer_evidence_requires_competency_acknowledgement() -> None:
    with pytest.raises(ValidationError):
        relief.PressureReliefReadinessRequest(
            request_id="reviewer-evidence",
            proposed_reviewer_evidence_reference="REVIEWER-001",
        )


def test_gauge_pressure_basis_requires_explicit_atmosphere_to_clear_gate() -> None:
    incomplete_pressure = pressure_basis(
        basis_kind=(
            relief.PressureReliefPressureBasisKind.GAUGE_WITH_ATMOSPHERIC_REFERENCE
        )
    )
    request = complete_request().model_copy(
        update={"pressure_basis": incomplete_pressure}
    )
    result = relief.assess_pressure_relief_readiness(request)
    assert relief.PRESSURE_RELIEF_MISSING_PRESSURE_BASIS_FINDING_ID in finding_ids(
        result
    )

    complete_pressure = pressure_basis(
        basis_kind=(
            relief.PressureReliefPressureBasisKind.GAUGE_WITH_ATMOSPHERIC_REFERENCE
        ),
        atmosphere=101_325.0,
    )
    complete_result = relief.assess_pressure_relief_readiness(
        complete_request().model_copy(update={"pressure_basis": complete_pressure})
    )
    assert relief.PRESSURE_RELIEF_MISSING_PRESSURE_BASIS_FINDING_ID not in finding_ids(
        complete_result
    )


def test_absolute_pressure_basis_rejects_conversion_atmosphere() -> None:
    with pytest.raises(ValidationError):
        pressure_basis(atmosphere=101_325.0)


@pytest.mark.parametrize(
    ("field_name", "forbidden_value"),
    (
        ("ready_for_sizing", True),
        ("calculation_performed", True),
        ("device_selected", True),
        ("standards_conformity_claimed", True),
        ("independent_review_required", False),
        ("preliminary_engineering_decision_support", False),
    ),
)
def test_result_cannot_be_reconstructed_as_approved_or_final(
    field_name: str,
    forbidden_value: bool,
) -> None:
    result = relief.assess_pressure_relief_readiness(complete_request())
    with pytest.raises(ValidationError):
        result.model_copy(update={field_name: forbidden_value})


def test_models_are_frozen_and_forbid_extra_fields() -> None:
    request = complete_request()
    with pytest.raises((ValidationError, TypeError)):
        request.request_id = "changed"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        relief.PressureReliefReadinessRequest(
            request_id="extra-field",
            unexpected="not allowed",  # type: ignore[call-arg]
        )


def test_round_trip_serialization_preserves_request_and_result() -> None:
    request = complete_request(relief.PressureReliefFluidPhase.GAS_VAPOUR)
    restored_request = relief.PressureReliefReadinessRequest.model_validate_json(
        request.model_dump_json()
    )
    assert restored_request == request
    result = relief.assess_pressure_relief_readiness(restored_request)
    restored_result = relief.PressureReliefSafetyGateResult.model_validate_json(
        result.model_dump_json()
    )
    assert restored_result == result


def test_result_fingerprint_covers_all_public_result_fields() -> None:
    result = relief.assess_pressure_relief_readiness(complete_request())
    public_payload = result.model_dump(
        mode="python",
        round_trip=True,
        exclude={"result_fingerprint"},
    )
    assert result.result_fingerprint == relief.fingerprint_pressure_relief_readiness(
        public_payload
    )


def test_result_rejects_forged_or_stale_fingerprint_evidence() -> None:
    result = relief.assess_pressure_relief_readiness(complete_request())
    values = result.model_dump(mode="python", round_trip=True)
    values["request_fingerprint"] = "0" * 64
    values["result_fingerprint"] = "0" * 64
    with pytest.raises(ValidationError, match="fingerprint is inconsistent"):
        relief.PressureReliefSafetyGateResult(**values)

    incomplete_competency = result.competency_requirement.model_copy(
        update={"required_checks": ()}
    )
    with pytest.raises(ValidationError, match="competency requirement"):
        result.model_copy(
            update={"competency_requirement": incomplete_competency}
        )


def test_fingerprint_canonicalizes_mapping_order_and_signed_zero() -> None:
    first = relief.fingerprint_pressure_relief_readiness(
        {"b": -0.0, "a": [1.0, "value"]}
    )
    second = relief.fingerprint_pressure_relief_readiness(
        {"a": (1.0, "value"), "b": 0.0}
    )
    assert first == second


@pytest.mark.parametrize("value", ({1: "bad-key"}, {"value": nan}, object()))
def test_fingerprint_rejects_unsupported_or_nonfinite_values(value: object) -> None:
    with pytest.raises(relief.PressureReliefInputError):
        relief.fingerprint_pressure_relief_readiness(value)


def test_public_assessor_revalidates_type_and_instance() -> None:
    with pytest.raises(relief.PressureReliefInputError):
        relief.assess_pressure_relief_readiness({"request_id": "mapping"})  # type: ignore[arg-type]
    request = complete_request()
    object.__setattr__(request, "request_id", " invalid ")
    with pytest.raises(relief.PressureReliefInputError):
        relief.assess_pressure_relief_readiness(request)


def test_required_competency_is_exact_and_propagated() -> None:
    result = relief.assess_pressure_relief_readiness(complete_request())
    assert (
        result.required_reviewer_competency
        == "Independent competent pressure-systems engineer"
    )
    assert result.competency_requirement == relief.PRESSURE_RELIEF_COMPETENCY_REQUIREMENT
    assert result.competency_requirement.independent_review_required is True
    assert result.competency_requirement.jurisdiction_review_required is True
    assert result.competency_requirement.site_and_installation_review_required is True
    assert result.competency_requirement.manufacturer_review_required is True


def test_module_and_package_exports_are_exact_and_duplicate_free() -> None:
    assert len(relief.__all__) == len(set(relief.__all__))
    assert len(calculations.__all__) == len(set(calculations.__all__))
    assert set(relief.__all__).issubset(set(calculations.__all__))
    assert all(
        getattr(calculations, name) is getattr(relief, name)
        for name in relief.__all__
    )


def test_existing_calculation_pack_boundaries_remain_unchanged() -> None:
    assert len(calculations.ENGINEERING_METHOD_IDS) == 26
    assert len(calculations.ENGINEERING_METHOD_REGISTRY.definitions) == 26
    assert calculations.DEFAULT_METHOD_REGISTRY.definitions == ()
    assert len(calculations.DP_FLOW_METHOD_REGISTRY) == 7
    assert len(calculations.CONTROL_VALVE_PACK_METHOD_REGISTRY) == 3
    assert len(calculations.CONTROL_VALVE_PACK_DISCOVERY_ENTRIES) == 4


def test_module_has_no_dynamic_execution_io_api_persistence_or_voice_coupling() -> None:
    source = inspect.getsource(relief)
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    called_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            called_names.add(node.func.id)
    assert imported_roots.isdisjoint(
        {
            "asyncio",
            "fastapi",
            "httpx",
            "importlib",
            "requests",
            "socket",
            "sqlalchemy",
            "subprocess",
            "urllib",
        }
    )
    assert called_names.isdisjoint(
        {"eval", "exec", "compile", "__import__", "open"}
    )
    assert "voice" not in source.casefold()
    assert "speech" not in source.casefold()
