"""Phase 7 Step 105 pressure-relief workflow contract tests."""

from __future__ import annotations

import ast
import inspect
from math import inf, nan
from types import MappingProxyType
from typing import Any

import pytest
from pydantic import ValidationError

from app.engineering.calculations import pressure_relief as relief
from app.engineering.calculations import pressure_relief_required_area as area
from app.engineering.calculations import pressure_relief_workflow_models as workflow
from app.engineering.calculations.models import CalculationStatus

EDITION_REFERENCE = "CONTROLLED-STANDARD-REGISTER-REV-F"
PROPERTY_REFERENCE = "PROCESS-DATASHEET-RELIEF-REV-E"


def flow_basis(required_mass_flow_kg_s: float = 5.0) -> relief.PressureReliefFlowBasis:
    return relief.PressureReliefFlowBasis(
        required_relieving_mass_flow_kg_s=required_mass_flow_kg_s,
        load_determination_reference="CALC-RELIEF-LOAD-105",
        load_determination_basis=(
            "The required mass flow comes from the independently reviewed "
            "overpressure scenario study."
        ),
        supplied_by="Process engineering",
    )


def scenario(
    *,
    required_mass_flow_kg_s: float = 5.0,
) -> relief.PressureReliefScenarioBasis:
    return relief.PressureReliefScenarioBasis(
        scenario_id="blocked-outlet-105",
        scenario_kind=relief.PressureReliefScenarioKind.BLOCKED_OUTLET,
        title="Documented Step 105 blocked-outlet case",
        protected_equipment_reference="V-105",
        scenario_description=(
            "The reviewed process study identifies a credible blocked outlet "
            "while feed continues at the documented relieving condition."
        ),
        credibility_confirmed=True,
        credibility_basis_reference="HAZOP-REV-F-NODE-105",
        flow_basis=flow_basis(required_mass_flow_kg_s),
    )


def pressure_basis() -> relief.PressureReliefPressureBasis:
    return relief.PressureReliefPressureBasis(
        basis_kind=relief.PressureReliefPressureBasisKind.ABSOLUTE,
        set_pressure_pa=1_000_000.0,
        maximum_allowable_working_pressure_pa=1_000_000.0,
        relieving_pressure_pa=1_000_000.0,
        total_backpressure_pa=100_000.0,
        pressure_source_reference="V-105-DESIGN-DATA-REV-F",
    )


def jurisdiction_basis() -> relief.PressureReliefJurisdictionBasis:
    return relief.PressureReliefJurisdictionBasis(
        jurisdiction_id="ZA-project-jurisdiction",
        authority_having_jurisdiction="Project pressure-equipment authority",
        applicable_design_code_reference="PROJECT-DESIGN-CODE-REV-F",
        standards_family=relief.PressureReliefStandardsFamily.API_520_521,
        exact_edition_and_amendment_reference=EDITION_REFERENCE,
        jurisdiction_source_reference="PROJECT-CODE-BASIS-REV-F",
    )


def fluid_properties(
    phase: relief.PressureReliefFluidPhase,
) -> relief.PressureReliefFluidProperties:
    values: dict[str, object] = {
        "phase": phase,
        "relieving_temperature_k": 300.0,
        "property_source_reference": PROPERTY_REFERENCE,
        "condition_basis": (
            "Properties are evaluated at the documented relieving pressure "
            "and temperature."
        ),
    }
    if phase is relief.PressureReliefFluidPhase.LIQUID:
        values["liquid_density_kg_m3"] = 1_000.0
    elif phase is relief.PressureReliefFluidPhase.GAS_VAPOUR:
        values.update(
            gas_molar_mass_kg_kmol=28.0,
            compressibility_factor=1.0,
            isentropic_exponent=1.4,
        )
    else:
        values.update(
            steam_specific_volume_m3_kg=0.2,
            dry_or_superheated_steam_confirmed=True,
        )
    return relief.PressureReliefFluidProperties(**values)


def readiness_request(
    phase: relief.PressureReliefFluidPhase,
    *,
    required_mass_flow_kg_s: float = 5.0,
    selected_pack: bool = True,
) -> relief.PressureReliefReadinessRequest:
    return relief.PressureReliefReadinessRequest(
        request_id=f"step105-{phase.value}",
        scenarios=(scenario(required_mass_flow_kg_s=required_mass_flow_kg_s),),
        pressure_basis=pressure_basis(),
        jurisdiction_basis=jurisdiction_basis(),
        fluid_properties=fluid_properties(phase),
        selected_standards_pack_id=(
            relief.API_520_521_STANDARDS_PACK_ID if selected_pack else None
        ),
        selected_standards_pack_version=(
            relief.PRESSURE_RELIEF_STANDARDS_PACK_VERSION if selected_pack else None
        ),
        competency_requirement_acknowledged=True,
        proposed_reviewer_evidence_reference="REVIEW-ASSIGNMENT-PRV-105",
    )


def required_area_case(
    phase: relief.PressureReliefFluidPhase,
) -> area.PressureReliefRequiredAreaCase:
    return area.PressureReliefRequiredAreaCase(
        readiness_request=readiness_request(phase),
        scenario_id="blocked-outlet-105",
        method_basis_reference=EDITION_REFERENCE,
        application_basis=(
            "The generic equation is selected for this separately reviewed "
            "scenario inside the stated applicability boundary."
        ),
        supplied_by="Pressure-systems engineer",
        device_inlet_pressure_basis_confirmed=True,
        downstream_system_basis_confirmed=True,
    )


def coefficients() -> area.TraceableReliefAreaCoefficients:
    return area.TraceableReliefAreaCoefficients(
        coefficient_set_id="coefficients.step105.reviewed",
        discharge_coefficient=0.8,
        discharge_coefficient_source_reference="COEFF-CD-RECORD-REV-F",
        discharge_coefficient_role="capacity_discharge_coefficient",
        combined_correction_factor=1.0,
        combined_correction_factor_source_reference="COEFF-K-RECORD-REV-F",
        combined_correction_factor_role="combined_correction_factor",
        standards_basis_reference=EDITION_REFERENCE,
        applicable_conditions=(
            "The supplied coefficients apply to this fluid, pressure, "
            "temperature, backpressure, and installation basis."
        ),
        supplied_by="Pressure-systems engineer",
        all_required_corrections_included=True,
        double_counting_review_completed=True,
    )


def liquid_input() -> area.LiquidPressureReliefRequiredAreaInput:
    return area.LiquidPressureReliefRequiredAreaInput(
        case=required_area_case(relief.PressureReliefFluidPhase.LIQUID),
        coefficients=coefficients(),
        applicability=area.TraceableLiquidReliefApplicability(
            vapor_pressure_absolute_pa=50_000.0,
            vapor_pressure_source_reference="FLUID-PROPERTY-RECORD-REV-F",
            confirmation_reference="LIQUID-APPLICABILITY-REVIEW-REV-F",
            single_phase_incompressible_confirmed=True,
            nonflashing_noncavitating_confirmed=True,
            newtonian_or_calibrated_coefficient_confirmed=True,
        ),
    )


def gas_input() -> area.GasVapourPressureReliefRequiredAreaInput:
    return area.GasVapourPressureReliefRequiredAreaInput(
        case=required_area_case(relief.PressureReliefFluidPhase.GAS_VAPOUR),
        coefficients=coefficients(),
        applicability=area.TraceableGasVapourReliefApplicability(
            confirmation_reference="GAS-APPLICABILITY-REVIEW-REV-F",
            single_phase_gas_vapour_confirmed=True,
            no_condensation_or_phase_transition_confirmed=True,
            isentropic_flow_model_confirmed=True,
            constant_k_and_upstream_z_approximation_accepted=True,
            property_variation_review_completed=True,
        ),
    )


def steam_input() -> area.EligibleSteamPressureReliefRequiredAreaInput:
    return area.EligibleSteamPressureReliefRequiredAreaInput(
        case=required_area_case(relief.PressureReliefFluidPhase.STEAM),
        coefficients=coefficients(),
        steam_flow=area.TraceableSteamFlowCoefficient(
            coefficient_id="steam.coefficient.step105",
            steam_mass_flux_coefficient=0.75,
            critical_pressure_ratio=0.55,
            steam_state=area.EligiblePressureReliefSteamState.DRY_SATURATED,
            source_reference="STEAM-FLOW-BASIS-RECORD-REV-F",
            critical_pressure_ratio_source_reference=("STEAM-CRITICAL-RATIO-REV-F"),
            eligibility_source_reference="STEAM-ELIGIBILITY-REVIEW-REV-F",
            standards_basis_reference=EDITION_REFERENCE,
            specific_volume_basis_reference=PROPERTY_REFERENCE,
            applicable_conditions=(
                "The supplied normalization applies to this eligible dry-steam "
                "state, pressure ratio, pressure, and specific-volume basis."
            ),
            supplied_by="Pressure-systems engineer",
            choked_flow_applicability_confirmed=True,
            no_entrained_liquid_confirmed=True,
            below_critical_pressure_confirmed=True,
            coefficient_normalization="G = C_s * sqrt(P1_abs / v1)",
        ),
    )


def execution_request(
    operation: workflow.PressureReliefOperation,
) -> workflow.PressureReliefExecutionRequest:
    if operation is workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA:
        return workflow.LiquidPressureReliefExecutionRequest(
            operation=operation.value,
            method_id=area.LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
            method_version=(area.LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION),
            sizing_input=liquid_input(),
        )
    if operation is workflow.PressureReliefOperation.GAS_VAPOUR_REQUIRED_AREA:
        return workflow.GasVapourPressureReliefExecutionRequest(
            operation=operation.value,
            method_id=(area.GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID),
            method_version=(
                area.GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION
            ),
            sizing_input=gas_input(),
        )
    return workflow.EligibleSteamPressureReliefExecutionRequest(
        operation=operation.value,
        method_id=area.ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        method_version=(
            area.ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION
        ),
        sizing_input=steam_input(),
    )


def calculate(
    request: workflow.PressureReliefExecutionRequest,
) -> workflow.PressureReliefRequiredAreaResult:
    if isinstance(request, workflow.LiquidPressureReliefExecutionRequest):
        return area.calculate_liquid_pressure_relief_required_area(request.sizing_input)
    if isinstance(request, workflow.GasVapourPressureReliefExecutionRequest):
        return area.calculate_gas_vapour_pressure_relief_required_area(
            request.sizing_input
        )
    return area.calculate_eligible_steam_pressure_relief_required_area(
        request.sizing_input
    )


def execution_outcome(
    operation: workflow.PressureReliefOperation,
) -> workflow.PressureReliefExecutionOutcome:
    request = execution_request(operation)
    return workflow.build_pressure_relief_execution_outcome(
        request,
        calculate(request),
    )


def dump(model: Any) -> dict[str, Any]:
    return model.model_dump(mode="python", round_trip=True, warnings="error")


def test_versions_limits_and_exact_public_surface() -> None:
    assert workflow.PRESSURE_RELIEF_WORKFLOW_VERSION == "1.0.0"
    assert workflow.PRESSURE_RELIEF_CALCULATOR_PACK_VERSION == "1.1.0"
    assert workflow.MAX_PRESSURE_RELIEF_TEXT_LENGTH == 2_500
    assert workflow.MAX_PUBLIC_PRESSURE_RELIEF_PRESSURE_PA == 1.0e12
    assert workflow.MAX_PUBLIC_PRESSURE_RELIEF_MASS_FLOW_KG_S == 1.0e9
    assert workflow.MAX_PUBLIC_PRESSURE_RELIEF_REQUIRED_AREA_M2 == 1.0e6
    assert tuple(workflow.PressureReliefOperation) == (
        workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA,
        workflow.PressureReliefOperation.GAS_VAPOUR_REQUIRED_AREA,
        workflow.PressureReliefOperation.ELIGIBLE_STEAM_REQUIRED_AREA,
    )


def test_catalogue_and_registry_bind_all_three_exact_methods() -> None:
    expected = (
        (
            workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA,
            area.LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
            "LiquidPressureReliefExecutionRequest",
            "LiquidPressureReliefRequiredAreaResult",
        ),
        (
            workflow.PressureReliefOperation.GAS_VAPOUR_REQUIRED_AREA,
            area.GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
            "GasVapourPressureReliefExecutionRequest",
            "GasVapourPressureReliefRequiredAreaResult",
        ),
        (
            workflow.PressureReliefOperation.ELIGIBLE_STEAM_REQUIRED_AREA,
            area.ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
            "EligibleSteamPressureReliefExecutionRequest",
            "EligibleSteamPressureReliefRequiredAreaResult",
        ),
    )
    assert isinstance(workflow.PRESSURE_RELIEF_API_REGISTRY, MappingProxyType)
    assert len(workflow.PRESSURE_RELIEF_API_CATALOGUE) == 3
    assert tuple(workflow.PRESSURE_RELIEF_API_REGISTRY) == tuple(
        item[0] for item in expected
    )
    for entry, binding in zip(
        workflow.PRESSURE_RELIEF_API_CATALOGUE,
        expected,
        strict=True,
    ):
        operation, method_id, input_name, result_name = binding
        metadata = area.PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY[
            (method_id, "1.0.0")
        ]
        assert (
            entry.operation,
            entry.method_id,
            entry.method_version,
            entry.input_model_name,
            entry.result_model_name,
        ) == (operation, method_id, "1.0.0", input_name, result_name)
        assert entry.implementation_name == metadata.implementation_name
        assert entry.executable is True
        assert entry.preliminary_only is True
        assert entry.generic_supplied_factor_method is True
        assert entry.knowledge_links_are_inert is True
        assert entry.standards_adapter_execution_count == 0
        assert entry.device_selection_performed is False
        assert entry.orifice_selection_performed is False
        assert entry.manufacturer_selection_performed is False
        assert entry.standards_conformity_claimed is False
        assert entry.final_compliance_claimed is False
        assert entry.final_design_approval_granted is False
    with pytest.raises(TypeError):
        workflow.PRESSURE_RELIEF_API_REGISTRY[
            workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA
        ] = workflow.PRESSURE_RELIEF_API_CATALOGUE[0]  # type: ignore[index]


def test_knowledge_links_are_exact_inert_and_immutable() -> None:
    assert isinstance(
        workflow.PRESSURE_RELIEF_KNOWLEDGE_REGISTRY,
        MappingProxyType,
    )
    assert tuple(
        item.source_id for item in workflow.PRESSURE_RELIEF_KNOWLEDGE_LINKS
    ) == (
        relief.API_520_521_STANDARDS_PACK_ID,
        relief.ISO_4126_STANDARDS_PACK_ID,
    )
    for item in workflow.PRESSURE_RELIEF_KNOWLEDGE_LINKS:
        assert item.retrieval_mode == "inert_metadata_only"
        assert item.network_access_performed is False
        assert item.protected_content_embedded is False
        assert item.approved_as_equation_or_factor_source is False
        assert item.executable is False
        assert item.conformity_evidence is False
        assert item.standards_conformity_claimed is False
        assert all(url.startswith("https://") for url in item.official_catalog_urls)
    with pytest.raises(TypeError):
        workflow.PRESSURE_RELIEF_KNOWLEDGE_REGISTRY["new"] = (  # type: ignore[index]
            workflow.PRESSURE_RELIEF_KNOWLEDGE_LINKS[0]
        )


@pytest.mark.parametrize("operation", tuple(workflow.PressureReliefOperation))
def test_three_discriminated_requests_round_trip_exactly(
    operation: workflow.PressureReliefOperation,
) -> None:
    request = execution_request(operation)
    normalized = workflow.validate_pressure_relief_execution_request(dump(request))
    metadata = workflow.PRESSURE_RELIEF_API_REGISTRY[operation]
    assert normalized == request
    assert normalized.operation == operation.value
    assert normalized.method_id == metadata.method_id
    assert normalized.method_version == metadata.method_version
    assert type(normalized).__name__ == metadata.input_model_name


@pytest.mark.parametrize("operation", tuple(workflow.PressureReliefOperation))
def test_execution_outcomes_are_exact_preliminary_and_deterministic(
    operation: workflow.PressureReliefOperation,
) -> None:
    first = execution_outcome(operation)
    second = execution_outcome(operation)
    metadata = workflow.PRESSURE_RELIEF_API_REGISTRY[operation]

    assert first == second
    assert first.disposition is (
        workflow.PressureReliefWorkflowDisposition.PRELIMINARY_REQUIRED_AREA_COMPLETE_REVIEW_REQUIRED
    )
    assert first.result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert first.normalized_request.sizing_input == first.result.normalized_input
    assert first.result.method_id == metadata.method_id
    assert first.result.method_version == metadata.method_version
    assert (
        workflow.validate_pressure_relief_required_area_result(dump(first.result))
        == first.result
    )
    assert first.audit.operation is operation
    assert first.audit.method_id == metadata.method_id
    assert first.audit.method_version == metadata.method_version
    assert first.audit.status == "completed_with_warnings"
    assert first.audit.calculation_performed is True
    assert first.audit.knowledge_source_ids == (relief.API_520_521_STANDARDS_PACK_ID,)
    assert first.audit.readiness_request_id == (
        first.normalized_request.sizing_input.case.readiness_request.request_id
    )
    assert first.audit.selected_scenario_id == "blocked-outlet-105"
    assert first.audit.protected_equipment_reference == "V-105"
    assert first.audit.selected_standards_pack_id == (
        relief.API_520_521_STANDARDS_PACK_ID
    )
    assert first.audit.selected_standards_pack_version == "1.0.0"
    assert first.safety_findings[0].code == (
        "preliminary_required_area_not_device_selection"
    )
    assert first.safety_findings[-1].code == (
        "independent_pressure_systems_review_required"
    )
    assert first.audit.normalized_input_fingerprint == (
        workflow.build_pressure_relief_input_fingerprint(first.normalized_request)
    )
    assert first.audit.result_fingerprint == (
        workflow.build_pressure_relief_result_fingerprint(
            first.normalized_request,
            first.result,
        )
    )
    assert first.audit.audit_fingerprint == (
        workflow.build_pressure_relief_audit_fingerprint(first.audit)
    )
    assert (
        len(
            {
                first.audit.normalized_input_fingerprint,
                first.audit.result_fingerprint,
                first.audit.attempt_fingerprint,
                first.audit.audit_fingerprint,
            }
        )
        == 4
    )


def test_readiness_outcome_is_safety_first_blocked_and_deterministic() -> None:
    request = workflow.PressureReliefReadinessAssessmentRequest(
        readiness_request=readiness_request(relief.PressureReliefFluidPhase.LIQUID)
    )
    result = relief.assess_pressure_relief_readiness(request.readiness_request)
    first = workflow.build_pressure_relief_readiness_outcome(request, result)
    second = workflow.build_pressure_relief_readiness_outcome(request, result)

    assert first == second
    assert first.result.status is CalculationStatus.BLOCKED
    assert (
        first.disposition
        is workflow.PressureReliefWorkflowDisposition.READINESS_BLOCKED
    )
    assert first.ready_for_required_area_execution is False
    assert first.audit.action is workflow.PressureReliefAuditAction.READINESS_ASSESSMENT
    assert first.audit.operation is None
    assert first.audit.method_id is None
    assert first.audit.method_version is None
    assert first.audit.status == "blocked"
    assert first.audit.calculation_performed is False
    assert first.audit.readiness_request_id == request.readiness_request.request_id
    assert first.audit.selected_scenario_id is None
    assert first.audit.protected_equipment_reference == "V-105"
    assert first.audit.selected_standards_pack_id == (
        relief.API_520_521_STANDARDS_PACK_ID
    )
    assert first.audit.selected_standards_pack_version == "1.0.0"
    assert first.safety_findings[0].source_finding_id == (
        relief.PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID
    )
    assert first.safety_findings[-1].code == (
        "independent_pressure_systems_review_required"
    )
    assert first.disclaimers == workflow.PRESSURE_RELIEF_FIXED_DISCLAIMERS
    assert first.preliminary_engineering_decision_support is True
    assert first.independent_review_required is True
    assert first.device_selected is False
    assert first.orifice_selected is False
    assert first.manufacturer_selection_performed is False
    assert first.standards_conformity_claimed is False
    assert first.final_compliance_claimed is False
    assert first.final_design_approval_granted is False
    assert first.approved_for_project_use is False
    assert first.audit.normalized_input_fingerprint == (
        workflow.build_pressure_relief_readiness_input_fingerprint(request)
    )
    assert first.audit.result_fingerprint == (
        workflow.build_pressure_relief_readiness_result_fingerprint(
            request,
            result,
        )
    )


def test_readiness_without_selected_pack_has_no_knowledge_claim() -> None:
    request = workflow.PressureReliefReadinessAssessmentRequest(
        readiness_request=readiness_request(
            relief.PressureReliefFluidPhase.LIQUID,
            selected_pack=False,
        )
    )
    result = relief.assess_pressure_relief_readiness(request.readiness_request)
    outcome = workflow.build_pressure_relief_readiness_outcome(request, result)
    assert outcome.audit.knowledge_source_ids == ()


@pytest.mark.parametrize("operation", tuple(workflow.PressureReliefOperation))
def test_every_execution_result_has_exact_disclaimers_and_fail_closed_flags(
    operation: workflow.PressureReliefOperation,
) -> None:
    outcome = execution_outcome(operation)
    assert len(workflow.PRESSURE_RELIEF_FIXED_DISCLAIMERS) == 4
    assert outcome.disclaimers == workflow.PRESSURE_RELIEF_FIXED_DISCLAIMERS
    assert outcome.audit.disclaimers == workflow.PRESSURE_RELIEF_FIXED_DISCLAIMERS
    joined = " ".join(outcome.disclaimers).casefold()
    for phrase in (
        "preliminary engineering decision support",
        "not approval for project use",
        "no device",
        "no api, iso",
        "independent competent pressure-systems engineer",
    ):
        assert phrase in joined
    assert outcome.preliminary_engineering_decision_support is True
    assert outcome.independent_review_required is True
    assert outcome.ready_for_device_selection is False
    assert outcome.device_selected is False
    assert outcome.orifice_selected is False
    assert outcome.manufacturer_selection_performed is False
    assert outcome.standards_conformity_claimed is False
    assert outcome.final_compliance_claimed is False
    assert outcome.final_design_approval_granted is False
    assert outcome.approved_for_project_use is False
    assert outcome.audit.persistence_performed is False
    assert outcome.audit.network_access_performed is False
    assert outcome.audit.standards_adapter_execution_count == 0
    assert outcome.audit.final_compliance_claimed is False
    assert outcome.audit.final_design_approval_granted is False


@pytest.mark.parametrize("operation", tuple(workflow.PressureReliefOperation))
def test_models_are_frozen_and_audit_is_stateless(
    operation: workflow.PressureReliefOperation,
) -> None:
    outcome = execution_outcome(operation)
    with pytest.raises(ValidationError):
        outcome.approved_for_project_use = True  # type: ignore[misc]
    with pytest.raises(ValidationError):
        outcome.audit.persistence_performed = True  # type: ignore[misc]
    with pytest.raises(ValidationError):
        outcome.normalized_request.method_version = "9.9.9"  # type: ignore[misc]
    assert not hasattr(outcome.audit, "database_id")
    assert not hasattr(outcome.audit, "stored_at")


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("method_version", "2.0.0"),
        ("method_version", " 1.0.0"),
        ("method_id", " pressure-relief.liquid.required-area.supplied-factors"),
        ("operation", " liquid_required_area"),
        ("operation", True),
    ),
)
def test_discriminated_request_rejects_wrong_or_coercive_identity(
    field: str,
    value: object,
) -> None:
    values = dump(
        execution_request(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
    )
    values[field] = value
    with pytest.raises(ValidationError):
        workflow.validate_pressure_relief_execution_request(values)


def test_request_rejects_unknown_fields_and_wrong_input_type() -> None:
    values = dump(
        execution_request(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
    )
    values["unexpected"] = "rejected"
    with pytest.raises(ValidationError):
        workflow.validate_pressure_relief_execution_request(values)

    values = dump(
        execution_request(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
    )
    values["sizing_input"] = dump(gas_input())
    with pytest.raises(ValidationError):
        workflow.validate_pressure_relief_execution_request(values)


@pytest.mark.parametrize("nonfinite", (nan, inf, -inf))
def test_nested_nonfinite_values_are_rejected(nonfinite: float) -> None:
    values = dump(
        execution_request(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
    )
    values["sizing_input"]["case"]["readiness_request"]["scenarios"][0]["flow_basis"][
        "required_relieving_mass_flow_kg_s"
    ] = nonfinite
    with pytest.raises(ValidationError):
        workflow.validate_pressure_relief_execution_request(values)
    with pytest.raises(ValueError, match="finite"):
        workflow.fingerprint_pressure_relief_workflow_payload({"value": nonfinite})


def test_nested_public_bounds_and_strict_confirmations_are_enforced() -> None:
    values = dump(
        execution_request(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
    )
    values["sizing_input"]["case"]["readiness_request"]["scenarios"][0]["flow_basis"][
        "required_relieving_mass_flow_kg_s"
    ] = workflow.MAX_PUBLIC_PRESSURE_RELIEF_MASS_FLOW_KG_S * 2.0
    with pytest.raises(ValidationError):
        workflow.validate_pressure_relief_execution_request(values)

    values = dump(
        execution_request(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
    )
    values["sizing_input"]["case"]["device_inlet_pressure_basis_confirmed"] = 1
    with pytest.raises(ValidationError):
        workflow.validate_pressure_relief_execution_request(values)


def test_fingerprint_canonicalization_is_stable_and_rejects_unsupported_values() -> (
    None
):
    first = workflow.fingerprint_pressure_relief_workflow_payload(
        {"b": [1, -0.0], "a": "μ"}
    )
    second = workflow.fingerprint_pressure_relief_workflow_payload(
        {"a": "μ", "b": (1, 0.0)}
    )
    assert first == second
    assert len(first) == 64
    assert first == first.lower()
    with pytest.raises(ValueError, match="keys"):
        workflow.fingerprint_pressure_relief_workflow_payload({1: "bad"})
    with pytest.raises(TypeError, match="unsupported"):
        workflow.fingerprint_pressure_relief_workflow_payload(object())


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("audit", "audit_fingerprint"), "0" * 64),
        (("audit", "attempt_fingerprint"), "f" * 64),
        (("audit", "knowledge_source_ids"), ("unknown.discovery",)),
        (("disclaimers",), ("A weakened disclaimer.",)),
        (("safety_findings",), ()),
        (("result", "required_area_m2"), 123.0),
    ),
)
def test_execution_outcome_rejects_tampered_nested_evidence(
    path: tuple[str, ...],
    value: object,
) -> None:
    values = dump(
        execution_outcome(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
    )
    target: dict[str, Any] = values
    for item in path[:-1]:
        target = target[item]
    target[path[-1]] = value
    with pytest.raises((TypeError, ValidationError)):
        workflow.PressureReliefExecutionOutcome.model_validate(values)


def test_execution_outcome_rejects_request_result_operation_mismatch() -> None:
    values = dump(
        execution_outcome(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
    )
    values["normalized_request"] = dump(
        execution_request(workflow.PressureReliefOperation.GAS_VAPOUR_REQUIRED_AREA)
    )
    with pytest.raises((TypeError, ValidationError)):
        workflow.PressureReliefExecutionOutcome.model_validate(values)


def test_readiness_outcome_rejects_result_from_another_request() -> None:
    first_request = workflow.PressureReliefReadinessAssessmentRequest(
        readiness_request=readiness_request(relief.PressureReliefFluidPhase.LIQUID)
    )
    first_result = relief.assess_pressure_relief_readiness(
        first_request.readiness_request
    )
    outcome = workflow.build_pressure_relief_readiness_outcome(
        first_request,
        first_result,
    )
    values = dump(outcome)
    other_request = readiness_request(relief.PressureReliefFluidPhase.GAS_VAPOUR)
    values["normalized_request"] = {
        "readiness_request": dump(other_request),
    }
    with pytest.raises(ValidationError):
        workflow.PressureReliefReadinessAssessmentOutcome.model_validate(values)


def test_readiness_outcome_rejects_coherently_rehashed_false_findings() -> None:
    request = workflow.PressureReliefReadinessAssessmentRequest(
        readiness_request=readiness_request(relief.PressureReliefFluidPhase.LIQUID)
    )
    result = relief.assess_pressure_relief_readiness(request.readiness_request)
    outcome = workflow.build_pressure_relief_readiness_outcome(request, result)

    forged_result_values = dump(result)
    forged_result_values["blocking_findings"] = (
        relief.PressureReliefSafetyFinding(
            finding_id=relief.PRESSURE_RELIEF_MISSING_SCENARIO_FINDING_ID,
            code=relief.PressureReliefReadinessFindingCode.MISSING_SCENARIO,
            title="False but schema-valid scenario finding",
            detail=(
                "This finding is deliberately forged for a trusted-output "
                "integrity test."
            ),
            required_action=(
                "Reject the record because it differs from the deterministic "
                "safety-gate result."
            ),
        ),
    )
    forged_result_values["result_fingerprint"] = (
        relief.fingerprint_pressure_relief_readiness(
            {
                key: value
                for key, value in forged_result_values.items()
                if key != "result_fingerprint"
            }
        )
    )
    forged_result = relief.PressureReliefSafetyGateResult.model_validate(
        forged_result_values
    )

    with pytest.raises(ValueError, match="deterministic safety gate"):
        workflow.build_pressure_relief_readiness_outcome(request, forged_result)

    outcome_values = dump(outcome)
    outcome_values["result"] = dump(forged_result)
    outcome_values["safety_findings"] = tuple(
        dump(finding)
        for finding in workflow.derive_pressure_relief_readiness_safety_findings(
            forged_result
        )
    )
    audit_values = outcome_values["audit"]
    audit_values["result_fingerprint"] = (
        workflow.build_pressure_relief_readiness_result_fingerprint(
            request,
            forged_result,
        )
    )
    audit_values["attempt_fingerprint"] = (
        workflow.build_pressure_relief_attempt_fingerprint(
            action=workflow.PressureReliefAuditAction.READINESS_ASSESSMENT,
            operation=None,
            input_fingerprint=audit_values["normalized_input_fingerprint"],
            result_fingerprint=audit_values["result_fingerprint"],
            status="blocked",
        )
    )
    audit_values["audit_fingerprint"] = (
        workflow.build_pressure_relief_audit_fingerprint(audit_values)
    )
    with pytest.raises(ValidationError, match="deterministic safety gate"):
        workflow.PressureReliefReadinessAssessmentOutcome.model_validate(outcome_values)


def test_public_validators_revalidate_forged_frozen_models() -> None:
    request = execution_request(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
    object.__setattr__(request, "method_version", "9.9.9")
    with pytest.raises(ValidationError):
        workflow.validate_pressure_relief_execution_request(request)

    readiness = workflow.PressureReliefReadinessAssessmentRequest(
        readiness_request=readiness_request(relief.PressureReliefFluidPhase.LIQUID)
    )
    object.__setattr__(readiness.readiness_request, "request_id", " padded ")
    with pytest.raises(ValidationError):
        workflow.validate_pressure_relief_readiness_assessment_request(readiness)


def test_audit_fingerprint_requires_complete_material_payload() -> None:
    with pytest.raises(ValueError, match="incomplete"):
        workflow.build_pressure_relief_audit_fingerprint({"action": "blocked"})
    with pytest.raises(TypeError, match="mapping or model"):
        workflow.build_pressure_relief_audit_fingerprint(object())


def test_workflow_module_has_no_io_persistence_dynamic_execution_or_selection() -> None:
    source = inspect.getsource(workflow)
    tree = ast.parse(source)
    forbidden_import_roots = {
        "aiohttp",
        "alembic",
        "asyncio",
        "httpx",
        "os",
        "pathlib",
        "requests",
        "socket",
        "sqlalchemy",
        "subprocess",
        "urllib",
    }
    imported_roots: set[str] = set()
    called_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called_names.add(node.func.attr)
    assert imported_roots.isdisjoint(forbidden_import_roots)
    assert called_names.isdisjoint(
        {"__import__", "compile", "eval", "exec", "open", "system"}
    )
    assert "app.db" not in source
    assert "app.repositories" not in source
    assert "select_pressure_relief_device" not in source
    assert "select_orifice" not in source
    assert "select_manufacturer" not in source
    assert not any(
        isinstance(node, (ast.AsyncFunctionDef, ast.Await)) for node in ast.walk(tree)
    )
