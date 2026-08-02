"""Deterministic Step 106 analyzer assistant acceptance tests."""

from __future__ import annotations

import ast
from math import pi
from pathlib import Path
from types import MappingProxyType

import pytest
from pydantic import BaseModel

import app.engineering.calculations as calculation_package
import app.engineering.design as design_package
from app.engineering.calculations.models import CalculationStatus, EngineeringQuantity
from app.engineering.calculations.units import QuantityKind
from app.engineering.design.analyzer_assistant import (
    ANALYZER_ASSISTANT_VERSION,
    ANALYZER_RULESET_VERSION,
    ANALYZER_TECHNOLOGY_CATALOGUE,
    ANALYZER_TECHNOLOGY_REGISTRY,
    ANALYZER_TECHNOLOGY_TAXONOMY_VERSION,
    ANALYZER_VERIFICATION_STEPS,
    DEFAULT_ANALYZER_APPLICATION_ASSISTANT,
    AnalyzerApplicationAssistant,
    AnalyzerApplicationAssistantError,
    assess_analyzer_application,
)
from app.engineering.design.analyzer_models import (
    ANALYZER_APPLICATION_MODEL_VERSION,
    AnalyzerAnalyteFamily,
    AnalyzerAnalyteRequirement,
    AnalyzerApplicationKind,
    AnalyzerApplicationRequest,
    AnalyzerConditionSeverity,
    AnalyzerEnvironmentCondition,
    AnalyzerInstallationContext,
    AnalyzerInterferenceMechanism,
    AnalyzerKnownInterference,
    AnalyzerMeasurementObjective,
    AnalyzerMeasurementRequirements,
    AnalyzerProcessContext,
    AnalyzerResponseContributorKind,
    AnalyzerResponseTimeContributor,
    AnalyzerRuleStatus,
    AnalyzerSafetyContext,
    AnalyzerSampleApproach,
    AnalyzerSampleDisposition,
    AnalyzerSamplePhase,
    AnalyzerSampleSystemContext,
    AnalyzerScenarioDisposition,
    AnalyzerTechnology,
    AnalyzerTriState,
    AnalyzerUtility,
    AnalyzerVerificationPriority,
)


def quantity(kind: QuantityKind, value: float, unit: str) -> EngineeringQuantity:
    return EngineeringQuantity(quantity_kind=kind.value, value=value, unit=unit)


def response_contributor(
    contributor_id: str,
    kind: AnalyzerResponseContributorKind,
    seconds: float,
    *,
    confirmed: bool = True,
) -> AnalyzerResponseTimeContributor:
    return AnalyzerResponseTimeContributor(
        contributor_id=contributor_id,
        kind=kind,
        duration=quantity(QuantityKind.TIME, seconds, "s"),
        basis="Caller-supplied preliminary response contributor",
        source_reference="Controlled response record",
        confirmed=confirmed,
    )


def complete_request(
    *,
    request_id: str,
    kind: AnalyzerApplicationKind,
    family: AnalyzerAnalyteFamily,
    phase: AnalyzerSamplePhase,
    approach: AnalyzerSampleApproach,
    utilities: tuple[AnalyzerUtility, ...] = (AnalyzerUtility.ELECTRICAL_POWER,),
    response_seconds: float = 5.0,
    cycle_seconds: float | None = None,
) -> AnalyzerApplicationRequest:
    extractive = approach in {
        AnalyzerSampleApproach.EXTRACTIVE,
        AnalyzerSampleApproach.FAST_LOOP,
        AnalyzerSampleApproach.GRAB_SAMPLE,
        AnalyzerSampleApproach.ASPIRATED_DETECTION,
    }
    contributors = [
        response_contributor(
            "response.analyzer",
            AnalyzerResponseContributorKind.ANALYZER_CELL,
            response_seconds,
        )
    ]
    if cycle_seconds is not None:
        contributors.append(
            response_contributor(
                "response.cycle",
                AnalyzerResponseContributorKind.ANALYSIS_CYCLE,
                cycle_seconds,
            )
        )
    return AnalyzerApplicationRequest(
        request_id=request_id,
        application_kind=kind,
        measurement=AnalyzerMeasurementRequirements(
            objectives=(
                AnalyzerMeasurementObjective.COMPOSITION_ANALYSIS
                if kind is AnalyzerApplicationKind.GAS_CHROMATOGRAPHY
                else AnalyzerMeasurementObjective.SAFETY_DETECTION
                if kind is AnalyzerApplicationKind.GAS_DETECTION
                else AnalyzerMeasurementObjective.PROCESS_CONTROL,
            ),
            analytes=(
                AnalyzerAnalyteRequirement(
                    analyte_id="analyte.primary",
                    display_name="Primary analyte",
                    family=family,
                    engineering_unit="mol/mol",
                    expected_minimum=0.0,
                    expected_normal=10.0,
                    expected_maximum=20.0,
                    required_detection_limit=0.1,
                    required_accuracy=1.0,
                    source_reference="Approved process basis",
                ),
            ),
            maximum_total_response_time=quantity(QuantityKind.TIME, 120.0, "s"),
            minimum_availability_percent=95.0,
            continuous_output_required=AnalyzerTriState.YES,
            local_indication_required=AnalyzerTriState.YES,
            automatic_calibration_required=AnalyzerTriState.NO,
        ),
        process=AnalyzerProcessContext(
            sample_phase=phase,
            stream_description="Representative process stream",
            matrix_components=("Balance component", "Primary analyte"),
            composition_variability=AnalyzerConditionSeverity.NONE,
            particulate_loading=AnalyzerConditionSeverity.NONE,
            liquid_droplets=AnalyzerConditionSeverity.NONE,
            wet_sample=AnalyzerConditionSeverity.NONE,
            corrosivity=AnalyzerConditionSeverity.NONE,
            fouling_tendency=AnalyzerConditionSeverity.NONE,
            reactivity=AnalyzerConditionSeverity.NONE,
            known_interferences_assessed=AnalyzerTriState.YES,
        ),
        sample_system=AnalyzerSampleSystemContext(
            approach=approach,
            delivered_sample_phase=phase,
            extraction_location_reference=("Process takeoff" if extractive else None),
            representative_sample_confirmed=AnalyzerTriState.YES,
            sample_probe_defined=AnalyzerTriState.YES,
            filtration_defined=AnalyzerTriState.YES,
            pressure_control_defined=AnalyzerTriState.YES,
            temperature_control_defined=AnalyzerTriState.YES,
            phase_preservation_confirmed=AnalyzerTriState.YES,
            materials_compatibility_confirmed=AnalyzerTriState.YES,
            calibration_introduction_defined=AnalyzerTriState.YES,
            sample_line_length=(
                quantity(QuantityKind.LENGTH, 10.0, "m") if extractive else None
            ),
            sample_line_internal_diameter=(
                quantity(QuantityKind.LENGTH, 0.01, "m") if extractive else None
            ),
            sample_flow_rate=(
                quantity(QuantityKind.ACTUAL_VOLUMETRIC_FLOW, 0.001, "m3/s")
                if extractive
                else None
            ),
            disposition=(
                AnalyzerSampleDisposition.CLOSED_RECOVERY
                if extractive
                else AnalyzerSampleDisposition.NOT_APPLICABLE
            ),
            disposition_basis_reference=(
                "Approved recovery basis" if extractive else None
            ),
            return_compatibility_confirmed=(
                AnalyzerTriState.YES if extractive else AnalyzerTriState.UNKNOWN
            ),
            response_time_budget_complete=AnalyzerTriState.YES,
            gc_separation_and_coelution_verified=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_CHROMATOGRAPHY
                else AnalyzerTriState.UNKNOWN
            ),
            gc_sample_loop_representative_confirmed=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_CHROMATOGRAPHY
                else AnalyzerTriState.UNKNOWN
            ),
            gc_calibration_mixture_defined=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_CHROMATOGRAPHY
                else AnalyzerTriState.UNKNOWN
            ),
            gc_carrier_gas_quality_confirmed=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_CHROMATOGRAPHY
                else AnalyzerTriState.UNKNOWN
            ),
            response_time_contributors=tuple(contributors),
        ),
        safety=AnalyzerSafetyContext(
            hazardous_area=AnalyzerTriState.NO,
            toxic_material=AnalyzerTriState.NO,
            flammable_material=AnalyzerTriState.NO,
            oxygen_deficiency_or_enrichment=AnalyzerTriState.NO,
            high_pressure_sampling=AnalyzerTriState.NO,
            high_temperature_sampling=AnalyzerTriState.NO,
            sample_containment_confirmed=AnalyzerTriState.YES,
            safe_vent_or_disposal_confirmed=AnalyzerTriState.YES,
            exposure_control_defined=AnalyzerTriState.YES,
            gas_detection_safety_function=(
                AnalyzerTriState.NO
                if kind is AnalyzerApplicationKind.GAS_DETECTION
                else AnalyzerTriState.UNKNOWN
            ),
            alarm_basis_defined=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_DETECTION
                else AnalyzerTriState.UNKNOWN
            ),
            detector_coverage_basis_defined=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_DETECTION
                else AnalyzerTriState.UNKNOWN
            ),
            detector_response_basis_defined=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_DETECTION
                else AnalyzerTriState.UNKNOWN
            ),
        ),
        installation=AnalyzerInstallationContext(
            available_utilities=utilities,
            utility_availability_confirmed=AnalyzerTriState.YES,
            environment_conditions=(AnalyzerEnvironmentCondition.INDOOR_CONTROLLED,),
            maintenance_access_confirmed=AnalyzerTriState.YES,
            calibration_access_confirmed=AnalyzerTriState.YES,
            shelter_or_enclosure_basis_defined=AnalyzerTriState.YES,
        ),
        application_notes="Generic Step 106 screening case",
    )


def replace_request(
    request: AnalyzerApplicationRequest, **updates
) -> AnalyzerApplicationRequest:
    values = request.model_dump(mode="python", round_trip=True)
    values.update(updates)
    return AnalyzerApplicationRequest.model_validate(values)


def replace_nested(
    request: AnalyzerApplicationRequest, field: str, **updates
) -> AnalyzerApplicationRequest:
    values = request.model_dump(mode="python", round_trip=True)
    nested = values[field]
    nested.update(updates)
    return AnalyzerApplicationRequest.model_validate(values)


def scenario(assessment, technology: AnalyzerTechnology):
    return next(item for item in assessment.scenarios if item.technology is technology)


def test_exact_versions_catalogue_and_immutable_singleton() -> None:
    assert ANALYZER_APPLICATION_MODEL_VERSION == "1.0.0"
    assert ANALYZER_ASSISTANT_VERSION == "1.0.0"
    assert ANALYZER_RULESET_VERSION == "1.0.0"
    assert ANALYZER_TECHNOLOGY_TAXONOMY_VERSION == "1.0.0"
    assert isinstance(
        DEFAULT_ANALYZER_APPLICATION_ASSISTANT, AnalyzerApplicationAssistant
    )
    assert isinstance(ANALYZER_TECHNOLOGY_REGISTRY, MappingProxyType)
    assert len(ANALYZER_TECHNOLOGY_CATALOGUE) == len(AnalyzerTechnology) == 21
    assert len(ANALYZER_VERIFICATION_STEPS) == 12
    with pytest.raises(TypeError):
        ANALYZER_TECHNOLOGY_REGISTRY[AnalyzerTechnology.PH_ELECTRODE] = (  # type: ignore[index]
            ANALYZER_TECHNOLOGY_CATALOGUE[0]
        )


def test_minimal_request_is_insufficient_without_guesses() -> None:
    result = assess_analyzer_application(
        AnalyzerApplicationRequest(request_id="request.insufficient")
    )
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert len(result.scenarios) == 21
    assert result.missing_information
    assert all(
        item.disposition is AnalyzerScenarioDisposition.INSUFFICIENT_INFORMATION
        for item in result.scenarios
    )
    assert max(item.confidence_score for item in result.scenarios) < 20.0
    assert not any(
        item.disposition is AnalyzerScenarioDisposition.PLAUSIBLE
        for item in result.scenarios
    )


def test_process_stream_and_matrix_cannot_be_silently_omitted() -> None:
    request = complete_request(
        request_id="request.missing-matrix",
        kind=AnalyzerApplicationKind.LIQUID_PROCESS,
        family=AnalyzerAnalyteFamily.CONDUCTIVITY,
        phase=AnalyzerSamplePhase.LIQUID,
        approach=AnalyzerSampleApproach.IN_SITU,
    )
    request = replace_nested(
        request,
        "process",
        stream_description=None,
        matrix_components=(),
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert {
        "process.stream_description",
        "process.matrix_components",
    } <= {item.field_id for item in result.missing_information}


def test_forged_model_copy_request_is_revalidated_at_entry() -> None:
    forged = BaseModel.model_copy(
        AnalyzerApplicationRequest(request_id="request.valid"),
        update={"request_id": " request.forged"},
    )
    with pytest.raises(AnalyzerApplicationAssistantError, match="revalidation"):
        assess_analyzer_application(forged)


def test_repeated_assessment_is_byte_and_fingerprint_stable() -> None:
    request = complete_request(
        request_id="request.stable",
        kind=AnalyzerApplicationKind.LIQUID_PROCESS,
        family=AnalyzerAnalyteFamily.ACIDITY_ALKALINITY,
        phase=AnalyzerSamplePhase.LIQUID,
        approach=AnalyzerSampleApproach.IN_SITU,
    )
    first = assess_analyzer_application(request)
    second = assess_analyzer_application(request)
    assert first.assessment_fingerprint == second.assessment_fingerprint
    assert first.model_dump_json() == second.model_dump_json()


def test_set_like_permutations_canonicalize_to_same_fingerprint() -> None:
    request = complete_request(
        request_id="request.permutation",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.HYDROCARBON,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
        utilities=(
            AnalyzerUtility.INSTRUMENT_AIR,
            AnalyzerUtility.ELECTRICAL_POWER,
            AnalyzerUtility.CALIBRATION_GAS,
        ),
    )
    values = request.model_dump(mode="python", round_trip=True)
    values["installation"]["available_utilities"] = tuple(
        reversed(values["installation"]["available_utilities"])
    )
    permuted = AnalyzerApplicationRequest.model_validate(values)
    assert assess_analyzer_application(request).assessment_fingerprint == (
        assess_analyzer_application(permuted).assessment_fingerprint
    )


def test_material_evidence_changes_fingerprint() -> None:
    request = complete_request(
        request_id="request.fingerprint",
        kind=AnalyzerApplicationKind.LIQUID_PROCESS,
        family=AnalyzerAnalyteFamily.CONDUCTIVITY,
        phase=AnalyzerSamplePhase.LIQUID,
        approach=AnalyzerSampleApproach.IN_SITU,
    )
    changed = replace_request(request, application_notes="Changed traceable evidence")
    assert assess_analyzer_application(request).assessment_fingerprint != (
        assess_analyzer_application(changed).assessment_fingerprint
    )


def test_complete_liquid_scenario_is_generic_and_plausible() -> None:
    result = assess_analyzer_application(
        complete_request(
            request_id="request.liquid",
            kind=AnalyzerApplicationKind.LIQUID_PROCESS,
            family=AnalyzerAnalyteFamily.ACIDITY_ALKALINITY,
            phase=AnalyzerSamplePhase.LIQUID,
            approach=AnalyzerSampleApproach.IN_SITU,
        )
    )
    ph = scenario(result, AnalyzerTechnology.PH_ELECTRODE)
    assert result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert ph.disposition is AnalyzerScenarioDisposition.PLAUSIBLE
    assert ph.manufacturer_selection_performed is False
    assert ph.model_selection_performed is False


def test_process_gas_oxygen_keeps_multiple_plausible_technologies() -> None:
    result = assess_analyzer_application(
        complete_request(
            request_id="request.gas-oxygen",
            kind=AnalyzerApplicationKind.PROCESS_GAS,
            family=AnalyzerAnalyteFamily.OXYGEN,
            phase=AnalyzerSamplePhase.GAS,
            approach=AnalyzerSampleApproach.IN_SITU,
        )
    )
    plausible = {
        item.technology
        for item in result.scenarios
        if item.disposition is AnalyzerScenarioDisposition.PLAUSIBLE
    }
    assert AnalyzerTechnology.ZIRCONIA_OXYGEN in plausible
    assert AnalyzerTechnology.TUNABLE_DIODE_LASER in plausible
    assert AnalyzerTechnology.GAS_CHROMATOGRAPH not in {
        item.technology for item in result.scenarios
    }


def test_continuous_duty_rejects_grab_sample_as_a_complete_arrangement() -> None:
    result = assess_analyzer_application(
        complete_request(
            request_id="request.continuous-grab",
            kind=AnalyzerApplicationKind.LIQUID_PROCESS,
            family=AnalyzerAnalyteFamily.ACIDITY_ALKALINITY,
            phase=AnalyzerSamplePhase.LIQUID,
            approach=AnalyzerSampleApproach.GRAB_SAMPLE,
        )
    )
    ph = scenario(result, AnalyzerTechnology.PH_ELECTRODE)
    duty_rule = next(
        item for item in ph.rule_results if item.rule_id == "rule.measurement_duty"
    )
    assert duty_rule.status is AnalyzerRuleStatus.FAILED
    assert ph.disposition is AnalyzerScenarioDisposition.CONDITIONAL


def test_single_technology_must_cover_every_requested_analyte_family() -> None:
    request = complete_request(
        request_id="request.multi-analyte",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.OXYGEN,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.IN_SITU,
    )
    values = request.model_dump(mode="python", round_trip=True)
    values["measurement"]["analytes"] = (
        *values["measurement"]["analytes"],
        AnalyzerAnalyteRequirement(
            analyte_id="analyte.secondary",
            display_name="Secondary analyte",
            family=AnalyzerAnalyteFamily.OTHER,
            engineering_unit="mol/mol",
            expected_minimum=0.0,
            expected_normal=1.0,
            expected_maximum=2.0,
            required_detection_limit=0.1,
            required_accuracy=1.0,
            source_reference="Approved process basis",
        ).model_dump(mode="python", round_trip=True),
    )
    result = assess_analyzer_application(
        AnalyzerApplicationRequest.model_validate(values)
    )
    zirconia = scenario(result, AnalyzerTechnology.ZIRCONIA_OXYGEN)
    tdl = scenario(result, AnalyzerTechnology.TUNABLE_DIODE_LASER)
    assert (
        next(
            item
            for item in zirconia.rule_results
            if item.rule_id == "rule.analyte_duty"
        ).status
        is AnalyzerRuleStatus.FAILED
    )
    assert tdl.disposition is AnalyzerScenarioDisposition.PLAUSIBLE


def test_controlled_phase_conversion_keeps_process_and_analyzer_phases_separate() -> (
    None
):
    request = complete_request(
        request_id="request.phase-conversion",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.OXYGEN,
        phase=AnalyzerSamplePhase.LIQUID,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    )
    request = replace_nested(
        request,
        "sample_system",
        delivered_sample_phase=AnalyzerSamplePhase.GAS,
        phase_conversion_basis_reference="Approved controlled vaporization basis",
    )
    converted = scenario(
        assess_analyzer_application(request), AnalyzerTechnology.TUNABLE_DIODE_LASER
    )
    assert (
        next(
            item
            for item in converted.rule_results
            if item.rule_id == "rule.sample_phase"
        ).status
        is AnalyzerRuleStatus.PASSED
    )
    missing_basis = replace_nested(
        request,
        "sample_system",
        phase_conversion_basis_reference=None,
    )
    unresolved = scenario(
        assess_analyzer_application(missing_basis),
        AnalyzerTechnology.TUNABLE_DIODE_LASER,
    )
    assert "sample_system.phase_conversion_basis_reference" in (
        unresolved.missing_information_ids
    )


def test_aspirated_detection_is_an_extractive_approach_not_a_sensor_principle() -> None:
    request = complete_request(
        request_id="request.aspirated-detection",
        kind=AnalyzerApplicationKind.GAS_DETECTION,
        family=AnalyzerAnalyteFamily.COMBUSTIBLE_GAS,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.ASPIRATED_DETECTION,
    )
    request = replace_nested(
        request,
        "safety",
        gas_detection_safety_function=AnalyzerTriState.YES,
        independence_requirement_defined=AnalyzerTriState.YES,
        proof_test_and_bypass_basis_defined=AnalyzerTriState.YES,
    )
    result = assess_analyzer_application(request)
    catalytic = scenario(result, AnalyzerTechnology.CATALYTIC_BEAD_GAS_DETECTOR)
    ultrasonic = scenario(result, AnalyzerTechnology.ULTRASONIC_GAS_LEAK_DETECTOR)
    assert catalytic.disposition is AnalyzerScenarioDisposition.PLAUSIBLE
    assert (
        next(
            item
            for item in ultrasonic.rule_results
            if item.rule_id == "rule.sample_approach"
        ).status
        is AnalyzerRuleStatus.FAILED
    )


def test_safety_detection_rejects_declared_absence_of_safety_function() -> None:
    request = complete_request(
        request_id="request.rejected-detection-function",
        kind=AnalyzerApplicationKind.GAS_DETECTION,
        family=AnalyzerAnalyteFamily.COMBUSTIBLE_GAS,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.POINT_DETECTOR,
    )

    result = assess_analyzer_application(request)

    assert result.status is CalculationStatus.BLOCKED
    assert "finding.detection_function_rejected" in {
        item.finding_id for item in result.safety_findings
    }


def test_safety_function_outside_detection_branch_is_blocked() -> None:
    request = complete_request(
        request_id="request.outside-detection-function",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.OXYGEN,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.IN_SITU,
    )
    request = replace_nested(
        request,
        "safety",
        gas_detection_safety_function=AnalyzerTriState.YES,
        independence_requirement_defined=AnalyzerTriState.YES,
        proof_test_and_bypass_basis_defined=AnalyzerTriState.YES,
    )

    result = assess_analyzer_application(request)

    assert result.status is CalculationStatus.BLOCKED
    assert "finding.detection_function_outside_scope" in {
        item.finding_id for item in result.safety_findings
    }


def test_gc_scenario_requires_and_uses_cycle_carrier_calibration_phase_and_disposal() -> (
    None
):
    request = complete_request(
        request_id="request.gc",
        kind=AnalyzerApplicationKind.GAS_CHROMATOGRAPHY,
        family=AnalyzerAnalyteFamily.MULTI_COMPONENT_COMPOSITION,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
        utilities=(
            AnalyzerUtility.CALIBRATION_GAS,
            AnalyzerUtility.CARRIER_GAS,
            AnalyzerUtility.ELECTRICAL_POWER,
        ),
        cycle_seconds=60.0,
    )
    result = assess_analyzer_application(request)
    gc = scenario(result, AnalyzerTechnology.GAS_CHROMATOGRAPH)
    assert gc.disposition is AnalyzerScenarioDisposition.PLAUSIBLE
    assert gc.estimated_total_response_time_seconds is not None
    assert "verify.gc_basis" in gc.verification_requirement_ids
    missing_carrier = replace_nested(
        request,
        "installation",
        available_utilities=(
            AnalyzerUtility.CALIBRATION_GAS,
            AnalyzerUtility.ELECTRICAL_POWER,
        ),
    )
    assert (
        scenario(
            assess_analyzer_application(missing_carrier),
            AnalyzerTechnology.GAS_CHROMATOGRAPH,
        ).disposition
        is AnalyzerScenarioDisposition.CONDITIONAL
    )


def test_gc_missing_cycle_is_visible_and_not_invented() -> None:
    request = complete_request(
        request_id="request.gc-no-cycle",
        kind=AnalyzerApplicationKind.GAS_CHROMATOGRAPHY,
        family=AnalyzerAnalyteFamily.MULTI_COMPONENT_COMPOSITION,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
        utilities=(
            AnalyzerUtility.CALIBRATION_GAS,
            AnalyzerUtility.CARRIER_GAS,
            AnalyzerUtility.ELECTRICAL_POWER,
        ),
    )
    result = assess_analyzer_application(request)
    gc = scenario(result, AnalyzerTechnology.GAS_CHROMATOGRAPH)
    assert gc.disposition is AnalyzerScenarioDisposition.INSUFFICIENT_INFORMATION
    assert "sample_system.analysis_cycle_time" in gc.missing_information_ids
    assert gc.estimated_total_response_time_seconds is None


@pytest.mark.parametrize(
    "field",
    (
        "gc_separation_and_coelution_verified",
        "gc_sample_loop_representative_confirmed",
        "gc_calibration_mixture_defined",
        "gc_carrier_gas_quality_confirmed",
    ),
)
def test_gc_requires_structured_separation_sampling_calibration_and_carrier_evidence(
    field: str,
) -> None:
    request = complete_request(
        request_id=f"request.gc-missing-{field}",
        kind=AnalyzerApplicationKind.GAS_CHROMATOGRAPHY,
        family=AnalyzerAnalyteFamily.MULTI_COMPONENT_COMPOSITION,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
        utilities=(
            AnalyzerUtility.CALIBRATION_GAS,
            AnalyzerUtility.CARRIER_GAS,
            AnalyzerUtility.ELECTRICAL_POWER,
        ),
        cycle_seconds=60.0,
    )
    request = replace_nested(
        request,
        "sample_system",
        **{field: AnalyzerTriState.UNKNOWN},
    )
    result = assess_analyzer_application(request)
    gc = scenario(result, AnalyzerTechnology.GAS_CHROMATOGRAPH)
    assert gc.disposition is AnalyzerScenarioDisposition.INSUFFICIENT_INFORMATION
    assert f"sample_system.{field}" in gc.missing_information_ids


def test_toxic_extractive_controlled_state_remains_warning_not_approval() -> None:
    request = complete_request(
        request_id="request.toxic-controlled",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.TOXIC_GAS,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    )
    request = replace_nested(
        request,
        "safety",
        toxic_material=AnalyzerTriState.YES,
        sample_containment_confirmed=AnalyzerTriState.YES,
        safe_vent_or_disposal_confirmed=AnalyzerTriState.YES,
        exposure_control_defined=AnalyzerTriState.YES,
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert "finding.hazardous_sample_handling" in {
        item.finding_id for item in result.safety_findings
    }
    assert not result.approved_for_project_use


@pytest.mark.parametrize(
    ("field", "missing_id"),
    (
        ("sample_containment_confirmed", "safety.sample_containment_confirmed"),
        ("safe_vent_or_disposal_confirmed", "safety.safe_vent_or_disposal_confirmed"),
        ("exposure_control_defined", "safety.exposure_control_defined"),
    ),
)
def test_toxic_extractive_unknown_controls_are_insufficient(
    field: str,
    missing_id: str,
) -> None:
    request = complete_request(
        request_id=f"request.toxic-unknown-{field}",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.TOXIC_GAS,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    )
    request = replace_nested(
        request,
        "safety",
        toxic_material=AnalyzerTriState.YES,
        **{field: AnalyzerTriState.UNKNOWN},
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert missing_id in {item.field_id for item in result.missing_information}


@pytest.mark.parametrize(
    ("field", "finding_id"),
    (
        ("sample_containment_confirmed", "finding.sample_containment_rejected"),
        ("safe_vent_or_disposal_confirmed", "finding.sample_disposal_rejected"),
        ("exposure_control_defined", "finding.exposure_control_rejected"),
    ),
)
def test_toxic_extractive_explicitly_rejected_controls_block(
    field: str,
    finding_id: str,
) -> None:
    request = complete_request(
        request_id=f"request.toxic-block-{field}",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.TOXIC_GAS,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    )
    request = replace_nested(
        request,
        "safety",
        toxic_material=AnalyzerTriState.YES,
        **{field: AnalyzerTriState.NO},
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.BLOCKED
    assert finding_id in {item.finding_id for item in result.safety_findings}


def complete_flammable_detection_request() -> AnalyzerApplicationRequest:
    request = complete_request(
        request_id="request.flammable-detection",
        kind=AnalyzerApplicationKind.GAS_DETECTION,
        family=AnalyzerAnalyteFamily.COMBUSTIBLE_GAS,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.POINT_DETECTOR,
    )
    return replace_nested(
        request,
        "safety",
        hazardous_area=AnalyzerTriState.YES,
        hazardous_area_classification="Project hazardous-area basis",
        hazardous_area_equipment_certification_confirmed=AnalyzerTriState.YES,
        flammable_material=AnalyzerTriState.YES,
        gas_detection_safety_function=AnalyzerTriState.YES,
        alarm_basis_defined=AnalyzerTriState.YES,
        detector_coverage_basis_defined=AnalyzerTriState.YES,
        detector_response_basis_defined=AnalyzerTriState.YES,
        independence_requirement_defined=AnalyzerTriState.YES,
        proof_test_and_bypass_basis_defined=AnalyzerTriState.YES,
    )


def test_flammable_detection_keeps_detector_options_without_safety_claim() -> None:
    result = assess_analyzer_application(complete_flammable_detection_request())
    plausible = {
        item.technology
        for item in result.scenarios
        if item.disposition is AnalyzerScenarioDisposition.PLAUSIBLE
    }
    assert AnalyzerTechnology.CATALYTIC_BEAD_GAS_DETECTOR in plausible
    assert AnalyzerTechnology.INFRARED_POINT_GAS_DETECTOR in plausible
    assert AnalyzerTechnology.GAS_CHROMATOGRAPH not in {
        item.technology for item in result.scenarios
    }
    assert result.safety_integrity_claimed is False
    assert "finding.gas_detection_scope" in {
        item.finding_id for item in result.safety_findings
    }


@pytest.mark.parametrize(
    "field",
    (
        "alarm_basis_defined",
        "detector_coverage_basis_defined",
        "detector_response_basis_defined",
        "independence_requirement_defined",
        "proof_test_and_bypass_basis_defined",
    ),
)
def test_detection_unknown_safety_evidence_is_insufficient(field: str) -> None:
    request = replace_nested(
        complete_flammable_detection_request(),
        "safety",
        **{field: AnalyzerTriState.UNKNOWN},
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert f"safety.{field}" in {item.field_id for item in result.missing_information}


@pytest.mark.parametrize(
    ("field", "finding_id"),
    (
        ("alarm_basis_defined", "finding.detection_alarm_basis_rejected"),
        (
            "detector_coverage_basis_defined",
            "finding.detection_coverage_basis_rejected",
        ),
        (
            "detector_response_basis_defined",
            "finding.detection_response_basis_rejected",
        ),
        ("independence_requirement_defined", "finding.detection_independence_rejected"),
        (
            "proof_test_and_bypass_basis_defined",
            "finding.detection_proof_test_rejected",
        ),
    ),
)
def test_detection_rejected_governance_blocks(field: str, finding_id: str) -> None:
    request = replace_nested(
        complete_flammable_detection_request(),
        "safety",
        **{field: AnalyzerTriState.NO},
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.BLOCKED
    assert finding_id in {item.finding_id for item in result.safety_findings}


def test_hazardous_area_missing_classification_blocks() -> None:
    request = replace_nested(
        complete_flammable_detection_request(),
        "safety",
        hazardous_area_classification=None,
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.BLOCKED
    assert "finding.hazardous_area_missing_classification" in {
        item.finding_id for item in result.safety_findings
    }


@pytest.mark.parametrize(
    ("safety_field", "control_field", "finding_id"),
    (
        (
            "high_pressure_sampling",
            "pressure_control_defined",
            "finding.pressure_control_rejected",
        ),
        (
            "high_temperature_sampling",
            "temperature_control_defined",
            "finding.temperature_control_rejected",
        ),
    ),
)
def test_rejected_hazardous_sample_controls_block(
    safety_field: str,
    control_field: str,
    finding_id: str,
) -> None:
    request = complete_request(
        request_id=f"request.rejected-{control_field}",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.OXYGEN,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    )
    request = replace_nested(
        request,
        "safety",
        **{safety_field: AnalyzerTriState.YES},
    )
    request = replace_nested(
        request,
        "sample_system",
        **{control_field: AnalyzerTriState.NO},
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.BLOCKED
    assert finding_id in {item.finding_id for item in result.safety_findings}


def test_oxygen_and_stored_energy_hazards_require_containment_and_disposal() -> None:
    request = complete_request(
        request_id="request.oxygen-pressure-controls",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.OXYGEN,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    )
    request = replace_nested(
        request,
        "safety",
        oxygen_deficiency_or_enrichment=AnalyzerTriState.YES,
        high_pressure_sampling=AnalyzerTriState.YES,
        sample_containment_confirmed=AnalyzerTriState.NO,
        safe_vent_or_disposal_confirmed=AnalyzerTriState.NO,
    )
    result = assess_analyzer_application(request)
    finding_ids = {item.finding_id for item in result.safety_findings}
    assert result.status is CalculationStatus.BLOCKED
    assert {
        "finding.oxygen_hazard_review",
        "finding.sample_containment_rejected",
        "finding.sample_disposal_rejected",
    } <= finding_ids


def test_extractive_sample_probe_basis_cannot_be_unknown() -> None:
    request = complete_request(
        request_id="request.sample-probe-unknown",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.OXYGEN,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    )
    request = replace_nested(
        request,
        "sample_system",
        sample_probe_defined=AnalyzerTriState.UNKNOWN,
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert "sample_system.sample_probe_defined" in {
        item.field_id for item in result.missing_information
    }


def test_particulate_service_reports_filter_and_representativeness_risk() -> None:
    request = complete_request(
        request_id="request.particulate",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.HYDROCARBON,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
        utilities=(
            AnalyzerUtility.CALIBRATION_GAS,
            AnalyzerUtility.ELECTRICAL_POWER,
            AnalyzerUtility.INSTRUMENT_AIR,
        ),
    )
    request = replace_nested(
        request,
        "process",
        particulate_loading=AnalyzerConditionSeverity.HIGH,
    )
    result = assess_analyzer_application(request)
    text = result.model_dump_json()
    assert result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert "filter bias" in text
    assert "representative" in text
    assert "fouling" in text


def test_particulate_service_without_filter_is_conditional() -> None:
    request = complete_request(
        request_id="request.particulate-no-filter",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.HYDROCARBON,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    )
    request = replace_nested(
        replace_nested(
            request,
            "process",
            particulate_loading=AnalyzerConditionSeverity.HIGH,
        ),
        "sample_system",
        filtration_defined=AnalyzerTriState.NO,
    )
    result = assess_analyzer_application(request)
    assert any(
        item.disposition is AnalyzerScenarioDisposition.CONDITIONAL
        for item in result.scenarios
    )


def test_wet_condensing_service_reports_phase_and_target_loss_risks() -> None:
    request = complete_request(
        request_id="request.wet",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.MOISTURE,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    )
    request = replace_nested(
        request,
        "process",
        wet_sample=AnalyzerConditionSeverity.HIGH,
        liquid_droplets=AnalyzerConditionSeverity.MODERATE,
    )
    result = assess_analyzer_application(request)
    text = result.model_dump_json()
    assert result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert "dew-point" in text
    assert "soluble-target loss" in text
    assert "condensate" in text


def test_corrosive_service_with_incompatible_materials_blocks() -> None:
    request = complete_request(
        request_id="request.corrosive",
        kind=AnalyzerApplicationKind.LIQUID_PROCESS,
        family=AnalyzerAnalyteFamily.CONDUCTIVITY,
        phase=AnalyzerSamplePhase.LIQUID,
        approach=AnalyzerSampleApproach.IN_SITU,
    )
    request = replace_nested(
        replace_nested(
            request,
            "process",
            corrosivity=AnalyzerConditionSeverity.HIGH,
        ),
        "sample_system",
        materials_compatibility_confirmed=AnalyzerTriState.NO,
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.BLOCKED
    assert "finding.materials_incompatible" in {
        item.finding_id for item in result.safety_findings
    }


def test_corrosive_service_with_unknown_materials_is_insufficient() -> None:
    request = complete_request(
        request_id="request.corrosive-unknown",
        kind=AnalyzerApplicationKind.LIQUID_PROCESS,
        family=AnalyzerAnalyteFamily.CONDUCTIVITY,
        phase=AnalyzerSamplePhase.LIQUID,
        approach=AnalyzerSampleApproach.IN_SITU,
    )
    request = replace_nested(
        replace_nested(
            request,
            "process",
            corrosivity=AnalyzerConditionSeverity.MODERATE,
        ),
        "sample_system",
        materials_compatibility_confirmed=AnalyzerTriState.UNKNOWN,
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT


def test_known_interference_remains_generic_and_requires_verification() -> None:
    request = complete_request(
        request_id="request.interference",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.HYDROCARBON,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    )
    request = replace_nested(
        request,
        "process",
        known_interferences_assessed=AnalyzerTriState.YES,
        known_interferences=(
            AnalyzerKnownInterference(
                interference_id="interference.matrix",
                component_name="Caller-named matrix component",
                mechanism=AnalyzerInterferenceMechanism.SPECTRAL_OVERLAP,
                severity=AnalyzerConditionSeverity.HIGH,
                source_reference="Interference review",
            ),
        ),
    )
    result = assess_analyzer_application(request)
    assert "technology-specific" in result.model_dump_json()
    assert all(
        "verify.interference" in item.verification_requirement_ids
        for item in result.scenarios
    )


def test_explicitly_unperformed_interference_assessment_is_insufficient() -> None:
    request = complete_request(
        request_id="request.interference-not-assessed",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.HYDROCARBON,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    )
    request = replace_nested(
        request,
        "process",
        known_interferences_assessed=AnalyzerTriState.NO,
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert "process.known_interferences_assessed" in {
        item.field_id for item in result.missing_information
    }


def test_nominal_line_residence_is_calculated_only_from_complete_actual_basis() -> None:
    request = complete_request(
        request_id="request.response",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.HYDROCARBON,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
        response_seconds=5.0,
    )
    result = assess_analyzer_application(request)
    expected = 5.0 + pi * 0.01**2 * 10.0 / (4.0 * 0.001)
    assert all(
        item.estimated_total_response_time_seconds == pytest.approx(expected)
        for item in result.scenarios
    )
    assert "not a verified end-to-end T90" in result.model_dump_json()


def test_partial_line_basis_does_not_create_a_response_total() -> None:
    request = complete_request(
        request_id="request.partial-response",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.HYDROCARBON,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    )
    request = replace_nested(
        request,
        "sample_system",
        sample_line_internal_diameter=None,
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert all(
        item.estimated_total_response_time_seconds is None for item in result.scenarios
    )
    assert "sample_system.transport_response_basis" in {
        item.field_id for item in result.missing_information
    }


def test_unconfirmed_response_contributor_is_not_totalled() -> None:
    request = complete_request(
        request_id="request.unconfirmed-response",
        kind=AnalyzerApplicationKind.LIQUID_PROCESS,
        family=AnalyzerAnalyteFamily.CONDUCTIVITY,
        phase=AnalyzerSamplePhase.LIQUID,
        approach=AnalyzerSampleApproach.IN_SITU,
    )
    request = replace_nested(
        request,
        "sample_system",
        response_time_contributors=(
            response_contributor(
                "response.unconfirmed",
                AnalyzerResponseContributorKind.ANALYZER_CELL,
                5.0,
                confirmed=False,
            ),
        ),
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert all(
        item.estimated_total_response_time_seconds is None for item in result.scenarios
    )


def test_incomplete_response_budget_never_reports_a_partial_total() -> None:
    request = complete_request(
        request_id="request.incomplete-response-budget",
        kind=AnalyzerApplicationKind.LIQUID_PROCESS,
        family=AnalyzerAnalyteFamily.CONDUCTIVITY,
        phase=AnalyzerSamplePhase.LIQUID,
        approach=AnalyzerSampleApproach.IN_SITU,
    )
    request = replace_nested(
        request,
        "sample_system",
        response_time_budget_complete=AnalyzerTriState.NO,
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert "sample_system.response_time_budget_complete" in {
        item.field_id for item in result.missing_information
    }
    assert all(
        item.estimated_total_response_time_seconds is None for item in result.scenarios
    )


def test_response_budget_over_requirement_is_conditional_not_compliant() -> None:
    request = complete_request(
        request_id="request.slow",
        kind=AnalyzerApplicationKind.LIQUID_PROCESS,
        family=AnalyzerAnalyteFamily.CONDUCTIVITY,
        phase=AnalyzerSamplePhase.LIQUID,
        approach=AnalyzerSampleApproach.IN_SITU,
        response_seconds=130.0,
    )
    result = assess_analyzer_application(request)
    assert all(
        item.disposition is AnalyzerScenarioDisposition.CONDITIONAL
        for item in result.scenarios
    )


def test_high_pressure_sampling_reports_cooling_condensation_and_release_risk() -> None:
    request = complete_request(
        request_id="request.high-pressure",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.OXYGEN,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.IN_SITU,
    )
    request = replace_nested(
        request,
        "safety",
        high_pressure_sampling=AnalyzerTriState.YES,
    )
    text = assess_analyzer_application(request).model_dump_json()
    assert "cooling" in text
    assert "condensation" in text
    assert "stored-energy" in text


def test_outdoor_installation_without_protection_basis_is_insufficient() -> None:
    request = complete_request(
        request_id="request.outdoor",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.OXYGEN,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.IN_SITU,
    )
    request = replace_nested(
        request,
        "installation",
        environment_conditions=(
            AnalyzerEnvironmentCondition.OUTDOOR,
            AnalyzerEnvironmentCondition.HIGH_VIBRATION,
        ),
        shelter_or_enclosure_basis_defined=AnalyzerTriState.UNKNOWN,
    )
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert "installation.shelter_or_enclosure_basis_defined" in {
        item.field_id for item in result.missing_information
    }


def test_undeclared_installation_environment_is_insufficient() -> None:
    request = complete_request(
        request_id="request.environment-unknown",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.OXYGEN,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.IN_SITU,
    )
    request = replace_nested(request, "installation", environment_conditions=())
    result = assess_analyzer_application(request)
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert "installation.environment_conditions" in {
        item.field_id for item in result.missing_information
    }


def test_safety_findings_lead_serialized_result() -> None:
    result = assess_analyzer_application(complete_flammable_detection_request())
    assert next(iter(result.model_dump(mode="json"))) == "safety_findings"
    assert result.safety_findings
    assert result.scenarios


def test_evidence_graph_links_resolve_without_orphans() -> None:
    result = assess_analyzer_application(complete_flammable_detection_request())
    missing_ids = {item.field_id for item in result.missing_information}
    finding_ids = {item.finding_id for item in result.safety_findings}
    verification_ids = {item.verification_id for item in result.verification_steps}
    used_verifications: set[str] = set()
    for item in result.scenarios:
        assert set(item.missing_information_ids) <= missing_ids
        assert set(item.finding_ids) <= finding_ids
        assert set(item.verification_requirement_ids) <= verification_ids
        used_verifications.update(item.verification_requirement_ids)
        for rule in item.rule_results:
            assert set(rule.verification_requirement_ids) <= verification_ids
            used_verifications.update(rule.verification_requirement_ids)
            assert {"ref.eng-070", "ref.e4m-calc-060"} <= set(rule.reference_ids)
    for finding in result.safety_findings:
        used_verifications.update(finding.verification_requirement_ids)
    assert used_verifications == verification_ids


def test_verification_steps_name_competency_evidence_and_acceptance() -> None:
    assert all(item.required_competency for item in ANALYZER_VERIFICATION_STEPS)
    assert all(item.evidence_required for item in ANALYZER_VERIFICATION_STEPS)
    assert all(item.acceptance_criteria for item in ANALYZER_VERIFICATION_STEPS)
    assert {item.priority for item in ANALYZER_VERIFICATION_STEPS} >= {
        AnalyzerVerificationPriority.IMPORTANT,
        AnalyzerVerificationPriority.SAFETY_CRITICAL,
    }


def test_no_selection_certification_or_conformity_claim_is_possible() -> None:
    result = assess_analyzer_application(complete_flammable_detection_request())
    assert result.vendor_neutral is True
    assert result.manufacturer_selection_performed is False
    assert result.manufacturer_declared_best is False
    assert result.model_selection_performed is False
    assert result.product_selected is False
    assert result.brand_ranked is False
    assert result.final_brand_selection == "user_decision_required"
    assert result.standards_conformity_claimed is False
    assert result.hazardous_area_certification_performed is False
    assert result.safety_integrity_claimed is False
    assert result.sample_system_approved is False
    assert result.alarm_setpoint_selected is False
    assert result.detector_placement_or_coverage_approved is False
    assert result.final_design_approval_granted is False
    assert result.approved_for_project_use is False
    assert all(item.vendor_neutral for item in result.scenarios)
    assert all(not item.final_suitability_claimed for item in result.scenarios)


def test_ultrasonic_detection_does_not_claim_identity_or_concentration() -> None:
    definition = ANALYZER_TECHNOLOGY_REGISTRY[
        AnalyzerTechnology.ULTRASONIC_GAS_LEAK_DETECTOR
    ]
    assert "does not identify a gas or measure concentration" in definition.principle


def test_calculation_registry_remains_exactly_26_methods() -> None:
    assert len(calculation_package.ENGINEERING_METHOD_IDS) == 26


def test_package_boundary_exports_step106_without_version_bump() -> None:
    assert design_package.FOUNDATION_VERSION == "0.2.0"
    assert design_package.VOICE_FUNCTIONALITY_ENABLED is False
    for name in (
        "ANALYZER_APPLICATION_MODEL_VERSION",
        "ANALYZER_ASSISTANT_VERSION",
        "ANALYZER_RULESET_VERSION",
        "ANALYZER_TECHNOLOGY_CATALOGUE",
        "ANALYZER_VERIFICATION_STEPS",
        "DEFAULT_ANALYZER_APPLICATION_ASSISTANT",
        "AnalyzerApplicationAssessment",
        "AnalyzerApplicationAssistant",
        "AnalyzerApplicationRequest",
        "assess_analyzer_application",
    ):
        assert name in design_package.__all__
        assert hasattr(design_package, name)


def test_assistant_source_has_no_io_api_dynamic_execution_or_voice_boundary() -> None:
    source_path = (
        Path(__file__).parents[1] / "app/engineering/design/analyzer_assistant.py"
    )
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_import_roots = {
        "asyncio",
        "fastapi",
        "httpx",
        "requests",
        "socket",
        "sqlalchemy",
        "sqlite3",
        "subprocess",
        "urllib",
    }
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not imports.intersection(forbidden_import_roots)
    assert not calls.intersection({"eval", "exec", "open", "compile", "__import__"})
    lowered = source.casefold()
    assert "speech_recognition" not in lowered
    assert "text_to_speech" not in lowered
    assert "apirouter" not in lowered
    assert "database" not in lowered


@pytest.mark.parametrize(
    "technology",
    (
        AnalyzerTechnology.CATALYTIC_BEAD_GAS_DETECTOR,
        AnalyzerTechnology.ELECTROCHEMICAL_GAS_DETECTOR,
        AnalyzerTechnology.INFRARED_POINT_GAS_DETECTOR,
        AnalyzerTechnology.OPEN_PATH_INFRARED_GAS_DETECTOR,
        AnalyzerTechnology.PHOTOIONIZATION_DETECTOR,
        AnalyzerTechnology.SEMICONDUCTOR_GAS_DETECTOR,
        AnalyzerTechnology.ULTRASONIC_GAS_LEAK_DETECTOR,
    ),
)
def test_detection_taxonomy_never_cross_labels_process_analyzers(
    technology: AnalyzerTechnology,
) -> None:
    definition = ANALYZER_TECHNOLOGY_REGISTRY[technology]
    assert definition.supported_application_kinds == (
        AnalyzerApplicationKind.GAS_DETECTION,
    )
    aspirated_compatible = {
        AnalyzerTechnology.CATALYTIC_BEAD_GAS_DETECTOR,
        AnalyzerTechnology.ELECTROCHEMICAL_GAS_DETECTOR,
        AnalyzerTechnology.INFRARED_POINT_GAS_DETECTOR,
        AnalyzerTechnology.PHOTOIONIZATION_DETECTOR,
        AnalyzerTechnology.SEMICONDUCTOR_GAS_DETECTOR,
    }
    assert (
        AnalyzerSampleApproach.ASPIRATED_DETECTION
        in definition.supported_sample_approaches
    ) is (technology in aspirated_compatible)


def test_all_rules_are_deterministic_bounded_and_traceable() -> None:
    result = assess_analyzer_application(complete_flammable_detection_request())
    for item in result.scenarios:
        assert 0.0 <= item.suitability_score <= 100.0
        assert 0.0 <= item.confidence_score <= 100.0
        assert item.limitations
        assert item.verification_requirement_ids
        for rule in item.rule_results:
            assert 0.0 < rule.weight <= 100.0
            assert 0.0 <= rule.awarded_weight <= rule.weight
            if rule.status is AnalyzerRuleStatus.MISSING_INFORMATION:
                assert rule.missing_field_ids
