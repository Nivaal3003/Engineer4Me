"""Strict contract tests for Phase 7 Step 106 analyzer models."""

from __future__ import annotations

from math import inf, nan

import pytest
from pydantic import ValidationError

from app.engineering.calculations.models import (
    CalculationStatus,
    EngineeringQuantity,
    FindingCategory,
)
from app.engineering.calculations.units import QuantityKind
from app.engineering.design.analyzer_assistant import (
    ANALYZER_TECHNOLOGY_CATALOGUE,
    assess_analyzer_application,
)
from app.engineering.design.analyzer_models import (
    ANALYZER_APPLICATION_MODEL_VERSION,
    AnalyzerAnalyteFamily,
    AnalyzerAnalyteRequirement,
    AnalyzerApplicationAssessment,
    AnalyzerApplicationKind,
    AnalyzerApplicationRequest,
    AnalyzerConditionSeverity,
    AnalyzerConfidenceBand,
    AnalyzerEnvironmentCondition,
    AnalyzerInstallationContext,
    AnalyzerMeasurementObjective,
    AnalyzerMeasurementRequirements,
    AnalyzerProcessContext,
    AnalyzerResponseContributorKind,
    AnalyzerResponseTimeContributor,
    AnalyzerRuleResult,
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
    analyzer_confidence_band,
    canonical_analyzer_quantity_value,
    fingerprint_analyzer_payload,
)


def quantity(kind: QuantityKind, value: float, unit: str) -> EngineeringQuantity:
    return EngineeringQuantity(quantity_kind=kind.value, value=value, unit=unit)


def analyte(
    family: AnalyzerAnalyteFamily = AnalyzerAnalyteFamily.ACIDITY_ALKALINITY,
    *,
    analyte_id: str = "analyte.primary",
) -> AnalyzerAnalyteRequirement:
    return AnalyzerAnalyteRequirement(
        analyte_id=analyte_id,
        display_name="Primary analyte",
        family=family,
        engineering_unit="mol/mol",
        expected_minimum=0.0,
        expected_normal=10.0,
        expected_maximum=20.0,
        required_detection_limit=0.1,
        required_accuracy=1.0,
        source_reference="Approved process basis",
    )


def complete_liquid_request() -> AnalyzerApplicationRequest:
    return AnalyzerApplicationRequest(
        request_id="request.liquid",
        application_kind=AnalyzerApplicationKind.LIQUID_PROCESS,
        measurement=AnalyzerMeasurementRequirements(
            objectives=(AnalyzerMeasurementObjective.PROCESS_CONTROL,),
            analytes=(analyte(),),
            minimum_availability_percent=95.0,
            continuous_output_required=AnalyzerTriState.YES,
            local_indication_required=AnalyzerTriState.YES,
            automatic_calibration_required=AnalyzerTriState.NO,
        ),
        process=AnalyzerProcessContext(
            sample_phase=AnalyzerSamplePhase.LIQUID,
            stream_description="Water service",
            matrix_components=("Water",),
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
            approach=AnalyzerSampleApproach.IN_SITU,
            representative_sample_confirmed=AnalyzerTriState.YES,
            phase_preservation_confirmed=AnalyzerTriState.YES,
            materials_compatibility_confirmed=AnalyzerTriState.YES,
            calibration_introduction_defined=AnalyzerTriState.YES,
            disposition=AnalyzerSampleDisposition.NOT_APPLICABLE,
        ),
        safety=AnalyzerSafetyContext(
            hazardous_area=AnalyzerTriState.NO,
            toxic_material=AnalyzerTriState.NO,
            flammable_material=AnalyzerTriState.NO,
            oxygen_deficiency_or_enrichment=AnalyzerTriState.NO,
            high_pressure_sampling=AnalyzerTriState.NO,
            high_temperature_sampling=AnalyzerTriState.NO,
        ),
        installation=AnalyzerInstallationContext(
            available_utilities=(AnalyzerUtility.ELECTRICAL_POWER,),
            utility_availability_confirmed=AnalyzerTriState.YES,
            environment_conditions=(AnalyzerEnvironmentCondition.INDOOR_CONTROLLED,),
            maintenance_access_confirmed=AnalyzerTriState.YES,
            calibration_access_confirmed=AnalyzerTriState.YES,
            shelter_or_enclosure_basis_defined=AnalyzerTriState.YES,
        ),
    )


def test_analyzer_model_version_is_exact() -> None:
    assert ANALYZER_APPLICATION_MODEL_VERSION == "1.0.0"


def test_analyzer_fingerprint_normalizes_semantic_zero() -> None:
    assert fingerprint_analyzer_payload({"value": 0.0}) == (
        fingerprint_analyzer_payload({"value": -0.0})
    )


def test_request_nested_defaults_are_independent_and_frozen() -> None:
    first = AnalyzerApplicationRequest(request_id="request.first")
    second = AnalyzerApplicationRequest(request_id="request.second")
    assert first.measurement is not second.measurement
    with pytest.raises(ValidationError):
        first.request_id = "request.changed"  # type: ignore[misc]


def test_assessment_collections_require_canonical_identifier_order() -> None:
    assessment = assess_analyzer_application(
        AnalyzerApplicationRequest(request_id="request.ordering")
    )
    values = assessment.model_dump(mode="python", round_trip=True)
    values["missing_information"] = tuple(reversed(values["missing_information"]))
    with pytest.raises(ValidationError, match="ordered by field_id"):
        AnalyzerApplicationAssessment.model_validate(values)

    values = assessment.model_dump(mode="python", round_trip=True)
    values["verification_steps"] = tuple(reversed(values["verification_steps"]))
    with pytest.raises(ValidationError, match="ordered by verification_id"):
        AnalyzerApplicationAssessment.model_validate(values)

    scenario_values = assessment.scenarios[0].model_dump(
        mode="python",
        round_trip=True,
    )
    scenario_values["rule_results"] = tuple(reversed(scenario_values["rule_results"]))
    with pytest.raises(ValidationError, match="ordered by rule_id"):
        type(assessment.scenarios[0]).model_validate(scenario_values)


@pytest.mark.parametrize(
    ("model", "values"),
    (
        (AnalyzerApplicationRequest, {"request_id": "request.extra", "extra": 1}),
        (AnalyzerMeasurementRequirements, {"unexpected": True}),
        (AnalyzerProcessContext, {"unexpected": "value"}),
        (AnalyzerSampleSystemContext, {"unexpected": "value"}),
        (AnalyzerSafetyContext, {"unexpected": "value"}),
        (AnalyzerInstallationContext, {"unexpected": "value"}),
    ),
)
def test_models_reject_extra_fields(model, values: dict[str, object]) -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        model.model_validate(values)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("request_id", " request.padded"),
        ("request_id", "request.padded "),
        ("application_notes", " padded note"),
    ),
)
def test_request_rejects_raw_padded_text(field: str, value: str) -> None:
    values: dict[str, object] = {"request_id": "request.valid", field: value}
    with pytest.raises(ValidationError, match="unpadded"):
        AnalyzerApplicationRequest.model_validate(values)


@pytest.mark.parametrize("value", (nan, inf, -inf))
def test_analyte_rejects_nonfinite_values(value: float) -> None:
    values = analyte().model_dump(mode="python")
    values["expected_normal"] = value
    with pytest.raises(ValidationError):
        AnalyzerAnalyteRequirement.model_validate(values)


@pytest.mark.parametrize(
    ("minimum", "normal", "maximum"),
    ((2.0, 1.0, 3.0), (1.0, 4.0, 3.0)),
)
def test_analyte_range_must_be_ordered(
    minimum: float,
    normal: float,
    maximum: float,
) -> None:
    values = analyte().model_dump(mode="python")
    values.update(
        expected_minimum=minimum,
        expected_normal=normal,
        expected_maximum=maximum,
    )
    with pytest.raises(ValidationError, match="minimum <= normal <= maximum"):
        AnalyzerAnalyteRequirement.model_validate(values)


def test_detection_limit_cannot_exceed_range() -> None:
    values = analyte().model_dump(mode="python")
    values["required_detection_limit"] = 21.0
    with pytest.raises(ValidationError, match="cannot exceed"):
        AnalyzerAnalyteRequirement.model_validate(values)


def test_analytes_are_unique_and_canonically_ordered() -> None:
    values = AnalyzerMeasurementRequirements(
        analytes=(
            analyte(analyte_id="zeta"),
            analyte(analyte_id="alpha"),
        )
    )
    assert tuple(item.analyte_id for item in values.analytes) == ("alpha", "zeta")
    with pytest.raises(ValidationError, match="unique"):
        AnalyzerMeasurementRequirements(
            analytes=(analyte(analyte_id="same"), analyte(analyte_id="same"))
        )


def test_set_input_is_rejected_for_ordered_contract() -> None:
    with pytest.raises(ValidationError):
        AnalyzerMeasurementRequirements.model_validate(
            {"objectives": {"process_control", "quality_control"}}
        )


def test_process_components_are_case_insensitively_unique_and_sorted() -> None:
    process = AnalyzerProcessContext(matrix_components=("Water", "Carbon dioxide"))
    assert process.matrix_components == ("Carbon dioxide", "Water")
    with pytest.raises(ValidationError, match="unique"):
        AnalyzerProcessContext(matrix_components=("Water", "water"))


def test_process_temperature_and_pressure_envelopes_are_ordered() -> None:
    with pytest.raises(ValidationError, match="temperatures"):
        AnalyzerProcessContext(
            minimum_temperature=quantity(QuantityKind.ABSOLUTE_TEMPERATURE, 300.0, "K"),
            normal_temperature=quantity(QuantityKind.ABSOLUTE_TEMPERATURE, 290.0, "K"),
            maximum_temperature=quantity(QuantityKind.ABSOLUTE_TEMPERATURE, 310.0, "K"),
        )
    with pytest.raises(ValidationError, match="pressures"):
        AnalyzerProcessContext(
            minimum_absolute_pressure=quantity(
                QuantityKind.ABSOLUTE_PRESSURE, 100000.0, "Pa"
            ),
            normal_absolute_pressure=quantity(
                QuantityKind.ABSOLUTE_PRESSURE, 300000.0, "Pa"
            ),
            maximum_absolute_pressure=quantity(
                QuantityKind.ABSOLUTE_PRESSURE, 200000.0, "Pa"
            ),
        )


@pytest.mark.parametrize(
    "values",
    (
        {
            "minimum_temperature": quantity(
                QuantityKind.ABSOLUTE_TEMPERATURE, 310.0, "K"
            ),
            "maximum_temperature": quantity(
                QuantityKind.ABSOLUTE_TEMPERATURE, 300.0, "K"
            ),
        },
        {
            "minimum_absolute_pressure": quantity(
                QuantityKind.ABSOLUTE_PRESSURE, 300000.0, "Pa"
            ),
            "maximum_absolute_pressure": quantity(
                QuantityKind.ABSOLUTE_PRESSURE, 200000.0, "Pa"
            ),
        },
    ),
)
def test_partial_process_envelopes_cannot_hide_reversed_limits(
    values: dict[str, EngineeringQuantity],
) -> None:
    with pytest.raises(ValidationError, match="must satisfy"):
        AnalyzerProcessContext.model_validate(values)


def test_quantities_require_the_correct_kind() -> None:
    with pytest.raises(ValidationError, match="quantity_kind"):
        AnalyzerSampleSystemContext(
            sample_line_length=quantity(QuantityKind.TIME, 1.0, "s")
        )
    with pytest.raises(ValidationError, match="quantity_kind"):
        AnalyzerMeasurementRequirements(
            maximum_total_response_time=quantity(QuantityKind.LENGTH, 1.0, "m")
        )


@pytest.mark.parametrize(
    "field", ("sample_line_length", "sample_line_internal_diameter")
)
def test_sample_line_dimensions_must_be_positive(field: str) -> None:
    values = {
        field: quantity(QuantityKind.LENGTH, 0.0, "m"),
    }
    with pytest.raises(ValidationError, match="greater than zero"):
        AnalyzerSampleSystemContext.model_validate(values)


def test_nonextractive_arrangement_rejects_line_transport_data() -> None:
    with pytest.raises(ValidationError, match="sample-line transport"):
        AnalyzerSampleSystemContext(
            approach=AnalyzerSampleApproach.IN_SITU,
            sample_line_length=quantity(QuantityKind.LENGTH, 10.0, "m"),
        )


def test_nonextractive_arrangement_rejects_extracted_disposition() -> None:
    with pytest.raises(ValidationError, match="sample disposition"):
        AnalyzerSampleSystemContext(
            approach=AnalyzerSampleApproach.OPEN_PATH,
            disposition=AnalyzerSampleDisposition.SAFE_VENT,
        )


def test_nonextractive_request_rejects_contradictory_phase_evidence() -> None:
    values = complete_liquid_request().model_dump(mode="python", round_trip=True)
    values["sample_system"]["delivered_sample_phase"] = AnalyzerSamplePhase.GAS
    values["sample_system"]["phase_conversion_basis_reference"] = (
        "Contradictory conversion basis"
    )
    with pytest.raises(ValidationError, match="phase-conversion|must match"):
        AnalyzerApplicationRequest.model_validate(values)


@pytest.mark.parametrize(
    "approach",
    (
        AnalyzerSampleApproach.EXTRACTIVE,
        AnalyzerSampleApproach.ASPIRATED_DETECTION,
    ),
)
def test_extractive_arrangement_requires_a_real_sample_destination(
    approach: AnalyzerSampleApproach,
) -> None:
    with pytest.raises(ValidationError, match="explicit sample disposition"):
        AnalyzerSampleSystemContext(
            approach=approach,
            disposition=AnalyzerSampleDisposition.NOT_APPLICABLE,
        )


def test_nonextractive_arrangement_rejects_transport_contributor() -> None:
    with pytest.raises(ValidationError, match="extractive response contributors"):
        AnalyzerSampleSystemContext(
            approach=AnalyzerSampleApproach.POINT_DETECTOR,
            response_time_contributors=(
                AnalyzerResponseTimeContributor(
                    contributor_id="response.transport",
                    kind=AnalyzerResponseContributorKind.TRANSPORT_LINE,
                    duration=quantity(QuantityKind.TIME, 5.0, "s"),
                    basis="Transport basis",
                    source_reference="Response record",
                    confirmed=True,
                ),
            ),
        )


def test_return_to_process_rejects_known_incompatibility() -> None:
    with pytest.raises(ValidationError, match="rejected compatibility"):
        AnalyzerSampleSystemContext(
            approach=AnalyzerSampleApproach.EXTRACTIVE,
            disposition=AnalyzerSampleDisposition.RETURN_TO_PROCESS,
            return_compatibility_confirmed=AnalyzerTriState.NO,
        )


def test_known_interference_contract_rejects_declared_no_with_entries() -> None:
    from app.engineering.design.analyzer_models import (
        AnalyzerInterferenceMechanism,
        AnalyzerKnownInterference,
    )

    with pytest.raises(ValidationError, match="assessment is no"):
        AnalyzerProcessContext(
            known_interferences_assessed=AnalyzerTriState.NO,
            known_interferences=(
                AnalyzerKnownInterference(
                    interference_id="interference.water",
                    component_name="Water",
                    mechanism=AnalyzerInterferenceMechanism.MOISTURE_EFFECT,
                    severity=AnalyzerConditionSeverity.MODERATE,
                    source_reference="Matrix review",
                ),
            ),
        )


def test_hazardous_area_no_rejects_classification_or_confirmed_certification() -> None:
    with pytest.raises(ValidationError, match="classification conflicts"):
        AnalyzerSafetyContext(
            hazardous_area=AnalyzerTriState.NO,
            hazardous_area_classification="Zone basis",
        )
    with pytest.raises(ValidationError, match="certification evidence conflicts"):
        AnalyzerSafetyContext(
            hazardous_area=AnalyzerTriState.NO,
            hazardous_area_equipment_certification_confirmed=AnalyzerTriState.YES,
        )


def test_undeclared_detection_function_rejects_proof_test_claim() -> None:
    with pytest.raises(ValidationError, match="undeclared safety function"):
        AnalyzerSafetyContext(
            gas_detection_safety_function=AnalyzerTriState.NO,
            proof_test_and_bypass_basis_defined=AnalyzerTriState.YES,
        )


def test_application_kind_and_process_phase_remain_separate_for_conditioning() -> None:
    request = AnalyzerApplicationRequest(
        request_id="request.phase-conversion",
        application_kind=AnalyzerApplicationKind.PROCESS_GAS,
        process=AnalyzerProcessContext(sample_phase=AnalyzerSamplePhase.LIQUID),
    )
    assert request.process.sample_phase is AnalyzerSamplePhase.LIQUID


def test_gc_can_screen_a_liquid_process_with_controlled_phase_verification() -> None:
    request = AnalyzerApplicationRequest(
        request_id="request.gc-liquid",
        application_kind=AnalyzerApplicationKind.GAS_CHROMATOGRAPHY,
        process=AnalyzerProcessContext(sample_phase=AnalyzerSamplePhase.LIQUID),
    )
    assert request.process.sample_phase is AnalyzerSamplePhase.LIQUID


def test_gas_detection_rejects_extractive_process_analyzer_arrangement() -> None:
    with pytest.raises(ValidationError, match="point or open-path"):
        AnalyzerApplicationRequest(
            request_id="request.bad-detection",
            application_kind=AnalyzerApplicationKind.GAS_DETECTION,
            sample_system=AnalyzerSampleSystemContext(
                approach=AnalyzerSampleApproach.EXTRACTIVE
            ),
        )


def test_response_contributor_is_traceable_positive_time() -> None:
    contributor = AnalyzerResponseTimeContributor(
        contributor_id="response.sensor",
        kind=AnalyzerResponseContributorKind.ANALYZER_CELL,
        duration=quantity(QuantityKind.TIME, 4.0, "s"),
        basis="Caller-supplied sensor evidence",
        source_reference="Data record",
        confirmed=True,
    )
    assert canonical_analyzer_quantity_value(contributor.duration) == 4.0
    values = contributor.model_dump(mode="python")
    values["duration"] = quantity(QuantityKind.TIME, 0.0, "s")
    with pytest.raises(ValidationError, match="greater than zero"):
        AnalyzerResponseTimeContributor.model_validate(values)


@pytest.mark.parametrize(
    ("score", "band"),
    (
        (0.0, AnalyzerConfidenceBand.VERY_LOW),
        (19.999, AnalyzerConfidenceBand.VERY_LOW),
        (20.0, AnalyzerConfidenceBand.LOW),
        (39.999, AnalyzerConfidenceBand.LOW),
        (40.0, AnalyzerConfidenceBand.MODERATE),
        (59.999, AnalyzerConfidenceBand.MODERATE),
        (60.0, AnalyzerConfidenceBand.HIGH),
        (79.999, AnalyzerConfidenceBand.HIGH),
        (80.0, AnalyzerConfidenceBand.VERY_HIGH),
        (100.0, AnalyzerConfidenceBand.VERY_HIGH),
    ),
)
def test_confidence_band_boundaries(
    score: float,
    band: AnalyzerConfidenceBand,
) -> None:
    assert analyzer_confidence_band(score) is band


def test_rule_missing_link_invariant_is_bidirectional() -> None:
    base = {
        "rule_id": "rule.test",
        "category": FindingCategory.DATA_QUALITY,
        "weight": 10.0,
        "awarded_weight": 0.0,
        "explanation": "Explicit rule evidence.",
        "verification_requirement_ids": ("verify.test",),
        "reference_ids": ("ref.test",),
    }
    with pytest.raises(ValidationError, match="exactly"):
        AnalyzerRuleResult(
            **base,
            status=AnalyzerRuleStatus.MISSING_INFORMATION,
        )
    with pytest.raises(ValidationError, match="exactly"):
        AnalyzerRuleResult(
            **base,
            status=AnalyzerRuleStatus.FAILED,
            missing_field_ids=("field.test",),
        )
    with pytest.raises(ValidationError, match="derived"):
        AnalyzerRuleResult(
            **base,
            status=AnalyzerRuleStatus.PASSED,
        )
    with pytest.raises(ValidationError, match="derived"):
        AnalyzerRuleResult(
            **{**base, "awarded_weight": 10.0},
            status=AnalyzerRuleStatus.CAUTION,
        )


def test_taxonomy_is_complete_unique_generic_and_fail_closed() -> None:
    technologies = tuple(item.technology for item in ANALYZER_TECHNOLOGY_CATALOGUE)
    assert technologies == tuple(
        sorted(AnalyzerTechnology, key=lambda item: item.value)
    )
    assert len(technologies) == len(set(technologies)) == 21
    assert all(item.vendor_neutral for item in ANALYZER_TECHNOLOGY_CATALOGUE)
    assert all(
        not item.manufacturer_model_selected for item in ANALYZER_TECHNOLOGY_CATALOGUE
    )
    assert all(
        not item.final_suitability_claimed for item in ANALYZER_TECHNOLOGY_CATALOGUE
    )
    detection = {
        item.technology
        for item in ANALYZER_TECHNOLOGY_CATALOGUE
        if AnalyzerApplicationKind.GAS_DETECTION in item.supported_application_kinds
    }
    assert {
        AnalyzerTechnology.CATALYTIC_BEAD_GAS_DETECTOR,
        AnalyzerTechnology.ELECTROCHEMICAL_GAS_DETECTOR,
        AnalyzerTechnology.INFRARED_POINT_GAS_DETECTOR,
        AnalyzerTechnology.OPEN_PATH_INFRARED_GAS_DETECTOR,
        AnalyzerTechnology.PHOTOIONIZATION_DETECTOR,
        AnalyzerTechnology.SEMICONDUCTOR_GAS_DETECTOR,
        AnalyzerTechnology.ULTRASONIC_GAS_LEAK_DETECTOR,
    } == detection


def test_assessment_fingerprint_is_sha256_and_tamper_evident() -> None:
    assessment = assess_analyzer_application(complete_liquid_request())
    assert len(assessment.assessment_fingerprint) == 64
    assert assessment.assessment_fingerprint == fingerprint_analyzer_payload(
        assessment.model_dump(
            mode="json",
            round_trip=True,
            warnings="error",
            exclude={"assessment_fingerprint"},
        )
    )
    values = assessment.model_dump(mode="python", round_trip=True)
    values["assessment_fingerprint"] = "0" * 64
    with pytest.raises(ValidationError, match="stale"):
        AnalyzerApplicationAssessment.model_validate(values)


def test_assessment_graph_rejects_dangling_missing_link() -> None:
    assessment = assess_analyzer_application(
        AnalyzerApplicationRequest(request_id="request.minimal")
    )
    values = assessment.model_dump(mode="python", round_trip=True)
    first = values["scenarios"][0]
    first["missing_information_ids"] = (
        *first["missing_information_ids"],
        "missing.unknown",
    )
    with pytest.raises(ValidationError):
        AnalyzerApplicationAssessment.model_validate(values)


def test_assessment_graph_rejects_forged_scenario_score() -> None:
    assessment = assess_analyzer_application(complete_liquid_request())
    values = assessment.model_dump(mode="python", round_trip=True)
    values["scenarios"][0]["suitability_score"] -= 1.0
    with pytest.raises(ValidationError, match="rule-derived"):
        AnalyzerApplicationAssessment.model_validate(values)


def test_assessment_graph_rejects_forged_ranking() -> None:
    assessment = assess_analyzer_application(complete_liquid_request())
    values = assessment.model_dump(mode="python", round_trip=True)
    ranked = [item for item in values["scenarios"] if item["screening_order"]]
    assert len(ranked) >= 2
    ranked[0]["screening_order"], ranked[1]["screening_order"] = (
        ranked[1]["screening_order"],
        ranked[0]["screening_order"],
    )
    values["scenarios"] = sorted(
        values["scenarios"],
        key=lambda item: (
            item["screening_order"] is None,
            item["screening_order"] or 999,
            str(item["technology"]),
        ),
    )
    with pytest.raises(ValidationError, match="score, confidence"):
        AnalyzerApplicationAssessment.model_validate(values)


def test_assessment_serializes_safety_findings_first_and_never_approves() -> None:
    assessment = assess_analyzer_application(complete_liquid_request())
    assert next(iter(assessment.model_dump(mode="json"))) == "safety_findings"
    assert assessment.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert assessment.vendor_neutral is True
    assert assessment.manufacturer_selection_performed is False
    assert assessment.manufacturer_declared_best is False
    assert assessment.model_selection_performed is False
    assert assessment.product_selected is False
    assert assessment.brand_ranked is False
    assert assessment.final_brand_selection == "user_decision_required"
    assert assessment.standards_conformity_claimed is False
    assert assessment.hazardous_area_certification_performed is False
    assert assessment.safety_integrity_claimed is False
    assert assessment.sample_system_approved is False
    assert assessment.alarm_setpoint_selected is False
    assert assessment.detector_placement_or_coverage_approved is False
    assert assessment.final_design_approval_granted is False
    assert assessment.approved_for_project_use is False


def test_recursive_json_schemas_are_closed() -> None:
    schema = AnalyzerApplicationAssessment.model_json_schema()
    object_nodes: list[dict[str, object]] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object":
                object_nodes.append(value)
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(schema)
    assert object_nodes
    assert all(node.get("additionalProperties") is False for node in object_nodes)


def test_assessment_scenarios_are_ranked_densely_and_deterministically() -> None:
    assessment = assess_analyzer_application(complete_liquid_request())
    orders = tuple(
        item.screening_order
        for item in assessment.scenarios
        if item.disposition
        not in {
            AnalyzerScenarioDisposition.BLOCKED,
            AnalyzerScenarioDisposition.NOT_APPLICABLE,
        }
    )
    assert orders == tuple(range(1, len(orders) + 1))
