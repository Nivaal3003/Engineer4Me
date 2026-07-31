"""Contract tests for Step 96 level-application design models."""

from __future__ import annotations

from pydantic import ValidationError
import pytest

from app.engineering.calculations.models import CalculationStatus
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import FindingCategory
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.units import QuantityKind
from app.engineering.design.level_application_models import (
    LevelApplicationAssessment,
)
from app.engineering.design.level_application_models import (
    LevelApplicationRequest,
)
from app.engineering.design.level_application_models import LevelConditionSeverity
from app.engineering.design.level_application_models import LevelConfidenceBand
from app.engineering.design.level_application_models import LevelDpArrangement
from app.engineering.design.level_application_models import (
    LevelEnvironmentCondition,
)
from app.engineering.design.level_application_models import LevelInstallationContext
from app.engineering.design.level_application_models import (
    LevelMeasurementObjective,
)
from app.engineering.design.level_application_models import (
    LevelMeasurementRequirements,
)
from app.engineering.design.level_application_models import (
    LevelMissingInformation,
)
from app.engineering.design.level_application_models import LevelMountingPosition
from app.engineering.design.level_application_models import LevelProcessContext
from app.engineering.design.level_application_models import LevelProcessPhase
from app.engineering.design.level_application_models import (
    LevelProtectionFunction,
)
from app.engineering.design.level_application_models import LevelRuleStatus
from app.engineering.design.level_application_models import LevelSafetyContext
from app.engineering.design.level_application_models import LevelScenarioDisposition
from app.engineering.design.level_application_models import (
    LevelScenarioRuleResult,
)
from app.engineering.design.level_application_models import LevelTechnology
from app.engineering.design.level_application_models import (
    LevelTechnologyScenario,
)
from app.engineering.design.level_application_models import LevelTriState
from app.engineering.design.level_application_models import LevelVerificationPriority
from app.engineering.design.level_application_models import LevelVerificationStep
from app.engineering.design.level_application_models import (
    LevelVesselConfiguration,
)
from app.engineering.design.level_application_models import LevelVesselContext
from app.engineering.design.level_application_models import LevelWizardFinding
from app.engineering.design.level_application_models import (
    SUPPORTED_LEVEL_CALCULATION_METHOD_IDS,
)
from app.engineering.design.level_application_wizard import (
    assess_level_application,
)


def quantity(
    kind: QuantityKind,
    value: float,
    unit: str,
) -> EngineeringQuantity:
    return EngineeringQuantity(
        quantity_kind=kind.value,
        value=value,
        unit=unit,
    )


def length(value: float, unit: str = "m") -> EngineeringQuantity:
    return quantity(QuantityKind.LENGTH, value, unit)


def temperature(value: float, unit: str = "K") -> EngineeringQuantity:
    return quantity(QuantityKind.ABSOLUTE_TEMPERATURE, value, unit)


def pressure(value: float, unit: str = "Pa") -> EngineeringQuantity:
    return quantity(QuantityKind.ABSOLUTE_PRESSURE, value, unit)


def density(value: float, unit: str = "kg/m3") -> EngineeringQuantity:
    return quantity(QuantityKind.DENSITY, value, unit)


def time_quantity(value: float, unit: str = "s") -> EngineeringQuantity:
    return quantity(QuantityKind.TIME, value, unit)


def viscosity(value: float, unit: str = "Pa.s") -> EngineeringQuantity:
    return quantity(QuantityKind.DYNAMIC_VISCOSITY, value, unit)


def test_minimal_request_is_frozen_and_extra_forbid() -> None:
    request = LevelApplicationRequest()

    with pytest.raises(ValidationError):
        LevelApplicationRequest(unknown_field="unsafe")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        request.industry = "chemical"  # type: ignore[misc]


def test_nested_defaults_are_distinct_frozen_instances() -> None:
    first = LevelApplicationRequest()
    second = LevelApplicationRequest()

    assert first.measurement == second.measurement
    assert first.measurement is not second.measurement
    with pytest.raises(ValidationError):
        first.measurement.objectives = ()  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field_name", "bad_quantity"),
    [
        ("measurement_span", time_quantity(1.0)),
        ("required_response_time", length(1.0)),
        ("upper_dead_zone_allowance", pressure(1.0)),
        ("lower_dead_zone_allowance", density(1.0)),
    ],
)
def test_measurement_quantities_require_explicit_kinds(
    field_name: str,
    bad_quantity: EngineeringQuantity,
) -> None:
    with pytest.raises(ValidationError):
        LevelMeasurementRequirements(**{field_name: bad_quantity})


def test_measurement_rejects_unknown_unit_and_nonpositive_span() -> None:
    with pytest.raises(ValidationError):
        LevelMeasurementRequirements(
            measurement_span=quantity(QuantityKind.LENGTH, 1.0, "furlong")
        )
    with pytest.raises(ValidationError):
        LevelMeasurementRequirements(measurement_span=length(0.0))


def test_dead_zone_allowances_must_leave_a_measurable_span() -> None:
    valid = LevelMeasurementRequirements(
        measurement_span=length(1000.0, "mm"),
        upper_dead_zone_allowance=length(0.2),
        lower_dead_zone_allowance=length(0.3),
    )
    assert valid.measurement_span is not None
    with pytest.raises(ValidationError, match="strictly less"):
        LevelMeasurementRequirements(
            measurement_span=length(1.0),
            upper_dead_zone_allowance=length(500.0, "mm"),
            lower_dead_zone_allowance=length(0.5),
        )


def test_measurement_objectives_are_unique_and_canonical() -> None:
    requirements = LevelMeasurementRequirements(
        objectives=[
            LevelMeasurementObjective.INVENTORY,
            LevelMeasurementObjective.CONTINUOUS_LEVEL,
        ]
    )
    assert requirements.objectives == (
        LevelMeasurementObjective.CONTINUOUS_LEVEL,
        LevelMeasurementObjective.INVENTORY,
    )
    with pytest.raises(ValidationError, match="unique"):
        LevelMeasurementRequirements(
            objectives=[
                LevelMeasurementObjective.INVENTORY,
                LevelMeasurementObjective.INVENTORY,
            ]
        )


def test_tuple_fields_reject_unordered_sets() -> None:
    with pytest.raises(ValidationError, match="ordered"):
        LevelMeasurementRequirements(
            objectives={LevelMeasurementObjective.INVENTORY}  # type: ignore[arg-type]
        )


def test_process_temperature_and_pressure_order_is_unit_aware() -> None:
    context = LevelProcessContext(
        minimum_temperature=temperature(273.15),
        normal_temperature=temperature(20.0, "degC"),
        maximum_temperature=temperature(100.0, "degC"),
        normal_absolute_pressure=pressure(1.0, "bar"),
        maximum_absolute_pressure=pressure(200.0, "kPa"),
    )
    assert context.maximum_temperature is not None

    with pytest.raises(ValidationError, match="minimum_temperature"):
        LevelProcessContext(
            minimum_temperature=temperature(50.0, "degC"),
            normal_temperature=temperature(20.0, "degC"),
        )
    with pytest.raises(ValidationError, match="normal_absolute_pressure"):
        LevelProcessContext(
            normal_absolute_pressure=pressure(300.0, "kPa"),
            maximum_absolute_pressure=pressure(2.0, "bar"),
        )


def test_process_rejects_wrong_quantity_kinds() -> None:
    with pytest.raises(ValidationError):
        LevelProcessContext(bulk_density=pressure(1.0))
    with pytest.raises(ValidationError):
        LevelProcessContext(dynamic_viscosity=density(1.0))
    with pytest.raises(ValidationError):
        LevelProcessContext(maximum_temperature=length(1.0))


def test_interface_density_order_is_explicit() -> None:
    valid = LevelProcessContext(
        phase=LevelProcessPhase.LIQUID_LIQUID_INTERFACE,
        lower_fluid_density=density(1000.0),
        upper_fluid_density=density(800.0),
    )
    assert valid.lower_fluid_density is not None
    with pytest.raises(ValidationError, match="must exceed"):
        LevelProcessContext(
            lower_fluid_density=density(700.0),
            upper_fluid_density=density(800.0),
        )


def test_process_condition_defaults_remain_unknown() -> None:
    process = LevelProcessContext()
    assert process.foam is LevelConditionSeverity.UNKNOWN
    assert process.turbulence is LevelConditionSeverity.UNKNOWN
    assert process.hygienic_service is LevelConditionSeverity.UNKNOWN


def test_vessel_dimensions_and_elevation_order() -> None:
    vessel = LevelVesselContext(
        internal_diameter=length(2.0),
        lower_level_elevation=length(0.5),
        upper_level_elevation=length(4.0),
    )
    assert vessel.internal_diameter is not None
    with pytest.raises(ValidationError, match="below"):
        LevelVesselContext(
            lower_level_elevation=length(2.0),
            upper_level_elevation=length(1.0),
        )
    with pytest.raises(ValidationError, match="greater than zero"):
        LevelVesselContext(internal_diameter=length(0.0))


def test_vessel_rejects_conflicting_open_dp_arrangement() -> None:
    with pytest.raises(ValidationError, match="conflicts"):
        LevelVesselContext(
            configuration=LevelVesselConfiguration.PRESSURIZED,
            dp_arrangement=LevelDpArrangement.OPEN_VESSEL,
        )


@pytest.mark.parametrize(
    ("configuration", "arrangement"),
    [
        (
            LevelVesselConfiguration.OPEN,
            LevelDpArrangement.CLOSED_WET_LEG,
        ),
        (
            LevelVesselConfiguration.OPEN,
            LevelDpArrangement.CLOSED_DRY_LEG,
        ),
        (
            LevelVesselConfiguration.OPEN_CHANNEL_OR_SUMP,
            LevelDpArrangement.REMOTE_SEALS,
        ),
    ],
)
def test_open_vessels_reject_closed_or_remote_dp_arrangements(
    configuration: LevelVesselConfiguration,
    arrangement: LevelDpArrangement,
) -> None:
    with pytest.raises(ValidationError, match="conflicts"):
        LevelVesselContext(
            configuration=configuration,
            dp_arrangement=arrangement,
        )


@pytest.mark.parametrize(
    "payload",
    [
        {
            "available_mounting_positions": (LevelMountingPosition.TOP,),
            "top_mounting_available": LevelTriState.NO,
        },
        {
            "available_mounting_positions": (),
            "top_mounting_available": LevelTriState.YES,
        },
        {
            "available_mounting_positions": (LevelMountingPosition.SIDE,),
            "side_connection_available": LevelTriState.NO,
        },
        {
            "available_mounting_positions": (),
            "side_connection_available": LevelTriState.YES,
        },
    ],
)
def test_mounting_flags_and_position_list_cannot_conflict(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="conflicts"):
        LevelVesselContext(**payload)


def test_request_rejects_pressurized_vapor_in_open_vessel() -> None:
    with pytest.raises(ValidationError, match="Pressurized vapor-space"):
        LevelApplicationRequest(
            process=LevelProcessContext(
                vapor_space_behavior="pressurized",
            ),
            vessel=LevelVesselContext(
                configuration=LevelVesselConfiguration.OPEN,
            ),
        )


def test_measurement_span_cannot_exceed_elevation_range() -> None:
    with pytest.raises(ValidationError, match="cannot exceed"):
        LevelApplicationRequest(
            measurement=LevelMeasurementRequirements(
                measurement_span=length(5.0),
            ),
            vessel=LevelVesselContext(
                lower_level_elevation=length(1.0),
                upper_level_elevation=length(4.0),
            ),
        )


def test_mounting_positions_are_unique_and_sorted() -> None:
    vessel = LevelVesselContext(
        available_mounting_positions=[
            LevelMountingPosition.TOP,
            LevelMountingPosition.SIDE,
        ]
    )
    assert vessel.available_mounting_positions == (
        LevelMountingPosition.SIDE,
        LevelMountingPosition.TOP,
    )
    with pytest.raises(ValidationError, match="unique"):
        LevelVesselContext(
            available_mounting_positions=[
                LevelMountingPosition.TOP,
                LevelMountingPosition.TOP,
            ]
        )


def test_installation_environment_is_canonical_and_ambient_is_ordered() -> None:
    installation = LevelInstallationContext(
        environments=[
            LevelEnvironmentCondition.OUTDOOR,
            LevelEnvironmentCondition.HIGH_VIBRATION,
        ],
        minimum_ambient_temperature=temperature(-20.0, "degC"),
        maximum_ambient_temperature=temperature(60.0, "degC"),
    )
    assert installation.environments == (
        LevelEnvironmentCondition.HIGH_VIBRATION,
        LevelEnvironmentCondition.OUTDOOR,
    )
    with pytest.raises(ValidationError, match="minimum_ambient"):
        LevelInstallationContext(
            minimum_ambient_temperature=temperature(60.0, "degC"),
            maximum_ambient_temperature=temperature(20.0, "degC"),
        )


def test_safety_contradictions_are_rejected() -> None:
    with pytest.raises(ValidationError, match="conflict"):
        LevelSafetyContext(
            hazardous_area=LevelTriState.NO,
            hazardous_area_classification="Zone 1",
        )
    with pytest.raises(ValidationError, match="conflict"):
        LevelSafetyContext(
            independent_protection_required=LevelTriState.NO,
            independent_protection_functions=(
                LevelProtectionFunction.HIGH_HIGH_TRIP,
            ),
        )
    with pytest.raises(ValidationError, match="cannot authorise"):
        LevelSafetyContext(
            radiometric_source_permitted=LevelTriState.NO,
            radiation_protection_program_confirmed=LevelTriState.YES,
        )
    with pytest.raises(ValidationError, match="unless it is yes"):
        LevelSafetyContext(
            independent_protection_functions=(
                LevelProtectionFunction.HIGH_HIGH_TRIP,
            ),
        )


def test_safety_collections_are_unique_and_canonical() -> None:
    safety = LevelSafetyContext(
        hazardous_area=LevelTriState.YES,
        required_approvals=["IECEx", "ATEX"],
        independent_protection_required=LevelTriState.YES,
        independent_protection_functions=[
            LevelProtectionFunction.OVERFILL_PREVENTION,
            LevelProtectionFunction.HIGH_HIGH_TRIP,
        ],
    )
    assert safety.required_approvals == ("ATEX", "IECEx")
    with pytest.raises(ValidationError, match="unique"):
        LevelSafetyContext(
            hazardous_area=LevelTriState.YES,
            required_approvals=["ATEX", "atex"],
        )


@pytest.mark.parametrize("field_name", ["safety_critical", "independent", "blocking"])
def test_boolean_evidence_fields_are_strict(field_name: str) -> None:
    payloads = {
        "safety_critical": dict(field_id="field.test", reason="Reason", safety_critical=1),
        "independent": dict(
            verification_id="verify.test",
            priority=LevelVerificationPriority.IMPORTANT,
            description="Description",
            acceptance_criteria="Accepted evidence",
            required_competency="Engineer",
            independent=1,
        ),
        "blocking": dict(
            finding_id="finding.test",
            category=FindingCategory.SAFETY,
            severity=FindingSeverity.WARNING,
            title="Title",
            message="Message",
            blocking=1,
        ),
    }
    model_types = {
        "safety_critical": LevelMissingInformation,
        "independent": LevelVerificationStep,
        "blocking": LevelWizardFinding,
    }
    with pytest.raises(ValidationError):
        model_types[field_name](**payloads[field_name])


def test_request_accepts_only_step95_level_method_links() -> None:
    request = LevelApplicationRequest(
        supporting_calculation_method_ids=list(
            reversed(SUPPORTED_LEVEL_CALCULATION_METHOD_IDS)
        )
    )
    assert request.supporting_calculation_method_ids == tuple(
        sorted(SUPPORTED_LEVEL_CALCULATION_METHOD_IDS)
    )
    with pytest.raises(ValidationError, match="Step 95"):
        LevelApplicationRequest(
            supporting_calculation_method_ids=("general.geometry.circle-area",)
        )


def test_finding_severity_and_blocking_invariants() -> None:
    base = dict(
        finding_id="finding.test",
        category=FindingCategory.SAFETY,
        title="Title",
        message="Message",
        affected_technologies=(LevelTechnology.NON_CONTACT_RADAR,),
        reference_ids=("ref.test",),
    )
    with pytest.raises(ValidationError, match="must be blocking"):
        LevelWizardFinding(
            **base,
            severity=FindingSeverity.CRITICAL,
            blocking=False,
            verification_requirement_ids=("verify.test",),
        )
    with pytest.raises(ValidationError, match="warning, error, or critical"):
        LevelWizardFinding(
            **base,
            severity=FindingSeverity.CAUTION,
            blocking=True,
            required_action="Act",
            verification_requirement_ids=("verify.test",),
        )
    with pytest.raises(ValidationError, match="required_action"):
        LevelWizardFinding(
            **base,
            severity=FindingSeverity.WARNING,
            blocking=True,
            verification_requirement_ids=("verify.test",),
        )


def rule(**updates: object) -> LevelScenarioRuleResult:
    payload: dict[str, object] = {
        "rule_id": "rule.test",
        "status": LevelRuleStatus.PASSED,
        "category": FindingCategory.APPLICABILITY,
        "weight": 10.0,
        "awarded_weight": 10.0,
        "explanation": "Explanation",
        "verification_requirement_ids": ("verify.test",),
        "reference_ids": ("ref.test",),
    }
    payload.update(updates)
    return LevelScenarioRuleResult(**payload)


def test_rule_result_requires_coherent_weights_and_missing_links() -> None:
    with pytest.raises(ValidationError, match="cannot exceed"):
        rule(awarded_weight=11.0)
    with pytest.raises(ValidationError, match="requires missing_field_ids"):
        rule(
            status=LevelRuleStatus.MISSING_INFORMATION,
            awarded_weight=0.0,
        )
    with pytest.raises(ValidationError, match="only valid"):
        rule(missing_field_ids=("field.test",))
    with pytest.raises(ValidationError, match="cannot award"):
        rule(status=LevelRuleStatus.FAILED, awarded_weight=1.0)


def test_verification_requires_concrete_expected_evidence() -> None:
    with pytest.raises(ValidationError):
        LevelVerificationStep(
            verification_id="verify.test",
            priority=LevelVerificationPriority.IMPORTANT,
            description="Description",
            acceptance_criteria="Acceptance criteria",
            required_competency="Engineer",
            evidence_required=(),
        )


def scenario(**updates: object) -> LevelTechnologyScenario:
    payload: dict[str, object] = {
        "scenario_id": "scenario.test",
        "technology": LevelTechnology.NON_CONTACT_RADAR,
        "title": "Test scenario",
        "summary": "Summary",
        "disposition": LevelScenarioDisposition.PREFERRED,
        "rank": 1,
        "suitability_score": 90.0,
        "confidence_score": 70.0,
        "confidence_band": LevelConfidenceBand.HIGH,
        "confidence_rationale": "Rationale",
        "ranking_rationale": "Exact score and disposition ties share a dense rank.",
        "rule_results": (rule(),),
        "reasons": ("Reason",),
        "limitations": ("Limitation",),
        "observations": ("Observation",),
        "assumptions": ("Assumption",),
        "escalation_conditions": ("Escalation",),
        "verification_requirement_ids": ("verify.test",),
        "reference_ids": ("ref.test",),
    }
    payload.update(updates)
    return LevelTechnologyScenario(**payload)


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (0.0, LevelConfidenceBand.VERY_LOW),
        (20.0, LevelConfidenceBand.LOW),
        (40.0, LevelConfidenceBand.MODERATE),
        (60.0, LevelConfidenceBand.HIGH),
        (80.0, LevelConfidenceBand.VERY_HIGH),
    ],
)
def test_scenario_confidence_band_boundaries(
    score: float,
    band: LevelConfidenceBand,
) -> None:
    assert scenario(confidence_score=score, confidence_band=band)


def test_scenario_rejects_mismatched_confidence_band() -> None:
    with pytest.raises(ValidationError, match="confidence_band"):
        scenario(confidence_score=10.0, confidence_band=LevelConfidenceBand.HIGH)


@pytest.mark.parametrize(
    "field_name",
    [
        "observations",
        "assumptions",
        "escalation_conditions",
        "verification_requirement_ids",
        "reference_ids",
    ],
)
def test_scenario_requires_e4m_calc_063_evidence(field_name: str) -> None:
    with pytest.raises(ValidationError):
        scenario(**{field_name: ()})


def test_blocked_and_not_applicable_scenarios_are_unranked() -> None:
    blocked = scenario(
        disposition=LevelScenarioDisposition.BLOCKED,
        rank=None,
        suitability_score=0.0,
        rule_results=(
            rule(
                status=LevelRuleStatus.BLOCKED,
                awarded_weight=0.0,
            ),
        ),
    )
    assert blocked.rank is None
    with pytest.raises(ValidationError, match="cannot be ranked"):
        scenario(
            disposition=LevelScenarioDisposition.NOT_APPLICABLE,
            rank=1,
            suitability_score=0.0,
        )
    with pytest.raises(ValidationError, match="zero suitability"):
        scenario(
            disposition=LevelScenarioDisposition.BLOCKED,
            rank=None,
            suitability_score=1.0,
        )


@pytest.mark.parametrize(
    "updates",
    [
        {
            "disposition": LevelScenarioDisposition.PREFERRED,
            "suitability_score": 70.0,
        },
        {
            "disposition": LevelScenarioDisposition.PLAUSIBLE,
            "suitability_score": 80.0,
        },
        {
            "disposition": LevelScenarioDisposition.CONDITIONAL,
            "suitability_score": 60.0,
        },
        {
            "disposition": LevelScenarioDisposition.INSUFFICIENT_INFORMATION,
        },
    ],
)
def test_scenario_disposition_is_structurally_coherent(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        scenario(**updates)


def test_assessment_model_revalidates_full_evidence_graph() -> None:
    result = assess_level_application(LevelApplicationRequest())
    copied = LevelApplicationAssessment.model_validate(
        result.model_dump(mode="python", round_trip=True)
    )
    assert copied == result

    payload = result.model_dump(mode="python", round_trip=True)
    payload["scenarios"][0]["reference_ids"] = ("ref.does-not-exist",)
    with pytest.raises(ValidationError, match="links must resolve"):
        LevelApplicationAssessment.model_validate(payload)


def test_assessment_rejects_dangling_rule_graph_links() -> None:
    result = assess_level_application(LevelApplicationRequest())
    payload = result.model_dump(mode="python", round_trip=True)
    payload["scenarios"][0]["rule_results"][0][
        "verification_requirement_ids"
    ] = ("verify.does-not-exist",)
    with pytest.raises(ValidationError, match="links must resolve"):
        LevelApplicationAssessment.model_validate(payload)


def test_assessment_rejects_orphan_reference_and_verification_nodes() -> None:
    result = assess_level_application(LevelApplicationRequest())

    payload = result.model_dump(mode="python", round_trip=True)
    orphan_reference = dict(payload["references"][0])
    orphan_reference["reference_id"] = "ref.orphan"
    payload["references"] = (*payload["references"], orphan_reference)
    with pytest.raises(ValidationError, match="cannot be orphaned"):
        LevelApplicationAssessment.model_validate(payload)

    payload = result.model_dump(mode="python", round_trip=True)
    orphan_verification = dict(payload["verification_steps"][0])
    orphan_verification["verification_id"] = "verify.orphan"
    payload["verification_steps"] = (
        *payload["verification_steps"],
        orphan_verification,
    )
    with pytest.raises(ValidationError, match="cannot be orphaned"):
        LevelApplicationAssessment.model_validate(payload)


def test_assessment_rejects_affected_technology_mismatch() -> None:
    result = assess_level_application(LevelApplicationRequest())
    payload = result.model_dump(mode="python", round_trip=True)
    payload["missing_information"][0]["affected_technologies"] = (
        LevelTechnology.NON_CONTACT_RADAR,
    )
    with pytest.raises(ValidationError, match="affected_technologies"):
        LevelApplicationAssessment.model_validate(payload)


def test_assessment_status_is_bidirectionally_coherent() -> None:
    result = assess_level_application(LevelApplicationRequest())
    payload = result.model_dump(mode="python", round_trip=True)
    payload["status"] = CalculationStatus.BLOCKED
    with pytest.raises(ValidationError, match="requires a blocking"):
        LevelApplicationAssessment.model_validate(payload)

    payload = result.model_dump(mode="python", round_trip=True)
    payload["missing_information"] = ()
    payload["status"] = CalculationStatus.COMPLETED_WITH_WARNINGS
    for scenario_payload in payload["scenarios"]:
        scenario_payload["missing_information_ids"] = ()
        scenario_payload["disposition"] = LevelScenarioDisposition.CONDITIONAL
        for rule_payload in scenario_payload["rule_results"]:
            if rule_payload["status"] is LevelRuleStatus.MISSING_INFORMATION:
                rule_payload["status"] = LevelRuleStatus.FAILED
                rule_payload["missing_field_ids"] = ()
    with pytest.raises(ValidationError, match="Assessment status"):
        LevelApplicationAssessment.model_validate(payload)


def test_all_public_models_expose_closed_json_schemas() -> None:
    model_types = (
        LevelApplicationRequest,
        LevelMeasurementRequirements,
        LevelProcessContext,
        LevelVesselContext,
        LevelInstallationContext,
        LevelSafetyContext,
        LevelMissingInformation,
        LevelVerificationStep,
        LevelWizardFinding,
        LevelScenarioRuleResult,
        LevelTechnologyScenario,
        LevelApplicationAssessment,
    )
    for model_type in model_types:
        assert model_type.model_json_schema()["additionalProperties"] is False
