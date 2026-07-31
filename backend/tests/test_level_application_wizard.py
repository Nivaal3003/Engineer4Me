"""Independent behavior tests for the Step 96 level application wizard."""

from __future__ import annotations

import ast
from pathlib import Path

from pydantic import ValidationError
import pytest

from app.engineering.calculations.models import CalculationStatus
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.units import QuantityKind
from app.engineering.design.level_application_models import (
    LevelApplicationRequest,
)
from app.engineering.design.level_application_models import LevelConditionSeverity
from app.engineering.design.level_application_models import LevelContactPreference
from app.engineering.design.level_application_models import LevelDpArrangement
from app.engineering.design.level_application_models import (
    LevelEnvironmentCondition,
)
from app.engineering.design.level_application_models import LevelIndustrySector
from app.engineering.design.level_application_models import LevelInstallationContext
from app.engineering.design.level_application_models import LevelMaintenanceAccess
from app.engineering.design.level_application_models import (
    LevelMeasurementObjective,
)
from app.engineering.design.level_application_models import (
    LevelMeasurementRequirements,
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
from app.engineering.design.level_application_models import LevelTechnology
from app.engineering.design.level_application_models import LevelTriState
from app.engineering.design.level_application_models import LevelVaporBehavior
from app.engineering.design.level_application_models import (
    LevelVesselConfiguration,
)
from app.engineering.design.level_application_models import LevelVesselContext
from app.engineering.design.level_application_models import LevelVesselGeometry
from app.engineering.design.level_application_models import (
    SUPPORTED_LEVEL_CALCULATION_METHOD_IDS,
)
from app.engineering.design.level_application_wizard import (
    DEFAULT_LEVEL_APPLICATION_WIZARD,
)
from app.engineering.design.level_application_wizard import (
    LEVEL_APPLICATION_RULESET_VERSION,
)
from app.engineering.design.level_application_wizard import (
    LEVEL_APPLICATION_WIZARD_VERSION,
)
from app.engineering.design.level_application_wizard import (
    LevelApplicationWizard,
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


def temperature(value: float, unit: str = "degC") -> EngineeringQuantity:
    return quantity(QuantityKind.ABSOLUTE_TEMPERATURE, value, unit)


def pressure(value: float, unit: str = "kPa") -> EngineeringQuantity:
    return quantity(QuantityKind.ABSOLUTE_PRESSURE, value, unit)


def density(value: float, unit: str = "kg/m3") -> EngineeringQuantity:
    return quantity(QuantityKind.DENSITY, value, unit)


def time_quantity(value: float, unit: str = "s") -> EngineeringQuantity:
    return quantity(QuantityKind.TIME, value, unit)


def viscosity(value: float, unit: str = "mPa.s") -> EngineeringQuantity:
    return quantity(QuantityKind.DYNAMIC_VISCOSITY, value, unit)


def complete_request(**updates: object) -> LevelApplicationRequest:
    request = LevelApplicationRequest(
        industry=LevelIndustrySector.CHEMICAL,
        industry_detail="Batch liquid storage",
        measurement=LevelMeasurementRequirements(
            objectives=(LevelMeasurementObjective.CONTINUOUS_LEVEL,),
            measurement_span=length(5.0),
            upper_dead_zone_allowance=length(0.2),
            lower_dead_zone_allowance=length(0.1),
            required_accuracy_percent_of_span=1.0,
            required_response_time=time_quantity(2.0),
            contact_preference=LevelContactPreference.CONTACT_ACCEPTABLE,
            continuous_output_required=LevelTriState.YES,
            local_indication_required=LevelTriState.NO,
        ),
        process=LevelProcessContext(
            phase=LevelProcessPhase.LIQUID,
            medium_description="Stable process liquid",
            vapor_space_composition="Air and process vapor",
            vapor_space_behavior=LevelVaporBehavior.STABLE,
            minimum_temperature=temperature(0.0),
            normal_temperature=temperature(25.0),
            maximum_temperature=temperature(80.0),
            normal_absolute_pressure=pressure(110.0),
            maximum_absolute_pressure=pressure(500.0),
            bulk_density=density(900.0),
            lower_fluid_density=density(1000.0),
            upper_fluid_density=density(800.0),
            density_variation_percent=2.0,
            dielectric_constant=4.0,
            dynamic_viscosity=viscosity(5.0),
            foam=LevelConditionSeverity.NONE,
            turbulence=LevelConditionSeverity.NONE,
            steam=LevelConditionSeverity.NONE,
            condensation=LevelConditionSeverity.NONE,
            dust=LevelConditionSeverity.NONE,
            buildup=LevelConditionSeverity.NONE,
            slurry=LevelConditionSeverity.NONE,
            sticky_material=LevelConditionSeverity.NONE,
            agitation=LevelConditionSeverity.NONE,
            corrosive_service=LevelConditionSeverity.NONE,
            abrasive_service=LevelConditionSeverity.NONE,
            hygienic_service=LevelConditionSeverity.NONE,
        ),
        vessel=LevelVesselContext(
            configuration=LevelVesselConfiguration.CLOSED,
            geometry=LevelVesselGeometry.VERTICAL_CYLINDER,
            dp_arrangement=LevelDpArrangement.REMOTE_SEALS,
            internal_diameter=length(3.0),
            straight_side_height=length(6.0),
            cylindrical_length=length(6.0),
            lower_level_elevation=length(0.5),
            upper_level_elevation=length(5.5),
            nozzle_diameter=length(0.15),
            nozzle_height=length(0.3),
            nozzle_geometry_confirmed=LevelTriState.YES,
            available_mounting_positions=(
                LevelMountingPosition.TOP,
                LevelMountingPosition.SIDE,
                LevelMountingPosition.EXTERNAL_CHAMBER,
                LevelMountingPosition.NON_INTRUSIVE_EXTERNAL,
            ),
            mounting_constraints="Clear top and side access is available.",
            top_mounting_available=LevelTriState.YES,
            side_connection_available=LevelTriState.YES,
            internal_obstructions=LevelConditionSeverity.NONE,
        ),
        installation=LevelInstallationContext(
            environments=(LevelEnvironmentCondition.OUTDOOR,),
            maintenance_access=LevelMaintenanceAccess.EASY,
            minimum_ambient_temperature=temperature(-20.0),
            maximum_ambient_temperature=temperature(50.0),
            electrical_power_available=LevelTriState.YES,
            instrument_air_available=LevelTriState.NO,
        ),
        safety=LevelSafetyContext(
            hazardous_area=LevelTriState.NO,
            independent_protection_required=LevelTriState.NO,
            radiometric_source_permitted=LevelTriState.YES,
            radiation_protection_program_confirmed=LevelTriState.YES,
            flammable_material=LevelTriState.NO,
            toxic_material=LevelTriState.NO,
        ),
        application_notes="Screening fixture with explicit multidisciplinary inputs.",
    )
    return request.model_copy(update=updates) if updates else request


def scenario_for(result: object, technology: LevelTechnology):
    return next(
        item
        for item in result.scenarios  # type: ignore[attr-defined]
        if item.technology is technology
    )


def rule_for(scenario: object, rule_id: str):
    return next(
        item
        for item in scenario.rule_results  # type: ignore[attr-defined]
        if item.rule_id == rule_id
    )


def update_process(
    request: LevelApplicationRequest,
    **updates: object,
) -> LevelApplicationRequest:
    return request.model_copy(
        update={"process": request.process.model_copy(update=updates)}
    )


def update_measurement(
    request: LevelApplicationRequest,
    **updates: object,
) -> LevelApplicationRequest:
    return request.model_copy(
        update={"measurement": request.measurement.model_copy(update=updates)}
    )


def update_vessel(
    request: LevelApplicationRequest,
    **updates: object,
) -> LevelApplicationRequest:
    return request.model_copy(
        update={"vessel": request.vessel.model_copy(update=updates)}
    )


def update_safety(
    request: LevelApplicationRequest,
    **updates: object,
) -> LevelApplicationRequest:
    return request.model_copy(
        update={"safety": request.safety.model_copy(update=updates)}
    )


def test_versions_and_singleton_are_frozen() -> None:
    assert LEVEL_APPLICATION_WIZARD_VERSION == "1.0.0"
    assert LEVEL_APPLICATION_RULESET_VERSION == "1.0.0"
    assert DEFAULT_LEVEL_APPLICATION_WIZARD.version == "1.0.0"
    assert DEFAULT_LEVEL_APPLICATION_WIZARD.ruleset_version == "1.0.0"
    with pytest.raises(AttributeError, match="immutable"):
        DEFAULT_LEVEL_APPLICATION_WIZARD.version = "2.0.0"  # type: ignore[misc]
    with pytest.raises(AttributeError, match="immutable"):
        del DEFAULT_LEVEL_APPLICATION_WIZARD._locked  # type: ignore[attr-defined]


def test_wizard_rejects_untyped_input() -> None:
    with pytest.raises(TypeError, match="LevelApplicationRequest"):
        LevelApplicationWizard().assess({})  # type: ignore[arg-type]


def test_minimal_request_is_explicitly_insufficient_with_zero_confidence() -> None:
    result = assess_level_application(LevelApplicationRequest())
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert result.missing_information
    assert len(result.scenarios) == len(LevelTechnology) == 12
    assert all(item.confidence_score == 0.0 for item in result.scenarios)
    assert any(
        item.field_id == "safety.hazardous_area"
        and item.safety_critical
        for item in result.missing_information
    )
    assert {item.rank for item in result.scenarios} == {1}


def test_complete_request_has_viable_scenarios_without_missing_information() -> None:
    result = assess_level_application(complete_request())
    assert result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert result.missing_information == ()
    assert any(
        item.disposition
        in (
            LevelScenarioDisposition.PREFERRED,
            LevelScenarioDisposition.PLAUSIBLE,
        )
        for item in result.scenarios
    )


def test_repeated_assessment_is_byte_and_fingerprint_stable() -> None:
    request = complete_request()
    first = assess_level_application(request)
    second = assess_level_application(request)
    assert first.model_dump_json() == second.model_dump_json()
    assert first.assessment_fingerprint == second.assessment_fingerprint


def test_set_like_input_permutations_have_same_fingerprint() -> None:
    first = complete_request(
        supporting_calculation_method_ids=(
            "level.tank.vertical-cylinder",
            "level.hydrostatic.column-pressure",
        )
    )
    second = complete_request(
        supporting_calculation_method_ids=(
            "level.hydrostatic.column-pressure",
            "level.tank.vertical-cylinder",
        )
    )
    assert assess_level_application(first).assessment_fingerprint == (
        assess_level_application(second).assessment_fingerprint
    )


def test_material_input_change_changes_fingerprint() -> None:
    first = complete_request()
    second = update_process(first, foam=LevelConditionSeverity.HIGH)
    assert assess_level_application(first).assessment_fingerprint != (
        assess_level_application(second).assessment_fingerprint
    )


def test_scenarios_have_deterministic_unique_contiguous_ranks() -> None:
    result = assess_level_application(complete_request())
    ranked = [item.rank for item in result.scenarios if item.rank is not None]
    unique_ranks = sorted(set(ranked))
    assert unique_ranks == list(range(1, len(unique_ranks) + 1))
    assert len({item.scenario_id for item in result.scenarios}) == 12
    assert len({item.technology for item in result.scenarios}) == 12


def test_every_scenario_meets_e4m_calc_060_through_063_contract() -> None:
    result = assess_level_application(complete_request())
    contract_refs = {
        "ref.e4m-calc-060",
        "ref.e4m-calc-061",
        "ref.e4m-calc-062",
        "ref.e4m-calc-063",
    }
    for scenario in result.scenarios:
        assert scenario.title
        assert scenario.summary
        assert scenario.observations
        assert scenario.assumptions
        assert scenario.escalation_conditions
        assert scenario.verification_requirement_ids
        assert contract_refs.issubset(scenario.reference_ids)
        assert scenario.confidence_score < 100.0


def test_all_evidence_graph_links_resolve() -> None:
    result = assess_level_application(complete_request())
    references = {item.reference_id for item in result.references}
    verifications = {
        item.verification_id for item in result.verification_steps
    }
    for scenario in result.scenarios:
        assert set(scenario.reference_ids) <= references
        assert set(scenario.verification_requirement_ids) <= verifications
        for rule in scenario.rule_results:
            assert set(rule.reference_ids) <= references
            assert set(rule.verification_requirement_ids) <= verifications
    assert all(item.acceptance_criteria for item in result.verification_steps)


def test_hazardous_area_without_classification_blocks_every_scenario() -> None:
    request = update_safety(
        complete_request(),
        hazardous_area=LevelTriState.YES,
        hazardous_area_classification=None,
        required_approvals=("IECEx",),
    )
    result = assess_level_application(request)
    assert result.status is CalculationStatus.BLOCKED
    finding = next(
        item
        for item in result.safety_findings
        if item.finding_id == "finding.hazardous-area-classification"
    )
    assert finding.severity is FindingSeverity.CRITICAL
    assert finding.blocking
    assert all(
        item.disposition is LevelScenarioDisposition.BLOCKED
        for item in result.scenarios
    )


def test_hazardous_area_with_classification_but_no_approvals_is_insufficient() -> None:
    request = update_safety(
        complete_request(),
        hazardous_area=LevelTriState.YES,
        hazardous_area_classification="Zone 1, IIB, T4",
        required_approvals=(),
    )
    result = assess_level_application(request)
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    assert any(
        item.field_id == "safety.required_approvals"
        and item.safety_critical
        for item in result.missing_information
    )


def test_independent_protection_without_functions_blocks() -> None:
    request = update_safety(
        complete_request(),
        independent_protection_required=LevelTriState.YES,
        independent_protection_functions=(),
    )
    result = assess_level_application(request)
    assert result.status is CalculationStatus.BLOCKED
    assert any(
        item.finding_id == "finding.independent-protection-undefined"
        and item.blocking
        for item in result.safety_findings
    )


def test_defined_independent_protection_stays_warning_not_proof() -> None:
    request = update_safety(
        complete_request(),
        independent_protection_required=LevelTriState.YES,
        independent_protection_functions=(
            LevelProtectionFunction.HIGH_HIGH_TRIP,
        ),
    )
    result = assess_level_application(request)
    assert result.status is not CalculationStatus.BLOCKED
    finding = next(
        item
        for item in result.safety_findings
        if item.finding_id == "finding.independent-protection-review"
    )
    assert finding.severity is FindingSeverity.WARNING
    assert not finding.blocking


@pytest.mark.parametrize(
    "protection_function",
    [
        LevelProtectionFunction.HIGH_HIGH_TRIP,
        LevelProtectionFunction.LOW_LOW_TRIP,
        LevelProtectionFunction.OVERFILL_PREVENTION,
        LevelProtectionFunction.DRY_RUN_PROTECTION,
    ],
)
def test_independent_point_layer_remains_a_viable_parallel_scenario(
    protection_function: LevelProtectionFunction,
) -> None:
    request = update_safety(
        complete_request(),
        independent_protection_required=LevelTriState.YES,
        independent_protection_functions=(protection_function,),
    )
    result = assess_level_application(request)
    fork = scenario_for(result, LevelTechnology.VIBRATING_FORK)
    radar = scenario_for(result, LevelTechnology.NON_CONTACT_RADAR)
    assert fork.disposition in (
        LevelScenarioDisposition.PREFERRED,
        LevelScenarioDisposition.PLAUSIBLE,
        LevelScenarioDisposition.CONDITIONAL,
    )
    assert radar.disposition in (
        LevelScenarioDisposition.PREFERRED,
        LevelScenarioDisposition.PLAUSIBLE,
    )
    assert "verify.independent-protection" in (
        fork.verification_requirement_ids
    )
    expected_path = (
        "verify.high-level-protection-path"
        if protection_function
        in {
            LevelProtectionFunction.HIGH_HIGH_TRIP,
            LevelProtectionFunction.OVERFILL_PREVENTION,
        }
        else "verify.low-level-protection-path"
    )
    assert expected_path in fork.verification_requirement_ids
    assert any(
        "separate protection-layer" in observation.lower()
        for observation in fork.observations
    )
    assert any(
        protection_function.value in observation
        for observation in fork.observations
    )


def test_multiple_protection_functions_preserve_both_acceptance_paths() -> None:
    request = update_safety(
        complete_request(),
        independent_protection_required=LevelTriState.YES,
        independent_protection_functions=(
            LevelProtectionFunction.HIGH_HIGH_TRIP,
            LevelProtectionFunction.LOW_LOW_TRIP,
        ),
    )
    fork = scenario_for(
        assess_level_application(request),
        LevelTechnology.VIBRATING_FORK,
    )
    assert {
        "verify.high-level-protection-path",
        "verify.low-level-protection-path",
    } <= set(fork.verification_requirement_ids)
    assert any("high-level protection path" in item for item in fork.escalation_conditions)
    assert any("low-level protection path" in item for item in fork.escalation_conditions)


def test_protection_function_identity_changes_assessment_evidence() -> None:
    results = []
    for function in (
        LevelProtectionFunction.HIGH_HIGH_TRIP,
        LevelProtectionFunction.LOW_LOW_TRIP,
    ):
        request = update_safety(
            complete_request(),
            independent_protection_required=LevelTriState.YES,
            independent_protection_functions=(function,),
        )
        payload = assess_level_application(request).model_dump(mode="json")
        payload.pop("request")
        payload.pop("assessment_fingerprint")
        results.append(payload)
    assert results[0] != results[1]


def test_mixed_continuous_and_high_alarm_keeps_point_layer_visible() -> None:
    request = update_measurement(
        complete_request(),
        objectives=(
            LevelMeasurementObjective.CONTINUOUS_LEVEL,
            LevelMeasurementObjective.HIGH_LEVEL_ALARM,
        ),
    )
    result = assess_level_application(request)
    fork = scenario_for(result, LevelTechnology.VIBRATING_FORK)
    assert fork.disposition is not LevelScenarioDisposition.NOT_APPLICABLE
    assert "separate alarm" in rule_for(
        fork,
        "common.measurement-objective",
    ).explanation.lower()


def test_interface_and_independent_trip_keep_parallel_point_layer() -> None:
    request = update_process(
        complete_request(),
        phase=LevelProcessPhase.LIQUID_LIQUID_INTERFACE,
    )
    request = update_measurement(
        request,
        objectives=(LevelMeasurementObjective.INTERFACE_LEVEL,),
    )
    request = update_safety(
        request,
        independent_protection_required=LevelTriState.YES,
        independent_protection_functions=(
            LevelProtectionFunction.HIGH_HIGH_TRIP,
        ),
    )
    result = assess_level_application(request)
    fork = scenario_for(result, LevelTechnology.VIBRATING_FORK)
    assert fork.disposition in (
        LevelScenarioDisposition.PREFERRED,
        LevelScenarioDisposition.PLAUSIBLE,
        LevelScenarioDisposition.CONDITIONAL,
    )
    assert rule_for(
        fork,
        "common.process-phase",
    ).status is LevelRuleStatus.PASSED


@pytest.mark.parametrize(
    ("industry", "expects_api"),
    [
        (LevelIndustrySector.OIL_AND_GAS, True),
        (LevelIndustrySector.PETROCHEMICAL, True),
        (LevelIndustrySector.WATER_AND_WASTEWATER, False),
        (LevelIndustrySector.CHEMICAL, False),
    ],
)
def test_api_2350_reference_is_limited_to_petroleum_storage_context(
    industry: LevelIndustrySector,
    expects_api: bool,
) -> None:
    request = complete_request(industry=industry)
    request = update_measurement(
        request,
        objectives=(LevelMeasurementObjective.OVERFILL_PREVENTION,),
    )
    result = assess_level_application(request)
    finding = next(
        item
        for item in result.safety_findings
        if item.finding_id == "finding.overfill-governance"
    )
    assert ("ref.api-2350-5" in finding.reference_ids) is expects_api


def test_radiometric_permission_and_program_are_explicit_rules() -> None:
    prohibited = update_safety(
        complete_request(),
        radiometric_source_permitted=LevelTriState.NO,
        radiation_protection_program_confirmed=LevelTriState.UNKNOWN,
    )
    scenario = scenario_for(
        assess_level_application(prohibited),
        LevelTechnology.RADIOMETRIC,
    )
    assert scenario.disposition is LevelScenarioDisposition.NOT_APPLICABLE

    no_program = update_safety(
        complete_request(),
        radiometric_source_permitted=LevelTriState.YES,
        radiation_protection_program_confirmed=LevelTriState.NO,
    )
    scenario = scenario_for(
        assess_level_application(no_program),
        LevelTechnology.RADIOMETRIC,
    )
    assert scenario.disposition is LevelScenarioDisposition.BLOCKED


def test_non_contact_requirement_excludes_contact_technologies() -> None:
    request = update_measurement(
        complete_request(),
        contact_preference=LevelContactPreference.NON_CONTACT_REQUIRED,
    )
    result = assess_level_application(request)
    assert scenario_for(
        result,
        LevelTechnology.GUIDED_WAVE_RADAR,
    ).disposition is LevelScenarioDisposition.NOT_APPLICABLE
    assert scenario_for(
        result,
        LevelTechnology.NON_CONTACT_RADAR,
    ).disposition is not LevelScenarioDisposition.NOT_APPLICABLE


def test_bulk_solid_phase_excludes_pressure_and_enables_rotary() -> None:
    request = update_process(
        complete_request(),
        phase=LevelProcessPhase.BULK_SOLID,
        dynamic_viscosity=None,
    )
    request = update_measurement(
        request,
        objectives=(LevelMeasurementObjective.HIGH_LEVEL_ALARM,),
    )
    result = assess_level_application(request)
    assert scenario_for(
        result,
        LevelTechnology.DIFFERENTIAL_PRESSURE,
    ).disposition is LevelScenarioDisposition.NOT_APPLICABLE
    rotary = scenario_for(result, LevelTechnology.ROTARY_PADDLE)
    assert "process.dynamic_viscosity" not in rotary.missing_information_ids


def test_interface_requires_both_density_inputs_and_filters_technologies() -> None:
    request = update_process(
        complete_request(),
        phase=LevelProcessPhase.LIQUID_LIQUID_INTERFACE,
        lower_fluid_density=None,
        upper_fluid_density=None,
    )
    request = update_measurement(
        request,
        objectives=(LevelMeasurementObjective.INTERFACE_LEVEL,),
    )
    result = assess_level_application(request)
    dp = scenario_for(result, LevelTechnology.DIFFERENTIAL_PRESSURE)
    assert {
        "process.lower_fluid_density",
        "process.upper_fluid_density",
    } <= set(dp.missing_information_ids)
    assert scenario_for(
        result,
        LevelTechnology.ULTRASONIC,
    ).disposition is LevelScenarioDisposition.NOT_APPLICABLE


def test_interface_objective_rejects_explicit_single_liquid_phase() -> None:
    with pytest.raises(ValidationError, match="interface or multiphase"):
        update_measurement(
            complete_request(),
            objectives=(LevelMeasurementObjective.INTERFACE_LEVEL,),
        )


@pytest.mark.parametrize(
    ("field_name", "technology", "rule_id"),
    [
        ("foam", LevelTechnology.NON_CONTACT_RADAR, "radar.foam"),
        ("foam", LevelTechnology.ULTRASONIC, "ultrasonic.foam"),
        ("steam", LevelTechnology.ULTRASONIC, "ultrasonic.steam"),
        (
            "condensation",
            LevelTechnology.ULTRASONIC,
            "ultrasonic.condensation",
        ),
        ("buildup", LevelTechnology.GUIDED_WAVE_RADAR, "gwr.buildup"),
        ("buildup", LevelTechnology.CAPACITANCE, "capacitance.buildup"),
        ("slurry", LevelTechnology.DIFFERENTIAL_PRESSURE, "pressure.slurry-buildup"),
    ],
)
def test_high_disturbances_are_auditable_failures(
    field_name: str,
    technology: LevelTechnology,
    rule_id: str,
) -> None:
    request = update_process(
        complete_request(),
        **{field_name: LevelConditionSeverity.HIGH},
    )
    scenario = scenario_for(assess_level_application(request), technology)
    assert rule_for(scenario, rule_id).status is LevelRuleStatus.FAILED


@pytest.mark.parametrize(
    ("field_name", "technology", "rule_id"),
    [
        ("turbulence", LevelTechnology.NON_CONTACT_RADAR, "radar.turbulence"),
        ("agitation", LevelTechnology.NON_CONTACT_RADAR, "process.agitation"),
        ("dust", LevelTechnology.ROTARY_PADDLE, "point.dust-or-slurry"),
        ("sticky_material", LevelTechnology.DISPLACER, "mechanical.sticky-slurry"),
        ("corrosive_service", LevelTechnology.DISPLACER, "materials.corrosion"),
        ("abrasive_service", LevelTechnology.MAGNETIC_FLOAT, "materials.abrasion"),
    ],
)
def test_additional_high_severity_inputs_are_not_dead_schema_fields(
    field_name: str,
    technology: LevelTechnology,
    rule_id: str,
) -> None:
    request = update_process(
        complete_request(),
        **{field_name: LevelConditionSeverity.HIGH},
    )
    result = assess_level_application(request)
    assert rule_for(
        scenario_for(result, technology),
        rule_id,
    ).status in (LevelRuleStatus.CAUTION, LevelRuleStatus.FAILED)


def test_failed_rule_caps_disposition_and_suitability() -> None:
    request = update_vessel(
        complete_request(),
        nozzle_geometry_confirmed=LevelTriState.NO,
    )
    radar = scenario_for(
        assess_level_application(request),
        LevelTechnology.NON_CONTACT_RADAR,
    )
    assert rule_for(radar, "signal-path.nozzle").status is LevelRuleStatus.FAILED
    assert radar.disposition is LevelScenarioDisposition.CONDITIONAL
    assert radar.suitability_score < 55.0


def test_nozzle_and_dead_zone_rules_affect_signal_path_scenarios() -> None:
    request = update_vessel(
        complete_request(),
        nozzle_geometry_confirmed=LevelTriState.NO,
    )
    request = update_measurement(
        request,
        upper_dead_zone_allowance=None,
    )
    radar = scenario_for(
        assess_level_application(request),
        LevelTechnology.NON_CONTACT_RADAR,
    )
    assert rule_for(radar, "signal-path.nozzle").status is LevelRuleStatus.FAILED
    assert "measurement.upper_dead_zone_allowance" in radar.missing_information_ids


def test_confirmed_nozzle_still_requires_diameter_and_height_evidence() -> None:
    request = update_vessel(
        complete_request(),
        nozzle_geometry_confirmed=LevelTriState.YES,
        nozzle_diameter=None,
        nozzle_height=None,
    )
    radar = scenario_for(
        assess_level_application(request),
        LevelTechnology.NON_CONTACT_RADAR,
    )
    assert {
        "vessel.nozzle_diameter",
        "vessel.nozzle_height",
    } <= set(radar.missing_information_ids)


def test_vapor_composition_and_behavior_are_both_required() -> None:
    request = update_process(
        complete_request(),
        vapor_space_composition=None,
        vapor_space_behavior=LevelVaporBehavior.UNKNOWN,
    )
    radar = scenario_for(
        assess_level_application(request),
        LevelTechnology.NON_CONTACT_RADAR,
    )
    rule = rule_for(radar, "signal-path.vapor-space")
    assert set(rule.missing_field_ids) == {
        "process.vapor_space_behavior",
        "process.vapor_space_composition",
    }


def test_mounting_access_and_constraints_apply_to_every_scenario() -> None:
    request = complete_request(
        installation=complete_request().installation.model_copy(
            update={"maintenance_access": LevelMaintenanceAccess.UNKNOWN}
        ),
        vessel=complete_request().vessel.model_copy(
            update={"mounting_constraints": None}
        ),
    )
    result = assess_level_application(request)
    for scenario in result.scenarios:
        assert "installation.maintenance_access" in scenario.missing_information_ids
        assert "vessel.mounting_constraints" in scenario.missing_information_ids


@pytest.mark.parametrize(
    ("power_state", "expected_status"),
    [
        (LevelTriState.UNKNOWN, LevelRuleStatus.MISSING_INFORMATION),
        (LevelTriState.NO, LevelRuleStatus.FAILED),
        (LevelTriState.YES, LevelRuleStatus.PASSED),
    ],
)
def test_active_electronic_scenarios_evaluate_electrical_power(
    power_state: LevelTriState,
    expected_status: LevelRuleStatus,
) -> None:
    request = complete_request(
        installation=complete_request().installation.model_copy(
            update={"electrical_power_available": power_state}
        )
    )
    radar = scenario_for(
        assess_level_application(request),
        LevelTechnology.NON_CONTACT_RADAR,
    )
    assert rule_for(radar, "installation.utilities").status is expected_status


def test_point_only_screen_does_not_require_tank_dimensions() -> None:
    request = update_measurement(
        complete_request(),
        objectives=(LevelMeasurementObjective.HIGH_LEVEL_ALARM,),
    )
    request = update_vessel(
        request,
        internal_diameter=None,
        straight_side_height=None,
    )
    fork = scenario_for(
        assess_level_application(request),
        LevelTechnology.VIBRATING_FORK,
    )
    assert "vessel.internal_diameter" not in fork.missing_information_ids
    assert "vessel.straight_side_height" not in fork.missing_information_ids
    assert "vessel.upper_level_elevation" not in fork.missing_information_ids


def test_high_point_screen_requires_upper_setpoint_elevation() -> None:
    request = update_measurement(
        complete_request(),
        objectives=(LevelMeasurementObjective.HIGH_LEVEL_ALARM,),
    )
    request = update_vessel(request, upper_level_elevation=None)
    fork = scenario_for(
        assess_level_application(request),
        LevelTechnology.VIBRATING_FORK,
    )
    assert "vessel.upper_level_elevation" in fork.missing_information_ids


def test_low_point_screen_requires_lower_setpoint_elevation() -> None:
    request = update_measurement(
        complete_request(),
        objectives=(LevelMeasurementObjective.LOW_LEVEL_ALARM,),
    )
    request = update_vessel(request, lower_level_elevation=None)
    fork = scenario_for(
        assess_level_application(request),
        LevelTechnology.VIBRATING_FORK,
    )
    assert "vessel.lower_level_elevation" in fork.missing_information_ids


def test_continuous_and_local_output_requirements_are_evaluated() -> None:
    request = update_measurement(
        complete_request(),
        continuous_output_required=LevelTriState.UNKNOWN,
        local_indication_required=LevelTriState.UNKNOWN,
    )
    result = assess_level_application(request)
    for scenario in result.scenarios:
        assert {
            "measurement.continuous_output_required",
            "measurement.local_indication_required",
        } <= set(scenario.missing_information_ids)


def test_missing_temperature_pressure_and_viscosity_are_auditable() -> None:
    request = update_process(
        complete_request(),
        minimum_temperature=None,
        normal_temperature=None,
        maximum_temperature=None,
        normal_absolute_pressure=None,
        maximum_absolute_pressure=None,
        dynamic_viscosity=None,
    )
    result = assess_level_application(request)
    gwr = scenario_for(result, LevelTechnology.GUIDED_WAVE_RADAR)
    assert {
        "process.minimum_temperature",
        "process.normal_temperature",
        "process.maximum_temperature",
        "process.normal_absolute_pressure",
        "process.maximum_absolute_pressure",
        "process.dynamic_viscosity",
    } <= set(gwr.missing_information_ids)


def test_point_only_objective_does_not_require_span_or_accuracy() -> None:
    request = update_measurement(
        complete_request(),
        objectives=(LevelMeasurementObjective.HIGH_LEVEL_ALARM,),
        measurement_span=None,
        required_accuracy_percent_of_span=None,
    )
    result = assess_level_application(request)
    fork = scenario_for(result, LevelTechnology.VIBRATING_FORK)
    assert "measurement.measurement_span" not in fork.missing_information_ids
    assert (
        "measurement.required_accuracy_percent_of_span"
        not in fork.missing_information_ids
    )
    assert rule_for(
        fork,
        "requirements.automation-and-indication",
    ).status is LevelRuleStatus.FAILED
    assert fork.disposition is LevelScenarioDisposition.CONDITIONAL


def test_trip_objective_with_independence_no_is_flagged_and_not_preferred() -> None:
    request = update_measurement(
        complete_request(),
        objectives=(LevelMeasurementObjective.HIGH_HIGH_LEVEL_TRIP,),
    )
    result = assess_level_application(request)
    assert any(
        item.finding_id == "finding.protective-objective-not-independent"
        for item in result.safety_findings
    )
    fork = scenario_for(result, LevelTechnology.VIBRATING_FORK)
    assert rule_for(
        fork,
        "safety.protective-objective-path",
    ).status is LevelRuleStatus.FAILED
    assert fork.disposition is LevelScenarioDisposition.CONDITIONAL
    assert result.status is CalculationStatus.FAILED
    assert result.missing_information == ()


def test_fully_specified_overfill_conflict_is_not_mislabeled_missing_input() -> None:
    request = update_measurement(
        complete_request(),
        objectives=(LevelMeasurementObjective.OVERFILL_PREVENTION,),
        continuous_output_required=LevelTriState.NO,
    )
    result = assess_level_application(request)
    assert result.missing_information == ()
    assert result.status is CalculationStatus.FAILED


def test_protective_response_time_is_verified_without_universal_threshold() -> None:
    request = update_measurement(
        complete_request(),
        objectives=(LevelMeasurementObjective.HIGH_HIGH_LEVEL_TRIP,),
        required_response_time=time_quantity(10_000.0),
    )
    request = update_safety(
        request,
        independent_protection_required=LevelTriState.YES,
        independent_protection_functions=(
            LevelProtectionFunction.HIGH_HIGH_TRIP,
        ),
    )
    result = assess_level_application(request)
    fork = scenario_for(result, LevelTechnology.VIBRATING_FORK)
    timing_rule = rule_for(fork, "safety.protective-objective-path")
    assert timing_rule.status is LevelRuleStatus.CAUTION
    assert "10000.0 s" in timing_rule.explanation
    assert "no universal acceptance threshold" in timing_rule.explanation
    assert fork.disposition is not LevelScenarioDisposition.PREFERRED


def test_density_variation_affects_buoyancy_technologies() -> None:
    request = update_process(
        complete_request(),
        density_variation_percent=20.0,
    )
    result = assess_level_application(request)
    for technology in (
        LevelTechnology.DISPLACER,
        LevelTechnology.MAGNETIC_FLOAT,
    ):
        item = scenario_for(result, technology)
        assert rule_for(
            item,
            "mechanical.density-variation",
        ).status is LevelRuleStatus.FAILED
        assert item.disposition is LevelScenarioDisposition.CONDITIONAL


@pytest.mark.parametrize(
    "technology",
    [
        LevelTechnology.DIFFERENTIAL_PRESSURE,
        LevelTechnology.HYDROSTATIC_PRESSURE,
    ],
)
def test_pressure_level_scenarios_require_density_variation(
    technology: LevelTechnology,
) -> None:
    request = update_process(
        complete_request(),
        density_variation_percent=None,
    )
    scenario = scenario_for(assess_level_application(request), technology)
    assert scenario.disposition is (
        LevelScenarioDisposition.INSUFFICIENT_INFORMATION
    )
    assert "process.density_variation_percent" in (
        scenario.missing_information_ids
    )
    assert rule_for(
        scenario,
        "pressure.density-variation",
    ).status is LevelRuleStatus.MISSING_INFORMATION


@pytest.mark.parametrize(
    ("variation", "expected_status"),
    [
        (10.0, LevelRuleStatus.PASSED),
        (10.000001, LevelRuleStatus.FAILED),
        (100.0, LevelRuleStatus.FAILED),
    ],
)
def test_density_variation_boundary_controls_density_dependent_scenarios(
    variation: float,
    expected_status: LevelRuleStatus,
) -> None:
    result = assess_level_application(
        update_process(
            complete_request(),
            density_variation_percent=variation,
        )
    )
    for technology in (
        LevelTechnology.DIFFERENTIAL_PRESSURE,
        LevelTechnology.HYDROSTATIC_PRESSURE,
        LevelTechnology.DISPLACER,
        LevelTechnology.MAGNETIC_FLOAT,
    ):
        scenario = scenario_for(result, technology)
        rule_id = (
            "pressure.density-variation"
            if technology
            in {
                LevelTechnology.DIFFERENTIAL_PRESSURE,
                LevelTechnology.HYDROSTATIC_PRESSURE,
            }
            else "mechanical.density-variation"
        )
        assert rule_for(scenario, rule_id).status is expected_status
        if variation > 10.0:
            assert scenario.disposition is LevelScenarioDisposition.CONDITIONAL
            assert scenario.suitability_score < 55.0
            if technology in {
                LevelTechnology.DIFFERENTIAL_PRESSURE,
                LevelTechnology.HYDROSTATIC_PRESSURE,
            }:
                assert scenario.supporting_calculation_method_ids == ()


def test_flammable_or_toxic_service_is_a_top_level_scoped_warning() -> None:
    request = update_safety(
        complete_request(),
        flammable_material=LevelTriState.YES,
        toxic_material=LevelTriState.YES,
    )
    result = assess_level_application(request)
    finding = next(
        item
        for item in result.safety_findings
        if item.finding_id == "finding.hazardous-material-service"
    )
    assert finding.severity is FindingSeverity.WARNING
    assert not finding.blocking


def test_hygienic_industry_cautions_contact_technology() -> None:
    request = complete_request(industry=LevelIndustrySector.PHARMACEUTICAL)
    request = update_process(
        request,
        hygienic_service=LevelConditionSeverity.HIGH,
    )
    result = assess_level_application(request)
    gwr = scenario_for(result, LevelTechnology.GUIDED_WAVE_RADAR)
    assert rule_for(gwr, "context.industry").status is LevelRuleStatus.CAUTION
    assert "verify.hygienic-service" in gwr.verification_requirement_ids


def test_high_vibration_environment_cautions_mechanical_technology() -> None:
    request = complete_request(
        installation=complete_request().installation.model_copy(
            update={
                "environments": (
                    LevelEnvironmentCondition.HIGH_VIBRATION,
                    LevelEnvironmentCondition.OUTDOOR,
                )
            }
        )
    )
    result = assess_level_application(request)
    displacer = scenario_for(result, LevelTechnology.DISPLACER)
    assert rule_for(
        displacer,
        "context.environment",
    ).status is LevelRuleStatus.CAUTION


@pytest.mark.parametrize(
    "environment",
    [
        LevelEnvironmentCondition.COASTAL_OR_MARINE,
        LevelEnvironmentCondition.WASHDOWN,
        LevelEnvironmentCondition.FLOOD_PRONE,
        LevelEnvironmentCondition.HIGH_VIBRATION,
        LevelEnvironmentCondition.HIGH_ELECTROMAGNETIC_INTERFERENCE,
        LevelEnvironmentCondition.CORROSIVE_ATMOSPHERE,
        LevelEnvironmentCondition.HIGH_DUST,
        LevelEnvironmentCondition.EXTREME_COLD,
        LevelEnvironmentCondition.EXTREME_HEAT,
        LevelEnvironmentCondition.LIMITED_CLEARANCE,
        LevelEnvironmentCondition.REMOTE_LOCATION,
    ],
)
def test_adverse_environment_conditions_never_silently_pass(
    environment: LevelEnvironmentCondition,
) -> None:
    request = complete_request(
        installation=complete_request().installation.model_copy(
            update={"environments": (environment,)}
        )
    )
    radar = scenario_for(
        assess_level_application(request),
        LevelTechnology.NON_CONTACT_RADAR,
    )
    assert rule_for(
        radar,
        "context.environment",
    ).status is LevelRuleStatus.CAUTION


def test_controlled_indoor_environment_can_be_explicitly_benign() -> None:
    request = complete_request(
        installation=complete_request().installation.model_copy(
            update={
                "environments": (
                    LevelEnvironmentCondition.INDOOR_CONTROLLED,
                )
            }
        )
    )
    radar = scenario_for(
        assess_level_application(request),
        LevelTechnology.NON_CONTACT_RADAR,
    )
    assert rule_for(
        radar,
        "context.environment",
    ).status is LevelRuleStatus.PASSED


def test_hygienic_service_is_considered_outside_food_and_pharma() -> None:
    request = update_process(
        complete_request(industry=LevelIndustrySector.CHEMICAL),
        hygienic_service=LevelConditionSeverity.HIGH,
    )
    gwr = scenario_for(
        assess_level_application(request),
        LevelTechnology.GUIDED_WAVE_RADAR,
    )
    assert rule_for(gwr, "context.industry").status is LevelRuleStatus.CAUTION


@pytest.mark.parametrize(
    ("arrangement", "method_id"),
    [
        (LevelDpArrangement.OPEN_VESSEL, "level.dp.open-vessel-range"),
        (LevelDpArrangement.CLOSED_DRY_LEG, "level.dp.closed-dry-leg-range"),
        (LevelDpArrangement.CLOSED_WET_LEG, "level.dp.closed-wet-leg-range"),
        (LevelDpArrangement.REMOTE_SEALS, "level.dp.remote-seal-range"),
    ],
)
def test_dp_scenario_links_without_executing_step95_methods(
    arrangement: LevelDpArrangement,
    method_id: str,
) -> None:
    request = update_vessel(
        complete_request(),
        dp_arrangement=arrangement,
        configuration=(
            LevelVesselConfiguration.OPEN
            if arrangement is LevelDpArrangement.OPEN_VESSEL
            else LevelVesselConfiguration.CLOSED
        ),
    )
    scenario = scenario_for(
        assess_level_application(request),
        LevelTechnology.DIFFERENTIAL_PRESSURE,
    )
    assert method_id in scenario.supporting_calculation_method_ids
    assert "level.dp.endpoint-range" in scenario.supporting_calculation_method_ids


@pytest.mark.parametrize(
    ("geometry", "method_id"),
    [
        (LevelVesselGeometry.VERTICAL_CYLINDER, "level.tank.vertical-cylinder"),
        (
            LevelVesselGeometry.HORIZONTAL_CYLINDER,
            "level.tank.horizontal-cylinder",
        ),
    ],
)
def test_tank_scenario_links_geometry_method(
    geometry: LevelVesselGeometry,
    method_id: str,
) -> None:
    scenario = scenario_for(
        assess_level_application(
            update_vessel(complete_request(), geometry=geometry)
        ),
        LevelTechnology.TANK_GAUGING,
    )
    assert method_id in scenario.supporting_calculation_method_ids


def test_all_method_links_are_reviewed_step95_ids() -> None:
    result = assess_level_application(complete_request())
    supported = set(SUPPORTED_LEVEL_CALCULATION_METHOD_IDS)
    for scenario in result.scenarios:
        assert set(scenario.supporting_calculation_method_ids) <= supported


def test_request_method_links_cannot_override_exact_context() -> None:
    request = complete_request(
        supporting_calculation_method_ids=(
            "level.dp.closed-wet-leg-range",
            "level.hydrostatic.column-pressure",
            "level.tank.horizontal-cylinder",
        )
    )
    result = assess_level_application(request)
    assert scenario_for(
        result,
        LevelTechnology.NON_CONTACT_RADAR,
    ).supporting_calculation_method_ids == ()
    dp_links = scenario_for(
        result,
        LevelTechnology.DIFFERENTIAL_PRESSURE,
    ).supporting_calculation_method_ids
    assert "level.dp.remote-seal-range" in dp_links
    assert "level.dp.closed-wet-leg-range" not in dp_links
    assert "level.hydrostatic.column-pressure" in scenario_for(
        result,
        LevelTechnology.HYDROSTATIC_PRESSURE,
    ).supporting_calculation_method_ids
    tank_links = scenario_for(
        result,
        LevelTechnology.TANK_GAUGING,
    ).supporting_calculation_method_ids
    assert "level.tank.vertical-cylinder" in tank_links
    assert "level.tank.horizontal-cylinder" not in tank_links


def test_dp_not_applicable_arrangement_has_no_rank_or_method_links() -> None:
    request = update_vessel(
        complete_request(),
        dp_arrangement=LevelDpArrangement.NOT_APPLICABLE,
    )
    scenario = scenario_for(
        assess_level_application(request),
        LevelTechnology.DIFFERENTIAL_PRESSURE,
    )
    assert scenario.disposition is LevelScenarioDisposition.NOT_APPLICABLE
    assert scenario.rank is None
    assert scenario.supporting_calculation_method_ids == ()


def test_unknown_vessel_configuration_blocks_pressure_method_links() -> None:
    request = update_vessel(
        complete_request(),
        configuration=LevelVesselConfiguration.UNKNOWN,
    )
    result = assess_level_application(request)
    for technology in (
        LevelTechnology.DIFFERENTIAL_PRESSURE,
        LevelTechnology.HYDROSTATIC_PRESSURE,
    ):
        scenario = scenario_for(result, technology)
        assert "vessel.configuration" in scenario.missing_information_ids
        assert scenario.disposition is (
            LevelScenarioDisposition.INSUFFICIENT_INFORMATION
        )
        assert scenario.supporting_calculation_method_ids == ()


@pytest.mark.parametrize(
    "configuration",
    [
        LevelVesselConfiguration.PRESSURIZED,
        LevelVesselConfiguration.VACUUM,
    ],
)
def test_standalone_hydrostatic_is_conditional_for_vapor_pressure_compensation(
    configuration: LevelVesselConfiguration,
) -> None:
    request = update_vessel(
        complete_request(),
        configuration=configuration,
    )
    hydro = scenario_for(
        assess_level_application(request),
        LevelTechnology.HYDROSTATIC_PRESSURE,
    )
    assert rule_for(
        hydro,
        "hydrostatic.vessel-configuration",
    ).status is LevelRuleStatus.FAILED
    assert hydro.disposition is LevelScenarioDisposition.CONDITIONAL
    assert hydro.supporting_calculation_method_ids == ()


def test_missing_range_elevations_withhold_pressure_and_tank_links() -> None:
    request = update_vessel(
        complete_request(),
        lower_level_elevation=None,
        upper_level_elevation=None,
    )
    result = assess_level_application(request)
    for technology in (
        LevelTechnology.DIFFERENTIAL_PRESSURE,
        LevelTechnology.HYDROSTATIC_PRESSURE,
        LevelTechnology.TANK_GAUGING,
    ):
        scenario = scenario_for(result, technology)
        assert {
            "vessel.lower_level_elevation",
            "vessel.upper_level_elevation",
        } <= set(scenario.missing_information_ids)
        assert scenario.supporting_calculation_method_ids == ()


def test_inventory_geometry_dimensions_gate_tank_method_link() -> None:
    request = update_measurement(
        complete_request(),
        objectives=(LevelMeasurementObjective.INVENTORY,),
    )
    request = update_vessel(
        request,
        internal_diameter=None,
        straight_side_height=None,
    )
    tank = scenario_for(
        assess_level_application(request),
        LevelTechnology.TANK_GAUGING,
    )
    assert {
        "vessel.internal_diameter",
        "vessel.straight_side_height",
    } <= set(tank.missing_information_ids)
    assert tank.supporting_calculation_method_ids == ()


def test_reference_metadata_and_currency_caveat_are_present() -> None:
    result = assess_level_application(complete_request())
    references = {item.reference_id: item for item in result.references}
    assert references["ref.iec-60079-0-2026"].edition_or_revision == (
        "2026 edition 8.0"
    )
    assert references["ref.iec-61511-1"].source_location == (
        "https://webstore.iec.ch/en/publication/61289"
    )
    assert all(
        "reconfirm" in limitation.lower()
        for limitation in result.limitations
        if "Standards currency" in limitation
    )


def test_wizard_source_has_no_calculation_dispatch_or_external_side_effects() -> None:
    source_path = (
        Path(__file__).parents[1]
        / "app"
        / "engineering"
        / "design"
        / "level_application_wizard.py"
    )
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    prohibited_modules = {
        "requests",
        "httpx",
        "socket",
        "sqlalchemy",
        "subprocess",
        "app.engineering.calculations.level",
    }
    assert imported_modules.isdisjoint(prohibited_modules)
    assert "eval(" not in source
    assert "exec(" not in source
    assert "product_id" not in source
    assert "model_number" not in source
    assert "voice" in source.lower()


def test_invalid_complete_fixture_update_remains_model_validated() -> None:
    request = complete_request()
    with pytest.raises(ValidationError):
        update_process(
            request,
            minimum_temperature=temperature(100.0),
            maximum_temperature=temperature(20.0),
        )
