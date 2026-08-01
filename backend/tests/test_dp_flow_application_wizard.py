"""Behavior tests for the Step 98 vendor-neutral DP application wizard."""

from __future__ import annotations

import pytest

from app.engineering.design.dp_flow_application_models import DPConfidenceBand
from app.engineering.design.dp_flow_application_models import DPCalculationReadiness
from app.engineering.design.dp_flow_application_models import DPFlowApplicationRequest
from app.engineering.design.dp_flow_application_models import DPFluidPhase
from app.engineering.design.dp_flow_application_models import DPMeasurementObjective
from app.engineering.design.dp_flow_application_models import DPOwnershipType
from app.engineering.design.dp_flow_application_models import DPScenarioDisposition
from app.engineering.design.dp_flow_application_models import DPTriState
from app.engineering.design.dp_flow_application_wizard import DEFAULT_DP_FLOW_APPLICATION_WIZARD
from app.engineering.design.dp_flow_application_wizard import PRIMARY_ELEMENT_CATALOGUE
from app.engineering.design.dp_flow_application_wizard import assess_dp_flow_application


def request(**changes: object) -> DPFlowApplicationRequest:
    data: dict[str, object] = {
        "assessment_id": "DP-CASE-001",
        "fluid_phase": DPFluidPhase.LIQUID,
        "objective": DPMeasurementObjective.PROCESS_CONTROL,
        "pipe_inside_diameter_m": 0.2,
        "minimum_mass_flow_kg_s": 1.0,
        "normal_mass_flow_kg_s": 4.0,
        "maximum_mass_flow_kg_s": 8.0,
        "flowing_density_kg_m3": 998.2,
        "flowing_viscosity_pa_s": 0.001,
        "flowing_absolute_pressure_pa": 500_000.0,
        "flowing_temperature_k": 293.15,
        "available_upstream_straight_run_d": 12.0,
        "available_downstream_straight_run_d": 6.0,
        "maximum_permanent_pressure_loss_pa": 50_000.0,
        "required_total_uncertainty_percent": 1.5,
        "dirty_or_solids_bearing": DPTriState.NO,
        "erosive": DPTriState.NO,
        "corrosive": DPTriState.NO,
        "pulsating_flow": DPTriState.NO,
        "bidirectional_flow": DPTriState.NO,
        "wet_gas_or_condensing": DPTriState.NO,
        "full_pipe_confirmed": DPTriState.YES,
        "flashing_or_cavitation_risk": DPTriState.NO,
        "sonic_or_choked_flow_risk": DPTriState.NO,
        "intrusive_element_allowed": DPTriState.YES,
        "hazardous_area": DPTriState.NO,
        "sour_or_toxic_service": DPTriState.NO,
        "oxygen_or_high_purity_service": DPTriState.NO,
        "approved_standard_or_oem_method_available": DPTriState.YES,
        "traceable_coefficient_available": DPTriState.YES,
    }
    data.update(changes)
    return DPFlowApplicationRequest.model_validate(data)


def scenario(assessment, option_id: str):
    return next(item for item in assessment.all_screened_options if item.option.option_id == option_id)


def test_complete_case_returns_generic_recommendation_and_all_options() -> None:
    result = DEFAULT_DP_FLOW_APPLICATION_WIZARD.assess(request())
    assert result.recommended_element is not None
    assert result.recommended_element.option.ownership_type is DPOwnershipType.GENERIC_TECHNOLOGY
    assert len(result.all_screened_options) == len(PRIMARY_ELEMENT_CATALOGUE) == 25
    assert result.manufacturer_declared_best is False
    assert result.standards_conformity_claimed is False
    assert result.final_brand_selection == "user_decision_required"
    assert "user makes the final brand decision" in result.final_brand_decision_notice.lower()


def test_owned_variants_are_disclosed_but_never_default_recommendation() -> None:
    result = assess_dp_flow_application(request())
    owned = [item for item in result.all_screened_options if item.option.ownership_type is not DPOwnershipType.GENERIC_TECHNOLOGY]
    assert len(owned) == 7
    assert all(item.disposition is DPScenarioDisposition.CONDITIONAL for item in owned)
    assert all(item.brand_ranked is False for item in owned)
    assert {notice.owner for notice in result.proprietary_notices} >= {"Emerson / Rosemount", "McCrometer", "Armstrong International / VERIS", "ABB"}


def test_slurry_rejects_concentric_plate_and_favors_suitable_generic_paths() -> None:
    result = assess_dp_flow_application(request(fluid_phase=DPFluidPhase.SLURRY, dirty_or_solids_bearing=DPTriState.YES))
    concentric = scenario(result, "generic.orifice.concentric-square-edge")
    wedge = scenario(result, "generic.wedge")
    eccentric = scenario(result, "generic.orifice.eccentric-or-segmental")
    assert concentric.disposition is DPScenarioDisposition.REJECTED
    assert wedge.engineering_score > 0
    assert eccentric.engineering_score > concentric.engineering_score


def test_large_pipe_low_loss_constraint_supports_generic_averaging_pitot() -> None:
    result = assess_dp_flow_application(request(pipe_inside_diameter_m=1.2, maximum_permanent_pressure_loss_pa=10_000.0))
    apt = scenario(result, "generic.averaging-pitot")
    orifice = scenario(result, "generic.orifice.concentric-square-edge")
    assert apt.engineering_score > orifice.engineering_score
    assert apt.disposition is DPScenarioDisposition.VIABLE


@pytest.mark.parametrize(
    "option_id",
    (
        "generic.nozzle.isa-or-long-radius",
        "generic.venturi.classical",
        "generic.venturi-nozzle",
        "generic.averaging-pitot",
    ),
)
def test_step98_generic_calculation_readiness_propagates(option_id: str) -> None:
    result = assess_dp_flow_application(request())
    assert (
        scenario(result, option_id).calculation_readiness
        is DPCalculationReadiness.STEP98_GENERIC_SUPPLIED_COEFFICIENTS
    )


def test_limited_straight_run_is_visible_not_silently_waived() -> None:
    result = assess_dp_flow_application(request(available_upstream_straight_run_d=2.0))
    conventional = scenario(result, "generic.orifice.concentric-square-edge")
    conditioning = scenario(result, "generic.conditioning.multi-hole")
    assert conventional.engineering_score < conditioning.engineering_score
    assert "Verify upstream/downstream fittings" in conditioning.straight_run_output
    assert conditioning.standards_conformity_claimed is False


def test_no_intrusive_element_means_no_dp_primary_element_recommendation() -> None:
    result = assess_dp_flow_application(request(intrusive_element_allowed=DPTriState.NO))
    assert result.recommended_element is None
    assert all(item.disposition is DPScenarioDisposition.REJECTED for item in result.all_screened_options)
    assert result.confidence_score <= 45


def test_restriction_orifice_is_rejected_as_measurement_by_default() -> None:
    result = assess_dp_flow_application(request())
    restriction = scenario(result, "excluded.restriction-orifice")
    assert restriction.disposition is DPScenarioDisposition.REJECTED
    assert "not supported as a measurement element" in " ".join(restriction.rejected_reasons)


def test_unknown_full_pipe_status_is_insufficient_information() -> None:
    result = assess_dp_flow_application(request(full_pipe_confirmed=DPTriState.UNKNOWN))
    assert result.recommended_element is None
    assert any(item.disposition is DPScenarioDisposition.INSUFFICIENT_INFORMATION for item in result.all_screened_options)
    assert "full-pipe confirmation" in result.missing_information


def test_owned_averaging_pitot_does_not_gain_brand_score() -> None:
    result = assess_dp_flow_application(request(pipe_inside_diameter_m=1.2, maximum_permanent_pressure_loss_pa=10_000.0))
    generic = scenario(result, "generic.averaging-pitot")
    for option_id in ("owned.emerson-rosemount.annubar", "owned.armstrong-veris.verabar", "owned.abb.torbar"):
        assert scenario(result, option_id).engineering_score == generic.engineering_score


@pytest.mark.parametrize(
    ("phase", "expected"),
    ((DPFluidPhase.LIQUID, "continuously downward"), (DPFluidPhase.GAS, "continuously upward"), (DPFluidPhase.STEAM, "matched condensate legs")),
)
def test_impulse_arrangement_is_phase_specific(phase: DPFluidPhase, expected: str) -> None:
    result = assess_dp_flow_application(request(fluid_phase=phase))
    assert result.recommended_element is not None
    assert expected in result.recommended_element.impulse_line_arrangement


def test_incomplete_case_reports_missing_information_and_reduces_confidence() -> None:
    result = assess_dp_flow_application(DPFlowApplicationRequest(
        assessment_id="DP-INCOMPLETE",
        fluid_phase=DPFluidPhase.UNKNOWN,
        objective=DPMeasurementObjective.MONITORING,
    ))
    assert "pipe inside diameter" in result.missing_information
    assert "required total uncertainty" in result.missing_information
    assert result.confidence_band is DPConfidenceBand.LOW


@pytest.mark.parametrize(
    ("field", "missing_label"),
    (
        ("full_pipe_confirmed", "full-pipe confirmation"),
        ("flashing_or_cavitation_risk", "flashing or cavitation risk"),
        ("sonic_or_choked_flow_risk", "sonic or choked-flow risk"),
        ("intrusive_element_allowed", "intrusive-element permission"),
        ("wet_gas_or_condensing", "wet-gas or condensing risk"),
        ("pulsating_flow", "pulsating-flow status"),
        ("bidirectional_flow", "bidirectional-flow status"),
        ("traceable_coefficient_available", "traceable coefficient availability"),
    ),
)
def test_unresolved_execution_prerequisites_cannot_be_viable(
    field: str,
    missing_label: str,
) -> None:
    """Wizard disposition and missing evidence align with service gates."""

    result = assess_dp_flow_application(request(**{field: DPTriState.UNKNOWN}))

    assert result.recommended_element is None
    assert missing_label in result.missing_information
    assert all(
        item.disposition is not DPScenarioDisposition.VIABLE
        for item in result.all_screened_options
    )


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("full_pipe_confirmed", DPTriState.NO),
        ("flashing_or_cavitation_risk", DPTriState.YES),
        ("sonic_or_choked_flow_risk", DPTriState.YES),
        ("intrusive_element_allowed", DPTriState.NO),
        ("wet_gas_or_condensing", DPTriState.YES),
        ("pulsating_flow", DPTriState.YES),
        ("bidirectional_flow", DPTriState.YES),
        ("traceable_coefficient_available", DPTriState.NO),
    ),
)
def test_explicit_unsupported_execution_conditions_reject_all_options(
    field: str,
    unsafe_value: DPTriState,
) -> None:
    """Positive scoring cannot offset an explicit current-workflow blocker."""

    result = assess_dp_flow_application(request(**{field: unsafe_value}))

    assert result.recommended_element is None
    assert all(
        item.disposition is DPScenarioDisposition.REJECTED
        for item in result.all_screened_options
    )


def test_safety_findings_expand_for_hazardous_toxic_steam_service() -> None:
    result = assess_dp_flow_application(request(
        fluid_phase=DPFluidPhase.STEAM,
        hazardous_area=DPTriState.YES,
        sour_or_toxic_service=DPTriState.YES,
    ))
    joined = " ".join(result.safety_findings).lower()
    assert "hazardous-area" in joined
    assert "toxic/sour-service" in joined
    assert "steam impulse" in joined


def test_hot_tap_request_adds_live_pressure_boundary_gate() -> None:
    result = assess_dp_flow_application(request(online_insertion_or_hot_tap_requested=DPTriState.YES))
    assert "hot tapping" in " ".join(result.safety_findings).lower()


def test_required_outputs_are_present_for_every_scenario() -> None:
    result = assess_dp_flow_application(request())
    for item in result.all_screened_options:
        assert item.pressure_loss_output
        assert item.straight_run_output
        assert item.uncertainty_output
        assert item.impulse_line_arrangement
        assert item.calculation_method
        assert item.brand_ranked is False


def test_fingerprint_is_deterministic_and_changes_with_evidence() -> None:
    first = assess_dp_flow_application(request())
    second = assess_dp_flow_application(request())
    changed = assess_dp_flow_application(request(available_upstream_straight_run_d=2.0))
    assert first.assessment_fingerprint == second.assessment_fingerprint
    assert first.assessment_fingerprint != changed.assessment_fingerprint


def test_proprietary_variants_can_be_excluded_without_changing_generic_catalogue() -> None:
    result = assess_dp_flow_application(request(include_proprietary_variants=False))
    assert all(item.option.ownership_type is DPOwnershipType.GENERIC_TECHNOLOGY for item in result.all_screened_options)
    assert result.proprietary_notices == ()
    assert len(result.official_sources) == 5


def test_package_boundary_exports_step99_versioned_hardening() -> None:
    from app.engineering import design

    assert design.FOUNDATION_VERSION == "0.2.0"
    assert design.VOICE_FUNCTIONALITY_ENABLED is False
    assert design.DP_FLOW_APPLICATION_MODEL_VERSION == "1.1.0"
    assert design.DP_FLOW_APPLICATION_WIZARD_VERSION == "1.1.0"
    assert design.DP_FLOW_APPLICATION_RULESET_VERSION == "1.1.0"
    assert design.DEFAULT_DP_FLOW_APPLICATION_WIZARD is DEFAULT_DP_FLOW_APPLICATION_WIZARD
