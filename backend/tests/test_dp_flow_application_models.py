"""Strict-model tests for Phase 7 Step 98 DP-flow application intelligence."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.engineering.design.dp_flow_application_models import DPFlowApplicationAssessment
from app.engineering.design.dp_flow_application_models import DPFlowApplicationRequest
from app.engineering.design.dp_flow_application_models import DPCalculationReadiness
from app.engineering.design.dp_flow_application_models import DPFluidPhase
from app.engineering.design.dp_flow_application_models import DPMeasurementObjective
from app.engineering.design.dp_flow_application_models import DPOwnershipType
from app.engineering.design.dp_flow_application_models import DPPressureLossClass
from app.engineering.design.dp_flow_application_models import DPPrimaryElementDefinition
from app.engineering.design.dp_flow_application_models import DPPrimaryElementFamily
from app.engineering.design.dp_flow_application_models import DPPrimaryElementScenario
from app.engineering.design.dp_flow_application_models import DPTriState
from app.engineering.design.dp_flow_application_wizard import GENERIC_PRIMARY_ELEMENTS
from app.engineering.design.dp_flow_application_wizard import PRIMARY_ELEMENT_CATALOGUE
from app.engineering.design.dp_flow_application_wizard import PROPRIETARY_PRIMARY_ELEMENTS
from app.engineering.design.dp_flow_application_wizard import assess_dp_flow_application


def request() -> DPFlowApplicationRequest:
    return DPFlowApplicationRequest(
        assessment_id="DP-CASE-001",
        fluid_phase=DPFluidPhase.LIQUID,
        objective=DPMeasurementObjective.PROCESS_CONTROL,
        pipe_inside_diameter_m=0.2,
        minimum_mass_flow_kg_s=1.0,
        normal_mass_flow_kg_s=4.0,
        maximum_mass_flow_kg_s=8.0,
        flowing_density_kg_m3=998.2,
        flowing_viscosity_pa_s=0.001,
        flowing_absolute_pressure_pa=500_000.0,
        flowing_temperature_k=293.15,
        available_upstream_straight_run_d=12.0,
        available_downstream_straight_run_d=6.0,
        maximum_permanent_pressure_loss_pa=50_000.0,
        required_total_uncertainty_percent=1.5,
        dirty_or_solids_bearing=DPTriState.NO,
        pulsating_flow=DPTriState.NO,
        bidirectional_flow=DPTriState.NO,
        wet_gas_or_condensing=DPTriState.NO,
        intrusive_element_allowed=DPTriState.YES,
        approved_standard_or_oem_method_available=DPTriState.YES,
        traceable_coefficient_available=DPTriState.YES,
        hazardous_area=DPTriState.NO,
        full_pipe_confirmed=DPTriState.YES,
        flashing_or_cavitation_risk=DPTriState.NO,
        sonic_or_choked_flow_risk=DPTriState.NO,
    )


def test_request_is_frozen_and_forbids_extra_fields() -> None:
    value = request()
    with pytest.raises((ValidationError, TypeError)):
        value.pipe_inside_diameter_m = 0.3  # type: ignore[misc]
    with pytest.raises(ValidationError):
        DPFlowApplicationRequest.model_validate({**value.model_dump(), "brand_preference": "x"})


def test_flow_cases_must_be_ordered() -> None:
    data = request().model_dump()
    data["minimum_mass_flow_kg_s"] = 9.0
    with pytest.raises(ValidationError, match="minimum <= normal <= maximum"):
        DPFlowApplicationRequest.model_validate(data)


@pytest.mark.parametrize("value", (1, 0, "true", "false", "yes", "no"))
def test_proprietary_variant_request_flag_is_strict_boolean(value: object) -> None:
    """The public request does not coerce numeric or textual booleans."""

    data = request().model_dump(mode="python")
    data["include_proprietary_variants"] = value
    with pytest.raises(ValidationError):
        DPFlowApplicationRequest.model_validate(data)


@pytest.mark.parametrize("field", ("pipe_inside_diameter_m", "flowing_density_kg_m3", "flowing_temperature_k"))
def test_nonfinite_values_are_rejected(field: str) -> None:
    data = request().model_dump()
    data[field] = float("nan")
    with pytest.raises(ValidationError):
        DPFlowApplicationRequest.model_validate(data)
    data[field] = True
    with pytest.raises(ValidationError):
        DPFlowApplicationRequest.model_validate(data)


def test_catalogue_covers_core_generic_families() -> None:
    families = {option.family for option in GENERIC_PRIMARY_ELEMENTS}
    assert {
        DPPrimaryElementFamily.ORIFICE_PLATE,
        DPPrimaryElementFamily.INTEGRAL_ORIFICE,
        DPPrimaryElementFamily.FLOW_NOZZLE,
        DPPrimaryElementFamily.VENTURI_TUBE,
        DPPrimaryElementFamily.VENTURI_NOZZLE,
        DPPrimaryElementFamily.WEDGE,
        DPPrimaryElementFamily.AVERAGING_PITOT,
        DPPrimaryElementFamily.SINGLE_POINT_PITOT,
        DPPrimaryElementFamily.CONE_METER,
        DPPrimaryElementFamily.CONDITIONING_ELEMENT,
        DPPrimaryElementFamily.LAMINAR_FLOW_ELEMENT,
        DPPrimaryElementFamily.ELBOW_METER,
    } <= families


def test_owned_options_are_never_generic_categories() -> None:
    assert len(PROPRIETARY_PRIMARY_ELEMENTS) == 7
    for option in PROPRIETARY_PRIMARY_ELEMENTS:
        assert option.ownership_type is not DPOwnershipType.GENERIC_TECHNOLOGY
        assert option.owner
        assert option.proprietary_notice is not None
        assert option.generic_alternative_id


def test_annubar_is_explicitly_owned_and_mapped_to_generic_apt() -> None:
    option = next(item for item in PRIMARY_ELEMENT_CATALOGUE if item.option_id.endswith("annubar"))
    assert option.owner == "Emerson / Rosemount"
    assert option.generic_alternative_id == "generic.averaging-pitot"
    assert "not a generic" in option.proprietary_notice.notice


def test_vcone_is_explicitly_owned_and_mapped_to_generic_cone() -> None:
    option = next(item for item in PRIMARY_ELEMENT_CATALOGUE if item.option_id.endswith("v-cone"))
    assert option.owner == "McCrometer"
    assert option.generic_alternative_id == "generic.cone.dp"


def test_generic_definition_cannot_claim_owner() -> None:
    with pytest.raises(ValidationError, match="generic options cannot"):
        DPPrimaryElementDefinition(
            option_id="generic.invalid",
            family=DPPrimaryElementFamily.WEDGE,
            title="Invalid generic",
            variant="Invalid owner claim",
            ownership_type=DPOwnershipType.GENERIC_TECHNOLOGY,
            owner="Vendor",
            typical_pressure_loss=DPPressureLossClass.MODERATE,
            calculation_readiness=DPCalculationReadiness.REVIEWED_STANDARD_METHOD_REQUIRED,
            coefficient_basis="A controlled coefficient would be required.",
            calculation_basis="A controlled calculation method would be required.",
            strengths_to_verify=("one strength",),
            limitations_to_verify=("one limitation",),
        )


def test_catalogue_ids_are_unique() -> None:
    ids = tuple(option.option_id for option in PRIMARY_ELEMENT_CATALOGUE)
    assert len(ids) == len(set(ids)) == 25


def test_only_supported_generic_orifice_links_to_step97_kernel() -> None:
    ready = [item for item in PRIMARY_ELEMENT_CATALOGUE if item.calculation_readiness is DPCalculationReadiness.STEP97_GENERIC_SUPPLIED_COEFFICIENTS]
    assert [item.option_id for item in ready] == ["generic.orifice.concentric-square-edge"]


def test_only_supported_generic_families_link_to_step98_kernels() -> None:
    ready = [
        item.option_id
        for item in PRIMARY_ELEMENT_CATALOGUE
        if item.calculation_readiness
        is DPCalculationReadiness.STEP98_GENERIC_SUPPLIED_COEFFICIENTS
    ]
    assert ready == [
        "generic.nozzle.isa-or-long-radius",
        "generic.venturi.classical",
        "generic.venturi-nozzle",
        "generic.averaging-pitot",
    ]


def test_restriction_orifice_is_explicitly_unsupported_for_measurement() -> None:
    option = next(item for item in PRIMARY_ELEMENT_CATALOGUE if item.option_id == "excluded.restriction-orifice")
    assert option.calculation_readiness is DPCalculationReadiness.UNSUPPORTED


@pytest.mark.parametrize(
    "field",
    ("manufacturer_declared_best", "standards_conformity_claimed"),
)
def test_assessment_cannot_forge_vendor_or_conformity_claims(field: str) -> None:
    data = assess_dp_flow_application(request()).model_dump(mode="python")
    data[field] = True

    with pytest.raises(ValidationError):
        DPFlowApplicationAssessment.model_validate(data)


@pytest.mark.parametrize(
    "field",
    ("brand_ranked", "standards_conformity_claimed"),
)
def test_scenario_cannot_forge_ranking_or_conformity_claims(field: str) -> None:
    scenario = assess_dp_flow_application(request()).all_screened_options[0]
    data = scenario.model_dump(mode="python")
    data[field] = True

    with pytest.raises(ValidationError):
        DPPrimaryElementScenario.model_validate(data)


def test_owned_variant_cannot_become_the_recommended_element() -> None:
    assessment = assess_dp_flow_application(request())
    owned = next(
        item
        for item in assessment.all_screened_options
        if item.option.ownership_type is not DPOwnershipType.GENERIC_TECHNOLOGY
    )
    data = assessment.model_dump(mode="python")
    data["recommended_element"] = owned.model_dump(mode="python")

    with pytest.raises(ValidationError, match="must be generic"):
        DPFlowApplicationAssessment.model_validate(data)
