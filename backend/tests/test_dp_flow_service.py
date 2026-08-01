"""Workflow-model and immutable service tests for Step 99 DP flow."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.engineering.calculations import dp_flow_workflow_models as workflow_module
from app.engineering.calculations.dp_flow import AveragingPitotFlowResult
from app.engineering.calculations.dp_flow import BoreSolverResult
from app.engineering.calculations.dp_flow import CircularRestrictionFlowResult
from app.engineering.calculations.dp_flow import DPFlowUncertaintyResult
from app.engineering.calculations.dp_flow import DPTransmitterRangeScreenResult
from app.engineering.calculations.dp_flow import DP_FLOW_DISCOVERY_ENTRIES
from app.engineering.calculations.dp_flow import FlowingFluidProperties
from app.engineering.calculations.dp_flow import OrificeFlowResult
from app.engineering.calculations.dp_flow import PermanentPressureLossResult
from app.engineering.calculations.dp_flow import RelativeUncertaintyComponent
from app.engineering.calculations.dp_flow import TraceableCoefficient
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowDesignCaseRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowExecutionOutcome,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowStoredDesignCaseReplayRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowUncertaintyRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPTransmitterRangeRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DP_FLOW_API_CATALOGUE,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DP_FLOW_API_REGISTRY,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DP_FLOW_KNOWLEDGE_LINKS,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DP_FLOW_STORED_DESIGN_CASE_EXAMPLES,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DP_FLOW_STORED_EXAMPLE_REGISTRY,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    GenericAveragingPitotFlowRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    GenericNozzleFlowRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    GenericOrificeFlowRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    GenericVenturiNozzleFlowRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    GenericVenturiTubeFlowRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    OrificeBoreSolveRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    PermanentPressureLossRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    build_input_fingerprint,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    build_stored_example_fingerprint,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    validate_execution_request,
)
from app.engineering.design.dp_flow_application_models import (
    DPFlowApplicationRequest,
)
from app.services.dp_flow_service import DEFAULT_DP_FLOW_SERVICE
from app.services.dp_flow_service import DPFlowConflictError
from app.services.dp_flow_service import DPFlowInputError
from app.services.dp_flow_service import DPFlowNotFoundError
from app.services.dp_flow_service import DPFlowService
from app.services import dp_flow_service as service_module


_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")


def coefficient(value: float, label: str = "test coefficient") -> TraceableCoefficient:
    """Return one explicit traceable coefficient for independent vectors."""

    return TraceableCoefficient(
        value=value,
        source_reference=f"Independent {label} record",
        applicable_conditions="Exact test geometry and operating point only",
        supplied_by="Independent engineering test",
    )


def request_identity(operation: str) -> dict[str, str]:
    """Return the mandatory reviewed identity for one operation."""

    entry = next(
        item for item in DP_FLOW_API_CATALOGUE
        if item.operation.value == operation
    )
    return {
        "operation": operation,
        "method_id": entry.method_id,
        "method_version": entry.method_version,
    }


def fluid(
    *,
    density: float = 998.0,
    viscosity: float = 0.001,
    pressure: float = 400_000.0,
    temperature: float = 293.15,
    phase: str = "liquid",
) -> FlowingFluidProperties:
    """Return explicit flowing-condition properties."""

    return FlowingFluidProperties(
        density_kg_m3=density,
        dynamic_viscosity_pa_s=viscosity,
        pressure_absolute_pa=pressure,
        temperature_k=temperature,
        phase=phase,
        property_source_reference="Independent property record",
        condition_basis="Exact test flowing condition",
    )


def application(
    *,
    assessment_id: str = "step99-test-case",
    phase: str = "liquid",
    diameter: float = 0.2,
    density: float = 998.0,
    viscosity: float = 0.001,
    pressure: float = 400_000.0,
    temperature: float = 293.15,
    minimum_flow: float = 1.0,
    normal_flow: float = 10.0,
    maximum_flow: float = 100.0,
) -> DPFlowApplicationRequest:
    """Return a sufficiently complete, explicitly safe application screen."""

    return DPFlowApplicationRequest(
        assessment_id=assessment_id,
        fluid_phase=phase,
        objective="process_control",
        pipe_inside_diameter_m=diameter,
        minimum_mass_flow_kg_s=minimum_flow,
        normal_mass_flow_kg_s=normal_flow,
        maximum_mass_flow_kg_s=maximum_flow,
        flowing_density_kg_m3=density,
        flowing_viscosity_pa_s=viscosity,
        flowing_absolute_pressure_pa=pressure,
        flowing_temperature_k=temperature,
        available_upstream_straight_run_d=20.0,
        available_downstream_straight_run_d=8.0,
        maximum_permanent_pressure_loss_pa=5_000.0,
        required_total_uncertainty_percent=2.0,
        dirty_or_solids_bearing="no",
        erosive="no",
        corrosive="no",
        pulsating_flow="no",
        bidirectional_flow="no",
        wet_gas_or_condensing="no",
        full_pipe_confirmed="yes",
        flashing_or_cavitation_risk="no",
        sonic_or_choked_flow_risk="no",
        intrusive_element_allowed="yes",
        hazardous_area="no",
        sour_or_toxic_service="no",
        oxygen_or_high_purity_service="no",
        approved_standard_or_oem_method_available="yes",
        traceable_coefficient_available="yes",
        include_proprietary_variants=True,
    )


def water_venturi_request() -> GenericVenturiTubeFlowRequest:
    """Return the independently calculated water Venturi vector."""

    return GenericVenturiTubeFlowRequest(
        **request_identity("generic_venturi_tube"),
        pipe_inside_diameter_m=0.2,
        throat_diameter_m=0.1,
        differential_pressure_pa=10_000.0,
        fluid=fluid(),
        discharge_coefficient=coefficient(0.985, "Venturi discharge"),
        expansibility_factor=coefficient(1.0, "liquid expansibility"),
    )


def steam_nozzle_request() -> GenericNozzleFlowRequest:
    """Return the independently calculated steam-nozzle vector."""

    return GenericNozzleFlowRequest(
        **request_identity("generic_nozzle"),
        pipe_inside_diameter_m=0.15,
        throat_diameter_m=0.09,
        differential_pressure_pa=25_000.0,
        fluid=fluid(
            density=6.2,
            viscosity=1.8e-5,
            pressure=1_000_000.0,
            temperature=453.15,
            phase="vapour",
        ),
        discharge_coefficient=coefficient(0.99, "nozzle discharge"),
        expansibility_factor=coefficient(0.96, "steam expansibility"),
    )


def all_requests() -> tuple[tuple[object, type[object]], ...]:
    """Return one valid request and expected result type for each operation."""

    base_fluid = fluid()
    discharge = coefficient(0.61, "orifice discharge")
    expansibility = coefficient(1.0, "liquid expansibility")
    return (
        (
            GenericOrificeFlowRequest(
                **request_identity("generic_orifice"),
                pipe_inside_diameter_m=0.2,
                bore_diameter_m=0.1,
                differential_pressure_pa=10_000.0,
                fluid=base_fluid,
                discharge_coefficient=discharge,
                expansibility_factor=expansibility,
            ),
            OrificeFlowResult,
        ),
        (
            OrificeBoreSolveRequest(
                **request_identity("orifice_bore_solver"),
                target_mass_flow_kg_s=30.0,
                pipe_inside_diameter_m=0.2,
                differential_pressure_pa=10_000.0,
                fluid=base_fluid,
                discharge_coefficient=discharge,
                expansibility_factor=expansibility,
                minimum_bore_diameter_m=0.05,
                maximum_bore_diameter_m=0.15,
            ),
            BoreSolverResult,
        ),
        (steam_nozzle_request(), CircularRestrictionFlowResult),
        (
            GenericVenturiNozzleFlowRequest(
                **request_identity("generic_venturi_nozzle"),
                **water_venturi_request().model_dump(
                    mode="python",
                    exclude={"operation", "method_id", "method_version"},
                )
            ),
            CircularRestrictionFlowResult,
        ),
        (water_venturi_request(), CircularRestrictionFlowResult),
        (
            GenericAveragingPitotFlowRequest(
                **request_identity("generic_averaging_pitot"),
                pipe_inside_diameter_m=0.6,
                differential_pressure_pa=400.0,
                fluid=base_fluid,
                meter_coefficient=coefficient(0.8, "meter coefficient"),
                expansibility_factor=expansibility,
            ),
            AveragingPitotFlowResult,
        ),
        (
            DPTransmitterRangeRequest(
                **request_identity("transmitter_range"),
                minimum_dp_pa=1_000.0,
                normal_dp_pa=10_000.0,
                maximum_dp_pa=20_000.0,
                configured_lrv_pa=0.0,
                configured_urv_pa=25_000.0,
                sensor_lrl_pa=-25_000.0,
                sensor_url_pa=25_000.0,
                minimum_required_dp_fraction_of_span=0.02,
            ),
            DPTransmitterRangeScreenResult,
        ),
        (
            PermanentPressureLossRequest(
                **request_identity("permanent_pressure_loss"),
                measured_differential_pressure_pa=10_000.0,
                permanent_loss_ratio=coefficient(0.12, "loss ratio"),
            ),
            PermanentPressureLossResult,
        ),
        (
            DPFlowUncertaintyRequest(
                **request_identity("relative_uncertainty"),
                components=(
                    RelativeUncertaintyComponent(
                        component_id="coefficient",
                        relative_standard_uncertainty_percent=0.5,
                        sensitivity_coefficient=1.0,
                        source_reference="Independent coefficient record",
                    ),
                    RelativeUncertaintyComponent(
                        component_id="transmitter",
                        relative_standard_uncertainty_percent=0.2,
                        sensitivity_coefficient=1.0,
                        source_reference="Independent transmitter record",
                    ),
                ),
                coverage_factor=2.0,
            ),
            DPFlowUncertaintyResult,
        ),
    )


def test_catalogue_registers_exactly_nine_versioned_operations() -> None:
    """The direct service has one immutable entry for each reviewed request."""

    assert len(DP_FLOW_API_CATALOGUE) == 9
    assert len(DP_FLOW_API_REGISTRY) == 9
    assert tuple(DP_FLOW_API_REGISTRY) == tuple(
        entry.operation for entry in DP_FLOW_API_CATALOGUE
    )
    assert len({entry.method_id for entry in DP_FLOW_API_CATALOGUE}) == 9
    assert len({entry.implementation_name for entry in DP_FLOW_API_CATALOGUE}) == 9
    assert all(entry.executable for entry in DP_FLOW_API_CATALOGUE)
    assert all(entry.lifecycle_status == "approved" for entry in DP_FLOW_API_CATALOGUE)
    assert all(not entry.standards_conformity_claimed for entry in DP_FLOW_API_CATALOGUE)


def test_workflow_module_exports_only_explicit_public_contracts() -> None:
    """The Step 99 module cannot expose helpers through a dynamic wildcard."""

    assert len(workflow_module.__all__) == len(set(workflow_module.__all__))
    assert all(not name.startswith("_") for name in workflow_module.__all__)
    assert all(hasattr(workflow_module, name) for name in workflow_module.__all__)


def test_three_iso_discovery_adapters_remain_inert_and_disjoint() -> None:
    """Standards-review metadata has no callable entry in the API registry."""

    assert len(DP_FLOW_DISCOVERY_ENTRIES) == 3
    executable_ids = {entry.method_id for entry in DP_FLOW_API_CATALOGUE}
    for adapter in DP_FLOW_DISCOVERY_ENTRIES:
        assert adapter.adapter_id not in executable_ids
        assert adapter.lifecycle_status == "standards_review"
        assert adapter.executable is False
        assert adapter.conformity_claimed is False


def test_twelve_knowledge_links_are_inert_no_network_metadata() -> None:
    """Public links cannot be confused with executable coefficient evidence."""

    assert len(DP_FLOW_KNOWLEDGE_LINKS) == 12
    assert len({link.source_id for link in DP_FLOW_KNOWLEDGE_LINKS}) == 12
    for link in DP_FLOW_KNOWLEDGE_LINKS:
        assert link.retrieval_mode == "inert_metadata_only"
        assert link.network_access_performed is False
        assert link.approved_as_coefficient_source is False
        assert link.executable is False
        assert link.conformity_evidence is False
        assert link.standards_conformity_claimed is False
        assert link.public_url.startswith("https://")
        assert link.usage_boundary


def test_stored_examples_are_exact_bounded_review_fixtures() -> None:
    """Example identities bind their exact revision and normalized content."""

    assert len(DP_FLOW_STORED_DESIGN_CASE_EXAMPLES) == 3
    assert len(DP_FLOW_STORED_EXAMPLE_REGISTRY) == 3
    assert tuple(
        example.example_id
        for example in DP_FLOW_STORED_DESIGN_CASE_EXAMPLES
    ) == (
        "dp-example.liquid-orifice",
        "dp-example.steam-nozzle",
        "dp-example.large-pipe-averaging-pitot",
    )
    for example in DP_FLOW_STORED_DESIGN_CASE_EXAMPLES:
        assert example.illustrative_only is True
        assert example.approved_for_project_use is False
        assert example.example_fingerprint == build_stored_example_fingerprint(
            example.example_id,
            example.revision,
            example.design_case,
        )
        assert _FINGERPRINT.fullmatch(example.example_fingerprint)


@pytest.mark.parametrize(
    ("execution_request", "result_type"),
    all_requests(),
)
def test_service_executes_all_nine_exact_operations(
    execution_request: object,
    result_type: type[object],
) -> None:
    """Every reviewed request reaches only its statically bound calculator."""

    outcome = DEFAULT_DP_FLOW_SERVICE.execute(  # type: ignore[arg-type]
        execution_request
    )

    assert isinstance(outcome.result, result_type)
    assert outcome.normalized_request == execution_request
    assert outcome.trace.operation.value == (  # type: ignore[attr-defined]
        execution_request.operation
    )
    assert outcome.trace.method_id == (  # type: ignore[attr-defined]
        execution_request.method_id
    )
    assert outcome.trace.method_version == (  # type: ignore[attr-defined]
        execution_request.method_version
    )
    assert _FINGERPRINT.fullmatch(outcome.trace.normalized_input_fingerprint)
    assert _FINGERPRINT.fullmatch(outcome.trace.result_fingerprint)
    assert _FINGERPRINT.fullmatch(outcome.trace.attempt_fingerprint)
    assert outcome.trace.standards_conformity_claimed is False
    assert outcome.trace.standards_adapter_execution_count == 0
    assert outcome.trace.coefficient_derivation_performed is False
    assert outcome.trace.manufacturer_selection_performed is False
    assert outcome.coefficient_derivation_performed is False
    assert outcome.manufacturer_selection_performed is False
    assert outcome.standards_conformity_claimed is False
    assert DPFlowExecutionOutcome.model_validate(
        outcome.model_dump(mode="json")
    ) == outcome
    forged = outcome.model_dump(mode="python")
    forged["standards_conformity_claimed"] = True
    with pytest.raises(ValidationError):
        DPFlowExecutionOutcome.model_validate(forged)
    forged = outcome.model_dump(mode="python")
    forged["trace"]["standards_adapter_execution_count"] = 1
    with pytest.raises(ValidationError):
        DPFlowExecutionOutcome.model_validate(forged)


def test_wrong_method_version_is_rejected_without_fallback() -> None:
    """No request can select an implicit latest or neighboring version."""

    payload = water_venturi_request().model_dump(mode="python")
    payload["method_version"] = "9.9.9"

    with pytest.raises(ValidationError):
        validate_execution_request(payload)
    with pytest.raises(DPFlowInputError):
        DEFAULT_DP_FLOW_SERVICE.execute(payload)  # type: ignore[arg-type]


@pytest.mark.parametrize("missing", ("operation", "method_id", "method_version"))
def test_exact_method_identity_is_mandatory_without_current_version_fallback(
    missing: str,
) -> None:
    """Omitted identity fields never select the currently registered method."""

    payload = water_venturi_request().model_dump(mode="python")
    payload.pop(missing)

    with pytest.raises(ValidationError):
        validate_execution_request(payload)
    with pytest.raises(DPFlowInputError):
        DEFAULT_DP_FLOW_SERVICE.execute(payload)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "adapter_id",
    tuple(adapter.adapter_id for adapter in DP_FLOW_DISCOVERY_ENTRIES),
)
def test_iso_discovery_adapter_ids_cannot_execute(adapter_id: str) -> None:
    """Known standards metadata cannot cross the executable request union."""

    payload = water_venturi_request().model_dump(mode="python")
    payload["method_id"] = adapter_id

    with pytest.raises(ValidationError):
        validate_execution_request(payload)
    with pytest.raises(DPFlowInputError):
        DEFAULT_DP_FLOW_SERVICE.execute(payload)  # type: ignore[arg-type]


def test_execution_fingerprints_are_stable_and_input_sensitive() -> None:
    """Identical normalized inputs reproduce all fingerprints exactly."""

    request = water_venturi_request()
    first = DEFAULT_DP_FLOW_SERVICE.execute(request)
    second = DEFAULT_DP_FLOW_SERVICE.execute(
        validate_execution_request(request.model_dump(mode="json"))
    )

    assert first == second
    changed = DEFAULT_DP_FLOW_SERVICE.execute(
        request.model_copy(update={"differential_pressure_pa": 10_001.0})
    )
    assert changed.trace.normalized_input_fingerprint != (
        first.trace.normalized_input_fingerprint
    )
    assert changed.trace.result_fingerprint != first.trace.result_fingerprint
    assert changed.trace.attempt_fingerprint != first.trace.attempt_fingerprint


def test_signed_zero_has_one_normalized_input_fingerprint() -> None:
    """JSON-equivalent positive and negative zero share one canonical trace."""

    request = next(
        item for item, _ in all_requests()
        if isinstance(item, DPTransmitterRangeRequest)
    )
    positive_payload = request.model_dump(mode="python")
    negative_payload = request.model_dump(mode="python")
    positive_payload["configured_lrv_pa"] = 0.0
    negative_payload["configured_lrv_pa"] = -0.0
    positive = validate_execution_request(positive_payload)
    negative = validate_execution_request(negative_payload)

    assert positive == negative
    assert positive.configured_lrv_pa == 0.0
    assert str(negative.configured_lrv_pa) == "0.0"
    assert build_input_fingerprint(positive) == build_input_fingerprint(negative)


def test_result_fingerprint_repeats_in_a_fresh_python_process() -> None:
    """Hash randomization and process state cannot alter the result trace."""

    example = DP_FLOW_STORED_DESIGN_CASE_EXAMPLES[0]
    expected = DEFAULT_DP_FLOW_SERVICE.execute(
        example.design_case.execution_request
    ).trace.result_fingerprint
    program = (
        "from app.engineering.calculations.dp_flow_workflow_models import "
        "DP_FLOW_STORED_DESIGN_CASE_EXAMPLES; "
        "from app.services.dp_flow_service import DEFAULT_DP_FLOW_SERVICE; "
        "item=DP_FLOW_STORED_DESIGN_CASE_EXAMPLES[0]; "
        "print(DEFAULT_DP_FLOW_SERVICE.execute("
        "item.design_case.execution_request).trace.result_fingerprint)"
    )

    completed = subprocess.run(
        [sys.executable, "-c", program],
        cwd=Path(__file__).resolve().parents[1],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stderr == ""
    assert completed.stdout.strip() == expected


def test_water_venturi_reference_vector() -> None:
    """The service reproduces an independently evaluated liquid vector."""

    outcome = DEFAULT_DP_FLOW_SERVICE.execute(water_venturi_request())

    assert isinstance(outcome.result, CircularRestrictionFlowResult)
    assert outcome.result.primary_element == "venturi_tube"
    assert outcome.result.mass_flow_kg_s == pytest.approx(
        35.696097744126654,
        rel=1e-12,
    )
    assert outcome.result.actual_volumetric_flow_m3_s == pytest.approx(
        0.035767633010146946,
        rel=1e-12,
    )
    assert outcome.result.standards_conformity_claimed is False
    assert outcome.trace.normalized_input_fingerprint == (
        "0de75ed2fa80c86fde41fd61a433086342f3cb9d1a2a27086f311105c4b4dd0b"
    )
    assert outcome.trace.result_fingerprint == (
        "35ead1453bfbf0e9296dbadac0657577bc1f7107b00db3de57f5b63258390510"
    )
    assert outcome.trace.attempt_fingerprint == (
        "009de33e8616e8138df566f401290cb0ea980260f8c44c314b433d6308e933ce"
    )


def test_steam_nozzle_reference_vector() -> None:
    """The service reproduces an independently evaluated vapour vector."""

    outcome = DEFAULT_DP_FLOW_SERVICE.execute(steam_nozzle_request())

    assert isinstance(outcome.result, CircularRestrictionFlowResult)
    assert outcome.result.primary_element == "flow_nozzle"
    assert outcome.result.mass_flow_kg_s == pytest.approx(
        3.6083007917347776,
        rel=1e-12,
    )
    assert outcome.result.actual_volumetric_flow_m3_s == pytest.approx(
        0.5819839986668995,
        rel=1e-12,
    )
    assert outcome.result.standards_conformity_claimed is False
    assert outcome.trace.normalized_input_fingerprint == (
        "458c6559406171e466f8785ad4a806920fb380497764fbcec2eb1dd218c1fa10"
    )
    assert outcome.trace.result_fingerprint == (
        "78f926e389a5d8faf2b91277e25c7c10988977a5b42c425ca921ef18d85af0f4"
    )
    assert outcome.trace.attempt_fingerprint == (
        "8cfe797337c179d366ffefe6ca50424917e5b158782e63d220a09fc045fd7e42"
    )


def test_stateless_and_stored_replay_have_equal_technical_fingerprints() -> None:
    """Source mode does not change a reviewed case's engineering result."""

    example = DP_FLOW_STORED_DESIGN_CASE_EXAMPLES[1]
    stateless = DEFAULT_DP_FLOW_SERVICE.evaluate_design_case(
        example.design_case
    )
    stored = DEFAULT_DP_FLOW_SERVICE.evaluate_stored_design_case(
        DPFlowStoredDesignCaseReplayRequest(
            example_id=example.example_id,
            revision=example.revision,
            example_fingerprint=example.example_fingerprint,
        )
    )

    assert stateless.execution_mode == "stateless"
    assert stored.execution_mode == "stored_example_replay"
    assert stored.stored_example_id == example.example_id
    assert stored.stored_example_revision == example.revision
    assert stateless.calculation.trace.result_fingerprint == (
        stored.calculation.trace.result_fingerprint
    )
    assert stateless.calculation.trace.attempt_fingerprint == (
        stored.calculation.trace.attempt_fingerprint
    )
    assert stateless.design_case_fingerprint == stored.design_case_fingerprint
    assert stateless.standards_conformity_claimed is False
    assert stored.standards_conformity_claimed is False
    assert stored.manufacturer_declared_best is False
    assert stored.final_brand_selection == "user_decision_required"


def test_stored_replay_requires_exact_revision_and_digest() -> None:
    """Stored fixtures have no latest-version or digest fallback."""

    example = DP_FLOW_STORED_DESIGN_CASE_EXAMPLES[0]
    with pytest.raises(DPFlowConflictError):
        DEFAULT_DP_FLOW_SERVICE.evaluate_stored_design_case(
            DPFlowStoredDesignCaseReplayRequest(
                example_id=example.example_id,
                revision=example.revision + 1,
                example_fingerprint=example.example_fingerprint,
            )
        )
    with pytest.raises(DPFlowConflictError):
        DEFAULT_DP_FLOW_SERVICE.evaluate_stored_design_case(
            DPFlowStoredDesignCaseReplayRequest(
                example_id=example.example_id,
                revision=example.revision,
                example_fingerprint="0" * 64,
            )
        )
    with pytest.raises(DPFlowNotFoundError):
        DEFAULT_DP_FLOW_SERVICE.evaluate_stored_design_case(
            DPFlowStoredDesignCaseReplayRequest(
                example_id="dp-example.unknown",
                revision=1,
                example_fingerprint="0" * 64,
            )
        )


def test_water_venturi_design_case_is_reproducible_end_to_end() -> None:
    """Wizard screening and calculation share one stable design trace."""

    request = DPFlowDesignCaseRequest(
        application_request=application(),
        selected_generic_option_id="generic.venturi.classical",
        execution_request=water_venturi_request(),
    )

    first = DEFAULT_DP_FLOW_SERVICE.evaluate_design_case(request)
    second = DEFAULT_DP_FLOW_SERVICE.evaluate_design_case(request)

    assert first == second
    assert first.execution_mode == "stateless"
    assert first.calculation.result.mass_flow_kg_s == pytest.approx(
        35.696097744126654,
        rel=1e-12,
    )
    assert first.application_assessment.manufacturer_declared_best is False
    assert first.application_assessment.final_brand_selection == (
        "user_decision_required"
    )
    assert first.application_assessment.standards_conformity_claimed is False
    assert _FINGERPRINT.fullmatch(first.design_case_fingerprint)


def test_steam_nozzle_design_case_carries_steam_safety_findings() -> None:
    """End-to-end steam calculation retains stored-energy precautions."""

    request = DPFlowDesignCaseRequest(
        application_request=application(
            phase="steam",
            diameter=0.15,
            density=6.2,
            viscosity=1.8e-5,
            pressure=1_000_000.0,
            temperature=453.15,
        ),
        selected_generic_option_id="generic.nozzle.isa-or-long-radius",
        execution_request=steam_nozzle_request(),
    )

    outcome = DEFAULT_DP_FLOW_SERVICE.evaluate_design_case(request)

    assert outcome.calculation.result.mass_flow_kg_s == pytest.approx(
        3.6083007917347776,
        rel=1e-12,
    )
    safety_text = " ".join(outcome.application_assessment.safety_findings)
    assert "stored-energy" in safety_text
    assert "condensate" in safety_text


def test_owned_selection_and_unsafe_application_fail_closed() -> None:
    """Owned options and unresolved process hazards never reach calculators."""

    payload = {
        "application_request": application().model_dump(mode="python"),
        "selected_generic_option_id": "owned.emerson-rosemount.annubar",
        "execution_request": water_venturi_request().model_dump(mode="python"),
    }
    with pytest.raises(ValidationError):
        DPFlowDesignCaseRequest.model_validate(payload)

    unsafe_application = DPFlowApplicationRequest.model_validate(
        application().model_copy(
            update={"full_pipe_confirmed": "no"}
        ).model_dump(mode="python")
    )
    unsafe_case = DPFlowDesignCaseRequest(
        application_request=unsafe_application,
        selected_generic_option_id="generic.venturi.classical",
        execution_request=water_venturi_request(),
    )
    with pytest.raises(DPFlowInputError):
        DEFAULT_DP_FLOW_SERVICE.evaluate_design_case(unsafe_case)


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("full_pipe_confirmed", "no"),
        ("flashing_or_cavitation_risk", "yes"),
        ("sonic_or_choked_flow_risk", "yes"),
        ("intrusive_element_allowed", "no"),
        ("wet_gas_or_condensing", "yes"),
        ("pulsating_flow", "yes"),
        ("bidirectional_flow", "yes"),
        ("traceable_coefficient_available", "no"),
        ("full_pipe_confirmed", "unknown"),
        ("flashing_or_cavitation_risk", "unknown"),
        ("sonic_or_choked_flow_risk", "unknown"),
        ("intrusive_element_allowed", "unknown"),
        ("wet_gas_or_condensing", "unknown"),
        ("pulsating_flow", "unknown"),
        ("bidirectional_flow", "unknown"),
        ("traceable_coefficient_available", "unknown"),
    ),
)
def test_unresolved_design_hazards_are_blocked_before_dispatch(
    field: str,
    unsafe_value: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every explicit design prerequisite is resolved before calculation."""

    payload = application().model_dump(mode="python")
    payload[field] = unsafe_value
    unsafe_application = DPFlowApplicationRequest.model_validate(payload)
    request = DPFlowDesignCaseRequest(
        application_request=unsafe_application,
        selected_generic_option_id="generic.venturi.classical",
        execution_request=water_venturi_request(),
    )
    calls = 0

    def unexpected_dispatch(_: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("unsafe request reached the calculation dispatcher")

    monkeypatch.setattr(service_module, "_dispatch", unexpected_dispatch)
    with pytest.raises(DPFlowInputError):
        DEFAULT_DP_FLOW_SERVICE.evaluate_design_case(request)
    assert calls == 0


@pytest.mark.parametrize(
    ("minimum_flow", "normal_flow", "maximum_flow"),
    (
        (40.0, 50.0, 60.0),
        (1.0, 20.0, 30.0),
    ),
)
def test_calculated_flow_outside_application_envelope_fails_closed(
    minimum_flow: float,
    normal_flow: float,
    maximum_flow: float,
) -> None:
    """A valid equation result cannot escape the declared design envelope."""

    request = DPFlowDesignCaseRequest(
        application_request=application(
            minimum_flow=minimum_flow,
            normal_flow=normal_flow,
            maximum_flow=maximum_flow,
        ),
        selected_generic_option_id="generic.venturi.classical",
        execution_request=water_venturi_request(),
    )

    with pytest.raises(DPFlowInputError):
        DEFAULT_DP_FLOW_SERVICE.evaluate_design_case(request)


def test_flow_envelope_endpoints_are_inclusive() -> None:
    """Reviewed minimum and maximum operating points remain executable."""

    mass_flow = DEFAULT_DP_FLOW_SERVICE.execute(
        water_venturi_request()
    ).result.mass_flow_kg_s
    for minimum_flow, normal_flow, maximum_flow in (
        (mass_flow, mass_flow, 100.0),
        (1.0, mass_flow, mass_flow),
    ):
        request = DPFlowDesignCaseRequest(
            application_request=application(
                minimum_flow=minimum_flow,
                normal_flow=normal_flow,
                maximum_flow=maximum_flow,
            ),
            selected_generic_option_id="generic.venturi.classical",
            execution_request=water_venturi_request(),
        )
        assert DEFAULT_DP_FLOW_SERVICE.evaluate_design_case(request)


def test_bore_target_outside_application_envelope_is_blocked_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The solver target is authorized against the application before work."""

    solver = next(
        item for item, _ in all_requests()
        if isinstance(item, OrificeBoreSolveRequest)
    )
    payload = solver.model_dump(mode="python")
    payload["target_mass_flow_kg_s"] = 0.5
    request = DPFlowDesignCaseRequest(
        application_request=application(),
        selected_generic_option_id="generic.orifice.concentric-square-edge",
        execution_request=OrificeBoreSolveRequest.model_validate(payload),
    )
    calls = 0

    def unexpected_dispatch(_: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("out-of-envelope solver target reached dispatcher")

    monkeypatch.setattr(service_module, "_dispatch", unexpected_dispatch)
    with pytest.raises(DPFlowInputError):
        DEFAULT_DP_FLOW_SERVICE.evaluate_design_case(request)
    assert calls == 0


def test_primary_element_and_operation_mismatch_fails_closed() -> None:
    """A valid calculator cannot be substituted for another element family."""

    request = DPFlowDesignCaseRequest(
        application_request=application(),
        selected_generic_option_id="generic.venturi.classical",
        execution_request=steam_nozzle_request(),
    )

    with pytest.raises(DPFlowInputError):
        DEFAULT_DP_FLOW_SERVICE.evaluate_design_case(request)


def test_requests_reject_extras_nonfinite_values_and_unbounded_components() -> None:
    """The workflow union remains strict, finite, and collection bounded."""

    payload = water_venturi_request().model_dump(mode="python")
    payload["private_callable"] = "not allowed"
    with pytest.raises(ValidationError):
        validate_execution_request(payload)

    payload = water_venturi_request().model_dump(mode="python")
    payload["differential_pressure_pa"] = float("nan")
    with pytest.raises(ValidationError):
        validate_execution_request(payload)

    component = RelativeUncertaintyComponent(
        component_id="component",
        relative_standard_uncertainty_percent=0.1,
        sensitivity_coefficient=1.0,
        source_reference="Independent record",
    )
    with pytest.raises(ValidationError):
        DPFlowUncertaintyRequest(
            **request_identity("relative_uncertainty"),
            components=(component,) * 65,
        )


def test_operation_mapping_and_execution_outcome_trace_are_immutable() -> None:
    """Shared authorization and returned traces cannot be forged after dispatch."""

    with pytest.raises(TypeError):
        service_module._OPTION_OPERATIONS[  # type: ignore[index]
            "generic.venturi.classical"
        ] = frozenset()

    outcome = DEFAULT_DP_FLOW_SERVICE.execute(water_venturi_request())
    forged = outcome.model_dump(mode="python")
    forged["trace"]["result_fingerprint"] = "0" * 64
    with pytest.raises(ValidationError, match="fingerprints"):
        DPFlowExecutionOutcome.model_validate(forged)


def test_service_and_returned_models_are_immutable_and_detached() -> None:
    """Callers cannot replace dependencies or mutate shared registry models."""

    service = DPFlowService()
    with pytest.raises(AttributeError):
        service._locked = False  # type: ignore[misc]
    catalogue = service.get_catalogue()
    assert catalogue == DP_FLOW_API_CATALOGUE
    assert catalogue is not DP_FLOW_API_CATALOGUE
    assert all(
        returned is not source
        for returned, source in zip(catalogue, DP_FLOW_API_CATALOGUE)
    )
