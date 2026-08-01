"""Immutable Step 99 service for the DP-flow workflow.

Stored design cases in this module are reviewed, immutable examples compiled
into the application.  They are not database persistence and cannot be
created, updated, or deleted through this service.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, TypeVar

from pydantic import BaseModel, ValidationError

from app.engineering.calculations.dp_flow import DPFlowCalculationError
from app.engineering.calculations.dp_flow import calculate_generic_averaging_pitot_flow
from app.engineering.calculations.dp_flow import calculate_generic_nozzle_flow
from app.engineering.calculations.dp_flow import calculate_generic_orifice_flow
from app.engineering.calculations.dp_flow import calculate_generic_venturi_nozzle_flow
from app.engineering.calculations.dp_flow import calculate_generic_venturi_tube_flow
from app.engineering.calculations.dp_flow import calculate_permanent_pressure_loss
from app.engineering.calculations.dp_flow import combine_dp_flow_relative_uncertainty
from app.engineering.calculations.dp_flow import screen_dp_transmitter_range
from app.engineering.calculations.dp_flow import solve_orifice_bore_for_mass_flow
from app.engineering.calculations.dp_flow_workflow_models import DPFlowDesignCaseOutcome
from app.engineering.calculations.dp_flow_workflow_models import DPFlowDesignCaseRequest
from app.engineering.calculations.dp_flow_workflow_models import DPFlowExecutionOutcome
from app.engineering.calculations.dp_flow_workflow_models import DPFlowExecutionRequest
from app.engineering.calculations.dp_flow_workflow_models import DPFlowExecutionTrace
from app.engineering.calculations.dp_flow_workflow_models import DPFlowKnowledgeLink
from app.engineering.calculations.dp_flow_workflow_models import DPFlowMethodCatalogueEntry
from app.engineering.calculations.dp_flow_workflow_models import DPFlowOperation
from app.engineering.calculations.dp_flow_workflow_models import DPFlowStoredDesignCaseExample
from app.engineering.calculations.dp_flow_workflow_models import DPFlowStoredDesignCaseReplayRequest
from app.engineering.calculations.dp_flow_workflow_models import DP_FLOW_API_CATALOGUE
from app.engineering.calculations.dp_flow_workflow_models import DP_FLOW_API_REGISTRY
from app.engineering.calculations.dp_flow_workflow_models import DP_FLOW_KNOWLEDGE_LINKS
from app.engineering.calculations.dp_flow_workflow_models import DP_FLOW_STORED_DESIGN_CASE_EXAMPLES
from app.engineering.calculations.dp_flow_workflow_models import DP_FLOW_STORED_EXAMPLE_REGISTRY
from app.engineering.calculations.dp_flow_workflow_models import DPTransmitterRangeRequest
from app.engineering.calculations.dp_flow_workflow_models import DPFlowUncertaintyRequest
from app.engineering.calculations.dp_flow_workflow_models import GenericAveragingPitotFlowRequest
from app.engineering.calculations.dp_flow_workflow_models import GenericNozzleFlowRequest
from app.engineering.calculations.dp_flow_workflow_models import GenericOrificeFlowRequest
from app.engineering.calculations.dp_flow_workflow_models import GenericVenturiNozzleFlowRequest
from app.engineering.calculations.dp_flow_workflow_models import GenericVenturiTubeFlowRequest
from app.engineering.calculations.dp_flow_workflow_models import OrificeBoreSolveRequest
from app.engineering.calculations.dp_flow_workflow_models import PermanentPressureLossRequest
from app.engineering.calculations.dp_flow_workflow_models import build_attempt_fingerprint
from app.engineering.calculations.dp_flow_workflow_models import build_design_case_fingerprint
from app.engineering.calculations.dp_flow_workflow_models import build_input_fingerprint
from app.engineering.calculations.dp_flow_workflow_models import build_result_fingerprint
from app.engineering.calculations.dp_flow_workflow_models import validate_execution_request
from app.engineering.design.dp_flow_application_models import DPFlowApplicationAssessment
from app.engineering.design.dp_flow_application_models import DPFlowApplicationRequest
from app.engineering.design.dp_flow_application_models import DPOwnershipType
from app.engineering.design.dp_flow_application_models import DPScenarioDisposition
from app.engineering.design.dp_flow_application_models import DPTriState
from app.engineering.design.dp_flow_application_wizard import assess_dp_flow_application


_ModelT = TypeVar("_ModelT", bound=BaseModel)


class DPFlowServiceError(RuntimeError):
    """Sanitized base error for a controlled DP-flow service failure."""

    code = "dp_flow_service_unavailable"

    def __init__(self) -> None:
        super().__init__("The controlled DP-flow service is unavailable.")


class DPFlowNotFoundError(DPFlowServiceError):
    """An exact immutable DP-flow resource does not exist."""

    code = "dp_flow_resource_not_found"

    def __init__(self) -> None:
        RuntimeError.__init__(self, "The requested DP-flow resource was not found.")


class DPFlowConflictError(DPFlowServiceError):
    """Stored example revision, fingerprint, or replay result conflicted."""

    code = "dp_flow_resource_conflict"

    def __init__(self) -> None:
        RuntimeError.__init__(self, "The DP-flow resource identity conflicts with its reviewed revision.")


class DPFlowInputError(DPFlowServiceError):
    """A typed request is unsafe, incompatible, or outside the supported boundary."""

    code = "dp_flow_input_error"

    def __init__(self) -> None:
        RuntimeError.__init__(self, "The DP-flow request is invalid.")


def _fresh(model_type: type[_ModelT], value: object) -> _ModelT:
    if not isinstance(value, BaseModel):
        raise TypeError("service boundaries require typed models")
    return model_type.model_validate(
        value.model_dump(mode="python", round_trip=True, warnings="error")
    )


def _dispatch(request: DPFlowExecutionRequest) -> BaseModel:
    """Dispatch only the nine statically reviewed request types."""

    if isinstance(request, GenericOrificeFlowRequest):
        return calculate_generic_orifice_flow(
            pipe_inside_diameter_m=request.pipe_inside_diameter_m,
            bore_diameter_m=request.bore_diameter_m,
            differential_pressure_pa=request.differential_pressure_pa,
            fluid=request.fluid,
            discharge_coefficient=request.discharge_coefficient,
            expansibility_factor=request.expansibility_factor,
        )
    if isinstance(request, OrificeBoreSolveRequest):
        return solve_orifice_bore_for_mass_flow(
            target_mass_flow_kg_s=request.target_mass_flow_kg_s,
            pipe_inside_diameter_m=request.pipe_inside_diameter_m,
            differential_pressure_pa=request.differential_pressure_pa,
            fluid=request.fluid,
            discharge_coefficient=request.discharge_coefficient,
            expansibility_factor=request.expansibility_factor,
            minimum_bore_diameter_m=request.minimum_bore_diameter_m,
            maximum_bore_diameter_m=request.maximum_bore_diameter_m,
            relative_tolerance=request.relative_tolerance,
            maximum_iterations=request.maximum_iterations,
        )
    if isinstance(request, GenericNozzleFlowRequest):
        return calculate_generic_nozzle_flow(
            pipe_inside_diameter_m=request.pipe_inside_diameter_m,
            throat_diameter_m=request.throat_diameter_m,
            differential_pressure_pa=request.differential_pressure_pa,
            fluid=request.fluid,
            discharge_coefficient=request.discharge_coefficient,
            expansibility_factor=request.expansibility_factor,
        )
    if isinstance(request, GenericVenturiNozzleFlowRequest):
        return calculate_generic_venturi_nozzle_flow(
            pipe_inside_diameter_m=request.pipe_inside_diameter_m,
            throat_diameter_m=request.throat_diameter_m,
            differential_pressure_pa=request.differential_pressure_pa,
            fluid=request.fluid,
            discharge_coefficient=request.discharge_coefficient,
            expansibility_factor=request.expansibility_factor,
        )
    if isinstance(request, GenericVenturiTubeFlowRequest):
        return calculate_generic_venturi_tube_flow(
            pipe_inside_diameter_m=request.pipe_inside_diameter_m,
            throat_diameter_m=request.throat_diameter_m,
            differential_pressure_pa=request.differential_pressure_pa,
            fluid=request.fluid,
            discharge_coefficient=request.discharge_coefficient,
            expansibility_factor=request.expansibility_factor,
        )
    if isinstance(request, GenericAveragingPitotFlowRequest):
        return calculate_generic_averaging_pitot_flow(
            pipe_inside_diameter_m=request.pipe_inside_diameter_m,
            differential_pressure_pa=request.differential_pressure_pa,
            fluid=request.fluid,
            meter_coefficient=request.meter_coefficient,
            expansibility_factor=request.expansibility_factor,
        )
    if isinstance(request, DPTransmitterRangeRequest):
        return screen_dp_transmitter_range(
            minimum_dp_pa=request.minimum_dp_pa,
            normal_dp_pa=request.normal_dp_pa,
            maximum_dp_pa=request.maximum_dp_pa,
            configured_lrv_pa=request.configured_lrv_pa,
            configured_urv_pa=request.configured_urv_pa,
            sensor_lrl_pa=request.sensor_lrl_pa,
            sensor_url_pa=request.sensor_url_pa,
            minimum_required_dp_fraction_of_span=request.minimum_required_dp_fraction_of_span,
        )
    if isinstance(request, PermanentPressureLossRequest):
        return calculate_permanent_pressure_loss(
            measured_differential_pressure_pa=request.measured_differential_pressure_pa,
            permanent_loss_ratio=request.permanent_loss_ratio,
        )
    if isinstance(request, DPFlowUncertaintyRequest):
        return combine_dp_flow_relative_uncertainty(
            components=request.components,
            coverage_factor=request.coverage_factor,
        )
    raise TypeError("unregistered DP-flow request type")


_OPTION_OPERATIONS: Final = MappingProxyType({
    "generic.orifice.concentric-square-edge": frozenset({
        DPFlowOperation.GENERIC_ORIFICE,
        DPFlowOperation.ORIFICE_BORE_SOLVER,
    }),
    "generic.nozzle.isa-or-long-radius": frozenset({
        DPFlowOperation.GENERIC_NOZZLE,
    }),
    "generic.venturi-nozzle": frozenset({
        DPFlowOperation.GENERIC_VENTURI_NOZZLE,
    }),
    "generic.venturi.classical": frozenset({
        DPFlowOperation.GENERIC_VENTURI_TUBE,
    }),
    "generic.averaging-pitot": frozenset({
        DPFlowOperation.GENERIC_AVERAGING_PITOT,
    }),
})


class DPFlowService:
    """Immutable no-network, no-persistence boundary for Step 99."""

    __slots__ = ("_locked",)

    def __init__(self) -> None:
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("DPFlowService instances are immutable.")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("DPFlowService instances are immutable.")
        object.__delattr__(self, name)

    def get_catalogue(self) -> tuple[DPFlowMethodCatalogueEntry, ...]:
        return tuple(_fresh(DPFlowMethodCatalogueEntry, item) for item in DP_FLOW_API_CATALOGUE)

    def get_knowledge_links(self) -> tuple[DPFlowKnowledgeLink, ...]:
        return tuple(_fresh(DPFlowKnowledgeLink, item) for item in DP_FLOW_KNOWLEDGE_LINKS)

    def get_design_case_examples(self) -> tuple[DPFlowStoredDesignCaseExample, ...]:
        return tuple(_fresh(DPFlowStoredDesignCaseExample, item) for item in DP_FLOW_STORED_DESIGN_CASE_EXAMPLES)

    def execute(self, request: DPFlowExecutionRequest) -> DPFlowExecutionOutcome:
        try:
            normalized = validate_execution_request(request)
            operation = DPFlowOperation(normalized.operation)
            metadata = DP_FLOW_API_REGISTRY[operation]
            if normalized.method_id != metadata.method_id or normalized.method_version != metadata.method_version:
                raise ValueError("method identity mismatch")
            result = _dispatch(normalized)
            input_fingerprint = build_input_fingerprint(normalized)
            result_fingerprint = build_result_fingerprint(
                normalized, result, metadata.knowledge_source_ids
            )
            trace = DPFlowExecutionTrace(
                operation=operation,
                method_id=metadata.method_id,
                method_version=metadata.method_version,
                implementation_name=metadata.implementation_name,
                normalized_input_fingerprint=input_fingerprint,
                result_fingerprint=result_fingerprint,
                attempt_fingerprint=build_attempt_fingerprint(
                    input_fingerprint, result_fingerprint
                ),
                knowledge_source_ids=metadata.knowledge_source_ids,
            )
            return DPFlowExecutionOutcome(
                normalized_request=normalized,
                result=result,
                trace=trace,
            )
        except (ValidationError, ValueError, TypeError, DPFlowCalculationError) as exc:
            raise DPFlowInputError() from exc
        except DPFlowServiceError:
            raise
        except Exception as exc:
            raise DPFlowServiceError() from exc

    def assess_application(
        self, request: DPFlowApplicationRequest
    ) -> DPFlowApplicationAssessment:
        try:
            normalized = _fresh(DPFlowApplicationRequest, request)
            return _fresh(
                DPFlowApplicationAssessment,
                assess_dp_flow_application(normalized),
            )
        except (ValidationError, ValueError, TypeError) as exc:
            raise DPFlowInputError() from exc
        except Exception as exc:
            raise DPFlowServiceError() from exc

    @staticmethod
    def _authorize_design_case(
        request: DPFlowDesignCaseRequest,
        assessment: DPFlowApplicationAssessment,
    ) -> None:
        application = request.application_request
        if (
            application.full_pipe_confirmed is not DPTriState.YES
            or application.flashing_or_cavitation_risk is not DPTriState.NO
            or application.sonic_or_choked_flow_risk is not DPTriState.NO
            or application.intrusive_element_allowed is not DPTriState.YES
            or application.wet_gas_or_condensing is not DPTriState.NO
            or application.pulsating_flow is not DPTriState.NO
            or application.bidirectional_flow is not DPTriState.NO
            or application.traceable_coefficient_available is not DPTriState.YES
        ):
            raise DPFlowInputError()
        scenario = next(
            (
                item for item in assessment.all_screened_options
                if item.option.option_id == request.selected_generic_option_id
            ),
            None,
        )
        if (
            scenario is None
            or scenario.option.ownership_type is not DPOwnershipType.GENERIC_TECHNOLOGY
            or scenario.disposition in {
                DPScenarioDisposition.REJECTED,
                DPScenarioDisposition.INSUFFICIENT_INFORMATION,
            }
        ):
            raise DPFlowInputError()
        allowed = _OPTION_OPERATIONS.get(request.selected_generic_option_id)
        operation = DPFlowOperation(request.execution_request.operation)
        if allowed is None or operation not in allowed:
            raise DPFlowInputError()

        execution = request.execution_request
        execution_pipe = getattr(execution, "pipe_inside_diameter_m", None)
        if (
            application.pipe_inside_diameter_m is None
            or execution_pipe is None
            or execution_pipe != application.pipe_inside_diameter_m
        ):
            raise DPFlowInputError()

        fluid = getattr(execution, "fluid", None)
        if fluid is None:
            raise DPFlowInputError()
        application_properties = (
            application.flowing_density_kg_m3,
            application.flowing_viscosity_pa_s,
            application.flowing_absolute_pressure_pa,
            application.flowing_temperature_k,
        )
        execution_properties = (
            fluid.density_kg_m3,
            fluid.dynamic_viscosity_pa_s,
            fluid.pressure_absolute_pa,
            fluid.temperature_k,
        )
        if any(value is None for value in application_properties):
            raise DPFlowInputError()
        if application_properties != execution_properties:
            raise DPFlowInputError()

        application_phase = application.fluid_phase.value
        compatible_phases = {
            "liquid": frozenset({"liquid"}),
            "gas": frozenset({"gas", "vapour"}),
            "steam": frozenset({"gas", "vapour"}),
            "vapour": frozenset({"gas", "vapour"}),
        }
        if fluid.phase not in compatible_phases.get(application_phase, frozenset()):
            raise DPFlowInputError()

        flow_cases = (
            application.minimum_mass_flow_kg_s,
            application.normal_mass_flow_kg_s,
            application.maximum_mass_flow_kg_s,
        )
        if any(value is None for value in flow_cases):
            raise DPFlowInputError()
        minimum_flow, _, maximum_flow = flow_cases
        if (
            isinstance(execution, OrificeBoreSolveRequest)
            and not minimum_flow <= execution.target_mass_flow_kg_s <= maximum_flow
        ):
            raise DPFlowInputError()

    @staticmethod
    def _authorize_flow_result(
        request: DPFlowDesignCaseRequest,
        calculation: DPFlowExecutionOutcome,
    ) -> None:
        """Require the calculated operating point inside the declared envelope."""

        result = calculation.result
        mass_flow = getattr(result, "mass_flow_kg_s", None)
        if mass_flow is None:
            mass_flow = getattr(result, "achieved_mass_flow_kg_s", None)
        application = request.application_request
        minimum_flow = application.minimum_mass_flow_kg_s
        maximum_flow = application.maximum_mass_flow_kg_s
        if (
            mass_flow is None
            or minimum_flow is None
            or maximum_flow is None
            or not minimum_flow <= mass_flow <= maximum_flow
        ):
            raise DPFlowInputError()

    def _evaluate(
        self,
        request: DPFlowDesignCaseRequest,
        *,
        mode: str,
        example_id: str | None = None,
        revision: int | None = None,
    ) -> DPFlowDesignCaseOutcome:
        try:
            normalized = _fresh(DPFlowDesignCaseRequest, request)
            assessment = self.assess_application(normalized.application_request)
            self._authorize_design_case(normalized, assessment)
            calculation = self.execute(normalized.execution_request)
            self._authorize_flow_result(normalized, calculation)
            fingerprint = build_design_case_fingerprint(
                normalized,
                assessment,
                calculation.trace.attempt_fingerprint,
            )
            return DPFlowDesignCaseOutcome(
                application_assessment=assessment,
                selected_generic_option_id=normalized.selected_generic_option_id,
                calculation=calculation,
                design_case_fingerprint=fingerprint,
                execution_mode=mode,
                stored_example_id=example_id,
                stored_example_revision=revision,
                illustrative_only=mode == "stored_example_replay",
            )
        except DPFlowServiceError:
            raise
        except (ValidationError, ValueError, TypeError) as exc:
            raise DPFlowInputError() from exc
        except Exception as exc:
            raise DPFlowServiceError() from exc

    def evaluate_design_case(
        self, request: DPFlowDesignCaseRequest
    ) -> DPFlowDesignCaseOutcome:
        return self._evaluate(request, mode="stateless")

    def evaluate_stored_design_case(
        self, request: DPFlowStoredDesignCaseReplayRequest
    ) -> DPFlowDesignCaseOutcome:
        try:
            normalized = _fresh(DPFlowStoredDesignCaseReplayRequest, request)
        except (ValidationError, ValueError, TypeError) as exc:
            raise DPFlowInputError() from exc
        key = (normalized.example_id, normalized.revision)
        example = DP_FLOW_STORED_EXAMPLE_REGISTRY.get(key)
        if example is None:
            if any(item.example_id == normalized.example_id for item in DP_FLOW_STORED_DESIGN_CASE_EXAMPLES):
                raise DPFlowConflictError()
            raise DPFlowNotFoundError()
        if normalized.example_fingerprint != example.example_fingerprint:
            raise DPFlowConflictError()
        return self._evaluate(
            example.design_case,
            mode="stored_example_replay",
            example_id=example.example_id,
            revision=example.revision,
        )


DEFAULT_DP_FLOW_SERVICE: Final = DPFlowService()


__all__ = [
    "DEFAULT_DP_FLOW_SERVICE",
    "DPFlowConflictError",
    "DPFlowInputError",
    "DPFlowNotFoundError",
    "DPFlowService",
    "DPFlowServiceError",
]
