"""Immutable Step 102 service for stateless control-valve workflows.

The service calculates every sizing result from caller-supplied raw inputs. It
does not accept caller-created child results, access a database or network,
select a product, derive manufacturer factors, or execute standards metadata.
"""

from __future__ import annotations

from typing import Final, TypeVar

from app.engineering.calculations.control_valve import (
    ControlValveCalculationError,
    LiquidControlValveSizingInput,
    LiquidControlValveSizingResult,
    size_liquid_control_valve,
)
from app.engineering.calculations.control_valve_compressible import (
    CompressibleControlValveSizingInput,
    CompressibleControlValveSizingResult,
    size_compressible_control_valve,
)
from app.engineering.calculations.control_valve_installed import (
    InstalledControlValveError,
    InstalledControlValveScreenResult,
    evaluate_installed_control_valve_scenarios,
)
from app.engineering.calculations.control_valve_workflow_models import (
    CONTROL_VALVE_API_CATALOGUE,
    CONTROL_VALVE_API_REGISTRY,
    CONTROL_VALVE_KNOWLEDGE_LINKS,
    CompressibleControlValveExecutionRequest,
    ControlValveDesignCaseOutcome,
    ControlValveDesignCaseRequest,
    ControlValveExecutionOutcome,
    ControlValveExecutionRequest,
    ControlValveExecutionTrace,
    ControlValveKnowledgeLink,
    ControlValveMethodCatalogueEntry,
    ControlValveOperation,
    ControlValveResult,
    ControlValveSizingInput,
    InstalledControlValveExecutionRequest,
    LiquidControlValveExecutionRequest,
    build_control_valve_attempt_fingerprint,
    build_control_valve_design_case_fingerprint,
    build_control_valve_input_fingerprint,
    build_control_valve_result_fingerprint,
    build_installed_screen_request,
    derive_control_valve_design_disposition,
    derive_control_valve_safety_findings,
    installed_sizing_inputs,
    validate_control_valve_execution_request,
)
from pydantic import BaseModel, ValidationError

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class ControlValveServiceError(RuntimeError):
    """Sanitized failure at a trusted workflow or response boundary."""

    code = "control_valve_service_unavailable"

    def __init__(self) -> None:
        super().__init__("The controlled control-valve service is unavailable.")


class ControlValveWorkflowInputError(ControlValveServiceError):
    """The supplied request is invalid or outside the reviewed boundary."""

    code = "control_valve_input_error"

    def __init__(self) -> None:
        RuntimeError.__init__(self, "The control-valve request is invalid.")


def _fresh(model_type: type[_ModelT], value: object) -> _ModelT:
    if not isinstance(value, BaseModel):
        raise TypeError("service boundaries require typed models")
    return model_type.model_validate(
        value.model_dump(mode="python", round_trip=True, warnings="error")
    )


def _size_input(
    value: ControlValveSizingInput,
) -> LiquidControlValveSizingResult | CompressibleControlValveSizingResult:
    if isinstance(value, LiquidControlValveSizingInput):
        return size_liquid_control_valve(value)
    if isinstance(value, CompressibleControlValveSizingInput):
        return size_compressible_control_valve(value)
    raise TypeError("unregistered control-valve sizing-input type")


def _dispatch(request: ControlValveExecutionRequest) -> ControlValveResult:
    """Dispatch only the three statically reviewed request types."""

    if isinstance(request, LiquidControlValveExecutionRequest):
        return size_liquid_control_valve(request.sizing_input)
    if isinstance(request, CompressibleControlValveExecutionRequest):
        return size_compressible_control_valve(request.sizing_input)
    if isinstance(request, InstalledControlValveExecutionRequest):
        sizing_results = tuple(
            _size_input(item) for item in installed_sizing_inputs(request)
        )
        return evaluate_installed_control_valve_scenarios(
            build_installed_screen_request(request),
            sizing_results,
        )
    raise TypeError("unregistered control-valve execution-request type")


class ControlValveService:
    """Immutable, deterministic, no-I/O control-valve service."""

    __slots__ = ("_locked",)

    def __init__(self) -> None:
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("ControlValveService instances are immutable.")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("ControlValveService instances are immutable.")
        object.__delattr__(self, name)

    def get_catalogue(self) -> tuple[ControlValveMethodCatalogueEntry, ...]:
        try:
            return tuple(
                _fresh(ControlValveMethodCatalogueEntry, item)
                for item in CONTROL_VALVE_API_CATALOGUE
            )
        except Exception as error:
            raise ControlValveServiceError() from error

    def get_knowledge_links(self) -> tuple[ControlValveKnowledgeLink, ...]:
        try:
            return tuple(
                _fresh(ControlValveKnowledgeLink, item)
                for item in CONTROL_VALVE_KNOWLEDGE_LINKS
            )
        except Exception as error:
            raise ControlValveServiceError() from error

    def execute(
        self,
        request: ControlValveExecutionRequest,
    ) -> ControlValveExecutionOutcome:
        """Normalize input, execute one method, then validate trusted output."""

        try:
            normalized = validate_control_valve_execution_request(request)
        except (ValidationError, TypeError, ValueError) as error:
            raise ControlValveWorkflowInputError() from error

        operation = ControlValveOperation(normalized.operation)
        metadata = CONTROL_VALVE_API_REGISTRY[operation]
        if (
            normalized.method_id != metadata.method_id
            or normalized.method_version != metadata.method_version
        ):
            raise ControlValveWorkflowInputError()
        try:
            result = _dispatch(normalized)
        except (ControlValveCalculationError, InstalledControlValveError) as error:
            raise ControlValveWorkflowInputError() from error
        except Exception as error:
            raise ControlValveServiceError() from error

        try:
            input_fingerprint = build_control_valve_input_fingerprint(normalized)
            result_fingerprint = build_control_valve_result_fingerprint(
                normalized,
                result,
                metadata.knowledge_source_ids,
            )
            trace = ControlValveExecutionTrace(
                operation=operation,
                method_id=metadata.method_id,
                method_version=metadata.method_version,
                calculator_version=result.calculator_version,
                implementation_name=metadata.implementation_name,
                normalized_input_fingerprint=input_fingerprint,
                result_fingerprint=result_fingerprint,
                attempt_fingerprint=build_control_valve_attempt_fingerprint(
                    input_fingerprint,
                    result_fingerprint,
                ),
                knowledge_source_ids=metadata.knowledge_source_ids,
            )
            if isinstance(result, InstalledControlValveScreenResult):
                safety_findings = derive_control_valve_safety_findings(result)
                disposition = derive_control_valve_design_disposition(safety_findings)
                candidate_identity_origin = "caller_supplied"
            else:
                safety_findings = ()
                disposition = None
                candidate_identity_origin = (
                    "not_applicable"
                    if isinstance(normalized, LiquidControlValveExecutionRequest)
                    else "caller_supplied"
                )
            return ControlValveExecutionOutcome(
                safety_findings=safety_findings,
                disposition=disposition,
                normalized_request=normalized,
                result=result,
                trace=trace,
                candidate_identity_origin=candidate_identity_origin,
            )
        except Exception as error:
            raise ControlValveServiceError() from error

    def evaluate_design_case(
        self,
        request: ControlValveDesignCaseRequest,
    ) -> ControlValveDesignCaseOutcome:
        """Evaluate one stateless caller-supplied candidate design case."""

        try:
            normalized = _fresh(ControlValveDesignCaseRequest, request)
        except (ValidationError, TypeError, ValueError) as error:
            raise ControlValveWorkflowInputError() from error

        calculation = self.execute(normalized.installed_execution_request)
        if not isinstance(calculation.result, InstalledControlValveScreenResult):
            raise ControlValveServiceError()
        try:
            findings = derive_control_valve_safety_findings(calculation.result)
            disposition = derive_control_valve_design_disposition(findings)
            fingerprint = build_control_valve_design_case_fingerprint(
                normalized,
                calculation,
                findings,
                disposition,
            )
            return ControlValveDesignCaseOutcome(
                safety_findings=findings,
                disposition=disposition,
                normalized_design_case=normalized,
                calculation=calculation,
                design_case_fingerprint=fingerprint,
            )
        except Exception as error:
            raise ControlValveServiceError() from error


DEFAULT_CONTROL_VALVE_SERVICE: Final = ControlValveService()


__all__ = [
    "DEFAULT_CONTROL_VALVE_SERVICE",
    "ControlValveService",
    "ControlValveServiceError",
    "ControlValveWorkflowInputError",
]
