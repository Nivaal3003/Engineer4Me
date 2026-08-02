"""Immutable Step 105 service for stateless pressure-relief workflows.

The service exposes the Step 103 readiness gate separately from the three
exact Step 104 required-area methods.  It accepts only typed raw-input
requests, calculates every trusted result server-side, and returns detached,
deterministic audit outcomes.  It performs no persistence, network access,
standards execution, device or orifice selection, manufacturer selection, or
project approval.
"""

from __future__ import annotations

from typing import Final

from pydantic import BaseModel, ValidationError

from app.engineering.calculations.pressure_relief import (
    PressureReliefError,
    assess_pressure_relief_readiness,
)
from app.engineering.calculations.pressure_relief_required_area import (
    PressureReliefRequiredAreaError,
    calculate_eligible_steam_pressure_relief_required_area,
    calculate_gas_vapour_pressure_relief_required_area,
    calculate_liquid_pressure_relief_required_area,
)
from app.engineering.calculations.pressure_relief_workflow_models import (
    PRESSURE_RELIEF_API_CATALOGUE,
    PRESSURE_RELIEF_API_REGISTRY,
    PRESSURE_RELIEF_KNOWLEDGE_LINKS,
    EligibleSteamPressureReliefExecutionRequest,
    GasVapourPressureReliefExecutionRequest,
    LiquidPressureReliefExecutionRequest,
    PressureReliefExecutionOutcome,
    PressureReliefExecutionRequest,
    PressureReliefKnowledgeLink,
    PressureReliefMethodCatalogueEntry,
    PressureReliefOperation,
    PressureReliefReadinessAssessmentOutcome,
    PressureReliefReadinessAssessmentRequest,
    PressureReliefRequiredAreaResult,
    build_pressure_relief_execution_outcome,
    build_pressure_relief_readiness_outcome,
    validate_pressure_relief_execution_request,
    validate_pressure_relief_readiness_assessment_request,
)


class PressureReliefServiceError(RuntimeError):
    """Sanitized failure at a trusted workflow or response boundary."""

    code = "pressure_relief_service_unavailable"

    def __init__(self) -> None:
        super().__init__("The controlled pressure-relief service is unavailable.")


class PressureReliefWorkflowInputError(PressureReliefServiceError):
    """The supplied request is invalid or outside the reviewed boundary."""

    code = "pressure_relief_input_error"

    def __init__(self) -> None:
        RuntimeError.__init__(self, "The pressure-relief request is invalid.")


def _fresh[ModelT: BaseModel](
    model_type: type[ModelT],
    value: object,
) -> ModelT:
    """Return one detached model revalidated at the service boundary."""

    if not isinstance(value, BaseModel):
        raise TypeError("service boundaries require typed models")
    return model_type.model_validate(
        value.model_dump(mode="python", round_trip=True, warnings="error")
    )


def _dispatch_required_area(
    request: PressureReliefExecutionRequest,
) -> PressureReliefRequiredAreaResult:
    """Dispatch only the three statically reviewed exact request types."""

    if isinstance(request, LiquidPressureReliefExecutionRequest):
        return calculate_liquid_pressure_relief_required_area(request.sizing_input)
    if isinstance(request, GasVapourPressureReliefExecutionRequest):
        return calculate_gas_vapour_pressure_relief_required_area(request.sizing_input)
    if isinstance(request, EligibleSteamPressureReliefExecutionRequest):
        return calculate_eligible_steam_pressure_relief_required_area(
            request.sizing_input
        )
    raise TypeError("unregistered pressure-relief execution-request type")


class PressureReliefService:
    """Immutable, deterministic, no-I/O pressure-relief service."""

    __slots__ = ("_locked",)

    def __init__(self) -> None:
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("PressureReliefService instances are immutable.")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("PressureReliefService instances are immutable.")
        object.__delattr__(self, name)

    def get_catalogue(self) -> tuple[PressureReliefMethodCatalogueEntry, ...]:
        """Return detached exact-version executable method metadata."""

        try:
            return tuple(
                _fresh(PressureReliefMethodCatalogueEntry, item)
                for item in PRESSURE_RELIEF_API_CATALOGUE
            )
        except Exception as error:
            raise PressureReliefServiceError() from error

    def get_knowledge_links(self) -> tuple[PressureReliefKnowledgeLink, ...]:
        """Return detached inert discovery metadata without network access."""

        try:
            return tuple(
                _fresh(PressureReliefKnowledgeLink, item)
                for item in PRESSURE_RELIEF_KNOWLEDGE_LINKS
            )
        except Exception as error:
            raise PressureReliefServiceError() from error

    def assess_readiness(
        self,
        request: PressureReliefReadinessAssessmentRequest,
    ) -> PressureReliefReadinessAssessmentOutcome:
        """Run the separate non-numerical Step 103 readiness gate."""

        try:
            normalized = validate_pressure_relief_readiness_assessment_request(request)
        except (ValidationError, TypeError, ValueError) as error:
            raise PressureReliefWorkflowInputError() from error

        try:
            result = assess_pressure_relief_readiness(normalized.readiness_request)
        except PressureReliefError as error:
            raise PressureReliefWorkflowInputError() from error
        except Exception as error:
            raise PressureReliefServiceError() from error

        try:
            return build_pressure_relief_readiness_outcome(normalized, result)
        except Exception as error:
            raise PressureReliefServiceError() from error

    def execute(
        self,
        request: PressureReliefExecutionRequest,
    ) -> PressureReliefExecutionOutcome:
        """Execute one exact generic method and build its audit outcome."""

        try:
            normalized = validate_pressure_relief_execution_request(request)
        except (ValidationError, TypeError, ValueError) as error:
            raise PressureReliefWorkflowInputError() from error

        operation = PressureReliefOperation(normalized.operation)
        metadata = PRESSURE_RELIEF_API_REGISTRY[operation]
        if (
            normalized.method_id != metadata.method_id
            or normalized.method_version != metadata.method_version
        ):
            raise PressureReliefWorkflowInputError()

        try:
            result = _dispatch_required_area(normalized)
        except PressureReliefRequiredAreaError as error:
            raise PressureReliefWorkflowInputError() from error
        except Exception as error:
            raise PressureReliefServiceError() from error

        try:
            return build_pressure_relief_execution_outcome(normalized, result)
        except Exception as error:
            raise PressureReliefServiceError() from error


DEFAULT_PRESSURE_RELIEF_SERVICE: Final = PressureReliefService()


__all__ = [
    "DEFAULT_PRESSURE_RELIEF_SERVICE",
    "PressureReliefService",
    "PressureReliefServiceError",
    "PressureReliefWorkflowInputError",
]
