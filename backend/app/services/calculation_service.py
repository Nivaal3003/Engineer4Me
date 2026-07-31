"""Application service for controlled engineering calculations.

The service keeps HTTP concerns outside the calculation foundation while
preserving its exact-version, immutable execution boundary.  Request,
metadata, trusted evidence, and result objects are revalidated at every
service crossing so callers cannot rely on previously constructed model
instances.
"""

from __future__ import annotations

from collections.abc import Callable
from inspect import isasyncgenfunction
from inspect import isawaitable
from inspect import iscoroutine
from inspect import iscoroutinefunction
from inspect import isgenerator
from inspect import isgeneratorfunction
from inspect import Parameter
from inspect import signature
from typing import Any
from typing import Final
from typing import TypeVar

from pydantic import BaseModel

from app.engineering.calculations.engine import CalculationEngine
from app.engineering.calculations.engine import DEFAULT_CALCULATION_ENGINE
from app.engineering.calculations.level import ENGINEERING_CALCULATION_ENGINE
from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
)
from app.engineering.calculations.method_models import (
    TrustedExecutionEvidence,
)
from app.engineering.calculations.models import CalculationRequest
from app.engineering.calculations.models import CalculationResult


EvidenceResolver = Callable[
    [CalculationRequest, CalculationMethodDefinition],
    TrustedExecutionEvidence,
]

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class CalculationServiceError(RuntimeError):
    """Base error for application-owned calculation-service failures."""

    code = "calculation_service_error"


class CalculationEvidenceResolutionError(CalculationServiceError):
    """Raised when server-owned trusted evidence cannot be resolved."""

    code = "calculation_evidence_resolution_error"

    def __init__(self) -> None:
        super().__init__(
            "Trusted calculation evidence could not be resolved."
        )


def _default_evidence_resolver(
    request: CalculationRequest,
    definition: CalculationMethodDefinition,
) -> TrustedExecutionEvidence:
    """Return an empty evidence set for methods needing no external data."""

    del request
    del definition
    return TrustedExecutionEvidence()


def _validate_evidence_resolver(
    resolver: EvidenceResolver,
) -> None:
    """Require one synchronous exact two-argument resolver contract."""

    callable_target = getattr(resolver, "__call__", resolver)
    if any(
        predicate(resolver) or predicate(callable_target)
        for predicate in (
            iscoroutinefunction,
            isgeneratorfunction,
            isasyncgenfunction,
        )
    ):
        raise TypeError(
            "evidence_resolver must be a synchronous function."
        )

    try:
        parameters = tuple(signature(resolver).parameters.values())
    except (TypeError, ValueError) as exc:
        raise TypeError(
            "evidence_resolver must have an inspectable signature."
        ) from exc

    positional_kinds = {
        Parameter.POSITIONAL_ONLY,
        Parameter.POSITIONAL_OR_KEYWORD,
    }
    if (
        len(parameters) != 2
        or any(
            parameter.kind not in positional_kinds
            or parameter.default is not Parameter.empty
            for parameter in parameters
        )
    ):
        raise TypeError(
            "evidence_resolver must accept exactly request and definition."
        )


def _fresh_model(
    model_type: type[_ModelT],
    value: Any,
) -> _ModelT:
    """Return a newly validated model without trusting an existing instance."""

    if isinstance(value, BaseModel):
        value = value.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )

    return model_type.model_validate(value)


class CalculationService:
    """Immutable application boundary around one calculation engine."""

    __slots__ = (
        "_engine",
        "_evidence_resolver",
        "_locked",
    )

    def __init__(
        self,
        *,
        engine: CalculationEngine = DEFAULT_CALCULATION_ENGINE,
        evidence_resolver: EvidenceResolver | None = None,
    ) -> None:
        """Bind the engine and server-owned evidence resolver permanently."""

        object.__setattr__(self, "_locked", False)

        if type(engine) is not CalculationEngine:
            raise TypeError("engine must be a CalculationEngine.")

        resolved_evidence_resolver = (
            _default_evidence_resolver
            if evidence_resolver is None
            else evidence_resolver
        )
        if not callable(resolved_evidence_resolver):
            raise TypeError("evidence_resolver must be callable.")
        _validate_evidence_resolver(resolved_evidence_resolver)

        object.__setattr__(self, "_engine", engine)
        object.__setattr__(
            self,
            "_evidence_resolver",
            resolved_evidence_resolver,
        )
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent dependency replacement after construction."""

        if getattr(self, "_locked", False):
            raise AttributeError(
                "CalculationService instances are immutable."
            )

        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """Prevent dependency deletion after construction."""

        if getattr(self, "_locked", False):
            raise AttributeError(
                "CalculationService instances are immutable."
            )

        object.__delattr__(self, name)

    @property
    def engine_version(self) -> str:
        """Return the bound deterministic engine version."""

        return self._engine.engine_version

    @property
    def method_count(self) -> int:
        """Return the number of exact registered method versions."""

        return len(self._engine.registry.definitions)

    def discover_methods(
        self,
        calculation_type: str | None = None,
    ) -> tuple[CalculationMethodDefinition, ...]:
        """Return freshly validated deterministic method metadata."""

        definitions = self._engine.registry.discover(
            calculation_type=calculation_type,
        )
        return tuple(
            _fresh_model(CalculationMethodDefinition, definition)
            for definition in definitions
        )

    def available_versions(self, method_id: str) -> tuple[str, ...]:
        """Return exact registered versions without implicit selection."""

        return self._engine.registry.available_versions(method_id)

    def get_method(
        self,
        method_id: str,
        method_version: str,
        calculation_type: str | None = None,
    ) -> CalculationMethodDefinition:
        """Return freshly validated metadata for one exact method version."""

        definition = self._engine.registry.resolve(
            method_id,
            method_version,
            calculation_type=calculation_type,
        )
        return _fresh_model(CalculationMethodDefinition, definition)

    def execute(
        self,
        request: CalculationRequest,
    ) -> CalculationResult:
        """Resolve trusted evidence and execute one exact validated request."""

        validated_request = _fresh_model(CalculationRequest, request)
        definition = self._engine.registry.resolve(
            validated_request.method_id,
            validated_request.method_version,
            calculation_type=validated_request.calculation_type,
        )
        validated_definition = _fresh_model(
            CalculationMethodDefinition,
            definition,
        )

        try:
            resolved_evidence = self._evidence_resolver(
                validated_request,
                validated_definition,
            )
            if isawaitable(resolved_evidence):
                if iscoroutine(resolved_evidence):
                    resolved_evidence.close()
                raise TypeError(
                    "evidence_resolver returned an awaitable."
                )
            if isgenerator(resolved_evidence):
                resolved_evidence.close()
                raise TypeError(
                    "evidence_resolver returned a generator."
                )
            validated_evidence = _fresh_model(
                TrustedExecutionEvidence,
                resolved_evidence,
            )
        except Exception as exc:
            raise CalculationEvidenceResolutionError() from exc

        result = self._engine.execute(
            validated_request,
            evidence=validated_evidence,
        )
        return _fresh_model(CalculationResult, result)


DEFAULT_CALCULATION_SERVICE: Final = CalculationService(
    engine=ENGINEERING_CALCULATION_ENGINE
)


__all__ = [
    "CalculationEvidenceResolutionError",
    "CalculationService",
    "CalculationServiceError",
    "DEFAULT_CALCULATION_SERVICE",
    "EvidenceResolver",
]
