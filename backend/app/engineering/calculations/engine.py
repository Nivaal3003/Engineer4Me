"""Deterministic, bounded execution engine for reviewed calculations.

Only exact, approved registrations from the immutable method registry can
reach an implementation function.  Validation and safety evaluation occur
first.  Implementations receive immutable normalized data and may return only
a bounded :class:`MethodExecutionOutcome`; they cannot choose the result
status, identities, timestamps, lifecycle, or fingerprint.

The in-process implementation boundary is trusted reviewed application code,
not a sandbox.  This module provides no expression evaluation, dynamic import,
shell invocation, document-formula execution, or request-controlled
reflection.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC
from datetime import datetime
from decimal import Decimal
from hashlib import sha256
import json
from math import isfinite
import re
from typing import Any
from typing import Final
from uuid import UUID
from uuid import uuid4

from app.engineering.calculations.method_models import (
    CANONICAL_METHOD_VERSION_PATTERN,
)
from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
)
from app.engineering.calculations.method_models import IterationLimits
from app.engineering.calculations.method_models import IterationOutcome
from app.engineering.calculations.method_models import (
    IterationTerminationReason,
)
from app.engineering.calculations.method_models import (
    MethodExecutionContext,
)
from app.engineering.calculations.method_models import (
    MethodExecutionOutcome,
)
from app.engineering.calculations.method_models import (
    TrustedExecutionEvidence,
)
from app.engineering.calculations.models import CalculationAssumption
from app.engineering.calculations.models import CalculationFinding
from app.engineering.calculations.models import CalculationInput
from app.engineering.calculations.models import CalculationModel
from app.engineering.calculations.models import CalculationOption
from app.engineering.calculations.models import CalculationReference
from app.engineering.calculations.models import CalculationRequest
from app.engineering.calculations.models import CalculationResult
from app.engineering.calculations.models import CalculationStatus
from app.engineering.calculations.models import CalculationTraceStep
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import FindingCategory
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import MAX_ABSOLUTE_OPTION_NUMBER
from app.engineering.calculations.models import MAX_ASSUMPTIONS
from app.engineering.calculations.models import MAX_FINDINGS
from app.engineering.calculations.models import MAX_INPUTS
from app.engineering.calculations.models import MAX_MISSING_INPUTS
from app.engineering.calculations.models import MAX_OPTIONS
from app.engineering.calculations.models import MAX_REFERENCES
from app.engineering.calculations.models import (
    MAX_VERIFICATION_REQUIREMENTS,
)
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.models import MissingCalculationInput
from app.engineering.calculations.models import TraceStepKind
from app.engineering.calculations.models import VerificationRequirement
from app.engineering.calculations.registry import (
    CalculationMethodRegistry,
)
from app.engineering.calculations.registry import DEFAULT_METHOD_REGISTRY
from app.engineering.calculations.registry import MethodRegistration
from app.engineering.calculations.safety import CalculationSafetyEngine
from app.engineering.calculations.safety import DEFAULT_SAFETY_ENGINE
from app.engineering.calculations.safety import SafetyEvaluationContext
from app.engineering.calculations.safety import SafetyReport
from app.engineering.calculations.validation import (
    CalculationValidationEngine,
)
from app.engineering.calculations.validation import (
    CalculationValidationReport,
)
from app.engineering.calculations.validation import (
    DEFAULT_VALIDATION_ENGINE,
)


ENGINE_VERSION: Final = "1.0.0"
FINGERPRINT_SCHEMA: Final = "e4m.calc.v1"
ATTEMPT_FINGERPRINT_SCHEMA: Final = "e4m.calc.attempt.v1"

ENGINE_LIFECYCLE_FINDING_ID: Final = "engine.lifecycle-blocked"
ENGINE_COMPATIBILITY_FINDING_ID: Final = "engine.incompatible"
ENGINE_EXECUTION_FINDING_ID: Final = "engine.execution-failed"
ENGINE_NONCONVERGENCE_FINDING_ID: Final = "engine.non-convergence"
ENGINE_PRE_EXECUTION_RESULT_FINDING_ID: Final = (
    "engine.pre-execution-result-invalid"
)
ENGINE_RESULT_FINDING_ID: Final = "engine.result-invalid"

_IDENTIFIER_PATTERN: Final = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{1,99}$"
)
_STABLE_VERSION_PATTERN: Final = re.compile(
    r"^(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)$"
)
_CANONICAL_METHOD_VERSION_PATTERN: Final = re.compile(
    rf"^{CANONICAL_METHOD_VERSION_PATTERN}$"
)


class CalculationEngineError(ValueError):
    """Base error for deterministic calculation-engine failures."""

    code = "calculation_engine_error"


class CalculationEvidenceError(CalculationEngineError):
    """Raised when trusted reference objects do not resolve request links."""

    code = "calculation_evidence_error"


class CalculationExecutionContractError(CalculationEngineError):
    """Raised internally when a reviewed implementation breaks its contract."""

    code = "calculation_execution_contract_error"


class IterationControlError(CalculationEngineError):
    """Base error for deterministic iterative-controller failures."""

    code = "iteration_control_error"


class IterationLimitExceededError(IterationControlError):
    """Raised before an implementation can start an excess iteration."""

    code = "iteration_limit_exceeded"


class IterationStateError(IterationControlError):
    """Raised when an implementation uses a terminated controller."""

    code = "iteration_state_error"


class NonFiniteIterationError(IterationControlError):
    """Raised when an iteration reports a non-finite numerical state."""

    code = "iteration_non_finite"


def _comparison_text(value: str) -> str:
    """Return the stable case-insensitive identifier comparison form."""

    return value.casefold()


def _validated_identifier_collection(
    values: tuple[str, ...],
    *,
    field_name: str,
    maximum_length: int,
) -> tuple[str, ...]:
    """Return a bounded, case-insensitively unique identifier collection."""

    if len(values) > maximum_length:
        raise CalculationExecutionContractError(
            f"{field_name} exceeds the controlled collection limit."
        )

    if any(
        not isinstance(value, str)
        or not _IDENTIFIER_PATTERN.fullmatch(value)
        for value in values
    ):
        raise CalculationExecutionContractError(
            f"{field_name} must contain canonical calculation identifiers."
        )

    comparison_values = tuple(
        _comparison_text(value)
        for value in values
    )
    if len(comparison_values) != len(set(comparison_values)):
        raise CalculationExecutionContractError(
            f"{field_name} must contain unique identifiers."
        )

    return values


def _revalidate_model(model_type, value):
    """Revalidate even an instance created through ``model_construct``."""

    if isinstance(value, CalculationModel):
        value = value.model_dump(
            mode="python",
            round_trip=True,
            warnings="none",
        )

    return model_type.model_validate(value)


def _canonical_number(value: float | int) -> str:
    """Return a locale-free, finite, non-exponential decimal string."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CalculationExecutionContractError(
            "A canonical numerical value must be an integer or float."
        )

    if isinstance(value, float) and not isfinite(value):
        raise CalculationExecutionContractError(
            "A canonical numerical value must be finite."
        )

    if value == 0:
        return "0"

    decimal_value = Decimal(value) if isinstance(value, int) else Decimal(
        str(value)
    )
    text = format(decimal_value, "f")

    if "." in text:
        text = text.rstrip("0").rstrip(".")

    if text in {"-0", "+0", ""}:
        return "0"

    return text


def _canonical_quantity(
    quantity: EngineeringQuantity,
) -> dict[str, Any]:
    """Return substantive quantity content without presentation metadata."""

    validated_quantity = _revalidate_model(
        EngineeringQuantity,
        quantity,
    )
    return {
        "quantity_kind": validated_quantity.quantity_kind,
        "uncertainty": (
            None
            if validated_quantity.uncertainty is None
            else _canonical_number(validated_quantity.uncertainty)
        ),
        "uncertainty_basis": validated_quantity.uncertainty_basis,
        "unit": validated_quantity.unit,
        "value": _canonical_number(validated_quantity.value),
    }


def _canonical_categorical(value: bool | str) -> dict[str, Any]:
    """Preserve strict categorical type in a collision-safe record."""

    if isinstance(value, bool):
        return {
            "type": "boolean",
            "value": value,
        }

    if isinstance(value, str):
        return {
            "type": "text",
            "value": value,
        }

    raise CalculationExecutionContractError(
        "Unsupported categorical value at fingerprint boundary."
    )


def _canonical_input(value: CalculationInput) -> dict[str, Any]:
    """Return one normalized calculation input fingerprint record."""

    validated_input = _revalidate_model(CalculationInput, value)
    record: dict[str, Any] = {
        "input_id": validated_input.input_id,
    }

    if validated_input.quantity is not None:
        record["quantity"] = _canonical_quantity(
            validated_input.quantity
        )
    else:
        record["categorical"] = _canonical_categorical(
            validated_input.categorical_value  # type: ignore[arg-type]
        )

    return record


def _canonical_request_input(
    value: CalculationInput,
) -> dict[str, Any]:
    """Return complete substantive request-input state for failed attempts."""

    validated_input = _revalidate_model(CalculationInput, value)
    record = _canonical_input(validated_input)
    record.update(
        {
            "assumption_id": validated_input.assumption_id,
            "name": validated_input.name,
            "notes": validated_input.notes,
            "origin": validated_input.origin.value,
            "source_reference_ids": sorted(
                validated_input.source_reference_ids,
                key=str.casefold,
            ),
            "source_trace_step_ids": sorted(
                validated_input.source_trace_step_ids,
                key=str.casefold,
            ),
        }
    )
    return record


def _canonical_option(value: CalculationOption) -> dict[str, Any]:
    """Return one strict material option fingerprint record."""

    validated_option = _revalidate_model(CalculationOption, value)
    option_value = validated_option.value

    if isinstance(option_value, bool):
        value_type = "boolean"
        canonical_value: bool | str = option_value
    elif isinstance(option_value, int):
        value_type = "integer"
        canonical_value = option_value
    elif isinstance(option_value, float):
        value_type = "float"
        canonical_value = _canonical_number(option_value)
    else:
        value_type = "text"
        canonical_value = option_value

    return {
        "option_id": validated_option.option_id,
        "type": value_type,
        "value": canonical_value,
    }


def _canonical_assumption(
    value: CalculationAssumption,
) -> dict[str, Any]:
    """Return substantive assumption content in deterministic form."""

    assumption = _revalidate_model(CalculationAssumption, value)
    verified_at = (
        None
        if assumption.verified_at is None
        else (
            assumption.verified_at.astimezone(UTC)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
    )
    return {
        "affects_result": assumption.affects_result,
        "assumption_id": assumption.assumption_id,
        "origin": assumption.origin.value,
        "requires_verification": assumption.requires_verification,
        "safety_critical": assumption.safety_critical,
        "source_reference_ids": sorted(
            assumption.source_reference_ids,
            key=str.casefold,
        ),
        "statement": assumption.statement,
        "verification_completed": assumption.verification_completed,
        "verified_at": verified_at,
        "verified_by": assumption.verified_by,
        "verification_requirement_ids": sorted(
            assumption.verification_requirement_ids,
            key=str.casefold,
        ),
    }


def _canonical_reference(
    value: CalculationReference,
) -> dict[str, Any]:
    """Return every material field visible on trusted reference evidence."""

    reference = _revalidate_model(CalculationReference, value)
    verified_at = (
        None
        if reference.verified_at is None
        else (
            reference.verified_at.astimezone(UTC)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
    )
    return {
        "applicability": reference.applicability,
        "corrigenda_status": reference.corrigenda_status,
        "document_number": reference.document_number,
        "edition_or_revision": reference.edition_or_revision,
        "implementation_basis": reference.implementation_basis,
        "part": reference.part,
        "publisher_or_owner": reference.publisher_or_owner,
        "reference_id": reference.reference_id,
        "reference_type": reference.reference_type.value,
        "relevant_section": reference.relevant_section,
        "source_location": reference.source_location,
        "title": reference.title,
        "verified": reference.verified,
        "verified_at": verified_at,
        "verified_by": reference.verified_by,
    }


def _canonical_verification_requirement(
    value: VerificationRequirement,
) -> dict[str, Any]:
    """Return every material field visible on trusted verification evidence."""

    requirement = _revalidate_model(VerificationRequirement, value)
    return {
        "acceptance_criteria": requirement.acceptance_criteria,
        "description": requirement.description,
        "evidence_required": sorted(
            requirement.evidence_required,
            key=str.casefold,
        ),
        "expected_result": requirement.expected_result,
        "independent_verification_required": (
            requirement.independent_verification_required
        ),
        "method": requirement.method,
        "required_competency": requirement.required_competency,
        "verification_id": requirement.verification_id,
        "verifier_role": requirement.verifier_role,
    }


def _canonical_evidence(
    references: tuple[CalculationReference, ...],
    verification_requirements: tuple[
        VerificationRequirement,
        ...,
    ],
) -> dict[str, Any] | None:
    """Return deterministic evidence visible to reviewed execution hooks."""

    if len(references) > MAX_REFERENCES:
        raise CalculationExecutionContractError(
            "references exceeds the controlled collection limit."
        )
    if (
        len(verification_requirements)
        > MAX_VERIFICATION_REQUIREMENTS
    ):
        raise CalculationExecutionContractError(
            "verification_requirements exceeds the controlled collection "
            "limit."
        )

    canonical_references = tuple(
        _canonical_reference(value)
        for value in references
    )
    canonical_verifications = tuple(
        _canonical_verification_requirement(value)
        for value in verification_requirements
    )

    if len(
        {
            value["reference_id"].casefold()
            for value in canonical_references
        }
    ) != len(canonical_references):
        raise CalculationExecutionContractError(
            "Evidence reference identifiers must be unique."
        )
    if len(
        {
            value["verification_id"].casefold()
            for value in canonical_verifications
        }
    ) != len(canonical_verifications):
        raise CalculationExecutionContractError(
            "Evidence verification identifiers must be unique."
        )

    if not canonical_references and not canonical_verifications:
        return None

    return {
        "references": sorted(
            canonical_references,
            key=lambda item: item["reference_id"].casefold(),
        ),
        "verification_requirements": sorted(
            canonical_verifications,
            key=lambda item: item["verification_id"].casefold(),
        ),
    }


def build_fingerprint_payload(
    *,
    method_id: str,
    method_version: str,
    normalized_inputs: tuple[CalculationInput, ...],
    effective_options: tuple[CalculationOption, ...],
    assumptions: tuple[CalculationAssumption, ...] = (),
    references: tuple[CalculationReference, ...] = (),
    verification_requirements: tuple[
        VerificationRequirement,
        ...,
    ] = (),
    status: CalculationStatus = CalculationStatus.COMPLETED,
    finding_ids: tuple[str, ...] = (),
    missing_input_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Build the versioned canonical successful-execution payload.

    Request IDs, calculation IDs, actors, timestamps, aliases, input ordering,
    and presentation-only precision metadata are intentionally absent.
    """

    if (
        not isinstance(method_id, str)
        or not _IDENTIFIER_PATTERN.fullmatch(method_id)
    ):
        raise CalculationExecutionContractError(
            "method_id must be a canonical calculation identifier."
        )

    if (
        not isinstance(method_version, str)
        or not _CANONICAL_METHOD_VERSION_PATTERN.fullmatch(
            method_version
        )
    ):
        raise CalculationExecutionContractError(
            "method_version must use canonical semantic X.Y.Z form."
        )

    try:
        validated_status = CalculationStatus(status)
    except (TypeError, ValueError) as exc:
        raise CalculationExecutionContractError(
            "status must be a supported calculation status."
        ) from exc

    if len(normalized_inputs) > MAX_INPUTS:
        raise CalculationExecutionContractError(
            "normalized_inputs exceeds the controlled collection limit."
        )
    if len(effective_options) > MAX_OPTIONS:
        raise CalculationExecutionContractError(
            "effective_options exceeds the controlled collection limit."
        )
    if len(assumptions) > MAX_ASSUMPTIONS:
        raise CalculationExecutionContractError(
            "assumptions exceeds the controlled collection limit."
        )

    canonical_inputs = tuple(
        _canonical_input(value)
        for value in normalized_inputs
    )
    canonical_options = tuple(
        _canonical_option(value)
        for value in effective_options
    )

    if len(
        {
            value["input_id"].casefold()
            for value in canonical_inputs
        }
    ) != len(canonical_inputs):
        raise CalculationExecutionContractError(
            "Fingerprint input identifiers must be unique."
        )

    if len(
        {
            value["option_id"].casefold()
            for value in canonical_options
        }
    ) != len(canonical_options):
        raise CalculationExecutionContractError(
            "Fingerprint option identifiers must be unique."
        )

    canonical_assumptions = tuple(
        _canonical_assumption(value)
        for value in assumptions
    )
    if len(
        {
            value["assumption_id"].casefold()
            for value in canonical_assumptions
        }
    ) != len(canonical_assumptions):
        raise CalculationExecutionContractError(
            "Fingerprint assumption identifiers must be unique."
        )

    validated_finding_ids = _validated_identifier_collection(
        finding_ids,
        field_name="finding_ids",
        maximum_length=MAX_FINDINGS,
    )
    validated_missing_input_ids = _validated_identifier_collection(
        missing_input_ids,
        field_name="missing_input_ids",
        maximum_length=MAX_MISSING_INPUTS,
    )

    payload: dict[str, Any] = {
        "fingerprint_schema": FINGERPRINT_SCHEMA,
        "inputs": sorted(
            canonical_inputs,
            key=lambda item: item["input_id"].casefold(),
        ),
        "method": {
            "method_id": method_id,
            "method_version": method_version,
        },
        "options": sorted(
            canonical_options,
            key=lambda item: item["option_id"].casefold(),
        ),
    }

    canonical_evidence = _canonical_evidence(
        references,
        verification_requirements,
    )
    if canonical_evidence is not None:
        payload["evidence"] = canonical_evidence

    if assumptions:
        payload["assumptions"] = sorted(
            canonical_assumptions,
            key=lambda item: item["assumption_id"].casefold(),
        )

    if validated_status is not CalculationStatus.COMPLETED:
        payload["result_context"] = {
            "finding_ids": sorted(
                validated_finding_ids,
                key=str.casefold,
            ),
            "missing_input_ids": sorted(
                validated_missing_input_ids,
                key=str.casefold,
            ),
            "status": validated_status.value,
        }

    return payload


def build_attempt_fingerprint_payload(
    *,
    definition: CalculationMethodDefinition,
    request: CalculationRequest,
    disposition: str,
    evidence: TrustedExecutionEvidence | None = None,
    finding_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Build a collision-resistant payload when normalization cannot finish."""

    validated_definition = _revalidate_model(
        CalculationMethodDefinition,
        definition,
    )
    validated_request = _revalidate_model(CalculationRequest, request)
    validated_evidence = (
        TrustedExecutionEvidence()
        if evidence is None
        else _revalidate_model(TrustedExecutionEvidence, evidence)
    )
    if (
        not isinstance(disposition, str)
        or not _IDENTIFIER_PATTERN.fullmatch(disposition)
    ):
        raise CalculationExecutionContractError(
            "disposition must be a canonical calculation identifier."
        )
    validated_finding_ids = _validated_identifier_collection(
        finding_ids,
        field_name="finding_ids",
        maximum_length=MAX_FINDINGS,
    )
    supplied_by_id = {
        _comparison_text(value.input_id): value
        for value in validated_request.inputs
    }
    input_records: list[dict[str, Any]] = []

    for specification in validated_definition.input_specifications:
        supplied = supplied_by_id.get(
            _comparison_text(specification.input_id)
        )

        if supplied is None:
            input_records.append(
                {
                    "input_id": specification.input_id,
                    "state": "missing",
                }
            )
            continue

        record = _canonical_request_input(supplied)
        record["state"] = "supplied_unvalidated"
        input_records.append(record)

    known_input_ids = {
        _comparison_text(value.input_id)
        for value in validated_definition.input_specifications
    }

    for supplied in validated_request.inputs:
        if _comparison_text(supplied.input_id) in known_input_ids:
            continue

        record = _canonical_request_input(supplied)
        record["state"] = "unknown"
        input_records.append(record)

    payload: dict[str, Any] = {
        "disposition": disposition,
        "finding_ids": sorted(
            validated_finding_ids,
            key=str.casefold,
        ),
        "fingerprint_schema": ATTEMPT_FINGERPRINT_SCHEMA,
        "inputs": sorted(
            input_records,
            key=lambda item: item["input_id"].casefold(),
        ),
        "method": {
            "method_id": validated_definition.method_id,
            "method_version": validated_definition.method_version,
        },
        "assumptions": sorted(
            (
                _canonical_assumption(value)
                for value in validated_request.assumptions
            ),
            key=lambda item: item["assumption_id"].casefold(),
        ),
        "options": sorted(
            (
                _canonical_option(value)
                for value in validated_request.options
            ),
            key=lambda item: item["option_id"].casefold(),
        ),
        "reference_ids": sorted(
            validated_request.reference_ids,
            key=str.casefold,
        ),
    }
    canonical_evidence = _canonical_evidence(
        validated_evidence.references,
        validated_evidence.verification_requirements,
    )
    if canonical_evidence is not None:
        payload["evidence"] = canonical_evidence

    return payload


def canonical_fingerprint_bytes(
    payload: dict[str, Any],
) -> bytes:
    """Serialize one canonical payload as compact sorted UTF-8 JSON."""

    try:
        text = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise CalculationExecutionContractError(
            "Fingerprint payload contains unsupported data."
        ) from exc

    return text.encode("utf-8")


def fingerprint_payload(payload: dict[str, Any]) -> str:
    """Return the lower-case SHA-256 of canonical fingerprint bytes."""

    return sha256(canonical_fingerprint_bytes(payload)).hexdigest()


class IterationController:
    """Per-execution finite iteration budget with no shared mutable state."""

    __slots__ = (
        "_iteration_count",
        "_limits",
        "_locked",
        "_outcome",
    )

    def __init__(self, limits: IterationLimits) -> None:
        """Revalidate and initialize one isolated reviewed budget."""

        object.__setattr__(self, "_locked", False)
        object.__setattr__(
            self,
            "_limits",
            _revalidate_model(IterationLimits, limits),
        )
        object.__setattr__(self, "_iteration_count", 0)
        object.__setattr__(self, "_outcome", None)
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent handlers from rewriting the engine-owned budget."""

        if getattr(self, "_locked", False):
            raise AttributeError(
                "IterationController instances are immutable."
            )

        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """Prevent handlers from deleting engine-owned iteration state."""

        if getattr(self, "_locked", False):
            raise AttributeError(
                "IterationController instances are immutable."
            )

        object.__delattr__(self, name)

    @property
    def limits(self) -> IterationLimits:
        """Return the immutable reviewed limits."""

        return self._limits

    @property
    def iterations_used(self) -> int:
        """Return the number of admitted iteration records."""

        return self._iteration_count

    @property
    def outcome(self) -> IterationOutcome | None:
        """Return the terminal immutable outcome, if reached."""

        return self._outcome

    @property
    def terminated(self) -> bool:
        """Return whether convergence or a hard stop has occurred."""

        return self._outcome is not None

    def record(
        self,
        residual: float,
        *,
        reference_magnitude: float = 0.0,
    ) -> bool:
        """Admit one iteration and return whether it converged.

        The maximum budget is checked before the next iteration starts, so an
        implementation can never record ``maximum_iterations + 1``.
        """

        if self._outcome is not None:
            raise IterationStateError(
                "The iteration controller has already terminated."
            )

        if self._iteration_count >= self._limits.maximum_iterations:
            raise IterationLimitExceededError(
                "The reviewed maximum iteration count was reached."
            )

        if (
            isinstance(residual, bool)
            or isinstance(reference_magnitude, bool)
            or not isinstance(residual, (int, float))
            or not isinstance(reference_magnitude, (int, float))
        ):
            raise NonFiniteIterationError(
                "Iteration residuals must be finite numerical values."
            )

        try:
            numeric_residual = float(residual)
        except (OverflowError, ValueError):
            numeric_residual = float("inf")

        try:
            numeric_reference = float(reference_magnitude)
        except (OverflowError, ValueError):
            numeric_reference = float("inf")
        object.__setattr__(
            self,
            "_iteration_count",
            self._iteration_count + 1,
        )

        if (
            not isfinite(numeric_residual)
            or not isfinite(numeric_reference)
            or abs(numeric_residual) > MAX_ABSOLUTE_OPTION_NUMBER
            or abs(numeric_reference) > MAX_ABSOLUTE_OPTION_NUMBER
        ):
            object.__setattr__(
                self,
                "_outcome",
                IterationOutcome(
                    iterations_used=self._iteration_count,
                    converged=False,
                    termination_reason=(
                        IterationTerminationReason.NON_FINITE_VALUE
                    ),
                    final_residual=MAX_ABSOLUTE_OPTION_NUMBER,
                    description=(
                        "Iteration stopped because a non-finite value was "
                        "reported."
                    ),
                ),
            )
            raise NonFiniteIterationError(
                "A non-finite iteration value was reported."
            )

        absolute_residual = abs(numeric_residual)

        if (
            self._limits.divergence_limit is not None
            and absolute_residual > self._limits.divergence_limit
        ):
            object.__setattr__(
                self,
                "_outcome",
                IterationOutcome(
                    iterations_used=self._iteration_count,
                    converged=False,
                    termination_reason=(
                        IterationTerminationReason.DIVERGED
                    ),
                    final_residual=min(
                        absolute_residual,
                        MAX_ABSOLUTE_OPTION_NUMBER,
                    ),
                    description=(
                        "Iteration stopped after exceeding the reviewed "
                        "divergence limit."
                    ),
                ),
            )
            return False

        threshold = max(
            self._limits.absolute_tolerance,
            (
                self._limits.relative_tolerance
                * abs(numeric_reference)
            ),
        )

        if absolute_residual <= threshold:
            object.__setattr__(
                self,
                "_outcome",
                IterationOutcome(
                    iterations_used=self._iteration_count,
                    converged=True,
                    termination_reason=(
                        IterationTerminationReason.CONVERGED
                    ),
                    final_residual=min(
                        absolute_residual,
                        MAX_ABSOLUTE_OPTION_NUMBER,
                    ),
                    description=(
                        "Reviewed convergence criteria were satisfied."
                    ),
                ),
            )
            return True

        if self._iteration_count == self._limits.maximum_iterations:
            object.__setattr__(
                self,
                "_outcome",
                IterationOutcome(
                    iterations_used=self._iteration_count,
                    converged=False,
                    termination_reason=(
                        IterationTerminationReason.MAXIMUM_ITERATIONS
                    ),
                    final_residual=min(
                        absolute_residual,
                        MAX_ABSOLUTE_OPTION_NUMBER,
                    ),
                    description=(
                        "The reviewed maximum iteration count was reached "
                        "without convergence."
                    ),
                ),
            )

        return False


def _deduplicate_models(
    values: tuple[CalculationModel, ...],
    *,
    attribute_name: str,
) -> tuple[Any, ...]:
    """Preserve order and reject conflicting identifier reuse."""

    result: list[CalculationModel] = []
    by_identifier: dict[str, CalculationModel] = {}

    for value in values:
        identifier = _comparison_text(
            str(getattr(value, attribute_name))
        )
        existing = by_identifier.get(identifier)

        if existing is None:
            by_identifier[identifier] = value
            result.append(value)
            continue

        if existing != value:
            raise CalculationExecutionContractError(
                "Conflicting calculation records share an identifier."
            )

    return tuple(result)


def _bounded_verification_requirements(
    values: tuple[VerificationRequirement, ...],
    *,
    findings: tuple[CalculationFinding, ...],
    assumptions: tuple[CalculationAssumption, ...],
) -> tuple[VerificationRequirement, ...]:
    """Preserve every linked verification and fill remaining capacity.

    Method metadata may legally occupy the entire shared collection bound.
    Engine- or safety-owned findings still require a resolvable verification
    record, so linked records are selected first and unlinked metadata fills
    only the remaining capacity.
    """

    deduplicated = _deduplicate_models(
        values,
        attribute_name="verification_id",
    )
    required_ids = {
        _comparison_text(identifier)
        for finding in findings
        for identifier in finding.verification_requirement_ids
    }
    required_ids.update(
        _comparison_text(identifier)
        for assumption in assumptions
        for identifier in assumption.verification_requirement_ids
    )
    available_ids = {
        _comparison_text(value.verification_id)
        for value in deduplicated
    }
    if not required_ids.issubset(available_ids):
        raise CalculationExecutionContractError(
            "A result links an unavailable verification requirement."
        )

    required_values = tuple(
        value
        for value in deduplicated
        if _comparison_text(value.verification_id) in required_ids
    )
    if len(required_values) > MAX_VERIFICATION_REQUIREMENTS:
        raise CalculationExecutionContractError(
            "Linked verification requirements exceed the result limit."
        )

    remaining_capacity = (
        MAX_VERIFICATION_REQUIREMENTS - len(required_values)
    )
    unlinked_values = tuple(
        value
        for value in deduplicated
        if _comparison_text(value.verification_id) not in required_ids
    )
    return (
        *required_values,
        *unlinked_values[:remaining_capacity],
    )


def _unique_identifier(
    base: str,
    existing: set[str],
) -> str:
    """Return a deterministic bounded engine-owned identifier."""

    candidate = base[:100]

    if _comparison_text(candidate) not in existing:
        return candidate

    for index in range(2, 10_000):
        suffix = f"-{index}"
        candidate = f"{base[:100 - len(suffix)]}{suffix}"

        if _comparison_text(candidate) not in existing:
            return candidate

    raise CalculationExecutionContractError(
        "No deterministic engine identifier remains available."
    )


class CalculationEngine:
    """Immutable orchestration boundary for one method registry."""

    __slots__ = (
        "_clock",
        "_engine_version",
        "_id_factory",
        "_locked",
        "_registry",
        "_safety_engine",
        "_validation_engine",
    )

    def __init__(
        self,
        *,
        registry: CalculationMethodRegistry = DEFAULT_METHOD_REGISTRY,
        validation_engine: CalculationValidationEngine = (
            DEFAULT_VALIDATION_ENGINE
        ),
        safety_engine: CalculationSafetyEngine = DEFAULT_SAFETY_ENGINE,
        engine_version: str = ENGINE_VERSION,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], UUID] | None = None,
    ) -> None:
        """Bind immutable application-owned dependencies."""

        object.__setattr__(self, "_locked", False)

        if type(registry) is not CalculationMethodRegistry:
            raise TypeError(
                "registry must be a CalculationMethodRegistry."
            )

        if type(validation_engine) is not CalculationValidationEngine:
            raise TypeError(
                "validation_engine must be a "
                "CalculationValidationEngine."
            )

        if type(safety_engine) is not CalculationSafetyEngine:
            raise TypeError(
                "safety_engine must be a CalculationSafetyEngine."
            )

        if (
            not isinstance(engine_version, str)
            or not _STABLE_VERSION_PATTERN.fullmatch(engine_version)
        ):
            raise ValueError(
                "engine_version must use canonical stable X.Y.Z form."
            )

        resolved_clock = clock or (lambda: datetime.now(UTC))
        resolved_id_factory = id_factory or uuid4

        if not callable(resolved_clock) or not callable(
            resolved_id_factory
        ):
            raise TypeError("clock and id_factory must be callable.")

        object.__setattr__(self, "_registry", registry)
        object.__setattr__(
            self,
            "_validation_engine",
            validation_engine,
        )
        object.__setattr__(self, "_safety_engine", safety_engine)
        object.__setattr__(self, "_engine_version", engine_version)
        object.__setattr__(self, "_clock", resolved_clock)
        object.__setattr__(
            self,
            "_id_factory",
            resolved_id_factory,
        )
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent dependency replacement after construction."""

        if getattr(self, "_locked", False):
            raise AttributeError("CalculationEngine instances are immutable.")

        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """Prevent dependency deletion after construction."""

        if getattr(self, "_locked", False):
            raise AttributeError("CalculationEngine instances are immutable.")

        object.__delattr__(self, name)

    @property
    def engine_version(self) -> str:
        """Return the stable deterministic engine version."""

        return self._engine_version

    @property
    def registry(self) -> CalculationMethodRegistry:
        """Return the immutable method registry."""

        return self._registry

    def execute(
        self,
        request: CalculationRequest,
        *,
        evidence: TrustedExecutionEvidence | None = None,
    ) -> CalculationResult:
        """Validate, gate, execute, fingerprint, and assemble one result."""

        validated_request = _revalidate_model(
            CalculationRequest,
            request,
        )
        definition = self._registry.resolve(
            validated_request.method_id,
            validated_request.method_version,
            calculation_type=validated_request.calculation_type,
        )
        resolved_evidence = self._resolve_evidence(
            definition,
            validated_request,
            (
                TrustedExecutionEvidence()
                if evidence is None
                else evidence
            ),
        )

        if not definition.is_executable:
            return self._lifecycle_blocked_result(
                definition,
                validated_request,
                resolved_evidence,
                incompatible=False,
            )

        if not definition.engine_compatibility.supports(
            self._engine_version
        ):
            return self._lifecycle_blocked_result(
                definition,
                validated_request,
                resolved_evidence,
                incompatible=True,
            )

        registration = self._registry.resolve_for_execution(
            validated_request.method_id,
            validated_request.method_version,
            calculation_type=validated_request.calculation_type,
            engine_version=self._engine_version,
        )
        validation_report = self._validate(
            validated_request,
            definition,
            resolved_evidence,
            registration,
        )
        safety_report = self._evaluate_safety(
            validation_report,
            registration,
        )
        pre_execution_status = self._pre_execution_status(
            validation_report,
            safety_report,
        )

        if pre_execution_status is not None:
            calculation_id = self._new_calculation_id()
            executed_at = self._execution_time()
            try:
                return self._assemble_pre_execution_result(
                    definition=definition,
                    request=validated_request,
                    validation_report=validation_report,
                    safety_report=safety_report,
                    status=pre_execution_status,
                    calculation_id=calculation_id,
                    executed_at=executed_at,
                )
            except Exception:
                return self._failed_result(
                    definition=definition,
                    request=validated_request,
                    validation_report=validation_report,
                    safety_report=safety_report,
                    finding_id=(
                        ENGINE_PRE_EXECUTION_RESULT_FINDING_ID
                    ),
                    title="Pre-execution result validation failed",
                    message=(
                        "The validated pre-execution state could not be "
                        "assembled into a controlled calculation result."
                    ),
                    calculation_id=calculation_id,
                    executed_at=executed_at,
                )

        execution_context = MethodExecutionContext(
            request=validated_request,
            definition=definition,
            engine_version=self._engine_version,
            normalized_inputs=validation_report.normalized_inputs,
            defaulted_inputs=validation_report.defaulted_inputs,
            effective_options=validation_report.effective_options,
            assumptions=validation_report.assumptions,
            evidence=validation_report.evidence,
        )
        iteration_controller = (
            None
            if definition.iteration_limits is None
            else IterationController(definition.iteration_limits)
        )

        try:
            raw_outcome = registration.implementation(
                execution_context,
                iteration_controller,
            )
            outcome = _revalidate_model(
                MethodExecutionOutcome,
                raw_outcome,
            )
            self._validate_outcome(
                definition,
                execution_context,
                outcome,
                iteration_controller,
            )
        except Exception:
            return self._failed_result(
                definition=definition,
                request=validated_request,
                validation_report=validation_report,
                safety_report=safety_report,
                finding_id=ENGINE_EXECUTION_FINDING_ID,
                title="Calculation execution failed",
                message=(
                    "The reviewed calculation implementation did not "
                    "complete its controlled execution contract."
                ),
            )

        if (
            outcome.iteration_outcome is not None
            and not outcome.iteration_outcome.converged
        ):
            return self._failed_result(
                definition=definition,
                request=validated_request,
                validation_report=validation_report,
                safety_report=safety_report,
                finding_id=ENGINE_NONCONVERGENCE_FINDING_ID,
                title="Calculation did not converge",
                message=(
                    "The iterative calculation stopped without satisfying "
                    "its reviewed convergence criteria."
                ),
                trace_steps=self._merge_trace(
                    validation_report.normalization_trace,
                    outcome.trace_steps,
                ),
            )

        return self._completed_result(
            definition=definition,
            request=validated_request,
            validation_report=validation_report,
            safety_report=safety_report,
            outcome=outcome,
        )

    def _validate(
        self,
        request: CalculationRequest,
        definition: CalculationMethodDefinition,
        evidence: TrustedExecutionEvidence,
        registration: MethodRegistration,
    ) -> CalculationValidationReport:
        """Run the complete generic and code-bound validation boundary."""

        return self._validation_engine.validate(
            request,
            definition,
            evidence=evidence,
            input_normalizers=registration.input_normalizers,
            applicability_evaluators=(
                registration.applicability_evaluators
            ),
        )

    def _evaluate_safety(
        self,
        report: CalculationValidationReport,
        registration: MethodRegistration,
    ) -> SafetyReport:
        """Run safety evaluation after validation and before execution."""

        try:
            context = SafetyEvaluationContext(
                request=report.request,
                definition=report.definition,
                supplied_inputs=report.request.inputs,
                normalized_inputs=report.normalized_inputs,
                defaulted_inputs=report.defaulted_inputs,
                effective_options=report.effective_options,
                assumptions=report.assumptions,
                missing_inputs=report.missing_inputs,
                existing_findings=report.findings,
                evidence=report.evidence,
            )
            return self._safety_engine.evaluate(
                context,
                registration.safety_evaluator,
            )
        except Exception:
            return self._safety_engine.failure_report(
                report.definition,
                existing_findings=report.findings,
                existing_verification_requirements=(
                    report.verification_requirements
                ),
            )

    @staticmethod
    def _pre_execution_status(
        validation_report: CalculationValidationReport,
        safety_report: SafetyReport,
    ) -> CalculationStatus | None:
        """Apply the frozen fail-closed pre-execution status precedence."""

        if safety_report.blocked:
            return CalculationStatus.BLOCKED

        blocking_applicability = any(
            finding.blocking
            and finding.category is FindingCategory.APPLICABILITY
            for finding in validation_report.findings
        )
        if blocking_applicability:
            return CalculationStatus.NOT_APPLICABLE

        if any(
            value.required_for_execution
            for value in validation_report.missing_inputs
        ):
            return CalculationStatus.INSUFFICIENT_INPUT

        if any(
            finding.blocking
            for finding in validation_report.findings
        ):
            return CalculationStatus.BLOCKED

        if not validation_report.can_execute:
            return CalculationStatus.BLOCKED

        return None

    @staticmethod
    def _validate_outcome(
        definition: CalculationMethodDefinition,
        context: MethodExecutionContext,
        outcome: MethodExecutionOutcome,
        iteration_controller: IterationController | None,
    ) -> None:
        """Recheck formulas, iteration state, and result-link boundaries."""

        formula_ids = {
            _comparison_text(value.formula_identifier)
            for value in definition.formulas
        }

        for step in outcome.trace_steps:
            if (
                step.formula_identifier is not None
                and _comparison_text(step.formula_identifier)
                not in formula_ids
            ):
                raise CalculationExecutionContractError(
                    "An execution trace used an undeclared formula."
                )

        if any(
            finding.category is FindingCategory.SAFETY
            for finding in outcome.findings
        ):
            raise CalculationExecutionContractError(
                "Safety findings must be produced before execution."
            )

        evidence_reference_ids = {
            _comparison_text(value.reference_id)
            for value in context.evidence.references
        }
        evidence_verification_ids = {
            _comparison_text(value.verification_id)
            for value in context.evidence.verification_requirements
        }

        for step in outcome.trace_steps:
            for trace_value in step.output_values:
                if not {
                    _comparison_text(value)
                    for value in trace_value.source_reference_ids
                }.issubset(evidence_reference_ids):
                    raise CalculationExecutionContractError(
                        "A trace value used unresolved evidence."
                    )

        for output in outcome.outputs:
            if not {
                _comparison_text(value)
                for value in output.source_reference_ids
            }.issubset(evidence_reference_ids):
                raise CalculationExecutionContractError(
                    "An output used unresolved evidence."
                )

        for finding in outcome.findings:
            if not {
                _comparison_text(value)
                for value in finding.reference_ids
            }.issubset(evidence_reference_ids):
                raise CalculationExecutionContractError(
                    "An execution finding used unresolved evidence."
                )

            if not {
                _comparison_text(value)
                for value in finding.verification_requirement_ids
            }.issubset(evidence_verification_ids):
                raise CalculationExecutionContractError(
                    "An execution finding used unresolved verification."
                )

        if definition.iteration_limits is None:
            if (
                iteration_controller is not None
                or outcome.iteration_outcome is not None
                or any(
                    step.kind is TraceStepKind.ITERATION
                    for step in outcome.trace_steps
                )
            ):
                raise CalculationExecutionContractError(
                    "A non-iterative method returned iteration state."
                )
            return

        if (
            iteration_controller is None
            or iteration_controller.outcome is None
            or outcome.iteration_outcome is None
        ):
            raise CalculationExecutionContractError(
                "An iterative method did not use its engine controller."
            )

        if getattr(iteration_controller, "_locked", None) is not True:
            raise CalculationExecutionContractError(
                "The engine iteration controller lock was altered."
            )

        reviewed_limits = _revalidate_model(
            IterationLimits,
            iteration_controller.limits,
        )
        controller_outcome = _revalidate_model(
            IterationOutcome,
            iteration_controller.outcome,
        )

        if reviewed_limits != definition.iteration_limits:
            raise CalculationExecutionContractError(
                "The engine iteration limits were altered."
            )

        if (
            type(iteration_controller.iterations_used) is not int
            or iteration_controller.iterations_used
            != outcome.iteration_outcome.iterations_used
        ):
            raise CalculationExecutionContractError(
                "Iteration count does not match the engine controller."
            )

        if controller_outcome != outcome.iteration_outcome:
            raise CalculationExecutionContractError(
                "Iteration outcome does not match the engine controller."
            )

        if (
            outcome.iteration_outcome.iterations_used
            > definition.iteration_limits.maximum_iterations
        ):
            raise CalculationExecutionContractError(
                "Iteration outcome exceeds the reviewed method limit."
            )

    def _completed_result(
        self,
        *,
        definition: CalculationMethodDefinition,
        request: CalculationRequest,
        validation_report: CalculationValidationReport,
        safety_report: SafetyReport,
        outcome: MethodExecutionOutcome,
    ) -> CalculationResult:
        """Assemble a completed result; fail safely on any graph defect."""

        calculation_id = self._new_calculation_id()
        executed_at = self._execution_time()
        try:
            findings = _deduplicate_models(
                (
                    *safety_report.findings,
                    *validation_report.findings,
                    *outcome.findings,
                ),
                attribute_name="finding_id",
            )
            assumptions = _deduplicate_models(
                (
                    *validation_report.assumptions,
                    *outcome.assumptions,
                ),
                attribute_name="assumption_id",
            )
            verification_requirements = _bounded_verification_requirements(
                (
                    *validation_report.evidence.verification_requirements,
                    *validation_report.verification_requirements,
                    *safety_report.verification_requirements,
                ),
                findings=findings,
                assumptions=assumptions,
            )
            trace_steps = self._merge_trace(
                validation_report.normalization_trace,
                outcome.trace_steps,
            )
            status = self._completed_status(
                findings=findings,
                missing_inputs=validation_report.missing_inputs,
                assumptions=assumptions,
                references=validation_report.evidence.references,
            )
            fingerprint = self._fingerprint_from_report(
                definition=definition,
                report=validation_report,
                assumptions=assumptions,
                status=status,
                findings=findings,
            )
            result = CalculationResult(
                calculation_id=calculation_id,
                request_id=request.request_id,
                calculation_type=definition.calculation_type,
                method_id=definition.method_id,
                method_version=definition.method_version,
                method_lifecycle_status=definition.lifecycle_status,
                engine_version=self._engine_version,
                executed_at=executed_at,
                status=status,
                result_fingerprint=fingerprint,
                supplied_inputs=request.inputs,
                normalized_inputs=validation_report.normalized_inputs,
                defaulted_inputs=validation_report.defaulted_inputs,
                effective_options=validation_report.effective_options,
                assumptions=assumptions,
                missing_inputs=validation_report.missing_inputs,
                findings=findings,
                trace_steps=trace_steps,
                outputs=outcome.outputs,
                references=validation_report.evidence.references,
                verification_requirements=verification_requirements,
                limitations=self._merge_text(
                    definition.limitations,
                    outcome.limitations,
                ),
                exclusions=self._merge_text(
                    definition.exclusions,
                    outcome.exclusions,
                ),
                required_reviewer_competency=(
                    definition.required_reviewer_competency
                ),
                disclaimer=definition.disclaimer,
            )
            return result
        except Exception:
            return self._failed_result(
                definition=definition,
                request=request,
                validation_report=validation_report,
                safety_report=safety_report,
                finding_id=ENGINE_RESULT_FINDING_ID,
                title="Calculation result validation failed",
                message=(
                    "The implementation output did not satisfy the complete "
                    "calculation-result contract."
                ),
                calculation_id=calculation_id,
                executed_at=executed_at,
            )

    @staticmethod
    def _completed_status(
        *,
        findings: tuple[CalculationFinding, ...],
        missing_inputs: tuple[MissingCalculationInput, ...],
        assumptions: tuple[CalculationAssumption, ...],
        references: tuple[CalculationReference, ...],
    ) -> CalculationStatus:
        """Derive the completed state from visible warning context."""

        warning_present = any(
            finding.severity
            in {
                FindingSeverity.CAUTION,
                FindingSeverity.WARNING,
                FindingSeverity.ERROR,
                FindingSeverity.CRITICAL,
            }
            for finding in findings
        )
        awaiting_verification = any(
            assumption.requires_verification
            and not assumption.verification_completed
            for assumption in assumptions
        )
        unverified_reference = any(
            not reference.verified
            for reference in references
        )

        if (
            warning_present
            or missing_inputs
            or awaiting_verification
            or unverified_reference
        ):
            return CalculationStatus.COMPLETED_WITH_WARNINGS

        return CalculationStatus.COMPLETED

    def _assemble_pre_execution_result(
        self,
        *,
        definition: CalculationMethodDefinition,
        request: CalculationRequest,
        validation_report: CalculationValidationReport,
        safety_report: SafetyReport,
        status: CalculationStatus,
        calculation_id: UUID,
        executed_at: datetime,
    ) -> CalculationResult:
        """Assemble a valid non-executed result with safety findings first."""

        findings = _deduplicate_models(
            (
                *safety_report.findings,
                *validation_report.findings,
            ),
            attribute_name="finding_id",
        )
        verification_requirements = _bounded_verification_requirements(
            (
                *validation_report.evidence.verification_requirements,
                *validation_report.verification_requirements,
                *safety_report.verification_requirements,
            ),
            findings=findings,
            assumptions=validation_report.assumptions,
        )
        fingerprint = self._fingerprint_from_report(
            definition=definition,
            report=validation_report,
            assumptions=validation_report.assumptions,
            status=status,
            findings=findings,
        )

        return CalculationResult(
            calculation_id=calculation_id,
            request_id=request.request_id,
            calculation_type=definition.calculation_type,
            method_id=definition.method_id,
            method_version=definition.method_version,
            method_lifecycle_status=definition.lifecycle_status,
            engine_version=self._engine_version,
            executed_at=executed_at,
            status=status,
            result_fingerprint=fingerprint,
            supplied_inputs=request.inputs,
            normalized_inputs=validation_report.normalized_inputs,
            defaulted_inputs=validation_report.defaulted_inputs,
            effective_options=validation_report.effective_options,
            assumptions=validation_report.assumptions,
            missing_inputs=validation_report.missing_inputs,
            findings=findings,
            trace_steps=validation_report.normalization_trace,
            references=validation_report.evidence.references,
            verification_requirements=verification_requirements,
            limitations=definition.limitations,
            exclusions=definition.exclusions,
            required_reviewer_competency=(
                definition.required_reviewer_competency
            ),
            disclaimer=definition.disclaimer,
        )

    def _failed_result(
        self,
        *,
        definition: CalculationMethodDefinition,
        request: CalculationRequest,
        validation_report: CalculationValidationReport,
        safety_report: SafetyReport,
        finding_id: str,
        title: str,
        message: str,
        trace_steps: tuple[CalculationTraceStep, ...] = (),
        calculation_id: UUID | None = None,
        executed_at: datetime | None = None,
    ) -> CalculationResult:
        """Return a sanitized deterministic failure without invalid outputs."""

        existing_verification_ids = {
            _comparison_text(value.verification_id)
            for value in (
                *validation_report.evidence.verification_requirements,
                *validation_report.verification_requirements,
                *safety_report.verification_requirements,
            )
        }
        verification_id = _unique_identifier(
            "verify.engine-execution",
            existing_verification_ids,
        )
        existing_finding_ids = {
            _comparison_text(value.finding_id)
            for value in (
                *validation_report.findings,
                *safety_report.findings,
            )
        }
        resolved_finding_id = _unique_identifier(
            finding_id,
            existing_finding_ids,
        )
        verification = VerificationRequirement(
            verification_id=verification_id,
            description=(
                "Independently review the calculation implementation, "
                "method metadata, normalized inputs, and execution trace."
            ),
            method=(
                "Reproduce the calculation using the approved method "
                "record and independent reference vectors."
            ),
            expected_result=(
                "The implementation completes deterministically and agrees "
                "with approved reference evidence."
            ),
            required_competency=(
                definition.required_reviewer_competency
            ),
            verifier_role="Independent competent engineering reviewer",
            independent_verification_required=True,
            evidence_required=(
                "Approved method record",
                "Independent reproduction evidence",
            ),
        )
        failure_finding = CalculationFinding(
            finding_id=resolved_finding_id,
            category=FindingCategory.NUMERICAL,
            severity=FindingSeverity.ERROR,
            title=title,
            message=message,
            blocking=True,
            required_action=(
                "Do not use a numerical result until the controlled "
                "implementation has been independently reviewed."
            ),
            verification_requirement_ids=(verification_id,),
        )
        resolved_calculation_id = (
            self._new_calculation_id()
            if calculation_id is None
            else calculation_id
        )
        resolved_executed_at = (
            self._execution_time()
            if executed_at is None
            else executed_at
        )
        try:
            findings = _deduplicate_models(
                (
                    *safety_report.findings,
                    *validation_report.findings,
                    failure_finding,
                ),
                attribute_name="finding_id",
            )
            verification_requirements = _bounded_verification_requirements(
                (
                    *validation_report.evidence.verification_requirements,
                    *validation_report.verification_requirements,
                    *safety_report.verification_requirements,
                    verification,
                ),
                findings=findings,
                assumptions=validation_report.assumptions,
            )
            fingerprint = self._fingerprint_from_report(
                definition=definition,
                report=validation_report,
                assumptions=validation_report.assumptions,
                status=CalculationStatus.FAILED,
                findings=findings,
            )
            return CalculationResult(
                calculation_id=resolved_calculation_id,
                request_id=request.request_id,
                calculation_type=definition.calculation_type,
                method_id=definition.method_id,
                method_version=definition.method_version,
                method_lifecycle_status=definition.lifecycle_status,
                engine_version=self._engine_version,
                executed_at=resolved_executed_at,
                status=CalculationStatus.FAILED,
                result_fingerprint=fingerprint,
                supplied_inputs=request.inputs,
                normalized_inputs=validation_report.normalized_inputs,
                defaulted_inputs=validation_report.defaulted_inputs,
                effective_options=validation_report.effective_options,
                assumptions=validation_report.assumptions,
                missing_inputs=validation_report.missing_inputs,
                findings=findings,
                trace_steps=trace_steps,
                references=validation_report.evidence.references,
                verification_requirements=verification_requirements,
                limitations=definition.limitations,
                exclusions=definition.exclusions,
                required_reviewer_competency=(
                    definition.required_reviewer_competency
                ),
                disclaimer=definition.disclaimer,
            )
        except (TypeError, ValueError):
            fallback_findings = (failure_finding,)
            fallback_verifications = (verification,)
            fallback_fingerprint = fingerprint_payload(
                build_attempt_fingerprint_payload(
                    definition=definition,
                    request=request,
                    disposition="execution_failed",
                    evidence=validation_report.evidence,
                    finding_ids=(failure_finding.finding_id,),
                )
            )
            return CalculationResult(
                calculation_id=resolved_calculation_id,
                request_id=request.request_id,
                calculation_type=definition.calculation_type,
                method_id=definition.method_id,
                method_version=definition.method_version,
                method_lifecycle_status=definition.lifecycle_status,
                engine_version=self._engine_version,
                executed_at=resolved_executed_at,
                status=CalculationStatus.FAILED,
                result_fingerprint=fallback_fingerprint,
                supplied_inputs=request.inputs,
                findings=fallback_findings,
                references=validation_report.evidence.references,
                verification_requirements=fallback_verifications,
                limitations=definition.limitations,
                exclusions=definition.exclusions,
                required_reviewer_competency=(
                    definition.required_reviewer_competency
                ),
                disclaimer=definition.disclaimer,
            )

    def _lifecycle_blocked_result(
        self,
        definition: CalculationMethodDefinition,
        request: CalculationRequest,
        evidence: TrustedExecutionEvidence,
        *,
        incompatible: bool,
    ) -> CalculationResult:
        """Return a visible block without exposing or invoking a handler."""

        existing_verification_ids = {
            _comparison_text(value.verification_id)
            for value in evidence.verification_requirements
        }
        verification_id = _unique_identifier(
            (
                "verify.engine-compatibility"
                if incompatible
                else "verify.method-lifecycle"
            ),
            existing_verification_ids,
        )
        verification = VerificationRequirement(
            verification_id=verification_id,
            description=(
                "Confirm the exact method lifecycle, review evidence, and "
                "engine compatibility before execution."
            ),
            method=(
                "Review the controlled method record and approved software "
                "release evidence."
            ),
            expected_result=(
                "The exact method version is approved and explicitly "
                "supports the active engine version."
            ),
            required_competency=(
                definition.required_reviewer_competency
            ),
        )
        finding = CalculationFinding(
            finding_id=(
                ENGINE_COMPATIBILITY_FINDING_ID
                if incompatible
                else ENGINE_LIFECYCLE_FINDING_ID
            ),
            category=FindingCategory.STANDARDS,
            severity=FindingSeverity.ERROR,
            title=(
                "Calculation method is engine-incompatible"
                if incompatible
                else "Calculation method is not approved"
            ),
            message=(
                "The exact method version cannot execute with this engine "
                "version."
                if incompatible
                else (
                    "The exact method version has not reached the approved "
                    "execution lifecycle."
                )
            ),
            blocking=True,
            required_action=(
                "Use only an exact method version with complete approval "
                "and explicit engine compatibility."
            ),
            verification_requirement_ids=(verification_id,),
        )
        fingerprint = fingerprint_payload(
            build_attempt_fingerprint_payload(
                definition=definition,
                request=request,
                disposition=(
                    "engine_incompatible"
                    if incompatible
                    else "lifecycle_blocked"
                ),
                evidence=evidence,
                finding_ids=(finding.finding_id,),
            )
        )

        return CalculationResult(
            calculation_id=self._new_calculation_id(),
            request_id=request.request_id,
            calculation_type=definition.calculation_type,
            method_id=definition.method_id,
            method_version=definition.method_version,
            method_lifecycle_status=definition.lifecycle_status,
            engine_version=self._engine_version,
            executed_at=self._execution_time(),
            status=CalculationStatus.BLOCKED,
            result_fingerprint=fingerprint,
            supplied_inputs=request.inputs,
            findings=(finding,),
            references=evidence.references,
            verification_requirements=(verification,),
            limitations=definition.limitations,
            exclusions=definition.exclusions,
            required_reviewer_competency=(
                definition.required_reviewer_competency
            ),
            disclaimer=definition.disclaimer,
        )

    @staticmethod
    def _resolve_evidence(
        definition: CalculationMethodDefinition,
        request: CalculationRequest,
        evidence: TrustedExecutionEvidence,
    ) -> TrustedExecutionEvidence:
        """Merge only exact server-resolved evidence required by the request."""

        if type(evidence) is not TrustedExecutionEvidence:
            raise CalculationEvidenceError(
                "Trusted execution evidence failed validation because it "
                "does not use the controlled evidence model."
            )

        try:
            validated_evidence = _revalidate_model(
                TrustedExecutionEvidence,
                evidence,
            )
        except (TypeError, ValueError) as exc:
            raise CalculationEvidenceError(
                "Trusted execution evidence failed validation."
            ) from exc
        method_references = {
            _comparison_text(value.reference_id): value
            for value in definition.references
        }
        method_verifications = {
            _comparison_text(value.verification_id): value
            for value in definition.verification_requirements
        }
        supplied_references = {
            _comparison_text(value.reference_id): value
            for value in validated_evidence.references
        }
        supplied_verifications = {
            _comparison_text(value.verification_id): value
            for value in validated_evidence.verification_requirements
        }
        requested_reference_ids = {
            _comparison_text(value)
            for value in request.reference_ids
        }
        requested_verification_ids = {
            _comparison_text(verification_id)
            for assumption in request.assumptions
            for verification_id
            in assumption.verification_requirement_ids
        }
        expected_external_references = (
            requested_reference_ids - set(method_references)
        )
        expected_external_verifications = (
            requested_verification_ids - set(method_verifications)
        )

        if set(supplied_references) != expected_external_references:
            raise CalculationEvidenceError(
                "Trusted references do not exactly resolve request links."
            )

        if set(supplied_verifications) != expected_external_verifications:
            raise CalculationEvidenceError(
                "Trusted verification records do not exactly resolve "
                "request assumptions."
            )

        merged_references = (
            *definition.references,
            *(
                supplied_references[key]
                for key in sorted(supplied_references)
            ),
        )
        merged_verifications = (
            *definition.verification_requirements,
            *(
                supplied_verifications[key]
                for key in sorted(supplied_verifications)
            ),
        )

        try:
            return TrustedExecutionEvidence(
                references=merged_references,
                verification_requirements=merged_verifications,
            )
        except (TypeError, ValueError) as exc:
            raise CalculationEvidenceError(
                "Resolved evidence exceeds or conflicts with the controlled "
                "execution boundary."
            ) from exc

    @staticmethod
    def _merge_trace(
        validation_trace: tuple[CalculationTraceStep, ...],
        execution_trace: tuple[CalculationTraceStep, ...],
    ) -> tuple[CalculationTraceStep, ...]:
        """Append implementation trace with engine-owned sequence numbers."""

        result = list(validation_trace)
        offset = len(result)

        for index, step in enumerate(execution_trace, start=1):
            result.append(
                step.model_copy(
                    update={"sequence": offset + index}
                )
            )

        return tuple(result)

    @staticmethod
    def _merge_text(
        first: tuple[str, ...],
        second: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Merge text case-insensitively while preserving first occurrence."""

        result: list[str] = []
        seen: set[str] = set()

        for value in (*first, *second):
            key = value.casefold()
            if key in seen:
                continue

            seen.add(key)
            result.append(value)

        return tuple(result)

    @staticmethod
    def _fingerprint_from_report(
        *,
        definition: CalculationMethodDefinition,
        report: CalculationValidationReport,
        assumptions: tuple[CalculationAssumption, ...],
        status: CalculationStatus,
        findings: tuple[CalculationFinding, ...],
    ) -> str:
        """Use normalized content when complete, otherwise typed raw content."""

        normalized_ids = {
            _comparison_text(value.input_id)
            for value in report.normalized_inputs
        }
        supplied_ids = {
            _comparison_text(value.input_id)
            for value in report.request.inputs
        }
        required_ids = {
            _comparison_text(value.input_id)
            for value in definition.input_specifications
            if value.presence.value in {"required", "defaulted"}
        }
        effective_option_ids = {
            _comparison_text(value.option_id)
            for value in report.effective_options
        }
        supplied_option_ids = {
            _comparison_text(value.option_id)
            for value in report.request.options
        }
        normalized_complete = (
            supplied_ids.issubset(normalized_ids)
            and required_ids.issubset(normalized_ids)
            and supplied_option_ids.issubset(effective_option_ids)
        )

        if normalized_complete:
            return fingerprint_payload(
                build_fingerprint_payload(
                    method_id=definition.method_id,
                    method_version=definition.method_version,
                    normalized_inputs=report.normalized_inputs,
                    effective_options=report.effective_options,
                    assumptions=assumptions,
                    references=report.evidence.references,
                    verification_requirements=(
                        report.evidence.verification_requirements
                    ),
                    status=status,
                    finding_ids=tuple(
                        value.finding_id
                        for value in findings
                    ),
                    missing_input_ids=tuple(
                        value.input_id
                        for value in report.missing_inputs
                    ),
                )
            )

        return fingerprint_payload(
            build_attempt_fingerprint_payload(
                definition=definition,
                request=report.request,
                disposition=status.value,
                evidence=report.evidence,
                finding_ids=tuple(
                    value.finding_id
                    for value in findings
                ),
            )
        )

    def _new_calculation_id(self) -> UUID:
        """Return a validated engine-owned result ID."""

        value = self._id_factory()

        if not isinstance(value, UUID):
            raise CalculationExecutionContractError(
                "id_factory must return UUID values."
            )

        return value

    def _execution_time(self) -> datetime:
        """Return one normalized aware execution timestamp."""

        value = self._clock()

        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise CalculationExecutionContractError(
                "clock must return an aware datetime."
            )

        return value.astimezone(UTC)


DEFAULT_CALCULATION_ENGINE = CalculationEngine()


__all__ = [
    "ATTEMPT_FINGERPRINT_SCHEMA",
    "CalculationEngine",
    "CalculationEngineError",
    "CalculationEvidenceError",
    "CalculationExecutionContractError",
    "DEFAULT_CALCULATION_ENGINE",
    "ENGINE_COMPATIBILITY_FINDING_ID",
    "ENGINE_EXECUTION_FINDING_ID",
    "ENGINE_LIFECYCLE_FINDING_ID",
    "ENGINE_NONCONVERGENCE_FINDING_ID",
    "ENGINE_PRE_EXECUTION_RESULT_FINDING_ID",
    "ENGINE_RESULT_FINDING_ID",
    "ENGINE_VERSION",
    "FINGERPRINT_SCHEMA",
    "IterationControlError",
    "IterationController",
    "IterationLimitExceededError",
    "IterationStateError",
    "NonFiniteIterationError",
    "build_attempt_fingerprint_payload",
    "build_fingerprint_payload",
    "canonical_fingerprint_bytes",
    "fingerprint_payload",
]
