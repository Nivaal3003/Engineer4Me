"""Deterministic request validation for reviewed calculation methods.

The validation boundary revalidates every Pydantic object it receives, walks
method input and option specifications in their declared order, and produces
an immutable report.  Generic quantities are normalized only through the
public Step 91 unit-registry API.  A method-specific quantity can be
normalized only by a direct, module-level Python function supplied by the
trusted method registry; no expression, callable name, module path, private
unit conversion, or dynamic import is accepted.
"""

from __future__ import annotations

from collections.abc import Callable
from collections.abc import Mapping
from inspect import Parameter
from inspect import isasyncgenfunction
from inspect import iscoroutinefunction
from inspect import isgeneratorfunction
from inspect import signature
from types import FunctionType
from types import MappingProxyType
import sys
from typing import Any
from typing import TypeVar

from pydantic import Field
from pydantic import StrictBool
from pydantic import ValidationError
from pydantic import model_validator

from app.engineering.calculations.method_models import ApplicabilityRule
from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
)
from app.engineering.calculations.method_models import InputNormalizationMode
from app.engineering.calculations.method_models import InputPresence
from app.engineering.calculations.method_models import InputValueType
from app.engineering.calculations.method_models import (
    MethodInputSpecification,
)
from app.engineering.calculations.method_models import (
    MethodOptionSpecification,
)
from app.engineering.calculations.method_models import (
    TrustedExecutionEvidence,
)
from app.engineering.calculations.models import CalculationAssumption
from app.engineering.calculations.models import CalculationFinding
from app.engineering.calculations.models import CalculationInput
from app.engineering.calculations.models import CalculationModel
from app.engineering.calculations.models import CalculationOption
from app.engineering.calculations.models import CalculationRequest
from app.engineering.calculations.models import CalculationTraceStep
from app.engineering.calculations.models import CalculationTraceValue
from app.engineering.calculations.models import FindingCategory
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import MAX_ASSUMPTIONS
from app.engineering.calculations.models import MAX_FINDINGS
from app.engineering.calculations.models import MAX_INPUTS
from app.engineering.calculations.models import MAX_MISSING_INPUTS
from app.engineering.calculations.models import MAX_OPTIONS
from app.engineering.calculations.models import MAX_TRACE_STEPS
from app.engineering.calculations.models import (
    MAX_VERIFICATION_REQUIREMENTS,
)
from app.engineering.calculations.models import MissingCalculationInput
from app.engineering.calculations.models import TraceStepKind
from app.engineering.calculations.models import TraceStepStatus
from app.engineering.calculations.models import VerificationRequirement
from app.engineering.calculations.units import DEFAULT_UNIT_REGISTRY
from app.engineering.calculations.units import UnitSystemError


MethodSpecificNormalizer = Callable[
    [MethodInputSpecification, CalculationInput],
    CalculationInput,
]
ApplicabilityEvaluator = Callable[
    [ApplicabilityRule, tuple[CalculationInput, ...]],
    bool,
]

_ModelT = TypeVar("_ModelT", bound=CalculationModel)
_GENERIC_VERIFICATION_ID = "validation-engine-review"
_EMPTY_NORMALIZERS: Mapping[str, MethodSpecificNormalizer] = MappingProxyType(
    {}
)
_EMPTY_EVALUATORS: Mapping[str, ApplicabilityEvaluator] = MappingProxyType({})


class CalculationValidationError(ValueError):
    """Base error for validation-boundary contract failures."""

    code = "calculation_validation_error"


class InvalidValidationContractError(CalculationValidationError):
    """Raised when a trusted boundary object cannot be revalidated."""

    code = "invalid_validation_contract"


class CalculationValidationReport(CalculationModel):
    """Immutable, bounded output of one method-validation attempt."""

    request: CalculationRequest
    definition: CalculationMethodDefinition
    evidence: TrustedExecutionEvidence
    normalized_inputs: tuple[CalculationInput, ...] = Field(
        default_factory=tuple,
        max_length=MAX_INPUTS,
    )
    defaulted_inputs: tuple[CalculationInput, ...] = Field(
        default_factory=tuple,
        max_length=MAX_INPUTS,
    )
    effective_options: tuple[CalculationOption, ...] = Field(
        default_factory=tuple,
        max_length=MAX_OPTIONS,
    )
    assumptions: tuple[CalculationAssumption, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ASSUMPTIONS,
    )
    missing_inputs: tuple[MissingCalculationInput, ...] = Field(
        default_factory=tuple,
        max_length=MAX_MISSING_INPUTS,
    )
    findings: tuple[CalculationFinding, ...] = Field(
        default_factory=tuple,
        max_length=MAX_FINDINGS,
    )
    verification_requirements: tuple[
        VerificationRequirement,
        ...
    ] = Field(
        default_factory=tuple,
        max_length=MAX_VERIFICATION_REQUIREMENTS,
    )
    normalization_trace: tuple[CalculationTraceStep, ...] = Field(
        default_factory=tuple,
        max_length=MAX_TRACE_STEPS,
    )
    can_execute: StrictBool

    @model_validator(mode="after")
    def validate_report(self) -> "CalculationValidationReport":
        """Require unique, linked, internally consistent report content."""

        if (
            self.request.method_id.casefold()
            != self.definition.method_id.casefold()
            or self.request.method_version
            != self.definition.method_version
            or self.request.calculation_type.casefold()
            != self.definition.calculation_type.casefold()
        ):
            if not any(
                finding.blocking
                and finding.category is FindingCategory.VALIDATION
                for finding in self.findings
            ):
                raise ValueError(
                    "A method-identity mismatch requires a blocking finding."
                )

        collections = (
            (self.normalized_inputs, "input_id", "normalized_inputs"),
            (self.defaulted_inputs, "input_id", "defaulted_inputs"),
            (self.effective_options, "option_id", "effective_options"),
            (self.assumptions, "assumption_id", "assumptions"),
            (self.missing_inputs, "input_id", "missing_inputs"),
            (self.findings, "finding_id", "findings"),
            (
                self.verification_requirements,
                "verification_id",
                "verification_requirements",
            ),
            (
                self.normalization_trace,
                "step_id",
                "normalization_trace",
            ),
        )

        for values, attribute_name, field_name in collections:
            identifiers = tuple(
                str(getattr(value, attribute_name)).casefold()
                for value in values
            )
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"{field_name} identifiers must be unique.")

        normalized_ids = {
            value.input_id.casefold()
            for value in self.normalized_inputs
        }
        if not {
            value.input_id.casefold()
            for value in self.defaulted_inputs
        }.issubset(normalized_ids):
            raise ValueError(
                "Every defaulted input requires a normalized counterpart."
            )

        verification_ids = {
            value.verification_id.casefold()
            for value in self.verification_requirements
        }
        for finding in self.findings:
            if not {
                value.casefold()
                for value in finding.verification_requirement_ids
            }.issubset(verification_ids):
                raise ValueError(
                    "A finding links an unavailable verification "
                    "requirement."
                )

        expected_sequences = tuple(
            range(1, len(self.normalization_trace) + 1)
        )
        actual_sequences = tuple(
            value.sequence
            for value in self.normalization_trace
        )
        if actual_sequences != expected_sequences:
            raise ValueError(
                "Normalization trace sequences must be contiguous."
            )

        if any(
            value.kind is not TraceStepKind.NORMALIZATION
            for value in self.normalization_trace
        ):
            raise ValueError(
                "normalization_trace accepts normalization steps only."
            )

        blocked = any(value.blocking for value in self.findings) or any(
            value.required_for_execution
            for value in self.missing_inputs
        )
        if self.can_execute is blocked:
            raise ValueError(
                "can_execute must be false when validation is blocked and "
                "true otherwise."
            )

        return self

    @property
    def blocking_findings(self) -> tuple[CalculationFinding, ...]:
        """Return blocking findings without exposing mutable state."""

        return tuple(value for value in self.findings if value.blocking)


def _revalidate_model(
    value: object,
    expected_type: type[_ModelT],
    *,
    label: str,
) -> _ModelT:
    """Revalidate a possibly bypass-constructed model at the trust boundary."""

    if not isinstance(value, expected_type):
        raise InvalidValidationContractError(
            f"{label} must be a {expected_type.__name__}."
        )

    try:
        dumped_value = value.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
        return expected_type.model_validate(dumped_value)
    except (TypeError, ValueError, ValidationError):
        raise InvalidValidationContractError(
            f"{label} failed validation."
        ) from None


def _is_direct_module_function(
    value: object,
    *,
    parameter_names: tuple[str, ...],
) -> bool:
    """Return whether a hook is a directly imported module-level function."""

    if not isinstance(value, FunctionType):
        return False
    if (
        iscoroutinefunction(value)
        or isgeneratorfunction(value)
        or isasyncgenfunction(value)
    ):
        return False
    if (
        "__signature__" in value.__dict__
        or "__wrapped__" in value.__dict__
    ):
        return False
    try:
        function_parameters = tuple(
            signature(value, follow_wrapped=False).parameters.values()
        )
    except (TypeError, ValueError):
        return False
    if (
        tuple(
            parameter.name
            for parameter in function_parameters
        )
        != parameter_names
        or any(
            parameter.kind
            not in {
                Parameter.POSITIONAL_ONLY,
                Parameter.POSITIONAL_OR_KEYWORD,
            }
            or parameter.default is not Parameter.empty
            for parameter in function_parameters
        )
    ):
        return False
    if value.__name__ == "<lambda>":
        return False
    if value.__qualname__ != value.__name__ or value.__closure__ is not None:
        return False
    if value.__code__.co_filename.startswith("<"):
        return False

    module = sys.modules.get(value.__module__)
    return (
        module is not None
        and vars(module).get(value.__name__) is value
    )


def _copy_hook_mapping(
    value: Mapping[str, Callable[..., object]] | None,
    *,
    parameter_names: tuple[str, ...],
) -> tuple[Mapping[str, Callable[..., object]], bool]:
    """Copy and attest a hook mapping without retaining caller state."""

    if value is None:
        return MappingProxyType({}), True
    if not isinstance(value, Mapping):
        return MappingProxyType({}), False

    copied: dict[str, Callable[..., object]] = {}
    comparison_keys: set[str] = set()

    try:
        entries = tuple(value.items())
    except Exception:
        return MappingProxyType({}), False

    if len(entries) > MAX_INPUTS:
        return MappingProxyType({}), False

    for key, hook in entries:
        if (
            not isinstance(key, str)
            or not key.strip()
            or len(key.strip()) > 100
            or not _is_direct_module_function(
                hook,
                parameter_names=parameter_names,
            )
        ):
            return MappingProxyType({}), False

        normalized_key = key.strip()
        comparison_key = normalized_key.casefold()
        if comparison_key in comparison_keys:
            return MappingProxyType({}), False

        comparison_keys.add(comparison_key)
        copied[comparison_key] = hook

    return MappingProxyType(copied), True


class _ReportBuilder:
    """Private deterministic collector with hard report-size limits."""

    def __init__(
        self,
        definition: CalculationMethodDefinition,
        evidence: TrustedExecutionEvidence,
    ) -> None:
        self.definition = definition
        self.evidence = evidence
        self.normalized_inputs: list[CalculationInput] = []
        self.defaulted_inputs: list[CalculationInput] = []
        self.effective_options: list[CalculationOption] = []
        self.assumptions: list[CalculationAssumption] = []
        self.missing_inputs: list[MissingCalculationInput] = []
        self.findings: list[CalculationFinding] = []
        self.normalization_trace: list[CalculationTraceStep] = []
        self._findings_overflowed = False
        self._verification_requirements: list[
            VerificationRequirement
        ] = []
        self._verification_by_id: dict[str, VerificationRequirement] = {}
        self._generic_verification_id: str | None = None
        self._merge_verification_requirements(
            definition.verification_requirements
        )
        self._merge_verification_requirements(
            evidence.verification_requirements
        )

    def _merge_verification_requirements(
        self,
        values: tuple[VerificationRequirement, ...],
    ) -> None:
        for value in values:
            key = value.verification_id.casefold()
            existing = self._verification_by_id.get(key)
            if existing is not None:
                if existing != value:
                    self._findings_overflowed = True
                continue
            if (
                len(self._verification_requirements)
                >= MAX_VERIFICATION_REQUIREMENTS
            ):
                self._findings_overflowed = True
                continue
            self._verification_by_id[key] = value
            self._verification_requirements.append(value)

    def generic_verification_id(self) -> str:
        """Return a deterministic requirement usable by internal blockers."""

        if self._generic_verification_id is not None:
            return self._generic_verification_id

        candidate = _GENERIC_VERIFICATION_ID
        suffix = 2
        while candidate.casefold() in self._verification_by_id:
            candidate = f"{_GENERIC_VERIFICATION_ID}-{suffix}"
            suffix += 1

        if (
            len(self._verification_requirements)
            < MAX_VERIFICATION_REQUIREMENTS
        ):
            requirement = VerificationRequirement(
                verification_id=candidate,
                description=(
                    "Independently review and resolve the calculation "
                    "validation findings before execution."
                ),
                method=(
                    "Review the controlled method definition, supplied "
                    "inputs, defaults, options, and validation evidence."
                ),
                expected_result=(
                    "Every blocking validation finding is resolved and "
                    "documented."
                ),
                acceptance_criteria=(
                    "No required input is missing and no blocking "
                    "validation or applicability finding remains."
                ),
                required_competency=(
                    self.definition.required_reviewer_competency
                ),
                verifier_role="Independent competent reviewer",
                independent_verification_required=True,
                evidence_required=(
                    "Documented validation resolution",
                ),
            )
            self._verification_requirements.append(requirement)
            self._verification_by_id[candidate.casefold()] = requirement
            self._generic_verification_id = candidate
            return candidate

        if self._verification_requirements:
            self._generic_verification_id = (
                self._verification_requirements[0].verification_id
            )
            return self._generic_verification_id

        raise InvalidValidationContractError(
            "Validation requirements exceed the supported bound."
        )

    def add_finding(
        self,
        *,
        category: FindingCategory,
        severity: FindingSeverity,
        title: str,
        message: str,
        blocking: bool,
        required_action: str | None = None,
        verification_requirement_ids: tuple[str, ...] = (),
        reference_ids: tuple[str, ...] = (),
    ) -> None:
        """Append a bounded deterministic finding."""

        # Reserve one globally mergeable slot for the mandatory safety
        # boundary that runs after validation.
        if len(self.findings) >= MAX_FINDINGS - 2:
            self._findings_overflowed = True
            return

        linked_verification_ids = verification_requirement_ids
        if blocking and not linked_verification_ids:
            linked_verification_ids = (self.generic_verification_id(),)

        self.findings.append(
            CalculationFinding(
                finding_id=(
                    f"validation.finding.{len(self.findings) + 1:04d}"
                ),
                category=category,
                severity=severity,
                title=title,
                message=message,
                blocking=blocking,
                required_action=(
                    required_action
                    if required_action is not None
                    else (
                        "Resolve the validation finding and obtain "
                        "independent review before execution."
                        if blocking
                        else None
                    )
                ),
                verification_requirement_ids=linked_verification_ids,
                reference_ids=reference_ids,
            )
        )

    def add_normalization_trace(
        self,
        specification: MethodInputSpecification,
        *,
        status: TraceStepStatus,
        normalized_input: CalculationInput | None,
        description: str,
        input_available: bool = True,
    ) -> None:
        """Record one definition-ordered normalization outcome."""

        output_values: tuple[CalculationTraceValue, ...] = ()
        if normalized_input is not None:
            output_values = (
                CalculationTraceValue(
                    value_id=f"normalized.{specification.input_id}",
                    name=specification.name,
                    quantity=normalized_input.quantity,
                    categorical_value=(
                        normalized_input.categorical_value
                    ),
                    source_reference_ids=(
                        normalized_input.source_reference_ids
                    ),
                    description=(
                        "Validated value prepared for reviewed method "
                        "execution."
                    ),
                ),
            )

        self.normalization_trace.append(
            CalculationTraceStep(
                step_id=(
                    f"normalization."
                    f"{len(self.normalization_trace) + 1:04d}"
                ),
                sequence=len(self.normalization_trace) + 1,
                kind=TraceStepKind.NORMALIZATION,
                status=status,
                title=f"Normalize {specification.name}",
                description=description,
                input_ids=(
                    (specification.input_id,)
                    if input_available
                    else ()
                ),
                output_values=output_values,
            )
        )

    def finalize_overflow(self) -> None:
        """Represent bounded-collector overflow as one fail-closed finding."""

        if not self._findings_overflowed:
            return
        if len(self.findings) >= MAX_FINDINGS:
            return
        self.findings.append(
            CalculationFinding(
                finding_id=(
                    f"validation.finding.{len(self.findings) + 1:04d}"
                ),
                category=FindingCategory.VALIDATION,
                severity=FindingSeverity.ERROR,
                title="Validation output limit reached",
                message=(
                    "Validation produced more findings or verification "
                    "metadata than the controlled report limit."
                ),
                blocking=True,
                required_action=(
                    "Reduce the request or method-definition complexity and "
                    "obtain independent review."
                ),
                verification_requirement_ids=(
                    self.generic_verification_id(),
                ),
            )
        )

    @property
    def verification_requirements(
        self,
    ) -> tuple[VerificationRequirement, ...]:
        return tuple(self._verification_requirements)


def _strict_metadata_matches(
    source: CalculationInput,
    normalized: CalculationInput,
) -> bool:
    """Require a method hook to alter only value and canonical identity."""

    return (
        source.origin is normalized.origin
        and source.assumption_id == normalized.assumption_id
        and source.source_reference_ids == normalized.source_reference_ids
        and source.source_trace_step_ids
        == normalized.source_trace_step_ids
        and source.notes == normalized.notes
    )


def _method_specific_output_is_valid(
    specification: MethodInputSpecification,
    source: CalculationInput,
    normalized: CalculationInput,
) -> bool:
    """Validate a hook result using public registry metadata only."""

    if (
        normalized.input_id.casefold() != specification.input_id.casefold()
        or normalized.name != specification.name
        or not _strict_metadata_matches(source, normalized)
        or normalized.quantity is None
        or normalized.categorical_value is not None
        or normalized.quantity.quantity_kind
        != specification.quantity_kind.value  # type: ignore[union-attr]
        or normalized.quantity.unit != specification.canonical_unit
    ):
        return False

    try:
        expected_dimension = DEFAULT_UNIT_REGISTRY.dimension_for(
            specification.quantity_kind  # type: ignore[arg-type]
        )
        actual_dimension = DEFAULT_UNIT_REGISTRY.resolve_unit(
            normalized.quantity.unit
        ).dimension
    except UnitSystemError:
        return False

    return actual_dimension is expected_dimension


def _normal_input(
    specification: MethodInputSpecification,
    source: CalculationInput,
) -> CalculationInput:
    """Normalize a non-method-specific input through public APIs."""

    if source.name != specification.name:
        raise ValueError("input name does not match specification")

    if specification.value_type is InputValueType.QUANTITY:
        if (
            source.quantity is None
            or source.categorical_value is not None
            or source.quantity.quantity_kind
            != specification.quantity_kind.value  # type: ignore[union-attr]
        ):
            raise ValueError("input quantity does not match specification")

        if (
            specification.normalization_mode
            is not InputNormalizationMode.UNIT_REGISTRY
        ):
            raise ValueError("unsupported generic normalization mode")

        normalized_quantity = DEFAULT_UNIT_REGISTRY.convert_quantity(
            source.quantity,
            specification.canonical_unit,  # type: ignore[arg-type]
        )
        return source.model_copy(
            update={
                "input_id": specification.input_id,
                "name": specification.name,
                "quantity": normalized_quantity,
            }
        )

    if (
        source.quantity is not None
        or source.categorical_value is None
        or not specification.accepts_categorical_value(
            source.categorical_value
        )
    ):
        raise ValueError(
            "categorical input does not match specification"
        )

    return source.model_copy(
        update={
            "input_id": specification.input_id,
            "name": specification.name,
        }
    )


def _append_assumption(
    builder: _ReportBuilder,
    assumption: CalculationAssumption,
) -> bool:
    """Append one unique bounded assumption."""

    key = assumption.assumption_id.casefold()
    existing = next(
        (
            value
            for value in builder.assumptions
            if value.assumption_id.casefold() == key
        ),
        None,
    )
    if existing is not None:
        if existing != assumption:
            builder.add_finding(
                category=FindingCategory.VALIDATION,
                severity=FindingSeverity.ERROR,
                title="Assumption identifier collision",
                message=(
                    "A request and controlled default use the same "
                    "assumption identifier with different content."
                ),
                blocking=True,
            )
            return False
        return True

    if len(builder.assumptions) >= MAX_ASSUMPTIONS:
        builder.add_finding(
            category=FindingCategory.VALIDATION,
            severity=FindingSeverity.ERROR,
            title="Assumption limit reached",
            message=(
                "The combined request and default assumptions exceed the "
                "controlled limit."
            ),
            blocking=True,
        )
        return False

    builder.assumptions.append(assumption)
    return True


class CalculationValidationEngine:
    """Stateless validation engine for one exact method definition."""

    __slots__ = ()

    def validate(
        self,
        request: CalculationRequest,
        definition: CalculationMethodDefinition,
        evidence: TrustedExecutionEvidence | None = None,
        *,
        input_normalizers: Mapping[
            str,
            MethodSpecificNormalizer,
        ] | None = None,
        applicability_evaluators: Mapping[
            str,
            ApplicabilityEvaluator,
        ] | None = None,
    ) -> CalculationValidationReport:
        """Return a deterministic, immutable, fail-closed validation report."""

        validated_request = _revalidate_model(
            request,
            CalculationRequest,
            label="request",
        )
        validated_definition = _revalidate_model(
            definition,
            CalculationMethodDefinition,
            label="definition",
        )
        validated_evidence = _revalidate_model(
            (
                TrustedExecutionEvidence()
                if evidence is None
                else evidence
            ),
            TrustedExecutionEvidence,
            label="evidence",
        )
        builder = _ReportBuilder(
            validated_definition,
            validated_evidence,
        )

        normalizers, normalizers_valid = _copy_hook_mapping(
            input_normalizers,
            parameter_names=("specification", "supplied_input"),
        )
        evaluators, evaluators_valid = _copy_hook_mapping(
            applicability_evaluators,
            parameter_names=("rule", "linked_inputs"),
        )
        if not normalizers_valid or not evaluators_valid:
            builder.add_finding(
                category=FindingCategory.VALIDATION,
                severity=FindingSeverity.ERROR,
                title="Invalid trusted validation hook binding",
                message=(
                    "The reviewed validation-hook binding is malformed."
                ),
                blocking=True,
            )

        self._validate_identity(
            validated_request,
            validated_definition,
            builder,
        )
        for assumption in validated_request.assumptions:
            _append_assumption(builder, assumption)

        normalized_by_id = self._validate_inputs(
            validated_request,
            validated_definition,
            normalizers,
            builder,
        )
        self._validate_options(
            validated_request,
            validated_definition,
            builder,
        )
        self._validate_applicability(
            validated_definition,
            normalized_by_id,
            evaluators,
            builder,
        )
        self._validate_hook_coverage(
            validated_definition,
            normalizers,
            evaluators,
            builder,
        )
        builder.finalize_overflow()

        can_execute = not any(
            value.blocking
            for value in builder.findings
        ) and not any(
            value.required_for_execution
            for value in builder.missing_inputs
        )

        return CalculationValidationReport(
            request=validated_request,
            definition=validated_definition,
            evidence=validated_evidence,
            normalized_inputs=tuple(builder.normalized_inputs),
            defaulted_inputs=tuple(builder.defaulted_inputs),
            effective_options=tuple(builder.effective_options),
            assumptions=tuple(builder.assumptions),
            missing_inputs=tuple(builder.missing_inputs),
            findings=tuple(builder.findings),
            verification_requirements=(
                builder.verification_requirements
            ),
            normalization_trace=tuple(builder.normalization_trace),
            can_execute=can_execute,
        )

    @staticmethod
    def _validate_identity(
        request: CalculationRequest,
        definition: CalculationMethodDefinition,
        builder: _ReportBuilder,
    ) -> None:
        if (
            request.method_id.casefold() != definition.method_id.casefold()
            or request.method_version != definition.method_version
            or request.calculation_type.casefold()
            != definition.calculation_type.casefold()
        ):
            builder.add_finding(
                category=FindingCategory.VALIDATION,
                severity=FindingSeverity.ERROR,
                title="Method identity mismatch",
                message=(
                    "The request identity does not match the reviewed method "
                    "definition."
                ),
                blocking=True,
            )

    def _validate_inputs(
        self,
        request: CalculationRequest,
        definition: CalculationMethodDefinition,
        normalizers: Mapping[str, Callable[..., object]],
        builder: _ReportBuilder,
    ) -> dict[str, CalculationInput]:
        specifications_by_id = {
            value.input_id.casefold(): value
            for value in definition.input_specifications
        }
        supplied_by_id = {
            value.input_id.casefold(): value
            for value in request.inputs
        }

        for supplied in request.inputs:
            if supplied.input_id.casefold() not in specifications_by_id:
                builder.add_finding(
                    category=FindingCategory.VALIDATION,
                    severity=FindingSeverity.ERROR,
                    title="Unknown calculation input",
                    message=(
                        f"Input {supplied.input_id!r} is not declared by "
                        "the reviewed method."
                    ),
                    blocking=True,
                )

        normalized_by_id: dict[str, CalculationInput] = {}
        for specification in definition.input_specifications:
            key = specification.input_id.casefold()
            source = supplied_by_id.get(key)
            was_defaulted = False

            if source is None:
                if specification.presence is InputPresence.DEFAULTED:
                    source = specification.default_input
                    was_defaulted = True
                    if (
                        specification.default_assumption is not None
                    ):
                        _append_assumption(
                            builder,
                            specification.default_assumption,
                        )
                else:
                    required = (
                        specification.presence is InputPresence.REQUIRED
                    )
                    builder.missing_inputs.append(
                        MissingCalculationInput(
                            input_id=specification.input_id,
                            name=specification.name,
                            reason=(
                                "The request did not supply this controlled "
                                "method input."
                            ),
                            required_for_execution=required,
                            safety_critical=(
                                specification.safety_critical
                            ),
                            expected_unit=specification.canonical_unit,
                        )
                    )
                    if required:
                        builder.add_finding(
                            category=FindingCategory.VALIDATION,
                            severity=(
                                FindingSeverity.CRITICAL
                                if specification.safety_critical
                                else FindingSeverity.ERROR
                            ),
                            title="Required input is missing",
                            message=(
                                f"Required input "
                                f"{specification.input_id!r} is missing."
                            ),
                            blocking=True,
                            required_action=(
                                "Supply and independently verify the "
                                "required input before execution."
                            ),
                            verification_requirement_ids=(
                                specification
                                .verification_requirement_ids
                            ),
                            reference_ids=specification.reference_ids,
                        )
                    builder.add_normalization_trace(
                        specification,
                        status=TraceStepStatus.SKIPPED,
                        normalized_input=None,
                        input_available=False,
                        description=(
                            "Normalization was skipped because the input "
                            "was not supplied."
                        ),
                    )
                    continue

            if source is None:
                builder.add_finding(
                    category=FindingCategory.VALIDATION,
                    severity=FindingSeverity.ERROR,
                    title="Controlled default is unavailable",
                    message=(
                        f"Defaulted input {specification.input_id!r} has no "
                        "validated default."
                    ),
                    blocking=True,
                )
                builder.add_normalization_trace(
                    specification,
                    status=TraceStepStatus.FAILED,
                    normalized_input=None,
                    input_available=False,
                    description=(
                        "The controlled default could not be resolved."
                    ),
                )
                continue

            normalized = self._normalize_input(
                specification,
                source,
                normalizers,
                builder,
            )
            if normalized is None:
                builder.add_normalization_trace(
                    specification,
                    status=TraceStepStatus.FAILED,
                    normalized_input=None,
                    description=(
                        "The input failed controlled normalization."
                    ),
                )
                continue

            builder.normalized_inputs.append(normalized)
            normalized_by_id[key] = normalized
            if was_defaulted:
                builder.defaulted_inputs.append(normalized)

            if (
                specification.numeric_range is not None
                and normalized.quantity is not None
                and not specification.numeric_range.contains(
                    normalized.quantity.value
                )
            ):
                builder.add_finding(
                    category=FindingCategory.APPLICABILITY,
                    severity=FindingSeverity.ERROR,
                    title="Input is outside the reviewed range",
                    message=(
                        f"Input {specification.input_id!r} is outside its "
                        "reviewed normalized applicability range."
                    ),
                    blocking=True,
                    required_action=(
                        "Confirm the input and select a reviewed method "
                        "whose applicability range includes it."
                    ),
                    verification_requirement_ids=(
                        specification.verification_requirement_ids
                    ),
                    reference_ids=specification.reference_ids,
                )

            builder.add_normalization_trace(
                specification,
                status=TraceStepStatus.COMPLETED,
                normalized_input=normalized,
                description=(
                    "The input was validated and normalized according to "
                    "the reviewed method specification."
                ),
            )

        return normalized_by_id

    @staticmethod
    def _normalize_input(
        specification: MethodInputSpecification,
        source: CalculationInput,
        normalizers: Mapping[str, Callable[..., object]],
        builder: _ReportBuilder,
    ) -> CalculationInput | None:
        try:
            source = _revalidate_model(
                source,
                CalculationInput,
                label="calculation input",
            )
        except InvalidValidationContractError:
            builder.add_finding(
                category=FindingCategory.VALIDATION,
                severity=FindingSeverity.ERROR,
                title="Invalid calculation input",
                message=(
                    f"Input {specification.input_id!r} failed validation."
                ),
                blocking=True,
            )
            return None

        if (
            source.input_id.casefold() != specification.input_id.casefold()
            or source.name != specification.name
        ):
            builder.add_finding(
                category=FindingCategory.VALIDATION,
                severity=FindingSeverity.ERROR,
                title="Input identity does not match specification",
                message=(
                    f"Input {specification.input_id!r} does not preserve "
                    "its reviewed identifier and name."
                ),
                blocking=True,
            )
            return None

        if (
            specification.normalization_mode
            is InputNormalizationMode.METHOD_SPECIFIC
        ):
            hook = normalizers.get(specification.input_id.casefold())
            if hook is None:
                builder.add_finding(
                    category=FindingCategory.VALIDATION,
                    severity=FindingSeverity.ERROR,
                    title="Method-specific normalizer is unavailable",
                    message=(
                        f"Input {specification.input_id!r} requires a "
                        "direct reviewed normalizer."
                    ),
                    blocking=True,
                )
                return None

            try:
                hook_output = hook(specification, source)
                normalized = _revalidate_model(
                    hook_output,
                    CalculationInput,
                    label="method-specific normalized input",
                )
            except Exception:
                builder.add_finding(
                    category=FindingCategory.VALIDATION,
                    severity=FindingSeverity.ERROR,
                    title="Method-specific normalization failed",
                    message=(
                        f"The reviewed normalizer for input "
                        f"{specification.input_id!r} failed."
                    ),
                    blocking=True,
                )
                return None

            if not _method_specific_output_is_valid(
                specification,
                source,
                normalized,
            ):
                builder.add_finding(
                    category=FindingCategory.VALIDATION,
                    severity=FindingSeverity.ERROR,
                    title="Invalid method-specific normalization output",
                    message=(
                        f"The reviewed normalizer for input "
                        f"{specification.input_id!r} returned an invalid "
                        "canonical value."
                    ),
                    blocking=True,
                )
                return None

            return normalized.model_copy(
                update={"input_id": specification.input_id}
            )

        try:
            return _normal_input(specification, source)
        except (TypeError, ValueError, UnitSystemError):
            builder.add_finding(
                category=FindingCategory.VALIDATION,
                severity=FindingSeverity.ERROR,
                title="Input normalization failed",
                message=(
                    f"Input {specification.input_id!r} does not satisfy "
                    "its reviewed value and unit contract."
                ),
                blocking=True,
                verification_requirement_ids=(
                    specification.verification_requirement_ids
                ),
                reference_ids=specification.reference_ids,
            )
            return None

    @staticmethod
    def _validate_options(
        request: CalculationRequest,
        definition: CalculationMethodDefinition,
        builder: _ReportBuilder,
    ) -> None:
        specifications_by_id = {
            value.option_id.casefold(): value
            for value in definition.option_specifications
        }
        supplied_by_id = {
            value.option_id.casefold(): value
            for value in request.options
        }

        for supplied in request.options:
            if supplied.option_id.casefold() not in specifications_by_id:
                builder.add_finding(
                    category=FindingCategory.VALIDATION,
                    severity=FindingSeverity.ERROR,
                    title="Unknown calculation option",
                    message=(
                        f"Option {supplied.option_id!r} is not declared by "
                        "the reviewed method."
                    ),
                    blocking=True,
                )

        for specification in definition.option_specifications:
            key = specification.option_id.casefold()
            supplied = supplied_by_id.get(key)
            option = (
                supplied
                if supplied is not None
                else specification.default_option
            )
            if option is None:
                if specification.required:
                    builder.add_finding(
                        category=FindingCategory.VALIDATION,
                        severity=FindingSeverity.ERROR,
                        title="Required option is missing",
                        message=(
                            f"Required option "
                            f"{specification.option_id!r} is missing."
                        ),
                        blocking=True,
                    )
                continue

            try:
                validated_option = _revalidate_model(
                    option,
                    CalculationOption,
                    label="calculation option",
                )
            except InvalidValidationContractError:
                builder.add_finding(
                    category=FindingCategory.VALIDATION,
                    severity=FindingSeverity.ERROR,
                    title="Invalid calculation option",
                    message=(
                        f"Option {specification.option_id!r} failed "
                        "validation."
                    ),
                    blocking=True,
                )
                continue

            if not specification.accepts_value(validated_option.value):
                builder.add_finding(
                    category=FindingCategory.VALIDATION,
                    severity=FindingSeverity.ERROR,
                    title="Option value is not allowed",
                    message=(
                        f"Option {specification.option_id!r} does not "
                        "satisfy its strict type, range, or allow-list."
                    ),
                    blocking=True,
                )
                continue

            builder.effective_options.append(
                validated_option.model_copy(
                    update={"option_id": specification.option_id}
                )
            )

    @staticmethod
    def _validate_applicability(
        definition: CalculationMethodDefinition,
        normalized_by_id: Mapping[str, CalculationInput],
        evaluators: Mapping[str, Callable[..., object]],
        builder: _ReportBuilder,
    ) -> None:
        for rule in definition.applicability_rules:
            linked_inputs: list[CalculationInput] = []
            missing_link = False
            for input_id in rule.input_ids:
                linked = normalized_by_id.get(input_id.casefold())
                if linked is None:
                    missing_link = True
                    break
                linked_inputs.append(linked)

            if missing_link:
                builder.add_finding(
                    category=FindingCategory.APPLICABILITY,
                    severity=FindingSeverity.ERROR,
                    title="Applicability could not be evaluated",
                    message=(
                        f"Rule {rule.rule_id!r} could not be evaluated "
                        "because a linked normalized input is unavailable."
                    ),
                    blocking=True,
                    reference_ids=rule.reference_ids,
                )
                continue

            evaluator = evaluators.get(rule.rule_id.casefold())
            if evaluator is None:
                builder.add_finding(
                    category=FindingCategory.APPLICABILITY,
                    severity=FindingSeverity.ERROR,
                    title="Applicability evaluator is unavailable",
                    message=(
                        f"Rule {rule.rule_id!r} requires a direct reviewed "
                        "evaluator."
                    ),
                    blocking=True,
                    reference_ids=rule.reference_ids,
                )
                continue

            try:
                accepted = evaluator(rule, tuple(linked_inputs))
            except Exception:
                builder.add_finding(
                    category=FindingCategory.APPLICABILITY,
                    severity=FindingSeverity.ERROR,
                    title="Applicability evaluation failed",
                    message=(
                        f"The reviewed evaluator for rule "
                        f"{rule.rule_id!r} failed."
                    ),
                    blocking=True,
                    reference_ids=rule.reference_ids,
                )
                continue

            if not isinstance(accepted, bool):
                builder.add_finding(
                    category=FindingCategory.APPLICABILITY,
                    severity=FindingSeverity.ERROR,
                    title="Invalid applicability result",
                    message=(
                        f"The reviewed evaluator for rule "
                        f"{rule.rule_id!r} returned a non-boolean result."
                    ),
                    blocking=True,
                    reference_ids=rule.reference_ids,
                )
                continue

            if not accepted:
                builder.add_finding(
                    category=FindingCategory.APPLICABILITY,
                    severity=rule.severity,
                    title=rule.title,
                    message=rule.description,
                    blocking=rule.blocking,
                    required_action=rule.required_action,
                    verification_requirement_ids=(
                        rule.verification_requirement_ids
                    ),
                    reference_ids=rule.reference_ids,
                )

    @staticmethod
    def _validate_hook_coverage(
        definition: CalculationMethodDefinition,
        normalizers: Mapping[str, Callable[..., object]],
        evaluators: Mapping[str, Callable[..., object]],
        builder: _ReportBuilder,
    ) -> None:
        expected_normalizers = {
            value.input_id.casefold()
            for value in definition.input_specifications
            if (
                value.normalization_mode
                is InputNormalizationMode.METHOD_SPECIFIC
            )
        }
        expected_evaluators = {
            value.rule_id.casefold()
            for value in definition.applicability_rules
        }

        if set(normalizers) != expected_normalizers:
            builder.add_finding(
                category=FindingCategory.VALIDATION,
                severity=FindingSeverity.ERROR,
                title="Method-specific hook coverage mismatch",
                message=(
                    "The direct method-specific normalizer bindings do not "
                    "exactly match the reviewed input definitions."
                ),
                blocking=True,
            )
        if set(evaluators) != expected_evaluators:
            builder.add_finding(
                category=FindingCategory.VALIDATION,
                severity=FindingSeverity.ERROR,
                title="Applicability hook coverage mismatch",
                message=(
                    "The direct applicability-evaluator bindings do not "
                    "exactly match the reviewed applicability rules."
                ),
                blocking=True,
            )


DEFAULT_VALIDATION_ENGINE = CalculationValidationEngine()
DEFAULT_CALCULATION_VALIDATION_ENGINE = DEFAULT_VALIDATION_ENGINE


__all__ = [
    "ApplicabilityEvaluator",
    "CalculationValidationEngine",
    "CalculationValidationError",
    "CalculationValidationReport",
    "DEFAULT_CALCULATION_VALIDATION_ENGINE",
    "DEFAULT_VALIDATION_ENGINE",
    "InvalidValidationContractError",
    "MethodSpecificNormalizer",
]
