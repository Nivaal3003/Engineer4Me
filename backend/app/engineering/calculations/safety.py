"""Fail-closed safety evaluation for Engineer4Me calculations.

This module turns declarative, reviewed method safety metadata into immutable
calculation findings.  It deliberately contains no engineering formula,
dynamic import, expression interpreter, acknowledgement override, or voice
functionality.

Safety evaluation occurs before a numerical implementation is called.  A
reviewed application function may report which declared conditional safety
requirements were triggered, but it cannot invent a requirement, lower its
severity, remove its required action, or choose the final calculation status.
Missing safety-critical inputs and evaluator failures always fail closed.
"""

from __future__ import annotations

from collections.abc import Callable
from collections.abc import Mapping
from hashlib import sha256
from typing import Any
from typing import Protocol
from typing import Self

from pydantic import Field
from pydantic import StrictBool
from pydantic import model_validator

from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
)
from app.engineering.calculations.method_models import (
    InputNormalizationMode,
)
from app.engineering.calculations.method_models import InputPresence
from app.engineering.calculations.method_models import (
    MethodInputSpecification,
)
from app.engineering.calculations.method_models import InputValueType
from app.engineering.calculations.method_models import SafetyRequirement
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
from app.engineering.calculations.models import FindingCategory
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import Identifier
from app.engineering.calculations.models import LongText
from app.engineering.calculations.models import MAX_ASSUMPTIONS
from app.engineering.calculations.models import MAX_FINDINGS
from app.engineering.calculations.models import MAX_INPUTS
from app.engineering.calculations.models import MAX_OPTIONS
from app.engineering.calculations.models import (
    MAX_VERIFICATION_REQUIREMENTS,
)
from app.engineering.calculations.models import MissingCalculationInput
from app.engineering.calculations.models import (
    VerificationRequirement,
)
from app.engineering.calculations.units import DEFAULT_UNIT_REGISTRY
from app.engineering.calculations.units import UnitSystemError


MAX_SAFETY_TRIGGERS = 256

SAFETY_EVALUATION_FAILED_FINDING_ID = "safety.evaluation-failed"
SAFETY_EVALUATION_FAILED_VERIFICATION_ID = "verify.safety-evaluation"

_FAILURE_TITLE = "Safety evaluation unavailable"
_FAILURE_MESSAGE = (
    "The controlled safety evaluation did not complete successfully."
)
_FAILURE_ACTION = (
    "Do not execute or use a numerical result until the safety evaluation "
    "has been independently restored and verified."
)
_FAILURE_VERIFICATION_DESCRIPTION = (
    "Review the safety-evaluation implementation and all safety-critical "
    "method inputs."
)
_FAILURE_VERIFICATION_METHOD = (
    "Perform an independent safety review using the approved method record, "
    "site requirements, and source evidence."
)
_FAILURE_VERIFICATION_EXPECTED_RESULT = (
    "The evaluator is restored and every safety condition is independently "
    "confirmed before execution."
)
_FAILURE_VERIFIER_ROLE = "Independent competent engineering reviewer"
_FAILURE_EVIDENCE = (
    "Approved safety review record",
    "Verified safety-critical input evidence",
)


class SafetyEvaluationError(ValueError):
    """Base error raised for an invalid internal safety contract."""


class SafetyEvaluator(Protocol):
    """Reviewed direct application function used for conditional safety."""

    def __call__(
        self,
        context: "SafetyEvaluationContext",
    ) -> "MethodSafetyExtension":
        """Return triggered declared requirements only."""


def _comparison_text(value: str) -> str:
    """Return the stable case-insensitive identifier comparison form."""

    return value.casefold()


def _revalidate_model(model_type, value):
    """Revalidate even an instance created through ``model_construct``."""

    if isinstance(value, CalculationModel):
        value = value.model_dump(
            mode="python",
            round_trip=True,
            warnings="none",
        )

    return model_type.model_validate(value)


def _require_unique_attributes(
    values: tuple[CalculationModel, ...],
    *,
    attribute_name: str,
    field_name: str,
) -> None:
    """Reject case-insensitive identifier collisions."""

    comparison_values = tuple(
        _comparison_text(str(getattr(value, attribute_name)))
        for value in values
    )

    if len(comparison_values) != len(set(comparison_values)):
        raise ValueError(
            f"{field_name} {attribute_name} values must be unique."
        )


def _derived_identifier(
    base: str,
    *,
    seed: str,
    existing: set[str],
) -> str:
    """Return a deterministic bounded identifier without collisions."""

    candidate = base[:100]

    if _comparison_text(candidate) not in existing:
        return candidate

    digest = sha256(seed.encode("utf-8")).hexdigest()[:12]
    suffix = f"-{digest}"
    candidate = f"{base[:100 - len(suffix)]}{suffix}"

    if _comparison_text(candidate) not in existing:
        return candidate

    for index in range(2, 10_000):
        numbered_suffix = f"-{digest}-{index}"
        candidate = (
            f"{base[:100 - len(numbered_suffix)]}{numbered_suffix}"
        )

        if _comparison_text(candidate) not in existing:
            return candidate

    raise SafetyEvaluationError(
        "No bounded deterministic safety identifier remains available."
    )


def _is_failure_finding(value: CalculationFinding) -> bool:
    """Return whether a finding has the fixed fail-closed semantics."""

    return (
        value.category is FindingCategory.SAFETY
        and value.severity is FindingSeverity.CRITICAL
        and value.title == _FAILURE_TITLE
        and value.message == _FAILURE_MESSAGE
        and value.blocking
        and value.required_action == _FAILURE_ACTION
        and len(value.verification_requirement_ids) == 1
        and not value.reference_ids
    )


def _is_failure_verification(
    value: VerificationRequirement,
) -> bool:
    """Return whether verification metadata restores safety evaluation."""

    return (
        value.description == _FAILURE_VERIFICATION_DESCRIPTION
        and value.method == _FAILURE_VERIFICATION_METHOD
        and value.expected_result
        == _FAILURE_VERIFICATION_EXPECTED_RESULT
        and value.acceptance_criteria is None
        and value.verifier_role == _FAILURE_VERIFIER_ROLE
        and value.independent_verification_required
        and value.evidence_required == _FAILURE_EVIDENCE
    )


class SafetyTrigger(CalculationModel):
    """One declared safety requirement triggered by reviewed code."""

    requirement_id: Identifier
    message: LongText | None = None


class MethodSafetyExtension(CalculationModel):
    """Bounded output accepted from a reviewed safety evaluator."""

    triggers: tuple[SafetyTrigger, ...] = Field(
        default_factory=tuple,
        max_length=MAX_SAFETY_TRIGGERS,
    )

    @model_validator(mode="after")
    def validate_triggers(self) -> Self:
        """Reject ambiguous duplicate requirement triggers."""

        _require_unique_attributes(
            self.triggers,
            attribute_name="requirement_id",
            field_name="triggers",
        )
        return self


class SafetyEvaluationContext(CalculationModel):
    """Immutable validated information visible to a safety evaluator."""

    request: CalculationRequest
    definition: CalculationMethodDefinition
    supplied_inputs: tuple[CalculationInput, ...] = Field(
        default_factory=tuple,
        max_length=MAX_INPUTS,
    )
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
        max_length=MAX_INPUTS,
    )
    existing_findings: tuple[CalculationFinding, ...] = Field(
        default_factory=tuple,
        max_length=MAX_FINDINGS,
    )
    evidence: TrustedExecutionEvidence = Field(
        default_factory=TrustedExecutionEvidence
    )

    @model_validator(mode="after")
    def validate_context(self) -> Self:
        """Require one coherent, deterministic validation-stage snapshot."""

        if (
            _comparison_text(self.request.method_id)
            != _comparison_text(self.definition.method_id)
            or self.request.method_version
            != self.definition.method_version
            or _comparison_text(self.request.calculation_type)
            != _comparison_text(self.definition.calculation_type)
        ):
            raise ValueError(
                "Safety context request identity does not match the method."
            )

        for values, attribute_name, field_name in (
            (self.supplied_inputs, "input_id", "supplied_inputs"),
            (self.normalized_inputs, "input_id", "normalized_inputs"),
            (self.defaulted_inputs, "input_id", "defaulted_inputs"),
            (self.effective_options, "option_id", "effective_options"),
            (self.assumptions, "assumption_id", "assumptions"),
            (self.missing_inputs, "input_id", "missing_inputs"),
            (self.existing_findings, "finding_id", "existing_findings"),
        ):
            _require_unique_attributes(
                values,
                attribute_name=attribute_name,
                field_name=field_name,
            )

        if len(self.existing_findings) >= MAX_FINDINGS:
            raise ValueError(
                "Safety evaluation requires capacity for a fail-closed "
                "finding."
            )

        specifications_by_id = {
            _comparison_text(value.input_id): value
            for value in self.definition.input_specifications
        }

        for collection in (
            self.normalized_inputs,
            self.defaulted_inputs,
            self.missing_inputs,
        ):
            if not {
                _comparison_text(value.input_id)
                for value in collection
            }.issubset(specifications_by_id):
                raise ValueError(
                    "Safety context contains an unknown method input."
                )

        if self.supplied_inputs != self.request.inputs:
            raise ValueError(
                "Safety supplied_inputs must exactly preserve request inputs "
                "and order."
            )

        normalized_by_id = {
            _comparison_text(value.input_id): value
            for value in self.normalized_inputs
        }
        defaulted_by_id = {
            _comparison_text(value.input_id): value
            for value in self.defaulted_inputs
        }
        supplied_by_id = {
            _comparison_text(value.input_id): value
            for value in self.supplied_inputs
            if (
                _comparison_text(value.input_id)
                in specifications_by_id
            )
        }
        missing_by_id = {
            _comparison_text(value.input_id): value
            for value in self.missing_inputs
        }

        if set(defaulted_by_id) - set(normalized_by_id):
            raise ValueError(
                "Every defaulted safety input requires a normalized "
                "counterpart."
            )

        if set(missing_by_id).intersection(normalized_by_id):
            raise ValueError(
                "A safety input cannot be both normalized and missing."
            )

        for input_key, value in defaulted_by_id.items():
            if normalized_by_id[input_key] != value:
                raise ValueError(
                    "A defaulted safety input must equal its normalized "
                    "counterpart."
                )

        for input_key, value in normalized_by_id.items():
            specification = specifications_by_id[input_key]
            self._validate_normalized_input(specification, value)
            source = supplied_by_id.get(input_key)
            if input_key in defaulted_by_id:
                source = specification.default_input

            if source is None:
                raise ValueError(
                    "Every normalized safety input requires a supplied or "
                    "controlled-default source."
                )

            if (
                value.origin is not source.origin
                or value.assumption_id != source.assumption_id
                or value.source_reference_ids
                != source.source_reference_ids
                or value.source_trace_step_ids
                != source.source_trace_step_ids
                or value.notes != source.notes
            ):
                raise ValueError(
                    "A normalized safety input must preserve source "
                    "provenance metadata."
                )

            if (
                specification.value_type is InputValueType.QUANTITY
                and specification.normalization_mode
                is InputNormalizationMode.UNIT_REGISTRY
            ):
                try:
                    expected_quantity = (
                        DEFAULT_UNIT_REGISTRY.convert_quantity(
                            source.quantity,  # type: ignore[arg-type]
                            specification.canonical_unit,  # type: ignore[arg-type]
                        )
                    )
                except UnitSystemError as exc:
                    raise ValueError(
                        "A normalized safety input has an invalid source "
                        "quantity."
                    ) from exc

                if value.quantity != expected_quantity:
                    raise ValueError(
                        "A normalized safety quantity does not match its "
                        "controlled source conversion."
                    )
            elif (
                specification.value_type is not InputValueType.QUANTITY
                and value.categorical_value
                != source.categorical_value
            ):
                raise ValueError(
                    "A normalized categorical safety input changed its "
                    "source value."
                )

        for input_key, value in missing_by_id.items():
            specification = specifications_by_id[input_key]
            expected_required = (
                specification.presence is InputPresence.REQUIRED
            )
            if (
                value.name != specification.name
                or value.required_for_execution != expected_required
                or value.safety_critical
                != specification.safety_critical
                or value.expected_unit != specification.canonical_unit
            ):
                raise ValueError(
                    "A missing safety input must preserve its method "
                    "specification metadata."
                )

        specification_order = tuple(specifications_by_id)
        for values, field_name in (
            (self.normalized_inputs, "normalized_inputs"),
            (self.defaulted_inputs, "defaulted_inputs"),
            (self.missing_inputs, "missing_inputs"),
        ):
            actual_order = tuple(
                _comparison_text(value.input_id)
                for value in values
            )
            expected_order = tuple(
                key
                for key in specification_order
                if key in set(actual_order)
            )
            if actual_order != expected_order:
                raise ValueError(
                    f"{field_name} must follow method-definition order."
                )

        option_specs_by_id = {
            _comparison_text(value.option_id): value
            for value in self.definition.option_specifications
        }
        effective_option_ids = tuple(
            _comparison_text(value.option_id)
            for value in self.effective_options
        )

        if not set(effective_option_ids).issubset(option_specs_by_id):
            raise ValueError(
                "Safety effective_options contains an unknown option."
            )

        expected_option_order = tuple(
            key
            for key in option_specs_by_id
            if key in set(effective_option_ids)
        )
        if effective_option_ids != expected_option_order:
            raise ValueError(
                "Safety effective_options must follow method-definition "
                "order."
            )

        for option in self.effective_options:
            specification = option_specs_by_id[
                _comparison_text(option.option_id)
            ]
            if not specification.accepts_value(option.value):
                raise ValueError(
                    "A safety effective option does not satisfy its schema."
                )

            supplied_option = next(
                (
                    value
                    for value in self.request.options
                    if _comparison_text(value.option_id)
                    == _comparison_text(specification.option_id)
                ),
                None,
            )
            source_option = (
                supplied_option
                if supplied_option is not None
                else specification.default_option
            )
            if (
                source_option is None
                or option
                != source_option.model_copy(
                    update={"option_id": specification.option_id}
                )
            ):
                raise ValueError(
                    "A safety effective option must preserve its supplied "
                    "or controlled-default value."
                )

        expected_assumptions = list(self.request.assumptions)
        assumption_ids = {
            _comparison_text(value.assumption_id)
            for value in expected_assumptions
        }
        defaulted_ids = set(defaulted_by_id)

        for specification in self.definition.input_specifications:
            default_assumption = specification.default_assumption
            if (
                _comparison_text(specification.input_id)
                not in defaulted_ids
                or default_assumption is None
            ):
                continue

            assumption_key = _comparison_text(
                default_assumption.assumption_id
            )
            if assumption_key in assumption_ids:
                existing = next(
                    value
                    for value in expected_assumptions
                    if _comparison_text(value.assumption_id)
                    == assumption_key
                )
                if existing != default_assumption:
                    continue
            else:
                expected_assumptions.append(default_assumption)
                assumption_ids.add(assumption_key)

        if self.assumptions != tuple(expected_assumptions):
            raise ValueError(
                "Safety assumptions must exactly preserve request and "
                "controlled-default assumptions."
            )

        return self

    @staticmethod
    def _validate_normalized_input(
        specification: MethodInputSpecification,
        value: CalculationInput,
    ) -> None:
        """Validate normalized structure without re-running applicability."""

        if value.name != specification.name:
            raise ValueError(
                "A normalized safety input must preserve its specified name."
            )

        if specification.value_type is InputValueType.QUANTITY:
            if (
                value.quantity is None
                or value.categorical_value is not None
                or value.quantity.quantity_kind
                != specification.quantity_kind.value  # type: ignore[union-attr]
                or value.quantity.unit != specification.canonical_unit
            ):
                raise ValueError(
                    "A normalized safety quantity does not match its "
                    "specification."
                )

            try:
                if (
                    specification.normalization_mode
                    is InputNormalizationMode.UNIT_REGISTRY
                ):
                    DEFAULT_UNIT_REGISTRY.validate_quantity(value.quantity)
                else:
                    expected_dimension = (
                        DEFAULT_UNIT_REGISTRY.dimension_for(
                            specification.quantity_kind  # type: ignore[arg-type]
                        )
                    )
                    actual_dimension = (
                        DEFAULT_UNIT_REGISTRY.resolve_unit(
                            value.quantity.unit
                        ).dimension
                    )
                    if actual_dimension is not expected_dimension:
                        raise ValueError(
                            "A method-specific safety quantity has the wrong "
                            "dimension."
                        )
            except UnitSystemError as exc:
                raise ValueError(
                    "A normalized safety quantity failed registry "
                    "validation."
                ) from exc
        elif (
            value.quantity is not None
            or value.categorical_value is None
            or not specification.accepts_categorical_value(
                value.categorical_value
            )
        ):
            raise ValueError(
                "A normalized categorical safety input does not match its "
                "specification."
            )


class SafetyReport(CalculationModel):
    """Deterministic safety findings returned before method execution."""

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
    evaluator_failed: StrictBool = False

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        """Require safety-only findings and resolvable verification links."""

        _require_unique_attributes(
            self.findings,
            attribute_name="finding_id",
            field_name="findings",
        )
        _require_unique_attributes(
            self.verification_requirements,
            attribute_name="verification_id",
            field_name="verification_requirements",
        )

        if any(
            finding.category is not FindingCategory.SAFETY
            for finding in self.findings
        ):
            raise ValueError(
                "SafetyReport may contain only safety findings."
            )

        verifications_by_id = {
            _comparison_text(value.verification_id): value
            for value in self.verification_requirements
        }

        for finding in self.findings:
            linked_ids = {
                _comparison_text(value)
                for value in finding.verification_requirement_ids
            }

            if not linked_ids.issubset(verifications_by_id):
                raise ValueError(
                    "A safety finding has an unresolved verification "
                    "requirement."
                )

        failure_shaped_findings = tuple(
            finding
            for finding in self.findings
            if _is_failure_finding(finding)
        )
        failure_findings = tuple(
            finding
            for finding in failure_shaped_findings
            if _is_failure_verification(
                verifications_by_id[
                    _comparison_text(
                        finding.verification_requirement_ids[0]
                    )
                ]
            )
        )
        reserved_findings = tuple(
            finding
            for finding in self.findings
            if _comparison_text(finding.finding_id)
            == _comparison_text(
                SAFETY_EVALUATION_FAILED_FINDING_ID
            )
        )

        if self.evaluator_failed:
            if (
                len(failure_findings) != 1
                or len(failure_shaped_findings) != 1
            ):
                raise ValueError(
                    "evaluator_failed requires exactly one strict "
                    "fail-closed finding."
                )

            if any(
                not _is_failure_finding(value)
                for value in reserved_findings
            ):
                raise ValueError(
                    "The reserved fail-closed identifier requires strict "
                    "failure metadata."
                )
        elif failure_shaped_findings or reserved_findings:
            raise ValueError(
                "Fail-closed finding metadata requires "
                "evaluator_failed=true."
            )

        return self

    @property
    def blocked(self) -> bool:
        """Return whether any safety finding prevents execution."""

        return any(finding.blocking for finding in self.findings)


class CalculationSafetyEngine:
    """Stateless fail-closed evaluator for reviewed safety metadata."""

    __slots__ = ()

    def failure_report(
        self,
        definition: CalculationMethodDefinition,
        *,
        existing_findings: tuple[CalculationFinding, ...] = (),
        existing_verification_requirements: tuple[
            VerificationRequirement,
            ...,
        ] = (),
    ) -> SafetyReport:
        """Return one deterministic collision-safe fail-closed report."""

        validated_definition = _revalidate_model(
            CalculationMethodDefinition,
            definition,
        )

        if not isinstance(existing_findings, tuple):
            raise SafetyEvaluationError(
                "existing_findings must be an ordered tuple."
            )
        if not isinstance(existing_verification_requirements, tuple):
            raise SafetyEvaluationError(
                "existing_verification_requirements must be an ordered "
                "tuple."
            )

        validated_findings = tuple(
            _revalidate_model(CalculationFinding, value)
            for value in existing_findings
        )
        validated_verifications = tuple(
            _revalidate_model(VerificationRequirement, value)
            for value in existing_verification_requirements
        )
        existing_finding_ids = {
            _comparison_text(value.finding_id)
            for value in validated_findings
        }
        existing_verification_ids = {
            _comparison_text(value.verification_id)
            for value in validated_verifications
        }
        seed_prefix = (
            f"{validated_definition.method_id}:"
            f"{validated_definition.method_version}"
        )
        verification_id = _derived_identifier(
            SAFETY_EVALUATION_FAILED_VERIFICATION_ID,
            seed=f"{seed_prefix}:failure-verification",
            existing=existing_verification_ids,
        )
        finding_id = _derived_identifier(
            SAFETY_EVALUATION_FAILED_FINDING_ID,
            seed=f"{seed_prefix}:failure-finding",
            existing=existing_finding_ids,
        )
        failure_verification = self._failure_verification(
            validated_definition,
            verification_id=verification_id,
        )
        failure_finding = self._failure_finding(
            finding_id=finding_id,
            verification_id=verification_id,
        )

        return SafetyReport(
            findings=(failure_finding,),
            verification_requirements=(failure_verification,),
            evaluator_failed=True,
        )

    def evaluate(
        self,
        context: SafetyEvaluationContext,
        evaluator: SafetyEvaluator | None = None,
    ) -> SafetyReport:
        """Evaluate missing inputs and a reviewed conditional safety hook."""

        validated_context = _revalidate_model(
            SafetyEvaluationContext,
            context,
        )
        requirements_by_id = {
            _comparison_text(value.requirement_id): value
            for value in validated_context.definition.safety_requirements
        }
        normalized_input_ids = {
            _comparison_text(value.input_id)
            for value in validated_context.normalized_inputs
        }
        missing_input_ids = {
            _comparison_text(value.input_id)
            for value in validated_context.missing_inputs
        }
        missing_input_ids.update(
            _comparison_text(value.input_id)
            for value in validated_context.definition.input_specifications
            if (
                _comparison_text(value.input_id)
                not in normalized_input_ids
            )
        )
        triggered_messages: dict[str, str | None] = {}

        for requirement in validated_context.definition.safety_requirements:
            required_input_ids = {
                _comparison_text(value)
                for value in requirement.required_input_ids
            }

            if required_input_ids.intersection(missing_input_ids):
                triggered_messages[
                    _comparison_text(requirement.requirement_id)
                ] = (
                    "A required input for this safety requirement is "
                    "missing."
                )

        evaluator_failed = False
        try:
            available_verifications = self._verification_index(
                validated_context
            )
            available_references = self._reference_index(
                validated_context
            )
        except SafetyEvaluationError:
            return self.failure_report(
                validated_context.definition,
                existing_findings=(
                    validated_context.existing_findings
                ),
                existing_verification_requirements=(
                    *validated_context.definition
                    .verification_requirements,
                    *validated_context.evidence
                    .verification_requirements,
                ),
            )

        if evaluator is not None:
            try:
                raw_extension = evaluator(validated_context)
                extension = _revalidate_model(
                    MethodSafetyExtension,
                    raw_extension,
                )
                unknown_trigger_ids = tuple(
                    trigger.requirement_id
                    for trigger in extension.triggers
                    if _comparison_text(trigger.requirement_id)
                    not in requirements_by_id
                )

                if unknown_trigger_ids:
                    raise SafetyEvaluationError(
                        "A safety evaluator returned an undeclared "
                        "requirement."
                    )

                for trigger in extension.triggers:
                    triggered_messages[
                        _comparison_text(trigger.requirement_id)
                    ] = trigger.message
            except Exception:
                evaluator_failed = True

        findings: list[CalculationFinding] = []
        verification_requirements: list[VerificationRequirement] = []
        used_finding_ids = {
            _comparison_text(value.finding_id)
            for value in validated_context.existing_findings
        }
        used_finding_ids.add(
            _comparison_text(SAFETY_EVALUATION_FAILED_FINDING_ID)
        )
        covered_missing_safety_inputs: set[str] = set()
        contract_failed = False

        for requirement in validated_context.definition.safety_requirements:
            requirement_key = _comparison_text(
                requirement.requirement_id
            )

            if requirement_key not in triggered_messages:
                continue

            if not self._links_resolve(
                requirement.verification_requirement_ids,
                requirement.reference_ids,
                available_verifications=available_verifications,
                available_references=available_references,
            ):
                contract_failed = True
                break

            finding_id = self._reserve_identifier(
                f"safety.{requirement.requirement_id}",
                seed=(
                    f"{validated_context.definition.method_id}:"
                    f"{validated_context.definition.method_version}:"
                    f"requirement:{requirement.requirement_id}"
                ),
                existing=used_finding_ids,
            )
            finding = self._finding_for_requirement(
                requirement,
                triggered_messages[requirement_key],
                finding_id=finding_id,
            )
            findings.append(finding)

            if finding.blocking:
                for input_id in requirement.required_input_ids:
                    if _comparison_text(input_id) in missing_input_ids:
                        covered_missing_safety_inputs.add(
                            _comparison_text(input_id)
                        )

            self._append_verifications(
                verification_requirements,
                requirement.verification_requirement_ids,
                available_verifications,
            )

        safety_critical_specifications = tuple(
            specification
            for specification
            in validated_context.definition.input_specifications
            if (
                specification.safety_critical
                and _comparison_text(specification.input_id)
                in missing_input_ids
            )
        )

        for specification in safety_critical_specifications:
            specification_key = _comparison_text(
                specification.input_id
            )

            if specification_key in covered_missing_safety_inputs:
                continue

            if not self._links_resolve(
                specification.verification_requirement_ids,
                specification.reference_ids,
                available_verifications=available_verifications,
                available_references=available_references,
            ):
                contract_failed = True
                break

            finding_id = self._reserve_identifier(
                f"safety.missing.{specification.input_id}",
                seed=(
                    f"{validated_context.definition.method_id}:"
                    f"{validated_context.definition.method_version}:"
                    f"missing-input:{specification.input_id}"
                ),
                existing=used_finding_ids,
            )
            findings.append(
                CalculationFinding(
                    finding_id=finding_id,
                    category=FindingCategory.SAFETY,
                    severity=FindingSeverity.CRITICAL,
                    title="Safety-critical input missing",
                    message=(
                        f"{specification.name} is required for safe "
                        "evaluation and was not supplied."
                    ),
                    blocking=True,
                    required_action=(
                        "Provide and independently verify the missing "
                        "safety-critical input before calculation."
                    ),
                    verification_requirement_ids=(
                        specification.verification_requirement_ids
                    ),
                    reference_ids=specification.reference_ids,
                )
            )

            self._append_verifications(
                verification_requirements,
                specification.verification_requirement_ids,
                available_verifications,
            )

        if not contract_failed:
            for assumption in validated_context.assumptions:
                if (
                    not assumption.safety_critical
                    or assumption.verification_completed
                ):
                    continue

                if not self._links_resolve(
                    assumption.verification_requirement_ids,
                    assumption.source_reference_ids,
                    available_verifications=available_verifications,
                    available_references=available_references,
                ):
                    contract_failed = True
                    break

                finding_id = self._reserve_identifier(
                    f"safety.assumption.{assumption.assumption_id}",
                    seed=(
                        f"{validated_context.definition.method_id}:"
                        f"{validated_context.definition.method_version}:"
                        f"assumption:{assumption.assumption_id}"
                    ),
                    existing=used_finding_ids,
                )
                findings.append(
                    CalculationFinding(
                        finding_id=finding_id,
                        category=FindingCategory.SAFETY,
                        severity=FindingSeverity.CRITICAL,
                        title="Safety-critical assumption unverified",
                        message=(
                            f"Safety-critical assumption "
                            f"{assumption.assumption_id!r} has not been "
                            "independently verified."
                        ),
                        blocking=True,
                        required_action=(
                            "Independently verify and document the "
                            "safety-critical assumption before calculation."
                        ),
                        verification_requirement_ids=(
                            assumption.verification_requirement_ids
                        ),
                        reference_ids=assumption.source_reference_ids,
                    )
                )
                self._append_verifications(
                    verification_requirements,
                    assumption.verification_requirement_ids,
                    available_verifications,
                )

        if contract_failed:
            return self.failure_report(
                validated_context.definition,
                existing_findings=(
                    validated_context.existing_findings
                ),
                existing_verification_requirements=(
                    *available_verifications.values(),
                ),
            )

        findings = list(
            self._deduplicate(
                findings,
                attribute_name="finding_id",
            )
        )
        verification_requirements = list(
            self._deduplicate(
                verification_requirements,
                attribute_name="verification_id",
            )
        )
        finding_capacity = (
            MAX_FINDINGS
            - len(validated_context.existing_findings)
        )

        if len(findings) > finding_capacity:
            evaluator_failed = True

        if evaluator_failed:
            retained_capacity = max(0, finding_capacity - 1)
            findings = findings[:retained_capacity]

            if (
                len(verification_requirements)
                >= MAX_VERIFICATION_REQUIREMENTS
            ):
                findings = []
                verification_requirements = []

            failure_report = self.failure_report(
                validated_context.definition,
                existing_findings=(
                    *validated_context.existing_findings,
                    *findings,
                ),
                existing_verification_requirements=(
                    *available_verifications.values(),
                    *verification_requirements,
                ),
            )
            findings.extend(failure_report.findings)
            verification_requirements.extend(
                failure_report.verification_requirements
            )

        return SafetyReport(
            findings=tuple(findings),
            verification_requirements=tuple(
                self._deduplicate(
                    verification_requirements,
                    attribute_name="verification_id",
                )
            ),
            evaluator_failed=evaluator_failed,
        )

    @staticmethod
    def _verification_index(
        context: SafetyEvaluationContext,
    ) -> dict[str, VerificationRequirement]:
        """Return server-resolved and method-owned verification metadata."""

        result: dict[str, VerificationRequirement] = {}

        for value in (
            *context.definition.verification_requirements,
            *context.evidence.verification_requirements,
        ):
            key = _comparison_text(value.verification_id)

            if key in result and result[key] != value:
                raise SafetyEvaluationError(
                    "Conflicting verification evidence was supplied."
                )

            result[key] = value

        return result

    @staticmethod
    def _reference_index(
        context: SafetyEvaluationContext,
    ) -> dict[str, CalculationReference]:
        """Return unambiguous method-owned and trusted references."""

        result: dict[str, CalculationReference] = {}

        for value in (
            *context.definition.references,
            *context.evidence.references,
        ):
            key = _comparison_text(value.reference_id)

            if key in result and result[key] != value:
                raise SafetyEvaluationError(
                    "Conflicting reference evidence was supplied."
                )

            result[key] = value

        return result

    @staticmethod
    def _links_resolve(
        verification_ids: tuple[str, ...],
        reference_ids: tuple[str, ...],
        *,
        available_verifications: Mapping[
            str,
            VerificationRequirement,
        ],
        available_references: Mapping[str, CalculationReference],
    ) -> bool:
        """Return whether every finding link has one unambiguous target."""

        return (
            {
                _comparison_text(value)
                for value in verification_ids
            }.issubset(available_verifications)
            and {
                _comparison_text(value)
                for value in reference_ids
            }.issubset(available_references)
        )

    @staticmethod
    def _append_verifications(
        target: list[VerificationRequirement],
        verification_ids: tuple[str, ...],
        available: Mapping[str, VerificationRequirement],
    ) -> None:
        """Append linked verification metadata in declared order."""

        for verification_id in verification_ids:
            target.append(
                available[_comparison_text(verification_id)]
            )

    @staticmethod
    def _reserve_identifier(
        base: str,
        *,
        seed: str,
        existing: set[str],
    ) -> str:
        """Derive and reserve one bounded collision-safe identifier."""

        result = _derived_identifier(
            base,
            seed=seed,
            existing=existing,
        )
        existing.add(_comparison_text(result))
        return result

    @staticmethod
    def _finding_for_requirement(
        requirement: SafetyRequirement,
        message: str | None,
        *,
        finding_id: str,
    ) -> CalculationFinding:
        """Build one finding without allowing a hook to weaken metadata."""

        return CalculationFinding(
            finding_id=finding_id,
            category=FindingCategory.SAFETY,
            severity=requirement.severity,
            title=requirement.title,
            message=message or requirement.hazard,
            blocking=requirement.blocking,
            required_action=requirement.required_action,
            verification_requirement_ids=(
                requirement.verification_requirement_ids
            ),
            reference_ids=requirement.reference_ids,
        )

    @staticmethod
    def _failure_verification(
        definition: CalculationMethodDefinition,
        *,
        verification_id: str,
    ) -> VerificationRequirement:
        """Return the fixed verification action for fail-closed evaluation."""

        return VerificationRequirement(
            verification_id=verification_id,
            description=_FAILURE_VERIFICATION_DESCRIPTION,
            method=_FAILURE_VERIFICATION_METHOD,
            expected_result=_FAILURE_VERIFICATION_EXPECTED_RESULT,
            required_competency=(
                definition.required_reviewer_competency
            ),
            verifier_role=_FAILURE_VERIFIER_ROLE,
            independent_verification_required=True,
            evidence_required=_FAILURE_EVIDENCE,
        )

    @staticmethod
    def _failure_finding(
        *,
        finding_id: str,
        verification_id: str,
    ) -> CalculationFinding:
        """Return a stable sanitized finding for evaluator failure."""

        return CalculationFinding(
            finding_id=finding_id,
            category=FindingCategory.SAFETY,
            severity=FindingSeverity.CRITICAL,
            title=_FAILURE_TITLE,
            message=_FAILURE_MESSAGE,
            blocking=True,
            required_action=_FAILURE_ACTION,
            verification_requirement_ids=(verification_id,),
        )

    @staticmethod
    def _deduplicate(
        values: list[CalculationModel],
        *,
        attribute_name: str,
    ) -> tuple[Any, ...]:
        """Preserve first occurrence while rejecting conflicting duplicates."""

        result: list[CalculationModel] = []
        values_by_key: dict[str, CalculationModel] = {}

        for value in values:
            key = _comparison_text(
                str(getattr(value, attribute_name))
            )
            existing = values_by_key.get(key)

            if existing is None:
                values_by_key[key] = value
                result.append(value)
                continue

            if existing != value:
                raise SafetyEvaluationError(
                    "Conflicting safety report identifiers were produced."
                )

        return tuple(result)


DEFAULT_SAFETY_ENGINE = CalculationSafetyEngine()


__all__ = [
    "CalculationSafetyEngine",
    "DEFAULT_SAFETY_ENGINE",
    "MAX_SAFETY_TRIGGERS",
    "MethodSafetyExtension",
    "SAFETY_EVALUATION_FAILED_FINDING_ID",
    "SAFETY_EVALUATION_FAILED_VERIFICATION_ID",
    "SafetyEvaluationContext",
    "SafetyEvaluationError",
    "SafetyEvaluator",
    "SafetyReport",
    "SafetyTrigger",
]
