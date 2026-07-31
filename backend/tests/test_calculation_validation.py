"""Focused tests for deterministic Step 92 calculation validation."""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
import inspect
from types import MappingProxyType
from typing import Any

from pydantic import ValidationError
import pytest

from app.engineering.calculations.method_models import ApplicabilityRule
from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
)
from app.engineering.calculations.method_models import EngineCompatibility
from app.engineering.calculations.method_models import InputNormalizationMode
from app.engineering.calculations.method_models import InputPresence
from app.engineering.calculations.method_models import InputValueType
from app.engineering.calculations.method_models import (
    MethodInputSpecification,
)
from app.engineering.calculations.method_models import (
    MethodOptionSpecification,
)
from app.engineering.calculations.method_models import MethodOptionValueType
from app.engineering.calculations.method_models import (
    NumericApplicabilityRange,
)
from app.engineering.calculations.method_models import (
    TrustedExecutionEvidence,
)
from app.engineering.calculations.models import CalculationAssumption
from app.engineering.calculations.models import CalculationInput
from app.engineering.calculations.models import CalculationOption
from app.engineering.calculations.models import CalculationReference
from app.engineering.calculations.models import CalculationRequest
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import FindingCategory
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import InputOrigin
from app.engineering.calculations.models import MAX_FINDINGS
from app.engineering.calculations.models import MAX_INPUTS
from app.engineering.calculations.models import MAX_OPTIONS
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.models import ReferenceType
from app.engineering.calculations.models import TraceStepKind
from app.engineering.calculations.models import TraceStepStatus
from app.engineering.calculations.models import VerificationRequirement
from app.engineering.calculations.units import QuantityKind
from app.engineering.calculations.units import UnitRegistry
from app.engineering.calculations.validation import (
    CalculationValidationEngine,
)
from app.engineering.calculations.validation import (
    CalculationValidationReport,
)
from app.engineering.calculations.validation import (
    DEFAULT_CALCULATION_VALIDATION_ENGINE,
)
from app.engineering.calculations.validation import DEFAULT_VALIDATION_ENGINE
from app.engineering.calculations.validation import (
    InvalidValidationContractError,
)


NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def normalize_reference_flow(
    specification: MethodInputSpecification,
    supplied_input: CalculationInput,
) -> CalculationInput:
    """Test-only direct reviewed normalizer for reference-qualified flow."""

    assert supplied_input.quantity is not None
    normalized_quantity = supplied_input.quantity.model_copy(
        update={
            "value": supplied_input.quantity.value / 3_600.0,
            "unit": "m3/s",
            "decimal_places": None,
        }
    )
    return supplied_input.model_copy(
        update={
            "input_id": specification.input_id,
            "name": specification.name,
            "quantity": normalized_quantity,
        }
    )


def normalize_raising_secret(
    specification: MethodInputSpecification,
    supplied_input: CalculationInput,
) -> CalculationInput:
    del specification, supplied_input
    raise RuntimeError("secret-token-should-never-leak")


def normalize_wrong_unit(
    specification: MethodInputSpecification,
    supplied_input: CalculationInput,
) -> CalculationInput:
    assert supplied_input.quantity is not None
    return supplied_input.model_copy(
        update={
            "input_id": specification.input_id,
            "quantity": supplied_input.quantity.model_copy(
                update={"unit": "m3/h"}
            ),
        }
    )


def normalize_wrong_metadata(
    specification: MethodInputSpecification,
    supplied_input: CalculationInput,
) -> CalculationInput:
    return supplied_input.model_copy(
        update={
            "input_id": specification.input_id,
            "name": specification.name,
            "notes": "Hook changed protected source metadata.",
        }
    )


def normalize_bypass_invalid(
    specification: MethodInputSpecification,
    supplied_input: CalculationInput,
) -> CalculationInput:
    del specification, supplied_input
    return CalculationInput.model_construct(
        input_id="flow",
        name="Reference flow",
        origin=InputOrigin.USER_SUPPLIED,
        quantity=None,
        categorical_value=None,
    )


def normalize_wrong_parameter_names(
    spec: MethodInputSpecification,
    supplied_input: CalculationInput,
) -> CalculationInput:
    return normalize_reference_flow(spec, supplied_input)


def normalize_defaulted_parameter(
    specification: MethodInputSpecification,
    supplied_input: CalculationInput | None = None,
) -> CalculationInput:
    assert supplied_input is not None
    return normalize_reference_flow(specification, supplied_input)


async def normalize_async(
    specification: MethodInputSpecification,
    supplied_input: CalculationInput,
) -> CalculationInput:
    return normalize_reference_flow(specification, supplied_input)


def normalize_generator(
    specification: MethodInputSpecification,
    supplied_input: CalculationInput,
) -> Any:
    yield normalize_reference_flow(specification, supplied_input)


async def normalize_async_generator(
    specification: MethodInputSpecification,
    supplied_input: CalculationInput,
) -> Any:
    yield normalize_reference_flow(specification, supplied_input)


def normalize_signature_spoof(
    specification: MethodInputSpecification,
    supplied_input: CalculationInput,
) -> CalculationInput:
    return normalize_reference_flow(specification, supplied_input)


def normalize_wrapped_spoof(
    specification: MethodInputSpecification,
    supplied_input: CalculationInput,
) -> CalculationInput:
    return normalize_reference_flow(specification, supplied_input)


def applicability_accept(
    rule: ApplicabilityRule,
    linked_inputs: tuple[CalculationInput, ...],
) -> bool:
    return (
        tuple(value.input_id for value in linked_inputs)
        == rule.input_ids
    )


def applicability_reject(
    rule: ApplicabilityRule,
    linked_inputs: tuple[CalculationInput, ...],
) -> bool:
    del rule, linked_inputs
    return False


def applicability_raising_secret(
    rule: ApplicabilityRule,
    linked_inputs: tuple[CalculationInput, ...],
) -> bool:
    del rule, linked_inputs
    raise RuntimeError("private-process-value-should-never-leak")


def applicability_non_boolean(
    rule: ApplicabilityRule,
    linked_inputs: tuple[CalculationInput, ...],
) -> Any:
    del rule, linked_inputs
    return 1


def applicability_wrong_parameter_names(
    applicability_rule: ApplicabilityRule,
    linked_inputs: tuple[CalculationInput, ...],
) -> bool:
    del applicability_rule, linked_inputs
    return True


class CallableNormalizer:
    def __call__(
        self,
        specification: MethodInputSpecification,
        supplied_input: CalculationInput,
    ) -> CalculationInput:
        return normalize_reference_flow(specification, supplied_input)


def verification_requirement(
    verification_id: str = "method-input-review",
    *,
    description: str = "Review controlled method inputs.",
) -> VerificationRequirement:
    return VerificationRequirement(
        verification_id=verification_id,
        description=description,
        method="Compare values with traceable source evidence.",
        expected_result="Inputs satisfy the reviewed method contract.",
        acceptance_criteria="All linked validation findings are resolved.",
        required_competency="Competent calculation reviewer",
    )


def length_input(
    value: float = 250.0,
    *,
    unit: str = "cm",
    input_id: str = "length",
    name: str = "Length",
) -> CalculationInput:
    return CalculationInput(
        input_id=input_id,
        name=name,
        origin=InputOrigin.USER_SUPPLIED,
        quantity=EngineeringQuantity(
            quantity_kind=QuantityKind.LENGTH.value,
            value=value,
            unit=unit,
        ),
    )


def mode_input(
    value: str | bool = "AUTO",
    *,
    name: str = "Mode",
) -> CalculationInput:
    return CalculationInput(
        input_id="mode",
        name=name,
        origin=InputOrigin.USER_SUPPLIED,
        categorical_value=value,
    )


def flow_input(
    value: float = 3_600.0,
    *,
    unit: str = "m3/h",
    name: str = "Reference flow",
) -> CalculationInput:
    return CalculationInput(
        input_id="flow",
        name=name,
        origin=InputOrigin.USER_SUPPLIED,
        quantity=EngineeringQuantity(
            quantity_kind=(
                QuantityKind.STANDARD_VOLUMETRIC_FLOW.value
            ),
            value=value,
            unit=unit,
        ),
    )


def default_factor_specification() -> MethodInputSpecification:
    assumption = CalculationAssumption(
        assumption_id="default.factor",
        statement="Use the reviewed neutral factor.",
        origin=InputOrigin.DEFAULTED,
    )
    default_input = CalculationInput(
        input_id="factor",
        name="Factor",
        origin=InputOrigin.DEFAULTED,
        quantity=EngineeringQuantity(
            quantity_kind=QuantityKind.DIMENSIONLESS.value,
            value=1.0,
            unit="1",
        ),
        assumption_id=assumption.assumption_id,
    )
    return MethodInputSpecification(
        input_id="factor",
        name="Factor",
        description="Reviewed default dimensionless factor.",
        presence=InputPresence.DEFAULTED,
        value_type=InputValueType.QUANTITY,
        normalization_mode=InputNormalizationMode.UNIT_REGISTRY,
        quantity_kind=QuantityKind.DIMENSIONLESS,
        canonical_unit="1",
        numeric_range=NumericApplicabilityRange(
            minimum=0.0,
            maximum=10.0,
        ),
        default_input=default_input,
        default_assumption=assumption,
    )


def make_definition(
    *,
    include_flow: bool = True,
    include_rule: bool = True,
    length_range: NumericApplicabilityRange | None = None,
    mode_specification: MethodInputSpecification | None = None,
) -> CalculationMethodDefinition:
    requirement = verification_requirement()
    specifications: list[MethodInputSpecification] = [
        MethodInputSpecification(
            input_id="length",
            name="Length",
            description="Controlled length input.",
            presence=InputPresence.REQUIRED,
            value_type=InputValueType.QUANTITY,
            normalization_mode=InputNormalizationMode.UNIT_REGISTRY,
            quantity_kind=QuantityKind.LENGTH,
            canonical_unit="m",
            numeric_range=(
                length_range
                if length_range is not None
                else NumericApplicabilityRange(
                    minimum=0.0,
                    maximum=10.0,
                )
            ),
            verification_requirement_ids=(
                requirement.verification_id,
            ),
        ),
        (
            mode_specification
            if mode_specification is not None
            else MethodInputSpecification(
                input_id="mode",
                name="Mode",
                description="Controlled operating mode.",
                presence=InputPresence.OPTIONAL,
                value_type=InputValueType.CATEGORICAL_TEXT,
                normalization_mode=InputNormalizationMode.NONE,
                allowed_categorical_values=("auto", "manual"),
            )
        ),
        default_factor_specification(),
    ]
    if include_flow:
        specifications.append(
            MethodInputSpecification(
                input_id="flow",
                name="Reference flow",
                description=(
                    "Reference-qualified volumetric flow requiring reviewed "
                    "method-specific normalization."
                ),
                presence=InputPresence.OPTIONAL,
                value_type=InputValueType.QUANTITY,
                normalization_mode=(
                    InputNormalizationMode.METHOD_SPECIFIC
                ),
                quantity_kind=(
                    QuantityKind.STANDARD_VOLUMETRIC_FLOW
                ),
                canonical_unit="m3/s",
                numeric_range=NumericApplicabilityRange(
                    minimum=0.0,
                    maximum=100.0,
                ),
            )
        )

    rules: tuple[ApplicabilityRule, ...] = ()
    if include_rule:
        rules = (
            ApplicabilityRule(
                rule_id="length-mode-applicability",
                title="Length and mode are not applicable",
                description=(
                    "The supplied length and mode are outside the reviewed "
                    "method applicability."
                ),
                input_ids=("length", "mode"),
                severity=FindingSeverity.ERROR,
                blocking=True,
                required_action=(
                    "Select inputs and a method within reviewed limits."
                ),
                verification_requirement_ids=(
                    requirement.verification_id,
                ),
            ),
        )

    return CalculationMethodDefinition(
        method_id="test.validation",
        method_version="1.0.0",
        calculation_type="validation.test",
        title="Validation test method",
        description="Reviewed metadata fixture for validation tests.",
        implementation_owner="Engineer4Me test engineering",
        lifecycle_status=MethodLifecycleStatus.DRAFT,
        engine_compatibility=EngineCompatibility(
            minimum_version="0.4.0",
            maximum_exclusive_version="1.0.0",
        ),
        input_specifications=tuple(specifications),
        option_specifications=(
            MethodOptionSpecification(
                option_id="enabled",
                description="Enable the reviewed calculation path.",
                value_type=MethodOptionValueType.BOOLEAN,
                required=True,
                allowed_values=(True, False),
            ),
            MethodOptionSpecification(
                option_id="iterations",
                description="Reviewed bounded iteration selection.",
                value_type=MethodOptionValueType.INTEGER,
                default_option=CalculationOption(
                    option_id="iterations",
                    value=3,
                ),
                allowed_values=(1, 3, 5),
                numeric_range=NumericApplicabilityRange(
                    minimum=1.0,
                    maximum=5.0,
                ),
            ),
        ),
        applicability_rules=rules,
        verification_requirements=(requirement,),
        required_reviewer_competency="Competent calculation reviewer",
        disclaimer="Preliminary engineering decision support only.",
    )


def make_request(
    *,
    inputs: tuple[CalculationInput, ...] | None = None,
    options: tuple[CalculationOption, ...] | None = None,
    assumptions: tuple[CalculationAssumption, ...] = (),
    method_id: str = "test.validation",
    method_version: str = "1.0.0",
    calculation_type: str = "validation.test",
) -> CalculationRequest:
    return CalculationRequest(
        calculation_type=calculation_type,
        method_id=method_id,
        method_version=method_version,
        requested_at=NOW,
        inputs=(
            (
                length_input(),
                mode_input(),
                flow_input(),
            )
            if inputs is None
            else inputs
        ),
        assumptions=assumptions,
        options=(
            (CalculationOption(option_id="enabled", value=True),)
            if options is None
            else options
        ),
    )


def normalizers() -> MappingProxyType[str, Any]:
    return MappingProxyType({"flow": normalize_reference_flow})


def evaluators() -> MappingProxyType[str, Any]:
    return MappingProxyType(
        {"length-mode-applicability": applicability_accept}
    )


def validate_happy_path() -> CalculationValidationReport:
    return DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        TrustedExecutionEvidence(),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )


def test_happy_path_is_definition_ordered_and_executable() -> None:
    report = validate_happy_path()

    assert report.can_execute is True
    assert report.findings == ()
    assert tuple(
        value.input_id
        for value in report.normalized_inputs
    ) == ("length", "mode", "factor", "flow")
    assert tuple(
        value.input_id
        for value in report.defaulted_inputs
    ) == ("factor",)
    assert tuple(
        value.option_id
        for value in report.effective_options
    ) == ("enabled", "iterations")
    assert tuple(
        value.assumption_id
        for value in report.assumptions
    ) == ("default.factor",)
    assert report.missing_inputs == ()
    assert tuple(
        value.sequence
        for value in report.normalization_trace
    ) == (1, 2, 3, 4)
    assert all(
        value.kind is TraceStepKind.NORMALIZATION
        for value in report.normalization_trace
    )
    assert all(
        value.status is TraceStepStatus.COMPLETED
        for value in report.normalization_trace
    )


def test_happy_path_normalizes_units_and_preserves_categorical_value() -> None:
    report = validate_happy_path()
    values = {
        value.input_id: value
        for value in report.normalized_inputs
    }

    assert values["length"].quantity is not None
    assert values["length"].quantity.value == pytest.approx(2.5)
    assert values["length"].quantity.unit == "m"
    assert values["mode"].categorical_value == "AUTO"
    assert values["factor"].quantity is not None
    assert values["factor"].quantity.value == 1.0
    assert values["flow"].quantity is not None
    assert values["flow"].quantity.value == pytest.approx(1.0)
    assert values["flow"].quantity.unit == "m3/s"


def test_validation_does_not_mutate_source_models() -> None:
    request = make_request()
    definition = make_definition()
    evidence = TrustedExecutionEvidence()
    snapshots = tuple(
        value.model_dump_json()
        for value in (request, definition, evidence)
    )

    DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        request,
        definition,
        evidence,
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )

    assert snapshots == tuple(
        value.model_dump_json()
        for value in (request, definition, evidence)
    )


def test_repeated_validation_is_deterministic() -> None:
    request = make_request()
    definition = make_definition()
    first = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        request,
        definition,
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    second = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        request,
        definition,
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_report_is_frozen_and_tuple_backed() -> None:
    report = validate_happy_path()

    assert isinstance(report.normalized_inputs, tuple)
    assert isinstance(report.findings, tuple)
    with pytest.raises(ValidationError):
        report.can_execute = False  # type: ignore[misc]
    with pytest.raises(ValidationError):
        report.model_copy(update={"can_execute": False})


def test_report_json_round_trip() -> None:
    report = validate_happy_path()
    restored = CalculationValidationReport.model_validate_json(
        report.model_dump_json()
    )
    assert restored == report


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    (
        ("method_id", "other.method"),
        ("method_version", "2.0.0"),
        ("calculation_type", "other.calculation"),
    ),
)
def test_method_identity_mismatch_fails_closed(
    field_name: str,
    replacement: str,
) -> None:
    request = make_request(**{field_name: replacement})
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        request,
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )

    assert report.can_execute is False
    assert any(
        value.title == "Method identity mismatch"
        and value.blocking
        for value in report.findings
    )


def test_unknown_input_is_rejected_without_displacing_known_order() -> None:
    unknown = CalculationInput(
        input_id="unknown.input",
        name="Unknown input",
        origin=InputOrigin.USER_SUPPLIED,
        categorical_value="value",
    )
    request = make_request(
        inputs=(
            unknown,
            flow_input(),
            mode_input(),
            length_input(),
        )
    )
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        request,
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )

    assert report.can_execute is False
    assert tuple(
        value.input_id
        for value in report.normalized_inputs
    ) == ("length", "mode", "factor", "flow")
    assert any(
        value.title == "Unknown calculation input"
        for value in report.findings
    )


def test_unknown_option_is_rejected() -> None:
    request = make_request(
        options=(
            CalculationOption(option_id="unknown.option", value=True),
            CalculationOption(option_id="enabled", value=True),
        )
    )
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        request,
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert any(
        value.title == "Unknown calculation option"
        for value in report.findings
    )


def test_missing_required_and_optional_inputs_are_deterministic() -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(inputs=()),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )

    assert tuple(
        value.input_id
        for value in report.missing_inputs
    ) == ("length", "mode", "flow")
    missing = {
        value.input_id: value
        for value in report.missing_inputs
    }
    assert missing["length"].required_for_execution is True
    assert missing["mode"].required_for_execution is False
    assert missing["flow"].required_for_execution is False
    assert tuple(
        value.input_id
        for value in report.normalized_inputs
    ) == ("factor",)
    assert tuple(
        value.status
        for value in report.normalization_trace
    ) == (
        TraceStepStatus.SKIPPED,
        TraceStepStatus.SKIPPED,
        TraceStepStatus.COMPLETED,
        TraceStepStatus.SKIPPED,
    )
    assert report.can_execute is False


@pytest.mark.parametrize(
    "invalid_input",
    (
        CalculationInput(
            input_id="length",
            name="Length",
            origin=InputOrigin.USER_SUPPLIED,
            categorical_value="2.5",
        ),
        CalculationInput(
            input_id="length",
            name="Length",
            origin=InputOrigin.USER_SUPPLIED,
            quantity=EngineeringQuantity(
                quantity_kind=QuantityKind.MASS.value,
                value=2.5,
                unit="kg",
            ),
        ),
        CalculationInput(
            input_id="length",
            name="Wrong name",
            origin=InputOrigin.USER_SUPPLIED,
            quantity=EngineeringQuantity(
                quantity_kind=QuantityKind.LENGTH.value,
                value=2.5,
                unit="m",
            ),
        ),
    ),
)
def test_quantity_shape_kind_and_name_are_strict(
    invalid_input: CalculationInput,
) -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(
            inputs=(invalid_input, mode_input(), flow_input())
        ),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert "length" not in {
        value.input_id
        for value in report.normalized_inputs
    }


@pytest.mark.parametrize(
    ("value_cm", "accepted"),
    (
        (0.0, True),
        (1_000.0, True),
        (-0.001, False),
        (1_000.001, False),
    ),
)
def test_quantity_range_boundaries(
    value_cm: float,
    accepted: bool,
) -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(
            inputs=(
                length_input(value_cm),
                mode_input(),
                flow_input(),
            )
        ),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    range_findings = tuple(
        value
        for value in report.findings
        if value.title == "Input is outside the reviewed range"
    )
    assert bool(range_findings) is (not accepted)


@pytest.mark.parametrize(
    ("minimum_inclusive", "maximum_inclusive", "value", "accepted"),
    (
        (False, True, 0.0, False),
        (False, True, 0.001, True),
        (True, False, 10.0, False),
        (True, False, 9.999, True),
    ),
)
def test_exclusive_quantity_range_boundaries(
    minimum_inclusive: bool,
    maximum_inclusive: bool,
    value: float,
    accepted: bool,
) -> None:
    definition = make_definition(
        length_range=NumericApplicabilityRange(
            minimum=0.0,
            maximum=10.0,
            minimum_inclusive=minimum_inclusive,
            maximum_inclusive=maximum_inclusive,
        )
    )
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(
            inputs=(
                length_input(value, unit="m"),
                mode_input(),
                flow_input(),
            )
        ),
        definition,
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    range_findings = tuple(
        item
        for item in report.findings
        if item.title == "Input is outside the reviewed range"
    )
    assert bool(range_findings) is (not accepted)


@pytest.mark.parametrize(
    ("mode_value", "accepted"),
    (
        ("auto", True),
        ("AUTO", True),
        ("Manual", True),
        ("unsupported", False),
        (True, False),
    ),
)
def test_categorical_text_allow_list_is_strict(
    mode_value: str | bool,
    accepted: bool,
) -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(
            inputs=(
                length_input(),
                mode_input(mode_value),
                flow_input(),
            )
        ),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    normalized_ids = {
        value.input_id
        for value in report.normalized_inputs
    }
    assert ("mode" in normalized_ids) is accepted


def test_case_sensitive_categorical_allow_list() -> None:
    mode_specification = MethodInputSpecification(
        input_id="mode",
        name="Mode",
        description="Case-sensitive mode.",
        presence=InputPresence.OPTIONAL,
        value_type=InputValueType.CATEGORICAL_TEXT,
        normalization_mode=InputNormalizationMode.NONE,
        allowed_categorical_values=("auto", "manual"),
        categorical_case_sensitive=True,
    )
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(mode_specification=mode_specification),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert "mode" not in {
        value.input_id
        for value in report.normalized_inputs
    }


def test_boolean_categorical_input_requires_boolean() -> None:
    mode_specification = MethodInputSpecification(
        input_id="mode",
        name="Mode",
        description="Boolean mode.",
        presence=InputPresence.OPTIONAL,
        value_type=InputValueType.CATEGORICAL_BOOLEAN,
        normalization_mode=InputNormalizationMode.NONE,
        allowed_categorical_values=(True, False),
    )
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(mode_specification=mode_specification),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert "mode" not in {
        value.input_id
        for value in report.normalized_inputs
    }


@pytest.mark.parametrize(
    ("option", "accepted"),
    (
        (CalculationOption(option_id="iterations", value=1), True),
        (CalculationOption(option_id="iterations", value=3), True),
        (CalculationOption(option_id="iterations", value=5), True),
        (CalculationOption(option_id="iterations", value=2), False),
        (CalculationOption(option_id="iterations", value=True), False),
        (CalculationOption(option_id="iterations", value=3.0), False),
    ),
)
def test_option_type_range_and_allow_list_are_strict(
    option: CalculationOption,
    accepted: bool,
) -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(
            options=(
                CalculationOption(option_id="enabled", value=True),
                option,
            )
        ),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    effective_ids = {
        value.option_id
        for value in report.effective_options
    }
    assert ("iterations" in effective_ids) is accepted


def test_required_option_missing_blocks_but_default_option_is_effective(
) -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(options=()),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert tuple(
        value.option_id
        for value in report.effective_options
    ) == ("iterations",)
    assert any(
        value.title == "Required option is missing"
        for value in report.findings
    )


def test_default_input_and_assumption_are_not_used_when_supplied() -> None:
    supplied_factor = CalculationInput(
        input_id="factor",
        name="Factor",
        origin=InputOrigin.USER_SUPPLIED,
        quantity=EngineeringQuantity(
            quantity_kind=QuantityKind.DIMENSIONLESS.value,
            value=2.0,
            unit="1",
        ),
    )
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(
            inputs=(
                length_input(),
                mode_input(),
                supplied_factor,
                flow_input(),
            )
        ),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    assert report.defaulted_inputs == ()
    assert report.assumptions == ()
    factor = next(
        value
        for value in report.normalized_inputs
        if value.input_id == "factor"
    )
    assert factor.quantity is not None
    assert factor.quantity.value == 2.0


def test_default_assumption_identifier_collision_fails_closed() -> None:
    request_assumption = CalculationAssumption(
        assumption_id="default.factor",
        statement="Conflicting user assumption.",
        origin=InputOrigin.USER_SUPPLIED,
    )
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(assumptions=(request_assumption,)),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert any(
        value.title == "Assumption identifier collision"
        for value in report.findings
    )


def test_method_specific_input_requires_direct_hook() -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        input_normalizers={},
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert any(
        value.title == "Method-specific normalizer is unavailable"
        for value in report.findings
    )
    assert "flow" not in {
        value.input_id
        for value in report.normalized_inputs
    }


@pytest.mark.parametrize(
    "invalid_hook",
    (
        lambda specification, source: source,
        CallableNormalizer(),
        normalize_wrong_parameter_names,
        normalize_defaulted_parameter,
        normalize_async,
        normalize_generator,
        normalize_async_generator,
    ),
)
def test_non_direct_normalizers_are_rejected(
    invalid_hook: Any,
) -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        input_normalizers={"flow": invalid_hook},
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert any(
        value.title == "Invalid trusted validation hook binding"
        for value in report.findings
    )


@pytest.mark.parametrize(
    ("hook", "spoof_attribute", "spoof_value"),
    (
        (
            normalize_signature_spoof,
            "__signature__",
            inspect.signature(normalize_reference_flow),
        ),
        (
            normalize_wrapped_spoof,
            "__wrapped__",
            normalize_reference_flow,
        ),
    ),
)
def test_callable_signature_spoofs_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    hook: Any,
    spoof_attribute: str,
    spoof_value: Any,
) -> None:
    monkeypatch.setattr(
        hook,
        spoof_attribute,
        spoof_value,
        raising=False,
    )
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        input_normalizers={"flow": hook},
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert any(
        value.title == "Invalid trusted validation hook binding"
        for value in report.findings
    )


def test_closure_normalizer_is_rejected() -> None:
    secret = "closed"

    def closure(
        specification: MethodInputSpecification,
        source: CalculationInput,
    ) -> CalculationInput:
        assert secret
        return normalize_reference_flow(specification, source)

    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        input_normalizers={"flow": closure},
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert any(
        value.title == "Invalid trusted validation hook binding"
        for value in report.findings
    )


@pytest.mark.parametrize(
    ("hook", "expected_title"),
    (
        (
            normalize_wrong_unit,
            "Invalid method-specific normalization output",
        ),
        (
            normalize_wrong_metadata,
            "Invalid method-specific normalization output",
        ),
        (
            normalize_bypass_invalid,
            "Method-specific normalization failed",
        ),
    ),
)
def test_method_specific_hook_output_is_revalidated(
    hook: Any,
    expected_title: str,
) -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        input_normalizers={"flow": hook},
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert any(
        value.title == expected_title
        for value in report.findings
    )


def test_method_specific_exception_is_sanitized() -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        input_normalizers={"flow": normalize_raising_secret},
        applicability_evaluators=evaluators(),
    )
    rendered = report.model_dump_json()
    assert report.can_execute is False
    assert "secret-token-should-never-leak" not in rendered
    assert "RuntimeError" not in rendered
    assert any(
        value.title == "Method-specific normalization failed"
        for value in report.findings
    )


def test_extra_and_casefold_duplicate_normalizer_bindings_fail_closed(
) -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        input_normalizers={
            "flow": normalize_reference_flow,
            "FLOW": normalize_reference_flow,
            "extra": normalize_reference_flow,
        },
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert any(
        value.title == "Invalid trusted validation hook binding"
        for value in report.findings
    )


def test_generic_reference_flow_cannot_use_private_registry_bypass() -> None:
    definition = make_definition()
    flow_specification = definition.input_specifications[-1].model_copy(
        update={
            "normalization_mode": InputNormalizationMode.UNIT_REGISTRY,
        }
    )
    definition = definition.model_copy(
        update={
            "input_specifications": (
                *definition.input_specifications[:-1],
                flow_specification,
            )
        }
    )
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        definition,
        input_normalizers={},
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert "flow" not in {
        value.input_id
        for value in report.normalized_inputs
    }
    source = inspect.getsource(
        __import__(
            "app.engineering.calculations.validation",
            fromlist=["validation"],
        )
    )
    assert "._convert_quantity" not in source
    assert "._validate_quantity" not in source


def test_public_unit_registry_conversion_is_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = make_request()
    definition = make_definition()
    original = UnitRegistry.convert_quantity
    calls: list[str] = []

    def spy(
        self: UnitRegistry,
        quantity: EngineeringQuantity,
        to_unit: str,
    ) -> EngineeringQuantity:
        calls.append(to_unit)
        return original(self, quantity, to_unit)

    monkeypatch.setattr(UnitRegistry, "convert_quantity", spy)
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        request,
        definition,
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is True
    assert calls.count("m") == 1
    assert calls.count("1") >= 1
    assert set(calls) == {"m", "1"}


def test_applicability_false_uses_reviewed_rule_metadata() -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators={
            "length-mode-applicability": applicability_reject
        },
    )
    finding = next(
        value
        for value in report.findings
        if value.title == "Length and mode are not applicable"
    )
    assert finding.category is FindingCategory.APPLICABILITY
    assert finding.severity is FindingSeverity.ERROR
    assert finding.blocking is True
    assert finding.verification_requirement_ids == (
        "method-input-review",
    )
    assert report.can_execute is False


def test_applicability_callback_receives_rule_input_order() -> None:
    report = validate_happy_path()
    assert not any(
        value.category is FindingCategory.APPLICABILITY
        for value in report.findings
    )


@pytest.mark.parametrize(
    ("evaluator", "expected_title"),
    (
        (
            applicability_raising_secret,
            "Applicability evaluation failed",
        ),
        (
            applicability_non_boolean,
            "Invalid applicability result",
        ),
    ),
)
def test_applicability_callback_failures_are_sanitized(
    evaluator: Any,
    expected_title: str,
) -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators={
            "length-mode-applicability": evaluator
        },
    )
    rendered = report.model_dump_json()
    assert report.can_execute is False
    assert any(
        value.title == expected_title
        for value in report.findings
    )
    assert "private-process-value-should-never-leak" not in rendered
    assert "RuntimeError" not in rendered


def test_missing_and_extra_applicability_bindings_fail_closed() -> None:
    missing = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators={},
    )
    extra = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators={
            "length-mode-applicability": applicability_accept,
            "extra.rule": applicability_accept,
        },
    )
    assert missing.can_execute is False
    assert extra.can_execute is False
    assert any(
        value.title == "Applicability hook coverage mismatch"
        for value in missing.findings
    )
    assert any(
        value.title == "Applicability hook coverage mismatch"
        for value in extra.findings
    )


def test_applicability_hook_signature_is_attested() -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators={
            "length-mode-applicability":
                applicability_wrong_parameter_names,
        },
    )
    assert report.can_execute is False
    assert any(
        value.title == "Invalid trusted validation hook binding"
        for value in report.findings
    )


def test_applicability_with_missing_linked_input_fails_closed() -> None:
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(inputs=(length_input(), flow_input())),
        make_definition(),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert any(
        value.title == "Applicability could not be evaluated"
        for value in report.findings
    )


def test_bypass_constructed_request_is_revalidated() -> None:
    request = make_request()
    object.__setattr__(request, "method_id", "!")
    with pytest.raises(
        InvalidValidationContractError,
        match="request failed validation",
    ):
        DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
            request,
            make_definition(),
        )


def test_bypass_constructed_definition_and_nested_spec_are_revalidated(
) -> None:
    definition = make_definition()
    bad_specification = MethodInputSpecification.model_construct(
        **{
            **definition.input_specifications[0].model_dump(
                mode="python",
                round_trip=True,
            ),
            "canonical_unit": "kg",
        }
    )
    object.__setattr__(
        definition,
        "input_specifications",
        (
            bad_specification,
            *definition.input_specifications[1:],
        ),
    )
    with pytest.raises(
        InvalidValidationContractError,
        match="definition failed validation",
    ):
        DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
            make_request(),
            definition,
        )


def test_bypass_constructed_evidence_is_revalidated() -> None:
    invalid_reference = CalculationReference.model_construct(
        reference_id="!",
        reference_type=ReferenceType.OTHER,
        title="Invalid reference",
        verified=False,
    )
    evidence = TrustedExecutionEvidence.model_construct(
        references=(invalid_reference,),
        verification_requirements=(),
    )
    with pytest.raises(
        InvalidValidationContractError,
        match="evidence failed validation",
    ):
        DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
            make_request(),
            make_definition(),
            evidence,
        )


def test_wrong_boundary_types_are_sanitized() -> None:
    engine = CalculationValidationEngine()
    with pytest.raises(
        InvalidValidationContractError,
        match="request must be a CalculationRequest",
    ):
        engine.validate(  # type: ignore[arg-type]
            {},
            make_definition(),
        )
    with pytest.raises(
        InvalidValidationContractError,
        match="definition must be a CalculationMethodDefinition",
    ):
        engine.validate(  # type: ignore[arg-type]
            make_request(),
            {},
        )


def test_evidence_requirements_merge_in_stable_order() -> None:
    extra = verification_requirement(
        "site-input-review",
        description="Review site-supplied evidence.",
    )
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        TrustedExecutionEvidence(
            verification_requirements=(extra,)
        ),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    assert tuple(
        value.verification_id
        for value in report.verification_requirements
    ) == ("method-input-review", "site-input-review")


def test_conflicting_evidence_requirement_fails_closed() -> None:
    conflicting = verification_requirement(
        "method-input-review",
        description="Conflicting evidence description.",
    )
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        TrustedExecutionEvidence(
            verification_requirements=(conflicting,)
        ),
        input_normalizers=normalizers(),
        applicability_evaluators=evaluators(),
    )
    assert report.can_execute is False
    assert any(
        value.title == "Validation output limit reached"
        for value in report.findings
    )


def test_finding_collection_is_bounded_and_reports_overflow() -> None:
    definition = CalculationMethodDefinition(
        method_id="test.empty",
        method_version="1.0.0",
        calculation_type="validation.empty",
        title="Empty method",
        description="Method fixture with no declared request values.",
        implementation_owner="Engineer4Me test engineering",
        lifecycle_status=MethodLifecycleStatus.DRAFT,
        engine_compatibility=EngineCompatibility(
            minimum_version="0.4.0",
            maximum_exclusive_version="1.0.0",
        ),
        required_reviewer_competency="Competent calculation reviewer",
        disclaimer="Preliminary engineering decision support only.",
    )
    inputs = tuple(
        CalculationInput(
            input_id=f"unknown.input.{index:03d}",
            name=f"Unknown input {index:03d}",
            origin=InputOrigin.USER_SUPPLIED,
            categorical_value=f"value-{index:03d}",
        )
        for index in range(MAX_INPUTS)
    )
    options = tuple(
        CalculationOption(
            option_id=f"unknown.option.{index:03d}",
            value=index,
        )
        for index in range(MAX_OPTIONS)
    )
    request = CalculationRequest(
        calculation_type=definition.calculation_type,
        method_id=definition.method_id,
        method_version=definition.method_version,
        requested_at=NOW,
        inputs=inputs,
        options=options,
    )
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        request,
        definition,
    )
    # One global finding slot remains available for the mandatory safety
    # boundary that follows validation.
    assert len(report.findings) == MAX_FINDINGS - 1
    assert report.findings[-1].title == "Validation output limit reached"
    assert report.can_execute is False


def test_hook_bindings_are_not_retained_or_exposed() -> None:
    normalizer_bindings = {"flow": normalize_reference_flow}
    evaluator_bindings = {
        "length-mode-applicability": applicability_accept
    }
    report = DEFAULT_CALCULATION_VALIDATION_ENGINE.validate(
        make_request(),
        make_definition(),
        input_normalizers=normalizer_bindings,
        applicability_evaluators=evaluator_bindings,
    )
    normalizer_bindings.clear()
    evaluator_bindings.clear()
    assert report.can_execute is True
    assert "normalizer" not in report.model_dump_json()
    assert "evaluator" not in report.model_dump_json()


def test_validation_module_has_no_dynamic_or_private_execution_path() -> None:
    import app.engineering.calculations.validation as validation_module

    source = inspect.getsource(validation_module)
    prohibited = (
        "eval(",
        "exec(",
        "importlib",
        "subprocess",
        "os.system",
        "._convert_quantity",
        "._validate_quantity",
    )
    assert all(value not in source for value in prohibited)


def test_default_engine_is_stateless() -> None:
    assert (
        DEFAULT_CALCULATION_VALIDATION_ENGINE
        is DEFAULT_VALIDATION_ENGINE
    )
    assert DEFAULT_CALCULATION_VALIDATION_ENGINE.__slots__ == ()
    with pytest.raises(AttributeError):
        setattr(
            DEFAULT_CALCULATION_VALIDATION_ENGINE,
            "state",
            {},
        )
