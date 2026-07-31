"""Tests for the immutable Phase 7 calculation-method allow list."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from datetime import UTC
from datetime import datetime
from functools import partial
from inspect import Parameter as InspectParameter
from inspect import Signature
from pathlib import Path
from types import FunctionType
from types import MappingProxyType

import pytest
from pydantic import ValidationError

import app.engineering.calculations.registry as registry_module
from app.engineering.calculations.method_models import ApplicabilityRule
from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
)
from app.engineering.calculations.method_models import EngineCompatibility
from app.engineering.calculations.method_models import FormulaMetadata
from app.engineering.calculations.method_models import (
    InputNormalizationMode,
)
from app.engineering.calculations.method_models import InputPresence
from app.engineering.calculations.method_models import InputValueType
from app.engineering.calculations.method_models import (
    MethodInputSpecification,
)
from app.engineering.calculations.method_models import MethodReviewRecord
from app.engineering.calculations.method_models import MethodReviewType
from app.engineering.calculations.models import CalculationReference
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.models import ReferenceType
from app.engineering.calculations.registry import (
    CalculationMethodRegistry,
)
from app.engineering.calculations.registry import DEFAULT_METHOD_REGISTRY
from app.engineering.calculations.registry import (
    DuplicateMethodRegistrationError,
)
from app.engineering.calculations.registry import InvalidMethodLookupError
from app.engineering.calculations.registry import (
    InvalidMethodRegistrationError,
)
from app.engineering.calculations.registry import (
    MethodCalculationTypeError,
)
from app.engineering.calculations.registry import (
    MethodEngineCompatibilityError,
)
from app.engineering.calculations.registry import (
    MethodExecutionNotAllowedError,
)
from app.engineering.calculations.registry import MethodRegistration
from app.engineering.calculations.registry import MethodRegistryError
from app.engineering.calculations.registry import UnknownMethodError
from app.engineering.calculations.registry import UnknownMethodVersionError
from app.engineering.calculations.units import QuantityKind


REVIEWED_AT = datetime(2025, 1, 15, 12, 0, tzinfo=UTC)


def approved_handler_one(
    context: object,
    iteration_controller: object,
) -> object:
    """Return an inert fixture outcome."""

    return context


def approved_handler_two(
    context: object,
    iteration_controller: object,
) -> object:
    """Return a second inert fixture outcome."""

    return context


def approved_handler_three(
    context: object,
    iteration_controller: object,
) -> object:
    """Return a third inert fixture outcome."""

    return context


def approved_handler_four(
    context: object,
    iteration_controller: object,
) -> object:
    """Return a fourth inert fixture outcome."""

    return context


def approved_handler_five(
    context: object,
    iteration_controller: object,
) -> object:
    """Return a fifth inert fixture outcome."""

    return context


def approved_handler_six(
    context: object,
    iteration_controller: object,
) -> object:
    """Return a sixth inert fixture outcome."""

    return context


async def asynchronous_handler(
    context: object,
    iteration_controller: object,
) -> object:
    """Return an unregistrable coroutine fixture."""

    return context


def generator_handler(
    context: object,
    iteration_controller: object,
):
    """Yield an unregistrable generator fixture."""

    yield context


async def asynchronous_generator_handler(
    context: object,
    iteration_controller: object,
):
    """Yield an unregistrable asynchronous-generator fixture."""

    yield context


def one_parameter_handler(context: object) -> object:
    """Use an invalid one-parameter executor signature."""

    return context


def default_parameter_handler(
    context: object,
    iteration_controller: object | None = None,
) -> object:
    """Use an invalid optional executor parameter."""

    return context


def variadic_handler(*values: object) -> object:
    """Use an invalid variadic executor signature."""

    return values


def keyword_variadic_handler(**values: object) -> object:
    """Use an invalid keyword-variadic executor signature."""

    return values


def keyword_only_handler(
    context: object,
    *,
    iteration_controller: object,
) -> object:
    """Use an invalid keyword-only executor parameter."""

    return context


def three_parameter_handler(
    context: object,
    iteration_controller: object,
    extra: object,
) -> object:
    """Use an invalid three-parameter executor signature."""

    return context


def wrong_parameter_names(
    first: object,
    second: object,
) -> object:
    """Use the right arity with an ambiguous executor contract."""

    return first


def spoofed_signature_handler(context: object) -> object:
    """Use a forged two-parameter inspection signature."""

    return context


spoofed_signature_handler.__signature__ = Signature(  # type: ignore[attr-defined]
    (
        InspectParameter(
            "context",
            InspectParameter.POSITIONAL_OR_KEYWORD,
        ),
        InspectParameter(
            "iteration_controller",
            InspectParameter.POSITIONAL_OR_KEYWORD,
        ),
    )
)


def wrapped_marker_handler(
    context: object,
    iteration_controller: object,
) -> object:
    """Use a forged wrapped-function marker."""

    return context


wrapped_marker_handler.__wrapped__ = (  # type: ignore[attr-defined]
    approved_handler_one
)


def normalize_length(
    specification: object,
    supplied_input: object,
) -> object:
    """Return an inert method-specific normalized fixture value."""

    return supplied_input


def evaluate_length_rule(
    rule: object,
    linked_inputs: object,
) -> object:
    """Return an inert applicability fixture value."""

    return linked_inputs


def evaluate_length_rule_two(
    rule: object,
    linked_inputs: object,
) -> object:
    """Return a second inert applicability fixture value."""

    return linked_inputs


def evaluate_safety(context: object) -> object:
    """Return an inert safety fixture value."""

    return context


BOMB_CALL_COUNT = 0


def bomb_handler(
    context: object,
    iteration_controller: object,
) -> object:
    """Fail if registry metadata operations invoke executable code."""

    global BOMB_CALL_COUNT
    BOMB_CALL_COUNT += 1
    raise AssertionError("The registry invoked executable code.")


class CallableObject:
    """Callable objects are not direct reviewed functions."""

    def __call__(self, context: object) -> object:
        return context


class HandlerOwner:
    """Methods are not direct module-level reviewed functions."""

    def handler(self, context: object) -> object:
        return context


def make_closure() -> object:
    """Build an unregistrable closure fixture."""

    captured_value = "captured"

    def closure(
        context: object,
        iteration_controller: object,
    ) -> object:
        return (context, iteration_controller, captured_value)

    return closure


def verified_reference(
    reference_id: str,
    reference_type: ReferenceType,
) -> CalculationReference:
    """Build a compact verified method reference."""

    return CalculationReference(
        reference_id=reference_id,
        reference_type=reference_type,
        title=f"Reference {reference_id}",
        verified=True,
        verified_by="Registry test reviewer",
        verified_at=REVIEWED_AT,
    )


def reviewed_records() -> tuple[MethodReviewRecord, ...]:
    """Build all independent review records required for approval."""

    return tuple(
        MethodReviewRecord(
            review_id=f"review.{review_type.value}",
            review_type=review_type,
            approved=True,
            reviewer="Registry test reviewer",
            reviewer_competency="Qualified test engineer",
            reviewed_at=REVIEWED_AT,
            evidence_reference_ids=("fixture.source",),
        )
        for review_type in MethodReviewType
    )


def approved_definition(
    *,
    method_id: str = "fixture.method",
    method_version: str = "1.0.0",
    calculation_type: str = "fixture.calculation",
    lifecycle_status: MethodLifecycleStatus = (
        MethodLifecycleStatus.APPROVED
    ),
) -> CalculationMethodDefinition:
    """Build complete approved metadata with no production formula."""

    return CalculationMethodDefinition(
        method_id=method_id,
        method_version=method_version,
        calculation_type=calculation_type,
        title="Registry fixture method",
        description="Inert metadata used only for registry tests.",
        implementation_owner="Engineer4Me test engineering",
        lifecycle_status=lifecycle_status,
        superseded_by_version=(
            "2.0.0"
            if lifecycle_status is MethodLifecycleStatus.SUPERSEDED
            else None
        ),
        disabled_reason=(
            "Disabled registry-test fixture."
            if lifecycle_status is MethodLifecycleStatus.DISABLED
            else None
        ),
        engine_compatibility=EngineCompatibility(
            minimum_version="0.4.0",
            maximum_exclusive_version="1.0.0",
        ),
        input_specifications=(
            MethodInputSpecification(
                input_id="length",
                name="Length",
                description="Controlled length input.",
                presence=InputPresence.REQUIRED,
                value_type=InputValueType.QUANTITY,
                normalization_mode=(
                    InputNormalizationMode.UNIT_REGISTRY
                ),
                quantity_kind=QuantityKind.LENGTH,
                canonical_unit="m",
            ),
        ),
        formulas=(
            FormulaMetadata(
                formula_identifier="fixture.formula",
                title="Fixture formula identifier",
                description=(
                    "Metadata only; this contains no executable expression."
                ),
                reference_ids=("fixture.source",),
            ),
        ),
        references=(
            verified_reference(
                "fixture.source",
                ReferenceType.ENGINEERING_TEXTBOOK,
            ),
            verified_reference(
                "fixture.vector",
                ReferenceType.TEST_VECTOR,
            ),
        ),
        reviews=reviewed_records(),
        test_vector_reference_ids=("fixture.vector",),
        limitations=("Fixture metadata is not an engineering method.",),
        exclusions=("Production calculation use is excluded.",),
        required_reviewer_competency="Qualified test engineer",
        disclaimer="Test fixture for decision-support infrastructure only.",
    )


BASE_DEFINITION = approved_definition()


def registration(
    definition: CalculationMethodDefinition = BASE_DEFINITION,
    implementation=approved_handler_one,
    *,
    input_normalizers=None,
    applicability_evaluators=None,
    safety_evaluator=None,
) -> MethodRegistration:
    """Build one explicit allow-list registration."""

    return MethodRegistration(
        definition=definition,
        implementation=implementation,
        input_normalizers=(
            {} if input_normalizers is None else input_normalizers
        ),
        applicability_evaluators=(
            {}
            if applicability_evaluators is None
            else applicability_evaluators
        ),
        safety_evaluator=safety_evaluator,
    )


def test_default_registry_is_empty_and_immutable() -> None:
    assert DEFAULT_METHOD_REGISTRY.definitions == ()
    assert DEFAULT_METHOD_REGISTRY.method_ids == ()
    assert DEFAULT_METHOD_REGISTRY.discover() == ()

    with pytest.raises(AttributeError):
        DEFAULT_METHOD_REGISTRY._definitions = (BASE_DEFINITION,)

    for attribute_name in CalculationMethodRegistry.__slots__:
        with pytest.raises(AttributeError):
            DEFAULT_METHOD_REGISTRY.__delattr__(attribute_name)


def test_empty_registry_reports_typed_unknown_method_errors() -> None:
    with pytest.raises(UnknownMethodError) as resolve_error:
        DEFAULT_METHOD_REGISTRY.resolve(
            "fixture.unknown",
            "1.0.0",
        )

    with pytest.raises(UnknownMethodError):
        DEFAULT_METHOD_REGISTRY.available_versions("fixture.unknown")

    assert resolve_error.value.code == "unknown_method"
    assert resolve_error.value.method_id == "fixture.unknown"


def test_registration_revalidates_and_copies_definition() -> None:
    source = approved_definition()
    registered = registration(source)

    assert registered.definition == source
    assert registered.definition is not source


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("method_id", ""),
        ("method_id", "x"),
        ("method_id", "bad identifier"),
        ("method_version", "1.0"),
        ("method_version", "01.0.0"),
        ("calculation_type", ""),
    ),
)
def test_registration_revalidates_model_construct_bypasses(
    field_name: str,
    invalid_value: str,
) -> None:
    payload = BASE_DEFINITION.model_dump(
        mode="python",
        round_trip=True,
    )
    payload[field_name] = invalid_value
    malformed = CalculationMethodDefinition.model_construct(**payload)

    with pytest.raises(
        InvalidMethodRegistrationError,
        match="definition is invalid",
    ):
        registration(malformed)


def test_registration_revalidates_nested_model_construct_bypass() -> None:
    malformed_compatibility = EngineCompatibility.model_construct(
        minimum_version="1.0.0",
        maximum_exclusive_version="0.4.0",
    )
    payload = BASE_DEFINITION.model_dump(
        mode="python",
        round_trip=True,
    )
    payload["engine_compatibility"] = malformed_compatibility
    malformed = CalculationMethodDefinition.model_construct(**payload)

    with pytest.raises(InvalidMethodRegistrationError):
        registration(malformed)


def test_registry_revalidates_a_bypass_constructed_registration() -> None:
    payload = BASE_DEFINITION.model_dump(
        mode="python",
        round_trip=True,
    )
    payload["method_version"] = "1.0"
    malformed_definition = CalculationMethodDefinition.model_construct(
        **payload
    )
    bypassed = object.__new__(MethodRegistration)
    object.__setattr__(bypassed, "definition", malformed_definition)
    object.__setattr__(
        bypassed,
        "implementation",
        approved_handler_one,
    )
    object.__setattr__(bypassed, "input_normalizers", {})
    object.__setattr__(bypassed, "applicability_evaluators", {})
    object.__setattr__(bypassed, "safety_evaluator", None)

    with pytest.raises(InvalidMethodRegistrationError):
        CalculationMethodRegistry((bypassed,))


def test_registry_resolves_only_the_exact_identity() -> None:
    method_registry = CalculationMethodRegistry((registration(),))

    resolved = method_registry.resolve(
        "fixture.method",
        "1.0.0",
    )

    assert resolved is method_registry.definitions[0]
    assert resolved == BASE_DEFINITION


def test_lookup_strips_only_surrounding_whitespace() -> None:
    method_registry = CalculationMethodRegistry((registration(),))

    assert method_registry.resolve(
        "  fixture.method  ",
        "  1.0.0  ",
    ) == BASE_DEFINITION

    with pytest.raises(InvalidMethodLookupError):
        method_registry.resolve("fixture. method", "1.0.0")


@pytest.mark.parametrize(
    "unsupported_version",
    (
        "0.9.9",
        "1.0.1",
        "1.1.0",
        "2.0.0",
        "999.999.999",
        "1.0.0-preview",
    ),
)
def test_registry_never_falls_back_to_another_version(
    unsupported_version: str,
) -> None:
    method_registry = CalculationMethodRegistry((registration(),))

    with pytest.raises(UnknownMethodVersionError) as error:
        method_registry.resolve(
            "fixture.method",
            unsupported_version,
        )

    assert error.value.code == "unknown_method_version"
    assert error.value.method_id == "fixture.method"
    assert error.value.method_version == unsupported_version


@pytest.mark.parametrize(
    "method_id",
    ("Fixture.method", "fixture.Method", "FIXTURE.METHOD"),
)
def test_method_identifiers_are_exact_and_case_sensitive(
    method_id: str,
) -> None:
    method_registry = CalculationMethodRegistry((registration(),))

    with pytest.raises(UnknownMethodError):
        method_registry.resolve(method_id, "1.0.0")


def test_method_versions_and_calculation_types_are_case_sensitive() -> None:
    definition = approved_definition(method_version="1.0.0-rc1")
    method_registry = CalculationMethodRegistry(
        (registration(definition),)
    )

    assert method_registry.resolve(
        "fixture.method",
        "1.0.0-rc1",
        calculation_type="fixture.calculation",
    ) == definition

    with pytest.raises(UnknownMethodVersionError):
        method_registry.resolve(
            "fixture.method",
            "1.0.0-RC1",
        )

    with pytest.raises(MethodCalculationTypeError):
        method_registry.resolve(
            "fixture.method",
            "1.0.0-rc1",
            calculation_type="Fixture.calculation",
        )


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("method_id", None),
        ("method_id", True),
        ("method_id", 1),
        ("method_id", ""),
        ("method_id", " "),
        ("method_id", "x"),
        ("method_id", "bad value"),
        ("method_id", "x" * 101),
        ("method_version", None),
        ("method_version", True),
        ("method_version", 1),
        ("method_version", ""),
        ("method_version", "1"),
        ("method_version", "1.0"),
        ("method_version", "01.0.0"),
        ("method_version", "1.00.0"),
        ("method_version", "1.0.00"),
        ("method_version", "v1.0.0"),
        ("method_version", "1.0.0-01"),
        ("method_version", "1.0.0-alpha..1"),
        ("method_version", "1.0.0-alpha."),
        ("method_version", "1.0.0+build..1"),
        ("method_version", "1.0.0+build."),
        ("method_version", "1.0.0-" + ("x" * 100)),
    ),
)
def test_invalid_lookup_components_have_stable_typed_errors(
    field_name: str,
    invalid_value: object,
) -> None:
    method_registry = CalculationMethodRegistry((registration(),))
    method_id: object = "fixture.method"
    method_version: object = "1.0.0"

    if field_name == "method_id":
        method_id = invalid_value
    else:
        method_version = invalid_value

    with pytest.raises(InvalidMethodLookupError) as error:
        method_registry.resolve(
            method_id,  # type: ignore[arg-type]
            method_version,  # type: ignore[arg-type]
        )

    assert error.value.code == "invalid_method_lookup"
    expected_message = (
        f"{field_name} is not a valid controlled identifier."
        if isinstance(invalid_value, str)
        else f"{field_name} must be a string."
    )
    assert str(error.value) == expected_message


def test_calculation_type_can_be_verified_during_exact_resolution() -> None:
    method_registry = CalculationMethodRegistry((registration(),))

    assert method_registry.resolve(
        "fixture.method",
        "1.0.0",
        calculation_type="fixture.calculation",
    ) == BASE_DEFINITION

    with pytest.raises(MethodCalculationTypeError) as error:
        method_registry.resolve(
            "fixture.method",
            "1.0.0",
            calculation_type="fixture.other",
        )

    assert error.value.code == "method_calculation_type_mismatch"
    assert error.value.method_id == "fixture.method"
    assert error.value.method_version == "1.0.0"
    assert error.value.calculation_type == "fixture.other"
    assert "fixture.other" not in str(error.value)


def test_unknown_identity_precedes_calculation_type_mismatch() -> None:
    method_registry = CalculationMethodRegistry((registration(),))

    with pytest.raises(UnknownMethodError):
        method_registry.resolve(
            "fixture.unknown",
            "1.0.0",
            calculation_type="fixture.other",
        )

    with pytest.raises(UnknownMethodVersionError):
        method_registry.resolve(
            "fixture.method",
            "2.0.0",
            calculation_type="fixture.other",
        )


def test_invalid_calculation_type_uses_lookup_error() -> None:
    method_registry = CalculationMethodRegistry((registration(),))

    with pytest.raises(InvalidMethodLookupError):
        method_registry.resolve(
            "fixture.method",
            "1.0.0",
            calculation_type="not a controlled type",
        )


def test_available_versions_does_not_select_a_version() -> None:
    definitions = (
        approved_definition(method_version="2.0.0"),
        approved_definition(method_version="1.10.0"),
        approved_definition(method_version="1.2.0"),
    )
    method_registry = CalculationMethodRegistry(
        (
            registration(definitions[0], approved_handler_one),
            registration(definitions[1], approved_handler_two),
            registration(definitions[2], approved_handler_three),
        )
    )

    versions = method_registry.available_versions("fixture.method")

    assert versions == tuple(sorted(("2.0.0", "1.10.0", "1.2.0")))
    assert isinstance(versions, tuple)


def test_discovery_returns_only_deterministically_sorted_metadata() -> None:
    beta = approved_definition(
        method_id="fixture.beta",
        calculation_type="fixture.beta_calculation",
    )
    alpha_v2 = approved_definition(
        method_id="fixture.alpha",
        method_version="2.0.0",
        calculation_type="fixture.alpha_calculation",
    )
    alpha_v1 = approved_definition(
        method_id="fixture.alpha",
        method_version="1.0.0",
        calculation_type="fixture.alpha_calculation",
    )
    method_registry = CalculationMethodRegistry(
        (
            registration(beta, approved_handler_one),
            registration(alpha_v2, approved_handler_two),
            registration(alpha_v1, approved_handler_three),
        )
    )

    discovered = method_registry.discover()

    assert tuple(
        (value.method_id, value.method_version)
        for value in discovered
    ) == (
        ("fixture.alpha", "1.0.0"),
        ("fixture.alpha", "2.0.0"),
        ("fixture.beta", "1.0.0"),
    )
    assert method_registry.method_ids == (
        "fixture.alpha",
        "fixture.beta",
    )
    assert all(
        isinstance(value, CalculationMethodDefinition)
        for value in discovered
    )
    assert not any(
        isinstance(value, MethodRegistration)
        for value in discovered
    )


def test_discovery_filter_returns_metadata_or_an_empty_tuple() -> None:
    alpha = approved_definition(
        method_id="fixture.alpha",
        calculation_type="fixture.alpha_calculation",
    )
    beta = approved_definition(
        method_id="fixture.beta",
        calculation_type="fixture.beta_calculation",
    )
    method_registry = CalculationMethodRegistry(
        (
            registration(alpha, approved_handler_one),
            registration(beta, approved_handler_two),
        )
    )

    assert method_registry.discover(
        calculation_type="fixture.alpha_calculation"
    ) == (method_registry.resolve("fixture.alpha", "1.0.0"),)
    assert method_registry.discover(
        calculation_type="fixture.unknown_calculation"
    ) == ()


def test_discovery_serialization_contains_no_callable_identity() -> None:
    method_registry = CalculationMethodRegistry((registration(),))
    serialized = method_registry.discover()[0].model_dump_json()

    assert "approved_handler_one" not in serialized
    assert "test_calculation_registry" not in serialized
    assert "input_normalizers" not in serialized
    assert "applicability_evaluators" not in serialized
    assert "safety_evaluator" not in serialized


def test_constructor_order_does_not_change_discovery() -> None:
    first = registration(
        approved_definition(method_id="fixture.alpha"),
        approved_handler_one,
    )
    second = registration(
        approved_definition(method_id="fixture.beta"),
        approved_handler_two,
    )

    forward = CalculationMethodRegistry((first, second))
    reverse = CalculationMethodRegistry((second, first))

    assert forward.definitions == reverse.definitions
    assert forward.method_ids == reverse.method_ids


def test_registry_rejects_duplicate_exact_identity() -> None:
    with pytest.raises(
        DuplicateMethodRegistrationError,
        match="Duplicate or case-conflicting",
    ):
        CalculationMethodRegistry(
            (
                registration(BASE_DEFINITION, approved_handler_one),
                registration(BASE_DEFINITION, approved_handler_two),
            )
        )


@pytest.mark.parametrize(
    ("method_id", "method_version"),
    (
        ("FIXTURE.METHOD", "1.0.0"),
        ("Fixture.Method", "1.0.0"),
        ("fixture.method", "1.0.0-RC1"),
    ),
)
def test_registry_rejects_case_conflicting_identity(
    method_id: str,
    method_version: str,
) -> None:
    original = approved_definition(
        method_version=(
            "1.0.0-rc1"
            if method_version.endswith("RC1")
            else "1.0.0"
        )
    )
    conflicting = approved_definition(
        method_id=method_id,
        method_version=method_version,
    )

    with pytest.raises(DuplicateMethodRegistrationError):
        CalculationMethodRegistry(
            (
                registration(original, approved_handler_one),
                registration(conflicting, approved_handler_two),
            )
        )


def test_registry_rejects_calculation_type_drift_across_versions() -> None:
    first = approved_definition(
        method_version="1.0.0",
        calculation_type="fixture.original",
    )
    second = approved_definition(
        method_version="2.0.0",
        calculation_type="fixture.changed",
    )

    with pytest.raises(
        InvalidMethodRegistrationError,
        match="same calculation type",
    ):
        CalculationMethodRegistry(
            (
                registration(first, approved_handler_one),
                registration(second, approved_handler_two),
            )
        )


def test_registry_allows_explicit_executor_reuse_across_versions() -> None:
    first = approved_definition(method_version="1.0.0")
    second = approved_definition(method_version="2.0.0")
    method_registry = CalculationMethodRegistry(
        (
            registration(first, approved_handler_one),
            registration(second, approved_handler_one),
        )
    )

    assert method_registry.resolve_for_execution(
        "fixture.method",
        "1.0.0",
        engine_version="0.4.0",
    ).implementation is approved_handler_one
    assert method_registry.resolve_for_execution(
        "fixture.method",
        "2.0.0",
        engine_version="0.4.0",
    ).implementation is approved_handler_one


@pytest.mark.parametrize(
    "candidate",
    (
        None,
        object(),
        "app.methods:execute",
        "app.methods.execute",
        123,
        len,
        CallableObject(),
        HandlerOwner().handler,
        partial(approved_handler_one),
        lambda value: value,
        asynchronous_handler,
        generator_handler,
        asynchronous_generator_handler,
    ),
    ids=(
        "none",
        "object",
        "module-colon-path",
        "module-dot-path",
        "integer",
        "builtin",
        "callable-object",
        "bound-method",
        "partial",
        "lambda",
        "coroutine-function",
        "generator-function",
        "async-generator-function",
    ),
)
def test_registration_rejects_non_direct_implementations(
    candidate: object,
) -> None:
    with pytest.raises(InvalidMethodRegistrationError):
        registration(
            implementation=candidate,  # type: ignore[arg-type]
        )


def test_registration_rejects_nested_closures() -> None:
    with pytest.raises(
        InvalidMethodRegistrationError,
        match="Nested functions, closures, and methods",
    ):
        registration(
            implementation=make_closure(),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "candidate",
    (
        one_parameter_handler,
        default_parameter_handler,
        variadic_handler,
        keyword_variadic_handler,
        keyword_only_handler,
        three_parameter_handler,
        wrong_parameter_names,
        spoofed_signature_handler,
        wrapped_marker_handler,
    ),
)
def test_registration_rejects_ambiguous_executor_signatures(
    candidate: object,
) -> None:
    with pytest.raises(InvalidMethodRegistrationError):
        registration(
            implementation=candidate,  # type: ignore[arg-type]
        )


def test_registration_rejects_dynamically_compiled_filename() -> None:
    dynamic_handler = FunctionType(
        approved_handler_one.__code__.replace(co_filename="<string>"),
        globals(),
        "dynamic_handler",
    )
    dynamic_handler.__qualname__ = "dynamic_handler"

    with pytest.raises(
        InvalidMethodRegistrationError,
        match="Dynamically compiled",
    ):
        registration(implementation=dynamic_handler)


def test_registration_rejects_function_not_bound_in_module() -> None:
    detached_handler = FunctionType(
        approved_handler_one.__code__,
        globals(),
        "detached_handler",
    )
    detached_handler.__qualname__ = "detached_handler"

    with pytest.raises(
        InvalidMethodRegistrationError,
        match="bound directly",
    ):
        registration(implementation=detached_handler)


def test_registration_requires_definition_instance() -> None:
    with pytest.raises(
        InvalidMethodRegistrationError,
        match="CalculationMethodDefinition",
    ):
        MethodRegistration(
            definition=BASE_DEFINITION.model_dump(),  # type: ignore[arg-type]
            implementation=approved_handler_one,
        )


@pytest.mark.parametrize(
    "candidate",
    (
        None,
        BASE_DEFINITION,
        (BASE_DEFINITION, approved_handler_one),
        "fixture.method",
    ),
)
def test_registry_requires_explicit_registration_objects(
    candidate: object,
) -> None:
    with pytest.raises(InvalidMethodRegistrationError):
        CalculationMethodRegistry(
            (candidate,)  # type: ignore[arg-type]
        )


def test_registration_has_stable_implementation_identity() -> None:
    registered = registration()

    assert registered.implementation_id == (
        f"{__name__}:approved_handler_one"
    )
    assert "0x" not in registered.implementation_id


@pytest.mark.parametrize(
    "lifecycle_status",
    tuple(MethodLifecycleStatus),
    ids=lambda status: status.value,
)
def test_lifecycle_is_discoverable_but_only_approved_can_resolve_execution(
    lifecycle_status: MethodLifecycleStatus,
) -> None:
    definition = approved_definition(
        lifecycle_status=lifecycle_status,
    )
    method_registry = CalculationMethodRegistry(
        (registration(definition),)
    )

    assert method_registry.resolve(
        definition.method_id,
        definition.method_version,
    ).lifecycle_status is lifecycle_status
    expected_eligibility = (
        lifecycle_status is MethodLifecycleStatus.APPROVED
    )
    assert method_registry.is_execution_eligible(
        definition.method_id,
        definition.method_version,
        engine_version="0.4.0",
    ) is expected_eligibility

    if expected_eligibility:
        resolved_registration = method_registry.resolve_for_execution(
            definition.method_id,
            definition.method_version,
            engine_version="0.4.0",
        )
        assert resolved_registration.implementation is approved_handler_one
    else:
        with pytest.raises(
            MethodExecutionNotAllowedError,
        ) as error:
            method_registry.resolve_for_execution(
                definition.method_id,
                definition.method_version,
                engine_version="0.4.0",
            )

        assert error.value.code == "method_execution_not_allowed"
        assert error.value.lifecycle_status is lifecycle_status


@pytest.mark.parametrize(
    ("engine_version", "expected"),
    (
        ("0.3.999", False),
        ("0.4.0", True),
        ("0.4.1", True),
        ("0.99.999", True),
        ("1.0.0", False),
        ("2.0.0", False),
    ),
)
def test_execution_eligibility_checks_compatibility_boundaries(
    engine_version: str,
    expected: bool,
) -> None:
    method_registry = CalculationMethodRegistry((registration(),))

    assert method_registry.is_execution_eligible(
        "fixture.method",
        "1.0.0",
        engine_version=engine_version,
    ) is expected

    if expected:
        assert method_registry.resolve_for_execution(
            "fixture.method",
            "1.0.0",
            engine_version=engine_version,
        ).implementation is approved_handler_one
    else:
        with pytest.raises(MethodEngineCompatibilityError) as error:
            method_registry.resolve_for_execution(
                "fixture.method",
                "1.0.0",
                engine_version=engine_version,
            )

        assert error.value.code == "method_engine_incompatible"
        assert error.value.engine_version == engine_version


def test_execution_resolution_requires_explicit_engine_version() -> None:
    method_registry = CalculationMethodRegistry((registration(),))

    with pytest.raises(TypeError):
        method_registry.is_execution_eligible(  # type: ignore[call-arg]
            "fixture.method",
            "1.0.0",
        )

    with pytest.raises(TypeError):
        method_registry.resolve_for_execution(  # type: ignore[call-arg]
            "fixture.method",
            "1.0.0",
        )


@pytest.mark.parametrize(
    "engine_version",
    (
        None,
        True,
        4,
        "",
        "0.4",
        "v0.4.0",
        "01.0.0",
        "1.0.0-rc1",
        "1.0.0+build",
        "1.0.0-" + ("x" * 100),
    ),
)
def test_invalid_explicit_engine_versions_use_typed_lookup_error(
    engine_version: object,
) -> None:
    if engine_version is None:
        engine_version = "contains confidential text"

    method_registry = CalculationMethodRegistry((registration(),))

    with pytest.raises(InvalidMethodLookupError) as error:
        method_registry.is_execution_eligible(
            "fixture.method",
            "1.0.0",
            engine_version=engine_version,  # type: ignore[arg-type]
        )

    expected_message = (
        "engine_version is not a valid controlled identifier."
        if isinstance(engine_version, str)
        else "engine_version must be a string."
    )
    assert str(error.value) == expected_message


def test_registry_never_invokes_handler_during_any_metadata_operation() -> None:
    global BOMB_CALL_COUNT
    BOMB_CALL_COUNT = 0
    method_registry = CalculationMethodRegistry(
        (registration(implementation=bomb_handler),)
    )

    assert method_registry.resolve(
        "fixture.method",
        "1.0.0",
    ) == BASE_DEFINITION
    assert method_registry.discover() == method_registry.definitions
    assert method_registry.available_versions(
        "fixture.method"
    ) == ("1.0.0",)
    assert method_registry.is_execution_eligible(
        "fixture.method",
        "1.0.0",
        engine_version="0.4.0",
    )
    assert method_registry.resolve_for_execution(
        "fixture.method",
        "1.0.0",
        engine_version="0.4.0",
    ).implementation is bomb_handler
    assert BOMB_CALL_COUNT == 0


def method_specific_definition() -> CalculationMethodDefinition:
    """Return a definition requiring trusted normalization and rule hooks."""

    method_specific_input = MethodInputSpecification(
        input_id="method_length",
        name="Method length",
        description="Length normalized by reviewed method code.",
        presence=InputPresence.REQUIRED,
        value_type=InputValueType.QUANTITY,
        normalization_mode=InputNormalizationMode.METHOD_SPECIFIC,
        quantity_kind=QuantityKind.LENGTH,
        canonical_unit="m",
    )
    rule = ApplicabilityRule(
        rule_id="length.applicability",
        title="Length applicability",
        description="Reviewed applicability rule metadata.",
        input_ids=("method_length",),
        severity=FindingSeverity.CAUTION,
        blocking=False,
    )
    payload = BASE_DEFINITION.model_dump(
        mode="python",
        round_trip=True,
    )
    payload["input_specifications"] = (method_specific_input,)
    payload["applicability_rules"] = (rule,)
    return CalculationMethodDefinition.model_validate(payload)


def test_trusted_hook_maps_are_exact_immutable_and_execution_only() -> None:
    definition = method_specific_definition()
    registered = registration(
        definition,
        input_normalizers={"METHOD_LENGTH": normalize_length},
        applicability_evaluators={
            "LENGTH.APPLICABILITY": evaluate_length_rule,
        },
        safety_evaluator=evaluate_safety,
    )
    method_registry = CalculationMethodRegistry((registered,))

    assert isinstance(registered.input_normalizers, MappingProxyType)
    assert isinstance(
        registered.applicability_evaluators,
        MappingProxyType,
    )
    assert method_registry.resolve(
        definition.method_id,
        definition.method_version,
    ) == definition
    assert "normalize_length" not in (
        method_registry.resolve(
            definition.method_id,
            definition.method_version,
        ).model_dump_json()
    )

    with pytest.raises(TypeError):
        registered.input_normalizers["method_length"] = (  # type: ignore[index]
            approved_handler_two
        )

    execution_registration = method_registry.resolve_for_execution(
        definition.method_id,
        definition.method_version,
        engine_version="0.4.0",
    )
    assert execution_registration.input_normalizers == {
        "method_length": normalize_length,
    }
    assert execution_registration.applicability_evaluators == {
        "length.applicability": evaluate_length_rule,
    }
    assert execution_registration.safety_evaluator is evaluate_safety


def test_hook_maps_are_snapshotted_before_registry_construction() -> None:
    definition = method_specific_definition()
    source_normalizers = {
        "method_length": normalize_length,
    }
    source_evaluators = {
        "length.applicability": evaluate_length_rule,
    }
    registered = registration(
        definition,
        input_normalizers=source_normalizers,
        applicability_evaluators=source_evaluators,
    )

    source_normalizers.clear()
    source_evaluators.clear()

    assert registered.input_normalizers == {
        "method_length": normalize_length,
    }
    assert registered.applicability_evaluators == {
        "length.applicability": evaluate_length_rule,
    }
    assert CalculationMethodRegistry(
        (registered,)
    ).resolve_for_execution(
        definition.method_id,
        definition.method_version,
        engine_version="0.4.0",
    ).input_normalizers == {
        "method_length": normalize_length,
    }


@pytest.mark.parametrize(
    ("input_normalizers", "applicability_evaluators"),
    (
        ({}, {"length.applicability": evaluate_length_rule}),
        (
            {"unknown": normalize_length},
            {"length.applicability": evaluate_length_rule},
        ),
        ({"method_length": normalize_length}, {}),
        (
            {"method_length": normalize_length},
            {"unknown": evaluate_length_rule},
        ),
        (
            {
                "method_length": normalize_length,
                "METHOD_LENGTH": approved_handler_two,
            },
            {"length.applicability": evaluate_length_rule},
        ),
    ),
)
def test_trusted_hook_maps_must_exactly_cover_metadata(
    input_normalizers: object,
    applicability_evaluators: object,
) -> None:
    with pytest.raises(InvalidMethodRegistrationError):
        registration(
            method_specific_definition(),
            input_normalizers=input_normalizers,
            applicability_evaluators=applicability_evaluators,
        )


@pytest.mark.parametrize(
    "invalid_hook",
    (
        "app.methods:normalize",
        CallableObject(),
        HandlerOwner().handler,
        partial(normalize_length),
        lambda value: value,
        make_closure(),
    ),
)
def test_trusted_hooks_require_direct_top_level_functions(
    invalid_hook: object,
) -> None:
    with pytest.raises(InvalidMethodRegistrationError):
        registration(
            method_specific_definition(),
            input_normalizers={
                "method_length": invalid_hook,
            },
            applicability_evaluators={
                "length.applicability": evaluate_length_rule,
            },
        )


def test_each_trusted_hook_role_enforces_its_exact_signature() -> None:
    definition = method_specific_definition()

    with pytest.raises(
        InvalidMethodRegistrationError,
        match="Method-specific normalizer must declare the exact",
    ):
        registration(
            definition,
            input_normalizers={
                "method_length": one_parameter_handler,
            },
            applicability_evaluators={
                "length.applicability": evaluate_length_rule,
            },
        )

    with pytest.raises(
        InvalidMethodRegistrationError,
        match="Applicability evaluator must declare the exact",
    ):
        registration(
            definition,
            input_normalizers={
                "method_length": normalize_length,
            },
            applicability_evaluators={
                "length.applicability": one_parameter_handler,
            },
        )

    with pytest.raises(
        InvalidMethodRegistrationError,
        match="Safety evaluator must declare the exact",
    ):
        registration(
            definition,
            input_normalizers={
                "method_length": normalize_length,
            },
            applicability_evaluators={
                "length.applicability": evaluate_length_rule,
            },
            safety_evaluator=approved_handler_three,
        )


def test_one_hook_cannot_fill_multiple_roles_in_one_registration() -> None:
    definition = method_specific_definition()
    second_input = definition.input_specifications[0].model_copy(
        update={
            "input_id": "method_width",
            "name": "Method width",
        }
    )
    definition = definition.model_copy(
        update={
            "input_specifications": (
                *definition.input_specifications,
                second_input,
            ),
        }
    )

    with pytest.raises(
        InvalidMethodRegistrationError,
        match="distinct reviewed function",
    ):
        registration(
            definition,
            input_normalizers={
                "method_length": normalize_length,
                "method_width": normalize_length,
            },
            applicability_evaluators={
                "length.applicability": evaluate_length_rule,
            },
        )


def test_hook_function_can_be_explicitly_reused_across_versions() -> None:
    first = method_specific_definition()
    second = first.model_copy(update={"method_version": "2.0.0"})
    first_registration = registration(
        first,
        approved_handler_one,
        input_normalizers={"method_length": normalize_length},
        applicability_evaluators={
            "length.applicability": evaluate_length_rule,
        },
    )
    second_registration = registration(
        second,
        approved_handler_two,
        input_normalizers={"method_length": normalize_length},
        applicability_evaluators={
            "length.applicability": evaluate_length_rule_two,
        },
    )

    method_registry = CalculationMethodRegistry(
        (first_registration, second_registration)
    )

    for method_version in ("1.0.0", "2.0.0"):
        assert method_registry.resolve_for_execution(
            "fixture.method",
            method_version,
            engine_version="0.4.0",
        ).input_normalizers["method_length"] is normalize_length


def test_registration_and_registry_are_frozen_without_instance_dicts() -> None:
    registered = registration()
    method_registry = CalculationMethodRegistry((registered,))

    assert not hasattr(registered, "__dict__")
    assert not hasattr(method_registry, "__dict__")

    with pytest.raises(FrozenInstanceError):
        registered.implementation = approved_handler_two

    with pytest.raises(FrozenInstanceError):
        registered.input_normalizers = {}

    with pytest.raises(AttributeError):
        method_registry._entries = {}

    with pytest.raises(AttributeError):
        method_registry.__delattr__("_entries")


def test_registry_internal_maps_are_read_only() -> None:
    method_registry = CalculationMethodRegistry((registration(),))

    assert isinstance(method_registry._entries, MappingProxyType)
    assert isinstance(
        method_registry._versions_by_method,
        MappingProxyType,
    )

    with pytest.raises(TypeError):
        method_registry._entries[  # type: ignore[index]
            ("fixture.other", "1.0.0")
        ] = registration()

    with pytest.raises(TypeError):
        method_registry._versions_by_method[  # type: ignore[index]
            "fixture.method"
        ] = ("2.0.0",)


def test_discovered_definition_remains_frozen_and_round_trips_json() -> None:
    method_registry = CalculationMethodRegistry((registration(),))
    definition = method_registry.discover()[0]

    with pytest.raises(ValidationError):
        definition.method_version = "2.0.0"

    restored = CalculationMethodDefinition.model_validate_json(
        definition.model_dump_json()
    )
    assert restored == definition


def test_registry_exposes_no_mutating_or_latest_version_api() -> None:
    method_registry = CalculationMethodRegistry((registration(),))

    for prohibited_name in (
        "add",
        "register",
        "remove",
        "replace",
        "unregister",
        "latest",
        "resolve_latest",
    ):
        assert not hasattr(method_registry, prohibited_name)


def test_registry_limit_is_checked_before_additional_entry_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registry_module, "MAX_REGISTERED_METHODS", 1)
    first = registration(
        approved_definition(method_id="fixture.first"),
        approved_handler_one,
    )
    second = registration(
        approved_definition(method_id="fixture.second"),
        approved_handler_two,
    )

    with pytest.raises(
        InvalidMethodRegistrationError,
        match="cannot exceed 1 entries",
    ):
        CalculationMethodRegistry((first, second))


def test_concurrent_exact_resolution_is_deterministic_and_inert() -> None:
    global BOMB_CALL_COUNT
    BOMB_CALL_COUNT = 0
    method_registry = CalculationMethodRegistry(
        (registration(implementation=bomb_handler),)
    )

    def resolve_once(_: int) -> tuple[int, int, bool]:
        definition = method_registry.resolve(
            "fixture.method",
            "1.0.0",
            calculation_type="fixture.calculation",
        )
        resolved_registration = method_registry.resolve_for_execution(
            "fixture.method",
            "1.0.0",
            calculation_type="fixture.calculation",
            engine_version="0.4.0",
        )
        return (
            id(definition),
            id(resolved_registration),
            resolved_registration.implementation is bomb_handler,
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = tuple(executor.map(resolve_once, range(512)))

    assert len({value[0] for value in results}) == 1
    assert len({value[1] for value in results}) == 1
    assert all(value[2] for value in results)
    assert BOMB_CALL_COUNT == 0


def test_concurrent_mixed_versions_route_exact_functions() -> None:
    version_one = approved_definition(method_version="1.0.0")
    version_two = approved_definition(method_version="2.0.0")
    method_registry = CalculationMethodRegistry(
        (
            registration(version_one, approved_handler_one),
            registration(version_two, approved_handler_two),
        )
    )
    requested_versions = tuple(
        "1.0.0" if index % 2 == 0 else "2.0.0"
        for index in range(512)
    )

    def resolve_version(method_version: str):
        return method_registry.resolve_for_execution(
            "fixture.method",
            method_version,
            engine_version="0.4.0",
        ).implementation

    with ThreadPoolExecutor(max_workers=16) as executor:
        resolved = tuple(
            executor.map(resolve_version, requested_versions)
        )

    assert all(
        implementation
        is (
            approved_handler_one
            if version == "1.0.0"
            else approved_handler_two
        )
        for version, implementation in zip(
            requested_versions,
            resolved,
            strict=True,
        )
    )


def test_registry_source_has_no_dynamic_execution_or_loading_path() -> None:
    source_path = Path(registry_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    prohibited_calls = {
        "eval",
        "exec",
        "compile",
        "__import__",
    }
    prohibited_modules = {
        "importlib",
        "subprocess",
    }

    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in prohibited_calls
        for node in ast.walk(tree)
    )
    assert not any(
        (
            isinstance(node, ast.Import)
            and any(
                alias.name.split(".", 1)[0] in prohibited_modules
                for alias in node.names
            )
        )
        or (
            isinstance(node, ast.ImportFrom)
            and node.module is not None
            and node.module.split(".", 1)[0] in prohibited_modules
        )
        for node in ast.walk(tree)
    )


def test_registry_error_codes_are_stable_and_unique() -> None:
    error_types = (
        MethodRegistryError,
        InvalidMethodRegistrationError,
        DuplicateMethodRegistrationError,
        InvalidMethodLookupError,
        UnknownMethodError,
        UnknownMethodVersionError,
        MethodCalculationTypeError,
        MethodExecutionNotAllowedError,
        MethodEngineCompatibilityError,
    )
    codes = tuple(error_type.code for error_type in error_types)

    assert len(codes) == len(set(codes))
    assert all(
        issubclass(error_type, ValueError)
        for error_type in error_types
    )


def test_registry_public_exports_are_explicit_and_handler_safe() -> None:
    expected_exports = {
        "ApplicabilityEvaluator",
        "CalculationMethodRegistry",
        "DEFAULT_METHOD_REGISTRY",
        "DuplicateMethodRegistrationError",
        "InvalidMethodLookupError",
        "InvalidMethodRegistrationError",
        "MAX_REGISTERED_METHODS",
        "MethodCalculationTypeError",
        "MethodEngineCompatibilityError",
        "MethodExecutionNotAllowedError",
        "MethodImplementation",
        "MethodSpecificNormalizer",
        "MethodRegistration",
        "MethodRegistryError",
        "SafetyEvaluator",
        "UnknownMethodError",
        "UnknownMethodVersionError",
    }

    assert set(registry_module.__all__) == expected_exports
    assert "import_string" not in registry_module.__all__
    assert "load_method" not in registry_module.__all__
