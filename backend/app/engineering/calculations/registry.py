"""Immutable allow-listed registry for reviewed calculation methods.

The registry is a construction-time boundary between inert method metadata and
directly imported, reviewed Python implementations.  It deliberately provides
no mutation API, version fallback, dynamic import, expression evaluation, or
string-to-callable resolution.
"""

from __future__ import annotations

from collections.abc import Callable
from collections.abc import Iterable
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field
from inspect import Parameter
from inspect import isasyncgenfunction
from inspect import iscoroutinefunction
from inspect import isgeneratorfunction
from inspect import signature
from re import fullmatch
import sys
from types import FunctionType
from types import MappingProxyType
from typing import Any
from typing import Final
from typing import TYPE_CHECKING

from pydantic import ValidationError

from app.engineering.calculations.method_models import ApplicabilityRule
from app.engineering.calculations.method_models import (
    CANONICAL_METHOD_VERSION_PATTERN,
)
from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
)
from app.engineering.calculations.method_models import (
    InputNormalizationMode,
)
from app.engineering.calculations.method_models import (
    MethodExecutionContext,
)
from app.engineering.calculations.method_models import (
    MethodExecutionOutcome,
)
from app.engineering.calculations.method_models import (
    MethodInputSpecification,
)
from app.engineering.calculations.models import CalculationInput
from app.engineering.calculations.models import MethodLifecycleStatus

if TYPE_CHECKING:
    from app.engineering.calculations.safety import SafetyEvaluationContext


MAX_REGISTERED_METHODS: Final = 4_096

_IDENTIFIER_PATTERN: Final = r"[A-Za-z0-9][A-Za-z0-9_.:/-]{1,99}"
_VERSION_PATTERN: Final = CANONICAL_METHOD_VERSION_PATTERN
_ENGINE_VERSION_PATTERN: Final = (
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
)

MethodImplementation = Callable[
    [MethodExecutionContext, object],
    MethodExecutionOutcome,
]
MethodSpecificNormalizer = Callable[
    [MethodInputSpecification, CalculationInput],
    CalculationInput,
]
ApplicabilityEvaluator = Callable[
    [ApplicabilityRule, tuple[CalculationInput, ...]],
    bool,
]
SafetyEvaluator = Callable[["SafetyEvaluationContext"], object]
MethodKey = tuple[str, str]


class MethodRegistryError(ValueError):
    """Base error for deterministic method-registry operations."""

    code = "method_registry_error"


class InvalidMethodRegistrationError(MethodRegistryError):
    """Raised when a registry entry is malformed or is not reviewable."""

    code = "invalid_method_registration"


class DuplicateMethodRegistrationError(MethodRegistryError):
    """Raised when a method identity is registered more than once."""

    code = "duplicate_method_registration"


class InvalidMethodLookupError(MethodRegistryError):
    """Raised when a lookup key is not a bounded controlled identifier."""

    code = "invalid_method_lookup"


class UnknownMethodError(MethodRegistryError):
    """Raised when an exact method identifier is not allow-listed."""

    code = "unknown_method"

    def __init__(self, method_id: str) -> None:
        self.method_id = method_id
        super().__init__(
            f"Unknown calculation method ID: {method_id!r}."
        )


class UnknownMethodVersionError(MethodRegistryError):
    """Raised when an exact version is not registered for a known method."""

    code = "unknown_method_version"

    def __init__(self, method_id: str, method_version: str) -> None:
        self.method_id = method_id
        self.method_version = method_version
        super().__init__(
            f"Unknown version {method_version!r} for calculation method "
            f"{method_id!r}."
        )


class MethodCalculationTypeError(MethodRegistryError):
    """Raised when a request names the wrong calculation type."""

    code = "method_calculation_type_mismatch"

    def __init__(
        self,
        method_id: str,
        method_version: str,
        calculation_type: str,
    ) -> None:
        self.method_id = method_id
        self.method_version = method_version
        self.calculation_type = calculation_type
        super().__init__(
            "The requested calculation type does not match the registered "
            "method."
        )


class MethodExecutionNotAllowedError(MethodRegistryError):
    """Raised when a discoverable lifecycle state cannot execute."""

    code = "method_execution_not_allowed"

    def __init__(
        self,
        method_id: str,
        method_version: str,
        lifecycle_status: MethodLifecycleStatus,
    ) -> None:
        self.method_id = method_id
        self.method_version = method_version
        self.lifecycle_status = lifecycle_status
        super().__init__(
            f"Calculation method {method_id!r} version "
            f"{method_version!r} is not approved for execution."
        )


class MethodEngineCompatibilityError(MethodRegistryError):
    """Raised when a method does not support the selected engine version."""

    code = "method_engine_incompatible"

    def __init__(
        self,
        method_id: str,
        method_version: str,
        engine_version: str,
    ) -> None:
        self.method_id = method_id
        self.method_version = method_version
        self.engine_version = engine_version
        super().__init__(
            f"Calculation method {method_id!r} version "
            f"{method_version!r} does not support engine version "
            f"{engine_version!r}."
        )


def _validated_definition(
    definition: CalculationMethodDefinition,
) -> CalculationMethodDefinition:
    """Return a fresh, fully revalidated method definition."""

    if not isinstance(definition, CalculationMethodDefinition):
        raise InvalidMethodRegistrationError(
            "A method registration requires a "
            "CalculationMethodDefinition."
        )

    try:
        dumped_definition = definition.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
        return CalculationMethodDefinition.model_validate(
            dumped_definition,
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise InvalidMethodRegistrationError(
            "The calculation method definition is invalid."
        ) from exc


def _validate_implementation(
    implementation: Callable[..., object],
    *,
    parameter_names: tuple[str, ...],
    role: str,
) -> None:
    """Require a direct module-level Python function object."""

    if not isinstance(implementation, FunctionType):
        raise InvalidMethodRegistrationError(
            "A method implementation must be a direct module-level "
            "Python function."
        )

    if (
        iscoroutinefunction(implementation)
        or isgeneratorfunction(implementation)
        or isasyncgenfunction(implementation)
    ):
        raise InvalidMethodRegistrationError(
            "Asynchronous and generator method functions are prohibited."
        )

    if (
        "__signature__" in implementation.__dict__
        or "__wrapped__" in implementation.__dict__
    ):
        raise InvalidMethodRegistrationError(
            "Callable signature overrides and wrapped functions are "
            "prohibited."
        )

    try:
        function_parameters = tuple(
            signature(
                implementation,
                follow_wrapped=False,
            ).parameters.values()
        )
    except (TypeError, ValueError) as exc:
        raise InvalidMethodRegistrationError(
            f"{role} has an invalid callable signature."
        ) from exc
    if (
        tuple(
            parameter.name
            for parameter in function_parameters
        ) != parameter_names
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
        raise InvalidMethodRegistrationError(
            f"{role} must declare the exact required positional signature "
            f"({', '.join(parameter_names)})."
        )

    if implementation.__name__ == "<lambda>":
        raise InvalidMethodRegistrationError(
            "Lambda method implementations are prohibited."
        )

    if (
        implementation.__qualname__ != implementation.__name__
        or implementation.__closure__ is not None
    ):
        raise InvalidMethodRegistrationError(
            "Nested functions, closures, and methods cannot be registered."
        )

    source_filename = implementation.__code__.co_filename
    if source_filename.startswith("<") and source_filename.endswith(">"):
        raise InvalidMethodRegistrationError(
            "Dynamically compiled method implementations are prohibited."
        )

    module = sys.modules.get(implementation.__module__)
    if (
        module is None
        or vars(module).get(implementation.__name__) is not implementation
    ):
        raise InvalidMethodRegistrationError(
            "A method implementation must be bound directly in its "
            "declaring module."
        )


def _validated_hook_mapping(
    hooks: Mapping[str, Callable[..., object]],
    *,
    expected_ids: tuple[str, ...],
    hook_name: str,
    parameter_names: tuple[str, ...],
    role: str,
) -> Mapping[str, Callable[..., object]]:
    """Return an immutable exact hook map for reviewed metadata IDs."""

    if not isinstance(hooks, Mapping):
        raise InvalidMethodRegistrationError(
            f"{hook_name} must be a mapping."
        )

    expected_ids_by_comparison = {
        expected_id.casefold(): expected_id
        for expected_id in expected_ids
    }
    validated_hooks: dict[str, Callable[..., object]] = {}

    for hook_id, hook in hooks.items():
        if not isinstance(hook_id, str):
            raise InvalidMethodRegistrationError(
                f"{hook_name} contains an unknown metadata identifier."
            )

        canonical_hook_id = expected_ids_by_comparison.get(
            hook_id.casefold()
        )
        if (
            canonical_hook_id is None
            or canonical_hook_id in validated_hooks
        ):
            raise InvalidMethodRegistrationError(
                f"{hook_name} contains an unknown or duplicate metadata "
                "identifier."
            )

        _validate_implementation(
            hook,
            parameter_names=parameter_names,
            role=role,
        )
        validated_hooks[canonical_hook_id] = hook

    if set(validated_hooks) != set(expected_ids):
        raise InvalidMethodRegistrationError(
            f"{hook_name} must bind every required metadata identifier."
        )

    return MappingProxyType(
        {
            hook_id: validated_hooks[hook_id]
            for hook_id in sorted(validated_hooks)
        }
    )


@dataclass(frozen=True, slots=True)
class MethodRegistration:
    """One immutable metadata-to-implementation allow-list binding.

    One reviewed callable may be bound explicitly to multiple exact method
    identities.  Inside one registration, however, every callable role must
    remain distinct.
    """

    definition: CalculationMethodDefinition
    implementation: MethodImplementation
    input_normalizers: Mapping[
        str,
        MethodSpecificNormalizer,
    ] = field(default_factory=dict)
    applicability_evaluators: Mapping[
        str,
        ApplicabilityEvaluator,
    ] = field(default_factory=dict)
    safety_evaluator: SafetyEvaluator | None = None

    def __post_init__(self) -> None:
        """Revalidate metadata and attest the implementation shape."""

        object.__setattr__(
            self,
            "definition",
            _validated_definition(self.definition),
        )
        _validate_implementation(
            self.implementation,
            parameter_names=("context", "iteration_controller"),
            role="Method implementation",
        )

        method_specific_input_ids = tuple(
            specification.input_id
            for specification in self.definition.input_specifications
            if (
                specification.normalization_mode
                is InputNormalizationMode.METHOD_SPECIFIC
            )
        )
        applicability_rule_ids = tuple(
            rule.rule_id
            for rule in self.definition.applicability_rules
        )

        object.__setattr__(
            self,
            "input_normalizers",
            _validated_hook_mapping(
                self.input_normalizers,
                expected_ids=method_specific_input_ids,
                hook_name="input_normalizers",
                parameter_names=("specification", "supplied_input"),
                role="Method-specific normalizer",
            ),
        )
        object.__setattr__(
            self,
            "applicability_evaluators",
            _validated_hook_mapping(
                self.applicability_evaluators,
                expected_ids=applicability_rule_ids,
                hook_name="applicability_evaluators",
                parameter_names=("rule", "linked_inputs"),
                role="Applicability evaluator",
            ),
        )

        if self.safety_evaluator is not None:
            _validate_implementation(
                self.safety_evaluator,
                parameter_names=("context",),
                role="Safety evaluator",
            )

        bound_callables = (
            self.implementation,
            *self.input_normalizers.values(),
            *self.applicability_evaluators.values(),
            *(
                ()
                if self.safety_evaluator is None
                else (self.safety_evaluator,)
            ),
        )
        if len({id(value) for value in bound_callables}) != len(
            bound_callables
        ):
            raise InvalidMethodRegistrationError(
                "Each executor and trusted hook must use a distinct "
                "reviewed function."
            )

    @property
    def method_id(self) -> str:
        """Return the permanent method identifier."""

        return self.definition.method_id

    @property
    def method_version(self) -> str:
        """Return the exact controlled method version."""

        return self.definition.method_version

    @property
    def calculation_type(self) -> str:
        """Return the controlled calculation type."""

        return self.definition.calculation_type

    @property
    def implementation_id(self) -> str:
        """Return a stable diagnostic identity without accepting a path."""

        return (
            f"{self.implementation.__module__}:"
            f"{self.implementation.__name__}"
        )


def _normalize_lookup(
    value: object,
    *,
    field_name: str,
    pattern: str,
) -> str:
    """Validate one bounded exact-lookup component."""

    if not isinstance(value, str):
        raise InvalidMethodLookupError(
            f"{field_name} must be a string."
        )

    normalized_value = value.strip()
    minimum_length, maximum_length = (
        (3, 64)
        if field_name in {"method_version", "engine_version"}
        else (2, 100)
    )
    if (
        len(normalized_value) < minimum_length
        or len(normalized_value) > maximum_length
        or fullmatch(pattern, normalized_value) is None
    ):
        raise InvalidMethodLookupError(
            f"{field_name} is not a valid controlled identifier."
        )

    return normalized_value


class CalculationMethodRegistry:
    """Immutable, exact-only registry of reviewed calculation functions."""

    __slots__ = (
        "_definitions",
        "_entries",
        "_locked",
        "_method_ids",
        "_versions_by_method",
    )

    def __init__(
        self,
        registrations: Iterable[MethodRegistration],
    ) -> None:
        """Build and permanently lock an allow-listed method registry."""

        object.__setattr__(self, "_locked", False)

        entries: dict[MethodKey, MethodRegistration] = {}
        casefold_keys: dict[MethodKey, MethodKey] = {}
        calculation_types: dict[str, str] = {}
        for index, candidate in enumerate(registrations):
            if index >= MAX_REGISTERED_METHODS:
                raise InvalidMethodRegistrationError(
                    "A method registry cannot exceed "
                    f"{MAX_REGISTERED_METHODS} entries."
                )

            if not isinstance(candidate, MethodRegistration):
                raise InvalidMethodRegistrationError(
                    "Registry entries must be MethodRegistration instances."
                )

            registration = MethodRegistration(
                definition=candidate.definition,
                implementation=candidate.implementation,
                input_normalizers=candidate.input_normalizers,
                applicability_evaluators=(
                    candidate.applicability_evaluators
                ),
                safety_evaluator=candidate.safety_evaluator,
            )
            key = (
                registration.method_id,
                registration.method_version,
            )
            folded_key = (
                registration.method_id.casefold(),
                registration.method_version.casefold(),
            )

            if key in entries or folded_key in casefold_keys:
                raise DuplicateMethodRegistrationError(
                    "Duplicate or case-conflicting calculation method "
                    "identity."
                )

            folded_method_id = registration.method_id.casefold()
            existing_type = calculation_types.get(folded_method_id)
            if (
                existing_type is not None
                and existing_type != registration.calculation_type
            ):
                raise InvalidMethodRegistrationError(
                    "Every version of a calculation method must retain "
                    "the same calculation type."
                )

            entries[key] = registration
            casefold_keys[folded_key] = key
            calculation_types[folded_method_id] = (
                registration.calculation_type
            )

        ordered_keys = tuple(sorted(entries))
        ordered_entries = {
            key: entries[key]
            for key in ordered_keys
        }
        definitions = tuple(
            ordered_entries[key].definition
            for key in ordered_keys
        )
        method_ids = tuple(
            sorted({key[0] for key in ordered_keys})
        )
        versions_by_method = {
            method_id: tuple(
                key[1]
                for key in ordered_keys
                if key[0] == method_id
            )
            for method_id in method_ids
        }

        object.__setattr__(
            self,
            "_entries",
            MappingProxyType(ordered_entries),
        )
        object.__setattr__(self, "_definitions", definitions)
        object.__setattr__(self, "_method_ids", method_ids)
        object.__setattr__(
            self,
            "_versions_by_method",
            MappingProxyType(versions_by_method),
        )
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent registry mutation after validated construction."""

        if getattr(self, "_locked", False):
            raise AttributeError(
                "CalculationMethodRegistry instances are immutable."
            )

        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """Prevent registry attribute deletion after construction."""

        if getattr(self, "_locked", False):
            raise AttributeError(
                "CalculationMethodRegistry instances are immutable."
            )

        object.__delattr__(self, name)

    @property
    def definitions(self) -> tuple[CalculationMethodDefinition, ...]:
        """Return metadata only, sorted by exact method identity."""

        return self._definitions

    @property
    def method_ids(self) -> tuple[str, ...]:
        """Return the sorted permanent method identifiers."""

        return self._method_ids

    def available_versions(self, method_id: str) -> tuple[str, ...]:
        """Return registered versions without selecting one implicitly."""

        normalized_method_id = _normalize_lookup(
            method_id,
            field_name="method_id",
            pattern=_IDENTIFIER_PATTERN,
        )
        versions = self._versions_by_method.get(normalized_method_id)
        if versions is None:
            raise UnknownMethodError(normalized_method_id)

        return versions

    def _resolve_registration(
        self,
        method_id: str,
        method_version: str,
        *,
        calculation_type: str | None = None,
    ) -> MethodRegistration:
        """Resolve one exact private registration without fallback."""

        normalized_method_id = _normalize_lookup(
            method_id,
            field_name="method_id",
            pattern=_IDENTIFIER_PATTERN,
        )
        normalized_version = _normalize_lookup(
            method_version,
            field_name="method_version",
            pattern=_VERSION_PATTERN,
        )

        if normalized_method_id not in self._versions_by_method:
            raise UnknownMethodError(normalized_method_id)

        registration = self._entries.get(
            (normalized_method_id, normalized_version)
        )
        if registration is None:
            raise UnknownMethodVersionError(
                normalized_method_id,
                normalized_version,
            )

        if calculation_type is not None:
            normalized_calculation_type = _normalize_lookup(
                calculation_type,
                field_name="calculation_type",
                pattern=_IDENTIFIER_PATTERN,
            )
            if normalized_calculation_type != registration.calculation_type:
                raise MethodCalculationTypeError(
                    normalized_method_id,
                    normalized_version,
                    normalized_calculation_type,
                )

        return registration

    def resolve(
        self,
        method_id: str,
        method_version: str,
        *,
        calculation_type: str | None = None,
    ) -> CalculationMethodDefinition:
        """Return exact method metadata, never an implicit version."""

        return self._resolve_registration(
            method_id,
            method_version,
            calculation_type=calculation_type,
        ).definition

    def discover(
        self,
        *,
        calculation_type: str | None = None,
    ) -> tuple[CalculationMethodDefinition, ...]:
        """Return deterministic metadata without implementation objects."""

        if calculation_type is None:
            return self._definitions

        normalized_calculation_type = _normalize_lookup(
            calculation_type,
            field_name="calculation_type",
            pattern=_IDENTIFIER_PATTERN,
        )
        return tuple(
            definition
            for definition in self._definitions
            if definition.calculation_type == normalized_calculation_type
        )

    def is_execution_eligible(
        self,
        method_id: str,
        method_version: str,
        *,
        engine_version: str,
        calculation_type: str | None = None,
    ) -> bool:
        """Check lifecycle and engine compatibility without invocation."""

        definition = self.resolve(
            method_id,
            method_version,
            calculation_type=calculation_type,
        )
        if not definition.is_executable:
            return False

        normalized_engine_version = _normalize_lookup(
            engine_version,
            field_name="engine_version",
            pattern=_ENGINE_VERSION_PATTERN,
        )
        return definition.engine_compatibility.supports(
            normalized_engine_version
        )

    def resolve_for_execution(
        self,
        method_id: str,
        method_version: str,
        *,
        engine_version: str,
        calculation_type: str | None = None,
    ) -> MethodRegistration:
        """Resolve an approved exact registration for controlled execution."""

        registration = self._resolve_registration(
            method_id,
            method_version,
            calculation_type=calculation_type,
        )
        lifecycle_status = registration.definition.lifecycle_status
        if not registration.definition.is_executable:
            raise MethodExecutionNotAllowedError(
                registration.method_id,
                registration.method_version,
                lifecycle_status,
            )

        normalized_engine_version = _normalize_lookup(
            engine_version,
            field_name="engine_version",
            pattern=_ENGINE_VERSION_PATTERN,
        )
        if not registration.definition.engine_compatibility.supports(
            normalized_engine_version
        ):
            raise MethodEngineCompatibilityError(
                registration.method_id,
                registration.method_version,
                normalized_engine_version,
            )

        return registration


DEFAULT_METHOD_REGISTRY = CalculationMethodRegistry(())


__all__ = [
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
    "MethodRegistration",
    "MethodRegistryError",
    "MethodSpecificNormalizer",
    "SafetyEvaluator",
    "UnknownMethodError",
    "UnknownMethodVersionError",
]
