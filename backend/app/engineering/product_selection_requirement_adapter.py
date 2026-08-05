"""Controlled calculation outputs for product-selection requirements.

Only four explicitly allow-listed scalar requirement fields can be proposed.
Every proposal is bound to one published-knowledge calculation link, one exact
output identity, quantity kind, and source unit.  The adapter converts through
the immutable default unit registry, fills only missing user fields, and records
an explicit decision whenever a user value is confirmed or retained.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from types import MappingProxyType
from typing import Annotated, Any, Final, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from app.engineering.calculations.models import (
    CalculationOutput,
    CalculationResult,
)
from app.engineering.calculations.units import (
    DEFAULT_UNIT_REGISTRY,
    QuantityKind,
    UnitSystemError,
)
from app.engineering.knowledge_calculation_adapter import (
    ControlledCalculationKnowledgeAdapter,
    ControlledCalculationKnowledgeLink,
    fingerprint_calculation_result,
)
from app.engineering.knowledge_models import EngineeringKnowledge
from app.engineering.recommendation_models import (
    EngineeringRequirements,
    RequirementImportance,
)

PRODUCT_SELECTION_REQUIREMENT_ADAPTER_VERSION: Final = "1.0.0"
MAX_SELECTION_REQUIREMENT_BINDINGS: Final = 128
MAX_REQUIREMENT_DECISIONS: Final = 4
MAX_REQUIREMENT_COLLECTION_ITEMS: Final = 128

ControlledIdentifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=2,
        max_length=100,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$",
    ),
]
StableVersion = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=5,
        max_length=64,
        pattern=r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$",
    ),
]
UnitSymbol = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=40),
]
RequirementCollectionText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=500),
]


class ProductSelectionRequirementAdapterError(ValueError):
    """Base error for fail-closed calculation-to-selection adaptation."""

    code = "product_selection_requirement_adapter_error"


class InvalidSelectionRequirementBindingError(ProductSelectionRequirementAdapterError):
    """Raised when a selection requirement binding is invalid."""

    code = "invalid_selection_requirement_binding"


class DuplicateSelectionRequirementBindingError(
    ProductSelectionRequirementAdapterError
):
    """Raised when selection output bindings are ambiguous."""

    code = "duplicate_selection_requirement_binding"


class UnknownSelectionRequirementBindingError(ProductSelectionRequirementAdapterError):
    """Raised when no selection binding exists for a controlled link."""

    code = "unknown_selection_requirement_binding"


class CalculationOutputRequirementError(ProductSelectionRequirementAdapterError):
    """Raised when a result output violates its exact binding."""

    code = "calculation_output_requirement_error"


class ConflictingRequirementCandidatesError(ProductSelectionRequirementAdapterError):
    """Raised when several outputs propose different values for one field."""

    code = "conflicting_requirement_candidates"


class KnowledgeSafetyBlocksSelectionError(ProductSelectionRequirementAdapterError):
    """Raised when published knowledge explicitly blocks further work."""

    code = "knowledge_safety_blocks_selection"


class InvalidEngineeringRequirementsError(ProductSelectionRequirementAdapterError):
    """Raised when caller requirements are invalid or non-finite."""

    code = "invalid_engineering_requirements"


class CalculatedRequirementValueError(ProductSelectionRequirementAdapterError):
    """Raised when a calculated proposal cannot form valid requirements."""

    code = "calculated_requirement_value_error"


class ProductRequirementField(StrEnum):
    """The only product-selection fields calculations may propose."""

    PROCESS_TEMPERATURE_C = "process_temperature_c"
    PROCESS_PRESSURE_BAR = "process_pressure_bar"
    AMBIENT_TEMPERATURE_C = "ambient_temperature_c"
    REQUIRED_ACCURACY_PERCENT = "required_accuracy_percent"


class RequirementDecision(StrEnum):
    """How one calculated proposal interacted with a caller value."""

    APPLIED_TO_MISSING = "applied_to_missing"
    USER_VALUE_CONFIRMED = "user_value_confirmed"
    USER_VALUE_RETAINED = "user_value_retained"


@dataclass(frozen=True, slots=True)
class _TargetPolicy:
    """Fixed semantic and unit policy for one target requirement field."""

    quantity_kind: QuantityKind
    target_unit: str


_TARGET_POLICIES: Final = MappingProxyType(
    {
        ProductRequirementField.PROCESS_TEMPERATURE_C: _TargetPolicy(
            quantity_kind=QuantityKind.ABSOLUTE_TEMPERATURE,
            target_unit="degC",
        ),
        ProductRequirementField.PROCESS_PRESSURE_BAR: _TargetPolicy(
            quantity_kind=QuantityKind.ABSOLUTE_PRESSURE,
            target_unit="bar",
        ),
        ProductRequirementField.AMBIENT_TEMPERATURE_C: _TargetPolicy(
            quantity_kind=QuantityKind.ABSOLUTE_TEMPERATURE,
            target_unit="degC",
        ),
        ProductRequirementField.REQUIRED_ACCURACY_PERCENT: _TargetPolicy(
            quantity_kind=QuantityKind.RATIO,
            target_unit="%",
        ),
    }
)


class _ImmutableAdapterModel(BaseModel):
    """Strict immutable configuration shared by adapter response models."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        validate_default=True,
        use_enum_values=False,
        allow_inf_nan=False,
        revalidate_instances="always",
    )

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Return a copy without permitting an unchecked Pydantic update."""

        if not update:
            return super().model_copy(deep=deep)
        copied_value = self.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
        copied_value.update(update)
        return type(self).model_validate(copied_value)


_REQUIREMENT_COLLECTION_FIELDS: Final = (
    "required_hazardous_area_approvals",
    "required_wetted_materials",
    "required_process_connections",
    "required_protocols",
    "installation_environment",
)


class EngineeringRequirementsSnapshot(_ImmutableAdapterModel):
    """Deeply immutable bounded snapshot of legacy selection requirements."""

    measurement_type: (
        Annotated[
            str,
            StringConstraints(strip_whitespace=True, min_length=1, max_length=100),
        ]
        | None
    ) = None
    process_temperature_c: StrictFloat | None = Field(default=None, ge=-273.15)
    process_temperature_importance: RequirementImportance = (
        RequirementImportance.MANDATORY
    )
    process_pressure_bar: StrictFloat | None = None
    process_pressure_importance: RequirementImportance = RequirementImportance.MANDATORY
    ambient_temperature_c: StrictFloat | None = Field(default=None, ge=-273.15)
    ambient_temperature_importance: RequirementImportance = (
        RequirementImportance.MANDATORY
    )
    required_accuracy_percent: StrictFloat | None = Field(default=None, gt=0)
    accuracy_importance: RequirementImportance = RequirementImportance.PREFERRED
    required_ingress_protection_rating: (
        Annotated[
            str,
            StringConstraints(strip_whitespace=True, min_length=2, max_length=20),
        ]
        | None
    ) = None
    ingress_protection_importance: RequirementImportance = (
        RequirementImportance.MANDATORY
    )
    hazardous_area_required: StrictBool = False
    required_hazardous_area_approvals: tuple[RequirementCollectionText, ...] = Field(
        default_factory=tuple, max_length=MAX_REQUIREMENT_COLLECTION_ITEMS
    )
    hazardous_area_importance: RequirementImportance = RequirementImportance.MANDATORY
    process_medium: (
        Annotated[
            str,
            StringConstraints(strip_whitespace=True, min_length=1, max_length=150),
        ]
        | None
    ) = None
    required_wetted_materials: tuple[RequirementCollectionText, ...] = Field(
        default_factory=tuple,
        max_length=MAX_REQUIREMENT_COLLECTION_ITEMS,
    )
    wetted_material_importance: RequirementImportance = RequirementImportance.MANDATORY
    required_process_connections: tuple[RequirementCollectionText, ...] = Field(
        default_factory=tuple,
        max_length=MAX_REQUIREMENT_COLLECTION_ITEMS,
    )
    process_connection_importance: RequirementImportance = (
        RequirementImportance.PREFERRED
    )
    required_protocols: tuple[RequirementCollectionText, ...] = Field(
        default_factory=tuple,
        max_length=MAX_REQUIREMENT_COLLECTION_ITEMS,
    )
    communication_protocol_importance: RequirementImportance = (
        RequirementImportance.PREFERRED
    )
    installation_environment: tuple[RequirementCollectionText, ...] = Field(
        default_factory=tuple,
        max_length=MAX_REQUIREMENT_COLLECTION_ITEMS,
    )
    application_notes: (
        Annotated[
            str,
            StringConstraints(strip_whitespace=True, max_length=2000),
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def validate_hazardous_area_requirements(
        self,
    ) -> EngineeringRequirementsSnapshot:
        """Preserve the legacy hazardous-area consistency requirement."""

        if self.required_hazardous_area_approvals and not self.hazardous_area_required:
            raise ValueError(
                "hazardous_area_required must be true when hazardous-area "
                "approvals are specified."
            )
        return self

    @classmethod
    def from_engineering_requirements(
        cls,
        value: EngineeringRequirements,
    ) -> EngineeringRequirementsSnapshot:
        """Create a bounded tuple-backed snapshot at the adapter boundary."""

        validated = _validated_requirements(value)
        payload = validated.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
        for field_name in _REQUIREMENT_COLLECTION_FIELDS:
            payload[field_name] = tuple(payload[field_name])
        try:
            return cls.model_validate(payload)
        except (TypeError, ValueError, ValidationError) as exc:
            raise InvalidEngineeringRequirementsError(
                "user_requirements exceed the controlled snapshot bounds."
            ) from exc

    def to_engineering_requirements(self) -> EngineeringRequirements:
        """Return a fresh mutable legacy model for an explicit selection call."""

        payload = self.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
        for field_name in _REQUIREMENT_COLLECTION_FIELDS:
            payload[field_name] = list(payload[field_name])
        return EngineeringRequirements.model_validate(payload)


class SelectionRequirementBinding(_ImmutableAdapterModel):
    """Explicit link-output-to-selection-field allowlist entry."""

    binding_id: ControlledIdentifier
    knowledge_method_binding_id: ControlledIdentifier
    output_id: ControlledIdentifier
    quantity_kind: QuantityKind
    output_unit: UnitSymbol
    target_field: ProductRequirementField
    target_unit: UnitSymbol

    @model_validator(mode="after")
    def validate_fixed_target_policy(self) -> SelectionRequirementBinding:
        """Pin every target field to one quantity kind and target unit."""

        policy = _TARGET_POLICIES[self.target_field]
        if self.quantity_kind is not policy.quantity_kind:
            raise ValueError(
                "quantity_kind does not match the fixed target-field policy."
            )
        if self.target_unit != policy.target_unit:
            raise ValueError(
                "target_unit does not match the fixed target-field policy."
            )

        try:
            source_definition = DEFAULT_UNIT_REGISTRY.resolve_unit(self.output_unit)
            target_definition = DEFAULT_UNIT_REGISTRY.resolve_unit(self.target_unit)
            expected_dimension = DEFAULT_UNIT_REGISTRY.dimension_for(self.quantity_kind)
        except UnitSystemError as exc:
            raise ValueError(
                "Binding units and quantity kind must exist in the controlled "
                "unit registry."
            ) from exc

        if (
            source_definition.symbol != self.output_unit
            or target_definition.symbol != self.target_unit
        ):
            raise ValueError(
                "Binding units must use exact registered symbols, not aliases."
            )
        if (
            source_definition.dimension is not expected_dimension
            or target_definition.dimension is not expected_dimension
        ):
            raise ValueError("Binding units are incompatible with quantity_kind.")
        return self


# Descriptive compatibility name retained for callers that treat each binding
# as an output mapping.  It is the same strict model, not a second contract.
RequirementOutputBinding = SelectionRequirementBinding


class CalculatedRequirementDecision(_ImmutableAdapterModel):
    """Auditable merge decision for one calculated requirement field."""

    target_field: ProductRequirementField
    decision: RequirementDecision
    conflict: StrictBool
    method_id: ControlledIdentifier
    method_version: StableVersion
    source_result_fingerprint: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=64,
            max_length=64,
            pattern=r"^[0-9a-f]{64}$",
        ),
    ]
    binding_ids: tuple[ControlledIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_SELECTION_REQUIREMENT_BINDINGS,
    )
    output_id: ControlledIdentifier
    output_ids: tuple[ControlledIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_SELECTION_REQUIREMENT_BINDINGS,
    )
    source_quantity_kind: QuantityKind
    source_unit: UnitSymbol
    source_units: tuple[UnitSymbol, ...] = Field(
        min_length=1,
        max_length=MAX_SELECTION_REQUIREMENT_BINDINGS,
    )
    target_unit: UnitSymbol
    calculated_value: StrictFloat
    user_value: StrictFloat | None
    effective_value: StrictFloat

    @field_validator("binding_ids", "output_ids")
    @classmethod
    def validate_unique_collections(
        cls,
        value: tuple[str, ...],
        info: Any,
    ) -> tuple[str, ...]:
        """Reject duplicate provenance identities."""

        comparison_values = [item.casefold() for item in value]
        if len(comparison_values) != len(set(comparison_values)):
            raise ValueError(f"{info.field_name} values must be unique.")
        return value

    @model_validator(mode="after")
    def validate_decision(self) -> CalculatedRequirementDecision:
        """Require values to agree with the recorded merge decision."""

        policy = _TARGET_POLICIES[self.target_field]
        if (
            self.source_quantity_kind is not policy.quantity_kind
            or self.target_unit != policy.target_unit
        ):
            raise ValueError(
                "Decision metadata does not match the target-field policy."
            )
        if len(self.binding_ids) != len(self.output_ids):
            raise ValueError("binding_ids and output_ids must have matching lengths.")
        if len(self.binding_ids) != len(self.source_units):
            raise ValueError("binding_ids and source_units must have matching lengths.")
        if (
            self.output_id != self.output_ids[0]
            or self.source_unit != self.source_units[0]
        ):
            raise ValueError(
                "Singular output and unit provenance must identify the first "
                "deterministically ordered candidate."
            )

        if self.decision is RequirementDecision.APPLIED_TO_MISSING:
            if self.user_value is not None or self.conflict:
                raise ValueError(
                    "An applied-to-missing decision cannot contain a user value."
                )
            if self.effective_value != self.calculated_value:
                raise ValueError(
                    "An applied calculation must become the effective value."
                )
        elif self.decision is RequirementDecision.USER_VALUE_CONFIRMED:
            if (
                self.user_value is None
                or self.user_value != self.calculated_value
                or self.effective_value != self.user_value
                or self.conflict
            ):
                raise ValueError(
                    "A confirmed user value must exactly equal the calculation."
                )
        elif (
            self.user_value is None
            or self.user_value == self.calculated_value
            or self.effective_value != self.user_value
            or not self.conflict
        ):
            raise ValueError(
                "A retained user value must differ from the calculation and "
                "remain the effective value."
            )

        return self

    @property
    def quantity_kind(self) -> QuantityKind:
        """Compatibility view of the explicitly sourced quantity kind."""

        return self.source_quantity_kind

    @property
    def merged_value(self) -> float:
        """Compatibility view of the effective candidate value."""

        return self.effective_value


class ProductSelectionRequirementAdaptation(_ImmutableAdapterModel):
    """Complete controlled merge result for product selection."""

    adapter_version: StableVersion
    knowledge_link: ControlledCalculationKnowledgeLink
    calculation_id: UUID
    result_fingerprint: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=64,
            max_length=64,
            pattern=r"^[0-9a-f]{64}$",
        ),
    ]
    source_result_fingerprint: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=64,
            max_length=64,
            pattern=r"^[0-9a-f]{64}$",
        ),
    ]
    user_requirements: EngineeringRequirementsSnapshot
    candidate_requirements: EngineeringRequirementsSnapshot
    has_conflicts: StrictBool
    decisions: tuple[CalculatedRequirementDecision, ...] = Field(
        min_length=1,
        max_length=MAX_REQUIREMENT_DECISIONS,
    )

    @field_validator("user_requirements", "candidate_requirements")
    @classmethod
    def validate_requirement_snapshot(
        cls,
        value: EngineeringRequirementsSnapshot,
    ) -> EngineeringRequirementsSnapshot:
        """Store a freshly validated requirements snapshot."""

        return EngineeringRequirementsSnapshot.model_validate(
            value.model_dump(
                mode="python",
                round_trip=True,
                warnings="error",
            )
        )

    @model_validator(mode="after")
    def validate_adaptation(self) -> ProductSelectionRequirementAdaptation:
        """Bind every decision to the exact candidate and result provenance."""

        fields = tuple(item.target_field for item in self.decisions)
        if len(fields) != len(set(fields)):
            raise ValueError("decisions must contain one item per target field.")
        if self.has_conflicts != any(item.conflict for item in self.decisions):
            raise ValueError(
                "has_conflicts must exactly summarize the field decisions."
            )
        user_payload = self.user_requirements.model_dump(mode="python")
        candidate_payload = self.candidate_requirements.model_dump(mode="python")
        decision_field_names = {item.target_field.value for item in self.decisions}
        if any(
            candidate_payload[field_name] != user_value
            for field_name, user_value in user_payload.items()
            if field_name not in decision_field_names
        ):
            raise ValueError(
                "Candidate requirements may differ from user requirements "
                "only for explicitly decided fields."
            )
        for item in self.decisions:
            if (
                getattr(self.user_requirements, item.target_field.value)
                != item.user_value
                or getattr(self.candidate_requirements, item.target_field.value)
                != item.effective_value
                or item.source_result_fingerprint != self.source_result_fingerprint
                or item.method_id != self.knowledge_link.method_id
                or item.method_version != self.knowledge_link.method_version
            ):
                raise ValueError(
                    "Requirement snapshots or provenance do not match their "
                    "controlled decisions."
                )
        return self

    @property
    def merged_requirements(self) -> EngineeringRequirements:
        """Return a fresh explicit legacy handoff for compatibility callers."""

        return self.candidate_requirements.to_engineering_requirements()

    def build_selection_requirements(self) -> EngineeringRequirements:
        """Return a fresh mutable candidate for an explicit selection call."""

        return self.candidate_requirements.to_engineering_requirements()


@dataclass(frozen=True, slots=True)
class _RequirementCandidate:
    """Internal converted candidate retained only during one adaptation."""

    binding: SelectionRequirementBinding
    value: float


def _revalidate_model[ModelT: BaseModel](
    model_type: type[ModelT],
    value: object,
    *,
    field_name: str,
) -> ModelT:
    """Return a fresh model instance and translate invalid boundary values."""

    if not isinstance(value, model_type):
        raise ProductSelectionRequirementAdapterError(
            f"{field_name} must be a {model_type.__name__}."
        )
    try:
        return model_type.model_validate(
            value.model_dump(
                mode="python",
                round_trip=True,
                warnings="error",
            )
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise ProductSelectionRequirementAdapterError(
            f"{field_name} failed controlled model validation."
        ) from exc


def _validated_requirements(
    value: EngineeringRequirements,
) -> EngineeringRequirements:
    """Deep-revalidate requirements and reject every non-finite target value."""

    if not isinstance(value, EngineeringRequirements):
        raise InvalidEngineeringRequirementsError(
            "user_requirements must be EngineeringRequirements."
        )
    try:
        validated = EngineeringRequirements.model_validate(
            value.model_dump(
                mode="python",
                round_trip=True,
                warnings="error",
            )
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise InvalidEngineeringRequirementsError(
            f"user_requirements failed deep validation: {exc}"
        ) from exc

    for target_field in ProductRequirementField:
        field_value = getattr(validated, target_field.value)
        if field_value is not None and not isfinite(field_value):
            raise InvalidEngineeringRequirementsError(
                f"{target_field.value} must be finite when supplied."
            )
    return validated


class ProductSelectionRequirementAdapter:
    """Safely propose calculation results as product-selection requirements."""

    __slots__ = (
        "_bindings",
        "_bindings_by_knowledge_binding",
        "_knowledge_adapter",
        "_locked",
    )

    ADAPTER_VERSION: Final = PRODUCT_SELECTION_REQUIREMENT_ADAPTER_VERSION

    def __init__(
        self,
        *,
        knowledge_adapter: ControlledCalculationKnowledgeAdapter,
        bindings: Sequence[SelectionRequirementBinding],
    ) -> None:
        """Build and permanently lock the explicit output mapping allowlist."""

        object.__setattr__(self, "_locked", False)
        if not isinstance(
            knowledge_adapter,
            ControlledCalculationKnowledgeAdapter,
        ):
            raise InvalidSelectionRequirementBindingError(
                "knowledge_adapter must be a ControlledCalculationKnowledgeAdapter."
            )
        if isinstance(bindings, (str, bytes)) or not isinstance(bindings, Sequence):
            raise InvalidSelectionRequirementBindingError(
                "bindings must be an ordered bounded sequence."
            )
        if not bindings or len(bindings) > MAX_SELECTION_REQUIREMENT_BINDINGS:
            raise InvalidSelectionRequirementBindingError(
                "bindings must contain between 1 and "
                f"{MAX_SELECTION_REQUIREMENT_BINDINGS} entries."
            )

        knowledge_binding_ids = {item.binding_id for item in knowledge_adapter.bindings}
        validated_bindings: list[SelectionRequirementBinding] = []
        folded_binding_ids: set[str] = set()
        folded_output_keys: set[tuple[str, str]] = set()
        grouped: dict[str, list[SelectionRequirementBinding]] = {}

        for candidate in bindings:
            try:
                binding = _revalidate_model(
                    SelectionRequirementBinding,
                    candidate,
                    field_name="binding",
                )
            except ProductSelectionRequirementAdapterError as exc:
                raise InvalidSelectionRequirementBindingError(str(exc)) from exc

            if binding.knowledge_method_binding_id not in knowledge_binding_ids:
                raise InvalidSelectionRequirementBindingError(
                    "A selection binding must reference an exact knowledge "
                    "method binding owned by knowledge_adapter."
                )
            folded_binding_id = binding.binding_id.casefold()
            folded_output_key = (
                binding.knowledge_method_binding_id.casefold(),
                binding.output_id.casefold(),
            )
            if (
                folded_binding_id in folded_binding_ids
                or folded_output_key in folded_output_keys
            ):
                raise DuplicateSelectionRequirementBindingError(
                    "Selection bindings must have unique IDs and map each "
                    "controlled output at most once."
                )

            validated_bindings.append(binding)
            folded_binding_ids.add(folded_binding_id)
            folded_output_keys.add(folded_output_key)
            grouped.setdefault(binding.knowledge_method_binding_id, []).append(binding)

        ordered_bindings = tuple(
            sorted(validated_bindings, key=lambda item: item.binding_id)
        )
        grouped_tuples = {
            key: tuple(sorted(values, key=lambda item: item.binding_id))
            for key, values in grouped.items()
        }
        object.__setattr__(self, "_knowledge_adapter", knowledge_adapter)
        object.__setattr__(self, "_bindings", ordered_bindings)
        object.__setattr__(
            self,
            "_bindings_by_knowledge_binding",
            MappingProxyType(grouped_tuples),
        )
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        """Prevent adapter mutation after construction."""

        if getattr(self, "_locked", False):
            raise AttributeError(
                "ProductSelectionRequirementAdapter instances are immutable."
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """Prevent adapter attribute deletion after construction."""

        if getattr(self, "_locked", False):
            raise AttributeError(
                "ProductSelectionRequirementAdapter instances are immutable."
            )
        object.__delattr__(self, name)

    @property
    def bindings(self) -> tuple[SelectionRequirementBinding, ...]:
        """Return immutable mapping metadata in deterministic order."""

        return self._bindings

    def adapt(
        self,
        knowledge: EngineeringKnowledge,
        calculation_id: str,
        result: CalculationResult,
        user_requirements: EngineeringRequirements,
    ) -> ProductSelectionRequirementAdaptation:
        """Propose exact completed outputs without replacing caller values."""

        user_snapshot = EngineeringRequirementsSnapshot.from_engineering_requirements(
            user_requirements
        )
        validated_requirements = user_snapshot.to_engineering_requirements()
        link = self._knowledge_adapter.resolve_link(
            knowledge,
            calculation_id,
        )
        validated_result = self._knowledge_adapter.validate_result(link, result)
        source_result_fingerprint = fingerprint_calculation_result(validated_result)
        if (
            link.knowledge_safety is not None
            and link.knowledge_safety.blocks_work_until_resolved
        ):
            raise KnowledgeSafetyBlocksSelectionError(
                "Published knowledge blocks selection until its safety "
                "condition is resolved."
            )

        bindings = self._bindings_by_knowledge_binding.get(link.binding_id)
        if not bindings:
            raise UnknownSelectionRequirementBindingError(
                "No product-selection bindings exist for the controlled "
                "knowledge calculation link."
            )

        output_ids = tuple(item.output_id for item in validated_result.outputs)
        folded_output_ids = tuple(item.casefold() for item in output_ids)
        if len(folded_output_ids) != len(set(folded_output_ids)):
            raise CalculationOutputRequirementError(
                "Calculation result output IDs must be unique without case conflicts."
            )
        outputs_by_id = {item.output_id: item for item in validated_result.outputs}
        candidates_by_field: dict[
            ProductRequirementField,
            list[_RequirementCandidate],
        ] = {}
        for binding in bindings:
            output = outputs_by_id.get(binding.output_id)
            if output is None:
                raise CalculationOutputRequirementError(
                    f"Required exact output {binding.output_id!r} is absent."
                )
            candidate = self._convert_candidate(binding, output)
            candidates_by_field.setdefault(binding.target_field, []).append(candidate)

        candidate_payload = validated_requirements.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
        decisions: list[CalculatedRequirementDecision] = []
        for target_field in ProductRequirementField:
            candidates = candidates_by_field.get(target_field)
            if not candidates:
                continue
            calculated_values = {item.value for item in candidates}
            if len(calculated_values) != 1:
                raise ConflictingRequirementCandidatesError(
                    "Multiple controlled outputs propose conflicting values "
                    f"for {target_field.value}."
                )

            calculated_value = next(iter(calculated_values))
            user_value = getattr(validated_requirements, target_field.value)
            if user_value is None:
                decision = RequirementDecision.APPLIED_TO_MISSING
                effective_value = calculated_value
                candidate_payload[target_field.value] = calculated_value
            elif user_value == calculated_value:
                decision = RequirementDecision.USER_VALUE_CONFIRMED
                effective_value = user_value
            else:
                decision = RequirementDecision.USER_VALUE_RETAINED
                effective_value = user_value

            policy = _TARGET_POLICIES[target_field]
            first_candidate = candidates[0]
            decisions.append(
                CalculatedRequirementDecision(
                    target_field=target_field,
                    decision=decision,
                    conflict=(decision is RequirementDecision.USER_VALUE_RETAINED),
                    method_id=link.method_id,
                    method_version=link.method_version,
                    source_result_fingerprint=source_result_fingerprint,
                    binding_ids=tuple(item.binding.binding_id for item in candidates),
                    output_id=first_candidate.binding.output_id,
                    output_ids=tuple(item.binding.output_id for item in candidates),
                    source_quantity_kind=policy.quantity_kind,
                    source_unit=first_candidate.binding.output_unit,
                    source_units=tuple(item.binding.output_unit for item in candidates),
                    target_unit=policy.target_unit,
                    calculated_value=calculated_value,
                    user_value=user_value,
                    effective_value=effective_value,
                )
            )

        try:
            candidate_requirements = EngineeringRequirements.model_validate(
                candidate_payload
            )
            candidate_requirements = _validated_requirements(candidate_requirements)
        except InvalidEngineeringRequirementsError as exc:
            raise CalculatedRequirementValueError(
                "A calculated proposal cannot form valid engineering requirements."
            ) from exc
        except (TypeError, ValueError, ValidationError) as exc:
            raise CalculatedRequirementValueError(
                "A calculated proposal cannot form valid engineering requirements."
            ) from exc

        return ProductSelectionRequirementAdaptation(
            adapter_version=self.ADAPTER_VERSION,
            knowledge_link=link,
            calculation_id=validated_result.calculation_id,
            result_fingerprint=validated_result.result_fingerprint,
            source_result_fingerprint=source_result_fingerprint,
            user_requirements=user_snapshot,
            candidate_requirements=(
                EngineeringRequirementsSnapshot.from_engineering_requirements(
                    candidate_requirements
                )
            ),
            has_conflicts=any(item.conflict for item in decisions),
            decisions=tuple(decisions),
        )

    @staticmethod
    def _convert_candidate(
        binding: SelectionRequirementBinding,
        output: CalculationOutput,
    ) -> _RequirementCandidate:
        """Validate and convert one exact numeric result output."""

        if output.quantity is None or output.categorical_value is not None:
            raise CalculationOutputRequirementError(
                "A selection requirement binding requires a numeric quantity output."
            )
        quantity = output.quantity
        if quantity.quantity_kind != binding.quantity_kind.value:
            raise CalculationOutputRequirementError(
                "The result output quantity kind does not match its exact "
                "selection binding."
            )
        if quantity.unit != binding.output_unit:
            raise CalculationOutputRequirementError(
                "The result output unit does not match its exact selection binding."
            )
        if quantity.uncertainty is not None:
            raise CalculationOutputRequirementError(
                "Uncertain calculation outputs cannot be mapped because the "
                "selection requirement contract has no uncertainty field."
            )

        try:
            validated_quantity = DEFAULT_UNIT_REGISTRY.validate_quantity(quantity)
            converted = DEFAULT_UNIT_REGISTRY.convert_quantity(
                validated_quantity,
                binding.target_unit,
            )
        except UnitSystemError as exc:
            raise CalculationOutputRequirementError(
                "The bound calculation output cannot be converted by the "
                "controlled unit registry."
            ) from exc

        if (
            converted.quantity_kind != binding.quantity_kind.value
            or converted.unit != binding.target_unit
            or not isfinite(converted.value)
        ):
            raise CalculationOutputRequirementError(
                "The converted output does not preserve the bound quantity identity."
            )
        return _RequirementCandidate(
            binding=binding,
            value=converted.value,
        )


__all__ = [
    "PRODUCT_SELECTION_REQUIREMENT_ADAPTER_VERSION",
    "CalculatedRequirementDecision",
    "CalculatedRequirementValueError",
    "CalculationOutputRequirementError",
    "ConflictingRequirementCandidatesError",
    "DuplicateSelectionRequirementBindingError",
    "EngineeringRequirementsSnapshot",
    "InvalidEngineeringRequirementsError",
    "InvalidSelectionRequirementBindingError",
    "KnowledgeSafetyBlocksSelectionError",
    "ProductRequirementField",
    "ProductSelectionRequirementAdaptation",
    "ProductSelectionRequirementAdapter",
    "ProductSelectionRequirementAdapterError",
    "RequirementDecision",
    "RequirementOutputBinding",
    "SelectionRequirementBinding",
    "UnknownSelectionRequirementBindingError",
]
