"""Controlled links between published knowledge and calculation methods.

This module is a deliberately narrow integration boundary.  Application-owned
bindings connect one exact revision of one published knowledge calculation
reference to one exact executable method and engine version.  Public links
contain identifiers and controlled review metadata only; formula expressions,
implementation callables, and dynamic import paths never cross the boundary.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from hashlib import sha256
from types import MappingProxyType
from typing import Annotated, Any, Final, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

from app.engineering.calculations.engine import CalculationEngine
from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
    TrustedExecutionEvidence,
)
from app.engineering.calculations.models import (
    CalculationRequest,
    CalculationResult,
    CalculationStatus,
    MethodLifecycleStatus,
)
from app.engineering.calculations.registry import (
    CalculationMethodRegistry,
    MethodRegistryError,
)
from app.engineering.knowledge_models import (
    EngineeringCalculationReference,
    EngineeringKnowledge,
    KnowledgeStatus,
    StandardReference,
)
from app.engineering.knowledge_models import (
    SafetySeverity as KnowledgeSafetySeverity,
)

KNOWLEDGE_CALCULATION_ADAPTER_VERSION: Final = "1.0.0"
MAX_KNOWLEDGE_METHOD_BINDINGS: Final = 256
MAX_LINK_IDENTIFIERS: Final = 256
MAX_LINK_STANDARDS: Final = 128
_KNOWLEDGE_FINGERPRINT_SCHEMA: Final = "engineer4me.knowledge-calculation.knowledge.v1"
_METHOD_FINGERPRINT_SCHEMA: Final = (
    "engineer4me.knowledge-calculation.method-definition.v1"
)
_LINK_FINGERPRINT_SCHEMA: Final = "engineer4me.knowledge-calculation.link.v1"
_COMPLETE_RESULT_FINGERPRINT_SCHEMA: Final = (
    "engineer4me.knowledge-calculation.complete-result.v1"
)

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
RevisionText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=50),
]
FingerprintText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    ),
]
BoundedText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=500),
]


class CalculationKnowledgeAdapterError(ValueError):
    """Base error for fail-closed knowledge/calculation integration."""

    code = "calculation_knowledge_adapter_error"


class InvalidKnowledgeMethodBindingError(CalculationKnowledgeAdapterError):
    """Raised when an application-owned binding is invalid."""

    code = "invalid_knowledge_method_binding"


class DuplicateKnowledgeMethodBindingError(CalculationKnowledgeAdapterError):
    """Raised when an allowlist contains an ambiguous binding."""

    code = "duplicate_knowledge_method_binding"


class UnknownKnowledgeMethodBindingError(CalculationKnowledgeAdapterError):
    """Raised when no exact application-owned binding exists."""

    code = "unknown_knowledge_method_binding"


class KnowledgePublicationRequiredError(CalculationKnowledgeAdapterError):
    """Raised when knowledge has not reached the published lifecycle state."""

    code = "knowledge_publication_required"


class KnowledgeCalculationReferenceError(CalculationKnowledgeAdapterError):
    """Raised when a bound calculation reference is absent or ambiguous."""

    code = "knowledge_calculation_reference_error"


class KnowledgeMethodResolutionError(CalculationKnowledgeAdapterError):
    """Raised when the calculation registry rejects a bound method."""

    code = "knowledge_method_resolution_error"


class CalculationResultLinkError(CalculationKnowledgeAdapterError):
    """Raised when a result does not match an approved controlled link."""

    code = "calculation_result_link_error"


class CalculationResultReplayError(CalculationResultLinkError):
    """Raised when exact approved deterministic replay differs from a result."""

    code = "calculation_result_replay_error"


class KnowledgeFingerprintMismatchError(CalculationKnowledgeAdapterError):
    """Raised when published knowledge differs from the bound exact revision."""

    code = "knowledge_fingerprint_mismatch"


class MethodDefinitionFingerprintMismatchError(CalculationKnowledgeAdapterError):
    """Raised when registered method metadata differs from the binding."""

    code = "method_definition_fingerprint_mismatch"


class _ImmutableAdapterModel(BaseModel):
    """Strict immutable configuration shared by adapter boundary models."""

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


class _IdentifierEnvelope(_ImmutableAdapterModel):
    """Internal strict envelope for one external lookup identifier."""

    identifier: ControlledIdentifier


class KnowledgeMethodBinding(_ImmutableAdapterModel):
    """Exact application-owned knowledge-to-method allowlist entry."""

    binding_id: ControlledIdentifier
    knowledge_id: ControlledIdentifier
    knowledge_revision: RevisionText
    calculation_reference_id: ControlledIdentifier
    method_id: ControlledIdentifier
    method_version: StableVersion
    calculation_type: ControlledIdentifier
    engine_version: StableVersion
    knowledge_fingerprint: FingerprintText
    method_definition_fingerprint: FingerprintText


class KnowledgeStandardIdentity(_ImmutableAdapterModel):
    """Non-executable identity metadata for one referenced standard."""

    organisation: BoundedText
    standard_number: BoundedText
    edition: (
        Annotated[
            str,
            StringConstraints(strip_whitespace=True, min_length=1, max_length=100),
        ]
        | None
    ) = None
    publication_year: StrictInt | None = Field(default=None, ge=1800, le=2200)
    clause: (
        Annotated[
            str,
            StringConstraints(strip_whitespace=True, min_length=1, max_length=150),
        ]
        | None
    ) = None
    jurisdiction: (
        Annotated[
            str,
            StringConstraints(strip_whitespace=True, min_length=1, max_length=150),
        ]
        | None
    ) = None


class KnowledgeSafetyIdentity(_ImmutableAdapterModel):
    """Safety-control identity without instruction or expression text."""

    severity: KnowledgeSafetySeverity
    hazard_ids: tuple[ControlledIdentifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LINK_IDENTIFIERS,
    )
    required_site_risk_assessment: StrictBool
    requires_authorised_person: StrictBool
    blocks_work_until_resolved: StrictBool

    @field_validator("hazard_ids")
    @classmethod
    def validate_hazard_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Reject duplicate or case-conflicting hazard identities."""

        _require_unique_identifiers(value, field_name="hazard_ids")
        return value


class ControlledCalculationKnowledgeLink(_ImmutableAdapterModel):
    """Metadata-only link to an executable reviewed calculation method."""

    adapter_version: StableVersion
    binding_id: ControlledIdentifier
    knowledge_id: ControlledIdentifier
    knowledge_revision: RevisionText
    calculation_reference_id: ControlledIdentifier
    method_id: ControlledIdentifier
    method_version: StableVersion
    calculation_type: ControlledIdentifier
    engine_version: StableVersion
    method_lifecycle_status: MethodLifecycleStatus
    knowledge_fingerprint: FingerprintText
    method_definition_fingerprint: FingerprintText
    link_fingerprint: FingerprintText

    knowledge_evidence_ids: tuple[ControlledIdentifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LINK_IDENTIFIERS,
    )
    verified_knowledge_evidence_ids: tuple[ControlledIdentifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LINK_IDENTIFIERS,
    )
    knowledge_standards: tuple[KnowledgeStandardIdentity, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LINK_STANDARDS,
    )
    calculation_standards: tuple[KnowledgeStandardIdentity, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LINK_STANDARDS,
    )
    knowledge_safety: KnowledgeSafetyIdentity | None
    calculation_has_safety_warnings: StrictBool
    knowledge_verification_ids: tuple[ControlledIdentifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LINK_IDENTIFIERS,
    )
    calculation_verification_ids: tuple[ControlledIdentifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LINK_IDENTIFIERS,
    )
    knowledge_formula_ids: tuple[ControlledIdentifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LINK_IDENTIFIERS,
    )
    method_reference_ids: tuple[ControlledIdentifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LINK_IDENTIFIERS,
    )
    verified_method_reference_ids: tuple[ControlledIdentifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LINK_IDENTIFIERS,
    )
    method_safety_requirement_ids: tuple[ControlledIdentifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LINK_IDENTIFIERS,
    )
    method_verification_ids: tuple[ControlledIdentifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LINK_IDENTIFIERS,
    )
    method_formula_ids: tuple[ControlledIdentifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_LINK_IDENTIFIERS,
    )

    @field_validator(
        "knowledge_evidence_ids",
        "verified_knowledge_evidence_ids",
        "knowledge_verification_ids",
        "calculation_verification_ids",
        "knowledge_formula_ids",
        "method_reference_ids",
        "verified_method_reference_ids",
        "method_safety_requirement_ids",
        "method_verification_ids",
        "method_formula_ids",
    )
    @classmethod
    def validate_identifier_collections(
        cls,
        value: tuple[str, ...],
        info: Any,
    ) -> tuple[str, ...]:
        """Reject duplicate or case-conflicting link identifiers."""

        _require_unique_identifiers(value, field_name=info.field_name)
        return value

    @model_validator(mode="after")
    def validate_controlled_link(self) -> ControlledCalculationKnowledgeLink:
        """Require approved lifecycle and internally consistent evidence."""

        if self.method_lifecycle_status is not MethodLifecycleStatus.APPROVED:
            raise ValueError(
                "A controlled calculation link requires an approved method."
            )

        knowledge_evidence = {value.casefold() for value in self.knowledge_evidence_ids}
        if not {
            value.casefold() for value in self.verified_knowledge_evidence_ids
        }.issubset(knowledge_evidence):
            raise ValueError(
                "Verified knowledge evidence must be present in the knowledge "
                "evidence identities."
            )

        method_references = {value.casefold() for value in self.method_reference_ids}
        if not {
            value.casefold() for value in self.verified_method_reference_ids
        }.issubset(method_references):
            raise ValueError(
                "Verified method references must be present in the method "
                "reference identities."
            )

        expected_fingerprint = _fingerprint_payload(
            _LINK_FINGERPRINT_SCHEMA,
            self.model_dump(
                mode="json",
                round_trip=True,
                exclude={"link_fingerprint"},
                warnings="error",
            ),
        )
        if self.link_fingerprint != expected_fingerprint:
            raise ValueError(
                "link_fingerprint does not bind the complete projected "
                "provenance metadata."
            )

        return self

    @property
    def approved_for_execution(self) -> bool:
        """Return the explicit approved-method disposition."""

        return self.method_lifecycle_status is MethodLifecycleStatus.APPROVED

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        """Compatibility view of published-knowledge evidence identities."""

        return self.knowledge_evidence_ids

    @property
    def verified_evidence_ids(self) -> tuple[str, ...]:
        """Compatibility view of verified published-knowledge evidence."""

        return self.verified_knowledge_evidence_ids

    @property
    def standard_identities(self) -> tuple[KnowledgeStandardIdentity, ...]:
        """Return knowledge and calculation standard identities by scope."""

        return (*self.knowledge_standards, *self.calculation_standards)

    @property
    def safety_identity(self) -> KnowledgeSafetyIdentity | None:
        """Compatibility view of published-knowledge safety identity."""

        return self.knowledge_safety


def _revalidate_model[ModelT: BaseModel](
    model_type: type[ModelT],
    value: object,
    *,
    field_name: str,
) -> ModelT:
    """Return a fresh validated model and translate boundary failures."""

    if not isinstance(value, model_type):
        raise CalculationKnowledgeAdapterError(
            f"{field_name} must be a {model_type.__name__}."
        )

    try:
        payload = value.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
        return model_type.model_validate(payload)
    except (TypeError, ValueError, ValidationError) as exc:
        raise CalculationKnowledgeAdapterError(
            f"{field_name} failed controlled model validation."
        ) from exc


def _fingerprint_payload(schema: str, payload: object) -> str:
    """Hash canonical JSON with an explicit schema-domain separator."""

    canonical_bytes = json.dumps(
        {"payload": payload, "schema": schema},
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(canonical_bytes).hexdigest()


def _json_payload(payload: dict[str, object]) -> dict[str, Any]:
    """Serialize prospective model values exactly as Pydantic JSON mode."""

    return TypeAdapter(dict[str, Any]).dump_python(
        payload,
        mode="json",
        round_trip=True,
        warnings="error",
    )


def fingerprint_knowledge(knowledge: EngineeringKnowledge) -> str:
    """Return the canonical fingerprint of a fully revalidated knowledge row."""

    validated = _revalidate_model(
        EngineeringKnowledge,
        knowledge,
        field_name="knowledge",
    )
    return _fingerprint_payload(
        _KNOWLEDGE_FINGERPRINT_SCHEMA,
        validated.model_dump(
            mode="json",
            round_trip=True,
            warnings="error",
        ),
    )


def fingerprint_method_definition(
    definition: CalculationMethodDefinition,
) -> str:
    """Return the canonical fingerprint of reviewed method metadata."""

    validated = _revalidate_model(
        CalculationMethodDefinition,
        definition,
        field_name="method_definition",
    )
    return _fingerprint_payload(
        _METHOD_FINGERPRINT_SCHEMA,
        validated.model_dump(
            mode="json",
            round_trip=True,
            warnings="error",
        ),
    )


def fingerprint_calculation_result(result: CalculationResult) -> str:
    """Bind every field of one fully revalidated calculation result."""

    validated = _revalidate_model(
        CalculationResult,
        result,
        field_name="result",
    )
    return _fingerprint_payload(
        _COMPLETE_RESULT_FINGERPRINT_SCHEMA,
        validated.model_dump(
            mode="json",
            round_trip=True,
            warnings="error",
        ),
    )


def _require_unique_identifiers(
    values: Sequence[str],
    *,
    field_name: str,
) -> None:
    """Require bounded identities to be unique case-insensitively."""

    comparison_values = [value.casefold() for value in values]
    if len(comparison_values) != len(set(comparison_values)):
        raise ValueError(f"{field_name} values must be unique.")


def _require_projected_count(
    values: Sequence[object],
    *,
    maximum: int,
    field_name: str,
) -> None:
    """Reject legacy collections before bounded link projection or hashing."""

    if len(values) > maximum:
        raise KnowledgeCalculationReferenceError(
            f"{field_name} exceed the controlled link bound."
        )


def _preflight_link_projection(
    knowledge: EngineeringKnowledge,
    calculation_reference: EngineeringCalculationReference,
) -> None:
    """Bound every legacy collection projected into one controlled link."""

    _require_projected_count(
        knowledge.evidence,
        maximum=MAX_LINK_IDENTIFIERS,
        field_name="Published knowledge evidence records",
    )
    _require_projected_count(
        knowledge.standards,
        maximum=MAX_LINK_STANDARDS,
        field_name="Published knowledge standards",
    )
    if knowledge.safety is not None:
        _require_projected_count(
            knowledge.safety.hazards,
            maximum=MAX_LINK_IDENTIFIERS,
            field_name="Published knowledge hazards",
        )
    _require_projected_count(
        calculation_reference.formulas,
        maximum=MAX_LINK_IDENTIFIERS,
        field_name="Knowledge calculation formulas",
    )
    combined_verifications = (
        *knowledge.verification_requirements,
        *calculation_reference.verification_requirements,
    )
    _require_projected_count(
        combined_verifications,
        maximum=MAX_LINK_IDENTIFIERS,
        field_name="Knowledge verification records",
    )
    formula_standard_count = sum(
        len(formula.applicable_standards)
        for formula in calculation_reference.formulas
    )
    if formula_standard_count > MAX_LINK_STANDARDS:
        raise KnowledgeCalculationReferenceError(
            "Knowledge formula standards exceed the controlled link bound."
        )


def _combine_unique_identifiers(
    *scopes: Sequence[str],
    field_name: str,
) -> tuple[str, ...]:
    """Combine scoped identifiers while rejecting cross-scope ambiguity."""

    combined = tuple(item for scope in scopes for item in scope)
    try:
        _require_unique_identifiers(combined, field_name=field_name)
    except ValueError as exc:
        raise KnowledgeCalculationReferenceError(str(exc)) from exc
    return combined


def _validate_external_identifier(value: object, *, field_name: str) -> str:
    """Validate an external exact lookup identifier without fallback."""

    try:
        return _IdentifierEnvelope(identifier=value).identifier
    except (TypeError, ValueError, ValidationError) as exc:
        raise KnowledgeCalculationReferenceError(
            f"{field_name} is not a valid controlled identifier."
        ) from exc


def _standard_identity(
    standard: StandardReference,
) -> KnowledgeStandardIdentity:
    """Project one standard to non-executable identity metadata."""

    try:
        return KnowledgeStandardIdentity(
            organisation=standard.organisation,
            standard_number=standard.standard_number,
            edition=standard.edition,
            publication_year=standard.publication_year,
            clause=standard.clause,
            jurisdiction=standard.jurisdiction,
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise KnowledgeCalculationReferenceError(
            "Published knowledge standard metadata cannot form a bounded "
            "controlled link."
        ) from exc


def _unique_standards(
    values: Sequence[KnowledgeStandardIdentity],
) -> tuple[KnowledgeStandardIdentity, ...]:
    """Deduplicate identical standard identities while preserving order."""

    result: list[KnowledgeStandardIdentity] = []
    seen: set[tuple[object, ...]] = set()
    for value in values:
        key = (
            value.organisation,
            value.standard_number,
            value.edition,
            value.publication_year,
            value.clause,
            value.jurisdiction,
        )
        if key not in seen:
            seen.add(key)
            result.append(value)
    return tuple(result)


class ControlledCalculationKnowledgeAdapter:
    """Resolve immutable published-knowledge calculation links."""

    __slots__ = (
        "_bindings",
        "_bindings_by_id",
        "_bindings_by_reference",
        "_locked",
        "_registry",
    )

    ADAPTER_VERSION: Final = KNOWLEDGE_CALCULATION_ADAPTER_VERSION

    def __init__(
        self,
        *,
        registry: CalculationMethodRegistry,
        bindings: Sequence[KnowledgeMethodBinding],
    ) -> None:
        """Build a permanently locked exact binding allowlist."""

        object.__setattr__(self, "_locked", False)
        if not isinstance(registry, CalculationMethodRegistry):
            raise InvalidKnowledgeMethodBindingError(
                "registry must be a CalculationMethodRegistry."
            )
        if isinstance(bindings, (str, bytes)) or not isinstance(bindings, Sequence):
            raise InvalidKnowledgeMethodBindingError(
                "bindings must be an ordered bounded sequence."
            )
        if not bindings or len(bindings) > MAX_KNOWLEDGE_METHOD_BINDINGS:
            raise InvalidKnowledgeMethodBindingError(
                "bindings must contain between 1 and "
                f"{MAX_KNOWLEDGE_METHOD_BINDINGS} entries."
            )

        validated_bindings: list[KnowledgeMethodBinding] = []
        by_id: dict[str, KnowledgeMethodBinding] = {}
        by_reference: dict[
            tuple[str, str, str],
            KnowledgeMethodBinding,
        ] = {}
        folded_ids: set[str] = set()
        folded_references: set[tuple[str, str, str]] = set()

        for candidate in bindings:
            try:
                binding = _revalidate_model(
                    KnowledgeMethodBinding,
                    candidate,
                    field_name="binding",
                )
            except CalculationKnowledgeAdapterError as exc:
                raise InvalidKnowledgeMethodBindingError(str(exc)) from exc

            folded_id = binding.binding_id.casefold()
            exact_reference = (
                binding.knowledge_id,
                binding.knowledge_revision,
                binding.calculation_reference_id,
            )
            folded_reference = tuple(value.casefold() for value in exact_reference)
            if folded_id in folded_ids or folded_reference in folded_references:
                raise DuplicateKnowledgeMethodBindingError(
                    "Knowledge method bindings must have unique IDs and exact "
                    "knowledge revision/reference identities."
                )

            self._resolve_binding_method(registry, binding)
            validated_bindings.append(binding)
            by_id[binding.binding_id] = binding
            by_reference[exact_reference] = binding
            folded_ids.add(folded_id)
            folded_references.add(folded_reference)

        ordered_bindings = tuple(
            sorted(validated_bindings, key=lambda item: item.binding_id)
        )
        object.__setattr__(self, "_registry", registry)
        object.__setattr__(self, "_bindings", ordered_bindings)
        object.__setattr__(
            self,
            "_bindings_by_id",
            MappingProxyType(by_id),
        )
        object.__setattr__(
            self,
            "_bindings_by_reference",
            MappingProxyType(by_reference),
        )
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        """Prevent adapter mutation after construction."""

        if getattr(self, "_locked", False):
            raise AttributeError(
                "ControlledCalculationKnowledgeAdapter instances are immutable."
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """Prevent adapter attribute deletion after construction."""

        if getattr(self, "_locked", False):
            raise AttributeError(
                "ControlledCalculationKnowledgeAdapter instances are immutable."
            )
        object.__delattr__(self, name)

    @property
    def bindings(self) -> tuple[KnowledgeMethodBinding, ...]:
        """Return immutable binding metadata without registry callables."""

        return self._bindings

    def resolve_link(
        self,
        knowledge: EngineeringKnowledge,
        calculation_id: str,
    ) -> ControlledCalculationKnowledgeLink:
        """Resolve one exact published knowledge calculation reference."""

        validated_knowledge = _revalidate_model(
            EngineeringKnowledge,
            knowledge,
            field_name="knowledge",
        )
        if validated_knowledge.status is not KnowledgeStatus.PUBLISHED:
            raise KnowledgePublicationRequiredError(
                "Calculation links require PUBLISHED engineering knowledge."
            )

        normalized_calculation_id = _validate_external_identifier(
            calculation_id,
            field_name="calculation_id",
        )
        reference_key = (
            validated_knowledge.knowledge_id,
            validated_knowledge.revision_metadata.revision,
            normalized_calculation_id,
        )
        binding = self._bindings_by_reference.get(reference_key)
        if binding is None:
            raise UnknownKnowledgeMethodBindingError(
                "No exact application-owned binding exists for the published "
                "knowledge revision and calculation reference."
            )

        _require_projected_count(
            validated_knowledge.calculations,
            maximum=MAX_LINK_IDENTIFIERS,
            field_name="Published knowledge calculation references",
        )
        calculation_reference = self._resolve_calculation_reference(
            validated_knowledge,
            normalized_calculation_id,
        )
        _preflight_link_projection(
            validated_knowledge,
            calculation_reference,
        )
        actual_knowledge_fingerprint = fingerprint_knowledge(validated_knowledge)
        if actual_knowledge_fingerprint != binding.knowledge_fingerprint:
            raise KnowledgeFingerprintMismatchError(
                "The published knowledge content does not match the exact "
                "fingerprint owned by the application binding."
            )

        definition = self._resolve_binding_method(self._registry, binding)

        knowledge_evidence_ids = tuple(
            item.evidence_id for item in validated_knowledge.evidence
        )
        verified_knowledge_evidence_ids = tuple(
            item.evidence_id for item in validated_knowledge.evidence if item.verified
        )
        knowledge_formula_ids = tuple(
            item.formula_id for item in calculation_reference.formulas
        )
        _require_unique_identifiers(
            knowledge_formula_ids,
            field_name="knowledge formula IDs",
        )

        knowledge_safety = None
        if validated_knowledge.safety is not None:
            hazard_ids = tuple(
                item.hazard_id for item in validated_knowledge.safety.hazards
            )
            _require_unique_identifiers(
                hazard_ids,
                field_name="knowledge hazard IDs",
            )
            try:
                knowledge_safety = KnowledgeSafetyIdentity(
                    severity=validated_knowledge.safety.severity,
                    hazard_ids=hazard_ids,
                    required_site_risk_assessment=(
                        validated_knowledge.safety.required_site_risk_assessment
                    ),
                    requires_authorised_person=(
                        validated_knowledge.safety.requires_authorised_person
                    ),
                    blocks_work_until_resolved=(
                        validated_knowledge.safety.blocks_work_until_resolved
                    ),
                )
            except (TypeError, ValueError, ValidationError) as exc:
                raise KnowledgeCalculationReferenceError(
                    "Published knowledge metadata cannot form a bounded "
                    "controlled link."
                ) from exc

        calculation_standards = _unique_standards(
            tuple(
                _standard_identity(standard)
                for formula in calculation_reference.formulas
                for standard in formula.applicable_standards
            )
        )
        knowledge_verification_ids = _combine_unique_identifiers(
            tuple(
                item.verification_id
                for item in validated_knowledge.verification_requirements
            ),
            tuple(
                item.verification_id
                for item in calculation_reference.verification_requirements
            ),
            field_name="knowledge verification IDs",
        )
        calculation_verification_ids = tuple(
            item.verification_id
            for item in calculation_reference.verification_requirements
        )
        link_values: dict[str, object] = {
            "adapter_version": self.ADAPTER_VERSION,
            "binding_id": binding.binding_id,
            "knowledge_id": binding.knowledge_id,
            "knowledge_revision": binding.knowledge_revision,
            "calculation_reference_id": binding.calculation_reference_id,
            "method_id": binding.method_id,
            "method_version": binding.method_version,
            "calculation_type": binding.calculation_type,
            "engine_version": binding.engine_version,
            "method_lifecycle_status": definition.lifecycle_status,
            "knowledge_fingerprint": actual_knowledge_fingerprint,
            "method_definition_fingerprint": (binding.method_definition_fingerprint),
            "knowledge_evidence_ids": knowledge_evidence_ids,
            "verified_knowledge_evidence_ids": (verified_knowledge_evidence_ids),
            "knowledge_standards": tuple(
                _standard_identity(item) for item in validated_knowledge.standards
            ),
            "calculation_standards": calculation_standards,
            "knowledge_safety": knowledge_safety,
            "calculation_has_safety_warnings": bool(
                calculation_reference.safety_warnings
            ),
            "knowledge_verification_ids": knowledge_verification_ids,
            "calculation_verification_ids": calculation_verification_ids,
            "knowledge_formula_ids": knowledge_formula_ids,
            "method_reference_ids": tuple(
                item.reference_id for item in definition.references
            ),
            "verified_method_reference_ids": tuple(
                item.reference_id for item in definition.references if item.verified
            ),
            "method_safety_requirement_ids": tuple(
                item.requirement_id for item in definition.safety_requirements
            ),
            "method_verification_ids": tuple(
                item.verification_id for item in definition.verification_requirements
            ),
            "method_formula_ids": tuple(
                item.formula_identifier for item in definition.formulas
            ),
        }
        try:
            link_fingerprint = _fingerprint_payload(
                _LINK_FINGERPRINT_SCHEMA,
                _json_payload(link_values),
            )
            return ControlledCalculationKnowledgeLink(
                **link_values,
                link_fingerprint=link_fingerprint,
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise KnowledgeCalculationReferenceError(
                "Published knowledge metadata cannot form a bounded "
                "controlled link."
            ) from exc

    def validate_result(
        self,
        link: ControlledCalculationKnowledgeLink,
        result: CalculationResult,
    ) -> CalculationResult:
        """Validate a completed result against one exact controlled link."""

        validated_link = _revalidate_model(
            ControlledCalculationKnowledgeLink,
            link,
            field_name="link",
        )
        binding = self._bindings_by_id.get(validated_link.binding_id)
        if binding is None or not self._link_matches_binding(
            validated_link,
            binding,
        ):
            raise CalculationResultLinkError(
                "The calculation link does not match an application-owned binding."
            )

        definition = self._resolve_binding_method(self._registry, binding)
        validated_result = _revalidate_model(
            CalculationResult,
            result,
            field_name="result",
        )
        expected_identity = (
            binding.calculation_type,
            binding.method_id,
            binding.method_version,
            binding.engine_version,
            definition.lifecycle_status,
        )
        actual_identity = (
            validated_result.calculation_type,
            validated_result.method_id,
            validated_result.method_version,
            validated_result.engine_version,
            validated_result.method_lifecycle_status,
        )
        if actual_identity != expected_identity:
            raise CalculationResultLinkError(
                "The calculation result identity does not match the exact "
                "controlled method binding."
            )
        if validated_result.status not in {
            CalculationStatus.COMPLETED,
            CalculationStatus.COMPLETED_WITH_WARNINGS,
        }:
            raise CalculationResultLinkError(
                "Only completed calculation results can cross the controlled "
                "integration boundary."
            )

        self._validate_deterministic_replay(
            binding=binding,
            definition=definition,
            result=validated_result,
        )

        return validated_result

    def _validate_deterministic_replay(
        self,
        *,
        binding: KnowledgeMethodBinding,
        definition: CalculationMethodDefinition,
        result: CalculationResult,
    ) -> None:
        """Re-execute the exact approved method and require a byte-bound match."""

        method_reference_ids = {
            item.reference_id.casefold() for item in definition.references
        }
        external_references = tuple(
            item
            for item in result.references
            if item.reference_id.casefold() not in method_reference_ids
        )
        method_verification_ids = {
            item.verification_id.casefold()
            for item in definition.verification_requirements
        }
        requested_verification_ids = {
            verification_id.casefold()
            for assumption in result.assumptions
            for verification_id in assumption.verification_requirement_ids
        }
        external_verification_ids = requested_verification_ids - method_verification_ids
        external_verifications = tuple(
            item
            for item in result.verification_requirements
            if item.verification_id.casefold() in external_verification_ids
        )
        if {
            item.verification_id.casefold() for item in external_verifications
        } != external_verification_ids:
            raise CalculationResultReplayError(
                "The calculation result does not contain the external "
                "verification evidence required for deterministic replay."
            )

        try:
            replay_request = CalculationRequest(
                request_id=result.request_id,
                calculation_type=binding.calculation_type,
                method_id=binding.method_id,
                method_version=binding.method_version,
                requested_at=result.executed_at,
                inputs=result.supplied_inputs,
                assumptions=result.assumptions,
                options=result.effective_options,
                reference_ids=tuple(item.reference_id for item in result.references),
            )
            replay_evidence = TrustedExecutionEvidence(
                references=external_references,
                verification_requirements=external_verifications,
            )
            replay_engine = CalculationEngine(
                registry=self._registry,
                engine_version=binding.engine_version,
                clock=lambda: result.executed_at,
                id_factory=lambda: result.calculation_id,
            )
            replayed_result = replay_engine.execute(
                replay_request,
                evidence=replay_evidence,
            )
        except (TypeError, ValueError) as exc:
            raise CalculationResultReplayError(
                "The calculation result could not be reconstructed for exact "
                "approved deterministic replay."
            ) from exc

        if replayed_result != result or fingerprint_calculation_result(
            replayed_result
        ) != fingerprint_calculation_result(result):
            raise CalculationResultReplayError(
                "The calculation result output, trace, or uncertainty differs "
                "from exact approved deterministic replay."
            )

    @staticmethod
    def _resolve_binding_method(
        registry: CalculationMethodRegistry,
        binding: KnowledgeMethodBinding,
    ) -> CalculationMethodDefinition:
        """Resolve approved metadata and discard the private callable binding."""

        try:
            registration = registry.resolve_for_execution(
                binding.method_id,
                binding.method_version,
                engine_version=binding.engine_version,
                calculation_type=binding.calculation_type,
            )
        except MethodRegistryError as exc:
            raise KnowledgeMethodResolutionError(
                "The bound calculation method is not approved and compatible "
                "for the exact engine version."
            ) from exc
        definition = registration.definition
        actual_fingerprint = fingerprint_method_definition(definition)
        if actual_fingerprint != binding.method_definition_fingerprint:
            raise MethodDefinitionFingerprintMismatchError(
                "The registered calculation method metadata does not match "
                "the exact fingerprint owned by the application binding."
            )
        return definition

    @staticmethod
    def _resolve_calculation_reference(
        knowledge: EngineeringKnowledge,
        calculation_id: str,
    ) -> EngineeringCalculationReference:
        """Require exactly one case-sensitive knowledge calculation reference."""

        exact_matches = tuple(
            item
            for item in knowledge.calculations
            if item.calculation_id == calculation_id
        )
        if len(exact_matches) != 1:
            raise KnowledgeCalculationReferenceError(
                "Published knowledge must contain exactly one exact bound "
                "EngineeringCalculationReference."
            )

        casefold_matches = tuple(
            item
            for item in knowledge.calculations
            if item.calculation_id.casefold() == calculation_id.casefold()
        )
        if len(casefold_matches) != 1:
            raise KnowledgeCalculationReferenceError(
                "Knowledge calculation reference IDs must be unique without "
                "case conflicts."
            )
        return exact_matches[0]

    @staticmethod
    def _link_matches_binding(
        link: ControlledCalculationKnowledgeLink,
        binding: KnowledgeMethodBinding,
    ) -> bool:
        """Compare every application-owned identity component exactly."""

        return (
            link.adapter_version == KNOWLEDGE_CALCULATION_ADAPTER_VERSION
            and link.binding_id == binding.binding_id
            and link.knowledge_id == binding.knowledge_id
            and link.knowledge_revision == binding.knowledge_revision
            and link.calculation_reference_id == binding.calculation_reference_id
            and link.method_id == binding.method_id
            and link.method_version == binding.method_version
            and link.calculation_type == binding.calculation_type
            and link.engine_version == binding.engine_version
            and link.knowledge_fingerprint == binding.knowledge_fingerprint
            and link.method_definition_fingerprint
            == binding.method_definition_fingerprint
            and link.method_lifecycle_status is MethodLifecycleStatus.APPROVED
        )


__all__ = [
    "KNOWLEDGE_CALCULATION_ADAPTER_VERSION",
    "CalculationKnowledgeAdapterError",
    "CalculationResultLinkError",
    "CalculationResultReplayError",
    "ControlledCalculationKnowledgeAdapter",
    "ControlledCalculationKnowledgeLink",
    "DuplicateKnowledgeMethodBindingError",
    "InvalidKnowledgeMethodBindingError",
    "KnowledgeCalculationReferenceError",
    "KnowledgeFingerprintMismatchError",
    "KnowledgeMethodBinding",
    "KnowledgeMethodResolutionError",
    "KnowledgePublicationRequiredError",
    "KnowledgeSafetyIdentity",
    "KnowledgeStandardIdentity",
    "MethodDefinitionFingerprintMismatchError",
    "UnknownKnowledgeMethodBindingError",
    "fingerprint_calculation_result",
    "fingerprint_knowledge",
    "fingerprint_method_definition",
]
