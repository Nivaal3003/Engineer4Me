"""Strict Step 108 contracts for design revisions and persisted runs.

The models in this module describe the public, immutable persistence boundary.
They do not perform database access.  Results can be persisted only after a
trusted Engineer4Me service has executed the originating calculation or
analyzer assessment; no public contract accepts a caller-supplied result.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal, Self
from uuid import UUID, uuid4

from pydantic import (
    AwareDatetime,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    model_validator,
)

from app.engineering.calculations.engine import (
    ATTEMPT_FINGERPRINT_SCHEMA,
    FINGERPRINT_SCHEMA,
    build_attempt_fingerprint_payload,
    build_fingerprint_payload,
    canonical_fingerprint_bytes,
    fingerprint_payload,
)
from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
    TrustedExecutionEvidence,
)
from app.engineering.calculations.models import (
    CalculationModel,
    CalculationRequest,
    CalculationResult,
    CalculationStatus,
    FingerprintText,
    Identifier,
    InputOrigin,
    LongText,
    ShortText,
    TextItem,
    VersionText,
)
from app.engineering.design.analyzer_models import AnalyzerApplicationRequest
from app.engineering.design.analyzer_workflow_models import AnalyzerAssessmentEnvelope


DESIGN_PERSISTENCE_VERSION = "1.0.0"
DESIGN_REVISION_SCHEMA = "engineer4me.design.revision.v1"
CALCULATION_RUN_SCHEMA = "engineer4me.persistence.calculation-run.v1"
ANALYZER_RUN_SCHEMA = "engineer4me.persistence.analyzer-run.v1"
RUN_CANONICALIZATION = "engineer4me.canonical-json.sha256.v1"
CALCULATION_EXECUTOR_ID = "engineering_calculation_engine"
ANALYZER_CALCULATION_TYPE = "analyzer_application"
ANALYZER_METHOD_ID = "analyzer_application_assistant"
ANALYZER_EXECUTOR_ID = "analyzer_application_workflow"
MAX_DESIGN_COLLECTION_ITEMS = 64
MAX_DESIGN_LIST_LIMIT = 100
MAX_RUN_LIST_LIMIT = 100

CaseReference = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=2,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{1,159}$",
    ),
]
ContextValue = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=4_000,
    ),
]
UnitText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=64,
    ),
]
CanonicalFingerprintBasis = Annotated[
    str,
    StringConstraints(
        min_length=2,
        max_length=1_000_000,
        pattern=r"^\{.*\}$",
    ),
]


class DesignLifecycleState(StrEnum):
    """Non-approval lifecycle states available in Step 108."""

    DRAFT = "draft"
    UNDER_REVIEW = "under_review"
    ON_HOLD = "on_hold"
    ARCHIVED = "archived"


class DesignApprovalState(StrEnum):
    """Step 108 deliberately stores no engineering approval."""

    UNAPPROVED = "unapproved"


class RecordedIdentityOrigin(StrEnum):
    """Provenance of actor text until authentication is implemented."""

    CALLER_SUPPLIED_UNVERIFIED = "caller_supplied_unverified"


class EngineeringRunKind(StrEnum):
    """Trusted execution types supported by the append-only run store."""

    CALCULATION = "calculation"
    ANALYZER_ASSESSMENT = "analyzer_assessment"


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(UTC)


def normalise_utc(value: datetime) -> datetime:
    """Normalize aware timestamps and fail closed on naive values."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must include a UTC offset")
    return value.astimezone(UTC)


def canonical_utc_text(value: datetime) -> str:
    """Return the timestamp representation used by persistence fingerprints."""

    return (
        normalise_utc(value)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def fingerprint_persistence_payload(value: object) -> str:
    """Return a lowercase SHA-256 over canonical JSON-compatible content."""

    if isinstance(value, CalculationModel):
        value = value.model_dump(mode="json", round_trip=True, warnings="error")
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _canonical_models(values, *, attribute: str):
    ordered = tuple(sorted(values, key=lambda item: str(getattr(item, attribute))))
    identifiers = [str(getattr(item, attribute)).casefold() for item in ordered]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"{attribute} values must be unique")
    return ordered


def _canonical_text(values: tuple[str, ...], *, field_name: str) -> tuple[str, ...]:
    ordered = tuple(sorted(values, key=str.casefold))
    if len({value.casefold() for value in ordered}) != len(ordered):
        raise ValueError(f"{field_name} values must be unique")
    return ordered


class DesignSourceOrigin(CalculationModel):
    """One bounded source record attached to a complete design revision."""

    source_id: Identifier
    origin: InputOrigin
    description: LongText
    reference_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DESIGN_COLLECTION_ITEMS,
    )

    def model_post_init(self, __context: object) -> None:
        object.__setattr__(
            self,
            "reference_ids",
            _canonical_text(self.reference_ids, field_name="reference_ids"),
        )


class DesignContextItem(CalculationModel):
    """One explicit plant or equipment context value."""

    field_id: Identifier
    label: ShortText
    value: ContextValue
    unit: UnitText | None = None
    origin: InputOrigin
    source_origin_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DESIGN_COLLECTION_ITEMS,
    )

    def model_post_init(self, __context: object) -> None:
        object.__setattr__(
            self,
            "source_origin_ids",
            _canonical_text(
                self.source_origin_ids,
                field_name="source_origin_ids",
            ),
        )


class DesignAssumption(CalculationModel):
    """One visible unresolved or accepted design assumption."""

    assumption_id: Identifier
    statement: LongText
    source_origin_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DESIGN_COLLECTION_ITEMS,
    )

    def model_post_init(self, __context: object) -> None:
        object.__setattr__(
            self,
            "source_origin_ids",
            _canonical_text(
                self.source_origin_ids,
                field_name="source_origin_ids",
            ),
        )


class DesignVerification(CalculationModel):
    """One required verification retained with the revision."""

    verification_id: Identifier
    action: LongText
    responsible_discipline: ShortText | None = None
    safety_critical: StrictBool = False
    source_origin_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DESIGN_COLLECTION_ITEMS,
    )

    def model_post_init(self, __context: object) -> None:
        object.__setattr__(
            self,
            "source_origin_ids",
            _canonical_text(
                self.source_origin_ids,
                field_name="source_origin_ids",
            ),
        )


class DesignRevisionPayload(CalculationModel):
    """Complete replacement snapshot stored for every design revision."""

    schema_id: Literal["engineer4me.design.revision.v1"] = DESIGN_REVISION_SCHEMA
    schema_version: Literal["1.0.0"] = DESIGN_PERSISTENCE_VERSION
    title: ShortText
    discipline: Identifier
    industry: ShortText | None = None
    lifecycle_state: DesignLifecycleState = DesignLifecycleState.DRAFT
    plant_context: tuple[DesignContextItem, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DESIGN_COLLECTION_ITEMS,
    )
    equipment_context: tuple[DesignContextItem, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DESIGN_COLLECTION_ITEMS,
    )
    source_origins: tuple[DesignSourceOrigin, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DESIGN_COLLECTION_ITEMS,
    )
    open_assumptions: tuple[DesignAssumption, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DESIGN_COLLECTION_ITEMS,
    )
    required_verifications: tuple[DesignVerification, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DESIGN_COLLECTION_ITEMS,
    )
    approval_state: Literal[DesignApprovalState.UNAPPROVED] = (
        DesignApprovalState.UNAPPROVED
    )
    final_design_approval_granted: Literal[False] = False

    def model_post_init(self, __context: object) -> None:
        for field_name, attribute in (
            ("plant_context", "field_id"),
            ("equipment_context", "field_id"),
            ("source_origins", "source_id"),
            ("open_assumptions", "assumption_id"),
            ("required_verifications", "verification_id"),
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_models(getattr(self, field_name), attribute=attribute),
            )

    @model_validator(mode="after")
    def validate_links(self) -> Self:
        source_ids = {item.source_id for item in self.source_origins}
        context_ids = [
            item.field_id.casefold()
            for item in (*self.plant_context, *self.equipment_context)
        ]
        if len(context_ids) != len(set(context_ids)):
            raise ValueError("plant and equipment context IDs must be unique")
        for collection in (
            self.plant_context,
            self.equipment_context,
            self.open_assumptions,
            self.required_verifications,
        ):
            for item in collection:
                if not set(item.source_origin_ids).issubset(source_ids):
                    raise ValueError("revision payload links an unknown source origin")
        return self


class DesignCaseCreate(CalculationModel):
    """Create one permanent design identity and its initial snapshot."""

    case_reference: CaseReference
    case_type: Identifier
    payload: DesignRevisionPayload
    change_reason: TextItem
    created_by: ShortText
    creator_origin: Literal[
        RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED
    ] = RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED


class DesignCaseRevisionCreate(CalculationModel):
    """Append a complete design snapshot using optimistic concurrency."""

    expected_current_revision: StrictInt = Field(ge=1, le=1_000_000)
    expected_current_fingerprint: FingerprintText
    payload: DesignRevisionPayload
    change_reason: TextItem
    created_by: ShortText
    creator_origin: Literal[
        RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED
    ] = RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED


def build_design_revision_fingerprint(
    *,
    revision_id: UUID,
    design_case_id: UUID,
    case_reference: str,
    case_type: str,
    revision_number: int,
    supersedes_revision_id: UUID | None,
    supersedes_revision_fingerprint: str | None,
    payload: DesignRevisionPayload,
    change_reason: str,
    created_by: str,
    creator_origin: RecordedIdentityOrigin,
    created_at: datetime,
) -> str:
    """Fingerprint every immutable revision identity and content field."""

    return fingerprint_persistence_payload(
        {
            "schema": DESIGN_REVISION_SCHEMA,
            "revision_id": str(revision_id),
            "design_case_id": str(design_case_id),
            "case_reference": case_reference,
            "case_type": case_type,
            "revision_number": revision_number,
            "supersedes_revision_id": (
                str(supersedes_revision_id)
                if supersedes_revision_id is not None
                else None
            ),
            "supersedes_revision_fingerprint": (
                supersedes_revision_fingerprint
            ),
            "payload": payload.model_dump(
                mode="json",
                round_trip=True,
                warnings="error",
            ),
            "change_reason": change_reason,
            "created_by": created_by,
            "creator_origin": creator_origin.value,
            "created_at": canonical_utc_text(created_at),
        }
    )


class DesignCaseRevisionRecord(CalculationModel):
    """One immutable, complete, fingerprinted design revision."""

    revision_id: UUID = Field(default_factory=uuid4)
    design_case_id: UUID
    case_reference: CaseReference
    case_type: Identifier
    revision_number: StrictInt = Field(ge=1, le=1_000_000)
    supersedes_revision_id: UUID | None = None
    supersedes_revision_fingerprint: FingerprintText | None = None
    payload: DesignRevisionPayload
    revision_fingerprint: FingerprintText
    change_reason: TextItem
    created_by: ShortText
    creator_origin: RecordedIdentityOrigin = (
        RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED
    )
    created_at: AwareDatetime = Field(default_factory=utc_now)
    append_only: Literal[True] = True

    @classmethod
    def create(
        cls,
        *,
        revision_id: UUID,
        design_case_id: UUID,
        case_reference: str,
        case_type: str,
        revision_number: int,
        supersedes_revision_id: UUID | None,
        supersedes_revision_fingerprint: str | None,
        payload: DesignRevisionPayload,
        change_reason: str,
        created_by: str,
        creator_origin: RecordedIdentityOrigin,
        created_at: datetime,
    ) -> "DesignCaseRevisionRecord":
        fingerprint = build_design_revision_fingerprint(
            revision_id=revision_id,
            design_case_id=design_case_id,
            case_reference=case_reference,
            case_type=case_type,
            revision_number=revision_number,
            supersedes_revision_id=supersedes_revision_id,
            supersedes_revision_fingerprint=supersedes_revision_fingerprint,
            payload=payload,
            change_reason=change_reason,
            created_by=created_by,
            creator_origin=creator_origin,
            created_at=created_at,
        )
        return cls(
            revision_id=revision_id,
            design_case_id=design_case_id,
            case_reference=case_reference,
            case_type=case_type,
            revision_number=revision_number,
            supersedes_revision_id=supersedes_revision_id,
            supersedes_revision_fingerprint=supersedes_revision_fingerprint,
            payload=payload,
            revision_fingerprint=fingerprint,
            change_reason=change_reason,
            created_by=created_by,
            creator_origin=creator_origin,
            created_at=created_at,
        )

    def model_post_init(self, __context: object) -> None:
        object.__setattr__(self, "created_at", normalise_utc(self.created_at))

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        predecessor_values = (
            self.supersedes_revision_id,
            self.supersedes_revision_fingerprint,
        )
        if any(value is None for value in predecessor_values) and any(
            value is not None for value in predecessor_values
        ):
            raise ValueError("revision predecessor linkage must be complete")
        if (self.revision_number == 1) is not all(
            value is None for value in predecessor_values
        ):
            raise ValueError("only revision one may omit a predecessor")
        expected = build_design_revision_fingerprint(
            revision_id=self.revision_id,
            design_case_id=self.design_case_id,
            case_reference=self.case_reference,
            case_type=self.case_type,
            revision_number=self.revision_number,
            supersedes_revision_id=self.supersedes_revision_id,
            supersedes_revision_fingerprint=(
                self.supersedes_revision_fingerprint
            ),
            payload=self.payload,
            change_reason=self.change_reason,
            created_by=self.created_by,
            creator_origin=self.creator_origin,
            created_at=self.created_at,
        )
        if self.revision_fingerprint != expected:
            raise ValueError("revision_fingerprint is stale")
        return self


class DesignCaseRecord(CalculationModel):
    """Permanent design-case head with its current immutable revision."""

    design_case_id: UUID
    case_reference: CaseReference
    case_type: Identifier
    current_revision: StrictInt = Field(ge=1, le=1_000_000)
    current_revision_fingerprint: FingerprintText
    concurrency_version: StrictInt = Field(ge=1, le=1_000_000)
    created_by: ShortText
    creator_origin: RecordedIdentityOrigin
    created_at: AwareDatetime
    updated_at: AwareDatetime
    revision: DesignCaseRevisionRecord
    permanent_identity: Literal[True] = True
    deletion_supported: Literal[False] = False

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        if self.revision.design_case_id != self.design_case_id:
            raise ValueError("current revision belongs to another design case")
        if self.revision.case_reference != self.case_reference:
            raise ValueError("current revision case_reference drifted")
        if self.revision.case_type != self.case_type:
            raise ValueError("current revision case_type drifted")
        if self.revision.revision_number != self.current_revision:
            raise ValueError("current revision number drifted")
        if self.revision.revision_fingerprint != self.current_revision_fingerprint:
            raise ValueError("current revision fingerprint drifted")
        if self.concurrency_version != self.current_revision:
            raise ValueError("concurrency version drifted from dense revisions")
        created = normalise_utc(self.created_at)
        updated = normalise_utc(self.updated_at)
        if updated < created:
            raise ValueError("updated_at cannot precede created_at")
        if updated != self.revision.created_at:
            raise ValueError("updated_at must equal the current revision timestamp")
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "updated_at", updated)
        return self


class DesignCaseSummary(CalculationModel):
    """Current design identity without its confidential revision payload."""

    design_case_id: UUID
    case_reference: CaseReference
    case_type: Identifier
    title: ShortText
    lifecycle_state: DesignLifecycleState
    current_revision: StrictInt = Field(ge=1, le=1_000_000)
    current_revision_fingerprint: FingerprintText
    concurrency_version: StrictInt = Field(ge=1, le=1_000_000)
    updated_at: AwareDatetime

    @model_validator(mode="after")
    def normalize_timestamp(self) -> Self:
        object.__setattr__(self, "updated_at", normalise_utc(self.updated_at))
        return self


class DesignCasePage(CalculationModel):
    """Bounded design-case list without confidential revision payloads."""

    items: tuple[DesignCaseSummary, ...] = Field(max_length=MAX_DESIGN_LIST_LIMIT)
    offset: StrictInt = Field(ge=0)
    limit: StrictInt = Field(ge=1, le=MAX_DESIGN_LIST_LIMIT)
    total: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def validate_page(self) -> Self:
        if len(self.items) > self.limit or self.total < len(self.items):
            raise ValueError("design-case page counts are inconsistent")
        return self


class DesignRevisionSummary(CalculationModel):
    """Revision identity without the complete snapshot payload."""

    revision_id: UUID
    design_case_id: UUID
    revision_number: StrictInt = Field(ge=1, le=1_000_000)
    supersedes_revision_id: UUID | None
    supersedes_revision_fingerprint: FingerprintText | None
    title: ShortText
    lifecycle_state: DesignLifecycleState
    revision_fingerprint: FingerprintText
    change_reason: TextItem
    created_by: ShortText
    creator_origin: RecordedIdentityOrigin
    created_at: AwareDatetime
    approval_state: Literal[DesignApprovalState.UNAPPROVED] = (
        DesignApprovalState.UNAPPROVED
    )
    final_design_approval_granted: Literal[False] = False

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        predecessor = (
            self.supersedes_revision_id,
            self.supersedes_revision_fingerprint,
        )
        if any(value is None for value in predecessor) and any(
            value is not None for value in predecessor
        ):
            raise ValueError("revision predecessor summary is incomplete")
        object.__setattr__(self, "created_at", normalise_utc(self.created_at))
        return self


class DesignRevisionPage(CalculationModel):
    """Bounded revision history without complete snapshot payloads."""

    items: tuple[DesignRevisionSummary, ...] = Field(
        max_length=MAX_DESIGN_LIST_LIMIT
    )
    offset: StrictInt = Field(ge=0)
    limit: StrictInt = Field(ge=1, le=MAX_DESIGN_LIST_LIMIT)
    total: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def validate_page(self) -> Self:
        if len(self.items) > self.limit or self.total < len(self.items):
            raise ValueError("design-revision page counts are inconsistent")
        return self


class CalculationRunPayload(CalculationModel):
    """Trusted calculation request/result pair created by the server."""

    kind: Literal[EngineeringRunKind.CALCULATION] = EngineeringRunKind.CALCULATION
    schema_id: Literal[
        "engineer4me.persistence.calculation-run.v1"
    ] = CALCULATION_RUN_SCHEMA
    request: CalculationRequest
    method_definition: CalculationMethodDefinition
    result: CalculationResult
    execution_fingerprint: FingerprintText
    fingerprint_basis_json: CanonicalFingerprintBasis

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if self.result.request_id != self.request.request_id:
            raise ValueError("calculation result request_id drifted")
        for field_name in ("calculation_type", "method_id", "method_version"):
            if getattr(self.result, field_name) != getattr(self.request, field_name):
                raise ValueError(f"calculation result {field_name} drifted")
            if getattr(self.method_definition, field_name) != getattr(
                self.request,
                field_name,
            ):
                raise ValueError(f"calculation definition {field_name} drifted")
        if self.execution_fingerprint != self.result.result_fingerprint:
            raise ValueError("calculation execution fingerprint drifted")
        try:
            basis = json.loads(self.fingerprint_basis_json)
        except (TypeError, ValueError) as exc:
            raise ValueError("calculation fingerprint basis is invalid JSON") from exc
        if not isinstance(basis, dict):
            raise ValueError("calculation fingerprint basis must be an object")
        canonical = canonical_fingerprint_bytes(basis).decode("utf-8")
        if canonical != self.fingerprint_basis_json:
            raise ValueError("calculation fingerprint basis is not canonical")
        if fingerprint_payload(basis) != self.result.result_fingerprint:
            raise ValueError("calculation fingerprint basis is stale")
        method = basis.get("method")
        if not isinstance(method, dict) or method != {
            "method_id": self.result.method_id,
            "method_version": self.result.method_version,
        }:
            raise ValueError("calculation fingerprint method identity drifted")
        if basis.get("fingerprint_schema") not in {
            FINGERPRINT_SCHEMA,
            ATTEMPT_FINGERPRINT_SCHEMA,
        }:
            raise ValueError("calculation fingerprint schema is unsupported")
        return self


class AnalyzerRunPayload(CalculationModel):
    """Trusted Step 107 assessment wrapped without mutating its semantics."""

    kind: Literal[EngineeringRunKind.ANALYZER_ASSESSMENT] = (
        EngineeringRunKind.ANALYZER_ASSESSMENT
    )
    schema_id: Literal[
        "engineer4me.persistence.analyzer-run.v1"
    ] = ANALYZER_RUN_SCHEMA
    envelope: AnalyzerAssessmentEnvelope
    execution_fingerprint: FingerprintText

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if self.execution_fingerprint != self.envelope.integration_fingerprint:
            raise ValueError("analyzer execution fingerprint drifted")
        if self.envelope.persistence_performed:
            raise ValueError("the stateless analyzer envelope must remain unmodified")
        return self


EngineeringRunPayload = Annotated[
    CalculationRunPayload | AnalyzerRunPayload,
    Field(discriminator="kind"),
]


class EngineeringExecutionMetadata(CalculationModel):
    """Searchable execution identity included in the immutable run hash."""

    calculation_type: Identifier
    method_id: Identifier
    method_version: VersionText
    executor_id: Identifier
    executor_version: VersionText
    status: CalculationStatus


def engineering_execution_metadata(
    payload: CalculationRunPayload | AnalyzerRunPayload,
) -> EngineeringExecutionMetadata:
    """Derive exact searchable metadata from the typed execution payload."""

    if isinstance(payload, CalculationRunPayload):
        return EngineeringExecutionMetadata(
            calculation_type=payload.result.calculation_type,
            method_id=payload.result.method_id,
            method_version=payload.result.method_version,
            executor_id=CALCULATION_EXECUTOR_ID,
            executor_version=payload.result.engine_version,
            status=payload.result.status,
        )
    return EngineeringExecutionMetadata(
        calculation_type=ANALYZER_CALCULATION_TYPE,
        method_id=ANALYZER_METHOD_ID,
        method_version=payload.envelope.assistant_version,
        executor_id=ANALYZER_EXECUTOR_ID,
        executor_version=payload.envelope.workflow_version,
        status=payload.envelope.assessment.status,
    )


def calculation_input_fingerprint(request: CalculationRequest) -> str:
    return fingerprint_persistence_payload(
        {
            "schema": "engineer4me.persistence.calculation-request.v1",
            "request": request.model_dump(
                mode="json",
                round_trip=True,
                warnings="error",
                exclude={
                    "request_id",
                    "requested_at",
                    "requested_by",
                    "design_case_id",
                    "correlation_id",
                },
            ),
        }
    )


def build_calculation_fingerprint_basis(
    *,
    definition: CalculationMethodDefinition,
    request: CalculationRequest,
    result: CalculationResult,
    evidence: TrustedExecutionEvidence,
) -> str:
    """Capture the exact canonical engine basis before durable persistence."""

    if result.request_id != request.request_id:
        raise ValueError("calculation result request_id drifted")
    for field_name in ("calculation_type", "method_id", "method_version"):
        if getattr(result, field_name) != getattr(request, field_name):
            raise ValueError(f"calculation result {field_name} drifted")
        if getattr(definition, field_name) != getattr(request, field_name):
            raise ValueError(f"calculation definition {field_name} drifted")
    normalized_ids = {item.input_id.casefold() for item in result.normalized_inputs}
    supplied_ids = {item.input_id.casefold() for item in request.inputs}
    required_ids = {
        item.input_id.casefold()
        for item in definition.input_specifications
        if item.presence.value in {"required", "defaulted"}
    }
    effective_option_ids = {
        item.option_id.casefold() for item in result.effective_options
    }
    supplied_option_ids = {item.option_id.casefold() for item in request.options}
    normalized_complete = (
        supplied_ids.issubset(normalized_ids)
        and required_ids.issubset(normalized_ids)
        and supplied_option_ids.issubset(effective_option_ids)
    )
    candidates: list[dict[str, object]] = []
    if normalized_complete:
        candidates.append(
            build_fingerprint_payload(
                method_id=definition.method_id,
                method_version=definition.method_version,
                normalized_inputs=result.normalized_inputs,
                effective_options=result.effective_options,
                assumptions=result.assumptions,
                references=result.references,
                verification_requirements=(
                    evidence.verification_requirements
                ),
                status=result.status,
                finding_ids=tuple(item.finding_id for item in result.findings),
                missing_input_ids=tuple(
                    item.input_id for item in result.missing_inputs
                ),
            )
        )
    dispositions = {
        result.status.value,
        "engine_incompatible",
        "execution_failed",
        "lifecycle_blocked",
    }
    candidates.extend(
        build_attempt_fingerprint_payload(
            definition=definition,
            request=request,
            disposition=disposition,
            evidence=evidence,
            finding_ids=tuple(item.finding_id for item in result.findings),
        )
        for disposition in dispositions
    )
    matched = {
        canonical_fingerprint_bytes(candidate).decode("utf-8")
        for candidate in candidates
        if fingerprint_payload(candidate) == result.result_fingerprint
    }
    if len(matched) != 1:
        raise ValueError("calculation result fingerprint cannot be reproduced")
    return matched.pop()


def verify_calculation_result_fingerprint(
    *,
    definition: CalculationMethodDefinition,
    request: CalculationRequest,
    result: CalculationResult,
    evidence: TrustedExecutionEvidence,
    fingerprint_basis_json: str,
) -> None:
    """Verify both the trusted execution and its stored canonical basis."""

    expected = build_calculation_fingerprint_basis(
        definition=definition,
        request=request,
        result=result,
        evidence=evidence,
    )
    if fingerprint_basis_json != expected:
        raise ValueError("stored calculation fingerprint basis drifted")


def build_engineering_run_fingerprint(
    *,
    run_id: UUID,
    design_case_id: UUID | None,
    design_revision_id: UUID | None,
    design_revision_number: int | None,
    design_revision_fingerprint: str | None,
    supersedes_run_id: UUID | None,
    supersedes_run_fingerprint: str | None,
    payload: CalculationRunPayload | AnalyzerRunPayload,
    execution_metadata: EngineeringExecutionMetadata,
    input_fingerprint: str,
    result_fingerprint: str,
    created_by: str,
    creator_origin: RecordedIdentityOrigin,
    recorded_at: datetime,
) -> str:
    return fingerprint_persistence_payload(
        {
            "schema": "engineer4me.persistence.engineering-run-record.v1",
            "run_id": str(run_id),
            "design_case_id": str(design_case_id) if design_case_id else None,
            "design_revision_id": (
                str(design_revision_id) if design_revision_id else None
            ),
            "design_revision_number": design_revision_number,
            "design_revision_fingerprint": design_revision_fingerprint,
            "supersedes_run_id": (
                str(supersedes_run_id) if supersedes_run_id else None
            ),
            "supersedes_run_fingerprint": supersedes_run_fingerprint,
            "payload": payload.model_dump(
                mode="json", round_trip=True, warnings="error"
            ),
            "execution_metadata": execution_metadata.model_dump(
                mode="json", round_trip=True, warnings="error"
            ),
            "input_fingerprint": input_fingerprint,
            "result_fingerprint": result_fingerprint,
            "created_by": created_by,
            "creator_origin": creator_origin.value,
            "recorded_at": canonical_utc_text(recorded_at),
            "canonicalization": RUN_CANONICALIZATION,
        }
    )


class EngineeringRunRecord(CalculationModel):
    """Immutable outer record proving subsequent durable persistence."""

    run_id: UUID = Field(default_factory=uuid4)
    design_case_id: UUID | None = None
    design_revision_id: UUID | None = None
    design_revision_number: StrictInt | None = Field(
        default=None,
        ge=1,
        le=1_000_000,
    )
    design_revision_fingerprint: FingerprintText | None = None
    supersedes_run_id: UUID | None = None
    supersedes_run_fingerprint: FingerprintText | None = None
    payload: EngineeringRunPayload
    execution_metadata: EngineeringExecutionMetadata
    input_fingerprint: FingerprintText
    result_fingerprint: FingerprintText
    run_fingerprint: FingerprintText
    canonicalization: Literal[
        "engineer4me.canonical-json.sha256.v1"
    ] = RUN_CANONICALIZATION
    created_by: ShortText
    creator_origin: RecordedIdentityOrigin = (
        RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED
    )
    recorded_at: AwareDatetime = Field(default_factory=utc_now)
    append_only: Literal[True] = True
    persistence_performed: Literal[True] = True
    final_design_approval_granted: Literal[False] = False

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        linked = (
            self.design_case_id,
            self.design_revision_id,
            self.design_revision_number,
            self.design_revision_fingerprint,
        )
        if any(value is None for value in linked) and any(
            value is not None for value in linked
        ):
            raise ValueError("design run linkage must be complete or absent")
        if self.supersedes_run_id == self.run_id:
            raise ValueError("a run cannot supersede itself")
        predecessor = (
            self.supersedes_run_id,
            self.supersedes_run_fingerprint,
        )
        if any(value is None for value in predecessor) and any(
            value is not None for value in predecessor
        ):
            raise ValueError("run predecessor linkage must be complete")
        expected_metadata = engineering_execution_metadata(self.payload)
        if self.execution_metadata != expected_metadata:
            raise ValueError("execution metadata drifted from the run payload")
        if isinstance(self.payload, CalculationRunPayload):
            self.payload.validate_binding()
            expected_input = calculation_input_fingerprint(self.payload.request)
            expected_result = self.payload.result.result_fingerprint
            if self.payload.request.design_case_id != self.design_case_id:
                raise ValueError("calculation request design_case_id drifted")
        else:
            self.payload.validate_binding()
            expected_input = self.payload.envelope.request_fingerprint
            expected_result = self.payload.execution_fingerprint
        if self.input_fingerprint != expected_input:
            raise ValueError("input_fingerprint is stale")
        if self.result_fingerprint != expected_result:
            raise ValueError("result_fingerprint is stale")
        expected_run = build_engineering_run_fingerprint(
            run_id=self.run_id,
            design_case_id=self.design_case_id,
            design_revision_id=self.design_revision_id,
            design_revision_number=self.design_revision_number,
            design_revision_fingerprint=self.design_revision_fingerprint,
            supersedes_run_id=self.supersedes_run_id,
            supersedes_run_fingerprint=self.supersedes_run_fingerprint,
            payload=self.payload,
            execution_metadata=self.execution_metadata,
            input_fingerprint=self.input_fingerprint,
            result_fingerprint=self.result_fingerprint,
            created_by=self.created_by,
            creator_origin=self.creator_origin,
            recorded_at=self.recorded_at,
        )
        if self.run_fingerprint != expected_run:
            raise ValueError("run_fingerprint is stale")
        object.__setattr__(self, "recorded_at", normalise_utc(self.recorded_at))
        return self


class EngineeringRunSummary(CalculationModel):
    """Searchable run identity without process input or result snapshots."""

    run_id: UUID
    run_kind: EngineeringRunKind
    design_case_id: UUID | None
    design_revision_number: StrictInt | None = Field(
        default=None,
        ge=1,
        le=1_000_000,
    )
    design_revision_fingerprint: FingerprintText | None = None
    supersedes_run_id: UUID | None = None
    supersedes_run_fingerprint: FingerprintText | None = None
    calculation_type: Identifier
    method_id: Identifier
    method_version: VersionText
    executor_id: Identifier
    executor_version: VersionText
    status: CalculationStatus
    input_fingerprint: FingerprintText
    result_fingerprint: FingerprintText
    run_fingerprint: FingerprintText
    created_by: ShortText
    creator_origin: RecordedIdentityOrigin
    recorded_at: AwareDatetime
    append_only: Literal[True] = True
    persistence_performed: Literal[True] = True
    final_design_approval_granted: Literal[False] = False

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        linked = (
            self.design_case_id,
            self.design_revision_number,
            self.design_revision_fingerprint,
        )
        if any(value is None for value in linked) and any(
            value is not None for value in linked
        ):
            raise ValueError("run summary design linkage is incomplete")
        predecessor = (
            self.supersedes_run_id,
            self.supersedes_run_fingerprint,
        )
        if any(value is None for value in predecessor) and any(
            value is not None for value in predecessor
        ):
            raise ValueError("run summary predecessor linkage is incomplete")
        object.__setattr__(self, "recorded_at", normalise_utc(self.recorded_at))
        return self


class EngineeringRunPage(CalculationModel):
    """Bounded append-only run history."""

    items: tuple[EngineeringRunSummary, ...] = Field(max_length=MAX_RUN_LIST_LIMIT)
    offset: StrictInt = Field(ge=0)
    limit: StrictInt = Field(ge=1, le=MAX_RUN_LIST_LIMIT)
    total: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def validate_page(self) -> Self:
        if len(self.items) > self.limit or self.total < len(self.items):
            raise ValueError("engineering-run page counts are inconsistent")
        return self


class DesignCalculationExecutionCommand(CalculationModel):
    """Execute and append one controlled calculation to an exact revision."""

    design_revision_number: StrictInt = Field(ge=1, le=1_000_000)
    calculation: CalculationRequest
    created_by: ShortText
    supersedes_run_id: UUID | None = None
    creator_origin: Literal[
        RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED
    ] = RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED


class DesignAnalyzerAssessmentCommand(CalculationModel):
    """Assess and append one analyzer request to an exact design revision."""

    design_revision_number: StrictInt = Field(ge=1, le=1_000_000)
    request: AnalyzerApplicationRequest
    created_by: ShortText
    supersedes_run_id: UUID | None = None
    creator_origin: Literal[
        RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED
    ] = RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED


class PersistedCalculationExecution(CalculationModel):
    """Typed trusted calculation result and its append-only record."""

    result: CalculationResult
    run: EngineeringRunRecord
    persistence_performed: Literal[True] = True

    @model_validator(mode="after")
    def validate_response(self) -> Self:
        if not isinstance(self.run.payload, CalculationRunPayload):
            raise ValueError("persisted calculation response has the wrong run kind")
        if self.run.payload.result != self.result:
            raise ValueError("persisted calculation result drifted from its run")
        return self


class PersistedAnalyzerAssessment(CalculationModel):
    """Typed analyzer envelope and its separate durable outer record."""

    assessment: AnalyzerAssessmentEnvelope
    run: EngineeringRunRecord
    persistence_performed: Literal[True] = True

    @model_validator(mode="after")
    def validate_response(self) -> Self:
        if not isinstance(self.run.payload, AnalyzerRunPayload):
            raise ValueError("persisted analyzer response has the wrong run kind")
        if self.run.payload.envelope != self.assessment:
            raise ValueError("persisted analyzer assessment drifted from its run")
        return self


__all__ = [
    "ANALYZER_RUN_SCHEMA",
    "ANALYZER_CALCULATION_TYPE",
    "ANALYZER_EXECUTOR_ID",
    "ANALYZER_METHOD_ID",
    "CALCULATION_RUN_SCHEMA",
    "CALCULATION_EXECUTOR_ID",
    "DESIGN_PERSISTENCE_VERSION",
    "DESIGN_REVISION_SCHEMA",
    "MAX_DESIGN_LIST_LIMIT",
    "MAX_RUN_LIST_LIMIT",
    "RUN_CANONICALIZATION",
    "AnalyzerRunPayload",
    "CalculationRunPayload",
    "DesignAnalyzerAssessmentCommand",
    "DesignApprovalState",
    "DesignAssumption",
    "DesignCalculationExecutionCommand",
    "DesignCaseCreate",
    "DesignCasePage",
    "DesignCaseRecord",
    "DesignCaseSummary",
    "DesignCaseRevisionCreate",
    "DesignCaseRevisionRecord",
    "DesignContextItem",
    "DesignLifecycleState",
    "DesignRevisionPage",
    "DesignRevisionPayload",
    "DesignRevisionSummary",
    "DesignSourceOrigin",
    "DesignVerification",
    "EngineeringRunKind",
    "EngineeringExecutionMetadata",
    "EngineeringRunPage",
    "EngineeringRunPayload",
    "EngineeringRunRecord",
    "EngineeringRunSummary",
    "PersistedAnalyzerAssessment",
    "PersistedCalculationExecution",
    "RecordedIdentityOrigin",
    "build_design_revision_fingerprint",
    "build_calculation_fingerprint_basis",
    "build_engineering_run_fingerprint",
    "calculation_input_fingerprint",
    "canonical_utc_text",
    "engineering_execution_metadata",
    "fingerprint_persistence_payload",
    "normalise_utc",
    "utc_now",
    "verify_calculation_result_fingerprint",
]
