"""Strict Step 110 contracts for durable datasheet records and exports."""

from __future__ import annotations

from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, model_validator

from app.engineering.calculations.models import (
    CalculationModel,
    FingerprintText,
    Identifier,
    ShortText,
    VersionText,
)
from app.engineering.design.datasheet_models import (
    DatasheetCompletenessState,
    DatasheetLifecycleState,
    DatasheetRevisionRecord,
)
from app.engineering.design.persistence_models import (
    DesignApprovalState,
    RecordedIdentityOrigin,
    normalise_utc,
)
from app.engineering.design.xlsx_renderer import DatasheetExportDescriptor


DATASHEET_PERSISTENCE_VERSION = "1.0.0"
DATASHEET_STORED_REVISION_SCHEMA = "engineer4me.datasheet.stored-revision.v1"
MAX_DATASHEET_LIST_LIMIT = 100


class PersistedDatasheetRevision(CalculationModel):
    """One immutable datasheet revision plus verified export checksums."""

    schema_id: Literal["engineer4me.datasheet.stored-revision.v1"] = (
        DATASHEET_STORED_REVISION_SCHEMA
    )
    schema_version: Literal["1.0.0"] = DATASHEET_PERSISTENCE_VERSION
    revision: DatasheetRevisionRecord
    export: DatasheetExportDescriptor
    append_only: Literal[True] = True
    deletion_supported: Literal[False] = False
    approval_state: Literal[DesignApprovalState.UNAPPROVED] = (
        DesignApprovalState.UNAPPROVED
    )
    final_design_approval_granted: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False

    @model_validator(mode="after")
    def validate_export_binding(self) -> Self:
        revision = self.revision
        content = revision.snapshot.content
        completeness = revision.snapshot.completeness
        if (
            self.export.datasheet_id != revision.datasheet_id
            or self.export.datasheet_revision_id != revision.revision_id
            or self.export.design_case_id != content.design_case_id
            or self.export.design_revision_id != content.design_revision_id
            or self.export.design_revision_number != content.design_revision_number
            or self.export.design_revision_fingerprint
            != content.design_revision_fingerprint
            or self.export.datasheet_revision_number != revision.revision_number
            or self.export.datasheet_revision_fingerprint
            != revision.revision_fingerprint
            or self.export.template_id != content.template_id
            or self.export.template_version != content.template_version
            or self.export.template_fingerprint != content.template_fingerprint
            or self.export.content_fingerprint != completeness.content_fingerprint
            or self.export.completeness_fingerprint
            != completeness.completeness_fingerprint
        ):
            raise ValueError("datasheet export descriptor is bound to another revision")
        return self


class PersistedDatasheetRecord(CalculationModel):
    """Stable datasheet identity and its exact current immutable revision."""

    datasheet_id: UUID
    design_case_id: UUID
    template_id: Identifier
    template_version: VersionText
    template_fingerprint: FingerprintText
    current_revision: StrictInt = Field(ge=1, le=100)
    current_revision_fingerprint: FingerprintText
    concurrency_version: StrictInt = Field(ge=1, le=100)
    created_by: ShortText
    creator_origin: Literal[RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED] = (
        RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED
    )
    created_at: AwareDatetime
    updated_at: AwareDatetime
    current: PersistedDatasheetRevision
    approval_state: Literal[DesignApprovalState.UNAPPROVED] = (
        DesignApprovalState.UNAPPROVED
    )
    final_design_approval_granted: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False

    @model_validator(mode="after")
    def validate_head(self) -> Self:
        revision = self.current.revision
        content = revision.snapshot.content
        if (
            revision.datasheet_id != self.datasheet_id
            or content.design_case_id != self.design_case_id
            or content.template_id != self.template_id
            or content.template_version != self.template_version
            or content.template_fingerprint != self.template_fingerprint
            or revision.revision_number != self.current_revision
            or revision.revision_fingerprint != self.current_revision_fingerprint
            or self.concurrency_version != self.current_revision
        ):
            raise ValueError("datasheet identity or current revision head drifted")
        created_at = normalise_utc(self.created_at)
        updated_at = normalise_utc(self.updated_at)
        if updated_at < created_at or updated_at != revision.created_at:
            raise ValueError("datasheet head timestamps are inconsistent")
        return self


class DatasheetSummary(CalculationModel):
    """Bounded list projection without the complete engineering snapshot."""

    datasheet_id: UUID
    design_case_id: UUID
    template_id: Identifier
    template_version: VersionText
    title: ShortText
    lifecycle_state: DatasheetLifecycleState
    completeness_state: DatasheetCompletenessState
    ready_for_review: StrictBool
    current_revision: StrictInt = Field(ge=1, le=100)
    current_revision_fingerprint: FingerprintText
    workbook_sha256: FingerprintText
    updated_at: AwareDatetime
    approval_state: Literal[DesignApprovalState.UNAPPROVED] = (
        DesignApprovalState.UNAPPROVED
    )
    final_design_approval_granted: Literal[False] = False


class DatasheetPage(CalculationModel):
    """Stable paged response for one design case's datasheets."""

    items: tuple[DatasheetSummary, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_LIST_LIMIT,
    )
    offset: StrictInt = Field(ge=0, le=1_000_000)
    limit: StrictInt = Field(ge=1, le=MAX_DATASHEET_LIST_LIMIT)
    total: StrictInt = Field(ge=0, le=1_000_000_000)

    @model_validator(mode="after")
    def validate_page(self) -> Self:
        if len(self.items) > self.limit or self.total < len(self.items):
            raise ValueError("datasheet page counts are inconsistent")
        return self


class DatasheetRevisionSummary(CalculationModel):
    """List-safe metadata for one immutable datasheet revision."""

    revision_id: UUID
    datasheet_id: UUID
    revision_number: StrictInt = Field(ge=1, le=100)
    revision_fingerprint: FingerprintText
    design_revision_number: StrictInt = Field(ge=1, le=1_000_000)
    design_revision_fingerprint: FingerprintText
    title: ShortText
    lifecycle_state: DatasheetLifecycleState
    completeness_state: DatasheetCompletenessState
    ready_for_review: StrictBool
    json_sha256: FingerprintText
    workbook_sha256: FingerprintText
    created_by: ShortText
    creator_origin: Literal[RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED] = (
        RecordedIdentityOrigin.CALLER_SUPPLIED_UNVERIFIED
    )
    created_at: AwareDatetime
    approval_state: Literal[DesignApprovalState.UNAPPROVED] = (
        DesignApprovalState.UNAPPROVED
    )
    final_design_approval_granted: Literal[False] = False


class DatasheetRevisionPage(CalculationModel):
    """Stable paged response for immutable datasheet revision metadata."""

    items: tuple[DatasheetRevisionSummary, ...] = Field(
        default_factory=tuple,
        max_length=MAX_DATASHEET_LIST_LIMIT,
    )
    offset: StrictInt = Field(ge=0, le=1_000_000)
    limit: StrictInt = Field(ge=1, le=MAX_DATASHEET_LIST_LIMIT)
    total: StrictInt = Field(ge=0, le=100)

    @model_validator(mode="after")
    def validate_page(self) -> Self:
        if len(self.items) > self.limit or self.total < len(self.items):
            raise ValueError("datasheet revision page counts are inconsistent")
        return self


__all__ = [
    "DATASHEET_PERSISTENCE_VERSION",
    "DATASHEET_STORED_REVISION_SCHEMA",
    "MAX_DATASHEET_LIST_LIMIT",
    "DatasheetPage",
    "DatasheetRevisionPage",
    "DatasheetRevisionSummary",
    "DatasheetSummary",
    "PersistedDatasheetRecord",
    "PersistedDatasheetRevision",
]
