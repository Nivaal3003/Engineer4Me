"""Deterministic completeness and revision workflow for Step 109 datasheets.

This service materializes omitted template fields as visible unknowns, validates
strict field types and units, evaluates declarative conditions without dynamic
execution, derives completeness, and appends immutable revision snapshots.
It performs no database access, API work, workbook export, or approval action.
"""

from __future__ import annotations

from datetime import datetime
from types import MappingProxyType
from uuid import UUID, uuid4

from pydantic import ValidationError

from app.engineering.design.datasheet_models import (
    DatasheetAssumptionVerificationState,
    DatasheetCompletenessReport,
    DatasheetCompletenessState,
    DatasheetContent,
    DatasheetCreateCommand,
    DatasheetFieldAssessment,
    DatasheetFieldDisposition,
    DatasheetFieldState,
    DatasheetFieldValue,
    DatasheetHistory,
    DatasheetLifecycleState,
    DatasheetRevisionCreate,
    DatasheetRevisionRecord,
    DatasheetRevisionSnapshot,
    DatasheetTemplateDefinition,
    build_datasheet_completeness_fingerprint,
    derive_blocking_assumption_ids,
    derive_datasheet_field_assessment,
    fingerprint_datasheet_content,
    validate_datasheet_field_value,
)
from app.engineering.design.datasheet_registry import (
    DEFAULT_DATASHEET_TEMPLATE_REGISTRY,
    DatasheetTemplateRegistry,
    DatasheetTemplateRegistryError,
)
from app.engineering.design.persistence_models import (
    normalise_utc,
    utc_now,
)

DATASHEET_LIFECYCLE_TRANSITIONS = MappingProxyType(
    {
        DatasheetLifecycleState.DRAFT: frozenset(DatasheetLifecycleState),
        DatasheetLifecycleState.UNDER_REVIEW: frozenset(DatasheetLifecycleState),
        DatasheetLifecycleState.ON_HOLD: frozenset(DatasheetLifecycleState),
        DatasheetLifecycleState.ARCHIVED: frozenset({DatasheetLifecycleState.ARCHIVED}),
    }
)


class DatasheetServiceError(RuntimeError):
    """Base error for controlled datasheet operations."""


class DatasheetTemplateMismatchError(DatasheetServiceError):
    """Raised when content does not match an exact controlled template."""


class DatasheetFieldValidationError(DatasheetServiceError):
    """Raised when a known field violates its controlled definition."""


class DatasheetConcurrencyError(DatasheetServiceError):
    """Raised when an append command targets a stale revision head."""


class DatasheetLifecycleError(DatasheetServiceError):
    """Raised when an incomplete sheet is moved under review."""


class DatasheetService:
    """Strict, stateless Step 109 datasheet workflow."""

    __slots__ = ("_allow_repository_provenance", "_locked", "_registry")

    def __init__(
        self,
        *,
        registry: DatasheetTemplateRegistry = (DEFAULT_DATASHEET_TEMPLATE_REGISTRY),
        _allow_repository_provenance: bool = False,
    ) -> None:
        if type(registry) is not DatasheetTemplateRegistry:
            raise TypeError("registry must be a DatasheetTemplateRegistry")
        if type(_allow_repository_provenance) is not bool:
            raise TypeError("_allow_repository_provenance must be a boolean")
        object.__setattr__(self, "_locked", False)
        object.__setattr__(self, "_registry", registry)
        object.__setattr__(
            self,
            "_allow_repository_provenance",
            _allow_repository_provenance,
        )
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        """Prevent mutation of shared registry and provenance policy state."""

        if getattr(self, "_locked", False):
            raise AttributeError("DatasheetService instances are immutable")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """Prevent deletion of shared registry and provenance policy state."""

        if getattr(self, "_locked", False):
            raise AttributeError("DatasheetService instances are immutable")
        object.__delattr__(self, name)

    @property
    def registry(self) -> DatasheetTemplateRegistry:
        return self._registry

    @staticmethod
    def _validated_content(content: object) -> DatasheetContent:
        """Revalidate caller content before any shared-service operation."""

        if not isinstance(content, DatasheetContent):
            raise TypeError("content must be a DatasheetContent")
        try:
            return DatasheetContent.model_validate(
                content.model_dump(
                    mode="python",
                    round_trip=True,
                    warnings="error",
                )
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise DatasheetFieldValidationError(
                "datasheet content failed controlled model validation"
            ) from exc

    def resolve_template(
        self, content: DatasheetContent
    ) -> DatasheetTemplateDefinition:
        """Resolve and bind one exact template identity without fallback."""

        content = self._validated_content(content)
        try:
            template = self._registry.resolve(
                template_id=content.template_id,
                template_version=content.template_version,
            )
        except DatasheetTemplateRegistryError as exc:
            raise DatasheetTemplateMismatchError(str(exc)) from exc
        if template.template_fingerprint != content.template_fingerprint:
            raise DatasheetTemplateMismatchError(
                "datasheet template fingerprint does not match the registry"
            )
        return template

    def materialize_unknown_fields(self, content: DatasheetContent) -> DatasheetContent:
        """Return a complete field set, never silently preserving omissions."""

        content = self._validated_content(content)
        template = self.resolve_template(content)
        supplied = {item.field_id.casefold(): item for item in content.field_values}
        template_ids = {item.field_id.casefold() for item in template.fields}
        unexpected = sorted(set(supplied) - template_ids)
        if unexpected:
            raise DatasheetTemplateMismatchError(
                "datasheet contains fields outside its template: "
                + ", ".join(unexpected)
            )
        values: list[DatasheetFieldValue] = []
        for definition in template.fields:
            value = supplied.get(definition.field_id.casefold())
            if value is None:
                value = DatasheetFieldValue(
                    field_id=definition.field_id,
                    state=DatasheetFieldState.UNKNOWN,
                    origin="unknown",
                    unknown_reason="Not supplied for this datasheet revision.",
                )
            elif value.field_id != definition.field_id:
                raise DatasheetTemplateMismatchError(
                    "datasheet field ID capitalization differs from its template"
                )
            try:
                validate_datasheet_field_value(definition, value)
            except ValueError as exc:
                raise DatasheetFieldValidationError(str(exc)) from exc
            values.append(value)
        return content.model_copy(update={"field_values": tuple(values)})

    def evaluate(self, content: DatasheetContent) -> DatasheetRevisionSnapshot:
        """Materialize unknowns and derive one deterministic completeness report."""

        normalized = self.materialize_unknown_fields(content)
        if not self._allow_repository_provenance and any(
            link.repository_provenance_verified for link in normalized.calculation_links
        ):
            raise DatasheetFieldValidationError(
                "repository provenance requires the persistent service boundary"
            )
        template = self.resolve_template(normalized)
        values = {item.field_id: item for item in normalized.field_values}
        definitions = {item.field_id: item for item in template.fields}
        assessments: list[DatasheetFieldAssessment] = []
        for definition in template.fields:
            value = values[definition.field_id]
            assessments.append(
                derive_datasheet_field_assessment(
                    definition=definition,
                    value=value,
                    all_values=values,
                    all_definitions=definitions,
                )
            )
        assessments_tuple = tuple(assessments)
        missing = tuple(
            item.field_id
            for item in assessments_tuple
            if item.disposition is DatasheetFieldDisposition.REQUIRED_MISSING
        )
        unknown = tuple(
            item.field_id
            for item in assessments_tuple
            if item.disposition is DatasheetFieldDisposition.REQUIRED_UNKNOWN
        )
        unconfirmed = tuple(
            item.field_id
            for item in assessments_tuple
            if item.disposition
            is DatasheetFieldDisposition.REQUIRED_VALUE_NOT_CONFIRMED
        )
        calculation_links = {
            item.link_id: item for item in normalized.calculation_links
        }
        unverified_calculations = tuple(
            item.field_id
            for item in normalized.field_values
            if item.state is DatasheetFieldState.KNOWN
            and item.origin.value == "calculated"
            and not calculation_links[
                item.calculation_link_ids[0]
            ].repository_provenance_verified
        )
        unresolved = tuple(
            item.field_id
            for item in assessments_tuple
            if item.disposition is DatasheetFieldDisposition.CONDITIONAL_UNRESOLVED
        )
        optional_open = tuple(
            item.field_id
            for item in assessments_tuple
            if item.disposition
            in {
                DatasheetFieldDisposition.OPTIONAL_MISSING,
                DatasheetFieldDisposition.OPTIONAL_UNKNOWN,
                DatasheetFieldDisposition.CONDITIONAL_VALUE_WHEN_NOT_REQUIRED,
            }
        )
        not_applicable = tuple(
            item.field_id
            for item in assessments_tuple
            if item.disposition is DatasheetFieldDisposition.CONDITIONAL_NOT_APPLICABLE
        )
        unresolved_assumptions = tuple(
            item.assumption_id
            for item in normalized.assumptions
            if item.verification_state
            is DatasheetAssumptionVerificationState.UNRESOLVED
        )
        blocking_assumptions = derive_blocking_assumption_ids(
            template=template,
            content=normalized,
            assessments=assessments_tuple,
        )
        field_blocked = any(item.blocking for item in assessments_tuple)
        incomplete = bool(
            missing or unknown or unconfirmed or unverified_calculations or unresolved
        )
        open_items = bool(optional_open or unresolved_assumptions)
        state = (
            DatasheetCompletenessState.BLOCKED
            if field_blocked or blocking_assumptions or unverified_calculations
            else DatasheetCompletenessState.INCOMPLETE
            if incomplete
            else DatasheetCompletenessState.COMPLETE_WITH_OPEN_ITEMS
            if open_items
            else DatasheetCompletenessState.COMPLETE
        )
        ready_for_review = state in {
            DatasheetCompletenessState.COMPLETE,
            DatasheetCompletenessState.COMPLETE_WITH_OPEN_ITEMS,
        }
        content_fingerprint = fingerprint_datasheet_content(normalized)
        completeness_fingerprint = build_datasheet_completeness_fingerprint(
            template_id=template.template_id,
            template_version=template.template_version,
            template_fingerprint=template.template_fingerprint,
            content_fingerprint=content_fingerprint,
            state=state,
            assessments=assessments_tuple,
            missing_required_field_ids=missing,
            unknown_required_field_ids=unknown,
            unconfirmed_required_field_ids=unconfirmed,
            unverified_calculation_field_ids=unverified_calculations,
            unresolved_conditional_field_ids=unresolved,
            optional_open_field_ids=optional_open,
            not_applicable_field_ids=not_applicable,
            unresolved_assumption_ids=unresolved_assumptions,
            blocking_assumption_ids=blocking_assumptions,
            ready_for_review=ready_for_review,
        )
        report = DatasheetCompletenessReport(
            template_id=template.template_id,
            template_version=template.template_version,
            template_fingerprint=template.template_fingerprint,
            content_fingerprint=content_fingerprint,
            completeness_fingerprint=completeness_fingerprint,
            state=state,
            assessments=assessments_tuple,
            missing_required_field_ids=missing,
            unknown_required_field_ids=unknown,
            unconfirmed_required_field_ids=unconfirmed,
            unverified_calculation_field_ids=unverified_calculations,
            unresolved_conditional_field_ids=unresolved,
            optional_open_field_ids=optional_open,
            not_applicable_field_ids=not_applicable,
            unresolved_assumption_ids=unresolved_assumptions,
            blocking_assumption_ids=blocking_assumptions,
            ready_for_review=ready_for_review,
        )
        return DatasheetRevisionSnapshot(
            template=template,
            content=normalized,
            completeness=report,
        )

    def create_history(
        self,
        command: DatasheetCreateCommand,
        *,
        revision_id: UUID | None = None,
        created_at: datetime | None = None,
    ) -> DatasheetHistory:
        """Create revision one after deriving exact completeness."""

        snapshot = self.evaluate(command.content)
        self._validate_lifecycle(snapshot, predecessor_state=None)
        timestamp = normalise_utc(created_at or utc_now())
        revision = DatasheetRevisionRecord.create(
            revision_id=revision_id or uuid4(),
            datasheet_id=snapshot.content.datasheet_id,
            revision_number=1,
            supersedes_revision_id=None,
            supersedes_revision_fingerprint=None,
            snapshot=snapshot,
            change_reason=command.change_reason,
            created_by=command.created_by,
            creator_origin=command.creator_origin,
            created_at=timestamp,
        )
        return DatasheetHistory(
            datasheet_id=snapshot.content.datasheet_id,
            design_case_id=snapshot.content.design_case_id,
            template_id=snapshot.content.template_id,
            template_version=snapshot.content.template_version,
            template_fingerprint=snapshot.content.template_fingerprint,
            current_revision=1,
            current_revision_fingerprint=revision.revision_fingerprint,
            revisions=(revision,),
        )

    def append_revision(
        self,
        history: DatasheetHistory,
        command: DatasheetRevisionCreate,
        *,
        revision_id: UUID | None = None,
        created_at: datetime | None = None,
    ) -> DatasheetHistory:
        """Append one complete replacement snapshot using exact CAS evidence."""

        trusted_history = DatasheetHistory.model_validate(
            history.model_dump(mode="python", round_trip=True)
        )
        if (
            command.expected_current_revision != trusted_history.current_revision
            or command.expected_current_fingerprint
            != trusted_history.current_revision_fingerprint
        ):
            raise DatasheetConcurrencyError(
                "datasheet revision head changed before this append"
            )
        content = command.content
        if content.datasheet_id != trusted_history.datasheet_id:
            raise DatasheetTemplateMismatchError(
                "revision content belongs to another datasheet"
            )
        if content.design_case_id != trusted_history.design_case_id:
            raise DatasheetTemplateMismatchError(
                "revision content belongs to another design case"
            )
        if (
            content.template_id != trusted_history.template_id
            or content.template_version != trusted_history.template_version
            or content.template_fingerprint != trusted_history.template_fingerprint
        ):
            raise DatasheetTemplateMismatchError(
                "a datasheet revision cannot change its controlled template"
            )
        snapshot = self.evaluate(content)
        predecessor = trusted_history.revisions[-1]
        self._validate_lifecycle(
            snapshot,
            predecessor_state=predecessor.snapshot.content.lifecycle_state,
        )
        timestamp = normalise_utc(created_at or utc_now())
        if timestamp < predecessor.created_at:
            raise DatasheetServiceError(
                "datasheet revision timestamp cannot precede its predecessor"
            )
        revision = DatasheetRevisionRecord.create(
            revision_id=revision_id or uuid4(),
            datasheet_id=content.datasheet_id,
            revision_number=trusted_history.current_revision + 1,
            supersedes_revision_id=predecessor.revision_id,
            supersedes_revision_fingerprint=predecessor.revision_fingerprint,
            snapshot=snapshot,
            change_reason=command.change_reason,
            created_by=command.created_by,
            creator_origin=command.creator_origin,
            created_at=timestamp,
        )
        revisions = (*trusted_history.revisions, revision)
        return DatasheetHistory(
            datasheet_id=trusted_history.datasheet_id,
            design_case_id=trusted_history.design_case_id,
            template_id=trusted_history.template_id,
            template_version=trusted_history.template_version,
            template_fingerprint=trusted_history.template_fingerprint,
            current_revision=revision.revision_number,
            current_revision_fingerprint=revision.revision_fingerprint,
            revisions=revisions,
        )

    def _validate_lifecycle(
        self,
        snapshot: DatasheetRevisionSnapshot,
        *,
        predecessor_state: DatasheetLifecycleState | None,
    ) -> None:
        state = snapshot.content.lifecycle_state
        if predecessor_state is None and state is DatasheetLifecycleState.ARCHIVED:
            raise DatasheetLifecycleError(
                "a datasheet cannot be created directly as archived"
            )
        if (
            predecessor_state is not None
            and state not in DATASHEET_LIFECYCLE_TRANSITIONS[predecessor_state]
        ):
            raise DatasheetLifecycleError(
                "the datasheet lifecycle transition is not permitted"
            )
        if (
            state is DatasheetLifecycleState.UNDER_REVIEW
            and not snapshot.completeness.ready_for_review
        ):
            raise DatasheetLifecycleError(
                "an incomplete or blocked datasheet cannot enter review"
            )


DEFAULT_DATASHEET_SERVICE = DatasheetService()


__all__ = [
    "DATASHEET_LIFECYCLE_TRANSITIONS",
    "DEFAULT_DATASHEET_SERVICE",
    "DatasheetConcurrencyError",
    "DatasheetFieldValidationError",
    "DatasheetLifecycleError",
    "DatasheetService",
    "DatasheetServiceError",
    "DatasheetTemplateMismatchError",
]
