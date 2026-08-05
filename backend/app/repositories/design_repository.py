"""Transactional repositories for Step 108 design persistence.

Only the design-case head is mutable.  Revisions and engineering runs expose
append operations and detached, fully revalidated reads; there are no update,
upsert, or delete repository methods for historical records.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.orm.exc import StaleDataError

from app.engineering.calculations.models import (
    CalculationRequest,
    CalculationResult,
)
from app.engineering.design.analyzer_workflow_models import (
    AnalyzerAssessmentEnvelope,
)
from app.engineering.design.persistence_models import (
    ANALYZER_RUN_SCHEMA,
    CALCULATION_RUN_SCHEMA,
    AnalyzerRunPayload,
    CalculationRunPayload,
    DesignApprovalState,
    DesignCaseRecord,
    DesignCaseRevisionRecord,
    DesignRevisionPayload,
    EngineeringRunKind,
    EngineeringRunRecord,
    EngineeringExecutionMetadata,
    RecordedIdentityOrigin,
    engineering_execution_metadata,
)
from app.models.calculation_run import CalculationRun
from app.models.design_case import DesignCase, DesignCaseRevision


CALCULATION_REQUEST_SCHEMA = "engineer4me.calculation.request.v1"
CALCULATION_RESULT_SCHEMA = "engineer4me.calculation.result.v1"
ANALYZER_REQUEST_SCHEMA = "engineer4me.analyzer.application-request.v1"
ANALYZER_RESULT_SCHEMA = "engineer4me.analyzer.assessment-envelope.v1"


class DesignRepositoryError(RuntimeError):
    """Sanitized persistence failure."""


class DesignCaseNotFoundError(DesignRepositoryError):
    """A permanent design identity does not exist."""


class DesignRevisionNotFoundError(DesignRepositoryError):
    """An exact design revision does not exist."""


class EngineeringRunNotFoundError(DesignRepositoryError):
    """An append-only engineering run does not exist."""


class DesignPersistenceConflictError(DesignRepositoryError):
    """A uniqueness, linkage, or optimistic-concurrency guard failed."""


class DesignPersistenceCorruptionError(DesignRepositoryError):
    """Stored bytes failed the complete typed or fingerprinted contract."""


def _json_document(value) -> dict[str, object]:
    document = value.model_dump(mode="json", round_trip=True, warnings="error")
    if not isinstance(document, dict):
        raise TypeError("persisted model documents must be JSON objects")
    return document


def _aware_utc(value: datetime) -> datetime:
    # SQLite returns naive values even for DateTime(timezone=True). PostgreSQL
    # returns aware values. Treat only the SQLite representation as UTC when
    # hydrating a record that was written from an aware server-owned time.
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _revision_loader():
    return joinedload(DesignCaseRevision.design_case)


def _run_loader():
    return joinedload(CalculationRun.design_case_revision).joinedload(
        DesignCaseRevision.design_case
    )


class DesignRepository:
    """Bound, request-scoped repository for cases, revisions, and runs."""

    __slots__ = ("_session",)

    def __init__(self, session: Session) -> None:
        if not isinstance(session, Session):
            raise TypeError("session must be a SQLAlchemy Session")
        self._session = session

    @staticmethod
    def _revision_record(
        row: DesignCaseRevision,
        case: DesignCase,
    ) -> DesignCaseRevisionRecord:
        try:
            payload = DesignRevisionPayload.model_validate(row.snapshot)
            stored_sources = tuple(row.source_origins)
            expected_sources = tuple(
                item.model_dump(mode="json", round_trip=True, warnings="error")
                for item in payload.source_origins
            )
            if stored_sources != expected_sources:
                raise ValueError("stored source-origin projection drifted")
            return DesignCaseRevisionRecord(
                revision_id=row.id,
                design_case_id=row.design_case_id,
                case_reference=case.case_reference,
                case_type=case.case_type,
                revision_number=row.revision_number,
                supersedes_revision_id=row.prior_revision_id,
                supersedes_revision_fingerprint=(
                    row.prior_revision_fingerprint
                ),
                payload=payload,
                revision_fingerprint=row.revision_fingerprint,
                change_reason=row.change_reason,
                created_by=row.created_by,
                creator_origin=RecordedIdentityOrigin(row.creator_origin),
                created_at=_aware_utc(row.created_at),
            )
        except Exception as exc:
            raise DesignPersistenceCorruptionError(
                "A stored design revision failed integrity validation."
            ) from exc

    @classmethod
    def _case_record(
        cls,
        row: DesignCase,
        revision_row: DesignCaseRevision | None,
    ) -> DesignCaseRecord:
        try:
            if revision_row is None:
                raise ValueError("the current design revision is unavailable")
            if (
                revision_row.design_case_id != row.id
                or revision_row.revision_number != row.current_revision
            ):
                raise ValueError("the current design revision linkage drifted")
            revision = cls._revision_record(revision_row, row)
            return DesignCaseRecord(
                design_case_id=row.id,
                case_reference=row.case_reference,
                case_type=row.case_type,
                current_revision=row.current_revision,
                current_revision_fingerprint=row.current_revision_fingerprint,
                concurrency_version=row.concurrency_version,
                created_by=row.created_by,
                creator_origin=RecordedIdentityOrigin(row.creator_origin),
                created_at=_aware_utc(row.created_at),
                updated_at=_aware_utc(row.updated_at),
                revision=revision,
            )
        except DesignPersistenceCorruptionError:
            raise
        except Exception as exc:
            raise DesignPersistenceCorruptionError(
                "A stored design-case head failed integrity validation."
            ) from exc

    @staticmethod
    def _run_payload(row: CalculationRun):
        metadata = row.execution_metadata
        if not isinstance(metadata, dict):
            raise ValueError("run execution metadata must be an object")
        execution_fingerprint = metadata.get("execution_fingerprint")
        payload_schema = metadata.get("payload_schema")
        payload_kind = metadata.get("payload_kind")
        if row.run_kind == EngineeringRunKind.CALCULATION.value:
            if (
                payload_kind != EngineeringRunKind.CALCULATION.value
                or payload_schema != CALCULATION_RUN_SCHEMA
                or row.request_schema != CALCULATION_REQUEST_SCHEMA
                or row.result_schema != CALCULATION_RESULT_SCHEMA
            ):
                raise ValueError("calculation run schema metadata drifted")
            payload = CalculationRunPayload(
                request=CalculationRequest.model_validate(row.request_payload),
                method_definition=metadata.get("method_definition"),
                result=CalculationResult.model_validate(row.result_payload),
                execution_fingerprint=execution_fingerprint,
                fingerprint_basis_json=metadata.get("fingerprint_basis_json"),
            )
        elif row.run_kind == EngineeringRunKind.ANALYZER_ASSESSMENT.value:
            if (
                payload_kind != EngineeringRunKind.ANALYZER_ASSESSMENT.value
                or payload_schema != ANALYZER_RUN_SCHEMA
                or row.request_schema != ANALYZER_REQUEST_SCHEMA
                or row.result_schema != ANALYZER_RESULT_SCHEMA
            ):
                raise ValueError("analyzer run schema metadata drifted")
            envelope = AnalyzerAssessmentEnvelope.model_validate(row.result_payload)
            if _json_document(envelope.assessment.request) != row.request_payload:
                raise ValueError("analyzer request projection drifted")
            payload = AnalyzerRunPayload(
                envelope=envelope,
                execution_fingerprint=execution_fingerprint,
            )
        else:
            raise ValueError("unknown engineering run kind")
        expected = engineering_execution_metadata(payload)
        actual = EngineeringExecutionMetadata(
            calculation_type=row.calculation_type,
            method_id=row.method_id,
            method_version=row.method_version,
            executor_id=row.executor_id,
            executor_version=row.executor_version,
            status=row.status,
        )
        if actual != expected:
            raise ValueError("searchable execution metadata drifted")
        expected_executed_at = (
            payload.result.executed_at
            if isinstance(payload, CalculationRunPayload)
            else row.created_at
        )
        if _aware_utc(row.executed_at) != _aware_utc(expected_executed_at):
            raise ValueError("execution timestamp projection drifted")
        return payload

    @classmethod
    def _run_record(cls, row: CalculationRun) -> EngineeringRunRecord:
        try:
            payload = cls._run_payload(row)
            revision = row.design_case_revision
            case = revision.design_case if revision is not None else None
            return EngineeringRunRecord(
                run_id=row.id,
                design_case_id=case.id if case is not None else None,
                design_revision_id=revision.id if revision is not None else None,
                design_revision_number=(
                    revision.revision_number if revision is not None else None
                ),
                design_revision_fingerprint=row.design_revision_fingerprint,
                supersedes_run_id=row.supersedes_run_id,
                supersedes_run_fingerprint=row.supersedes_run_fingerprint,
                payload=payload,
                execution_metadata=engineering_execution_metadata(payload),
                input_fingerprint=row.input_fingerprint,
                result_fingerprint=row.result_fingerprint,
                run_fingerprint=row.run_fingerprint,
                canonicalization=row.canonicalization,
                created_by=row.created_by,
                creator_origin=RecordedIdentityOrigin(row.creator_origin),
                recorded_at=_aware_utc(row.created_at),
            )
        except Exception as exc:
            if isinstance(exc, DesignPersistenceCorruptionError):
                raise
            raise DesignPersistenceCorruptionError(
                "A stored engineering run failed integrity validation."
            ) from exc

    def create_case(self, record: DesignCaseRecord) -> DesignCaseRecord:
        revision = record.revision
        case_row = DesignCase(
            id=record.design_case_id,
            case_reference=record.case_reference,
            case_type=record.case_type,
            current_revision=record.current_revision,
            current_revision_fingerprint=record.current_revision_fingerprint,
            concurrency_version=record.concurrency_version,
            created_by=record.created_by,
            creator_origin=record.creator_origin.value,
            created_at=record.created_at,
            updated_at=record.updated_at,
        )
        revision_row = DesignCaseRevision(
            id=revision.revision_id,
            design_case_id=record.design_case_id,
            revision_number=revision.revision_number,
            prior_revision_id=revision.supersedes_revision_id,
            prior_revision_fingerprint=(
                revision.supersedes_revision_fingerprint
            ),
            change_reason=revision.change_reason,
            payload_schema=revision.payload.schema_id,
            payload_version=revision.payload.schema_version,
            snapshot=_json_document(revision.payload),
            source_origins=[
                _json_document(item) for item in revision.payload.source_origins
            ],
            revision_fingerprint=revision.revision_fingerprint,
            approval_state=DesignApprovalState.UNAPPROVED.value,
            final_design_approval_granted=False,
            created_by=revision.created_by,
            creator_origin=revision.creator_origin.value,
            created_at=revision.created_at,
        )
        case_row.revisions.append(revision_row)
        try:
            self._session.add(case_row)
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise DesignPersistenceConflictError(
                "The design identity or initial revision already exists."
            ) from exc
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise DesignRepositoryError(
                "The design case could not be persisted."
            ) from exc
        return self.get_case(record.design_case_id)

    def append_revision(
        self,
        record: DesignCaseRevisionRecord,
        *,
        expected_current_revision: int,
        expected_current_fingerprint: str,
    ) -> DesignCaseRecord:
        try:
            case_row = self._session.scalar(
                select(DesignCase)
                .where(DesignCase.id == record.design_case_id)
                .with_for_update()
            )
            if case_row is None:
                raise DesignCaseNotFoundError("The design case was not found.")
            if (
                case_row.current_revision != expected_current_revision
                or case_row.current_revision_fingerprint
                != expected_current_fingerprint
            ):
                raise DesignPersistenceConflictError(
                    "The design case has changed since it was read."
                )
            prior = self._session.scalar(
                select(DesignCaseRevision).where(
                    DesignCaseRevision.design_case_id == case_row.id,
                    DesignCaseRevision.revision_number
                    == expected_current_revision,
                )
            )
            if prior is None:
                raise DesignPersistenceCorruptionError(
                    "The current design revision is unavailable."
                )
            if (
                record.case_reference != case_row.case_reference
                or record.case_type != case_row.case_type
                or record.revision_number != expected_current_revision + 1
                or record.supersedes_revision_id != prior.id
                or record.supersedes_revision_fingerprint
                != prior.revision_fingerprint
            ):
                raise DesignPersistenceConflictError(
                    "The new revision does not extend the current design head."
                )
            revision_row = DesignCaseRevision(
                id=record.revision_id,
                design_case_id=record.design_case_id,
                revision_number=record.revision_number,
                prior_revision_id=record.supersedes_revision_id,
                prior_revision_fingerprint=(
                    record.supersedes_revision_fingerprint
                ),
                change_reason=record.change_reason,
                payload_schema=record.payload.schema_id,
                payload_version=record.payload.schema_version,
                snapshot=_json_document(record.payload),
                source_origins=[
                    _json_document(item) for item in record.payload.source_origins
                ],
                revision_fingerprint=record.revision_fingerprint,
                approval_state=DesignApprovalState.UNAPPROVED.value,
                final_design_approval_granted=False,
                created_by=record.created_by,
                creator_origin=record.creator_origin.value,
                created_at=record.created_at,
            )
            self._session.add(revision_row)
            case_row.current_revision = record.revision_number
            case_row.current_revision_fingerprint = record.revision_fingerprint
            case_row.updated_at = record.created_at
            self._session.flush()
        except (DesignCaseNotFoundError, DesignPersistenceConflictError):
            self._session.rollback()
            raise
        except DesignPersistenceCorruptionError:
            self._session.rollback()
            raise
        except (IntegrityError, StaleDataError) as exc:
            self._session.rollback()
            raise DesignPersistenceConflictError(
                "The design case changed during revision creation."
            ) from exc
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise DesignRepositoryError(
                "The design revision could not be persisted."
            ) from exc
        return self.get_case(record.design_case_id)

    def commit_write(self) -> None:
        """Commit a service-verified write and translate database failures."""

        try:
            self._session.commit()
        except (IntegrityError, StaleDataError) as exc:
            self._session.rollback()
            raise DesignPersistenceConflictError(
                "The design transaction failed an integrity guard."
            ) from exc
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise DesignRepositoryError(
                "The design transaction could not be committed."
            ) from exc

    def rollback_write(self) -> None:
        """Roll back the current design unit of work."""

        self._session.rollback()

    def get_case(self, design_case_id: UUID) -> DesignCaseRecord:
        try:
            result = self._session.execute(
                select(DesignCase, DesignCaseRevision)
                .outerjoin(
                    DesignCaseRevision,
                    (
                        DesignCaseRevision.design_case_id == DesignCase.id
                    )
                    & (
                        DesignCaseRevision.revision_number
                        == DesignCase.current_revision
                    ),
                )
                .where(DesignCase.id == design_case_id)
            ).one_or_none()
        except SQLAlchemyError as exc:
            raise DesignRepositoryError(
                "The design case could not be read."
            ) from exc
        if result is None:
            raise DesignCaseNotFoundError("The design case was not found.")
        case_row, revision_row = result
        return self._case_record(case_row, revision_row)

    def list_cases(
        self,
        *,
        offset: int,
        limit: int,
    ) -> tuple[tuple[DesignCaseRecord, ...], int]:
        try:
            total = self._session.scalar(select(func.count(DesignCase.id))) or 0
            rows = self._session.execute(
                select(DesignCase, DesignCaseRevision)
                .outerjoin(
                    DesignCaseRevision,
                    (
                        DesignCaseRevision.design_case_id == DesignCase.id
                    )
                    & (
                        DesignCaseRevision.revision_number
                        == DesignCase.current_revision
                    ),
                )
                .order_by(DesignCase.updated_at.desc(), DesignCase.id)
                .offset(offset)
                .limit(limit)
            ).all()
            return (
                tuple(
                    self._case_record(case_row, revision_row)
                    for case_row, revision_row in rows
                ),
                int(total),
            )
        except DesignPersistenceCorruptionError:
            raise
        except SQLAlchemyError as exc:
            raise DesignRepositoryError(
                "Design cases could not be listed."
            ) from exc

    def get_revision(
        self,
        design_case_id: UUID,
        revision_number: int,
    ) -> DesignCaseRevisionRecord:
        try:
            row = self._session.scalar(
                select(DesignCaseRevision)
                .options(_revision_loader())
                .where(
                    DesignCaseRevision.design_case_id == design_case_id,
                    DesignCaseRevision.revision_number == revision_number,
                )
            )
        except SQLAlchemyError as exc:
            raise DesignRepositoryError(
                "The design revision could not be read."
            ) from exc
        if row is None:
            if self._session.get(DesignCase, design_case_id) is None:
                raise DesignCaseNotFoundError("The design case was not found.")
            raise DesignRevisionNotFoundError(
                "The exact design revision was not found."
            )
        return self._revision_record(row, row.design_case)

    def list_revisions(
        self,
        design_case_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> tuple[tuple[DesignCaseRevisionRecord, ...], int]:
        if self._session.get(DesignCase, design_case_id) is None:
            raise DesignCaseNotFoundError("The design case was not found.")
        try:
            criteria = DesignCaseRevision.design_case_id == design_case_id
            total = self._session.scalar(
                select(func.count(DesignCaseRevision.id)).where(criteria)
            ) or 0
            rows = self._session.scalars(
                select(DesignCaseRevision)
                .options(_revision_loader())
                .where(criteria)
                .order_by(DesignCaseRevision.revision_number.desc())
                .offset(offset)
                .limit(limit)
            ).all()
            return (
                tuple(self._revision_record(row, row.design_case) for row in rows),
                int(total),
            )
        except DesignPersistenceCorruptionError:
            raise
        except SQLAlchemyError as exc:
            raise DesignRepositoryError(
                "Design revisions could not be listed."
            ) from exc

    def append_run(self, record: EngineeringRunRecord) -> EngineeringRunRecord:
        payload = record.payload
        metadata = engineering_execution_metadata(payload)
        if record.execution_metadata != metadata:
            raise DesignPersistenceConflictError(
                "The engineering run metadata is stale."
            )
        revision_row = None
        if record.design_revision_id is not None:
            revision_row = self._session.scalar(
                select(DesignCaseRevision)
                .options(_revision_loader())
                .where(DesignCaseRevision.id == record.design_revision_id)
            )
            if revision_row is None:
                raise DesignRevisionNotFoundError(
                    "The exact design revision was not found."
                )
            if (
                revision_row.design_case_id != record.design_case_id
                or revision_row.revision_number != record.design_revision_number
                or revision_row.revision_fingerprint
                != record.design_revision_fingerprint
            ):
                raise DesignPersistenceConflictError(
                    "The engineering run design linkage is stale."
                )
        if record.supersedes_run_id is not None:
            predecessor = self._session.scalar(
                select(CalculationRun)
                .options(_run_loader())
                .where(CalculationRun.id == record.supersedes_run_id)
            )
            if predecessor is None:
                raise EngineeringRunNotFoundError(
                    "The superseded engineering run was not found."
                )
            predecessor_case_id = (
                predecessor.design_case_revision.design_case_id
                if predecessor.design_case_revision is not None
                else None
            )
            if (
                predecessor.run_kind != record.payload.kind.value
                or predecessor_case_id != record.design_case_id
                or predecessor.run_fingerprint
                != record.supersedes_run_fingerprint
                or predecessor.calculation_type
                != metadata.calculation_type
                or predecessor.method_id != metadata.method_id
                or predecessor.method_version
                != metadata.method_version
                or predecessor.executor_id
                != metadata.executor_id
                or predecessor.executor_version
                != metadata.executor_version
            ):
                raise DesignPersistenceConflictError(
                    "The superseded run belongs to another execution history."
                )
        if isinstance(payload, CalculationRunPayload):
            request_schema = CALCULATION_REQUEST_SCHEMA
            result_schema = CALCULATION_RESULT_SCHEMA
            request_payload = _json_document(payload.request)
            result_payload = _json_document(payload.result)
            executed_at = payload.result.executed_at
            payload_metadata = {
                "payload_kind": payload.kind.value,
                "payload_schema": payload.schema_id,
                "execution_fingerprint": payload.execution_fingerprint,
                "method_definition": _json_document(
                    payload.method_definition
                ),
                "fingerprint_basis_json": payload.fingerprint_basis_json,
            }
        elif isinstance(payload, AnalyzerRunPayload):
            request_schema = ANALYZER_REQUEST_SCHEMA
            result_schema = ANALYZER_RESULT_SCHEMA
            request_payload = _json_document(payload.envelope.assessment.request)
            result_payload = _json_document(payload.envelope)
            executed_at = record.recorded_at
            payload_metadata = {
                "payload_kind": payload.kind.value,
                "payload_schema": payload.schema_id,
                "execution_fingerprint": payload.execution_fingerprint,
            }
        else:  # pragma: no cover - the discriminated model prevents this
            raise TypeError("unsupported engineering run payload")

        row = CalculationRun(
            id=record.run_id,
            run_kind=payload.kind.value,
            design_case_revision_id=record.design_revision_id,
            supersedes_run_id=record.supersedes_run_id,
            design_revision_fingerprint=record.design_revision_fingerprint,
            supersedes_run_fingerprint=record.supersedes_run_fingerprint,
            calculation_type=metadata.calculation_type,
            method_id=metadata.method_id,
            method_version=metadata.method_version,
            executor_id=metadata.executor_id,
            executor_version=metadata.executor_version,
            status=metadata.status.value,
            request_schema=request_schema,
            result_schema=result_schema,
            request_payload=request_payload,
            result_payload=result_payload,
            execution_metadata=payload_metadata,
            input_fingerprint=record.input_fingerprint,
            result_fingerprint=record.result_fingerprint,
            run_fingerprint=record.run_fingerprint,
            canonicalization=record.canonicalization,
            created_by=record.created_by,
            creator_origin=record.creator_origin.value,
            executed_at=executed_at,
            created_at=record.recorded_at,
        )
        try:
            self._session.add(row)
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise DesignPersistenceConflictError(
                "The engineering run identity or linkage already exists."
            ) from exc
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise DesignRepositoryError(
                "The engineering run could not be persisted."
            ) from exc
        return self.get_run(record.run_id)

    def get_run(self, run_id: UUID) -> EngineeringRunRecord:
        try:
            row = self._session.scalar(
                select(CalculationRun)
                .options(_run_loader())
                .where(CalculationRun.id == run_id)
            )
        except SQLAlchemyError as exc:
            raise DesignRepositoryError(
                "The engineering run could not be read."
            ) from exc
        if row is None:
            raise EngineeringRunNotFoundError(
                "The engineering run was not found."
            )
        return self._run_record(row)

    def list_runs(
        self,
        design_case_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> tuple[tuple[EngineeringRunRecord, ...], int]:
        if self._session.get(DesignCase, design_case_id) is None:
            raise DesignCaseNotFoundError("The design case was not found.")
        try:
            criteria = DesignCaseRevision.design_case_id == design_case_id
            total = self._session.scalar(
                select(func.count(CalculationRun.id))
                .join(DesignCaseRevision)
                .where(criteria)
            ) or 0
            rows = self._session.scalars(
                select(CalculationRun)
                .join(DesignCaseRevision)
                .options(_run_loader())
                .where(criteria)
                .order_by(CalculationRun.created_at.desc(), CalculationRun.id)
                .offset(offset)
                .limit(limit)
            ).all()
            return tuple(self._run_record(row) for row in rows), int(total)
        except DesignPersistenceCorruptionError:
            raise
        except SQLAlchemyError as exc:
            raise DesignRepositoryError(
                "Engineering runs could not be listed."
            ) from exc


__all__ = [
    "DesignCaseNotFoundError",
    "DesignPersistenceConflictError",
    "DesignPersistenceCorruptionError",
    "DesignRepository",
    "DesignRepositoryError",
    "DesignRevisionNotFoundError",
    "EngineeringRunNotFoundError",
]
