"""Transactional, append-only Step 110 datasheet repository."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, joinedload, selectinload, undefer_group
from sqlalchemy.orm.exc import StaleDataError

from app.engineering.design.datasheet_models import (
    DATASHEET_MODEL_VERSION,
    DatasheetCalculationLink,
    DatasheetHistory,
    DatasheetRevisionRecord,
    DatasheetRevisionSnapshot,
)
from app.engineering.design.datasheet_persistence_models import (
    DatasheetPage,
    DatasheetRevisionPage,
    DatasheetRevisionSummary,
    DatasheetSummary,
    PersistedDatasheetRecord,
    PersistedDatasheetRevision,
)
from app.engineering.design.persistence_models import (
    DesignApprovalState,
    RecordedIdentityOrigin,
)
from app.engineering.design.xlsx_renderer import (
    DatasheetExportBundle,
    DatasheetExportDescriptor,
    build_datasheet_export_bundle,
    validate_datasheet_json_artifact,
)
from app.models.design_case import DesignCase, DesignCaseRevision
from app.models.engineering_datasheet import (
    EngineeringDatasheet,
    EngineeringDatasheetCalculationLink,
    EngineeringDatasheetRevision,
)
from app.repositories.design_repository import (
    DesignPersistenceCorruptionError,
    DesignRepository,
    DesignRepositoryError,
    EngineeringRunNotFoundError,
)


DATASHEET_SNAPSHOT_SCHEMA = "engineer4me.datasheet.revision-snapshot.v1"


class DatasheetRepositoryError(RuntimeError):
    """Sanitized persistence failure."""


class DatasheetNotFoundError(DatasheetRepositoryError):
    """The requested datasheet is absent from the requested design case."""


class DatasheetRevisionNotFoundError(DatasheetRepositoryError):
    """The exact immutable datasheet revision does not exist."""


class DatasheetPersistenceConflictError(DatasheetRepositoryError):
    """An identity, immutable link, or compare-and-swap guard failed."""


class DatasheetPersistenceCorruptionError(DatasheetRepositoryError):
    """Stored datasheet bytes or relational projections failed validation."""


@dataclass(frozen=True, slots=True)
class StoredDatasheetExport:
    """Immutable persisted artifact bytes for one exact revision."""

    stored: PersistedDatasheetRevision
    json_bytes: bytes
    workbook_bytes: bytes


def _json_document(value) -> dict[str, object]:
    document = value.model_dump(mode="json", round_trip=True, warnings="error")
    if not isinstance(document, dict):
        raise TypeError("persisted datasheet documents must be JSON objects")
    return document


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _revision_options():
    return (
        joinedload(EngineeringDatasheetRevision.design_case_revision),
        selectinload(EngineeringDatasheetRevision.calculation_links),
    )


class DatasheetRepository:
    """Request-scoped repository for permanent datasheet histories."""

    __slots__ = ("_session",)

    def __init__(self, session: Session) -> None:
        if not isinstance(session, Session):
            raise TypeError("session must be a SQLAlchemy Session")
        self._session = session

    @staticmethod
    def _verify_link_projection(
        record: DatasheetRevisionRecord,
        rows: list[EngineeringDatasheetCalculationLink],
    ) -> None:
        expected = {
            item.link_id: item for item in record.snapshot.content.calculation_links
        }
        actual = {item.link_id: item for item in rows}
        if set(expected) != set(actual):
            raise ValueError("stored datasheet calculation-link projection drifted")
        for link_id, link in expected.items():
            row = actual[link_id]
            if not link.repository_provenance_verified:
                raise ValueError("a stored calculation link lacks repository proof")
            if (
                row.datasheet_revision_id != record.revision_id
                or row.run_id != link.run_id
                or row.output_id != link.output.output_id
                or row.run_fingerprint != link.run_fingerprint
                or row.result_fingerprint != link.result_fingerprint
            ):
                raise ValueError("stored datasheet calculation-link evidence drifted")

    @classmethod
    def _revision_record(
        cls,
        row: EngineeringDatasheetRevision,
    ) -> DatasheetRevisionRecord:
        try:
            snapshot = DatasheetRevisionSnapshot.model_validate(row.snapshot)
            record = DatasheetRevisionRecord(
                revision_id=row.id,
                datasheet_id=row.datasheet_id,
                revision_number=row.revision_number,
                supersedes_revision_id=row.prior_revision_id,
                supersedes_revision_fingerprint=(row.prior_revision_fingerprint),
                snapshot=snapshot,
                revision_fingerprint=row.revision_fingerprint,
                change_reason=row.change_reason,
                created_by=row.created_by,
                creator_origin=RecordedIdentityOrigin(row.creator_origin),
                created_at=_aware_utc(row.created_at),
            )
            content = snapshot.content
            design_revision = row.design_case_revision
            if (
                row.snapshot_schema != DATASHEET_SNAPSHOT_SCHEMA
                or row.snapshot_version != DATASHEET_MODEL_VERSION
                or design_revision is None
                or design_revision.id != content.design_revision_id
                or design_revision.design_case_id != content.design_case_id
                or row.design_revision_number != content.design_revision_number
                or row.design_revision_fingerprint
                != content.design_revision_fingerprint
                or design_revision.revision_number != content.design_revision_number
                or design_revision.revision_fingerprint
                != content.design_revision_fingerprint
                or row.lifecycle_state != content.lifecycle_state.value
                or row.completeness_state != snapshot.completeness.state.value
                or row.ready_for_review != snapshot.completeness.ready_for_review
                or row.approval_state != DesignApprovalState.UNAPPROVED.value
                or row.final_design_approval_granted
                or row.standards_conformity_claimed
            ):
                raise ValueError("stored datasheet revision projection drifted")
            cls._verify_link_projection(record, row.calculation_links)
            return record
        except Exception as exc:
            raise DatasheetPersistenceCorruptionError(
                "A stored datasheet revision failed integrity validation."
            ) from exc

    @classmethod
    def _persisted_revision(
        cls,
        row: EngineeringDatasheetRevision,
    ) -> PersistedDatasheetRevision:
        try:
            revision = cls._revision_record(row)
            export = DatasheetExportDescriptor.model_validate(row.export_descriptor)
            return PersistedDatasheetRevision(revision=revision, export=export)
        except DatasheetPersistenceCorruptionError:
            raise
        except Exception as exc:
            raise DatasheetPersistenceCorruptionError(
                "A stored datasheet export descriptor failed integrity validation."
            ) from exc

    @classmethod
    def _stored_export(
        cls,
        row: EngineeringDatasheetRevision,
        *,
        validate_workbook: bool,
    ) -> StoredDatasheetExport:
        try:
            stored = cls._persisted_revision(row)
            descriptor = stored.export
            json_bytes = bytes(row.json_artifact)
            workbook_bytes = bytes(row.workbook_artifact)
            if (
                len(json_bytes) != descriptor.json_size_bytes
                or sha256(json_bytes).hexdigest() != descriptor.json_sha256
                or len(workbook_bytes) != descriptor.workbook_size_bytes
                or sha256(workbook_bytes).hexdigest() != descriptor.workbook_sha256
            ):
                raise ValueError("stored datasheet artifact checksum drifted")
            if validate_workbook:
                DatasheetExportBundle(
                    revision=stored.revision,
                    descriptor=descriptor,
                    json_bytes=json_bytes,
                    workbook_bytes=workbook_bytes,
                )
            else:
                validate_datasheet_json_artifact(
                    stored.revision,
                    descriptor,
                    json_bytes,
                )
            return StoredDatasheetExport(
                stored=stored,
                json_bytes=json_bytes,
                workbook_bytes=workbook_bytes,
            )
        except DatasheetPersistenceCorruptionError:
            raise
        except Exception as exc:
            raise DatasheetPersistenceCorruptionError(
                "A stored datasheet artifact failed integrity validation."
            ) from exc

    @classmethod
    def _record(
        cls,
        row: EngineeringDatasheet,
        revision_row: EngineeringDatasheetRevision | None,
    ) -> PersistedDatasheetRecord:
        try:
            if revision_row is None:
                raise ValueError("the current datasheet revision is unavailable")
            current = cls._persisted_revision(revision_row)
            return PersistedDatasheetRecord(
                datasheet_id=row.id,
                design_case_id=row.design_case_id,
                template_id=row.template_id,
                template_version=row.template_version,
                template_fingerprint=row.template_fingerprint,
                current_revision=row.current_revision,
                current_revision_fingerprint=(row.current_revision_fingerprint),
                concurrency_version=row.concurrency_version,
                created_by=row.created_by,
                creator_origin=RecordedIdentityOrigin(row.creator_origin),
                created_at=_aware_utc(row.created_at),
                updated_at=_aware_utc(row.updated_at),
                current=current,
            )
        except DatasheetPersistenceCorruptionError:
            raise
        except Exception as exc:
            raise DatasheetPersistenceCorruptionError(
                "A stored datasheet head failed integrity validation."
            ) from exc

    @staticmethod
    def _calculation_link_rows(
        record: DatasheetRevisionRecord,
    ) -> list[EngineeringDatasheetCalculationLink]:
        rows: list[EngineeringDatasheetCalculationLink] = []
        for link in record.snapshot.content.calculation_links:
            if not link.repository_provenance_verified:
                raise DatasheetPersistenceConflictError(
                    "A calculated datasheet field lacks repository provenance."
                )
            rows.append(
                EngineeringDatasheetCalculationLink(
                    datasheet_revision_id=record.revision_id,
                    link_id=link.link_id,
                    run_id=link.run_id,
                    output_id=link.output.output_id,
                    run_fingerprint=link.run_fingerprint,
                    result_fingerprint=link.result_fingerprint,
                )
            )
        return rows

    @classmethod
    def _revision_row(
        cls,
        record: DatasheetRevisionRecord,
    ) -> EngineeringDatasheetRevision:
        snapshot = record.snapshot
        bundle = build_datasheet_export_bundle(record)
        export = bundle.descriptor
        row = EngineeringDatasheetRevision(
            id=record.revision_id,
            datasheet_id=record.datasheet_id,
            design_case_revision_id=snapshot.content.design_revision_id,
            design_revision_number=snapshot.content.design_revision_number,
            design_revision_fingerprint=(snapshot.content.design_revision_fingerprint),
            revision_number=record.revision_number,
            prior_revision_id=record.supersedes_revision_id,
            prior_revision_fingerprint=(record.supersedes_revision_fingerprint),
            snapshot_schema=DATASHEET_SNAPSHOT_SCHEMA,
            snapshot_version=DATASHEET_MODEL_VERSION,
            snapshot=_json_document(snapshot),
            export_descriptor=_json_document(export),
            json_artifact=bundle.json_bytes,
            workbook_artifact=bundle.workbook_bytes,
            revision_fingerprint=record.revision_fingerprint,
            change_reason=record.change_reason,
            lifecycle_state=snapshot.content.lifecycle_state.value,
            completeness_state=snapshot.completeness.state.value,
            ready_for_review=snapshot.completeness.ready_for_review,
            approval_state=DesignApprovalState.UNAPPROVED.value,
            final_design_approval_granted=False,
            standards_conformity_claimed=False,
            created_by=record.created_by,
            creator_origin=record.creator_origin.value,
            created_at=record.created_at,
        )
        row.calculation_links = cls._calculation_link_rows(record)
        return row

    def _validate_design_revision(self, record: DatasheetRevisionRecord) -> None:
        content = record.snapshot.content
        design_revision = self._session.get(
            DesignCaseRevision,
            content.design_revision_id,
        )
        if design_revision is None:
            raise DatasheetPersistenceConflictError(
                "The exact design revision was not found."
            )
        if (
            design_revision.design_case_id != content.design_case_id
            or design_revision.revision_number != content.design_revision_number
            or design_revision.revision_fingerprint
            != content.design_revision_fingerprint
        ):
            raise DatasheetPersistenceConflictError(
                "The datasheet design-revision linkage is stale."
            )
        design_repository = DesignRepository(self._session)
        for link in content.calculation_links:
            try:
                run = design_repository.get_run(link.run_id)
            except EngineeringRunNotFoundError as exc:
                raise DatasheetPersistenceConflictError(
                    "A linked calculation run was not found."
                ) from exc
            except DesignPersistenceCorruptionError as exc:
                raise DatasheetPersistenceCorruptionError(
                    "A linked calculation run failed integrity validation."
                ) from exc
            except DesignRepositoryError as exc:
                raise DatasheetRepositoryError(
                    "A linked calculation run could not be read."
                ) from exc
            try:
                trusted = DatasheetCalculationLink._from_repository_run(
                    link_id=link.link_id,
                    run=run,
                    output_id=link.output.output_id,
                )
            except Exception as exc:
                raise DatasheetPersistenceConflictError(
                    "A linked calculation run output is not eligible."
                ) from exc
            if trusted != link:
                raise DatasheetPersistenceConflictError(
                    "A linked calculation run does not match trusted persistence."
                )

    def create(self, history: DatasheetHistory) -> PersistedDatasheetRecord:
        trusted = DatasheetHistory.model_validate(
            history.model_dump(mode="python", round_trip=True, warnings="error")
        )
        if len(trusted.revisions) != 1 or trusted.current_revision != 1:
            raise DatasheetPersistenceConflictError(
                "A new datasheet must contain exactly revision one."
            )
        revision = trusted.revisions[0]
        self._validate_design_revision(revision)
        content = revision.snapshot.content
        if self._session.get(DesignCase, content.design_case_id) is None:
            raise DatasheetPersistenceConflictError(
                "The parent design case was not found."
            )
        row = EngineeringDatasheet(
            id=trusted.datasheet_id,
            design_case_id=trusted.design_case_id,
            template_id=trusted.template_id,
            template_version=trusted.template_version,
            template_fingerprint=trusted.template_fingerprint,
            current_revision=1,
            current_revision_fingerprint=revision.revision_fingerprint,
            concurrency_version=1,
            created_by=revision.created_by,
            creator_origin=revision.creator_origin.value,
            created_at=revision.created_at,
            updated_at=revision.created_at,
        )
        row.revisions.append(self._revision_row(revision))
        try:
            self._session.add(row)
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise DatasheetPersistenceConflictError(
                "The datasheet identity or initial revision already exists."
            ) from exc
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise DatasheetRepositoryError(
                "The datasheet could not be persisted."
            ) from exc
        return self.get_record(trusted.design_case_id, trusted.datasheet_id)

    def append_revision(
        self,
        record: DatasheetRevisionRecord,
        *,
        expected_current_revision: int,
        expected_current_fingerprint: str,
    ) -> PersistedDatasheetRecord:
        self._validate_design_revision(record)
        try:
            row = self._session.scalar(
                select(EngineeringDatasheet)
                .where(EngineeringDatasheet.id == record.datasheet_id)
                .with_for_update()
            )
            if row is None:
                raise DatasheetNotFoundError("The datasheet was not found.")
            if (
                row.design_case_id != record.snapshot.content.design_case_id
                or row.current_revision != expected_current_revision
                or row.current_revision_fingerprint != expected_current_fingerprint
            ):
                raise DatasheetPersistenceConflictError(
                    "The datasheet has changed since it was read."
                )
            prior = self._session.scalar(
                select(EngineeringDatasheetRevision).where(
                    EngineeringDatasheetRevision.datasheet_id == row.id,
                    EngineeringDatasheetRevision.revision_number
                    == expected_current_revision,
                )
            )
            if prior is None:
                raise DatasheetPersistenceCorruptionError(
                    "The current datasheet revision is unavailable."
                )
            content = record.snapshot.content
            if (
                record.revision_number != expected_current_revision + 1
                or record.supersedes_revision_id != prior.id
                or record.supersedes_revision_fingerprint != prior.revision_fingerprint
                or content.design_revision_number < prior.design_revision_number
                or (
                    content.design_revision_number == prior.design_revision_number
                    and (
                        content.design_revision_id != prior.design_case_revision_id
                        or content.design_revision_fingerprint
                        != prior.design_revision_fingerprint
                    )
                )
                or content.template_id != row.template_id
                or content.template_version != row.template_version
                or content.template_fingerprint != row.template_fingerprint
            ):
                raise DatasheetPersistenceConflictError(
                    "The new revision does not extend the current datasheet head."
                )
            self._session.add(self._revision_row(record))
            row.current_revision = record.revision_number
            row.current_revision_fingerprint = record.revision_fingerprint
            row.updated_at = record.created_at
            self._session.flush()
        except (
            DatasheetNotFoundError,
            DatasheetPersistenceConflictError,
            DatasheetPersistenceCorruptionError,
        ):
            self._session.rollback()
            raise
        except (IntegrityError, StaleDataError) as exc:
            self._session.rollback()
            raise DatasheetPersistenceConflictError(
                "The datasheet changed during revision creation."
            ) from exc
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise DatasheetRepositoryError(
                "The datasheet revision could not be persisted."
            ) from exc
        return self.get_record(row.design_case_id, row.id)

    def commit_write(self) -> None:
        """Commit a service-verified write and translate database failures."""

        try:
            self._session.commit()
        except (IntegrityError, StaleDataError) as exc:
            self._session.rollback()
            raise DatasheetPersistenceConflictError(
                "The datasheet transaction failed an integrity guard."
            ) from exc
        except SQLAlchemyError as exc:
            self._session.rollback()
            raise DatasheetRepositoryError(
                "The datasheet transaction could not be committed."
            ) from exc

    def rollback_write(self) -> None:
        """Roll back the current datasheet unit of work."""

        self._session.rollback()

    def _head_query(self, design_case_id: UUID, datasheet_id: UUID):
        return (
            select(EngineeringDatasheet, EngineeringDatasheetRevision)
            .outerjoin(
                EngineeringDatasheetRevision,
                (EngineeringDatasheetRevision.datasheet_id == EngineeringDatasheet.id)
                & (
                    EngineeringDatasheetRevision.revision_number
                    == EngineeringDatasheet.current_revision
                ),
            )
            .options(*_revision_options())
            .where(
                EngineeringDatasheet.id == datasheet_id,
                EngineeringDatasheet.design_case_id == design_case_id,
            )
        )

    def get_record(
        self,
        design_case_id: UUID,
        datasheet_id: UUID,
    ) -> PersistedDatasheetRecord:
        try:
            result = (
                self._session.execute(self._head_query(design_case_id, datasheet_id))
                .unique()
                .one_or_none()
            )
        except SQLAlchemyError as exc:
            raise DatasheetRepositoryError("The datasheet could not be read.") from exc
        if result is None:
            raise DatasheetNotFoundError("The datasheet was not found.")
        return self._record(*result)

    def get_revision(
        self,
        design_case_id: UUID,
        datasheet_id: UUID,
        revision_number: int,
    ) -> PersistedDatasheetRevision:
        try:
            row = self._session.scalar(
                select(EngineeringDatasheetRevision)
                .join(EngineeringDatasheet)
                .options(*_revision_options())
                .where(
                    EngineeringDatasheet.id == datasheet_id,
                    EngineeringDatasheet.design_case_id == design_case_id,
                    EngineeringDatasheetRevision.revision_number == revision_number,
                )
            )
        except SQLAlchemyError as exc:
            raise DatasheetRepositoryError(
                "The datasheet revision could not be read."
            ) from exc
        if row is None:
            if (
                self._session.scalar(
                    select(EngineeringDatasheet.id).where(
                        EngineeringDatasheet.id == datasheet_id,
                        EngineeringDatasheet.design_case_id == design_case_id,
                    )
                )
                is None
            ):
                raise DatasheetNotFoundError("The datasheet was not found.")
            raise DatasheetRevisionNotFoundError(
                "The exact datasheet revision was not found."
            )
        return self._persisted_revision(row)

    def get_export(
        self,
        design_case_id: UUID,
        datasheet_id: UUID,
        revision_number: int,
        *,
        validate_workbook: bool = True,
    ) -> StoredDatasheetExport:
        """Read exact immutable artifact bytes scoped to their design case."""

        try:
            row = self._session.scalar(
                select(EngineeringDatasheetRevision)
                .join(EngineeringDatasheet)
                .options(*_revision_options(), undefer_group("datasheet_artifacts"))
                .where(
                    EngineeringDatasheet.id == datasheet_id,
                    EngineeringDatasheet.design_case_id == design_case_id,
                    EngineeringDatasheetRevision.revision_number == revision_number,
                )
            )
        except SQLAlchemyError as exc:
            raise DatasheetRepositoryError(
                "The datasheet export could not be read."
            ) from exc
        if row is None:
            if (
                self._session.scalar(
                    select(EngineeringDatasheet.id).where(
                        EngineeringDatasheet.id == datasheet_id,
                        EngineeringDatasheet.design_case_id == design_case_id,
                    )
                )
                is None
            ):
                raise DatasheetNotFoundError("The datasheet was not found.")
            raise DatasheetRevisionNotFoundError(
                "The exact datasheet revision was not found."
            )
        return self._stored_export(row, validate_workbook=validate_workbook)

    def get_history(
        self,
        design_case_id: UUID,
        datasheet_id: UUID,
    ) -> DatasheetHistory:
        try:
            head = self._session.scalar(
                select(EngineeringDatasheet)
                .where(
                    EngineeringDatasheet.id == datasheet_id,
                    EngineeringDatasheet.design_case_id == design_case_id,
                )
                .with_for_update()
            )
            if head is None:
                raise DatasheetNotFoundError("The datasheet was not found.")
            rows = self._session.scalars(
                select(EngineeringDatasheetRevision)
                .options(*_revision_options())
                .where(EngineeringDatasheetRevision.datasheet_id == datasheet_id)
                .order_by(EngineeringDatasheetRevision.revision_number)
            ).all()
            revisions = tuple(self._revision_record(row) for row in rows)
            return DatasheetHistory(
                datasheet_id=head.id,
                design_case_id=head.design_case_id,
                template_id=head.template_id,
                template_version=head.template_version,
                template_fingerprint=head.template_fingerprint,
                current_revision=head.current_revision,
                current_revision_fingerprint=head.current_revision_fingerprint,
                revisions=revisions,
            )
        except DatasheetNotFoundError:
            raise
        except DatasheetPersistenceCorruptionError:
            raise
        except SQLAlchemyError as exc:
            raise DatasheetRepositoryError(
                "The datasheet history could not be read."
            ) from exc

    @classmethod
    def _summary(
        cls,
        row: EngineeringDatasheet,
        revision_row: EngineeringDatasheetRevision,
    ) -> DatasheetSummary:
        record = cls._record(row, revision_row)
        revision = record.current.revision
        return DatasheetSummary(
            datasheet_id=record.datasheet_id,
            design_case_id=record.design_case_id,
            template_id=record.template_id,
            template_version=record.template_version,
            title=revision.snapshot.content.title,
            lifecycle_state=revision.snapshot.content.lifecycle_state,
            completeness_state=revision.snapshot.completeness.state,
            ready_for_review=revision.snapshot.completeness.ready_for_review,
            current_revision=record.current_revision,
            current_revision_fingerprint=record.current_revision_fingerprint,
            workbook_sha256=record.current.export.workbook_sha256,
            updated_at=record.updated_at,
        )

    def list_records(
        self,
        design_case_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> DatasheetPage:
        if self._session.get(DesignCase, design_case_id) is None:
            from app.repositories.design_repository import DesignCaseNotFoundError

            raise DesignCaseNotFoundError("The design case was not found.")
        criteria = EngineeringDatasheet.design_case_id == design_case_id
        try:
            rows = (
                self._session.execute(
                    select(
                        EngineeringDatasheet,
                        EngineeringDatasheetRevision,
                        func.count(EngineeringDatasheet.id).over().label("page_total"),
                    )
                    .join(
                        EngineeringDatasheetRevision,
                        (
                            EngineeringDatasheetRevision.datasheet_id
                            == EngineeringDatasheet.id
                        )
                        & (
                            EngineeringDatasheetRevision.revision_number
                            == EngineeringDatasheet.current_revision
                        ),
                    )
                    .options(*_revision_options())
                    .where(criteria)
                    .order_by(
                        EngineeringDatasheet.updated_at.desc(),
                        EngineeringDatasheet.id,
                    )
                    .offset(offset)
                    .limit(limit)
                )
                .unique()
                .all()
            )
            total = int(rows[0][2]) if rows else 0
            if not rows:
                total = int(
                    self._session.scalar(
                        select(func.count(EngineeringDatasheet.id)).where(criteria)
                    )
                    or 0
                )
                if total > offset:
                    rows = (
                        self._session.execute(
                            select(
                                EngineeringDatasheet,
                                EngineeringDatasheetRevision,
                                func.count(EngineeringDatasheet.id)
                                .over()
                                .label("page_total"),
                            )
                            .join(
                                EngineeringDatasheetRevision,
                                (
                                    EngineeringDatasheetRevision.datasheet_id
                                    == EngineeringDatasheet.id
                                )
                                & (
                                    EngineeringDatasheetRevision.revision_number
                                    == EngineeringDatasheet.current_revision
                                ),
                            )
                            .options(*_revision_options())
                            .where(criteria)
                            .order_by(
                                EngineeringDatasheet.updated_at.desc(),
                                EngineeringDatasheet.id,
                            )
                            .offset(offset)
                            .limit(limit)
                        )
                        .unique()
                        .all()
                    )
                    if rows:
                        total = int(rows[0][2])
            return DatasheetPage(
                items=tuple(self._summary(row[0], row[1]) for row in rows),
                offset=offset,
                limit=limit,
                total=int(total),
            )
        except DatasheetPersistenceCorruptionError:
            raise
        except SQLAlchemyError as exc:
            raise DatasheetRepositoryError("Datasheets could not be listed.") from exc

    @classmethod
    def _revision_summary(
        cls,
        row: EngineeringDatasheetRevision,
    ) -> DatasheetRevisionSummary:
        stored = cls._persisted_revision(row)
        revision = stored.revision
        content = revision.snapshot.content
        completeness = revision.snapshot.completeness
        return DatasheetRevisionSummary(
            revision_id=revision.revision_id,
            datasheet_id=revision.datasheet_id,
            revision_number=revision.revision_number,
            revision_fingerprint=revision.revision_fingerprint,
            design_revision_number=content.design_revision_number,
            design_revision_fingerprint=content.design_revision_fingerprint,
            title=content.title,
            lifecycle_state=content.lifecycle_state,
            completeness_state=completeness.state,
            ready_for_review=completeness.ready_for_review,
            json_sha256=stored.export.json_sha256,
            workbook_sha256=stored.export.workbook_sha256,
            created_by=revision.created_by,
            creator_origin=revision.creator_origin,
            created_at=revision.created_at,
        )

    def list_revisions(
        self,
        design_case_id: UUID,
        datasheet_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> DatasheetRevisionPage:
        self.get_record(design_case_id, datasheet_id)
        criteria = EngineeringDatasheetRevision.datasheet_id == datasheet_id
        try:
            statement = (
                select(
                    EngineeringDatasheetRevision,
                    func.count(EngineeringDatasheetRevision.id)
                    .over()
                    .label("page_total"),
                )
                .options(*_revision_options())
                .where(criteria)
                .order_by(EngineeringDatasheetRevision.revision_number.desc())
                .offset(offset)
                .limit(limit)
            )
            rows = self._session.execute(statement).unique().all()
            total = int(rows[0][1]) if rows else 0
            if not rows:
                total = int(
                    self._session.scalar(
                        select(func.count(EngineeringDatasheetRevision.id)).where(
                            criteria
                        )
                    )
                    or 0
                )
                if total > offset:
                    rows = self._session.execute(statement).unique().all()
                    if rows:
                        total = int(rows[0][1])
            return DatasheetRevisionPage(
                items=tuple(self._revision_summary(row[0]) for row in rows),
                offset=offset,
                limit=limit,
                total=int(total),
            )
        except DatasheetPersistenceCorruptionError:
            raise
        except SQLAlchemyError as exc:
            raise DatasheetRepositoryError(
                "Datasheet revisions could not be listed."
            ) from exc


__all__ = [
    "DATASHEET_SNAPSHOT_SCHEMA",
    "DatasheetNotFoundError",
    "DatasheetPersistenceConflictError",
    "DatasheetPersistenceCorruptionError",
    "DatasheetRepository",
    "DatasheetRepositoryError",
    "DatasheetRevisionNotFoundError",
    "StoredDatasheetExport",
]
