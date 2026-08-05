"""Trusted Step 110 orchestration for datasheets and exact exports."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID, uuid4

from app.engineering.design.datasheet_models import (
    DatasheetCalculationLink,
    DatasheetContent,
    DatasheetCreateCommand,
    DatasheetRevisionCreate,
)
from app.engineering.design.datasheet_persistence_models import (
    DatasheetPage,
    DatasheetRevisionPage,
    PersistedDatasheetRecord,
    PersistedDatasheetRevision,
)
from app.engineering.design.datasheet_service import DatasheetService
from app.engineering.design.persistence_models import (
    CalculationRunPayload,
    normalise_utc,
    utc_now,
)
from app.engineering.design.xlsx_renderer import (
    DATASHEET_JSON_MEDIA_TYPE,
    DATASHEET_XLSX_MEDIA_TYPE,
    DatasheetExportBundle,
)
from app.repositories.datasheet_repository import (
    DatasheetPersistenceCorruptionError,
    DatasheetRepository,
    StoredDatasheetExport,
)
from app.repositories.design_repository import (
    DesignRepository,
    EngineeringRunNotFoundError,
)


Clock = Callable[[], datetime]
UuidFactory = Callable[[], UUID]


@dataclass(frozen=True, slots=True)
class DatasheetExportFile:
    """One exact, bounded export file selected by the caller."""

    format: Literal["json", "xlsx"]
    filename: str
    media_type: str
    checksum_sha256: str
    content: bytes


class DatasheetPersistenceServiceError(RuntimeError):
    """Base class for service-owned datasheet failures."""

    code = "datasheet_persistence_service_error"


class DatasheetPersistenceInputError(DatasheetPersistenceServiceError):
    """A path, design revision, template, or calculation link is invalid."""

    code = "datasheet_persistence_input_error"


class DatasheetPersistenceIntegrityError(DatasheetPersistenceServiceError):
    """Server-owned identity, time, stored data, or export integrity failed."""

    code = "datasheet_persistence_integrity_error"


class DatasheetPersistenceService:
    """Bind stateless datasheet rules to durable design/run records."""

    __slots__ = (
        "_clock",
        "_datasheet_service",
        "_design_repository",
        "_id_factory",
        "_repository",
    )

    def __init__(
        self,
        *,
        repository: DatasheetRepository,
        design_repository: DesignRepository,
        datasheet_service: DatasheetService | None = None,
        clock: Clock = utc_now,
        id_factory: UuidFactory = uuid4,
    ) -> None:
        if not isinstance(repository, DatasheetRepository):
            raise TypeError("repository must be a DatasheetRepository")
        if not isinstance(design_repository, DesignRepository):
            raise TypeError("design_repository must be a DesignRepository")
        if datasheet_service is not None and not isinstance(
            datasheet_service, DatasheetService
        ):
            raise TypeError("datasheet_service must be a DatasheetService")
        if not callable(clock) or not callable(id_factory):
            raise TypeError("clock and id_factory must be callable")
        self._repository = repository
        self._design_repository = design_repository
        self._datasheet_service = datasheet_service or DatasheetService(
            _allow_repository_provenance=True
        )
        self._clock = clock
        self._id_factory = id_factory

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise DatasheetPersistenceIntegrityError(
                "The datasheet clock returned an invalid value."
            )
        try:
            return normalise_utc(value)
        except Exception as exc:
            raise DatasheetPersistenceIntegrityError(
                "The datasheet clock returned an invalid value."
            ) from exc

    def _new_id(self) -> UUID:
        value = self._id_factory()
        if not isinstance(value, UUID):
            raise DatasheetPersistenceIntegrityError(
                "The datasheet identity factory returned an invalid value."
            )
        return value

    def _verify_design_binding(
        self,
        design_case_id: UUID,
        content: DatasheetContent,
    ) -> None:
        if content.design_case_id != design_case_id:
            raise DatasheetPersistenceInputError(
                "The datasheet belongs to another design case."
            )
        revision = self._design_repository.get_revision(
            design_case_id,
            content.design_revision_number,
        )
        if (
            revision.revision_id != content.design_revision_id
            or revision.revision_fingerprint != content.design_revision_fingerprint
        ):
            raise DatasheetPersistenceInputError(
                "The datasheet design-revision identity is stale."
            )

    @staticmethod
    def _link_evidence(link: DatasheetCalculationLink) -> dict[str, object]:
        document = link.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
        document["repository_provenance_verified"] = True
        return document

    def _trusted_calculation_link(
        self,
        content: DatasheetContent,
        supplied: DatasheetCalculationLink,
    ) -> DatasheetCalculationLink:
        try:
            run = self._design_repository.get_run(supplied.run_id)
        except EngineeringRunNotFoundError as exc:
            raise DatasheetPersistenceInputError(
                "The calculated field output could not be verified."
            ) from exc
        if not isinstance(run.payload, CalculationRunPayload):
            raise DatasheetPersistenceInputError(
                "Datasheet calculated fields require a calculation run."
            )
        if (
            run.design_case_id != content.design_case_id
            or run.design_revision_id != content.design_revision_id
            or run.design_revision_number != content.design_revision_number
            or run.design_revision_fingerprint != content.design_revision_fingerprint
        ):
            raise DatasheetPersistenceInputError(
                "The calculated field belongs to another design revision."
            )
        try:
            trusted = DatasheetCalculationLink._from_repository_run(
                link_id=supplied.link_id,
                run=run,
                output_id=supplied.output.output_id,
            )
        except Exception as exc:
            raise DatasheetPersistenceInputError(
                "The calculated field output could not be verified."
            ) from exc
        claimed = DatasheetCalculationLink.model_validate(self._link_evidence(supplied))
        if trusted != claimed:
            raise DatasheetPersistenceInputError(
                "The calculated field evidence does not match the stored run."
            )
        return trusted

    def _normalize_content(
        self,
        design_case_id: UUID,
        content: DatasheetContent,
    ) -> DatasheetContent:
        validated = DatasheetContent.model_validate(
            content.model_dump(mode="python", round_trip=True, warnings="error")
        )
        # Preserve the Step 109 domain contract (all template identity drift is
        # a mismatch) while allowing the HTTP persistence boundary to expose a
        # genuinely unavailable controlled template/version as not found.
        self._datasheet_service.registry.resolve(
            validated.template_id,
            validated.template_version,
        )
        self._verify_design_binding(design_case_id, validated)
        verified_links = tuple(
            self._trusted_calculation_link(validated, link)
            for link in validated.calculation_links
        )
        return validated.model_copy(update={"calculation_links": verified_links})

    def _verify_persisted_revision(
        self,
        stored: PersistedDatasheetRevision,
    ) -> None:
        content = stored.revision.snapshot.content
        try:
            self._verify_design_binding(content.design_case_id, content)
            for link in content.calculation_links:
                if self._trusted_calculation_link(content, link) != link:
                    raise ValueError("stored calculation evidence drifted")
        except DatasheetPersistenceInputError as exc:
            raise DatasheetPersistenceIntegrityError(
                "Stored datasheet evidence failed repository verification."
            ) from exc
        except Exception as exc:
            raise DatasheetPersistenceIntegrityError(
                "Stored datasheet export evidence failed integrity verification."
            ) from exc

    def create(
        self,
        design_case_id: UUID,
        command: DatasheetCreateCommand,
    ) -> PersistedDatasheetRecord:
        validated = DatasheetCreateCommand.model_validate(
            command.model_dump(mode="python", round_trip=True, warnings="error")
        )
        content = self._normalize_content(design_case_id, validated.content)
        normalized = validated.model_copy(update={"content": content})
        history = self._datasheet_service.create_history(
            normalized,
            revision_id=self._new_id(),
            created_at=self._now(),
        )
        try:
            stored = self._repository.create(history)
            self._verify_persisted_revision(stored.current)
            self._repository.commit_write()
            return stored
        except Exception:
            self._repository.rollback_write()
            raise

    def revise(
        self,
        design_case_id: UUID,
        datasheet_id: UUID,
        command: DatasheetRevisionCreate,
    ) -> PersistedDatasheetRecord:
        validated = DatasheetRevisionCreate.model_validate(
            command.model_dump(mode="python", round_trip=True, warnings="error")
        )
        if validated.content.datasheet_id != datasheet_id:
            raise DatasheetPersistenceInputError(
                "The revision belongs to another datasheet."
            )
        try:
            history = self._repository.get_history(design_case_id, datasheet_id)
            content = self._normalize_content(design_case_id, validated.content)
            normalized = validated.model_copy(update={"content": content})
            revised = self._datasheet_service.append_revision(
                history,
                normalized,
                revision_id=self._new_id(),
                created_at=self._now(),
            )
            revision = revised.revisions[-1]
            stored = self._repository.append_revision(
                revision,
                expected_current_revision=validated.expected_current_revision,
                expected_current_fingerprint=(validated.expected_current_fingerprint),
            )
            self._verify_persisted_revision(stored.current)
            self._repository.commit_write()
            return stored
        except Exception:
            self._repository.rollback_write()
            raise

    def get(
        self,
        design_case_id: UUID,
        datasheet_id: UUID,
    ) -> PersistedDatasheetRecord:
        stored = self._repository.get_record(design_case_id, datasheet_id)
        self._verify_persisted_revision(stored.current)
        return stored

    def list(
        self,
        design_case_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> DatasheetPage:
        return self._repository.list_records(
            design_case_id,
            offset=offset,
            limit=limit,
        )

    def get_revision(
        self,
        design_case_id: UUID,
        datasheet_id: UUID,
        revision_number: int,
    ) -> PersistedDatasheetRevision:
        stored = self._repository.get_revision(
            design_case_id,
            datasheet_id,
            revision_number,
        )
        self._verify_persisted_revision(stored)
        return stored

    def list_revisions(
        self,
        design_case_id: UUID,
        datasheet_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> DatasheetRevisionPage:
        return self._repository.list_revisions(
            design_case_id,
            datasheet_id,
            offset=offset,
            limit=limit,
        )

    def _get_stored_export(
        self,
        design_case_id: UUID,
        datasheet_id: UUID,
        revision_number: int,
        *,
        validate_workbook: bool,
    ) -> StoredDatasheetExport:
        try:
            artifact = self._repository.get_export(
                design_case_id,
                datasheet_id,
                revision_number,
                validate_workbook=validate_workbook,
            )
        except DatasheetPersistenceCorruptionError as exc:
            raise DatasheetPersistenceIntegrityError(
                "The stored exact datasheet artifact failed integrity verification."
            ) from exc
        self._verify_persisted_revision(artifact.stored)
        return artifact

    def export(
        self,
        design_case_id: UUID,
        datasheet_id: UUID,
        revision_number: int,
    ) -> DatasheetExportBundle:
        artifact = self._get_stored_export(
            design_case_id,
            datasheet_id,
            revision_number,
            validate_workbook=True,
        )
        return DatasheetExportBundle(
            revision=artifact.stored.revision,
            descriptor=artifact.stored.export,
            json_bytes=artifact.json_bytes,
            workbook_bytes=artifact.workbook_bytes,
        )

    def export_json(
        self,
        design_case_id: UUID,
        datasheet_id: UUID,
        revision_number: int,
    ) -> DatasheetExportFile:
        """Read and verify the immutable canonical JSON artifact."""

        artifact = self._get_stored_export(
            design_case_id,
            datasheet_id,
            revision_number,
            validate_workbook=False,
        )
        descriptor = artifact.stored.export
        return DatasheetExportFile(
            format="json",
            filename=descriptor.json_filename,
            media_type=f"{DATASHEET_JSON_MEDIA_TYPE}; charset=utf-8",
            checksum_sha256=descriptor.json_sha256,
            content=artifact.json_bytes,
        )

    def export_workbook(
        self,
        design_case_id: UUID,
        datasheet_id: UUID,
        revision_number: int,
    ) -> DatasheetExportFile:
        """Read and verify the immutable deterministic XLSX artifact."""

        artifact = self._get_stored_export(
            design_case_id,
            datasheet_id,
            revision_number,
            validate_workbook=True,
        )
        descriptor = artifact.stored.export
        return DatasheetExportFile(
            format="xlsx",
            filename=descriptor.workbook_filename,
            media_type=DATASHEET_XLSX_MEDIA_TYPE,
            checksum_sha256=descriptor.workbook_sha256,
            content=artifact.workbook_bytes,
        )


__all__ = [
    "Clock",
    "DatasheetExportFile",
    "DatasheetPersistenceInputError",
    "DatasheetPersistenceIntegrityError",
    "DatasheetPersistenceService",
    "DatasheetPersistenceServiceError",
    "UuidFactory",
]
