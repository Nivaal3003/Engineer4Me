"""Trusted Step 108 service for persistent design cases and execution runs."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel

from app.engineering.calculations.models import CalculationRequest
from app.engineering.design.persistence_models import (
    AnalyzerRunPayload,
    CalculationRunPayload,
    DesignAnalyzerAssessmentCommand,
    DesignCalculationExecutionCommand,
    DesignCaseCreate,
    DesignCasePage,
    DesignCaseRecord,
    DesignCaseRevisionCreate,
    DesignCaseRevisionRecord,
    DesignCaseSummary,
    DesignRevisionPage,
    DesignRevisionSummary,
    EngineeringRunPage,
    EngineeringRunRecord,
    EngineeringRunSummary,
    PersistedAnalyzerAssessment,
    PersistedCalculationExecution,
    build_calculation_fingerprint_basis,
    build_engineering_run_fingerprint,
    calculation_input_fingerprint,
    engineering_execution_metadata,
    normalise_utc,
    utc_now,
)
from app.repositories.design_repository import DesignRepository
from app.services.analyzer_application_service import (
    DEFAULT_ANALYZER_APPLICATION_SERVICE,
    AnalyzerApplicationService,
)
from app.services.calculation_service import (
    DEFAULT_CALCULATION_SERVICE,
    CalculationService,
)


Clock = Callable[[], datetime]
UuidFactory = Callable[[], UUID]


class DesignPersistenceServiceError(RuntimeError):
    """Base class for service-owned failures."""

    code = "design_persistence_service_error"


class DesignPersistenceInputError(DesignPersistenceServiceError):
    """A cross-record command binding is invalid."""

    code = "design_persistence_input_error"


class DesignPersistenceIntegrityError(DesignPersistenceServiceError):
    """Trusted execution or stored bytes failed fingerprint validation."""

    code = "design_persistence_integrity_error"


def _fresh[ModelT: BaseModel](
    model_type: type[ModelT],
    value: object,
) -> ModelT:
    if isinstance(value, BaseModel):
        value = value.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
    return model_type.model_validate(value)


class DesignPersistenceService:
    """Request-scoped orchestration around one transactional repository."""

    __slots__ = (
        "_analyzer_service",
        "_calculation_service",
        "_clock",
        "_id_factory",
        "_repository",
    )

    def __init__(
        self,
        *,
        repository: DesignRepository,
        calculation_service: CalculationService = DEFAULT_CALCULATION_SERVICE,
        analyzer_service: AnalyzerApplicationService = (
            DEFAULT_ANALYZER_APPLICATION_SERVICE
        ),
        clock: Clock = utc_now,
        id_factory: UuidFactory = uuid4,
    ) -> None:
        if not isinstance(repository, DesignRepository):
            raise TypeError("repository must be a DesignRepository")
        if not isinstance(calculation_service, CalculationService):
            raise TypeError("calculation_service must be a CalculationService")
        if not isinstance(analyzer_service, AnalyzerApplicationService):
            raise TypeError("analyzer_service must be an AnalyzerApplicationService")
        if not callable(clock) or not callable(id_factory):
            raise TypeError("clock and id_factory must be callable")
        self._repository = repository
        self._calculation_service = calculation_service
        self._analyzer_service = analyzer_service
        self._clock = clock
        self._id_factory = id_factory

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise DesignPersistenceIntegrityError(
                "The persistence clock returned an invalid value."
            )
        try:
            return normalise_utc(value)
        except Exception as exc:
            raise DesignPersistenceIntegrityError(
                "The persistence clock returned an invalid value."
            ) from exc

    def _new_id(self) -> UUID:
        value = self._id_factory()
        if not isinstance(value, UUID):
            raise DesignPersistenceIntegrityError(
                "The persistence identity factory returned an invalid value."
            )
        return value

    @staticmethod
    def _case_summary(record: DesignCaseRecord) -> DesignCaseSummary:
        return DesignCaseSummary(
            design_case_id=record.design_case_id,
            case_reference=record.case_reference,
            case_type=record.case_type,
            title=record.revision.payload.title,
            lifecycle_state=record.revision.payload.lifecycle_state,
            current_revision=record.current_revision,
            current_revision_fingerprint=record.current_revision_fingerprint,
            concurrency_version=record.concurrency_version,
            updated_at=record.updated_at,
        )

    @staticmethod
    def _revision_summary(
        record: DesignCaseRevisionRecord,
    ) -> DesignRevisionSummary:
        return DesignRevisionSummary(
            revision_id=record.revision_id,
            design_case_id=record.design_case_id,
            revision_number=record.revision_number,
            supersedes_revision_id=record.supersedes_revision_id,
            supersedes_revision_fingerprint=(
                record.supersedes_revision_fingerprint
            ),
            title=record.payload.title,
            lifecycle_state=record.payload.lifecycle_state,
            revision_fingerprint=record.revision_fingerprint,
            change_reason=record.change_reason,
            created_by=record.created_by,
            creator_origin=record.creator_origin,
            created_at=record.created_at,
            approval_state=record.payload.approval_state,
            final_design_approval_granted=(
                record.payload.final_design_approval_granted
            ),
        )

    @staticmethod
    def _run_summary(record: EngineeringRunRecord) -> EngineeringRunSummary:
        payload = record.payload
        metadata = record.execution_metadata
        return EngineeringRunSummary(
            run_id=record.run_id,
            run_kind=payload.kind,
            design_case_id=record.design_case_id,
            design_revision_number=record.design_revision_number,
            design_revision_fingerprint=record.design_revision_fingerprint,
            supersedes_run_id=record.supersedes_run_id,
            supersedes_run_fingerprint=record.supersedes_run_fingerprint,
            calculation_type=metadata.calculation_type,
            method_id=metadata.method_id,
            method_version=metadata.method_version,
            executor_id=metadata.executor_id,
            executor_version=metadata.executor_version,
            status=metadata.status,
            input_fingerprint=record.input_fingerprint,
            result_fingerprint=record.result_fingerprint,
            run_fingerprint=record.run_fingerprint,
            created_by=record.created_by,
            creator_origin=record.creator_origin,
            recorded_at=record.recorded_at,
        )

    def create_case(self, command: DesignCaseCreate) -> DesignCaseRecord:
        validated = _fresh(DesignCaseCreate, command)
        case_id = self._new_id()
        revision_id = self._new_id()
        created_at = self._now()
        revision = DesignCaseRevisionRecord.create(
            revision_id=revision_id,
            design_case_id=case_id,
            case_reference=validated.case_reference,
            case_type=validated.case_type,
            revision_number=1,
            supersedes_revision_id=None,
            supersedes_revision_fingerprint=None,
            payload=validated.payload,
            change_reason=validated.change_reason,
            created_by=validated.created_by,
            creator_origin=validated.creator_origin,
            created_at=created_at,
        )
        record = DesignCaseRecord(
            design_case_id=case_id,
            case_reference=validated.case_reference,
            case_type=validated.case_type,
            current_revision=1,
            current_revision_fingerprint=revision.revision_fingerprint,
            concurrency_version=1,
            created_by=validated.created_by,
            creator_origin=validated.creator_origin,
            created_at=created_at,
            updated_at=created_at,
            revision=revision,
        )
        try:
            stored = _fresh(
                DesignCaseRecord,
                self._repository.create_case(record),
            )
            self._repository.commit_write()
            return stored
        except Exception:
            self._repository.rollback_write()
            raise

    def revise_case(
        self,
        design_case_id: UUID,
        command: DesignCaseRevisionCreate,
    ) -> DesignCaseRecord:
        validated = _fresh(DesignCaseRevisionCreate, command)
        current = self._repository.get_case(design_case_id)
        if (
            current.current_revision != validated.expected_current_revision
            or current.current_revision_fingerprint
            != validated.expected_current_fingerprint
        ):
            from app.repositories.design_repository import (
                DesignPersistenceConflictError,
            )

            raise DesignPersistenceConflictError(
                "The design case has changed since it was read."
            )
        revision = DesignCaseRevisionRecord.create(
            revision_id=self._new_id(),
            design_case_id=current.design_case_id,
            case_reference=current.case_reference,
            case_type=current.case_type,
            revision_number=current.current_revision + 1,
            supersedes_revision_id=current.revision.revision_id,
            supersedes_revision_fingerprint=(
                current.revision.revision_fingerprint
            ),
            payload=validated.payload,
            change_reason=validated.change_reason,
            created_by=validated.created_by,
            creator_origin=validated.creator_origin,
            created_at=self._now(),
        )
        try:
            result = self._repository.append_revision(
                revision,
                expected_current_revision=validated.expected_current_revision,
                expected_current_fingerprint=(
                    validated.expected_current_fingerprint
                ),
            )
            stored = _fresh(DesignCaseRecord, result)
            self._repository.commit_write()
            return stored
        except Exception:
            self._repository.rollback_write()
            raise

    def get_case(self, design_case_id: UUID) -> DesignCaseRecord:
        return _fresh(DesignCaseRecord, self._repository.get_case(design_case_id))

    def list_cases(self, *, offset: int, limit: int) -> DesignCasePage:
        records, total = self._repository.list_cases(offset=offset, limit=limit)
        return DesignCasePage(
            items=tuple(self._case_summary(record) for record in records),
            offset=offset,
            limit=limit,
            total=total,
        )

    def get_revision(
        self,
        design_case_id: UUID,
        revision_number: int,
    ) -> DesignCaseRevisionRecord:
        return _fresh(
            DesignCaseRevisionRecord,
            self._repository.get_revision(design_case_id, revision_number),
        )

    def list_revisions(
        self,
        design_case_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> DesignRevisionPage:
        records, total = self._repository.list_revisions(
            design_case_id,
            offset=offset,
            limit=limit,
        )
        return DesignRevisionPage(
            items=tuple(self._revision_summary(record) for record in records),
            offset=offset,
            limit=limit,
            total=total,
        )

    def _build_run(
        self,
        *,
        revision: DesignCaseRevisionRecord,
        payload: CalculationRunPayload | AnalyzerRunPayload,
        input_fingerprint: str,
        result_fingerprint: str,
        created_by: str,
        creator_origin,
        supersedes_run_id: UUID | None,
    ) -> EngineeringRunRecord:
        run_id = self._new_id()
        recorded_at = self._now()
        predecessor_fingerprint = None
        metadata = engineering_execution_metadata(payload)
        if supersedes_run_id is not None:
            predecessor = self.get_run(supersedes_run_id)
            predecessor_metadata = predecessor.execution_metadata
            if (
                predecessor.payload.kind != payload.kind
                or predecessor.design_case_id != revision.design_case_id
                or predecessor_metadata.calculation_type
                != metadata.calculation_type
                or predecessor_metadata.method_id != metadata.method_id
                or predecessor_metadata.method_version != metadata.method_version
                or predecessor_metadata.executor_id != metadata.executor_id
                or predecessor_metadata.executor_version
                != metadata.executor_version
            ):
                raise DesignPersistenceInputError(
                    "The superseded run belongs to another execution history."
                )
            predecessor_fingerprint = predecessor.run_fingerprint
        run_fingerprint = build_engineering_run_fingerprint(
            run_id=run_id,
            design_case_id=revision.design_case_id,
            design_revision_id=revision.revision_id,
            design_revision_number=revision.revision_number,
            design_revision_fingerprint=revision.revision_fingerprint,
            supersedes_run_id=supersedes_run_id,
            supersedes_run_fingerprint=predecessor_fingerprint,
            payload=payload,
            execution_metadata=metadata,
            input_fingerprint=input_fingerprint,
            result_fingerprint=result_fingerprint,
            created_by=created_by,
            creator_origin=creator_origin,
            recorded_at=recorded_at,
        )
        return EngineeringRunRecord(
            run_id=run_id,
            design_case_id=revision.design_case_id,
            design_revision_id=revision.revision_id,
            design_revision_number=revision.revision_number,
            design_revision_fingerprint=revision.revision_fingerprint,
            supersedes_run_id=supersedes_run_id,
            supersedes_run_fingerprint=predecessor_fingerprint,
            payload=payload,
            execution_metadata=metadata,
            input_fingerprint=input_fingerprint,
            result_fingerprint=result_fingerprint,
            run_fingerprint=run_fingerprint,
            created_by=created_by,
            creator_origin=creator_origin,
            recorded_at=recorded_at,
        )

    def execute_calculation(
        self,
        design_case_id: UUID,
        command: DesignCalculationExecutionCommand,
    ) -> PersistedCalculationExecution:
        validated = _fresh(DesignCalculationExecutionCommand, command)
        revision = self.get_revision(
            design_case_id,
            validated.design_revision_number,
        )
        request = validated.calculation
        if request.design_case_id not in {None, design_case_id}:
            raise DesignPersistenceInputError(
                "The calculation request belongs to another design case."
            )
        request_data = request.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
        request_data["design_case_id"] = design_case_id
        bound_request = CalculationRequest.model_validate(request_data)
        execution = self._calculation_service.execute_controlled(bound_request)
        result = execution.result
        try:
            fingerprint_basis = build_calculation_fingerprint_basis(
                definition=execution.definition,
                request=execution.request,
                result=result,
                evidence=execution.evidence,
            )
        except Exception as exc:
            raise DesignPersistenceIntegrityError(
                "The trusted calculation fingerprint could not be reproduced."
            ) from exc
        payload = CalculationRunPayload(
            request=bound_request,
            method_definition=execution.definition,
            result=result,
            execution_fingerprint=result.result_fingerprint,
            fingerprint_basis_json=fingerprint_basis,
        )
        run = self._build_run(
            revision=revision,
            payload=payload,
            input_fingerprint=calculation_input_fingerprint(bound_request),
            result_fingerprint=result.result_fingerprint,
            created_by=validated.created_by,
            creator_origin=validated.creator_origin,
            supersedes_run_id=validated.supersedes_run_id,
        )
        try:
            stored = self._repository.append_run(run)
            self._verify_hydrated_run(stored)
            response = PersistedCalculationExecution(result=result, run=stored)
            self._repository.commit_write()
            return response
        except Exception:
            self._repository.rollback_write()
            raise

    def assess_analyzer(
        self,
        design_case_id: UUID,
        command: DesignAnalyzerAssessmentCommand,
    ) -> PersistedAnalyzerAssessment:
        validated = _fresh(DesignAnalyzerAssessmentCommand, command)
        revision = self.get_revision(
            design_case_id,
            validated.design_revision_number,
        )
        envelope = self._analyzer_service.assess(validated.request)
        payload = AnalyzerRunPayload(
            envelope=envelope,
            execution_fingerprint=envelope.integration_fingerprint,
        )
        run = self._build_run(
            revision=revision,
            payload=payload,
            input_fingerprint=envelope.request_fingerprint,
            result_fingerprint=envelope.integration_fingerprint,
            created_by=validated.created_by,
            creator_origin=validated.creator_origin,
            supersedes_run_id=validated.supersedes_run_id,
        )
        try:
            stored = self._repository.append_run(run)
            self._verify_hydrated_run(stored)
            response = PersistedAnalyzerAssessment(
                assessment=envelope,
                run=stored,
            )
            self._repository.commit_write()
            return response
        except Exception:
            self._repository.rollback_write()
            raise

    def _verify_hydrated_run(self, record: EngineeringRunRecord) -> None:
        _fresh(EngineeringRunRecord, record)

    def get_run(self, run_id: UUID) -> EngineeringRunRecord:
        record = self._repository.get_run(run_id)
        self._verify_hydrated_run(record)
        return _fresh(EngineeringRunRecord, record)

    def list_runs(
        self,
        design_case_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> EngineeringRunPage:
        records, total = self._repository.list_runs(
            design_case_id,
            offset=offset,
            limit=limit,
        )
        for record in records:
            self._verify_hydrated_run(record)
        return EngineeringRunPage(
            items=tuple(self._run_summary(record) for record in records),
            offset=offset,
            limit=limit,
            total=total,
        )


__all__ = [
    "Clock",
    "DesignPersistenceInputError",
    "DesignPersistenceIntegrityError",
    "DesignPersistenceService",
    "DesignPersistenceServiceError",
    "UuidFactory",
]
