"""Synchronous document-processing orchestration for Engineer4Me.

The orchestrator connects the ingestion job lifecycle to the deterministic
Phase 5 document-processing components:

- source-content loading through an injected storage boundary;
- document validation and parsing;
- metadata and engineering-fact extraction;
- deterministic knowledge-index construction;
- controlled knowledge conversion and repository registration;
- cooperative cancellation, diagnostics, and final job reconciliation.

Document-level duplicate detection, a separate evidence-linking pass, and a
standalone knowledge-generator pass are intentionally not invoked here because
their modules do not yet expose public callable contracts. Duplicate facts are
still handled by ``EngineeringKnowledgeIndexer``, evidence produced by
``EngineeringExtractor`` is preserved in index records, and controlled
knowledge conversion is performed by the repository publisher.

The class is synchronous by design. A future worker, queue consumer, or task
runner can call ``process_job`` without placing transport, storage, or broker
concerns inside the engineering pipeline.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, TypeVar
from uuid import UUID

from pydantic import ValidationError

from app.ingestion.document_models import (
    DocumentFormat,
    DocumentSource,
    DocumentUpload,
    EngineeringExtractionResult,
    ExtractedDocumentMetadata,
)
from app.ingestion.document_parser import (
    DocumentParser,
    DocumentParserError,
    UnsupportedDocumentFormatError,
)
from app.ingestion.engineering_extractor import (
    EngineeringExtractionError,
    EngineeringExtractor,
)
from app.ingestion.ingestion_job_models import (
    IngestionDiagnostic,
    IngestionDocumentResult,
    IngestionDocumentStatus,
    IngestionFailureCategory,
    IngestionJob,
    IngestionJobStatus,
    IngestionStage,
)
from app.ingestion.ingestion_job_service import IngestionJobService
from app.ingestion.knowledge_index import (
    EngineeringKnowledgeIndexer,
    KnowledgeIndexBuildResult,
)
from app.ingestion.metadata_extractor import (
    MetadataExtractionError,
    MetadataExtractor,
)
from app.ingestion.repository_publisher import (
    EngineeringKnowledgeRepositoryPublisher,
    RepositoryPublicationResult,
    RepositoryPublisherError,
)


_ResultT = TypeVar("_ResultT")


class DocumentProcessingOrchestratorError(Exception):
    """Base exception raised by document-processing orchestration."""


class DocumentProcessingStateError(DocumentProcessingOrchestratorError):
    """Raised when a job cannot be processed safely in its current state."""


class DocumentProcessingCancelled(DocumentProcessingOrchestratorError):
    """Raised after a cooperative document-processing cancellation."""


class DocumentContentLoadError(DocumentProcessingOrchestratorError):
    """Raised when source document bytes cannot be loaded."""


class DocumentProcessingFailure(DocumentProcessingOrchestratorError):
    """Normalised failure produced by one document-processing stage."""

    def __init__(
        self,
        *,
        stage: IngestionStage,
        failure_category: IngestionFailureCategory,
        code: str,
        message: str,
        recoverable: bool,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.failure_category = failure_category
        self.code = code
        self.recoverable = recoverable
        self.details = dict(details or {})


class DocumentContentLoader(Protocol):
    """Storage boundary used to obtain bytes for one submitted document."""

    def load(
        self,
        job: IngestionJob,
        document: IngestionDocumentResult,
    ) -> bytes:
        """Return the complete source bytes for a submitted document."""


@dataclass(frozen=True, slots=True)
class DocumentProcessingOrchestratorConfig:
    """Runtime controls for synchronous document processing."""

    continue_after_document_failure: bool = True
    verify_declared_file_size: bool = True
    verify_checksum_sha256: bool = True
    skip_existing_knowledge: bool = True
    created_by: str = "document-ingestion"

    def __post_init__(self) -> None:
        created_by = self.created_by.strip()

        if not created_by:
            raise ValueError("created_by cannot be blank.")

        if len(created_by) > 255:
            raise ValueError(
                "created_by cannot contain more than 255 characters."
            )

        object.__setattr__(self, "created_by", created_by)


class DocumentProcessingOrchestrator:
    """Coordinate one complete document-ingestion job."""

    PIPELINE_VERSION = "1.0.0"

    def __init__(
        self,
        *,
        job_service: IngestionJobService,
        content_loader: DocumentContentLoader,
        parser: DocumentParser | None = None,
        metadata_extractor: MetadataExtractor | None = None,
        engineering_extractor: EngineeringExtractor | None = None,
        knowledge_indexer: EngineeringKnowledgeIndexer | None = None,
        repository_publisher: (
            EngineeringKnowledgeRepositoryPublisher | None
        ) = None,
        config: DocumentProcessingOrchestratorConfig | None = None,
    ) -> None:
        """Initialise the orchestrator with explicit lifecycle and storage."""

        self._job_service = job_service
        self._content_loader = content_loader
        self._parser = parser or DocumentParser()
        self._metadata_extractor = (
            metadata_extractor or MetadataExtractor()
        )
        self._engineering_extractor = (
            engineering_extractor or EngineeringExtractor()
        )
        self._knowledge_indexer = (
            knowledge_indexer or EngineeringKnowledgeIndexer()
        )
        self._repository_publisher = (
            repository_publisher
            or EngineeringKnowledgeRepositoryPublisher()
        )
        self._config = config or DocumentProcessingOrchestratorConfig()

    @property
    def job_service(self) -> IngestionJobService:
        """Return the configured ingestion job lifecycle service."""

        return self._job_service

    @property
    def config(self) -> DocumentProcessingOrchestratorConfig:
        """Return the immutable orchestrator configuration."""

        return self._config

    def process_job(self, job_id: UUID) -> IngestionJob:
        """Process all pending documents and finalise the ingestion job."""

        job = self._job_service.get(job_id)

        if job.terminal:
            return job

        if job.status in {
            IngestionJobStatus.PENDING,
            IngestionJobStatus.QUEUED,
        }:
            job = self._job_service.start(
                job_id,
                stage=IngestionStage.VALIDATING,
            )
        elif job.status == IngestionJobStatus.PROCESSING:
            if job.cancellation_requested:
                return self._job_service.apply_cancellation(job_id)

            self._require_resumable_processing_state(job)
        else:
            raise DocumentProcessingStateError(
                f"Ingestion job {job_id} cannot be processed from "
                f"{job.status.value} status."
            )

        if job.terminal:
            return job

        pending_document_ids = [
            document.document_id
            for document in job.documents
            if document.status == IngestionDocumentStatus.PENDING
        ]

        for document_id in pending_document_ids:
            try:
                self.process_document(job_id, document_id)
            except DocumentProcessingCancelled:
                return self._job_service.get(job_id)
            except DocumentProcessingFailure as failure:
                self._record_document_failure(
                    job_id,
                    document_id,
                    failure,
                )

                if not self._config.continue_after_document_failure:
                    failed_job = self._job_service.get(job_id)
                    return self._job_service.fail(
                        job_id,
                        stage=failure.stage,
                        error_count=failed_job.error_count,
                    )

        try:
            self._check_cancellation(job_id)
        except DocumentProcessingCancelled:
            return self._job_service.get(job_id)

        return self._job_service.complete(job_id)

    def process_document(
        self,
        job_id: UUID,
        document_id: UUID,
    ) -> IngestionJob:
        """Process one pending document in an active ingestion job."""

        job = self._job_service.get(job_id)

        if job.status != IngestionJobStatus.PROCESSING:
            raise DocumentProcessingStateError(
                "Documents may only be processed while their ingestion job "
                "has processing status."
            )

        self._require_resumable_processing_state(job)
        document = self._find_document(job, document_id)

        if document.status != IngestionDocumentStatus.PENDING:
            raise DocumentProcessingStateError(
                f"Document {document_id} cannot be processed from "
                f"{document.status.value} status."
            )

        self._check_cancellation(job_id)

        started_job = self._job_service.start_document(
            job_id,
            document_id,
            stage=IngestionStage.VALIDATING,
        )

        if started_job.terminal:
            raise DocumentProcessingCancelled(
                f"Ingestion job {job_id} was cancelled before document "
                "processing started."
            )

        document = self._find_document(started_job, document_id)
        attributes = self._initial_processing_attributes(
            started_job,
            document,
        )
        warnings: list[IngestionDiagnostic] = []

        content = self._run_stage(
            stage=IngestionStage.VALIDATING,
            failure_category=IngestionFailureCategory.FILE_ACCESS,
            code="DOCUMENT_CONTENT_LOAD_FAILED",
            operation=lambda: self._load_content(
                started_job,
                document,
            ),
        )

        upload = self._run_stage(
            stage=IngestionStage.VALIDATING,
            failure_category=IngestionFailureCategory.VALIDATION,
            code="DOCUMENT_VALIDATION_FAILED",
            operation=lambda: self._prepare_upload(
                started_job,
                document,
                content,
            ),
        )

        self._set_processing_values(
            attributes,
            content_size_bytes=len(content),
            checksum_sha256=upload.checksum_sha256,
            document_format=upload.document_format.value,
        )
        self._checkpoint(
            job_id,
            document_id,
            stage=IngestionStage.VALIDATING,
            progress_percent=10,
            warnings=warnings,
            attributes=attributes,
        )

        self._checkpoint(
            job_id,
            document_id,
            stage=IngestionStage.PARSING,
            progress_percent=15,
            warnings=warnings,
            attributes=attributes,
        )
        parsed_document = self._run_stage(
            stage=IngestionStage.PARSING,
            failure_category=IngestionFailureCategory.PARSING,
            code="DOCUMENT_PARSING_FAILED",
            operation=lambda: self._parser.parse(upload, content),
        )
        self._add_warning_messages(
            warnings,
            parsed_document.warnings,
            stage=IngestionStage.PARSING,
            code="DOCUMENT_PARSER_WARNING",
        )
        self._set_processing_values(
            attributes,
            parsed_document_id=str(parsed_document.parsed_document_id),
            parsed_page_count=parsed_document.page_count,
            parsed_character_count=parsed_document.character_count,
            parser_name=parsed_document.parser_name,
            parser_version=parsed_document.parser_version,
            parsing_confidence=parsed_document.extraction_confidence,
        )
        self._checkpoint(
            job_id,
            document_id,
            stage=IngestionStage.PARSING,
            progress_percent=30,
            warnings=warnings,
            attributes=attributes,
        )
        self._raise_for_stage_errors(
            parsed_document.errors,
            stage=IngestionStage.PARSING,
            failure_category=IngestionFailureCategory.PARSING,
            code="DOCUMENT_PARSER_REPORTED_ERRORS",
        )

        self._checkpoint(
            job_id,
            document_id,
            stage=IngestionStage.EXTRACTING_METADATA,
            progress_percent=35,
            warnings=warnings,
            attributes=attributes,
        )
        extracted_metadata = self._run_stage(
            stage=IngestionStage.EXTRACTING_METADATA,
            failure_category=(
                IngestionFailureCategory.METADATA_EXTRACTION
            ),
            code="METADATA_EXTRACTION_FAILED",
            operation=lambda: self._metadata_extractor.extract(
                parsed_document,
                document_id=document_id,
                filename=document.filename,
                raw_metadata=upload.metadata,
            ),
        )
        self._record_metadata_summary(attributes, extracted_metadata)
        self._checkpoint(
            job_id,
            document_id,
            stage=IngestionStage.EXTRACTING_METADATA,
            progress_percent=45,
            warnings=warnings,
            attributes=attributes,
        )

        self._checkpoint(
            job_id,
            document_id,
            stage=IngestionStage.EXTRACTING_ENGINEERING_FACTS,
            progress_percent=50,
            warnings=warnings,
            attributes=attributes,
        )
        extraction_result = self._run_stage(
            stage=IngestionStage.EXTRACTING_ENGINEERING_FACTS,
            failure_category=(
                IngestionFailureCategory.ENGINEERING_EXTRACTION
            ),
            code="ENGINEERING_EXTRACTION_FAILED",
            operation=lambda: self._engineering_extractor.extract(
                parsed_document,
                extracted_metadata,
            ),
        )
        self._add_warning_messages(
            warnings,
            extraction_result.warnings,
            stage=IngestionStage.EXTRACTING_ENGINEERING_FACTS,
            code="ENGINEERING_EXTRACTION_WARNING",
        )

        if extraction_result.fact_count == 0:
            self._add_warning_messages(
                warnings,
                [
                    "No engineering facts were extracted from the "
                    "document."
                ],
                stage=IngestionStage.EXTRACTING_ENGINEERING_FACTS,
                code="NO_ENGINEERING_FACTS",
            )

        self._record_extraction_summary(attributes, extraction_result)
        self._checkpoint(
            job_id,
            document_id,
            stage=IngestionStage.EXTRACTING_ENGINEERING_FACTS,
            progress_percent=65,
            warnings=warnings,
            attributes=attributes,
        )
        self._raise_for_stage_errors(
            extraction_result.errors,
            stage=IngestionStage.EXTRACTING_ENGINEERING_FACTS,
            failure_category=(
                IngestionFailureCategory.ENGINEERING_EXTRACTION
            ),
            code="ENGINEERING_EXTRACTOR_REPORTED_ERRORS",
        )

        self._checkpoint(
            job_id,
            document_id,
            stage=IngestionStage.BUILDING_INDEX,
            progress_percent=70,
            warnings=warnings,
            attributes=attributes,
        )
        index_build = self._run_stage(
            stage=IngestionStage.BUILDING_INDEX,
            failure_category=IngestionFailureCategory.INDEXING,
            code="KNOWLEDGE_INDEX_BUILD_FAILED",
            operation=lambda: self._knowledge_indexer.build(
                extraction_result.facts,
                metadata=extracted_metadata,
            ),
        )
        self._add_warning_messages(
            warnings,
            index_build.warnings,
            stage=IngestionStage.BUILDING_INDEX,
            code="KNOWLEDGE_INDEX_WARNING",
        )

        if extraction_result.fact_count > 0 and not index_build.records:
            self._add_warning_messages(
                warnings,
                [
                    "Engineering facts were extracted, but no new "
                    "knowledge index records were generated."
                ],
                stage=IngestionStage.BUILDING_INDEX,
                code="NO_KNOWLEDGE_INDEX_RECORDS",
            )

        self._record_index_summary(attributes, index_build)
        self._checkpoint(
            job_id,
            document_id,
            stage=IngestionStage.BUILDING_INDEX,
            progress_percent=80,
            warnings=warnings,
            attributes=attributes,
        )
        self._raise_for_stage_errors(
            index_build.errors,
            stage=IngestionStage.BUILDING_INDEX,
            failure_category=IngestionFailureCategory.INDEXING,
            code="KNOWLEDGE_INDEX_REPORTED_ERRORS",
        )

        publication: RepositoryPublicationResult | None = None

        if index_build.records:
            self._checkpoint(
                job_id,
                document_id,
                stage=IngestionStage.CONVERTING_KNOWLEDGE,
                progress_percent=85,
                warnings=warnings,
                attributes=attributes,
            )
            publication = self._run_stage(
                stage=IngestionStage.REGISTERING_KNOWLEDGE,
                failure_category=(
                    IngestionFailureCategory.REPOSITORY_PUBLICATION
                ),
                code="KNOWLEDGE_REPOSITORY_PUBLICATION_FAILED",
                operation=lambda: self._repository_publisher.publish_build(
                    index_build,
                    created_by=self._config.created_by,
                    skip_existing=(
                        self._config.skip_existing_knowledge
                    ),
                ),
            )
            self._add_warning_messages(
                warnings,
                publication.warnings,
                stage=IngestionStage.REGISTERING_KNOWLEDGE,
                code="KNOWLEDGE_PUBLICATION_WARNING",
            )
            self._record_publication_summary(attributes, publication)
            self._checkpoint(
                job_id,
                document_id,
                stage=IngestionStage.REGISTERING_KNOWLEDGE,
                progress_percent=95,
                warnings=warnings,
                attributes=attributes,
            )

            publication_errors = list(publication.errors)
            if publication.failed_count:
                publication_errors.append(
                    f"{publication.failed_count} knowledge record(s) "
                    "failed controlled repository registration."
                )

            if not publication.successful and not publication_errors:
                publication_errors.append(
                    "Controlled repository publication did not complete "
                    "successfully."
                )

            self._raise_for_stage_errors(
                publication_errors,
                stage=IngestionStage.REGISTERING_KNOWLEDGE,
                failure_category=(
                    IngestionFailureCategory.REPOSITORY_PUBLICATION
                ),
                code="KNOWLEDGE_REPOSITORY_REPORTED_ERRORS",
                details={
                    "registered_count": publication.registered_count,
                    "skipped_count": publication.skipped_count,
                    "failed_count": publication.failed_count,
                },
            )
        else:
            self._set_processing_values(
                attributes,
                registered_knowledge_count=0,
                skipped_knowledge_count=0,
                failed_knowledge_count=0,
                registered_knowledge_ids=[],
            )

        self._checkpoint(
            job_id,
            document_id,
            stage=IngestionStage.FINALISING,
            progress_percent=98,
            warnings=warnings,
            attributes=attributes,
        )

        registered_count = (
            publication.registered_count if publication else 0
        )
        skipped_count = (
            publication.skipped_count if publication else 0
        )

        return self._job_service.complete_document(
            job_id,
            document_id,
            registered_knowledge_count=registered_count,
            skipped_knowledge_count=skipped_count,
            diagnostics=warnings,
            metadata=attributes,
        )

    def _load_content(
        self,
        job: IngestionJob,
        document: IngestionDocumentResult,
    ) -> bytes:
        """Load and normalise source content through the storage boundary."""

        try:
            content = self._content_loader.load(job, document)
        except Exception as error:
            raise DocumentContentLoadError(
                f"Unable to load source content for "
                f"{document.source_name}: {error}"
            ) from error

        if not isinstance(content, (bytes, bytearray, memoryview)):
            raise DocumentContentLoadError(
                "The document content loader must return bytes."
            )

        return bytes(content)

    def _prepare_upload(
        self,
        job: IngestionJob,
        document: IngestionDocumentResult,
        content: bytes,
    ) -> DocumentUpload:
        """Build the validated parser input for one job document."""

        actual_size = len(content)

        if (
            self._config.verify_declared_file_size
            and document.file_size_bytes is not None
            and document.file_size_bytes != actual_size
        ):
            raise ValueError(
                "Declared file size does not match loaded content: "
                f"expected {document.file_size_bytes} bytes, received "
                f"{actual_size} bytes."
            )

        checksum = DocumentUpload.calculate_sha256(content)

        if (
            self._config.verify_checksum_sha256
            and document.checksum_sha256 is not None
            and document.checksum_sha256.lower() != checksum
        ):
            raise ValueError(
                "Declared SHA-256 checksum does not match loaded content."
            )

        document_format = self._infer_document_format(
            document.filename
        )
        supplier = self._optional_text_attribute(
            document.attributes,
            "supplier",
            maximum_length=255,
        )
        storage_key = document.source_path or document.source_name

        if len(storage_key) > 1024:
            storage_key = document.source_name

        archive_member_count = self._optional_non_negative_integer(
            document.attributes.get("archive_member_count")
        )
        password_protected = document.attributes.get(
            "password_protected",
            False,
        )

        if not isinstance(password_protected, bool):
            password_protected = False

        return DocumentUpload(
            document_id=document.document_id,
            filename=document.filename,
            document_format=document_format,
            media_type=document.media_type,
            size_bytes=actual_size,
            storage_key=storage_key,
            checksum_sha256=checksum,
            source=DocumentSource(
                source_name=job.source_type.value,
                source_uri=document.source_path,
                supplier=supplier,
                uploaded_by=job.submitted_by,
            ),
            original_filename=document.source_name,
            password_protected=password_protected,
            archive_member_count=archive_member_count,
            metadata={
                "job_id": str(job.job_id),
                "correlation_id": job.correlation_id,
                "job_metadata": dict(job.metadata),
                "document_attributes": dict(document.attributes),
            },
        )

    def _checkpoint(
        self,
        job_id: UUID,
        document_id: UUID,
        *,
        stage: IngestionStage,
        progress_percent: int,
        warnings: Sequence[IngestionDiagnostic],
        attributes: Mapping[str, Any],
    ) -> IngestionJob:
        """Persist a cancellable document-processing checkpoint."""

        self._check_cancellation(job_id)
        return self._job_service.update_document_progress(
            job_id,
            document_id,
            stage=stage,
            progress_percent=progress_percent,
            diagnostics=list(warnings),
            warning_count=len(warnings),
            error_count=0,
            metadata=dict(attributes),
        )

    def _check_cancellation(self, job_id: UUID) -> None:
        """Apply a cooperative cancellation request between stages."""

        job = self._job_service.get(job_id)

        if job.status == IngestionJobStatus.CANCELLED:
            raise DocumentProcessingCancelled(
                f"Ingestion job {job_id} has been cancelled."
            )

        if job.cancellation_requested:
            if not job.terminal:
                self._job_service.apply_cancellation(job_id)
            raise DocumentProcessingCancelled(
                f"Cancellation was applied to ingestion job {job_id}."
            )

    def _run_stage(
        self,
        *,
        stage: IngestionStage,
        failure_category: IngestionFailureCategory,
        code: str,
        operation: Callable[[], _ResultT],
    ) -> _ResultT:
        """Execute one operation and normalise component exceptions."""

        try:
            return operation()
        except DocumentProcessingFailure:
            raise
        except UnsupportedDocumentFormatError as error:
            failure = self._build_failure(
                error,
                stage=stage,
                failure_category=(
                    IngestionFailureCategory.UNSUPPORTED_FORMAT
                ),
                code="UNSUPPORTED_DOCUMENT_FORMAT",
            )
            raise failure from error
        except Exception as error:
            failure = self._build_failure(
                error,
                stage=stage,
                failure_category=failure_category,
                code=code,
            )
            raise failure from error

    def _build_failure(
        self,
        error: Exception,
        *,
        stage: IngestionStage,
        failure_category: IngestionFailureCategory,
        code: str,
    ) -> DocumentProcessingFailure:
        """Create a bounded diagnostic failure from a component exception."""

        message = self._bounded_message(str(error))
        if not message:
            message = type(error).__name__

        recoverable = isinstance(
            error,
            (
                DocumentContentLoadError,
                DocumentParserError,
                MetadataExtractionError,
                EngineeringExtractionError,
                RepositoryPublisherError,
                ValidationError,
                OSError,
                ValueError,
            ),
        )

        return DocumentProcessingFailure(
            stage=stage,
            failure_category=failure_category,
            code=code,
            message=message,
            recoverable=recoverable,
            details={
                "exception_type": type(error).__name__,
                "pipeline_version": self.PIPELINE_VERSION,
            },
        )

    def _raise_for_stage_errors(
        self,
        errors: Sequence[str],
        *,
        stage: IngestionStage,
        failure_category: IngestionFailureCategory,
        code: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Fail a stage when a component reports structured errors."""

        messages = [
            message.strip()
            for message in errors
            if isinstance(message, str) and message.strip()
        ]

        if not messages:
            return

        raise DocumentProcessingFailure(
            stage=stage,
            failure_category=failure_category,
            code=code,
            message=self._bounded_message("; ".join(messages)),
            recoverable=True,
            details={
                "reported_error_count": len(messages),
                "pipeline_version": self.PIPELINE_VERSION,
                **dict(details or {}),
            },
        )

    def _record_document_failure(
        self,
        job_id: UUID,
        document_id: UUID,
        failure: DocumentProcessingFailure,
    ) -> IngestionJob:
        """Persist one normalised document failure."""

        job = self._job_service.get(job_id)

        if job.terminal:
            return job

        document = self._find_document(job, document_id)
        attributes = self._copy_attributes(document.attributes)
        self._set_processing_values(
            attributes,
            failed_stage=failure.stage.value,
            failure_category=failure.failure_category.value,
            failure_code=failure.code,
            failure_recoverable=failure.recoverable,
        )

        diagnostic = IngestionDiagnostic(
            code=failure.code,
            message=self._bounded_message(str(failure)),
            stage=failure.stage,
            failure_category=failure.failure_category,
            document_id=document_id,
            recoverable=failure.recoverable,
            details=dict(failure.details),
        )

        return self._job_service.fail_document(
            job_id,
            document_id,
            diagnostics=[diagnostic],
            metadata=attributes,
        )

    def _require_resumable_processing_state(
        self,
        job: IngestionJob,
    ) -> None:
        """Prevent unsafe replay of a partially processed document."""

        processing_documents = [
            document.document_id
            for document in job.documents
            if document.status == IngestionDocumentStatus.PROCESSING
        ]

        if processing_documents:
            identifiers = ", ".join(
                str(document_id)
                for document_id in processing_documents
            )
            raise DocumentProcessingStateError(
                "The ingestion job already contains an active document and "
                "cannot be resumed without an explicit recovery decision: "
                f"{identifiers}."
            )

    def _initial_processing_attributes(
        self,
        job: IngestionJob,
        document: IngestionDocumentResult,
    ) -> dict[str, Any]:
        """Create cumulative, bounded document processing metadata."""

        attributes = self._copy_attributes(document.attributes)
        self._set_processing_values(
            attributes,
            pipeline_version=self.PIPELINE_VERSION,
            job_id=str(job.job_id),
            document_id=str(document.document_id),
            submitted_by=job.submitted_by,
            source_type=job.source_type.value,
        )
        return attributes

    def _record_metadata_summary(
        self,
        attributes: dict[str, Any],
        metadata: ExtractedDocumentMetadata,
    ) -> None:
        """Record compact extracted metadata without storing source text."""

        reference = metadata.product_reference
        self._set_processing_values(
            attributes,
            metadata_id=str(metadata.metadata_id),
            document_type=metadata.document_type.value,
            language=metadata.language.value,
            metadata_confidence=metadata.metadata_confidence,
            manufacturer=reference.manufacturer,
            brand=reference.brand,
            product_family=reference.product_family,
            product_series=reference.product_series,
            model_numbers=list(reference.model_numbers),
            part_numbers=list(reference.part_numbers),
            standards_referenced=list(metadata.standards_referenced),
        )

    def _record_extraction_summary(
        self,
        attributes: dict[str, Any],
        result: EngineeringExtractionResult,
    ) -> None:
        """Record compact engineering extraction statistics."""

        self._set_processing_values(
            attributes,
            extraction_id=str(result.extraction_id),
            extracted_fact_count=result.fact_count,
            safety_fact_count=result.safety_fact_count,
            extraction_confidence=result.extraction_confidence,
            processed_block_count=result.processed_block_count,
            skipped_block_count=result.skipped_block_count,
            extraction_engine=result.extraction_engine,
            extraction_engine_version=result.extraction_engine_version,
        )

    def _record_index_summary(
        self,
        attributes: dict[str, Any],
        result: KnowledgeIndexBuildResult,
    ) -> None:
        """Record compact knowledge-index build statistics."""

        self._set_processing_values(
            attributes,
            index_build_id=str(result.build_id),
            generated_knowledge_count=result.indexed_fact_count,
            indexed_fact_count=result.indexed_fact_count,
            duplicate_fact_count=result.duplicate_fact_count,
            skipped_fact_count=result.skipped_fact_count,
            index_engine=result.index_engine,
            index_version=result.index_version,
        )

    def _record_publication_summary(
        self,
        attributes: dict[str, Any],
        result: RepositoryPublicationResult,
    ) -> None:
        """Record controlled repository-registration outcomes."""

        self._set_processing_values(
            attributes,
            registered_knowledge_count=result.registered_count,
            skipped_knowledge_count=result.skipped_count,
            failed_knowledge_count=result.failed_count,
            registered_knowledge_ids=list(
                result.registered_knowledge_ids
            ),
            repository_publication_successful=result.successful,
        )

    @staticmethod
    def _find_document(
        job: IngestionJob,
        document_id: UUID,
    ) -> IngestionDocumentResult:
        """Find one document in a job snapshot."""

        for document in job.documents:
            if document.document_id == document_id:
                return document

        raise DocumentProcessingStateError(
            f"Document {document_id} was not found in ingestion job "
            f"{job.job_id}."
        )

    @staticmethod
    def _copy_attributes(
        source: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Copy attributes and isolate the orchestrator-owned namespace."""

        attributes = dict(source)
        processing = attributes.get("document_processing")

        if isinstance(processing, Mapping):
            attributes["document_processing"] = dict(processing)
        else:
            attributes["document_processing"] = {}

        return attributes

    @staticmethod
    def _set_processing_values(
        attributes: dict[str, Any],
        **values: Any,
    ) -> None:
        """Merge values into the orchestrator-owned metadata namespace."""

        processing = attributes.get("document_processing")

        if not isinstance(processing, dict):
            processing = {}
            attributes["document_processing"] = processing

        processing.update(values)

    @staticmethod
    def _add_warning_messages(
        warnings: list[IngestionDiagnostic],
        messages: Sequence[str],
        *,
        stage: IngestionStage,
        code: str,
    ) -> None:
        """Append non-empty component warnings as structured diagnostics."""

        for message in messages:
            if not isinstance(message, str):
                continue

            cleaned = message.strip()
            if not cleaned:
                continue

            warnings.append(
                IngestionDiagnostic(
                    code=code,
                    message=DocumentProcessingOrchestrator._bounded_message(
                        cleaned
                    ),
                    stage=stage,
                    recoverable=True,
                )
            )

    @staticmethod
    def _infer_document_format(filename: str) -> DocumentFormat:
        """Infer the declared document format from a filename suffix."""

        normalised = filename.replace("\\", "/").rsplit("/", 1)[-1]
        suffix = normalised.rpartition(".")[2].lower()

        if not suffix:
            return DocumentFormat.UNKNOWN

        try:
            return DocumentFormat(suffix)
        except ValueError:
            return DocumentFormat.UNKNOWN

    @staticmethod
    def _optional_text_attribute(
        attributes: Mapping[str, Any],
        key: str,
        *,
        maximum_length: int,
    ) -> str | None:
        """Return a bounded optional text attribute."""

        value = attributes.get(key)

        if not isinstance(value, str):
            return None

        cleaned = value.strip()

        if not cleaned or len(cleaned) > maximum_length:
            return None

        return cleaned

    @staticmethod
    def _optional_non_negative_integer(value: Any) -> int | None:
        """Return an optional non-negative integer without coercing booleans."""

        if isinstance(value, bool):
            return None

        if isinstance(value, int) and value >= 0:
            return value

        return None

    @staticmethod
    def _bounded_message(message: str, maximum: int = 2000) -> str:
        """Return a diagnostic-safe message within model limits."""

        cleaned = " ".join(message.split())

        if len(cleaned) <= maximum:
            return cleaned

        return cleaned[: maximum - 3] + "..."


__all__ = [
    "DocumentContentLoadError",
    "DocumentContentLoader",
    "DocumentProcessingCancelled",
    "DocumentProcessingFailure",
    "DocumentProcessingOrchestrator",
    "DocumentProcessingOrchestratorConfig",
    "DocumentProcessingOrchestratorError",
    "DocumentProcessingStateError",
]