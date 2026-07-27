"""Tests for the Engineer4Me document-processing orchestrator."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass, field
from hashlib import sha256
from types import SimpleNamespace
from typing import Any, Callable
from uuid import UUID, uuid4

import pytest

from app.ingestion.document_models import DocumentFormat
from app.ingestion.document_parser import (
    UnsupportedDocumentFormatError,
)
from app.ingestion.document_processing_orchestrator import (
    DocumentProcessingFailure,
    DocumentProcessingOrchestrator,
    DocumentProcessingOrchestratorConfig,
    DocumentProcessingStateError,
)
from app.ingestion.ingestion_job_models import (
    IngestionDocumentResult,
    IngestionDocumentStatus,
    IngestionFailureCategory,
    IngestionJob,
    IngestionJobStatus,
    IngestionJobType,
    IngestionSourceType,
    IngestionStage,
)
from app.ingestion.ingestion_job_service import IngestionJobService


DEFAULT_CONTENT = (
    b"Rosemount pressure transmitter technical datasheet.\n"
    b"Verify process isolation before maintenance.\n"
)


def checksum_for(content: bytes) -> str:
    """Return a lowercase SHA-256 checksum."""

    return sha256(content).hexdigest()


def find_document(
    job: IngestionJob,
    document_id: UUID,
) -> IngestionDocumentResult:
    """Return one document from an ingestion job snapshot."""

    return next(
        document
        for document in job.documents
        if document.document_id == document_id
    )


def build_submitted_job(
    *,
    filenames: tuple[str, ...] = ("manual.txt",),
    content_by_name: dict[str, bytes] | None = None,
    declare_size: bool = True,
    declare_checksum: bool = True,
    document_attributes: dict[str, Any] | None = None,
) -> tuple[
    IngestionJobService,
    IngestionJob,
    dict[str, bytes],
]:
    """Build and submit a valid pending ingestion job."""

    contents = content_by_name or {
        filename: DEFAULT_CONTENT
        for filename in filenames
    }
    documents = [
        IngestionDocumentResult(
            source_name=filename,
            source_path=f"uploads/{filename}",
            media_type="text/plain",
            file_size_bytes=(
                len(contents[filename])
                if declare_size
                else None
            ),
            checksum_sha256=(
                checksum_for(contents[filename])
                if declare_checksum
                else None
            ),
            attributes=dict(document_attributes or {}),
        )
        for filename in filenames
    ]
    job = IngestionJob(
        job_type=(
            IngestionJobType.SINGLE_DOCUMENT
            if len(documents) == 1
            else IngestionJobType.DOCUMENT_BATCH
        ),
        source_type=IngestionSourceType.API_UPLOAD,
        submitted_by="orchestrator-test",
        correlation_id="phase-6-orchestrator-test",
        documents=documents,
        total_document_count=len(documents),
        metadata={"test_suite": "document_processing_orchestrator"},
    )
    service = IngestionJobService()
    service.submit(job)

    return service, job, contents


@dataclass
class FakeContentLoader:
    """Record document-content loads and provide configured bytes."""

    content_by_name: dict[str, Any]
    errors_by_name: dict[str, Exception] = field(
        default_factory=dict
    )
    calls: list[tuple[UUID, UUID, str]] = field(
        default_factory=list
    )

    def load(
        self,
        job: IngestionJob,
        document: IngestionDocumentResult,
    ) -> bytes:
        """Return configured content or raise a configured error."""

        self.calls.append(
            (
                job.job_id,
                document.document_id,
                document.source_name,
            )
        )

        error = self.errors_by_name.get(document.source_name)
        if error is not None:
            raise error

        return self.content_by_name[document.source_name]


@dataclass
class ParsedResult:
    """Minimal parsed-document result used by the orchestrator."""

    document_id: UUID
    parsed_document_id: UUID = field(default_factory=uuid4)
    page_count: int = 2
    character_count: int = 250
    parser_name: str = "fake-parser"
    parser_version: str = "1.0-test"
    extraction_confidence: float = 0.97
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class FakeParser:
    """Record parser calls and return a configurable result."""

    result: ParsedResult | None = None
    error: Exception | None = None
    before_return: (
        Callable[[Any, bytes], None] | None
    ) = None
    calls: list[tuple[Any, bytes]] = field(default_factory=list)

    def parse(
        self,
        upload: Any,
        content: bytes,
    ) -> ParsedResult:
        """Return the configured parsed document."""

        self.calls.append((upload, content))

        if self.error is not None:
            raise self.error

        if self.before_return is not None:
            self.before_return(upload, content)

        if self.result is not None:
            return self.result

        return ParsedResult(document_id=upload.document_id)


@dataclass
class ProductReferenceResult:
    """Minimal product-reference metadata."""

    manufacturer: str | None = "Emerson"
    brand: str | None = "Rosemount"
    product_family: str | None = "Pressure Transmitters"
    product_series: str | None = "3051"
    model_numbers: list[str] = field(
        default_factory=lambda: ["3051S"]
    )
    part_numbers: list[str] = field(
        default_factory=lambda: ["3051S-T"]
    )


@dataclass
class MetadataResult:
    """Minimal extracted metadata used by the orchestrator."""

    document_id: UUID
    metadata_id: UUID = field(default_factory=uuid4)
    document_type: Any = field(
        default_factory=lambda: SimpleNamespace(
            value="datasheet"
        )
    )
    language: Any = field(
        default_factory=lambda: SimpleNamespace(value="en")
    )
    metadata_confidence: float = 0.91
    product_reference: ProductReferenceResult = field(
        default_factory=ProductReferenceResult
    )
    standards_referenced: list[str] = field(
        default_factory=lambda: ["IEC 61511"]
    )


@dataclass
class FakeMetadataExtractor:
    """Record metadata extraction calls."""

    result: MetadataResult | None = None
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    def extract(
        self,
        document: ParsedResult,
        *,
        document_id: UUID,
        filename: str,
        raw_metadata: dict[str, Any],
    ) -> MetadataResult:
        """Return configured document metadata."""

        self.calls.append(
            {
                "document": document,
                "document_id": document_id,
                "filename": filename,
                "raw_metadata": raw_metadata,
            }
        )

        if self.error is not None:
            raise self.error

        if self.result is not None:
            return self.result

        return MetadataResult(document_id=document_id)


@dataclass
class ExtractionResult:
    """Minimal engineering-extraction result."""

    facts: list[Any] = field(default_factory=list)
    extraction_id: UUID = field(default_factory=uuid4)
    fact_count: int = 0
    safety_fact_count: int = 0
    extraction_confidence: float = 0.89
    processed_block_count: int = 4
    skipped_block_count: int = 0
    extraction_engine: str = "fake-engineering-extractor"
    extraction_engine_version: str = "1.0-test"
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class FakeEngineeringExtractor:
    """Record engineering-fact extraction calls."""

    result: ExtractionResult = field(
        default_factory=ExtractionResult
    )
    error: Exception | None = None
    calls: list[tuple[ParsedResult, MetadataResult]] = field(
        default_factory=list
    )

    def extract(
        self,
        document: ParsedResult,
        metadata: MetadataResult,
    ) -> ExtractionResult:
        """Return a configured extraction result."""

        self.calls.append((document, metadata))

        if self.error is not None:
            raise self.error

        return self.result


@dataclass
class IndexBuildResult:
    """Minimal deterministic knowledge-index build result."""

    records: list[Any] = field(default_factory=list)
    build_id: UUID = field(default_factory=uuid4)
    indexed_fact_count: int = 0
    duplicate_fact_count: int = 0
    skipped_fact_count: int = 0
    index_engine: str = "fake-knowledge-indexer"
    index_version: str = "1.0-test"
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class FakeKnowledgeIndexer:
    """Record index-build calls."""

    result: IndexBuildResult = field(
        default_factory=IndexBuildResult
    )
    error: Exception | None = None
    calls: list[tuple[list[Any], MetadataResult]] = field(
        default_factory=list
    )

    def build(
        self,
        facts: list[Any],
        *,
        metadata: MetadataResult,
    ) -> IndexBuildResult:
        """Return a configured index build."""

        self.calls.append((facts, metadata))

        if self.error is not None:
            raise self.error

        return self.result


@dataclass
class PublicationResult:
    """Minimal controlled repository-publication result."""

    registered_count: int = 0
    skipped_count: int = 0
    failed_count: int = 0
    registered_knowledge_ids: list[str] = field(
        default_factory=list
    )
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    successful: bool = True


@dataclass
class FakeRepositoryPublisher:
    """Record controlled publication calls."""

    result: PublicationResult = field(
        default_factory=PublicationResult
    )
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    def publish_build(
        self,
        build: IndexBuildResult,
        *,
        created_by: str,
        skip_existing: bool,
    ) -> PublicationResult:
        """Return a configured publication result."""

        self.calls.append(
            {
                "build": build,
                "created_by": created_by,
                "skip_existing": skip_existing,
            }
        )

        if self.error is not None:
            raise self.error

        return self.result


@dataclass
class PipelineFakes:
    """All injected boundaries used by one orchestrator."""

    loader: FakeContentLoader
    parser: FakeParser
    metadata_extractor: FakeMetadataExtractor
    engineering_extractor: FakeEngineeringExtractor
    indexer: FakeKnowledgeIndexer
    publisher: FakeRepositoryPublisher


def build_orchestrator(
    service: IngestionJobService,
    contents: dict[str, Any],
    *,
    loader: FakeContentLoader | None = None,
    parser: FakeParser | None = None,
    metadata_extractor: FakeMetadataExtractor | None = None,
    engineering_extractor: FakeEngineeringExtractor | None = None,
    indexer: FakeKnowledgeIndexer | None = None,
    publisher: FakeRepositoryPublisher | None = None,
    config: DocumentProcessingOrchestratorConfig | None = None,
) -> tuple[DocumentProcessingOrchestrator, PipelineFakes]:
    """Build an orchestrator with fully observable fake boundaries."""

    fakes = PipelineFakes(
        loader=loader or FakeContentLoader(contents),
        parser=parser or FakeParser(),
        metadata_extractor=(
            metadata_extractor or FakeMetadataExtractor()
        ),
        engineering_extractor=(
            engineering_extractor
            or FakeEngineeringExtractor()
        ),
        indexer=indexer or FakeKnowledgeIndexer(),
        publisher=publisher or FakeRepositoryPublisher(),
    )
    orchestrator = DocumentProcessingOrchestrator(
        job_service=service,
        content_loader=fakes.loader,
        parser=fakes.parser,
        metadata_extractor=fakes.metadata_extractor,
        engineering_extractor=fakes.engineering_extractor,
        knowledge_indexer=fakes.indexer,
        repository_publisher=fakes.publisher,
        config=config,
    )

    return orchestrator, fakes


def assert_document_failure(
    job: IngestionJob,
    *,
    code: str,
    stage: IngestionStage,
    category: IngestionFailureCategory,
    recoverable: bool,
) -> IngestionDocumentResult:
    """Assert one normalised document failure."""

    assert job.status == IngestionJobStatus.FAILED
    assert job.failed_document_count == 1
    assert job.error_count == 1

    document = job.documents[0]
    assert document.status == IngestionDocumentStatus.FAILED
    assert len(document.errors) == 1

    diagnostic = document.errors[0]
    assert diagnostic.code == code
    assert diagnostic.stage == stage
    assert diagnostic.failure_category == category
    assert diagnostic.document_id == document.document_id
    assert diagnostic.recoverable is recoverable

    processing = document.attributes["document_processing"]
    assert processing["failed_stage"] == stage.value
    assert processing["failure_category"] == category.value
    assert processing["failure_code"] == code
    assert processing["failure_recoverable"] is recoverable

    return document


def test_config_has_safety_preserving_defaults():
    """Default configuration preserves validation and batch isolation."""

    config = DocumentProcessingOrchestratorConfig()

    assert config.continue_after_document_failure is True
    assert config.verify_declared_file_size is True
    assert config.verify_checksum_sha256 is True
    assert config.skip_existing_knowledge is True
    assert config.created_by == "document-ingestion"


def test_config_normalises_created_by():
    """Publication ownership is stripped before use."""

    config = DocumentProcessingOrchestratorConfig(
        created_by="  ingestion-worker  ",
    )

    assert config.created_by == "ingestion-worker"


@pytest.mark.parametrize(
    "created_by",
    [
        "   ",
        "x" * 256,
    ],
)
def test_config_rejects_invalid_created_by(created_by):
    """Publication ownership must be present and bounded."""

    with pytest.raises(ValueError, match="created_by"):
        DocumentProcessingOrchestratorConfig(
            created_by=created_by,
        )


def test_config_is_immutable():
    """Runtime controls cannot change during a processing run."""

    config = DocumentProcessingOrchestratorConfig()

    with pytest.raises(FrozenInstanceError):
        config.created_by = "changed"


def test_orchestrator_exposes_injected_service_and_config():
    """The lifecycle service and configuration remain observable."""

    service, _, contents = build_submitted_job()
    config = DocumentProcessingOrchestratorConfig(
        created_by="phase-6-test",
    )
    orchestrator, _ = build_orchestrator(
        service,
        contents,
        config=config,
    )

    assert orchestrator.job_service is service
    assert orchestrator.config is config
    assert orchestrator.PIPELINE_VERSION == "1.0.0"


def test_process_pending_job_without_facts_completes():
    """A valid document with no facts completes with a warning."""

    service, job, contents = build_submitted_job()
    orchestrator, fakes = build_orchestrator(
        service,
        contents,
    )

    completed = orchestrator.process_job(job.job_id)

    assert completed.status == IngestionJobStatus.COMPLETED
    assert completed.stage == IngestionStage.COMPLETE
    assert completed.progress_percent == 100
    assert completed.completed_document_count == 1
    assert completed.failed_document_count == 0
    assert completed.warning_count == 1
    assert completed.error_count == 0

    document = completed.documents[0]
    assert document.status == IngestionDocumentStatus.COMPLETED
    assert document.attempt_count == 1
    assert document.registered_knowledge_count == 0
    assert document.skipped_knowledge_count == 0
    assert [item.code for item in document.warnings] == [
        "NO_ENGINEERING_FACTS"
    ]

    processing = document.attributes["document_processing"]
    assert processing["pipeline_version"] == "1.0.0"
    assert processing["content_size_bytes"] == len(DEFAULT_CONTENT)
    assert processing["checksum_sha256"] == checksum_for(
        DEFAULT_CONTENT
    )
    assert processing["document_format"] == "txt"
    assert processing["parsed_page_count"] == 2
    assert processing["manufacturer"] == "Emerson"
    assert processing["brand"] == "Rosemount"
    assert processing["extracted_fact_count"] == 0
    assert processing["generated_knowledge_count"] == 0
    assert processing["registered_knowledge_count"] == 0

    assert len(fakes.loader.calls) == 1
    assert len(fakes.parser.calls) == 1
    assert len(fakes.metadata_extractor.calls) == 1
    assert len(fakes.engineering_extractor.calls) == 1
    assert len(fakes.indexer.calls) == 1
    assert fakes.publisher.calls == []


def test_process_queued_job_starts_and_completes():
    """A queued job enters processing automatically."""

    service, job, contents = build_submitted_job()
    service.queue(job.job_id)
    orchestrator, _ = build_orchestrator(service, contents)

    completed = orchestrator.process_job(job.job_id)

    assert completed.status == IngestionJobStatus.COMPLETED
    assert completed.documents[0].status == (
        IngestionDocumentStatus.COMPLETED
    )


def test_process_resumable_processing_job_completes():
    """A processing job with no active document can resume safely."""

    service, job, contents = build_submitted_job()
    service.start(
        job.job_id,
        stage=IngestionStage.VALIDATING,
    )
    orchestrator, _ = build_orchestrator(service, contents)

    completed = orchestrator.process_job(job.job_id)

    assert completed.status == IngestionJobStatus.COMPLETED
    assert completed.completed_document_count == 1


def test_full_pipeline_records_publication_and_warnings():
    """Successful controlled publication is reflected in job output."""

    service, job, contents = build_submitted_job(
        document_attributes={"supplier": "OEM source"},
    )
    facts = [
        SimpleNamespace(fact_id=uuid4()),
        SimpleNamespace(fact_id=uuid4()),
    ]
    extraction = ExtractionResult(
        facts=facts,
        fact_count=2,
        safety_fact_count=1,
        warnings=["Engineering confidence review recommended."],
    )
    index_build = IndexBuildResult(
        records=[
            SimpleNamespace(index_id=uuid4()),
            SimpleNamespace(index_id=uuid4()),
        ],
        indexed_fact_count=2,
        duplicate_fact_count=1,
        warnings=["One duplicate fact was consolidated."],
    )
    publication = PublicationResult(
        registered_count=1,
        skipped_count=1,
        registered_knowledge_ids=["knowledge-pressure-001"],
        warnings=["Existing knowledge record was skipped."],
    )
    parser = FakeParser(
        result=ParsedResult(
            document_id=job.documents[0].document_id,
            warnings=["Minor parser layout warning."],
        )
    )
    publisher = FakeRepositoryPublisher(result=publication)
    orchestrator, fakes = build_orchestrator(
        service,
        contents,
        parser=parser,
        engineering_extractor=FakeEngineeringExtractor(
            result=extraction
        ),
        indexer=FakeKnowledgeIndexer(result=index_build),
        publisher=publisher,
    )

    completed = orchestrator.process_job(job.job_id)

    assert completed.status == IngestionJobStatus.COMPLETED
    assert completed.warning_count == 4
    assert completed.registered_knowledge_count == 1

    document = completed.documents[0]
    assert document.registered_knowledge_count == 1
    assert document.skipped_knowledge_count == 1
    assert [item.code for item in document.warnings] == [
        "DOCUMENT_PARSER_WARNING",
        "ENGINEERING_EXTRACTION_WARNING",
        "KNOWLEDGE_INDEX_WARNING",
        "KNOWLEDGE_PUBLICATION_WARNING",
    ]

    processing = document.attributes["document_processing"]
    assert processing["extracted_fact_count"] == 2
    assert processing["safety_fact_count"] == 1
    assert processing["indexed_fact_count"] == 2
    assert processing["duplicate_fact_count"] == 1
    assert processing["registered_knowledge_count"] == 1
    assert processing["skipped_knowledge_count"] == 1
    assert processing["failed_knowledge_count"] == 0
    assert processing["registered_knowledge_ids"] == [
        "knowledge-pressure-001"
    ]
    assert processing["repository_publication_successful"] is True

    upload = fakes.parser.calls[0][0]
    assert upload.source.supplier == "OEM source"
    assert upload.metadata["job_id"] == str(job.job_id)
    assert upload.metadata["job_metadata"] == job.metadata
    assert publisher.calls[0]["build"] is index_build


def test_publication_receives_configured_controls():
    """Publication receives explicit ownership and duplicate policy."""

    service, job, contents = build_submitted_job()
    fact = SimpleNamespace(fact_id=uuid4())
    extraction = ExtractionResult(
        facts=[fact],
        fact_count=1,
    )
    index_build = IndexBuildResult(
        records=[SimpleNamespace(index_id=uuid4())],
        indexed_fact_count=1,
    )
    publisher = FakeRepositoryPublisher()
    config = DocumentProcessingOrchestratorConfig(
        created_by="  controlled-worker  ",
        skip_existing_knowledge=False,
    )
    orchestrator, _ = build_orchestrator(
        service,
        contents,
        engineering_extractor=FakeEngineeringExtractor(
            result=extraction
        ),
        indexer=FakeKnowledgeIndexer(result=index_build),
        publisher=publisher,
        config=config,
    )

    completed = orchestrator.process_job(job.job_id)

    assert completed.status == IngestionJobStatus.COMPLETED
    assert publisher.calls == [
        {
            "build": index_build,
            "created_by": "controlled-worker",
            "skip_existing": False,
        }
    ]


def test_process_document_completes_only_requested_document():
    """Direct document processing leaves job finalisation to caller."""

    service, job, contents = build_submitted_job(
        filenames=("first.txt", "second.txt"),
    )
    processing = service.start(
        job.job_id,
        stage=IngestionStage.VALIDATING,
    )
    first = processing.documents[0]
    orchestrator, fakes = build_orchestrator(
        service,
        contents,
    )

    updated = orchestrator.process_document(
        job.job_id,
        first.document_id,
    )

    assert updated.status == IngestionJobStatus.PROCESSING
    assert updated.completed_document_count == 1
    assert find_document(
        updated,
        first.document_id,
    ).status == IngestionDocumentStatus.COMPLETED
    assert updated.documents[1].status == (
        IngestionDocumentStatus.PENDING
    )
    assert [call[2] for call in fakes.loader.calls] == [
        "first.txt"
    ]


def test_terminal_job_is_idempotent_no_op():
    """Reprocessing a terminal job performs no component work."""

    service, job, contents = build_submitted_job()
    orchestrator, fakes = build_orchestrator(
        service,
        contents,
    )
    completed = orchestrator.process_job(job.job_id)
    call_count = len(fakes.loader.calls)

    repeated = orchestrator.process_job(job.job_id)

    assert repeated == completed
    assert len(fakes.loader.calls) == call_count


def test_active_document_blocks_unsafe_job_resume():
    """An in-flight document requires an explicit recovery decision."""

    service, job, contents = build_submitted_job()
    processing = service.start(
        job.job_id,
        stage=IngestionStage.VALIDATING,
    )
    service.start_document(
        job.job_id,
        processing.documents[0].document_id,
        stage=IngestionStage.PARSING,
    )
    orchestrator, fakes = build_orchestrator(
        service,
        contents,
    )

    with pytest.raises(
        DocumentProcessingStateError,
        match="explicit recovery decision",
    ):
        orchestrator.process_job(job.job_id)

    assert fakes.loader.calls == []


def test_process_document_requires_processing_job():
    """Documents cannot start while their job remains pending."""

    service, job, contents = build_submitted_job()
    orchestrator, _ = build_orchestrator(service, contents)

    with pytest.raises(
        DocumentProcessingStateError,
        match="processing status",
    ):
        orchestrator.process_document(
            job.job_id,
            job.documents[0].document_id,
        )


def test_process_document_rejects_unknown_document():
    """Unknown document identifiers cannot enter the pipeline."""

    service, job, contents = build_submitted_job()
    service.start(
        job.job_id,
        stage=IngestionStage.VALIDATING,
    )
    orchestrator, _ = build_orchestrator(service, contents)

    with pytest.raises(
        DocumentProcessingStateError,
        match="was not found",
    ):
        orchestrator.process_document(job.job_id, uuid4())


def test_cancellation_requested_before_start_is_applied():
    """A pre-start cancellation prevents all content access."""

    service, job, contents = build_submitted_job()
    service.request_cancellation(job.job_id)
    orchestrator, fakes = build_orchestrator(
        service,
        contents,
    )

    cancelled = orchestrator.process_job(job.job_id)

    assert cancelled.status == IngestionJobStatus.CANCELLED
    assert cancelled.cancellation_requested is True
    assert cancelled.cancelled_document_count == 1
    assert cancelled.documents[0].status == (
        IngestionDocumentStatus.CANCELLED
    )
    assert fakes.loader.calls == []


def test_cancellation_during_pipeline_is_applied_at_checkpoint():
    """Cancellation is applied cooperatively between stages."""

    service, job, contents = build_submitted_job()

    def request_cancellation(
        upload: Any,
        content: bytes,
    ) -> None:
        del upload, content
        service.request_cancellation(job.job_id)

    parser = FakeParser(before_return=request_cancellation)
    orchestrator, fakes = build_orchestrator(
        service,
        contents,
        parser=parser,
    )

    cancelled = orchestrator.process_job(job.job_id)

    assert cancelled.status == IngestionJobStatus.CANCELLED
    assert cancelled.documents[0].status == (
        IngestionDocumentStatus.CANCELLED
    )
    assert len(fakes.parser.calls) == 1
    assert fakes.metadata_extractor.calls == []


def test_batch_continues_after_document_failure():
    """One failed document does not block a later valid document."""

    contents = {
        "bad.txt": DEFAULT_CONTENT,
        "good.txt": DEFAULT_CONTENT,
    }
    service, job, _ = build_submitted_job(
        filenames=("bad.txt", "good.txt"),
        content_by_name=contents,
    )
    loader = FakeContentLoader(
        contents,
        errors_by_name={
            "bad.txt": OSError("object storage unavailable")
        },
    )
    orchestrator, fakes = build_orchestrator(
        service,
        contents,
        loader=loader,
    )

    completed = orchestrator.process_job(job.job_id)

    assert completed.status == (
        IngestionJobStatus.PARTIALLY_COMPLETED
    )
    assert completed.failed_document_count == 1
    assert completed.completed_document_count == 1
    assert completed.error_count == 1
    assert [
        document.status
        for document in completed.documents
    ] == [
        IngestionDocumentStatus.FAILED,
        IngestionDocumentStatus.COMPLETED,
    ]
    assert [call[2] for call in fakes.loader.calls] == [
        "bad.txt",
        "good.txt",
    ]
    assert len(fakes.parser.calls) == 1


def test_batch_can_stop_after_first_document_failure():
    """Configured fail-fast mode leaves later documents pending."""

    contents = {
        "bad.txt": DEFAULT_CONTENT,
        "later.txt": DEFAULT_CONTENT,
    }
    service, job, _ = build_submitted_job(
        filenames=("bad.txt", "later.txt"),
        content_by_name=contents,
    )
    loader = FakeContentLoader(
        contents,
        errors_by_name={
            "bad.txt": OSError("object storage unavailable")
        },
    )
    config = DocumentProcessingOrchestratorConfig(
        continue_after_document_failure=False,
    )
    orchestrator, fakes = build_orchestrator(
        service,
        contents,
        loader=loader,
        config=config,
    )

    failed = orchestrator.process_job(job.job_id)

    assert failed.status == IngestionJobStatus.FAILED
    assert failed.stage == IngestionStage.VALIDATING
    assert [
        document.status
        for document in failed.documents
    ] == [
        IngestionDocumentStatus.FAILED,
        IngestionDocumentStatus.PENDING,
    ]
    assert [call[2] for call in fakes.loader.calls] == [
        "bad.txt"
    ]


def test_content_loader_exception_is_normalised():
    """Storage exceptions produce recoverable file-access failures."""

    service, job, contents = build_submitted_job()
    loader = FakeContentLoader(
        contents,
        errors_by_name={
            "manual.txt": OSError("storage timeout")
        },
    )
    orchestrator, _ = build_orchestrator(
        service,
        contents,
        loader=loader,
    )

    failed = orchestrator.process_job(job.job_id)

    document = assert_document_failure(
        failed,
        code="DOCUMENT_CONTENT_LOAD_FAILED",
        stage=IngestionStage.VALIDATING,
        category=IngestionFailureCategory.FILE_ACCESS,
        recoverable=True,
    )
    assert "storage timeout" in document.errors[0].message
    assert (
        document.errors[0].details["exception_type"]
        == "DocumentContentLoadError"
    )


def test_content_loader_must_return_bytes():
    """Non-byte storage output is rejected safely."""

    service, job, _ = build_submitted_job(
        declare_size=False,
        declare_checksum=False,
    )
    contents: dict[str, Any] = {
        "manual.txt": "not bytes",
    }
    orchestrator, _ = build_orchestrator(
        service,
        contents,
    )

    failed = orchestrator.process_job(job.job_id)

    document = assert_document_failure(
        failed,
        code="DOCUMENT_CONTENT_LOAD_FAILED",
        stage=IngestionStage.VALIDATING,
        category=IngestionFailureCategory.FILE_ACCESS,
        recoverable=True,
    )
    assert "must return bytes" in document.errors[0].message


def test_declared_file_size_mismatch_fails_validation():
    """Loaded content must match the declared byte size."""

    service, job, contents = build_submitted_job()
    document = job.documents[0].model_copy(
        update={"file_size_bytes": len(DEFAULT_CONTENT) + 1}
    )
    replacement = job.model_copy(
        update={"documents": [document]}
    )
    service.repository.replace(replacement)
    orchestrator, _ = build_orchestrator(
        service,
        contents,
    )

    failed = orchestrator.process_job(job.job_id)

    document = assert_document_failure(
        failed,
        code="DOCUMENT_VALIDATION_FAILED",
        stage=IngestionStage.VALIDATING,
        category=IngestionFailureCategory.VALIDATION,
        recoverable=True,
    )
    assert "Declared file size" in document.errors[0].message


def test_declared_checksum_mismatch_fails_validation():
    """Loaded content must match its declared SHA-256 checksum."""

    service, job, contents = build_submitted_job()
    document = job.documents[0].model_copy(
        update={"checksum_sha256": "0" * 64}
    )
    replacement = job.model_copy(
        update={"documents": [document]}
    )
    service.repository.replace(replacement)
    orchestrator, _ = build_orchestrator(
        service,
        contents,
    )

    failed = orchestrator.process_job(job.job_id)

    document = assert_document_failure(
        failed,
        code="DOCUMENT_VALIDATION_FAILED",
        stage=IngestionStage.VALIDATING,
        category=IngestionFailureCategory.VALIDATION,
        recoverable=True,
    )
    assert "Declared SHA-256 checksum" in (
        document.errors[0].message
    )


def test_integrity_checks_can_be_disabled_explicitly():
    """Trusted callers may explicitly disable declared-integrity checks."""

    service, job, contents = build_submitted_job()
    document = job.documents[0].model_copy(
        update={
            "file_size_bytes": 1,
            "checksum_sha256": "0" * 64,
        }
    )
    replacement = job.model_copy(
        update={"documents": [document]}
    )
    service.repository.replace(replacement)
    config = DocumentProcessingOrchestratorConfig(
        verify_declared_file_size=False,
        verify_checksum_sha256=False,
    )
    orchestrator, _ = build_orchestrator(
        service,
        contents,
        config=config,
    )

    completed = orchestrator.process_job(job.job_id)

    assert completed.status == IngestionJobStatus.COMPLETED
    processing = completed.documents[0].attributes[
        "document_processing"
    ]
    assert processing["content_size_bytes"] == len(DEFAULT_CONTENT)
    assert processing["checksum_sha256"] == checksum_for(
        DEFAULT_CONTENT
    )


def test_unsupported_format_has_specific_failure_category():
    """Unsupported formats remain distinct from general parser errors."""

    service, job, contents = build_submitted_job(
        filenames=("manual.xyz",),
    )
    parser = FakeParser(
        error=UnsupportedDocumentFormatError(
            "XYZ files are not supported."
        )
    )
    orchestrator, _ = build_orchestrator(
        service,
        contents,
        parser=parser,
    )

    failed = orchestrator.process_job(job.job_id)

    assert_document_failure(
        failed,
        code="UNSUPPORTED_DOCUMENT_FORMAT",
        stage=IngestionStage.PARSING,
        category=IngestionFailureCategory.UNSUPPORTED_FORMAT,
        recoverable=True,
    )


def test_unexpected_parser_exception_is_non_recoverable():
    """Unexpected parser defects are classified as non-recoverable."""

    service, job, contents = build_submitted_job()
    parser = FakeParser(error=RuntimeError("parser defect"))
    orchestrator, _ = build_orchestrator(
        service,
        contents,
        parser=parser,
    )

    failed = orchestrator.process_job(job.job_id)

    document = assert_document_failure(
        failed,
        code="DOCUMENT_PARSING_FAILED",
        stage=IngestionStage.PARSING,
        category=IngestionFailureCategory.PARSING,
        recoverable=False,
    )
    assert (
        document.errors[0].details["exception_type"]
        == "RuntimeError"
    )


def test_parser_reported_errors_fail_parsing_stage():
    """Structured parser errors stop downstream extraction."""

    service, job, contents = build_submitted_job()
    parser = FakeParser(
        result=ParsedResult(
            document_id=job.documents[0].document_id,
            errors=["Page structure could not be resolved."],
        )
    )
    orchestrator, fakes = build_orchestrator(
        service,
        contents,
        parser=parser,
    )

    failed = orchestrator.process_job(job.job_id)

    assert_document_failure(
        failed,
        code="DOCUMENT_PARSER_REPORTED_ERRORS",
        stage=IngestionStage.PARSING,
        category=IngestionFailureCategory.PARSING,
        recoverable=True,
    )
    assert fakes.metadata_extractor.calls == []


def test_metadata_extraction_exception_is_normalised():
    """Metadata exceptions retain their pipeline stage."""

    service, job, contents = build_submitted_job()
    metadata_extractor = FakeMetadataExtractor(
        error=ValueError("metadata rules failed")
    )
    orchestrator, fakes = build_orchestrator(
        service,
        contents,
        metadata_extractor=metadata_extractor,
    )

    failed = orchestrator.process_job(job.job_id)

    assert_document_failure(
        failed,
        code="METADATA_EXTRACTION_FAILED",
        stage=IngestionStage.EXTRACTING_METADATA,
        category=(
            IngestionFailureCategory.METADATA_EXTRACTION
        ),
        recoverable=True,
    )
    assert fakes.engineering_extractor.calls == []


def test_engineering_extractor_reported_errors_fail_stage():
    """Structured fact-extraction errors block indexing."""

    service, job, contents = build_submitted_job()
    extraction = ExtractionResult(
        errors=["Engineering statement could not be normalised."],
    )
    orchestrator, fakes = build_orchestrator(
        service,
        contents,
        engineering_extractor=FakeEngineeringExtractor(
            result=extraction
        ),
    )

    failed = orchestrator.process_job(job.job_id)

    assert_document_failure(
        failed,
        code="ENGINEERING_EXTRACTOR_REPORTED_ERRORS",
        stage=IngestionStage.EXTRACTING_ENGINEERING_FACTS,
        category=(
            IngestionFailureCategory.ENGINEERING_EXTRACTION
        ),
        recoverable=True,
    )
    assert fakes.indexer.calls == []


def test_indexer_reported_errors_fail_stage():
    """Structured index errors block repository publication."""

    service, job, contents = build_submitted_job()
    fact = SimpleNamespace(fact_id=uuid4())
    extraction = ExtractionResult(
        facts=[fact],
        fact_count=1,
    )
    index_build = IndexBuildResult(
        errors=["Index identifier could not be generated."],
    )
    orchestrator, fakes = build_orchestrator(
        service,
        contents,
        engineering_extractor=FakeEngineeringExtractor(
            result=extraction
        ),
        indexer=FakeKnowledgeIndexer(result=index_build),
    )

    failed = orchestrator.process_job(job.job_id)

    document = assert_document_failure(
        failed,
        code="KNOWLEDGE_INDEX_REPORTED_ERRORS",
        stage=IngestionStage.BUILDING_INDEX,
        category=IngestionFailureCategory.INDEXING,
        recoverable=True,
    )
    assert fakes.publisher.calls == []
    assert [item.code for item in document.warnings] == [
        "NO_KNOWLEDGE_INDEX_RECORDS"
    ]


def test_publication_failure_records_controlled_counts():
    """Repository failures preserve registration outcome counts."""

    service, job, contents = build_submitted_job()
    fact = SimpleNamespace(fact_id=uuid4())
    extraction = ExtractionResult(
        facts=[fact],
        fact_count=1,
    )
    index_build = IndexBuildResult(
        records=[SimpleNamespace(index_id=uuid4())],
        indexed_fact_count=1,
    )
    publication = PublicationResult(
        registered_count=0,
        skipped_count=0,
        failed_count=1,
        successful=False,
    )
    orchestrator, _ = build_orchestrator(
        service,
        contents,
        engineering_extractor=FakeEngineeringExtractor(
            result=extraction
        ),
        indexer=FakeKnowledgeIndexer(result=index_build),
        publisher=FakeRepositoryPublisher(result=publication),
    )

    failed = orchestrator.process_job(job.job_id)

    document = assert_document_failure(
        failed,
        code="KNOWLEDGE_REPOSITORY_REPORTED_ERRORS",
        stage=IngestionStage.REGISTERING_KNOWLEDGE,
        category=(
            IngestionFailureCategory.REPOSITORY_PUBLICATION
        ),
        recoverable=True,
    )
    diagnostic = document.errors[0]
    assert diagnostic.details["registered_count"] == 0
    assert diagnostic.details["skipped_count"] == 0
    assert diagnostic.details["failed_count"] == 1
    processing = document.attributes["document_processing"]
    assert processing["failed_knowledge_count"] == 1
    assert processing["repository_publication_successful"] is False


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("manual.PDF", DocumentFormat.PDF),
        (r"folder\manual.docx", DocumentFormat.DOCX),
        ("manual", DocumentFormat.UNKNOWN),
        ("manual.unsupported", DocumentFormat.UNKNOWN),
    ],
)
def test_infer_document_format(filename, expected):
    """Filename suffix handling is case-insensitive and bounded."""

    assert (
        DocumentProcessingOrchestrator._infer_document_format(
            filename
        )
        == expected
    )


def test_bounded_message_normalises_and_truncates():
    """Diagnostics remain single-line and within model limits."""

    assert DocumentProcessingOrchestrator._bounded_message(
        "  storage\n   timeout  "
    ) == "storage timeout"
    assert DocumentProcessingOrchestrator._bounded_message(
        "abcdefghijk",
        maximum=10,
    ) == "abcdefg..."


def test_processing_failure_copies_details():
    """Failure details cannot change through caller mutation."""

    details = {"attempt": 1}
    failure = DocumentProcessingFailure(
        stage=IngestionStage.PARSING,
        failure_category=IngestionFailureCategory.PARSING,
        code="TEST_FAILURE",
        message="Test failure.",
        recoverable=True,
        details=details,
    )
    details["attempt"] = 2

    assert str(failure) == "Test failure."
    assert failure.stage == IngestionStage.PARSING
    assert failure.failure_category == (
        IngestionFailureCategory.PARSING
    )
    assert failure.code == "TEST_FAILURE"
    assert failure.recoverable is True
    assert failure.details == {"attempt": 1}


def test_run_stage_preserves_existing_processing_failure():
    """Already normalised failures are not wrapped a second time."""

    service, _, contents = build_submitted_job()
    orchestrator, _ = build_orchestrator(service, contents)
    failure = DocumentProcessingFailure(
        stage=IngestionStage.BUILDING_INDEX,
        failure_category=IngestionFailureCategory.INDEXING,
        code="EXISTING_FAILURE",
        message="Already normalised.",
        recoverable=True,
    )

    with pytest.raises(DocumentProcessingFailure) as captured:
        orchestrator._run_stage(
            stage=IngestionStage.PARSING,
            failure_category=IngestionFailureCategory.PARSING,
            code="WRAPPER_FAILURE",
            operation=lambda: (_ for _ in ()).throw(failure),
        )

    assert captured.value is failure