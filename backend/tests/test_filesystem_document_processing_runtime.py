"""Tests for filesystem-backed document-processing runtime composition."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass, field
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest

from app.ingestion.document_processing_orchestrator import (
    DocumentProcessingOrchestrator,
    DocumentProcessingOrchestratorConfig,
)
from app.ingestion.filesystem_document_content_loader import (
    FilesystemDocumentContentLoader,
    FilesystemDocumentContentLoaderConfig,
)
from app.ingestion.filesystem_document_processing_runtime import (
    FilesystemDocumentProcessingRuntime,
    FilesystemDocumentProcessingRuntimeConfig,
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
    """Return the lowercase SHA-256 checksum expected by job models."""

    return sha256(content).hexdigest()


def build_submitted_job(
    root_directory: Path,
    *,
    source_path: str = "uploads/manual.txt",
    content: bytes = DEFAULT_CONTENT,
    write_source: bool = True,
) -> tuple[IngestionJobService, IngestionJob]:
    """Build and submit one valid filesystem-backed ingestion job."""

    if write_source:
        persisted_source = root_directory.joinpath(
            *source_path.split("/")
        )
        persisted_source.parent.mkdir(parents=True, exist_ok=True)
        persisted_source.write_bytes(content)

    document = IngestionDocumentResult(
        source_name=Path(source_path).name,
        source_path=source_path,
        media_type="text/plain",
        file_size_bytes=len(content),
        checksum_sha256=checksum_for(content),
        attributes={"supplier": "Emerson"},
    )
    job = IngestionJob(
        job_type=IngestionJobType.SINGLE_DOCUMENT,
        source_type=IngestionSourceType.API_UPLOAD,
        submitted_by="filesystem-runtime-test",
        correlation_id="phase-6-filesystem-runtime-test",
        documents=[document],
        total_document_count=1,
        metadata={
            "test_suite": "filesystem_document_processing_runtime",
        },
    )
    service = IngestionJobService()
    service.submit(job)

    return service, job


def build_runtime(
    root_directory: Path,
    *,
    service: IngestionJobService | None = None,
    orchestrator_config: (
        DocumentProcessingOrchestratorConfig | None
    ) = None,
) -> FilesystemDocumentProcessingRuntime:
    """Build the concrete runtime with validated nested controls."""

    return FilesystemDocumentProcessingRuntime(
        job_service=service or IngestionJobService(),
        config=FilesystemDocumentProcessingRuntimeConfig(
            content_loader_config=(
                FilesystemDocumentContentLoaderConfig(
                    root_directory=root_directory,
                )
            ),
            orchestrator=(
                orchestrator_config
                or DocumentProcessingOrchestratorConfig()
            ),
        ),
    )


@dataclass
class RecordingParser:
    """Return one minimal parsed document and retain exact parser inputs."""

    calls: list[tuple[Any, bytes]] = field(default_factory=list)

    def parse(
        self,
        upload: Any,
        content: bytes,
    ) -> SimpleNamespace:
        """Return a parsed-document shape accepted by the orchestrator."""

        self.calls.append((upload, content))

        return SimpleNamespace(
            document_id=upload.document_id,
            parsed_document_id=uuid4(),
            page_count=1,
            character_count=len(content.decode("utf-8")),
            parser_name="runtime-integration-parser",
            parser_version="1.0-test",
            extraction_confidence=1.0,
            warnings=[],
            errors=[],
        )


@dataclass
class RecordingMetadataExtractor:
    """Return deterministic metadata and retain the extraction call."""

    calls: list[dict[str, Any]] = field(default_factory=list)

    def extract(
        self,
        document: Any,
        *,
        document_id: UUID,
        filename: str,
        raw_metadata: dict[str, Any],
    ) -> SimpleNamespace:
        """Return the metadata shape consumed by later stages."""

        self.calls.append(
            {
                "document": document,
                "document_id": document_id,
                "filename": filename,
                "raw_metadata": raw_metadata,
            }
        )

        return SimpleNamespace(
            metadata_id=uuid4(),
            document_type=SimpleNamespace(value="datasheet"),
            language=SimpleNamespace(value="en"),
            metadata_confidence=0.95,
            product_reference=SimpleNamespace(
                manufacturer="Emerson",
                brand="Rosemount",
                product_family="Pressure Transmitters",
                product_series="3051",
                model_numbers=["3051S"],
                part_numbers=[],
            ),
            standards_referenced=["IEC 61511"],
        )


@dataclass
class RecordingEngineeringExtractor:
    """Return a safe no-fact extraction result for runtime integration."""

    calls: list[tuple[Any, Any]] = field(default_factory=list)

    def extract(
        self,
        document: Any,
        metadata: Any,
    ) -> SimpleNamespace:
        """Return the extraction-result shape consumed by indexing."""

        self.calls.append((document, metadata))

        return SimpleNamespace(
            extraction_id=uuid4(),
            facts=[],
            fact_count=0,
            safety_fact_count=0,
            extraction_confidence=0.9,
            processed_block_count=1,
            skipped_block_count=0,
            extraction_engine="runtime-integration-extractor",
            extraction_engine_version="1.0-test",
            warnings=[],
            errors=[],
        )


@dataclass
class RecordingKnowledgeIndexer:
    """Return an empty deterministic index and retain exact inputs."""

    calls: list[tuple[list[Any], Any]] = field(
        default_factory=list
    )

    def build(
        self,
        facts: list[Any],
        *,
        metadata: Any,
    ) -> SimpleNamespace:
        """Return the index-result shape consumed by finalisation."""

        self.calls.append((facts, metadata))

        return SimpleNamespace(
            build_id=uuid4(),
            records=[],
            indexed_fact_count=0,
            duplicate_fact_count=0,
            skipped_fact_count=0,
            index_engine="runtime-integration-indexer",
            index_version="1.0-test",
            warnings=[],
            errors=[],
        )


@dataclass
class RuntimePipelineFakes:
    """Observable downstream components used by one integration test."""

    parser: RecordingParser = field(default_factory=RecordingParser)
    metadata_extractor: RecordingMetadataExtractor = field(
        default_factory=RecordingMetadataExtractor
    )
    engineering_extractor: RecordingEngineeringExtractor = field(
        default_factory=RecordingEngineeringExtractor
    )
    indexer: RecordingKnowledgeIndexer = field(
        default_factory=RecordingKnowledgeIndexer
    )


def install_pipeline_fakes(
    runtime: FilesystemDocumentProcessingRuntime,
) -> RuntimePipelineFakes:
    """Replace downstream processors while retaining real runtime wiring."""

    fakes = RuntimePipelineFakes()
    runtime.orchestrator._parser = fakes.parser
    runtime.orchestrator._metadata_extractor = (
        fakes.metadata_extractor
    )
    runtime.orchestrator._engineering_extractor = (
        fakes.engineering_extractor
    )
    runtime.orchestrator._knowledge_indexer = fakes.indexer

    return fakes


def test_config_uses_safe_defaults_and_is_frozen(
    tmp_path: Path,
) -> None:
    """Runtime configuration owns validated immutable nested controls."""

    loader_config = FilesystemDocumentContentLoaderConfig(
        root_directory=tmp_path,
    )
    config = FilesystemDocumentProcessingRuntimeConfig(
        content_loader_config=loader_config,
    )

    assert config.content_loader_config is loader_config
    assert isinstance(
        config.orchestrator,
        DocumentProcessingOrchestratorConfig,
    )
    assert config.orchestrator.verify_declared_file_size is True
    assert config.orchestrator.verify_checksum_sha256 is True

    with pytest.raises(FrozenInstanceError):
        config.orchestrator = (  # type: ignore[misc]
            DocumentProcessingOrchestratorConfig()
        )


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "expected_message"),
    [
        (
            "content_loader_config",
            object(),
            "FilesystemDocumentContentLoaderConfig",
        ),
        (
            "orchestrator",
            object(),
            "DocumentProcessingOrchestratorConfig",
        ),
    ],
)
def test_config_rejects_invalid_nested_controls(
    tmp_path: Path,
    field_name: str,
    invalid_value: object,
    expected_message: str,
) -> None:
    """Only validated loader and orchestrator controls are accepted."""

    values: dict[str, object] = {
        "content_loader_config": (
            FilesystemDocumentContentLoaderConfig(
                root_directory=tmp_path,
            )
        ),
        "orchestrator": DocumentProcessingOrchestratorConfig(),
    }
    values[field_name] = invalid_value

    with pytest.raises(TypeError, match=expected_message):
        FilesystemDocumentProcessingRuntimeConfig(
            **values,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("job_service", "config_factory", "expected_message"),
    [
        (
            object(),
            lambda root: FilesystemDocumentProcessingRuntimeConfig(
                content_loader_config=(
                    FilesystemDocumentContentLoaderConfig(
                        root_directory=root,
                    )
                )
            ),
            "IngestionJobService",
        ),
        (
            IngestionJobService(),
            lambda _root: object(),
            "FilesystemDocumentProcessingRuntimeConfig",
        ),
    ],
)
def test_runtime_rejects_invalid_dependencies(
    tmp_path: Path,
    job_service: object,
    config_factory: Any,
    expected_message: str,
) -> None:
    """Runtime construction rejects unvalidated dependency objects."""

    with pytest.raises(TypeError, match=expected_message):
        FilesystemDocumentProcessingRuntime(
            job_service=job_service,  # type: ignore[arg-type]
            config=config_factory(tmp_path),
        )


def test_runtime_exposes_one_fully_composed_pipeline(
    tmp_path: Path,
) -> None:
    """The runtime shares one service and both exact nested controls."""

    service = IngestionJobService()
    loader_config = FilesystemDocumentContentLoaderConfig(
        root_directory=tmp_path,
        maximum_content_bytes=4096,
    )
    orchestrator_config = DocumentProcessingOrchestratorConfig(
        created_by="filesystem-runtime-test",
    )
    config = FilesystemDocumentProcessingRuntimeConfig(
        content_loader_config=loader_config,
        orchestrator=orchestrator_config,
    )
    runtime = FilesystemDocumentProcessingRuntime(
        job_service=service,
        config=config,
    )

    assert runtime.job_service is service
    assert runtime.config is config
    assert isinstance(
        runtime.content_loader,
        FilesystemDocumentContentLoader,
    )
    assert runtime.content_loader.config is loader_config
    assert isinstance(
        runtime.orchestrator,
        DocumentProcessingOrchestrator,
    )
    assert runtime.orchestrator.job_service is service
    assert runtime.orchestrator.config is orchestrator_config


def test_process_job_delegates_to_composed_orchestrator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The runtime forwards one job identifier and returns its snapshot."""

    runtime = build_runtime(tmp_path)
    job_id = uuid4()
    expected = SimpleNamespace(job_id=job_id)
    calls: list[UUID] = []

    def process_job(received_job_id: UUID) -> Any:
        calls.append(received_job_id)
        return expected

    monkeypatch.setattr(
        runtime.orchestrator,
        "process_job",
        process_job,
    )

    assert runtime.process_job(job_id) is expected
    assert calls == [job_id]


def test_process_document_delegates_to_composed_orchestrator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The runtime forwards both identifiers without finalising the job."""

    runtime = build_runtime(tmp_path)
    job_id = uuid4()
    document_id = uuid4()
    expected = SimpleNamespace(job_id=job_id)
    calls: list[tuple[UUID, UUID]] = []

    def process_document(
        received_job_id: UUID,
        received_document_id: UUID,
    ) -> Any:
        calls.append(
            (received_job_id, received_document_id)
        )
        return expected

    monkeypatch.setattr(
        runtime.orchestrator,
        "process_document",
        process_document,
    )

    assert runtime.process_document(job_id, document_id) is expected
    assert calls == [(job_id, document_id)]


def test_process_job_reads_real_source_and_completes(
    tmp_path: Path,
) -> None:
    """Filesystem loading and lifecycle orchestration work end to end."""

    service, job = build_submitted_job(tmp_path)
    runtime = build_runtime(
        tmp_path,
        service=service,
    )
    fakes = install_pipeline_fakes(runtime)

    completed = runtime.process_job(job.job_id)

    assert completed.status == IngestionJobStatus.COMPLETED
    assert completed.stage == IngestionStage.COMPLETE
    assert completed.progress_percent == 100
    assert completed.completed_document_count == 1
    assert completed.failed_document_count == 0

    document = completed.documents[0]
    assert document.status == IngestionDocumentStatus.COMPLETED
    assert document.progress_percent == 100
    assert document.attempt_count == 1
    assert [warning.code for warning in document.warnings] == [
        "NO_ENGINEERING_FACTS"
    ]

    assert len(fakes.parser.calls) == 1
    upload, loaded_content = fakes.parser.calls[0]
    assert loaded_content == DEFAULT_CONTENT
    assert upload.document_id == document.document_id
    assert upload.storage_key == "uploads/manual.txt"
    assert upload.source.supplier == "Emerson"

    assert len(fakes.metadata_extractor.calls) == 1
    assert len(fakes.engineering_extractor.calls) == 1
    assert len(fakes.indexer.calls) == 1

    processing = document.attributes["document_processing"]
    assert processing["content_size_bytes"] == len(DEFAULT_CONTENT)
    assert processing["checksum_sha256"] == checksum_for(
        DEFAULT_CONTENT
    )
    assert processing["document_format"] == "txt"
    assert processing["manufacturer"] == "Emerson"
    assert processing["brand"] == "Rosemount"
    assert processing["extracted_fact_count"] == 0
    assert processing["registered_knowledge_count"] == 0


def test_process_job_records_guarded_missing_source_failure(
    tmp_path: Path,
) -> None:
    """A missing file becomes a structured recoverable job failure."""

    service, job = build_submitted_job(
        tmp_path,
        source_path="private/customer-a/missing.txt",
        write_source=False,
    )
    runtime = build_runtime(
        tmp_path,
        service=service,
    )

    failed = runtime.process_job(job.job_id)

    assert failed.status == IngestionJobStatus.FAILED
    assert failed.stage == IngestionStage.COMPLETE
    assert failed.failed_document_count == 1
    assert failed.error_count == 1

    document = failed.documents[0]
    assert document.status == IngestionDocumentStatus.FAILED
    assert document.stage == IngestionStage.VALIDATING
    assert document.progress_percent == 0

    diagnostic = document.errors[0]
    assert diagnostic.code == "DOCUMENT_CONTENT_LOAD_FAILED"
    assert diagnostic.failure_category == (
        IngestionFailureCategory.FILE_ACCESS
    )
    assert diagnostic.recoverable is True
    assert str(job.job_id) in diagnostic.message
    assert str(document.document_id) in diagnostic.message
    assert "private/customer-a/missing.txt" not in diagnostic.message

    processing = document.attributes["document_processing"]
    assert processing["failed_stage"] == "validating"
    assert processing["failure_category"] == "file_access"
    assert processing["failure_code"] == (
        "DOCUMENT_CONTENT_LOAD_FAILED"
    )
    assert processing["failure_recoverable"] is True
