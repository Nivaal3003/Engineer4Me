"""Tests for guarded filesystem-backed ingestion job execution."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from threading import Event
from typing import Any
from uuid import UUID, uuid4

import pytest

from app.ingestion.document_processing_orchestrator import (
    DocumentProcessingStateError,
)
from app.ingestion.filesystem_document_content_loader import (
    FilesystemDocumentContentLoaderConfig,
)
from app.ingestion.filesystem_document_execution_service import (
    FilesystemDocumentExecutionConflictError,
    FilesystemDocumentExecutionEligibilityError,
    FilesystemDocumentExecutionError,
    FilesystemDocumentExecutionService,
    FilesystemDocumentExecutionStateError,
)
from app.ingestion.filesystem_document_processing_runtime import (
    FilesystemDocumentProcessingRuntime,
    FilesystemDocumentProcessingRuntimeConfig,
)
from app.ingestion.filesystem_document_storage import (
    FilesystemDocumentStorage,
    FilesystemDocumentStorageConfig,
)
from app.ingestion.filesystem_document_upload_service import (
    FilesystemDocumentUpload,
    FilesystemDocumentUploadService,
)
from app.ingestion.ingestion_job_models import (
    IngestionDocumentResult,
    IngestionJob,
    IngestionJobStatus,
    IngestionSourceType,
)
from app.ingestion.ingestion_job_repository import (
    IngestionJobNotFoundError,
)
from app.ingestion.ingestion_job_service import IngestionJobService
from app.ingestion.pdf_office_document_parser import (
    PdfOfficeDocumentParserConfig,
)


MAXIMUM_CONTENT_BYTES = 16 * 1024
DEFAULT_CONTENT = (
    b"Maximum operating pressure is 16 bar. "
    b"Temperature range is -20 to 80 degrees C."
)


@pytest.fixture
def job_service() -> IngestionJobService:
    """Return one isolated in-memory lifecycle service."""

    return IngestionJobService()


@pytest.fixture
def storage_root(tmp_path: Path) -> Path:
    """Return one isolated existing upload root."""

    root = tmp_path / "uploads"
    root.mkdir()
    return root


@pytest.fixture
def storage(
    storage_root: Path,
) -> FilesystemDocumentStorage:
    """Return guarded storage aligned with the execution runtime."""

    return FilesystemDocumentStorage(
        FilesystemDocumentStorageConfig(
            root_directory=storage_root,
            maximum_content_bytes=MAXIMUM_CONTENT_BYTES,
        )
    )


@pytest.fixture
def upload_service(
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> FilesystemDocumentUploadService:
    """Return transactional upload composition for valid job fixtures."""

    return FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
    )


@pytest.fixture
def runtime(
    storage_root: Path,
    job_service: IngestionJobService,
) -> FilesystemDocumentProcessingRuntime:
    """Return the production filesystem/PDF/Office runtime."""

    return FilesystemDocumentProcessingRuntime(
        job_service=job_service,
        config=FilesystemDocumentProcessingRuntimeConfig(
            content_loader_config=(
                FilesystemDocumentContentLoaderConfig(
                    root_directory=storage_root,
                    maximum_content_bytes=MAXIMUM_CONTENT_BYTES,
                )
            ),
            document_parser=PdfOfficeDocumentParserConfig(
                maximum_document_bytes=MAXIMUM_CONTENT_BYTES,
            ),
        ),
    )


@pytest.fixture
def execution_service(
    runtime: FilesystemDocumentProcessingRuntime,
) -> FilesystemDocumentExecutionService:
    """Return the guarded execution coordinator under test."""

    return FilesystemDocumentExecutionService(runtime=runtime)


def submit_upload(
    service: FilesystemDocumentUploadService,
    *,
    filename: str = "control-valve.txt",
    content: bytes = DEFAULT_CONTENT,
    submitted_by: str = "execution-test",
) -> IngestionJob:
    """Persist and register one authoritative filesystem upload."""

    return service.submit_upload(
        upload=FilesystemDocumentUpload(
            filename=filename,
            stream=BytesIO(content),
            media_type="text/plain",
        ),
        submitted_by=submitted_by,
    )


def submit_batch(
    service: FilesystemDocumentUploadService,
) -> IngestionJob:
    """Persist and register two authoritative documents."""

    return service.submit_uploads(
        uploads=(
            FilesystemDocumentUpload(
                filename="pressure.txt",
                stream=BytesIO(
                    b"Maximum pressure is 16 bar."
                ),
                media_type="text/plain",
            ),
            FilesystemDocumentUpload(
                filename="temperature.txt",
                stream=BytesIO(
                    b"Maximum temperature is 80 degrees C."
                ),
                media_type="text/plain",
            ),
        ),
        submitted_by="batch-execution-test",
    )


def replace_job(
    job: IngestionJob,
    **updates: Any,
) -> IngestionJob:
    """Return a detached unchecked job copy for validation-edge tests."""

    return job.model_copy(
        update=updates,
        deep=True,
    )


def replace_document(
    job: IngestionJob,
    **updates: Any,
) -> IngestionJob:
    """Return a job whose first document contains unchecked updates."""

    document = job.documents[0].model_copy(
        update=updates,
        deep=True,
    )
    documents = [document, *job.documents[1:]]

    return replace_job(
        job,
        documents=documents,
    )


def replace_storage_metadata(
    job: IngestionJob,
    value: Any,
) -> IngestionJob:
    """Replace the first document's reserved storage metadata."""

    document = job.documents[0]
    attributes = dict(document.attributes)
    attributes["engineer4me_storage"] = value
    return replace_document(job, attributes=attributes)


def replace_upload_metadata(
    job: IngestionJob,
    value: Any,
) -> IngestionJob:
    """Replace the job's reserved upload metadata."""

    metadata = dict(job.metadata)
    metadata["engineer4me_upload"] = value
    return replace_job(job, metadata=metadata)


def canonical_storage_metadata(
    job: IngestionJob,
) -> dict[str, Any]:
    """Return a detached first-document storage metadata mapping."""

    return dict(
        job.documents[0].attributes["engineer4me_storage"]
    )


def test_exception_hierarchy_is_stable() -> None:
    """Public errors share one execution-service base."""

    assert issubclass(
        FilesystemDocumentExecutionEligibilityError,
        FilesystemDocumentExecutionError,
    )
    assert issubclass(
        FilesystemDocumentExecutionConflictError,
        FilesystemDocumentExecutionError,
    )
    assert issubclass(
        FilesystemDocumentExecutionStateError,
        FilesystemDocumentExecutionError,
    )


@pytest.mark.parametrize(
    "value",
    [
        None,
        object(),
        IngestionJobService(),
        "runtime",
        1,
    ],
)
def test_constructor_rejects_invalid_runtime(value: Any) -> None:
    """Composition requires the concrete complete runtime."""

    with pytest.raises(
        TypeError,
        match="FilesystemDocumentProcessingRuntime",
    ):
        FilesystemDocumentExecutionService(
            runtime=value,  # type: ignore[arg-type]
        )


def test_runtime_property_preserves_injected_instance(
    execution_service: FilesystemDocumentExecutionService,
    runtime: FilesystemDocumentProcessingRuntime,
) -> None:
    """The service exposes the exact shared runtime."""

    assert execution_service.runtime is runtime


def test_active_job_ids_starts_empty_and_is_immutable(
    execution_service: FilesystemDocumentExecutionService,
) -> None:
    """Callers receive an immutable detached execution snapshot."""

    snapshot = execution_service.active_job_ids

    assert snapshot == frozenset()

    with pytest.raises(AttributeError):
        snapshot.add(uuid4())  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "value",
    [None, object(), {}, "job", uuid4()],
)
def test_validate_job_rejects_non_job_values(
    execution_service: FilesystemDocumentExecutionService,
    value: Any,
) -> None:
    """Eligibility validation accepts only the shared job model."""

    with pytest.raises(TypeError, match="IngestionJob"):
        execution_service.validate_job(
            value,  # type: ignore[arg-type]
        )


def test_validate_job_accepts_authoritative_single_upload(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """One genuine upload passes every provenance check."""

    execution_service.validate_job(
        submit_upload(upload_service)
    )


def test_validate_job_accepts_authoritative_batch(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Every document in one genuine batch is validated."""

    execution_service.validate_job(
        submit_batch(upload_service)
    )


def test_validate_job_accepts_display_name_with_uppercase_suffix(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Storage-normalised suffixes remain valid for display-name casing."""

    job = submit_upload(
        upload_service,
        filename="Valve-Manual.TXT",
    )

    execution_service.validate_job(job)
    assert job.documents[0].source_name.endswith(".TXT")
    assert (job.documents[0].source_path or "").endswith(".txt")


@pytest.mark.parametrize(
    "source_type",
    [
        IngestionSourceType.LOCAL_FILE,
        IngestionSourceType.DIRECTORY_SCAN,
        IngestionSourceType.ARCHIVE_UPLOAD,
        IngestionSourceType.OBJECT_STORAGE,
        IngestionSourceType.MANUAL,
        IngestionSourceType.SYSTEM,
    ],
)
def test_validate_job_rejects_non_api_upload_sources(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    source_type: IngestionSourceType,
) -> None:
    """The filesystem executor cannot process unrelated source types."""

    job = replace_job(
        submit_upload(upload_service),
        source_type=source_type,
    )

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="API upload",
    ):
        execution_service.validate_job(job)


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        {},
        [],
        "filesystem",
        1,
        {1: "invalid-key"},
    ],
)
def test_validate_job_rejects_invalid_upload_metadata_mapping(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    metadata: Any,
) -> None:
    """Reserved job metadata must be a non-empty string-keyed mapping."""

    job = replace_upload_metadata(
        submit_upload(upload_service),
        metadata,
    )

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="upload metadata",
    ):
        execution_service.validate_job(job)


@pytest.mark.parametrize(
    "backend",
    [None, "", "object-storage", "FILESYSTEM", 1],
)
def test_validate_job_rejects_wrong_upload_backend(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    backend: Any,
) -> None:
    """The reserved backend marker must be exact."""

    job = submit_upload(upload_service)
    metadata = dict(job.metadata["engineer4me_upload"])
    metadata["storage_backend"] = backend

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="does not use filesystem",
    ):
        execution_service.validate_job(
            replace_upload_metadata(job, metadata)
        )


@pytest.mark.parametrize(
    "document_count",
    [None, True, False, 0, -1, 1.0, "1"],
)
def test_validate_job_rejects_invalid_document_count(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    document_count: Any,
) -> None:
    """Upload document counts are strict positive integers."""

    job = submit_upload(upload_service)
    metadata = dict(job.metadata["engineer4me_upload"])
    metadata["document_count"] = document_count

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="document-count",
    ):
        execution_service.validate_job(
            replace_upload_metadata(job, metadata)
        )


def test_validate_job_rejects_document_count_mismatch(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Server metadata must match the actual registered document list."""

    job = submit_upload(upload_service)
    metadata = dict(job.metadata["engineer4me_upload"])
    metadata["document_count"] = 2

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="does not match",
    ):
        execution_service.validate_job(
            replace_upload_metadata(job, metadata)
        )


def test_validate_job_rejects_total_count_mismatch(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """The model's total count must remain consistent with upload metadata."""

    job = replace_job(
        submit_upload(upload_service),
        total_document_count=2,
    )

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="does not match",
    ):
        execution_service.validate_job(job)


@pytest.mark.parametrize(
    "maximum_bytes",
    [None, True, False, 0, -1, 1.5, "16384"],
)
def test_validate_job_rejects_invalid_upload_size_limit(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    maximum_bytes: Any,
) -> None:
    """Upload-time size bounds are strict positive integers."""

    job = submit_upload(upload_service)
    metadata = dict(job.metadata["engineer4me_upload"])
    metadata["maximum_content_bytes"] = maximum_bytes

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="size-limit",
    ):
        execution_service.validate_job(
            replace_upload_metadata(job, metadata)
        )


def test_validate_job_rejects_upload_limit_above_runtime_limit(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Processing cannot silently weaken an upload-time size guarantee."""

    job = submit_upload(upload_service)
    metadata = dict(job.metadata["engineer4me_upload"])
    metadata["maximum_content_bytes"] = (
        MAXIMUM_CONTENT_BYTES + 1
    )

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="exceeds the configured processing limit",
    ):
        execution_service.validate_job(
            replace_upload_metadata(job, metadata)
        )


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        {},
        [],
        "filesystem",
        1,
        {1: "invalid-key"},
    ],
)
def test_validate_job_rejects_invalid_document_storage_mapping(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    metadata: Any,
) -> None:
    """Every document requires non-empty string-keyed storage metadata."""

    job = replace_storage_metadata(
        submit_upload(upload_service),
        metadata,
    )

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="storage metadata",
    ):
        execution_service.validate_job(job)


@pytest.mark.parametrize(
    "backend",
    [None, "", "object-storage", "FILESYSTEM", 1],
)
def test_validate_job_rejects_wrong_document_backend(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    backend: Any,
) -> None:
    """Every document backend marker must be exact."""

    job = submit_upload(upload_service)
    metadata = canonical_storage_metadata(job)
    metadata["backend"] = backend

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="does not use filesystem",
    ):
        execution_service.validate_job(
            replace_storage_metadata(job, metadata)
        )


@pytest.mark.parametrize(
    "storage_id",
    [
        None,
        "",
        "not-a-uuid",
        1,
        uuid4(),
        "{00000000-0000-0000-0000-000000000001}",
        "ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF",
    ],
)
def test_validate_job_rejects_invalid_storage_id(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    storage_id: Any,
) -> None:
    """Storage identity must be one canonical lowercase UUID string."""

    job = submit_upload(upload_service)
    metadata = canonical_storage_metadata(job)
    metadata["storage_id"] = storage_id

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="storage identity",
    ):
        execution_service.validate_job(
            replace_storage_metadata(job, metadata)
        )


@pytest.mark.parametrize(
    "stored_at",
    [
        None,
        "",
        "not-a-timestamp",
        "2026-07-30T10:00:00",
        datetime.now(UTC),
        1,
    ],
)
def test_validate_job_rejects_invalid_storage_timestamp(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    stored_at: Any,
) -> None:
    """Storage timestamps must be timezone-aware ISO-8601 strings."""

    job = submit_upload(upload_service)
    metadata = canonical_storage_metadata(job)
    metadata["stored_at"] = stored_at

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="storage timestamp",
    ):
        execution_service.validate_job(
            replace_storage_metadata(job, metadata)
        )


@pytest.mark.parametrize(
    "source_path",
    [
        None,
        "",
        " ",
        " aa/bb/file.txt",
        "aa/bb/file.txt ",
        r"aa\bb\file.txt",
        "/aa/bb/file.txt",
        "aa/file.txt",
        "aa/bb/cc/file.txt",
        "aa/../file.txt",
        "./aa/bb/file.txt",
    ],
)
def test_validate_job_rejects_malformed_storage_reference(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    source_path: str | None,
) -> None:
    """Absolute, traversal, ambiguous, and non-sharded paths are refused."""

    job = replace_document(
        submit_upload(upload_service),
        source_path=source_path,
    )

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="storage reference",
    ):
        execution_service.validate_job(job)


def test_validate_job_rejects_wrong_storage_shards(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Opaque UUID shards must match the identifier."""

    job = submit_upload(upload_service)
    source_path = job.documents[0].source_path
    assert source_path is not None
    parts = source_path.split("/")
    parts[0] = "00" if parts[0] != "00" else "ff"

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="non-canonical",
    ):
        execution_service.validate_job(
            replace_document(
                job,
                source_path="/".join(parts),
            )
        )


def test_validate_job_rejects_storage_uuid_path_mismatch(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """A metadata UUID cannot authorize another opaque object path."""

    job = submit_upload(upload_service)
    metadata = canonical_storage_metadata(job)
    metadata["storage_id"] = str(uuid4())

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="non-canonical",
    ):
        execution_service.validate_job(
            replace_storage_metadata(job, metadata)
        )


def test_validate_job_rejects_storage_suffix_mismatch(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """The display suffix and stored suffix must agree."""

    job = submit_upload(upload_service)
    source_path = job.documents[0].source_path
    assert source_path is not None

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="non-canonical",
    ):
        execution_service.validate_job(
            replace_document(
                job,
                source_path=source_path.removesuffix(".txt") + ".pdf",
            )
        )


def test_validate_job_rejects_uppercase_storage_reference(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Opaque filesystem keys remain canonical lowercase values."""

    job = submit_upload(upload_service)
    source_path = job.documents[0].source_path
    assert source_path is not None

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="non-canonical",
    ):
        execution_service.validate_job(
            replace_document(
                job,
                source_path=source_path.upper(),
            )
        )


@pytest.mark.parametrize(
    "file_size",
    [None, True, False, 0, -1, 1.5, "10"],
)
def test_validate_job_rejects_invalid_file_size(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    file_size: Any,
) -> None:
    """Authoritative stored size must be one positive integer."""

    job = replace_document(
        submit_upload(upload_service),
        file_size_bytes=file_size,
    )

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="file-size",
    ):
        execution_service.validate_job(job)


def test_validate_job_rejects_file_size_above_upload_limit(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Document size cannot exceed the job's recorded upload bound."""

    job = submit_upload(upload_service)
    metadata = dict(job.metadata["engineer4me_upload"])
    metadata["maximum_content_bytes"] = 1
    job = replace_upload_metadata(job, metadata)

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="file-size",
    ):
        execution_service.validate_job(job)


@pytest.mark.parametrize(
    "checksum",
    [
        None,
        "",
        "0" * 63,
        "0" * 65,
        "g" * 64,
        "A" * 64,
        1,
    ],
)
def test_validate_job_rejects_invalid_checksum(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    checksum: Any,
) -> None:
    """Execution requires canonical lowercase SHA-256 metadata."""

    job = replace_document(
        submit_upload(upload_service),
        checksum_sha256=checksum,
    )

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="SHA-256",
    ):
        execution_service.validate_job(job)


@pytest.mark.parametrize(
    "job_id",
    [None, "", 1, object()],
)
def test_process_job_rejects_non_uuid_identifier(
    execution_service: FilesystemDocumentExecutionService,
    job_id: Any,
) -> None:
    """Execution identifiers use the shared UUID contract."""

    with pytest.raises(TypeError, match="job_id"):
        execution_service.process_job(
            job_id,  # type: ignore[arg-type]
        )


def test_process_job_propagates_not_found(
    execution_service: FilesystemDocumentExecutionService,
) -> None:
    """Missing job lookup remains a repository-level not-found signal."""

    with pytest.raises(IngestionJobNotFoundError):
        execution_service.process_job(uuid4())


def test_process_pending_job_end_to_end(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """A pending stored upload reaches a terminal successful state."""

    job = submit_upload(upload_service)
    completed = execution_service.process_job(job.job_id)

    assert completed.status is IngestionJobStatus.COMPLETED
    assert completed.progress_percent == 100
    assert completed.completed_document_count == 1
    assert completed.failed_document_count == 0
    assert completed.documents[0].status.value == "completed"
    assert not execution_service.active_job_ids


def test_process_queued_job_end_to_end(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    job_service: IngestionJobService,
) -> None:
    """A queued upload is started and completed by the runtime."""

    job = submit_upload(upload_service)
    queued = job_service.queue(job.job_id)
    assert queued.status is IngestionJobStatus.QUEUED

    completed = execution_service.process_job(job.job_id)

    assert completed.status is IngestionJobStatus.COMPLETED
    assert completed.queued_at is not None
    assert completed.started_at is not None


def test_process_batch_end_to_end(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Every authoritative document in a batch is processed."""

    job = submit_batch(upload_service)
    completed = execution_service.process_job(job.job_id)

    assert completed.status is IngestionJobStatus.COMPLETED
    assert completed.completed_document_count == 2
    assert all(
        document.status.value == "completed"
        for document in completed.documents
    )


def test_terminal_replay_is_idempotent(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Replaying a completed job returns its existing terminal state."""

    job = submit_upload(upload_service)
    first = execution_service.process_job(job.job_id)
    second = execution_service.process_job(job.job_id)

    assert second == first
    assert second.status is IngestionJobStatus.COMPLETED
    assert not execution_service.active_job_ids


def test_missing_stored_file_becomes_controlled_failed_job(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
) -> None:
    """The runtime records confined file-access failures on the job."""

    job = submit_upload(upload_service)
    source_path = job.documents[0].source_path
    assert source_path is not None
    (storage_root / source_path).unlink()

    failed = execution_service.process_job(job.job_id)

    assert failed.status is IngestionJobStatus.FAILED
    assert failed.failed_document_count == 1
    assert failed.error_count >= 1
    assert failed.documents[0].status.value == "failed"
    assert not execution_service.active_job_ids


def test_changed_content_becomes_controlled_failed_job(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
) -> None:
    """Runtime checksum verification detects post-upload modification."""

    job = submit_upload(upload_service)
    source_path = job.documents[0].source_path
    assert source_path is not None
    stored_path = storage_root / source_path
    original_size = stored_path.stat().st_size
    stored_path.write_bytes(b"x" * original_size)

    failed = execution_service.process_job(job.job_id)

    assert failed.status is IngestionJobStatus.FAILED
    assert failed.failed_document_count == 1
    assert failed.documents[0].status.value == "failed"


def test_process_validates_before_delegating(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    job_service: IngestionJobService,
    runtime: FilesystemDocumentProcessingRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ineligible jobs never enter the processing runtime."""

    job = submit_upload(upload_service)
    metadata = dict(job.metadata["engineer4me_upload"])
    metadata["storage_backend"] = "object-storage"
    invalid = replace_upload_metadata(job, metadata)
    job_service.repository.replace(invalid)
    called = False

    def process_job(received_job_id: UUID) -> IngestionJob:
        nonlocal called
        called = True
        return job_service.get(received_job_id)

    monkeypatch.setattr(runtime, "process_job", process_job)

    with pytest.raises(
        FilesystemDocumentExecutionEligibilityError,
        match="does not use filesystem",
    ):
        execution_service.process_job(job.job_id)

    assert not called
    assert not execution_service.active_job_ids


def test_process_translates_runtime_state_error(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    runtime: FilesystemDocumentProcessingRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unsafe runtime resume errors become one public service error."""

    job = submit_upload(upload_service)
    state_error = DocumentProcessingStateError("unsafe state")

    def process_job(received_job_id: UUID) -> IngestionJob:
        assert received_job_id == job.job_id
        raise state_error

    monkeypatch.setattr(runtime, "process_job", process_job)

    with pytest.raises(
        FilesystemDocumentExecutionStateError,
        match="current state",
    ) as captured:
        execution_service.process_job(job.job_id)

    assert captured.value.__cause__ is state_error
    assert not execution_service.active_job_ids


def test_execution_lease_is_released_after_unexpected_error(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    runtime: FilesystemDocumentProcessingRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected runtime failures cannot leave a stale active lease."""

    job = submit_upload(upload_service)
    unexpected = RuntimeError("unexpected runtime failure")

    def process_job(received_job_id: UUID) -> IngestionJob:
        assert received_job_id == job.job_id
        raise unexpected

    monkeypatch.setattr(runtime, "process_job", process_job)

    with pytest.raises(RuntimeError) as captured:
        execution_service.process_job(job.job_id)

    assert captured.value is unexpected
    assert not execution_service.active_job_ids


def test_concurrent_execution_of_same_job_is_rejected(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    job_service: IngestionJobService,
    runtime: FilesystemDocumentProcessingRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only one in-process caller may hold a job execution lease."""

    job = submit_upload(upload_service)
    entered_runtime = Event()
    release_runtime = Event()

    def process_job(received_job_id: UUID) -> IngestionJob:
        assert received_job_id == job.job_id
        entered_runtime.set()

        if not release_runtime.wait(timeout=5):
            raise TimeoutError("Test execution lease was not released.")

        return job_service.get(received_job_id)

    monkeypatch.setattr(runtime, "process_job", process_job)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            execution_service.process_job,
            job.job_id,
        )

        assert entered_runtime.wait(timeout=5)
        assert execution_service.active_job_ids == frozenset(
            {job.job_id}
        )

        with pytest.raises(
            FilesystemDocumentExecutionConflictError,
            match="already executing",
        ):
            execution_service.process_job(job.job_id)

        release_runtime.set()
        result = future.result(timeout=5)

    assert result.job_id == job.job_id
    assert not execution_service.active_job_ids


def test_different_jobs_can_execute_concurrently(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    job_service: IngestionJobService,
    runtime: FilesystemDocumentProcessingRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per-job leases do not serialize unrelated uploads."""

    first = submit_upload(
        upload_service,
        filename="first.txt",
    )
    second = submit_upload(
        upload_service,
        filename="second.txt",
    )
    both_entered = Event()
    release_runtime = Event()
    entered: set[UUID] = set()

    def process_job(received_job_id: UUID) -> IngestionJob:
        entered.add(received_job_id)

        if len(entered) == 2:
            both_entered.set()

        if not release_runtime.wait(timeout=5):
            raise TimeoutError("Concurrent test was not released.")

        return job_service.get(received_job_id)

    monkeypatch.setattr(runtime, "process_job", process_job)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(
            execution_service.process_job,
            first.job_id,
        )
        second_future = executor.submit(
            execution_service.process_job,
            second.job_id,
        )

        assert both_entered.wait(timeout=5)
        assert execution_service.active_job_ids == frozenset(
            {first.job_id, second.job_id}
        )

        release_runtime.set()
        first_result = first_future.result(timeout=5)
        second_result = second_future.result(timeout=5)

    assert first_result.job_id == first.job_id
    assert second_result.job_id == second.job_id
    assert not execution_service.active_job_ids


def test_terminal_replay_does_not_acquire_execution_lease(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    runtime: FilesystemDocumentProcessingRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Already terminal jobs use the runtime's idempotent fast path."""

    job = submit_upload(upload_service)
    completed = execution_service.process_job(job.job_id)
    observed_active_ids: list[frozenset[UUID]] = []

    def process_job(received_job_id: UUID) -> IngestionJob:
        observed_active_ids.append(
            execution_service.active_job_ids
        )
        assert received_job_id == completed.job_id
        return completed

    monkeypatch.setattr(runtime, "process_job", process_job)

    replayed = execution_service.process_job(job.job_id)

    assert replayed == completed
    assert observed_active_ids == [frozenset()]


def test_validation_does_not_read_or_modify_stored_file(
    execution_service: FilesystemDocumentExecutionService,
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
) -> None:
    """Eligibility checks remain metadata-only and side-effect free."""

    job = submit_upload(upload_service)
    source_path = job.documents[0].source_path
    assert source_path is not None
    stored_path = storage_root / source_path
    before = stored_path.stat()

    execution_service.validate_job(job)

    after = stored_path.stat()
    assert stored_path.read_bytes() == DEFAULT_CONTENT
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns


def test_public_exports_are_complete() -> None:
    """The module exposes only its supported service contract."""

    from app.ingestion import (  # noqa: PLC0415
        filesystem_document_execution_service as module,
    )

    assert module.__all__ == [
        "FilesystemDocumentExecutionConflictError",
        "FilesystemDocumentExecutionEligibilityError",
        "FilesystemDocumentExecutionError",
        "FilesystemDocumentExecutionService",
        "FilesystemDocumentExecutionStateError",
    ]
