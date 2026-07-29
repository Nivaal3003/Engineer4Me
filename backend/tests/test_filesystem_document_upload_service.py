"""Tests for transactional filesystem-backed document uploads."""

from __future__ import annotations

from collections.abc import Generator
from io import BytesIO
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from app.ingestion.filesystem_document_storage import (
    DocumentStorageDeleteError,
    DocumentStorageEmptyError,
    DocumentStorageReadError,
    DocumentStorageTooLargeError,
    DocumentStorageWriteError,
    FilesystemDocumentStorage,
    FilesystemDocumentStorageConfig,
    StoredDocument,
)
from app.ingestion.filesystem_document_upload_service import (
    DocumentUploadRollbackError,
    DocumentUploadStorageError,
    DocumentUploadSubmissionError,
    DocumentUploadValidationError,
    FilesystemDocumentUpload,
    FilesystemDocumentUploadService,
    FilesystemDocumentUploadServiceConfig,
)
from app.ingestion.ingestion_job_models import (
    IngestionDocumentStatus,
    IngestionJob,
    IngestionJobStatus,
    IngestionJobType,
    IngestionSourceType,
    IngestionStage,
)
from app.ingestion.ingestion_job_repository import (
    IngestionJobRepository,
)
from app.ingestion.ingestion_job_service import IngestionJobService


DEFAULT_CONTENT = b"Engineer4Me upload transaction test document."


class NoReadMethod:
    """Object that does not implement the binary stream contract."""


class NonBinaryStream:
    """Stream that violates the storage adapter's binary result contract."""

    def read(self, size: int) -> str:
        """Return text instead of bytes."""

        return "not binary"


class OversizedChunkStream:
    """Stream that returns more data than the requested chunk size."""

    def read(self, size: int) -> bytes:
        """Return one byte more than requested."""

        return b"x" * (size + 1)


class RaisingReadStream:
    """Stream that fails when storage attempts to read it."""

    def read(self, size: int) -> bytes:
        """Raise a deterministic source failure."""

        raise OSError("forced stream read failure")


class TrackingBytesIO(BytesIO):
    """BytesIO that records whether a caller closed the stream."""

    def __init__(self, content: bytes) -> None:
        """Initialise the stream and close tracker."""

        super().__init__(content)
        self.was_closed = False

    def close(self) -> None:
        """Record closure before delegating to BytesIO."""

        self.was_closed = True
        super().close()


class UncopyableValue:
    """Metadata value that refuses defensive copying."""

    def __deepcopy__(self, memo: dict[int, Any]) -> Any:
        """Raise a deterministic copy failure."""

        raise RuntimeError("forced deepcopy failure")


class FailingIngestionJobService(IngestionJobService):
    """Job service that fails every submission after storage succeeds."""

    def __init__(
        self,
        error: Exception | None = None,
    ) -> None:
        """Initialise an isolated repository and deterministic error."""

        super().__init__(IngestionJobRepository())
        self.error = error or RuntimeError(
            "forced ingestion submission failure"
        )
        self.submission_count = 0

    def submit(self, job: IngestionJob) -> IngestionJob:
        """Record the attempt and raise the configured error."""

        self.submission_count += 1
        raise self.error


class RecordingFilesystemDocumentStorage(
    FilesystemDocumentStorage
):
    """Storage adapter that records stores and rollback deletions."""

    def __init__(
        self,
        config: FilesystemDocumentStorageConfig,
    ) -> None:
        """Initialise storage and operation records."""

        super().__init__(config)
        self.stored_documents: list[StoredDocument] = []
        self.delete_calls: list[tuple[str, str | None]] = []

    def store_stream(
        self,
        *,
        filename: str,
        stream: Any,
        media_type: str | None = None,
        storage_id: Any = None,
    ) -> StoredDocument:
        """Store through the production adapter and record metadata."""

        stored = super().store_stream(
            filename=filename,
            stream=stream,
            media_type=media_type,
            storage_id=storage_id,
        )
        self.stored_documents.append(stored)

        return stored

    def delete(
        self,
        source_path: str,
        *,
        expected_checksum_sha256: str | None = None,
    ) -> bool:
        """Record rollback arguments and perform guarded deletion."""

        self.delete_calls.append(
            (source_path, expected_checksum_sha256)
        )

        return super().delete(
            source_path,
            expected_checksum_sha256=expected_checksum_sha256,
        )


class MissingRollbackFilesystemDocumentStorage(
    RecordingFilesystemDocumentStorage
):
    """Storage adapter that reports stored content missing on rollback."""

    def delete(
        self,
        source_path: str,
        *,
        expected_checksum_sha256: str | None = None,
    ) -> bool:
        """Record the call and refuse to confirm deletion."""

        self.delete_calls.append(
            (source_path, expected_checksum_sha256)
        )
        return False


class FailingRollbackFilesystemDocumentStorage(
    RecordingFilesystemDocumentStorage
):
    """Storage adapter that raises during every rollback deletion."""

    def delete(
        self,
        source_path: str,
        *,
        expected_checksum_sha256: str | None = None,
    ) -> bool:
        """Record the call and raise a guarded deletion failure."""

        self.delete_calls.append(
            (source_path, expected_checksum_sha256)
        )
        raise DocumentStorageDeleteError(
            "forced rollback deletion failure"
        )


class SecondStoreFailureFilesystemDocumentStorage(
    RecordingFilesystemDocumentStorage
):
    """Storage adapter that fails before storing its second stream."""

    def __init__(
        self,
        config: FilesystemDocumentStorageConfig,
        *,
        fail_rollback: bool = False,
    ) -> None:
        """Initialise storage with optional rollback failure."""

        super().__init__(config)
        self.store_attempt_count = 0
        self.fail_rollback = fail_rollback

    def store_stream(
        self,
        *,
        filename: str,
        stream: Any,
        media_type: str | None = None,
        storage_id: Any = None,
    ) -> StoredDocument:
        """Store the first stream and fail the second."""

        self.store_attempt_count += 1

        if self.store_attempt_count == 2:
            raise DocumentStorageWriteError(
                "forced second storage failure"
            )

        return super().store_stream(
            filename=filename,
            stream=stream,
            media_type=media_type,
            storage_id=storage_id,
        )

    def delete(
        self,
        source_path: str,
        *,
        expected_checksum_sha256: str | None = None,
    ) -> bool:
        """Optionally fail rollback after the second store fails."""

        if self.fail_rollback:
            self.delete_calls.append(
                (source_path, expected_checksum_sha256)
            )
            raise DocumentStorageDeleteError(
                "forced rollback failure after store failure"
            )

        return super().delete(
            source_path,
            expected_checksum_sha256=expected_checksum_sha256,
        )


@pytest.fixture
def storage_root(tmp_path: Path) -> Path:
    """Return an isolated existing storage root."""

    root = tmp_path / "uploads"
    root.mkdir()

    return root


@pytest.fixture
def storage(
    storage_root: Path,
) -> FilesystemDocumentStorage:
    """Return production storage with a small deterministic limit."""

    return FilesystemDocumentStorage(
        FilesystemDocumentStorageConfig(
            root_directory=storage_root,
            maximum_content_bytes=1_024,
            read_chunk_bytes=16,
        )
    )


@pytest.fixture
def job_service() -> IngestionJobService:
    """Return an isolated ingestion job service."""

    return IngestionJobService(IngestionJobRepository())


@pytest.fixture
def upload_service(
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> FilesystemDocumentUploadService:
    """Return the complete upload transaction service."""

    return FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
    )


def make_upload(
    *,
    filename: str = "manual.pdf",
    content: bytes = DEFAULT_CONTENT,
    media_type: str | None = "application/pdf",
    attributes: dict[str, Any] | None = None,
    stream: Any | None = None,
) -> FilesystemDocumentUpload:
    """Build one valid upload input."""

    return FilesystemDocumentUpload(
        filename=filename,
        stream=BytesIO(content) if stream is None else stream,
        media_type=media_type,
        attributes=attributes or {},
    )


def stored_files(root: Path) -> list[Path]:
    """Return every regular file below a storage root."""

    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
    )


def resolve_stored_file(
    root: Path,
    source_path: str,
) -> Path:
    """Resolve one opaque storage reference for test inspection."""

    return root.joinpath(*source_path.split("/"))


def assert_no_side_effects(
    *,
    root: Path,
    job_service: IngestionJobService,
) -> None:
    """Assert that validation or rollback left no files or jobs."""

    assert stored_files(root) == []
    assert job_service.statistics().total_jobs == 0


def test_config_uses_bounded_defaults() -> None:
    """Default transaction controls align with ingestion constraints."""

    config = FilesystemDocumentUploadServiceConfig()

    assert config.maximum_documents_per_job == 20
    assert config.default_maximum_attempts == 3


@pytest.mark.parametrize(
    "value",
    [True, False, 0, -1, 1_001, 1.5, "20", None],
)
def test_config_rejects_invalid_maximum_documents(
    value: Any,
) -> None:
    """The batch bound must be an integer from 1 through 1,000."""

    with pytest.raises(ValueError):
        FilesystemDocumentUploadServiceConfig(
            maximum_documents_per_job=value,
        )


@pytest.mark.parametrize(
    "value",
    [True, False, 0, -1, 21, 1.5, "3", None],
)
def test_config_rejects_invalid_default_attempts(
    value: Any,
) -> None:
    """The default retry bound must match the ingestion model."""

    with pytest.raises(ValueError):
        FilesystemDocumentUploadServiceConfig(
            default_maximum_attempts=value,
        )


def test_config_accepts_boundary_values() -> None:
    """Valid lower and upper bounds are retained exactly."""

    lower = FilesystemDocumentUploadServiceConfig(
        maximum_documents_per_job=1,
        default_maximum_attempts=1,
    )
    upper = FilesystemDocumentUploadServiceConfig(
        maximum_documents_per_job=1_000,
        default_maximum_attempts=20,
    )

    assert lower.maximum_documents_per_job == 1
    assert lower.default_maximum_attempts == 1
    assert upper.maximum_documents_per_job == 1_000
    assert upper.default_maximum_attempts == 20


def test_upload_copies_attributes_defensively() -> None:
    """Later mutation of caller metadata cannot alter upload metadata."""

    attributes = {
        "manufacturer": "Example",
        "nested": {"revision": "A"},
    }
    upload = make_upload(attributes=attributes)

    attributes["manufacturer"] = "Changed"
    attributes["nested"]["revision"] = "B"

    assert upload.attributes["manufacturer"] == "Example"
    assert upload.attributes["nested"]["revision"] == "A"


def test_upload_accepts_readable_stream_and_mapping_proxy() -> None:
    """Read-capable streams and immutable mappings satisfy the contract."""

    stream = BytesIO(DEFAULT_CONTENT)
    attributes = MappingProxyType({"source": "test"})
    upload = FilesystemDocumentUpload(
        filename="manual.pdf",
        stream=stream,
        media_type=None,
        attributes=attributes,
    )

    assert upload.stream is stream
    assert upload.media_type is None
    assert upload.attributes == {"source": "test"}
    assert isinstance(upload.attributes, dict)


@pytest.mark.parametrize("value", [None, 1, b"manual.pdf"])
def test_upload_rejects_non_string_filename(value: Any) -> None:
    """Filename metadata must be supplied as text."""

    with pytest.raises(TypeError):
        FilesystemDocumentUpload(
            filename=value,
            stream=BytesIO(DEFAULT_CONTENT),
        )


@pytest.mark.parametrize("value", ["", " ", "\t\r\n"])
def test_upload_rejects_blank_filename(value: str) -> None:
    """Blank filenames fail before storage creates shard directories."""

    with pytest.raises(
        DocumentUploadValidationError,
        match="filename cannot be blank",
    ):
        FilesystemDocumentUpload(
            filename=value,
            stream=BytesIO(DEFAULT_CONTENT),
        )


def test_upload_rejects_stream_without_read_method() -> None:
    """Every upload must provide a callable read method."""

    with pytest.raises(TypeError, match="callable read method"):
        FilesystemDocumentUpload(
            filename="manual.pdf",
            stream=NoReadMethod(),
        )


@pytest.mark.parametrize("value", [1, b"application/pdf", []])
def test_upload_rejects_non_string_media_type(value: Any) -> None:
    """Optional media types must be text."""

    with pytest.raises(TypeError, match="media_type"):
        FilesystemDocumentUpload(
            filename="manual.pdf",
            stream=BytesIO(DEFAULT_CONTENT),
            media_type=value,
        )


@pytest.mark.parametrize("value", [[], "metadata", 1])
def test_upload_rejects_non_mapping_attributes(value: Any) -> None:
    """Document attributes must be supplied as a mapping."""

    with pytest.raises(TypeError, match="attributes must be a mapping"):
        FilesystemDocumentUpload(
            filename="manual.pdf",
            stream=BytesIO(DEFAULT_CONTENT),
            attributes=value,
        )


def test_upload_rejects_non_string_attribute_keys() -> None:
    """Metadata keys must remain JSON-compatible strings."""

    with pytest.raises(
        DocumentUploadValidationError,
        match="keys must be strings",
    ):
        FilesystemDocumentUpload(
            filename="manual.pdf",
            stream=BytesIO(DEFAULT_CONTENT),
            attributes={1: "invalid"},
        )


def test_upload_rejects_uncopyable_attributes() -> None:
    """Caller metadata must support defensive copying."""

    with pytest.raises(
        DocumentUploadValidationError,
        match="could not be copied safely",
    ):
        FilesystemDocumentUpload(
            filename="manual.pdf",
            stream=BytesIO(DEFAULT_CONTENT),
            attributes={"value": UncopyableValue()},
        )


def test_service_uses_default_config(
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    """Omitted configuration resolves to validated defaults."""

    service = FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
    )

    assert service.storage is storage
    assert service.job_service is job_service
    assert service.config == FilesystemDocumentUploadServiceConfig()


def test_service_exposes_explicit_dependencies(
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    """Configured dependencies remain available for composition."""

    config = FilesystemDocumentUploadServiceConfig(
        maximum_documents_per_job=5,
        default_maximum_attempts=4,
    )
    service = FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
        config=config,
    )

    assert service.storage is storage
    assert service.job_service is job_service
    assert service.config is config


@pytest.mark.parametrize("value", [None, object(), "storage"])
def test_service_rejects_invalid_storage(
    value: Any,
    job_service: IngestionJobService,
) -> None:
    """Composition requires the guarded filesystem adapter."""

    with pytest.raises(TypeError, match="storage"):
        FilesystemDocumentUploadService(
            storage=value,
            job_service=job_service,
        )


@pytest.mark.parametrize("value", [None, object(), "service"])
def test_service_rejects_invalid_job_service(
    value: Any,
    storage: FilesystemDocumentStorage,
) -> None:
    """Composition requires the ingestion lifecycle service."""

    with pytest.raises(TypeError, match="job_service"):
        FilesystemDocumentUploadService(
            storage=storage,
            job_service=value,
        )


@pytest.mark.parametrize("value", [object(), {}, "config"])
def test_service_rejects_invalid_config(
    value: Any,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    """Explicit configuration must use the validated config type."""

    with pytest.raises(TypeError, match="config"):
        FilesystemDocumentUploadService(
            storage=storage,
            job_service=job_service,
            config=value,
        )


def test_submit_single_upload_creates_pending_job(
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
) -> None:
    """A valid stream becomes one pending single-document job."""

    job = upload_service.submit_upload(
        upload=make_upload(),
        submitted_by="upload-user",
        correlation_id="UPLOAD-001",
        metadata={"purpose": "manual ingestion"},
    )

    assert job.job_type is IngestionJobType.SINGLE_DOCUMENT
    assert job.source_type is IngestionSourceType.API_UPLOAD
    assert job.status is IngestionJobStatus.PENDING
    assert job.stage is IngestionStage.WAITING
    assert job.submitted_by == "upload-user"
    assert job.correlation_id == "UPLOAD-001"
    assert job.total_document_count == 1
    assert len(job.documents) == 1

    document = job.documents[0]

    assert document.status is IngestionDocumentStatus.PENDING
    assert document.stage is IngestionStage.WAITING
    assert document.progress_percent == 0
    assert document.source_name == "manual.pdf"
    assert document.media_type == "application/pdf"
    assert document.file_size_bytes == len(DEFAULT_CONTENT)
    assert len(document.checksum_sha256 or "") == 64
    assert document.maximum_attempts == 3
    assert resolve_stored_file(
        storage_root,
        document.source_path or "",
    ).read_bytes() == DEFAULT_CONTENT


def test_submit_single_upload_registers_repository_copy(
    upload_service: FilesystemDocumentUploadService,
    job_service: IngestionJobService,
) -> None:
    """The lifecycle repository contains the returned upload job."""

    submitted = upload_service.submit_upload(
        upload=make_upload(),
        submitted_by="repository-test",
    )

    assert job_service.get(submitted.job_id) == submitted
    assert job_service.statistics().total_jobs == 1
    assert job_service.statistics().total_documents == 1


def test_submit_normalises_identity_and_correlation(
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Text identity inputs are stripped before job construction."""

    job = upload_service.submit_upload(
        upload=make_upload(),
        submitted_by="  upload-user  ",
        correlation_id="  TRACE-001  ",
    )

    assert job.submitted_by == "upload-user"
    assert job.correlation_id == "TRACE-001"


@pytest.mark.parametrize("value", [None, "", " ", "\t"])
def test_submit_normalises_blank_correlation_to_none(
    value: str | None,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Blank optional correlation identifiers are omitted."""

    job = upload_service.submit_upload(
        upload=make_upload(),
        submitted_by="upload-user",
        correlation_id=value,
    )

    assert job.correlation_id is None


def test_submit_normalises_filename_and_media_type(
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
) -> None:
    """Storage supplies the authoritative display name and media type."""

    job = upload_service.submit_upload(
        upload=make_upload(
            filename=r"C:\untrusted\folder\Manual.PDF",
            media_type="  Application/PDF  ",
        ),
        submitted_by="upload-user",
    )
    document = job.documents[0]

    assert document.source_name == "Manual.PDF"
    assert document.media_type == "application/pdf"
    assert (document.source_path or "").endswith(".pdf")
    assert resolve_stored_file(
        storage_root,
        document.source_path or "",
    ).is_file()


def test_submit_derives_authoritative_document_metadata(
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Caller attempts cannot spoof the reserved storage attribute."""

    job = upload_service.submit_upload(
        upload=make_upload(
            attributes={
                "manufacturer": "Example",
                "engineer4me_storage": {
                    "backend": "spoofed",
                    "storage_id": "spoofed",
                },
            },
        ),
        submitted_by="upload-user",
    )
    document = job.documents[0]
    storage_metadata = document.attributes[
        "engineer4me_storage"
    ]

    assert document.attributes["manufacturer"] == "Example"
    assert storage_metadata["backend"] == "filesystem"
    assert storage_metadata["storage_id"] != "spoofed"
    assert len(storage_metadata["storage_id"]) == 36
    assert storage_metadata["stored_at"].endswith("+00:00")
    assert set(storage_metadata) == {
        "backend",
        "storage_id",
        "stored_at",
    }


def test_submit_derives_authoritative_job_metadata(
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Caller attempts cannot spoof reserved job upload metadata."""

    job = upload_service.submit_upload(
        upload=make_upload(),
        submitted_by="upload-user",
        metadata={
            "purpose": "test",
            "engineer4me_upload": {
                "storage_backend": "spoofed",
            },
        },
    )
    upload_metadata = job.metadata["engineer4me_upload"]

    assert job.metadata["purpose"] == "test"
    assert upload_metadata == {
        "storage_backend": "filesystem",
        "document_count": 1,
        "maximum_content_bytes": 1_024,
    }


def test_submit_copies_job_metadata_defensively(
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Mutating caller metadata after submission cannot alter the job."""

    metadata = {"nested": {"revision": "A"}}
    job = upload_service.submit_upload(
        upload=make_upload(),
        submitted_by="upload-user",
        metadata=metadata,
    )

    metadata["nested"]["revision"] = "B"

    assert job.metadata["nested"]["revision"] == "A"


def test_submit_uses_explicit_maximum_attempts(
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """A valid request override applies to every document."""

    job = upload_service.submit_upload(
        upload=make_upload(),
        submitted_by="upload-user",
        maximum_attempts=7,
    )

    assert job.documents[0].maximum_attempts == 7


def test_submit_uses_configured_default_attempts(
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    """Service configuration controls the default retry limit."""

    service = FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
        config=FilesystemDocumentUploadServiceConfig(
            default_maximum_attempts=5,
        ),
    )
    job = service.submit_upload(
        upload=make_upload(),
        submitted_by="upload-user",
    )

    assert job.documents[0].maximum_attempts == 5


def test_submit_does_not_close_caller_stream(
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Stream lifetime remains owned by the transport adapter."""

    stream = TrackingBytesIO(DEFAULT_CONTENT)

    upload_service.submit_upload(
        upload=make_upload(stream=stream),
        submitted_by="upload-user",
    )

    assert stream.was_closed is False
    stream.close()


def test_submit_batch_preserves_order_and_content(
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
) -> None:
    """A valid batch becomes one ordered document-batch job."""

    contents = [b"first", b"second", b"third"]
    uploads = [
        make_upload(
            filename=f"manual-{index}.pdf",
            content=content,
            attributes={"position": index},
        )
        for index, content in enumerate(contents, start=1)
    ]

    job = upload_service.submit_uploads(
        uploads=uploads,
        submitted_by="batch-user",
    )

    assert job.job_type is IngestionJobType.DOCUMENT_BATCH
    assert job.total_document_count == 3
    assert [
        document.source_name
        for document in job.documents
    ] == [
        "manual-1.pdf",
        "manual-2.pdf",
        "manual-3.pdf",
    ]
    assert [
        document.attributes["position"]
        for document in job.documents
    ] == [1, 2, 3]
    assert [
        resolve_stored_file(
            storage_root,
            document.source_path or "",
        ).read_bytes()
        for document in job.documents
    ] == contents
    assert job.metadata["engineer4me_upload"][
        "document_count"
    ] == 3


def test_submit_batch_generates_unique_storage_references(
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Duplicate display filenames cannot collide in storage."""

    job = upload_service.submit_uploads(
        uploads=[
            make_upload(filename="manual.pdf", content=b"one"),
            make_upload(filename="manual.pdf", content=b"two"),
        ],
        submitted_by="batch-user",
    )
    references = [
        document.source_path
        for document in job.documents
    ]

    assert len(references) == 2
    assert len(set(references)) == 2


def test_submit_accepts_upload_generator(
    upload_service: FilesystemDocumentUploadService,
) -> None:
    """Transport adapters may supply a finite upload generator."""

    uploads = (
        make_upload(
            filename=f"manual-{index}.pdf",
            content=str(index).encode(),
        )
        for index in range(2)
    )

    job = upload_service.submit_uploads(
        uploads=uploads,
        submitted_by="generator-user",
    )

    assert job.total_document_count == 2
    assert job.job_type is IngestionJobType.DOCUMENT_BATCH


def test_submit_accepts_configured_batch_boundary(
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    """A batch exactly at the configured limit is accepted."""

    service = FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
        config=FilesystemDocumentUploadServiceConfig(
            maximum_documents_per_job=2,
        ),
    )

    job = service.submit_uploads(
        uploads=[
            make_upload(filename="one.pdf", content=b"one"),
            make_upload(filename="two.pdf", content=b"two"),
        ],
        submitted_by="boundary-user",
    )

    assert job.total_document_count == 2


@pytest.mark.parametrize(
    "uploads",
    [
        "uploads",
        b"uploads",
        bytearray(b"uploads"),
        memoryview(b"uploads"),
        1,
        None,
    ],
)
def test_submit_rejects_invalid_upload_collection(
    uploads: Any,
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Non-upload collections fail without storage or repository writes."""

    with pytest.raises(TypeError, match="iterable"):
        upload_service.submit_uploads(
            uploads=uploads,
            submitted_by="upload-user",
        )

    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_submit_rejects_empty_upload_collection(
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """A job must contain at least one document."""

    with pytest.raises(
        DocumentUploadValidationError,
        match="At least one",
    ):
        upload_service.submit_uploads(
            uploads=[],
            submitted_by="upload-user",
        )

    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_submit_rejects_upload_collection_above_limit(
    storage: FilesystemDocumentStorage,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Batch limits are enforced before the first stream is read."""

    service = FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
        config=FilesystemDocumentUploadServiceConfig(
            maximum_documents_per_job=2,
        ),
    )

    with pytest.raises(
        DocumentUploadValidationError,
        match="more than",
    ):
        service.submit_uploads(
            uploads=[
                make_upload(filename="one.pdf"),
                make_upload(filename="two.pdf"),
                make_upload(filename="three.pdf"),
            ],
            submitted_by="upload-user",
        )

    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_submit_rejects_non_upload_element(
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Every batch element must use the upload input model."""

    with pytest.raises(TypeError, match="contain only"):
        upload_service.submit_uploads(
            uploads=[make_upload(), object()],
            submitted_by="upload-user",
        )

    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


@pytest.mark.parametrize("value", [None, 1, b"user"])
def test_submit_rejects_non_string_submitted_by(
    value: Any,
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Submitter identity must be text."""

    with pytest.raises(TypeError, match="submitted_by"):
        upload_service.submit_upload(
            upload=make_upload(),
            submitted_by=value,
        )

    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


@pytest.mark.parametrize("value", ["", " ", "\t\r\n"])
def test_submit_rejects_blank_submitted_by(
    value: str,
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Blank submitter identity is rejected before storage."""

    with pytest.raises(
        DocumentUploadValidationError,
        match="submitted_by cannot be blank",
    ):
        upload_service.submit_upload(
            upload=make_upload(),
            submitted_by=value,
        )

    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_submit_rejects_long_submitted_by(
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Submitter identity cannot exceed the job model limit."""

    with pytest.raises(
        DocumentUploadValidationError,
        match="255-character",
    ):
        upload_service.submit_upload(
            upload=make_upload(),
            submitted_by="u" * 256,
        )

    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


@pytest.mark.parametrize("value", [1, b"trace", []])
def test_submit_rejects_non_string_correlation_id(
    value: Any,
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Optional correlation identifiers must be text."""

    with pytest.raises(TypeError, match="correlation_id"):
        upload_service.submit_upload(
            upload=make_upload(),
            submitted_by="upload-user",
            correlation_id=value,
        )

    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_submit_rejects_long_correlation_id(
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Correlation identifiers cannot exceed the model limit."""

    with pytest.raises(
        DocumentUploadValidationError,
        match="255-character",
    ):
        upload_service.submit_upload(
            upload=make_upload(),
            submitted_by="upload-user",
            correlation_id="c" * 256,
        )

    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


@pytest.mark.parametrize(
    "value",
    [True, False, 0, -1, 21, 1.5, "3"],
)
def test_submit_rejects_invalid_maximum_attempts(
    value: Any,
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Per-request retry limits are validated before storage."""

    with pytest.raises(
        DocumentUploadValidationError,
        match="maximum_attempts",
    ):
        upload_service.submit_upload(
            upload=make_upload(),
            submitted_by="upload-user",
            maximum_attempts=value,
        )

    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


@pytest.mark.parametrize("value", [[], "metadata", 1])
def test_submit_rejects_non_mapping_job_metadata(
    value: Any,
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Job metadata must be a mapping."""

    with pytest.raises(TypeError, match="metadata must be a mapping"):
        upload_service.submit_upload(
            upload=make_upload(),
            submitted_by="upload-user",
            metadata=value,
        )

    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_submit_rejects_non_string_job_metadata_keys(
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Job metadata keys must be strings."""

    with pytest.raises(
        DocumentUploadValidationError,
        match="keys must be strings",
    ):
        upload_service.submit_upload(
            upload=make_upload(),
            submitted_by="upload-user",
            metadata={1: "invalid"},
        )

    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_submit_rejects_uncopyable_job_metadata(
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Uncopyable metadata fails before storage."""

    with pytest.raises(
        DocumentUploadValidationError,
        match="could not be copied safely",
    ):
        upload_service.submit_upload(
            upload=make_upload(),
            submitted_by="upload-user",
            metadata={"value": UncopyableValue()},
        )

    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_unsupported_suffix_raises_storage_error(
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Storage filename policy is exposed through a generic service error."""

    with pytest.raises(DocumentUploadStorageError) as captured:
        upload_service.submit_upload(
            upload=make_upload(filename="payload.exe"),
            submitted_by="upload-user",
        )

    assert captured.value.__cause__ is not None
    assert "could not be stored safely" in str(captured.value)
    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_empty_stream_raises_storage_error(
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Empty uploads are rejected and leave no stored file."""

    with pytest.raises(DocumentUploadStorageError) as captured:
        upload_service.submit_upload(
            upload=make_upload(content=b""),
            submitted_by="upload-user",
        )

    assert isinstance(
        captured.value.__cause__,
        DocumentStorageEmptyError,
    )
    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_oversized_stream_raises_storage_error(
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Uploads beyond storage limits are removed and not registered."""

    storage = FilesystemDocumentStorage(
        FilesystemDocumentStorageConfig(
            root_directory=storage_root,
            maximum_content_bytes=4,
            read_chunk_bytes=2,
        )
    )
    service = FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
    )

    with pytest.raises(DocumentUploadStorageError) as captured:
        service.submit_upload(
            upload=make_upload(content=b"12345"),
            submitted_by="upload-user",
        )

    assert isinstance(
        captured.value.__cause__,
        DocumentStorageTooLargeError,
    )
    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


@pytest.mark.parametrize(
    ("stream", "expected_cause"),
    [
        (NonBinaryStream(), DocumentStorageReadError),
        (OversizedChunkStream(), DocumentStorageReadError),
        (RaisingReadStream(), DocumentStorageReadError),
    ],
)
def test_invalid_stream_result_raises_storage_error(
    stream: Any,
    expected_cause: type[Exception],
    upload_service: FilesystemDocumentUploadService,
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Untrusted stream contract violations remain contained."""

    with pytest.raises(DocumentUploadStorageError) as captured:
        upload_service.submit_upload(
            upload=make_upload(stream=stream),
            submitted_by="upload-user",
        )

    assert isinstance(captured.value.__cause__, expected_cause)
    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_second_storage_failure_rolls_back_first_file(
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """A later storage failure checksum-deletes earlier files."""

    storage = SecondStoreFailureFilesystemDocumentStorage(
        FilesystemDocumentStorageConfig(
            root_directory=storage_root,
            maximum_content_bytes=1_024,
            read_chunk_bytes=16,
        )
    )
    service = FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
    )

    with pytest.raises(DocumentUploadStorageError) as captured:
        service.submit_uploads(
            uploads=[
                make_upload(filename="first.pdf", content=b"first"),
                make_upload(filename="second.pdf", content=b"second"),
            ],
            submitted_by="upload-user",
        )

    assert isinstance(
        captured.value.__cause__,
        DocumentStorageWriteError,
    )
    assert len(storage.stored_documents) == 1
    assert storage.delete_calls == [
        (
            storage.stored_documents[0].source_path,
            storage.stored_documents[0].checksum_sha256,
        )
    ]
    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_submission_failure_rolls_back_stored_file(
    storage_root: Path,
) -> None:
    """A job submission failure leaves no orphaned upload."""

    storage = RecordingFilesystemDocumentStorage(
        FilesystemDocumentStorageConfig(
            root_directory=storage_root,
            maximum_content_bytes=1_024,
            read_chunk_bytes=16,
        )
    )
    job_service = FailingIngestionJobService()
    service = FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
    )

    with pytest.raises(DocumentUploadSubmissionError) as captured:
        service.submit_upload(
            upload=make_upload(),
            submitted_by="upload-user",
        )

    assert isinstance(captured.value.__cause__, RuntimeError)
    assert job_service.submission_count == 1
    assert len(storage.stored_documents) == 1
    assert storage.delete_calls == [
        (
            storage.stored_documents[0].source_path,
            storage.stored_documents[0].checksum_sha256,
        )
    ]
    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_batch_submission_failure_rolls_back_in_reverse_order(
    storage_root: Path,
) -> None:
    """Batch rollback reverses creation order and checks every checksum."""

    storage = RecordingFilesystemDocumentStorage(
        FilesystemDocumentStorageConfig(
            root_directory=storage_root,
            maximum_content_bytes=1_024,
            read_chunk_bytes=16,
        )
    )
    job_service = FailingIngestionJobService()
    service = FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
    )

    with pytest.raises(DocumentUploadSubmissionError):
        service.submit_uploads(
            uploads=[
                make_upload(filename="one.pdf", content=b"one"),
                make_upload(filename="two.pdf", content=b"two"),
                make_upload(filename="three.pdf", content=b"three"),
            ],
            submitted_by="upload-user",
        )

    expected_calls = [
        (stored.source_path, stored.checksum_sha256)
        for stored in reversed(storage.stored_documents)
    ]

    assert len(storage.stored_documents) == 3
    assert storage.delete_calls == expected_calls
    assert_no_side_effects(
        root=storage_root,
        job_service=job_service,
    )


def test_missing_rollback_file_raises_rollback_error(
    storage_root: Path,
) -> None:
    """An unconfirmed rollback is surfaced as a transaction failure."""

    storage = MissingRollbackFilesystemDocumentStorage(
        FilesystemDocumentStorageConfig(
            root_directory=storage_root,
            maximum_content_bytes=1_024,
            read_chunk_bytes=16,
        )
    )
    job_service = FailingIngestionJobService()
    service = FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
    )

    with pytest.raises(DocumentUploadRollbackError) as captured:
        service.submit_upload(
            upload=make_upload(),
            submitted_by="upload-user",
        )

    error = captured.value

    assert error.primary_error_type == "RuntimeError"
    assert error.rollback_error_count == 1
    assert error.rollback_error_types == (
        "DocumentStorageDeleteError",
    )
    assert error.stored_document_count == 1
    assert isinstance(error.__cause__, RuntimeError)
    assert len(stored_files(storage_root)) == 1
    assert job_service.statistics().total_jobs == 0


def test_raised_rollback_failure_preserves_safe_error_details(
    storage_root: Path,
) -> None:
    """Rollback failures expose types and counts without storage secrets."""

    storage = FailingRollbackFilesystemDocumentStorage(
        FilesystemDocumentStorageConfig(
            root_directory=storage_root,
            maximum_content_bytes=1_024,
            read_chunk_bytes=16,
        )
    )
    job_service = FailingIngestionJobService(
        ValueError("forced job validation failure")
    )
    service = FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
    )

    with pytest.raises(DocumentUploadRollbackError) as captured:
        service.submit_upload(
            upload=make_upload(),
            submitted_by="upload-user",
        )

    error = captured.value
    stored = storage.stored_documents[0]

    assert error.primary_error is job_service.error
    assert error.primary_error_type == "ValueError"
    assert error.rollback_error_count == 1
    assert error.rollback_error_types == (
        "DocumentStorageDeleteError",
    )
    assert stored.source_path not in str(error)
    assert stored.checksum_sha256 not in str(error)
    assert len(stored_files(storage_root)) == 1


def test_multiple_rollback_failures_are_all_reported(
    storage_root: Path,
) -> None:
    """Every failed batch deletion contributes one rollback error."""

    storage = FailingRollbackFilesystemDocumentStorage(
        FilesystemDocumentStorageConfig(
            root_directory=storage_root,
            maximum_content_bytes=1_024,
            read_chunk_bytes=16,
        )
    )
    job_service = FailingIngestionJobService()
    service = FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
    )

    with pytest.raises(DocumentUploadRollbackError) as captured:
        service.submit_uploads(
            uploads=[
                make_upload(filename="one.pdf", content=b"one"),
                make_upload(filename="two.pdf", content=b"two"),
            ],
            submitted_by="upload-user",
        )

    error = captured.value

    assert error.stored_document_count == 2
    assert error.rollback_error_count == 2
    assert error.rollback_error_types == (
        "DocumentStorageDeleteError",
        "DocumentStorageDeleteError",
    )
    assert len(storage.delete_calls) == 2
    assert len(stored_files(storage_root)) == 2
    assert job_service.statistics().total_jobs == 0


def test_storage_failure_and_rollback_failure_raise_rollback_error(
    storage_root: Path,
    job_service: IngestionJobService,
) -> None:
    """Rollback remains authoritative when the primary failure is storage."""

    storage = SecondStoreFailureFilesystemDocumentStorage(
        FilesystemDocumentStorageConfig(
            root_directory=storage_root,
            maximum_content_bytes=1_024,
            read_chunk_bytes=16,
        ),
        fail_rollback=True,
    )
    service = FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
    )

    with pytest.raises(DocumentUploadRollbackError) as captured:
        service.submit_uploads(
            uploads=[
                make_upload(filename="one.pdf", content=b"one"),
                make_upload(filename="two.pdf", content=b"two"),
            ],
            submitted_by="upload-user",
        )

    error = captured.value

    assert error.primary_error_type == "DocumentStorageWriteError"
    assert error.rollback_error_count == 1
    assert error.stored_document_count == 1
    assert isinstance(error.__cause__, DocumentStorageWriteError)
    assert len(stored_files(storage_root)) == 1
    assert job_service.statistics().total_jobs == 0


@pytest.mark.parametrize(
    ("primary_error", "rollback_errors", "stored_count", "error_type"),
    [
        ("not-error", (RuntimeError("rollback"),), 1, TypeError),
        (RuntimeError("primary"), (), 1, ValueError),
        (
            RuntimeError("primary"),
            ("not-error",),
            1,
            ValueError,
        ),
        (
            RuntimeError("primary"),
            (RuntimeError("rollback"),),
            0,
            ValueError,
        ),
        (
            RuntimeError("primary"),
            (RuntimeError("rollback"),),
            True,
            ValueError,
        ),
    ],
)
def test_rollback_error_rejects_invalid_direct_construction(
    primary_error: Any,
    rollback_errors: Any,
    stored_count: Any,
    error_type: type[Exception],
) -> None:
    """Rollback error metadata validates even when built directly."""

    with pytest.raises(error_type):
        DocumentUploadRollbackError(
            primary_error=primary_error,
            rollback_errors=rollback_errors,
            stored_document_count=stored_count,
        )


def test_rollback_error_exposes_count_property() -> None:
    """Rollback failure count is derived from its immutable tuple."""

    error = DocumentUploadRollbackError(
        primary_error=RuntimeError("primary"),
        rollback_errors=(
            RuntimeError("one"),
            ValueError("two"),
        ),
        stored_document_count=2,
    )

    assert error.rollback_error_count == 2
    assert error.primary_error_type == "RuntimeError"
    assert error.rollback_error_types == (
        "RuntimeError",
        "ValueError",
    )
    assert "could not be rolled back safely" in str(error)
