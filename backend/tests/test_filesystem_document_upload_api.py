"""Tests for the filesystem-backed multipart document-upload API."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Generator
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.api.filesystem_document_upload_api import (
    DocumentUploadRequestError,
    FilesystemDocumentUploadApiConfig,
    FilesystemDocumentUploadApiConfigurationError,
    _decode_document_attributes,
    _decode_json_mapping,
    _prepare_storage_root,
    _read_environment_integer,
    get_filesystem_document_storage,
    get_filesystem_document_storage_dependency,
    get_filesystem_document_upload_api_config,
    get_filesystem_document_upload_api_config_dependency,
    get_filesystem_document_upload_service,
    router as upload_router,
)
from app.api.ingestion import (
    get_ingestion_job_service,
    router as ingestion_router,
)
from app.ingestion.filesystem_document_storage import (
    DocumentStorageContentError,
    DocumentStorageFilenameError,
    DocumentStorageTooLargeError,
    DocumentStorageWriteError,
    FilesystemDocumentStorage,
    FilesystemDocumentStorageConfig,
)
from app.ingestion.filesystem_document_upload_service import (
    DocumentUploadRollbackError,
    DocumentUploadStorageError,
    DocumentUploadSubmissionError,
    FilesystemDocumentUploadService,
)
from app.ingestion.ingestion_job_models import (
    IngestionDocumentStatus,
    IngestionJobStatus,
    IngestionJobType,
    IngestionSourceType,
    IngestionStage,
)
from app.ingestion.ingestion_job_repository import IngestionJobRepository
from app.ingestion.ingestion_job_service import IngestionJobService


UPLOAD_API = "/api/v1/ingestion/uploads"
INGESTION_API = "/api/v1/ingestion"


@pytest.fixture(autouse=True)
def clear_upload_dependency_caches() -> Generator[None, None, None]:
    """Prevent process configuration caches leaking between tests."""

    get_filesystem_document_upload_api_config.cache_clear()
    get_filesystem_document_storage.cache_clear()

    try:
        yield
    finally:
        get_filesystem_document_upload_api_config.cache_clear()
        get_filesystem_document_storage.cache_clear()


@pytest.fixture
def api_config(tmp_path: Path) -> FilesystemDocumentUploadApiConfig:
    """Return small deterministic limits for API tests."""

    return FilesystemDocumentUploadApiConfig(
        storage_root_directory=tmp_path / "uploads",
        maximum_content_bytes=64,
        read_chunk_bytes=8,
        maximum_documents_per_job=3,
        default_maximum_attempts=4,
    )


@pytest.fixture
def storage(
    api_config: FilesystemDocumentUploadApiConfig,
) -> FilesystemDocumentStorage:
    """Return isolated guarded storage matching the API limits."""

    root = _prepare_storage_root(api_config.storage_root_directory)
    return FilesystemDocumentStorage(
        FilesystemDocumentStorageConfig(
            root_directory=root,
            maximum_content_bytes=api_config.maximum_content_bytes,
            read_chunk_bytes=api_config.read_chunk_bytes,
        )
    )


@pytest.fixture
def ingestion_service() -> IngestionJobService:
    """Return an isolated shared job lifecycle service."""

    return IngestionJobService(IngestionJobRepository())


@pytest.fixture
def app(
    api_config: FilesystemDocumentUploadApiConfig,
    storage: FilesystemDocumentStorage,
    ingestion_service: IngestionJobService,
) -> Generator[FastAPI, None, None]:
    """Compose upload and lifecycle routers with isolated dependencies."""

    application = FastAPI()
    application.include_router(ingestion_router, prefix="/api/v1")
    application.include_router(upload_router, prefix="/api/v1")
    application.dependency_overrides[
        get_ingestion_job_service
    ] = lambda: ingestion_service
    application.dependency_overrides[
        get_filesystem_document_storage_dependency
    ] = lambda: storage
    application.dependency_overrides[
        get_filesystem_document_upload_api_config_dependency
    ] = lambda: api_config

    try:
        yield application
    finally:
        application.dependency_overrides.clear()


@pytest.fixture
def client(app: FastAPI) -> Generator[TestClient, None, None]:
    """Return a client for the isolated composed API."""

    with TestClient(app) as test_client:
        yield test_client


def _multipart_files(
    *documents: tuple[str, bytes, str],
) -> list[tuple[str, tuple[str, bytes, str]]]:
    """Build repeated multipart file fields."""

    return [("files", document) for document in documents]


def _post_upload(
    client: TestClient,
    *,
    documents: tuple[tuple[str, bytes, str], ...] | None = None,
    data: dict[str, str] | None = None,
) -> Any:
    """Post one valid-by-default upload request."""

    resolved_documents = documents or (
        ("motor-manual.pdf", b"phase-six-pdf", "application/pdf"),
    )
    resolved_data = {"submitted_by": "upload-api-test"}

    if data:
        resolved_data.update(data)

    return client.post(
        UPLOAD_API,
        files=_multipart_files(*resolved_documents),
        data=resolved_data,
    )


def _stored_files(root: Path) -> list[Path]:
    """Return only persisted document files beneath storage."""

    return sorted(path for path in root.rglob("*") if path.is_file())


def _assert_no_side_effects(
    storage: FilesystemDocumentStorage,
    ingestion_service: IngestionJobService,
) -> None:
    """Assert validation left storage and the repository unchanged."""

    assert _stored_files(storage.root_directory) == []
    assert ingestion_service.statistics().total_jobs == 0


def _wrapped_storage_error(cause: Exception) -> DocumentUploadStorageError:
    """Build the transaction-layer wrapper used by production service."""

    error = DocumentUploadStorageError("safe test wrapper")
    error.__cause__ = cause
    return error


class _RaisingUploadService:
    """Minimal dependency double that raises one configured exception."""

    def __init__(self, error: Exception) -> None:
        self.error = error

    def submit_uploads(self, **_: Any) -> None:
        """Raise the configured failure."""

        raise self.error


def _error_client(error: Exception) -> TestClient:
    """Build a client whose upload service raises one error."""

    application = FastAPI()
    application.include_router(upload_router, prefix="/api/v1")
    application.dependency_overrides[
        get_filesystem_document_upload_service
    ] = lambda: _RaisingUploadService(error)
    return TestClient(application, raise_server_exceptions=False)


def test_single_upload_creates_pending_ingestion_job(
    client: TestClient,
) -> None:
    """A valid document becomes one pending API-upload job."""

    response = _post_upload(
        client,
        data={
            "correlation_id": "UPLOAD-001",
            "metadata_json": json.dumps({"site": "plant-a"}),
            "document_attributes_json": json.dumps(
                [{"manufacturer": "Example Motors"}]
            ),
        },
    )

    assert response.status_code == 201
    body = response.json()
    document = body["documents"][0]

    assert body["job_type"] == IngestionJobType.SINGLE_DOCUMENT.value
    assert body["source_type"] == IngestionSourceType.API_UPLOAD.value
    assert body["status"] == IngestionJobStatus.PENDING.value
    assert body["stage"] == IngestionStage.WAITING.value
    assert body["submitted_by"] == "upload-api-test"
    assert body["correlation_id"] == "UPLOAD-001"
    assert body["total_document_count"] == 1
    assert body["metadata"]["site"] == "plant-a"
    assert body["metadata"]["engineer4me_upload"] == {
        "storage_backend": "filesystem",
        "document_count": 1,
        "maximum_content_bytes": 64,
    }
    assert document["source_name"] == "motor-manual.pdf"
    assert document["media_type"] == "application/pdf"
    assert document["file_size_bytes"] == len(b"phase-six-pdf")
    assert document["checksum_sha256"] == hashlib.sha256(
        b"phase-six-pdf"
    ).hexdigest()
    assert document["status"] == IngestionDocumentStatus.PENDING.value
    assert document["maximum_attempts"] == 4
    assert document["attributes"]["manufacturer"] == "Example Motors"


def test_batch_upload_preserves_document_order_and_content(
    client: TestClient,
    storage: FilesystemDocumentStorage,
) -> None:
    """A multipart batch creates ordered opaque stored documents."""

    documents = (
        ("first.pdf", b"first-content", "application/pdf"),
        (
            "second.docx",
            b"second-content",
            (
                "application/vnd.openxmlformats-officedocument."
                "wordprocessingml.document"
            ),
        ),
    )
    response = _post_upload(
        client,
        documents=documents,
        data={
            "document_attributes_json": json.dumps(
                [{"order": 1}, {"order": 2}]
            )
        },
    )

    assert response.status_code == 201
    body = response.json()

    assert body["job_type"] == IngestionJobType.DOCUMENT_BATCH.value
    assert body["total_document_count"] == 2
    assert [item["source_name"] for item in body["documents"]] == [
        "first.pdf",
        "second.docx",
    ]
    assert [
        item["attributes"]["order"] for item in body["documents"]
    ] == [1, 2]

    for document, (_, expected_content, _) in zip(
        body["documents"],
        documents,
        strict=True,
    ):
        source_path = document["source_path"]
        stored_path = storage.root_directory / source_path

        assert not Path(source_path).is_absolute()
        assert ".." not in Path(source_path).parts
        assert stored_path.read_bytes() == expected_content


def test_upload_is_visible_through_shared_lifecycle_api(
    client: TestClient,
) -> None:
    """The upload route and lifecycle route use the same repository."""

    created = _post_upload(client).json()
    response = client.get(
        f"{INGESTION_API}/jobs/{created['job_id']}"
    )

    assert response.status_code == 200
    assert response.json() == created


def test_upload_updates_shared_statistics(
    client: TestClient,
) -> None:
    """Lifecycle statistics immediately include uploaded work."""

    _post_upload(
        client,
        documents=(
            ("one.pdf", b"one", "application/pdf"),
            ("two.xlsx", b"two", "application/vnd.ms-excel"),
        ),
    )
    response = client.get(f"{INGESTION_API}/statistics")

    assert response.status_code == 200
    body = response.json()
    assert body["total_jobs"] == 1
    assert body["total_documents"] == 2
    assert body["pending_jobs"] == 1


def test_uploaded_job_can_be_queued_through_lifecycle_api(
    client: TestClient,
) -> None:
    """Uploaded jobs participate in the existing lifecycle operations."""

    created = _post_upload(client).json()
    response = client.post(
        f"{INGESTION_API}/jobs/{created['job_id']}/queue"
    )

    assert response.status_code == 200
    assert response.json()["status"] == IngestionJobStatus.QUEUED.value


def test_explicit_maximum_attempts_applies_to_every_document(
    client: TestClient,
) -> None:
    """A bounded form override is copied to all batch documents."""

    response = _post_upload(
        client,
        documents=(
            ("one.pdf", b"one", "application/pdf"),
            ("two.pdf", b"two", "application/pdf"),
        ),
        data={"maximum_attempts": "7"},
    )

    assert response.status_code == 201
    assert [
        item["maximum_attempts"]
        for item in response.json()["documents"]
    ] == [7, 7]


def test_blank_optional_values_normalise_to_empty_metadata_and_no_trace(
    client: TestClient,
) -> None:
    """Whitespace-only optional form values use safe empty defaults."""

    response = _post_upload(
        client,
        data={
            "correlation_id": "   ",
            "metadata_json": "   ",
            "document_attributes_json": "   ",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["correlation_id"] is None
    assert set(body["metadata"]) == {"engineer4me_upload"}
    assert set(body["documents"][0]["attributes"]) == {
        "engineer4me_storage"
    }


def test_storage_sanitises_client_filename_to_final_component(
    client: TestClient,
) -> None:
    """Client path components never become server paths."""

    response = _post_upload(
        client,
        documents=(
            (
                "../../caller/path/manual.pdf",
                b"manual",
                "application/pdf",
            ),
        ),
    )

    assert response.status_code == 201
    document = response.json()["documents"][0]
    assert document["source_name"] == "manual.pdf"
    assert "caller" not in document["source_path"]
    assert "manual" not in document["source_path"]


def test_server_owned_metadata_replaces_spoofed_values(
    client: TestClient,
) -> None:
    """Authoritative storage metadata wins over caller JSON."""

    response = _post_upload(
        client,
        data={
            "metadata_json": json.dumps(
                {"engineer4me_upload": {"storage_backend": "attacker"}}
            ),
            "document_attributes_json": json.dumps(
                [{"engineer4me_storage": {"backend": "attacker"}}]
            ),
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["metadata"]["engineer4me_upload"][
        "storage_backend"
    ] == "filesystem"
    storage_metadata = body["documents"][0]["attributes"][
        "engineer4me_storage"
    ]
    assert storage_metadata["backend"] == "filesystem"
    assert UUID(storage_metadata["storage_id"])
    assert storage_metadata["stored_at"].endswith("+00:00")


def test_response_uses_opaque_server_owned_storage_reference(
    client: TestClient,
    storage: FilesystemDocumentStorage,
) -> None:
    """No absolute filesystem root is exposed to API callers."""

    response = _post_upload(client)
    source_path = response.json()["documents"][0]["source_path"]

    assert str(storage.root_directory) not in source_path
    assert len(source_path.split("/")) == 3
    assert (storage.root_directory / source_path).is_file()


@pytest.mark.parametrize(
    ("request_kwargs", "expected_status"),
    [
        (
            {
                "files": [],
                "data": {"submitted_by": "upload-api-test"},
            },
            422,
        ),
        (
            {
                "files": _multipart_files(
                    ("one.pdf", b"one", "application/pdf")
                ),
                "data": {},
            },
            422,
        ),
        (
            {
                "files": _multipart_files(
                    ("one.pdf", b"one", "application/pdf")
                ),
                "data": {"submitted_by": ""},
            },
            422,
        ),
        (
            {
                "files": _multipart_files(
                    ("one.pdf", b"one", "application/pdf")
                ),
                "data": {
                    "submitted_by": "upload-api-test",
                    "maximum_attempts": "0",
                },
            },
            422,
        ),
        (
            {
                "files": _multipart_files(
                    ("one.pdf", b"one", "application/pdf")
                ),
                "data": {
                    "submitted_by": "upload-api-test",
                    "maximum_attempts": "21",
                },
            },
            422,
        ),
        (
            {
                "files": _multipart_files(
                    ("one.pdf", b"one", "application/pdf")
                ),
                "data": {
                    "submitted_by": "upload-api-test",
                    "correlation_id": "x" * 256,
                },
            },
            422,
        ),
    ],
)
def test_fastapi_rejects_invalid_required_or_bounded_form_fields(
    client: TestClient,
    storage: FilesystemDocumentStorage,
    ingestion_service: IngestionJobService,
    request_kwargs: dict[str, Any],
    expected_status: int,
) -> None:
    """Framework-level form validation rejects invalid requests."""

    response = client.post(UPLOAD_API, **request_kwargs)

    assert response.status_code == expected_status
    _assert_no_side_effects(storage, ingestion_service)


def test_blank_submitter_is_rejected_before_storage(
    client: TestClient,
    storage: FilesystemDocumentStorage,
    ingestion_service: IngestionJobService,
) -> None:
    """Whitespace passes form length but fails service normalisation."""

    response = _post_upload(client, data={"submitted_by": "   "})

    assert response.status_code == 422
    assert response.json()["detail"] == "submitted_by cannot be blank."
    _assert_no_side_effects(storage, ingestion_service)


def test_too_many_documents_are_rejected_before_storage(
    client: TestClient,
    storage: FilesystemDocumentStorage,
    ingestion_service: IngestionJobService,
) -> None:
    """The configured batch limit is checked transactionally."""

    response = _post_upload(
        client,
        documents=tuple(
            (
                f"{index}.pdf",
                f"content-{index}".encode(),
                "application/pdf",
            )
            for index in range(4)
        ),
    )

    assert response.status_code == 422
    assert "configured 3 documents" in response.json()["detail"]
    _assert_no_side_effects(storage, ingestion_service)


@pytest.mark.parametrize(
    ("filename", "content", "expected_status"),
    [
        ("unsupported.exe", b"content", 422),
        ("empty.pdf", b"", 422),
        ("large.pdf", b"x" * 65, 413),
        ("/", b"content", 422),
    ],
)
def test_storage_rejections_are_safely_mapped_and_rolled_back(
    client: TestClient,
    storage: FilesystemDocumentStorage,
    ingestion_service: IngestionJobService,
    filename: str,
    content: bytes,
    expected_status: int,
) -> None:
    """Invalid filename/content failures reveal no storage internals."""

    response = _post_upload(
        client,
        documents=((filename, content, "application/pdf"),),
    )

    assert response.status_code == expected_status
    detail = response.json()["detail"]
    assert str(storage.root_directory) not in detail
    assert "checksum" not in detail.lower()
    _assert_no_side_effects(storage, ingestion_service)


@pytest.mark.parametrize(
    "metadata_json",
    [
        "{",
        "[]",
        "null",
        "NaN",
        "Infinity",
        "-Infinity",
        '{"value": NaN}',
        "1" * 5_000,
        "[" * 1_100 + "0" + "]" * 1_100,
    ],
)
def test_invalid_job_metadata_is_rejected_without_side_effects(
    client: TestClient,
    storage: FilesystemDocumentStorage,
    ingestion_service: IngestionJobService,
    metadata_json: str,
) -> None:
    """Malformed, non-object, and unsafe JSON never reaches storage."""

    response = _post_upload(
        client,
        data={"metadata_json": metadata_json},
    )

    assert response.status_code == 422
    _assert_no_side_effects(storage, ingestion_service)


@pytest.mark.parametrize(
    "attributes_json",
    [
        "{}",
        "null",
        "NaN",
        "[",
        "[]",
        '[{"first": true}, {"second": true}]',
        "[1]",
        '["not-an-object"]',
        "1" * 5_000,
        "[" * 1_100 + "0" + "]" * 1_100,
    ],
)
def test_invalid_document_attributes_are_rejected_without_side_effects(
    client: TestClient,
    storage: FilesystemDocumentStorage,
    ingestion_service: IngestionJobService,
    attributes_json: str,
) -> None:
    """Attributes must be one strict object per multipart document."""

    response = _post_upload(
        client,
        data={"document_attributes_json": attributes_json},
    )

    assert response.status_code == 422
    _assert_no_side_effects(storage, ingestion_service)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("metadata_json", "x" * (64 * 1024 + 1)),
        (
            "document_attributes_json",
            "x" * (256 * 1024 + 1),
        ),
    ],
)
def test_json_form_character_limits_are_enforced(
    client: TestClient,
    storage: FilesystemDocumentStorage,
    ingestion_service: IngestionJobService,
    field_name: str,
    value: str,
) -> None:
    """Oversized metadata form fields are rejected before decoding."""

    response = _post_upload(client, data={field_name: value})

    assert response.status_code == 422
    _assert_no_side_effects(storage, ingestion_service)


@pytest.mark.parametrize(
    ("error", "status_code", "detail"),
    [
        (
            _wrapped_storage_error(
                DocumentStorageTooLargeError("private limit")
            ),
            413,
            (
                "One or more uploaded documents exceed the configured "
                "content-size limit."
            ),
        ),
        (
            _wrapped_storage_error(
                DocumentStorageFilenameError("private path")
            ),
            422,
            (
                "One or more uploaded documents could not be accepted "
                "within the configured storage rules."
            ),
        ),
        (
            _wrapped_storage_error(
                DocumentStorageContentError("private content")
            ),
            422,
            (
                "One or more uploaded documents could not be accepted "
                "within the configured storage rules."
            ),
        ),
        (
            _wrapped_storage_error(
                DocumentStorageWriteError("private disk path")
            ),
            503,
            "Document upload storage is unavailable.",
        ),
        (
            DocumentUploadSubmissionError("private repository error"),
            503,
            (
                "The uploaded documents could not be registered for "
                "processing."
            ),
        ),
    ],
)
def test_transaction_failures_map_to_safe_http_responses(
    error: Exception,
    status_code: int,
    detail: str,
) -> None:
    """Known transaction failures return stable non-sensitive details."""

    with _error_client(error) as client:
        response = _post_upload(client)

    assert response.status_code == status_code
    assert response.json() == {"detail": detail}
    assert "private" not in response.text


def test_rollback_failure_maps_to_reconciliation_response(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Rollback failures return 500 while logging only safe type data."""

    error = DocumentUploadRollbackError(
        primary_error=RuntimeError("private primary"),
        rollback_errors=(OSError("private rollback"),),
        stored_document_count=1,
    )

    with _error_client(error) as client:
        response = _post_upload(client)

    assert response.status_code == 500
    assert response.json() == {
        "detail": (
            "The upload transaction failed and requires storage "
            "reconciliation."
        )
    }
    assert "private primary" not in caplog.text
    assert "private rollback" not in caplog.text
    assert "RuntimeError" in caplog.text
    assert "OSError" in caplog.text


def test_unexpected_programmer_error_is_not_disguised_as_422() -> None:
    """Unknown exceptions remain internal server failures."""

    with _error_client(TypeError("private programming bug")) as client:
        response = _post_upload(client)

    assert response.status_code == 500
    assert "private programming bug" not in response.text


@pytest.mark.parametrize(
    ("field_name", "value", "exception_type"),
    [
        ("storage_root_directory", object(), TypeError),
        ("storage_root_directory", "", ValueError),
        ("storage_root_directory", "relative/path", ValueError),
        ("maximum_content_bytes", True, TypeError),
        ("maximum_content_bytes", "64", TypeError),
        ("maximum_content_bytes", 0, ValueError),
        ("read_chunk_bytes", True, TypeError),
        ("read_chunk_bytes", 0, ValueError),
        ("read_chunk_bytes", 65, ValueError),
        ("maximum_documents_per_job", True, TypeError),
        ("maximum_documents_per_job", 0, ValueError),
        ("maximum_documents_per_job", 1_001, ValueError),
        ("default_maximum_attempts", True, TypeError),
        ("default_maximum_attempts", 0, ValueError),
        ("default_maximum_attempts", 21, ValueError),
    ],
)
def test_api_config_rejects_invalid_values(
    tmp_path: Path,
    field_name: str,
    value: Any,
    exception_type: type[Exception],
) -> None:
    """Trusted composition values must satisfy model bounds."""

    values: dict[str, Any] = {
        "storage_root_directory": tmp_path / "uploads",
        "maximum_content_bytes": 64,
        "read_chunk_bytes": 8,
        "maximum_documents_per_job": 3,
        "default_maximum_attempts": 4,
    }
    values[field_name] = value

    with pytest.raises(exception_type):
        FilesystemDocumentUploadApiConfig(**values)


def test_api_config_is_canonical_and_frozen(tmp_path: Path) -> None:
    """Configuration normalises its root and cannot be mutated."""

    config = FilesystemDocumentUploadApiConfig(
        storage_root_directory=str(tmp_path / "uploads")
    )

    assert config.storage_root_directory == tmp_path / "uploads"

    with pytest.raises(FrozenInstanceError):
        config.maximum_content_bytes = 1  # type: ignore[misc]


def test_environment_defaults_are_complete() -> None:
    """An empty environment uses documented production defaults."""

    config = FilesystemDocumentUploadApiConfig.from_environment({})

    assert config.storage_root_directory == Path(
        "/var/lib/engineer4me/uploads"
    )
    assert config.maximum_content_bytes == 25 * 1024 * 1024
    assert config.read_chunk_bytes == 64 * 1024
    assert config.maximum_documents_per_job == 20
    assert config.default_maximum_attempts == 3


def test_environment_overrides_are_parsed_strictly(
    tmp_path: Path,
) -> None:
    """All supported environment settings compose one config."""

    config = FilesystemDocumentUploadApiConfig.from_environment(
        {
            "ENGINEER4ME_UPLOAD_ROOT": str(tmp_path / "root"),
            "ENGINEER4ME_UPLOAD_MAXIMUM_CONTENT_BYTES": "4096",
            "ENGINEER4ME_UPLOAD_READ_CHUNK_BYTES": "512",
            "ENGINEER4ME_UPLOAD_MAXIMUM_DOCUMENTS_PER_JOB": "7",
            "ENGINEER4ME_UPLOAD_DEFAULT_MAXIMUM_ATTEMPTS": "6",
        }
    )

    assert config.storage_root_directory == tmp_path / "root"
    assert config.maximum_content_bytes == 4096
    assert config.read_chunk_bytes == 512
    assert config.maximum_documents_per_job == 7
    assert config.default_maximum_attempts == 6


@pytest.mark.parametrize(
    "environment",
    [
        {"ENGINEER4ME_UPLOAD_ROOT": 3},
        {"ENGINEER4ME_UPLOAD_ROOT": ""},
        {"ENGINEER4ME_UPLOAD_ROOT": "relative"},
        {"ENGINEER4ME_UPLOAD_MAXIMUM_CONTENT_BYTES": ""},
        {"ENGINEER4ME_UPLOAD_MAXIMUM_CONTENT_BYTES": "abc"},
        {"ENGINEER4ME_UPLOAD_MAXIMUM_CONTENT_BYTES": "0"},
        {"ENGINEER4ME_UPLOAD_MAXIMUM_CONTENT_BYTES": 64},
        {"ENGINEER4ME_UPLOAD_READ_CHUNK_BYTES": "0"},
        {"ENGINEER4ME_UPLOAD_MAXIMUM_DOCUMENTS_PER_JOB": "1001"},
        {"ENGINEER4ME_UPLOAD_DEFAULT_MAXIMUM_ATTEMPTS": "21"},
    ],
)
def test_environment_rejects_invalid_values(
    environment: dict[str, Any],
) -> None:
    """Malformed trusted environment values fail closed."""

    with pytest.raises(
        (
            FilesystemDocumentUploadApiConfigurationError,
            TypeError,
            ValueError,
        )
    ):
        FilesystemDocumentUploadApiConfig.from_environment(environment)


def test_environment_argument_must_be_mapping() -> None:
    """The explicit environment seam rejects non-mappings."""

    with pytest.raises(TypeError, match="environment must be a mapping"):
        FilesystemDocumentUploadApiConfig.from_environment(
            []  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("raw_value", "exception_type"),
    [
        ("", FilesystemDocumentUploadApiConfigurationError),
        ("abc", FilesystemDocumentUploadApiConfigurationError),
        ("0", FilesystemDocumentUploadApiConfigurationError),
        (True, FilesystemDocumentUploadApiConfigurationError),
    ],
)
def test_environment_integer_helper_rejects_invalid_values(
    raw_value: Any,
    exception_type: type[Exception],
) -> None:
    """The low-level environment reader accepts only bounded strings."""

    with pytest.raises(exception_type):
        _read_environment_integer(
            {"LIMIT": raw_value},
            name="LIMIT",
            default=8,
            minimum=1,
            maximum=10,
        )


def test_environment_integer_helper_uses_default_and_bounds() -> None:
    """Missing values use defaults and valid strings are converted."""

    assert (
        _read_environment_integer(
            {},
            name="LIMIT",
            default=8,
            minimum=1,
            maximum=10,
        )
        == 8
    )
    assert (
        _read_environment_integer(
            {"LIMIT": " 9 "},
            name="LIMIT",
            default=8,
            minimum=1,
            maximum=10,
        )
        == 9
    )


def test_config_dependency_is_cached(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Environment configuration is composed only once per process."""

    monkeypatch.setenv("ENGINEER4ME_UPLOAD_ROOT", str(tmp_path / "one"))
    first = get_filesystem_document_upload_api_config()
    monkeypatch.setenv("ENGINEER4ME_UPLOAD_ROOT", str(tmp_path / "two"))
    second = get_filesystem_document_upload_api_config()

    assert second is first
    assert second.storage_root_directory == tmp_path / "one"


def test_storage_dependency_creates_private_cached_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Production composition creates one private guarded adapter."""

    root = tmp_path / "nested" / "uploads"
    monkeypatch.setenv("ENGINEER4ME_UPLOAD_ROOT", str(root))
    monkeypatch.setenv(
        "ENGINEER4ME_UPLOAD_MAXIMUM_CONTENT_BYTES",
        "128",
    )
    monkeypatch.setenv(
        "ENGINEER4ME_UPLOAD_READ_CHUNK_BYTES",
        "16",
    )

    first = get_filesystem_document_storage()
    second = get_filesystem_document_storage()

    assert first is second
    assert first.root_directory == root.resolve()
    assert first.config.maximum_content_bytes == 128
    assert first.config.read_chunk_bytes == 16
    assert root.is_dir()

    if os.name == "posix":
        assert stat.S_IMODE(root.stat().st_mode) == 0o700


def test_prepare_storage_root_rejects_existing_file(
    tmp_path: Path,
) -> None:
    """The configured upload root must be a real directory."""

    root = tmp_path / "not-a-directory"
    root.write_text("file", encoding="utf-8")

    with pytest.raises(
        FilesystemDocumentUploadApiConfigurationError
    ):
        _prepare_storage_root(root)


def test_prepare_storage_root_rejects_symbolic_link(
    tmp_path: Path,
) -> None:
    """A symbolic-link upload root is rejected before storage."""

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"

    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic links are unavailable on this platform.")

    with pytest.raises(
        FilesystemDocumentUploadApiConfigurationError
    ):
        _prepare_storage_root(link)


def test_config_dependency_wrapper_returns_safe_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid cached environment configuration becomes HTTP 503."""

    def raise_configuration_error() -> None:
        raise FilesystemDocumentUploadApiConfigurationError("private")

    monkeypatch.setattr(
        (
            "app.api.filesystem_document_upload_api."
            "get_filesystem_document_upload_api_config"
        ),
        raise_configuration_error,
    )

    with pytest.raises(HTTPException) as captured:
        get_filesystem_document_upload_api_config_dependency()

    assert captured.value.status_code == 503
    assert captured.value.detail == (
        "Document upload storage is unavailable."
    )


def test_storage_dependency_wrapper_returns_safe_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unavailable storage composition becomes HTTP 503."""

    def raise_configuration_error() -> None:
        raise FilesystemDocumentUploadApiConfigurationError("private")

    monkeypatch.setattr(
        (
            "app.api.filesystem_document_upload_api."
            "get_filesystem_document_storage"
        ),
        raise_configuration_error,
    )

    with pytest.raises(HTTPException) as captured:
        get_filesystem_document_storage_dependency()

    assert captured.value.status_code == 503
    assert captured.value.detail == (
        "Document upload storage is unavailable."
    )


def test_service_dependency_composes_exact_dependencies(
    api_config: FilesystemDocumentUploadApiConfig,
    storage: FilesystemDocumentStorage,
    ingestion_service: IngestionJobService,
) -> None:
    """HTTP composition passes shared dependencies and configured limits."""

    service = get_filesystem_document_upload_service(
        storage=storage,
        job_service=ingestion_service,
        api_config=api_config,
    )

    assert isinstance(service, FilesystemDocumentUploadService)
    assert service.storage is storage
    assert service.job_service is ingestion_service
    assert service.config.maximum_documents_per_job == 3
    assert service.config.default_maximum_attempts == 4


def test_json_mapping_helper_returns_detached_empty_defaults() -> None:
    """Absent JSON metadata produces independent dictionaries."""

    first = _decode_json_mapping(None, label="metadata_json")
    second = _decode_json_mapping(" ", label="metadata_json")

    assert first == {}
    assert second == {}
    assert first is not second


def test_document_attributes_helper_returns_one_mapping_per_file() -> None:
    """Absent per-document metadata creates independent mappings."""

    values = _decode_document_attributes(None, expected_count=2)

    assert values == ({}, {})
    assert values[0] is not values[1]


@pytest.mark.parametrize("expected_count", [True, -1, 1.5, "1"])
def test_document_attributes_helper_rejects_invalid_count(
    expected_count: Any,
) -> None:
    """Internal expected-count misuse remains a programmer error."""

    with pytest.raises(ValueError):
        _decode_document_attributes(
            None,
            expected_count=expected_count,
        )


def test_request_error_is_a_value_error() -> None:
    """The boundary request error retains its public exception hierarchy."""

    assert issubclass(DocumentUploadRequestError, ValueError)


def test_upload_route_openapi_contract(app: FastAPI) -> None:
    """OpenAPI advertises multipart input and all stable response classes."""

    operation = app.openapi()["paths"][UPLOAD_API]["post"]

    assert operation["summary"] == (
        "Upload documents and create an ingestion job"
    )
    assert "multipart/form-data" in operation["requestBody"]["content"]
    assert set(operation["responses"]) >= {
        "201",
        "413",
        "422",
        "500",
        "503",
    }
    assert operation["tags"] == ["Document Ingestion"]


def test_router_contains_only_upload_endpoint() -> None:
    """The isolated router adds exactly one multipart endpoint."""

    route_paths = [
        route.path
        for route in upload_router.routes
        if hasattr(route, "methods")
    ]

    assert route_paths == ["/ingestion/uploads"]
    assert upload_router.routes[0].methods == {"POST"}
