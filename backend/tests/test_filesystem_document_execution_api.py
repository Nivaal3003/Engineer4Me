"""Tests for the filesystem-backed ingestion execution API."""

from __future__ import annotations

from collections.abc import Generator
from io import BytesIO
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.api import filesystem_document_execution_api as execution_api
from app.api.filesystem_document_execution_api import (
    FilesystemDocumentExecutionApiConfigurationError,
    _raise_execution_api_error,
    execute_filesystem_ingestion_job,
    get_filesystem_document_execution_service,
    get_filesystem_document_execution_service_dependency,
    router as execution_router,
)
from app.api.filesystem_document_upload_api import (
    FilesystemDocumentUploadApiConfigurationError,
)
from app.ingestion.filesystem_document_execution_service import (
    FilesystemDocumentExecutionConflictError,
    FilesystemDocumentExecutionEligibilityError,
    FilesystemDocumentExecutionService,
    FilesystemDocumentExecutionStateError,
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
    IngestionJobType,
    IngestionSourceType,
    InvalidIngestionJobTransitionError,
)
from app.ingestion.ingestion_job_repository import (
    IngestionJobConflictError,
    IngestionJobNotFoundError,
    IngestionJobRepositoryError,
)
from app.ingestion.ingestion_job_service import (
    IngestionJobService,
    IngestionJobServiceError,
)


EXECUTION_API = "/api/v1/ingestion/jobs/{job_id}/execute"
MAXIMUM_CONTENT_BYTES = 32 * 1024
DOCUMENT_CONTENT = (
    b"Maximum operating pressure is 16 bar. "
    b"Temperature range is -20 to 80 degrees C."
)


class StubExecutionService:
    """Minimal dependency override recording one route invocation."""

    def __init__(
        self,
        *,
        result: IngestionJob | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.job_ids: list[UUID] = []

    def process_job(self, job_id: UUID) -> IngestionJob:
        self.job_ids.append(job_id)

        if self.error is not None:
            raise self.error

        if self.result is None:
            raise AssertionError("Stub execution result was not configured.")

        return self.result


@pytest.fixture(autouse=True)
def clear_execution_service_cache() -> Generator[None, None, None]:
    """Prevent the process-wide execution coordinator leaking across tests."""

    get_filesystem_document_execution_service.cache_clear()

    try:
        yield
    finally:
        get_filesystem_document_execution_service.cache_clear()


@pytest.fixture
def storage_root(tmp_path: Path) -> Path:
    """Return one isolated existing filesystem upload root."""

    root = tmp_path / "uploads"
    root.mkdir()
    return root


@pytest.fixture
def storage(
    storage_root: Path,
) -> FilesystemDocumentStorage:
    """Return guarded storage with a small deterministic content bound."""

    return FilesystemDocumentStorage(
        FilesystemDocumentStorageConfig(
            root_directory=storage_root,
            maximum_content_bytes=MAXIMUM_CONTENT_BYTES,
            read_chunk_bytes=1024,
        )
    )


@pytest.fixture
def job_service() -> IngestionJobService:
    """Return one isolated in-memory ingestion lifecycle service."""

    return IngestionJobService()


@pytest.fixture
def upload_service(
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> FilesystemDocumentUploadService:
    """Return transactional upload composition for valid route jobs."""

    return FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
    )


def submit_upload(
    service: FilesystemDocumentUploadService,
    *,
    filename: str = "pressure-transmitter.txt",
    content: bytes = DOCUMENT_CONTENT,
) -> IngestionJob:
    """Persist and register one authoritative filesystem upload."""

    return service.submit_upload(
        upload=FilesystemDocumentUpload(
            filename=filename,
            stream=BytesIO(content),
            media_type="text/plain",
        ),
        submitted_by="execution-api-test",
    )


def simple_job() -> IngestionJob:
    """Return one valid response-model job for dependency-override tests."""

    return IngestionJob(
        job_type=IngestionJobType.SINGLE_DOCUMENT,
        source_type=IngestionSourceType.API_UPLOAD,
        submitted_by="execution-api-stub",
        documents=[
            IngestionDocumentResult(
                source_name="stub.txt",
                media_type="text/plain",
                file_size_bytes=4,
                checksum_sha256="0" * 64,
            )
        ],
        total_document_count=1,
    )


def build_application(
    service: Any,
    *,
    raise_server_exceptions: bool = True,
) -> tuple[FastAPI, TestClient]:
    """Build one isolated API with an overridden execution dependency."""

    application = FastAPI()
    application.include_router(
        execution_router,
        prefix="/api/v1",
    )
    application.dependency_overrides[
        get_filesystem_document_execution_service_dependency
    ] = lambda: service

    return application, TestClient(
        application,
        raise_server_exceptions=raise_server_exceptions,
    )


def configure_real_execution_service(
    monkeypatch: pytest.MonkeyPatch,
    *,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> FilesystemDocumentExecutionService:
    """Compose the production cached service from isolated dependencies."""

    monkeypatch.setattr(
        execution_api,
        "get_filesystem_document_storage",
        lambda: storage,
    )
    monkeypatch.setattr(
        execution_api,
        "get_ingestion_job_service",
        lambda: job_service,
    )
    get_filesystem_document_execution_service.cache_clear()
    return get_filesystem_document_execution_service()


def test_configuration_error_is_runtime_error() -> None:
    assert issubclass(
        FilesystemDocumentExecutionApiConfigurationError,
        RuntimeError,
    )


def test_router_exposes_exact_execution_path() -> None:
    assert [route.path for route in execution_router.routes] == [
        "/ingestion/jobs/{job_id}/execute"
    ]


def test_router_uses_post_only() -> None:
    route = execution_router.routes[0]

    assert route.methods == {"POST"}


def test_router_response_model_is_ingestion_job() -> None:
    route = execution_router.routes[0]

    assert route.response_model is IngestionJob


def test_router_summary_is_stable() -> None:
    route = execution_router.routes[0]

    assert route.summary == "Execute a filesystem-backed ingestion job"


def test_router_documents_expected_error_statuses() -> None:
    route = execution_router.routes[0]

    assert set(route.responses) == {404, 409, 422, 503}


def test_factory_composes_execution_service(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    service = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )

    assert isinstance(service, FilesystemDocumentExecutionService)
    assert service.runtime.job_service is job_service
    assert not service.active_job_ids


def test_factory_uses_storage_root(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    service = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )

    assert (
        service.runtime.content_loader.root_directory
        == storage.root_directory
    )


def test_factory_aligns_content_loader_limit(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    service = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )

    assert (
        service.runtime.content_loader.config.maximum_content_bytes
        == MAXIMUM_CONTENT_BYTES
    )


def test_factory_aligns_pdf_office_limit(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    service = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )

    assert (
        service.runtime.document_parser.config.maximum_document_bytes
        == MAXIMUM_CONTENT_BYTES
    )


def test_factory_aligns_ocr_image_limit(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    service = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )

    assert (
        service.runtime.document_parser.config
        .fallback_parser.maximum_image_bytes
        == MAXIMUM_CONTENT_BYTES
    )


def test_factory_aligns_native_parser_limit(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    service = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )

    assert (
        service.runtime.document_parser.config
        .fallback_parser.standard_parser.max_document_size_bytes
        == MAXIMUM_CONTENT_BYTES
    )


def test_factory_returns_process_wide_cached_service(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    first = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )
    second = get_filesystem_document_execution_service()

    assert second is first
    assert (
        get_filesystem_document_execution_service.cache_info().currsize
        == 1
    )


def test_cache_clear_rebuilds_execution_service(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    first = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )
    get_filesystem_document_execution_service.cache_clear()
    second = get_filesystem_document_execution_service()

    assert second is not first
    assert second.runtime.job_service is job_service


def test_factory_wraps_upload_configuration_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cause = FilesystemDocumentUploadApiConfigurationError(
        "private storage path"
    )

    def fail() -> None:
        raise cause

    monkeypatch.setattr(
        execution_api,
        "get_filesystem_document_storage",
        fail,
    )

    with pytest.raises(
        FilesystemDocumentExecutionApiConfigurationError
    ) as captured:
        get_filesystem_document_execution_service()

    assert captured.value.__cause__ is cause
    assert "private storage path" not in str(captured.value)


@pytest.mark.parametrize(
    "error",
    [
        OSError("private operating-system detail"),
        ValueError("private invalid configuration detail"),
    ],
)
def test_factory_wraps_expected_composition_failures(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    def fail() -> None:
        raise error

    monkeypatch.setattr(
        execution_api,
        "get_filesystem_document_storage",
        fail,
    )

    with pytest.raises(
        FilesystemDocumentExecutionApiConfigurationError
    ) as captured:
        get_filesystem_document_execution_service()

    assert captured.value.__cause__ is error
    assert str(error) not in str(captured.value)


def test_factory_preserves_programmer_type_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = TypeError("programmer dependency contract failed")

    def fail() -> None:
        raise error

    monkeypatch.setattr(
        execution_api,
        "get_filesystem_document_storage",
        fail,
    )

    with pytest.raises(TypeError) as captured:
        get_filesystem_document_execution_service()

    assert captured.value is error


def test_factory_preserves_unexpected_attribute_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = SimpleNamespace(config=object())

    monkeypatch.setattr(
        execution_api,
        "get_filesystem_document_storage",
        lambda: storage,
    )

    with pytest.raises(AttributeError):
        get_filesystem_document_execution_service()


def test_dependency_returns_cached_service(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    expected = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )

    assert (
        get_filesystem_document_execution_service_dependency()
        is expected
    )


def test_dependency_maps_configuration_failure_to_safe_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail() -> None:
        raise FilesystemDocumentExecutionApiConfigurationError(
            "private root"
        )

    monkeypatch.setattr(
        execution_api,
        "get_filesystem_document_execution_service",
        fail,
    )

    with pytest.raises(HTTPException) as captured:
        get_filesystem_document_execution_service_dependency()

    assert captured.value.status_code == 503
    assert captured.value.detail == "Document processing is unavailable."
    assert "private root" not in str(captured.value.detail)


def test_dependency_preserves_programmer_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = RuntimeError("programmer failure")

    def fail() -> None:
        raise error

    monkeypatch.setattr(
        execution_api,
        "get_filesystem_document_execution_service",
        fail,
    )

    with pytest.raises(RuntimeError) as captured:
        get_filesystem_document_execution_service_dependency()

    assert captured.value is error


def test_route_returns_execution_result() -> None:
    job = simple_job()
    service = StubExecutionService(result=job)
    _, client = build_application(service)

    response = client.post(
        EXECUTION_API.format(job_id=job.job_id),
    )

    assert response.status_code == 200
    assert response.json()["job_id"] == str(job.job_id)
    assert service.job_ids == [job.job_id]


def test_route_accepts_canonical_uppercase_uuid_text() -> None:
    job = simple_job()
    service = StubExecutionService(result=job)
    _, client = build_application(service)

    response = client.post(
        EXECUTION_API.format(job_id=str(job.job_id).upper()),
    )

    assert response.status_code == 200
    assert service.job_ids == [job.job_id]


@pytest.mark.parametrize(
    "job_id",
    [
        "not-a-uuid",
        "123",
        "00000000-0000-0000-0000-00000000000z",
    ],
)
def test_route_rejects_invalid_uuid_before_service(
    job_id: str,
) -> None:
    service = StubExecutionService(result=simple_job())
    _, client = build_application(service)

    response = client.post(
        EXECUTION_API.format(job_id=job_id),
    )

    assert response.status_code == 422
    assert service.job_ids == []


def test_route_rejects_get_method() -> None:
    job = simple_job()
    service = StubExecutionService(result=job)
    _, client = build_application(service)

    response = client.get(
        EXECUTION_API.format(job_id=job.job_id),
    )

    assert response.status_code == 405
    assert service.job_ids == []


def test_route_rejects_delete_method() -> None:
    job = simple_job()
    service = StubExecutionService(result=job)
    _, client = build_application(service)

    response = client.delete(
        EXECUTION_API.format(job_id=job.job_id),
    )

    assert response.status_code == 405
    assert service.job_ids == []


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_detail"),
    [
        (
            IngestionJobNotFoundError("private missing detail"),
            404,
            "The requested ingestion job was not found.",
        ),
        (
            FilesystemDocumentExecutionEligibilityError(
                "private metadata detail"
            ),
            422,
            (
                "The ingestion job is not eligible for filesystem "
                "document processing."
            ),
        ),
        (
            FilesystemDocumentExecutionConflictError(
                "private lease detail"
            ),
            409,
            "The ingestion job is already being processed.",
        ),
        (
            FilesystemDocumentExecutionStateError(
                "private runtime state"
            ),
            409,
            (
                "The ingestion job cannot be processed safely from "
                "its current state."
            ),
        ),
        (
            IngestionJobConflictError("private repository conflict"),
            409,
            (
                "The ingestion job cannot be processed safely from "
                "its current state."
            ),
        ),
        (
            InvalidIngestionJobTransitionError(
                "private transition detail"
            ),
            409,
            (
                "The ingestion job cannot be processed safely from "
                "its current state."
            ),
        ),
        (
            IngestionJobRepositoryError("private repository failure"),
            503,
            "Document processing is unavailable.",
        ),
        (
            IngestionJobServiceError("private lifecycle failure"),
            503,
            "Document processing is unavailable.",
        ),
    ],
)
def test_route_maps_expected_errors_without_private_details(
    error: Exception,
    expected_status: int,
    expected_detail: str,
) -> None:
    job_id = uuid4()
    service = StubExecutionService(error=error)
    _, client = build_application(service)

    response = client.post(
        EXECUTION_API.format(job_id=job_id),
    )

    assert response.status_code == expected_status
    assert response.json() == {"detail": expected_detail}
    assert str(error) not in response.text
    assert service.job_ids == [job_id]


def test_not_found_mapping_precedes_repository_mapping() -> None:
    error = IngestionJobNotFoundError("private")

    with pytest.raises(HTTPException) as captured:
        _raise_execution_api_error(error)

    assert captured.value.status_code == 404


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("programmer runtime failure"),
        TypeError("programmer type failure"),
        AssertionError("programmer assertion failure"),
    ],
)
def test_error_mapper_preserves_unexpected_failures(
    error: Exception,
) -> None:
    with pytest.raises(type(error)) as captured:
        _raise_execution_api_error(error)

    assert captured.value is error


def test_route_preserves_programmer_failure() -> None:
    error = RuntimeError("programmer route failure")
    service = StubExecutionService(error=error)
    _, client = build_application(service)

    with pytest.raises(RuntimeError) as captured:
        client.post(
            EXECUTION_API.format(job_id=uuid4()),
        )

    assert captured.value is error


def test_route_returns_generic_500_when_server_exceptions_disabled(
) -> None:
    service = StubExecutionService(
        error=RuntimeError("private programmer failure")
    )
    _, client = build_application(
        service,
        raise_server_exceptions=False,
    )

    response = client.post(
        EXECUTION_API.format(job_id=uuid4()),
    )

    assert response.status_code == 500
    assert "private programmer failure" not in response.text


def test_openapi_contains_execution_operation() -> None:
    application, _ = build_application(
        StubExecutionService(result=simple_job())
    )

    operation = application.openapi()["paths"][
        "/api/v1/ingestion/jobs/{job_id}/execute"
    ]["post"]

    assert operation["summary"] == (
        "Execute a filesystem-backed ingestion job"
    )
    assert operation["tags"] == ["Document Ingestion"]


def test_openapi_declares_ingestion_job_response() -> None:
    application, _ = build_application(
        StubExecutionService(result=simple_job())
    )

    operation = application.openapi()["paths"][
        "/api/v1/ingestion/jobs/{job_id}/execute"
    ]["post"]
    response_schema = operation["responses"]["200"]["content"][
        "application/json"
    ]["schema"]

    assert response_schema["$ref"].endswith("/IngestionJob")


def test_execute_function_delegates_exact_uuid() -> None:
    job = simple_job()
    service = StubExecutionService(result=job)

    returned = execute_filesystem_ingestion_job(
        job_id=job.job_id,
        service=service,  # type: ignore[arg-type]
    )

    assert returned is job
    assert service.job_ids == [job.job_id]


def test_real_route_executes_pending_upload_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    job = submit_upload(upload_service)
    service = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )
    _, client = build_application(service)

    response = client.post(
        EXECUTION_API.format(job_id=job.job_id),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["job_id"] == str(job.job_id)
    assert payload["status"] == IngestionJobStatus.COMPLETED
    assert payload["completed_document_count"] == 1
    assert payload["failed_document_count"] == 0


def test_real_route_executes_queued_upload_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    job = submit_upload(upload_service)
    job_service.queue(job.job_id)
    service = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )
    _, client = build_application(service)

    response = client.post(
        EXECUTION_API.format(job_id=job.job_id),
    )

    assert response.status_code == 200
    assert response.json()["status"] == IngestionJobStatus.COMPLETED


def test_real_route_replays_terminal_job_idempotently(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    job = submit_upload(upload_service)
    service = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )
    _, client = build_application(service)
    path = EXECUTION_API.format(job_id=job.job_id)

    first = client.post(path)
    second = client.post(path)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()
    assert second.json()["status"] == IngestionJobStatus.COMPLETED


def test_real_route_maps_unknown_job_to_404(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    service = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )
    _, client = build_application(service)

    response = client.post(
        EXECUTION_API.format(job_id=uuid4()),
    )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "The requested ingestion job was not found."
    }


def test_real_route_rejects_non_filesystem_job(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
) -> None:
    job = simple_job()
    job_service.submit(job)
    service = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )
    _, client = build_application(service)

    response = client.post(
        EXECUTION_API.format(job_id=job.job_id),
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": (
            "The ingestion job is not eligible for filesystem "
            "document processing."
        )
    }


def test_real_route_returns_controlled_failed_job_when_file_missing(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    job = submit_upload(upload_service)
    reference = job.documents[0].source_path or ""
    source = storage.root_directory.joinpath(
        *PurePosixPath(reference).parts
    )
    source.unlink()
    service = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )
    _, client = build_application(service)

    response = client.post(
        EXECUTION_API.format(job_id=job.job_id),
    )

    assert response.status_code == 200
    assert response.json()["status"] == IngestionJobStatus.FAILED
    assert response.json()["failed_document_count"] == 1


def test_real_route_returns_controlled_failed_job_when_content_changed(
    monkeypatch: pytest.MonkeyPatch,
    storage: FilesystemDocumentStorage,
    job_service: IngestionJobService,
    upload_service: FilesystemDocumentUploadService,
) -> None:
    job = submit_upload(upload_service)
    reference = job.documents[0].source_path or ""
    source = storage.root_directory.joinpath(
        *PurePosixPath(reference).parts
    )
    source.write_bytes(b"altered content")
    service = configure_real_execution_service(
        monkeypatch,
        storage=storage,
        job_service=job_service,
    )
    _, client = build_application(service)

    response = client.post(
        EXECUTION_API.format(job_id=job.job_id),
    )

    assert response.status_code == 200
    assert response.json()["status"] == IngestionJobStatus.FAILED
    assert response.json()["failed_document_count"] == 1


def test_public_exports_are_complete() -> None:
    assert execution_api.__all__ == [
        "FilesystemDocumentExecutionApiConfigurationError",
        "FilesystemDocumentExecutionServiceDependency",
        "execute_filesystem_ingestion_job",
        "get_filesystem_document_execution_service",
        "get_filesystem_document_execution_service_dependency",
        "router",
    ]
