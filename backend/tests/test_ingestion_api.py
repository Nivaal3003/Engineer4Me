"""Tests for the Engineer4Me document-ingestion API."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.encoders import jsonable_encoder
from fastapi.testclient import TestClient

from app.api.ingestion import get_ingestion_job_service
from app.ingestion.ingestion_job_models import (
    IngestionDocumentStatus,
    IngestionJobStatus,
    IngestionJobType,
    IngestionSourceType,
    IngestionStage,
)
from app.ingestion.ingestion_job_repository import (
    IngestionJobRepository,
    IngestionJobSortOrder,
)
from app.ingestion.ingestion_job_service import IngestionJobService
from app.main import app


INGESTION_API = "/api/v1/ingestion"


@pytest.fixture
def ingestion_service() -> IngestionJobService:
    """Return an isolated ingestion service for one API test."""

    return IngestionJobService(IngestionJobRepository())


@pytest.fixture
def client(
    ingestion_service: IngestionJobService,
) -> Generator[TestClient, None, None]:
    """Return a test client using the isolated ingestion service."""

    app.dependency_overrides[get_ingestion_job_service] = (
        lambda: ingestion_service
    )

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(
            get_ingestion_job_service,
            None,
        )


def build_submission_payload(
    *,
    submitted_by: str = "api-test-user",
    correlation_id: str | None = "API-TEST-001",
    document_count: int = 1,
) -> dict[str, Any]:
    """Build a valid ingestion job submission request."""

    job_type = (
        IngestionJobType.SINGLE_DOCUMENT
        if document_count == 1
        else IngestionJobType.DOCUMENT_BATCH
    )

    return {
        "job_type": job_type.value,
        "source_type": IngestionSourceType.API_UPLOAD.value,
        "submitted_by": submitted_by,
        "correlation_id": correlation_id,
        "documents": [
            {
                "source_name": f"manual-{index + 1}.pdf",
                "source_path": (
                    f"ingestion/api-test/manual-{index + 1}.pdf"
                ),
                "media_type": "application/pdf",
                "file_size_bytes": 2048 + index,
                "checksum_sha256": f"{index + 1:064x}",
                "maximum_attempts": 3,
                "attributes": {
                    "manufacturer": "Example Manufacturer",
                    "ip_owner": "Example Manufacturer",
                    "proprietary_content": True,
                },
            }
            for index in range(document_count)
        ],
        "metadata": {
            "source": "api-test-suite",
            "compliance_review_required": True,
        },
    }


def submit_job(
    client: TestClient,
    *,
    submitted_by: str = "api-test-user",
    correlation_id: str | None = "API-TEST-001",
    document_count: int = 1,
) -> dict[str, Any]:
    """Submit and return one ingestion job through the API."""

    response = client.post(
        f"{INGESTION_API}/jobs",
        json=build_submission_payload(
            submitted_by=submitted_by,
            correlation_id=correlation_id,
            document_count=document_count,
        ),
    )

    assert response.status_code == 201
    return response.json()


def fail_submitted_job(
    service: IngestionJobService,
    job: dict[str, Any],
) -> None:
    """Move an API-submitted job to failed status for retry tests."""

    job_id = UUID(job["job_id"])
    document_id = UUID(job["documents"][0]["document_id"])

    service.queue(job_id)
    service.start(job_id)
    service.start_document(job_id, document_id)
    service.fail_document(job_id, document_id)
    failed = service.complete(job_id)

    assert failed.status == IngestionJobStatus.FAILED


def fail_submitted_document(
    service: IngestionJobService,
    job: dict[str, Any],
) -> None:
    """Fail one API-submitted document while its job remains active."""

    job_id = UUID(job["job_id"])
    document_id = UUID(job["documents"][0]["document_id"])

    service.start(job_id)
    service.start_document(job_id, document_id)
    service.fail_document(job_id, document_id)


def test_ingestion_lifecycle_routes_are_registered() -> None:
    """The main application exposes every lifecycle API operation."""

    paths = set(app.openapi()["paths"])
    required_paths = {
        f"{INGESTION_API}/statistics",
        f"{INGESTION_API}/jobs",
        f"{INGESTION_API}/jobs/search",
        f"{INGESTION_API}/jobs/{{job_id}}",
        f"{INGESTION_API}/jobs/{{job_id}}/queue",
        f"{INGESTION_API}/jobs/{{job_id}}/start",
        (
            f"{INGESTION_API}/jobs/{{job_id}}/"
            "cancellation-request"
        ),
        f"{INGESTION_API}/jobs/{{job_id}}/cancel",
        f"{INGESTION_API}/jobs/{{job_id}}/retry",
        (
            f"{INGESTION_API}/jobs/{{job_id}}/documents/"
            "{document_id}/retry"
        ),
    }

    assert required_paths.issubset(paths)


def test_submit_ingestion_job(client: TestClient) -> None:
    """A valid submission creates a pending ingestion job."""

    response = client.post(
        f"{INGESTION_API}/jobs",
        json=build_submission_payload(),
    )

    assert response.status_code == 201

    body = response.json()
    document = body["documents"][0]

    assert body["status"] == IngestionJobStatus.PENDING.value
    assert body["stage"] == IngestionStage.WAITING.value
    assert body["job_type"] == IngestionJobType.SINGLE_DOCUMENT.value
    assert body["source_type"] == IngestionSourceType.API_UPLOAD.value
    assert body["submitted_by"] == "api-test-user"
    assert body["total_document_count"] == 1
    assert body["metadata"]["compliance_review_required"] is True
    assert document["source_name"] == "manual-1.pdf"
    assert document["status"] == IngestionDocumentStatus.PENDING.value
    assert document["attributes"]["proprietary_content"] is True


def test_submit_document_batch(client: TestClient) -> None:
    """A multi-document request creates a batch ingestion job."""

    job = submit_job(
        client,
        correlation_id="API-BATCH-001",
        document_count=2,
    )

    assert job["job_type"] == IngestionJobType.DOCUMENT_BATCH.value
    assert job["total_document_count"] == 2
    assert len(job["documents"]) == 2


@pytest.mark.parametrize(
    "payload_update",
    [
        {"documents": []},
        {"submitted_by": ""},
    ],
)
def test_submit_rejects_invalid_job_payload(
    client: TestClient,
    payload_update: dict[str, Any],
) -> None:
    """Submission request validation rejects incomplete job metadata."""

    payload = build_submission_payload()
    payload.update(payload_update)

    response = client.post(
        f"{INGESTION_API}/jobs",
        json=payload,
    )

    assert response.status_code == 422


def test_submit_rejects_invalid_document_payload(
    client: TestClient,
) -> None:
    """Document metadata must satisfy the API field constraints."""

    payload = build_submission_payload()
    payload["documents"][0]["maximum_attempts"] = 0

    response = client.post(
        f"{INGESTION_API}/jobs",
        json=payload,
    )

    assert response.status_code == 422


def test_get_ingestion_job(client: TestClient) -> None:
    """A submitted job can be retrieved by identifier."""

    submitted = submit_job(client)

    response = client.get(
        f"{INGESTION_API}/jobs/{submitted['job_id']}",
    )

    assert response.status_code == 200
    assert response.json() == submitted


def test_get_unknown_ingestion_job_returns_404(
    client: TestClient,
) -> None:
    """Unknown job identifiers return a not-found response."""

    response = client.get(
        f"{INGESTION_API}/jobs/{uuid4()}",
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_search_ingestion_jobs(client: TestClient) -> None:
    """Structured search filters jobs by submitter."""

    matching = submit_job(
        client,
        submitted_by="operator-alpha",
        correlation_id="SEARCH-ALPHA",
    )
    excluded = submit_job(
        client,
        submitted_by="operator-beta",
        correlation_id="SEARCH-BETA",
    )

    response = client.post(
        f"{INGESTION_API}/jobs/search",
        json={
            "submitted_by": "operator-alpha",
            "sort_order": (
                IngestionJobSortOrder.CREATED_DESCENDING.value
            ),
            "offset": 0,
            "limit": 10,
        },
    )

    assert response.status_code == 200
    assert matching["job_id"] in response.text
    assert excluded["job_id"] not in response.text


def test_search_rejects_invalid_pagination(
    client: TestClient,
) -> None:
    """Search pagination remains within the public API limits."""

    response = client.post(
        f"{INGESTION_API}/jobs/search",
        json={"limit": 0},
    )

    assert response.status_code == 422


def test_get_ingestion_statistics(
    client: TestClient,
    ingestion_service: IngestionJobService,
) -> None:
    """The statistics endpoint exposes repository aggregates."""

    submit_job(client)

    response = client.get(
        f"{INGESTION_API}/statistics",
    )

    assert response.status_code == 200
    assert response.json() == jsonable_encoder(
        ingestion_service.statistics()
    )


def test_queue_ingestion_job(client: TestClient) -> None:
    """A pending job can be moved into the queue."""

    submitted = submit_job(client)

    response = client.post(
        f"{INGESTION_API}/jobs/{submitted['job_id']}/queue",
    )

    assert response.status_code == 200
    assert response.json()["status"] == IngestionJobStatus.QUEUED.value
    assert response.json()["queued_at"] is not None


def test_queue_rejects_invalid_transition(
    client: TestClient,
) -> None:
    """Queueing an already queued job returns a conflict."""

    submitted = submit_job(client)
    endpoint = f"{INGESTION_API}/jobs/{submitted['job_id']}/queue"

    first_response = client.post(endpoint)
    second_response = client.post(endpoint)

    assert first_response.status_code == 200
    assert second_response.status_code == 409


def test_start_ingestion_job(client: TestClient) -> None:
    """A queued job can start at the requested processing stage."""

    submitted = submit_job(client)
    client.post(
        f"{INGESTION_API}/jobs/{submitted['job_id']}/queue",
    )

    response = client.post(
        f"{INGESTION_API}/jobs/{submitted['job_id']}/start",
        json={"stage": IngestionStage.PARSING.value},
    )

    assert response.status_code == 200

    body = response.json()
    assert body["status"] == IngestionJobStatus.PROCESSING.value
    assert body["stage"] == IngestionStage.PARSING.value
    assert body["started_at"] is not None


def test_start_uses_default_stage(client: TestClient) -> None:
    """An empty start request uses the parsing stage."""

    submitted = submit_job(client)

    response = client.post(
        f"{INGESTION_API}/jobs/{submitted['job_id']}/start",
        json={},
    )

    assert response.status_code == 200
    assert response.json()["stage"] == IngestionStage.PARSING.value


def test_request_and_apply_cancellation(
    client: TestClient,
) -> None:
    """An explicit cancellation request can be applied to a job."""

    submitted = submit_job(
        client,
        document_count=2,
    )
    base_endpoint = (
        f"{INGESTION_API}/jobs/{submitted['job_id']}"
    )

    requested_response = client.post(
        f"{base_endpoint}/cancellation-request",
    )
    cancelled_response = client.post(
        f"{base_endpoint}/cancel",
    )

    assert requested_response.status_code == 202
    assert requested_response.json()["cancellation_requested"] is True
    assert cancelled_response.status_code == 200

    cancelled = cancelled_response.json()
    assert cancelled["status"] == IngestionJobStatus.CANCELLED.value
    assert cancelled["stage"] == IngestionStage.COMPLETE.value
    assert all(
        document["status"]
        == IngestionDocumentStatus.CANCELLED.value
        for document in cancelled["documents"]
    )


def test_apply_cancellation_requires_request(
    client: TestClient,
) -> None:
    """Applying cancellation without a request returns a conflict."""

    submitted = submit_job(client)

    response = client.post(
        f"{INGESTION_API}/jobs/{submitted['job_id']}/cancel",
    )

    assert response.status_code == 409
    assert "has not been requested" in response.json()["detail"]


def test_retry_failed_ingestion_job(
    client: TestClient,
    ingestion_service: IngestionJobService,
) -> None:
    """A failed job can be reset through the retry endpoint."""

    submitted = submit_job(client)
    fail_submitted_job(ingestion_service, submitted)

    response = client.post(
        f"{INGESTION_API}/jobs/{submitted['job_id']}/retry",
    )

    assert response.status_code == 200

    retried = response.json()
    assert retried["status"] == IngestionJobStatus.PENDING.value
    assert retried["stage"] == IngestionStage.WAITING.value
    assert retried["progress_percent"] == 0
    assert retried["completed_at"] is None
    assert retried["documents"][0]["status"] == (
        IngestionDocumentStatus.PENDING.value
    )


def test_retry_rejects_active_ingestion_job(
    client: TestClient,
) -> None:
    """A pending job is not eligible for retry."""

    submitted = submit_job(client)

    response = client.post(
        f"{INGESTION_API}/jobs/{submitted['job_id']}/retry",
    )

    assert response.status_code == 409
    assert "Only failed" in response.json()["detail"]


def test_retry_failed_ingestion_document(
    client: TestClient,
    ingestion_service: IngestionJobService,
) -> None:
    """A failed document can be reset through its retry endpoint."""

    submitted = submit_job(client)
    fail_submitted_document(ingestion_service, submitted)
    document_id = submitted["documents"][0]["document_id"]

    response = client.post(
        (
            f"{INGESTION_API}/jobs/{submitted['job_id']}"
            f"/documents/{document_id}/retry"
        ),
    )

    assert response.status_code == 200

    document = response.json()["documents"][0]
    assert document["status"] == IngestionDocumentStatus.PENDING.value
    assert document["stage"] == IngestionStage.WAITING.value
    assert document["progress_percent"] == 0
    assert document["completed_at"] is None


def test_retry_document_rejects_non_failed_document(
    client: TestClient,
) -> None:
    """A pending document is not eligible for retry."""

    submitted = submit_job(client)
    document_id = submitted["documents"][0]["document_id"]

    response = client.post(
        (
            f"{INGESTION_API}/jobs/{submitted['job_id']}"
            f"/documents/{document_id}/retry"
        ),
    )

    assert response.status_code == 409
    assert "Only a failed document" in response.json()["detail"]


def test_retry_unknown_document_returns_404(
    client: TestClient,
) -> None:
    """Retrying an unknown document returns a not-found response."""

    submitted = submit_job(client)

    response = client.post(
        (
            f"{INGESTION_API}/jobs/{submitted['job_id']}"
            f"/documents/{uuid4()}/retry"
        ),
    )

    assert response.status_code == 404
