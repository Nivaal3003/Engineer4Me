"""Registration tests for the filesystem document execution transport."""

from __future__ import annotations

from app.main import app, root


EXECUTION_PATH = "/api/v1/ingestion/jobs/{job_id}/execute"
UPLOAD_PATH = "/api/v1/ingestion/uploads"
JOBS_PATH = "/api/v1/ingestion/jobs"


def test_application_version_includes_execution_transport() -> None:
    """The application and root payload expose the Phase 6 API version."""

    assert app.version == "0.9.0"
    assert root() == {
        "application": "Engineer4Me",
        "status": "running",
        "version": "0.9.0",
    }


def test_execution_route_has_one_post_operation() -> None:
    """The main application exposes one POST execution operation."""

    operation = app.openapi()["paths"][EXECUTION_PATH]

    assert list(operation) == ["post"]
    assert operation["post"]["operationId"].startswith(
        "execute_filesystem_ingestion_job_"
    )


def test_execution_openapi_operation_is_complete() -> None:
    """OpenAPI exposes the stable execution contract and safe responses."""

    operation = app.openapi()["paths"][EXECUTION_PATH]

    assert set(operation) == {"post"}
    assert operation["post"]["summary"] == (
        "Execute a filesystem-backed ingestion job"
    )
    assert set(operation["post"]["responses"]) == {
        "200",
        "404",
        "409",
        "422",
        "503",
    }


def test_execution_response_uses_ingestion_job_schema() -> None:
    """The successful execution response remains an ingestion job."""

    response = (
        app.openapi()["paths"][EXECUTION_PATH]["post"]["responses"]["200"]
    )

    assert response["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/IngestionJob"
    }


def test_existing_ingestion_transports_remain_registered() -> None:
    """Execution registration preserves upload and lifecycle endpoints."""

    paths = set(app.openapi()["paths"])

    assert {
        EXECUTION_PATH,
        UPLOAD_PATH,
        JOBS_PATH,
    }.issubset(paths)
