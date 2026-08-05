"""HTTP contracts for Step 108 durable design persistence."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.designs import (
    DESIGN_API_PREFIX,
    MAX_DESIGN_REQUEST_BYTES,
    get_design_persistence_service,
)
from app.db.database import Base, get_db
from app.engineering.calculations.models import (
    CalculationInput,
    CalculationRequest,
    EngineeringQuantity,
    InputOrigin,
)
from app.engineering.calculations.units import QuantityKind
from app.engineering.design.analyzer_workflow_models import (
    ANALYZER_DESIGN_CASE_EXAMPLES,
)
from app.engineering.design.persistence_models import (
    DesignAnalyzerAssessmentCommand,
    DesignCalculationExecutionCommand,
    DesignCaseCreate,
    DesignCaseRevisionCreate,
    DesignContextItem,
    DesignRevisionPayload,
    DesignSourceOrigin,
)
from app.main import APPLICATION_VERSION, app
from app.models.calculation_run import CalculationRun
from app.models.design_case import DesignCase, DesignCaseRevision
from app.services.calculation_service import DEFAULT_CALCULATION_SERVICE


@dataclass(frozen=True)
class _ApiContext:
    client: TestClient
    engine: Engine


@pytest.fixture
def api() -> Iterator[_ApiContext]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(
        engine,
        tables=(
            DesignCase.__table__,
            DesignCaseRevision.__table__,
            CalculationRun.__table__,
        ),
    )

    def _database_override():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_db] = _database_override
    try:
        with TestClient(app) as client:
            yield _ApiContext(client=client, engine=engine)
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def _payload(*, title: str = "Step 108 analyzer design") -> DesignRevisionPayload:
    return DesignRevisionPayload(
        title=title,
        discipline="process-instrumentation",
        source_origins=(
            DesignSourceOrigin(
                source_id="source-datasheet",
                origin=InputOrigin.DOCUMENT_EXTRACTED,
                description="Project process datasheet revision B",
                reference_ids=("datasheet-b",),
            ),
        ),
        plant_context=(
            DesignContextItem(
                field_id="normal-pressure",
                label="Normal process pressure",
                value="5.2",
                unit="bar(a)",
                origin=InputOrigin.DOCUMENT_EXTRACTED,
                source_origin_ids=("source-datasheet",),
            ),
        ),
    )


def _create_document(*, reference: str = "E4M-API-108") -> dict[str, object]:
    return DesignCaseCreate(
        case_reference=reference,
        case_type="analyzer-application",
        payload=_payload(),
        change_reason="Create the controlled design case.",
        created_by="API test engineer",
    ).model_dump(mode="json", round_trip=True, warnings="error")


def _create_case(api: _ApiContext, *, reference: str = "E4M-API-108"):
    response = api.client.post(
        DESIGN_API_PREFIX,
        json=_create_document(reference=reference),
    )
    assert response.status_code == 201, response.text
    return response.json()


def _calculation_request() -> CalculationRequest:
    definition = DEFAULT_CALCULATION_SERVICE.get_method(
        "level.hydrostatic.column-pressure",
        "1.0.0",
    )
    specifications = {
        item.input_id: item for item in definition.input_specifications
    }
    values = (
        ("density", QuantityKind.DENSITY, 998.2, "kg/m3"),
        ("vertical-height", QuantityKind.LENGTH, 3.5, "m"),
        (
            "gravitational-acceleration",
            QuantityKind.ACCELERATION,
            9.80665,
            "m/s2",
        ),
    )
    return CalculationRequest(
        calculation_type=definition.calculation_type,
        method_id=definition.method_id,
        method_version=definition.method_version,
        requested_by="API test engineer",
        inputs=tuple(
            CalculationInput(
                input_id=input_id,
                name=specifications[input_id].name,
                origin=InputOrigin.USER_SUPPLIED,
                quantity=EngineeringQuantity(
                    quantity_kind=quantity_kind.value,
                    value=value,
                    unit=unit,
                ),
            )
            for input_id, quantity_kind, value, unit in values
        ),
    )


def test_openapi_exposes_only_append_or_read_design_operations() -> None:
    document = app.openapi()
    expected = {
        "/api/v1/designs",
        "/api/v1/designs/{design_case_id}",
        "/api/v1/designs/{design_case_id}/revisions",
        "/api/v1/designs/{design_case_id}/revisions/{revision_number}",
        "/api/v1/designs/{design_case_id}/calculations",
        "/api/v1/designs/{design_case_id}/analyzer-assessments",
        "/api/v1/designs/{design_case_id}/runs",
        "/api/v1/design-runs/{run_id}",
    }
    assert expected.issubset(document["paths"])
    for path in expected:
        assert not ({"put", "patch", "delete"} & set(document["paths"][path]))
    assert APPLICATION_VERSION == "0.10.0"
    assert document["info"]["version"] == APPLICATION_VERSION


def test_case_create_read_list_and_dense_revision(api: _ApiContext) -> None:
    created = _create_case(api)
    case_id = created["design_case_id"]
    assert created["current_revision"] == 1
    assert created["concurrency_version"] == 1
    assert created["revision"]["payload"]["approval_state"] == "unapproved"
    assert not created["revision"]["payload"]["final_design_approval_granted"]

    listed = api.client.get(DESIGN_API_PREFIX)
    assert listed.status_code == 200
    page = listed.json()
    assert page["total"] == 1
    assert "payload" not in page["items"][0]

    current = api.client.get(f"{DESIGN_API_PREFIX}/{case_id}")
    assert current.status_code == 200
    assert current.json() == created

    revision_command = DesignCaseRevisionCreate(
        expected_current_revision=1,
        expected_current_fingerprint=created["current_revision_fingerprint"],
        payload=_payload(title="Step 108 analyzer design revision two"),
        change_reason="Record the revised project context.",
        created_by="API test engineer",
    ).model_dump(mode="json", round_trip=True, warnings="error")
    revised = api.client.post(
        f"{DESIGN_API_PREFIX}/{case_id}/revisions",
        json=revision_command,
    )
    assert revised.status_code == 201, revised.text
    revised_record = revised.json()
    assert revised_record["current_revision"] == 2
    assert revised_record["concurrency_version"] == 2
    assert (
        revised_record["revision"]["supersedes_revision_fingerprint"]
        == created["revision"]["revision_fingerprint"]
    )

    history = api.client.get(f"{DESIGN_API_PREFIX}/{case_id}/revisions")
    assert history.status_code == 200
    assert history.json()["total"] == 2
    assert all("payload" not in item for item in history.json()["items"])
    exact = api.client.get(f"{DESIGN_API_PREFIX}/{case_id}/revisions/1")
    assert exact.status_code == 200
    assert exact.json()["revision_fingerprint"] == created["revision"][
        "revision_fingerprint"
    ]

    stale = api.client.post(
        f"{DESIGN_API_PREFIX}/{case_id}/revisions",
        json=revision_command,
    )
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "design_persistence_conflict"


def test_case_reference_is_unique_case_insensitively(api: _ApiContext) -> None:
    _create_case(api, reference="CASE-UNIQUE-108")
    duplicate = api.client.post(
        DESIGN_API_PREFIX,
        json=_create_document(reference="case-unique-108"),
    )
    assert duplicate.status_code == 409


def test_calculation_is_executed_server_side_and_recorded(api: _ApiContext) -> None:
    created = _create_case(api, reference="CALC-API-108")
    case_id = UUID(created["design_case_id"])
    command = DesignCalculationExecutionCommand(
        design_revision_number=1,
        calculation=_calculation_request(),
        created_by="API test engineer",
    )
    response = api.client.post(
        f"{DESIGN_API_PREFIX}/{case_id}/calculations",
        json=command.model_dump(mode="json", round_trip=True, warnings="error"),
    )
    assert response.status_code == 201, response.text
    document = response.json()
    assert document["persistence_performed"]
    assert document["run"]["append_only"]
    assert document["run"]["payload"]["method_definition"]["method_id"] == (
        document["result"]["method_id"]
    )
    assert document["run"]["payload"]["fingerprint_basis_json"]
    assert document["run"]["result_fingerprint"] == document["result"][
        "result_fingerprint"
    ]
    assert document["run"]["execution_metadata"]["executor_id"] == (
        "engineering_calculation_engine"
    )

    run_id = document["run"]["run_id"]
    fetched = api.client.get(f"/api/v1/design-runs/{run_id}")
    assert fetched.status_code == 200
    assert fetched.json() == document["run"]
    listed = api.client.get(f"{DESIGN_API_PREFIX}/{case_id}/runs")
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert "payload" not in listed.json()["items"][0]


def test_analyzer_inner_envelope_remains_stateless_inside_durable_run(
    api: _ApiContext,
) -> None:
    created = _create_case(api, reference="ANALYZER-API-108")
    case_id = created["design_case_id"]
    command = DesignAnalyzerAssessmentCommand(
        design_revision_number=1,
        request=ANALYZER_DESIGN_CASE_EXAMPLES[0].request,
        created_by="API test engineer",
    )
    response = api.client.post(
        f"{DESIGN_API_PREFIX}/{case_id}/analyzer-assessments",
        json=command.model_dump(mode="json", round_trip=True, warnings="error"),
    )
    assert response.status_code == 201, response.text
    document = response.json()
    assert not document["assessment"]["persistence_performed"]
    assert document["persistence_performed"]
    assert document["run"]["persistence_performed"]
    assert document["run"]["result_fingerprint"] == document["assessment"][
        "integration_fingerprint"
    ]
    assert document["run"]["execution_metadata"]["executor_id"] == (
        "analyzer_application_workflow"
    )
    assert not document["run"]["final_design_approval_granted"]


def test_fixed_transport_and_request_contract_errors(api: _ApiContext) -> None:
    malformed = api.client.post(
        DESIGN_API_PREFIX,
        content=b"\xff",
        headers={"content-type": "application/json"},
    )
    assert malformed.status_code == 400
    assert malformed.json()["detail"]["code"] == (
        "calculation_request_parse_error"
    )

    duplicate = api.client.post(
        DESIGN_API_PREFIX,
        content=(
            b'{"case_reference":"A1","case_reference":"A2",'
            b'"case_type":"generic-design","payload":{},'
            b'"change_reason":"Initial.","created_by":"Engineer"}'
        ),
        headers={"content-type": "application/json"},
    )
    assert duplicate.status_code == 400
    assert duplicate.json()["detail"]["code"] == (
        "calculation_request_duplicate_member"
    )

    unknown_query = api.client.get(f"{DESIGN_API_PREFIX}?unknown=true")
    assert unknown_query.status_code == 422
    assert unknown_query.json()["detail"][0]["type"] == (
        "unexpected_query_parameter"
    )

    oversized = api.client.post(
        DESIGN_API_PREFIX,
        content=b"x" * (MAX_DESIGN_REQUEST_BYTES + 1),
        headers={"content-type": "application/json"},
    )
    assert oversized.status_code == 413
    assert oversized.json()["detail"]["code"] == "design_request_too_large"

    missing = api.client.get(f"{DESIGN_API_PREFIX}/{uuid4()}")
    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == "design_case_not_found"


def test_unexpected_service_failure_is_sanitized(api: _ApiContext) -> None:
    class _FailingService:
        def list_cases(self, *, offset: int, limit: int):
            del offset, limit
            raise RuntimeError("private database diagnostics")

    app.dependency_overrides[get_design_persistence_service] = _FailingService
    try:
        response = api.client.get(DESIGN_API_PREFIX)
    finally:
        app.dependency_overrides.pop(get_design_persistence_service, None)
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "design_persistence_unavailable"
    assert "private database diagnostics" not in response.text
