"""HTTP and end-to-end hardening tests for Step 105 pressure relief."""

from __future__ import annotations

import ast
import inspect
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import pressure_relief as api_module
from app.api.calculations import (
    CalculationApiErrorResponse,
    CalculationApiRoute,
    CalculationApiValidationErrorResponse,
    CalculationRequestBodyLimitMiddleware,
)
from app.api.pressure_relief import (
    MAX_PRESSURE_RELIEF_REQUEST_BYTES,
    PRESSURE_RELIEF_CATALOGUE_PATH,
    PRESSURE_RELIEF_EXECUTION_PATH,
    PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH,
    PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH,
    PressureReliefRequestBodyLimitMiddleware,
    get_pressure_relief_service,
    router,
)
from app.engineering.calculations import pressure_relief as relief
from app.engineering.calculations import pressure_relief_workflow_models as workflow
from app.services.pressure_relief_service import (
    PressureReliefService,
    PressureReliefServiceError,
    PressureReliefWorkflowInputError,
)
from tests.test_calculation_pressure_relief_workflow import (
    execution_request,
    readiness_request,
)
from tests.test_pressure_relief_service import readiness_assessment_request

GET_PATHS = (
    PRESSURE_RELIEF_CATALOGUE_PATH,
    PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH,
)
POST_PATHS = (
    PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH,
    PRESSURE_RELIEF_EXECUTION_PATH,
)
ALL_PATHS = GET_PATHS + POST_PATHS


def build_client(
    *,
    service: object | None = None,
    max_body_bytes: int = MAX_PRESSURE_RELIEF_REQUEST_BYTES,
    raise_server_exceptions: bool = True,
) -> TestClient:
    application = FastAPI()
    application.add_middleware(
        PressureReliefRequestBodyLimitMiddleware,
        max_body_bytes=max_body_bytes,
    )
    application.include_router(router, prefix="/api/v1")
    if service is not None:
        application.dependency_overrides[get_pressure_relief_service] = lambda: service
    return TestClient(
        application,
        raise_server_exceptions=raise_server_exceptions,
    )


@pytest.fixture
def client() -> Iterator[TestClient]:
    with build_client() as isolated_client:
        yield isolated_client


def readiness_payload(*, complete: bool = True) -> dict[str, Any]:
    return readiness_assessment_request(complete=complete).model_dump(mode="json")


def execution_payload(
    operation: workflow.PressureReliefOperation,
) -> dict[str, Any]:
    return execution_request(operation).model_dump(mode="json")


def test_router_and_openapi_freeze_exact_four_route_contract() -> None:
    application = FastAPI()
    application.include_router(router, prefix="/api/v1")
    schema = application.openapi()
    paths = schema["paths"]

    assert len(router.routes) == 4
    assert all(isinstance(route, CalculationApiRoute) for route in router.routes)
    assert issubclass(
        PressureReliefRequestBodyLimitMiddleware,
        CalculationRequestBodyLimitMiddleware,
    )
    assert MAX_PRESSURE_RELIEF_REQUEST_BYTES == 512 * 1024
    assert set(paths) == set(ALL_PATHS)
    expected = {
        PRESSURE_RELIEF_CATALOGUE_PATH: (
            "get",
            "getPressureReliefCatalogue",
            "Get pressure-relief catalogue",
        ),
        PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH: (
            "get",
            "listPressureReliefKnowledgeLinks",
            "List pressure-relief knowledge links",
        ),
        PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH: (
            "post",
            "assessPressureReliefReadiness",
            "Assess pressure-relief readiness",
        ),
        PRESSURE_RELIEF_EXECUTION_PATH: (
            "post",
            "executePressureReliefCalculation",
            "Execute an exact pressure-relief calculation",
        ),
    }
    for path, (verb, operation_id, summary) in expected.items():
        assert set(paths[path]) == {verb}
        operation = paths[path][verb]
        assert operation["operationId"] == operation_id
        assert operation["summary"] == summary
        assert set(operation["responses"]) == (
            {"200", "422", "503"}
            if verb == "get"
            else {"200", "400", "413", "422", "503"}
        )

    catalogue_schema = paths[PRESSURE_RELIEF_CATALOGUE_PATH]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]
    links_schema = paths[PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH]["get"]["responses"][
        "200"
    ]["content"]["application/json"]["schema"]
    assert (catalogue_schema["minItems"], catalogue_schema["maxItems"]) == (3, 3)
    assert (links_schema["minItems"], links_schema["maxItems"]) == (2, 2)
    assert paths[PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH]["post"]["requestBody"][
        "content"
    ]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/PressureReliefReadinessAssessmentRequest"
    }
    execution = paths[PRESSURE_RELIEF_EXECUTION_PATH]["post"]
    request_schema = execution["requestBody"]["content"]["application/json"]["schema"]
    assert request_schema["discriminator"]["propertyName"] == "operation"
    assert set(request_schema["discriminator"]["mapping"]) == {
        item.value for item in workflow.PressureReliefOperation
    }
    assert len(request_schema["oneOf"]) == 3
    assert execution["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/PressureReliefExecutionOutcome"
    }


def test_catalogue_and_knowledge_links_are_bounded_inert_metadata(
    client: TestClient,
) -> None:
    catalogue = client.get(PRESSURE_RELIEF_CATALOGUE_PATH)
    links = client.get(PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH)

    assert catalogue.status_code == links.status_code == 200
    assert len(catalogue.json()) == 3
    assert len(links.json()) == 2
    assert all(
        item["executable"] is True
        and item["preliminary_only"] is True
        and item["standards_adapter_execution_count"] == 0
        and item["device_selection_performed"] is False
        and item["standards_conformity_claimed"] is False
        and item["final_compliance_claimed"] is False
        and item["final_design_approval_granted"] is False
        for item in catalogue.json()
    )
    assert all(
        item["retrieval_mode"] == "inert_metadata_only"
        and item["network_access_performed"] is False
        and item["approved_as_equation_or_factor_source"] is False
        and item["executable"] is False
        and item["conformity_evidence"] is False
        and item["standards_conformity_claimed"] is False
        for item in links.json()
    )


@pytest.mark.parametrize("complete", (False, True), ids=("incomplete", "complete"))
def test_readiness_endpoint_returns_valid_blocks_with_audit_and_disclaimers(
    client: TestClient,
    complete: bool,
) -> None:
    first = client.post(
        PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH,
        json=readiness_payload(complete=complete),
    )
    second = client.post(
        PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH,
        json=readiness_payload(complete=complete),
    )

    assert first.status_code == second.status_code == 200
    assert next(iter(first.json())) == "safety_findings"
    outcome = workflow.PressureReliefReadinessAssessmentOutcome.model_validate(
        first.json()
    )
    repeated = workflow.PressureReliefReadinessAssessmentOutcome.model_validate(
        second.json()
    )
    assert outcome == repeated
    assert outcome.result.status == "blocked"
    assert outcome.disposition == "readiness_blocked"
    assert outcome.safety_findings
    assert outcome.audit.status == "blocked"
    assert outcome.audit.calculation_performed is False
    assert outcome.audit.persistence_performed is False
    assert outcome.disclaimers == workflow.PRESSURE_RELIEF_FIXED_DISCLAIMERS
    assert outcome.ready_for_required_area_execution is False
    assert outcome.device_selected is False
    assert outcome.orifice_selected is False
    assert outcome.standards_conformity_claimed is False
    assert outcome.final_compliance_claimed is False
    assert outcome.final_design_approval_granted is False
    assert outcome.approved_for_project_use is False


@pytest.mark.parametrize("operation", tuple(workflow.PressureReliefOperation))
def test_all_three_exact_executions_cross_http_boundary_deterministically(
    client: TestClient,
    operation: workflow.PressureReliefOperation,
) -> None:
    payload = execution_payload(operation)
    first = client.post(PRESSURE_RELIEF_EXECUTION_PATH, json=payload)
    second = client.post(PRESSURE_RELIEF_EXECUTION_PATH, json=payload)

    assert first.status_code == second.status_code == 200
    assert next(iter(first.json())) == "safety_findings"
    outcome = workflow.PressureReliefExecutionOutcome.model_validate(first.json())
    repeated = workflow.PressureReliefExecutionOutcome.model_validate(second.json())
    assert outcome == repeated
    assert outcome.normalized_request == execution_request(operation)
    assert outcome.audit.operation is operation
    assert outcome.audit.status == "completed_with_warnings"
    assert outcome.audit.calculation_performed is True
    assert outcome.audit.persistence_performed is False
    assert outcome.audit.network_access_performed is False
    assert outcome.audit.standards_adapter_execution_count == 0
    assert outcome.disclaimers == workflow.PRESSURE_RELIEF_FIXED_DISCLAIMERS
    assert outcome.safety_findings[0].code == (
        "preliminary_required_area_not_device_selection"
    )
    assert outcome.ready_for_device_selection is False
    assert outcome.device_selected is False
    assert outcome.orifice_selected is False
    assert outcome.manufacturer_selection_performed is False
    assert outcome.standards_conformity_claimed is False
    assert outcome.final_compliance_claimed is False
    assert outcome.final_design_approval_granted is False
    assert outcome.approved_for_project_use is False


@pytest.mark.parametrize("path", POST_PATHS)
def test_malformed_and_duplicate_json_are_sanitized(path: str) -> None:
    client = build_client()
    malformed = client.post(
        path,
        content=b"\xffSECRET-DO-NOT-REFLECT",
        headers={"content-type": "application/json"},
    )
    assert malformed.status_code == 400
    assert "SECRET-DO-NOT-REFLECT" not in malformed.text
    CalculationApiErrorResponse.model_validate(malformed.json())

    duplicate_body = (
        b'{"readiness_request":{"request_id":"valid-id",'
        b'"request_id":"SECRET-DO-NOT-REFLECT"}}'
        if path == PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH
        else (
            b'{"operation":"liquid_required_area","operation":"SECRET-DO-NOT-REFLECT"}'
        )
    )
    duplicate = client.post(
        path,
        content=duplicate_body,
        headers={"content-type": "application/json"},
    )
    assert duplicate.status_code == 400
    assert duplicate.json()["detail"]["code"] == (
        "calculation_request_duplicate_member"
    )
    assert "SECRET-DO-NOT-REFLECT" not in duplicate.text


@pytest.mark.parametrize("path", POST_PATHS)
def test_declared_and_streamed_overflow_are_rejected(path: str) -> None:
    client = build_client(max_body_bytes=128)
    body = b'{"unknown":"' + (b"x" * 256) + b'"}'
    declared = client.post(
        path,
        content=body,
        headers={"content-type": "application/json"},
    )
    assert declared.status_code == 413
    assert declared.json()["detail"]["code"] == ("pressure_relief_request_too_large")

    def chunks() -> Iterator[bytes]:
        yield b'{"unknown":"'
        yield b"x" * 256
        yield b'"}'

    streamed = client.post(
        path,
        content=chunks(),
        headers={"content-type": "application/json"},
    )
    assert streamed.status_code == 413
    assert streamed.json()["detail"]["code"] == ("pressure_relief_request_too_large")


def test_validation_and_domain_errors_are_nonreflective_422(
    client: TestClient,
) -> None:
    invalid = execution_payload(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
    invalid["SECRET-DO-NOT-REFLECT"] = "SECRET-DO-NOT-REFLECT"
    validation = client.post(PRESSURE_RELIEF_EXECUTION_PATH, json=invalid)
    assert validation.status_code == 422
    assert "SECRET-DO-NOT-REFLECT" not in validation.text
    CalculationApiValidationErrorResponse.model_validate(validation.json())

    domain = execution_payload(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA)
    domain["sizing_input"]["applicability"]["vapor_pressure_absolute_pa"] = 100_000.0
    response = client.post(PRESSURE_RELIEF_EXECUTION_PATH, json=domain)
    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "pressure_relief_input_error"
    CalculationApiValidationErrorResponse.model_validate(response.json())


class FailingService:
    """Dependency double that raises one configured public or private error."""

    def __init__(self, failure: Exception) -> None:
        self.failure = failure

    def get_catalogue(self) -> tuple[Any, ...]:
        raise self.failure

    def get_knowledge_links(self) -> tuple[Any, ...]:
        raise self.failure

    def assess_readiness(self, request: object) -> object:
        del request
        raise self.failure

    def execute(self, request: object) -> object:
        del request
        raise self.failure


def test_workflow_input_error_is_sanitized_422() -> None:
    client = build_client(service=FailingService(PressureReliefWorkflowInputError()))
    for path, payload in (
        (PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH, readiness_payload()),
        (
            PRESSURE_RELIEF_EXECUTION_PATH,
            execution_payload(workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA),
        ),
    ):
        response = client.post(path, json=payload)
        assert response.status_code == 422
        assert response.json()["detail"][0]["type"] == ("pressure_relief_input_error")
        CalculationApiValidationErrorResponse.model_validate(response.json())


@pytest.mark.parametrize("path", ALL_PATHS)
def test_trusted_failures_are_generic_nonreflective_503(path: str) -> None:
    client = build_client(
        service=FailingService(RuntimeError("SECRET-PRIVATE-PROGRAMMER-DETAIL"))
    )
    response = (
        client.get(path)
        if path in GET_PATHS
        else client.post(
            path,
            json=(
                readiness_payload()
                if path == PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH
                else execution_payload(
                    workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA
                )
            ),
        )
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == ("pressure_relief_service_unavailable")
    assert "SECRET-PRIVATE-PROGRAMMER-DETAIL" not in response.text
    CalculationApiErrorResponse.model_validate(response.json())


class MismatchedResponseService(PressureReliefService):
    """Return valid trusted outcomes that do not bind the inbound request."""

    def assess_readiness(
        self, request: object
    ) -> workflow.PressureReliefReadinessAssessmentOutcome:
        del request
        alternate = workflow.PressureReliefReadinessAssessmentRequest(
            readiness_request=readiness_request(
                relief.PressureReliefFluidPhase.GAS_VAPOUR
            )
        )
        return super().assess_readiness(alternate)

    def execute(self, request: object) -> workflow.PressureReliefExecutionOutcome:
        del request
        return super().execute(
            execution_request(workflow.PressureReliefOperation.GAS_VAPOUR_REQUIRED_AREA)
        )


@pytest.mark.parametrize("path", POST_PATHS)
def test_response_for_another_request_fails_closed(path: str) -> None:
    response = build_client(service=MismatchedResponseService()).post(
        path,
        json=(
            readiness_payload()
            if path == PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH
            else execution_payload(
                workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA
            )
        ),
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == ("pressure_relief_service_unavailable")


class TamperedOutputService(PressureReliefService):
    """Return forged frozen models that bypassed ordinary model validation."""

    def execute(self, request: object) -> workflow.PressureReliefExecutionOutcome:
        outcome = super().execute(request)  # type: ignore[arg-type]
        forged_audit = outcome.audit.model_copy(update={"audit_fingerprint": "0" * 64})
        return outcome.model_copy(update={"audit": forged_audit})


def test_tampered_trusted_output_is_revalidated_and_rejected() -> None:
    response = build_client(service=TamperedOutputService()).post(
        PRESSURE_RELIEF_EXECUTION_PATH,
        json=execution_payload(
            workflow.PressureReliefOperation.ELIGIBLE_STEAM_REQUIRED_AREA
        ),
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == ("pressure_relief_service_unavailable")


class DriftedDiscoveryService(PressureReliefService):
    """Return schema-valid metadata outside the frozen public catalogue."""

    def get_catalogue(self) -> tuple[Any, ...]:
        changed = workflow.PRESSURE_RELIEF_API_CATALOGUE[0].model_copy(
            update={"title": "Unauthorized but schema-valid catalogue drift"}
        )
        return (changed, *workflow.PRESSURE_RELIEF_API_CATALOGUE[1:])

    def get_knowledge_links(self) -> tuple[Any, ...]:
        changed = workflow.PRESSURE_RELIEF_KNOWLEDGE_LINKS[0].model_copy(
            update={"title": "Unauthorized but schema-valid knowledge drift"}
        )
        return (changed, workflow.PRESSURE_RELIEF_KNOWLEDGE_LINKS[1])


@pytest.mark.parametrize("path", GET_PATHS)
def test_discovery_drift_fails_closed(path: str) -> None:
    response = build_client(service=DriftedDiscoveryService()).get(path)
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == ("pressure_relief_service_unavailable")


@pytest.mark.parametrize("path", ALL_PATHS)
def test_routes_reject_undeclared_query_parameters(path: str) -> None:
    client = build_client()
    response = (
        client.get(path, params={"unexpected": "SECRET-QUERY-VALUE"})
        if path in GET_PATHS
        else client.post(
            path,
            params={"unexpected": "SECRET-QUERY-VALUE"},
            json=(
                readiness_payload()
                if path == PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH
                else execution_payload(
                    workflow.PressureReliefOperation.LIQUID_REQUIRED_AREA
                )
            ),
        )
    )
    assert response.status_code == 422
    assert "SECRET-QUERY-VALUE" not in response.text
    CalculationApiValidationErrorResponse.model_validate(response.json())


@pytest.mark.parametrize("path", POST_PATHS)
def test_body_limit_is_mount_safe_and_scoped_to_exact_paths(path: str) -> None:
    child = FastAPI()
    child.add_middleware(
        PressureReliefRequestBodyLimitMiddleware,
        max_body_bytes=128,
    )
    child.include_router(router, prefix="/api/v1")
    parent = FastAPI()
    parent.mount("/engineering", child)
    client = TestClient(parent)
    body = b'{"unknown":"' + (b"x" * 256) + b'"}'

    mounted = client.post(
        "/engineering" + path,
        content=body,
        headers={"content-type": "application/json"},
    )
    unrelated = client.post(
        "/engineering/api/v1/unrelated",
        content=body,
        headers={"content-type": "application/json"},
    )
    assert mounted.status_code == 413
    assert unrelated.status_code == 404


@pytest.mark.parametrize("path", GET_PATHS)
def test_catalogue_routes_are_read_only(path: str) -> None:
    client = build_client()
    assert client.post(path, json={}).status_code == 405
    assert client.put(path, json={}).status_code == 405
    assert client.delete(path).status_code == 405


@pytest.mark.parametrize("path", POST_PATHS)
def test_execution_routes_are_post_only(path: str) -> None:
    client = build_client()
    assert client.get(path).status_code == 405
    assert client.put(path, json={}).status_code == 405
    assert client.delete(path).status_code == 405


def test_main_application_registers_routes_and_middleware_once() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    for path in ALL_PATHS:
        assert path in paths
        assert set(paths[path]) == {"get" if path in GET_PATHS else "post"}
    assert (
        sum(getattr(route, "original_router", None) is router for route in app.routes)
        == 1
    )
    assert (
        sum(
            item.cls is PressureReliefRequestBodyLimitMiddleware
            for item in app.user_middleware
        )
        == 1
    )


def test_api_module_has_no_persistence_or_outbound_network_coupling() -> None:
    tree = ast.parse(inspect.getsource(api_module))
    imports: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id.casefold())
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr.casefold())

    assert not {name.split(".", 1)[0] for name in imports} & {
        "aiohttp",
        "httpx",
        "requests",
        "socket",
        "sqlalchemy",
        "urllib",
    }
    assert not calls & {
        "connect",
        "create_engine",
        "open",
        "save",
        "sessionmaker",
        "urlopen",
        "write",
    }
    source = inspect.getsource(api_module).casefold()
    assert "app.db" not in source
    assert "app.repositories" not in source
    assert "app.api.selections" not in source


def test_public_api_exports_are_exact() -> None:
    assert set(api_module.__all__) == {
        "MAX_PRESSURE_RELIEF_REQUEST_BYTES",
        "PRESSURE_RELIEF_API_PREFIX",
        "PRESSURE_RELIEF_CATALOGUE_PATH",
        "PRESSURE_RELIEF_EXECUTION_PATH",
        "PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH",
        "PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH",
        "PressureReliefCatalogueResponse",
        "PressureReliefKnowledgeLinksResponse",
        "PressureReliefRequestBodyLimitMiddleware",
        "PressureReliefServiceDependency",
        "assess_pressure_relief_readiness",
        "execute_pressure_relief_required_area",
        "get_pressure_relief_catalogue",
        "get_pressure_relief_service",
        "list_pressure_relief_knowledge_links",
        "router",
    }


def test_dedicated_service_error_uses_exact_public_503_contract() -> None:
    response = build_client(service=FailingService(PressureReliefServiceError())).get(
        PRESSURE_RELIEF_CATALOGUE_PATH
    )
    assert response.status_code == 503
    assert response.json() == {
        "detail": {
            "code": "pressure_relief_service_unavailable",
            "message": (
                "Pressure-relief readiness assessment and required-area "
                "calculation are temporarily unavailable."
            ),
        }
    }
