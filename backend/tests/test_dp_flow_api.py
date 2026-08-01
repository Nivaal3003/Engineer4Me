"""HTTP contract and transport-hardening tests for Step 99 DP flow."""

from __future__ import annotations

from collections.abc import Iterator
import json
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import dp_flow as api_module
from app.api.calculations import CalculationApiErrorResponse
from app.api.calculations import CalculationApiRoute
from app.api.calculations import CalculationApiValidationErrorResponse
from app.api.calculations import CalculationRequestBodyLimitMiddleware
from app.api.dp_flow import DP_FLOW_APPLICATION_ASSESSMENT_PATH
from app.api.dp_flow import DP_FLOW_CATALOGUE_PATH
from app.api.dp_flow import DP_FLOW_DESIGN_CASE_EVALUATION_PATH
from app.api.dp_flow import DP_FLOW_DESIGN_CASE_EXAMPLES_PATH
from app.api.dp_flow import DP_FLOW_EXECUTION_PATH
from app.api.dp_flow import DP_FLOW_KNOWLEDGE_LINKS_PATH
from app.api.dp_flow import DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH
from app.api.dp_flow import DPFlowRequestBodyLimitMiddleware
from app.api.dp_flow import MAX_DP_FLOW_REQUEST_BYTES
from app.api.dp_flow import get_dp_flow_service
from app.api.dp_flow import router
from app.engineering.calculations.dp_flow import DP_FLOW_DISCOVERY_ENTRIES
from app.engineering.calculations.dp_flow import DP_FLOW_UNCERTAINTY_METHOD_ID
from app.engineering.calculations.dp_flow import DP_FLOW_UNCERTAINTY_METHOD_VERSION
from app.engineering.calculations.dp_flow import RelativeUncertaintyComponent
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowDesignCaseOutcome,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowExecutionOutcome,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowStoredDesignCaseReplayRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DPFlowUncertaintyRequest,
)
from app.engineering.calculations.dp_flow_workflow_models import (
    DP_FLOW_STORED_DESIGN_CASE_EXAMPLES,
)
from app.engineering.calculations.level import (
    ENGINEERING_METHOD_REGISTRATIONS,
)
from app.services.dp_flow_service import DPFlowServiceError


POST_PATHS = (
    DP_FLOW_EXECUTION_PATH,
    DP_FLOW_APPLICATION_ASSESSMENT_PATH,
    DP_FLOW_DESIGN_CASE_EVALUATION_PATH,
    DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH,
)
GET_PATHS = (
    DP_FLOW_CATALOGUE_PATH,
    DP_FLOW_KNOWLEDGE_LINKS_PATH,
    DP_FLOW_DESIGN_CASE_EXAMPLES_PATH,
)
ALL_PATHS = GET_PATHS + POST_PATHS


def build_client(
    *,
    service: object | None = None,
    max_body_bytes: int = MAX_DP_FLOW_REQUEST_BYTES,
    raise_server_exceptions: bool = True,
) -> TestClient:
    """Build one isolated API using the reviewed default service."""

    application = FastAPI()
    application.add_middleware(
        DPFlowRequestBodyLimitMiddleware,
        max_body_bytes=max_body_bytes,
    )
    application.include_router(router, prefix="/api/v1")
    if service is not None:
        application.dependency_overrides[get_dp_flow_service] = (
            lambda: service
        )
    return TestClient(
        application,
        raise_server_exceptions=raise_server_exceptions,
    )


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Yield an isolated DP-flow client and close its resources."""

    with build_client() as isolated_client:
        yield isolated_client


def test_dp_flow_transport_and_routes_reuse_reviewed_boundaries() -> None:
    """Step 99 extends the existing sanitized route and body-limit classes."""

    assert MAX_DP_FLOW_REQUEST_BYTES == 512 * 1024
    assert issubclass(
        DPFlowRequestBodyLimitMiddleware,
        CalculationRequestBodyLimitMiddleware,
    )
    assert len(router.routes) == 7
    assert all(isinstance(route, CalculationApiRoute) for route in router.routes)


def test_default_get_routes_return_bounded_typed_catalogues(
    client: TestClient,
) -> None:
    """Discovery output is fixed, inert, and explicit about project use."""

    catalogue = client.get(DP_FLOW_CATALOGUE_PATH)
    assert catalogue.status_code == 200
    assert len(catalogue.json()) == 9
    assert all(item["executable"] is True for item in catalogue.json())
    assert all(
        item["knowledge_links_are_inert"] is True
        for item in catalogue.json()
    )
    assert all(
        item["coefficient_derivation_performed"] is False
        for item in catalogue.json()
    )
    assert all(
        item["manufacturer_selection_performed"] is False
        for item in catalogue.json()
    )
    assert all(
        item["standards_conformity_claimed"] is False
        for item in catalogue.json()
    )

    links = client.get(DP_FLOW_KNOWLEDGE_LINKS_PATH)
    assert links.status_code == 200
    assert len(links.json()) == 12
    for link in links.json():
        assert link["retrieval_mode"] == "inert_metadata_only"
        assert link["network_access_performed"] is False
        assert link["approved_as_coefficient_source"] is False
        assert link["executable"] is False
        assert link["conformity_evidence"] is False
        assert link["standards_conformity_claimed"] is False

    examples = client.get(DP_FLOW_DESIGN_CASE_EXAMPLES_PATH)
    assert examples.status_code == 200
    assert [item["example_id"] for item in examples.json()] == [
        "dp-example.liquid-orifice",
        "dp-example.steam-nozzle",
        "dp-example.large-pipe-averaging-pitot",
    ]
    assert all(item["illustrative_only"] is True for item in examples.json())
    assert all(
        item["approved_for_project_use"] is False
        for item in examples.json()
    )


def test_exact_execution_route_returns_reproducible_typed_result(
    client: TestClient,
) -> None:
    """A valid exact-version request reaches the static service boundary."""

    request = DP_FLOW_STORED_DESIGN_CASE_EXAMPLES[0].design_case.execution_request
    response = client.post(
        DP_FLOW_EXECUTION_PATH,
        json=request.model_dump(mode="json"),
    )

    assert response.status_code == 200
    outcome = DPFlowExecutionOutcome.model_validate(response.json())
    assert outcome.normalized_request == request
    assert outcome.trace.method_id == request.method_id
    assert outcome.trace.method_version == request.method_version
    assert outcome.trace.standards_adapter_execution_count == 0
    assert outcome.coefficient_derivation_performed is False
    assert outcome.manufacturer_selection_performed is False
    assert outcome.standards_conformity_claimed is False


def test_application_assessment_keeps_incomplete_engineering_as_http_200(
    client: TestClient,
) -> None:
    """Missing process facts are an assessment outcome, not transport failure."""

    response = client.post(
        DP_FLOW_APPLICATION_ASSESSMENT_PATH,
        json={
            "assessment_id": "step99-incomplete",
            "fluid_phase": "unknown",
            "objective": "monitoring",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["missing_information"]
    assert body["confidence_band"] == "low"
    assert len(body["all_screened_options"]) == 25
    assert len(body["proprietary_notices"]) == 7
    assert body["manufacturer_declared_best"] is False
    assert body["final_brand_selection"] == "user_decision_required"
    assert body["standards_conformity_claimed"] is False


def test_stateless_and_stored_api_paths_reproduce_the_same_design_result(
    client: TestClient,
) -> None:
    """An exact immutable replay matches the equivalent stateless request."""

    example = DP_FLOW_STORED_DESIGN_CASE_EXAMPLES[1]
    stateless_response = client.post(
        DP_FLOW_DESIGN_CASE_EVALUATION_PATH,
        json=example.design_case.model_dump(mode="json"),
    )
    stored_response = client.post(
        DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH,
        json=DPFlowStoredDesignCaseReplayRequest(
            example_id=example.example_id,
            revision=example.revision,
            example_fingerprint=example.example_fingerprint,
        ).model_dump(mode="json"),
    )

    assert stateless_response.status_code == 200
    assert stored_response.status_code == 200
    stateless = DPFlowDesignCaseOutcome.model_validate(
        stateless_response.json()
    )
    stored = DPFlowDesignCaseOutcome.model_validate(stored_response.json())
    assert stateless.execution_mode == "stateless"
    assert stored.execution_mode == "stored_example_replay"
    assert stateless.design_case_fingerprint == stored.design_case_fingerprint
    assert stateless.calculation.trace.result_fingerprint == (
        stored.calculation.trace.result_fingerprint
    )
    assert stored.approved_for_project_use is False
    assert stored.manufacturer_declared_best is False
    assert stored.final_brand_selection == "user_decision_required"
    assert stored.standards_conformity_claimed is False


@pytest.mark.parametrize(
    ("mutation", "status_code", "error_code"),
    (
        (
            {"revision": 2},
            409,
            "dp_flow_resource_conflict",
        ),
        (
            {"example_fingerprint": "0" * 64},
            409,
            "dp_flow_resource_conflict",
        ),
        (
            {
                "example_id": "dp-example.unknown",
                "example_fingerprint": "0" * 64,
            },
            404,
            "dp_flow_resource_not_found",
        ),
    ),
)
def test_stored_api_requires_exact_identity_revision_and_digest(
    client: TestClient,
    mutation: dict[str, object],
    status_code: int,
    error_code: str,
) -> None:
    """The HTTP boundary exposes no latest-version or fingerprint fallback."""

    example = DP_FLOW_STORED_DESIGN_CASE_EXAMPLES[0]
    payload: dict[str, object] = {
        "example_id": example.example_id,
        "revision": example.revision,
        "example_fingerprint": example.example_fingerprint,
    }
    payload.update(mutation)

    response = client.post(
        DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH,
        json=payload,
    )

    assert response.status_code == status_code
    assert response.json()["detail"]["code"] == error_code
    CalculationApiErrorResponse.model_validate(response.json())


def test_unsafe_and_element_mismatched_design_cases_are_sanitized_422(
    client: TestClient,
) -> None:
    """Structurally valid but unsafe design execution fails before calculation."""

    example = DP_FLOW_STORED_DESIGN_CASE_EXAMPLES[0]
    unsafe = example.design_case.model_dump(mode="json")
    unsafe["application_request"]["full_pipe_confirmed"] = "no"
    response = client.post(
        DP_FLOW_DESIGN_CASE_EVALUATION_PATH,
        json=unsafe,
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "dp_flow_input_error"
    assert "full_pipe" not in response.text

    mismatch = example.design_case.model_dump(mode="json")
    mismatch["selected_generic_option_id"] = "generic.venturi.classical"
    response = client.post(
        DP_FLOW_DESIGN_CASE_EVALUATION_PATH,
        json=mismatch,
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "dp_flow_input_error"


def test_owned_primary_element_is_not_a_design_execution_identifier(
    client: TestClient,
) -> None:
    """Owned variants cannot be silently mapped through a generic calculator."""

    payload = DP_FLOW_STORED_DESIGN_CASE_EXAMPLES[0].design_case.model_dump(
        mode="json"
    )
    payload["selected_generic_option_id"] = (
        "owned.emerson-rosemount.annubar"
    )

    response = client.post(
        DP_FLOW_DESIGN_CASE_EVALUATION_PATH,
        json=payload,
    )

    assert response.status_code == 422
    assert "annubar" not in response.text.lower()
    CalculationApiValidationErrorResponse.model_validate(response.json())


def test_wrong_version_and_iso_metadata_ids_cannot_execute(
    client: TestClient,
) -> None:
    """The request union rejects non-exact versions and all inert ISO IDs."""

    request = DP_FLOW_STORED_DESIGN_CASE_EXAMPLES[0].design_case.execution_request
    payload = request.model_dump(mode="json")
    payload["method_version"] = "9.9.9"
    response = client.post(DP_FLOW_EXECUTION_PATH, json=payload)
    assert response.status_code == 422

    for adapter in DP_FLOW_DISCOVERY_ENTRIES:
        payload = request.model_dump(mode="json")
        payload["method_id"] = adapter.adapter_id
        response = client.post(DP_FLOW_EXECUTION_PATH, json=payload)
        assert response.status_code == 422


@pytest.mark.parametrize("missing", ("operation", "method_id", "method_version"))
def test_api_requires_explicit_exact_method_identity(
    client: TestClient,
    missing: str,
) -> None:
    """The HTTP boundary never inserts a current or latest method identity."""

    request = DP_FLOW_STORED_DESIGN_CASE_EXAMPLES[0].design_case.execution_request
    payload = request.model_dump(mode="json")
    payload.pop(missing)
    response = client.post(DP_FLOW_EXECUTION_PATH, json=payload)
    assert response.status_code == 422
    CalculationApiValidationErrorResponse.model_validate(response.json())


def test_strict_invalid_execution_requests_are_bounded_and_nonreflective(
    client: TestClient,
) -> None:
    """Extras, non-finite values, and oversized collections never execute."""

    request = DP_FLOW_STORED_DESIGN_CASE_EXAMPLES[0].design_case.execution_request
    payload = request.model_dump(mode="json")
    payload["SECRET-DO-NOT-REFLECT"] = "SECRET-DO-NOT-REFLECT"
    response = client.post(DP_FLOW_EXECUTION_PATH, json=payload)
    assert response.status_code == 422
    assert "SECRET-DO-NOT-REFLECT" not in response.text

    payload = request.model_dump(mode="json")
    payload["fluid"]["density_kg_m3"] = True
    response = client.post(DP_FLOW_EXECUTION_PATH, json=payload)
    assert response.status_code == 422

    payload = request.model_dump(mode="json")
    payload["discharge_coefficient"]["value"] = True
    response = client.post(DP_FLOW_EXECUTION_PATH, json=payload)
    assert response.status_code == 422

    for value in (1.0e308, int("9" * 400)):
        payload = request.model_dump(mode="json")
        payload["pipe_inside_diameter_m"] = value
        response = client.post(DP_FLOW_EXECUTION_PATH, json=payload)
        assert response.status_code == 422
        CalculationApiValidationErrorResponse.model_validate(response.json())

    payload = request.model_dump(mode="json")
    payload["fluid"]["density_kg_m3"] = int("9" * 400)
    response = client.post(DP_FLOW_EXECUTION_PATH, json=payload)
    assert response.status_code == 422
    CalculationApiValidationErrorResponse.model_validate(response.json())

    payload = request.model_dump(mode="json")
    payload["differential_pressure_pa"] = float("nan")
    raw = json.dumps(
        payload,
        allow_nan=True,
        separators=(",", ":"),
    )
    response = client.post(
        DP_FLOW_EXECUTION_PATH,
        content=raw,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert "NaN" not in response.text

    component = RelativeUncertaintyComponent(
        component_id="component",
        relative_standard_uncertainty_percent=0.1,
        sensitivity_coefficient=1.0,
        source_reference="Independent record",
    )
    bounded = DPFlowUncertaintyRequest(
        operation="relative_uncertainty",
        method_id=DP_FLOW_UNCERTAINTY_METHOD_ID,
        method_version=DP_FLOW_UNCERTAINTY_METHOD_VERSION,
        components=(component,),
    )
    payload = bounded.model_dump(mode="json")
    payload["components"] = [component.model_dump(mode="json")] * 65
    response = client.post(DP_FLOW_EXECUTION_PATH, json=payload)
    assert response.status_code == 422
    CalculationApiValidationErrorResponse.model_validate(response.json())


@pytest.mark.parametrize("value", (1, 0, "true", "false", "yes", "no"))
def test_application_api_rejects_coercive_boolean_flags(
    client: TestClient,
    value: object,
) -> None:
    """The public assessment route accepts only JSON true or false."""

    payload = DP_FLOW_STORED_DESIGN_CASE_EXAMPLES[
        0
    ].design_case.application_request.model_dump(mode="json")
    payload["include_proprietary_variants"] = value
    response = client.post(DP_FLOW_APPLICATION_ASSESSMENT_PATH, json=payload)
    assert response.status_code == 422
    CalculationApiValidationErrorResponse.model_validate(response.json())


def test_chunked_body_overflow_is_rejected_during_receive() -> None:
    """The 512 KiB boundary also protects requests without Content-Length."""

    client = build_client(max_body_bytes=128)

    def chunks() -> Iterator[bytes]:
        yield b'{"unknown":"'
        yield b"x" * 256
        yield b'"}'

    response = client.post(
        DP_FLOW_EXECUTION_PATH,
        content=chunks(),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "dp_flow_request_too_large"


def test_body_limit_does_not_capture_an_unrelated_route() -> None:
    """The DP guard cannot alter other API transport boundaries."""

    client = build_client(max_body_bytes=128)
    response = client.post(
        "/api/v1/unrelated",
        content=b"x" * 256,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 404


def test_body_limit_uses_route_path_when_application_is_mounted() -> None:
    """An ASGI mount prefix cannot bypass the dedicated DP guard."""

    child = FastAPI()
    child.add_middleware(
        DPFlowRequestBodyLimitMiddleware,
        max_body_bytes=128,
    )
    child.include_router(router, prefix="/api/v1")
    parent = FastAPI()
    parent.mount("/engineering", child)
    client = TestClient(parent)
    body = b'{"unknown":"' + (b"x" * 256) + b'"}'

    response = client.post(
        "/engineering" + DP_FLOW_EXECUTION_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "dp_flow_request_too_large"


class FailingCatalogueService:
    """Small dependency double for sanitized availability tests."""

    def __init__(self, failure: Exception) -> None:
        self.failure = failure

    def get_catalogue(self) -> tuple[Any, ...]:
        raise self.failure


def test_dedicated_service_failure_is_a_sanitized_503() -> None:
    """Only the public service error crosses as service unavailable."""

    client = build_client(service=FailingCatalogueService(DPFlowServiceError()))
    response = client.get(DP_FLOW_CATALOGUE_PATH)

    assert response.status_code == 503
    assert response.json() == {
        "detail": {
            "code": "dp_flow_service_unavailable",
            "message": (
                "DP-flow calculation and application assessment are "
                "temporarily unavailable."
            ),
        }
    }
    CalculationApiErrorResponse.model_validate(response.json())


def test_unexpected_failure_is_hidden_by_http_500_boundary() -> None:
    """Private programmer details are never translated into client input errors."""

    client = build_client(
        service=FailingCatalogueService(
            RuntimeError("SECRET-PRIVATE-PROGRAMMER-DETAIL")
        ),
        raise_server_exceptions=False,
    )
    response = client.get(DP_FLOW_CATALOGUE_PATH)

    assert response.status_code == 500
    assert "SECRET-PRIVATE-PROGRAMMER-DETAIL" not in response.text


def test_openapi_freezes_the_seven_dp_flow_routes() -> None:
    """No undocumented write or standards-execution route is registered."""

    application = FastAPI()
    application.include_router(router, prefix="/api/v1")
    paths = application.openapi()["paths"]

    assert set(paths) == set(ALL_PATHS)
    for path in GET_PATHS:
        assert set(paths[path]) == {"get"}
    for path in POST_PATHS:
        assert set(paths[path]) == {"post"}

    operations = {
        DP_FLOW_CATALOGUE_PATH: (
            "getDPFlowCatalogue",
            "Get DP-flow catalogue",
        ),
        DP_FLOW_KNOWLEDGE_LINKS_PATH: (
            "listDPFlowKnowledgeLinks",
            "List DP-flow knowledge links",
        ),
        DP_FLOW_DESIGN_CASE_EXAMPLES_PATH: (
            "listDPFlowDesignCaseExamples",
            "List DP-flow design-case examples",
        ),
        DP_FLOW_EXECUTION_PATH: (
            "executeDPFlowCalculation",
            "Execute an exact DP-flow calculation",
        ),
        DP_FLOW_APPLICATION_ASSESSMENT_PATH: (
            "assessDPFlowApplication",
            "Assess DP-flow application",
        ),
        DP_FLOW_DESIGN_CASE_EVALUATION_PATH: (
            "evaluateDPFlowDesignCase",
            "Evaluate a stateless DP-flow design case",
        ),
        DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH: (
            "evaluateStoredDPFlowDesignCase",
            "Evaluate an exact stored DP-flow design case",
        ),
    }
    for path, (operation_id, summary) in operations.items():
        verb = "get" if path in GET_PATHS else "post"
        assert paths[path][verb]["operationId"] == operation_id
        assert paths[path][verb]["summary"] == summary


def test_openapi_freezes_dp_request_response_and_error_contracts() -> None:
    """Exact unions, result models, and translated statuses are documented."""

    application = FastAPI()
    application.include_router(router, prefix="/api/v1")
    schema = application.openapi()
    paths = schema["paths"]
    expected_statuses = {
        DP_FLOW_CATALOGUE_PATH: {"200", "422", "503"},
        DP_FLOW_KNOWLEDGE_LINKS_PATH: {"200", "422", "503"},
        DP_FLOW_DESIGN_CASE_EXAMPLES_PATH: {"200", "422", "503"},
        DP_FLOW_EXECUTION_PATH: {"200", "400", "404", "413", "422", "503"},
        DP_FLOW_APPLICATION_ASSESSMENT_PATH: {
            "200", "400", "413", "422", "503"
        },
        DP_FLOW_DESIGN_CASE_EVALUATION_PATH: {
            "200", "400", "404", "413", "422", "503"
        },
        DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH: {
            "200", "400", "404", "409", "413", "422", "503"
        },
    }
    for path, statuses in expected_statuses.items():
        verb = "get" if path in GET_PATHS else "post"
        assert set(paths[path][verb]["responses"]) == statuses

    execution = paths[DP_FLOW_EXECUTION_PATH]["post"]
    request_schema = execution["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert request_schema["discriminator"]["propertyName"] == "operation"
    assert set(request_schema["discriminator"]["mapping"]) == {
        "generic_orifice",
        "orifice_bore_solver",
        "generic_nozzle",
        "generic_venturi_nozzle",
        "generic_venturi_tube",
        "generic_averaging_pitot",
        "transmitter_range",
        "permanent_pressure_loss",
        "relative_uncertainty",
    }
    assert len(request_schema["oneOf"]) == 9
    for definition_reference in request_schema["discriminator"][
        "mapping"
    ].values():
        definition_name = definition_reference.rsplit("/", 1)[-1]
        required = set(
            schema["components"]["schemas"][definition_name]["required"]
        )
        assert {"operation", "method_id", "method_version"} <= required
    assert execution["responses"]["200"]["content"]["application/json"][
        "schema"
    ] == {"$ref": "#/components/schemas/DPFlowExecutionOutcome"}
    assert paths[DP_FLOW_DESIGN_CASE_EVALUATION_PATH]["post"]["responses"][
        "200"
    ]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/DPFlowDesignCaseOutcome"
    }
    assert schema["components"]["schemas"]["GenericOrificeFlowRequest"][
        "additionalProperties"
    ] is False


@pytest.mark.parametrize("path", POST_PATHS)
def test_declared_oversized_dp_flow_bodies_are_rejected(
    path: str,
) -> None:
    """Every DP-flow POST route shares the fixed transport limit."""

    client = build_client(max_body_bytes=128)
    body = b'{"unknown":"' + (b"x" * 256) + b'"}'

    response = client.post(
        path,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json() == {
        "detail": {
            "code": "dp_flow_request_too_large",
            "message": (
                "The DP-flow request exceeds the permitted transport size."
            ),
        }
    }
    CalculationApiErrorResponse.model_validate(response.json())


@pytest.mark.parametrize("path", POST_PATHS)
def test_exact_body_limit_is_not_misclassified_as_too_large(
    path: str,
) -> None:
    """The guard permits exactly the configured byte count."""

    client = build_client(max_body_bytes=128)
    response = client.post(
        path,
        content=b" " * 128,
        headers={"content-type": "application/json"},
    )

    assert response.status_code != 413


@pytest.mark.parametrize("path", POST_PATHS)
def test_malformed_json_is_a_sanitized_bounded_response(path: str) -> None:
    """Invalid bytes never reach a workflow service or reflect body content."""

    client = build_client()
    response = client.post(
        path,
        content=b"\xffSECRET-DO-NOT-REFLECT",
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 400
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    CalculationApiErrorResponse.model_validate(response.json())


@pytest.mark.parametrize("path", POST_PATHS)
def test_duplicate_json_members_are_rejected_before_validation(
    path: str,
) -> None:
    """Ambiguous JSON objects fail closed across the complete DP boundary."""

    client = build_client()
    response = client.post(
        path,
        content=(
            b'{"operation":"first","operation":'
            b'"SECRET-DO-NOT-REFLECT"}'
        ),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == (
        "calculation_request_duplicate_member"
    )
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    CalculationApiErrorResponse.model_validate(response.json())


@pytest.mark.parametrize("path", ALL_PATHS)
def test_dp_flow_routes_reject_undeclared_query_parameters(
    path: str,
) -> None:
    """No route accepts an alternate query-driven execution contract."""

    client = build_client()
    if path in POST_PATHS:
        response = client.post(
            path + "?secret=SECRET-DO-NOT-REFLECT",
            json={},
        )
    else:
        response = client.get(
            path + "?secret=SECRET-DO-NOT-REFLECT"
        )

    assert response.status_code == 422
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    CalculationApiValidationErrorResponse.model_validate(response.json())


@pytest.mark.parametrize("path", GET_PATHS)
def test_catalogue_routes_are_read_only(client: TestClient, path: str) -> None:
    """Discovery routes cannot be used as mutation or execution endpoints."""

    assert client.post(path, json={}).status_code == 405
    assert client.put(path, json={}).status_code == 405
    assert client.delete(path).status_code == 405


@pytest.mark.parametrize("path", POST_PATHS)
def test_execution_routes_are_post_only(client: TestClient, path: str) -> None:
    """Execution and assessment routes cannot be invoked with GET or PUT."""

    assert client.get(path).status_code == 405
    assert client.put(path, json={}).status_code == 405
    assert client.delete(path).status_code == 405


def test_step99_does_not_expand_the_core_method_registry() -> None:
    """The direct DP API remains separate from the 26-method core engine."""

    assert len(ENGINEERING_METHOD_REGISTRATIONS) == 26


def test_main_application_registers_each_dp_route_once() -> None:
    """The production application exposes exactly the reviewed Step 99 set."""

    from app.main import app

    paths = app.openapi()["paths"]
    assert all(path in paths for path in ALL_PATHS)
    for path in ALL_PATHS:
        expected_method = "get" if path in GET_PATHS else "post"
        assert set(paths[path]) == {expected_method}


def test_public_api_exports_are_exact() -> None:
    """The API module does not accidentally publish internal helpers."""

    assert set(api_module.__all__) == {
        "DP_FLOW_API_PREFIX",
        "DP_FLOW_APPLICATION_ASSESSMENT_PATH",
        "DP_FLOW_CATALOGUE_PATH",
        "DP_FLOW_DESIGN_CASE_EVALUATION_PATH",
        "DP_FLOW_DESIGN_CASE_EXAMPLES_PATH",
        "DP_FLOW_EXECUTION_PATH",
        "DP_FLOW_KNOWLEDGE_LINKS_PATH",
        "DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH",
        "DPFlowRequestBodyLimitMiddleware",
        "DPFlowServiceDependency",
        "MAX_DP_FLOW_REQUEST_BYTES",
        "assess_dp_flow_application",
        "evaluate_dp_flow_design_case",
        "evaluate_stored_dp_flow_design_case",
        "execute_dp_flow_calculation",
        "get_dp_flow_catalogue",
        "get_dp_flow_service",
        "list_dp_flow_design_case_examples",
        "list_dp_flow_knowledge_links",
        "router",
    }
