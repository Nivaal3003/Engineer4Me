"""HTTP contract and transport-hardening tests for Step 102 control valves."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from app.api import control_valves as api_module
from app.api.calculations import (
    CalculationApiErrorResponse,
    CalculationApiRoute,
    CalculationApiValidationErrorResponse,
    CalculationRequestBodyLimitMiddleware,
)
from app.api.control_valves import (
    CONTROL_VALVE_CATALOGUE_PATH,
    CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH,
    CONTROL_VALVE_EXECUTION_PATH,
    CONTROL_VALVE_KNOWLEDGE_LINKS_PATH,
    MAX_CONTROL_VALVE_REQUEST_BYTES,
    ControlValveRequestBodyLimitMiddleware,
    get_control_valve_service,
    router,
)
from app.engineering.calculations.control_valve import (
    LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
    LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
    LiquidControlValvePressureState,
    LiquidControlValveProperties,
    LiquidControlValveSizingInput,
    TraceableLiquidValveFactors,
    ValveInstallationBasis,
    size_liquid_control_valve,
)
from app.engineering.calculations.control_valve_installed import (
    CONTROL_VALVE_INSTALLED_METHOD_VERSION,
    INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
    TraceableInstalledValveCandidate,
    TraceableTravelCapacityPoint,
)
from app.engineering.calculations.control_valve_workflow_models import (
    CONTROL_VALVE_API_CATALOGUE,
    CONTROL_VALVE_KNOWLEDGE_LINKS,
    ControlValveDesignCaseOutcome,
    ControlValveDesignCaseRequest,
    ControlValveExecutionOutcome,
    ControlValveOperatingPointInput,
    InstalledControlValveExecutionRequest,
    LiquidControlValveExecutionRequest,
    build_control_valve_attempt_fingerprint,
    build_control_valve_result_fingerprint,
)
from app.services.control_valve_service import (
    ControlValveService,
    ControlValveServiceError,
    ControlValveWorkflowInputError,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.test_calculation_control_valve_workflow import _compressible_request

GET_PATHS = (
    CONTROL_VALVE_CATALOGUE_PATH,
    CONTROL_VALVE_KNOWLEDGE_LINKS_PATH,
)
POST_PATHS = (
    CONTROL_VALVE_EXECUTION_PATH,
    CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH,
)
ALL_PATHS = GET_PATHS + POST_PATHS


def build_client(
    *,
    service: object | None = None,
    max_body_bytes: int = MAX_CONTROL_VALVE_REQUEST_BYTES,
    raise_server_exceptions: bool = True,
) -> TestClient:
    application = FastAPI()
    application.add_middleware(
        ControlValveRequestBodyLimitMiddleware,
        max_body_bytes=max_body_bytes,
    )
    application.include_router(router, prefix="/api/v1")
    if service is not None:
        application.dependency_overrides[get_control_valve_service] = lambda: service
    return TestClient(
        application,
        raise_server_exceptions=raise_server_exceptions,
    )


@pytest.fixture
def client() -> Iterator[TestClient]:
    with build_client() as isolated_client:
        yield isolated_client


def liquid_input(
    *,
    case_id: str = "CV-STEP102-ONE",
    flow_m3_h: float = 20.0,
) -> LiquidControlValveSizingInput:
    return LiquidControlValveSizingInput(
        case_id=case_id,
        actual_volumetric_flow_m3_h=flow_m3_h,
        volumetric_flow_basis="actual_at_inlet_conditions",
        flow_source_reference="controlled Step 102 design flow record",
        flow_condition_basis="actual liquid volume at the declared inlet state",
        properties=LiquidControlValveProperties(
            specific_gravity=1.0,
            flowing_temperature_k=293.15,
            vapor_pressure_absolute_pa=20_000.0,
            critical_pressure_absolute_pa=22_064_000.0,
            thermodynamic_pressure_basis="absolute",
            property_source_reference="controlled Step 102 property record",
            condition_basis="properties at the declared inlet state",
        ),
        pressure_state=LiquidControlValvePressureState(
            upstream_pressure_absolute_pa=1_000_000.0,
            downstream_pressure_absolute_pa=700_000.0,
            pressure_basis="absolute",
            pressure_source_reference="controlled Step 102 pressure record",
            condition_basis="simultaneous steady operating pressures",
        ),
        factors=TraceableLiquidValveFactors(
            installation_basis=ValveInstallationBasis.BARE_VALVE,
            bare_valve_pressure_recovery_factor=0.9,
            source_reference="controlled Step 102 liquid factor record",
            applicable_conditions=(
                "exact valve candidate trim travel direction and bare-valve arrangement"
            ),
            supplied_by="competent control-valve engineer",
        ),
        outlet_inside_diameter_m=0.15,
        outlet_diameter_source_reference="controlled downstream pipe record",
        fluid_phase="liquid",
        rheology="newtonian",
        turbulent_flow_confirmed=True,
        incompressible_flow_confirmed=True,
        single_phase_inlet_confirmed=True,
        suspended_solids_absent_confirmed=True,
    )


def liquid_execution_request() -> LiquidControlValveExecutionRequest:
    return LiquidControlValveExecutionRequest(
        operation="liquid_sizing",
        method_id=LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
        method_version=LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
        sizing_input=liquid_input(),
    )


def installed_execution_request() -> InstalledControlValveExecutionRequest:
    inputs = (
        liquid_input(case_id="CV-STEP102-MIN", flow_m3_h=10.0),
        liquid_input(case_id="CV-STEP102-NORMAL", flow_m3_h=20.0),
        liquid_input(case_id="CV-STEP102-MAX", flow_m3_h=30.0),
    )
    results = tuple(size_liquid_control_valve(item) for item in inputs)
    candidate = TraceableInstalledValveCandidate(
        candidate_id="CALLER-CANDIDATE-STEP102",
        trim_id="CALLER-TRIM-STEP102",
        installation_context_id="CALLER-INSTALLATION-STEP102",
        flow_direction="flow to open",
        capacity_curve=(
            TraceableTravelCapacityPoint(
                travel_percent=10.0,
                available_cv=results[0].required_cv / 2.0,
            ),
            TraceableTravelCapacityPoint(
                travel_percent=20.0,
                available_cv=results[0].required_cv,
            ),
            TraceableTravelCapacityPoint(
                travel_percent=40.0,
                available_cv=results[1].required_cv,
            ),
            TraceableTravelCapacityPoint(
                travel_percent=60.0,
                available_cv=results[2].required_cv,
            ),
            TraceableTravelCapacityPoint(
                travel_percent=100.0,
                available_cv=results[2].required_cv * 2.0,
            ),
        ),
        minimum_controllable_travel_percent=15.0,
        maximum_recommended_travel_percent=90.0,
        declared_inherent_rangeability=50.0,
        maximum_factor_travel_mismatch_percent=1.0,
        interpolation_basis="caller_supplied_piecewise_linear",
        source_reference="controlled caller candidate curve record",
        applicable_conditions="exact candidate trim direction and installation context",
        supplied_by="competent control-valve engineer",
    )
    points = tuple(
        ControlValveOperatingPointInput(sizing_input=item) for item in inputs
    )
    return InstalledControlValveExecutionRequest(
        operation="installed_screen",
        method_id=INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
        method_version=CONTROL_VALVE_INSTALLED_METHOD_VERSION,
        screen_id="CV-STEP102-INSTALLED-SCREEN",
        candidate=candidate,
        minimum_case=points[0],
        normal_case=points[1],
        maximum_case=points[2],
        candidate_binding_confirmed=True,
        candidate_binding_source_reference=(
            "controlled caller candidate binding record Step 102"
        ),
    )


def design_case_request() -> ControlValveDesignCaseRequest:
    return ControlValveDesignCaseRequest(
        design_case_id="CV-STEP102-DESIGN",
        revision=1,
        title="Step 102 liquid control-valve design case",
        service_description=(
            "Controlled three-case liquid service for preliminary candidate screening."
        ),
        installed_execution_request=installed_execution_request(),
    )


def test_control_valve_routes_reuse_reviewed_transport_boundaries() -> None:
    assert MAX_CONTROL_VALVE_REQUEST_BYTES == 512 * 1024
    assert issubclass(
        ControlValveRequestBodyLimitMiddleware,
        CalculationRequestBodyLimitMiddleware,
    )
    assert len(router.routes) == 4
    assert all(isinstance(route, CalculationApiRoute) for route in router.routes)


def test_catalogue_and_links_are_bounded_inert_metadata(
    client: TestClient,
) -> None:
    catalogue = client.get(CONTROL_VALVE_CATALOGUE_PATH)
    assert catalogue.status_code == 200
    assert len(catalogue.json()) == 3
    assert all(item["executable"] is True for item in catalogue.json())
    assert all(
        item["manufacturer_factors_derived"] is False
        and item["manufacturer_selection_performed"] is False
        and item["standards_conformity_claimed"] is False
        for item in catalogue.json()
    )

    links = client.get(CONTROL_VALVE_KNOWLEDGE_LINKS_PATH)
    assert links.status_code == 200
    assert len(links.json()) == len(CONTROL_VALVE_KNOWLEDGE_LINKS) == 3
    assert all(item["retrieval_mode"] == "inert_metadata_only" for item in links.json())
    assert all(item["network_access_performed"] is False for item in links.json())
    assert all(item["executable"] is False for item in links.json())
    assert all(item["conformity_evidence"] is False for item in links.json())


def test_exact_liquid_execution_is_typed_and_reproducible(
    client: TestClient,
) -> None:
    request = liquid_execution_request()
    first = client.post(
        CONTROL_VALVE_EXECUTION_PATH,
        json=request.model_dump(mode="json"),
    )
    second = client.post(
        CONTROL_VALVE_EXECUTION_PATH,
        json=request.model_dump(mode="json"),
    )

    assert first.status_code == second.status_code == 200
    outcome = ControlValveExecutionOutcome.model_validate(first.json())
    repeated = ControlValveExecutionOutcome.model_validate(second.json())
    assert outcome.normalized_request == request
    assert outcome.trace == repeated.trace
    assert outcome.result == repeated.result
    assert outcome.selection_ready is False
    assert outcome.manufacturer_selection_performed is False
    assert outcome.exact_product_selected is False
    assert outcome.sound_pressure_level_predicted is False
    assert outcome.standards_conformity_claimed is False


class MismatchedResponseService(ControlValveService):
    """Return valid outcomes for requests other than the inbound request."""

    def execute(self, request: object) -> ControlValveExecutionOutcome:
        del request
        alternate = LiquidControlValveExecutionRequest(
            operation="liquid_sizing",
            method_id=LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
            method_version=LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
            sizing_input=liquid_input(flow_m3_h=21.0),
        )
        return super().execute(alternate)

    def evaluate_design_case(
        self,
        request: object,
    ) -> ControlValveDesignCaseOutcome:
        del request
        alternate = design_case_request().model_copy(update={"revision": 2})
        return super().evaluate_design_case(alternate)


class MismatchedNestedResultService(ControlValveService):
    """Forge a result for another input while preserving the inbound request."""

    def execute(self, request: object) -> ControlValveExecutionOutcome:
        assert isinstance(request, LiquidControlValveExecutionRequest)
        legitimate = super().execute(request)
        alternate_request = request.model_copy(
            update={"sizing_input": liquid_input(flow_m3_h=21.0)}
        )
        alternate = super().execute(alternate_request)
        result_fingerprint = build_control_valve_result_fingerprint(
            request,
            alternate.result,
            legitimate.trace.knowledge_source_ids,
        )
        forged_trace = legitimate.trace.model_copy(
            update={
                "result_fingerprint": result_fingerprint,
                "attempt_fingerprint": build_control_valve_attempt_fingerprint(
                    legitimate.trace.normalized_input_fingerprint,
                    result_fingerprint,
                ),
            }
        )
        return legitimate.model_copy(
            update={"result": alternate.result, "trace": forged_trace}
        )


class ReorderedSafetyResponseService(ControlValveService):
    """Return forged trusted models with safety findings in reverse order."""

    def execute(self, request: object) -> ControlValveExecutionOutcome:
        outcome = super().execute(request)  # type: ignore[arg-type]
        return outcome.model_copy(
            update={"safety_findings": tuple(reversed(outcome.safety_findings))}
        )

    def evaluate_design_case(
        self,
        request: object,
    ) -> ControlValveDesignCaseOutcome:
        outcome = super().evaluate_design_case(request)  # type: ignore[arg-type]
        return outcome.model_copy(
            update={"safety_findings": tuple(reversed(outcome.safety_findings))}
        )


@pytest.mark.parametrize(
    ("path", "payload"),
    (
        (
            CONTROL_VALVE_EXECUTION_PATH,
            liquid_execution_request().model_dump(mode="json"),
        ),
        (
            CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH,
            design_case_request().model_dump(mode="json"),
        ),
    ),
    ids=("execute", "design-case"),
)
def test_post_responses_must_match_the_inbound_request(
    path: str,
    payload: dict[str, object],
) -> None:
    response = build_client(service=MismatchedResponseService()).post(
        path,
        json=payload,
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "control_valve_service_unavailable"
    )
    CalculationApiErrorResponse.model_validate(response.json())


def test_nested_result_for_another_input_fails_closed_at_http_boundary() -> None:
    response = build_client(service=MismatchedNestedResultService()).post(
        CONTROL_VALVE_EXECUTION_PATH,
        json=liquid_execution_request().model_dump(mode="json"),
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "control_valve_service_unavailable"
    )
    CalculationApiErrorResponse.model_validate(response.json())


@pytest.mark.parametrize(
    ("path", "payload"),
    (
        (
            CONTROL_VALVE_EXECUTION_PATH,
            installed_execution_request().model_dump(mode="json"),
        ),
        (
            CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH,
            design_case_request().model_dump(mode="json"),
        ),
    ),
    ids=("execute", "design-case"),
)
def test_reordered_trusted_safety_findings_fail_closed_at_http_boundary(
    path: str,
    payload: dict[str, object],
) -> None:
    response = build_client(service=ReorderedSafetyResponseService()).post(
        path,
        json=payload,
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "control_valve_service_unavailable"
    )
    CalculationApiErrorResponse.model_validate(response.json())


def test_valid_unsafe_design_case_is_http_200_and_safety_leading(
    client: TestClient,
) -> None:
    response = client.post(
        CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH,
        json=design_case_request().model_dump(mode="json"),
    )

    assert response.status_code == 200
    assert next(iter(response.json())) == "safety_findings"
    outcome = ControlValveDesignCaseOutcome.model_validate(response.json())
    assert outcome.disposition == "blocked"
    assert outcome.safety_findings
    assert outcome.safety_findings[0].severity == "blocking"
    assert {finding.code for finding in outcome.safety_findings} >= {
        "liquid_factor_binding_unverified"
    }
    assert outcome.selection_ready is False
    assert outcome.manufacturer_declared_best is False
    assert outcome.final_brand_selection == "user_decision_required"
    assert outcome.approved_for_project_use is False
    assert outcome.sound_pressure_level_predicted is False
    assert outcome.standards_conformity_claimed is False


@pytest.mark.parametrize(
    "execution_request",
    (_compressible_request(), installed_execution_request()),
    ids=("compressible", "installed-screen"),
)
def test_remaining_exact_execution_variants_cross_the_http_boundary(
    client: TestClient,
    execution_request: object,
) -> None:
    response = client.post(
        CONTROL_VALVE_EXECUTION_PATH,
        json=execution_request.model_dump(mode="json"),  # type: ignore[attr-defined]
    )
    assert response.status_code == 200
    outcome = ControlValveExecutionOutcome.model_validate(response.json())
    assert outcome.normalized_request == execution_request


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("method_version", "9.9.9"),
        ("method_id", "official.iec.60534-2-1"),
        ("operation", "manufacturer_selection"),
    ),
)
def test_nonexact_or_inert_operations_cannot_execute(
    client: TestClient,
    field: str,
    value: str,
) -> None:
    payload = liquid_execution_request().model_dump(mode="json")
    payload[field] = value
    response = client.post(CONTROL_VALVE_EXECUTION_PATH, json=payload)
    assert response.status_code == 422
    CalculationApiValidationErrorResponse.model_validate(response.json())


def test_installed_api_accepts_raw_inputs_only(client: TestClient) -> None:
    payload = installed_execution_request().model_dump(mode="json")
    payload["sizing_results"] = [{"private": "SECRET-CALLER-CREATED-RESULT"}]

    response = client.post(CONTROL_VALVE_EXECUTION_PATH, json=payload)

    assert response.status_code == 422
    assert "SECRET-CALLER-CREATED-RESULT" not in response.text
    CalculationApiValidationErrorResponse.model_validate(response.json())


@pytest.mark.parametrize("path", POST_PATHS)
def test_declared_oversized_bodies_are_rejected(path: str) -> None:
    client = build_client(max_body_bytes=128)
    response = client.post(
        path,
        content=b'{"unknown":"' + (b"x" * 256) + b'"}',
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == ("control_valve_request_too_large")
    CalculationApiErrorResponse.model_validate(response.json())


@pytest.mark.parametrize("path", POST_PATHS)
def test_exact_body_limit_is_permitted(path: str) -> None:
    client = build_client(max_body_bytes=128)
    response = client.post(
        path,
        content=b" " * 128,
        headers={"content-type": "application/json"},
    )
    assert response.status_code != 413


@pytest.mark.parametrize("path", POST_PATHS)
def test_chunked_body_overflow_is_rejected_during_receive(path: str) -> None:
    client = build_client(max_body_bytes=128)

    def chunks() -> Iterator[bytes]:
        yield b'{"unknown":"'
        yield b"x" * 256
        yield b'"}'

    response = client.post(
        path,
        content=chunks(),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413


@pytest.mark.parametrize("path", POST_PATHS)
def test_body_limit_is_exactly_scoped_and_mount_safe(path: str) -> None:
    child = FastAPI()
    child.add_middleware(
        ControlValveRequestBodyLimitMiddleware,
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

    duplicate = client.post(
        path,
        content=(b'{"operation":"liquid_sizing","operation":"SECRET-DO-NOT-REFLECT"}'),
        headers={"content-type": "application/json"},
    )
    assert duplicate.status_code == 400
    assert duplicate.json()["detail"]["code"] == (
        "calculation_request_duplicate_member"
    )
    assert "SECRET-DO-NOT-REFLECT" not in duplicate.text


@pytest.mark.parametrize("path", ALL_PATHS)
def test_routes_reject_undeclared_query_parameters(path: str) -> None:
    client = build_client()
    if path in POST_PATHS:
        response = client.post(
            path + "?secret=SECRET-DO-NOT-REFLECT",
            json={},
        )
    else:
        response = client.get(path + "?secret=SECRET-DO-NOT-REFLECT")
    assert response.status_code == 422
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    CalculationApiValidationErrorResponse.model_validate(response.json())


class FailingService:
    def __init__(self, failure: Exception) -> None:
        self.failure = failure

    def get_catalogue(self) -> tuple[Any, ...]:
        raise self.failure

    def get_knowledge_links(self) -> tuple[Any, ...]:
        raise self.failure

    def execute(self, request: object) -> object:
        del request
        raise self.failure

    def evaluate_design_case(self, request: object) -> object:
        del request
        raise self.failure


def test_workflow_input_error_is_sanitized_422() -> None:
    client = build_client(service=FailingService(ControlValveWorkflowInputError()))
    for path, payload in (
        (
            CONTROL_VALVE_EXECUTION_PATH,
            liquid_execution_request().model_dump(mode="json"),
        ),
        (
            CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH,
            design_case_request().model_dump(mode="json"),
        ),
    ):
        response = client.post(path, json=payload)
        assert response.status_code == 422
        assert response.json()["detail"][0]["type"] == (
            "control_valve_input_error"
        )
        CalculationApiValidationErrorResponse.model_validate(response.json())


@pytest.mark.parametrize(
    ("failure", "path"),
    (
        (ControlValveServiceError(), CONTROL_VALVE_CATALOGUE_PATH),
        (
            RuntimeError("SECRET-PRIVATE-PROGRAMMER-DETAIL"),
            CONTROL_VALVE_KNOWLEDGE_LINKS_PATH,
        ),
    ),
)
def test_internal_failures_are_generic_nonreflective_503(
    failure: Exception,
    path: str,
) -> None:
    client = build_client(service=FailingService(failure))
    response = client.get(path)
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == ("control_valve_service_unavailable")
    assert "SECRET-PRIVATE-PROGRAMMER-DETAIL" not in response.text
    CalculationApiErrorResponse.model_validate(response.json())


class DriftedDiscoveryService(ControlValveService):
    """Return schema-valid discovery metadata outside the frozen contracts."""

    def get_catalogue(self) -> tuple[Any, ...]:
        changed = CONTROL_VALVE_API_CATALOGUE[0].model_copy(
            update={"title": "Schema-valid but unauthorized catalogue drift"}
        )
        return (changed, *CONTROL_VALVE_API_CATALOGUE, changed)

    def get_knowledge_links(self) -> tuple[Any, ...]:
        changed = CONTROL_VALVE_KNOWLEDGE_LINKS[0].model_copy(
            update={
                "public_url": (
                    "https://webstore.iec.ch/en/publication/unauthorized-drift"
                )
            }
        )
        return (changed, *CONTROL_VALVE_KNOWLEDGE_LINKS, changed)


@pytest.mark.parametrize("path", GET_PATHS)
def test_discovery_drift_and_duplicates_fail_closed(path: str) -> None:
    response = build_client(service=DriftedDiscoveryService()).get(path)
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "control_valve_service_unavailable"
    )
    CalculationApiErrorResponse.model_validate(response.json())


def test_openapi_freezes_exact_routes_and_typed_contracts() -> None:
    application = FastAPI()
    application.include_router(router, prefix="/api/v1")
    schema = application.openapi()
    paths = schema["paths"]
    assert set(paths) == set(ALL_PATHS)
    for path in GET_PATHS:
        assert set(paths[path]) == {"get"}
    for path in POST_PATHS:
        assert set(paths[path]) == {"post"}

    operations = {
        CONTROL_VALVE_CATALOGUE_PATH: (
            "getControlValveCatalogue",
            "Get control-valve catalogue",
        ),
        CONTROL_VALVE_KNOWLEDGE_LINKS_PATH: (
            "listControlValveKnowledgeLinks",
            "List control-valve knowledge links",
        ),
        CONTROL_VALVE_EXECUTION_PATH: (
            "executeControlValveCalculation",
            "Execute an exact control-valve calculation",
        ),
        CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH: (
            "evaluateControlValveDesignCase",
            "Evaluate a stateless control-valve design case",
        ),
    }
    for path, (operation_id, summary) in operations.items():
        verb = "get" if path in GET_PATHS else "post"
        operation = paths[path][verb]
        assert operation["operationId"] == operation_id
        assert operation["summary"] == summary
        assert set(operation["responses"]) == (
            {"200", "422", "503"}
            if verb == "get"
            else {"200", "400", "413", "422", "503"}
        )

    execution = paths[CONTROL_VALVE_EXECUTION_PATH]["post"]
    request_schema = execution["requestBody"]["content"]["application/json"]["schema"]
    assert request_schema["discriminator"]["propertyName"] == "operation"
    assert set(request_schema["discriminator"]["mapping"]) == {
        "liquid_sizing",
        "compressible_sizing",
        "installed_screen",
    }
    assert len(request_schema["oneOf"]) == 3
    assert execution["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ControlValveExecutionOutcome"
    }
    design_response = paths[CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH]["post"][
        "responses"
    ]["200"]
    assert design_response["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ControlValveDesignCaseOutcome"
    }
    for path in GET_PATHS:
        response_schema = paths[path]["get"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]
        assert response_schema["minItems"] == 3
        assert response_schema["maxItems"] == 3
    public_url_schema = schema["components"]["schemas"][
        "ControlValveKnowledgeLink"
    ]["properties"]["public_url"]
    assert public_url_schema["maxLength"] == 500


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


def test_main_application_registers_each_route_once() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    for path in ALL_PATHS:
        assert path in paths
        expected_method = "get" if path in GET_PATHS else "post"
        assert set(paths[path]) == {expected_method}
        matching_routes = tuple(
            nested_route
            for included_route in app.routes
            for nested_route in getattr(
                getattr(included_route, "original_router", None),
                "routes",
                (),
            )
            if (
                getattr(
                    getattr(included_route, "include_context", None),
                    "prefix",
                    "",
                )
                + getattr(nested_route, "path", "")
                == path
            )
            and expected_method.upper()
            in getattr(nested_route, "methods", set())
        )
        assert len(matching_routes) == 1
    assert (
        sum(getattr(route, "original_router", None) is router for route in app.routes)
        == 1
    )


def test_public_api_exports_are_exact() -> None:
    assert set(api_module.__all__) == {
        "CONTROL_VALVE_API_PREFIX",
        "CONTROL_VALVE_CATALOGUE_PATH",
        "CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH",
        "CONTROL_VALVE_EXECUTION_PATH",
        "CONTROL_VALVE_KNOWLEDGE_LINKS_PATH",
        "ControlValveRequestBodyLimitMiddleware",
        "ControlValveCatalogueResponse",
        "ControlValveKnowledgeLinksResponse",
        "ControlValveServiceDependency",
        "MAX_CONTROL_VALVE_REQUEST_BYTES",
        "evaluate_control_valve_design_case",
        "execute_control_valve_calculation",
        "get_control_valve_catalogue",
        "get_control_valve_service",
        "list_control_valve_knowledge_links",
        "router",
    }


def test_strict_requests_are_bounded_and_nonreflective(
    client: TestClient,
) -> None:
    payload = liquid_execution_request().model_dump(mode="json")
    payload["SECRET-DO-NOT-REFLECT"] = "SECRET-DO-NOT-REFLECT"
    response = client.post(CONTROL_VALVE_EXECUTION_PATH, json=payload)
    assert response.status_code == 422
    assert "SECRET-DO-NOT-REFLECT" not in response.text

    payload = liquid_execution_request().model_dump(mode="json")
    payload["sizing_input"]["actual_volumetric_flow_m3_h"] = True
    response = client.post(CONTROL_VALVE_EXECUTION_PATH, json=payload)
    assert response.status_code == 422

    payload = liquid_execution_request().model_dump(mode="json")
    payload["sizing_input"]["actual_volumetric_flow_m3_h"] = int("9" * 400)
    response = client.post(CONTROL_VALVE_EXECUTION_PATH, json=payload)
    assert response.status_code == 422

    payload = liquid_execution_request().model_dump(mode="json")
    payload["sizing_input"]["actual_volumetric_flow_m3_h"] = float("nan")
    response = client.post(
        CONTROL_VALVE_EXECUTION_PATH,
        content=json.dumps(payload, allow_nan=True),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422
    assert "NaN" not in response.text
