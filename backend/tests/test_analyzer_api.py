"""HTTP contract and transport-hardening tests for Step 107 analyzers."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import analyzers as api_module
from app.api.analyzers import (
    ANALYZER_APPLICATION_ASSESSMENT_PATH,
    ANALYZER_CATALOGUE_PATH,
    ANALYZER_DESIGN_CASE_EXAMPLES_PATH,
    ANALYZER_KNOWLEDGE_LINKS_PATH,
    MAX_ANALYZER_REQUEST_BYTES,
    AnalyzerRequestBodyLimitMiddleware,
    get_analyzer_application_service,
    router,
)
from app.api.calculations import (
    CalculationApiErrorResponse,
    CalculationApiRoute,
    CalculationApiValidationErrorResponse,
    CalculationRequestBodyLimitMiddleware,
)
from app.engineering.design.analyzer_assistant import (
    ANALYZER_TECHNOLOGY_CATALOGUE,
)
from app.engineering.design.analyzer_models import (
    AnalyzerApplicationRequest,
)
from app.engineering.design.analyzer_workflow_models import (
    ANALYZER_DESIGN_CASE_EXAMPLES,
    ANALYZER_KNOWLEDGE_LINKS,
    AnalyzerAssessmentEnvelope,
)
from app.services.analyzer_application_service import (
    DEFAULT_ANALYZER_APPLICATION_SERVICE,
    AnalyzerApplicationInputError,
    AnalyzerApplicationService,
    AnalyzerApplicationServiceError,
)

GET_PATHS = (
    ANALYZER_CATALOGUE_PATH,
    ANALYZER_KNOWLEDGE_LINKS_PATH,
    ANALYZER_DESIGN_CASE_EXAMPLES_PATH,
)
POST_PATHS = (ANALYZER_APPLICATION_ASSESSMENT_PATH,)
ALL_PATHS = GET_PATHS + POST_PATHS


def build_client(
    *,
    service: object | None = None,
    max_body_bytes: int = MAX_ANALYZER_REQUEST_BYTES,
    raise_server_exceptions: bool = True,
) -> TestClient:
    """Build an isolated analyzer API with an optional exact dependency."""

    application = FastAPI()
    application.add_middleware(
        AnalyzerRequestBodyLimitMiddleware,
        max_body_bytes=max_body_bytes,
    )
    application.include_router(router, prefix="/api/v1")
    if service is not None:
        application.dependency_overrides[get_analyzer_application_service] = lambda: (
            service
        )
    return TestClient(
        application,
        raise_server_exceptions=raise_server_exceptions,
    )


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Yield one isolated client backed by the reviewed default service."""

    with build_client() as isolated_client:
        yield isolated_client


def _example(example_id: str):
    return next(
        item for item in ANALYZER_DESIGN_CASE_EXAMPLES if item.example_id == example_id
    )


def _post_example(client: TestClient, example_id: str):
    example = _example(example_id)
    return client.post(
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
        json=example.request.model_dump(mode="json"),
    )


def test_transport_router_and_default_dependency_are_frozen() -> None:
    """The API reuses reviewed boundaries and exposes exactly four routes."""

    assert get_analyzer_application_service() is (DEFAULT_ANALYZER_APPLICATION_SERVICE)
    assert MAX_ANALYZER_REQUEST_BYTES == 512 * 1024
    assert issubclass(
        AnalyzerRequestBodyLimitMiddleware,
        CalculationRequestBodyLimitMiddleware,
    )
    assert len(router.routes) == 4
    assert all(isinstance(route, CalculationApiRoute) for route in router.routes)


def test_three_get_routes_return_exact_bounded_controlled_fixtures(
    client: TestClient,
) -> None:
    """Catalogue, knowledge, and examples remain exact inert fixtures."""

    catalogue = client.get(ANALYZER_CATALOGUE_PATH)
    links = client.get(ANALYZER_KNOWLEDGE_LINKS_PATH)
    examples = client.get(ANALYZER_DESIGN_CASE_EXAMPLES_PATH)

    assert catalogue.status_code == links.status_code == examples.status_code == 200
    assert len(catalogue.json()) == 21
    assert len(links.json()) == 5
    assert len(examples.json()) == 9
    assert catalogue.json() == [
        item.model_dump(mode="json") for item in ANALYZER_TECHNOLOGY_CATALOGUE
    ]
    assert links.json() == [
        item.model_dump(mode="json") for item in ANALYZER_KNOWLEDGE_LINKS
    ]
    assert examples.json() == [
        item.model_dump(mode="json") for item in ANALYZER_DESIGN_CASE_EXAMPLES
    ]

    assert all(
        item["vendor_neutral"] is True
        and item["manufacturer_model_selected"] is False
        and item["final_suitability_claimed"] is False
        for item in catalogue.json()
    )
    assert all(
        item["retrieval_mode"] == "inert_metadata_only"
        and item["network_access_performed"] is False
        and item["protected_content_embedded"] is False
        and item["approved_as_equation_or_factor_source"] is False
        and item["approved_as_product_or_selection_source"] is False
        and item["manufacturer_data_present"] is False
        and item["executable"] is False
        and item["conformity_evidence"] is False
        and item["standards_conformity_claimed"] is False
        and item["final_design_approval_granted"] is False
        for item in links.json()
    )
    assert all(
        item["illustrative_only"] is True
        and item["persisted"] is False
        and item["approved_for_project_use"] is False
        and item["manufacturer_or_model_selected"] is False
        and item["final_brand_selection"] == "user_decision_required"
        and item["standards_conformity_claimed"] is False
        and item["final_design_approval_granted"] is False
        for item in examples.json()
    )


def test_design_examples_are_sorted_and_cover_required_outcomes(
    client: TestClient,
) -> None:
    """The nine examples visibly include plausible, blocked, and unknown work."""

    body = client.get(ANALYZER_DESIGN_CASE_EXAMPLES_PATH).json()
    example_ids = [item["example_id"] for item in body]
    assert example_ids == sorted(example_ids)
    assert {
        "completed_with_warnings",
        "blocked",
        "insufficient_input",
    }.issubset({item["expected_status"] for item in body})
    assert {
        scenario["disposition"]
        for item in body
        for scenario in item["expected_scenarios"]
    }.issuperset({"plausible", "blocked", "insufficient_information"})


@pytest.mark.parametrize(
    ("example_id", "expected_status", "expected_disposition"),
    (
        (
            "analyzer-example.liquid-ph",
            "completed_with_warnings",
            "plausible",
        ),
        (
            "analyzer-example.corrosive-liquid-blocked",
            "blocked",
            "blocked",
        ),
        (
            "analyzer-example.insufficient-input",
            "insufficient_input",
            "insufficient_information",
        ),
    ),
)
def test_plausible_blocked_and_insufficient_engineering_are_http_200(
    client: TestClient,
    example_id: str,
    expected_status: str,
    expected_disposition: str,
) -> None:
    """Valid engineering outcomes never masquerade as transport failures."""

    response = _post_example(client, example_id)

    assert response.status_code == 200
    envelope = AnalyzerAssessmentEnvelope.model_validate(response.json())
    assert envelope.assessment.status.value == expected_status
    assert expected_disposition in {
        item.disposition.value for item in envelope.assessment.scenarios
    }
    assert len(envelope.knowledge_links) == 5
    assert envelope.external_knowledge_access_performed is False
    assert envelope.persistence_performed is False
    assert envelope.manufacturer_or_model_selection_performed is False
    assert envelope.standards_conformity_claimed is False
    assert envelope.final_design_approval_granted is False
    assert envelope.assessment.manufacturer_selection_performed is False
    assert envelope.assessment.model_selection_performed is False
    assert envelope.assessment.product_selected is False
    assert envelope.assessment.final_brand_selection == "user_decision_required"
    assert envelope.assessment.approved_for_project_use is False


def test_all_nine_reviewed_requests_cross_the_http_boundary(client: TestClient) -> None:
    """Every compiled example remains a valid stateless assessment request."""

    for example in ANALYZER_DESIGN_CASE_EXAMPLES:
        response = client.post(
            ANALYZER_APPLICATION_ASSESSMENT_PATH,
            json=example.request.model_dump(mode="json"),
        )
        assert response.status_code == 200
        outcome = AnalyzerAssessmentEnvelope.model_validate(response.json())
        assert outcome.assessment.request == example.request
        assert outcome.assessment.status is example.expected_status
        assert (
            outcome.assessment.assessment_fingerprint
            == example.expected_assessment_fingerprint
        )


def test_assessment_is_byte_deterministic_across_repeated_requests(
    client: TestClient,
) -> None:
    """The stateless integration envelope is reproducible in full."""

    example = _example("analyzer-example.process-gas-oxygen")
    payload = example.request.model_dump(mode="json")
    first = client.post(ANALYZER_APPLICATION_ASSESSMENT_PATH, json=payload)
    second = client.post(ANALYZER_APPLICATION_ASSESSMENT_PATH, json=payload)

    assert first.status_code == second.status_code == 200
    assert first.content == second.content
    assert (
        first.json()["integration_fingerprint"]
        == (second.json()["integration_fingerprint"])
    )


class RecordingService:
    """Dependency double that records each exact public API operation."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, object | None]] = []

    def get_catalogue(self):
        self.calls.append(("catalogue", None))
        return DEFAULT_ANALYZER_APPLICATION_SERVICE.get_catalogue()

    def get_knowledge_links(self):
        self.calls.append(("knowledge_links", None))
        return DEFAULT_ANALYZER_APPLICATION_SERVICE.get_knowledge_links()

    def get_design_case_examples(self):
        self.calls.append(("examples", None))
        return DEFAULT_ANALYZER_APPLICATION_SERVICE.get_design_case_examples()

    def assess(self, request: AnalyzerApplicationRequest):
        self.calls.append(("assess", request))
        return DEFAULT_ANALYZER_APPLICATION_SERVICE.assess(request)


def test_dependency_override_receives_typed_request_and_all_operations() -> None:
    """FastAPI dependency injection is exact and the request is typed."""

    service = RecordingService()
    client = build_client(service=service)
    example = _example("analyzer-example.liquid-ph")

    assert client.get(ANALYZER_CATALOGUE_PATH).status_code == 200
    assert client.get(ANALYZER_KNOWLEDGE_LINKS_PATH).status_code == 200
    assert client.get(ANALYZER_DESIGN_CASE_EXAMPLES_PATH).status_code == 200
    assert (
        client.post(
            ANALYZER_APPLICATION_ASSESSMENT_PATH,
            json=example.request.model_dump(mode="json"),
        ).status_code
        == 200
    )
    assert tuple(name for name, _ in service.calls) == (
        "catalogue",
        "knowledge_links",
        "examples",
        "assess",
    )
    assert isinstance(service.calls[-1][1], AnalyzerApplicationRequest)
    assert service.calls[-1][1] == example.request


def test_low_level_decode_failure_is_a_fixed_sanitized_400() -> None:
    """Rejected non-UTF-8 bytes cannot be reflected in the response."""

    response = build_client().post(
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
        content=b"\xffSECRET-DO-NOT-REFLECT",
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": {
            "code": "calculation_request_parse_error",
            "message": ("The calculation request body could not be decoded or parsed."),
        }
    }
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    CalculationApiErrorResponse.model_validate(response.json())


def test_duplicate_json_members_are_a_fixed_sanitized_400() -> None:
    """Ambiguous top-level and nested request members are rejected early."""

    for body in (
        b'{"request_id":"valid-id","request_id":"SECRET-DO-NOT-REFLECT"}',
        (
            b'{"request_id":"valid-id","safety":{'
            b'"hazardous_area":"no",'
            b'"hazardous_area":"SECRET-DO-NOT-REFLECT"}}'
        ),
    ):
        response = build_client().post(
            ANALYZER_APPLICATION_ASSESSMENT_PATH,
            content=body,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == (
            "calculation_request_duplicate_member"
        )
        assert "SECRET-DO-NOT-REFLECT" not in response.text
        CalculationApiErrorResponse.model_validate(response.json())


@pytest.mark.parametrize(
    "payload",
    (
        None,
        [],
        {"request_id": " padded-id "},
        {"request_id": "valid-id", "application_kind": "SECRET-VALUE"},
        {"request_id": "valid-id", "SECRET-FIELD": "SECRET-DO-NOT-REFLECT"},
        {"request_id": False},
    ),
)
def test_invalid_unknown_and_extra_request_values_are_sanitized_422(
    payload: Any,
) -> None:
    """Closed strict request models never echo rejected values."""

    response = build_client().post(
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
        json=payload,
    )

    assert response.status_code == 422
    assert "SECRET" not in response.text
    assert "input" not in response.text
    validated = CalculationApiValidationErrorResponse.model_validate(response.json())
    assert validated.detail
    assert all(
        issue.msg == "The request value is invalid." for issue in validated.detail
    )


def test_many_extra_fields_produce_one_bounded_nonreflective_422() -> None:
    """An adversarial request cannot create an unbounded error document."""

    payload = {"request_id": "valid-id"}
    payload.update({f"SECRET-DO-NOT-REFLECT-{index}": index for index in range(100)})

    response = build_client().post(
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
        json=payload,
    )

    assert response.status_code == 422
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    issues = response.json()["detail"]
    assert len(issues) == 64
    assert issues[-1] == {
        "type": "request_validation_truncated",
        "loc": ["request"],
        "msg": (
            "Additional invalid request values were omitted from this bounded response."
        ),
    }
    CalculationApiValidationErrorResponse.model_validate(response.json())


@pytest.mark.parametrize("path", ALL_PATHS)
def test_routes_reject_unknown_and_duplicate_query_parameters(path: str) -> None:
    """The four fixed routes have no query-string contract."""

    service = RecordingService()
    client = build_client(service=service)
    response = (
        client.get(path + "?secret=SECRET-QUERY&secret=again")
        if path in GET_PATHS
        else client.post(
            path + "?secret=SECRET-QUERY&secret=again",
            json={"request_id": "valid-id"},
        )
    )

    assert response.status_code == 422
    assert "SECRET-QUERY" not in response.text
    validated = CalculationApiValidationErrorResponse.model_validate(response.json())
    assert tuple(issue.type for issue in validated.detail) == (
        "unexpected_query_parameter",
        "duplicate_query_parameter",
    )
    assert service.calls == []


def test_declared_oversized_assessment_body_is_rejected_before_parsing() -> None:
    """Content-Length overflow receives the analyzer-specific 413 envelope."""

    service = RecordingService()
    client = build_client(service=service, max_body_bytes=128)
    response = client.post(
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
        content=b'{"unknown":"' + (b"x" * 256) + b'"}',
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json() == {
        "detail": {
            "code": "analyzer_request_too_large",
            "message": ("The analyzer request exceeds the permitted transport size."),
        }
    }
    CalculationApiErrorResponse.model_validate(response.json())
    assert service.calls == []


def test_streamed_oversized_assessment_body_is_rejected_during_receive() -> None:
    """Chunked transfer cannot bypass the analyzer transport bound."""

    service = RecordingService()
    client = build_client(service=service, max_body_bytes=128)

    def chunks() -> Iterator[bytes]:
        yield b'{"unknown":"'
        yield b"x" * 256
        yield b'"}'

    response = client.post(
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
        content=chunks(),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "analyzer_request_too_large"
    assert service.calls == []


def test_body_limit_is_inclusive_and_scoped_to_the_exact_post_path() -> None:
    """The fixed bound accepts its edge and ignores unrelated routes/verbs."""

    client = build_client()
    exact_body = b'{"request_id":"valid-id"}'
    exact_body += b" " * (MAX_ANALYZER_REQUEST_BYTES - len(exact_body))

    accepted = client.post(
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
        content=exact_body,
        headers={"content-type": "application/json"},
    )
    rejected = client.post(
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
        content=exact_body + b" ",
        headers={"content-type": "application/json"},
    )
    unrelated = client.post(
        "/api/v1/unrelated",
        content=exact_body + b" ",
        headers={"content-type": "application/json"},
    )
    wrong_verb = client.put(
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
        content=exact_body + b" ",
        headers={"content-type": "application/json"},
    )

    assert accepted.status_code == 200
    assert rejected.status_code == 413
    assert unrelated.status_code == 404
    assert wrong_verb.status_code == 405


def test_body_limit_uses_route_path_when_application_is_mounted() -> None:
    """An ASGI mount prefix cannot bypass the dedicated body guard."""

    child = FastAPI()
    child.add_middleware(
        AnalyzerRequestBodyLimitMiddleware,
        max_body_bytes=128,
    )
    child.include_router(router, prefix="/api/v1")
    parent = FastAPI()
    parent.mount("/engineering", child)
    client = TestClient(parent)

    response = client.post(
        "/engineering" + ANALYZER_APPLICATION_ASSESSMENT_PATH,
        content=b'{"unknown":"' + (b"x" * 256) + b'"}',
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "analyzer_request_too_large"


class FailingService:
    """Raise one configured trusted-boundary failure from every operation."""

    def __init__(self, failure: Exception) -> None:
        self.failure = failure

    def get_catalogue(self):
        raise self.failure

    def get_knowledge_links(self):
        raise self.failure

    def get_design_case_examples(self):
        raise self.failure

    def assess(self, request: object):
        del request
        raise self.failure


@pytest.mark.parametrize("path", ALL_PATHS)
def test_trusted_failures_are_fixed_nonreflective_503(path: str) -> None:
    """Private service exceptions expose only the public unavailable error."""

    client = build_client(
        service=FailingService(RuntimeError("SECRET-PRIVATE-SERVICE-DETAIL"))
    )
    response = (
        client.get(path)
        if path in GET_PATHS
        else client.post(path, json={"request_id": "valid-id"})
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": {
            "code": "analyzer_service_unavailable",
            "message": ("Analyzer application assessment is temporarily unavailable."),
        }
    }
    assert "SECRET-PRIVATE-SERVICE-DETAIL" not in response.text
    CalculationApiErrorResponse.model_validate(response.json())


def test_service_input_error_is_translated_to_sanitized_422() -> None:
    """The service's typed input signal remains distinct from availability."""

    client = build_client(service=FailingService(AnalyzerApplicationInputError()))
    response = client.post(
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
        json={"request_id": "valid-id"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == [
        {
            "type": "analyzer_input_error",
            "loc": ["body"],
            "msg": "The analyzer application request is invalid.",
        }
    ]
    CalculationApiValidationErrorResponse.model_validate(response.json())


class DriftedDiscoveryService(AnalyzerApplicationService):
    """Return schema-valid but unauthorized discovery fixtures."""

    def get_catalogue(self):
        changed = ANALYZER_TECHNOLOGY_CATALOGUE[0].model_copy(
            update={"title": "Unauthorized schema-valid catalogue drift"}
        )
        return (changed, *ANALYZER_TECHNOLOGY_CATALOGUE[1:])

    def get_knowledge_links(self):
        changed = ANALYZER_KNOWLEDGE_LINKS[0].model_copy(
            update={"retrieval_mode": "inert_metadata_only"}
        )
        return (changed, *reversed(ANALYZER_KNOWLEDGE_LINKS[1:]))

    def get_design_case_examples(self):
        changed = ANALYZER_DESIGN_CASE_EXAMPLES[0].model_copy(
            update={"title": "Unauthorized schema-valid example drift"}
        )
        return (changed, *ANALYZER_DESIGN_CASE_EXAMPLES[1:])


@pytest.mark.parametrize("path", GET_PATHS)
def test_discovery_output_drift_fails_closed_as_503(path: str) -> None:
    """Only the exact controlled 21/5/9 fixtures may cross the boundary."""

    response = build_client(service=DriftedDiscoveryService()).get(path)

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "analyzer_service_unavailable"


class ForgedAssessmentService(AnalyzerApplicationService):
    """Return a frozen envelope whose fingerprint bypassed model validation."""

    def assess(self, request: AnalyzerApplicationRequest):
        outcome = super().assess(request)
        return outcome.model_copy(update={"integration_fingerprint": "0" * 64})


def test_forged_assessment_output_is_revalidated_and_rejected_as_503() -> None:
    """The HTTP boundary does not trust frozen model-copy output."""

    response = build_client(service=ForgedAssessmentService()).post(
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
        json=_example("analyzer-example.liquid-ph").request.model_dump(mode="json"),
    )

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "analyzer_service_unavailable"


class MismatchedAssessmentService(AnalyzerApplicationService):
    """Return a valid envelope bound to a different request."""

    def assess(self, request: AnalyzerApplicationRequest):
        del request
        return super().assess(_example("analyzer-example.process-gas-oxygen").request)


def test_assessment_output_for_another_request_fails_closed_as_503() -> None:
    """A valid envelope must still bind the exact inbound request."""

    response = build_client(service=MismatchedAssessmentService()).post(
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
        json=_example("analyzer-example.liquid-ph").request.model_dump(mode="json"),
    )

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "analyzer_service_unavailable"


@pytest.mark.parametrize("path", GET_PATHS)
def test_discovery_routes_are_get_only(path: str) -> None:
    """Read-only discovery endpoints reject mutation verbs."""

    client = build_client()
    assert client.post(path, json={}).status_code == 405
    assert client.put(path, json={}).status_code == 405
    assert client.patch(path, json={}).status_code == 405
    assert client.delete(path).status_code == 405


def test_assessment_route_is_post_only() -> None:
    """The stateless assessment endpoint rejects every wrong verb."""

    client = build_client()
    assert client.get(ANALYZER_APPLICATION_ASSESSMENT_PATH).status_code == 405
    assert client.put(ANALYZER_APPLICATION_ASSESSMENT_PATH, json={}).status_code == 405
    assert (
        client.patch(ANALYZER_APPLICATION_ASSESSMENT_PATH, json={}).status_code == 405
    )
    assert client.delete(ANALYZER_APPLICATION_ASSESSMENT_PATH).status_code == 405


def test_openapi_freezes_four_exact_routes_and_typed_contracts() -> None:
    """OpenAPI exposes the exact Step 107 surface and bounded responses."""

    application = FastAPI()
    application.include_router(router, prefix="/api/v1")
    document = application.openapi()
    paths = document["paths"]

    assert set(paths) == set(ALL_PATHS)
    expected = {
        ANALYZER_CATALOGUE_PATH: (
            "get",
            "getAnalyzerTechnologyCatalogue",
            "Get analyzer technology catalogue",
        ),
        ANALYZER_KNOWLEDGE_LINKS_PATH: (
            "get",
            "listAnalyzerKnowledgeLinks",
            "List analyzer knowledge links",
        ),
        ANALYZER_DESIGN_CASE_EXAMPLES_PATH: (
            "get",
            "listAnalyzerDesignCaseExamples",
            "List analyzer design-case examples",
        ),
        ANALYZER_APPLICATION_ASSESSMENT_PATH: (
            "post",
            "assessAnalyzerApplication",
            "Assess analyzer application",
        ),
    }
    for path, (verb, operation_id, summary) in expected.items():
        assert set(paths[path]) == {verb}
        operation = paths[path][verb]
        assert operation["operationId"] == operation_id
        assert operation["summary"] == summary
        assert operation["tags"] == ["Engineering Calculations"]
        assert set(operation["responses"]) == (
            {"200", "422", "503"}
            if verb == "get"
            else {"200", "400", "413", "422", "503"}
        )

    for path, expected_size in (
        (ANALYZER_CATALOGUE_PATH, 21),
        (ANALYZER_KNOWLEDGE_LINKS_PATH, 5),
        (ANALYZER_DESIGN_CASE_EXAMPLES_PATH, 9),
    ):
        schema = paths[path]["get"]["responses"]["200"]["content"]["application/json"][
            "schema"
        ]
        assert (schema["minItems"], schema["maxItems"]) == (
            expected_size,
            expected_size,
        )

    operation = paths[ANALYZER_APPLICATION_ASSESSMENT_PATH]["post"]
    assert operation["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/AnalyzerApplicationRequest"
    }
    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/AnalyzerAssessmentEnvelope"
    }
    assert operation["responses"]["422"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/CalculationApiValidationErrorResponse"
    }


def test_openapi_request_and_response_models_are_closed_and_vendor_neutral() -> None:
    """Public schemas do not expose executors, voice, or persistence controls."""

    document = build_client().app.openapi()  # type: ignore[union-attr]
    schemas = document["components"]["schemas"]
    request_schema = schemas["AnalyzerApplicationRequest"]
    response_schema = schemas["AnalyzerAssessmentEnvelope"]
    serialized = str(
        {"request": request_schema, "response": response_schema}
    ).casefold()

    assert request_schema["additionalProperties"] is False
    assert response_schema["additionalProperties"] is False
    assert "manufacturer_id" not in serialized
    assert "product_id" not in serialized
    assert "model_number" not in serialized
    assert "executor" not in serialized
    assert "voice" not in serialized
    assert "database" not in serialized


def test_main_application_registers_routes_and_middleware_once() -> None:
    """The production application exposes each route behind one body guard."""

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
            item.cls is AnalyzerRequestBodyLimitMiddleware
            for item in app.user_middleware
        )
        == 1
    )


@pytest.mark.parametrize("max_body_bytes", (True, 0, -1, 1.5))
def test_body_limit_rejects_invalid_configuration(max_body_bytes: Any) -> None:
    """The specialized guard retains the inherited positive-int invariant."""

    with pytest.raises(ValueError, match="positive integer"):
        AnalyzerRequestBodyLimitMiddleware(
            FastAPI(),
            max_body_bytes=max_body_bytes,
        )


def test_public_api_exports_are_exact() -> None:
    """Only reviewed analyzer HTTP boundary names are publicly advertised."""

    assert api_module.__all__ == [
        "ANALYZER_API_PREFIX",
        "ANALYZER_APPLICATION_ASSESSMENT_PATH",
        "ANALYZER_CATALOGUE_PATH",
        "ANALYZER_DESIGN_CASE_EXAMPLES_PATH",
        "ANALYZER_KNOWLEDGE_LINKS_PATH",
        "MAX_ANALYZER_REQUEST_BYTES",
        "AnalyzerApplicationServiceDependency",
        "AnalyzerCatalogueResponse",
        "AnalyzerDesignCaseExamplesResponse",
        "AnalyzerKnowledgeLinksResponse",
        "AnalyzerRequestBodyLimitMiddleware",
        "assess_analyzer_application",
        "get_analyzer_application_service",
        "get_analyzer_technology_catalogue",
        "list_analyzer_design_case_examples",
        "list_analyzer_knowledge_links",
        "router",
    ]


def test_public_service_error_has_no_private_constructor_message() -> None:
    """The documented unavailable signal itself is fixed and sanitized."""

    error = AnalyzerApplicationServiceError()
    assert error.code == "analyzer_service_unavailable"
    assert str(error) == ("The controlled analyzer application service is unavailable.")
