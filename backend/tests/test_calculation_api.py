"""API contract tests for controlled engineering calculations."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.calculations import (
    CALCULATION_EXECUTION_PATH,
    MAX_CALCULATION_REQUEST_BYTES,
    MAX_CALCULATION_VALIDATION_ISSUES,
    CalculationApiErrorResponse,
    CalculationApiValidationErrorResponse,
    CalculationExecutionRequest,
    CalculationMethodCatalogue,
    CalculationMethodSummary,
    CalculationMethodVersionCatalogue,
    CalculationRequestBodyLimitMiddleware,
    get_calculation_service,
    router,
)
from app.engineering.calculations.engine import (
    CalculationEngine,
    CalculationEvidenceError,
)
from app.engineering.calculations.level import ENGINEERING_METHOD_REGISTRY
from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
    EngineCompatibility,
    MethodExecutionContext,
    MethodExecutionOutcome,
)
from app.engineering.calculations.models import (
    CalculationInput,
    CalculationRequest,
    CalculationResult,
    CalculationStatus,
    EngineeringQuantity,
    InputOrigin,
    MethodLifecycleStatus,
    MissingCalculationInput,
)
from app.engineering.calculations.registry import (
    MAX_REGISTERED_METHODS,
    CalculationMethodRegistry,
    InvalidMethodLookupError,
    MethodCalculationTypeError,
    MethodRegistration,
    UnknownMethodError,
    UnknownMethodVersionError,
)
from app.engineering.calculations.units import QuantityKind
from app.main import app, root
from app.services.calculation_service import (
    CalculationEvidenceResolutionError,
    CalculationService,
    CalculationServiceError,
)

METHODS_PATH = "/api/v1/calculations/methods"
VERSIONS_PATH = "/api/v1/calculations/methods/versions"
DEFINITION_PATH = "/api/v1/calculations/methods/definition"
EXECUTE_PATH = "/api/v1/calculations/execute"
LEVEL_APPLICATION_PATH = (
    "/api/v1/calculations/level/application-assessment"
)
DP_FLOW_CATALOGUE_PATH = "/api/v1/calculations/dp-flow/catalogue"
DP_FLOW_KNOWLEDGE_LINKS_PATH = (
    "/api/v1/calculations/dp-flow/knowledge-links"
)
DP_FLOW_DESIGN_CASE_EXAMPLES_PATH = (
    "/api/v1/calculations/dp-flow/design-case-examples"
)
DP_FLOW_EXECUTION_PATH = "/api/v1/calculations/dp-flow/execute"
DP_FLOW_APPLICATION_ASSESSMENT_PATH = (
    "/api/v1/calculations/dp-flow/application-assessment"
)
DP_FLOW_DESIGN_CASE_EVALUATION_PATH = (
    "/api/v1/calculations/dp-flow/design-cases/evaluate"
)
DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH = (
    "/api/v1/calculations/dp-flow/design-cases/stored/evaluate"
)
CONTROL_VALVE_CATALOGUE_PATH = (
    "/api/v1/calculations/control-valves/catalogue"
)
CONTROL_VALVE_KNOWLEDGE_LINKS_PATH = (
    "/api/v1/calculations/control-valves/knowledge-links"
)
CONTROL_VALVE_EXECUTION_PATH = (
    "/api/v1/calculations/control-valves/execute"
)
CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH = (
    "/api/v1/calculations/control-valves/design-cases/evaluate"
)
PRESSURE_RELIEF_CATALOGUE_PATH = (
    "/api/v1/calculations/pressure-relief/catalogue"
)
PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH = (
    "/api/v1/calculations/pressure-relief/knowledge-links"
)
PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH = (
    "/api/v1/calculations/pressure-relief/readiness-assessment"
)
PRESSURE_RELIEF_EXECUTION_PATH = (
    "/api/v1/calculations/pressure-relief/execute"
)
ANALYZER_CATALOGUE_PATH = "/api/v1/calculations/analyzers/catalogue"
ANALYZER_KNOWLEDGE_LINKS_PATH = (
    "/api/v1/calculations/analyzers/knowledge-links"
)
ANALYZER_DESIGN_CASE_EXAMPLES_PATH = (
    "/api/v1/calculations/analyzers/design-case-examples"
)
ANALYZER_APPLICATION_ASSESSMENT_PATH = (
    "/api/v1/calculations/analyzers/application-assessment"
)


def api_integration_executor(
    context: MethodExecutionContext,
    iteration_controller: object,
) -> MethodExecutionOutcome:
    """Fail if the draft integration method reaches executable code."""

    del context
    del iteration_controller
    raise AssertionError("A draft integration method must not execute.")


def build_definition(
    *,
    method_id: str = "general/identity",
    method_version: str = "1.0.0",
    calculation_type: str = "general.identity",
    lifecycle_status: MethodLifecycleStatus = MethodLifecycleStatus.DRAFT,
    minimum_engine_version: str = "1.0.0",
    maximum_engine_version: str = "2.0.0",
) -> CalculationMethodDefinition:
    """Build compact valid metadata for transport tests."""

    return CalculationMethodDefinition(
        method_id=method_id,
        method_version=method_version,
        calculation_type=calculation_type,
        title=f"Identity method {method_version}",
        description=(
            "Controlled metadata used to test exact method discovery."
        ),
        implementation_owner="Engineer4Me calculation test team",
        lifecycle_status=lifecycle_status,
        engine_compatibility=EngineCompatibility(
            minimum_version=minimum_engine_version,
            maximum_exclusive_version=maximum_engine_version,
        ),
        required_reviewer_competency=(
            "Competent instrumentation engineer"
        ),
        disclaimer=(
            "Test metadata does not replace competent engineering review."
        ),
    )


def build_request(
    *,
    request_id: UUID | None = None,
    method_id: str = "general/identity",
    method_version: str = "1.0.0",
    calculation_type: str = "general.identity",
) -> CalculationRequest:
    """Build one valid empty-input execution request."""

    return CalculationRequest(
        request_id=request_id or uuid4(),
        calculation_type=calculation_type,
        method_id=method_id,
        method_version=method_version,
    )


def build_result(
    *,
    request_id: UUID,
    method_id: str = "general/identity",
    method_version: str = "1.0.0",
    calculation_type: str = "general.identity",
) -> CalculationResult:
    """Build a controlled insufficient-input result for HTTP 200 tests."""

    return CalculationResult(
        request_id=request_id,
        calculation_type=calculation_type,
        method_id=method_id,
        method_version=method_version,
        method_lifecycle_status=MethodLifecycleStatus.DRAFT,
        engine_version="1.0.0",
        status=CalculationStatus.INSUFFICIENT_INPUT,
        result_fingerprint="a" * 64,
        missing_inputs=(
            MissingCalculationInput(
                input_id="input.required",
                name="Required engineering input",
                reason="The required engineering input was not supplied.",
            ),
        ),
        required_reviewer_competency=(
            "Competent instrumentation engineer"
        ),
    )


class StubCalculationService:
    """Small recording double for one API application."""

    def __init__(
        self,
        *,
        definitions: tuple[CalculationMethodDefinition, ...] = (),
        versions: tuple[str, ...] = ("1.0.0",),
        result: CalculationResult | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.engine_version = "1.0.0"
        self.method_count = len(definitions)
        self.definitions = definitions
        self.versions = versions
        self.result = result
        self.failure = failure
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def _record(
        self,
        operation: str,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self.calls.append((operation, args, kwargs))
        if self.failure is not None:
            raise self.failure

    def discover_methods(
        self,
        calculation_type: str | None = None,
    ) -> tuple[CalculationMethodDefinition, ...]:
        self._record(
            "discover_methods",
            calculation_type=calculation_type,
        )
        if calculation_type is None:
            return self.definitions
        return tuple(
            definition
            for definition in self.definitions
            if definition.calculation_type == calculation_type
        )

    def available_versions(self, method_id: str) -> tuple[str, ...]:
        self._record("available_versions", method_id)
        return self.versions

    def get_method(
        self,
        method_id: str,
        method_version: str,
        calculation_type: str | None = None,
    ) -> CalculationMethodDefinition:
        self._record(
            "get_method",
            method_id,
            method_version,
            calculation_type=calculation_type,
        )
        return self.definitions[0]

    def execute(self, request: CalculationRequest) -> CalculationResult:
        self._record("execute", request)
        if self.result is None:
            raise AssertionError("The stub execution result was not set.")
        return self.result


def build_client(
    service: StubCalculationService | CalculationService,
    *,
    raise_server_exceptions: bool = True,
    max_body_bytes: int = MAX_CALCULATION_REQUEST_BYTES,
) -> TestClient:
    """Build an isolated calculation API with an exact dependency override."""

    application = FastAPI()
    application.add_middleware(
        CalculationRequestBodyLimitMiddleware,
        max_body_bytes=max_body_bytes,
    )
    application.include_router(router, prefix="/api/v1")
    application.dependency_overrides[get_calculation_service] = (
        lambda: service
    )
    return TestClient(
        application,
        raise_server_exceptions=raise_server_exceptions,
    )


@pytest.fixture
def full_app_client() -> Iterator[TestClient]:
    """Expose the full application without leaking dependency overrides."""

    service = StubCalculationService()
    app.dependency_overrides[get_calculation_service] = lambda: service
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_calculation_service, None)


def test_application_registers_phase_7_calculation_api(
    full_app_client: TestClient,
) -> None:
    """The main app, root payload, and OpenAPI expose version 0.10.0."""

    assert app.version == "0.10.0"
    assert root()["version"] == "0.10.0"
    assert app.openapi()["info"]["version"] == "0.10.0"
    assert full_app_client.get("/").json()["version"] == "0.10.0"

    paths = set(app.openapi()["paths"])
    assert {
        METHODS_PATH,
        VERSIONS_PATH,
        DEFINITION_PATH,
        EXECUTE_PATH,
        LEVEL_APPLICATION_PATH,
        DP_FLOW_CATALOGUE_PATH,
        DP_FLOW_KNOWLEDGE_LINKS_PATH,
        DP_FLOW_DESIGN_CASE_EXAMPLES_PATH,
        DP_FLOW_EXECUTION_PATH,
        DP_FLOW_APPLICATION_ASSESSMENT_PATH,
        DP_FLOW_DESIGN_CASE_EVALUATION_PATH,
        DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH,
        CONTROL_VALVE_CATALOGUE_PATH,
        CONTROL_VALVE_KNOWLEDGE_LINKS_PATH,
        CONTROL_VALVE_EXECUTION_PATH,
        CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH,
        PRESSURE_RELIEF_CATALOGUE_PATH,
        PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH,
        PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH,
        PRESSURE_RELIEF_EXECUTION_PATH,
        ANALYZER_CATALOGUE_PATH,
        ANALYZER_KNOWLEDGE_LINKS_PATH,
        ANALYZER_DESIGN_CASE_EXAMPLES_PATH,
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
        "/api/v1/ingestion/jobs/{job_id}/execute",
        "/api/v1/knowledge",
    }.issubset(paths)


def test_openapi_freezes_exact_calculation_operations() -> None:
    """The twenty-four Phase 7 paths expose only their intended methods."""

    paths = app.openapi()["paths"]
    calculation_paths = {
        path
        for path in paths
        if path.startswith("/api/v1/calculations")
    }

    assert calculation_paths == {
        METHODS_PATH,
        VERSIONS_PATH,
        DEFINITION_PATH,
        EXECUTE_PATH,
        LEVEL_APPLICATION_PATH,
        DP_FLOW_CATALOGUE_PATH,
        DP_FLOW_KNOWLEDGE_LINKS_PATH,
        DP_FLOW_DESIGN_CASE_EXAMPLES_PATH,
        DP_FLOW_EXECUTION_PATH,
        DP_FLOW_APPLICATION_ASSESSMENT_PATH,
        DP_FLOW_DESIGN_CASE_EVALUATION_PATH,
        DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH,
        CONTROL_VALVE_CATALOGUE_PATH,
        CONTROL_VALVE_KNOWLEDGE_LINKS_PATH,
        CONTROL_VALVE_EXECUTION_PATH,
        CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH,
        PRESSURE_RELIEF_CATALOGUE_PATH,
        PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH,
        PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH,
        PRESSURE_RELIEF_EXECUTION_PATH,
        ANALYZER_CATALOGUE_PATH,
        ANALYZER_KNOWLEDGE_LINKS_PATH,
        ANALYZER_DESIGN_CASE_EXAMPLES_PATH,
        ANALYZER_APPLICATION_ASSESSMENT_PATH,
    }
    assert set(paths[METHODS_PATH]) == {"get"}
    assert set(paths[VERSIONS_PATH]) == {"get"}
    assert set(paths[DEFINITION_PATH]) == {"get"}
    assert set(paths[EXECUTE_PATH]) == {"post"}
    assert set(paths[LEVEL_APPLICATION_PATH]) == {"post"}
    assert set(paths[DP_FLOW_CATALOGUE_PATH]) == {"get"}
    assert set(paths[DP_FLOW_KNOWLEDGE_LINKS_PATH]) == {"get"}
    assert set(paths[DP_FLOW_DESIGN_CASE_EXAMPLES_PATH]) == {"get"}
    assert set(paths[DP_FLOW_EXECUTION_PATH]) == {"post"}
    assert set(paths[DP_FLOW_APPLICATION_ASSESSMENT_PATH]) == {"post"}
    assert set(paths[DP_FLOW_DESIGN_CASE_EVALUATION_PATH]) == {"post"}
    assert set(paths[DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH]) == {
        "post"
    }
    assert set(paths[CONTROL_VALVE_CATALOGUE_PATH]) == {"get"}
    assert set(paths[CONTROL_VALVE_KNOWLEDGE_LINKS_PATH]) == {"get"}
    assert set(paths[CONTROL_VALVE_EXECUTION_PATH]) == {"post"}
    assert set(paths[CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH]) == {
        "post"
    }
    assert set(paths[PRESSURE_RELIEF_CATALOGUE_PATH]) == {"get"}
    assert set(paths[PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH]) == {"get"}
    assert set(paths[PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH]) == {"post"}
    assert set(paths[PRESSURE_RELIEF_EXECUTION_PATH]) == {"post"}
    assert set(paths[ANALYZER_CATALOGUE_PATH]) == {"get"}
    assert set(paths[ANALYZER_KNOWLEDGE_LINKS_PATH]) == {"get"}
    assert set(paths[ANALYZER_DESIGN_CASE_EXAMPLES_PATH]) == {"get"}
    assert set(paths[ANALYZER_APPLICATION_ASSESSMENT_PATH]) == {"post"}

    assert paths[METHODS_PATH]["get"]["summary"] == (
        "List controlled calculation methods"
    )
    assert paths[VERSIONS_PATH]["get"]["summary"] == (
        "List exact calculation method versions"
    )
    assert paths[DEFINITION_PATH]["get"]["summary"] == (
        "Get exact calculation method metadata"
    )
    assert paths[EXECUTE_PATH]["post"]["summary"] == (
        "Execute an exact controlled calculation method"
    )
    assert paths[LEVEL_APPLICATION_PATH]["post"]["summary"] == (
        "Assess level measurement application"
    )
    assert paths[DP_FLOW_CATALOGUE_PATH]["get"]["summary"] == (
        "Get DP-flow catalogue"
    )
    assert paths[DP_FLOW_KNOWLEDGE_LINKS_PATH]["get"]["summary"] == (
        "List DP-flow knowledge links"
    )
    assert paths[DP_FLOW_DESIGN_CASE_EXAMPLES_PATH]["get"]["summary"] == (
        "List DP-flow design-case examples"
    )
    assert paths[DP_FLOW_EXECUTION_PATH]["post"]["summary"] == (
        "Execute an exact DP-flow calculation"
    )
    assert paths[DP_FLOW_APPLICATION_ASSESSMENT_PATH]["post"]["summary"] == (
        "Assess DP-flow application"
    )
    assert paths[DP_FLOW_DESIGN_CASE_EVALUATION_PATH]["post"]["summary"] == (
        "Evaluate a stateless DP-flow design case"
    )
    assert paths[DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH]["post"][
        "summary"
    ] == "Evaluate an exact stored DP-flow design case"
    assert paths[CONTROL_VALVE_CATALOGUE_PATH]["get"]["summary"] == (
        "Get control-valve catalogue"
    )
    assert paths[CONTROL_VALVE_KNOWLEDGE_LINKS_PATH]["get"]["summary"] == (
        "List control-valve knowledge links"
    )
    assert paths[CONTROL_VALVE_EXECUTION_PATH]["post"]["summary"] == (
        "Execute an exact control-valve calculation"
    )
    assert paths[CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH]["post"][
        "summary"
    ] == "Evaluate a stateless control-valve design case"
    assert paths[PRESSURE_RELIEF_CATALOGUE_PATH]["get"]["summary"] == (
        "Get pressure-relief catalogue"
    )
    assert paths[PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH]["get"]["summary"] == (
        "List pressure-relief knowledge links"
    )
    assert paths[PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH]["post"][
        "summary"
    ] == "Assess pressure-relief readiness"
    assert paths[PRESSURE_RELIEF_EXECUTION_PATH]["post"]["summary"] == (
        "Execute an exact pressure-relief calculation"
    )
    assert paths[ANALYZER_CATALOGUE_PATH]["get"]["summary"] == (
        "Get analyzer technology catalogue"
    )
    assert paths[ANALYZER_KNOWLEDGE_LINKS_PATH]["get"]["summary"] == (
        "List analyzer knowledge links"
    )
    assert paths[ANALYZER_DESIGN_CASE_EXAMPLES_PATH]["get"]["summary"] == (
        "List analyzer design-case examples"
    )
    assert paths[ANALYZER_APPLICATION_ASSESSMENT_PATH]["post"]["summary"] == (
        "Assess analyzer application"
    )
    assert paths[METHODS_PATH]["get"]["operationId"] == (
        "listCalculationMethods"
    )
    assert paths[VERSIONS_PATH]["get"]["operationId"] == (
        "listCalculationMethodVersions"
    )
    assert paths[DEFINITION_PATH]["get"]["operationId"] == (
        "getCalculationMethodDefinition"
    )
    assert paths[EXECUTE_PATH]["post"]["operationId"] == (
        "executeCalculation"
    )
    assert paths[LEVEL_APPLICATION_PATH]["post"]["operationId"] == (
        "assessLevelApplication"
    )
    assert paths[DP_FLOW_CATALOGUE_PATH]["get"]["operationId"] == (
        "getDPFlowCatalogue"
    )
    assert paths[DP_FLOW_KNOWLEDGE_LINKS_PATH]["get"]["operationId"] == (
        "listDPFlowKnowledgeLinks"
    )
    assert paths[DP_FLOW_DESIGN_CASE_EXAMPLES_PATH]["get"]["operationId"] == (
        "listDPFlowDesignCaseExamples"
    )
    assert paths[DP_FLOW_EXECUTION_PATH]["post"]["operationId"] == (
        "executeDPFlowCalculation"
    )
    assert paths[DP_FLOW_APPLICATION_ASSESSMENT_PATH]["post"][
        "operationId"
    ] == "assessDPFlowApplication"
    assert paths[DP_FLOW_DESIGN_CASE_EVALUATION_PATH]["post"][
        "operationId"
    ] == "evaluateDPFlowDesignCase"
    assert paths[DP_FLOW_STORED_DESIGN_CASE_EVALUATION_PATH]["post"][
        "operationId"
    ] == "evaluateStoredDPFlowDesignCase"
    assert paths[CONTROL_VALVE_CATALOGUE_PATH]["get"]["operationId"] == (
        "getControlValveCatalogue"
    )
    assert paths[CONTROL_VALVE_KNOWLEDGE_LINKS_PATH]["get"][
        "operationId"
    ] == "listControlValveKnowledgeLinks"
    assert paths[CONTROL_VALVE_EXECUTION_PATH]["post"]["operationId"] == (
        "executeControlValveCalculation"
    )
    assert paths[CONTROL_VALVE_DESIGN_CASE_EVALUATION_PATH]["post"][
        "operationId"
    ] == "evaluateControlValveDesignCase"
    assert paths[PRESSURE_RELIEF_CATALOGUE_PATH]["get"]["operationId"] == (
        "getPressureReliefCatalogue"
    )
    assert paths[PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH]["get"][
        "operationId"
    ] == "listPressureReliefKnowledgeLinks"
    assert paths[PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH]["post"][
        "operationId"
    ] == "assessPressureReliefReadiness"
    assert paths[PRESSURE_RELIEF_EXECUTION_PATH]["post"]["operationId"] == (
        "executePressureReliefCalculation"
    )
    assert paths[ANALYZER_CATALOGUE_PATH]["get"]["operationId"] == (
        "getAnalyzerTechnologyCatalogue"
    )
    assert paths[ANALYZER_KNOWLEDGE_LINKS_PATH]["get"]["operationId"] == (
        "listAnalyzerKnowledgeLinks"
    )
    assert paths[ANALYZER_DESIGN_CASE_EXAMPLES_PATH]["get"]["operationId"] == (
        "listAnalyzerDesignCaseExamples"
    )
    assert paths[ANALYZER_APPLICATION_ASSESSMENT_PATH]["post"]["operationId"] == (
        "assessAnalyzerApplication"
    )


def test_openapi_documents_exact_response_contracts() -> None:
    """Success and translated error statuses are explicit and stable."""

    paths = app.openapi()["paths"]

    assert set(paths[METHODS_PATH]["get"]["responses"]) == {"200", "422"}
    assert set(paths[VERSIONS_PATH]["get"]["responses"]) == {
        "200",
        "404",
        "422",
    }
    assert set(paths[DEFINITION_PATH]["get"]["responses"]) == {
        "200",
        "404",
        "422",
    }
    assert set(paths[EXECUTE_PATH]["post"]["responses"]) == {
        "200",
        "400",
        "404",
        "413",
        "422",
        "503",
    }
    assert set(paths[LEVEL_APPLICATION_PATH]["post"]["responses"]) == {
        "200",
        "400",
        "413",
        "422",
        "503",
    }
    assert set(paths[PRESSURE_RELIEF_CATALOGUE_PATH]["get"]["responses"]) == {
        "200",
        "422",
        "503",
    }
    assert set(
        paths[PRESSURE_RELIEF_KNOWLEDGE_LINKS_PATH]["get"]["responses"]
    ) == {
        "200",
        "422",
        "503",
    }
    for pressure_relief_path in (
        PRESSURE_RELIEF_READINESS_ASSESSMENT_PATH,
        PRESSURE_RELIEF_EXECUTION_PATH,
    ):
        assert set(paths[pressure_relief_path]["post"]["responses"]) == {
            "200",
            "400",
            "413",
            "422",
            "503",
        }
    for analyzer_path in (
        ANALYZER_CATALOGUE_PATH,
        ANALYZER_KNOWLEDGE_LINKS_PATH,
        ANALYZER_DESIGN_CASE_EXAMPLES_PATH,
    ):
        assert set(paths[analyzer_path]["get"]["responses"]) == {
            "200",
            "422",
            "503",
        }
    assert set(paths[ANALYZER_APPLICATION_ASSESSMENT_PATH]["post"]["responses"]) == {
        "200",
        "400",
        "413",
        "422",
        "503",
    }

    execute_response = paths[EXECUTE_PATH]["post"]["responses"]["200"]
    assert execute_response["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/CalculationExecutionResult"
    }
    assessment_response = paths[LEVEL_APPLICATION_PATH]["post"]["responses"][
        "200"
    ]
    assert assessment_response["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/LevelApplicationAssessment"
    }
    analyzer_response = paths[ANALYZER_APPLICATION_ASSESSMENT_PATH]["post"][
        "responses"
    ]["200"]
    assert analyzer_response["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/AnalyzerAssessmentEnvelope"
    }
    definition_response = paths[DEFINITION_PATH]["get"]["responses"]["200"]
    assert definition_response["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/CalculationMethodMetadata"
    }
    assert paths[EXECUTE_PATH]["post"]["responses"]["422"]["content"][
        "application/json"
    ]["schema"] == {
        "$ref": "#/components/schemas/"
        "CalculationApiValidationErrorResponse"
    }


def test_openapi_request_is_typed_and_excludes_trusted_evidence() -> None:
    """Clients receive only the CalculationRequest execution boundary."""

    operation = app.openapi()["paths"][EXECUTE_PATH]["post"]
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert schema == {
        "$ref": "#/components/schemas/CalculationExecutionRequest"
    }

    request_schema = app.openapi()["components"]["schemas"][
        "CalculationExecutionRequest"
    ]
    assert request_schema["additionalProperties"] is False
    assert "evidence" not in request_schema["properties"]
    assert "trusted_execution_evidence" not in request_schema["properties"]
    version_pattern = request_schema["properties"]["method_version"][
        "pattern"
    ]
    assert re.fullmatch(version_pattern, "1.0.0")
    assert re.fullmatch(version_pattern, "1.2.3-rc.1+reviewed.5")
    assert re.fullmatch(version_pattern, "1.0") is None
    assert re.fullmatch(version_pattern, "01.0.0") is None
    assert re.fullmatch(version_pattern, "1.0.0-01") is None


def test_openapi_bounds_discovery_and_request_collections() -> None:
    """OpenAPI records the registry and calculation-model collection limits."""

    schemas = app.openapi()["components"]["schemas"]

    assert schemas["CalculationMethodCatalogue"]["properties"]["methods"][
        "maxItems"
    ] == MAX_REGISTERED_METHODS
    assert schemas["CalculationExecutionRequest"]["properties"]["inputs"][
        "maxItems"
    ] == 256
    assert schemas["CalculationExecutionRequest"]["properties"]["assumptions"][
        "maxItems"
    ] == 128
    assert schemas["CalculationExecutionRequest"]["properties"]["options"][
        "maxItems"
    ] == 128
    assert schemas["CalculationExecutionRequest"]["properties"][
        "reference_ids"
    ][
        "maxItems"
    ] == 256
    assert schemas["CalculationApiValidationErrorResponse"]["properties"][
        "detail"
    ]["maxItems"] == MAX_CALCULATION_VALIDATION_ISSUES


@pytest.mark.parametrize(
    ("schema_name", "property_path"),
    [
        ("CalculationExecutionRequest", ("method_version",)),
        ("CalculationExecutionResult", ("method_version",)),
        ("CalculationMethodMetadata", ("method_version",)),
        ("CalculationMethodMetadata", ("superseded_by_version",)),
        ("CalculationMethodSummary", ("method_version",)),
        ("CalculationMethodVersionCatalogue", ("versions", "items")),
    ],
)
def test_openapi_exposes_canonical_method_version_schemas(
    schema_name: str,
    property_path: tuple[str, ...],
) -> None:
    """Every public method-version field advertises canonical SemVer."""

    schema: dict[str, Any] = app.openapi()["components"]["schemas"][
        schema_name
    ]["properties"][property_path[0]]
    for component in property_path[1:]:
        schema = schema[component]

    if "anyOf" in schema:
        schema = next(
            item
            for item in schema["anyOf"]
            if item.get("type") == "string"
        )

    version_pattern = schema["pattern"]
    assert re.fullmatch(version_pattern, "1.0.0")
    assert re.fullmatch(version_pattern, "1.2.3-rc.1+reviewed.5")
    assert re.fullmatch(version_pattern, "1.0") is None
    assert re.fullmatch(version_pattern, "01.0.0") is None
    assert re.fullmatch(version_pattern, "1.0.0-01") is None


def test_default_production_discovery_lists_engineering_methods() -> None:
    """Step 95 exposes the reviewed general and level method catalogue."""

    client = TestClient(app)
    response = client.get(METHODS_PATH)

    assert response.status_code == 200
    body = response.json()
    assert body["engine_version"] == "1.0.0"
    assert body["method_count"] == 26
    assert tuple(
        method["method_id"]
        for method in body["methods"]
    ) == ENGINEERING_METHOD_REGISTRY.method_ids
    assert all(
        method["method_version"] == "1.0.0"
        and method["lifecycle_status"] == "approved"
        and method["execution_eligible"] is True
        and "implementation" not in method
        for method in body["methods"]
    )


def test_default_api_executes_registered_level_reference_vector() -> None:
    """The production HTTP path executes an exact Step 95 level method."""

    definition = ENGINEERING_METHOD_REGISTRY.resolve(
        "level.hydrostatic.column-pressure",
        "1.0.0",
    )
    specifications = {
        item.input_id: item
        for item in definition.input_specifications
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
    request = CalculationRequest(
        request_id=uuid4(),
        calculation_type=definition.calculation_type,
        method_id=definition.method_id,
        method_version=definition.method_version,
        inputs=tuple(
            CalculationInput(
                input_id=input_id,
                name=specifications[input_id].name,
                origin=InputOrigin.USER_SUPPLIED,
                quantity=EngineeringQuantity(
                    quantity_kind=kind.value,
                    value=value,
                    unit=unit,
                ),
            )
            for input_id, kind, value, unit in values
        ),
    )

    response = TestClient(app).post(
        EXECUTE_PATH,
        json=request.model_dump(mode="json"),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["method_id"] == "level.hydrostatic.column-pressure"
    output = next(
        item
        for item in payload["outputs"]
        if item["output_id"] == "differential-pressure"
    )
    assert output["quantity"]["value"] == pytest.approx(34_261.493105)
    assert output["quantity"]["unit"] == "Pa"


def test_method_listing_returns_compact_eligibility_metadata() -> None:
    """Discovery exposes metadata counts but no implementation object."""

    compatible = build_definition()
    incompatible = build_definition(
        method_id="general/legacy",
        method_version="2.0.0",
        calculation_type="general.legacy",
        minimum_engine_version="2.0.0",
        maximum_engine_version="3.0.0",
    )
    service = StubCalculationService(
        definitions=(compatible, incompatible),
    )
    client = build_client(service)

    response = client.get(METHODS_PATH)

    assert response.status_code == 200
    payload = response.json()
    assert payload["engine_version"] == "1.0.0"
    assert payload["method_count"] == 2
    assert payload["methods"][0] == {
        "method_id": "general/identity",
        "method_version": "1.0.0",
        "calculation_type": "general.identity",
        "title": "Identity method 1.0.0",
        "lifecycle_status": "draft",
        "engine_compatible": True,
        "execution_eligible": False,
        "input_count": 0,
        "option_count": 0,
        "reference_count": 0,
    }
    assert payload["methods"][1]["engine_compatible"] is False
    assert "implementation" not in response.text
    assert service.calls == [
        (
            "discover_methods",
            (),
            {"calculation_type": None},
        )
    ]


def test_method_listing_forwards_exact_type_filter() -> None:
    """A bounded optional type filter reaches the service unchanged."""

    definition = build_definition()
    service = StubCalculationService(definitions=(definition,))
    client = build_client(service)

    response = client.get(
        METHODS_PATH,
        params={"calculation_type": "general.identity"},
    )

    assert response.status_code == 200
    assert response.json()["method_count"] == 1
    assert service.calls[-1] == (
        "discover_methods",
        (),
        {"calculation_type": "general.identity"},
    )


def test_version_listing_supports_method_ids_containing_slash() -> None:
    """Query-based exact lookup preserves every legal method identifier."""

    service = StubCalculationService(
        versions=("1.0.0", "1.1.0", "2.0.0"),
    )
    client = build_client(service)

    response = client.get(
        VERSIONS_PATH,
        params={"method_id": "level/dp/wet-leg"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "method_id": "level/dp/wet-leg",
        "version_count": 3,
        "versions": ["1.0.0", "1.1.0", "2.0.0"],
    }
    assert service.calls == [
        (
            "available_versions",
            ("level/dp/wet-leg",),
            {},
        )
    ]


def test_exact_definition_delegates_all_lookup_fields() -> None:
    """Metadata resolution never selects an implicit method version."""

    definition = build_definition()
    service = StubCalculationService(definitions=(definition,))
    client = build_client(service)

    response = client.get(
        DEFINITION_PATH,
        params={
            "method_id": "general/identity",
            "method_version": "1.0.0",
            "calculation_type": "general.identity",
        },
    )

    assert response.status_code == 200
    assert response.json()["method_id"] == "general/identity"
    assert response.json()["method_version"] == "1.0.0"
    assert service.calls == [
        (
            "get_method",
            ("general/identity", "1.0.0"),
            {"calculation_type": "general.identity"},
        )
    ]


def test_typed_execution_delegates_a_calculation_request() -> None:
    """A valid request reaches the service as the controlled model."""

    request = build_request()
    result = build_result(request_id=request.request_id)
    service = StubCalculationService(result=result)
    client = build_client(service)

    response = client.post(
        EXECUTE_PATH,
        json=request.model_dump(mode="json"),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "insufficient_input"
    assert response.json()["request_id"] == str(request.request_id)
    assert len(service.calls) == 1
    operation, arguments, keywords = service.calls[0]
    assert operation == "execute"
    assert keywords == {}
    assert len(arguments) == 1
    assert isinstance(arguments[0], CalculationRequest)
    assert isinstance(arguments[0], CalculationExecutionRequest)
    assert arguments[0].model_dump(mode="json") == request.model_dump(
        mode="json"
    )


def test_real_api_service_engine_path_returns_controlled_blocked_result(
) -> None:
    """The complete HTTP-to-engine path preserves typed domain outcomes."""

    definition = build_definition()
    registry = CalculationMethodRegistry(
        (
            MethodRegistration(
                definition=definition,
                implementation=api_integration_executor,
            ),
        )
    )
    service = CalculationService(
        engine=CalculationEngine(registry=registry),
    )
    client = build_client(service)
    request = build_request()

    response = client.post(
        EXECUTE_PATH,
        json=request.model_dump(mode="json"),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "blocked"
    assert payload["method_id"] == definition.method_id
    assert payload["method_version"] == definition.method_version
    assert payload["method_lifecycle_status"] == "draft"
    assert payload["outputs"] == []
    assert payload["findings"][0]["finding_id"] == (
        "engine.lifecycle-blocked"
    )


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    [
        (
            UnknownMethodError("private/method"),
            "unknown_method",
        ),
        (
            UnknownMethodVersionError("private/method", "9.9.9"),
            "unknown_method_version",
        ),
    ],
)
def test_unknown_method_errors_are_sanitized_404_responses(
    failure: Exception,
    expected_code: str,
) -> None:
    """Lookup details are not reflected from registry exception messages."""

    service = StubCalculationService(failure=failure)
    client = build_client(service)

    response = client.get(
        VERSIONS_PATH,
        params={"method_id": "general/identity"},
    )

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == expected_code
    assert "private" not in response.text
    CalculationApiErrorResponse.model_validate(response.json())


@pytest.mark.parametrize(
    ("failure", "expected_type", "expected_location"),
    [
        (
            InvalidMethodLookupError("private invalid lookup"),
            "invalid_method_lookup",
            ["query", "method_id"],
        ),
        (
            MethodCalculationTypeError(
                "general/identity",
                "1.0.0",
                "private.type",
            ),
            "method_calculation_type_mismatch",
            ["query", "calculation_type"],
        ),
    ],
)
def test_lookup_contract_errors_are_sanitized_422_responses(
    failure: Exception,
    expected_type: str,
    expected_location: list[str],
) -> None:
    """User-correctable lookup failures use validation-shaped responses."""

    definition = build_definition()
    service = StubCalculationService(
        definitions=(definition,),
        failure=failure,
    )
    client = build_client(service)

    response = client.get(
        DEFINITION_PATH,
        params={
            "method_id": "general/identity",
            "method_version": "1.0.0",
        },
    )

    assert response.status_code == 422
    issue = response.json()["detail"][0]
    assert issue["type"] == expected_type
    assert issue["loc"] == expected_location
    assert "private" not in response.text
    CalculationApiValidationErrorResponse.model_validate(response.json())


def test_evidence_error_is_a_sanitized_422_response() -> None:
    """Client evidence links fail without exposing engine exception detail."""

    request = build_request()
    service = StubCalculationService(
        result=build_result(request_id=request.request_id),
        failure=CalculationEvidenceError(
            "private server evidence details"
        ),
    )
    client = build_client(service)

    response = client.post(
        EXECUTE_PATH,
        json=request.model_dump(mode="json"),
    )

    assert response.status_code == 422
    issue = response.json()["detail"][0]
    assert issue == {
        "type": "calculation_evidence_error",
        "loc": ["body", "reference_ids"],
        "msg": (
            "The request evidence links could not be resolved exactly."
        ),
    }
    assert "private" not in response.text


def test_server_evidence_failure_is_a_sanitized_503_response(
) -> None:
    """Only dedicated service failures become service-unavailable errors."""

    request = build_request()
    service = StubCalculationService(
        result=build_result(request_id=request.request_id),
        failure=CalculationEvidenceResolutionError(),
    )
    client = build_client(service)

    response = client.post(
        EXECUTE_PATH,
        json=request.model_dump(mode="json"),
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": {
            "code": "calculation_service_unavailable",
            "message": (
                "Engineering calculation execution is temporarily "
                "unavailable."
            ),
        }
    }
    assert "private" not in response.text


def test_unexpected_service_failure_propagates_in_test_mode() -> None:
    """Programmer and engine-contract failures are not misclassified."""

    service = StubCalculationService(
        failure=RuntimeError("private programmer detail"),
    )
    client = build_client(service)

    with pytest.raises(RuntimeError, match="private programmer detail"):
        client.get(METHODS_PATH)


def test_generic_service_failure_is_not_misclassified_as_unavailable() -> None:
    """Only the dedicated evidence-resolution error is translated to 503."""

    service = StubCalculationService(
        failure=CalculationServiceError("private programmer detail"),
    )
    client = build_client(service)

    with pytest.raises(
        CalculationServiceError,
        match="private programmer detail",
    ):
        client.get(METHODS_PATH)


def test_unexpected_service_failure_is_generic_500_in_http_mode() -> None:
    """The framework hides an unexpected private failure from clients."""

    service = StubCalculationService(
        failure=RuntimeError("private programmer detail"),
    )
    client = build_client(
        service,
        raise_server_exceptions=False,
    )

    response = client.get(METHODS_PATH)

    assert response.status_code == 500
    assert response.text == "Internal Server Error"
    assert "private" not in response.text


@pytest.mark.parametrize(
    ("path", "params"),
    [
        (VERSIONS_PATH, {}),
        (
            VERSIONS_PATH,
            {"method_id": "bad method"},
        ),
        (
            DEFINITION_PATH,
            {
                "method_id": "general/identity",
                "method_version": "latest",
            },
        ),
        (
            METHODS_PATH,
            {"calculation_type": "x" * 101},
        ),
    ],
)
def test_invalid_queries_never_call_the_service(
    path: str,
    params: dict[str, str],
) -> None:
    """Missing, malformed, implicit, and oversized lookups fail at 422."""

    service = StubCalculationService()
    client = build_client(service)

    response = client.get(path, params=params)

    assert response.status_code == 422
    assert service.calls == []


@pytest.mark.parametrize(
    ("path", "query"),
    [
        (METHODS_PATH, "unexpected=SECRET-DO-NOT-REFLECT"),
        (
            METHODS_PATH,
            "calculation_type=a.b&calculation_type=c.d",
        ),
        (
            VERSIONS_PATH,
            "method_id=general/identity&method_id=other/method",
        ),
        (
            DEFINITION_PATH,
            (
                "method_id=general/identity&method_version=1.0.0"
                "&method_version=2.0.0"
            ),
        ),
        (EXECUTE_PATH, "unexpected=SECRET-DO-NOT-REFLECT"),
    ],
)
def test_unknown_and_duplicate_query_parameters_are_rejected(
    path: str,
    query: str,
) -> None:
    """Parameter pollution fails closed before dependency invocation."""

    service = StubCalculationService()
    client = build_client(service)

    if path == EXECUTE_PATH:
        response = client.post(
            f"{path}?{query}",
            json=build_request().model_dump(mode="json"),
        )
    else:
        response = client.get(f"{path}?{query}")

    assert response.status_code == 422
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    CalculationApiValidationErrorResponse.model_validate(response.json())
    assert service.calls == []


@pytest.mark.parametrize(
    "mutation",
    [
        {"method_version": "latest"},
        {"method_version": "1.0"},
        {"method_version": "01.0.0"},
        {"method_version": "1.0.0-01"},
        {"unexpected": "x"},
        {"method_id": "bad method"},
        {"reference_ids": [f"ref-{index}" for index in range(257)]},
    ],
)
def test_invalid_execution_bodies_never_call_the_service(
    mutation: dict[str, Any],
) -> None:
    """Strict request schemas reject bad or unbounded client content."""

    service = StubCalculationService()
    client = build_client(service)
    payload = build_request().model_dump(mode="json")
    payload.update(mutation)

    response = client.post(EXECUTE_PATH, json=payload)

    assert response.status_code == 422
    assert service.calls == []


def test_automatic_validation_does_not_reflect_rejected_secrets() -> None:
    """Framework validation errors expose neither inputs nor private values."""

    service = StubCalculationService()
    client = build_client(service)
    payload = build_request().model_dump(mode="json")
    payload["SECRET-DO-NOT-REFLECT"] = "SECRET-DO-NOT-REFLECT"

    response = client.post(EXECUTE_PATH, json=payload)

    assert response.status_code == 422
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    assert "input" not in response.text
    validated = CalculationApiValidationErrorResponse.model_validate(
        response.json()
    )
    assert validated.detail[0].msg == "The request value is invalid."
    assert service.calls == []


@pytest.mark.parametrize("non_finite", ("NaN", "Infinity", "-Infinity"))
def test_non_finite_raw_json_is_a_sanitized_422_response(
    non_finite: str,
) -> None:
    """Non-standard non-finite JSON cannot break error serialization."""

    service = StubCalculationService()
    client = build_client(service)
    prefix = (
        '{"calculation_type":"general.identity",'
        '"method_id":"general/identity",'
        '"method_version":"1.0.0",'
        '"unexpected":'
    )
    body = (prefix + non_finite + "}").encode("ascii")

    response = client.post(
        EXECUTE_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 422
    assert non_finite not in response.text
    CalculationApiValidationErrorResponse.model_validate(response.json())
    assert service.calls == []


@pytest.mark.parametrize(
    "body",
    (
        b"\xff",
        (
            b'{"calculation_type":"general.identity",'
            b'"method_id":"general/identity",'
            b'"method_version":"1.0.0",'
            b'"unexpected":'
            + (b"9" * 5_000)
            + b"}"
        ),
    ),
)
def test_low_level_body_parse_errors_are_sanitized_400_responses(
    body: bytes,
) -> None:
    """Decode and parser limits never escape as undocumented responses."""

    service = StubCalculationService()
    client = build_client(service)

    response = client.post(
        EXECUTE_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": {
            "code": "calculation_request_parse_error",
            "message": (
                "The calculation request body could not be decoded or "
                "parsed."
            ),
        }
    }
    CalculationApiErrorResponse.model_validate(response.json())
    assert service.calls == []


@pytest.mark.parametrize(
    "body",
    (
        (
            b'{"calculation_type":"general.identity",'
            b'"method_id":"general/first",'
            b'"method_id":"SECRET-DO-NOT-REFLECT",'
            b'"method_version":"1.0.0"}'
        ),
        (
            b'{"calculation_type":"general.identity",'
            b'"method_id":"general/identity",'
            b'"method_version":"1.0.0",'
            b'"nested":{"SECRET-DO-NOT-REFLECT":1,'
            b'"SECRET-DO-NOT-REFLECT":2}}'
        ),
    ),
    ids=("top-level", "nested"),
)
def test_duplicate_json_members_are_sanitized_400_responses(
    body: bytes,
) -> None:
    """Ambiguous JSON objects fail before validation or service execution."""

    service = StubCalculationService()
    client = build_client(service)

    response = client.post(
        EXECUTE_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": {
            "code": "calculation_request_duplicate_member",
            "message": (
                "The calculation request body contains duplicate object "
                "members."
            ),
        }
    }
    assert "SECRET-DO-NOT-REFLECT" not in response.text
    CalculationApiErrorResponse.model_validate(response.json())
    assert service.calls == []


def test_many_validation_errors_are_truncated_to_public_bound() -> None:
    """Adversarial invalid collections cannot create an unbounded response."""

    service = StubCalculationService()
    client = build_client(service)
    payload = build_request().model_dump(mode="json")
    payload["inputs"] = [{} for _ in range(256)]

    response = client.post(EXECUTE_PATH, json=payload)

    assert response.status_code == 422
    issues = response.json()["detail"]
    assert len(issues) == MAX_CALCULATION_VALIDATION_ISSUES
    assert issues[-1] == {
        "type": "request_validation_truncated",
        "loc": ["request"],
        "msg": (
            "Additional invalid request values were omitted from this "
            "bounded response."
        ),
    }
    CalculationApiValidationErrorResponse.model_validate(response.json())
    assert service.calls == []


def test_registry_version_lookup_error_points_to_body_method_version() -> None:
    """A broad domain version rejected by the registry has the right locus."""

    request = build_request()
    service = StubCalculationService(
        result=build_result(request_id=request.request_id),
        failure=InvalidMethodLookupError(
            "method_version is not a valid controlled identifier."
        ),
    )
    client = build_client(service)

    response = client.post(
        EXECUTE_PATH,
        json=request.model_dump(mode="json"),
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == [
        "body",
        "method_version",
    ]


def test_execution_type_mismatch_points_to_body_calculation_type() -> None:
    """A typed execution mismatch never cites a nonexistent query field."""

    request = build_request()
    service = StubCalculationService(
        result=build_result(request_id=request.request_id),
        failure=MethodCalculationTypeError(
            request.method_id,
            request.method_version,
            request.calculation_type,
        ),
    )
    client = build_client(service)

    response = client.post(
        EXECUTE_PATH,
        json=request.model_dump(mode="json"),
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == [
        "body",
        "calculation_type",
    ]


def test_oversized_content_length_is_rejected_before_json_parsing() -> None:
    """The transport limit prevents allocation of an oversized JSON body."""

    service = StubCalculationService()
    client = build_client(service, max_body_bytes=128)
    body = b'{"unknown":"' + (b"x" * 256) + b'"}'

    response = client.post(
        EXECUTE_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json() == {
        "detail": {
            "code": "calculation_request_too_large",
            "message": (
                "The calculation request exceeds the permitted transport "
                "size."
            ),
        }
    }
    assert service.calls == []


def test_chunked_oversized_body_is_rejected_during_receive() -> None:
    """The byte limit remains effective when Content-Length is unavailable."""

    service = StubCalculationService()
    client = build_client(service, max_body_bytes=128)

    def chunks() -> Iterator[bytes]:
        yield b'{"unknown":"'
        yield b"x" * 256
        yield b'"}'

    response = client.post(
        EXECUTE_PATH,
        content=chunks(),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == (
        "calculation_request_too_large"
    )
    assert service.calls == []


def test_body_limit_does_not_apply_to_other_routes() -> None:
    """The calculation transport guard is narrowly scoped to execution."""

    service = StubCalculationService()
    client = build_client(service, max_body_bytes=16)

    response = client.post(
        METHODS_PATH,
        content=b"x" * 128,
    )

    assert response.status_code == 405
    assert service.calls == []


def test_body_limit_uses_route_path_when_application_is_mounted() -> None:
    """An ASGI mount prefix cannot bypass the execution transport limit."""

    service = StubCalculationService()
    child = FastAPI()
    child.add_middleware(
        CalculationRequestBodyLimitMiddleware,
        max_body_bytes=128,
    )
    child.include_router(router, prefix="/api/v1")
    child.dependency_overrides[get_calculation_service] = lambda: service
    parent = FastAPI()
    parent.mount("/engineering", child)
    client = TestClient(parent)
    body = b'{"unknown":"' + (b"x" * 256) + b'"}'

    response = client.post(
        "/engineering" + EXECUTE_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == (
        "calculation_request_too_large"
    )
    assert service.calls == []


def test_wrong_execution_methods_are_not_registered() -> None:
    """The stateless execution route accepts POST only."""

    service = StubCalculationService()
    client = build_client(service)

    assert client.get(EXECUTE_PATH).status_code == 405
    assert client.delete(EXECUTE_PATH).status_code == 405
    assert client.put(EXECUTE_PATH).status_code == 405
    assert service.calls == []


def test_catalogue_models_reject_count_and_payload_overflow() -> None:
    """Response contracts cannot exceed the registry-wide hard bound."""

    definition = build_definition()
    summary = CalculationMethodSummary.from_definition(
        definition,
        engine_version="1.0.0",
    )

    with pytest.raises(ValidationError, match="method_count"):
        CalculationMethodCatalogue(
            engine_version="1.0.0",
            method_count=0,
            methods=(summary,),
        )

    with pytest.raises(ValidationError):
        CalculationMethodCatalogue(
            engine_version="1.0.0",
            method_count=MAX_REGISTERED_METHODS + 1,
            methods=(summary,) * (MAX_REGISTERED_METHODS + 1),
        )


@pytest.mark.parametrize(
    ("versions", "version_count"),
    [
        (("1.0.0", "1.0.0"), 2),
        (("2.0.0", "1.0.0"), 2),
        (("1.0.0",), 2),
    ],
)
def test_version_catalogue_rejects_ambiguous_sequences(
    versions: tuple[str, ...],
    version_count: int,
) -> None:
    """Version responses stay unique, sorted, and count aligned."""

    with pytest.raises(ValidationError):
        CalculationMethodVersionCatalogue(
            method_id="general/identity",
            version_count=version_count,
            versions=versions,
        )


def test_default_service_returns_fixed_unknown_method_error() -> None:
    """An unknown method still fails closed with production methods enabled."""

    client = TestClient(app)
    request = build_request()

    response = client.post(
        EXECUTE_PATH,
        json=request.model_dump(mode="json"),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {
        "code": "unknown_method",
        "message": "The requested calculation method was not found.",
    }


def test_execution_path_constant_matches_registered_route() -> None:
    """The request-limit middleware and frozen route share one path."""

    assert CALCULATION_EXECUTION_PATH == EXECUTE_PATH


def test_public_api_models_are_immutable() -> None:
    """Calculation response contracts cannot be changed after validation."""

    catalogue = CalculationMethodCatalogue(
        engine_version="1.0.0",
        method_count=0,
    )

    with pytest.raises(ValidationError):
        catalogue.engine_version = "2.0.0"
