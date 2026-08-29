"""Reviewed exact inventory of the Engineer4Me application route surface."""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import FastAPI

from app.security.identity_models import SecurityModel
from app.security.route_policy import OperationIdentifier, RouteHTTPMethod, RoutePathTemplate


class ApplicationRouteIdentity(SecurityModel):
    operation_id: OperationIdentifier
    method: RouteHTTPMethod
    path_template: RoutePathTemplate


APPLICATION_ROUTE_INVENTORY = (
    ApplicationRouteIdentity(operation_id="root", method=RouteHTTPMethod.GET, path_template="/"),
    ApplicationRouteIdentity(operation_id="assessAnalyzerApplication", method=RouteHTTPMethod.POST, path_template="/api/v1/calculations/analyzers/application-assessment"),
    ApplicationRouteIdentity(operation_id="getAnalyzerTechnologyCatalogue", method=RouteHTTPMethod.GET, path_template="/api/v1/calculations/analyzers/catalogue"),
    ApplicationRouteIdentity(operation_id="listAnalyzerDesignCaseExamples", method=RouteHTTPMethod.GET, path_template="/api/v1/calculations/analyzers/design-case-examples"),
    ApplicationRouteIdentity(operation_id="listAnalyzerKnowledgeLinks", method=RouteHTTPMethod.GET, path_template="/api/v1/calculations/analyzers/knowledge-links"),
    ApplicationRouteIdentity(operation_id="getControlValveCatalogue", method=RouteHTTPMethod.GET, path_template="/api/v1/calculations/control-valves/catalogue"),
    ApplicationRouteIdentity(operation_id="evaluateControlValveDesignCase", method=RouteHTTPMethod.POST, path_template="/api/v1/calculations/control-valves/design-cases/evaluate"),
    ApplicationRouteIdentity(operation_id="executeControlValveCalculation", method=RouteHTTPMethod.POST, path_template="/api/v1/calculations/control-valves/execute"),
    ApplicationRouteIdentity(operation_id="listControlValveKnowledgeLinks", method=RouteHTTPMethod.GET, path_template="/api/v1/calculations/control-valves/knowledge-links"),
    ApplicationRouteIdentity(operation_id="assessDPFlowApplication", method=RouteHTTPMethod.POST, path_template="/api/v1/calculations/dp-flow/application-assessment"),
    ApplicationRouteIdentity(operation_id="getDPFlowCatalogue", method=RouteHTTPMethod.GET, path_template="/api/v1/calculations/dp-flow/catalogue"),
    ApplicationRouteIdentity(operation_id="listDPFlowDesignCaseExamples", method=RouteHTTPMethod.GET, path_template="/api/v1/calculations/dp-flow/design-case-examples"),
    ApplicationRouteIdentity(operation_id="evaluateDPFlowDesignCase", method=RouteHTTPMethod.POST, path_template="/api/v1/calculations/dp-flow/design-cases/evaluate"),
    ApplicationRouteIdentity(operation_id="evaluateStoredDPFlowDesignCase", method=RouteHTTPMethod.POST, path_template="/api/v1/calculations/dp-flow/design-cases/stored/evaluate"),
    ApplicationRouteIdentity(operation_id="executeDPFlowCalculation", method=RouteHTTPMethod.POST, path_template="/api/v1/calculations/dp-flow/execute"),
    ApplicationRouteIdentity(operation_id="listDPFlowKnowledgeLinks", method=RouteHTTPMethod.GET, path_template="/api/v1/calculations/dp-flow/knowledge-links"),
    ApplicationRouteIdentity(operation_id="executeCalculation", method=RouteHTTPMethod.POST, path_template="/api/v1/calculations/execute"),
    ApplicationRouteIdentity(operation_id="assessLevelApplication", method=RouteHTTPMethod.POST, path_template="/api/v1/calculations/level/application-assessment"),
    ApplicationRouteIdentity(operation_id="listCalculationMethods", method=RouteHTTPMethod.GET, path_template="/api/v1/calculations/methods"),
    ApplicationRouteIdentity(operation_id="getCalculationMethodDefinition", method=RouteHTTPMethod.GET, path_template="/api/v1/calculations/methods/definition"),
    ApplicationRouteIdentity(operation_id="listCalculationMethodVersions", method=RouteHTTPMethod.GET, path_template="/api/v1/calculations/methods/versions"),
    ApplicationRouteIdentity(operation_id="getPressureReliefCatalogue", method=RouteHTTPMethod.GET, path_template="/api/v1/calculations/pressure-relief/catalogue"),
    ApplicationRouteIdentity(operation_id="executePressureReliefCalculation", method=RouteHTTPMethod.POST, path_template="/api/v1/calculations/pressure-relief/execute"),
    ApplicationRouteIdentity(operation_id="listPressureReliefKnowledgeLinks", method=RouteHTTPMethod.GET, path_template="/api/v1/calculations/pressure-relief/knowledge-links"),
    ApplicationRouteIdentity(operation_id="assessPressureReliefReadiness", method=RouteHTTPMethod.POST, path_template="/api/v1/calculations/pressure-relief/readiness-assessment"),
    ApplicationRouteIdentity(operation_id="getEngineeringRun", method=RouteHTTPMethod.GET, path_template="/api/v1/design-runs/{run_id}"),
    ApplicationRouteIdentity(operation_id="listDesignCases", method=RouteHTTPMethod.GET, path_template="/api/v1/designs"),
    ApplicationRouteIdentity(operation_id="createDesignCase", method=RouteHTTPMethod.POST, path_template="/api/v1/designs"),
    ApplicationRouteIdentity(operation_id="getDesignCase", method=RouteHTTPMethod.GET, path_template="/api/v1/designs/{design_case_id}"),
    ApplicationRouteIdentity(operation_id="assessAndPersistDesignAnalyzerApplication", method=RouteHTTPMethod.POST, path_template="/api/v1/designs/{design_case_id}/analyzer-assessments"),
    ApplicationRouteIdentity(operation_id="executeAndPersistDesignCalculation", method=RouteHTTPMethod.POST, path_template="/api/v1/designs/{design_case_id}/calculations"),
    ApplicationRouteIdentity(operation_id="listDesignDatasheets", method=RouteHTTPMethod.GET, path_template="/api/v1/designs/{design_case_id}/datasheets"),
    ApplicationRouteIdentity(operation_id="createDesignDatasheet", method=RouteHTTPMethod.POST, path_template="/api/v1/designs/{design_case_id}/datasheets"),
    ApplicationRouteIdentity(operation_id="getDesignDatasheet", method=RouteHTTPMethod.GET, path_template="/api/v1/designs/{design_case_id}/datasheets/{datasheet_id}"),
    ApplicationRouteIdentity(operation_id="listDesignDatasheetRevisions", method=RouteHTTPMethod.GET, path_template="/api/v1/designs/{design_case_id}/datasheets/{datasheet_id}/revisions"),
    ApplicationRouteIdentity(operation_id="reviseDesignDatasheet", method=RouteHTTPMethod.POST, path_template="/api/v1/designs/{design_case_id}/datasheets/{datasheet_id}/revisions"),
    ApplicationRouteIdentity(operation_id="getDesignDatasheetRevision", method=RouteHTTPMethod.GET, path_template="/api/v1/designs/{design_case_id}/datasheets/{datasheet_id}/revisions/{revision_number}"),
    ApplicationRouteIdentity(operation_id="downloadDesignDatasheetRevision", method=RouteHTTPMethod.GET, path_template="/api/v1/designs/{design_case_id}/datasheets/{datasheet_id}/revisions/{revision_number}/exports/{export_format}"),
    ApplicationRouteIdentity(operation_id="listDesignCaseRevisions", method=RouteHTTPMethod.GET, path_template="/api/v1/designs/{design_case_id}/revisions"),
    ApplicationRouteIdentity(operation_id="reviseDesignCase", method=RouteHTTPMethod.POST, path_template="/api/v1/designs/{design_case_id}/revisions"),
    ApplicationRouteIdentity(operation_id="getDesignCaseRevision", method=RouteHTTPMethod.GET, path_template="/api/v1/designs/{design_case_id}/revisions/{revision_number}"),
    ApplicationRouteIdentity(operation_id="listDesignEngineeringRuns", method=RouteHTTPMethod.GET, path_template="/api/v1/designs/{design_case_id}/runs"),
    ApplicationRouteIdentity(operation_id="submit_ingestion_job", method=RouteHTTPMethod.POST, path_template="/api/v1/ingestion/jobs"),
    ApplicationRouteIdentity(operation_id="search_ingestion_jobs", method=RouteHTTPMethod.POST, path_template="/api/v1/ingestion/jobs/search"),
    ApplicationRouteIdentity(operation_id="get_ingestion_job", method=RouteHTTPMethod.GET, path_template="/api/v1/ingestion/jobs/{job_id}"),
    ApplicationRouteIdentity(operation_id="cancel_ingestion_job", method=RouteHTTPMethod.POST, path_template="/api/v1/ingestion/jobs/{job_id}/cancel"),
    ApplicationRouteIdentity(operation_id="request_ingestion_job_cancellation", method=RouteHTTPMethod.POST, path_template="/api/v1/ingestion/jobs/{job_id}/cancellation-request"),
    ApplicationRouteIdentity(operation_id="retry_ingestion_document", method=RouteHTTPMethod.POST, path_template="/api/v1/ingestion/jobs/{job_id}/documents/{document_id}/retry"),
    ApplicationRouteIdentity(operation_id="execute_filesystem_ingestion_job", method=RouteHTTPMethod.POST, path_template="/api/v1/ingestion/jobs/{job_id}/execute"),
    ApplicationRouteIdentity(operation_id="queue_ingestion_job", method=RouteHTTPMethod.POST, path_template="/api/v1/ingestion/jobs/{job_id}/queue"),
    ApplicationRouteIdentity(operation_id="retry_ingestion_job", method=RouteHTTPMethod.POST, path_template="/api/v1/ingestion/jobs/{job_id}/retry"),
    ApplicationRouteIdentity(operation_id="start_ingestion_job", method=RouteHTTPMethod.POST, path_template="/api/v1/ingestion/jobs/{job_id}/start"),
    ApplicationRouteIdentity(operation_id="get_ingestion_statistics", method=RouteHTTPMethod.GET, path_template="/api/v1/ingestion/statistics"),
    ApplicationRouteIdentity(operation_id="upload_ingestion_documents", method=RouteHTTPMethod.POST, path_template="/api/v1/ingestion/uploads"),
    ApplicationRouteIdentity(operation_id="list_knowledge", method=RouteHTTPMethod.GET, path_template="/api/v1/knowledge"),
    ApplicationRouteIdentity(operation_id="register_knowledge", method=RouteHTTPMethod.POST, path_template="/api/v1/knowledge"),
    ApplicationRouteIdentity(operation_id="upsert_knowledge", method=RouteHTTPMethod.PUT, path_template="/api/v1/knowledge"),
    ApplicationRouteIdentity(operation_id="assess_publication_readiness", method=RouteHTTPMethod.POST, path_template="/api/v1/knowledge/publication-readiness"),
    ApplicationRouteIdentity(operation_id="search_knowledge", method=RouteHTTPMethod.POST, path_template="/api/v1/knowledge/search"),
    ApplicationRouteIdentity(operation_id="search_safety_guidance", method=RouteHTTPMethod.POST, path_template="/api/v1/knowledge/search/safety"),
    ApplicationRouteIdentity(operation_id="search_knowledge_text", method=RouteHTTPMethod.POST, path_template="/api/v1/knowledge/search/text"),
    ApplicationRouteIdentity(operation_id="search_verified_knowledge", method=RouteHTTPMethod.POST, path_template="/api/v1/knowledge/search/verified"),
    ApplicationRouteIdentity(operation_id="get_knowledge_statistics", method=RouteHTTPMethod.GET, path_template="/api/v1/knowledge/statistics"),
    ApplicationRouteIdentity(operation_id="list_knowledge_summaries", method=RouteHTTPMethod.GET, path_template="/api/v1/knowledge/summaries"),
    ApplicationRouteIdentity(operation_id="delete_knowledge", method=RouteHTTPMethod.DELETE, path_template="/api/v1/knowledge/{knowledge_id}"),
    ApplicationRouteIdentity(operation_id="get_knowledge", method=RouteHTTPMethod.GET, path_template="/api/v1/knowledge/{knowledge_id}"),
    ApplicationRouteIdentity(operation_id="revise_knowledge", method=RouteHTTPMethod.PUT, path_template="/api/v1/knowledge/{knowledge_id}"),
    ApplicationRouteIdentity(operation_id="get_knowledge_history", method=RouteHTTPMethod.GET, path_template="/api/v1/knowledge/{knowledge_id}/history"),
    ApplicationRouteIdentity(operation_id="get_publication_readiness", method=RouteHTTPMethod.GET, path_template="/api/v1/knowledge/{knowledge_id}/publication-readiness"),
    ApplicationRouteIdentity(operation_id="get_knowledge_summary", method=RouteHTTPMethod.GET, path_template="/api/v1/knowledge/{knowledge_id}/summary"),
    ApplicationRouteIdentity(operation_id="list_manufacturers", method=RouteHTTPMethod.GET, path_template="/api/v1/manufacturers"),
    ApplicationRouteIdentity(operation_id="create_manufacturer", method=RouteHTTPMethod.POST, path_template="/api/v1/manufacturers"),
    ApplicationRouteIdentity(operation_id="delete_manufacturer", method=RouteHTTPMethod.DELETE, path_template="/api/v1/manufacturers/{manufacturer_id}"),
    ApplicationRouteIdentity(operation_id="get_manufacturer", method=RouteHTTPMethod.GET, path_template="/api/v1/manufacturers/{manufacturer_id}"),
    ApplicationRouteIdentity(operation_id="update_manufacturer", method=RouteHTTPMethod.PATCH, path_template="/api/v1/manufacturers/{manufacturer_id}"),
    ApplicationRouteIdentity(operation_id="list_measurements", method=RouteHTTPMethod.GET, path_template="/api/v1/measurements/"),
    ApplicationRouteIdentity(operation_id="list_product_families", method=RouteHTTPMethod.GET, path_template="/api/v1/product-families"),
    ApplicationRouteIdentity(operation_id="create_product_family", method=RouteHTTPMethod.POST, path_template="/api/v1/product-families"),
    ApplicationRouteIdentity(operation_id="delete_product_family", method=RouteHTTPMethod.DELETE, path_template="/api/v1/product-families/{product_family_id}"),
    ApplicationRouteIdentity(operation_id="get_product_family", method=RouteHTTPMethod.GET, path_template="/api/v1/product-families/{product_family_id}"),
    ApplicationRouteIdentity(operation_id="update_product_family", method=RouteHTTPMethod.PATCH, path_template="/api/v1/product-families/{product_family_id}"),
    ApplicationRouteIdentity(operation_id="list_products", method=RouteHTTPMethod.GET, path_template="/api/v1/products"),
    ApplicationRouteIdentity(operation_id="create_product", method=RouteHTTPMethod.POST, path_template="/api/v1/products"),
    ApplicationRouteIdentity(operation_id="delete_product", method=RouteHTTPMethod.DELETE, path_template="/api/v1/products/{product_id}"),
    ApplicationRouteIdentity(operation_id="get_product", method=RouteHTTPMethod.GET, path_template="/api/v1/products/{product_id}"),
    ApplicationRouteIdentity(operation_id="update_product", method=RouteHTTPMethod.PATCH, path_template="/api/v1/products/{product_id}"),
    ApplicationRouteIdentity(operation_id="list_protocols", method=RouteHTTPMethod.GET, path_template="/api/v1/protocols"),
    ApplicationRouteIdentity(operation_id="create_protocol", method=RouteHTTPMethod.POST, path_template="/api/v1/protocols"),
    ApplicationRouteIdentity(operation_id="delete_protocol", method=RouteHTTPMethod.DELETE, path_template="/api/v1/protocols/{protocol_id}"),
    ApplicationRouteIdentity(operation_id="get_protocol", method=RouteHTTPMethod.GET, path_template="/api/v1/protocols/{protocol_id}"),
    ApplicationRouteIdentity(operation_id="update_protocol", method=RouteHTTPMethod.PATCH, path_template="/api/v1/protocols/{protocol_id}"),
    ApplicationRouteIdentity(operation_id="select_products", method=RouteHTTPMethod.POST, path_template="/api/v1/selections"),
    ApplicationRouteIdentity(operation_id="health", method=RouteHTTPMethod.GET, path_template="/health"),
)

PUBLIC_ROUTE_IDENTITIES = frozenset({("root", RouteHTTPMethod.GET, "/"), ("health", RouteHTTPMethod.GET, "/health")})
FRAMEWORK_ROUTE_PATHS = frozenset({"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"})


class ApplicationRouteInventoryError(RuntimeError):
    """Sanitized failure when runtime routes drift from the reviewed inventory."""


def _identity_key(identity: ApplicationRouteIdentity) -> tuple[str, RouteHTTPMethod, str]:
    return (identity.operation_id, identity.method, identity.path_template)


_DECLARED_BY_ROUTE_PAIR = {
    (identity.method, identity.path_template): identity
    for identity in APPLICATION_ROUTE_INVENTORY
}


def discover_application_route_inventory(application: FastAPI) -> tuple[ApplicationRouteIdentity, ...]:
    if not isinstance(application, FastAPI):
        raise TypeError("application route inventory requires FastAPI")

    try:
        schema = application.openapi()
    except Exception as error:
        raise ApplicationRouteInventoryError("application route schema is unavailable") from error
    if not isinstance(schema, Mapping):
        raise ApplicationRouteInventoryError("application route schema is invalid")
    paths = schema.get("paths")
    if not isinstance(paths, Mapping):
        raise ApplicationRouteInventoryError("application route paths are unavailable")

    identities: list[ApplicationRouteIdentity] = []
    supported_methods = {method.value.lower(): method for method in RouteHTTPMethod}
    for path, path_item in paths.items():
        if not isinstance(path, str) or not isinstance(path_item, Mapping):
            raise ApplicationRouteInventoryError("application route schema contains an invalid path")
        if path in FRAMEWORK_ROUTE_PATHS:
            continue
        for schema_method, operation in path_item.items():
            method = supported_methods.get(str(schema_method).lower())
            if method is None:
                continue
            if not isinstance(operation, Mapping):
                raise ApplicationRouteInventoryError("application route operation schema is invalid")
            expected = _DECLARED_BY_ROUTE_PAIR.get((method, path))
            if expected is None:
                raise ApplicationRouteInventoryError("application route is outside the reviewed inventory")
            schema_operation_id = operation.get("operationId")
            if not isinstance(schema_operation_id, str) or not schema_operation_id:
                raise ApplicationRouteInventoryError("application route operation identity is unavailable")
            if schema_operation_id != expected.operation_id and not schema_operation_id.startswith(
                f"{expected.operation_id}_"
            ):
                raise ApplicationRouteInventoryError("application route operation identity changed")
            identities.append(expected)
    return tuple(sorted(identities, key=lambda item: (item.path_template, item.method.value, item.operation_id)))


def validate_application_route_inventory(application: FastAPI) -> tuple[ApplicationRouteIdentity, ...]:
    discovered = discover_application_route_inventory(application)
    declared = tuple(sorted(APPLICATION_ROUTE_INVENTORY, key=lambda item: (item.path_template, item.method.value, item.operation_id)))
    if discovered != declared:
        raise ApplicationRouteInventoryError(
            f"application route inventory mismatch: declared {len(declared)}, discovered {len(discovered)}"
        )
    return discovered


_DECLARED_KEYS = tuple(_identity_key(identity) for identity in APPLICATION_ROUTE_INVENTORY)
if len(APPLICATION_ROUTE_INVENTORY) != 93 or len(_DECLARED_KEYS) != len(set(_DECLARED_KEYS)):
    raise RuntimeError("declared application route inventory is internally invalid")
