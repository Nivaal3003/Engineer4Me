"""Controlled Microsoft Graph proof of the reviewed Entra identity inventory.

The probe has no default transport and accepts no bearer token.  It revalidates
one exact digest-approved Step 207 inventory, emits four immutable read-only
Microsoft Graph v1.0 entity requests through an explicitly injected transport,
and compares bounded provider responses with the approved local projection.

Only a response sealed by the module-owned default HTTPS loader can confer live
provider evidence.  Public response objects and injected HTTP openers remain
synthetic evidence, even when their bodies exactly match the projection.

Official contract references:
* https://learn.microsoft.com/en-us/graph/api/application-get?view=graph-rest-1.0
* https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get?view=graph-rest-1.0
* https://learn.microsoft.com/en-us/graph/permissions-reference
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from math import isfinite
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, ValidationError, model_validator

from app.security.authentication_entra_application_service_principal_inventory_readiness import (
    EntraApplicationServicePrincipalInventoryReadinessError,
    load_entra_application_service_principal_inventory_readiness,
    render_entra_application_service_principal_inventory_readiness_receipt,
)
from app.security.authentication_entra_graph_http_loader import (
    ENTRA_GRAPH_BASE_URL,
    ENTRA_GRAPH_INVENTORY_REQUEST_TIMEOUT_SECONDS,
    MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_BYTES,
    BoundedHTTPSEntraGraphInventoryLoader,
    EntraGraphInventoryRequest,
    EntraGraphInventoryResponse,
    EntraGraphInventoryTransport,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
)
from app.security.identity_models import SecurityModel


ENTRA_GRAPH_INVENTORY_PROBE_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_graph_identity_inventory_probe_receipt"
)
ENTRA_GRAPH_INVENTORY_PROBE_SCHEMA_VERSION = 1
ENTRA_GRAPH_INVENTORY_PROBE_SCOPE = (
    "controlled_read_only_graph_identity_inventory_proof"
)
ENTRA_GRAPH_API_VERSION = "v1.0"
ENTRA_GRAPH_APPLICATION_READ_ALL_PERMISSION = "Application.Read.All"
ENTRA_GRAPH_APPLICATION_READ_ALL_DELEGATED_PERMISSION_ID = (
    "c79f8feb-a9db-4090-85f9-90d820caa0eb"
)
ENTRA_GRAPH_INVENTORY_REQUEST_COUNT = 4
MAX_ENTRA_GRAPH_INVENTORY_TOTAL_RESPONSE_BYTES = (
    ENTRA_GRAPH_INVENTORY_REQUEST_COUNT * MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_BYTES
)
MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_NESTING_DEPTH = 4
MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_CONTAINERS = 32
_SHA256_HEX_LENGTH = 64
_APPLICATION_SELECT = "id,appId,deletedDateTime"
_SERVICE_PRINCIPAL_SELECT = (
    "id,appId,appOwnerOrganizationId,servicePrincipalType,accountEnabled,"
    "disabledByMicrosoftStatus,deletedDateTime"
)


class EntraGraphInventoryProbeError(ValueError):
    """Sanitized rejection of invalid prerequisites or provider evidence."""


@dataclass(frozen=True, slots=True)
class EntraGraphInventoryAuthorizationContract:
    """Declared least-privilege operator boundary, never token evidence."""

    permission_type: Literal["delegated_work_school"]
    permission_name: str
    permission_id: str
    consent_requirement: Literal["admin"]
    credential_origin: Literal["out_of_band_operator"]

    def __post_init__(self) -> None:
        if (
            self.permission_type != "delegated_work_school"
            or self.permission_name != ENTRA_GRAPH_APPLICATION_READ_ALL_PERMISSION
            or self.permission_id
            != ENTRA_GRAPH_APPLICATION_READ_ALL_DELEGATED_PERMISSION_ID
            or self.consent_requirement != "admin"
            or self.credential_origin != "out_of_band_operator"
        ):
            raise ValueError("Microsoft Graph authorization contract is invalid")


class _ApplicationResponse(SecurityModel):
    odata_context: str | None = Field(default=None, alias="@odata.context")
    odata_type: Literal["#microsoft.graph.application"] | None = Field(
        default=None,
        alias="@odata.type",
    )
    id: UUID
    app_id: UUID = Field(alias="appId")
    deleted_date_time: Literal[None] = Field(alias="deletedDateTime")

    @model_validator(mode="after")
    def validate_context(self) -> "_ApplicationResponse":
        if self.odata_context is not None and not _valid_odata_context(
            self.odata_context, "applications"
        ):
            raise ValueError("application OData context is invalid")
        return self


class _ServicePrincipalResponse(SecurityModel):
    odata_context: str | None = Field(default=None, alias="@odata.context")
    odata_type: Literal["#microsoft.graph.servicePrincipal"] | None = Field(
        default=None,
        alias="@odata.type",
    )
    id: UUID
    app_id: UUID = Field(alias="appId")
    app_owner_organization_id: UUID = Field(alias="appOwnerOrganizationId")
    service_principal_type: Literal["Application"] = Field(
        alias="servicePrincipalType"
    )
    account_enabled: Literal[True] = Field(alias="accountEnabled")
    disabled_by_microsoft_status: Literal[None, "NotDisabled"] = Field(
        alias="disabledByMicrosoftStatus"
    )
    deleted_date_time: Literal[None] = Field(alias="deletedDateTime")

    @model_validator(mode="after")
    def validate_context(self) -> "_ServicePrincipalResponse":
        if self.odata_context is not None and not _valid_odata_context(
            self.odata_context, "servicePrincipals"
        ):
            raise ValueError("service-principal OData context is invalid")
        return self


@dataclass(frozen=True, slots=True)
class EntraGraphInventoryProbeReceipt:
    receipt_type: str
    schema_version: int
    validation_scope: str
    graph_api_version: str
    authorization_permission_type: str
    authorization_permission_name: str
    authorization_permission_id: str
    authorization_consent_requirement: str
    authorization_credential_origin: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    inventory_document_sha256: str
    offline_inventory_receipt_sha256: str
    request_plan_sha256: str
    api_application_response_sha256: str
    calling_client_application_response_sha256: str
    api_service_principal_response_sha256: str
    calling_client_service_principal_response_sha256: str
    request_count: int
    response_count: int
    total_response_bytes: int
    approved_inventory_digest_bound: bool
    exact_entity_gets_validated: bool
    graph_v1_endpoint_validated: bool
    read_only_methods_validated: bool
    minimal_select_projection_validated: bool
    no_collection_discovery_validated: bool
    no_batch_paging_retry_validated: bool
    response_bounds_validated: bool
    response_schema_validated: bool
    non_deleted_objects_validated: bool
    application_identity_match_validated: bool
    service_principal_identity_match_validated: bool
    application_service_principal_relationships_validated: bool
    tenant_ownership_validated: bool
    service_principal_type_validated: bool
    account_enabled_validated: bool
    microsoft_disablement_status_validated: bool
    least_privilege_delegated_permission_contract_validated: bool
    out_of_band_operator_contract_validated: bool
    application_permission_contract_rejected: bool
    synthetic_transport_used: bool
    live_https_transport_attested: bool
    provider_io_performed: bool
    provider_state_checked: bool
    live_inventory_checked: bool
    source_authenticity_checked: bool
    authorization_token_claims_checked: bool
    actual_token_type_checked: bool
    app_only_token_checked: bool
    work_school_account_checked: bool
    provider_permission_grant_checked: bool
    admin_consent_checked: bool
    delegated_operator_identity_checked: bool
    delegated_operator_role_checked: bool
    token_tenant_checked: bool
    token_graph_audience_checked: bool
    atomic_inventory_snapshot_checked: bool
    concurrent_provider_mutation_checked: bool
    application_credential_inventory_checked: bool
    service_principal_credential_inventory_checked: bool
    owner_tenant_membership_checked: bool
    service_principal_assignment_required_checked: bool
    service_principal_lock_checked: bool
    claims_policy_assignments_checked: bool
    delegated_permission_grant_checked: bool
    user_flow_checked: bool
    conditional_access_checked: bool
    runtime_pkce_s256_checked: bool
    real_signed_api_token_checked: bool
    redirect_endpoint_ownership_checked: bool
    application_mutation_performed: bool
    service_principal_mutation_performed: bool
    activation_ready: bool

    def __post_init__(self) -> None:
        digests = tuple(
            getattr(self, name)
            for name in self.__dataclass_fields__
            if name.endswith("_sha256")
        )
        validated = (
            self.approved_inventory_digest_bound,
            self.exact_entity_gets_validated,
            self.graph_v1_endpoint_validated,
            self.read_only_methods_validated,
            self.minimal_select_projection_validated,
            self.no_collection_discovery_validated,
            self.no_batch_paging_retry_validated,
            self.response_bounds_validated,
            self.response_schema_validated,
            self.non_deleted_objects_validated,
            self.application_identity_match_validated,
            self.service_principal_identity_match_validated,
            self.application_service_principal_relationships_validated,
            self.tenant_ownership_validated,
            self.service_principal_type_validated,
            self.account_enabled_validated,
            self.microsoft_disablement_status_validated,
            self.least_privilege_delegated_permission_contract_validated,
            self.out_of_band_operator_contract_validated,
            self.application_permission_contract_rejected,
        )
        deferred = (
            self.authorization_token_claims_checked,
            self.actual_token_type_checked,
            self.app_only_token_checked,
            self.work_school_account_checked,
            self.provider_permission_grant_checked,
            self.admin_consent_checked,
            self.delegated_operator_identity_checked,
            self.delegated_operator_role_checked,
            self.token_tenant_checked,
            self.token_graph_audience_checked,
            self.atomic_inventory_snapshot_checked,
            self.concurrent_provider_mutation_checked,
            self.application_credential_inventory_checked,
            self.service_principal_credential_inventory_checked,
            self.owner_tenant_membership_checked,
            self.service_principal_assignment_required_checked,
            self.service_principal_lock_checked,
            self.claims_policy_assignments_checked,
            self.delegated_permission_grant_checked,
            self.user_flow_checked,
            self.conditional_access_checked,
            self.runtime_pkce_s256_checked,
            self.real_signed_api_token_checked,
            self.redirect_endpoint_ownership_checked,
            self.application_mutation_performed,
            self.service_principal_mutation_performed,
            self.activation_ready,
        )
        live = self.live_https_transport_attested
        if (
            self.receipt_type != ENTRA_GRAPH_INVENTORY_PROBE_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version != ENTRA_GRAPH_INVENTORY_PROBE_SCHEMA_VERSION
            or self.validation_scope != ENTRA_GRAPH_INVENTORY_PROBE_SCOPE
            or self.graph_api_version != ENTRA_GRAPH_API_VERSION
            or self.authorization_permission_type != "delegated_work_school"
            or self.authorization_permission_name
            != ENTRA_GRAPH_APPLICATION_READ_ALL_PERMISSION
            or self.authorization_permission_id
            != ENTRA_GRAPH_APPLICATION_READ_ALL_DELEGATED_PERMISSION_ID
            or self.authorization_consent_requirement != "admin"
            or self.authorization_credential_origin != "out_of_band_operator"
            or any(not _is_lower_sha256(value) for value in digests)
            or not hmac.compare_digest(
                self.approved_inventory_document_sha256,
                self.inventory_document_sha256,
            )
            or type(self.request_count) is not int
            or self.request_count != ENTRA_GRAPH_INVENTORY_REQUEST_COUNT
            or type(self.response_count) is not int
            or self.response_count != ENTRA_GRAPH_INVENTORY_REQUEST_COUNT
            or type(self.total_response_bytes) is not int
            or not 0
            < self.total_response_bytes
            <= MAX_ENTRA_GRAPH_INVENTORY_TOTAL_RESPONSE_BYTES
            or any(value is not True for value in validated)
            or any(value is not False for value in deferred)
            or type(self.synthetic_transport_used) is not bool
            or type(live) is not bool
            or self.synthetic_transport_used is live
            or self.provider_io_performed is not live
            or self.provider_state_checked is not live
            or self.live_inventory_checked is not live
            or self.source_authenticity_checked is not live
        ):
            raise ValueError("Microsoft Graph inventory probe receipt is invalid")


def _is_lower_sha256(value: object) -> bool:
    if (
        type(value) is not str
        or len(value) != _SHA256_HEX_LENGTH
        or value != value.lower()
    ):
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _evidence_sha256(label: str, material: bytes) -> str:
    framed = (
        b"engineer4me-step208-v1\x00"
        + str(len(label)).encode("ascii")
        + b":"
        + label.encode("ascii")
        + str(len(material)).encode("ascii")
        + b":"
        + material
    )
    return hashlib.sha256(framed).hexdigest()


def _valid_odata_context(value: object, resource: str) -> bool:
    if type(value) is not str or not 1 <= len(value) <= 512:
        return False
    prefix = f"{ENTRA_GRAPH_BASE_URL}/$metadata#{resource}"
    return value.startswith(prefix) and value.endswith("/$entity")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EntraGraphInventoryProbeError(
                "Microsoft Graph response contains a duplicate key"
            )
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    del value
    raise EntraGraphInventoryProbeError(
        "Microsoft Graph response contains a non-finite number"
    )


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph response contains a non-finite number"
        )
    return parsed


def _require_bounded_structure(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    containers = 0
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            containers += 1
            if depth > MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_NESTING_DEPTH:
                raise EntraGraphInventoryProbeError(
                    "Microsoft Graph response exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if depth > MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_NESTING_DEPTH:
                raise EntraGraphInventoryProbeError(
                    "Microsoft Graph response exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_CONTAINERS:
            raise EntraGraphInventoryProbeError(
                "Microsoft Graph response exceeds the structure limit"
            )


def _canonical_uuid(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.int != 0 and str(parsed) == value


def _content_type_is_json(value: str) -> bool:
    if (
        type(value) is not str
        or not value
        or len(value) > 512
        or any(character in value for character in "\x00\r\n")
    ):
        return False
    parts = [part.strip() for part in value.split(";")]
    if not parts or parts[0].lower() != "application/json":
        return False
    allowed = {
        "odata.metadata": frozenset({"minimal", "full", "none"}),
        "odata.streaming": frozenset({"true", "false"}),
        "ieee754compatible": frozenset({"true", "false"}),
        "charset": frozenset({"utf-8"}),
    }
    seen: set[str] = set()
    for parameter in parts[1:]:
        if parameter.count("=") != 1:
            return False
        name, parameter_value = (
            component.strip().lower() for component in parameter.split("=", 1)
        )
        if (
            not name
            or name in seen
            or name not in allowed
            or parameter_value not in allowed[name]
        ):
            return False
        seen.add(name)
    return True


def _parse_response(
    response: EntraGraphInventoryResponse,
    request: EntraGraphInventoryRequest,
    *,
    resource: Literal["application", "service_principal"],
) -> tuple[_ApplicationResponse | _ServicePrincipalResponse, bytes]:
    if type(response) is not EntraGraphInventoryResponse:
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph transport returned an invalid response"
        )
    try:
        response.validate()
    except ValueError:
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph transport returned an invalid response"
        ) from None
    if (
        response.status_code != 200
        or not hmac.compare_digest(response.final_url, request.url)
        or not _content_type_is_json(response.content_type)
        or not response.body
        or len(response.body) > request.maximum_response_bytes
    ):
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph response failed the transport contract"
        )
    try:
        decoded = response.body.decode("utf-8")
    except UnicodeDecodeError:
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph response must be UTF-8 JSON"
        ) from None
    try:
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
            parse_float=_parse_finite_float,
        )
    except EntraGraphInventoryProbeError:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph response is not valid JSON"
        ) from None
    if not isinstance(parsed, dict):
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph response root must be an object"
        )
    _require_bounded_structure(parsed)
    if (
        "value" in parsed
        or "@odata.nextLink" in parsed
        or "@odata.count" in parsed
    ):
        raise EntraGraphInventoryProbeError(
            "collection or paging evidence is not accepted"
        )
    uuid_fields = (
        ("id", "appId")
        if resource == "application"
        else ("id", "appId", "appOwnerOrganizationId")
    )
    if any(not _canonical_uuid(parsed.get(field)) for field in uuid_fields):
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph response failed identity validation"
        )
    if "deletedDateTime" not in parsed or parsed["deletedDateTime"] is not None:
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph response is not an active directory object"
        )
    if resource == "service_principal" and (
        type(parsed.get("accountEnabled")) is not bool
        or "disabledByMicrosoftStatus" not in parsed
        or (
            parsed["disabledByMicrosoftStatus"] is not None
            and type(parsed["disabledByMicrosoftStatus"]) is not str
        )
    ):
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph response failed identity validation"
        )
    required = (
        {"id", "appId", "deletedDateTime"}
        if resource == "application"
        else {
            "id",
            "appId",
            "appOwnerOrganizationId",
            "servicePrincipalType",
            "accountEnabled",
            "disabledByMicrosoftStatus",
            "deletedDateTime",
        }
    )
    allowed = required | {"@odata.context", "@odata.type"}
    if not required.issubset(parsed) or not set(parsed).issubset(allowed):
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph response fields do not match the selected contract"
        )
    try:
        canonical = _canonical_bytes(parsed)
        model: _ApplicationResponse | _ServicePrincipalResponse
        if resource == "application":
            model = _ApplicationResponse.model_validate_json(canonical)
        else:
            model = _ServicePrincipalResponse.model_validate_json(canonical)
    except (RecursionError, TypeError, ValueError, ValidationError):
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph response failed schema validation"
        ) from None
    return model, canonical


def _inventory_identities(document: bytes) -> dict[str, str]:
    """Recover public identities only after the Step 207 strict loader succeeds."""

    try:
        parsed = json.loads(document.decode("utf-8"))
        inventory = parsed["inventory"]
        applications = {entry["role"]: entry for entry in inventory["applications"]}
        principals = {
            entry["role"]: entry for entry in inventory["service_principals"]
        }
        return {
            "tenant_id": inventory["tenant_id"],
            "api_application_id": applications["api"]["application_id"],
            "api_application_object_id": applications["api"]["application_object_id"],
            "calling_client_application_id": applications["calling_client"][
                "application_id"
            ],
            "calling_client_application_object_id": applications["calling_client"][
                "application_object_id"
            ],
            "api_service_principal_object_id": principals["api"][
                "service_principal_object_id"
            ],
            "calling_client_service_principal_object_id": principals[
                "calling_client"
            ]["service_principal_object_id"],
        }
    except (KeyError, TypeError, UnicodeDecodeError, ValueError):
        raise EntraGraphInventoryProbeError(
            "approved inventory evidence cannot be reconstructed"
        ) from None


def _request_plan(
    identities: dict[str, str],
) -> tuple[EntraGraphInventoryRequest, ...]:
    definitions = (
        (
            "api",
            "application",
            "applications",
            identities["api_application_object_id"],
            _APPLICATION_SELECT,
        ),
        (
            "calling_client",
            "application",
            "applications",
            identities["calling_client_application_object_id"],
            _APPLICATION_SELECT,
        ),
        (
            "api",
            "service_principal",
            "servicePrincipals",
            identities["api_service_principal_object_id"],
            _SERVICE_PRINCIPAL_SELECT,
        ),
        (
            "calling_client",
            "service_principal",
            "servicePrincipals",
            identities["calling_client_service_principal_object_id"],
            _SERVICE_PRINCIPAL_SELECT,
        ),
    )
    return tuple(
        EntraGraphInventoryRequest(
            sequence=index,
            role=role,
            resource=resource,
            method="GET",
            url=f"{ENTRA_GRAPH_BASE_URL}/{collection}/{object_id}?$select={select}",
            headers=(
                ("Accept", "application/json"),
                ("Accept-Encoding", "identity"),
            ),
            body=None,
            timeout_seconds=ENTRA_GRAPH_INVENTORY_REQUEST_TIMEOUT_SECONDS,
            maximum_response_bytes=MAX_ENTRA_GRAPH_INVENTORY_RESPONSE_BYTES,
            follow_redirects=False,
            maximum_retries=0,
            proxy_allowed=False,
        )
        for index, (role, resource, collection, object_id, select) in enumerate(
            definitions,
            start=1,
        )
    )


def _run_entra_application_service_principal_inventory_probe(
    *,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    authorization: EntraGraphInventoryAuthorizationContract,
    transport: EntraGraphInventoryTransport,
    _live_transport_expected: bool,
) -> EntraGraphInventoryProbeReceipt:
    """Private shared implementation for sealed synthetic/live entrypoints."""

    if not isinstance(inventory_document, bytes):
        raise TypeError("approved Entra inventory document must be bytes")
    if not _is_lower_sha256(approved_inventory_document_sha256):
        raise TypeError("approved Entra inventory document digest is required")
    if type(authorization) is not EntraGraphInventoryAuthorizationContract:
        raise TypeError("Microsoft Graph authorization contract is required")
    try:
        authorization.__post_init__()
    except ValueError:
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph authorization contract is invalid"
        ) from None
    if not callable(transport):
        raise TypeError("an explicit Microsoft Graph inventory transport is required")
    if type(_live_transport_expected) is not bool:
        raise TypeError("private Microsoft Graph transport mode is required")

    try:
        offline_receipt = (
            load_entra_application_service_principal_inventory_readiness(
                document=inventory_document,
                authentication_preview=authentication_preview,
                api_registration_document=api_registration_document,
                accepted_api_registration_document_sha256=(
                    accepted_api_registration_document_sha256
                ),
                calling_client_registration_document=(
                    calling_client_registration_document
                ),
                accepted_calling_client_registration_document_sha256=(
                    accepted_calling_client_registration_document_sha256
                ),
            )
        )
    except (
        TypeError,
        ValueError,
        EntraApplicationServicePrincipalInventoryReadinessError,
    ):
        raise EntraGraphInventoryProbeError(
            "approved offline inventory evidence is not valid"
        ) from None
    if not hmac.compare_digest(
        offline_receipt.inventory_document_sha256,
        approved_inventory_document_sha256,
    ):
        raise EntraGraphInventoryProbeError(
            "offline inventory does not match its approved digest"
        )

    identities = _inventory_identities(inventory_document)
    requests = _request_plan(identities)
    responses: list[EntraGraphInventoryResponse] = []
    models: list[_ApplicationResponse | _ServicePrincipalResponse] = []
    canonical_responses: list[bytes] = []
    for request in requests:
        try:
            response = transport(request)
        except Exception:
            raise EntraGraphInventoryProbeError(
                "Microsoft Graph inventory transport failed"
            ) from None
        model, canonical = _parse_response(
            response,
            request,
            resource=request.resource,
        )
        if _live_transport_expected and not response.live_https_attested:
            raise EntraGraphInventoryProbeError(
                "live Microsoft Graph response provenance is not attested"
            )
        if not _live_transport_expected and response.live_https_attested:
            raise EntraGraphInventoryProbeError(
                "attested responses are not accepted by synthetic validation"
            )
        responses.append(response)
        models.append(model)
        canonical_responses.append(canonical)

    api_application, client_application, api_principal, client_principal = models
    if (
        type(api_application) is not _ApplicationResponse
        or type(client_application) is not _ApplicationResponse
        or type(api_principal) is not _ServicePrincipalResponse
        or type(client_principal) is not _ServicePrincipalResponse
        or str(api_application.id) != identities["api_application_object_id"]
        or str(api_application.app_id) != identities["api_application_id"]
        or str(client_application.id)
        != identities["calling_client_application_object_id"]
        or str(client_application.app_id)
        != identities["calling_client_application_id"]
        or str(api_principal.id) != identities["api_service_principal_object_id"]
        or str(api_principal.app_id) != identities["api_application_id"]
        or str(api_principal.app_owner_organization_id) != identities["tenant_id"]
        or str(client_principal.id)
        != identities["calling_client_service_principal_object_id"]
        or str(client_principal.app_id)
        != identities["calling_client_application_id"]
        or str(client_principal.app_owner_organization_id)
        != identities["tenant_id"]
    ):
        raise EntraGraphInventoryProbeError(
            "Microsoft Graph inventory does not match approved identity evidence"
        )

    request_plan_material = _canonical_bytes(
        [
            {
                "sequence": request.sequence,
                "role": request.role,
                "resource": request.resource,
                "method": request.method,
                "url": request.url,
                "headers": request.headers,
                "body": request.body,
                "timeout_seconds": request.timeout_seconds,
                "maximum_response_bytes": request.maximum_response_bytes,
                "follow_redirects": request.follow_redirects,
                "maximum_retries": request.maximum_retries,
                "proxy_allowed": request.proxy_allowed,
            }
            for request in requests
        ]
    )
    live = _live_transport_expected
    return EntraGraphInventoryProbeReceipt(
        receipt_type=ENTRA_GRAPH_INVENTORY_PROBE_RECEIPT_TYPE,
        schema_version=ENTRA_GRAPH_INVENTORY_PROBE_SCHEMA_VERSION,
        validation_scope=ENTRA_GRAPH_INVENTORY_PROBE_SCOPE,
        graph_api_version=ENTRA_GRAPH_API_VERSION,
        authorization_permission_type=authorization.permission_type,
        authorization_permission_name=authorization.permission_name,
        authorization_permission_id=authorization.permission_id,
        authorization_consent_requirement=authorization.consent_requirement,
        authorization_credential_origin=authorization.credential_origin,
        configuration_sha256=offline_receipt.configuration_sha256,
        api_registration_document_sha256=(
            offline_receipt.api_registration_document_sha256
        ),
        calling_client_registration_document_sha256=(
            offline_receipt.calling_client_registration_document_sha256
        ),
        approved_inventory_document_sha256=approved_inventory_document_sha256,
        inventory_document_sha256=offline_receipt.inventory_document_sha256,
        offline_inventory_receipt_sha256=hashlib.sha256(
            render_entra_application_service_principal_inventory_readiness_receipt(
                offline_receipt
            ).encode("utf-8")
        ).hexdigest(),
        request_plan_sha256=_evidence_sha256(
            "request_plan",
            request_plan_material,
        ),
        api_application_response_sha256=_evidence_sha256(
            "api_application_response",
            canonical_responses[0],
        ),
        calling_client_application_response_sha256=_evidence_sha256(
            "calling_client_application_response",
            canonical_responses[1],
        ),
        api_service_principal_response_sha256=_evidence_sha256(
            "api_service_principal_response",
            canonical_responses[2],
        ),
        calling_client_service_principal_response_sha256=_evidence_sha256(
            "calling_client_service_principal_response",
            canonical_responses[3],
        ),
        request_count=len(requests),
        response_count=len(responses),
        total_response_bytes=sum(len(response.body) for response in responses),
        approved_inventory_digest_bound=True,
        exact_entity_gets_validated=True,
        graph_v1_endpoint_validated=True,
        read_only_methods_validated=True,
        minimal_select_projection_validated=True,
        no_collection_discovery_validated=True,
        no_batch_paging_retry_validated=True,
        response_bounds_validated=True,
        response_schema_validated=True,
        non_deleted_objects_validated=True,
        application_identity_match_validated=True,
        service_principal_identity_match_validated=True,
        application_service_principal_relationships_validated=True,
        tenant_ownership_validated=True,
        service_principal_type_validated=True,
        account_enabled_validated=True,
        microsoft_disablement_status_validated=True,
        least_privilege_delegated_permission_contract_validated=True,
        out_of_band_operator_contract_validated=True,
        application_permission_contract_rejected=True,
        synthetic_transport_used=not live,
        live_https_transport_attested=live,
        provider_io_performed=live,
        provider_state_checked=live,
        live_inventory_checked=live,
        source_authenticity_checked=live,
        authorization_token_claims_checked=False,
        actual_token_type_checked=False,
        app_only_token_checked=False,
        work_school_account_checked=False,
        provider_permission_grant_checked=False,
        admin_consent_checked=False,
        delegated_operator_identity_checked=False,
        delegated_operator_role_checked=False,
        token_tenant_checked=False,
        token_graph_audience_checked=False,
        atomic_inventory_snapshot_checked=False,
        concurrent_provider_mutation_checked=False,
        application_credential_inventory_checked=False,
        service_principal_credential_inventory_checked=False,
        owner_tenant_membership_checked=False,
        service_principal_assignment_required_checked=False,
        service_principal_lock_checked=False,
        claims_policy_assignments_checked=False,
        delegated_permission_grant_checked=False,
        user_flow_checked=False,
        conditional_access_checked=False,
        runtime_pkce_s256_checked=False,
        real_signed_api_token_checked=False,
        redirect_endpoint_ownership_checked=False,
        application_mutation_performed=False,
        service_principal_mutation_performed=False,
        activation_ready=False,
    )


def validate_entra_application_service_principal_inventory_probe(
    *,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    authorization: EntraGraphInventoryAuthorizationContract,
    transport: EntraGraphInventoryTransport,
) -> EntraGraphInventoryProbeReceipt:
    """Validate deterministic responses; never emit live-provider evidence."""

    return _run_entra_application_service_principal_inventory_probe(
        inventory_document=inventory_document,
        approved_inventory_document_sha256=approved_inventory_document_sha256,
        authentication_preview=authentication_preview,
        api_registration_document=api_registration_document,
        accepted_api_registration_document_sha256=(
            accepted_api_registration_document_sha256
        ),
        calling_client_registration_document=calling_client_registration_document,
        accepted_calling_client_registration_document_sha256=(
            accepted_calling_client_registration_document_sha256
        ),
        authorization=authorization,
        transport=transport,
        _live_transport_expected=False,
    )


def probe_live_entra_application_service_principal_inventory(
    *,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    authorization: EntraGraphInventoryAuthorizationContract,
    delegated_access_token: str,
) -> EntraGraphInventoryProbeReceipt:
    """Perform the direct live HTTPS proof with one ephemeral opaque token.

    The four entity reads are not atomic.  Failure after request one, two, or
    three can therefore leave partial read I/O but never returns a receipt.
    """

    loader = BoundedHTTPSEntraGraphInventoryLoader(
        delegated_access_token=delegated_access_token
    )
    try:
        return _run_entra_application_service_principal_inventory_probe(
            inventory_document=inventory_document,
            approved_inventory_document_sha256=approved_inventory_document_sha256,
            authentication_preview=authentication_preview,
            api_registration_document=api_registration_document,
            accepted_api_registration_document_sha256=(
                accepted_api_registration_document_sha256
            ),
            calling_client_registration_document=(
                calling_client_registration_document
            ),
            accepted_calling_client_registration_document_sha256=(
                accepted_calling_client_registration_document_sha256
            ),
            authorization=authorization,
            transport=loader,
            _live_transport_expected=True,
        )
    finally:
        loader.close()


def render_entra_graph_inventory_probe_receipt(
    receipt: EntraGraphInventoryProbeReceipt,
) -> str:
    """Render canonical privacy-minimized proof evidence."""

    if type(receipt) is not EntraGraphInventoryProbeReceipt:
        raise TypeError("Microsoft Graph inventory probe receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {field: getattr(receipt, field) for field in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_GRAPH_APPLICATION_READ_ALL_DELEGATED_PERMISSION_ID",
    "ENTRA_GRAPH_APPLICATION_READ_ALL_PERMISSION",
    "ENTRA_GRAPH_API_VERSION",
    "ENTRA_GRAPH_INVENTORY_PROBE_RECEIPT_TYPE",
    "ENTRA_GRAPH_INVENTORY_PROBE_SCHEMA_VERSION",
    "ENTRA_GRAPH_INVENTORY_PROBE_SCOPE",
    "ENTRA_GRAPH_INVENTORY_REQUEST_COUNT",
    "MAX_ENTRA_GRAPH_INVENTORY_TOTAL_RESPONSE_BYTES",
    "EntraGraphInventoryAuthorizationContract",
    "EntraGraphInventoryProbeError",
    "EntraGraphInventoryProbeReceipt",
    "probe_live_entra_application_service_principal_inventory",
    "render_entra_graph_inventory_probe_receipt",
    "validate_entra_application_service_principal_inventory_probe",
]
