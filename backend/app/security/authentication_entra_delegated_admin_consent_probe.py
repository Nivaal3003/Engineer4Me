"""Controlled Microsoft Graph proof of one exact delegated admin-consent grant.

The proof revalidates an independently digest-approved Step 209 desired-state
document, issues one exact filtered GET through an explicit transport, and
requires exactly one normalized ``oAuth2PermissionGrant`` result.  It never
creates, updates, deletes, merges, or revokes a grant.

Only the live entrypoint can build the module-owned HTTPS loader and confer
Graph response evidence.  The synthetic entrypoint always remains local
validation, even if a caller supplies a sealed response object.  Graph does not
return a tenant identifier here, and the opaque token is not parsed, so even a
live result is scoped to the token's unverified tenant context and cannot prove
intended-tenant ownership.

Official contract references:
* https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0
* https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0
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

from pydantic import Field, ValidationError, field_validator, model_validator

from app.security.authentication_entra_delegated_admin_consent_graph_http_loader import (
    ENTRA_DELEGATED_ADMIN_CONSENT_QUERY_TIMEOUT_SECONDS,
    MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_BYTES,
    BoundedHTTPSEntraDelegatedAdminConsentGraphLoader,
    EntraDelegatedAdminConsentGraphRequest,
    EntraDelegatedAdminConsentGraphResponse,
    EntraDelegatedAdminConsentGraphTransport,
    consent_grant_query_url,
)
from app.security.authentication_entra_delegated_admin_consent_readiness import (
    EntraDelegatedAdminConsentReadinessError,
    load_entra_delegated_admin_consent_readiness,
    render_entra_delegated_admin_consent_readiness_receipt,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
)
from app.security.identity_models import SecurityModel


ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_RECEIPT_TYPE = (
    "engineer4me_microsoft_entra_delegated_admin_consent_probe_receipt"
)
ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_SCHEMA_VERSION = 1
ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_SCOPE = (
    "controlled_read_only_exact_filtered_delegated_admin_consent_proof"
)
ENTRA_GRAPH_DIRECTORY_READ_ALL_PERMISSION = "Directory.Read.All"
ENTRA_GRAPH_DIRECTORY_READ_ALL_DELEGATED_PERMISSION_ID = (
    "06da0dbc-49e2-44d2-8312-53f166ab848a"
)
MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_NESTING_DEPTH = 5
MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_CONTAINERS = 32
MAX_ENTRA_DELEGATED_ADMIN_CONSENT_GRANT_ID_LENGTH = 1_024
MAX_ENTRA_DELEGATED_ADMIN_CONSENT_ODATA_ID_LENGTH = 2_048
_SHA256_HEX_LENGTH = 64


class EntraDelegatedAdminConsentProbeError(ValueError):
    """Sanitized rejection of invalid prerequisites or provider evidence."""


@dataclass(frozen=True, slots=True)
class EntraDelegatedAdminConsentProbeAuthorizationContract:
    """Declared operator contract; it is not evidence about the opaque token."""

    permission_type: Literal["delegated_work_school"]
    permission_name: str
    permission_id: str
    consent_requirement: Literal["admin"]
    credential_origin: Literal["out_of_band_operator"]

    def __post_init__(self) -> None:
        if (
            self.permission_type != "delegated_work_school"
            or self.permission_name != ENTRA_GRAPH_DIRECTORY_READ_ALL_PERMISSION
            or self.permission_id
            != ENTRA_GRAPH_DIRECTORY_READ_ALL_DELEGATED_PERMISSION_ID
            or self.consent_requirement != "admin"
            or self.credential_origin != "out_of_band_operator"
        ):
            raise ValueError("Microsoft Graph consent probe authorization is invalid")


def _bounded_opaque(value: str, *, maximum: int) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= maximum
        and value == value.strip()
        and all(ord(character) >= 0x20 and ord(character) != 0x7F for character in value)
    )


class _GrantResponse(SecurityModel):
    odata_id: str | None = Field(default=None, alias="@odata.id")
    grant_id: str = Field(alias="id")
    client_service_principal_object_id: UUID = Field(alias="clientId")
    consent_type: Literal["AllPrincipals"] = Field(alias="consentType")
    principal_id: Literal[None] = Field(alias="principalId")
    resource_service_principal_object_id: UUID = Field(alias="resourceId")
    scope: Literal["access_as_user"]

    @field_validator("grant_id")
    @classmethod
    def validate_grant_id(cls, value: str) -> str:
        if not _bounded_opaque(
            value,
            maximum=MAX_ENTRA_DELEGATED_ADMIN_CONSENT_GRANT_ID_LENGTH,
        ):
            raise ValueError("provider grant ID is invalid")
        return value

    @field_validator("odata_id")
    @classmethod
    def validate_odata_id(cls, value: str | None) -> str | None:
        if value is not None and not _bounded_opaque(
            value,
            maximum=MAX_ENTRA_DELEGATED_ADMIN_CONSENT_ODATA_ID_LENGTH,
        ):
            raise ValueError("provider OData ID is invalid")
        return value

    @model_validator(mode="after")
    def validate_principals(self) -> "_GrantResponse":
        if (
            self.client_service_principal_object_id.int == 0
            or self.resource_service_principal_object_id.int == 0
            or self.client_service_principal_object_id
            == self.resource_service_principal_object_id
        ):
            raise ValueError("provider grant principals are invalid")
        return self


class _GrantCollectionResponse(SecurityModel):
    odata_context: Literal[
        "https://graph.microsoft.com/v1.0/$metadata#oauth2PermissionGrants"
    ] | None = Field(default=None, alias="@odata.context")
    value: tuple[_GrantResponse, ...] = Field(min_length=1, max_length=1)


@dataclass(frozen=True, slots=True)
class EntraDelegatedAdminConsentProbeReceipt:
    receipt_type: str
    schema_version: int
    validation_scope: str
    authorization_permission_type: str
    authorization_permission_name: str
    authorization_permission_id: str
    authorization_consent_requirement: str
    authorization_credential_origin: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    approved_inventory_document_sha256: str
    approved_desired_state_document_sha256: str
    desired_state_document_sha256: str
    offline_desired_state_receipt_sha256: str
    exact_query_sha256: str
    response_projection_sha256: str
    response_grant_id_sha256: str
    delegated_grant_relationship_sha256: str
    request_count: int
    matching_response_count: int
    response_bytes: int
    approved_desired_state_digest_bound: bool
    exact_four_predicate_filter_validated: bool
    client_id_filter_included: bool
    read_only_get_validated: bool
    no_request_body_validated: bool
    no_select_top_count_batch_or_paging_requested: bool
    response_bounds_validated: bool
    response_schema_validated: bool
    exactly_one_matching_response_validated: bool
    client_service_principal_match_validated: bool
    resource_service_principal_match_validated: bool
    tenant_wide_consent_type_validated: bool
    null_principal_id_validated: bool
    exact_single_scope_validated: bool
    response_grant_id_present_and_hashed: bool
    least_privilege_delegated_permission_contract_validated: bool
    out_of_band_operator_contract_validated: bool
    synthetic_transport_used: bool
    live_https_transport_attested: bool
    provider_io_performed: bool
    graph_response_state_checked: bool
    source_authenticity_checked: bool
    exact_response_relationship_checked: bool
    duplicate_matching_grants_checked: bool
    target_grant_response_checked: bool
    replication_freshness_checked: bool
    eventual_consistency_resolved: bool
    concurrent_grant_mutation_checked: bool
    tenant_wide_complete_grant_inventory_checked: bool
    individual_principal_grants_checked: bool
    other_client_resource_relationships_checked: bool
    authorization_token_claims_checked: bool
    actual_token_type_checked: bool
    work_school_account_checked: bool
    token_tenant_checked: bool
    intended_tenant_context_checked: bool
    token_graph_audience_checked: bool
    operator_token_directory_read_all_grant_checked: bool
    operator_identity_checked: bool
    operator_role_checked: bool
    operator_authorization_checked: bool
    admin_consent_effectiveness_checked: bool
    user_assignment_checked: bool
    user_flow_checked: bool
    conditional_access_checked: bool
    runtime_pkce_s256_checked: bool
    real_signed_api_token_scope_checked: bool
    grant_creation_performed: bool
    grant_update_performed: bool
    grant_deletion_performed: bool
    activation_ready: bool

    def __post_init__(self) -> None:
        digests = tuple(
            getattr(self, name)
            for name in self.__dataclass_fields__
            if name.endswith("_sha256")
        )
        static_true = (
            self.approved_desired_state_digest_bound,
            self.exact_four_predicate_filter_validated,
            self.client_id_filter_included,
            self.read_only_get_validated,
            self.no_request_body_validated,
            self.no_select_top_count_batch_or_paging_requested,
            self.response_bounds_validated,
            self.response_schema_validated,
            self.exactly_one_matching_response_validated,
            self.client_service_principal_match_validated,
            self.resource_service_principal_match_validated,
            self.tenant_wide_consent_type_validated,
            self.null_principal_id_validated,
            self.exact_single_scope_validated,
            self.response_grant_id_present_and_hashed,
            self.least_privilege_delegated_permission_contract_validated,
            self.out_of_band_operator_contract_validated,
        )
        deferred = (
            self.replication_freshness_checked,
            self.eventual_consistency_resolved,
            self.concurrent_grant_mutation_checked,
            self.tenant_wide_complete_grant_inventory_checked,
            self.individual_principal_grants_checked,
            self.other_client_resource_relationships_checked,
            self.authorization_token_claims_checked,
            self.actual_token_type_checked,
            self.work_school_account_checked,
            self.token_tenant_checked,
            self.intended_tenant_context_checked,
            self.token_graph_audience_checked,
            self.operator_token_directory_read_all_grant_checked,
            self.operator_identity_checked,
            self.operator_role_checked,
            self.operator_authorization_checked,
            self.admin_consent_effectiveness_checked,
            self.user_assignment_checked,
            self.user_flow_checked,
            self.conditional_access_checked,
            self.runtime_pkce_s256_checked,
            self.real_signed_api_token_scope_checked,
            self.grant_creation_performed,
            self.grant_update_performed,
            self.grant_deletion_performed,
            self.activation_ready,
        )
        live = self.live_https_transport_attested
        if (
            self.receipt_type != ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version != ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_SCHEMA_VERSION
            or self.validation_scope != ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_SCOPE
            or self.authorization_permission_type != "delegated_work_school"
            or self.authorization_permission_name
            != ENTRA_GRAPH_DIRECTORY_READ_ALL_PERMISSION
            or self.authorization_permission_id
            != ENTRA_GRAPH_DIRECTORY_READ_ALL_DELEGATED_PERMISSION_ID
            or self.authorization_consent_requirement != "admin"
            or self.authorization_credential_origin != "out_of_band_operator"
            or any(not _is_lower_sha256(value) for value in digests)
            or not hmac.compare_digest(
                self.approved_desired_state_document_sha256,
                self.desired_state_document_sha256,
            )
            or type(self.request_count) is not int
            or self.request_count != 1
            or type(self.matching_response_count) is not int
            or self.matching_response_count != 1
            or type(self.response_bytes) is not int
            or not 0 < self.response_bytes <= MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_BYTES
            or any(value is not True for value in static_true)
            or any(value is not False for value in deferred)
            or type(self.synthetic_transport_used) is not bool
            or type(live) is not bool
            or self.synthetic_transport_used is live
            or self.provider_io_performed is not live
            or self.graph_response_state_checked is not live
            or self.source_authenticity_checked is not live
            or self.exact_response_relationship_checked is not live
            or self.duplicate_matching_grants_checked is not live
            or self.target_grant_response_checked is not live
        ):
            raise ValueError("Entra delegated admin-consent probe receipt is invalid")


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
        b"engineer4me-step210-v1\x00"
        + str(len(label)).encode("ascii")
        + b":"
        + label.encode("ascii")
        + str(len(material)).encode("ascii")
        + b":"
        + material
    )
    return hashlib.sha256(framed).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EntraDelegatedAdminConsentProbeError(
                "Microsoft Graph consent response contains a duplicate key"
            )
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    del value
    raise EntraDelegatedAdminConsentProbeError(
        "Microsoft Graph consent response contains a non-finite number"
    )


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph consent response contains a non-finite number"
        )
    return parsed


def _require_bounded_structure(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    containers = 0
    while stack:
        current, depth = stack.pop()
        if isinstance(current, dict):
            containers += 1
            if depth > MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_NESTING_DEPTH:
                raise EntraDelegatedAdminConsentProbeError(
                    "Microsoft Graph consent response exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            containers += 1
            if depth > MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_NESTING_DEPTH:
                raise EntraDelegatedAdminConsentProbeError(
                    "Microsoft Graph consent response exceeds the nesting limit"
                )
            stack.extend((item, depth + 1) for item in current)
        if containers > MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_CONTAINERS:
            raise EntraDelegatedAdminConsentProbeError(
                "Microsoft Graph consent response exceeds the structure limit"
            )


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


def _desired_grant(document: bytes) -> dict[str, str | None]:
    try:
        parsed = json.loads(document.decode("utf-8"))
        grant = parsed["grant"]
        return {
            "clientId": grant["clientId"],
            "consentType": grant["consentType"],
            "principalId": grant["principalId"],
            "resourceId": grant["resourceId"],
            "scope": grant["scope"],
        }
    except (KeyError, TypeError, UnicodeDecodeError, ValueError):
        raise EntraDelegatedAdminConsentProbeError(
            "approved desired grant cannot be reconstructed"
        ) from None


def _parse_response(
    response: EntraDelegatedAdminConsentGraphResponse,
    request: EntraDelegatedAdminConsentGraphRequest,
) -> tuple[_GrantCollectionResponse, bytes]:
    if type(response) is not EntraDelegatedAdminConsentGraphResponse:
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph transport returned an invalid consent response"
        )
    try:
        response.validate()
    except ValueError:
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph transport returned an invalid consent response"
        ) from None
    if (
        response.status_code != 200
        or not hmac.compare_digest(response.final_url, request.url)
        or not _content_type_is_json(response.content_type)
        or not response.body
        or len(response.body) > request.maximum_response_bytes
    ):
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph consent response failed the transport contract"
        )
    try:
        decoded = response.body.decode("utf-8")
    except UnicodeDecodeError:
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph consent response must be UTF-8 JSON"
        ) from None
    try:
        parsed = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
            parse_float=_parse_finite_float,
        )
    except EntraDelegatedAdminConsentProbeError:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph consent response is not valid JSON"
        ) from None
    if not isinstance(parsed, dict):
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph consent response root must be an object"
        )
    _require_bounded_structure(parsed)
    allowed_root = {"@odata.context", "value"}
    if "value" not in parsed or not set(parsed).issubset(allowed_root):
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph consent response is incomplete or widened"
        )
    if "@odata.context" in parsed and parsed["@odata.context"] is None:
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph consent response metadata is invalid"
        )
    raw_values = parsed["value"]
    if isinstance(raw_values, list) and any(
        isinstance(item, dict)
        and "@odata.id" in item
        and item["@odata.id"] is None
        for item in raw_values
    ):
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph consent response item metadata is invalid"
        )
    try:
        canonical = _canonical_bytes(parsed)
        validated = _GrantCollectionResponse.model_validate_json(canonical)
    except (RecursionError, TypeError, ValueError, ValidationError):
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph consent response failed schema validation"
        ) from None
    return validated, canonical


def _run_probe(
    *,
    desired_state_document: bytes,
    approved_desired_state_document_sha256: str,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authorization: EntraDelegatedAdminConsentProbeAuthorizationContract,
    transport: EntraDelegatedAdminConsentGraphTransport,
    _live_transport_expected: bool,
) -> EntraDelegatedAdminConsentProbeReceipt:
    if not isinstance(desired_state_document, bytes):
        raise TypeError("approved delegated admin-consent document must be bytes")
    if not _is_lower_sha256(approved_desired_state_document_sha256):
        raise TypeError("approved delegated admin-consent digest is required")
    if type(authorization) is not EntraDelegatedAdminConsentProbeAuthorizationContract:
        raise TypeError("Microsoft Graph consent probe authorization is required")
    try:
        authorization.__post_init__()
    except ValueError:
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph consent probe authorization is invalid"
        ) from None
    if not callable(transport) or type(_live_transport_expected) is not bool:
        raise TypeError("an explicit consent probe transport and mode are required")
    try:
        desired_receipt = load_entra_delegated_admin_consent_readiness(
            document=desired_state_document,
            authentication_preview=authentication_preview,
            api_registration_document=api_registration_document,
            accepted_api_registration_document_sha256=(
                accepted_api_registration_document_sha256
            ),
            calling_client_registration_document=calling_client_registration_document,
            accepted_calling_client_registration_document_sha256=(
                accepted_calling_client_registration_document_sha256
            ),
            inventory_document=inventory_document,
            approved_inventory_document_sha256=approved_inventory_document_sha256,
        )
    except (TypeError, ValueError, EntraDelegatedAdminConsentReadinessError):
        raise EntraDelegatedAdminConsentProbeError(
            "approved consent desired-state evidence is not valid"
        ) from None
    if not hmac.compare_digest(
        desired_receipt.desired_state_document_sha256,
        approved_desired_state_document_sha256,
    ):
        raise EntraDelegatedAdminConsentProbeError(
            "consent desired state does not match its approved digest"
        )
    desired = _desired_grant(desired_state_document)
    request = EntraDelegatedAdminConsentGraphRequest(
        method="GET",
        url=consent_grant_query_url(
            client_service_principal_object_id=str(desired["clientId"]),
            resource_service_principal_object_id=str(desired["resourceId"]),
        ),
        headers=(
            ("Accept", "application/json"),
            ("Accept-Encoding", "identity"),
        ),
        body=None,
        timeout_seconds=ENTRA_DELEGATED_ADMIN_CONSENT_QUERY_TIMEOUT_SECONDS,
        maximum_response_bytes=MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_BYTES,
        follow_redirects=False,
        maximum_retries=0,
        proxy_allowed=False,
    )
    try:
        response = transport(request)
    except Exception:
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph consent probe transport failed"
        ) from None
    collection, canonical_response = _parse_response(response, request)
    if _live_transport_expected and not response.live_https_attested:
        raise EntraDelegatedAdminConsentProbeError(
            "live Microsoft Graph consent response is not attested"
        )
    if not _live_transport_expected and response.live_https_attested:
        raise EntraDelegatedAdminConsentProbeError(
            "attested responses are not accepted by synthetic consent validation"
        )
    grant = collection.value[0]
    if (
        str(grant.client_service_principal_object_id) != desired["clientId"]
        or grant.consent_type != desired["consentType"]
        or grant.principal_id is not desired["principalId"]
        or str(grant.resource_service_principal_object_id) != desired["resourceId"]
        or grant.scope != desired["scope"]
    ):
        raise EntraDelegatedAdminConsentProbeError(
            "Microsoft Graph consent grant does not match approved desired state"
        )
    live = _live_transport_expected
    return EntraDelegatedAdminConsentProbeReceipt(
        receipt_type=ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_RECEIPT_TYPE,
        schema_version=ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_SCHEMA_VERSION,
        validation_scope=ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_SCOPE,
        authorization_permission_type=authorization.permission_type,
        authorization_permission_name=authorization.permission_name,
        authorization_permission_id=authorization.permission_id,
        authorization_consent_requirement=authorization.consent_requirement,
        authorization_credential_origin=authorization.credential_origin,
        configuration_sha256=desired_receipt.configuration_sha256,
        api_registration_document_sha256=(
            desired_receipt.api_registration_document_sha256
        ),
        calling_client_registration_document_sha256=(
            desired_receipt.calling_client_registration_document_sha256
        ),
        approved_inventory_document_sha256=approved_inventory_document_sha256,
        approved_desired_state_document_sha256=(
            approved_desired_state_document_sha256
        ),
        desired_state_document_sha256=desired_receipt.desired_state_document_sha256,
        offline_desired_state_receipt_sha256=hashlib.sha256(
            render_entra_delegated_admin_consent_readiness_receipt(
                desired_receipt
            ).encode("utf-8")
        ).hexdigest(),
        exact_query_sha256=_evidence_sha256("exact_query", request.url.encode()),
        response_projection_sha256=_evidence_sha256(
            "response_projection",
            canonical_response,
        ),
        response_grant_id_sha256=_evidence_sha256(
            "response_grant_id",
            grant.grant_id.encode(),
        ),
        delegated_grant_relationship_sha256=_evidence_sha256(
            "delegated_grant_relationship",
            _canonical_bytes(
                {
                    "clientId": str(grant.client_service_principal_object_id),
                    "consentType": grant.consent_type,
                    "principalId": grant.principal_id,
                    "resourceId": str(grant.resource_service_principal_object_id),
                    "scope": grant.scope,
                }
            ),
        ),
        request_count=1,
        matching_response_count=1,
        response_bytes=len(response.body),
        approved_desired_state_digest_bound=True,
        exact_four_predicate_filter_validated=True,
        client_id_filter_included=True,
        read_only_get_validated=True,
        no_request_body_validated=True,
        no_select_top_count_batch_or_paging_requested=True,
        response_bounds_validated=True,
        response_schema_validated=True,
        exactly_one_matching_response_validated=True,
        client_service_principal_match_validated=True,
        resource_service_principal_match_validated=True,
        tenant_wide_consent_type_validated=True,
        null_principal_id_validated=True,
        exact_single_scope_validated=True,
        response_grant_id_present_and_hashed=True,
        least_privilege_delegated_permission_contract_validated=True,
        out_of_band_operator_contract_validated=True,
        synthetic_transport_used=not live,
        live_https_transport_attested=live,
        provider_io_performed=live,
        graph_response_state_checked=live,
        source_authenticity_checked=live,
        exact_response_relationship_checked=live,
        duplicate_matching_grants_checked=live,
        target_grant_response_checked=live,
        replication_freshness_checked=False,
        eventual_consistency_resolved=False,
        concurrent_grant_mutation_checked=False,
        tenant_wide_complete_grant_inventory_checked=False,
        individual_principal_grants_checked=False,
        other_client_resource_relationships_checked=False,
        authorization_token_claims_checked=False,
        actual_token_type_checked=False,
        work_school_account_checked=False,
        token_tenant_checked=False,
        intended_tenant_context_checked=False,
        token_graph_audience_checked=False,
        operator_token_directory_read_all_grant_checked=False,
        operator_identity_checked=False,
        operator_role_checked=False,
        operator_authorization_checked=False,
        admin_consent_effectiveness_checked=False,
        user_assignment_checked=False,
        user_flow_checked=False,
        conditional_access_checked=False,
        runtime_pkce_s256_checked=False,
        real_signed_api_token_scope_checked=False,
        grant_creation_performed=False,
        grant_update_performed=False,
        grant_deletion_performed=False,
        activation_ready=False,
    )


def validate_entra_delegated_admin_consent_probe(
    *,
    desired_state_document: bytes,
    approved_desired_state_document_sha256: str,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authorization: EntraDelegatedAdminConsentProbeAuthorizationContract,
    transport: EntraDelegatedAdminConsentGraphTransport,
) -> EntraDelegatedAdminConsentProbeReceipt:
    """Validate deterministic response bytes without provider-proof claims."""

    return _run_probe(
        desired_state_document=desired_state_document,
        approved_desired_state_document_sha256=(
            approved_desired_state_document_sha256
        ),
        authentication_preview=authentication_preview,
        api_registration_document=api_registration_document,
        accepted_api_registration_document_sha256=(
            accepted_api_registration_document_sha256
        ),
        calling_client_registration_document=calling_client_registration_document,
        accepted_calling_client_registration_document_sha256=(
            accepted_calling_client_registration_document_sha256
        ),
        inventory_document=inventory_document,
        approved_inventory_document_sha256=approved_inventory_document_sha256,
        authorization=authorization,
        transport=transport,
        _live_transport_expected=False,
    )


def probe_live_entra_delegated_admin_consent(
    *,
    desired_state_document: bytes,
    approved_desired_state_document_sha256: str,
    authentication_preview: AuthenticationReadinessPreview,
    api_registration_document: bytes,
    accepted_api_registration_document_sha256: str,
    calling_client_registration_document: bytes,
    accepted_calling_client_registration_document_sha256: str,
    inventory_document: bytes,
    approved_inventory_document_sha256: str,
    authorization: EntraDelegatedAdminConsentProbeAuthorizationContract,
    delegated_access_token: str,
) -> EntraDelegatedAdminConsentProbeReceipt:
    """Perform the single direct live HTTPS query with an ephemeral token."""

    loader = BoundedHTTPSEntraDelegatedAdminConsentGraphLoader(
        delegated_access_token=delegated_access_token
    )
    try:
        return _run_probe(
            desired_state_document=desired_state_document,
            approved_desired_state_document_sha256=(
                approved_desired_state_document_sha256
            ),
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
            inventory_document=inventory_document,
            approved_inventory_document_sha256=approved_inventory_document_sha256,
            authorization=authorization,
            transport=loader,
            _live_transport_expected=True,
        )
    finally:
        loader.close()


def render_entra_delegated_admin_consent_probe_receipt(
    receipt: EntraDelegatedAdminConsentProbeReceipt,
) -> str:
    """Render canonical privacy-minimized proof evidence."""

    if type(receipt) is not EntraDelegatedAdminConsentProbeReceipt:
        raise TypeError("Entra delegated admin-consent probe receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {field: getattr(receipt, field) for field in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_RECEIPT_TYPE",
    "ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_SCHEMA_VERSION",
    "ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_SCOPE",
    "ENTRA_GRAPH_DIRECTORY_READ_ALL_DELEGATED_PERMISSION_ID",
    "ENTRA_GRAPH_DIRECTORY_READ_ALL_PERMISSION",
    "EntraDelegatedAdminConsentProbeAuthorizationContract",
    "EntraDelegatedAdminConsentProbeError",
    "EntraDelegatedAdminConsentProbeReceipt",
    "probe_live_entra_delegated_admin_consent",
    "render_entra_delegated_admin_consent_probe_receipt",
    "validate_entra_delegated_admin_consent_probe",
]
