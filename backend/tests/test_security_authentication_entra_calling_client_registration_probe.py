"""Tests for the controlled Step 213 Graph SPA-registration proof."""

from __future__ import annotations

import inspect
import json
from dataclasses import fields

import app.security.authentication_entra_calling_client_registration_graph_http_loader as loader_module
import app.security.authentication_entra_calling_client_registration_probe as module
import pytest
from app.security.authentication_entra_api_registration_readiness import (
    ENTRA_API_REGISTRATION_DOCUMENT_TYPE,
    load_entra_api_registration_readiness,
)
from app.security.authentication_entra_application_service_principal_inventory_readiness import (
    ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_TYPE,
    ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SOURCE,
    load_entra_application_service_principal_inventory_readiness,
)
from app.security.authentication_entra_calling_client_registration_graph_http_loader import (
    ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_SELECT,
    ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_REQUEST_COUNT,
    EntraCallingClientRegistrationGraphResponse,
)
from app.security.authentication_entra_calling_client_registration_probe import (
    ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_RECEIPT_TYPE,
    ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_SCOPE,
    ENTRA_GRAPH_APPLICATION_READ_ALL_DELEGATED_PERMISSION_ID,
    ENTRA_GRAPH_APPLICATION_READ_ALL_PERMISSION,
    ENTRA_GRAPH_CALLING_CLIENT_OWNER_ACCESS_BASIS,
    MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_TOTAL_RESPONSE_BYTES,
    EntraCallingClientRegistrationGraphAuthorizationContract,
    EntraCallingClientRegistrationGraphProbeError,
    probe_live_entra_calling_client_registration_graph,
    render_entra_calling_client_registration_graph_probe_receipt,
    validate_entra_calling_client_registration_graph_probe,
)
from app.security.authentication_entra_calling_client_registration_readiness import (
    ENTRA_CALLING_CLIENT_ARCHITECTURE,
    ENTRA_CALLING_CLIENT_REGISTRATION_DOCUMENT_TYPE,
    load_entra_calling_client_registration_readiness,
)
from app.security.authentication_readiness_document import (
    load_authentication_readiness_document,
)

TENANT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeee0200"
API_APPLICATION_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffff0300"
API_APPLICATION_OBJECT_ID = "cccccccc-dddd-4eee-8fff-aaaaaaaa0400"
API_SCOPE_ID = "dddddddd-eeee-4fff-8aaa-bbbbbbbb0500"
CALLING_CLIENT_APPLICATION_ID = "11111111-2222-4333-8abc-555555555555"
CALLING_CLIENT_OBJECT_ID = "22222222-3333-4444-8def-666666666666"
API_SERVICE_PRINCIPAL_OBJECT_ID = "33333333-4444-4555-8abc-777777777777"
CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID = "44444444-5555-4666-8def-888888888888"
OWNER_ID = "eeeeeeee-ffff-4aaa-8bbb-cccccccc0600"
OWNER_ID_2 = "ffffffff-aaaa-4bbb-8ccc-dddddddd0700"
REDIRECT_URI = "https://app.engineer4me.invalid/auth/callback"
REDIRECT_URI_2 = "https://app.engineer4me.invalid/auth/complete"
ISSUER = f"https://synthetic.ciamlogin.com/{TENANT_ID}/v2.0"
TOKEN = "step213-sentinel-opaque-token"
_UNSET = object()


def authentication_preview():
    document = {
        "document_type": "engineer4me_authentication_readiness",
        "schema_version": 1,
        "authentication": {
            "issuer": ISSUER,
            "audience": API_APPLICATION_ID,
            "jwks_url": "https://synthetic.ciamlogin.com/discovery/v2.0/keys",
            "algorithms": ["RS256"],
            "token_identifier_claim": "uti",
            "token_profile": "microsoft_entra_v2",
            "microsoft_entra_tenant_id": TENANT_ID,
            "microsoft_entra_api_application_id": API_APPLICATION_ID,
            "microsoft_entra_required_delegated_scope": "access_as_user",
            "microsoft_entra_calling_client_application_id": (
                CALLING_CLIENT_APPLICATION_ID
            ),
            "microsoft_entra_required_azpacr": "0",
        },
    }
    return load_authentication_readiness_document(json.dumps(document).encode()).preview


def api_registration_values(preview):
    return {
        "document_type": ENTRA_API_REGISTRATION_DOCUMENT_TYPE,
        "schema_version": 1,
        "approved_configuration_sha256": preview.configuration_sha256,
        "registration": {
            "tenant_id": TENANT_ID,
            "api_application_id": API_APPLICATION_ID,
            "application_object_id": API_APPLICATION_OBJECT_ID,
            "display_name": "Engineer4Me API",
            "description": None,
            "notes": None,
            "marketing_url": None,
            "privacy_statement_url": None,
            "support_url": None,
            "terms_of_service_url": None,
            "logo_configured": False,
            "owner_object_ids": [OWNER_ID],
            "sign_in_audience": "AzureADMyOrg",
            "requested_access_token_version": 2,
            "accept_mapped_claims": False,
            "identifier_uris": [f"api://{API_APPLICATION_ID}"],
            "delegated_scopes": [
                {
                    "scope_id": API_SCOPE_ID,
                    "value": "access_as_user",
                    "consent": "admins_only",
                    "enabled": True,
                    "admin_consent_display_name": (
                        "Access Engineer4Me as the signed-in user"
                    ),
                    "admin_consent_description": (
                        "Allow this application to access Engineer4Me as the signed-in user."
                    ),
                    "user_consent_display_name": None,
                    "user_consent_description": None,
                }
            ],
            "web_redirect_uris": [],
            "spa_redirect_uris": [],
            "public_client_redirect_uris": [],
            "implicit_access_token_enabled": False,
            "implicit_id_token_enabled": False,
            "public_client_fallback_enabled": False,
            "password_credential_ids": [],
            "key_credential_ids": [],
            "federated_identity_credential_ids": [],
            "app_role_ids": [],
            "preauthorized_client_application_ids": [],
            "known_client_application_ids": [],
            "required_resource_application_ids": [],
            "optional_claims_configured": False,
            "group_membership_claims_configured": False,
            "token_encryption_key_configured": False,
            "add_in_ids": [],
            "home_page_url": None,
            "logout_url": None,
        },
    }


def calling_client_values(preview, api_receipt):
    return {
        "document_type": ENTRA_CALLING_CLIENT_REGISTRATION_DOCUMENT_TYPE,
        "schema_version": 1,
        "approved_configuration_sha256": preview.configuration_sha256,
        "approved_api_registration_document_sha256": (
            api_receipt.registration_document_sha256
        ),
        "registration": {
            "tenant_id": TENANT_ID,
            "api_application_id": API_APPLICATION_ID,
            "api_application_object_id": API_APPLICATION_OBJECT_ID,
            "api_delegated_scope_id": API_SCOPE_ID,
            "calling_client_application_id": CALLING_CLIENT_APPLICATION_ID,
            "calling_client_application_object_id": CALLING_CLIENT_OBJECT_ID,
            "display_name": "Engineer4Me Web",
            "description": None,
            "notes": None,
            "marketing_url": None,
            "privacy_statement_url": None,
            "support_url": None,
            "terms_of_service_url": None,
            "desired_logo_configured": False,
            "owner_object_ids": [OWNER_ID, OWNER_ID_2],
            "desired_sign_in_audience": "AzureADMyOrg",
            "desired_client_architecture": ENTRA_CALLING_CLIENT_ARCHITECTURE,
            "desired_browser_flow": "authorization_code_pkce",
            "desired_pkce_method": "S256",
            "desired_client_authentication_method": "none",
            "desired_authorization_code_flow_enabled": True,
            "desired_pkce_required": True,
            "spa_redirect_uris": sorted([REDIRECT_URI, REDIRECT_URI_2]),
            "web_redirect_uris": [],
            "public_client_redirect_uris": [],
            "desired_implicit_access_token_enabled": False,
            "desired_implicit_id_token_enabled": False,
            "desired_public_client_fallback_enabled": False,
            "desired_native_authentication_apis_enabled": "none",
            "desired_device_only_auth_supported": False,
            "desired_device_code_flow_enabled": False,
            "desired_resource_owner_password_flow_enabled": False,
            "desired_client_credentials_flow_enabled": False,
            "desired_on_behalf_of_flow_enabled": False,
            "password_credential_ids": [],
            "key_credential_ids": [],
            "federated_identity_credential_ids": [],
            "required_resource_access": [
                {
                    "resource_application_id": API_APPLICATION_ID,
                    "delegated_scope_id": API_SCOPE_ID,
                    "permission_type": "Scope",
                    "scope_value": "access_as_user",
                }
            ],
            "microsoft_graph_permission_ids": [],
            "identifier_uris": [],
            "exposed_delegated_scope_ids": [],
            "app_role_ids": [],
            "preauthorized_client_application_ids": [],
            "known_client_application_ids": [],
            "desired_optional_claims_configured": False,
            "desired_group_membership_claims_configured": False,
            "desired_token_encryption_key_configured": False,
            "desired_api_accept_mapped_claims": False,
            "desired_oauth2_required_post_response": False,
            "add_in_ids": [],
            "desired_runtime_oidc_scopes": ["offline_access", "openid", "profile"],
            "desired_runtime_api_scope": f"api://{API_APPLICATION_ID}/access_as_user",
            "home_page_url": None,
            "logout_url": None,
        },
    }


def inventory_values(preview, registration):
    return {
        "document_type": ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_DOCUMENT_TYPE,
        "schema_version": 1,
        "source": ENTRA_APPLICATION_SERVICE_PRINCIPAL_INVENTORY_SOURCE,
        "approved_configuration_sha256": preview.configuration_sha256,
        "approved_api_registration_document_sha256": registration[
            "accepted_api_registration_document_sha256"
        ],
        "approved_calling_client_registration_document_sha256": registration[
            "accepted_calling_client_registration_document_sha256"
        ],
        "inventory": {
            "tenant_id": TENANT_ID,
            "applications": [
                {
                    "role": "api",
                    "application_id": API_APPLICATION_ID,
                    "application_object_id": API_APPLICATION_OBJECT_ID,
                },
                {
                    "role": "calling_client",
                    "application_id": CALLING_CLIENT_APPLICATION_ID,
                    "application_object_id": CALLING_CLIENT_OBJECT_ID,
                },
            ],
            "service_principals": [
                {
                    "role": "api",
                    "service_principal_object_id": API_SERVICE_PRINCIPAL_OBJECT_ID,
                    "application_id": API_APPLICATION_ID,
                    "application_owner_organization_id": TENANT_ID,
                    "service_principal_type": "Application",
                    "account_enabled": True,
                    "disabled_by_microsoft_status": None,
                },
                {
                    "role": "calling_client",
                    "service_principal_object_id": (
                        CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID
                    ),
                    "application_id": CALLING_CLIENT_APPLICATION_ID,
                    "application_owner_organization_id": TENANT_ID,
                    "service_principal_type": "Application",
                    "account_enabled": True,
                    "disabled_by_microsoft_status": "NotDisabled",
                },
            ],
        },
    }


def prerequisites():
    preview = authentication_preview()
    api_document = json.dumps(api_registration_values(preview)).encode()
    api_receipt = load_entra_api_registration_readiness(
        document=api_document,
        authentication_preview=preview,
    )
    client_document = json.dumps(calling_client_values(preview, api_receipt)).encode()
    client_receipt = load_entra_calling_client_registration_readiness(
        document=client_document,
        authentication_preview=preview,
        api_registration_document=api_document,
        accepted_api_registration_document_sha256=(
            api_receipt.registration_document_sha256
        ),
    )
    registration = {
        "api_registration_document": api_document,
        "accepted_api_registration_document_sha256": (
            api_receipt.registration_document_sha256
        ),
        "calling_client_registration_document": client_document,
        "accepted_calling_client_registration_document_sha256": (
            client_receipt.client_registration_document_sha256
        ),
    }
    inventory_document = json.dumps(inventory_values(preview, registration)).encode()
    inventory_receipt = load_entra_application_service_principal_inventory_readiness(
        document=inventory_document,
        authentication_preview=preview,
        **registration,
    )
    return {
        "authentication_preview": preview,
        **registration,
        "inventory_document": inventory_document,
        "approved_inventory_document_sha256": (
            inventory_receipt.inventory_document_sha256
        ),
    }


def authorization():
    return EntraCallingClientRegistrationGraphAuthorizationContract(
        permission_type="delegated_work_school",
        permission_name=ENTRA_GRAPH_APPLICATION_READ_ALL_PERMISSION,
        permission_id=ENTRA_GRAPH_APPLICATION_READ_ALL_DELEGATED_PERMISSION_ID,
        consent_requirement="admin",
        credential_origin="out_of_band_operator",
        access_basis=ENTRA_GRAPH_CALLING_CLIENT_OWNER_ACCESS_BASIS,
    )


def application_body(*, context=False, types=False):
    body = {
        "id": CALLING_CLIENT_OBJECT_ID,
        "appId": CALLING_CLIENT_APPLICATION_ID,
        "deletedDateTime": None,
        "disabledByMicrosoftStatus": None,
        "displayName": "Engineer4Me Web",
        "description": None,
        "notes": None,
        "signInAudience": "AzureADMyOrg",
        "spa": {"redirectUris": [REDIRECT_URI_2, REDIRECT_URI]},
        "web": {
            "homePageUrl": None,
            "logoutUrl": None,
            "redirectUris": [],
            "implicitGrantSettings": {
                "enableAccessTokenIssuance": False,
                "enableIdTokenIssuance": False,
            },
        },
        "publicClient": {"redirectUris": []},
        "isFallbackPublicClient": None,
        "isDeviceOnlyAuthSupported": False,
        "nativeAuthenticationApisEnabled": "none",
        "oauth2RequiredPostResponse": False,
        "passwordCredentials": [],
        "keyCredentials": [],
        "requiredResourceAccess": [
            {
                "resourceAppId": API_APPLICATION_ID,
                "resourceAccess": [{"id": API_SCOPE_ID, "type": "Scope"}],
            }
        ],
        "identifierUris": [],
        "appRoles": [],
        "api": {
            "acceptMappedClaims": None,
            "knownClientApplications": [],
            "oauth2PermissionScopes": [],
            "preAuthorizedApplications": [],
            "requestedAccessTokenVersion": None,
        },
        "optionalClaims": None,
        "groupMembershipClaims": None,
        "tokenEncryptionKeyId": None,
        "addIns": [],
        "info": {
            "logoUrl": None,
            "marketingUrl": None,
            "privacyStatementUrl": None,
            "supportUrl": None,
            "termsOfServiceUrl": None,
        },
    }
    if context:
        body["@odata.context"] = (
            "https://graph.microsoft.com/v1.0/$metadata#applications("
            f"{ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_APPLICATION_SELECT})/$entity"
        )
    if types:
        body["@odata.type"] = "#microsoft.graph.application"
        body["spa"]["@odata.type"] = "#microsoft.graph.spaApplication"
        body["web"]["@odata.type"] = "#microsoft.graph.webApplication"
        body["web"]["implicitGrantSettings"]["@odata.type"] = (
            "#microsoft.graph.implicitGrantSettings"
        )
        body["publicClient"]["@odata.type"] = "#microsoft.graph.publicClientApplication"
        body["requiredResourceAccess"][0]["@odata.type"] = (
            "#microsoft.graph.requiredResourceAccess"
        )
        body["requiredResourceAccess"][0]["resourceAccess"][0]["@odata.type"] = (
            "#microsoft.graph.resourceAccess"
        )
        body["api"]["@odata.type"] = "#microsoft.graph.apiApplication"
        body["info"]["@odata.type"] = "#microsoft.graph.informationalUrl"
    return body


def owners_body(*, context=False, types=False, reverse=False):
    values = [{"id": OWNER_ID}, {"id": OWNER_ID_2}]
    if reverse:
        values.reverse()
    if types:
        values[0]["@odata.type"] = "#microsoft.graph.user"
        values[1]["@odata.type"] = "#microsoft.graph.servicePrincipal"
    body = {"value": values}
    if context:
        body["@odata.context"] = (
            "https://graph.microsoft.com/v1.0/$metadata#directoryObjects(id)"
        )
    return body


def fic_body(*, context=False, selected=True):
    body = {"value": []}
    if context:
        suffix = "(id)" if selected else ""
        body["@odata.context"] = (
            "https://graph.microsoft.com/v1.0/$metadata#applications("
            f"'{CALLING_CLIENT_OBJECT_ID}')/federatedIdentityCredentials{suffix}"
        )
    return body


def response_set(plan, *, application=None, owners=None, fic=None, changes=None):
    bodies = (
        application_body() if application is None else application,
        owners_body() if owners is None else owners,
        fic_body() if fic is None else fic,
    )
    result = []
    for index, (request, body) in enumerate(zip(plan, bodies, strict=True)):
        encoded = body if isinstance(body, bytes) else json.dumps(body).encode()
        values = {
            "status_code": 200,
            "final_url": request.url,
            "content_type": "application/json",
            "body": encoded,
        }
        values.update((changes or {}).get(index, {}))
        result.append(EntraCallingClientRegistrationGraphResponse(**values))
    return tuple(result)


class SyntheticTransport:
    def __init__(self, *, application=None, owners=None, fic=None, responses=_UNSET):
        self.application = application
        self.owners = owners
        self.fic = fic
        self.responses = responses
        self.plans = []

    def __call__(self, plan):
        self.plans.append(plan)
        if self.responses is not _UNSET:
            return self.responses
        return response_set(
            plan,
            application=self.application,
            owners=self.owners,
            fic=self.fic,
        )


def validate(*, prerequisite=None, transport=None):
    return validate_entra_calling_client_registration_graph_probe(
        **(prerequisite or prerequisites()),
        authorization=authorization(),
        transport=transport or SyntheticTransport(),
    )


def assert_no_secret_in_production_exception_graph(error, secrets):
    modules = {module.__name__, loader_module.__name__}
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        for secret in secrets:
            assert secret not in str(current)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
        traceback = current.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if frame.f_globals.get("__name__") in modules:
                values = list(frame.f_locals.values())
                checked = set()
                while values:
                    value = values.pop()
                    if id(value) in checked:
                        continue
                    checked.add(id(value))
                    if isinstance(value, str):
                        for secret in secrets:
                            assert secret not in value
                    elif isinstance(value, bytes):
                        for secret in secrets:
                            assert secret.encode() not in value
                    elif isinstance(value, dict):
                        values.extend(value.keys())
                        values.extend(value.values())
                    elif isinstance(value, (list, tuple, set, frozenset)):
                        values.extend(value)
                    if hasattr(value, "_delegated_access_token"):
                        values.append(value._delegated_access_token)
            traceback = traceback.tb_next


def set_path(value, path, replacement):
    target = value
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = replacement


def test_valid_synthetic_proof_is_canonical_private_and_precise():
    receipt = validate()
    rendered = render_entra_calling_client_registration_graph_probe_receipt(receipt)
    parsed = json.loads(rendered)
    assert rendered == json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    assert (
        parsed["receipt_type"]
        == ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_RECEIPT_TYPE
    )
    assert (
        parsed["validation_scope"]
        == ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_PROBE_SCOPE
    )
    assert parsed["request_count"] == parsed["response_count"] == 3
    assert parsed["response_owner_count"] == 2
    assert parsed["desired_spa_redirect_uri_count"] == 2
    assert parsed["synthetic_transport_used"] is True
    assert parsed["live_https_transport_attested"] is False
    assert parsed["provider_state_checked"] is False
    assert parsed["api_requested_access_token_version"] is None
    assert parsed["api_requested_access_token_version_approved_state_checked"] is False
    assert parsed["spa_redirect_wire_order_normalized"] is True
    assert parsed["receipt_self_authenticating"] is False
    assert parsed["activation_ready"] is False
    assert parsed["total_response_bytes"] <= (
        MAX_ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_TOTAL_RESPONSE_BYTES
    )
    for secret in (
        TENANT_ID,
        API_APPLICATION_ID,
        API_APPLICATION_OBJECT_ID,
        API_SCOPE_ID,
        CALLING_CLIENT_APPLICATION_ID,
        CALLING_CLIENT_OBJECT_ID,
        OWNER_ID,
        OWNER_ID_2,
        REDIRECT_URI,
        REDIRECT_URI_2,
        TOKEN,
    ):
        assert secret not in rendered


def test_request_plan_is_exact_same_object_get_only_and_unpaged():
    transport = SyntheticTransport()
    validate(transport=transport)
    plan = transport.plans[0]
    assert len(plan) == ENTRA_CALLING_CLIENT_REGISTRATION_GRAPH_REQUEST_COUNT == 3
    assert [request.sequence for request in plan] == [1, 2, 3]
    assert [request.resource for request in plan] == [
        "calling_client_application",
        "owners",
        "federated_identity_credentials",
    ]
    assert all(request.method == "GET" and request.body is None for request in plan)
    assert all(
        "graph.microsoft.com/v1.0/applications/" in request.url for request in plan
    )
    assert all(CALLING_CLIENT_OBJECT_ID in request.url for request in plan)
    assert all(
        term not in request.url
        for request in plan
        for term in ("$top", "$count", "$expand", "$batch")
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("permission_type", "application"),
        ("permission_name", "Directory.Read.All"),
        ("permission_id", "00000000-0000-0000-0000-000000000000"),
        ("consent_requirement", "user"),
        ("credential_origin", "application_secret"),
        ("access_basis", "global_administrator"),
    ],
)
def test_authorization_contract_rejects_every_widening(field, value):
    values = (
        authorization().__dict__.copy()
        if hasattr(authorization(), "__dict__")
        else {
            name: getattr(authorization(), name)
            for name in authorization().__dataclass_fields__
        }
    )
    values[field] = value
    with pytest.raises(ValueError, match="authorization"):
        EntraCallingClientRegistrationGraphAuthorizationContract(**values)


def test_documented_metadata_types_and_default_normalizations_are_accepted():
    app = application_body(context=True, types=True)
    app["isFallbackPublicClient"] = False
    app["isDeviceOnlyAuthSupported"] = None
    app["api"]["acceptMappedClaims"] = False
    app["groupMembershipClaims"] = "None"
    app["api"]["requestedAccessTokenVersion"] = 2
    receipt = validate(
        transport=SyntheticTransport(
            application=app,
            owners=owners_body(context=True, types=True, reverse=True),
            fic=fic_body(context=True),
        )
    )
    assert receipt.fallback_public_client_wire_form == "false"
    assert receipt.device_only_auth_wire_form == "null"
    assert receipt.accept_mapped_claims_wire_form == "false"
    assert receipt.group_membership_claims_wire_form == "None"
    assert receipt.api_requested_access_token_version == 2


@pytest.mark.parametrize(
    "context",
    [
        "https://graph.microsoft.us/v1.0/$metadata#applications(id)/$entity",
        "https://graph.microsoft.com/beta/$metadata#applications(id)/$entity",
        "https://graph.microsoft.com/v1.0/$metadata#applications(id)",
        "https://graph.microsoft.com/v1.0/$metadata#servicePrincipals(id)/$entity",
    ],
)
def test_wrong_application_context_rejects(context):
    body = application_body()
    body["@odata.context"] = context
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=SyntheticTransport(application=body))


def test_redirect_and_owner_wire_order_are_normalized_with_stable_identity_hashes():
    first = validate()
    app = application_body()
    app["spa"]["redirectUris"].reverse()
    second = validate(
        transport=SyntheticTransport(
            application=app,
            owners=owners_body(reverse=True),
        )
    )
    assert first.spa_redirect_uris_sha256 == second.spa_redirect_uris_sha256
    assert first.owner_object_ids_sha256 == second.owner_object_ids_sha256
    assert (
        first.registration_security_surfaces_sha256
        == second.registration_security_surfaces_sha256
    )
    assert first.application_response_sha256 != second.application_response_sha256


@pytest.mark.parametrize("version", [None, 1, 2])
def test_requested_access_token_version_is_bounded_but_not_claimed_approved(version):
    app = application_body()
    app["api"]["requestedAccessTokenVersion"] = version
    receipt = validate(transport=SyntheticTransport(application=app))
    assert receipt.api_requested_access_token_version == version
    assert receipt.api_requested_access_token_version_approved_state_checked is False


@pytest.mark.parametrize("version", [0, 3, True, "2", [], {}])
def test_requested_access_token_version_rejects_other_values(version):
    app = application_body()
    app["api"]["requestedAccessTokenVersion"] = version
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=SyntheticTransport(application=app))


@pytest.mark.parametrize(
    "path",
    [
        ("web", "implicitGrantSettings", "enableAccessTokenIssuance"),
        ("web", "implicitGrantSettings", "enableIdTokenIssuance"),
        ("nativeAuthenticationApisEnabled",),
        ("oauth2RequiredPostResponse",),
    ],
)
def test_null_is_not_a_wildcard_for_exact_disabled_security_fields(path):
    body = application_body()
    set_path(body, path, None)
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=SyntheticTransport(application=body))


@pytest.mark.parametrize(
    "path,replacement",
    [
        (("id",), API_APPLICATION_OBJECT_ID),
        (("appId",), API_APPLICATION_ID),
        (("deletedDateTime",), "2026-01-01T00:00:00Z"),
        (("disabledByMicrosoftStatus",), "DisabledDueToViolationOfServicesAgreement"),
        (("displayName",), "Other"),
        (("description",), "text"),
        (("notes",), "text"),
        (("signInAudience",), "AzureADMultipleOrgs"),
        (("spa", "redirectUris"), [REDIRECT_URI]),
        (("spa", "redirectUris"), [REDIRECT_URI, REDIRECT_URI]),
        (("web", "redirectUris"), [REDIRECT_URI]),
        (("web", "homePageUrl"), REDIRECT_URI),
        (("web", "logoutUrl"), REDIRECT_URI),
        (("web", "implicitGrantSettings", "enableAccessTokenIssuance"), True),
        (("web", "implicitGrantSettings", "enableIdTokenIssuance"), True),
        (("publicClient", "redirectUris"), ["http://localhost"]),
        (("isFallbackPublicClient",), True),
        (("isDeviceOnlyAuthSupported",), True),
        (("nativeAuthenticationApisEnabled",), "all"),
        (("oauth2RequiredPostResponse",), True),
        (("passwordCredentials",), [{"keyId": OWNER_ID}]),
        (("keyCredentials",), [{"keyId": OWNER_ID}]),
        (("requiredResourceAccess", 0, "resourceAppId"), CALLING_CLIENT_APPLICATION_ID),
        (("requiredResourceAccess", 0, "resourceAccess", 0, "id"), OWNER_ID),
        (("requiredResourceAccess", 0, "resourceAccess", 0, "type"), "Role"),
        (("identifierUris",), ["api://other"]),
        (("appRoles",), [{"id": OWNER_ID}]),
        (("api", "acceptMappedClaims"), True),
        (("api", "knownClientApplications"), [API_APPLICATION_ID]),
        (("api", "oauth2PermissionScopes"), [{"id": OWNER_ID}]),
        (("api", "preAuthorizedApplications"), [{"appId": API_APPLICATION_ID}]),
        (("optionalClaims",), {}),
        (("groupMembershipClaims",), "All"),
        (("tokenEncryptionKeyId",), OWNER_ID),
        (("addIns",), [{"id": OWNER_ID}]),
        (("info", "logoUrl"), "https://logo.invalid/x"),
        (("info", "marketingUrl"), "https://marketing.invalid"),
        (("info", "privacyStatementUrl"), "https://privacy.invalid"),
        (("info", "supportUrl"), "https://support.invalid"),
        (("info", "termsOfServiceUrl"), "https://terms.invalid"),
    ],
)
def test_every_selected_core_security_surface_mismatch_rejects(path, replacement):
    body = application_body()
    set_path(body, path, replacement)
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=SyntheticTransport(application=body))


@pytest.mark.parametrize("field", [key for key in application_body()])
def test_missing_every_selected_core_field_rejects(field):
    body = application_body()
    del body[field]
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=SyntheticTransport(application=body))


@pytest.mark.parametrize(
    "path",
    [
        ("id",),
        ("appId",),
        ("requiredResourceAccess", 0, "resourceAppId"),
        ("requiredResourceAccess", 0, "resourceAccess", 0, "id"),
    ],
)
@pytest.mark.parametrize(
    "transform",
    [str.upper, lambda value: "{" + value + "}", lambda value: value.replace("-", "")],
)
def test_noncanonical_core_uuid_wire_forms_reject(path, transform):
    body = application_body()
    target = body
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = transform(target[path[-1]])
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=SyntheticTransport(application=body))


def test_unknown_fields_and_explicit_null_metadata_reject_at_every_level():
    bodies = []
    for path in [
        (),
        ("spa",),
        ("web",),
        ("web", "implicitGrantSettings"),
        ("publicClient",),
        ("requiredResourceAccess", 0),
        ("requiredResourceAccess", 0, "resourceAccess", 0),
        ("api",),
        ("info",),
    ]:
        body = application_body()
        target = body
        for part in path:
            target = target[part]
        target["unknown"] = True
        bodies.append(body)
        body = application_body()
        target = body
        for part in path:
            target = target[part]
        target["@odata.type"] = None
        bodies.append(body)
    for body in bodies:
        with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
            validate(transport=SyntheticTransport(application=body))


@pytest.mark.parametrize(
    "odata_type",
    [
        "#microsoft.graph.agentIdentityBlueprint",
        "#microsoft.graph.servicePrincipal",
        "microsoft.graph.application",
        None,
    ],
)
def test_wrong_or_explicit_null_root_wire_type_rejects(odata_type):
    body = application_body()
    body["@odata.type"] = odata_type
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=SyntheticTransport(application=body))


@pytest.mark.parametrize(
    "mutator",
    [
        lambda body: body.update(
            {"@odata.nextLink": "https://graph.microsoft.com/next"}
        ),
        lambda body: body.update({"@odata.count": 2}),
        lambda body: body.update({"extra": True}),
        lambda body: body.update({"@odata.context": None}),
        lambda body: body.update({"value": [{"id": OWNER_ID}]}),
        lambda body: body.update({"value": [{"id": OWNER_ID}, {"id": OWNER_ID}]}),
        lambda body: body.update(
            {"value": [{"id": OWNER_ID}, {"id": API_APPLICATION_ID}]}
        ),
        lambda body: body["value"][0].update({"displayName": "leak"}),
        lambda body: body["value"][0].update({"@odata.type": "#microsoft.graph.group"}),
        lambda body: body["value"][0].update({"@odata.type": None}),
        lambda body: body["value"][0].update({"id": OWNER_ID.upper()}),
    ],
)
def test_owner_collection_alias_paging_schema_identity_and_canonicality_reject(mutator):
    body = owners_body()
    mutator(body)
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=SyntheticTransport(owners=body))


@pytest.mark.parametrize(
    "context",
    [
        "https://graph.microsoft.us/v1.0/$metadata#directoryObjects(id)",
        "https://graph.microsoft.com/beta/$metadata#directoryObjects(id)",
        "https://graph.microsoft.com/v1.0/$metadata#users(id)",
    ],
)
def test_wrong_owner_context_rejects(context):
    body = owners_body()
    body["@odata.context"] = context
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=SyntheticTransport(owners=body))


@pytest.mark.parametrize("selected", [False, True])
def test_exact_object_bound_fic_context_forms_accept(selected):
    validate(
        transport=SyntheticTransport(fic=fic_body(context=True, selected=selected))
    )


@pytest.mark.parametrize("selected", [False, True])
def test_documented_no_version_object_bound_fic_context_forms_accept(selected):
    body = fic_body(context=True, selected=selected)
    body["@odata.context"] = body["@odata.context"].replace(
        "https://graph.microsoft.com/v1.0",
        "https://graph.microsoft.com",
    )
    validate(transport=SyntheticTransport(fic=body))


@pytest.mark.parametrize(
    "body",
    [
        {"value": [{"id": OWNER_ID}]},
        {"value": [], "@odata.nextLink": "https://graph.microsoft.com/next"},
        {"value": [], "@odata.count": 0},
        {"value": [], "extra": True},
        {"value": [], "@odata.context": None},
        {
            "value": [],
            "@odata.context": (
                "https://graph.microsoft.com/v1.0/$metadata#applications("
                f"'{API_APPLICATION_OBJECT_ID}')/federatedIdentityCredentials(id)"
            ),
        },
        {
            "value": [],
            "@odata.context": (
                "https://graph.microsoft.us/v1.0/$metadata#federatedIdentityCredentials(id)"
            ),
        },
    ],
)
def test_fic_collection_nonempty_paged_extra_null_wrong_id_or_cloud_rejects(body):
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=SyntheticTransport(fic=body))


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json",
        "Application/JSON; charset=UTF-8",
        "application/json;odata.metadata=minimal;odata.streaming=true",
        "application/json;IEEE754Compatible=false",
    ],
)
def test_documented_json_content_types_accept(content_type):
    def with_type(plan):
        return response_set(
            plan,
            changes={index: {"content_type": content_type} for index in range(3)},
        )

    validate(transport=with_type)


@pytest.mark.parametrize(
    "content_type",
    [
        "text/json",
        "application/json; charset=latin1",
        "application/json; charset=utf-8; charset=utf-8",
        "application/json; unknown=x",
        "application/json;odata.metadata=verbose",
        "application/json\r\nX: y",
    ],
)
def test_undocumented_content_types_reject(content_type):
    def transport(plan):
        return response_set(plan, changes={0: {"content_type": content_type}})

    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=transport)


def test_nonascii_final_url_is_rejected_without_compare_digest_type_error():
    def transport(plan):
        return response_set(plan, changes={0: {"final_url": plan[0].url + "é"}})

    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=transport)


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"\xff",
        b"{",
        b"{} trailing",
        b'{"id":NaN}',
        b'{"id":"x","id":"y"}',
        json.dumps({"x": [[[[[[[[[[[[]]]]]]]]]]]]}).encode(),
    ],
)
def test_invalid_json_utf8_duplicate_nonfinite_and_depth_reject(body):
    def transport(plan):
        return response_set(plan, application=body)

    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=transport)


def test_synthetic_validation_rejects_private_attested_response():
    def forged(plan):
        responses = list(response_set(plan))
        responses[0] = loader_module._attested_live_response(
            status_code=200,
            final_url=plan[0].url,
            content_type="application/json",
            body=responses[0].body,
        )
        return tuple(responses)

    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=forged)


@pytest.mark.parametrize(
    "responses", [None, (), (object(),), [object()] * 3, (object(),) * 4]
)
def test_transport_must_return_exact_response_tuple(responses):
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=SyntheticTransport(responses=responses))


def test_swapped_response_tuple_rejects_resource_correlation():
    def transport(plan):
        responses = response_set(plan)
        return responses[1], responses[0], responses[2]

    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(transport=transport)


def test_partial_transport_failure_emits_no_receipt_and_detaches_secrets():
    prerequisite = prerequisites()

    def transport(plan):
        del plan
        raise RuntimeError("Authorization: Bearer " + TOKEN)

    with pytest.raises(EntraCallingClientRegistrationGraphProbeError) as raised:
        validate(prerequisite=prerequisite, transport=transport)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert_no_secret_in_production_exception_graph(
        raised.value,
        [
            TOKEN,
            TENANT_ID,
            CALLING_CLIENT_APPLICATION_ID,
            CALLING_CLIENT_OBJECT_ID,
            OWNER_ID,
            REDIRECT_URI,
        ],
    )


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, SystemExit])
def test_synthetic_keyboard_or_system_exit_is_fresh_and_secret_free(failure_type):
    prerequisite = prerequisites()

    def transport(plan):
        del plan
        raise failure_type("Authorization: Bearer " + TOKEN)

    with pytest.raises(failure_type) as raised:
        validate(prerequisite=prerequisite, transport=transport)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert_no_secret_in_production_exception_graph(
        raised.value,
        [TOKEN, TENANT_ID, CALLING_CLIENT_OBJECT_ID, OWNER_ID, REDIRECT_URI],
    )


@pytest.mark.parametrize("kind", ["utf8", "json", "schema", "prerequisite"])
def test_every_untrusted_failure_class_detaches_raw_source_evidence(kind):
    prerequisite = prerequisites()
    transport = SyntheticTransport()
    raw_body_sentinel = "step213-raw-body-private-sentinel"
    if kind == "utf8":
        transport = SyntheticTransport(application=b"\xff" + raw_body_sentinel.encode())
    elif kind == "json":
        transport = SyntheticTransport(
            application=(b'{"private":"' + raw_body_sentinel.encode())
        )
    elif kind == "schema":
        body = application_body()
        body["displayName"] = raw_body_sentinel + REDIRECT_URI
        transport = SyntheticTransport(application=body)
    else:
        values = json.loads(prerequisite["calling_client_registration_document"])
        values["registration"]["display_name"] = raw_body_sentinel
        prerequisite["calling_client_registration_document"] = json.dumps(
            values
        ).encode()
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError) as raised:
        validate(prerequisite=prerequisite, transport=transport)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert_no_secret_in_production_exception_graph(
        raised.value,
        [
            raw_body_sentinel,
            TENANT_ID,
            CALLING_CLIENT_APPLICATION_ID,
            CALLING_CLIENT_OBJECT_ID,
            OWNER_ID,
            OWNER_ID_2,
            REDIRECT_URI,
            REDIRECT_URI_2,
        ],
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("authentication_preview", object()),
        ("api_registration_document", object()),
        ("accepted_api_registration_document_sha256", object()),
        ("calling_client_registration_document", object()),
        ("accepted_calling_client_registration_document_sha256", object()),
        ("inventory_document", object()),
        ("approved_inventory_document_sha256", object()),
    ],
)
def test_public_wrong_type_inputs_preserve_fresh_sanitized_typeerror(field, value):
    prerequisite = prerequisites()
    prerequisite[field] = value
    with pytest.raises(TypeError, match="inputs are invalid") as raised:
        validate(prerequisite=prerequisite)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert_no_secret_in_production_exception_graph(
        raised.value,
        [TENANT_ID, CALLING_CLIENT_OBJECT_ID, OWNER_ID, REDIRECT_URI],
    )


@pytest.mark.parametrize("target", ["authorization", "transport"])
def test_wrong_authorization_or_transport_type_is_fresh_sanitized_typeerror(target):
    kwargs = {
        **prerequisites(),
        "authorization": authorization(),
        "transport": SyntheticTransport(),
    }
    kwargs[target] = object()
    with pytest.raises(TypeError, match="inputs are invalid") as raised:
        validate_entra_calling_client_registration_graph_probe(**kwargs)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert_no_secret_in_production_exception_graph(
        raised.value,
        [TENANT_ID, CALLING_CLIENT_OBJECT_ID, OWNER_ID, REDIRECT_URI],
    )


@pytest.mark.parametrize("target", ["api", "client", "inventory"])
def test_raw_prerequisite_byte_or_digest_reblessing_fails_closed(target):
    prerequisite = prerequisites()
    if target == "api":
        document_key = "api_registration_document"
        digest_key = "accepted_api_registration_document_sha256"
    elif target == "client":
        document_key = "calling_client_registration_document"
        digest_key = "accepted_calling_client_registration_document_sha256"
    else:
        document_key = "inventory_document"
        digest_key = "approved_inventory_document_sha256"
    values = json.loads(prerequisite[document_key])
    values["schema_version"] = 2
    tampered = json.dumps(values).encode()
    prerequisite[document_key] = tampered
    prerequisite[digest_key] = __import__("hashlib").sha256(tampered).hexdigest()
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(prerequisite=prerequisite)


def test_inventory_object_role_swap_and_wrong_approved_digest_reject():
    prerequisite = prerequisites()
    values = json.loads(prerequisite["inventory_document"])
    values["inventory"]["applications"].reverse()
    prerequisite["inventory_document"] = json.dumps(values).encode()
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(prerequisite=prerequisite)


def test_schema_valid_reblessed_inventory_object_substitution_rejects():
    import hashlib

    prerequisite = prerequisites()
    values = json.loads(prerequisite["inventory_document"])
    values["inventory"]["applications"][1]["application_object_id"] = (
        "77777777-8888-4999-8abc-bbbbbbbbbbbb"
    )
    changed = json.dumps(values).encode()
    prerequisite["inventory_document"] = changed
    prerequisite["approved_inventory_document_sha256"] = hashlib.sha256(
        json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(prerequisite=prerequisite)
    prerequisite = prerequisites()
    prerequisite["approved_inventory_document_sha256"] = "0" * 64
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError):
        validate(prerequisite=prerequisite)


def test_step208_receipt_is_not_a_prerequisite_or_forgery_seam():
    signature = inspect.signature(
        validate_entra_calling_client_registration_graph_probe
    )
    assert all(
        "step208" not in name and "probe_receipt" not in name
        for name in signature.parameters
    )


def test_every_receipt_field_is_unique_and_tamper_enforced_by_post_init_and_renderer():
    receipt = validate()
    names = [field.name for field in fields(receipt)]
    assert len(names) == len(set(names))
    for field in fields(receipt):
        current = getattr(receipt, field.name)
        if field.name.endswith("_sha256"):
            changed = "0" * 63
        elif type(current) is bool:
            changed = not current
        elif type(current) is int:
            changed = True
        elif current is None:
            changed = 0
        elif type(current) is str:
            changed = "invalid"
        else:
            pytest.fail(f"unhandled receipt field {field.name}")
        tampered = object.__new__(type(receipt))
        for receipt_field in fields(receipt):
            object.__setattr__(
                tampered,
                receipt_field.name,
                changed
                if receipt_field.name == field.name
                else getattr(receipt, receipt_field.name),
            )
        with pytest.raises(ValueError, match="receipt"):
            tampered.__post_init__()
        with pytest.raises(ValueError, match="receipt"):
            render_entra_calling_client_registration_graph_probe_receipt(tampered)


def test_receipt_domain_separated_hashes_are_distinct_and_raw_evidence_omitted():
    receipt = validate()
    digest_values = [
        getattr(receipt, field.name)
        for field in fields(receipt)
        if field.name.endswith("_sha256")
    ]
    assert (
        receipt.approved_inventory_document_sha256 == receipt.inventory_document_sha256
    )
    distinct_evidence = [
        value
        for field, value in zip(
            [item for item in fields(receipt) if item.name.endswith("_sha256")],
            digest_values,
            strict=True,
        )
        if field.name != "approved_inventory_document_sha256"
    ]
    assert len(distinct_evidence) == len(set(distinct_evidence))
    rendered = render_entra_calling_client_registration_graph_probe_receipt(receipt)
    assert "Authorization" not in rendered
    assert "Bearer" not in rendered
    assert "redirectUris" not in rendered
    assert '"value"' not in rendered
    for raw in (
        TOKEN,
        TENANT_ID,
        API_APPLICATION_ID,
        API_APPLICATION_OBJECT_ID,
        API_SCOPE_ID,
        CALLING_CLIENT_APPLICATION_ID,
        CALLING_CLIENT_OBJECT_ID,
        API_SERVICE_PRINCIPAL_OBJECT_ID,
        CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
        OWNER_ID,
        OWNER_ID_2,
        REDIRECT_URI,
        REDIRECT_URI_2,
        "https://graph.microsoft.com/v1.0/applications/",
        "@odata.context",
        "federatedIdentityCredentials",
    ):
        assert raw not in rendered


def test_receipt_rejects_valid_shape_but_mismatched_approved_inventory_digest():
    receipt = validate()
    tampered = object.__new__(type(receipt))
    for field in fields(receipt):
        object.__setattr__(
            tampered,
            field.name,
            "0" * 64
            if field.name == "approved_inventory_document_sha256"
            else getattr(receipt, field.name),
        )
    with pytest.raises(ValueError, match="receipt"):
        tampered.__post_init__()


def test_live_wrapper_rejects_synthetic_loader_and_always_closes(monkeypatch):
    closed = []

    class FakeLoader:
        def __init__(self, *, delegated_access_token):
            assert delegated_access_token == TOKEN

        def __call__(self, plan):
            return response_set(plan)

        def close(self):
            closed.append(True)

    monkeypatch.setattr(
        module,
        "BoundedHTTPSEntraCallingClientRegistrationGraphLoader",
        FakeLoader,
    )
    with pytest.raises(EntraCallingClientRegistrationGraphProbeError) as raised:
        probe_live_entra_calling_client_registration_graph(
            **prerequisites(),
            authorization=authorization(),
            delegated_access_token=TOKEN,
        )
    assert closed == [True]
    assert_no_secret_in_production_exception_graph(raised.value, [TOKEN])


def test_live_wrapper_accepts_only_private_attested_triple_and_marks_live(monkeypatch):
    closed = []

    class FakeLoader:
        def __init__(self, *, delegated_access_token):
            assert delegated_access_token == TOKEN

        def __call__(self, plan):
            synthetic = response_set(plan)
            return tuple(
                loader_module._attested_live_response(
                    status_code=200,
                    final_url=request.url,
                    content_type="application/json",
                    body=response.body,
                )
                for request, response in zip(plan, synthetic, strict=True)
            )

        def close(self):
            closed.append(True)

    monkeypatch.setattr(
        module,
        "BoundedHTTPSEntraCallingClientRegistrationGraphLoader",
        FakeLoader,
    )
    receipt = probe_live_entra_calling_client_registration_graph(
        **prerequisites(),
        authorization=authorization(),
        delegated_access_token=TOKEN,
    )
    assert closed == [True]
    assert receipt.synthetic_transport_used is False
    assert receipt.live_https_transport_attested is True
    assert receipt.provider_io_performed is True
    assert receipt.provider_state_checked is True
    assert receipt.source_authenticity_checked is True
    assert receipt.live_application_registration_checked is True
    assert receipt.live_spa_redirect_registration_checked is True
    assert receipt.live_owner_inventory_checked is True
    assert receipt.live_federated_identity_credential_inventory_checked is True
    assert all(
        getattr(receipt, name) is False for name in module._DEFERRED_FALSE_FIELDS
    )


@pytest.mark.parametrize("failure_call", [1, 2, 3])
@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_live_get_failure_paths_are_fresh_secret_free_and_close(
    monkeypatch,
    failure_call,
    failure_type,
):
    closed = []

    class FakeLoader:
        def __init__(self, *, delegated_access_token):
            self._delegated_access_token = delegated_access_token

        def __call__(self, plan):
            for sequence, _request in enumerate(plan, 1):
                if sequence == failure_call:
                    raise failure_type("Authorization: Bearer " + TOKEN)
            pytest.fail("failure call not reached")

        def close(self):
            self._delegated_access_token = None
            closed.append(True)

    monkeypatch.setattr(
        module,
        "BoundedHTTPSEntraCallingClientRegistrationGraphLoader",
        FakeLoader,
    )
    expected = (
        failure_type
        if failure_type in {KeyboardInterrupt, SystemExit}
        else EntraCallingClientRegistrationGraphProbeError
    )
    with pytest.raises(expected) as raised:
        probe_live_entra_calling_client_registration_graph(
            **prerequisites(),
            authorization=authorization(),
            delegated_access_token=TOKEN,
        )
    assert closed == [True]
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert_no_secret_in_production_exception_graph(
        raised.value,
        [TOKEN, TENANT_ID, CALLING_CLIENT_OBJECT_ID, OWNER_ID, REDIRECT_URI],
    )


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_live_close_failure_is_fresh_and_secret_free(monkeypatch, failure_type):
    class FakeLoader:
        def __init__(self, *, delegated_access_token):
            self._delegated_access_token = delegated_access_token

        def __call__(self, plan):
            synthetic = response_set(plan)
            return tuple(
                loader_module._attested_live_response(
                    status_code=200,
                    final_url=request.url,
                    content_type="application/json",
                    body=response.body,
                )
                for request, response in zip(plan, synthetic, strict=True)
            )

        def close(self):
            self._delegated_access_token = None
            raise failure_type("Authorization: Bearer " + TOKEN)

    monkeypatch.setattr(
        module,
        "BoundedHTTPSEntraCallingClientRegistrationGraphLoader",
        FakeLoader,
    )
    expected = (
        failure_type
        if failure_type in {KeyboardInterrupt, SystemExit}
        else EntraCallingClientRegistrationGraphProbeError
    )
    with pytest.raises(expected) as raised:
        probe_live_entra_calling_client_registration_graph(
            **prerequisites(),
            authorization=authorization(),
            delegated_access_token=TOKEN,
        )
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert_no_secret_in_production_exception_graph(
        raised.value,
        [TOKEN, TENANT_ID, CALLING_CLIENT_OBJECT_ID, OWNER_ID, REDIRECT_URI],
    )


def test_synthetic_path_has_no_hidden_provider_or_operational_io(monkeypatch):
    import builtins
    import socket

    def fail(*args, **kwargs):
        del args, kwargs
        pytest.fail("synthetic proof performed hidden I/O")

    monkeypatch.setattr(builtins, "open", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    validate()
