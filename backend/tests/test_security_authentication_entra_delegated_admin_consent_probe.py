"""Tests for the controlled Step 210 delegated-consent Graph proof."""

from __future__ import annotations

from dataclasses import fields, replace
import inspect
import json

import pytest

import app.security.authentication_entra_delegated_admin_consent_graph_http_loader as loader_module
import app.security.authentication_entra_delegated_admin_consent_probe as module
from app.security.authentication_entra_delegated_admin_consent_graph_http_loader import (
    MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_BYTES,
    EntraDelegatedAdminConsentGraphResponse,
)
from app.security.authentication_entra_delegated_admin_consent_probe import (
    ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_RECEIPT_TYPE,
    ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_SCOPE,
    ENTRA_GRAPH_DIRECTORY_READ_ALL_DELEGATED_PERMISSION_ID,
    ENTRA_GRAPH_DIRECTORY_READ_ALL_PERMISSION,
    MAX_ENTRA_DELEGATED_ADMIN_CONSENT_GRANT_ID_LENGTH,
    EntraDelegatedAdminConsentProbeAuthorizationContract,
    EntraDelegatedAdminConsentProbeError,
    probe_live_entra_delegated_admin_consent,
    render_entra_delegated_admin_consent_probe_receipt,
    validate_entra_delegated_admin_consent_probe,
)
from app.security.authentication_entra_delegated_admin_consent_readiness import (
    load_entra_delegated_admin_consent_readiness,
)
from test_security_authentication_entra_delegated_admin_consent_readiness import (
    API_APPLICATION_ID,
    API_APPLICATION_OBJECT_ID,
    API_SCOPE_ID,
    API_SERVICE_PRINCIPAL_OBJECT_ID,
    CALLING_CLIENT_APPLICATION_ID,
    CALLING_CLIENT_OBJECT_ID,
    CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
    TENANT_ID,
    prerequisites,
    values,
)


GRANT_ID = "opaque-provider-generated-grant-id"
ODATA_CONTEXT = "https://graph.microsoft.com/v1.0/$metadata#oauth2PermissionGrants"


def authorization() -> EntraDelegatedAdminConsentProbeAuthorizationContract:
    return EntraDelegatedAdminConsentProbeAuthorizationContract(
        permission_type="delegated_work_school",
        permission_name=ENTRA_GRAPH_DIRECTORY_READ_ALL_PERMISSION,
        permission_id=ENTRA_GRAPH_DIRECTORY_READ_ALL_DELEGATED_PERMISSION_ID,
        consent_requirement="admin",
        credential_origin="out_of_band_operator",
    )


def probe_inputs() -> dict[str, object]:
    prerequisite = prerequisites()
    desired_document = json.dumps(values(prerequisite)).encode()
    receipt = load_entra_delegated_admin_consent_readiness(
        document=desired_document,
        **prerequisite,
    )
    return {
        "desired_state_document": desired_document,
        "approved_desired_state_document_sha256": (
            receipt.desired_state_document_sha256
        ),
        **prerequisite,
        "authorization": authorization(),
    }


def grant_values(**changes: object) -> dict[str, object]:
    value = {
        "id": GRANT_ID,
        "clientId": CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
        "consentType": "AllPrincipals",
        "principalId": None,
        "resourceId": API_SERVICE_PRINCIPAL_OBJECT_ID,
        "scope": "access_as_user",
    }
    value.update(changes)
    return value


def graph_body(*, grants=None, **root_changes: object) -> bytes:
    root = {"@odata.context": ODATA_CONTEXT, "value": grants or [grant_values()]}
    root.update(root_changes)
    return json.dumps(root, separators=(",", ":")).encode()


class SyntheticTransport:
    def __init__(
        self,
        *,
        body: bytes | None = None,
        status_code: int = 200,
        content_type: str = "application/json",
        final_url: str | None = None,
    ) -> None:
        self.body = graph_body() if body is None else body
        self.status_code = status_code
        self.content_type = content_type
        self.final_url = final_url
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        return EntraDelegatedAdminConsentGraphResponse(
            status_code=self.status_code,
            final_url=request.url if self.final_url is None else self.final_url,
            content_type=self.content_type,
            body=self.body,
        )


def run_probe(*, transport=None, **changes):
    arguments = probe_inputs()
    arguments.update(changes)
    return validate_entra_delegated_admin_consent_probe(
        **arguments,
        transport=transport or SyntheticTransport(),
    )


def test_valid_synthetic_proof_binds_exact_query_and_stays_non_provider_evidence():
    transport = SyntheticTransport()
    receipt = run_probe(transport=transport)
    assert receipt.receipt_type == ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_RECEIPT_TYPE
    assert receipt.schema_version == 1
    assert receipt.validation_scope == ENTRA_DELEGATED_ADMIN_CONSENT_PROBE_SCOPE
    assert receipt.request_count == receipt.matching_response_count == 1
    assert receipt.approved_desired_state_digest_bound is True
    assert receipt.exact_four_predicate_filter_validated is True
    assert receipt.client_id_filter_included is True
    assert receipt.read_only_get_validated is True
    assert receipt.no_request_body_validated is True
    assert receipt.no_select_top_count_batch_or_paging_requested is True
    assert receipt.exactly_one_matching_response_validated is True
    assert receipt.client_service_principal_match_validated is True
    assert receipt.resource_service_principal_match_validated is True
    assert receipt.tenant_wide_consent_type_validated is True
    assert receipt.null_principal_id_validated is True
    assert receipt.exact_single_scope_validated is True
    assert receipt.response_grant_id_present_and_hashed is True
    assert receipt.synthetic_transport_used is True
    assert receipt.live_https_transport_attested is False
    assert receipt.provider_io_performed is False
    assert receipt.graph_response_state_checked is False
    assert receipt.source_authenticity_checked is False
    assert receipt.exact_response_relationship_checked is False
    assert receipt.target_grant_response_checked is False
    request = transport.requests[0]
    assert request.method == "GET"
    assert request.body is None
    assert request.follow_redirects is False
    assert request.maximum_retries == 0
    assert request.proxy_allowed is False
    assert "oauth2PermissionGrants?$filter=" in request.url
    assert all(term not in request.url for term in ("$select", "$top", "$count"))


def test_receipt_keeps_all_unproved_and_mutation_boundaries_false():
    receipt = run_probe()
    names = (
        "replication_freshness_checked",
        "eventual_consistency_resolved",
        "concurrent_grant_mutation_checked",
        "tenant_wide_complete_grant_inventory_checked",
        "individual_principal_grants_checked",
        "other_client_resource_relationships_checked",
        "authorization_token_claims_checked",
        "actual_token_type_checked",
        "work_school_account_checked",
        "token_tenant_checked",
        "intended_tenant_context_checked",
        "token_graph_audience_checked",
        "operator_token_directory_read_all_grant_checked",
        "operator_identity_checked",
        "operator_role_checked",
        "operator_authorization_checked",
        "admin_consent_effectiveness_checked",
        "user_assignment_checked",
        "user_flow_checked",
        "conditional_access_checked",
        "runtime_pkce_s256_checked",
        "real_signed_api_token_scope_checked",
        "grant_creation_performed",
        "grant_update_performed",
        "grant_deletion_performed",
        "activation_ready",
    )
    assert all(getattr(receipt, name) is False for name in names)


def test_rendered_receipt_is_canonical_and_omits_all_raw_sensitive_evidence():
    rendered = render_entra_delegated_admin_consent_probe_receipt(run_probe())
    assert rendered == render_entra_delegated_admin_consent_probe_receipt(run_probe())
    for secret in (
        TENANT_ID,
        API_APPLICATION_ID,
        API_APPLICATION_OBJECT_ID,
        API_SCOPE_ID,
        API_SERVICE_PRINCIPAL_OBJECT_ID,
        CALLING_CLIENT_APPLICATION_ID,
        CALLING_CLIENT_OBJECT_ID,
        CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID,
        GRANT_ID,
        "access_as_user",
        "oauth2PermissionGrants?$filter=",
        "opaque-token",
    ):
        assert secret not in rendered
    parsed = json.loads(rendered)
    assert "response_grant_id_sha256" in parsed
    assert "provider_grant_id_sha256" not in parsed


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("clientId", API_SERVICE_PRINCIPAL_OBJECT_ID),
        ("clientId", CALLING_CLIENT_APPLICATION_ID),
        ("clientId", CALLING_CLIENT_OBJECT_ID),
        ("clientId", "55555555-6666-4777-8888-999999999999"),
        ("resourceId", CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID),
        ("resourceId", API_APPLICATION_ID),
        ("resourceId", API_APPLICATION_OBJECT_ID),
        ("resourceId", "55555555-6666-4777-8888-999999999999"),
        ("consentType", "Principal"),
        ("principalId", "55555555-6666-4777-8888-999999999999"),
        ("scope", "access_as_user User.Read"),
        ("scope", "Access_As_User"),
        ("scope", " access_as_user"),
    ],
)
def test_response_rejects_identity_confusion_or_scope_widening(field, replacement):
    transport = SyntheticTransport(body=graph_body(grants=[grant_values(**{field: replacement})]))
    with pytest.raises(EntraDelegatedAdminConsentProbeError):
        run_probe(transport=transport)


def test_response_rejects_equal_client_and_resource_principals():
    transport = SyntheticTransport(
        body=graph_body(
            grants=[
                grant_values(
                    clientId=API_SERVICE_PRINCIPAL_OBJECT_ID,
                    resourceId=API_SERVICE_PRINCIPAL_OBJECT_ID,
                )
            ]
        )
    )
    with pytest.raises(EntraDelegatedAdminConsentProbeError):
        run_probe(transport=transport)


@pytest.mark.parametrize(
    "grants",
    [
        [],
        [grant_values(), grant_values(id="second")],
    ],
)
def test_response_requires_exactly_one_filtered_matching_record(grants):
    body = json.dumps({"@odata.context": ODATA_CONTEXT, "value": grants}).encode()
    with pytest.raises(EntraDelegatedAdminConsentProbeError):
        run_probe(transport=SyntheticTransport(body=body))


@pytest.mark.parametrize(
    "field,value",
    [
        ("@odata.nextLink", "https://graph.microsoft.com/next"),
        ("@odata.count", 1),
        ("@odata.deltaLink", "https://graph.microsoft.com/delta"),
        ("unknown", True),
    ],
)
def test_response_rejects_paging_count_delta_or_unknown_root_fields(field, value):
    with pytest.raises(EntraDelegatedAdminConsentProbeError):
        run_probe(transport=SyntheticTransport(body=graph_body(**{field: value})))


@pytest.mark.parametrize(
    "mutation",
    [
        {"displayName": "privacy leak"},
        {"@odata.type": "#microsoft.graph.oAuth2PermissionGrant"},
        {"client_id": CALLING_CLIENT_SERVICE_PRINCIPAL_OBJECT_ID},
        {"resource_id": API_SERVICE_PRINCIPAL_OBJECT_ID},
    ],
)
def test_response_rejects_unselected_annotations_aliases_and_unknown_item_fields(
    mutation,
):
    with pytest.raises(EntraDelegatedAdminConsentProbeError):
        run_probe(
            transport=SyntheticTransport(
                body=graph_body(grants=[grant_values(**mutation)])
            )
        )


@pytest.mark.parametrize(
    "grant_id",
    ["", " padded", "trailing ", "control\n", "x" * (MAX_ENTRA_DELEGATED_ADMIN_CONSENT_GRANT_ID_LENGTH + 1)],
)
def test_response_rejects_invalid_opaque_grant_ids(grant_id):
    with pytest.raises(EntraDelegatedAdminConsentProbeError):
        run_probe(
            transport=SyntheticTransport(
                body=graph_body(grants=[grant_values(id=grant_id)])
            )
        )


def test_optional_bounded_odata_id_is_accepted_but_not_tenant_evidence():
    receipt = run_probe(
        transport=SyntheticTransport(
            body=graph_body(
                grants=[grant_values(**{"@odata.id": "opaque/documented/id"})]
            )
        )
    )
    assert receipt.token_tenant_checked is False
    assert receipt.intended_tenant_context_checked is False


@pytest.mark.parametrize(
    "body",
    [
        json.dumps({"@odata.context": None, "value": [grant_values()]}).encode(),
        graph_body(grants=[grant_values(**{"@odata.id": None})]),
    ],
)
def test_optional_metadata_may_be_absent_but_explicit_null_is_rejected(body):
    with pytest.raises(EntraDelegatedAdminConsentProbeError, match="metadata"):
        run_probe(transport=SyntheticTransport(body=body))


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"null",
        b"[]",
        b"not-json",
        b"\xff",
        b'{"value":[],"value":[]}',
        b'{"value":[{"id":NaN}]}',
        b'{"value":[{"id":Infinity}]}',
        b'{"@odata.context":"wrong","value":[]}',
        b'{"value":null}',
    ],
)
def test_response_rejects_empty_nonobject_malformed_ambiguous_or_nonfinite_json(body):
    with pytest.raises(EntraDelegatedAdminConsentProbeError):
        run_probe(transport=SyntheticTransport(body=body))


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json;odata.metadata=minimal;odata.streaming=true;IEEE754Compatible=false;charset=utf-8",
        "Application/JSON; Charset=UTF-8",
        "application/json",
    ],
)
def test_documented_odata_json_content_types_are_accepted(content_type):
    assert run_probe(transport=SyntheticTransport(content_type=content_type))


@pytest.mark.parametrize(
    "content_type",
    [
        "text/json",
        "application/json;foo=bar",
        "application/json;charset=utf-8;charset=utf-8",
        "application/json;odata.streaming=maybe",
        "application/json\r\nX-Evil: yes",
    ],
)
def test_response_rejects_malformed_unknown_or_duplicate_content_type_parameters(
    content_type,
):
    with pytest.raises(EntraDelegatedAdminConsentProbeError):
        run_probe(transport=SyntheticTransport(content_type=content_type))


def test_response_rejects_transport_contract_or_body_size_failures():
    for transport in (
        SyntheticTransport(status_code=404),
        SyntheticTransport(final_url="https://graph.microsoft.com/v1.0/other"),
        SyntheticTransport(body=b"x" * (MAX_ENTRA_DELEGATED_ADMIN_CONSENT_RESPONSE_BYTES + 1)),
    ):
        with pytest.raises(EntraDelegatedAdminConsentProbeError):
            run_probe(transport=transport)


def test_independent_desired_state_digest_is_checked_before_transport():
    calls = 0

    def transport(request):
        nonlocal calls
        del request
        calls += 1
        raise AssertionError("transport must not run")

    with pytest.raises(EntraDelegatedAdminConsentProbeError, match="approved digest"):
        run_probe(
            transport=transport,
            approved_desired_state_document_sha256="0" * 64,
        )
    assert calls == 0


@pytest.mark.parametrize(
    "field",
    [
        "accepted_api_registration_document_sha256",
        "accepted_calling_client_registration_document_sha256",
        "approved_inventory_document_sha256",
    ],
)
def test_altered_prerequisite_digest_rejects_before_transport(field):
    calls = 0

    def transport(request):
        nonlocal calls
        del request
        calls += 1
        raise AssertionError("transport must not run")

    with pytest.raises(EntraDelegatedAdminConsentProbeError):
        run_probe(transport=transport, **{field: "0" * 64})
    assert calls == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"permission_type": "application"},
        {"permission_name": "Application.Read.All"},
        {"permission_name": "Directory.ReadWrite.All"},
        {"permission_id": "00000000-0000-0000-0000-000000000000"},
        {"consent_requirement": "user"},
        {"credential_origin": "service_principal"},
    ],
)
def test_authorization_contract_rejects_app_only_or_wider_wrong_permissions(changes):
    base = {
        "permission_type": "delegated_work_school",
        "permission_name": ENTRA_GRAPH_DIRECTORY_READ_ALL_PERMISSION,
        "permission_id": ENTRA_GRAPH_DIRECTORY_READ_ALL_DELEGATED_PERMISSION_ID,
        "consent_requirement": "admin",
        "credential_origin": "out_of_band_operator",
    }
    base.update(changes)
    with pytest.raises(ValueError, match="authorization is invalid"):
        EntraDelegatedAdminConsentProbeAuthorizationContract(**base)


def test_transport_failure_is_sanitized_and_never_echoes_provider_details():
    def transport(request):
        del request
        raise RuntimeError("raw provider/token detail")

    with pytest.raises(EntraDelegatedAdminConsentProbeError) as error:
        run_probe(transport=transport)
    assert "raw provider/token detail" not in str(error.value)


def test_synthetic_entrypoint_rejects_even_module_sealed_live_response():
    def transport(request):
        return loader_module._attested_live_response(
            status_code=200,
            final_url=request.url,
            content_type="application/json",
            body=graph_body(),
        )

    with pytest.raises(EntraDelegatedAdminConsentProbeError, match="synthetic"):
        run_probe(transport=transport)


def test_live_entrypoint_exposes_no_transport_or_opener_injection():
    parameters = inspect.signature(probe_live_entra_delegated_admin_consent).parameters
    assert "delegated_access_token" in parameters
    assert "transport" not in parameters
    assert "open_url" not in parameters


def test_live_entrypoint_seals_graph_response_provenance_but_not_tenant_or_token(
    monkeypatch,
):
    instances = []
    opaque_token = "opaque-live-token-must-never-escape"

    class LiveLoader:
        def __init__(self, *, delegated_access_token):
            assert delegated_access_token == opaque_token
            self.closed = False
            instances.append(self)

        def __call__(self, request):
            return loader_module._attested_live_response(
                status_code=200,
                final_url=request.url,
                content_type="application/json",
                body=graph_body(),
            )

        def close(self):
            self.closed = True

    monkeypatch.setattr(
        module,
        "BoundedHTTPSEntraDelegatedAdminConsentGraphLoader",
        LiveLoader,
    )
    receipt = probe_live_entra_delegated_admin_consent(
        **probe_inputs(),
        delegated_access_token=opaque_token,
    )
    assert instances[0].closed is True
    assert receipt.synthetic_transport_used is False
    assert receipt.live_https_transport_attested is True
    for name in (
        "provider_io_performed",
        "graph_response_state_checked",
        "source_authenticity_checked",
        "exact_response_relationship_checked",
        "duplicate_matching_grants_checked",
        "target_grant_response_checked",
    ):
        assert getattr(receipt, name) is True
    for name in (
        "authorization_token_claims_checked",
        "actual_token_type_checked",
        "work_school_account_checked",
        "token_tenant_checked",
        "intended_tenant_context_checked",
        "token_graph_audience_checked",
        "operator_token_directory_read_all_grant_checked",
        "operator_identity_checked",
        "operator_role_checked",
        "operator_authorization_checked",
    ):
        assert getattr(receipt, name) is False
    assert opaque_token not in repr(receipt)
    assert opaque_token not in render_entra_delegated_admin_consent_probe_receipt(
        receipt
    )


@pytest.mark.parametrize("fail_before_transport", [False, True])
def test_live_entrypoint_closes_loader_and_sanitizes_token_on_any_failure(
    monkeypatch,
    fail_before_transport,
):
    instances = []
    opaque_token = "opaque-live-failure-token"

    class LiveLoader:
        def __init__(self, *, delegated_access_token):
            assert delegated_access_token == opaque_token
            self.closed = False
            instances.append(self)

        def __call__(self, request):
            return loader_module._attested_live_response(
                status_code=200,
                final_url=request.url,
                content_type="application/json",
                body=b'{"value":[]}',
            )

        def close(self):
            self.closed = True

    monkeypatch.setattr(
        module,
        "BoundedHTTPSEntraDelegatedAdminConsentGraphLoader",
        LiveLoader,
    )
    arguments = probe_inputs()
    if fail_before_transport:
        arguments["approved_desired_state_document_sha256"] = "0" * 64
    with pytest.raises(EntraDelegatedAdminConsentProbeError) as error:
        probe_live_entra_delegated_admin_consent(
            **arguments,
            delegated_access_token=opaque_token,
        )
    assert instances[0].closed is True
    assert opaque_token not in str(error.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("token_tenant_checked", True),
        ("intended_tenant_context_checked", True),
        ("operator_token_directory_read_all_grant_checked", True),
        ("grant_creation_performed", True),
        ("activation_ready", True),
        ("provider_io_performed", True),
        ("response_grant_id_present_and_hashed", False),
    ],
)
def test_receipt_cannot_promote_deferred_proof_or_break_provenance(field, value):
    with pytest.raises(ValueError, match="receipt is invalid"):
        replace(run_probe(), **{field: value})


def test_renderer_revalidates_exact_receipt_type_and_invariants():
    with pytest.raises(TypeError):
        render_entra_delegated_admin_consent_probe_receipt(object())  # type: ignore[arg-type]
    receipt = run_probe()
    object.__setattr__(receipt, "token_tenant_checked", True)
    with pytest.raises(ValueError):
        render_entra_delegated_admin_consent_probe_receipt(receipt)


def test_receipt_field_names_do_not_overclaim_provider_or_tenant_provenance():
    names = {field.name for field in fields(type(run_probe()))}
    assert "provider_grant_id_sha256" not in names
    assert "provider_permission_grant_checked" not in names
    assert "provider_state_checked" not in names
    assert "response_grant_id_sha256" in names
    assert "operator_token_directory_read_all_grant_checked" in names
    assert "intended_tenant_context_checked" in names
