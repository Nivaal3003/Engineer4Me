"""Focused tests for local authentication-readiness document validation."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import traceback
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from app.main import app as pre_activation_app
from app.security.authentication_deployment import load_authentication_deployment
from app.security.authentication_readiness_document import (
    AUTHENTICATION_READINESS_DOCUMENT_TYPE,
    AUTHENTICATION_READINESS_SCHEMA_VERSION,
    AUTHENTICATION_READINESS_VALIDATION_SCOPE,
    MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES,
    AuthenticationReadinessDocumentError,
    load_authentication_readiness_document,
    render_authentication_readiness_preview,
)
from app.security.token_verifier import REQUIRED_CLAIMS


ISSUER = "https://identity.engineer4me.test/tenant"
AUDIENCE = "engineer4me-api"
JWKS_URL = "https://keys.engineer4me.test/.well-known/jwks.json"
ENTRA_TENANT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeee0200"
ENTRA_API_APPLICATION_ID = "bbbbbbbb-cccc-4ddd-8eee-ffffffff0300"
ENTRA_CALLING_CLIENT_APPLICATION_ID = "cccccccc-dddd-4eee-8fff-aaaaaaaa0400"
ENTRA_ISSUER = f"https://synthetic.ciamlogin.com/{ENTRA_TENANT_ID}/v2.0"
ENTRA_REQUIRED_DELEGATED_SCOPE = "access_as_user"
ENTRA_REQUIRED_AZPACR = "0"
BACKEND_ROOT = Path(__file__).resolve().parents[1]


def values() -> dict[str, object]:
    return {
        "document_type": AUTHENTICATION_READINESS_DOCUMENT_TYPE,
        "schema_version": AUTHENTICATION_READINESS_SCHEMA_VERSION,
        "authentication": {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "jwks_url": JWKS_URL,
            "algorithms": ["RS256"],
        },
    }


def encoded(
    payload: object | None = None,
    **json_options: object,
) -> bytes:
    return json.dumps(
        values() if payload is None else payload,
        **json_options,
    ).encode("utf-8")


def route_state() -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            id(route),
            getattr(route, "path", None),
            tuple(sorted(getattr(route, "methods", ()) or ())),
            id(getattr(route, "endpoint", None)),
            id(getattr(route, "dependant", None)),
            tuple(id(item) for item in getattr(route, "dependencies", ())),
        )
        for route in pre_activation_app.routes
    )


def test_minimal_document_resolves_authoritative_secure_defaults():
    result = load_authentication_readiness_document(encoded())

    assert result.deployment.runtime.issuer == ISSUER
    assert result.deployment.runtime.audience == AUDIENCE
    assert result.deployment.runtime.algorithms == ("RS256",)
    assert result.deployment.runtime.token_identifier_claim == "jti"
    assert result.deployment.runtime.token_profile == "provider_neutral"
    assert result.deployment.runtime.microsoft_entra_tenant_id is None
    assert (
        result.deployment.runtime.microsoft_entra_calling_client_application_id
        is None
    )
    assert result.deployment.runtime.microsoft_entra_required_delegated_scope is None
    assert result.deployment.runtime.microsoft_entra_required_azpacr is None
    assert result.deployment.runtime.clock_skew_seconds == 30
    assert result.deployment.runtime.maximum_token_age_seconds == 3_600
    assert result.deployment.runtime.jwks.source_url == JWKS_URL
    assert result.deployment.runtime.jwks.cache_seconds == 300
    assert result.deployment.runtime.jwks.maximum_keys == 20
    assert result.deployment.transport.timeout_seconds == 5.0
    assert result.deployment.transport.maximum_response_bytes == 131_072
    assert result.preview.document_type == AUTHENTICATION_READINESS_DOCUMENT_TYPE
    assert result.preview.schema_version == AUTHENTICATION_READINESS_SCHEMA_VERSION
    assert result.preview.required_claims == REQUIRED_CLAIMS
    assert result.preview.token_identifier_claim == "jti"
    assert result.preview.token_profile == "provider_neutral"
    assert result.preview.microsoft_entra_tenant_id is None
    assert result.preview.microsoft_entra_calling_client_application_id is None
    assert result.preview.microsoft_entra_required_delegated_scope is None
    assert result.preview.microsoft_entra_required_azpacr is None
    assert result.preview.configuration_validated is True
    assert result.preview.jwks_reachability_checked is False
    assert result.preview.signed_token_checked is False
    assert result.preview.activation_ready is False
    assert re.fullmatch(r"[0-9a-f]{64}", result.preview.configuration_sha256)


def test_explicit_bounded_values_are_preserved_by_the_authoritative_loader():
    payload = values()
    payload["authentication"].update(
        {
            "algorithms": ["RS512", "ES256"],
            "token_identifier_claim": "uti",
            "clock_skew_seconds": 15,
            "maximum_token_age_seconds": 900,
            "jwks_cache_seconds": 120,
            "jwks_maximum_keys": 10,
            "jwks_timeout_seconds": 4.5,
            "jwks_maximum_response_bytes": 65_536,
        }
    )

    result = load_authentication_readiness_document(encoded(payload))

    assert result.deployment.runtime.algorithms == ("RS512", "ES256")
    assert result.deployment.runtime.token_identifier_claim == "uti"
    assert result.deployment.runtime.clock_skew_seconds == 15
    assert result.deployment.runtime.maximum_token_age_seconds == 900
    assert result.deployment.runtime.jwks.cache_seconds == 120
    assert result.deployment.runtime.jwks.maximum_keys == 10
    assert result.deployment.transport.timeout_seconds == 4.5
    assert result.deployment.transport.maximum_response_bytes == 65_536
    assert result.preview.algorithms == ("ES256", "RS512")
    assert result.preview.required_claims == (
        "exp",
        "iat",
        "iss",
        "aud",
        "sub",
        "uti",
    )


def test_resolved_configuration_matches_direct_authoritative_loading():
    result = load_authentication_readiness_document(encoded())
    direct = load_authentication_deployment(
        {
            "E4M_AUTH_ISSUER": ISSUER,
            "E4M_AUTH_AUDIENCE": AUDIENCE,
            "E4M_AUTH_JWKS_URL": JWKS_URL,
            "E4M_AUTH_ALGORITHMS": "RS256",
            "E4M_AUTH_TOKEN_IDENTIFIER_CLAIM": "jti",
            "E4M_AUTH_CLOCK_SKEW_SECONDS": "30",
            "E4M_AUTH_MAXIMUM_TOKEN_AGE_SECONDS": "3600",
            "E4M_AUTH_JWKS_CACHE_SECONDS": "300",
            "E4M_AUTH_JWKS_MAXIMUM_KEYS": "20",
            "E4M_AUTH_JWKS_TIMEOUT_SECONDS": "5.0",
            "E4M_AUTH_JWKS_MAXIMUM_RESPONSE_BYTES": "131072",
        }
    )
    assert result.deployment == direct


def test_digest_is_canonical_across_layout_order_defaults_and_algorithm_order():
    minimal = values()
    minimal["authentication"]["algorithms"] = ["RS512", "ES256"]
    explicit = values()
    explicit["authentication"] = {
        "jwks_maximum_response_bytes": 131_072,
        "jwks_timeout_seconds": 5.0,
        "jwks_maximum_keys": 20,
        "jwks_cache_seconds": 300,
        "maximum_token_age_seconds": 3_600,
        "clock_skew_seconds": 30,
        "algorithms": ["ES256", "RS512"],
        "token_identifier_claim": "jti",
        "jwks_url": JWKS_URL,
        "audience": AUDIENCE,
        "issuer": ISSUER,
    }
    expanded = dict(reversed(tuple(explicit.items())))

    digests = {
        load_authentication_readiness_document(document).preview.configuration_sha256
        for document in (
            encoded(minimal, separators=(",", ":"), sort_keys=True),
            encoded(expanded, indent=3),
        )
    }
    assert len(digests) == 1


def test_token_identifier_profile_is_explicitly_digest_bound():
    default_document = values()
    explicit_jti_document = values()
    explicit_jti_document["authentication"]["token_identifier_claim"] = "jti"
    entra_document = values()
    entra_document["authentication"]["token_identifier_claim"] = "uti"

    default_preview = load_authentication_readiness_document(
        encoded(default_document)
    ).preview
    explicit_jti_preview = load_authentication_readiness_document(
        encoded(explicit_jti_document)
    ).preview
    entra_preview = load_authentication_readiness_document(
        encoded(entra_document)
    ).preview

    assert (
        default_preview.configuration_sha256
        == explicit_jti_preview.configuration_sha256
    )
    assert entra_preview.configuration_sha256 != default_preview.configuration_sha256
    assert entra_preview.token_identifier_claim == "uti"
    assert entra_preview.required_claims[-1] == "uti"


def test_microsoft_entra_v2_tenant_and_claim_contract_are_digest_bound():
    payload = values()
    payload["authentication"].update(
        {
            "token_identifier_claim": "uti",
            "token_profile": "microsoft_entra_v2",
            "microsoft_entra_tenant_id": ENTRA_TENANT_ID,
            "microsoft_entra_api_application_id": ENTRA_API_APPLICATION_ID,
            "microsoft_entra_calling_client_application_id": (
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "microsoft_entra_required_delegated_scope": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "microsoft_entra_required_azpacr": ENTRA_REQUIRED_AZPACR,
            "issuer": ENTRA_ISSUER,
            "audience": ENTRA_API_APPLICATION_ID,
        }
    )
    result = load_authentication_readiness_document(encoded(payload))
    preview = result.preview

    assert preview.token_profile == "microsoft_entra_v2"
    assert preview.microsoft_entra_tenant_id == ENTRA_TENANT_ID
    assert preview.microsoft_entra_api_application_id == ENTRA_API_APPLICATION_ID
    assert (
        preview.microsoft_entra_calling_client_application_id
        == ENTRA_CALLING_CLIENT_APPLICATION_ID
    )
    assert (
        preview.microsoft_entra_required_delegated_scope
        == ENTRA_REQUIRED_DELEGATED_SCOPE
    )
    assert preview.microsoft_entra_required_azpacr == ENTRA_REQUIRED_AZPACR
    assert preview.required_claims == (
        "exp",
        "iat",
        "iss",
        "aud",
        "sub",
        "uti",
        "tid",
        "ver",
        "scp",
        "azp",
        "azpacr",
    )
    rendered = json.loads(render_authentication_readiness_preview(preview))
    assert rendered["token_profile"] == "microsoft_entra_v2"
    assert rendered["microsoft_entra_tenant_id"] == ENTRA_TENANT_ID
    assert (
        rendered["microsoft_entra_api_application_id"]
        == ENTRA_API_APPLICATION_ID
    )
    assert (
        rendered["microsoft_entra_calling_client_application_id"]
        == ENTRA_CALLING_CLIENT_APPLICATION_ID
    )
    assert (
        rendered["microsoft_entra_required_delegated_scope"]
        == ENTRA_REQUIRED_DELEGATED_SCOPE
    )
    assert rendered["microsoft_entra_required_azpacr"] == ENTRA_REQUIRED_AZPACR
    changed = values()
    changed["authentication"].update(
        {
            "token_identifier_claim": "uti",
            "token_profile": "microsoft_entra_v2",
            "microsoft_entra_tenant_id": (
                "00000000-0000-4000-8000-000000000001"
            ),
            "microsoft_entra_api_application_id": (
                "00000000-0000-4000-8000-000000000002"
            ),
            "microsoft_entra_calling_client_application_id": (
                "00000000-0000-4000-8000-000000000003"
            ),
            "microsoft_entra_required_delegated_scope": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "microsoft_entra_required_azpacr": ENTRA_REQUIRED_AZPACR,
            "audience": "00000000-0000-4000-8000-000000000002",
            "issuer": (
                "https://synthetic.ciamlogin.com/"
                "00000000-0000-4000-8000-000000000001/v2.0"
            ),
        }
    )
    assert (
        load_authentication_readiness_document(encoded(changed))
        .preview.configuration_sha256
        != preview.configuration_sha256
    )

    changed_caller = json.loads(encoded(payload))
    changed_caller["authentication"][
        "microsoft_entra_calling_client_application_id"
    ] = "dddddddd-eeee-4fff-8000-bbbbbbbb0500"
    changed_caller_preview = load_authentication_readiness_document(
        encoded(changed_caller)
    ).preview
    assert changed_caller_preview.configuration_sha256 != preview.configuration_sha256


@pytest.mark.parametrize(
    "calling_client_id",
    [
        None,
        "00000000-0000-0000-0000-000000000000",
        ENTRA_TENANT_ID,
        ENTRA_API_APPLICATION_ID,
        ENTRA_CALLING_CLIENT_APPLICATION_ID.upper(),
        "not-a-guid",
    ],
)
def test_microsoft_entra_v2_requires_one_distinct_canonical_calling_client_id(
    calling_client_id,
):
    payload = values()
    payload["authentication"].update(
        {
            "token_identifier_claim": "uti",
            "token_profile": "microsoft_entra_v2",
            "microsoft_entra_tenant_id": ENTRA_TENANT_ID,
            "microsoft_entra_api_application_id": ENTRA_API_APPLICATION_ID,
            "microsoft_entra_required_delegated_scope": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "microsoft_entra_required_azpacr": ENTRA_REQUIRED_AZPACR,
            "issuer": ENTRA_ISSUER,
            "audience": ENTRA_API_APPLICATION_ID,
        }
    )
    if calling_client_id is not None:
        payload["authentication"][
            "microsoft_entra_calling_client_application_id"
        ] = calling_client_id

    with pytest.raises(AuthenticationReadinessDocumentError) as captured:
        load_authentication_readiness_document(encoded(payload))
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "scope",
    [None, "wrong_scope", " access_as_user", "access_as_user "],
)
def test_microsoft_entra_v2_rejects_missing_wrong_or_whitespace_scope(scope):
    payload = values()
    payload["authentication"].update(
        {
            "token_identifier_claim": "uti",
            "token_profile": "microsoft_entra_v2",
            "microsoft_entra_tenant_id": ENTRA_TENANT_ID,
            "microsoft_entra_api_application_id": ENTRA_API_APPLICATION_ID,
            "microsoft_entra_calling_client_application_id": (
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "issuer": ENTRA_ISSUER,
            "audience": ENTRA_API_APPLICATION_ID,
            "microsoft_entra_required_azpacr": ENTRA_REQUIRED_AZPACR,
        }
    )
    if scope is not None:
        payload["authentication"][
            "microsoft_entra_required_delegated_scope"
        ] = scope
    with pytest.raises(AuthenticationReadinessDocumentError) as captured:
        load_authentication_readiness_document(encoded(payload))
    assert captured.value.__cause__ is None


def test_provider_neutral_document_rejects_entra_delegated_scope():
    payload = values()
    payload["authentication"][
        "microsoft_entra_required_delegated_scope"
    ] = ENTRA_REQUIRED_DELEGATED_SCOPE
    with pytest.raises(AuthenticationReadinessDocumentError) as captured:
        load_authentication_readiness_document(encoded(payload))
    assert captured.value.__cause__ is None


def test_provider_neutral_document_rejects_entra_calling_client_identity():
    payload = values()
    payload["authentication"][
        "microsoft_entra_calling_client_application_id"
    ] = ENTRA_CALLING_CLIENT_APPLICATION_ID
    with pytest.raises(AuthenticationReadinessDocumentError) as captured:
        load_authentication_readiness_document(encoded(payload))
    assert captured.value.__cause__ is None


def test_provider_neutral_document_rejects_entra_azpacr_contract():
    payload = values()
    payload["authentication"]["microsoft_entra_required_azpacr"] = "0"
    with pytest.raises(AuthenticationReadinessDocumentError) as captured:
        load_authentication_readiness_document(encoded(payload))
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "azpacr",
    [None, 0, 0.0, False, True, [], {}, "", " ", "00", "+0", "1", "2", "０"],
)
def test_microsoft_entra_document_requires_exact_string_public_client_azpacr(
    azpacr,
):
    payload = values()
    payload["authentication"].update(
        {
            "token_identifier_claim": "uti",
            "token_profile": "microsoft_entra_v2",
            "microsoft_entra_tenant_id": ENTRA_TENANT_ID,
            "microsoft_entra_api_application_id": ENTRA_API_APPLICATION_ID,
            "microsoft_entra_calling_client_application_id": (
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "microsoft_entra_required_delegated_scope": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "issuer": ENTRA_ISSUER,
            "audience": ENTRA_API_APPLICATION_ID,
        }
    )
    if azpacr is not None:
        payload["authentication"]["microsoft_entra_required_azpacr"] = azpacr
    with pytest.raises(AuthenticationReadinessDocumentError) as captured:
        load_authentication_readiness_document(encoded(payload))
    assert captured.value.__cause__ is None


def test_preview_is_frozen_canonical_public_and_explicitly_non_activating():
    preview = load_authentication_readiness_document(encoded()).preview
    with pytest.raises(FrozenInstanceError):
        preview.audience = "changed"

    rendered = render_authentication_readiness_preview(preview)
    parsed = json.loads(rendered)
    assert rendered == json.dumps(
        parsed,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    assert parsed == {
        "activation_ready": False,
        "algorithms": ["RS256"],
        "audience": AUDIENCE,
        "clock_skew_seconds": 30,
        "configuration_validated": True,
        "configuration_sha256": preview.configuration_sha256,
        "document_type": AUTHENTICATION_READINESS_DOCUMENT_TYPE,
        "issuer": ISSUER,
        "jwks_cache_seconds": 300,
        "jwks_maximum_keys": 20,
        "jwks_maximum_response_bytes": 131_072,
        "jwks_timeout_seconds": 5.0,
        "jwks_url": JWKS_URL,
        "jwks_reachability_checked": False,
        "maximum_token_age_seconds": 3_600,
        "required_claims": list(REQUIRED_CLAIMS),
        "schema_version": AUTHENTICATION_READINESS_SCHEMA_VERSION,
        "signed_token_checked": False,
        "token_identifier_claim": "jti",
        "token_profile": "provider_neutral",
        "microsoft_entra_tenant_id": None,
        "microsoft_entra_api_application_id": None,
        "microsoft_entra_calling_client_application_id": None,
        "microsoft_entra_required_delegated_scope": None,
        "microsoft_entra_required_azpacr": None,
        "validation_scope": AUTHENTICATION_READINESS_VALIDATION_SCOPE,
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"configuration_validated": False},
        {"jwks_reachability_checked": True},
        {"signed_token_checked": True},
        {"activation_ready": True},
        {"required_claims": ("exp",)},
        {"document_type": "different_document"},
        {"schema_version": 2},
        {"configuration_sha256": "0" * 64},
        {"algorithms": ("RS512", "RS256")},
        {"issuer": f"  {ISSUER}  "},
        {"audience": f"  {AUDIENCE}  "},
        {"jwks_url": f"  {JWKS_URL}  "},
        {"algorithms": (" RS256 ",)},
        {"algorithms": None},
        {"algorithms": ("RS256", 1)},
        {"token_identifier_claim": "UTI"},
        {"token_identifier_claim": "uti "},
        {"token_identifier_claim": "sid"},
        {"token_identifier_claim": None},
        {"token_profile": "microsoft_entra"},
        {"token_profile": None},
        {"microsoft_entra_tenant_id": ENTRA_TENANT_ID},
        {"microsoft_entra_api_application_id": ENTRA_API_APPLICATION_ID},
        {
            "microsoft_entra_calling_client_application_id": (
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            )
        },
        {
            "microsoft_entra_required_delegated_scope": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            )
        },
        {"microsoft_entra_required_azpacr": ENTRA_REQUIRED_AZPACR},
        {"jwks_timeout_seconds": 5},
    ],
)
def test_renderer_rejects_forged_or_non_local_readiness_claims(changes):
    preview = load_authentication_readiness_document(encoded()).preview
    forged = replace(preview, **changes)
    with pytest.raises(ValueError, match="not locally validated"):
        render_authentication_readiness_preview(forged)


def test_configuration_digest_includes_the_required_claim_contract():
    preview = load_authentication_readiness_document(encoded()).preview
    canonical = {
        "document_type": AUTHENTICATION_READINESS_DOCUMENT_TYPE,
        "schema_version": AUTHENTICATION_READINESS_SCHEMA_VERSION,
        "authentication": {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "jwks_url": JWKS_URL,
            "algorithms": ["RS256"],
            "token_identifier_claim": "jti",
            "token_profile": "provider_neutral",
            "microsoft_entra_tenant_id": None,
            "microsoft_entra_api_application_id": None,
            "microsoft_entra_calling_client_application_id": None,
            "microsoft_entra_required_delegated_scope": None,
            "microsoft_entra_required_azpacr": None,
            "clock_skew_seconds": 30,
            "maximum_token_age_seconds": 3_600,
            "jwks_cache_seconds": 300,
            "jwks_maximum_keys": 20,
            "jwks_timeout_seconds": 5.0,
            "jwks_maximum_response_bytes": 131_072,
            "required_claims": list(REQUIRED_CLAIMS),
        },
    }
    canonical_bytes = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    assert preview.configuration_sha256 == hashlib.sha256(canonical_bytes).hexdigest()


@pytest.mark.parametrize("document", [b"", b"\xff", b"{", b"[]", b'"text"'])
def test_empty_non_utf8_malformed_and_non_object_documents_fail_closed(document):
    with pytest.raises(AuthenticationReadinessDocumentError):
        load_authentication_readiness_document(document)


def test_document_size_and_bytes_only_boundaries_are_exact():
    with pytest.raises(AuthenticationReadinessDocumentError, match="byte limit"):
        load_authentication_readiness_document(
            b" " * (MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES + 1)
        )
    for value in ("{}", bytearray(b"{}"), memoryview(b"{}"), None):
        with pytest.raises(TypeError, match="must be bytes"):
            load_authentication_readiness_document(value)


def test_duplicate_keys_are_rejected_at_top_level_and_nested_levels():
    document = encoded(separators=(",", ":"))
    duplicate_top = document[:-1] + b',"schema_version":1}'
    duplicate_nested = document.replace(
        b'"audience":"engineer4me-api"',
        b'"audience":"engineer4me-api","audience":"other"',
    )
    for candidate in (duplicate_top, duplicate_nested):
        with pytest.raises(AuthenticationReadinessDocumentError, match="duplicate key"):
            load_authentication_readiness_document(candidate)


@pytest.mark.parametrize(
    "number", [b"NaN", b"Infinity", b"-Infinity", b"1e999", b"-1e999"]
)
def test_non_finite_numbers_are_rejected_before_contract_validation(number):
    payload = values()
    payload["authentication"]["jwks_timeout_seconds"] = 5.0
    document = encoded(payload, separators=(",", ":")).replace(
        b'"jwks_timeout_seconds":5.0',
        b'"jwks_timeout_seconds":' + number,
    )
    with pytest.raises(AuthenticationReadinessDocumentError, match="non-finite"):
        load_authentication_readiness_document(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("document_type", "other_document"),
        ("schema_version", 2),
        ("schema_version", True),
    ],
)
def test_wrong_document_discriminator_or_version_is_rejected(field, value):
    payload = values()
    payload[field] = value
    with pytest.raises(
        AuthenticationReadinessDocumentError, match="contract validation"
    ):
        load_authentication_readiness_document(encoded(payload))


@pytest.mark.parametrize(
    "path",
    [
        ("document_type",),
        ("schema_version",),
        ("authentication",),
        ("authentication", "issuer"),
        ("authentication", "audience"),
        ("authentication", "jwks_url"),
        ("authentication", "algorithms"),
    ],
)
def test_every_required_field_is_required(path):
    payload = values()
    target = payload
    for part in path[:-1]:
        target = target[part]
    del target[path[-1]]
    with pytest.raises(
        AuthenticationReadinessDocumentError, match="contract validation"
    ):
        load_authentication_readiness_document(encoded(payload))


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("issuer", None),
        ("issuer", 7),
        ("audience", ""),
        ("jwks_url", []),
        ("algorithms", "RS256"),
        ("algorithms", []),
        ("token_identifier_claim", "UTI"),
        ("token_identifier_claim", "uti "),
        ("token_identifier_claim", "sid"),
        ("token_identifier_claim", None),
        ("token_profile", "microsoft_entra"),
        ("token_profile", None),
        ("microsoft_entra_tenant_id", "not-a-guid"),
        ("microsoft_entra_api_application_id", "not-a-guid"),
        ("microsoft_entra_required_delegated_scope", "wrong_scope"),
        ("microsoft_entra_required_delegated_scope", "access_as_user "),
        ("clock_skew_seconds", True),
        ("clock_skew_seconds", -1),
        ("clock_skew_seconds", 301),
        ("maximum_token_age_seconds", 59),
        ("maximum_token_age_seconds", 86_401),
        ("jwks_cache_seconds", 29),
        ("jwks_cache_seconds", 3_601),
        ("jwks_maximum_keys", 0),
        ("jwks_maximum_keys", 101),
        ("jwks_timeout_seconds", True),
        ("jwks_timeout_seconds", 0.49),
        ("jwks_timeout_seconds", 30.01),
        ("jwks_maximum_response_bytes", 1_023),
        ("jwks_maximum_response_bytes", 1_048_577),
    ],
)
def test_invalid_types_and_bounds_fail_contract_validation(field, invalid):
    payload = values()
    payload["authentication"][field] = invalid
    with pytest.raises(
        AuthenticationReadinessDocumentError, match="contract validation"
    ):
        load_authentication_readiness_document(encoded(payload))


@pytest.mark.parametrize(
    "issuer",
    [
        "http://identity.example.test",
        "identity.example.test",
        "https://user@identity.example.test",
        "https://identity.example.test?tenant=one",
        "https://identity.example.test#issuer",
        "https://[invalid",
        "https://identity.example.test:notaport/tenant",
        "https://identity.example.test:99999/tenant",
        "https://identity.example.test:0/tenant",
        "https://@identity.example.test/tenant",
        "https://identity.example.test/ten\nant",
        "https://identity.example.test\\unexpected/tenant",
        "https://identity .example.test/tenant",
    ],
)
def test_non_https_or_ambiguous_issuer_fails_deployment_validation(issuer):
    payload = values()
    payload["authentication"]["issuer"] = issuer
    with pytest.raises(
        AuthenticationReadinessDocumentError,
        match="deployment validation",
    ) as captured:
        load_authentication_readiness_document(encoded(payload))
    assert issuer not in str(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "jwks_url",
    [
        "http://keys.example.test/jwks.json",
        "keys.example.test/jwks.json",
        "https://user@keys.example.test/jwks.json",
        "https://keys.example.test/jwks.json#keys",
        "https://keys.example.test/jwks.json?api_key=private-value",
        "https://keys.example.test/jwks.json?",
        "https://[invalid",
        "https://keys.example.test:notaport/jwks.json",
        "https://keys.example.test:99999/jwks.json",
        "https://keys.example.test:0/jwks.json",
        "https://@keys.example.test/jwks.json",
        "https://keys .example.test/jwks.json",
        "https://keys.example.test\\unexpected/jwks.json",
        "https://keys.example.test/jw\nks.json",
    ],
)
def test_unsafe_jwks_source_fails_deployment_validation(jwks_url):
    payload = values()
    payload["authentication"]["jwks_url"] = jwks_url
    with pytest.raises(
        AuthenticationReadinessDocumentError,
        match="deployment validation",
    ) as captured:
        load_authentication_readiness_document(encoded(payload))
    assert jwks_url not in str(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "algorithms",
    [
        ["none"],
        ["HS256"],
        ["RS256", "RS256"],
        ["RS256", ""],
        ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"],
    ],
)
def test_unsafe_empty_duplicate_or_oversized_algorithm_sets_fail_closed(algorithms):
    payload = values()
    payload["authentication"]["algorithms"] = algorithms
    expected = "contract validation" if len(algorithms) > 6 else "deployment validation"
    with pytest.raises(AuthenticationReadinessDocumentError, match=expected):
        load_authentication_readiness_document(encoded(payload))


@pytest.mark.parametrize(
    "field",
    [
        "client_secret",
        "private_key",
        "password",
        "api_key",
        "access_token",
        "refresh_token",
        "id_token",
        "cookie",
    ],
)
def test_secret_and_credential_fields_are_rejected_without_value_disclosure(field):
    secret = f"private-{field}-value"
    payload = values()
    payload["authentication"][field] = secret
    with pytest.raises(AuthenticationReadinessDocumentError) as captured:
        load_authentication_readiness_document(encoded(payload))
    rendered_traceback = "".join(traceback.format_exception(captured.value))
    assert secret not in str(captured.value)
    assert secret not in rendered_traceback


def test_unknown_top_level_and_authentication_fields_fail_closed():
    top_level = values()
    top_level["notes"] = "unreviewed"
    nested = values()
    nested["authentication"]["E4M_AUTH_JWKS_TIMOUT_SECONDS"] = "5"
    for payload in (top_level, nested):
        with pytest.raises(
            AuthenticationReadinessDocumentError, match="contract validation"
        ):
            load_authentication_readiness_document(encoded(payload))


def test_loading_and_rendering_perform_no_external_or_global_io(monkeypatch):
    routes_before = route_state()
    openapi_before = pre_activation_app.openapi_schema

    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected external access")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr("os.getenv", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    monkeypatch.setattr("app.security.jwks_http_loader._default_open", forbidden)
    monkeypatch.setattr("app.db.database.SessionLocal", forbidden)

    result = load_authentication_readiness_document(encoded())
    rendered = render_authentication_readiness_preview(result.preview)

    assert json.loads(rendered)["jwks_reachability_checked"] is False
    assert route_state() == routes_before
    assert pre_activation_app.openapi_schema is openapi_before
    assert not hasattr(pre_activation_app.state, "security_composition")


def test_fresh_readiness_import_does_not_read_database_url_or_construct_engine():
    script = """
import os
import sys

original_getenv = os.getenv

def guarded_getenv(key, *args, **kwargs):
    if key == "DATABASE_URL":
        raise AssertionError("readiness import read DATABASE_URL")
    return original_getenv(key, *args, **kwargs)

os.getenv = guarded_getenv
import app.security.authentication_readiness_document
assert "app.db.database" not in sys.modules
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=BACKEND_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_renderer_rejects_unvalidated_objects():
    with pytest.raises(TypeError, match="preview is required"):
        render_authentication_readiness_preview({})
