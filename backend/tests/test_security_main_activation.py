"""Bootstrap-confirmed construction tests for the reviewed secured application."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
from uuid import UUID

from fastapi.testclient import TestClient
import pytest

from app.main import (
    OperationalSecuredApplicationActivationError,
    OperationalSecuredApplicationActivationReceipt,
    app,
    create_bootstrap_confirmed_secured_application,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
    load_authentication_readiness_document,
)
from app.security.security_bootstrap_operational_postflight import (
    OperationalSecurityBootstrapPostflightReceipt,
)


NOW = datetime(2026, 8, 10, 18, 5, tzinfo=UTC)
ENTRA_CALLING_CLIENT_APPLICATION_ID = "cccccccc-dddd-4eee-8fff-aaaaaaaa0400"
AUTHENTICATION_DOCUMENT = json.dumps(
    {
        "document_type": "engineer4me_authentication_readiness",
        "schema_version": 1,
        "authentication": {
            "issuer": "https://identity.engineer4me.test/step185",
            "audience": "engineer4me-api",
            "jwks_url": (
                "https://keys.engineer4me.test/step185/jwks.json"
            ),
            "algorithms": ["RS256"],
        },
    },
    separators=(",", ":"),
).encode()


class SessionFactoryProbe:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self):
        self.calls += 1
        raise AssertionError("unexpected eager database session")


class NetworkProbe:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args, **kwargs):
        del args, kwargs
        self.calls += 1
        raise AssertionError("unexpected eager JWKS request")


def authentication_readiness() -> AuthenticationReadinessPreview:
    return load_authentication_readiness_document(
        AUTHENTICATION_DOCUMENT
    ).preview


def microsoft_entra_readiness() -> AuthenticationReadinessPreview:
    tenant_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeee0200"
    application_id = "bbbbbbbb-cccc-4ddd-8eee-ffffffff0300"
    return load_authentication_readiness_document(
        json.dumps(
            {
                "document_type": "engineer4me_authentication_readiness",
                "schema_version": 1,
                "authentication": {
                    "issuer": (
                        "https://synthetic.ciamlogin.com/"
                        f"{tenant_id}/v2.0"
                    ),
                    "audience": application_id,
                    "jwks_url": (
                        "https://keys.engineer4me.test/step203/jwks.json"
                    ),
                    "algorithms": ["RS256"],
                    "token_identifier_claim": "uti",
                    "token_profile": "microsoft_entra_v2",
                    "microsoft_entra_tenant_id": tenant_id,
                    "microsoft_entra_api_application_id": application_id,
                    "microsoft_entra_calling_client_application_id": (
                        ENTRA_CALLING_CLIENT_APPLICATION_ID
                    ),
                    "microsoft_entra_required_delegated_scope": (
                        "access_as_user"
                    ),
                    "microsoft_entra_required_azpacr": "0",
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).preview


def bootstrap_postflight(
    *,
    configuration_sha256: str | None = None,
) -> OperationalSecurityBootstrapPostflightReceipt:
    readiness = authentication_readiness()
    return OperationalSecurityBootstrapPostflightReceipt(
        execution_receipt_sha256="1" * 64,
        preview_document_sha256="2" * 64,
        configuration_sha256=(
            readiness.configuration_sha256
            if configuration_sha256 is None
            else configuration_sha256
        ),
        jwks_document_sha256="3" * 64,
        bootstrap_document_sha256="4" * 64,
        issuer_sha256="5" * 64,
        subject_sha256="6" * 64,
        bootstrap_id=UUID("18500000-0000-4000-8000-000000000001"),
        request_id=UUID("18500000-0000-4000-8000-000000000002"),
        user_id=UUID("18500000-0000-4000-8000-000000000003"),
        organisation_id=UUID("18500000-0000-4000-8000-000000000004"),
        membership_id=UUID("18500000-0000-4000-8000-000000000005"),
        entitlement_snapshot_id=UUID(
            "18500000-0000-4000-8000-000000000006"
        ),
        execution_checked_at=NOW - timedelta(seconds=10),
        verification_checked_at=NOW,
    )


def build_application():
    access = SessionFactoryProbe()
    audit = SessionFactoryProbe()
    network = NetworkProbe()
    application = create_bootstrap_confirmed_secured_application(
        authentication_readiness=authentication_readiness(),
        bootstrap_postflight=bootstrap_postflight(),
        access_session_factory=access,
        audit_session_factory=audit,
        open_url=network,
    )
    return application, access, audit, network


def test_exact_bootstrap_and_authentication_evidence_builds_secured_surface():
    application, access, audit, network = build_application()
    composition = application.state.security_composition
    activation = application.state.security_activation

    assert len(composition.manifest.registrations) == 93
    assert len(composition.manifest.protected_registrations()) == 91
    assert len(composition.manifest.public_registrations()) == 2
    assert isinstance(
        activation,
        OperationalSecuredApplicationActivationReceipt,
    )
    assert activation.configuration_sha256 == (
        authentication_readiness().configuration_sha256
    )
    assert activation.execution_receipt_sha256 == "1" * 64
    assert activation.bootstrap_document_sha256 == "4" * 64
    assert activation.user_id == bootstrap_postflight().user_id
    assert activation.organisation_id == bootstrap_postflight().organisation_id
    assert activation.route_bindings == 93
    assert activation.protected_bindings == 91
    assert activation.public_bindings == 2
    assert activation.bootstrap_verified is activation.activation_ready is True
    assert access.calls == audit.calls == network.calls == 0


def test_public_surface_remains_available_without_security_io():
    application, access, audit, network = build_application()
    client = TestClient(application)

    assert client.get("/").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200
    assert access.calls == audit.calls == network.calls == 0


def test_protected_surface_rejects_missing_bearer_before_security_io():
    application, access, audit, network = build_application()
    response = TestClient(application).get("/api/v1/manufacturers")

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}
    assert response.headers["www-authenticate"] == "Bearer"
    assert access.calls == audit.calls == network.calls == 0


def test_configuration_digest_mismatch_fails_before_composition(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.main.create_reviewed_secured_application",
        lambda **kwargs: calls.append(kwargs),
    )
    with pytest.raises(
        OperationalSecuredApplicationActivationError,
        match="authentication and bootstrap evidence do not match",
    ) as captured:
        create_bootstrap_confirmed_secured_application(
            authentication_readiness=authentication_readiness(),
            bootstrap_postflight=bootstrap_postflight(
                configuration_sha256="f" * 64
            ),
            access_session_factory=SessionFactoryProbe(),
            audit_session_factory=SessionFactoryProbe(),
            open_url=NetworkProbe(),
        )
    assert captured.value.__cause__ is None
    assert calls == []


@pytest.mark.parametrize(
    "readiness",
    [
        object(),
        replace(authentication_readiness(), activation_ready=True),
        replace(authentication_readiness(), issuer=" https://private.invalid "),
        replace(authentication_readiness(), configuration_sha256="0" * 64),
    ],
)
def test_invalid_or_forged_readiness_fails_before_composition(
    monkeypatch,
    readiness,
):
    calls = []
    monkeypatch.setattr(
        "app.main.create_reviewed_secured_application",
        lambda **kwargs: calls.append(kwargs),
    )
    with pytest.raises(
        OperationalSecuredApplicationActivationError,
        match="authentication readiness is invalid",
    ) as captured:
        create_bootstrap_confirmed_secured_application(
            authentication_readiness=readiness,
            bootstrap_postflight=bootstrap_postflight(),
            access_session_factory=SessionFactoryProbe(),
            audit_session_factory=SessionFactoryProbe(),
            open_url=NetworkProbe(),
        )
    assert captured.value.__cause__ is None
    assert calls == []


def test_exact_postflight_receipt_type_is_required_before_composition(
    monkeypatch,
):
    calls = []
    monkeypatch.setattr(
        "app.main.create_reviewed_secured_application",
        lambda **kwargs: calls.append(kwargs),
    )
    with pytest.raises(TypeError, match="postflight receipt is required"):
        create_bootstrap_confirmed_secured_application(
            authentication_readiness=authentication_readiness(),
            bootstrap_postflight=object(),
            access_session_factory=SessionFactoryProbe(),
            audit_session_factory=SessionFactoryProbe(),
            open_url=NetworkProbe(),
        )
    assert calls == []


def test_explicit_factories_and_network_transport_are_forwarded(monkeypatch):
    readiness = authentication_readiness()
    postflight = bootstrap_postflight()
    access = object()
    audit = object()
    network = object()
    observed = []

    class Manifest:
        registrations = tuple(range(93))

        @staticmethod
        def protected_registrations():
            return tuple(range(91))

        @staticmethod
        def public_registrations():
            return tuple(range(2))

    class State:
        security_composition = type("Composition", (), {"manifest": Manifest()})()

    class Application:
        state = State()

    def create(**kwargs):
        observed.append(kwargs)
        return Application()

    monkeypatch.setattr("app.main.create_reviewed_secured_application", create)
    application = create_bootstrap_confirmed_secured_application(
        authentication_readiness=readiness,
        bootstrap_postflight=postflight,
        access_session_factory=access,
        audit_session_factory=audit,
        open_url=network,
    )

    assert application.state.security_activation.activation_ready is True
    assert observed[0]["access_session_factory"] is access
    assert observed[0]["audit_session_factory"] is audit
    assert observed[0]["open_url"] is network
    assert observed[0]["environment"] == {
        "E4M_AUTH_ISSUER": readiness.issuer,
        "E4M_AUTH_AUDIENCE": readiness.audience,
        "E4M_AUTH_JWKS_URL": readiness.jwks_url,
        "E4M_AUTH_ALGORITHMS": "RS256",
        "E4M_AUTH_TOKEN_IDENTIFIER_CLAIM": "jti",
        "E4M_AUTH_TOKEN_PROFILE": "provider_neutral",
        "E4M_AUTH_CLOCK_SKEW_SECONDS": "30",
        "E4M_AUTH_MAXIMUM_TOKEN_AGE_SECONDS": "3600",
        "E4M_AUTH_JWKS_CACHE_SECONDS": "300",
        "E4M_AUTH_JWKS_MAXIMUM_KEYS": "20",
        "E4M_AUTH_JWKS_TIMEOUT_SECONDS": "5.0",
        "E4M_AUTH_JWKS_MAXIMUM_RESPONSE_BYTES": "131072",
    }


def test_microsoft_entra_profile_scope_and_calling_client_reach_runtime(
    monkeypatch,
):
    readiness = microsoft_entra_readiness()
    observed = []

    class Manifest:
        registrations = tuple(range(93))

        @staticmethod
        def protected_registrations():
            return tuple(range(91))

        @staticmethod
        def public_registrations():
            return tuple(range(2))

    class Application:
        state = type(
            "State",
            (),
            {"security_composition": type("C", (), {"manifest": Manifest()})()},
        )()

    def create(**kwargs):
        observed.append(kwargs)
        return Application()

    monkeypatch.setattr("app.main.create_reviewed_secured_application", create)
    create_bootstrap_confirmed_secured_application(
        authentication_readiness=readiness,
        bootstrap_postflight=bootstrap_postflight(
            configuration_sha256=readiness.configuration_sha256
        ),
        access_session_factory=object(),
        audit_session_factory=object(),
    )

    environment = observed[0]["environment"]
    assert environment["E4M_AUTH_TOKEN_IDENTIFIER_CLAIM"] == "uti"
    assert environment["E4M_AUTH_TOKEN_PROFILE"] == "microsoft_entra_v2"
    assert environment["E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID"] == (
        readiness.microsoft_entra_tenant_id
    )
    assert environment["E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID"] == (
        readiness.microsoft_entra_api_application_id
    )
    assert environment[
        "E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID"
    ] == readiness.microsoft_entra_calling_client_application_id
    assert environment["E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE"] == (
        "access_as_user"
    )
    assert environment["E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_AZPACR"] == "0"


def test_activation_factory_does_not_mutate_pre_activation_app():
    before_routes = tuple(
        (
            id(route),
            tuple(getattr(route, "dependencies", ())),
            id(getattr(route, "dependant", None)),
        )
        for route in app.routes
    )
    before_schema = app.openapi()

    application, _, _, _ = build_application()

    assert application is not app
    assert tuple(
        (
            id(route),
            tuple(getattr(route, "dependencies", ())),
            id(getattr(route, "dependant", None)),
        )
        for route in app.routes
    ) == before_routes
    assert app.openapi() is before_schema
    assert not hasattr(app.state, "security_activation")
    assert not hasattr(app.state, "security_composition")


def test_activation_receipt_is_frozen_and_contains_no_raw_provider_values():
    application, _, _, _ = build_application()
    activation = application.state.security_activation

    with pytest.raises(AttributeError):
        activation.activation_ready = False
    rendered = repr(activation)
    assert "identity.engineer4me.test" not in rendered
    assert "engineer4me-api" not in rendered
    assert "jwks.json" not in rendered
