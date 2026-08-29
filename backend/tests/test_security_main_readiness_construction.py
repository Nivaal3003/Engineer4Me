"""Tests for digest-confirmed readiness-bound secured app construction."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi.testclient import TestClient
import pytest

from app.main import (
    OPERATIONAL_ACTIVATION_READINESS_FUTURE_SKEW_SECONDS,
    OPERATIONAL_ACTIVATION_READINESS_MAXIMUM_AGE_SECONDS,
    OperationalReadinessConfirmedApplicationReceipt,
    OperationalSecuredApplicationActivationError,
    app,
    create_readiness_confirmed_secured_application,
)
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
    load_authentication_readiness_document,
)
from app.security.authentication_token_readiness import (
    authentication_identity_sha256,
)
from app.security.security_application_activation_readiness import (
    OperationalApplicationActivationReadinessReceipt,
    render_operational_application_activation_readiness,
)


NOW = datetime(2026, 8, 10, 22, 0, tzinfo=UTC)
ISSUER = "https://identity.engineer4me.test/step190"
AUTHENTICATION_DOCUMENT = json.dumps(
    {
        "document_type": "engineer4me_authentication_readiness",
        "schema_version": 1,
        "authentication": {
            "issuer": ISSUER,
            "audience": "engineer4me-api",
            "jwks_url": "https://keys.engineer4me.test/step190/jwks.json",
            "algorithms": ["RS256"],
        },
    },
    sort_keys=True,
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


def activation_readiness(
    *,
    configuration_sha256: str | None = None,
    issuer_sha256: str | None = None,
    checked_at: datetime = NOW,
) -> OperationalApplicationActivationReadinessReceipt:
    authentication = authentication_readiness()
    return OperationalApplicationActivationReadinessReceipt(
        postflight_receipt_sha256="1" * 64,
        configuration_sha256=(
            authentication.configuration_sha256
            if configuration_sha256 is None
            else configuration_sha256
        ),
        jwks_document_sha256="2" * 64,
        bootstrap_document_sha256="3" * 64,
        issuer_sha256=(
            authentication_identity_sha256(ISSUER)
            if issuer_sha256 is None
            else issuer_sha256
        ),
        subject_sha256="4" * 64,
        bootstrap_id=UUID("19000000-0000-4000-8000-000000000001"),
        request_id=UUID("19000000-0000-4000-8000-000000000002"),
        user_id=UUID("19000000-0000-4000-8000-000000000003"),
        organisation_id=UUID("19000000-0000-4000-8000-000000000004"),
        membership_id=UUID("19000000-0000-4000-8000-000000000005"),
        entitlement_snapshot_id=UUID(
            "19000000-0000-4000-8000-000000000006"
        ),
        checked_at=checked_at,
    )


def readiness_document(**changes) -> bytes:
    return render_operational_application_activation_readiness(
        activation_readiness(**changes)
    ).encode()


def build_application(*, document: bytes | None = None, **changes):
    value = document or readiness_document()
    access = SessionFactoryProbe()
    audit = SessionFactoryProbe()
    network = NetworkProbe()
    arguments = {
        "authentication_readiness": authentication_readiness(),
        "activation_readiness_document": value,
        "approved_activation_readiness_sha256": hashlib.sha256(
            value
        ).hexdigest(),
        "access_session_factory": access,
        "audit_session_factory": audit,
        "open_url": network,
        "clock": lambda: NOW,
    }
    arguments.update(changes)
    application = create_readiness_confirmed_secured_application(**arguments)
    return application, access, audit, network


def test_exact_approved_fresh_readiness_builds_reviewed_secured_surface():
    application, access, audit, network = build_application()
    composition = application.state.security_composition
    receipt = application.state.security_activation

    assert len(composition.manifest.registrations) == 93
    assert len(composition.manifest.protected_registrations()) == 91
    assert len(composition.manifest.public_registrations()) == 2
    assert type(receipt) is OperationalReadinessConfirmedApplicationReceipt
    assert receipt.activation_readiness_sha256 == hashlib.sha256(
        readiness_document()
    ).hexdigest()
    assert receipt.configuration_sha256 == (
        authentication_readiness().configuration_sha256
    )
    assert receipt.postflight_receipt_sha256 == "1" * 64
    assert receipt.bootstrap_document_sha256 == "3" * 64
    assert receipt.user_id == activation_readiness().user_id
    assert receipt.organisation_id == activation_readiness().organisation_id
    assert receipt.entitlement_snapshot_id == (
        activation_readiness().entitlement_snapshot_id
    )
    assert receipt.readiness_checked_at == NOW
    assert receipt.construction_checked_at == NOW
    assert receipt.readiness_bound is receipt.application_constructed is True
    assert receipt.deployment_cutover_performed is False
    assert access.calls == audit.calls == network.calls == 0


def test_public_surface_remains_available_without_security_io():
    application, access, audit, network = build_application()
    client = TestClient(application)

    assert client.get("/").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200
    assert access.calls == audit.calls == network.calls == 0


def test_missing_bearer_is_rejected_before_security_io():
    application, access, audit, network = build_application()
    response = TestClient(application).get("/api/v1/manufacturers")

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}
    assert response.headers["www-authenticate"] == "Bearer"
    assert access.calls == audit.calls == network.calls == 0


def test_digest_mismatch_precedes_receipt_loading_and_composition(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.main.load_operational_application_activation_readiness_receipt",
        lambda value: calls.append(value),
    )
    monkeypatch.setattr(
        "app.main.create_reviewed_secured_application",
        lambda **kwargs: calls.append(kwargs),
    )
    with pytest.raises(
        OperationalSecuredApplicationActivationError,
        match="does not match approval",
    ):
        build_application(approved_activation_readiness_sha256="f" * 64)
    assert calls == []


@pytest.mark.parametrize("approved", [None, "INVALID", "A" * 64])
def test_invalid_approval_precedes_receipt_loading(monkeypatch, approved):
    calls = []
    monkeypatch.setattr(
        "app.main.load_operational_application_activation_readiness_receipt",
        lambda value: calls.append(value),
    )
    with pytest.raises(
        OperationalSecuredApplicationActivationError,
        match="digest is invalid",
    ):
        build_application(approved_activation_readiness_sha256=approved)
    assert calls == []


def test_malformed_approved_receipt_fails_before_composition(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.main.create_reviewed_secured_application",
        lambda **kwargs: calls.append(kwargs),
    )
    with pytest.raises(
        OperationalSecuredApplicationActivationError,
        match="evidence is invalid",
    ) as captured:
        build_application(document=b"{}")
    assert captured.value.__cause__ is None
    assert calls == []


@pytest.mark.parametrize(
    "checked_at,constructed_at",
    [
        (
            NOW
            - timedelta(
                seconds=OPERATIONAL_ACTIVATION_READINESS_MAXIMUM_AGE_SECONDS
                + 1
            ),
            NOW,
        ),
        (
            NOW
            + timedelta(
                seconds=OPERATIONAL_ACTIVATION_READINESS_FUTURE_SKEW_SECONDS
                + 1
            ),
            NOW,
        ),
    ],
)
def test_stale_or_future_readiness_fails_before_composition(
    monkeypatch,
    checked_at,
    constructed_at,
):
    calls = []
    monkeypatch.setattr(
        "app.main.create_reviewed_secured_application",
        lambda **kwargs: calls.append(kwargs),
    )
    document = readiness_document(checked_at=checked_at)
    with pytest.raises(
        OperationalSecuredApplicationActivationError,
        match="is not current",
    ):
        build_application(
            document=document,
            clock=lambda: constructed_at,
        )
    assert calls == []


@pytest.mark.parametrize(
    "checked_at",
    [
        NOW
        - timedelta(
            seconds=OPERATIONAL_ACTIVATION_READINESS_MAXIMUM_AGE_SECONDS
        ),
        NOW
        + timedelta(
            seconds=OPERATIONAL_ACTIVATION_READINESS_FUTURE_SKEW_SECONDS
        ),
    ],
)
def test_exact_freshness_boundaries_are_accepted(checked_at):
    document = readiness_document(checked_at=checked_at)
    application, _, _, _ = build_application(document=document)

    assert application.state.security_activation.readiness_checked_at == checked_at


def test_configuration_mismatch_fails_before_composition(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.main.create_reviewed_secured_application",
        lambda **kwargs: calls.append(kwargs),
    )
    document = readiness_document(configuration_sha256="f" * 64)
    with pytest.raises(
        OperationalSecuredApplicationActivationError,
        match="authentication and activation evidence do not match",
    ):
        build_application(document=document)
    assert calls == []


def test_issuer_mismatch_fails_before_composition(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.main.create_reviewed_secured_application",
        lambda **kwargs: calls.append(kwargs),
    )
    document = readiness_document(issuer_sha256="f" * 64)
    with pytest.raises(
        OperationalSecuredApplicationActivationError,
        match="identity evidence does not match",
    ):
        build_application(document=document)
    assert calls == []


@pytest.mark.parametrize(
    "readiness",
    [
        object(),
        replace(authentication_readiness(), activation_ready=True),
        replace(authentication_readiness(), configuration_sha256="f" * 64),
    ],
)
def test_invalid_authentication_readiness_fails_before_composition(
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
        match="authentication readiness is invalid|evidence do not match",
    ):
        build_application(authentication_readiness=readiness)
    assert calls == []


@pytest.mark.parametrize(
    "change,message",
    [
        ({"activation_readiness_document": bytearray(b"{}")}, "must be bytes"),
        ({"access_session_factory": object()}, "access session factory"),
        ({"audit_session_factory": object()}, "audit session factory"),
        ({"open_url": object()}, "JWKS transport"),
        ({"clock": object()}, "construction clock"),
    ],
)
def test_invalid_construction_dependencies_fail_without_composition(
    monkeypatch,
    change,
    message,
):
    calls = []
    monkeypatch.setattr(
        "app.main.create_reviewed_secured_application",
        lambda **kwargs: calls.append(kwargs),
    )
    with pytest.raises(TypeError, match=message):
        build_application(**change)
    assert calls == []


def test_readiness_factory_does_not_mutate_pre_activation_app():
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


def test_construction_receipt_is_frozen_and_privacy_minimised():
    application, _, _, _ = build_application()
    receipt = application.state.security_activation

    with pytest.raises(FrozenInstanceError):
        receipt.application_constructed = False
    rendered = repr(receipt)
    assert ISSUER not in rendered
    assert "engineer4me-api" not in rendered
    assert "jwks.json" not in rendered
