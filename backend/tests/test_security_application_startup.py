"""Tests for fresh readiness-verified secured application startup assembly."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.main import (
    OperationalReadinessConfirmedApplicationReceipt,
    OperationalSecuredApplicationActivationError,
    app as pre_activation_app,
    create_readiness_confirmed_secured_application as main_constructor,
)
from app.security.authentication_readiness_document import (
    load_authentication_readiness_document,
)
from app.security.authentication_token_readiness import (
    authentication_identity_sha256,
)
from app.security.security_application_activation_readiness import (
    OperationalApplicationActivationReadinessError,
    OperationalApplicationActivationReadinessReceipt,
    render_operational_application_activation_readiness,
)
from app.security.security_application_construction import (
    render_operational_application_construction_receipt,
)
from app.security.security_application_startup import (
    OPERATIONAL_SECURED_APPLICATION_STARTUP_SCOPE,
    OperationalSecuredApplicationStartupError,
    OperationalSecuredApplicationStartupReceipt,
    create_fresh_readiness_verified_secured_application,
    render_operational_secured_application_startup_receipt,
)


NOW = datetime(2026, 8, 11, 0, 0, tzinfo=UTC)
ISSUER = "https://identity.engineer4me.test/step192"
AUTHENTICATION_DOCUMENT = json.dumps(
    {
        "document_type": "engineer4me_authentication_readiness",
        "schema_version": 1,
        "authentication": {
            "issuer": ISSUER,
            "audience": "engineer4me-api",
            "jwks_url": "https://keys.engineer4me.test/step192/jwks.json",
            "algorithms": ["RS256"],
        },
    },
    sort_keys=True,
    separators=(",", ":"),
).encode()
POSTFLIGHT_DOCUMENT = b'{"synthetic":"step192-postflight"}'
BOOTSTRAP_DOCUMENT = b'{"synthetic":"step192-bootstrap"}'
APPROVED_POSTFLIGHT = hashlib.sha256(POSTFLIGHT_DOCUMENT).hexdigest()


class Probe:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args, **kwargs):
        del args, kwargs
        self.calls += 1
        raise AssertionError("unexpected startup I/O")


class ClockProbe:
    def __init__(self, *values: datetime) -> None:
        self.values = list(values)
        self.calls = 0

    def __call__(self) -> datetime:
        value = self.values[self.calls]
        self.calls += 1
        return value


def authentication_readiness():
    return load_authentication_readiness_document(
        AUTHENTICATION_DOCUMENT
    ).preview


def readiness_receipt(
    *, checked_at: datetime = NOW,
) -> OperationalApplicationActivationReadinessReceipt:
    return OperationalApplicationActivationReadinessReceipt(
        postflight_receipt_sha256=APPROVED_POSTFLIGHT,
        configuration_sha256=authentication_readiness().configuration_sha256,
        jwks_document_sha256="2" * 64,
        bootstrap_document_sha256="3" * 64,
        issuer_sha256=authentication_identity_sha256(ISSUER),
        subject_sha256="4" * 64,
        bootstrap_id=UUID("19200000-0000-4000-8000-000000000001"),
        request_id=UUID("19200000-0000-4000-8000-000000000002"),
        user_id=UUID("19200000-0000-4000-8000-000000000003"),
        organisation_id=UUID("19200000-0000-4000-8000-000000000004"),
        membership_id=UUID("19200000-0000-4000-8000-000000000005"),
        entitlement_snapshot_id=UUID(
            "19200000-0000-4000-8000-000000000006"
        ),
        checked_at=checked_at,
    )


def construction_receipt(
    *,
    readiness: OperationalApplicationActivationReadinessReceipt | None = None,
    constructed_at: datetime = NOW,
) -> OperationalReadinessConfirmedApplicationReceipt:
    value = readiness or readiness_receipt()
    readiness_document = render_operational_application_activation_readiness(
        value
    ).encode()
    return OperationalReadinessConfirmedApplicationReceipt(
        activation_readiness_sha256=hashlib.sha256(
            readiness_document
        ).hexdigest(),
        postflight_receipt_sha256=value.postflight_receipt_sha256,
        configuration_sha256=value.configuration_sha256,
        jwks_document_sha256=value.jwks_document_sha256,
        bootstrap_document_sha256=value.bootstrap_document_sha256,
        issuer_sha256=value.issuer_sha256,
        user_id=value.user_id,
        organisation_id=value.organisation_id,
        entitlement_snapshot_id=value.entitlement_snapshot_id,
        readiness_checked_at=value.checked_at,
        construction_checked_at=constructed_at,
        route_bindings=93,
        protected_bindings=91,
        public_bindings=2,
    )


def startup_receipt() -> OperationalSecuredApplicationStartupReceipt:
    readiness = readiness_receipt()
    construction = construction_receipt(readiness=readiness)
    readiness_document = render_operational_application_activation_readiness(
        readiness
    ).encode()
    construction_document = render_operational_application_construction_receipt(
        construction
    ).encode()
    return OperationalSecuredApplicationStartupReceipt(
        activation_readiness_sha256=hashlib.sha256(
            readiness_document
        ).hexdigest(),
        construction_receipt_sha256=hashlib.sha256(
            construction_document
        ).hexdigest(),
        postflight_receipt_sha256=readiness.postflight_receipt_sha256,
        configuration_sha256=readiness.configuration_sha256,
        jwks_document_sha256=readiness.jwks_document_sha256,
        bootstrap_document_sha256=readiness.bootstrap_document_sha256,
        issuer_sha256=readiness.issuer_sha256,
        user_id=readiness.user_id,
        organisation_id=readiness.organisation_id,
        entitlement_snapshot_id=readiness.entitlement_snapshot_id,
        readiness_checked_at=NOW,
        construction_checked_at=NOW,
        route_bindings=93,
        protected_bindings=91,
        public_bindings=2,
    )


def route_fingerprint(application: FastAPI):
    return tuple(
        (
            type(route),
            id(route),
            getattr(route, "path", None),
            tuple(sorted(getattr(route, "methods", ()) or ())),
            id(getattr(route, "endpoint", None)),
            tuple(
                id(dependency)
                for dependency in (getattr(route, "dependencies", ()) or ())
            ),
            id(getattr(route, "router", None)),
            getattr(route, "prefix", None),
        )
        for route in application.routes
    )


def build_application(monkeypatch):
    readiness = readiness_receipt()
    verification_calls = []

    def verify(**kwargs):
        verification_calls.append(kwargs)
        return readiness

    monkeypatch.setattr(
        "app.security.security_application_startup."
        "verify_operational_application_activation_readiness",
        verify,
    )
    readiness_session = Probe()
    access = Probe()
    audit = Probe()
    network = Probe()
    application = create_fresh_readiness_verified_secured_application(
        authentication_document=AUTHENTICATION_DOCUMENT,
        postflight_receipt_document=POSTFLIGHT_DOCUMENT,
        bootstrap_document=BOOTSTRAP_DOCUMENT,
        approved_postflight_receipt_sha256=APPROVED_POSTFLIGHT,
        readiness_session_factory=readiness_session,
        access_session_factory=access,
        audit_session_factory=audit,
        open_url=network,
        clock=lambda: NOW,
    )
    return (
        application,
        readiness,
        verification_calls,
        readiness_session,
        access,
        audit,
        network,
    )


def test_fresh_readiness_builds_exact_separate_secured_application(monkeypatch):
    before = route_fingerprint(pre_activation_app)
    before_openapi = pre_activation_app.openapi_schema
    (
        application,
        readiness,
        verification_calls,
        readiness_session,
        access,
        audit,
        network,
    ) = build_application(monkeypatch)
    startup = application.state.security_startup
    construction = application.state.security_activation

    assert application is not pre_activation_app
    assert type(startup) is OperationalSecuredApplicationStartupReceipt
    assert type(construction) is OperationalReadinessConfirmedApplicationReceipt
    assert startup.configuration_sha256 == readiness.configuration_sha256
    assert startup.user_id == readiness.user_id
    assert startup.organisation_id == readiness.organisation_id
    assert startup.entitlement_snapshot_id == readiness.entitlement_snapshot_id
    assert startup.route_bindings == 93
    assert startup.protected_bindings == 91
    assert startup.public_bindings == 2
    assert startup.database_reverified is True
    assert startup.readiness_bound is startup.application_constructed is True
    assert startup.deployment_cutover_performed is False
    assert len(verification_calls) == 1
    assert verification_calls[0]["session_factory"] is readiness_session
    assert verification_calls[0]["clock"]() == NOW
    assert readiness_session.calls == access.calls == audit.calls == network.calls == 0
    assert route_fingerprint(pre_activation_app) == before
    assert pre_activation_app.openapi_schema is before_openapi
    assert not hasattr(pre_activation_app.state, "security_startup")


def test_verification_receives_exact_evidence_and_precedes_construction(
    monkeypatch,
):
    events = []
    clock = ClockProbe(NOW, NOW + timedelta(seconds=1))

    def verify(**kwargs):
        events.append(("verify", kwargs.copy()))
        return readiness_receipt(checked_at=kwargs["clock"]())

    def construct(**kwargs):
        events.append(("construct", kwargs.copy()))
        return main_constructor(**kwargs)

    monkeypatch.setattr(
        "app.security.security_application_startup."
        "verify_operational_application_activation_readiness",
        verify,
    )
    monkeypatch.setattr(
        "app.security.security_application_startup."
        "create_readiness_confirmed_secured_application",
        construct,
    )
    application = create_fresh_readiness_verified_secured_application(
        authentication_document=AUTHENTICATION_DOCUMENT,
        postflight_receipt_document=POSTFLIGHT_DOCUMENT,
        bootstrap_document=BOOTSTRAP_DOCUMENT,
        approved_postflight_receipt_sha256=APPROVED_POSTFLIGHT,
        readiness_session_factory=Probe(),
        access_session_factory=Probe(),
        audit_session_factory=Probe(),
        open_url=Probe(),
        clock=clock,
    )

    assert [event[0] for event in events] == ["verify", "construct"]
    verified = events[0][1]
    assert verified["authentication_document"] is AUTHENTICATION_DOCUMENT
    assert verified["postflight_receipt_document"] is POSTFLIGHT_DOCUMENT
    assert verified["bootstrap_document"] is BOOTSTRAP_DOCUMENT
    assert verified["approved_postflight_receipt_sha256"] == APPROVED_POSTFLIGHT
    constructed = events[1][1]
    readiness_document = constructed["activation_readiness_document"]
    assert constructed["approved_activation_readiness_sha256"] == hashlib.sha256(
        readiness_document
    ).hexdigest()
    assert application.state.security_startup.readiness_checked_at == NOW
    assert application.state.security_startup.construction_checked_at == (
        NOW + timedelta(seconds=1)
    )
    assert clock.calls == 2


def test_public_and_missing_credential_boundaries_remain_no_io(monkeypatch):
    application, _, _, readiness_session, access, audit, network = (
        build_application(monkeypatch)
    )
    client = TestClient(application)

    assert client.get("/").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200
    response = client.get("/api/v1/manufacturers")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}
    assert response.headers["www-authenticate"] == "Bearer"
    assert readiness_session.calls == access.calls == audit.calls == network.calls == 0


def test_readiness_failure_precedes_authentication_reload_and_construction(
    monkeypatch,
):
    calls = []

    def fail(**kwargs):
        del kwargs
        raise OperationalApplicationActivationReadinessError("sensitive")

    monkeypatch.setattr(
        "app.security.security_application_startup."
        "verify_operational_application_activation_readiness",
        fail,
    )
    monkeypatch.setattr(
        "app.security.security_application_startup."
        "load_authentication_readiness_document",
        lambda value: calls.append(("load", value)),
    )
    monkeypatch.setattr(
        "app.security.security_application_startup."
        "create_readiness_confirmed_secured_application",
        lambda **kwargs: calls.append(("construct", kwargs)),
    )
    with pytest.raises(
        OperationalSecuredApplicationStartupError,
        match="readiness verification failed",
    ) as captured:
        create_fresh_readiness_verified_secured_application(
            authentication_document=AUTHENTICATION_DOCUMENT,
            postflight_receipt_document=POSTFLIGHT_DOCUMENT,
            bootstrap_document=BOOTSTRAP_DOCUMENT,
            approved_postflight_receipt_sha256=APPROVED_POSTFLIGHT,
            readiness_session_factory=Probe(),
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )
    assert captured.value.__cause__ is None
    assert calls == []
    assert "sensitive" not in str(captured.value)


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("authentication_document", None, "authentication document"),
        ("postflight_receipt_document", None, "postflight receipt"),
        ("bootstrap_document", None, "bootstrap document"),
        ("readiness_session_factory", object(), "readiness session factory"),
        ("access_session_factory", object(), "access session factory"),
        ("audit_session_factory", object(), "audit session factory"),
        ("open_url", object(), "JWKS transport"),
        ("clock", object(), "startup clock"),
    ],
)
def test_invalid_inputs_fail_before_readiness_verification(
    monkeypatch,
    field,
    value,
    message,
):
    calls = []
    monkeypatch.setattr(
        "app.security.security_application_startup."
        "verify_operational_application_activation_readiness",
        lambda **kwargs: calls.append(kwargs),
    )
    arguments = {
        "authentication_document": AUTHENTICATION_DOCUMENT,
        "postflight_receipt_document": POSTFLIGHT_DOCUMENT,
        "bootstrap_document": BOOTSTRAP_DOCUMENT,
        "approved_postflight_receipt_sha256": APPROVED_POSTFLIGHT,
        "readiness_session_factory": Probe(),
        "access_session_factory": Probe(),
        "audit_session_factory": Probe(),
        "clock": lambda: NOW,
    }
    arguments[field] = value
    with pytest.raises(TypeError, match=message):
        create_fresh_readiness_verified_secured_application(**arguments)
    assert calls == []


def test_construction_failure_is_sanitized(monkeypatch):
    monkeypatch.setattr(
        "app.security.security_application_startup."
        "verify_operational_application_activation_readiness",
        lambda **kwargs: readiness_receipt(),
    )

    def fail(**kwargs):
        del kwargs
        raise OperationalSecuredApplicationActivationError("sensitive")

    monkeypatch.setattr(
        "app.security.security_application_startup."
        "create_readiness_confirmed_secured_application",
        fail,
    )
    with pytest.raises(
        OperationalSecuredApplicationStartupError,
        match="construction failed",
    ) as captured:
        create_fresh_readiness_verified_secured_application(
            authentication_document=AUTHENTICATION_DOCUMENT,
            postflight_receipt_document=POSTFLIGHT_DOCUMENT,
            bootstrap_document=BOOTSTRAP_DOCUMENT,
            approved_postflight_receipt_sha256=APPROVED_POSTFLIGHT,
            readiness_session_factory=Probe(),
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )
    assert captured.value.__cause__ is None
    assert "sensitive" not in str(captured.value)


def test_mismatched_construction_receipt_is_rejected(monkeypatch):
    readiness = readiness_receipt()
    application = FastAPI()
    application.state.security_activation = replace(
        construction_receipt(readiness=readiness),
        configuration_sha256="f" * 64,
    )
    monkeypatch.setattr(
        "app.security.security_application_startup."
        "verify_operational_application_activation_readiness",
        lambda **kwargs: readiness,
    )
    monkeypatch.setattr(
        "app.security.security_application_startup."
        "create_readiness_confirmed_secured_application",
        lambda **kwargs: application,
    )
    with pytest.raises(
        OperationalSecuredApplicationStartupError,
        match="evidence do not match",
    ):
        create_fresh_readiness_verified_secured_application(
            authentication_document=AUTHENTICATION_DOCUMENT,
            postflight_receipt_document=POSTFLIGHT_DOCUMENT,
            bootstrap_document=BOOTSTRAP_DOCUMENT,
            approved_postflight_receipt_sha256=APPROVED_POSTFLIGHT,
            readiness_session_factory=Probe(),
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )


def test_missing_construction_receipt_is_rejected_safely(monkeypatch):
    application = FastAPI()
    monkeypatch.setattr(
        "app.security.security_application_startup."
        "verify_operational_application_activation_readiness",
        lambda **kwargs: readiness_receipt(),
    )
    monkeypatch.setattr(
        "app.security.security_application_startup."
        "create_readiness_confirmed_secured_application",
        lambda **kwargs: application,
    )
    with pytest.raises(
        OperationalSecuredApplicationStartupError,
        match="construction evidence is invalid",
    ) as captured:
        create_fresh_readiness_verified_secured_application(
            authentication_document=AUTHENTICATION_DOCUMENT,
            postflight_receipt_document=POSTFLIGHT_DOCUMENT,
            bootstrap_document=BOOTSTRAP_DOCUMENT,
            approved_postflight_receipt_sha256=APPROVED_POSTFLIGHT,
            readiness_session_factory=Probe(),
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )
    assert captured.value.__cause__ is None


def test_startup_renderer_is_canonical_privacy_minimised_and_non_cutover():
    rendered = render_operational_secured_application_startup_receipt(
        startup_receipt()
    )
    value = json.loads(rendered)

    assert rendered == json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert value["scope"] == OPERATIONAL_SECURED_APPLICATION_STARTUP_SCOPE
    assert value["database_reverified"] is True
    assert value["readiness_bound"] is True
    assert value["application_constructed"] is True
    assert value["deployment_cutover_performed"] is False
    assert value["route_bindings"] == 93
    assert value["protected_bindings"] == 91
    assert value["public_bindings"] == 2
    assert ISSUER not in rendered
    assert "engineer4me-api" not in rendered
    assert "jwks.json" not in rendered


def test_startup_renderer_rejects_wrong_or_forged_receipt():
    with pytest.raises(TypeError, match="receipt is required"):
        render_operational_secured_application_startup_receipt(object())
    with pytest.raises(ValueError, match="receipt is invalid"):
        render_operational_secured_application_startup_receipt(
            replace(startup_receipt(), deployment_cutover_performed=True)
        )
