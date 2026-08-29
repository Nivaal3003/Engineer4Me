"""Tests for read-only bootstrap-confirmed application activation readiness."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from app.security.authentication_readiness_document import (
    load_authentication_readiness_document,
)
from app.security.authentication_token_readiness import (
    authentication_identity_sha256,
)
from app.security.bootstrap_document import load_security_bootstrap_document
from app.security.security_application_activation_readiness import (
    MAX_OPERATIONAL_APPLICATION_ACTIVATION_READINESS_RECEIPT_BYTES,
    OPERATIONAL_APPLICATION_ACTIVATION_READINESS_SCOPE,
    OperationalApplicationActivationReadinessDocumentError,
    OperationalApplicationActivationReadinessError,
    OperationalApplicationActivationReadinessReceipt,
    load_operational_application_activation_readiness_receipt,
    render_operational_application_activation_readiness,
    verify_operational_application_activation_readiness,
)
from app.security.security_bootstrap_operational_postflight import (
    OperationalSecurityBootstrapPostflightReceipt,
    OperationalSecurityBootstrapPostflightStateError,
    render_operational_security_bootstrap_postflight_receipt,
)


NOW = datetime(2026, 8, 10, 19, 0, tzinfo=UTC)
ISSUER = "https://identity.engineer4me.test/step187"
SUBJECT = "private-provider-owner-subject-step187"
IDS = {
    "bootstrap_id": UUID("18700000-0000-4000-8000-000000000001"),
    "request_id": UUID("18700000-0000-4000-8000-000000000002"),
    "user_id": UUID("18700000-0000-4000-8000-000000000003"),
    "organisation_id": UUID("18700000-0000-4000-8000-000000000004"),
    "membership_id": UUID("18700000-0000-4000-8000-000000000005"),
    "entitlement_snapshot_id": UUID(
        "18700000-0000-4000-8000-000000000006"
    ),
}


def authentication_document(*, audience: str = "engineer4me-api") -> bytes:
    value = {
        "document_type": "engineer4me_authentication_readiness",
        "schema_version": 1,
        "authentication": {
            "issuer": ISSUER,
            "audience": audience,
            "jwks_url": "https://keys.engineer4me.test/step187/jwks.json",
            "algorithms": ["RS256"],
        },
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def bootstrap_document(
    *,
    effective_at: datetime | None = None,
    expires_at: datetime | None = None,
    organisation_name: str = "Reviewed Organisation Step 187",
) -> bytes:
    value = {
        "bootstrap_id": str(IDS["bootstrap_id"]),
        "request_id": str(IDS["request_id"]),
        "user_id": str(IDS["user_id"]),
        "organisation_id": str(IDS["organisation_id"]),
        "membership_id": str(IDS["membership_id"]),
        "email": "private-owner-step187@example.com",
        "display_name": "Private Initial Owner Step 187",
        "issuer": ISSUER,
        "subject": SUBJECT,
        "organisation_slug": "reviewed-organisation-step187",
        "organisation_name": organisation_name,
        "initial_role": "owner",
        "activated_at": (NOW - timedelta(minutes=2)).isoformat(),
        "entitlement": {
            "snapshot_id": str(IDS["entitlement_snapshot_id"]),
            "organisation_id": str(IDS["organisation_id"]),
            "plan_id": "reviewed-plan-step187",
            "subscription_status": "active",
            "features": ["engineering_calculations"],
            "quotas": [],
            "effective_at": (
                effective_at or NOW - timedelta(minutes=3)
            ).isoformat(),
            "expires_at": (
                expires_at or NOW + timedelta(hours=1)
            ).isoformat(),
            "source_reference": "private reviewed source step187",
        },
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def postflight_receipt(
    *,
    authentication: bytes | None = None,
    bootstrap: bytes | None = None,
) -> OperationalSecurityBootstrapPostflightReceipt:
    configuration_sha256 = load_authentication_readiness_document(
        authentication or authentication_document()
    ).preview.configuration_sha256
    bootstrap_sha256 = load_security_bootstrap_document(
        bootstrap or bootstrap_document()
    ).preview.document_sha256
    return OperationalSecurityBootstrapPostflightReceipt(
        execution_receipt_sha256="1" * 64,
        preview_document_sha256="2" * 64,
        configuration_sha256=configuration_sha256,
        jwks_document_sha256="3" * 64,
        bootstrap_document_sha256=bootstrap_sha256,
        issuer_sha256=authentication_identity_sha256(ISSUER),
        subject_sha256=authentication_identity_sha256(ISSUER, SUBJECT),
        bootstrap_id=IDS["bootstrap_id"],
        request_id=IDS["request_id"],
        user_id=IDS["user_id"],
        organisation_id=IDS["organisation_id"],
        membership_id=IDS["membership_id"],
        entitlement_snapshot_id=IDS["entitlement_snapshot_id"],
        execution_checked_at=NOW - timedelta(minutes=1),
        verification_checked_at=NOW - timedelta(seconds=30),
    )


def postflight_document(
    *,
    authentication: bytes | None = None,
    bootstrap: bytes | None = None,
) -> bytes:
    return (
        render_operational_security_bootstrap_postflight_receipt(
            postflight_receipt(
                authentication=authentication,
                bootstrap=bootstrap,
            )
        )
        + "\n"
    ).encode()


class SessionFactoryProbe:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self):
        self.calls += 1
        raise AssertionError("unexpected direct session access")


def install_successful_reverification(monkeypatch):
    calls = []

    def reverify(**kwargs):
        calls.append(kwargs)
        return replace(postflight_receipt(), verification_checked_at=NOW)

    monkeypatch.setattr(
        "app.security.security_application_activation_readiness."
        "reverify_operational_security_bootstrap_postflight",
        reverify,
    )
    return calls


def verify(monkeypatch, *, observed=None, **changes):
    calls = (
        install_successful_reverification(monkeypatch)
        if observed is None
        else observed
    )
    document = changes.pop("postflight_receipt_document", postflight_document())
    values = {
        "authentication_document": authentication_document(),
        "postflight_receipt_document": document,
        "bootstrap_document": bootstrap_document(),
        "approved_postflight_receipt_sha256": hashlib.sha256(
            document
        ).hexdigest(),
        "session_factory": SessionFactoryProbe(),
        "clock": lambda: NOW,
    }
    values.update(changes)
    return verify_operational_application_activation_readiness(**values), calls


def test_exact_documents_and_fresh_database_reverification_become_ready(
    monkeypatch,
):
    receipt, calls = verify(monkeypatch)

    assert receipt.activation_ready is True
    assert receipt.database_reverified is True
    assert receipt.entitlement_current is True
    assert receipt.configuration_bound is True
    assert receipt.checked_at == NOW
    assert receipt.configuration_sha256 == postflight_receipt().configuration_sha256
    assert receipt.bootstrap_id == IDS["bootstrap_id"]
    assert len(calls) == 1
    assert calls[0]["session_factory"].calls == 0
    assert calls[0]["clock"]() == NOW


def test_readiness_renderer_is_canonical_and_privacy_minimised(monkeypatch):
    receipt, _ = verify(monkeypatch)
    rendered = render_operational_application_activation_readiness(receipt)
    value = json.loads(rendered)

    assert rendered == json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert value["validation_scope"] == (
        OPERATIONAL_APPLICATION_ACTIVATION_READINESS_SCOPE
    )
    assert value["activation_ready"] is True
    assert value["database_reverified"] is True
    assert value["provider_ownership_attested"] is True
    assert value["provider_ownership_technically_verified"] is False
    for private in (
        ISSUER,
        SUBJECT,
        "private-owner-step187@example.com",
        "Private Initial Owner Step 187",
        "private reviewed source step187",
    ):
        assert private not in rendered


def canonical_readiness_document(monkeypatch) -> bytes:
    receipt, _ = verify(monkeypatch)
    return render_operational_application_activation_readiness(receipt).encode()


@pytest.mark.parametrize("suffix", [b"", b"\n", b"\r\n"])
def test_canonical_readiness_document_round_trips(monkeypatch, suffix):
    document = canonical_readiness_document(monkeypatch)
    receipt = load_operational_application_activation_readiness_receipt(
        document + suffix
    )

    assert type(receipt) is OperationalApplicationActivationReadinessReceipt
    assert receipt == verify(monkeypatch)[0]
    assert render_operational_application_activation_readiness(receipt) == (
        document.decode()
    )


@pytest.mark.parametrize("document", [None, "{}", bytearray(b"{}")])
def test_readiness_document_requires_exact_bytes(document):
    with pytest.raises(TypeError, match="must be bytes"):
        load_operational_application_activation_readiness_receipt(document)


@pytest.mark.parametrize(
    "document,message",
    [
        (b"", "size is invalid"),
        (
            b"x"
            * (
                MAX_OPERATIONAL_APPLICATION_ACTIVATION_READINESS_RECEIPT_BYTES
                + 1
            ),
            "size is invalid",
        ),
        (b"\xff", "not valid UTF-8"),
        (b"{}\n{}", "one canonical line"),
        (b"{}\r{}", "one canonical line"),
        (b"{}\n\n", "one canonical line"),
        (b"{}\r\n\r\n", "one canonical line"),
    ],
)
def test_readiness_document_byte_boundary_is_strict(document, message):
    with pytest.raises(
        OperationalApplicationActivationReadinessDocumentError,
        match=message,
    ):
        load_operational_application_activation_readiness_receipt(document)


@pytest.mark.parametrize(
    "document,message",
    [
        (b"not-json", "receipt is invalid"),
        (b"[]", "must be an object"),
        (b'"value"', "must be an object"),
        (
            b'{"activation_ready":true,"activation_ready":true}',
            "duplicate keys",
        ),
        (b'{"value":NaN}', "non-finite number"),
        (b'{"value":Infinity}', "non-finite number"),
        (b'{"value":-Infinity}', "non-finite number"),
        (
            (b"[" * 1_100) + (b"]" * 1_100),
            "receipt is invalid|must be an object",
        ),
    ],
)
def test_readiness_document_rejects_malformed_structures(document, message):
    with pytest.raises(
        OperationalApplicationActivationReadinessDocumentError,
        match=message,
    ) as captured:
        load_operational_application_activation_readiness_receipt(document)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "key,value",
    [
        ("activation_ready", False),
        ("activation_ready", 1),
        ("configuration_bound", False),
        ("database_reverified", False),
        ("entitlement_current", False),
        ("operational_schema", "private"),
        ("migration_revision", "wrong"),
        ("provider_ownership_attested", False),
        ("provider_ownership_technically_verified", True),
        ("validation_scope", "wrong"),
        ("configuration_sha256", "f" * 63),
        ("bootstrap_id", "not-a-uuid"),
        ("verified_at", "2026-08-10T19:00:00"),
        ("verified_at", "2026-08-10T21:00:00+02:00"),
    ],
)
def test_changed_readiness_evidence_is_rejected(
    monkeypatch,
    key,
    value,
):
    document = json.loads(canonical_readiness_document(monkeypatch))
    document[key] = value
    changed = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

    with pytest.raises(
        OperationalApplicationActivationReadinessDocumentError,
        match="contract is invalid|not canonical",
    ):
        load_operational_application_activation_readiness_receipt(changed)


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.pop("user_id"),
        lambda value: value.update({"unexpected": "private-value"}),
    ],
)
def test_missing_or_extra_readiness_fields_are_rejected(monkeypatch, change):
    value = json.loads(canonical_readiness_document(monkeypatch))
    change(value)
    changed = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    with pytest.raises(
        OperationalApplicationActivationReadinessDocumentError,
        match="contract is invalid|not canonical",
    ) as captured:
        load_operational_application_activation_readiness_receipt(changed)
    assert "private-value" not in str(captured.value)


def test_noncanonical_readiness_json_is_rejected(monkeypatch):
    value = json.loads(canonical_readiness_document(monkeypatch))
    changed = json.dumps(
        value,
        sort_keys=True,
        separators=(", ", ": "),
    ).encode()

    with pytest.raises(
        OperationalApplicationActivationReadinessDocumentError,
        match="not canonical",
    ):
        load_operational_application_activation_readiness_receipt(changed)


def test_readiness_loading_performs_no_file_database_or_network_io(
    monkeypatch,
):
    document = canonical_readiness_document(monkeypatch)
    calls = []
    monkeypatch.setattr(
        "builtins.open",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    monkeypatch.setattr(
        "app.security.security_application_activation_readiness."
        "reverify_operational_security_bootstrap_postflight",
        lambda **kwargs: calls.append(kwargs),
    )

    receipt = load_operational_application_activation_readiness_receipt(document)

    assert receipt.activation_ready is True
    assert calls == []


def test_postflight_digest_approval_precedes_document_or_database_access(
    monkeypatch,
):
    calls = []
    monkeypatch.setattr(
        "app.security.security_application_activation_readiness."
        "load_authentication_readiness_document",
        lambda value: calls.append(value),
    )
    with pytest.raises(
        OperationalApplicationActivationReadinessError,
        match="does not match approval",
    ):
        verify_operational_application_activation_readiness(
            authentication_document=b"private",
            postflight_receipt_document=postflight_document(),
            bootstrap_document=b"private",
            approved_postflight_receipt_sha256="f" * 64,
            session_factory=SessionFactoryProbe(),
            clock=lambda: NOW,
        )
    assert calls == []


def test_authentication_configuration_mismatch_precedes_database_access(
    monkeypatch,
):
    calls = install_successful_reverification(monkeypatch)
    document = postflight_document()
    with pytest.raises(
        OperationalApplicationActivationReadinessError,
        match="authentication and bootstrap evidence do not match",
    ):
        verify_operational_application_activation_readiness(
            authentication_document=authentication_document(
                audience="different-api"
            ),
            postflight_receipt_document=document,
            bootstrap_document=bootstrap_document(),
            approved_postflight_receipt_sha256=hashlib.sha256(
                document
            ).hexdigest(),
            session_factory=SessionFactoryProbe(),
            clock=lambda: NOW,
        )
    assert calls == []


def test_changed_bootstrap_document_precedes_database_access(monkeypatch):
    calls = install_successful_reverification(monkeypatch)
    with pytest.raises(
        OperationalApplicationActivationReadinessError,
        match="does not match bootstrap document",
    ):
        verify(
            monkeypatch,
            observed=calls,
            bootstrap_document=bootstrap_document(
                organisation_name="Private changed organisation"
            ),
        )
    assert calls == []


@pytest.mark.parametrize(
    ("document", "checked_at"),
    [
        (
            bootstrap_document(
                effective_at=NOW - timedelta(minutes=2),
            ),
            NOW - timedelta(minutes=2, seconds=1),
        ),
        (bootstrap_document(expires_at=NOW), NOW),
        (bootstrap_document(expires_at=NOW - timedelta(seconds=1)), NOW),
    ],
)
def test_noncurrent_entitlement_precedes_database_access(
    monkeypatch,
    document,
    checked_at,
):
    calls = install_successful_reverification(monkeypatch)
    matching_postflight = postflight_document(bootstrap=document)
    with pytest.raises(
        OperationalApplicationActivationReadinessError,
        match="entitlement is not currently usable",
    ):
        verify(
            monkeypatch,
            observed=calls,
            bootstrap_document=document,
            postflight_receipt_document=matching_postflight,
            clock=lambda: checked_at,
        )
    assert calls == []


def test_database_reverification_failure_is_sanitized(monkeypatch):
    def fail(**kwargs):
        del kwargs
        raise OperationalSecurityBootstrapPostflightStateError(
            "private database drift"
        )

    monkeypatch.setattr(
        "app.security.security_application_activation_readiness."
        "reverify_operational_security_bootstrap_postflight",
        fail,
    )
    document = postflight_document()
    with pytest.raises(
        OperationalApplicationActivationReadinessError,
        match="state is not ready for activation",
    ) as captured:
        verify_operational_application_activation_readiness(
            authentication_document=authentication_document(),
            postflight_receipt_document=document,
            bootstrap_document=bootstrap_document(),
            approved_postflight_receipt_sha256=hashlib.sha256(
                document
            ).hexdigest(),
            session_factory=SessionFactoryProbe(),
            clock=lambda: NOW,
        )
    assert captured.value.__cause__ is None
    assert "private" not in str(captured.value)


def test_readiness_receipt_is_frozen_and_rejects_forged_state(monkeypatch):
    receipt, _ = verify(monkeypatch)
    with pytest.raises(FrozenInstanceError):
        receipt.activation_ready = False
    with pytest.raises(ValueError, match="readiness receipt is invalid"):
        replace(receipt, activation_ready=False)
    with pytest.raises(ValueError, match="readiness receipt is invalid"):
        replace(receipt, database_reverified=False)
    with pytest.raises(ValueError, match="readiness receipt is invalid"):
        replace(receipt, checked_at=datetime(2026, 8, 10, 19, 0))


def test_invalid_collaborators_fail_before_document_processing(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.security.security_application_activation_readiness."
        "load_authentication_readiness_document",
        lambda value: calls.append(value),
    )
    document = postflight_document()
    with pytest.raises(TypeError, match="session factory"):
        verify_operational_application_activation_readiness(
            authentication_document=b"private",
            postflight_receipt_document=document,
            bootstrap_document=b"private",
            approved_postflight_receipt_sha256=hashlib.sha256(
                document
            ).hexdigest(),
            session_factory=object(),
            clock=lambda: NOW,
        )
    assert calls == []


def test_renderer_requires_exact_receipt_type():
    with pytest.raises(TypeError, match="readiness receipt is required"):
        render_operational_application_activation_readiness(object())
