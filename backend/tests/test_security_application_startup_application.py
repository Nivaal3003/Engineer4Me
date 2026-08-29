"""Tests for the controlled local secured-app startup application."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI
import pytest

from app.main import app as pre_activation_app
from app.security.authentication_readiness_document import (
    load_authentication_readiness_document,
)
from app.security.authentication_token_readiness import (
    authentication_identity_sha256,
)
from app.security.security_application_activation_readiness import (
    OperationalApplicationActivationReadinessReceipt,
)
from app.security.security_application_startup import (
    OperationalSecuredApplicationStartupError,
    OperationalSecuredApplicationStartupReceipt,
)
from app.security.security_application_startup_application import (
    OperationalSecuredApplicationStartupApplicationError,
    OperationalSecuredApplicationStartupFileError,
    construct_local_fresh_readiness_verified_secured_application,
    main,
)
from app.security.security_bootstrap_operational_postflight import (
    MAX_OPERATIONAL_BOOTSTRAP_POSTFLIGHT_RECEIPT_BYTES,
)


NOW = datetime(2026, 8, 11, 1, 0, tzinfo=UTC)
ISSUER = "https://identity.engineer4me.test/step193"
AUTHENTICATION_DOCUMENT = json.dumps(
    {
        "document_type": "engineer4me_authentication_readiness",
        "schema_version": 1,
        "authentication": {
            "issuer": ISSUER,
            "audience": "engineer4me-api",
            "jwks_url": "https://keys.engineer4me.test/step193/jwks.json",
            "algorithms": ["RS256"],
        },
    },
    sort_keys=True,
    separators=(",", ":"),
).encode()
POSTFLIGHT_DOCUMENT = b'{"synthetic":"step193-postflight"}'
BOOTSTRAP_DOCUMENT = b'{"synthetic":"step193-bootstrap"}'
APPROVED_POSTFLIGHT = hashlib.sha256(POSTFLIGHT_DOCUMENT).hexdigest()


class Probe:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args, **kwargs):
        del args, kwargs
        self.calls += 1
        raise AssertionError("unexpected startup application I/O")


def authentication_readiness():
    return load_authentication_readiness_document(
        AUTHENTICATION_DOCUMENT
    ).preview


def readiness_receipt() -> OperationalApplicationActivationReadinessReceipt:
    return OperationalApplicationActivationReadinessReceipt(
        postflight_receipt_sha256=APPROVED_POSTFLIGHT,
        configuration_sha256=authentication_readiness().configuration_sha256,
        jwks_document_sha256="2" * 64,
        bootstrap_document_sha256="3" * 64,
        issuer_sha256=authentication_identity_sha256(ISSUER),
        subject_sha256="4" * 64,
        bootstrap_id=UUID("19300000-0000-4000-8000-000000000001"),
        request_id=UUID("19300000-0000-4000-8000-000000000002"),
        user_id=UUID("19300000-0000-4000-8000-000000000003"),
        organisation_id=UUID("19300000-0000-4000-8000-000000000004"),
        membership_id=UUID("19300000-0000-4000-8000-000000000005"),
        entitlement_snapshot_id=UUID(
            "19300000-0000-4000-8000-000000000006"
        ),
        checked_at=NOW,
    )


def startup_receipt() -> OperationalSecuredApplicationStartupReceipt:
    readiness = readiness_receipt()
    return OperationalSecuredApplicationStartupReceipt(
        activation_readiness_sha256="5" * 64,
        construction_receipt_sha256="6" * 64,
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


def write_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    authentication = tmp_path / "authentication.json"
    postflight = tmp_path / "postflight.json"
    bootstrap = tmp_path / "bootstrap.json"
    authentication.write_bytes(AUTHENTICATION_DOCUMENT)
    postflight.write_bytes(POSTFLIGHT_DOCUMENT)
    bootstrap.write_bytes(BOOTSTRAP_DOCUMENT)
    return authentication, postflight, bootstrap


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


def build_application(tmp_path, monkeypatch):
    verification_calls = []

    def verify(**kwargs):
        verification_calls.append(kwargs)
        return readiness_receipt()

    monkeypatch.setattr(
        "app.security.security_application_startup."
        "verify_operational_application_activation_readiness",
        verify,
    )
    authentication, postflight, bootstrap = write_inputs(tmp_path)
    readiness_session = Probe()
    access = Probe()
    audit = Probe()
    network = Probe()
    application = construct_local_fresh_readiness_verified_secured_application(
        authentication_document_path=authentication,
        postflight_receipt_path=postflight,
        bootstrap_document_path=bootstrap,
        approved_postflight_receipt_sha256=APPROVED_POSTFLIGHT,
        readiness_session_factory=readiness_session,
        access_session_factory=access,
        audit_session_factory=audit,
        open_url=network,
        clock=lambda: NOW,
    )
    return (
        application,
        verification_calls,
        readiness_session,
        access,
        audit,
        network,
    )


def test_exact_local_evidence_builds_separate_non_cutover_application(
    tmp_path,
    monkeypatch,
):
    before = route_fingerprint(pre_activation_app)
    before_openapi = pre_activation_app.openapi_schema
    application, calls, readiness_session, access, audit, network = (
        build_application(tmp_path, monkeypatch)
    )
    startup = application.state.security_startup

    assert application is not pre_activation_app
    assert type(startup) is OperationalSecuredApplicationStartupReceipt
    assert startup.route_bindings == 93
    assert startup.protected_bindings == 91
    assert startup.public_bindings == 2
    assert startup.database_reverified is True
    assert startup.deployment_cutover_performed is False
    assert len(calls) == 1
    assert calls[0]["session_factory"] is readiness_session
    assert calls[0]["authentication_document"] == AUTHENTICATION_DOCUMENT
    assert calls[0]["postflight_receipt_document"] == POSTFLIGHT_DOCUMENT
    assert calls[0]["bootstrap_document"] == BOOTSTRAP_DOCUMENT
    assert calls[0]["approved_postflight_receipt_sha256"] == APPROVED_POSTFLIGHT
    assert readiness_session.calls == access.calls == audit.calls == network.calls == 0
    assert route_fingerprint(pre_activation_app) == before
    assert pre_activation_app.openapi_schema is before_openapi
    assert not hasattr(pre_activation_app.state, "security_startup")


def test_postflight_approval_precedes_other_files_and_assembly(
    monkeypatch,
):
    reads = []
    assemblies = []

    def read(path, *, maximum_bytes, label):
        del path, maximum_bytes
        reads.append(label)
        return POSTFLIGHT_DOCUMENT

    monkeypatch.setattr(
        "app.security.security_application_startup_application."
        "_read_local_document",
        read,
    )
    monkeypatch.setattr(
        "app.security.security_application_startup_application."
        "create_fresh_readiness_verified_secured_application",
        lambda **kwargs: assemblies.append(kwargs),
    )
    with pytest.raises(
        OperationalSecuredApplicationStartupApplicationError,
        match="does not match approval",
    ):
        construct_local_fresh_readiness_verified_secured_application(
            authentication_document_path="auth",
            postflight_receipt_path="postflight",
            bootstrap_document_path="bootstrap",
            approved_postflight_receipt_sha256="f" * 64,
            readiness_session_factory=Probe(),
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )
    assert reads == ["postflight receipt"]
    assert assemblies == []


@pytest.mark.parametrize("approved", [None, "invalid", "A" * 64])
def test_invalid_approval_precedes_all_file_access(monkeypatch, approved):
    reads = []
    monkeypatch.setattr(
        "app.security.security_application_startup_application."
        "_read_local_document",
        lambda *args, **kwargs: reads.append((args, kwargs)),
    )
    with pytest.raises(
        OperationalSecuredApplicationStartupApplicationError,
        match="digest is invalid",
    ):
        construct_local_fresh_readiness_verified_secured_application(
            authentication_document_path="auth",
            postflight_receipt_path="postflight",
            bootstrap_document_path="bootstrap",
            approved_postflight_receipt_sha256=approved,
            readiness_session_factory=Probe(),
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )
    assert reads == []


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("readiness_session_factory", object(), "readiness session factory"),
        ("access_session_factory", object(), "access session factory"),
        ("audit_session_factory", object(), "audit session factory"),
        ("open_url", object(), "JWKS transport"),
        ("clock", object(), "assembly clock"),
    ],
)
def test_invalid_dependencies_fail_before_file_access(
    monkeypatch,
    field,
    value,
    message,
):
    reads = []
    monkeypatch.setattr(
        "app.security.security_application_startup_application."
        "_read_local_document",
        lambda *args, **kwargs: reads.append((args, kwargs)),
    )
    arguments = {
        "authentication_document_path": "auth",
        "postflight_receipt_path": "postflight",
        "bootstrap_document_path": "bootstrap",
        "approved_postflight_receipt_sha256": APPROVED_POSTFLIGHT,
        "readiness_session_factory": Probe(),
        "access_session_factory": Probe(),
        "audit_session_factory": Probe(),
        "clock": lambda: NOW,
    }
    arguments[field] = value
    with pytest.raises(TypeError, match=message):
        construct_local_fresh_readiness_verified_secured_application(**arguments)
    assert reads == []


def test_default_session_factories_are_distinct_and_lazy(tmp_path, monkeypatch):
    captured = {}
    application = FastAPI()
    application.state.security_startup = startup_receipt()

    def assemble(**kwargs):
        captured.update(kwargs)
        return application

    monkeypatch.setattr(
        "app.security.security_application_startup_application."
        "create_fresh_readiness_verified_secured_application",
        assemble,
    )
    created = []

    def maker():
        value = object()
        created.append(value)
        return value

    resolutions = []

    def resolve():
        resolutions.append("resolved")
        return maker

    monkeypatch.setattr(
        "app.security.security_application_startup_application."
        "_operational_session_factory",
        resolve,
    )
    authentication, postflight, bootstrap = write_inputs(tmp_path)
    result = construct_local_fresh_readiness_verified_secured_application(
        authentication_document_path=authentication,
        postflight_receipt_path=postflight,
        bootstrap_document_path=bootstrap,
        approved_postflight_receipt_sha256=APPROVED_POSTFLIGHT,
        clock=lambda: NOW,
    )

    assert result is application
    factories = (
        captured["readiness_session_factory"],
        captured["access_session_factory"],
        captured["audit_session_factory"],
    )
    assert len({id(factory) for factory in factories}) == 3
    assert resolutions == created == []
    sessions = tuple(factory() for factory in factories)
    assert len({id(session) for session in sessions}) == 3
    assert len(resolutions) == len(created) == 3


@pytest.mark.parametrize(
    "content,message",
    [
        (b"", "is empty"),
        (
            b"x"
            * (MAX_OPERATIONAL_BOOTSTRAP_POSTFLIGHT_RECEIPT_BYTES + 1),
            "exceeds the byte limit",
        ),
    ],
)
def test_empty_or_oversized_postflight_file_fails_safely(
    tmp_path,
    content,
    message,
):
    authentication, postflight, bootstrap = write_inputs(tmp_path)
    postflight.write_bytes(content)
    with pytest.raises(
        OperationalSecuredApplicationStartupFileError,
        match=message,
    ):
        construct_local_fresh_readiness_verified_secured_application(
            authentication_document_path=authentication,
            postflight_receipt_path=postflight,
            bootstrap_document_path=bootstrap,
            approved_postflight_receipt_sha256="a" * 64,
            readiness_session_factory=Probe(),
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )


def test_directory_postflight_input_fails_safely(tmp_path):
    authentication, _, bootstrap = write_inputs(tmp_path)
    with pytest.raises(
        OperationalSecuredApplicationStartupFileError,
        match="regular non-symlink",
    ):
        construct_local_fresh_readiness_verified_secured_application(
            authentication_document_path=authentication,
            postflight_receipt_path=tmp_path,
            bootstrap_document_path=bootstrap,
            approved_postflight_receipt_sha256="a" * 64,
            readiness_session_factory=Probe(),
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )


def test_symlink_postflight_input_fails_safely(tmp_path):
    authentication, postflight, bootstrap = write_inputs(tmp_path)
    link = tmp_path / "postflight-link.json"
    try:
        link.symlink_to(postflight)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    with pytest.raises(
        OperationalSecuredApplicationStartupFileError,
        match="regular non-symlink",
    ):
        construct_local_fresh_readiness_verified_secured_application(
            authentication_document_path=authentication,
            postflight_receipt_path=link,
            bootstrap_document_path=bootstrap,
            approved_postflight_receipt_sha256=APPROVED_POSTFLIGHT,
            readiness_session_factory=Probe(),
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )


def test_assembly_failure_is_sanitized(tmp_path, monkeypatch):
    authentication, postflight, bootstrap = write_inputs(tmp_path)

    def fail(**kwargs):
        del kwargs
        raise OperationalSecuredApplicationStartupError("sensitive")

    monkeypatch.setattr(
        "app.security.security_application_startup_application."
        "create_fresh_readiness_verified_secured_application",
        fail,
    )
    with pytest.raises(
        OperationalSecuredApplicationStartupApplicationError,
        match="startup assembly failed",
    ) as captured:
        construct_local_fresh_readiness_verified_secured_application(
            authentication_document_path=authentication,
            postflight_receipt_path=postflight,
            bootstrap_document_path=bootstrap,
            approved_postflight_receipt_sha256=APPROVED_POSTFLIGHT,
            readiness_session_factory=Probe(),
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )
    assert captured.value.__cause__ is None
    assert "sensitive" not in str(captured.value)


def test_cli_prints_one_canonical_non_cutover_receipt(
    tmp_path,
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "app.security.security_application_startup."
        "verify_operational_application_activation_readiness",
        lambda **kwargs: readiness_receipt(),
    )
    monkeypatch.setattr(
        "app.security.security_application_startup_application._utc_now",
        lambda: NOW,
    )
    authentication, postflight, bootstrap = write_inputs(tmp_path)
    assert (
        main(
            [
                str(authentication),
                str(postflight),
                str(bootstrap),
                "--approve-postflight-receipt-sha256",
                APPROVED_POSTFLIGHT,
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert output.count("\n") == 1
    value = json.loads(output)
    assert value["route_bindings"] == 93
    assert value["database_reverified"] is True
    assert value["deployment_cutover_performed"] is False
    assert ISSUER not in output


def test_cli_failure_is_sanitized_without_path_or_value_disclosure(
    tmp_path,
    capsys,
):
    sensitive = tmp_path / "private-owner-value.json"
    sensitive.write_text("secret-sentinel")
    with pytest.raises(SystemExit) as captured:
        main(
            [
                str(sensitive),
                str(sensitive),
                str(sensitive),
                "--approve-postflight-receipt-sha256",
                "a" * 64,
            ]
        )
    output = capsys.readouterr()
    combined = output.out + output.err
    assert captured.value.code == 2
    assert combined == "operational secured application startup assembly failed\n"
    assert str(sensitive) not in combined
    assert "secret-sentinel" not in combined
