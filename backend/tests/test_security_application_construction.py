"""Tests for controlled local readiness-bound application construction."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI
import pytest

from app.main import (
    OperationalReadinessConfirmedApplicationReceipt,
    app as pre_activation_app,
)
from app.security.authentication_readiness_document import (
    load_authentication_readiness_document,
)
from app.security.authentication_token_readiness import (
    authentication_identity_sha256,
)
from app.security.security_application_activation_readiness import (
    MAX_OPERATIONAL_APPLICATION_ACTIVATION_READINESS_RECEIPT_BYTES,
    OperationalApplicationActivationReadinessReceipt,
    render_operational_application_activation_readiness,
)
from app.security.security_application_construction import (
    OPERATIONAL_APPLICATION_CONSTRUCTION_SCOPE,
    OperationalApplicationConstructionError,
    OperationalApplicationConstructionFileError,
    construct_local_readiness_confirmed_secured_application,
    main,
    render_operational_application_construction_receipt,
)


NOW = datetime(2026, 8, 10, 23, 0, tzinfo=UTC)
ISSUER = "https://identity.engineer4me.test/step191"
AUTHENTICATION_DOCUMENT = json.dumps(
    {
        "document_type": "engineer4me_authentication_readiness",
        "schema_version": 1,
        "authentication": {
            "issuer": ISSUER,
            "audience": "engineer4me-api",
            "jwks_url": "https://keys.engineer4me.test/step191/jwks.json",
            "algorithms": ["RS256"],
        },
    },
    sort_keys=True,
    separators=(",", ":"),
).encode()


class Probe:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args, **kwargs):
        del args, kwargs
        self.calls += 1
        raise AssertionError("unexpected construction I/O")


def authentication_readiness():
    return load_authentication_readiness_document(
        AUTHENTICATION_DOCUMENT
    ).preview


def readiness_receipt() -> OperationalApplicationActivationReadinessReceipt:
    return OperationalApplicationActivationReadinessReceipt(
        postflight_receipt_sha256="1" * 64,
        configuration_sha256=authentication_readiness().configuration_sha256,
        jwks_document_sha256="2" * 64,
        bootstrap_document_sha256="3" * 64,
        issuer_sha256=authentication_identity_sha256(ISSUER),
        subject_sha256="4" * 64,
        bootstrap_id=UUID("19100000-0000-4000-8000-000000000001"),
        request_id=UUID("19100000-0000-4000-8000-000000000002"),
        user_id=UUID("19100000-0000-4000-8000-000000000003"),
        organisation_id=UUID("19100000-0000-4000-8000-000000000004"),
        membership_id=UUID("19100000-0000-4000-8000-000000000005"),
        entitlement_snapshot_id=UUID(
            "19100000-0000-4000-8000-000000000006"
        ),
        checked_at=NOW,
    )


def readiness_document() -> bytes:
    return render_operational_application_activation_readiness(
        readiness_receipt()
    ).encode()


def write_inputs(tmp_path: Path) -> tuple[Path, Path, str]:
    authentication = tmp_path / "authentication.json"
    readiness = tmp_path / "activation-readiness.json"
    authentication.write_bytes(AUTHENTICATION_DOCUMENT)
    document = readiness_document()
    readiness.write_bytes(document)
    return authentication, readiness, hashlib.sha256(document).hexdigest()


def construct(tmp_path: Path, **changes):
    authentication, readiness, approved = write_inputs(tmp_path)
    access = Probe()
    audit = Probe()
    network = Probe()
    arguments = {
        "authentication_document_path": authentication,
        "activation_readiness_path": readiness,
        "approved_activation_readiness_sha256": approved,
        "access_session_factory": access,
        "audit_session_factory": audit,
        "open_url": network,
        "clock": lambda: NOW,
    }
    arguments.update(changes)
    application = construct_local_readiness_confirmed_secured_application(
        **arguments
    )
    return application, access, audit, network


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


def test_exact_local_evidence_constructs_separate_reviewed_application(tmp_path):
    before = route_fingerprint(pre_activation_app)
    before_openapi = pre_activation_app.openapi_schema
    application, access, audit, network = construct(tmp_path)
    receipt = application.state.security_activation

    assert application is not pre_activation_app
    assert type(receipt) is OperationalReadinessConfirmedApplicationReceipt
    assert receipt.activation_readiness_sha256 == hashlib.sha256(
        readiness_document()
    ).hexdigest()
    assert receipt.route_bindings == 93
    assert receipt.protected_bindings == 91
    assert receipt.public_bindings == 2
    assert receipt.readiness_bound is receipt.application_constructed is True
    assert receipt.deployment_cutover_performed is False
    assert access.calls == audit.calls == network.calls == 0
    assert route_fingerprint(pre_activation_app) == before
    assert pre_activation_app.openapi_schema is before_openapi
    assert not hasattr(pre_activation_app.state, "security_composition")


def test_approved_digest_mismatch_precedes_authentication_file_access(
    tmp_path,
    monkeypatch,
):
    authentication, readiness, _ = write_inputs(tmp_path)
    calls = []
    target = (
        "app.security.security_application_construction."
        "read_authentication_readiness_preview"
    )
    monkeypatch.setattr(
        target,
        lambda path: calls.append(path),
    )
    with pytest.raises(
        OperationalApplicationConstructionError,
        match="does not match approval",
    ):
        construct_local_readiness_confirmed_secured_application(
            authentication_document_path=authentication,
            activation_readiness_path=readiness,
            approved_activation_readiness_sha256="f" * 64,
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )
    assert calls == []


@pytest.mark.parametrize("approved", [None, "invalid", "A" * 64])
def test_invalid_approval_precedes_all_file_access(tmp_path, monkeypatch, approved):
    calls = []
    monkeypatch.setattr(
        "app.security.security_application_construction.os.lstat",
        lambda path: calls.append(path),
    )
    with pytest.raises(
        OperationalApplicationConstructionError,
        match="digest is invalid",
    ):
        construct_local_readiness_confirmed_secured_application(
            authentication_document_path=tmp_path / "auth",
            activation_readiness_path=tmp_path / "readiness",
            approved_activation_readiness_sha256=approved,
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )
    assert calls == []


def test_default_operational_session_factories_remain_lazy(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.security.security_application_construction._operational_session_factory",
        lambda: calls.append("resolved"),
    )
    authentication, readiness, approved = write_inputs(tmp_path)
    application = construct_local_readiness_confirmed_secured_application(
        authentication_document_path=authentication,
        activation_readiness_path=readiness,
        approved_activation_readiness_sha256=approved,
        clock=lambda: NOW,
    )
    assert application.state.security_activation.application_constructed is True
    assert calls == []


def test_default_factories_are_distinct_lazy_callables(tmp_path, monkeypatch):
    captured = {}
    application = FastAPI()
    application.state.security_activation = sample_construction_receipt()

    def fake_factory(**kwargs):
        captured.update(kwargs)
        return application

    target = (
        "app.security.security_application_construction."
        "create_readiness_confirmed_secured_application"
    )
    monkeypatch.setattr(
        target,
        fake_factory,
    )
    authentication, readiness, approved = write_inputs(tmp_path)
    result = construct_local_readiness_confirmed_secured_application(
        authentication_document_path=authentication,
        activation_readiness_path=readiness,
        approved_activation_readiness_sha256=approved,
        clock=lambda: NOW,
    )
    assert result is application
    assert callable(captured["access_session_factory"])
    assert callable(captured["audit_session_factory"])
    assert captured["access_session_factory"] is not captured["audit_session_factory"]


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("access_session_factory", object(), "access session factory"),
        ("audit_session_factory", object(), "audit session factory"),
        ("open_url", object(), "JWKS transport"),
        ("clock", object(), "construction clock"),
    ],
)
def test_invalid_dependencies_fail_before_file_access(
    tmp_path,
    monkeypatch,
    field,
    value,
    message,
):
    calls = []
    monkeypatch.setattr(
        "app.security.security_application_construction.os.lstat",
        lambda path: calls.append(path),
    )
    arguments = {
        "authentication_document_path": tmp_path / "auth",
        "activation_readiness_path": tmp_path / "readiness",
        "approved_activation_readiness_sha256": "a" * 64,
        "access_session_factory": Probe(),
        "audit_session_factory": Probe(),
        "clock": lambda: NOW,
    }
    arguments[field] = value
    with pytest.raises(TypeError, match=message):
        construct_local_readiness_confirmed_secured_application(**arguments)
    assert calls == []


def test_empty_readiness_file_fails_safely(tmp_path):
    authentication = tmp_path / "auth.json"
    readiness = tmp_path / "readiness.json"
    authentication.write_bytes(AUTHENTICATION_DOCUMENT)
    readiness.write_bytes(b"")
    with pytest.raises(
        OperationalApplicationConstructionFileError,
        match="is empty",
    ):
        construct_local_readiness_confirmed_secured_application(
            authentication_document_path=authentication,
            activation_readiness_path=readiness,
            approved_activation_readiness_sha256="a" * 64,
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )


def test_oversized_readiness_file_fails_safely(tmp_path):
    authentication = tmp_path / "auth.json"
    readiness = tmp_path / "readiness.json"
    authentication.write_bytes(AUTHENTICATION_DOCUMENT)
    readiness.write_bytes(
        b"x" * (MAX_OPERATIONAL_APPLICATION_ACTIVATION_READINESS_RECEIPT_BYTES + 1)
    )
    with pytest.raises(
        OperationalApplicationConstructionFileError,
        match="exceeds the byte limit",
    ):
        construct_local_readiness_confirmed_secured_application(
            authentication_document_path=authentication,
            activation_readiness_path=readiness,
            approved_activation_readiness_sha256="a" * 64,
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )


def test_directory_readiness_input_fails_safely(tmp_path):
    with pytest.raises(
        OperationalApplicationConstructionFileError,
        match="regular non-symlink",
    ):
        construct_local_readiness_confirmed_secured_application(
            authentication_document_path=tmp_path / "auth",
            activation_readiness_path=tmp_path,
            approved_activation_readiness_sha256="a" * 64,
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )


def test_symlink_readiness_input_fails_safely(tmp_path):
    target = tmp_path / "target.json"
    target.write_bytes(readiness_document())
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    with pytest.raises(
        OperationalApplicationConstructionFileError,
        match="regular non-symlink",
    ):
        construct_local_readiness_confirmed_secured_application(
            authentication_document_path=tmp_path / "auth",
            activation_readiness_path=link,
            approved_activation_readiness_sha256=hashlib.sha256(
                target.read_bytes()
            ).hexdigest(),
            access_session_factory=Probe(),
            audit_session_factory=Probe(),
            clock=lambda: NOW,
        )


def sample_construction_receipt() -> OperationalReadinessConfirmedApplicationReceipt:
    source = readiness_receipt()
    return OperationalReadinessConfirmedApplicationReceipt(
        activation_readiness_sha256=hashlib.sha256(
            readiness_document()
        ).hexdigest(),
        postflight_receipt_sha256=source.postflight_receipt_sha256,
        configuration_sha256=source.configuration_sha256,
        jwks_document_sha256=source.jwks_document_sha256,
        bootstrap_document_sha256=source.bootstrap_document_sha256,
        issuer_sha256=source.issuer_sha256,
        user_id=source.user_id,
        organisation_id=source.organisation_id,
        entitlement_snapshot_id=source.entitlement_snapshot_id,
        readiness_checked_at=NOW,
        construction_checked_at=NOW,
        route_bindings=93,
        protected_bindings=91,
        public_bindings=2,
    )


def test_renderer_is_canonical_privacy_minimised_non_cutover_evidence():
    receipt = sample_construction_receipt()
    rendered = render_operational_application_construction_receipt(receipt)
    parsed = json.loads(rendered)

    assert rendered == json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    assert parsed["scope"] == OPERATIONAL_APPLICATION_CONSTRUCTION_SCOPE
    assert parsed["route_bindings"] == 93
    assert parsed["protected_bindings"] == 91
    assert parsed["public_bindings"] == 2
    assert parsed["readiness_bound"] is True
    assert parsed["application_constructed"] is True
    assert parsed["deployment_cutover_performed"] is False
    assert ISSUER not in rendered
    assert "engineer4me-api" not in rendered
    assert "jwks.json" not in rendered


def test_renderer_rejects_wrong_or_forged_receipt():
    with pytest.raises(TypeError, match="receipt is required"):
        render_operational_application_construction_receipt(object())
    with pytest.raises(ValueError, match="receipt is invalid"):
        render_operational_application_construction_receipt(
            replace(sample_construction_receipt(), deployment_cutover_performed=True)
        )


def test_cli_prints_one_canonical_receipt_line(tmp_path, capsys, monkeypatch):
    real_constructor = construct_local_readiness_confirmed_secured_application

    def construct_with_fixed_clock(**kwargs):
        return real_constructor(**kwargs, clock=lambda: NOW)

    monkeypatch.setattr(
        "app.security.security_application_construction."
        "construct_local_readiness_confirmed_secured_application",
        construct_with_fixed_clock,
    )
    authentication, readiness, approved = write_inputs(tmp_path)
    assert (
        main(
            [
                str(authentication),
                str(readiness),
                "--approve-activation-readiness-sha256",
                approved,
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert output.count("\n") == 1
    assert json.loads(output)["deployment_cutover_performed"] is False


def test_cli_failure_is_sanitized_without_input_disclosure(tmp_path, capsys):
    sensitive_path = tmp_path / "private-token-value.json"
    sensitive_path.write_text("secret-sentinel")
    with pytest.raises(SystemExit) as captured:
        main(
            [
                str(sensitive_path),
                str(sensitive_path),
                "--approve-activation-readiness-sha256",
                "a" * 64,
            ]
        )
    output = capsys.readouterr()
    combined = output.out + output.err
    assert captured.value.code == 2
    assert combined == "operational secured application construction failed\n"
    assert str(sensitive_path) not in combined
    assert "secret-sentinel" not in combined
