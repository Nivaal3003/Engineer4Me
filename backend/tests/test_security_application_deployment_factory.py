"""Tests for the strict process-configured secured application factory."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Mapping
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from uuid import UUID

from fastapi import FastAPI
import pytest

from app.main import app as pre_activation_app
from app.security.security_application_deployment_factory import (
    MAXIMUM_STARTUP_PATH_CHARACTERS,
    OPERATIONAL_SECURED_APPLICATION_FACTORY_SCOPE,
    STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256,
    STARTUP_AUTHENTICATION_DOCUMENT_PATH,
    STARTUP_BOOTSTRAP_DOCUMENT_PATH,
    STARTUP_ENVIRONMENT_KEYS,
    STARTUP_ENVIRONMENT_PREFIX,
    STARTUP_POSTFLIGHT_RECEIPT_PATH,
    OperationalSecuredApplicationDeploymentFactoryError,
    OperationalSecuredApplicationFactoryReceipt,
    OperationalSecuredApplicationProcessConfiguration,
    create_process_configured_secured_application,
    load_operational_secured_application_process_configuration,
    render_operational_secured_application_factory_receipt,
)
from app.security.security_application_startup import (
    OperationalSecuredApplicationStartupReceipt,
)
from app.security.security_application_startup_application import (
    OperationalSecuredApplicationStartupApplicationError,
)


NOW = datetime(2026, 8, 11, 2, 0, tzinfo=UTC)
AUTH_PATH = "/run/engineer4me/step194/authentication.json"
POSTFLIGHT_PATH = "/run/engineer4me/step194/postflight.json"
BOOTSTRAP_PATH = "/run/engineer4me/step194/bootstrap.json"
APPROVED = "a" * 64
COMPLETE_ENVIRONMENT = {
    STARTUP_AUTHENTICATION_DOCUMENT_PATH: AUTH_PATH,
    STARTUP_POSTFLIGHT_RECEIPT_PATH: POSTFLIGHT_PATH,
    STARTUP_BOOTSTRAP_DOCUMENT_PATH: BOOTSTRAP_PATH,
    STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256: APPROVED,
}


class Probe:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args, **kwargs):
        del args, kwargs
        self.calls += 1
        raise AssertionError("unexpected factory I/O")


class SelectiveEnvironment(Mapping[str, str]):
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.reads: list[str] = []

    def __iter__(self) -> Iterator[str]:
        return iter(self.values)

    def __len__(self) -> int:
        return len(self.values)

    def __getitem__(self, key: str) -> str:
        self.reads.append(key)
        if key == "DATABASE_PASSWORD":
            raise AssertionError("unrelated secret was read")
        return self.values[key]


def startup_receipt() -> OperationalSecuredApplicationStartupReceipt:
    return OperationalSecuredApplicationStartupReceipt(
        activation_readiness_sha256="1" * 64,
        construction_receipt_sha256="2" * 64,
        postflight_receipt_sha256="3" * 64,
        configuration_sha256="4" * 64,
        jwks_document_sha256="5" * 64,
        bootstrap_document_sha256="6" * 64,
        issuer_sha256="7" * 64,
        user_id=UUID("19400000-0000-4000-8000-000000000001"),
        organisation_id=UUID("19400000-0000-4000-8000-000000000002"),
        entitlement_snapshot_id=UUID(
            "19400000-0000-4000-8000-000000000003"
        ),
        readiness_checked_at=NOW,
        construction_checked_at=NOW,
        route_bindings=93,
        protected_bindings=91,
        public_bindings=2,
    )


def factory_receipt() -> OperationalSecuredApplicationFactoryReceipt:
    return OperationalSecuredApplicationFactoryReceipt(
        startup_receipt_sha256="8" * 64,
        configuration_sha256="4" * 64,
        startup_checked_at=NOW,
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
            id(getattr(route, "router", None)),
        )
        for route in application.routes
    )


def test_explicit_complete_mapping_builds_and_binds_separate_application(
    monkeypatch,
):
    calls = []
    application = FastAPI()
    application.state.security_startup = startup_receipt()

    def construct(**kwargs):
        calls.append(kwargs)
        return application

    monkeypatch.setattr(
        "app.security.security_application_deployment_factory."
        "construct_local_fresh_readiness_verified_secured_application",
        construct,
    )
    readiness = Probe()
    access = Probe()
    audit = Probe()
    network = Probe()
    clock = lambda: NOW
    before = route_fingerprint(pre_activation_app)
    before_environment = dict(COMPLETE_ENVIRONMENT)
    result = create_process_configured_secured_application(
        environment=COMPLETE_ENVIRONMENT,
        readiness_session_factory=readiness,
        access_session_factory=access,
        audit_session_factory=audit,
        open_url=network,
        clock=clock,
    )

    assert result is application
    assert len(calls) == 1
    assert calls[0] == {
        "authentication_document_path": AUTH_PATH,
        "postflight_receipt_path": POSTFLIGHT_PATH,
        "bootstrap_document_path": BOOTSTRAP_PATH,
        "approved_postflight_receipt_sha256": APPROVED,
        "readiness_session_factory": readiness,
        "access_session_factory": access,
        "audit_session_factory": audit,
        "open_url": network,
        "clock": clock,
    }
    receipt = application.state.security_deployment_factory
    assert type(receipt) is OperationalSecuredApplicationFactoryReceipt
    assert receipt.configuration_sha256 == "4" * 64
    assert receipt.route_bindings == 93
    assert receipt.protected_bindings == 91
    assert receipt.public_bindings == 2
    assert receipt.process_configuration_validated is True
    assert receipt.application_constructed is True
    assert receipt.deployment_cutover_performed is False
    assert COMPLETE_ENVIRONMENT == before_environment
    assert readiness.calls == access.calls == audit.calls == network.calls == 0
    assert route_fingerprint(pre_activation_app) == before
    assert not hasattr(pre_activation_app.state, "security_deployment_factory")


def test_loader_reads_only_startup_prefixed_values():
    environment = SelectiveEnvironment(
        {
            "DATABASE_PASSWORD": "secret-sentinel",
            "UNRELATED": "unrelated-value",
            **COMPLETE_ENVIRONMENT,
        }
    )
    configuration = load_operational_secured_application_process_configuration(
        environment
    )

    assert configuration.authentication_document_path == AUTH_PATH
    assert configuration.postflight_receipt_path == POSTFLIGHT_PATH
    assert configuration.bootstrap_document_path == BOOTSTRAP_PATH
    assert configuration.approved_postflight_receipt_sha256 == APPROVED
    assert set(environment.reads) == set(STARTUP_ENVIRONMENT_KEYS)
    assert "DATABASE_PASSWORD" not in environment.reads
    assert "UNRELATED" not in environment.reads


def test_none_environment_uses_process_snapshot(monkeypatch):
    calls = []
    application = FastAPI()
    application.state.security_startup = startup_receipt()
    for key in tuple(os.environ):
        if key.startswith(STARTUP_ENVIRONMENT_PREFIX):
            monkeypatch.delenv(key, raising=False)
    for key, value in COMPLETE_ENVIRONMENT.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("UNRELATED_SECRET", "secret-sentinel")
    monkeypatch.setattr(
        "app.security.security_application_deployment_factory."
        "construct_local_fresh_readiness_verified_secured_application",
        lambda **kwargs: calls.append(kwargs) or application,
    )

    result = create_process_configured_secured_application()

    assert result is application
    assert len(calls) == 1
    serialized = json.dumps(calls[0], default=str)
    assert "secret-sentinel" not in serialized
    assert "UNRELATED_SECRET" not in serialized


def test_explicit_empty_mapping_never_falls_back_to_process(monkeypatch):
    calls = []
    for key, value in COMPLETE_ENVIRONMENT.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(
        "app.security.security_application_deployment_factory."
        "construct_local_fresh_readiness_verified_secured_application",
        lambda **kwargs: calls.append(kwargs),
    )

    with pytest.raises(
        OperationalSecuredApplicationDeploymentFactoryError,
        match="configuration is incomplete",
    ):
        create_process_configured_secured_application(environment={})
    assert calls == []


@pytest.mark.parametrize("missing", STARTUP_ENVIRONMENT_KEYS)
def test_every_missing_required_key_fails_before_construction(
    monkeypatch,
    missing,
):
    calls = []
    environment = dict(COMPLETE_ENVIRONMENT)
    del environment[missing]
    monkeypatch.setattr(
        "app.security.security_application_deployment_factory."
        "construct_local_fresh_readiness_verified_secured_application",
        lambda **kwargs: calls.append(kwargs),
    )
    with pytest.raises(
        OperationalSecuredApplicationDeploymentFactoryError,
        match="configuration is incomplete",
    ):
        create_process_configured_secured_application(environment=environment)
    assert calls == []


def test_unknown_prefixed_key_fails_closed_before_construction(monkeypatch):
    calls = []
    environment = {
        **COMPLETE_ENVIRONMENT,
        "E4M_SECURITY_STARTUP_AUTHENTICATION_DOCUMNET_PATH": AUTH_PATH,
    }
    monkeypatch.setattr(
        "app.security.security_application_deployment_factory."
        "construct_local_fresh_readiness_verified_secured_application",
        lambda **kwargs: calls.append(kwargs),
    )
    with pytest.raises(
        OperationalSecuredApplicationDeploymentFactoryError,
        match="configuration is incomplete",
    ):
        create_process_configured_secured_application(environment=environment)
    assert calls == []


@pytest.mark.parametrize(
    "key,value",
    [
        (STARTUP_AUTHENTICATION_DOCUMENT_PATH, None),
        (STARTUP_AUTHENTICATION_DOCUMENT_PATH, ""),
        (
            STARTUP_AUTHENTICATION_DOCUMENT_PATH,
            "x" * (MAXIMUM_STARTUP_PATH_CHARACTERS + 1),
        ),
        (STARTUP_AUTHENTICATION_DOCUMENT_PATH, "bad\npath"),
        (STARTUP_AUTHENTICATION_DOCUMENT_PATH, "bad\x00path"),
        (
            STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256,
            "invalid-sensitive-sentinel",
        ),
        (STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256, "A" * 64),
    ],
)
def test_invalid_values_fail_sanitized_before_construction(
    monkeypatch,
    key,
    value,
):
    calls = []
    environment = dict(COMPLETE_ENVIRONMENT)
    environment[key] = value
    monkeypatch.setattr(
        "app.security.security_application_deployment_factory."
        "construct_local_fresh_readiness_verified_secured_application",
        lambda **kwargs: calls.append(kwargs),
    )
    with pytest.raises(
        OperationalSecuredApplicationDeploymentFactoryError,
        match="configuration is invalid",
    ) as captured:
        create_process_configured_secured_application(environment=environment)
    assert captured.value.__cause__ is None
    assert calls == []
    if isinstance(value, str) and value:
        assert value not in str(captured.value)


def test_configuration_is_frozen_and_strict():
    configuration = load_operational_secured_application_process_configuration(
        COMPLETE_ENVIRONMENT
    )
    with pytest.raises(FrozenInstanceError):
        configuration.authentication_document_path = "changed"
    with pytest.raises(ValueError, match="configuration is invalid"):
        OperationalSecuredApplicationProcessConfiguration(
            authentication_document_path="",
            postflight_receipt_path=POSTFLIGHT_PATH,
            bootstrap_document_path=BOOTSTRAP_PATH,
            approved_postflight_receipt_sha256=APPROVED,
        )


def test_local_construction_failure_is_sanitized(monkeypatch):
    def fail(**kwargs):
        del kwargs
        raise OperationalSecuredApplicationStartupApplicationError("sensitive")

    monkeypatch.setattr(
        "app.security.security_application_deployment_factory."
        "construct_local_fresh_readiness_verified_secured_application",
        fail,
    )
    with pytest.raises(
        OperationalSecuredApplicationDeploymentFactoryError,
        match="factory construction failed",
    ) as captured:
        create_process_configured_secured_application(
            environment=COMPLETE_ENVIRONMENT
        )
    assert captured.value.__cause__ is None
    assert "sensitive" not in str(captured.value)


@pytest.mark.parametrize("mode", ["wrong-type", "missing-receipt"])
def test_invalid_factory_result_is_rejected(monkeypatch, mode):
    if mode == "wrong-type":
        result = object()
    else:
        result = FastAPI()
    monkeypatch.setattr(
        "app.security.security_application_deployment_factory."
        "construct_local_fresh_readiness_verified_secured_application",
        lambda **kwargs: result,
    )
    with pytest.raises(
        OperationalSecuredApplicationDeploymentFactoryError,
        match="factory result is invalid",
    ) as captured:
        create_process_configured_secured_application(
            environment=COMPLETE_ENVIRONMENT
        )
    assert captured.value.__cause__ is None


def test_factory_renderer_is_canonical_privacy_minimised_and_non_cutover():
    rendered = render_operational_secured_application_factory_receipt(
        factory_receipt()
    )
    value = json.loads(rendered)

    assert rendered == json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert value["scope"] == OPERATIONAL_SECURED_APPLICATION_FACTORY_SCOPE
    assert value["route_bindings"] == 93
    assert value["protected_bindings"] == 91
    assert value["public_bindings"] == 2
    assert value["process_configuration_validated"] is True
    assert value["application_constructed"] is True
    assert value["deployment_cutover_performed"] is False
    for raw in (AUTH_PATH, POSTFLIGHT_PATH, BOOTSTRAP_PATH, APPROVED):
        assert raw not in rendered


def test_factory_renderer_rejects_wrong_or_forged_receipt():
    with pytest.raises(TypeError, match="receipt is required"):
        render_operational_secured_application_factory_receipt(object())
    with pytest.raises(ValueError, match="receipt is invalid"):
        render_operational_secured_application_factory_receipt(
            replace(factory_receipt(), deployment_cutover_performed=True)
        )
