"""Tests for the import-inert secured ASGI application factory entrypoint."""

from __future__ import annotations

import hashlib
import inspect
import json
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime

from fastapi import FastAPI
import pytest

from app.main import app as pre_activation_app
from app.security.security_application_deployment_factory import (
    OperationalSecuredApplicationFactoryReceipt,
    render_operational_secured_application_factory_receipt,
)
from app.security.security_application_factory_entrypoint import (
    OPERATIONAL_SECURED_APPLICATION_ENTRYPOINT_SCOPE,
    OperationalSecuredApplicationEntrypointError,
    OperationalSecuredApplicationEntrypointReceipt,
    create_operational_secured_application,
    render_operational_secured_application_entrypoint_receipt,
)


NOW = datetime(2026, 8, 11, 7, 0, tzinfo=UTC)
SENSITIVE = "step195-sensitive-startup-value"


def factory_receipt() -> OperationalSecuredApplicationFactoryReceipt:
    return OperationalSecuredApplicationFactoryReceipt(
        startup_receipt_sha256="1" * 64,
        configuration_sha256="2" * 64,
        startup_checked_at=NOW,
        route_bindings=93,
        protected_bindings=91,
        public_bindings=2,
    )


def entrypoint_receipt() -> OperationalSecuredApplicationEntrypointReceipt:
    return OperationalSecuredApplicationEntrypointReceipt(
        factory_receipt_sha256="3" * 64,
        configuration_sha256="2" * 64,
        startup_checked_at=NOW,
        route_bindings=93,
        protected_bindings=91,
        public_bindings=2,
    )


def secured_application() -> FastAPI:
    application = FastAPI()
    application.state.security_deployment_factory = factory_receipt()
    return application


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


def test_entrypoint_module_import_is_inert_in_fresh_process():
    script = r'''
import builtins
import importlib
import sys

original_import = builtins.__import__
blocked = {
    "app.main",
    "app.db.database",
    "app.security.security_application_deployment_factory",
}

def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name in blocked:
        raise AssertionError("blocked import: " + name)
    return original_import(name, globals, locals, fromlist, level)

builtins.__import__ = guarded_import
module = importlib.import_module(
    "app.security.security_application_factory_entrypoint"
)
assert not hasattr(module, "app")
assert "app.main" not in sys.modules
assert "app.db.database" not in sys.modules
assert "app.security.security_application_deployment_factory" not in sys.modules
assert callable(module.create_operational_secured_application)
'''
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_injected_factory_returns_separate_app_with_exact_receipt():
    application = secured_application()
    calls = []
    before = route_fingerprint(pre_activation_app)

    result = create_operational_secured_application(
        application_factory=lambda: calls.append(True) or application
    )

    assert result is application
    assert calls == [True]
    receipt = result.state.security_factory_entrypoint
    source = result.state.security_deployment_factory
    source_document = render_operational_secured_application_factory_receipt(
        source
    ).encode("utf-8")
    assert receipt.factory_receipt_sha256 == hashlib.sha256(
        source_document
    ).hexdigest()
    assert receipt.configuration_sha256 == source.configuration_sha256
    assert receipt.startup_checked_at == NOW
    assert receipt.route_bindings == 93
    assert receipt.protected_bindings == 91
    assert receipt.public_bindings == 2
    assert receipt.entrypoint_factory_completed is True
    assert receipt.serving_started is False
    assert receipt.deployment_cutover_performed is False
    assert route_fingerprint(pre_activation_app) == before
    assert not hasattr(pre_activation_app.state, "security_factory_entrypoint")


def test_default_entrypoint_calls_process_factory_once(monkeypatch):
    application = secured_application()
    calls = []

    def factory():
        calls.append(True)
        return application

    monkeypatch.setattr(
        "app.security.security_application_deployment_factory."
        "create_process_configured_secured_application",
        factory,
    )

    assert create_operational_secured_application() is application
    assert calls == [True]


@pytest.mark.parametrize(
    "factory",
    [
        None,
        lambda: object(),
        lambda: FastAPI(),
    ],
)
def test_invalid_injected_factory_or_result_fails_sanitized(factory):
    selected = SENSITIVE if factory is None else factory
    with pytest.raises(
        OperationalSecuredApplicationEntrypointError,
        match="entrypoint startup failed",
    ) as captured:
        create_operational_secured_application(
            application_factory=selected
        )
    assert captured.value.__cause__ is None
    assert SENSITIVE not in str(captured.value)


def test_factory_exception_fails_sanitized_without_fallback():
    calls = []

    def fail():
        calls.append(True)
        raise RuntimeError(SENSITIVE)

    with pytest.raises(
        OperationalSecuredApplicationEntrypointError,
        match="entrypoint startup failed",
    ) as captured:
        create_operational_secured_application(application_factory=fail)
    assert captured.value.__cause__ is None
    assert SENSITIVE not in str(captured.value)
    assert calls == [True]


def test_invalid_factory_evidence_fails_closed():
    application = secured_application()
    application.state.security_deployment_factory = object()
    with pytest.raises(
        OperationalSecuredApplicationEntrypointError,
        match="factory evidence is invalid",
    ) as captured:
        create_operational_secured_application(
            application_factory=lambda: application
        )
    assert captured.value.__cause__ is None


def test_entrypoint_receipt_is_frozen_and_strict():
    receipt = entrypoint_receipt()
    with pytest.raises(FrozenInstanceError):
        receipt.serving_started = True
    with pytest.raises(ValueError, match="receipt is invalid"):
        OperationalSecuredApplicationEntrypointReceipt(
            factory_receipt_sha256="invalid",
            configuration_sha256="2" * 64,
            startup_checked_at=NOW,
            route_bindings=93,
            protected_bindings=91,
            public_bindings=2,
        )


def test_entrypoint_receipt_renderer_is_canonical_and_non_cutover():
    rendered = render_operational_secured_application_entrypoint_receipt(
        entrypoint_receipt()
    )
    value = json.loads(rendered)

    assert rendered == json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert value["scope"] == OPERATIONAL_SECURED_APPLICATION_ENTRYPOINT_SCOPE
    assert value["route_bindings"] == 93
    assert value["protected_bindings"] == 91
    assert value["public_bindings"] == 2
    assert value["entrypoint_factory_completed"] is True
    assert value["serving_started"] is False
    assert value["deployment_cutover_performed"] is False
    assert SENSITIVE not in rendered


def test_entrypoint_receipt_renderer_rejects_wrong_or_forged_values():
    with pytest.raises(TypeError, match="receipt is required"):
        render_operational_secured_application_entrypoint_receipt(object())
    with pytest.raises(ValueError, match="receipt is invalid"):
        render_operational_secured_application_entrypoint_receipt(
            replace(entrypoint_receipt(), serving_started=True)
        )


def test_entrypoint_callable_is_synchronous_and_requires_no_arguments():
    signature = inspect.signature(create_operational_secured_application)
    assert all(
        parameter.default is not inspect.Parameter.empty
        for parameter in signature.parameters.values()
    )
    assert inspect.iscoroutinefunction(
        create_operational_secured_application
    ) is False
