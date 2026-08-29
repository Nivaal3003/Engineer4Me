"""Strict process-configured factory for a separate secured application."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import FastAPI

from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.jwks_http_loader import OpenURL
from app.security.security_application_startup import (
    OperationalSecuredApplicationStartupReceipt,
    render_operational_secured_application_startup_receipt,
)
from app.security.security_application_startup_application import (
    OperationalSecuredApplicationStartupApplicationError,
    OperationalSecuredApplicationStartupFileError,
    construct_local_fresh_readiness_verified_secured_application,
)


OPERATIONAL_SECURED_APPLICATION_FACTORY_SCOPE = (
    "strict_process_configured_secured_application_factory"
)
STARTUP_ENVIRONMENT_PREFIX = "E4M_SECURITY_STARTUP_"
STARTUP_AUTHENTICATION_DOCUMENT_PATH = (
    "E4M_SECURITY_STARTUP_AUTHENTICATION_DOCUMENT_PATH"
)
STARTUP_POSTFLIGHT_RECEIPT_PATH = (
    "E4M_SECURITY_STARTUP_POSTFLIGHT_RECEIPT_PATH"
)
STARTUP_BOOTSTRAP_DOCUMENT_PATH = (
    "E4M_SECURITY_STARTUP_BOOTSTRAP_DOCUMENT_PATH"
)
STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256 = (
    "E4M_SECURITY_STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256"
)
STARTUP_ENVIRONMENT_KEYS = (
    STARTUP_AUTHENTICATION_DOCUMENT_PATH,
    STARTUP_POSTFLIGHT_RECEIPT_PATH,
    STARTUP_BOOTSTRAP_DOCUMENT_PATH,
    STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256,
)
MAXIMUM_STARTUP_PATH_CHARACTERS = 4_096


class OperationalSecuredApplicationDeploymentFactoryError(RuntimeError):
    """Sanitized rejection before a process factory can return an app."""


@dataclass(frozen=True, slots=True)
class OperationalSecuredApplicationProcessConfiguration:
    """Exact process-derived paths and approval for one factory call."""

    authentication_document_path: str
    postflight_receipt_path: str
    bootstrap_document_path: str
    approved_postflight_receipt_sha256: str

    def __post_init__(self) -> None:
        paths = (
            self.authentication_document_path,
            self.postflight_receipt_path,
            self.bootstrap_document_path,
        )
        if (
            any(
                type(value) is not str
                or not value
                or len(value) > MAXIMUM_STARTUP_PATH_CHARACTERS
                or any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in value
                )
                for value in paths
            )
            or type(self.approved_postflight_receipt_sha256) is not str
            or SHA256_PATTERN.fullmatch(
                self.approved_postflight_receipt_sha256
            )
            is None
        ):
            raise ValueError(
                "operational secured application process configuration is invalid"
            )


@dataclass(frozen=True, slots=True)
class OperationalSecuredApplicationFactoryReceipt:
    """Privacy-minimised evidence for one process-configured factory result."""

    startup_receipt_sha256: str
    configuration_sha256: str
    startup_checked_at: datetime
    route_bindings: int
    protected_bindings: int
    public_bindings: int
    process_configuration_validated: bool = True
    application_constructed: bool = True
    deployment_cutover_performed: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.startup_receipt_sha256) is not str
            or SHA256_PATTERN.fullmatch(self.startup_receipt_sha256) is None
            or type(self.configuration_sha256) is not str
            or SHA256_PATTERN.fullmatch(self.configuration_sha256) is None
            or not isinstance(self.startup_checked_at, datetime)
            or self.startup_checked_at.tzinfo is None
            or self.startup_checked_at.utcoffset() is None
            or self.route_bindings != 93
            or self.protected_bindings != 91
            or self.public_bindings != 2
            or self.process_configuration_validated is not True
            or self.application_constructed is not True
            or self.deployment_cutover_performed is not False
        ):
            raise ValueError(
                "operational secured application factory receipt is invalid"
            )


def _startup_environment_snapshot(
    source: Mapping[str, str],
) -> dict[str, str]:
    if not isinstance(source, Mapping):
        raise TypeError("operational startup environment must be a mapping")
    selected: dict[str, str] = {}
    try:
        for key in source:
            if type(key) is str and key.startswith(STARTUP_ENVIRONMENT_PREFIX):
                selected[key] = source[key]
    except Exception:
        raise OperationalSecuredApplicationDeploymentFactoryError(
            "operational startup environment could not be inspected safely"
        ) from None
    return selected


def load_operational_secured_application_process_configuration(
    environment: Mapping[str, str],
) -> OperationalSecuredApplicationProcessConfiguration:
    """Load all and only the exact startup-prefixed process configuration."""

    selected = _startup_environment_snapshot(environment)
    unknown = set(selected).difference(STARTUP_ENVIRONMENT_KEYS)
    missing = set(STARTUP_ENVIRONMENT_KEYS).difference(selected)
    if unknown or missing or len(selected) != len(STARTUP_ENVIRONMENT_KEYS):
        raise OperationalSecuredApplicationDeploymentFactoryError(
            "operational secured application process configuration is incomplete"
        )
    try:
        return OperationalSecuredApplicationProcessConfiguration(
            authentication_document_path=selected[
                STARTUP_AUTHENTICATION_DOCUMENT_PATH
            ],
            postflight_receipt_path=selected[STARTUP_POSTFLIGHT_RECEIPT_PATH],
            bootstrap_document_path=selected[STARTUP_BOOTSTRAP_DOCUMENT_PATH],
            approved_postflight_receipt_sha256=selected[
                STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256
            ],
        )
    except (TypeError, ValueError):
        raise OperationalSecuredApplicationDeploymentFactoryError(
            "operational secured application process configuration is invalid"
        ) from None


def _factory_receipt(
    startup: OperationalSecuredApplicationStartupReceipt,
) -> OperationalSecuredApplicationFactoryReceipt:
    if type(startup) is not OperationalSecuredApplicationStartupReceipt:
        raise OperationalSecuredApplicationDeploymentFactoryError(
            "operational secured application startup evidence is invalid"
        )
    try:
        rendered = render_operational_secured_application_startup_receipt(
            startup
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise OperationalSecuredApplicationDeploymentFactoryError(
            "operational secured application startup evidence is invalid"
        ) from None
    return OperationalSecuredApplicationFactoryReceipt(
        startup_receipt_sha256=hashlib.sha256(rendered).hexdigest(),
        configuration_sha256=startup.configuration_sha256,
        startup_checked_at=startup.construction_checked_at.astimezone(UTC),
        route_bindings=startup.route_bindings,
        protected_bindings=startup.protected_bindings,
        public_bindings=startup.public_bindings,
    )


def create_process_configured_secured_application(
    *,
    environment: Mapping[str, str] | None = None,
    readiness_session_factory: Callable[[], object] | None = None,
    access_session_factory: Callable[[], object] | None = None,
    audit_session_factory: Callable[[], object] | None = None,
    open_url: OpenURL | None = None,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Build one secured app on explicit invocation; never install or serve it."""

    source = os.environ if environment is None else environment
    configuration = load_operational_secured_application_process_configuration(
        source
    )
    arguments = {
        "authentication_document_path": (
            configuration.authentication_document_path
        ),
        "postflight_receipt_path": configuration.postflight_receipt_path,
        "bootstrap_document_path": configuration.bootstrap_document_path,
        "approved_postflight_receipt_sha256": (
            configuration.approved_postflight_receipt_sha256
        ),
        "readiness_session_factory": readiness_session_factory,
        "access_session_factory": access_session_factory,
        "audit_session_factory": audit_session_factory,
        "open_url": open_url,
    }
    if clock is not None:
        if not callable(clock):
            raise TypeError("operational secured application factory clock is invalid")
        arguments["clock"] = clock
    try:
        application = construct_local_fresh_readiness_verified_secured_application(
            **arguments
        )
    except (
        OperationalSecuredApplicationStartupApplicationError,
        OperationalSecuredApplicationStartupFileError,
    ):
        raise OperationalSecuredApplicationDeploymentFactoryError(
            "operational secured application factory construction failed"
        ) from None
    if not isinstance(application, FastAPI):
        raise OperationalSecuredApplicationDeploymentFactoryError(
            "operational secured application factory result is invalid"
        )
    try:
        receipt = _factory_receipt(application.state.security_startup)
    except OperationalSecuredApplicationDeploymentFactoryError:
        raise
    except (AttributeError, TypeError, ValueError):
        raise OperationalSecuredApplicationDeploymentFactoryError(
            "operational secured application factory result is invalid"
        ) from None
    application.state.security_deployment_factory = receipt
    return application


def _canonical_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def render_operational_secured_application_factory_receipt(
    receipt: OperationalSecuredApplicationFactoryReceipt,
) -> str:
    """Render canonical non-cutover factory evidence without paths or values."""

    if type(receipt) is not OperationalSecuredApplicationFactoryReceipt:
        raise TypeError("operational secured application factory receipt is required")
    try:
        canonical = OperationalSecuredApplicationFactoryReceipt(
            startup_receipt_sha256=receipt.startup_receipt_sha256,
            configuration_sha256=receipt.configuration_sha256,
            startup_checked_at=receipt.startup_checked_at,
            route_bindings=receipt.route_bindings,
            protected_bindings=receipt.protected_bindings,
            public_bindings=receipt.public_bindings,
            process_configuration_validated=(
                receipt.process_configuration_validated
            ),
            application_constructed=receipt.application_constructed,
            deployment_cutover_performed=receipt.deployment_cutover_performed,
        )
    except (TypeError, ValueError):
        raise ValueError(
            "operational secured application factory receipt is invalid"
        ) from None
    if canonical != receipt:
        raise ValueError("operational secured application factory receipt is invalid")
    return json.dumps(
        {
            "scope": OPERATIONAL_SECURED_APPLICATION_FACTORY_SCOPE,
            "startup_receipt_sha256": canonical.startup_receipt_sha256,
            "configuration_sha256": canonical.configuration_sha256,
            "startup_checked_at": _canonical_timestamp(
                canonical.startup_checked_at
            ),
            "route_bindings": canonical.route_bindings,
            "protected_bindings": canonical.protected_bindings,
            "public_bindings": canonical.public_bindings,
            "process_configuration_validated": (
                canonical.process_configuration_validated
            ),
            "application_constructed": canonical.application_constructed,
            "deployment_cutover_performed": (
                canonical.deployment_cutover_performed
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


__all__ = [
    "MAXIMUM_STARTUP_PATH_CHARACTERS",
    "OPERATIONAL_SECURED_APPLICATION_FACTORY_SCOPE",
    "STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256",
    "STARTUP_AUTHENTICATION_DOCUMENT_PATH",
    "STARTUP_BOOTSTRAP_DOCUMENT_PATH",
    "STARTUP_ENVIRONMENT_KEYS",
    "STARTUP_ENVIRONMENT_PREFIX",
    "STARTUP_POSTFLIGHT_RECEIPT_PATH",
    "OperationalSecuredApplicationDeploymentFactoryError",
    "OperationalSecuredApplicationFactoryReceipt",
    "OperationalSecuredApplicationProcessConfiguration",
    "create_process_configured_secured_application",
    "load_operational_secured_application_process_configuration",
    "render_operational_secured_application_factory_receipt",
]
