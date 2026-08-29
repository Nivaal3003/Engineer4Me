"""Import-inert ASGI factory entrypoint for the reviewed secured application."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import FastAPI


OPERATIONAL_SECURED_APPLICATION_ENTRYPOINT_SCOPE = (
    "secured_application_factory_entrypoint"
)
SHA256_PATTERN_TEXT = r"^[0-9a-f]{64}$"


class OperationalSecuredApplicationEntrypointError(RuntimeError):
    """Sanitized startup rejection before an ASGI server receives an app."""


@dataclass(frozen=True, slots=True)
class OperationalSecuredApplicationEntrypointReceipt:
    """Point-in-time evidence returned before any server begins serving."""

    factory_receipt_sha256: str
    configuration_sha256: str
    startup_checked_at: datetime
    route_bindings: int
    protected_bindings: int
    public_bindings: int
    entrypoint_factory_completed: bool = True
    serving_started: bool = False
    deployment_cutover_performed: bool = False

    def __post_init__(self) -> None:
        import re

        if (
            type(self.factory_receipt_sha256) is not str
            or re.fullmatch(
                SHA256_PATTERN_TEXT,
                self.factory_receipt_sha256,
            )
            is None
            or type(self.configuration_sha256) is not str
            or re.fullmatch(
                SHA256_PATTERN_TEXT,
                self.configuration_sha256,
            )
            is None
            or not isinstance(self.startup_checked_at, datetime)
            or self.startup_checked_at.tzinfo is None
            or self.startup_checked_at.utcoffset() is None
            or self.route_bindings != 93
            or self.protected_bindings != 91
            or self.public_bindings != 2
            or self.entrypoint_factory_completed is not True
            or self.serving_started is not False
            or self.deployment_cutover_performed is not False
        ):
            raise ValueError(
                "operational secured application entrypoint receipt is invalid"
            )


def _entrypoint_receipt(source) -> OperationalSecuredApplicationEntrypointReceipt:
    from app.security.security_application_deployment_factory import (
        OperationalSecuredApplicationFactoryReceipt,
        render_operational_secured_application_factory_receipt,
    )

    if type(source) is not OperationalSecuredApplicationFactoryReceipt:
        raise OperationalSecuredApplicationEntrypointError(
            "operational secured application factory evidence is invalid"
        )
    try:
        rendered = render_operational_secured_application_factory_receipt(
            source
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise OperationalSecuredApplicationEntrypointError(
            "operational secured application factory evidence is invalid"
        ) from None
    return OperationalSecuredApplicationEntrypointReceipt(
        factory_receipt_sha256=hashlib.sha256(rendered).hexdigest(),
        configuration_sha256=source.configuration_sha256,
        startup_checked_at=source.startup_checked_at.astimezone(UTC),
        route_bindings=source.route_bindings,
        protected_bindings=source.protected_bindings,
        public_bindings=source.public_bindings,
    )


def create_operational_secured_application(
    *,
    application_factory: Callable[[], FastAPI] | None = None,
) -> FastAPI:
    """Construct one app for an explicit ASGI factory call; never serve it."""

    try:
        if application_factory is None:
            from app.security.security_application_deployment_factory import (
                create_process_configured_secured_application,
            )

            selected_factory = create_process_configured_secured_application
        else:
            selected_factory = application_factory
        if not callable(selected_factory):
            raise TypeError("secured application factory must be callable")
        application = selected_factory()
        if not isinstance(application, FastAPI):
            raise TypeError("secured application factory result is invalid")
        receipt = _entrypoint_receipt(
            application.state.security_deployment_factory
        )
    except OperationalSecuredApplicationEntrypointError:
        raise
    except Exception:
        raise OperationalSecuredApplicationEntrypointError(
            "operational secured application entrypoint startup failed"
        ) from None
    application.state.security_factory_entrypoint = receipt
    return application


def _canonical_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def render_operational_secured_application_entrypoint_receipt(
    receipt: OperationalSecuredApplicationEntrypointReceipt,
) -> str:
    """Render canonical point-in-time evidence without paths or raw values."""

    if type(receipt) is not OperationalSecuredApplicationEntrypointReceipt:
        raise TypeError(
            "operational secured application entrypoint receipt is required"
        )
    try:
        canonical = OperationalSecuredApplicationEntrypointReceipt(
            factory_receipt_sha256=receipt.factory_receipt_sha256,
            configuration_sha256=receipt.configuration_sha256,
            startup_checked_at=receipt.startup_checked_at,
            route_bindings=receipt.route_bindings,
            protected_bindings=receipt.protected_bindings,
            public_bindings=receipt.public_bindings,
            entrypoint_factory_completed=receipt.entrypoint_factory_completed,
            serving_started=receipt.serving_started,
            deployment_cutover_performed=receipt.deployment_cutover_performed,
        )
    except (TypeError, ValueError):
        raise ValueError(
            "operational secured application entrypoint receipt is invalid"
        ) from None
    if canonical != receipt:
        raise ValueError(
            "operational secured application entrypoint receipt is invalid"
        )
    return json.dumps(
        {
            "scope": OPERATIONAL_SECURED_APPLICATION_ENTRYPOINT_SCOPE,
            "factory_receipt_sha256": canonical.factory_receipt_sha256,
            "configuration_sha256": canonical.configuration_sha256,
            "startup_checked_at": _canonical_timestamp(
                canonical.startup_checked_at
            ),
            "route_bindings": canonical.route_bindings,
            "protected_bindings": canonical.protected_bindings,
            "public_bindings": canonical.public_bindings,
            "entrypoint_factory_completed": (
                canonical.entrypoint_factory_completed
            ),
            "serving_started": canonical.serving_started,
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
    "OPERATIONAL_SECURED_APPLICATION_ENTRYPOINT_SCOPE",
    "OperationalSecuredApplicationEntrypointError",
    "OperationalSecuredApplicationEntrypointReceipt",
    "create_operational_secured_application",
    "render_operational_secured_application_entrypoint_receipt",
]
