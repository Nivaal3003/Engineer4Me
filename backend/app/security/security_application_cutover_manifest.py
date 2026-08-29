"""Immutable, non-executing manifest for a future secured-app cutover."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


OPERATIONAL_SECURED_APPLICATION_CUTOVER_MANIFEST_SCOPE = (
    "secured_application_deployment_cutover_manifest"
)
CURRENT_APPLICATION_COMMAND = (
    "uvicorn",
    "app.main:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8000",
)
TARGET_APPLICATION_COMMAND = (
    "uvicorn",
    (
        "app.security.security_application_factory_entrypoint:"
        "create_operational_secured_application"
    ),
    "--factory",
    "--host",
    "0.0.0.0",
    "--port",
    "8000",
)
REQUIRED_STARTUP_ENVIRONMENT_KEYS = (
    "E4M_SECURITY_STARTUP_AUTHENTICATION_DOCUMENT_PATH",
    "E4M_SECURITY_STARTUP_POSTFLIGHT_RECEIPT_PATH",
    "E4M_SECURITY_STARTUP_BOOTSTRAP_DOCUMENT_PATH",
    "E4M_SECURITY_STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256",
)
REQUIRED_READ_ONLY_DOCUMENTS = (
    "authentication_readiness_document",
    "operational_bootstrap_postflight_receipt",
    "provider_bound_bootstrap_document",
)


@dataclass(frozen=True, slots=True)
class OperationalSecuredApplicationCutoverManifest:
    """Exact future launch transition with fail-closed operational controls."""

    current_command: tuple[str, ...] = CURRENT_APPLICATION_COMMAND
    target_command: tuple[str, ...] = TARGET_APPLICATION_COMMAND
    required_startup_environment_keys: tuple[
        str, ...
    ] = REQUIRED_STARTUP_ENVIRONMENT_KEYS
    required_read_only_documents: tuple[str, ...] = REQUIRED_READ_ONLY_DOCUMENTS
    bootstrap_completion_required: bool = True
    postflight_verification_required: bool = True
    fresh_readiness_reverification_required: bool = True
    backend_quiescence_required: bool = True
    unsecured_fallback_allowed: bool = False
    automatic_rollback_allowed: bool = False
    failure_action: str = "remain_stopped"
    backend_recreation_required: bool = True
    deployment_cutover_performed: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.current_command) is not tuple
            or self.current_command != CURRENT_APPLICATION_COMMAND
            or type(self.target_command) is not tuple
            or self.target_command != TARGET_APPLICATION_COMMAND
            or type(self.required_startup_environment_keys) is not tuple
            or self.required_startup_environment_keys
            != REQUIRED_STARTUP_ENVIRONMENT_KEYS
            or type(self.required_read_only_documents) is not tuple
            or self.required_read_only_documents != REQUIRED_READ_ONLY_DOCUMENTS
            or self.bootstrap_completion_required is not True
            or self.postflight_verification_required is not True
            or self.fresh_readiness_reverification_required is not True
            or self.backend_quiescence_required is not True
            or self.unsecured_fallback_allowed is not False
            or self.automatic_rollback_allowed is not False
            or self.failure_action != "remain_stopped"
            or self.backend_recreation_required is not True
            or self.deployment_cutover_performed is not False
        ):
            raise ValueError(
                "operational secured application cutover manifest is invalid"
            )


def reviewed_operational_secured_application_cutover_manifest(
) -> OperationalSecuredApplicationCutoverManifest:
    """Return the sole reviewed, non-executing deployment transition."""

    return OperationalSecuredApplicationCutoverManifest()


def render_operational_secured_application_cutover_manifest(
    manifest: OperationalSecuredApplicationCutoverManifest,
) -> str:
    """Render the canonical manifest without any real path or digest value."""

    if type(manifest) is not OperationalSecuredApplicationCutoverManifest:
        raise TypeError(
            "operational secured application cutover manifest is required"
        )
    try:
        canonical = OperationalSecuredApplicationCutoverManifest(
            current_command=manifest.current_command,
            target_command=manifest.target_command,
            required_startup_environment_keys=(
                manifest.required_startup_environment_keys
            ),
            required_read_only_documents=manifest.required_read_only_documents,
            bootstrap_completion_required=(
                manifest.bootstrap_completion_required
            ),
            postflight_verification_required=(
                manifest.postflight_verification_required
            ),
            fresh_readiness_reverification_required=(
                manifest.fresh_readiness_reverification_required
            ),
            backend_quiescence_required=manifest.backend_quiescence_required,
            unsecured_fallback_allowed=manifest.unsecured_fallback_allowed,
            automatic_rollback_allowed=manifest.automatic_rollback_allowed,
            failure_action=manifest.failure_action,
            backend_recreation_required=manifest.backend_recreation_required,
            deployment_cutover_performed=manifest.deployment_cutover_performed,
        )
    except (TypeError, ValueError):
        raise ValueError(
            "operational secured application cutover manifest is invalid"
        ) from None
    if canonical != manifest:
        raise ValueError(
            "operational secured application cutover manifest is invalid"
        )
    return json.dumps(
        {
            "scope": OPERATIONAL_SECURED_APPLICATION_CUTOVER_MANIFEST_SCOPE,
            "current_command": list(canonical.current_command),
            "target_command": list(canonical.target_command),
            "required_startup_environment_keys": list(
                canonical.required_startup_environment_keys
            ),
            "required_read_only_documents": list(
                canonical.required_read_only_documents
            ),
            "bootstrap_completion_required": (
                canonical.bootstrap_completion_required
            ),
            "postflight_verification_required": (
                canonical.postflight_verification_required
            ),
            "fresh_readiness_reverification_required": (
                canonical.fresh_readiness_reverification_required
            ),
            "backend_quiescence_required": (
                canonical.backend_quiescence_required
            ),
            "unsecured_fallback_allowed": canonical.unsecured_fallback_allowed,
            "automatic_rollback_allowed": canonical.automatic_rollback_allowed,
            "failure_action": canonical.failure_action,
            "backend_recreation_required": canonical.backend_recreation_required,
            "deployment_cutover_performed": (
                canonical.deployment_cutover_performed
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def operational_secured_application_cutover_manifest_sha256(
    manifest: OperationalSecuredApplicationCutoverManifest,
) -> str:
    """Hash the exact canonical future transition for later approval."""

    rendered = render_operational_secured_application_cutover_manifest(
        manifest
    ).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


__all__ = [
    "CURRENT_APPLICATION_COMMAND",
    "OPERATIONAL_SECURED_APPLICATION_CUTOVER_MANIFEST_SCOPE",
    "REQUIRED_READ_ONLY_DOCUMENTS",
    "REQUIRED_STARTUP_ENVIRONMENT_KEYS",
    "TARGET_APPLICATION_COMMAND",
    "OperationalSecuredApplicationCutoverManifest",
    "operational_secured_application_cutover_manifest_sha256",
    "render_operational_secured_application_cutover_manifest",
    "reviewed_operational_secured_application_cutover_manifest",
]
