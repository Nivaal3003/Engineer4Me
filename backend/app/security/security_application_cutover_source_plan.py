"""Immutable source-transition plan for a future secured deployment cutover."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from app.security.security_application_cutover_manifest import (
    CURRENT_APPLICATION_COMMAND,
    REQUIRED_STARTUP_ENVIRONMENT_KEYS,
    TARGET_APPLICATION_COMMAND,
)


OPERATIONAL_SECURED_APPLICATION_CUTOVER_SOURCE_PLAN_SCOPE = (
    "secured_application_deployment_source_transition_plan"
)
CURRENT_DOCKERFILE_SHA256 = (
    "372a69eefc4266819838c6ef7ca8d9092cda1ca05f26a0dd5bf40a378274322c"
)
CURRENT_COMPOSE_SHA256 = (
    "85ddf0410812d0cae36ce251c6f0f16d5990ed5ab66fcbad93e218fdcaa5916c"
)
CURRENT_DOCKERFILE_COMMAND = (
    'CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", '
    '"--port", "8000"]'
)
TARGET_DOCKERFILE_COMMAND = (
    'CMD ["uvicorn", '
    '"app.security.security_application_factory_entrypoint:'
    'create_operational_secured_application", "--factory", "--host", '
    '"0.0.0.0", "--port", "8000"]'
)
AUTHENTICATION_DOCUMENT_CONTAINER_PATH = (
    "/run/engineer4me/security/authentication-readiness.json"
)
POSTFLIGHT_RECEIPT_CONTAINER_PATH = (
    "/run/engineer4me/security/bootstrap-postflight-receipt.json"
)
BOOTSTRAP_DOCUMENT_CONTAINER_PATH = (
    "/run/engineer4me/security/bootstrap-document.json"
)
HOST_DOCUMENT_PATH_KEYS = (
    "E4M_DEPLOY_AUTHENTICATION_DOCUMENT_HOST_PATH",
    "E4M_DEPLOY_POSTFLIGHT_RECEIPT_HOST_PATH",
    "E4M_DEPLOY_BOOTSTRAP_DOCUMENT_HOST_PATH",
)
COMPOSE_STARTUP_ENVIRONMENT = (
    (
        "E4M_SECURITY_STARTUP_AUTHENTICATION_DOCUMENT_PATH",
        AUTHENTICATION_DOCUMENT_CONTAINER_PATH,
    ),
    (
        "E4M_SECURITY_STARTUP_POSTFLIGHT_RECEIPT_PATH",
        POSTFLIGHT_RECEIPT_CONTAINER_PATH,
    ),
    (
        "E4M_SECURITY_STARTUP_BOOTSTRAP_DOCUMENT_PATH",
        BOOTSTRAP_DOCUMENT_CONTAINER_PATH,
    ),
    (
        "E4M_SECURITY_STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256",
        "${E4M_SECURITY_STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256:?required}",
    ),
)
COMPOSE_READ_ONLY_MOUNTS = (
    (
        "${E4M_DEPLOY_AUTHENTICATION_DOCUMENT_HOST_PATH:?required}:"
        f"{AUTHENTICATION_DOCUMENT_CONTAINER_PATH}:ro"
    ),
    (
        "${E4M_DEPLOY_POSTFLIGHT_RECEIPT_HOST_PATH:?required}:"
        f"{POSTFLIGHT_RECEIPT_CONTAINER_PATH}:ro"
    ),
    (
        "${E4M_DEPLOY_BOOTSTRAP_DOCUMENT_HOST_PATH:?required}:"
        f"{BOOTSTRAP_DOCUMENT_CONTAINER_PATH}:ro"
    ),
)


@dataclass(frozen=True, slots=True)
class OperationalSecuredApplicationCutoverSourcePlan:
    """Exact source edits proposed for later approval and application."""

    current_dockerfile_sha256: str = CURRENT_DOCKERFILE_SHA256
    current_compose_sha256: str = CURRENT_COMPOSE_SHA256
    current_dockerfile_command: str = CURRENT_DOCKERFILE_COMMAND
    target_dockerfile_command: str = TARGET_DOCKERFILE_COMMAND
    current_application_command: tuple[str, ...] = CURRENT_APPLICATION_COMMAND
    target_application_command: tuple[str, ...] = TARGET_APPLICATION_COMMAND
    required_startup_environment_keys: tuple[
        str, ...
    ] = REQUIRED_STARTUP_ENVIRONMENT_KEYS
    host_document_path_keys: tuple[str, ...] = HOST_DOCUMENT_PATH_KEYS
    compose_startup_environment: tuple[
        tuple[str, str], ...
    ] = COMPOSE_STARTUP_ENVIRONMENT
    compose_read_only_mounts: tuple[str, ...] = COMPOSE_READ_ONLY_MOUNTS
    dockerfile_change_required: bool = True
    compose_change_required: bool = True
    source_files_modified: bool = False
    deployment_cutover_performed: bool = False

    def __post_init__(self) -> None:
        if (
            self.current_dockerfile_sha256 != CURRENT_DOCKERFILE_SHA256
            or self.current_compose_sha256 != CURRENT_COMPOSE_SHA256
            or self.current_dockerfile_command != CURRENT_DOCKERFILE_COMMAND
            or self.target_dockerfile_command != TARGET_DOCKERFILE_COMMAND
            or type(self.current_application_command) is not tuple
            or self.current_application_command != CURRENT_APPLICATION_COMMAND
            or type(self.target_application_command) is not tuple
            or self.target_application_command != TARGET_APPLICATION_COMMAND
            or type(self.required_startup_environment_keys) is not tuple
            or self.required_startup_environment_keys
            != REQUIRED_STARTUP_ENVIRONMENT_KEYS
            or type(self.host_document_path_keys) is not tuple
            or self.host_document_path_keys != HOST_DOCUMENT_PATH_KEYS
            or type(self.compose_startup_environment) is not tuple
            or self.compose_startup_environment != COMPOSE_STARTUP_ENVIRONMENT
            or type(self.compose_read_only_mounts) is not tuple
            or self.compose_read_only_mounts != COMPOSE_READ_ONLY_MOUNTS
            or self.dockerfile_change_required is not True
            or self.compose_change_required is not True
            or self.source_files_modified is not False
            or self.deployment_cutover_performed is not False
        ):
            raise ValueError(
                "operational secured application cutover source plan is invalid"
            )


def reviewed_operational_secured_application_cutover_source_plan(
) -> OperationalSecuredApplicationCutoverSourcePlan:
    """Return the sole reviewed, non-applying source-transition plan."""

    return OperationalSecuredApplicationCutoverSourcePlan()


def render_operational_secured_application_cutover_source_plan(
    plan: OperationalSecuredApplicationCutoverSourcePlan,
) -> str:
    """Render canonical source-transition evidence without real path values."""

    if type(plan) is not OperationalSecuredApplicationCutoverSourcePlan:
        raise TypeError(
            "operational secured application cutover source plan is required"
        )
    try:
        canonical = OperationalSecuredApplicationCutoverSourcePlan(
            current_dockerfile_sha256=plan.current_dockerfile_sha256,
            current_compose_sha256=plan.current_compose_sha256,
            current_dockerfile_command=plan.current_dockerfile_command,
            target_dockerfile_command=plan.target_dockerfile_command,
            current_application_command=plan.current_application_command,
            target_application_command=plan.target_application_command,
            required_startup_environment_keys=(
                plan.required_startup_environment_keys
            ),
            host_document_path_keys=plan.host_document_path_keys,
            compose_startup_environment=plan.compose_startup_environment,
            compose_read_only_mounts=plan.compose_read_only_mounts,
            dockerfile_change_required=plan.dockerfile_change_required,
            compose_change_required=plan.compose_change_required,
            source_files_modified=plan.source_files_modified,
            deployment_cutover_performed=plan.deployment_cutover_performed,
        )
    except (TypeError, ValueError):
        raise ValueError(
            "operational secured application cutover source plan is invalid"
        ) from None
    if canonical != plan:
        raise ValueError(
            "operational secured application cutover source plan is invalid"
        )
    return json.dumps(
        {
            "scope": OPERATIONAL_SECURED_APPLICATION_CUTOVER_SOURCE_PLAN_SCOPE,
            "current_dockerfile_sha256": canonical.current_dockerfile_sha256,
            "current_compose_sha256": canonical.current_compose_sha256,
            "current_dockerfile_command": canonical.current_dockerfile_command,
            "target_dockerfile_command": canonical.target_dockerfile_command,
            "current_application_command": list(
                canonical.current_application_command
            ),
            "target_application_command": list(
                canonical.target_application_command
            ),
            "required_startup_environment_keys": list(
                canonical.required_startup_environment_keys
            ),
            "host_document_path_keys": list(canonical.host_document_path_keys),
            "compose_startup_environment": [
                list(value) for value in canonical.compose_startup_environment
            ],
            "compose_read_only_mounts": list(
                canonical.compose_read_only_mounts
            ),
            "dockerfile_change_required": canonical.dockerfile_change_required,
            "compose_change_required": canonical.compose_change_required,
            "source_files_modified": canonical.source_files_modified,
            "deployment_cutover_performed": (
                canonical.deployment_cutover_performed
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def operational_secured_application_cutover_source_plan_sha256(
    plan: OperationalSecuredApplicationCutoverSourcePlan,
) -> str:
    """Hash the exact canonical source-transition proposal."""

    rendered = render_operational_secured_application_cutover_source_plan(
        plan
    ).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


__all__ = [
    "AUTHENTICATION_DOCUMENT_CONTAINER_PATH",
    "BOOTSTRAP_DOCUMENT_CONTAINER_PATH",
    "COMPOSE_READ_ONLY_MOUNTS",
    "COMPOSE_STARTUP_ENVIRONMENT",
    "CURRENT_COMPOSE_SHA256",
    "CURRENT_DOCKERFILE_COMMAND",
    "CURRENT_DOCKERFILE_SHA256",
    "HOST_DOCUMENT_PATH_KEYS",
    "OPERATIONAL_SECURED_APPLICATION_CUTOVER_SOURCE_PLAN_SCOPE",
    "POSTFLIGHT_RECEIPT_CONTAINER_PATH",
    "TARGET_DOCKERFILE_COMMAND",
    "OperationalSecuredApplicationCutoverSourcePlan",
    "operational_secured_application_cutover_source_plan_sha256",
    "render_operational_secured_application_cutover_source_plan",
    "reviewed_operational_secured_application_cutover_source_plan",
]
