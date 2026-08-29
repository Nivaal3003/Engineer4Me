"""Tests for the non-applying secured deployment source-transition plan."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from pathlib import PurePosixPath

import pytest

from app.security.security_application_cutover_manifest import (
    CURRENT_APPLICATION_COMMAND,
    REQUIRED_STARTUP_ENVIRONMENT_KEYS,
    TARGET_APPLICATION_COMMAND,
)
from app.security.security_application_cutover_source_plan import (
    AUTHENTICATION_DOCUMENT_CONTAINER_PATH,
    BOOTSTRAP_DOCUMENT_CONTAINER_PATH,
    COMPOSE_READ_ONLY_MOUNTS,
    COMPOSE_STARTUP_ENVIRONMENT,
    CURRENT_COMPOSE_SHA256,
    CURRENT_DOCKERFILE_COMMAND,
    CURRENT_DOCKERFILE_SHA256,
    HOST_DOCUMENT_PATH_KEYS,
    OPERATIONAL_SECURED_APPLICATION_CUTOVER_SOURCE_PLAN_SCOPE,
    POSTFLIGHT_RECEIPT_CONTAINER_PATH,
    TARGET_DOCKERFILE_COMMAND,
    OperationalSecuredApplicationCutoverSourcePlan,
    operational_secured_application_cutover_source_plan_sha256,
    render_operational_secured_application_cutover_source_plan,
    reviewed_operational_secured_application_cutover_source_plan,
)


def plan() -> OperationalSecuredApplicationCutoverSourcePlan:
    return reviewed_operational_secured_application_cutover_source_plan()


def test_plan_is_exact_frozen_and_non_applying():
    reviewed = plan()

    assert reviewed.current_dockerfile_sha256 == CURRENT_DOCKERFILE_SHA256
    assert reviewed.current_compose_sha256 == CURRENT_COMPOSE_SHA256
    assert reviewed.current_application_command == CURRENT_APPLICATION_COMMAND
    assert reviewed.target_application_command == TARGET_APPLICATION_COMMAND
    assert reviewed.dockerfile_change_required is True
    assert reviewed.compose_change_required is True
    assert reviewed.source_files_modified is False
    assert reviewed.deployment_cutover_performed is False
    with pytest.raises(FrozenInstanceError):
        reviewed.source_files_modified = True


def test_dockerfile_command_replacement_is_exact():
    assert CURRENT_DOCKERFILE_COMMAND == (
        'CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", '
        '"--port", "8000"]'
    )
    assert "app.main:app" in CURRENT_DOCKERFILE_COMMAND
    assert "app.main:app" not in TARGET_DOCKERFILE_COMMAND
    assert TARGET_APPLICATION_COMMAND[1] in TARGET_DOCKERFILE_COMMAND
    assert TARGET_DOCKERFILE_COMMAND.count('"--factory"') == 1
    assert "--reload" not in TARGET_DOCKERFILE_COMMAND


def test_container_document_paths_are_exact_distinct_and_bounded():
    paths = (
        AUTHENTICATION_DOCUMENT_CONTAINER_PATH,
        POSTFLIGHT_RECEIPT_CONTAINER_PATH,
        BOOTSTRAP_DOCUMENT_CONTAINER_PATH,
    )
    assert len(set(paths)) == 3
    for value in paths:
        path = PurePosixPath(value)
        assert path.is_absolute()
        assert path.parts[:4] == ("/", "run", "engineer4me", "security")
        assert ".." not in path.parts
        assert len(value) <= 128


def test_host_document_keys_are_not_exposed_as_startup_configuration():
    assert len(HOST_DOCUMENT_PATH_KEYS) == 3
    assert len(set(HOST_DOCUMENT_PATH_KEYS)) == 3
    assert all(key.startswith("E4M_DEPLOY_") for key in HOST_DOCUMENT_PATH_KEYS)
    assert all(
        not key.startswith("E4M_SECURITY_STARTUP_")
        for key in HOST_DOCUMENT_PATH_KEYS
    )
    assert set(HOST_DOCUMENT_PATH_KEYS).isdisjoint(
        REQUIRED_STARTUP_ENVIRONMENT_KEYS
    )


def test_compose_startup_environment_is_exact_and_value_safe():
    assert tuple(key for key, _ in COMPOSE_STARTUP_ENVIRONMENT) == (
        REQUIRED_STARTUP_ENVIRONMENT_KEYS
    )
    assert len(COMPOSE_STARTUP_ENVIRONMENT) == 4
    assert COMPOSE_STARTUP_ENVIRONMENT[-1] == (
        "E4M_SECURITY_STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256",
        "${E4M_SECURITY_STARTUP_APPROVED_POSTFLIGHT_RECEIPT_SHA256:?required}",
    )
    serialized = json.dumps(COMPOSE_STARTUP_ENVIRONMENT)
    assert "client_secret" not in serialized
    assert "private_key" not in serialized
    assert "access_token" not in serialized


def test_compose_mounts_are_exact_read_only_and_correlated():
    assert len(COMPOSE_READ_ONLY_MOUNTS) == 3
    assert len(set(COMPOSE_READ_ONLY_MOUNTS)) == 3
    container_paths = (
        AUTHENTICATION_DOCUMENT_CONTAINER_PATH,
        POSTFLIGHT_RECEIPT_CONTAINER_PATH,
        BOOTSTRAP_DOCUMENT_CONTAINER_PATH,
    )
    for host_key, container_path, mount in zip(
        HOST_DOCUMENT_PATH_KEYS,
        container_paths,
        COMPOSE_READ_ONLY_MOUNTS,
        strict=True,
    ):
        assert mount == (
            f"${{{host_key}:?required}}:{container_path}:ro"
        )
        assert mount.endswith(":ro")


def test_reviewed_current_source_hashes_are_exact_lowercase_sha256():
    assert CURRENT_DOCKERFILE_SHA256 == (
        "372a69eefc4266819838c6ef7ca8d9092cda1ca05f26a0dd5bf40a378274322c"
    )
    assert CURRENT_COMPOSE_SHA256 == (
        "85ddf0410812d0cae36ce251c6f0f16d5990ed5ab66fcbad93e218fdcaa5916c"
    )
    for value in (CURRENT_DOCKERFILE_SHA256, CURRENT_COMPOSE_SHA256):
        assert len(value) == 64
        assert value == value.lower()
        int(value, 16)


def test_plan_renderer_is_canonical_and_digest_is_exact():
    reviewed = plan()
    rendered = render_operational_secured_application_cutover_source_plan(
        reviewed
    )
    value = json.loads(rendered)

    assert rendered == json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert value["scope"] == (
        OPERATIONAL_SECURED_APPLICATION_CUTOVER_SOURCE_PLAN_SCOPE
    )
    assert value["source_files_modified"] is False
    assert value["deployment_cutover_performed"] is False
    assert operational_secured_application_cutover_source_plan_sha256(
        reviewed
    ) == hashlib.sha256(rendered.encode("utf-8")).hexdigest()


@pytest.mark.parametrize(
    "changes",
    [
        {"current_dockerfile_sha256": "0" * 64},
        {"current_compose_sha256": "0" * 64},
        {"current_dockerfile_command": "other"},
        {"target_dockerfile_command": "other"},
        {"current_application_command": ()},
        {"target_application_command": ()},
        {"required_startup_environment_keys": ()},
        {"host_document_path_keys": ()},
        {"compose_startup_environment": ()},
        {"compose_read_only_mounts": ()},
        {"dockerfile_change_required": False},
        {"compose_change_required": False},
        {"source_files_modified": True},
        {"deployment_cutover_performed": True},
    ],
)
def test_plan_rejects_every_changed_or_weakened_boundary(changes):
    with pytest.raises(ValueError, match="source plan is invalid"):
        replace(plan(), **changes)


def test_renderer_rejects_wrong_type():
    with pytest.raises(TypeError, match="source plan is required"):
        render_operational_secured_application_cutover_source_plan(object())


def test_plan_construction_and_rendering_perform_no_io(monkeypatch):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected source-plan I/O")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr("os.getenv", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)

    reviewed = reviewed_operational_secured_application_cutover_source_plan()
    rendered = render_operational_secured_application_cutover_source_plan(
        reviewed
    )

    assert reviewed.source_files_modified is False
    assert json.loads(rendered)["deployment_cutover_performed"] is False
