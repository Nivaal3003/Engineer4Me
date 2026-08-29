"""Tests for the immutable, non-executing secured-app cutover manifest."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from app.security.security_application_cutover_manifest import (
    CURRENT_APPLICATION_COMMAND,
    OPERATIONAL_SECURED_APPLICATION_CUTOVER_MANIFEST_SCOPE,
    REQUIRED_READ_ONLY_DOCUMENTS,
    REQUIRED_STARTUP_ENVIRONMENT_KEYS,
    TARGET_APPLICATION_COMMAND,
    OperationalSecuredApplicationCutoverManifest,
    operational_secured_application_cutover_manifest_sha256,
    render_operational_secured_application_cutover_manifest,
    reviewed_operational_secured_application_cutover_manifest,
)
from app.security.security_application_deployment_factory import (
    STARTUP_ENVIRONMENT_KEYS,
)
from app.security.security_application_factory_entrypoint import (
    create_operational_secured_application,
)


BACKEND_ROOT = Path(__file__).resolve().parents[1]


def manifest() -> OperationalSecuredApplicationCutoverManifest:
    return reviewed_operational_secured_application_cutover_manifest()


def test_manifest_is_exact_frozen_and_non_executing():
    reviewed = manifest()

    assert reviewed.current_command == CURRENT_APPLICATION_COMMAND
    assert reviewed.target_command == TARGET_APPLICATION_COMMAND
    assert reviewed.required_startup_environment_keys == (
        REQUIRED_STARTUP_ENVIRONMENT_KEYS
    )
    assert reviewed.required_read_only_documents == REQUIRED_READ_ONLY_DOCUMENTS
    assert reviewed.bootstrap_completion_required is True
    assert reviewed.postflight_verification_required is True
    assert reviewed.fresh_readiness_reverification_required is True
    assert reviewed.backend_quiescence_required is True
    assert reviewed.unsecured_fallback_allowed is False
    assert reviewed.automatic_rollback_allowed is False
    assert reviewed.failure_action == "remain_stopped"
    assert reviewed.backend_recreation_required is True
    assert reviewed.deployment_cutover_performed is False
    with pytest.raises(FrozenInstanceError):
        reviewed.deployment_cutover_performed = True


def test_target_is_exact_uvicorn_factory_protocol():
    assert TARGET_APPLICATION_COMMAND == (
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
    assert TARGET_APPLICATION_COMMAND.count("--factory") == 1
    assert "--reload" not in TARGET_APPLICATION_COMMAND
    assert callable(create_operational_secured_application)


def test_required_environment_keys_match_strict_step194_factory():
    assert REQUIRED_STARTUP_ENVIRONMENT_KEYS == STARTUP_ENVIRONMENT_KEYS
    assert len(REQUIRED_STARTUP_ENVIRONMENT_KEYS) == 4
    assert len(set(REQUIRED_STARTUP_ENVIRONMENT_KEYS)) == 4
    assert all(
        key.startswith("E4M_SECURITY_STARTUP_")
        for key in REQUIRED_STARTUP_ENVIRONMENT_KEYS
    )


def test_documents_are_roles_only_without_invented_operational_paths():
    assert REQUIRED_READ_ONLY_DOCUMENTS == (
        "authentication_readiness_document",
        "operational_bootstrap_postflight_receipt",
        "provider_bound_bootstrap_document",
    )
    rendered = render_operational_secured_application_cutover_manifest(
        manifest()
    )
    assert "/run/" not in rendered
    assert "C:\\" not in rendered
    assert "sha256_value" not in rendered


def test_current_dockerfile_command_matches_manifest_exactly():
    dockerfile = (BACKEND_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert (
        'CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", '
        '"--port", "8000"]'
    ) in dockerfile
    assert CURRENT_APPLICATION_COMMAND == (
        "uvicorn",
        "app.main:app",
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
    )
    assert TARGET_APPLICATION_COMMAND[1] not in dockerfile
    assert '"--factory"' not in dockerfile


def test_manifest_records_a_future_transition_without_source_mutation():
    reviewed = manifest()

    assert reviewed.current_command != reviewed.target_command
    assert reviewed.current_command[1] == "app.main:app"
    assert reviewed.target_command[1].endswith(
        ":create_operational_secured_application"
    )
    assert reviewed.backend_recreation_required is True
    assert reviewed.deployment_cutover_performed is False


def test_manifest_renderer_is_canonical_and_digest_is_exact():
    reviewed = manifest()
    rendered = render_operational_secured_application_cutover_manifest(
        reviewed
    )
    value = json.loads(rendered)

    assert rendered == json.dumps(value, sort_keys=True, separators=(",", ":"))
    assert value["scope"] == (
        OPERATIONAL_SECURED_APPLICATION_CUTOVER_MANIFEST_SCOPE
    )
    assert value["target_command"] == list(TARGET_APPLICATION_COMMAND)
    assert value["deployment_cutover_performed"] is False
    assert value["unsecured_fallback_allowed"] is False
    assert value["failure_action"] == "remain_stopped"
    assert operational_secured_application_cutover_manifest_sha256(
        reviewed
    ) == hashlib.sha256(rendered.encode("utf-8")).hexdigest()


@pytest.mark.parametrize(
    "changes",
    [
        {"current_command": ("uvicorn", "other:app")},
        {"target_command": CURRENT_APPLICATION_COMMAND},
        {"required_startup_environment_keys": ()},
        {"required_read_only_documents": ()},
        {"bootstrap_completion_required": False},
        {"postflight_verification_required": False},
        {"fresh_readiness_reverification_required": False},
        {"backend_quiescence_required": False},
        {"unsecured_fallback_allowed": True},
        {"automatic_rollback_allowed": True},
        {"failure_action": "restart_unsecured"},
        {"backend_recreation_required": False},
        {"deployment_cutover_performed": True},
    ],
)
def test_manifest_rejects_every_weakened_or_changed_boundary(changes):
    with pytest.raises(ValueError, match="manifest is invalid"):
        replace(manifest(), **changes)


def test_manifest_renderer_rejects_wrong_type():
    with pytest.raises(TypeError, match="manifest is required"):
        render_operational_secured_application_cutover_manifest(object())


def test_manifest_construction_has_no_file_or_runtime_io(monkeypatch):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected cutover-manifest I/O")

    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr("os.getenv", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)

    reviewed = reviewed_operational_secured_application_cutover_manifest()
    rendered = render_operational_secured_application_cutover_manifest(
        reviewed
    )

    assert reviewed.deployment_cutover_performed is False
    assert json.loads(rendered)["failure_action"] == "remain_stopped"
