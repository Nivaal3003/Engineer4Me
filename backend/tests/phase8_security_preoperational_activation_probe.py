"""Read-only Phase 8 pre-operational activation blocker inventory probe."""

from __future__ import annotations

import hashlib
from pathlib import Path

from app.main import app
from app.security.route_inventory import (
    PUBLIC_ROUTE_IDENTITIES,
    validate_application_route_inventory,
)
from app.security.security_application_cutover_manifest import (
    operational_secured_application_cutover_manifest_sha256,
    reviewed_operational_secured_application_cutover_manifest,
)
from app.security.security_application_cutover_source_plan import (
    CURRENT_DOCKERFILE_COMMAND,
    CURRENT_DOCKERFILE_SHA256,
    operational_secured_application_cutover_source_plan_sha256,
    reviewed_operational_secured_application_cutover_source_plan,
)


BACKEND_ROOT = Path(__file__).resolve().parents[1]
OUTSTANDING_OPERATIONAL_GATES = (
    "reviewed real authentication document",
    "digest-confirmed live JWKS readiness",
    "digest-confirmed real signed-token readiness",
    "provider ownership attestation",
    "approved provider-bound bootstrap document",
    "exclusive operational bootstrap commit",
    "exact read-only bootstrap postflight",
    "fresh activation readiness verification",
    "real startup environment values and read-only document mounts",
    "explicit source-transition and cutover approval",
    "backend rebuild and recreation",
    "authenticated post-cutover operational smoke",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    inventory = validate_application_route_inventory(app)
    public = {
        (identity.operation_id, identity.method, identity.path_template)
        for identity in inventory
        if (
            identity.operation_id,
            identity.method,
            identity.path_template,
        )
        in PUBLIC_ROUTE_IDENTITIES
    }
    if len(inventory) != 93 or len(public) != 2:
        raise AssertionError("reviewed application route inventory changed")
    if hasattr(app.state, "security_activation") or hasattr(
        app.state,
        "security_composition",
    ):
        raise AssertionError("pre-activation app unexpectedly became secured")
    if hasattr(app.state, "security_factory_entrypoint"):
        raise AssertionError("operational factory entrypoint was unexpectedly invoked")

    dockerfile = BACKEND_ROOT / "Dockerfile"
    if _sha256(dockerfile) != CURRENT_DOCKERFILE_SHA256:
        raise AssertionError("reviewed Dockerfile source changed")
    dockerfile_text = dockerfile.read_text(encoding="utf-8")
    if CURRENT_DOCKERFILE_COMMAND not in dockerfile_text:
        raise AssertionError("current pre-activation Dockerfile command changed")
    if "security_application_factory_entrypoint" in dockerfile_text:
        raise AssertionError("secured Dockerfile source was unexpectedly applied")

    manifest = reviewed_operational_secured_application_cutover_manifest()
    manifest_sha256 = operational_secured_application_cutover_manifest_sha256(
        manifest
    )
    if (
        manifest.deployment_cutover_performed is not False
        or manifest.unsecured_fallback_allowed is not False
        or manifest.failure_action != "remain_stopped"
    ):
        raise AssertionError("reviewed cutover manifest weakened")

    source_plan = reviewed_operational_secured_application_cutover_source_plan()
    source_plan_sha256 = (
        operational_secured_application_cutover_source_plan_sha256(source_plan)
    )
    if (
        source_plan.source_files_modified is not False
        or source_plan.deployment_cutover_performed is not False
    ):
        raise AssertionError("reviewed source transition was unexpectedly applied")

    for digest in (manifest_sha256, source_plan_sha256):
        if len(digest) != 64 or digest != digest.lower():
            raise AssertionError("pre-operational evidence digest is invalid")
        int(digest, 16)
    if len(OUTSTANDING_OPERATIONAL_GATES) != 12 or len(
        set(OUTSTANDING_OPERATIONAL_GATES)
    ) != 12:
        raise AssertionError("operational blocker inventory is incomplete")

    print("Application inventory: 93 exact bindings; 2 public and 91 planned protected")
    print("Current app.main: accepted pre-activation surface; no security composition")
    print("Current Dockerfile: exact app.main:app launch source unchanged")
    print("Cutover manifest: canonical fail-closed evidence verified")
    print("Source transition: canonical plan verified; no source file applied")
    print(
        "Operational security domain: separate read-only preflight remains "
        "authoritative"
    )
    print("Outstanding operational gates: 12 exact requirements recorded")
    print("Activation readiness: false")
    print("Deployment cutover: not performed")
    print("Operational writes: none")


if __name__ == "__main__":
    main()
