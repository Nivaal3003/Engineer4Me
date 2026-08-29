"""Focused tests for provider-bound security bootstrap readiness."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from app.security.authentication_bootstrap_readiness import (
    AUTHENTICATION_BOOTSTRAP_READINESS_SCOPE,
    AuthenticationBootstrapReadinessError,
    bind_authentication_bootstrap_readiness,
    render_authentication_bootstrap_readiness_receipt,
)
from app.security.authentication_token_readiness import (
    AuthenticationTokenReadinessReceipt,
    authentication_identity_sha256,
)
from app.security.entitlements import ControlledFeature, QuotaKind, SubscriptionStatus
from app.security.identity_models import OrganisationRole
from app.security.token_verifier import REQUIRED_CLAIMS


ISSUER = "https://identity.engineer4me.test/tenant"
SUBJECT = "private-provider-owner-subject-step175"
EMAIL = "private-owner@example.com"
DISPLAY_NAME = "Private Initial Owner"
SOURCE_REFERENCE = "private approved commercial source step175"
NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)
BACKEND_ROOT = Path(__file__).resolve().parents[1]
IDS = {
    "bootstrap_id": UUID("17500000-0000-4000-8000-000000000001"),
    "request_id": UUID("17500000-0000-4000-8000-000000000002"),
    "user_id": UUID("17500000-0000-4000-8000-000000000003"),
    "organisation_id": UUID("17500000-0000-4000-8000-000000000004"),
    "membership_id": UUID("17500000-0000-4000-8000-000000000005"),
    "snapshot_id": UUID("17500000-0000-4000-8000-000000000006"),
}


def bootstrap_values(*, issuer: str = ISSUER, subject: str = SUBJECT) -> dict:
    return {
        "bootstrap_id": str(IDS["bootstrap_id"]),
        "request_id": str(IDS["request_id"]),
        "user_id": str(IDS["user_id"]),
        "organisation_id": str(IDS["organisation_id"]),
        "membership_id": str(IDS["membership_id"]),
        "email": EMAIL,
        "display_name": DISPLAY_NAME,
        "issuer": issuer,
        "subject": subject,
        "organisation_slug": "reviewed-organisation-step175",
        "organisation_name": "Reviewed Organisation Step 175",
        "initial_role": "owner",
        "activated_at": NOW.isoformat(),
        "entitlement": {
            "snapshot_id": str(IDS["snapshot_id"]),
            "organisation_id": str(IDS["organisation_id"]),
            "plan_id": "reviewed-plan-step175",
            "subscription_status": "trial",
            "features": ["engineering_calculations", "document_ingestion"],
            "quotas": [
                {"kind": "monthly_calculation_runs", "limit": 100},
                {"kind": "monthly_document_ingestions", "limit": 25},
            ],
            "effective_at": (NOW - timedelta(minutes=1)).isoformat(),
            "expires_at": (NOW + timedelta(days=30)).isoformat(),
            "source_reference": SOURCE_REFERENCE,
        },
    }


def bootstrap_document(*, issuer: str = ISSUER, subject: str = SUBJECT) -> bytes:
    return json.dumps(
        bootstrap_values(issuer=issuer, subject=subject),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def token_readiness(
    *, issuer: str = ISSUER, subject: str = SUBJECT
) -> AuthenticationTokenReadinessReceipt:
    return AuthenticationTokenReadinessReceipt(
        configuration_sha256="1" * 64,
        jwks_document_sha256="2" * 64,
        checked_at=NOW,
        token_algorithm="RS256",
        issuer_sha256=authentication_identity_sha256(issuer),
        audience_sha256=authentication_identity_sha256("engineer4me-api"),
        subject_sha256=authentication_identity_sha256(issuer, subject),
        required_claims=REQUIRED_CLAIMS,
    )


def test_exact_signed_token_identity_binds_to_complete_bootstrap_contract():
    receipt = bind_authentication_bootstrap_readiness(
        token_readiness=token_readiness(),
        bootstrap_document=bootstrap_document(),
    )

    assert receipt.configuration_sha256 == "1" * 64
    assert receipt.jwks_document_sha256 == "2" * 64
    assert receipt.bootstrap_id == IDS["bootstrap_id"]
    assert receipt.request_id == IDS["request_id"]
    assert receipt.user_id == IDS["user_id"]
    assert receipt.organisation_id == IDS["organisation_id"]
    assert receipt.membership_id == IDS["membership_id"]
    assert receipt.entitlement_snapshot_id == IDS["snapshot_id"]
    assert receipt.initial_role is OrganisationRole.OWNER
    assert receipt.subscription_status is SubscriptionStatus.TRIAL
    assert receipt.features == (
        ControlledFeature.ENGINEERING_CALCULATIONS,
        ControlledFeature.DOCUMENT_INGESTION,
    )
    assert receipt.quota_kinds == (
        QuotaKind.MONTHLY_CALCULATION_RUNS,
        QuotaKind.MONTHLY_DOCUMENT_INGESTIONS,
    )


def test_issuer_mismatch_fails_closed_without_subject_comparison_detail():
    private_issuer = "https://private-wrong-issuer.example/tenant"
    with pytest.raises(
        AuthenticationBootstrapReadinessError,
        match="issuer does not match",
    ) as captured:
        bind_authentication_bootstrap_readiness(
            token_readiness=token_readiness(),
            bootstrap_document=bootstrap_document(issuer=private_issuer),
        )
    assert private_issuer not in str(captured.value)


def test_subject_mismatch_fails_closed_without_raw_identity_detail():
    private_subject = "private-wrong-subject-step175"
    with pytest.raises(
        AuthenticationBootstrapReadinessError,
        match="subject does not match",
    ) as captured:
        bind_authentication_bootstrap_readiness(
            token_readiness=token_readiness(),
            bootstrap_document=bootstrap_document(subject=private_subject),
        )
    assert private_subject not in str(captured.value)
    assert SUBJECT not in str(captured.value)


@pytest.mark.parametrize("document", [b"", b"{", b"[]", b' {"password":"private"} '])
def test_invalid_bootstrap_document_is_contained_at_sanitized_boundary(document):
    with pytest.raises(
        AuthenticationBootstrapReadinessError,
        match="document is invalid",
    ) as captured:
        bind_authentication_bootstrap_readiness(
            token_readiness=token_readiness(),
            bootstrap_document=document,
        )
    assert captured.value.__cause__ is None
    assert "private" not in str(captured.value)


def test_token_readiness_must_be_the_exact_reviewed_receipt_type():
    with pytest.raises(TypeError, match="token readiness receipt is required"):
        bind_authentication_bootstrap_readiness(
            token_readiness={},
            bootstrap_document=bootstrap_document(),
        )


def test_rendered_receipt_is_canonical_review_evidence_and_not_execution_ready():
    receipt = bind_authentication_bootstrap_readiness(
        token_readiness=token_readiness(),
        bootstrap_document=bootstrap_document(),
    )
    rendered = render_authentication_bootstrap_readiness_receipt(receipt)
    parsed = json.loads(rendered)

    assert rendered == json.dumps(
        parsed,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    assert parsed["validation_scope"] == AUTHENTICATION_BOOTSTRAP_READINESS_SCOPE
    assert parsed["identity_binding_checked"] is True
    assert parsed["signed_token_evidence_bound"] is True
    assert parsed["bootstrap_execution_ready"] is False
    assert parsed["operational_empty_domain_rechecked"] is False
    assert parsed["provider_ownership_checked"] is False
    assert parsed["activation_ready"] is False
    for forbidden in (
        ISSUER,
        SUBJECT,
        EMAIL,
        DISPLAY_NAME,
        SOURCE_REFERENCE,
        "reviewed-organisation-step175",
        "Reviewed Organisation Step 175",
    ):
        assert forbidden not in rendered


def test_receipt_is_frozen_and_rejects_forged_contract_values():
    receipt = bind_authentication_bootstrap_readiness(
        token_readiness=token_readiness(),
        bootstrap_document=bootstrap_document(),
    )
    with pytest.raises(FrozenInstanceError):
        receipt.entitlement_plan = "changed"
    for changes in (
        {"configuration_sha256": "A" * 64},
        {"bootstrap_id": receipt.request_id},
        {"initial_role": OrganisationRole.ADMINISTRATOR},
        {"subscription_status": SubscriptionStatus.SUSPENDED},
        {"features": (ControlledFeature.ENGINEERING_CALCULATIONS,) * 2},
        {"quota_kinds": ("monthly_calculation_runs",)},
    ):
        with pytest.raises(ValueError, match="receipt is invalid"):
            replace(receipt, **changes)
    with pytest.raises(TypeError, match="receipt is required"):
        render_authentication_bootstrap_readiness_receipt({})


def test_identity_hashing_is_length_delimited_and_requires_exact_text():
    assert authentication_identity_sha256("ab", "c") != authentication_identity_sha256(
        "a", "bc"
    )
    assert authentication_identity_sha256(
        ISSUER, SUBJECT
    ) == authentication_identity_sha256(ISSUER, SUBJECT)
    for values in ((), ("",), (ISSUER, 1)):
        with pytest.raises(TypeError, match="non-empty strings"):
            authentication_identity_sha256(*values)


def test_binding_contract_performs_no_file_environment_network_database_or_app_io(
    monkeypatch,
):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected external access")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    receipt = bind_authentication_bootstrap_readiness(
        token_readiness=token_readiness(),
        bootstrap_document=bootstrap_document(),
    )
    assert receipt.initial_role is OrganisationRole.OWNER


def test_fresh_module_import_does_not_read_database_url_or_construct_engine():
    script = """
import os
import sys
original_getenv = os.getenv
def guarded_getenv(key, *args, **kwargs):
    if key == "DATABASE_URL":
        raise AssertionError("bootstrap readiness import read DATABASE_URL")
    return original_getenv(key, *args, **kwargs)
os.getenv = guarded_getenv
from app.security import authentication_bootstrap_readiness
assert "app.db.database" not in sys.modules
assert authentication_bootstrap_readiness.__name__.endswith("bootstrap_readiness")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
