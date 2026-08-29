"""Focused tests for explicit digest-confirmed bootstrap application."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.security.bootstrap_document import SecurityBootstrapDocumentError
from app.services.security_bootstrap_application import DigestConfirmedSecurityBootstrapApplication, SecurityBootstrapApprovalError
from app.services.security_bootstrap_executor import SecurityBootstrapPersistenceError, SecurityBootstrapReceipt, SecurityBootstrapStateError


NOW = datetime(2026, 8, 9, 3, 0, tzinfo=UTC)


def document(**changes):
    organisation_id = uuid4()
    payload = {
        "bootstrap_id": str(uuid4()),
        "request_id": str(uuid4()),
        "user_id": str(uuid4()),
        "organisation_id": str(organisation_id),
        "membership_id": str(uuid4()),
        "email": "owner@example.com",
        "display_name": "Initial Owner",
        "issuer": "https://identity.engineer4me.test",
        "subject": "private-provider-subject-151",
        "organisation_slug": "initial-organisation",
        "organisation_name": "Initial Organisation",
        "initial_role": "owner",
        "activated_at": NOW.isoformat(),
        "entitlement": {
            "snapshot_id": str(uuid4()),
            "organisation_id": str(organisation_id),
            "plan_id": "reviewed-plan-151",
            "subscription_status": "trial",
            "features": ["engineering_calculations"],
            "quotas": [{"kind": "monthly_calculation_runs", "limit": 100}],
            "effective_at": (NOW - timedelta(minutes=1)).isoformat(),
            "expires_at": (NOW + timedelta(days=30)).isoformat(),
            "source_reference": "approved bootstrap request 151",
        },
    }
    payload.update(changes)
    return json.dumps(payload).encode("utf-8")


class Executor:
    def __init__(self, error=None):
        self.error = error
        self.commands = []

    def execute(self, command):
        self.commands.append(command)
        if self.error is not None:
            raise self.error
        return SecurityBootstrapReceipt(
            bootstrap_id=command.bootstrap_id,
            request_id=command.request_id,
            user_id=command.user_id,
            organisation_id=command.organisation_id,
            membership_id=command.membership_id,
            entitlement_snapshot_id=command.entitlement.snapshot_id,
        )


def test_preview_returns_approval_digest_without_invoking_executor():
    executor = Executor()
    preview = DigestConfirmedSecurityBootstrapApplication(executor).preview(document())
    assert len(preview.document_sha256) == 64
    assert preview.entitlement_plan == "reviewed-plan-151"
    assert executor.commands == []


def test_exact_digest_executes_the_same_validated_command_once():
    executor = Executor()
    application = DigestConfirmedSecurityBootstrapApplication(executor)
    value = document()
    preview = application.preview(value)
    receipt = application.execute(value, approved_document_sha256=preview.document_sha256)
    assert len(executor.commands) == 1
    assert receipt.bootstrap_id == preview.bootstrap_id
    assert receipt.entitlement_snapshot_id == preview.entitlement_snapshot_id


def test_semantically_identical_json_layout_retains_explicit_approval():
    executor = Executor()
    application = DigestConfirmedSecurityBootstrapApplication(executor)
    compact = document()
    expanded = json.dumps(json.loads(compact), indent=4, sort_keys=True).encode("utf-8")
    digest = application.preview(compact).document_sha256
    application.execute(expanded, approved_document_sha256=digest)
    assert len(executor.commands) == 1


def test_changed_document_is_rejected_before_executor_access():
    executor = Executor()
    application = DigestConfirmedSecurityBootstrapApplication(executor)
    approved = application.preview(document()).document_sha256
    changed = document(email="different@example.com")
    with pytest.raises(SecurityBootstrapApprovalError, match="does not match"):
        application.execute(changed, approved_document_sha256=approved)
    assert executor.commands == []


@pytest.mark.parametrize("digest", [None, "", "0" * 63, "0" * 65, "G" * 64, "A" * 64])
def test_missing_malformed_or_noncanonical_digest_is_rejected_before_document_parsing(digest):
    executor = Executor()
    application = DigestConfirmedSecurityBootstrapApplication(executor)
    with pytest.raises(SecurityBootstrapApprovalError, match="digest is invalid"):
        application.execute(b"not-json", approved_document_sha256=digest)
    assert executor.commands == []


def test_invalid_document_is_rejected_even_with_well_formed_approval_digest():
    executor = Executor()
    with pytest.raises(SecurityBootstrapDocumentError):
        DigestConfirmedSecurityBootstrapApplication(executor).execute(b"{}", approved_document_sha256="0" * 64)
    assert executor.commands == []


@pytest.mark.parametrize(
    "error",
    [
        SecurityBootstrapStateError("security bootstrap requires an empty security domain"),
        SecurityBootstrapPersistenceError("security bootstrap could not be committed"),
    ],
)
def test_fail_closed_executor_outcomes_propagate_without_a_receipt(error):
    executor = Executor(error=error)
    application = DigestConfirmedSecurityBootstrapApplication(executor)
    value = document()
    digest = application.preview(value).document_sha256
    with pytest.raises(type(error), match=str(error)):
        application.execute(value, approved_document_sha256=digest)
    assert len(executor.commands) == 1


def test_approval_errors_do_not_disclose_document_identity_values():
    application = DigestConfirmedSecurityBootstrapApplication(Executor())
    with pytest.raises(SecurityBootstrapApprovalError) as captured:
        application.execute(document(), approved_document_sha256="0" * 64)
    message = str(captured.value)
    assert "owner@example.com" not in message
    assert "private-provider-subject-151" not in message


@pytest.mark.parametrize("executor", [None, object()])
def test_executor_dependency_must_expose_a_callable_execute(executor):
    with pytest.raises(TypeError, match="must provide execute"):
        DigestConfirmedSecurityBootstrapApplication(executor)
