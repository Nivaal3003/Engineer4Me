"""Focused tests for bounded bootstrap document validation and preview."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, asdict
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.security.bootstrap_document import MAX_BOOTSTRAP_DOCUMENT_BYTES, SecurityBootstrapDocumentError, load_security_bootstrap_document
from app.security.entitlements import ControlledFeature, QuotaKind, SubscriptionStatus
from app.security.identity_models import OrganisationRole


NOW = datetime(2026, 8, 9, 2, 0, tzinfo=UTC)


def values():
    organisation_id = uuid4()
    return {
        "bootstrap_id": str(uuid4()),
        "request_id": str(uuid4()),
        "user_id": str(uuid4()),
        "organisation_id": str(organisation_id),
        "membership_id": str(uuid4()),
        "email": "owner@example.com",
        "display_name": "Initial Owner",
        "issuer": "https://identity.engineer4me.test",
        "subject": "private-provider-subject-150",
        "organisation_slug": "initial-organisation",
        "organisation_name": "Initial Organisation",
        "initial_role": "owner",
        "activated_at": NOW.isoformat(),
        "entitlement": {
            "snapshot_id": str(uuid4()),
            "organisation_id": str(organisation_id),
            "plan_id": "reviewed-plan-150",
            "subscription_status": "trial",
            "features": ["engineering_calculations", "document_ingestion"],
            "quotas": [{"kind": "monthly_calculation_runs", "limit": 100}],
            "effective_at": (NOW - timedelta(minutes=1)).isoformat(),
            "expires_at": (NOW + timedelta(days=30)).isoformat(),
            "source_reference": "approved bootstrap document 150",
        },
    }


def encoded(payload=None, **json_options):
    return json.dumps(values() if payload is None else payload, **json_options).encode("utf-8")


def test_complete_json_document_builds_the_strict_command_and_preview():
    result = load_security_bootstrap_document(encoded())
    assert result.command.initial_role is OrganisationRole.OWNER
    assert result.preview.subscription_status is SubscriptionStatus.TRIAL
    assert result.preview.features == (ControlledFeature.ENGINEERING_CALCULATIONS, ControlledFeature.DOCUMENT_INGESTION)
    assert result.preview.quota_kinds == (QuotaKind.MONTHLY_CALCULATION_RUNS,)
    assert len(result.preview.document_sha256) == 64


def test_preview_digest_is_canonical_across_json_layout_and_key_order():
    payload = values()
    compact = encoded(payload, separators=(",", ":"), sort_keys=True)
    expanded = encoded(dict(reversed(tuple(payload.items()))), indent=3)
    assert load_security_bootstrap_document(compact).preview.document_sha256 == load_security_bootstrap_document(expanded).preview.document_sha256


def test_preview_is_frozen_and_excludes_identity_and_credential_detail():
    preview = load_security_bootstrap_document(encoded()).preview
    with pytest.raises(FrozenInstanceError):
        preview.entitlement_plan = "changed"
    serialized = json.dumps(asdict(preview), default=str)
    for forbidden in ("owner@example.com", "Initial Owner", "private-provider-subject-150", "identity.engineer4me.test", "source_reference", "password", "token", "secret"):
        assert forbidden not in serialized


@pytest.mark.parametrize("document", [b"", b"\xff", b"{", b"[]", b'"text"'])
def test_empty_non_utf8_malformed_and_non_object_documents_are_rejected(document):
    with pytest.raises(SecurityBootstrapDocumentError):
        load_security_bootstrap_document(document)


def test_document_larger_than_the_fixed_boundary_is_rejected():
    with pytest.raises(SecurityBootstrapDocumentError, match="byte limit"):
        load_security_bootstrap_document(b" " * (MAX_BOOTSTRAP_DOCUMENT_BYTES + 1))


def test_non_bytes_input_is_rejected_before_parsing():
    with pytest.raises(TypeError, match="must be bytes"):
        load_security_bootstrap_document("{}")


def test_duplicate_keys_are_rejected_at_any_depth():
    payload = encoded()
    duplicate_top = payload[:-1] + b',"email":"other@example.com"}'
    duplicate_nested = payload.replace(b'"plan_id": "reviewed-plan-150"', b'"plan_id": "reviewed-plan-150", "plan_id": "other"')
    for document in (duplicate_top, duplicate_nested):
        with pytest.raises(SecurityBootstrapDocumentError, match="duplicate key"):
            load_security_bootstrap_document(document)


def test_non_finite_json_number_is_rejected():
    payload = encoded().replace(b'"limit": 100', b'"limit": NaN')
    with pytest.raises(SecurityBootstrapDocumentError, match="non-finite"):
        load_security_bootstrap_document(payload)


@pytest.mark.parametrize("number", [b"1e999", b"-1e999"])
def test_exponent_overflow_is_rejected_as_non_finite_without_a_cause(number):
    payload = encoded().replace(b'"limit": 100', b'"limit": ' + number)
    with pytest.raises(SecurityBootstrapDocumentError, match="non-finite") as captured:
        load_security_bootstrap_document(payload)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("path", "invalid"),
    [
        (("bootstrap_id",), "not-a-uuid"),
        (("activated_at",), "not-a-time"),
        (("initial_role",), "administrator"),
        (("entitlement", "subscription_status"), "suspended"),
    ],
)
def test_invalid_security_contract_values_fail_at_the_document_boundary(path, invalid):
    payload = values()
    target = payload
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = invalid
    with pytest.raises(SecurityBootstrapDocumentError, match="contract validation"):
        load_security_bootstrap_document(encoded(payload))


def test_unknown_fields_fail_closed_without_leaking_validation_detail():
    payload = values()
    payload["password"] = "private-value"
    with pytest.raises(SecurityBootstrapDocumentError, match="contract validation") as captured:
        load_security_bootstrap_document(encoded(payload))
    assert "private-value" not in str(captured.value)
    assert captured.value.__cause__ is None


def test_loader_performs_no_file_network_database_or_environment_access(monkeypatch):
    def forbidden(*args, **kwargs):
        del args, kwargs
        raise AssertionError("unexpected external access")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr("os.getenv", forbidden)
    result = load_security_bootstrap_document(encoded())
    assert result.command.email == "owner@example.com"
