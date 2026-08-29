"""Controlled parsing and privacy-minimised preview of bootstrap documents."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from math import isfinite
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from app.security.bootstrap_models import SecurityBootstrapCommand
from app.security.entitlements import ControlledFeature, QuotaKind, SubscriptionStatus
from app.security.identity_models import OrganisationRole


MAX_BOOTSTRAP_DOCUMENT_BYTES = 32_768


class SecurityBootstrapDocumentError(ValueError):
    """Sanitized rejection of an untrusted bootstrap document."""


@dataclass(frozen=True, slots=True)
class SecurityBootstrapPreview:
    document_sha256: str
    bootstrap_id: UUID
    request_id: UUID
    user_id: UUID
    organisation_id: UUID
    membership_id: UUID
    entitlement_snapshot_id: UUID
    initial_role: OrganisationRole
    entitlement_plan: str
    subscription_status: SubscriptionStatus
    features: tuple[ControlledFeature, ...]
    quota_kinds: tuple[QuotaKind, ...]


@dataclass(frozen=True, slots=True)
class ValidatedSecurityBootstrapDocument:
    command: SecurityBootstrapCommand
    preview: SecurityBootstrapPreview


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SecurityBootstrapDocumentError(
                "security bootstrap document contains a duplicate key"
            )
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    del value
    raise SecurityBootstrapDocumentError(
        "security bootstrap document contains a non-finite number"
    )


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not isfinite(parsed):
        raise SecurityBootstrapDocumentError(
            "security bootstrap document contains a non-finite number"
        )
    return parsed


def load_security_bootstrap_document(
    document: bytes,
) -> ValidatedSecurityBootstrapDocument:
    """Validate one bounded JSON document without file, network, or database I/O."""

    if not isinstance(document, bytes):
        raise TypeError("security bootstrap document must be bytes")
    if not document:
        raise SecurityBootstrapDocumentError("security bootstrap document is empty")
    if len(document) > MAX_BOOTSTRAP_DOCUMENT_BYTES:
        raise SecurityBootstrapDocumentError(
            "security bootstrap document exceeds the byte limit"
        )
    try:
        text = document.decode("utf-8")
    except UnicodeDecodeError:
        raise SecurityBootstrapDocumentError(
            "security bootstrap document must be UTF-8"
        ) from None
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_number,
            parse_float=_parse_finite_float,
        )
    except SecurityBootstrapDocumentError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError):
        raise SecurityBootstrapDocumentError(
            "security bootstrap document is not valid JSON"
        ) from None
    if not isinstance(parsed, dict):
        raise SecurityBootstrapDocumentError(
            "security bootstrap document root must be an object"
        )
    try:
        canonical_input = json.dumps(
            parsed,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        raise SecurityBootstrapDocumentError(
            "security bootstrap document is not valid JSON"
        ) from None
    try:
        command = SecurityBootstrapCommand.model_validate_json(canonical_input)
    except ValidationError:
        raise SecurityBootstrapDocumentError(
            "security bootstrap document failed contract validation"
        ) from None
    canonical_command = json.dumps(
        command.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    preview = SecurityBootstrapPreview(
        document_sha256=hashlib.sha256(canonical_command).hexdigest(),
        bootstrap_id=command.bootstrap_id,
        request_id=command.request_id,
        user_id=command.user_id,
        organisation_id=command.organisation_id,
        membership_id=command.membership_id,
        entitlement_snapshot_id=command.entitlement.snapshot_id,
        initial_role=command.initial_role,
        entitlement_plan=command.entitlement.plan_id,
        subscription_status=command.entitlement.subscription_status,
        features=command.entitlement.features,
        quota_kinds=tuple(grant.kind for grant in command.entitlement.quotas),
    )
    return ValidatedSecurityBootstrapDocument(command=command, preview=preview)
