"""Digest-confirmed application boundary for the one-time security bootstrap."""

from __future__ import annotations

import hmac
import re
from typing import Protocol

from app.security.bootstrap_document import SecurityBootstrapPreview, load_security_bootstrap_document
from app.security.bootstrap_models import SecurityBootstrapCommand
from app.services.security_bootstrap_executor import SecurityBootstrapReceipt


SHA256_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")


class SecurityBootstrapApprovalError(ValueError):
    """Sanitized rejection when explicit document approval is absent or stale."""


class SecurityBootstrapExecutor(Protocol):
    def execute(self, command: SecurityBootstrapCommand) -> SecurityBootstrapReceipt: ...


class DigestConfirmedSecurityBootstrapApplication:
    """Preview or execute the exact canonical command approved by its digest."""

    def __init__(self, executor: SecurityBootstrapExecutor) -> None:
        if not callable(getattr(executor, "execute", None)):
            raise TypeError("security bootstrap executor must provide execute")
        self._executor = executor

    def preview(self, document: bytes) -> SecurityBootstrapPreview:
        return load_security_bootstrap_document(document).preview

    def execute(self, document: bytes, *, approved_document_sha256: str) -> SecurityBootstrapReceipt:
        if not isinstance(approved_document_sha256, str) or SHA256_PATTERN.fullmatch(approved_document_sha256) is None:
            raise SecurityBootstrapApprovalError("approved security bootstrap digest is invalid")
        validated = load_security_bootstrap_document(document)
        if not hmac.compare_digest(validated.preview.document_sha256, approved_document_sha256):
            raise SecurityBootstrapApprovalError("security bootstrap document does not match the approved digest")
        return self._executor.execute(validated.command)
