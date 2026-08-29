"""FastAPI bearer authentication boundary backed by verified JWT claims."""

from __future__ import annotations

import re
from typing import Annotated
from uuid import UUID, uuid5

from fastapi import Header, HTTPException, status

from app.security.token_verifier import OIDCTokenVerifier, TokenVerificationError
from app.services.security_access_service import TrustedAuthenticationContext


_BEARER_PATTERN = re.compile(r"\ABearer ([A-Za-z0-9._~-]+)\Z", re.IGNORECASE)
_SESSION_ID_NAMESPACE = UUID("a7a4ea3e-9aff-5e98-8ed7-9af4bff9eaf8")
MAX_AUTHORIZATION_HEADER = 32780


def _session_id(*, issuer: str, subject: str, token_id: str) -> UUID:
    """Derive one pseudonymous per-token audit correlation UUID."""

    correlation_name = (
        f"{len(issuer)}:{issuer}{len(subject)}:{subject}{token_id}"
    )
    return uuid5(_SESSION_ID_NAMESPACE, correlation_name)


class BearerAuthenticationDependency:
    """Convert exactly one verified bearer token into trusted context."""

    def __init__(self, verifier: OIDCTokenVerifier) -> None:
        self._verifier = verifier

    def __call__(
        self,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ) -> TrustedAuthenticationContext:
        if (
            authorization is None
            or len(authorization) > MAX_AUTHORIZATION_HEADER
        ):
            raise self._unauthorized()
        match = _BEARER_PATTERN.fullmatch(authorization)
        if match is None:
            raise self._unauthorized()
        try:
            claims = self._verifier.verify(match.group(1))
            return TrustedAuthenticationContext(
                issuer=claims.issuer,
                subject=claims.subject,
                authenticated_at=claims.issued_at,
                session_id=_session_id(
                    issuer=claims.issuer,
                    subject=claims.subject,
                    token_id=claims.token_id,
                ),
            )
        except (TokenVerificationError, ValueError):
            raise self._unauthorized() from None

    @staticmethod
    def _unauthorized() -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
