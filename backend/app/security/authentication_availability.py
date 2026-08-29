"""Sanitized fail-closed containment for authentication-provider outages."""

from __future__ import annotations

from typing import Annotated

from fastapi import Header, HTTPException, status

from app.security.authentication import BearerAuthenticationDependency
from app.security.jwks_http_loader import JWKSHTTPError
from app.security.jwks_resolver import JWKSResolutionError
from app.services.security_access_service import TrustedAuthenticationContext


class AvailabilityAwareAuthenticationDependency:
    """Preserve 401 credential failures and contain known JWKS outages as 503."""

    def __init__(self, dependency: BearerAuthenticationDependency) -> None:
        self._dependency = dependency

    def __call__(
        self,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ) -> TrustedAuthenticationContext:
        try:
            return self._dependency(authorization)
        except (JWKSHTTPError, JWKSResolutionError):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service temporarily unavailable.",
                headers={"Retry-After": "5"},
            ) from None
