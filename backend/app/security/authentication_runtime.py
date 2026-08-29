"""Controlled composition for the Phase 8 bearer-authentication boundary."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self
from uuid import UUID

from pydantic import Field, model_validator

from app.security.identity_models import IdentityText, SecurityModel
from app.security.jwks_resolver import (
    ControlledJWKSResolver,
    JWKSConfiguration,
    JWKSLoader,
)
from app.security.token_verifier import (
    ASYMMETRIC_ALGORITHMS,
    DEFAULT_AUTHENTICATION_TOKEN_PROFILE,
    DEFAULT_TOKEN_IDENTIFIER_CLAIM,
    AuthenticationTokenProfile,
    MICROSOFT_ENTRA_ACCESS_AS_USER_SCOPE,
    MICROSOFT_ENTRA_PUBLIC_CLIENT_AZPACR,
    MicrosoftEntraPublicClientAzpacr,
    MicrosoftEntraDelegatedScope,
    OIDCTokenVerifier,
    OIDCTokenVerifierConfig,
    TokenIdentifierClaim,
    microsoft_entra_v2_audience_matches_application,
    microsoft_entra_v2_issuer_matches_tenant,
)

if TYPE_CHECKING:
    from app.security.authentication_availability import (
        AvailabilityAwareAuthenticationDependency,
    )


class AuthenticationRuntimeConfiguration(SecurityModel):
    """Validated, provider-neutral inputs for one authentication runtime."""

    issuer: IdentityText
    audience: IdentityText
    algorithms: tuple[str, ...] = Field(min_length=1, max_length=6)
    jwks: JWKSConfiguration
    clock_skew_seconds: int = Field(default=30, ge=0, le=300)
    maximum_token_age_seconds: int = Field(default=3600, ge=60, le=86400)
    token_identifier_claim: TokenIdentifierClaim = DEFAULT_TOKEN_IDENTIFIER_CLAIM
    token_profile: AuthenticationTokenProfile = DEFAULT_AUTHENTICATION_TOKEN_PROFILE
    microsoft_entra_tenant_id: UUID | None = None
    microsoft_entra_api_application_id: UUID | None = None
    microsoft_entra_required_delegated_scope: MicrosoftEntraDelegatedScope | None = (
        None
    )
    microsoft_entra_calling_client_application_id: UUID | None = None
    microsoft_entra_required_azpacr: MicrosoftEntraPublicClientAzpacr | None = None

    @model_validator(mode="after")
    def validate_algorithms(self) -> Self:
        if len(self.algorithms) != len(set(self.algorithms)):
            raise ValueError("authentication algorithms must be unique")
        if any(item not in ASYMMETRIC_ALGORITHMS for item in self.algorithms):
            raise ValueError("authentication requires controlled asymmetric algorithms")
        if self.token_profile == "microsoft_entra_v2":
            if self.token_identifier_claim != "uti":
                raise ValueError("Microsoft Entra v2 authentication requires uti")
            if self.microsoft_entra_tenant_id is None:
                raise ValueError(
                    "Microsoft Entra v2 authentication requires a tenant ID"
                )
            if self.microsoft_entra_api_application_id is None:
                raise ValueError(
                    "Microsoft Entra v2 authentication requires an API application ID"
                )
            if (
                self.microsoft_entra_required_delegated_scope
                != MICROSOFT_ENTRA_ACCESS_AS_USER_SCOPE
            ):
                raise ValueError(
                    "Microsoft Entra v2 authentication requires the delegated API scope"
                )
            if (
                self.microsoft_entra_calling_client_application_id is None
                or self.microsoft_entra_calling_client_application_id.int == 0
                or self.microsoft_entra_calling_client_application_id
                in {
                    self.microsoft_entra_tenant_id,
                    self.microsoft_entra_api_application_id,
                }
            ):
                raise ValueError(
                    "Microsoft Entra v2 authentication requires a distinct calling client"
                )
            if (
                self.microsoft_entra_required_azpacr
                != MICROSOFT_ENTRA_PUBLIC_CLIENT_AZPACR
            ):
                raise ValueError(
                    "Microsoft Entra v2 authentication requires the public client class"
                )
            if not microsoft_entra_v2_issuer_matches_tenant(
                issuer=self.issuer,
                tenant_id=self.microsoft_entra_tenant_id,
            ):
                raise ValueError(
                    "Microsoft Entra v2 issuer must match the configured tenant ID"
                )
            if not microsoft_entra_v2_audience_matches_application(
                audience=self.audience,
                application_id=self.microsoft_entra_api_application_id,
            ):
                raise ValueError(
                    "Microsoft Entra v2 audience must match the API application ID"
                )
        elif (
            self.microsoft_entra_tenant_id is not None
            or self.microsoft_entra_api_application_id is not None
            or self.microsoft_entra_required_delegated_scope is not None
            or self.microsoft_entra_calling_client_application_id is not None
            or self.microsoft_entra_required_azpacr is not None
        ):
            raise ValueError(
                "provider-neutral authentication cannot bind Entra identifiers"
            )
        return self


def build_bearer_authentication_dependency(
    *,
    config: AuthenticationRuntimeConfiguration,
    jwks_loader: JWKSLoader,
) -> AvailabilityAwareAuthenticationDependency:
    """Compose explicit configuration and an injected loader; perform no I/O."""

    from app.security.authentication import BearerAuthenticationDependency
    from app.security.authentication_availability import (
        AvailabilityAwareAuthenticationDependency,
    )

    resolver = ControlledJWKSResolver(config=config.jwks, loader=jwks_loader)
    verifier = OIDCTokenVerifier(
        config=OIDCTokenVerifierConfig(
            issuer=config.issuer,
            audience=config.audience,
            algorithms=config.algorithms,
            clock_skew_seconds=config.clock_skew_seconds,
            maximum_token_age_seconds=config.maximum_token_age_seconds,
            token_identifier_claim=config.token_identifier_claim,
            token_profile=config.token_profile,
            microsoft_entra_tenant_id=config.microsoft_entra_tenant_id,
            microsoft_entra_api_application_id=(
                config.microsoft_entra_api_application_id
            ),
            microsoft_entra_required_delegated_scope=(
                config.microsoft_entra_required_delegated_scope
            ),
            microsoft_entra_calling_client_application_id=(
                config.microsoft_entra_calling_client_application_id
            ),
            microsoft_entra_required_azpacr=config.microsoft_entra_required_azpacr,
        ),
        key_resolver=resolver,
    )
    return AvailabilityAwareAuthenticationDependency(
        BearerAuthenticationDependency(verifier)
    )
