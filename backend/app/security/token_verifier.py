"""Provider-neutral asymmetric JWT verification boundary for Phase 8."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal, Protocol, Self
from urllib.parse import urlsplit
from uuid import UUID

import jwt
from jwt import InvalidTokenError
from pydantic import AwareDatetime, Field, StringConstraints, model_validator

from app.security.identity_models import IdentityText, SecurityModel, SubjectText


TokenIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)
]
KeyIdentifier = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300)
]
ASYMMETRIC_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
)
TokenIdentifierClaim = Literal["jti", "uti"]
TOKEN_IDENTIFIER_CLAIMS = frozenset({"jti", "uti"})
DEFAULT_TOKEN_IDENTIFIER_CLAIM: TokenIdentifierClaim = "jti"
AuthenticationTokenProfile = Literal[
    "provider_neutral",
    "microsoft_entra_v2",
]
AUTHENTICATION_TOKEN_PROFILES = frozenset(
    {"provider_neutral", "microsoft_entra_v2"}
)
DEFAULT_AUTHENTICATION_TOKEN_PROFILE: AuthenticationTokenProfile = "provider_neutral"
MICROSOFT_ENTRA_ACCESS_AS_USER_SCOPE = "access_as_user"
MicrosoftEntraDelegatedScope = Literal["access_as_user"]
MICROSOFT_ENTRA_PUBLIC_CLIENT_AZPACR = "0"
MicrosoftEntraPublicClientAzpacr = Literal["0"]
BASE_REQUIRED_CLAIMS = ("exp", "iat", "iss", "aud", "sub")


def required_token_claims(
    token_identifier_claim: TokenIdentifierClaim,
    token_profile: AuthenticationTokenProfile = DEFAULT_AUTHENTICATION_TOKEN_PROFILE,
) -> tuple[str, ...]:
    """Return the exact digest-bound claim contract for one provider profile."""

    if token_identifier_claim not in TOKEN_IDENTIFIER_CLAIMS:
        raise ValueError("token identifier claim is not supported")
    if token_profile not in AUTHENTICATION_TOKEN_PROFILES:
        raise ValueError("authentication token profile is not supported")
    claims = (*BASE_REQUIRED_CLAIMS, token_identifier_claim)
    if token_profile == "microsoft_entra_v2":
        return (*claims, "tid", "ver", "scp", "azp", "azpacr")
    return claims


REQUIRED_CLAIMS = required_token_claims(DEFAULT_TOKEN_IDENTIFIER_CLAIM)


def microsoft_entra_v2_issuer_matches_tenant(
    *,
    issuer: str,
    tenant_id: UUID,
) -> bool:
    """Require the exact tenant UUID in one Microsoft Entra v2 issuer path."""

    if type(issuer) is not str or type(tenant_id) is not UUID:
        return False
    if any(
        character == "\\"
        or character.isspace()
        or ord(character) < 0x20
        or ord(character) == 0x7F
        for character in issuer
    ):
        return False
    try:
        parsed = urlsplit(issuer)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(hostname)
        and parsed.username is None
        and parsed.password is None
        and port != 0
        and not parsed.netloc.endswith(":")
        and parsed.path == f"/{tenant_id}/v2.0"
        and not parsed.query
        and not parsed.fragment
    )


def microsoft_entra_v2_audience_matches_application(
    *,
    audience: str,
    application_id: UUID,
) -> bool:
    """Require the v2 access-token audience to be one exact API app UUID."""

    return (
        type(audience) is str
        and type(application_id) is UUID
        and audience == str(application_id)
    )


def microsoft_entra_v2_calling_client_matches_application(
    *,
    calling_client: object,
    application_id: UUID,
) -> bool:
    """Require one canonical GUID-valued v2 ``azp`` for the approved client."""

    if type(calling_client) is not str or type(application_id) is not UUID:
        return False
    try:
        parsed = UUID(calling_client)
    except (AttributeError, TypeError, ValueError):
        return False
    return (
        parsed.int != 0
        and calling_client.lower() == str(parsed)
        and parsed == application_id
    )


def microsoft_entra_v2_azpacr_is_public_client(
    *,
    azpacr: object,
) -> bool:
    """Require the signed v2 ``azpacr`` claim to identify a public client."""

    return (
        type(azpacr) is str
        and azpacr == MICROSOFT_ENTRA_PUBLIC_CLIENT_AZPACR
    )


class TokenVerificationReason(StrEnum):
    MALFORMED_TOKEN = "malformed_token"
    DISALLOWED_ALGORITHM = "disallowed_algorithm"
    MISSING_KEY_ID = "missing_key_id"
    KEY_NOT_FOUND = "key_not_found"
    INVALID_SIGNATURE_OR_CLAIMS = "invalid_signature_or_claims"
    TOKEN_TOO_OLD = "token_too_old"


class TokenVerificationError(RuntimeError):
    def __init__(self, reason: TokenVerificationReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class OIDCTokenVerifierConfig(SecurityModel):
    issuer: IdentityText
    audience: IdentityText
    algorithms: tuple[str, ...] = Field(min_length=1, max_length=6)
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
            raise ValueError("algorithms must be unique")
        if any(item not in ASYMMETRIC_ALGORITHMS for item in self.algorithms):
            raise ValueError("only controlled asymmetric algorithms are permitted")
        if self.token_profile == "microsoft_entra_v2":
            if self.token_identifier_claim != "uti":
                raise ValueError("Microsoft Entra v2 tokens require uti")
            if self.microsoft_entra_tenant_id is None:
                raise ValueError("Microsoft Entra v2 tokens require a tenant ID")
            if self.microsoft_entra_api_application_id is None:
                raise ValueError(
                    "Microsoft Entra v2 tokens require an API application ID"
                )
            if (
                self.microsoft_entra_required_delegated_scope
                != MICROSOFT_ENTRA_ACCESS_AS_USER_SCOPE
            ):
                raise ValueError(
                    "Microsoft Entra v2 tokens require the delegated API scope"
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
                    "Microsoft Entra v2 tokens require a distinct calling client"
                )
            if (
                self.microsoft_entra_required_azpacr
                != MICROSOFT_ENTRA_PUBLIC_CLIENT_AZPACR
            ):
                raise ValueError(
                    "Microsoft Entra v2 tokens require the public client class"
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
                "provider-neutral tokens cannot bind Entra application identifiers"
            )
        return self


class VerifiedTokenClaims(SecurityModel):
    issuer: IdentityText
    subject: SubjectText
    audiences: tuple[IdentityText, ...]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    token_id: TokenIdentifier
    key_id: KeyIdentifier
    algorithm: str
    token_profile: AuthenticationTokenProfile = DEFAULT_AUTHENTICATION_TOKEN_PROFILE
    microsoft_entra_tenant_id: UUID | None = None
    microsoft_entra_api_application_id: UUID | None = None
    microsoft_entra_delegated_scope: MicrosoftEntraDelegatedScope | None = None
    microsoft_entra_calling_client_application_id: UUID | None = None
    microsoft_entra_azpacr: MicrosoftEntraPublicClientAzpacr | None = None
    token_version: str | None = None

    @model_validator(mode="after")
    def validate_times(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("token expiry must be later than issue time")
        if self.token_profile == "microsoft_entra_v2":
            if (
                self.microsoft_entra_tenant_id is None
                or self.microsoft_entra_api_application_id is None
                or self.microsoft_entra_delegated_scope
                != MICROSOFT_ENTRA_ACCESS_AS_USER_SCOPE
                or self.microsoft_entra_calling_client_application_id is None
                or self.microsoft_entra_calling_client_application_id.int == 0
                or self.microsoft_entra_calling_client_application_id
                in {
                    self.microsoft_entra_tenant_id,
                    self.microsoft_entra_api_application_id,
                }
                or self.microsoft_entra_azpacr
                != MICROSOFT_ENTRA_PUBLIC_CLIENT_AZPACR
                or self.token_version != "2.0"
            ):
                raise ValueError("Microsoft Entra v2 claim binding is incomplete")
        elif (
            self.microsoft_entra_tenant_id is not None
            or self.microsoft_entra_api_application_id is not None
            or self.microsoft_entra_delegated_scope is not None
            or self.microsoft_entra_calling_client_application_id is not None
            or self.microsoft_entra_azpacr is not None
            or self.token_version is not None
        ):
            raise ValueError(
                "provider-neutral claims cannot carry Entra binding evidence"
            )
        return self


class VerificationKeyResolver(Protocol):
    def resolve(self, *, key_id: str, algorithm: str) -> object | None: ...


class StaticVerificationKeyResolver:
    """Immutable in-process resolver for tests and controlled deployments."""

    def __init__(self, keys: dict[tuple[str, str], object]) -> None:
        self._keys = dict(keys)

    def resolve(self, *, key_id: str, algorithm: str) -> object | None:
        return self._keys.get((key_id, algorithm))


class OIDCTokenVerifier:
    def __init__(
        self, *, config: OIDCTokenVerifierConfig, key_resolver: VerificationKeyResolver
    ) -> None:
        self._config = config
        self._key_resolver = key_resolver

    def verify(
        self, token: str, *, verified_at: datetime | None = None
    ) -> VerifiedTokenClaims:
        if not isinstance(token, str) or not token.strip() or len(token) > 32768:
            raise TokenVerificationError(TokenVerificationReason.MALFORMED_TOKEN)
        try:
            header = jwt.get_unverified_header(token)
        except InvalidTokenError as exc:
            raise TokenVerificationError(
                TokenVerificationReason.MALFORMED_TOKEN
            ) from exc
        algorithm = header.get("alg")
        if not isinstance(algorithm, str) or algorithm not in self._config.algorithms:
            raise TokenVerificationError(TokenVerificationReason.DISALLOWED_ALGORITHM)
        key_id = header.get("kid")
        if not isinstance(key_id, str) or not key_id.strip() or len(key_id) > 300:
            raise TokenVerificationError(TokenVerificationReason.MISSING_KEY_ID)
        key = self._key_resolver.resolve(key_id=key_id, algorithm=algorithm)
        if key is None:
            raise TokenVerificationError(TokenVerificationReason.KEY_NOT_FOUND)
        required_claims = required_token_claims(
            self._config.token_identifier_claim,
            self._config.token_profile,
        )
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(self._config.algorithms),
                audience=self._config.audience,
                issuer=self._config.issuer,
                leeway=self._config.clock_skew_seconds,
                options={
                    "require": list(required_claims),
                    "verify_signature": True,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_sub": True,
                    "verify_jti": self._config.token_identifier_claim == "jti",
                },
            )
        except InvalidTokenError as exc:
            raise TokenVerificationError(
                TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS
            ) from exc
        now = verified_at or datetime.now(UTC)
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise TokenVerificationError(
                TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS
            )
        now = now.astimezone(UTC)
        try:
            issued_at = datetime.fromtimestamp(int(claims["iat"]), tz=UTC)
            expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=UTC)
            not_before = (
                datetime.fromtimestamp(int(claims["nbf"]), tz=UTC)
                if "nbf" in claims
                else None
            )
        except (KeyError, OSError, OverflowError, TypeError, ValueError):
            raise TokenVerificationError(
                TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS
            ) from None
        skew = self._config.clock_skew_seconds
        if expires_at <= now - timedelta(seconds=skew):
            raise TokenVerificationError(
                TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS
            )
        if issued_at > now + timedelta(seconds=skew):
            raise TokenVerificationError(
                TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS
            )
        if not_before is not None and not_before > now + timedelta(seconds=skew):
            raise TokenVerificationError(
                TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS
            )
        if (
            (now - issued_at).total_seconds()
            > self._config.maximum_token_age_seconds + skew
        ):
            raise TokenVerificationError(TokenVerificationReason.TOKEN_TOO_OLD)
        raw_audience = claims["aud"]
        audiences = (
            (raw_audience,) if isinstance(raw_audience, str) else tuple(raw_audience)
        )
        microsoft_entra_tenant_id: UUID | None = None
        microsoft_entra_api_application_id: UUID | None = None
        microsoft_entra_delegated_scope: MicrosoftEntraDelegatedScope | None = None
        microsoft_entra_calling_client_application_id: UUID | None = None
        microsoft_entra_azpacr: MicrosoftEntraPublicClientAzpacr | None = None
        token_version: str | None = None
        if self._config.token_profile == "microsoft_entra_v2":
            try:
                microsoft_entra_tenant_id = UUID(claims["tid"])
            except (AttributeError, TypeError, ValueError):
                raise TokenVerificationError(
                    TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS
                ) from None
            if (
                microsoft_entra_tenant_id
                != self._config.microsoft_entra_tenant_id
                or claims["ver"] != "2.0"
                or type(claims["aud"]) is not str
                or claims["aud"] != str(self._config.microsoft_entra_api_application_id)
                or type(claims["scp"]) is not str
                or claims["scp"]
                != self._config.microsoft_entra_required_delegated_scope
                or not microsoft_entra_v2_calling_client_matches_application(
                    calling_client=claims["azp"],
                    application_id=(
                        self._config.microsoft_entra_calling_client_application_id
                    ),
                )
                or not microsoft_entra_v2_azpacr_is_public_client(
                    azpacr=claims["azpacr"],
                )
                or "roles" in claims
                or (
                    "idtyp" in claims
                    and claims["idtyp"] != "user"
                )
            ):
                raise TokenVerificationError(
                    TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS
                )
            token_version = "2.0"
            microsoft_entra_api_application_id = (
                self._config.microsoft_entra_api_application_id
            )
            microsoft_entra_delegated_scope = (
                self._config.microsoft_entra_required_delegated_scope
            )
            microsoft_entra_calling_client_application_id = (
                self._config.microsoft_entra_calling_client_application_id
            )
            microsoft_entra_azpacr = self._config.microsoft_entra_required_azpacr
        try:
            return VerifiedTokenClaims(
                issuer=claims["iss"],
                subject=claims["sub"],
                audiences=audiences,
                issued_at=issued_at,
                expires_at=expires_at,
                token_id=claims[self._config.token_identifier_claim],
                key_id=key_id,
                algorithm=algorithm,
                token_profile=self._config.token_profile,
                microsoft_entra_tenant_id=microsoft_entra_tenant_id,
                microsoft_entra_api_application_id=(
                    microsoft_entra_api_application_id
                ),
                microsoft_entra_delegated_scope=(
                    microsoft_entra_delegated_scope
                ),
                microsoft_entra_calling_client_application_id=(
                    microsoft_entra_calling_client_application_id
                ),
                microsoft_entra_azpacr=microsoft_entra_azpacr,
                token_version=token_version,
            )
        except (TypeError, ValueError) as exc:
            raise TokenVerificationError(
                TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS
            ) from exc
