"""Security regression tests for asymmetric JWT verification."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from app.security.token_verifier import (
    OIDCTokenVerifier,
    OIDCTokenVerifierConfig,
    StaticVerificationKeyResolver,
    TokenVerificationError,
    TokenVerificationReason,
    VerifiedTokenClaims,
    required_token_claims,
)


NOW = datetime.now(UTC).replace(microsecond=0)
ISSUER = "https://identity.engineer4me.test"
AUDIENCE = "engineer4me-api"
KEY_ID = "key-128"
ENTRA_TENANT_ID = UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeee0200")
ENTRA_API_APPLICATION_ID = UUID("bbbbbbbb-cccc-4ddd-8eee-ffffffff0300")
ENTRA_CALLING_CLIENT_APPLICATION_ID = UUID(
    "cccccccc-dddd-4eee-8fff-aaaaaaaa0400"
)
ENTRA_ISSUER = f"https://synthetic.ciamlogin.com/{ENTRA_TENANT_ID}/v2.0"
ENTRA_REQUIRED_DELEGATED_SCOPE = "access_as_user"
ENTRA_REQUIRED_AZPACR = "0"
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()


def config(**overrides):
    values = dict(
        issuer=ISSUER,
        audience=AUDIENCE,
        algorithms=("RS256",),
        clock_skew_seconds=5,
        maximum_token_age_seconds=3600,
    )
    values.update(overrides)
    return OIDCTokenVerifierConfig(**values)


def verifier(**overrides):
    return OIDCTokenVerifier(
        config=config(**overrides),
        key_resolver=StaticVerificationKeyResolver({(KEY_ID, "RS256"): PUBLIC_KEY}),
    )


def token(**overrides):
    claims = dict(
        iss=ISSUER,
        aud=AUDIENCE,
        sub="subject-128",
        jti=str(uuid4()),
        iat=NOW,
        exp=NOW + timedelta(minutes=5),
    )
    claims.update(overrides)
    return jwt.encode(claims, PRIVATE_KEY, algorithm="RS256", headers={"kid": KEY_ID})


def reason(value, expected):
    with pytest.raises(TokenVerificationError) as captured:
        verifier().verify(value, verified_at=NOW)
    assert captured.value.reason is expected


def test_valid_asymmetric_token_returns_bounded_claims():
    result = verifier().verify(token(), verified_at=NOW)
    assert result.issuer == ISSUER and result.subject == "subject-128"
    assert (
        result.audiences == (AUDIENCE,)
        and result.algorithm == "RS256"
        and result.key_id == KEY_ID
    )


@pytest.mark.parametrize(
    "algorithms", [("none",), ("HS256",), ("RS256", "HS256"), ("RS256", "RS256")]
)
def test_configuration_rejects_unsafe_or_duplicate_algorithm_sets(algorithms):
    with pytest.raises(ValidationError):
        config(algorithms=algorithms)


def test_unsigned_none_token_is_rejected_before_key_resolution():
    unsigned = jwt.encode(
        {"sub": "subject-128"}, key="", algorithm="none", headers={"kid": KEY_ID}
    )
    reason(unsigned, TokenVerificationReason.DISALLOWED_ALGORITHM)


def test_hmac_algorithm_confusion_is_rejected():
    value = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "subject-128",
            "jti": "jti",
            "iat": NOW,
            "exp": NOW + timedelta(minutes=5),
        },
        key=b"a" * 32,
        algorithm="HS256",
        headers={"kid": KEY_ID},
    )
    reason(value, TokenVerificationReason.DISALLOWED_ALGORITHM)


def test_missing_and_unknown_key_identifiers_fail_closed():
    missing = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "subject-128",
            "jti": "jti",
            "iat": NOW,
            "exp": NOW + timedelta(minutes=5),
        },
        PRIVATE_KEY,
        algorithm="RS256",
    )
    reason(missing, TokenVerificationReason.MISSING_KEY_ID)
    unknown = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "subject-128",
            "jti": "jti",
            "iat": NOW,
            "exp": NOW + timedelta(minutes=5),
        },
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": "unknown"},
    )
    reason(unknown, TokenVerificationReason.KEY_NOT_FOUND)


@pytest.mark.parametrize("claim", ["exp", "iat", "iss", "aud", "sub", "jti"])
def test_every_required_claim_is_enforced(claim):
    claims = dict(
        iss=ISSUER,
        aud=AUDIENCE,
        sub="subject-128",
        jti="jti",
        iat=NOW,
        exp=NOW + timedelta(minutes=5),
    )
    claims.pop(claim)
    reason(
        jwt.encode(claims, PRIVATE_KEY, algorithm="RS256", headers={"kid": KEY_ID}),
        TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS,
    )


def test_wrong_issuer_and_audience_are_rejected():
    reason(
        token(iss="https://attacker.invalid"),
        TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS,
    )
    reason(token(aud="other-api"), TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS)


def test_expired_and_future_issued_tokens_are_rejected():
    reason(
        token(exp=NOW - timedelta(seconds=10)),
        TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS,
    )
    reason(
        token(iat=NOW + timedelta(minutes=5)),
        TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS,
    )


def test_wrong_signature_is_rejected():
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    claims = dict(
        iss=ISSUER,
        aud=AUDIENCE,
        sub="subject-128",
        jti="jti",
        iat=NOW,
        exp=NOW + timedelta(minutes=5),
    )
    reason(
        jwt.encode(claims, attacker, algorithm="RS256", headers={"kid": KEY_ID}),
        TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS,
    )


def test_token_older_than_configured_maximum_is_rejected():
    old = token(iat=NOW - timedelta(minutes=10), exp=NOW + timedelta(minutes=5))
    with pytest.raises(TokenVerificationError) as captured:
        verifier(maximum_token_age_seconds=300).verify(old, verified_at=NOW)
    assert captured.value.reason is TokenVerificationReason.TOKEN_TOO_OLD


def test_malformed_and_oversized_tokens_are_rejected():
    reason("not-a-token", TokenVerificationReason.MALFORMED_TOKEN)
    reason("x" * 32769, TokenVerificationReason.MALFORMED_TOKEN)


def provider_token(*, identifier_claim, identifier_value="provider-token-id"):
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "subject-128",
        identifier_claim: identifier_value,
        "iat": NOW,
        "exp": NOW + timedelta(minutes=5),
    }
    return jwt.encode(
        claims,
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )


def entra_verifier(**overrides):
    values = {
        "issuer": ENTRA_ISSUER,
        "audience": str(ENTRA_API_APPLICATION_ID),
        "token_identifier_claim": "uti",
        "token_profile": "microsoft_entra_v2",
        "microsoft_entra_tenant_id": ENTRA_TENANT_ID,
        "microsoft_entra_api_application_id": ENTRA_API_APPLICATION_ID,
        "microsoft_entra_required_delegated_scope": (
            ENTRA_REQUIRED_DELEGATED_SCOPE
        ),
        "microsoft_entra_calling_client_application_id": (
            ENTRA_CALLING_CLIENT_APPLICATION_ID
        ),
        "microsoft_entra_required_azpacr": ENTRA_REQUIRED_AZPACR,
    }
    values.update(overrides)
    return verifier(**values)


def entra_claims(**overrides):
    claims = {
        "iss": ENTRA_ISSUER,
        "aud": str(ENTRA_API_APPLICATION_ID),
        "sub": "subject-128",
        "uti": "entra-token-id",
        "iat": NOW,
        "exp": NOW + timedelta(minutes=5),
        "tid": str(ENTRA_TENANT_ID),
        "ver": "2.0",
        "scp": ENTRA_REQUIRED_DELEGATED_SCOPE,
        "azp": str(ENTRA_CALLING_CLIENT_APPLICATION_ID),
        "azpacr": ENTRA_REQUIRED_AZPACR,
    }
    claims.update(overrides)
    return claims


def signed_entra_token(claims=None, **overrides):
    payload = entra_claims() if claims is None else dict(claims)
    payload.update(overrides)
    return jwt.encode(
        payload,
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )


def test_microsoft_entra_uti_profile_returns_the_configured_token_identifier():
    result = verifier(token_identifier_claim="uti").verify(
        provider_token(identifier_claim="uti"),
        verified_at=NOW,
    )
    assert result.token_id == "provider-token-id"
    assert required_token_claims("uti") == (
        "exp",
        "iat",
        "iss",
        "aud",
        "sub",
        "uti",
    )


def test_microsoft_entra_v2_profile_binds_exact_tenant_version_and_uti():
    result = entra_verifier().verify(signed_entra_token(), verified_at=NOW)
    assert result.token_profile == "microsoft_entra_v2"
    assert result.microsoft_entra_tenant_id == ENTRA_TENANT_ID
    assert result.microsoft_entra_api_application_id == ENTRA_API_APPLICATION_ID
    assert (
        result.microsoft_entra_delegated_scope
        == ENTRA_REQUIRED_DELEGATED_SCOPE
    )
    assert (
        result.microsoft_entra_calling_client_application_id
        == ENTRA_CALLING_CLIENT_APPLICATION_ID
    )
    assert result.microsoft_entra_azpacr == ENTRA_REQUIRED_AZPACR
    assert result.token_version == "2.0"
    assert required_token_claims("uti", "microsoft_entra_v2") == (
        "exp",
        "iat",
        "iss",
        "aud",
        "sub",
        "uti",
        "tid",
        "ver",
        "scp",
        "azp",
        "azpacr",
    )


@pytest.mark.parametrize(
    "claims",
    [
        {"tid": str(ENTRA_TENANT_ID)},
        {"ver": "2.0"},
        {"tid": str(uuid4()), "ver": "2.0"},
        {"tid": str(ENTRA_TENANT_ID), "ver": "1.0"},
        {"tid": "not-a-guid", "ver": "2.0"},
    ],
)
def test_microsoft_entra_v2_profile_rejects_missing_or_mismatched_binding(claims):
    payload = entra_claims()
    payload.pop("tid")
    payload.pop("ver")
    payload.update(claims)
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(
            signed_entra_token(payload),
            verified_at=NOW,
        )
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


@pytest.mark.parametrize(
    "overrides",
    [
        {"token_profile": "microsoft_entra_v2"},
        {
            "token_profile": "microsoft_entra_v2",
            "token_identifier_claim": "jti",
            "microsoft_entra_tenant_id": ENTRA_TENANT_ID,
            "microsoft_entra_api_application_id": ENTRA_API_APPLICATION_ID,
            "microsoft_entra_required_delegated_scope": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "microsoft_entra_calling_client_application_id": (
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "microsoft_entra_required_azpacr": ENTRA_REQUIRED_AZPACR,
        },
        {"microsoft_entra_tenant_id": ENTRA_TENANT_ID},
        {"microsoft_entra_api_application_id": ENTRA_API_APPLICATION_ID},
        {
            "microsoft_entra_required_delegated_scope": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            )
        },
        {
            "microsoft_entra_calling_client_application_id": (
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            )
        },
        {"microsoft_entra_required_azpacr": ENTRA_REQUIRED_AZPACR},
        {
            "issuer": ISSUER,
            "token_profile": "microsoft_entra_v2",
            "token_identifier_claim": "uti",
            "microsoft_entra_tenant_id": ENTRA_TENANT_ID,
            "microsoft_entra_api_application_id": ENTRA_API_APPLICATION_ID,
            "microsoft_entra_required_delegated_scope": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "microsoft_entra_calling_client_application_id": (
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "microsoft_entra_required_azpacr": ENTRA_REQUIRED_AZPACR,
        },
        {
            "issuer": ENTRA_ISSUER,
            "token_profile": "microsoft_entra_v2",
            "token_identifier_claim": "uti",
            "microsoft_entra_tenant_id": ENTRA_TENANT_ID,
            "microsoft_entra_required_delegated_scope": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "microsoft_entra_calling_client_application_id": (
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "microsoft_entra_required_azpacr": ENTRA_REQUIRED_AZPACR,
        },
        {
            "issuer": ENTRA_ISSUER,
            "audience": AUDIENCE,
            "token_profile": "microsoft_entra_v2",
            "token_identifier_claim": "uti",
            "microsoft_entra_tenant_id": ENTRA_TENANT_ID,
            "microsoft_entra_api_application_id": ENTRA_API_APPLICATION_ID,
            "microsoft_entra_required_delegated_scope": (
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            "microsoft_entra_calling_client_application_id": (
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "microsoft_entra_required_azpacr": ENTRA_REQUIRED_AZPACR,
        },
        {
            "issuer": ENTRA_ISSUER,
            "audience": str(ENTRA_API_APPLICATION_ID),
            "token_profile": "microsoft_entra_v2",
            "token_identifier_claim": "uti",
            "microsoft_entra_tenant_id": ENTRA_TENANT_ID,
            "microsoft_entra_api_application_id": ENTRA_API_APPLICATION_ID,
            "microsoft_entra_required_delegated_scope": "wrong_scope",
            "microsoft_entra_calling_client_application_id": (
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            "microsoft_entra_required_azpacr": ENTRA_REQUIRED_AZPACR,
        },
        {"token_profile": "microsoft_entra"},
    ],
)
def test_incomplete_or_unknown_token_profile_configuration_is_rejected(overrides):
    with pytest.raises(ValidationError):
        config(**overrides)


@pytest.mark.parametrize(
    "configured_scope",
    [None, "", "Access_as_user", " access_as_user", "access_as_user ", True],
)
def test_microsoft_entra_v2_configuration_requires_exact_delegated_scope(
    configured_scope,
):
    with pytest.raises(ValidationError):
        config(
            issuer=ENTRA_ISSUER,
            audience=str(ENTRA_API_APPLICATION_ID),
            token_identifier_claim="uti",
            token_profile="microsoft_entra_v2",
            microsoft_entra_tenant_id=ENTRA_TENANT_ID,
            microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
            microsoft_entra_required_delegated_scope=configured_scope,
            microsoft_entra_calling_client_application_id=(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            microsoft_entra_required_azpacr=ENTRA_REQUIRED_AZPACR,
        )


@pytest.mark.parametrize(
    "calling_client_application_id",
    [
        None,
        UUID(int=0),
        ENTRA_TENANT_ID,
        ENTRA_API_APPLICATION_ID,
    ],
)
def test_microsoft_entra_v2_configuration_requires_one_distinct_calling_client(
    calling_client_application_id,
):
    with pytest.raises(ValidationError):
        config(
            issuer=ENTRA_ISSUER,
            audience=str(ENTRA_API_APPLICATION_ID),
            token_identifier_claim="uti",
            token_profile="microsoft_entra_v2",
            microsoft_entra_tenant_id=ENTRA_TENANT_ID,
            microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
            microsoft_entra_required_delegated_scope=(
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            microsoft_entra_calling_client_application_id=(
                calling_client_application_id
            ),
            microsoft_entra_required_azpacr=ENTRA_REQUIRED_AZPACR,
        )


@pytest.mark.parametrize(
    "azpacr",
    [None, 0, 0.0, False, True, "", "00", "+0", "-0", "0.0", "０", "1", "2"],
)
def test_microsoft_entra_v2_configuration_requires_exact_public_client_azpacr(
    azpacr,
):
    with pytest.raises(ValidationError):
        config(
            issuer=ENTRA_ISSUER,
            audience=str(ENTRA_API_APPLICATION_ID),
            token_identifier_claim="uti",
            token_profile="microsoft_entra_v2",
            microsoft_entra_tenant_id=ENTRA_TENANT_ID,
            microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
            microsoft_entra_required_delegated_scope=(
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            microsoft_entra_calling_client_application_id=(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            microsoft_entra_required_azpacr=azpacr,
        )


@pytest.mark.parametrize(
    "issuer",
    [
        f"http://synthetic.ciamlogin.com/{ENTRA_TENANT_ID}/v2.0",
        f"https://user@synthetic.ciamlogin.com/{ENTRA_TENANT_ID}/v2.0",
        f"https://synthetic.ciamlogin.com:0/{ENTRA_TENANT_ID}/v2.0",
        f"https://synthetic.ciamlogin.com:notaport/{ENTRA_TENANT_ID}/v2.0",
        f"https://synthetic.ciamlogin.com/{ENTRA_TENANT_ID}/v2.0/",
        f"https://synthetic.ciamlogin.com/{ENTRA_TENANT_ID}/v2.0?x=1",
        f"https://synthetic.ciamlogin.com/{ENTRA_TENANT_ID}/v2.0#fragment",
        f"https://synthetic.ciamlogin.com/{ENTRA_TENANT_ID}/v1.0",
        "https://synthetic.ciamlogin.com/common/v2.0",
        f"https://synthetic.ciamlogin.com\\evil/{ENTRA_TENANT_ID}/v2.0",
    ],
)
def test_microsoft_entra_v2_profile_rejects_non_exact_issuer_urls(issuer):
    with pytest.raises(ValidationError):
        config(
            issuer=issuer,
            audience=str(ENTRA_API_APPLICATION_ID),
            token_identifier_claim="uti",
            token_profile="microsoft_entra_v2",
            microsoft_entra_tenant_id=ENTRA_TENANT_ID,
            microsoft_entra_api_application_id=ENTRA_API_APPLICATION_ID,
            microsoft_entra_required_delegated_scope=(
                ENTRA_REQUIRED_DELEGATED_SCOPE
            ),
            microsoft_entra_calling_client_application_id=(
                ENTRA_CALLING_CLIENT_APPLICATION_ID
            ),
            microsoft_entra_required_azpacr=ENTRA_REQUIRED_AZPACR,
        )


@pytest.mark.parametrize(
    "token_audience",
    [
        str(uuid4()),
        f"api://{ENTRA_API_APPLICATION_ID}",
        [str(ENTRA_API_APPLICATION_ID)],
        [str(ENTRA_API_APPLICATION_ID), "another-audience"],
    ],
)
def test_microsoft_entra_v2_profile_rejects_non_exact_api_audience(token_audience):
    candidate = signed_entra_token(aud=token_audience)
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(candidate, verified_at=NOW)
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


@pytest.mark.parametrize(
    "calling_client",
    [
        str(ENTRA_CALLING_CLIENT_APPLICATION_ID).upper(),
        str(ENTRA_CALLING_CLIENT_APPLICATION_ID).replace("c", "C").replace("d", "D"),
    ],
)
def test_microsoft_entra_v2_profile_accepts_canonical_case_variant_azp(
    calling_client,
):
    result = entra_verifier().verify(
        signed_entra_token(azp=calling_client),
        verified_at=NOW,
    )
    assert (
        result.microsoft_entra_calling_client_application_id
        == ENTRA_CALLING_CLIENT_APPLICATION_ID
    )


def test_microsoft_entra_v2_profile_requires_the_signed_azp_claim():
    claims = entra_claims()
    claims.pop("azp")
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(signed_entra_token(claims), verified_at=NOW)
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


@pytest.mark.parametrize(
    "calling_client",
    [
        None,
        7,
        True,
        [str(ENTRA_CALLING_CLIENT_APPLICATION_ID)],
        {"value": str(ENTRA_CALLING_CLIENT_APPLICATION_ID)},
        "",
        f" {ENTRA_CALLING_CLIENT_APPLICATION_ID}",
        f"{ENTRA_CALLING_CLIENT_APPLICATION_ID} ",
        f"{{{ENTRA_CALLING_CLIENT_APPLICATION_ID}}}",
        f"urn:uuid:{ENTRA_CALLING_CLIENT_APPLICATION_ID}",
        ENTRA_CALLING_CLIENT_APPLICATION_ID.hex,
        str(UUID(int=0)),
        str(uuid4()),
        str(ENTRA_TENANT_ID),
        str(ENTRA_API_APPLICATION_ID),
    ],
)
def test_microsoft_entra_v2_profile_rejects_non_exact_or_unapproved_azp(
    calling_client,
):
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(
            signed_entra_token(azp=calling_client),
            verified_at=NOW,
        )
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


@pytest.mark.parametrize("alias", ["appid", "client_id"])
def test_microsoft_entra_calling_client_alias_cannot_replace_azp(alias):
    claims = entra_claims()
    claims.pop("azp")
    claims[alias] = str(ENTRA_CALLING_CLIENT_APPLICATION_ID)
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(signed_entra_token(claims), verified_at=NOW)
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


def test_microsoft_entra_authoritative_azp_is_not_replaced_by_aliases():
    result = entra_verifier().verify(
        signed_entra_token(
            appid=str(uuid4()),
            client_id=str(uuid4()),
        ),
        verified_at=NOW,
    )
    assert (
        result.microsoft_entra_calling_client_application_id
        == ENTRA_CALLING_CLIENT_APPLICATION_ID
    )


def test_microsoft_entra_v2_profile_requires_the_signed_azpacr_claim():
    claims = entra_claims()
    claims.pop("azpacr")
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(signed_entra_token(claims), verified_at=NOW)
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


@pytest.mark.parametrize(
    "azpacr",
    [
        None,
        0,
        0.0,
        False,
        True,
        [],
        {},
        "",
        " ",
        " 0",
        "0 ",
        "00",
        "+0",
        "-0",
        "0.0",
        "０",
        "1",
        "2",
        "public",
    ],
)
def test_microsoft_entra_v2_profile_requires_exact_public_client_azpacr(azpacr):
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(
            signed_entra_token(azpacr=azpacr),
            verified_at=NOW,
        )
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


@pytest.mark.parametrize("alias", ["appidacr", "acr", "amr", "client_authentication_method"])
def test_microsoft_entra_azpacr_alias_cannot_replace_the_signed_claim(alias):
    claims = entra_claims()
    claims.pop("azpacr")
    claims[alias] = ENTRA_REQUIRED_AZPACR
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(signed_entra_token(claims), verified_at=NOW)
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


def test_microsoft_entra_authoritative_azpacr_ignores_conflicting_aliases():
    result = entra_verifier().verify(
        signed_entra_token(
            appidacr="2",
            acr="1",
            amr=["certificate"],
            client_authentication_method="secret",
        ),
        verified_at=NOW,
    )
    assert result.microsoft_entra_azpacr == ENTRA_REQUIRED_AZPACR


def test_microsoft_entra_v2_profile_requires_the_signed_scp_claim():
    claims = entra_claims()
    claims.pop("scp")
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(signed_entra_token(claims), verified_at=NOW)
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


@pytest.mark.parametrize(
    "supplied_scope",
    [
        None,
        7,
        True,
        "",
        "Access_as_user",
        " access_as_user",
        "access_as_user ",
        "access_as_user\t",
        "access_as_user\n",
        "access_as_user extra_scope",
        "extra_scope access_as_user",
        "access_as_user access_as_user",
        ["access_as_user"],
        {"value": "access_as_user"},
    ],
)
def test_microsoft_entra_v2_profile_requires_one_exact_string_scope(
    supplied_scope,
):
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(
            signed_entra_token(scp=supplied_scope),
            verified_at=NOW,
        )
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


def test_microsoft_entra_scope_alias_cannot_replace_the_signed_scp_claim():
    claims = entra_claims()
    claims.pop("scp")
    claims["scope"] = ENTRA_REQUIRED_DELEGATED_SCOPE
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(signed_entra_token(claims), verified_at=NOW)
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


@pytest.mark.parametrize(
    "roles",
    [
        [],
        ["access_as_user"],
        ["Engineer4Me.Administrator"],
        "access_as_user",
        None,
    ],
)
def test_microsoft_entra_v2_profile_rejects_any_roles_claim(roles):
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(
            signed_entra_token(roles=roles),
            verified_at=NOW,
        )
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


def test_microsoft_entra_roles_only_application_token_is_rejected():
    claims = entra_claims(roles=["access_as_user"])
    claims.pop("scp")
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(signed_entra_token(claims), verified_at=NOW)
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


def test_microsoft_entra_roleless_application_token_is_rejected():
    claims = entra_claims(idtyp="app")
    claims.pop("scp")
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(signed_entra_token(claims), verified_at=NOW)
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


def test_microsoft_entra_explicit_user_token_type_is_accepted():
    result = entra_verifier().verify(
        signed_entra_token(idtyp="user"),
        verified_at=NOW,
    )
    assert result.microsoft_entra_delegated_scope == ENTRA_REQUIRED_DELEGATED_SCOPE


@pytest.mark.parametrize(
    "token_type",
    ["app", "service", "User", "", None, True, ["user"]],
)
def test_microsoft_entra_non_user_token_type_is_rejected(token_type):
    with pytest.raises(TokenVerificationError) as captured:
        entra_verifier().verify(
            signed_entra_token(idtyp=token_type),
            verified_at=NOW,
        )
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


def test_unrelated_signed_claims_do_not_replace_or_expand_delegated_access():
    result = entra_verifier().verify(
        signed_entra_token(
            custom_permission="administrator",
            groups=["synthetic-group"],
        ),
        verified_at=NOW,
    )
    assert result.microsoft_entra_delegated_scope == ENTRA_REQUIRED_DELEGATED_SCOPE


def test_provider_neutral_profile_does_not_inherit_entra_claim_restrictions():
    result = verifier().verify(
        token(
            scp="provider-specific-scope",
            roles=["provider-role"],
            idtyp="app",
            azp="provider-specific-client",
            azpacr="2",
            appid="provider-specific-alias",
            client_id="provider-specific-client-alias",
        ),
        verified_at=NOW,
    )
    assert result.token_profile == "provider_neutral"
    assert result.microsoft_entra_delegated_scope is None
    assert result.microsoft_entra_calling_client_application_id is None
    assert result.microsoft_entra_azpacr is None


@pytest.mark.parametrize("azpacr", [None, "1", "2"])
def test_verified_entra_claims_cannot_forge_public_client_evidence(azpacr):
    result = entra_verifier().verify(signed_entra_token(), verified_at=NOW)
    values = result.model_dump()
    values["microsoft_entra_azpacr"] = azpacr
    with pytest.raises(ValidationError):
        VerifiedTokenClaims(**values)


@pytest.mark.parametrize(
    ("configured_claim", "supplied_claim"),
    [("jti", "uti"), ("uti", "jti")],
)
def test_token_identifier_alias_is_not_used_as_an_implicit_fallback(
    configured_claim,
    supplied_claim,
):
    with pytest.raises(TokenVerificationError) as captured:
        verifier(token_identifier_claim=configured_claim).verify(
            provider_token(identifier_claim=supplied_claim),
            verified_at=NOW,
        )
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


@pytest.mark.parametrize(
    ("configured_claim", "expected_token_id"),
    [("jti", "standard-token-id"), ("uti", "entra-token-id")],
)
def test_configured_identifier_remains_authoritative_when_alias_is_also_present(
    configured_claim,
    expected_token_id,
):
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "subject-128",
        "jti": "standard-token-id",
        "uti": "entra-token-id",
        "iat": NOW,
        "exp": NOW + timedelta(minutes=5),
    }
    value = jwt.encode(
        claims,
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )
    result = verifier(token_identifier_claim=configured_claim).verify(
        value,
        verified_at=NOW,
    )
    assert result.token_id == expected_token_id


@pytest.mark.parametrize("identifier_value", [None, 7, True, "", "x" * 501])
def test_microsoft_entra_uti_must_be_one_bounded_string(identifier_value):
    with pytest.raises(TokenVerificationError) as captured:
        verifier(token_identifier_claim="uti").verify(
            provider_token(
                identifier_claim="uti",
                identifier_value=identifier_value,
            ),
            verified_at=NOW,
        )
    assert captured.value.reason is TokenVerificationReason.INVALID_SIGNATURE_OR_CLAIMS


@pytest.mark.parametrize("claim", ["UTI", "uti ", "sid", "oid", "*"])
def test_unreviewed_token_identifier_claim_configuration_is_rejected(claim):
    with pytest.raises(ValidationError):
        config(token_identifier_claim=claim)
