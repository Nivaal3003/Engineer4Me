"""Focused tests for controlled JWKS resolution and rotation."""

from datetime import UTC, datetime

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from app.security.jwks_resolver import ControlledJWKSResolver, JWKSConfiguration, JWKSResolutionError, TrustedJWKSResponse


URL="https://identity.engineer4me.test/.well-known/jwks.json"


def jwk(kid="key-129",alg="RS256",use="sig"):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key()
    data=jwt.algorithms.RSAAlgorithm.to_jwk(key,as_dict=True)
    data.update(kid=kid,alg=alg,use=use);return data


class Loader:
    def __init__(self,*documents): self.documents=list(documents);self.calls=[]
    def __call__(self,url): self.calls.append(url);document=self.documents.pop(0) if len(self.documents)>1 else self.documents[0];return TrustedJWKSResponse(source_url=url,fetched_at=datetime.now(UTC),document=document)


def resolver(loader,**overrides): return ControlledJWKSResolver(config=JWKSConfiguration(source_url=URL,cache_seconds=300,**overrides),loader=loader)


def test_resolves_rsa_signing_key_and_reuses_cache():
    loader=Loader({"keys":[jwk()]});value=resolver(loader)
    assert value.resolve(key_id="key-129",algorithm="RS256") is not None
    assert value.resolve(key_id="key-129",algorithm="RS256") is not None
    assert loader.calls==[URL]


def test_unknown_kid_forces_one_rotation_refresh():
    loader=Loader({"keys":[jwk("old")]},{"keys":[jwk("new")]});value=resolver(loader)
    assert value.resolve(key_id="old",algorithm="RS256") is not None
    assert value.resolve(key_id="new",algorithm="RS256") is not None
    assert loader.calls==[URL,URL]


@pytest.mark.parametrize(
    "url",
    [
        "http://identity.test/jwks",
        "/relative/jwks",
        "https://user:pass@identity.test/jwks",
        "https://@identity.test/jwks",
        "https://identity.test/jwks#fragment",
        "https://identity.test/jwks#",
        "https://identity.test/jwks?version=1",
        "https://identity.test/jwks?",
        "https://[invalid",
        "https://identity.test:notaport/jwks",
        "https://identity.test:99999/jwks",
        "https://identity.test:0/jwks",
        "https://identity.test:",
        "https://identity .test/jwks",
        "https://identity.test\\unexpected/jwks",
        "https://identity.test/jw\nks",
    ],
)
def test_source_url_is_fail_closed(url):
    with pytest.raises(ValidationError): JWKSConfiguration(source_url=url)


@pytest.mark.parametrize(
    "url",
    [
        "https://identity.test:8443/jwks",
        "https://[2001:db8::1]:8443/jwks",
    ],
)
def test_source_url_preserves_valid_ports_and_ipv6(url):
    assert JWKSConfiguration(source_url=url).source_url == url


def test_symmetric_algorithm_is_never_resolved():
    loader=Loader({"keys":[jwk()]});value=resolver(loader)
    assert value.resolve(key_id="key-129",algorithm="HS256") is None
    assert loader.calls==[]


def test_duplicate_kid_is_rejected_even_across_algorithms():
    loader=Loader({"keys":[jwk("duplicate"),jwk("duplicate")]})
    with pytest.raises(JWKSResolutionError,match="unique"): resolver(loader).resolve(key_id="duplicate",algorithm="RS256")


def test_non_signing_keys_are_ignored_and_empty_usable_set_rejected():
    loader=Loader({"keys":[jwk(use="enc")]})
    with pytest.raises(JWKSResolutionError,match="no usable"): resolver(loader).resolve(key_id="key-129",algorithm="RS256")


def test_key_type_algorithm_mismatch_is_rejected():
    data=jwk();data["kty"]="EC";loader=Loader({"keys":[data]})
    with pytest.raises(JWKSResolutionError,match="inconsistent"): resolver(loader).resolve(key_id="key-129",algorithm="RS256")


def test_missing_empty_and_oversized_key_sets_are_rejected():
    for document in ({},{"keys":[]},{"keys":[jwk(str(index)) for index in range(3)]}):
        value=resolver(Loader(document),maximum_keys=2)
        with pytest.raises(JWKSResolutionError): value.resolve(key_id="key-129",algorithm="RS256")


def test_loader_source_substitution_is_rejected():
    response=TrustedJWKSResponse(source_url="https://attacker.invalid/jwks",fetched_at=datetime.now(UTC),document={"keys":[jwk()]})
    loader=lambda _url: response
    with pytest.raises(JWKSResolutionError,match="unexpected source"): resolver(loader).resolve(key_id="key-129",algorithm="RS256")
