"""Dependency contract for the Phase 8 JWT verification boundary."""

from importlib.metadata import version

import cryptography
import jwt


def test_pyjwt_and_cryptography_are_installed():
    assert tuple(int(item) for item in version("PyJWT").split(".")[:2]) >= (2, 13)
    assert cryptography.__version__
    assert callable(jwt.decode)


def test_none_algorithm_is_not_in_asymmetric_allow_list():
    configured_asymmetric_algorithms = ("RS256", "ES256")
    assert "none" not in configured_asymmetric_algorithms
    assert all(not item.startswith("HS") for item in configured_asymmetric_algorithms)
