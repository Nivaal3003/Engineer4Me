"""Pure Step 236 compatibility probe for bounded official metadata evidence.

The sibling loader owns live HTTPS.  This module accepts only its closed,
bounded evidence object, binds the exact Step 235 chain, and verifies the
reviewed direct/supporting package and toolchain metadata tuple.  It does not
perform network, filesystem, subprocess, package-manager, browser, OAuth, or
configuration operations.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import model_validator

from app.security.authentication_entra_calling_client_msal_browser_frontend_host_ecosystem_registry_http_loader import (
    DIRECT_PACKAGES,
    MAX_AGGREGATE_RESPONSE_BYTES,
    MAX_REQUEST_COUNT,
    NODE_DISTRIBUTION_ORIGIN,
    NODE_VERSION,
    NODE_VERSION_TAG,
    NPM_REGISTRY_ORIGIN,
    NPM_VERSION,
    SELECTED_PACKAGES,
    TOOLCHAIN_NPM_PACKAGE,
    TRANSITIVE_ANCHOR_PACKAGES,
    BoundedOfficialHttpResponse,
    LiveEcosystemRegistryEvidence,
    is_attested_live_ecosystem_registry_evidence,
    official_request_contract_projection,
)
from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_"
    "ecosystem_official_registry_compatibility_authorization"
)
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_controlled_official_ecosystem_registry_compatibility_proof"
SCOPE = (
    "exact_step235_chain_plus_live_official_selected_package_and_node_"
    "toolchain_metadata_compatibility_proof"
)
STATUS = (
    "official_registry_selected_metadata_compatible_lock_and_"
    "materialization_remain_blocked"
)
SELECTION_PROFILE = "engineer4me_frontend_ecosystem_exact_tuple_2026_08_19_v1"
CURRENT_NPM_SIGNING_KEY_ID = (
    "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U"
)
CURRENT_NPM_SIGNING_KEY_MATERIAL = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY6Ya7W++7aUPzvMTrezH6Ycx3c+HOKYCcNGybJZSCJq/fd7Qa8uuAKtdIkUQtQiEKERhAmE5lMMJhP8OkDOa2g=="
)
CURRENT_NPM_SIGNING_KEY_TYPE = "ecdsa-sha2-nistp256"
CURRENT_NPM_SIGNING_KEY_SCHEME = "ecdsa-sha2-nistp256"
NODE_LTS_CODENAME = "Krypton"
NODE_RELEASE_DATE = "2026-08-03"
NODE_SHASUMS_BODY_SHA256 = (
    "be0629ee2bcd8e40bb856abdd3407f0762101b76bd60a36b8867f637733631c0"
)

STEP235_PACKAGE_MANIFEST_SHA256 = (
    "ffd92f5353e6e41c545b96d18c390eec2b6354776c08ee45544684a85e4a63f1"
)
STEP235_ACCEPTED_STATE_MANIFEST_SHA256 = (
    "09b211df4fae291a33b3509d83dceebaa1e9742d4995c331324cfdf64e7ed023"
)
STEP235_ARCHITECTURE_SELECTION_READINESS_SHA256 = (
    "7dcf0b63695a5857f878264f19c5c4248cea419c6e2bf66896a266c28dac1e22"
)
STEP235_ARCHITECTURE_SELECTION_TEST_SHA256 = (
    "e6cfa249fad7fd40696cd977971674fad4a52f9e6671f1e82bf561e8f5b8959f"
)
STEP235_CANONICAL_RECEIPT_SHA256 = (
    "6b70abd5db7496af97884707a64c52e272c62292de2568aec8adb6a505cf5ee4"
)
STEP235_READINESS_DOCUMENT_SHA256 = (
    "10e40546438acece101c6be7490772a47cf159dc19283eb0c9693ed4bbe9d723"
)
STEP235_ARCHITECTURE_PLAN_SHA256 = (
    "d6ffd2561b069d69f16db836b32f58ff29e5d6fa021559160051035d5b3e8a37"
)
STEP235_SECURITY_PLAN_SHA256 = (
    "5e1edc9034c672ee81c451641852a20661e4724c80742601ed6d7153c79d3ba8"
)
STEP235_EXPERIENCE_AND_TEST_PLAN_SHA256 = (
    "cf47c7b86e4dcebcea1ca442c8d463c98cecbe5bb9fd3b22883f0f60c905d5be"
)
STEP235_DEFERRED_GATE_PLAN_SHA256 = (
    "7253144525f0f93e70d92dd94074aee696389fb54b30bacb1d064caf021e93c7"
)

MAX_AUTHORIZATION_BYTES = 16_384
MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 200_000


@dataclass(frozen=True, slots=True)
class ExpectedPackageMetadata:
    license: str
    integrity: str
    signature_count: int
    provenance_present: bool


EXPECTED_PACKAGE_METADATA: dict[str, ExpectedPackageMetadata] = {
    "react": ExpectedPackageMetadata(
        "MIT",
        "sha512-PWaYA1L/q9u2u7xYQi+Y3L3Yfnie7XyLeaJICV1MGD6LprsBxcAqGjYyr0eY3p+QdsA+x/Irkt4Qif8D63+Sbw==",
        1,
        True,
    ),
    "react-dom": ExpectedPackageMetadata(
        "MIT",
        "sha512-rVprimfGBG3DR+Tq0IQG2DT5PxKth1WIGDmj5yPmlzr4YBe7uyE+Du4oVqTDXZSHGGGXRtTJEGSSePyQCMBglQ==",
        1,
        True,
    ),
    "react-router": ExpectedPackageMetadata(
        "MIT",
        "sha512-qyPMvW83jGIct3yiieisxdk9M745anqhpIMKN5m1t6yBMfgVPpt77aHOqs5fUlEJRMCGffg9BaQLH9oPVOL7xQ==",
        1,
        True,
    ),
    "@azure/msal-browser": ExpectedPackageMetadata(
        "MIT",
        "sha512-SPTeHYZghdEdRddJzNjhH+CI5MSQtquNYwGJnYXfOHIBRXCmrWimBS85OhwXpXFIlrCtNTbBPm5mPAWRNEoktA==",
        2,
        False,
    ),
    "@azure/msal-common": ExpectedPackageMetadata(
        "MIT",
        "sha512-hgLgfRdbG2AmhXPygebf1KYJEvse86+ZZLWufdiTKaGRYEUqOzHdlf6AS1IiuUCHWbynkgbHc451jSNkbfhWlg==",
        2,
        False,
    ),
    "vite": ExpectedPackageMetadata(
        "MIT",
        "sha512-EU/eS7BH3XROHh2YnBefjM6DBKA6ZeMZEYQbj7NLWg5wHYlhB8B/Mayd5XsgWq+NFYccDOTemRpdETWR6Ka/lw==",
        2,
        True,
    ),
    "@vitejs/plugin-react": ExpectedPackageMetadata(
        "MIT",
        "sha512-BOVzne/NL162sMdResB25mUv+vWMF5NoAjNf09TeGlE7ZpszZWSD3winycicLJw72yeVsoCn/2kOhEuCvEShMA==",
        2,
        True,
    ),
    "typescript": ExpectedPackageMetadata(
        "Apache-2.0",
        "sha512-bGdAIrZ0wiGDo5l8c++HWtbaNCWTS4UTv7RaTH/ThVIgjkveJt83m74bBHMJkuCbslY8ixgLBVZJIOiQlQTjfQ==",
        1,
        False,
    ),
    "@types/node": ExpectedPackageMetadata(
        "MIT",
        "sha512-Dh8vAsV36ig5wa9OX4pXvMc9D3Veibfw2wix0CUwYODLD8nkj9UsLjASr49nPg+2eKzxhBV+v7L8pXvT4e639Q==",
        1,
        False,
    ),
    "@types/react": ExpectedPackageMetadata(
        "MIT",
        "sha512-AnzbBERsrLKtk2XSfTbYRLjQPdy116Sty4q+T+Bp3IC4l6jNBvreVPAHmpq9qhXQM7CXZPjLVmGMw9sy+hxQ3w==",
        2,
        False,
    ),
    "@types/react-dom": ExpectedPackageMetadata(
        "MIT",
        "sha512-Bsc+QHgp+P/F02XDzNCY9jnZNCUuLki36KT7VKrTXXLdHf+vHMNZnW1rVu5DNW/rCK+fya3DATySbLM4yhtKUw==",
        2,
        False,
    ),
    "vitest": ExpectedPackageMetadata(
        "MIT",
        "sha512-fhACrNXUidIbGSBr5FlbuBkO7VWC1ZyLl0DO4CU2DrQoAPxX84Ysxs+HeGQpii5lZWV1Q4gBZTTu49mF+A6Edw==",
        1,
        True,
    ),
    "jsdom": ExpectedPackageMetadata(
        "MIT",
        "sha512-52v7mUVUfNQVYYqE1lcdaymWL0njO7lTLUog6ZvW2U5KsbiLk/GnZlVJ+qx0xfNJZ6Gn+KSpPNE52vurbxZwrA==",
        2,
        True,
    ),
    "@testing-library/react": ExpectedPackageMetadata(
        "MIT",
        "sha512-XU5/SytQM+ykqMnAnvB2umaJNIOsLF3PVv//1Ew4CTcpz0/BRyy/af40qqrt7SjKpDdT1saBMc42CUok5gaw+g==",
        1,
        True,
    ),
    "@testing-library/dom": ExpectedPackageMetadata(
        "MIT",
        "sha512-o4PXJQidqJl82ckFaXUeoAW+XysPLauYI43Abki5hABd853iMhitooc6znOnczgbTYmEP6U6/y1ZyKAIsvMKGg==",
        1,
        False,
    ),
    "@testing-library/jest-dom": ExpectedPackageMetadata(
        "MIT",
        "sha512-oMDTC3oA+6CXSO2JZnvOI7CA6oVub6kij5ggk9ohwye5slmkwxYDXcPOVxgMw/RQlticjtO0C1RZkR97HgrWMw==",
        2,
        True,
    ),
    "@testing-library/user-event": ExpectedPackageMetadata(
        "MIT",
        "sha512-FhqjldLTpteueBaKflhNFlMT3+PM0O5fiBUivht6b9CZ1eesJyy7+g3Jr7XwJzt/Hip3ZG5hWwK1MX1FuDiE4w==",
        2,
        True,
    ),
    "@playwright/test": ExpectedPackageMetadata(
        "Apache-2.0",
        "sha512-DTcUc8qii+cpHvtOwggMtBRMjKZHXYWdw8syRYu2vtzuq4Wxphqq4NfCs5Zt44L6mA8rfDfj+PHnxFc/FeK6mQ==",
        2,
        True,
    ),
    "playwright": ExpectedPackageMetadata(
        "Apache-2.0",
        "sha512-0M+L3LAD8/nm554LOla9Ayx0j0tmFZ0FBcoQ7F1VuVHpM/XpiC8RcDzBQB8W5+hA8L22THxELzeF+2WcUzvcLg==",
        2,
        True,
    ),
    "playwright-core": ExpectedPackageMetadata(
        "Apache-2.0",
        "sha512-wPYSwEBJY9GHraISXqyqtx0na0LpO3XEX7jNDhntbex7tzUS7kLnZsOlFruFJB4Hi/rhDMjXGqHewDZ68nYZVw==",
        2,
        True,
    ),
    "@axe-core/playwright": ExpectedPackageMetadata(
        "MPL-2.0",
        "sha512-6YLx+kxXu5GJceG4ozFg+33a2EMTdjYwWGloJ3sb9Kta5pp+ZNS53uxGVog5JetIY8s++P5UrtX+cri+u0VAVg==",
        2,
        True,
    ),
    "axe-core": ExpectedPackageMetadata(
        "MPL-2.0",
        "sha512-UzGt8zg7Ny8djbYMhxl2zuEevVa7r2gJjYY5Lwr1xM7+XU2nd6CkIWFTVcCIbAP63vSz71NaVyyuSk9lHKcy0A==",
        2,
        True,
    ),
    "npm": ExpectedPackageMetadata(
        "Artistic-2.0",
        "sha512-PurxiZexEHDTE4SSaLI3ZrnbAGiZfeyUcQcxcP5D+hfytNAze/D1IzDuInTn9XVLIbAQUnQuSPXJx02LHjLvQw==",
        1,
        False,
    ),
}


class EntraCallingClientMSALFrontendHostEcosystemCompatibilityError(ValueError):
    """Sanitized Step 236 evidence or compatibility failure."""


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def _bounded_json(body: bytes) -> object:
    if type(body) is not bytes or not body:
        raise ValueError("JSON evidence must be non-empty exact bytes")
    text = body.decode("utf-8", errors="strict")
    value = json.loads(
        text,
        object_pairs_hook=_pairs,
        parse_constant=_reject_constant,
    )
    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ValueError("JSON evidence structure exceeds its approved bound")
        if type(item) is dict:
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is float and not math.isfinite(item):
            raise ValueError("JSON evidence contains a non-finite number")
        elif type(item) not in (str, int, float, bool, type(None)):
            raise ValueError("JSON evidence contains an unsupported value")
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _framed(domain: str, value: object) -> str:
    return hashlib.sha256(
        b"Engineer4Me-Step236-v1\x00"
        + domain.encode("ascii")
        + b"\x00"
        + _canonical(value)
    ).hexdigest()


class EntraCallingClientMSALFrontendHostEcosystemCompatibilityAuthorization(
    SecurityModel
):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_ecosystem_official_registry_compatibility_authorization"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_controlled_official_ecosystem_registry_compatibility_proof"
    ]
    approved_step235_package_manifest_sha256: str
    approved_step235_accepted_state_manifest_sha256: str
    approved_step235_architecture_selection_readiness_sha256: str
    approved_step235_architecture_selection_test_sha256: str
    approved_step235_canonical_receipt_sha256: str
    approved_step235_readiness_document_sha256: str
    approved_step235_architecture_plan_sha256: str
    approved_step235_security_plan_sha256: str
    approved_step235_experience_and_test_plan_sha256: str
    approved_step235_deferred_gate_plan_sha256: str
    selection_profile: Literal[
        "engineer4me_frontend_ecosystem_exact_tuple_2026_08_19_v1"
    ]

    @model_validator(mode="before")
    @classmethod
    def validate_exact_wire_contract(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError("ecosystem authorization must be an exact object")
        expected = {
            "document_type": str,
            "schema_version": int,
            "source": str,
            "approved_step235_package_manifest_sha256": str,
            "approved_step235_accepted_state_manifest_sha256": str,
            "approved_step235_architecture_selection_readiness_sha256": str,
            "approved_step235_architecture_selection_test_sha256": str,
            "approved_step235_canonical_receipt_sha256": str,
            "approved_step235_readiness_document_sha256": str,
            "approved_step235_architecture_plan_sha256": str,
            "approved_step235_security_plan_sha256": str,
            "approved_step235_experience_and_test_plan_sha256": str,
            "approved_step235_deferred_gate_plan_sha256": str,
            "selection_profile": str,
        }
        if set(value) != set(expected) or any(
            type(value[name]) is not expected_type
            for name, expected_type in expected.items()
        ):
            raise ValueError("ecosystem authorization keys or types are not exact")
        return value

    @model_validator(mode="after")
    def validate_approved_identities(
        self,
    ) -> EntraCallingClientMSALFrontendHostEcosystemCompatibilityAuthorization:
        expected = {
            "approved_step235_package_manifest_sha256": STEP235_PACKAGE_MANIFEST_SHA256,
            "approved_step235_accepted_state_manifest_sha256": STEP235_ACCEPTED_STATE_MANIFEST_SHA256,
            "approved_step235_architecture_selection_readiness_sha256": STEP235_ARCHITECTURE_SELECTION_READINESS_SHA256,
            "approved_step235_architecture_selection_test_sha256": STEP235_ARCHITECTURE_SELECTION_TEST_SHA256,
            "approved_step235_canonical_receipt_sha256": STEP235_CANONICAL_RECEIPT_SHA256,
            "approved_step235_readiness_document_sha256": STEP235_READINESS_DOCUMENT_SHA256,
            "approved_step235_architecture_plan_sha256": STEP235_ARCHITECTURE_PLAN_SHA256,
            "approved_step235_security_plan_sha256": STEP235_SECURITY_PLAN_SHA256,
            "approved_step235_experience_and_test_plan_sha256": STEP235_EXPERIENCE_AND_TEST_PLAN_SHA256,
            "approved_step235_deferred_gate_plan_sha256": STEP235_DEFERRED_GATE_PLAN_SHA256,
        }
        if any(
            not _is_sha256(getattr(self, name))
            or getattr(self, name) != digest
            for name, digest in expected.items()
        ):
            raise ValueError("ecosystem authorization identity is invalid")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostEcosystemCompatibilityReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    readiness_status: str
    selection_profile: str
    approved_step235_package_manifest_sha256: str
    approved_step235_accepted_state_manifest_sha256: str
    approved_step235_architecture_selection_readiness_sha256: str
    approved_step235_architecture_selection_test_sha256: str
    approved_step235_canonical_receipt_sha256: str
    approved_step235_readiness_document_sha256: str
    approved_step235_architecture_plan_sha256: str
    approved_step235_security_plan_sha256: str
    approved_step235_experience_and_test_plan_sha256: str
    approved_step235_deferred_gate_plan_sha256: str
    node_version: str
    bundled_npm_version: str
    node_lts_codename: str
    manifest_direct_package_count: int
    mandatory_transitive_anchor_count: int
    frontend_ecosystem_metadata_count: int
    registry_package_metadata_count: int
    official_http_request_count: int
    aggregate_response_bytes: int
    signature_entry_count: int
    signature_verified_package_count: int
    provenance_present_count: int
    provenance_absence_disposition_count: int
    deprecated_package_count: int
    selected_metadata_advisory_count: int
    peer_relationship_count: int
    optional_peer_absence_disposition_count: int
    selected_package_tuple_sha256: str
    package_metadata_projection_sha256: str
    package_response_body_set_sha256: str
    official_response_body_set_sha256: str
    engine_compatibility_projection_sha256: str
    peer_compatibility_projection_sha256: str
    dependency_anchor_projection_sha256: str
    license_deprecation_projection_sha256: str
    integrity_projection_sha256: str
    signature_projection_sha256: str
    provenance_projection_sha256: str
    advisory_projection_sha256: str
    node_release_projection_sha256: str
    node_shasums_projection_sha256: str
    exact_step235_chain_bound: bool
    live_official_network_evidence_processed: bool
    official_npm_registry_origin_required: bool
    official_node_distribution_origin_required: bool
    redirect_proxy_credential_and_retry_paths_forbidden: bool
    response_request_and_deadline_bounds_enforced: bool
    exact_manifest_direct_versions_selected: bool
    exact_transitive_anchor_versions_bound: bool
    exact_node_patch_and_bundled_npm_selected: bool
    react_and_react_dom_version_parity_verified: bool
    node_engine_compatibility_verified: bool
    selected_peer_compatibility_verified: bool
    required_dependency_anchors_verified: bool
    licenses_and_deprecations_disposed: bool
    exact_published_sha512_integrity_metadata_bound: bool
    current_registry_signature_verified_for_each_package: bool
    provenance_status_or_absence_disposed: bool
    selected_metadata_advisory_disposition_complete: bool
    receipt_is_not_independent_network_provenance: bool
    accepted_console_invocation_and_exact_payload_hashes_required: bool
    package_tarball_downloaded: bool
    package_tarball_bytes_integrity_verified: bool
    provenance_attestation_statement_downloaded_or_verified: bool
    node_distribution_artifact_selected: bool
    node_binary_downloaded: bool
    node_binary_signature_verified: bool
    node_shasums_signature_verified: bool
    complete_transitive_dependency_graph_resolved: bool
    transitive_dependency_advisory_audit_completed: bool
    package_manifest_created_or_modified: bool
    lockfile_created_or_modified: bool
    package_manager_executed: bool
    lifecycle_script_executed: bool
    dependency_installed: bool
    frontend_root_created: bool
    scaffold_file_written: bool
    browser_or_oauth_executed: bool
    application_configuration_modified: bool
    application_activated: bool
    operational_write_performed: bool

    def __post_init__(self) -> None:
        integer_fields = (
            "schema_version",
            "manifest_direct_package_count",
            "mandatory_transitive_anchor_count",
            "frontend_ecosystem_metadata_count",
            "registry_package_metadata_count",
            "official_http_request_count",
            "aggregate_response_bytes",
            "signature_entry_count",
            "signature_verified_package_count",
            "provenance_present_count",
            "provenance_absence_disposition_count",
            "deprecated_package_count",
            "selected_metadata_advisory_count",
            "peer_relationship_count",
            "optional_peer_absence_disposition_count",
        )
        if any(type(getattr(self, name)) is not int for name in integer_fields):
            raise ValueError("ecosystem receipt integer field is invalid")
        constants = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "readiness_status": STATUS,
            "selection_profile": SELECTION_PROFILE,
            "approved_step235_package_manifest_sha256": STEP235_PACKAGE_MANIFEST_SHA256,
            "approved_step235_accepted_state_manifest_sha256": STEP235_ACCEPTED_STATE_MANIFEST_SHA256,
            "approved_step235_architecture_selection_readiness_sha256": STEP235_ARCHITECTURE_SELECTION_READINESS_SHA256,
            "approved_step235_architecture_selection_test_sha256": STEP235_ARCHITECTURE_SELECTION_TEST_SHA256,
            "approved_step235_canonical_receipt_sha256": STEP235_CANONICAL_RECEIPT_SHA256,
            "approved_step235_readiness_document_sha256": STEP235_READINESS_DOCUMENT_SHA256,
            "approved_step235_architecture_plan_sha256": STEP235_ARCHITECTURE_PLAN_SHA256,
            "approved_step235_security_plan_sha256": STEP235_SECURITY_PLAN_SHA256,
            "approved_step235_experience_and_test_plan_sha256": STEP235_EXPERIENCE_AND_TEST_PLAN_SHA256,
            "approved_step235_deferred_gate_plan_sha256": STEP235_DEFERRED_GATE_PLAN_SHA256,
            "node_version": NODE_VERSION,
            "bundled_npm_version": NPM_VERSION,
            "manifest_direct_package_count": 19,
            "mandatory_transitive_anchor_count": 3,
            "frontend_ecosystem_metadata_count": 22,
            "registry_package_metadata_count": 23,
            "official_http_request_count": MAX_REQUEST_COUNT,
            "deprecated_package_count": 0,
            "selected_metadata_advisory_count": 0,
            "node_lts_codename": NODE_LTS_CODENAME,
            "signature_entry_count": 37,
            "signature_verified_package_count": 23,
            "provenance_present_count": 15,
            "provenance_absence_disposition_count": 8,
            "peer_relationship_count": 41,
            "optional_peer_absence_disposition_count": 23,
        }
        if any(getattr(self, name) != value for name, value in constants.items()):
            raise ValueError("ecosystem receipt constant is invalid")
        for name in (
            "selected_package_tuple_sha256",
            "package_metadata_projection_sha256",
            "package_response_body_set_sha256",
            "official_response_body_set_sha256",
            "engine_compatibility_projection_sha256",
            "peer_compatibility_projection_sha256",
            "dependency_anchor_projection_sha256",
            "license_deprecation_projection_sha256",
            "integrity_projection_sha256",
            "signature_projection_sha256",
            "provenance_projection_sha256",
            "advisory_projection_sha256",
            "node_release_projection_sha256",
            "node_shasums_projection_sha256",
        ):
            if not _is_sha256(getattr(self, name)):
                raise ValueError("ecosystem receipt digest is invalid")
        required_true = (
            "exact_step235_chain_bound",
            "live_official_network_evidence_processed",
            "official_npm_registry_origin_required",
            "official_node_distribution_origin_required",
            "redirect_proxy_credential_and_retry_paths_forbidden",
            "response_request_and_deadline_bounds_enforced",
            "exact_manifest_direct_versions_selected",
            "exact_transitive_anchor_versions_bound",
            "exact_node_patch_and_bundled_npm_selected",
            "react_and_react_dom_version_parity_verified",
            "node_engine_compatibility_verified",
            "selected_peer_compatibility_verified",
            "required_dependency_anchors_verified",
            "licenses_and_deprecations_disposed",
            "exact_published_sha512_integrity_metadata_bound",
            "current_registry_signature_verified_for_each_package",
            "provenance_status_or_absence_disposed",
            "selected_metadata_advisory_disposition_complete",
            "receipt_is_not_independent_network_provenance",
            "accepted_console_invocation_and_exact_payload_hashes_required",
        )
        required_false = (
            "package_tarball_downloaded",
            "package_tarball_bytes_integrity_verified",
            "provenance_attestation_statement_downloaded_or_verified",
            "node_distribution_artifact_selected",
            "node_binary_downloaded",
            "node_binary_signature_verified",
            "node_shasums_signature_verified",
            "complete_transitive_dependency_graph_resolved",
            "transitive_dependency_advisory_audit_completed",
            "package_manifest_created_or_modified",
            "lockfile_created_or_modified",
            "package_manager_executed",
            "lifecycle_script_executed",
            "dependency_installed",
            "frontend_root_created",
            "scaffold_file_written",
            "browser_or_oauth_executed",
            "application_configuration_modified",
            "application_activated",
            "operational_write_performed",
        )
        if any(
            type(getattr(self, name)) is not bool or not getattr(self, name)
            for name in required_true
        ):
            raise ValueError("ecosystem required control is not true")
        if any(
            type(getattr(self, name)) is not bool or getattr(self, name)
            for name in required_false
        ):
            raise ValueError("ecosystem deferred or mutation control is not false")
        if (
            type(self.aggregate_response_bytes) is not int
            or self.aggregate_response_bytes <= 0
            or self.aggregate_response_bytes > MAX_AGGREGATE_RESPONSE_BYTES
            or self.provenance_present_count
            + self.provenance_absence_disposition_count
            != self.registry_package_metadata_count
        ):
            raise ValueError("ecosystem receipt count or resource correlation is invalid")


_VERSION_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+|x|X|\*))?(?:\.(\d+|x|X|\*))?"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


def _version_parts(value: str) -> tuple[int, int, int, int]:
    match = _VERSION_RE.fullmatch(value.strip())
    if match is None:
        raise ValueError("unsupported semantic version")
    raw = match.groups()
    parts: list[int] = []
    precision = 0
    for item in raw:
        if item is None or item.lower() == "x" or item == "*":
            parts.append(0)
        else:
            parts.append(int(item))
            precision += 1
    return parts[0], parts[1], parts[2], precision


def _compare(left: tuple[int, int, int], right: tuple[int, int, int]) -> int:
    return (left > right) - (left < right)


def _one_semver_token(version: tuple[int, int, int], token: str) -> bool:
    token = token.strip()
    if token in ("", "*", "x", "X"):
        return True
    match = re.fullmatch(r"(\^|~|>=|<=|>|<|=)?(.+)", token)
    if match is None:
        raise ValueError("unsupported semantic version comparator")
    operator = match.group(1) or ""
    major, minor, patch, precision = _version_parts(match.group(2))
    base = (major, minor, patch)
    comparison = _compare(version, base)
    if operator == ">=":
        return comparison >= 0
    if operator == "<=":
        return comparison <= 0
    if operator == ">":
        return comparison > 0
    if operator == "<":
        return comparison < 0
    if operator == "=":
        return comparison == 0
    if operator == "^":
        if major > 0:
            upper = (major + 1, 0, 0)
        elif minor > 0:
            upper = (0, minor + 1, 0)
        else:
            upper = (0, 0, patch + 1)
        return comparison >= 0 and _compare(version, upper) < 0
    if operator == "~":
        upper = (major + 1, 0, 0) if precision == 1 else (major, minor + 1, 0)
        return comparison >= 0 and _compare(version, upper) < 0
    if precision == 1:
        return major == version[0]
    if precision == 2:
        return (major, minor) == version[:2]
    return comparison == 0


def _satisfies_semver(version_value: str, range_value: str) -> bool:
    version = _version_parts(version_value)[:3]
    if type(range_value) is not str or not range_value.strip():
        raise ValueError("semantic version range is invalid")
    normalized = re.sub(r"([<>=~^]+)\s+", r"\1", range_value.strip())
    alternatives = [alternative.strip() for alternative in normalized.split("||")]
    if not alternatives or any(not alternative for alternative in alternatives):
        raise ValueError("semantic version range alternatives are invalid")
    for alternative in alternatives:
        hyphen = re.fullmatch(r"(.+?)\s+-\s+(.+)", alternative)
        if hyphen is not None:
            if _one_semver_token(version, ">=" + hyphen.group(1)) and _one_semver_token(
                version, "<=" + hyphen.group(2)
            ):
                return True
            continue
        tokens = [token for token in re.split(r"[\s,]+", alternative) if token]
        if tokens and all(_one_semver_token(version, token) for token in tokens):
            return True
    return False


def _expected_responses(
    evidence: LiveEcosystemRegistryEvidence,
) -> dict[str, BoundedOfficialHttpResponse]:
    if not is_attested_live_ecosystem_registry_evidence(evidence):
        raise ValueError("exact live ecosystem evidence is required")
    if (
        evidence.evidence_source != "live_bounded_official_https"
        or evidence.request_count != MAX_REQUEST_COUNT
        or len(evidence.requests) != MAX_REQUEST_COUNT
        or evidence.aggregate_response_bytes
        != sum(len(response.body) for response in evidence.requests)
        or evidence.redirects_followed != 0
        or evidence.automatic_retries != 0
        or evidence.environment_proxy_configuration_used
        or evidence.credentials_sent
        or evidence.package_tarball_downloaded
        or evidence.node_binary_downloaded
    ):
        raise ValueError("live ecosystem transport controls are invalid")
    request_contract = {
        item["request_id"]: item for item in official_request_contract_projection()
    }
    if len(request_contract) != MAX_REQUEST_COUNT:
        raise ValueError("official request contract inventory is not exact")
    for request_id, contract in request_contract.items():
        allow_missing_content_type = contract.get("allow_missing_content_type")
        if (
            type(allow_missing_content_type) is not bool
            or allow_missing_content_type
            != (request_id == "npm-direct-advisories")
        ):
            raise ValueError("official request content-type contract is not exact")
    responses: dict[str, BoundedOfficialHttpResponse] = {}
    for response in evidence.requests:
        if type(response) is not BoundedOfficialHttpResponse:
            raise ValueError("ecosystem response type is invalid")
        if response.request_id in responses:
            raise ValueError("duplicate ecosystem response")
        contract = request_contract.get(response.request_id)
        media_type_is_exact = (
            contract is not None
            and (
                response.media_type in contract["accepted_media_types"]
                or (
                    contract["allow_missing_content_type"] is True
                    and response.media_type == "absent"
                )
            )
        )
        if (
            contract is None
            or response.method != contract["method"]
            or response.url != contract["url"]
            or not media_type_is_exact
        ):
            raise ValueError("ecosystem response request correlation is invalid")
        if response.status_code != 200 or not response.body:
            raise ValueError("ecosystem response status or body is invalid")
        if not _is_sha256(response.body_sha256) or response.body_sha256 != hashlib.sha256(
            response.body
        ).hexdigest():
            raise ValueError("ecosystem response body identity is invalid")
        parsed = urlsplit(response.url)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("ecosystem response URL is not exact HTTPS")
        if response.request_id.startswith("npm-") and parsed.hostname != "registry.npmjs.org":
            raise ValueError("npm ecosystem response origin is invalid")
        if response.request_id.startswith("node-") and parsed.hostname != "nodejs.org":
            raise ValueError("Node ecosystem response origin is invalid")
        responses[response.request_id] = response
    expected_ids = set(request_contract)
    if set(responses) != expected_ids:
        raise ValueError("ecosystem response inventory is not exact")
    return responses


def _signing_key(response: BoundedOfficialHttpResponse) -> ec.EllipticCurvePublicKey:
    parsed = _bounded_json(response.body)
    if type(parsed) is not dict or set(parsed) != {"keys"} or type(parsed["keys"]) is not list:
        raise ValueError("npm signing-key response is invalid")
    matches: list[dict[str, object]] = []
    seen: set[str] = set()
    for key in parsed["keys"]:
        if type(key) is not dict or type(key.get("keyid")) is not str:
            raise ValueError("npm signing-key entry is invalid")
        keyid = key["keyid"]
        if keyid in seen:
            raise ValueError("npm signing-key identifier is duplicated")
        seen.add(keyid)
        if keyid == CURRENT_NPM_SIGNING_KEY_ID:
            matches.append(key)
    if (
        len(matches) != 1
        or matches[0].get("key") != CURRENT_NPM_SIGNING_KEY_MATERIAL
        or matches[0].get("keytype") != CURRENT_NPM_SIGNING_KEY_TYPE
        or matches[0].get("scheme") != CURRENT_NPM_SIGNING_KEY_SCHEME
        or "expires" not in matches[0]
        or matches[0]["expires"] is not None
    ):
        raise ValueError("current npm signing key is not exact")
    try:
        encoded = base64.b64decode(CURRENT_NPM_SIGNING_KEY_MATERIAL, validate=True)
        public_key = serialization.load_der_public_key(encoded)
    except (ValueError, TypeError) as error:
        raise ValueError("current npm signing key material is invalid") from error
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise ValueError("current npm signing key algorithm is invalid")
    return public_key


def _validate_tarball_url(name: str, version: str, value: object) -> str:
    if type(value) is not str:
        raise ValueError("npm tarball metadata is invalid")
    basename = name.rsplit("/", 1)[-1]
    expected = f"{NPM_REGISTRY_ORIGIN}/{name}/-/{basename}-{version}.tgz"
    parsed = urlsplit(value)
    if (
        value != expected
        or parsed.scheme != "https"
        or parsed.hostname != "registry.npmjs.org"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
    ):
        raise ValueError(f"npm tarball URL is invalid for {name}")
    return value


def _validate_package_metadata(
    responses: dict[str, BoundedOfficialHttpResponse],
    public_key: ec.EllipticCurvePublicKey,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]], int, int]:
    selections = SELECTED_PACKAGES + (TOOLCHAIN_NPM_PACKAGE,)
    versions = {item.name: item.version for item in selections}
    if len(versions) != 23 or set(versions) != set(EXPECTED_PACKAGE_METADATA):
        raise ValueError("ecosystem package tuple is not exact")
    metadata_by_name: dict[str, dict[str, object]] = {}
    package_projections: list[dict[str, object]] = []
    signature_projections: list[dict[str, object]] = []
    provenance_projections: list[dict[str, object]] = []
    signature_total = 0
    for selection in selections:
        response = responses[f"npm-package:{selection.name}@{selection.version}"]
        parsed = _bounded_json(response.body)
        if type(parsed) is not dict:
            raise ValueError("npm package metadata must be an object")
        expected = EXPECTED_PACKAGE_METADATA[selection.name]
        if (
            parsed.get("name") != selection.name
            or parsed.get("version") != selection.version
            or parsed.get("license") != expected.license
            or "deprecated" in parsed
            or type(parsed.get("dist")) is not dict
        ):
            raise ValueError(f"npm package identity or disposition is invalid: {selection.name}")
        dist = parsed["dist"]
        if dist.get("integrity") != expected.integrity:
            raise ValueError(f"npm package integrity metadata changed: {selection.name}")
        encoded_integrity = expected.integrity.removeprefix("sha512-")
        if not expected.integrity.startswith("sha512-"):
            raise ValueError("expected integrity algorithm is invalid")
        try:
            if len(base64.b64decode(encoded_integrity, validate=True)) != 64:
                raise ValueError("integrity digest length is invalid")
        except (ValueError, TypeError) as error:
            raise ValueError("expected integrity encoding is invalid") from error
        tarball = _validate_tarball_url(
            selection.name, selection.version, dist.get("tarball")
        )
        signatures = dist.get("signatures")
        if type(signatures) is not list or len(signatures) != expected.signature_count:
            raise ValueError(f"npm signature count changed: {selection.name}")
        signature_values: set[str] = set()
        for signature in signatures:
            if (
                type(signature) is not dict
                or set(signature) != {"keyid", "sig"}
                or signature["keyid"] != CURRENT_NPM_SIGNING_KEY_ID
                or type(signature["sig"]) is not str
                or signature["sig"] in signature_values
            ):
                raise ValueError(f"npm signature entry is invalid: {selection.name}")
            try:
                signature_bytes = base64.b64decode(signature["sig"], validate=True)
                signed = (
                    f"{selection.name}@{selection.version}:{expected.integrity}"
                ).encode("utf-8")
                public_key.verify(
                    signature_bytes, signed, ec.ECDSA(hashes.SHA256())
                )
            except (ValueError, TypeError, InvalidSignature) as error:
                raise ValueError(
                    f"current npm signature is invalid: {selection.name}"
                ) from error
            signature_values.add(signature["sig"])
        signature_total += len(signatures)
        attestations_present = "attestations" in dist
        if attestations_present != expected.provenance_present:
            raise ValueError(f"npm provenance status changed: {selection.name}")
        if attestations_present:
            attestations = dist["attestations"]
            encoded_name = selection.name.replace("/", "%2f")
            expected_attestation_url = (
                f"{NPM_REGISTRY_ORIGIN}/-/npm/v1/attestations/"
                f"{encoded_name}@{selection.version}"
            )
            if (
                type(attestations) is not dict
                or set(attestations) != {"url", "provenance"}
                or attestations.get("url") != expected_attestation_url
                or attestations.get("provenance")
                != {"predicateType": "https://slsa.dev/provenance/v1"}
            ):
                raise ValueError(f"npm provenance metadata is invalid: {selection.name}")
            attestation_url = urlsplit(attestations["url"])
            if (
                attestation_url.scheme != "https"
                or attestation_url.hostname != "registry.npmjs.org"
                or attestation_url.username is not None
                or attestation_url.password is not None
                or attestation_url.port is not None
                or attestation_url.query
                or attestation_url.fragment
                or not attestation_url.path.startswith("/-/npm/v1/attestations/")
                or unquote(attestation_url.path)
                != (
                    f"/-/npm/v1/attestations/"
                    f"{selection.name}@{selection.version}"
                )
                or "%2F" in attestation_url.path
            ):
                raise ValueError(f"npm provenance URL is invalid: {selection.name}")
        metadata_by_name[selection.name] = parsed
        package_projections.append(
            {
                "name": selection.name,
                "version": selection.version,
                "role": selection.role,
                "license": expected.license,
                "integrity": expected.integrity,
                "tarball_url": tarball,
                "deprecated_absent": True,
                "metadata_body_sha256": response.body_sha256,
                "engines": parsed.get("engines", {}),
                "dependencies": parsed.get("dependencies", {}),
                "peer_dependencies": parsed.get("peerDependencies", {}),
                "peer_dependencies_meta": parsed.get("peerDependenciesMeta", {}),
            }
        )
        signature_projections.append(
            {
                "name": selection.name,
                "signature_count": len(signatures),
                "current_key_signature_verified": True,
            }
        )
        provenance_projections.append(
            {
                "name": selection.name,
                "metadata_present": attestations_present,
                "attestation_statement_downloaded": False,
            }
        )

    engine_projections: list[dict[str, object]] = []
    peer_projections: list[dict[str, object]] = []
    optional_absences = 0
    for selection in selections:
        metadata = metadata_by_name[selection.name]
        engines = metadata.get("engines", {})
        if type(engines) is not dict:
            raise ValueError("npm engines metadata is invalid")
        node_range = engines.get("node")
        if node_range is not None:
            if type(node_range) is not str or not _satisfies_semver(
                NODE_VERSION, node_range
            ):
                raise ValueError(f"Node engine is incompatible: {selection.name}")
        engine_projections.append(
            {
                "name": selection.name,
                "node_range": node_range if node_range is not None else "absent",
                "selected_node_compatible": True,
            }
        )
        peers = metadata.get("peerDependencies", {})
        peer_meta = metadata.get("peerDependenciesMeta", {})
        if type(peers) is not dict or type(peer_meta) is not dict:
            raise ValueError("npm peer metadata is invalid")
        for peer_name, peer_range in sorted(peers.items()):
            if type(peer_name) is not str or type(peer_range) is not str:
                raise ValueError("npm peer relationship is invalid")
            optional = (
                type(peer_meta.get(peer_name)) is dict
                and peer_meta[peer_name].get("optional") is True
            )
            selected_peer_version = versions.get(peer_name)
            if selected_peer_version is None:
                if not optional:
                    raise ValueError(
                        f"required npm peer is not selected: {selection.name}/{peer_name}"
                    )
                optional_absences += 1
                peer_projections.append(
                    {
                        "consumer": selection.name,
                        "peer": peer_name,
                        "range": peer_range,
                        "disposition": "optional_absent",
                    }
                )
                continue
            if not _satisfies_semver(selected_peer_version, peer_range):
                raise ValueError(
                    f"selected npm peer is incompatible: {selection.name}/{peer_name}"
                )
            peer_projections.append(
                {
                    "consumer": selection.name,
                    "peer": peer_name,
                    "range": peer_range,
                    "selected_version": selected_peer_version,
                    "disposition": "selected_compatible",
                }
            )

    dependency_requirements = {
        ("@azure/msal-browser", "@azure/msal-common"): "16.12.0",
        ("@axe-core/playwright", "axe-core"): "~4.13.0",
        ("@playwright/test", "playwright"): "1.62.1",
        ("playwright", "playwright-core"): "1.62.1",
        ("vitest", "vite"): "^6.0.0 || ^7.0.0 || ^8.0.0",
    }
    dependency_projections: list[dict[str, object]] = []
    observed_selected_edges: dict[tuple[str, str], str] = {}
    for consumer in sorted(metadata_by_name):
        dependencies = metadata_by_name[consumer].get("dependencies", {})
        if type(dependencies) is not dict or any(
            type(name) is not str or type(value) is not str
            for name, value in dependencies.items()
        ):
            raise ValueError(f"npm dependency metadata is invalid: {consumer}")
        for dependency, dependency_range in sorted(dependencies.items()):
            selected_version = versions.get(dependency)
            if selected_version is None:
                continue
            if not _satisfies_semver(selected_version, dependency_range):
                raise ValueError(
                    f"selected dependency is incompatible: {consumer}/{dependency}"
                )
            observed_selected_edges[(consumer, dependency)] = dependency_range
            dependency_projections.append(
                {
                    "consumer": consumer,
                    "dependency": dependency,
                    "published_range": dependency_range,
                    "selected_version": selected_version,
                    "compatible": True,
                }
            )
    if observed_selected_edges != dependency_requirements:
        raise ValueError("selected dependency edge inventory is not exact")
    return (
        package_projections,
        signature_projections,
        provenance_projections,
        signature_total,
        optional_absences,
    ), engine_projections, peer_projections, dependency_projections, len(peer_projections)


def _validate_node_release(
    index_response: BoundedOfficialHttpResponse,
    shasums_response: BoundedOfficialHttpResponse,
) -> tuple[dict[str, object], list[dict[str, str]]]:
    index = _bounded_json(index_response.body)
    if type(index) is not list:
        raise ValueError("Node release index must be an array")
    matches = [
        item
        for item in index
        if type(item) is dict and item.get("version") == NODE_VERSION_TAG
    ]
    if len(matches) != 1:
        raise ValueError("exact Node release is missing or duplicated")
    release = matches[0]
    if (
        release.get("npm") != NPM_VERSION
        or release.get("lts") != NODE_LTS_CODENAME
        or release.get("date") != NODE_RELEASE_DATE
        or type(release.get("security")) is not bool
        or release["security"] is not False
        or type(release.get("files")) is not list
        or not release["files"]
        or any(
            type(item) is not str
            or re.fullmatch(r"[a-z0-9-]+", item) is None
            for item in release["files"]
        )
        or len(set(release["files"])) != len(release["files"])
    ):
        raise ValueError("exact Node release toolchain metadata is invalid")
    v24_lts_versions: list[tuple[int, int, int]] = []
    for item in index:
        if type(item) is not dict or type(item.get("version")) is not str:
            continue
        try:
            version_parts = _version_parts(item["version"])[:3]
        except ValueError:
            continue
        if version_parts[0] == 24 and item.get("lts") == NODE_LTS_CODENAME:
            v24_lts_versions.append(version_parts)
    if not v24_lts_versions or max(v24_lts_versions) != _version_parts(NODE_VERSION)[:3]:
        raise ValueError("selected Node release is no longer the highest Node 24 LTS")
    release_projection = {
        "version": NODE_VERSION_TAG,
        "npm": NPM_VERSION,
        "lts": NODE_LTS_CODENAME,
        "date": NODE_RELEASE_DATE,
        "security": False,
        "files": sorted(release["files"]),
        "index_body_sha256": index_response.body_sha256,
    }
    try:
        text = shasums_response.body.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("Node release checksums are not canonical ASCII") from error
    if shasums_response.body_sha256 != NODE_SHASUMS_BODY_SHA256:
        raise ValueError("exact Node release checksum body identity changed")
    checksums: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)", line)
        if match is None or match.group(2) in seen:
            raise ValueError("Node release checksum line is invalid")
        filename = match.group(2)
        segments = filename.split("/")
        if (
            filename.startswith("/")
            or filename.endswith("/")
            or "//" in filename
            or any(segment in ("", ".", "..") for segment in segments)
        ):
            raise ValueError("Node release checksum path is not canonical")
        seen.add(filename)
        checksums.append({"filename": filename, "sha256": match.group(1)})
    if not checksums:
        raise ValueError("Node release checksum inventory is empty")
    checksums.sort(key=lambda item: item["filename"])
    return release_projection, checksums


def validate_entra_calling_client_msal_frontend_host_ecosystem_compatibility_authorization(
    authorization: bytes,
) -> EntraCallingClientMSALFrontendHostEcosystemCompatibilityAuthorization:
    """Validate the exact authorization before any live request is permitted."""

    try:
        if type(authorization) is not bytes or not authorization or len(
            authorization
        ) > MAX_AUTHORIZATION_BYTES:
            raise ValueError("ecosystem authorization size is invalid")
        parsed_authorization = _bounded_json(authorization)
        return EntraCallingClientMSALFrontendHostEcosystemCompatibilityAuthorization.model_validate(
            parsed_authorization
        )
    except (
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise EntraCallingClientMSALFrontendHostEcosystemCompatibilityError(
            "frontend-host ecosystem compatibility authorization failed"
        ) from error


def load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
    authorization: bytes,
    evidence: LiveEcosystemRegistryEvidence,
) -> EntraCallingClientMSALFrontendHostEcosystemCompatibilityReceipt:
    """Validate one exact live metadata tuple and return a bounded receipt."""

    try:
        authorization_model = validate_entra_calling_client_msal_frontend_host_ecosystem_compatibility_authorization(
            authorization
        )
        responses = _expected_responses(evidence)
        public_key = _signing_key(responses["npm-signing-keys"])
        (
            package_result,
            engine_projections,
            peer_projections,
            dependency_projections,
            peer_count,
        ) = _validate_package_metadata(responses, public_key)
        (
            package_projections,
            signature_projections,
            provenance_projections,
            signature_total,
            optional_absences,
        ) = package_result
        advisories = _bounded_json(responses["npm-direct-advisories"].body)
        if type(advisories) is not dict or advisories:
            raise ValueError("official selected-metadata advisory disposition is not empty")
        node_release, node_checksums = _validate_node_release(
            responses["node-release-index"], responses["node-release-shasums"]
        )
        package_tuple = [
            {"name": item.name, "version": item.version, "role": item.role}
            for item in SELECTED_PACKAGES + (TOOLCHAIN_NPM_PACKAGE,)
        ]
        package_body_set = [
            {
                "request_id": response.request_id,
                "body_sha256": response.body_sha256,
            }
            for response in evidence.requests
            if response.request_id.startswith("npm-package:")
        ]
        official_body_set = [
            {
                "request_id": response.request_id,
                "method": response.method,
                "url": response.url,
                "media_type": response.media_type,
                "body_sha256": response.body_sha256,
            }
            for response in evidence.requests
        ]
        license_deprecation = [
            {
                "name": projection["name"],
                "license": projection["license"],
                "deprecated_absent": projection["deprecated_absent"],
            }
            for projection in package_projections
        ]
        integrity = [
            {
                "name": projection["name"],
                "integrity": projection["integrity"],
                "tarball_url": projection["tarball_url"],
                "tarball_downloaded": False,
            }
            for projection in package_projections
        ]
        provenance_present_count = sum(
            1 for item in provenance_projections if item["metadata_present"]
        )
        receipt = EntraCallingClientMSALFrontendHostEcosystemCompatibilityReceipt(
            receipt_type=RECEIPT_TYPE,
            schema_version=SCHEMA_VERSION,
            source=SOURCE,
            validation_scope=SCOPE,
            readiness_status=STATUS,
            selection_profile=SELECTION_PROFILE,
            approved_step235_package_manifest_sha256=STEP235_PACKAGE_MANIFEST_SHA256,
            approved_step235_accepted_state_manifest_sha256=STEP235_ACCEPTED_STATE_MANIFEST_SHA256,
            approved_step235_architecture_selection_readiness_sha256=STEP235_ARCHITECTURE_SELECTION_READINESS_SHA256,
            approved_step235_architecture_selection_test_sha256=STEP235_ARCHITECTURE_SELECTION_TEST_SHA256,
            approved_step235_canonical_receipt_sha256=STEP235_CANONICAL_RECEIPT_SHA256,
            approved_step235_readiness_document_sha256=STEP235_READINESS_DOCUMENT_SHA256,
            approved_step235_architecture_plan_sha256=STEP235_ARCHITECTURE_PLAN_SHA256,
            approved_step235_security_plan_sha256=STEP235_SECURITY_PLAN_SHA256,
            approved_step235_experience_and_test_plan_sha256=STEP235_EXPERIENCE_AND_TEST_PLAN_SHA256,
            approved_step235_deferred_gate_plan_sha256=STEP235_DEFERRED_GATE_PLAN_SHA256,
            node_version=NODE_VERSION,
            bundled_npm_version=NPM_VERSION,
            node_lts_codename=node_release["lts"],
            manifest_direct_package_count=len(DIRECT_PACKAGES),
            mandatory_transitive_anchor_count=len(TRANSITIVE_ANCHOR_PACKAGES),
            frontend_ecosystem_metadata_count=len(SELECTED_PACKAGES),
            registry_package_metadata_count=len(package_tuple),
            official_http_request_count=evidence.request_count,
            aggregate_response_bytes=evidence.aggregate_response_bytes,
            signature_entry_count=signature_total,
            signature_verified_package_count=len(package_tuple),
            provenance_present_count=provenance_present_count,
            provenance_absence_disposition_count=(
                len(package_tuple) - provenance_present_count
            ),
            deprecated_package_count=0,
            selected_metadata_advisory_count=0,
            peer_relationship_count=peer_count,
            optional_peer_absence_disposition_count=optional_absences,
            selected_package_tuple_sha256=_framed("selected-package-tuple", package_tuple),
            package_metadata_projection_sha256=_framed(
                "package-metadata", package_projections
            ),
            package_response_body_set_sha256=_framed(
                "package-response-body-set", package_body_set
            ),
            official_response_body_set_sha256=_framed(
                "official-response-body-set", official_body_set
            ),
            engine_compatibility_projection_sha256=_framed(
                "engine-compatibility", engine_projections
            ),
            peer_compatibility_projection_sha256=_framed(
                "peer-compatibility", peer_projections
            ),
            dependency_anchor_projection_sha256=_framed(
                "dependency-anchors", dependency_projections
            ),
            license_deprecation_projection_sha256=_framed(
                "license-deprecation", license_deprecation
            ),
            integrity_projection_sha256=_framed("published-integrity", integrity),
            signature_projection_sha256=_framed(
                "registry-signatures", signature_projections
            ),
            provenance_projection_sha256=_framed(
                "registry-provenance", provenance_projections
            ),
            advisory_projection_sha256=_framed(
                "selected-metadata-advisories",
                {
                    "request_body_profile": "exact_23_package_name_version_map",
                    "response": advisories,
                    "response_body_sha256": responses[
                        "npm-direct-advisories"
                    ].body_sha256,
                },
            ),
            node_release_projection_sha256=_framed(
                "node-release", node_release
            ),
            node_shasums_projection_sha256=_framed(
                "node-shasums",
                {
                    "checksums": node_checksums,
                    "response_body_sha256": responses[
                        "node-release-shasums"
                    ].body_sha256,
                    "distribution_artifact_selected": False,
                },
            ),
            exact_step235_chain_bound=True,
            live_official_network_evidence_processed=True,
            official_npm_registry_origin_required=True,
            official_node_distribution_origin_required=True,
            redirect_proxy_credential_and_retry_paths_forbidden=True,
            response_request_and_deadline_bounds_enforced=True,
            exact_manifest_direct_versions_selected=True,
            exact_transitive_anchor_versions_bound=True,
            exact_node_patch_and_bundled_npm_selected=True,
            react_and_react_dom_version_parity_verified=(
                next(item.version for item in DIRECT_PACKAGES if item.name == "react")
                == next(
                    item.version for item in DIRECT_PACKAGES if item.name == "react-dom"
                )
            ),
            node_engine_compatibility_verified=True,
            selected_peer_compatibility_verified=True,
            required_dependency_anchors_verified=True,
            licenses_and_deprecations_disposed=True,
            exact_published_sha512_integrity_metadata_bound=True,
            current_registry_signature_verified_for_each_package=True,
            provenance_status_or_absence_disposed=True,
            selected_metadata_advisory_disposition_complete=True,
            receipt_is_not_independent_network_provenance=True,
            accepted_console_invocation_and_exact_payload_hashes_required=True,
            package_tarball_downloaded=False,
            package_tarball_bytes_integrity_verified=False,
            provenance_attestation_statement_downloaded_or_verified=False,
            node_distribution_artifact_selected=False,
            node_binary_downloaded=False,
            node_binary_signature_verified=False,
            node_shasums_signature_verified=False,
            complete_transitive_dependency_graph_resolved=False,
            transitive_dependency_advisory_audit_completed=False,
            package_manifest_created_or_modified=False,
            lockfile_created_or_modified=False,
            package_manager_executed=False,
            lifecycle_script_executed=False,
            dependency_installed=False,
            frontend_root_created=False,
            scaffold_file_written=False,
            browser_or_oauth_executed=False,
            application_configuration_modified=False,
            application_activated=False,
            operational_write_performed=False,
        )
        receipt.__post_init__()
        return receipt
    except (
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise EntraCallingClientMSALFrontendHostEcosystemCompatibilityError(
            "frontend-host ecosystem compatibility validation failed"
        ) from error


def render_entra_calling_client_msal_frontend_host_ecosystem_compatibility_receipt(
    receipt: EntraCallingClientMSALFrontendHostEcosystemCompatibilityReceipt,
) -> bytes:
    """Render only one exact validated receipt as canonical UTF-8 JSON."""

    if type(receipt) is not EntraCallingClientMSALFrontendHostEcosystemCompatibilityReceipt:
        raise TypeError("exact frontend-host ecosystem receipt is required")
    receipt.__post_init__()
    return _canonical(
        {field.name: getattr(receipt, field.name) for field in dataclasses.fields(receipt)}
    )


__all__ = [
    "CURRENT_NPM_SIGNING_KEY_ID",
    "DOCUMENT_TYPE",
    "EXPECTED_PACKAGE_METADATA",
    "EntraCallingClientMSALFrontendHostEcosystemCompatibilityAuthorization",
    "EntraCallingClientMSALFrontendHostEcosystemCompatibilityError",
    "EntraCallingClientMSALFrontendHostEcosystemCompatibilityReceipt",
    "MAX_AUTHORIZATION_BYTES",
    "RECEIPT_TYPE",
    "SCHEMA_VERSION",
    "SELECTION_PROFILE",
    "SOURCE",
    "STATUS",
    "STEP235_ACCEPTED_STATE_MANIFEST_SHA256",
    "STEP235_ARCHITECTURE_PLAN_SHA256",
    "STEP235_ARCHITECTURE_SELECTION_READINESS_SHA256",
    "STEP235_ARCHITECTURE_SELECTION_TEST_SHA256",
    "STEP235_CANONICAL_RECEIPT_SHA256",
    "STEP235_DEFERRED_GATE_PLAN_SHA256",
    "STEP235_EXPERIENCE_AND_TEST_PLAN_SHA256",
    "STEP235_PACKAGE_MANIFEST_SHA256",
    "STEP235_READINESS_DOCUMENT_SHA256",
    "STEP235_SECURITY_PLAN_SHA256",
    "load_entra_calling_client_msal_frontend_host_ecosystem_compatibility",
    "render_entra_calling_client_msal_frontend_host_ecosystem_compatibility_receipt",
    "validate_entra_calling_client_msal_frontend_host_ecosystem_compatibility_authorization",
]
