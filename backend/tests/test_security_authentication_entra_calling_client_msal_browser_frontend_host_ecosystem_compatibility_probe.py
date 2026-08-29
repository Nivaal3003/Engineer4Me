from __future__ import annotations

import ast
import base64
import dataclasses
import hashlib
import inspect
import json
from typing import Callable

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from app.security import (
    authentication_entra_calling_client_msal_browser_frontend_host_ecosystem_compatibility_probe
    as probe,
)
from app.security import (
    authentication_entra_calling_client_msal_browser_frontend_host_ecosystem_registry_http_loader
    as loader,
)


class _UnreadSyncByteStream(httpx.SyncByteStream):
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __iter__(self):
        yield self._body


def _unread_response(
    request: httpx.Request,
    *,
    body: bytes,
    headers: dict[str, str],
) -> httpx.Response:
    response = httpx.Response(
        200,
        headers=headers,
        stream=_UnreadSyncByteStream(body),
        request=request,
    )
    assert not response.is_stream_consumed
    assert not response.is_closed
    return response


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _valid_authorization(**changes: object) -> bytes:
    value: dict[str, object] = {
        "document_type": probe.DOCUMENT_TYPE,
        "schema_version": probe.SCHEMA_VERSION,
        "source": probe.SOURCE,
        "approved_step235_package_manifest_sha256": (
            probe.STEP235_PACKAGE_MANIFEST_SHA256
        ),
        "approved_step235_accepted_state_manifest_sha256": (
            probe.STEP235_ACCEPTED_STATE_MANIFEST_SHA256
        ),
        "approved_step235_architecture_selection_readiness_sha256": (
            probe.STEP235_ARCHITECTURE_SELECTION_READINESS_SHA256
        ),
        "approved_step235_architecture_selection_test_sha256": (
            probe.STEP235_ARCHITECTURE_SELECTION_TEST_SHA256
        ),
        "approved_step235_canonical_receipt_sha256": (
            probe.STEP235_CANONICAL_RECEIPT_SHA256
        ),
        "approved_step235_readiness_document_sha256": (
            probe.STEP235_READINESS_DOCUMENT_SHA256
        ),
        "approved_step235_architecture_plan_sha256": (
            probe.STEP235_ARCHITECTURE_PLAN_SHA256
        ),
        "approved_step235_security_plan_sha256": probe.STEP235_SECURITY_PLAN_SHA256,
        "approved_step235_experience_and_test_plan_sha256": (
            probe.STEP235_EXPERIENCE_AND_TEST_PLAN_SHA256
        ),
        "approved_step235_deferred_gate_plan_sha256": (
            probe.STEP235_DEFERRED_GATE_PLAN_SHA256
        ),
        "selection_profile": probe.SELECTION_PROFILE,
    }
    value.update(changes)
    return _canonical(value)


ENGINE_RANGES = {
    "@azure/msal-browser": ">=0.8.0",
    "react": ">=0.10.0",
    "react-router": ">=22.22.0",
    "@playwright/test": ">=20",
    "@testing-library/dom": ">=18",
    "@testing-library/jest-dom": ">=22",
    "@testing-library/react": ">=18",
    "@testing-library/user-event": ">=12",
    "@vitejs/plugin-react": "^20.19.0 || >=22.12.0",
    "axe-core": ">=4",
    "jsdom": "^22.22.2 || ^24.15.0 || >=26.0.0",
    "typescript": ">=14.17",
    "vite": "^20.19.0 || >=22.12.0",
    "vitest": "^20.0.0 || ^22.0.0 || >=24.0.0",
    "@azure/msal-common": ">=0.8.0",
    "playwright": ">=20",
    "playwright-core": ">=20",
    "npm": "^20.17.0 || >=22.9.0",
}

EXTRA_ENGINE_FIELDS: dict[str, dict[str, str]] = {
    "@testing-library/jest-dom": {"npm": ">=6", "yarn": ">=1"},
    "@testing-library/user-event": {"npm": ">=6"},
}

PEER_RANGES: dict[str, dict[str, str]] = {
    "react-dom": {"react": "^19.2.8"},
    "react-router": {"react": ">=19.2.7", "react-dom": ">=19.2.7"},
    "@axe-core/playwright": {"playwright-core": ">= 1.0.0"},
    "@testing-library/jest-dom": {
        "@testing-library/dom": ">=10 <11",
        "vitest": ">= 0.32",
    },
    "@testing-library/react": {
        "@testing-library/dom": "^10.0.0",
        "@types/react": "^18.0.0 || ^19.0.0",
        "@types/react-dom": "^18.0.0 || ^19.0.0",
        "react": "^18.0.0 || ^19.0.0",
        "react-dom": "^18.0.0 || ^19.0.0",
    },
    "@testing-library/user-event": {"@testing-library/dom": ">=7.21.4"},
    "@types/react-dom": {"@types/react": "^19.2.0"},
    "@vitejs/plugin-react": {
        "@rolldown/plugin-babel": "^0.1.7 || ^0.2.0",
        "babel-plugin-react-compiler": "^1.0.0",
        "vite": "^8.0.0",
    },
    "jsdom": {"canvas": "^3.2.3"},
    "vite": {
        "@types/node": "^20.19.0 || >=22.12.0",
        "@vitejs/devtools": "^0.4.0",
        "esbuild": "^0.27.0 || ^0.28.0",
        "jiti": ">=1.21.0",
        "less": "^4.0.0",
        "sass": "^1.70.0",
        "sass-embedded": "^1.70.0",
        "stylus": ">=0.54.8",
        "sugarss": "^5.0.0",
        "terser": "^5.16.0",
        "tsx": "^4.8.1",
        "yaml": "^2.4.2",
    },
    "vitest": {
        "@edge-runtime/vm": "*",
        "@opentelemetry/api": "^1.9.0",
        "@types/node": "^20.0.0 || ^22.0.0 || >=24.0.0",
        "@vitest/browser-playwright": "4.1.11",
        "@vitest/browser-preview": "4.1.11",
        "@vitest/browser-webdriverio": "4.1.11",
        "@vitest/coverage-istanbul": "4.1.11",
        "@vitest/coverage-v8": "4.1.11",
        "@vitest/ui": "4.1.11",
        "happy-dom": "*",
        "jsdom": "*",
        "vite": "^6.0.0 || ^7.0.0 || ^8.0.0",
    },
}

OPTIONAL_PEERS = {
    ("react-router", "react-dom"),
    ("@testing-library/jest-dom", "vitest"),
    ("@testing-library/react", "@types/react"),
    ("@testing-library/react", "@types/react-dom"),
    ("@vitejs/plugin-react", "@rolldown/plugin-babel"),
    ("@vitejs/plugin-react", "babel-plugin-react-compiler"),
    ("jsdom", "canvas"),
    ("vite", "@types/node"),
    ("vite", "@vitejs/devtools"),
    ("vite", "esbuild"),
    ("vite", "jiti"),
    ("vite", "less"),
    ("vite", "sass"),
    ("vite", "sass-embedded"),
    ("vite", "stylus"),
    ("vite", "sugarss"),
    ("vite", "terser"),
    ("vite", "tsx"),
    ("vite", "yaml"),
    ("vitest", "@edge-runtime/vm"),
    ("vitest", "@opentelemetry/api"),
    ("vitest", "@types/node"),
    ("vitest", "@vitest/browser-playwright"),
    ("vitest", "@vitest/browser-preview"),
    ("vitest", "@vitest/browser-webdriverio"),
    ("vitest", "@vitest/coverage-istanbul"),
    ("vitest", "@vitest/coverage-v8"),
    ("vitest", "@vitest/ui"),
    ("vitest", "happy-dom"),
    ("vitest", "jsdom"),
}

DEPENDENCIES = {
    "@azure/msal-browser": {"@azure/msal-common": "16.12.0"},
    "@playwright/test": {"playwright": "1.62.1"},
    "playwright": {"playwright-core": "1.62.1"},
    "@axe-core/playwright": {"axe-core": "~4.13.0"},
    "vitest": {"vite": "^6.0.0 || ^7.0.0 || ^8.0.0"},
}

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _metadata_body(
    name: str,
    version: str,
    private_key: ec.EllipticCurvePrivateKey,
) -> bytes:
    expected = probe.EXPECTED_PACKAGE_METADATA[name]
    signed = f"{name}@{version}:{expected.integrity}".encode("utf-8")
    first_signature_bytes = private_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    current_signature = base64.b64encode(first_signature_bytes).decode("ascii")
    signatures: list[dict[str, str]] = [
        {"keyid": probe.CURRENT_NPM_SIGNING_KEY_ID, "sig": current_signature}
    ]
    if expected.signature_count == 2:
        r_value, s_value = utils.decode_dss_signature(first_signature_bytes)
        second_signature = utils.encode_dss_signature(
            r_value, P256_ORDER - s_value
        )
        signatures.append(
            {
                "keyid": probe.CURRENT_NPM_SIGNING_KEY_ID,
                "sig": base64.b64encode(second_signature).decode("ascii"),
            }
        )
    basename = name.rsplit("/", 1)[-1]
    dist: dict[str, object] = {
        "integrity": expected.integrity,
        "tarball": f"https://registry.npmjs.org/{name}/-/{basename}-{version}.tgz",
        "signatures": signatures,
    }
    if expected.provenance_present:
        dist["attestations"] = {
            "url": (
                "https://registry.npmjs.org/-/npm/v1/attestations/"
                + name.replace("/", "%2f")
                + "@"
                + version
            ),
            "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
        }
    peers = PEER_RANGES.get(name, {})
    peer_meta = {
        peer: {"optional": True}
        for peer in peers
        if (name, peer) in OPTIONAL_PEERS
    }
    value: dict[str, object] = {
        "name": name,
        "version": version,
        "license": expected.license,
        "dist": dist,
    }
    if name in ENGINE_RANGES:
        value["engines"] = {
            "node": ENGINE_RANGES[name],
            **EXTRA_ENGINE_FIELDS.get(name, {}),
        }
    if peers:
        value["peerDependencies"] = peers
    if peer_meta:
        value["peerDependenciesMeta"] = peer_meta
    if name in DEPENDENCIES:
        value["dependencies"] = DEPENDENCIES[name]
    return _canonical(value)


def _proof_bodies(
    private_key: ec.EllipticCurvePrivateKey,
) -> tuple[dict[str, bytes], bytes]:
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_material = base64.b64encode(public_der).decode("ascii")
    bodies: dict[str, bytes] = {}
    selections = loader.SELECTED_PACKAGES + (loader.TOOLCHAIN_NPM_PACKAGE,)
    for selection in selections:
        bodies[f"npm-package:{selection.name}@{selection.version}"] = _metadata_body(
            selection.name, selection.version, private_key
        )
    bodies["npm-signing-keys"] = _canonical(
        {
            "keys": [
                {
                    "keyid": probe.CURRENT_NPM_SIGNING_KEY_ID,
                    "key": public_material,
                    "keytype": probe.CURRENT_NPM_SIGNING_KEY_TYPE,
                    "scheme": probe.CURRENT_NPM_SIGNING_KEY_SCHEME,
                    "expires": None,
                },
                {
                    "keyid": "SHA256:unrelated-key",
                    "key": public_material,
                    "keytype": probe.CURRENT_NPM_SIGNING_KEY_TYPE,
                    "scheme": probe.CURRENT_NPM_SIGNING_KEY_SCHEME,
                    "expires": "2027-01-01T00:00:00.000Z",
                },
            ]
        }
    )
    bodies["npm-direct-advisories"] = b"{}"
    bodies["node-release-index"] = _canonical(
        [
            {
                "version": "v25.1.0",
                "date": "2026-08-10",
                "files": ["headers", "linux-x64"],
                "lts": False,
                "npm": "11.17.0",
                "security": False,
            },
            {
                "version": loader.NODE_VERSION_TAG,
                "date": probe.NODE_RELEASE_DATE,
                "files": ["headers", "linux-x64", "win-x64-zip"],
                "lts": probe.NODE_LTS_CODENAME,
                "npm": loader.NPM_VERSION,
                "security": False,
            },
            {
                "version": "v24.18.0",
                "date": "2026-07-01",
                "files": ["headers", "linux-x64"],
                "lts": probe.NODE_LTS_CODENAME,
                "npm": "11.16.0",
                "security": False,
            },
        ]
    )
    shasums = (
        b"0000000000000000000000000000000000000000000000000000000000000000  node-v24.19.0.tar.gz\n"
        b"1111111111111111111111111111111111111111111111111111111111111111  win-x64/node.exe\n"
    )
    bodies["node-release-shasums"] = shasums
    return bodies, public_material.encode("ascii")


def _live_evidence(
    monkeypatch: pytest.MonkeyPatch,
    body_mutator: Callable[[dict[str, bytes]], None] | None = None,
    *,
    advisory_content_type_absent: bool = False,
) -> tuple[bytes, loader.LiveEcosystemRegistryEvidence, dict[str, bytes]]:
    private_key = ec.derive_private_key(
        0x236235236235236235236235236235236235236235236235236235236235,
        ec.SECP256R1(),
    )
    bodies, public_material_bytes = _proof_bodies(private_key)
    if body_mutator is not None:
        body_mutator(bodies)
    monkeypatch.setattr(
        probe, "CURRENT_NPM_SIGNING_KEY_MATERIAL", public_material_bytes.decode("ascii")
    )
    monkeypatch.setattr(
        probe,
        "NODE_SHASUMS_BODY_SHA256",
        hashlib.sha256(bodies["node-release-shasums"]).hexdigest(),
    )
    contract = {
        (item["method"], item["url"]): item
        for item in loader.official_request_contract_projection()
    }

    def handler(request: httpx.Request) -> httpx.Response:
        item = contract[(request.method, str(request.url))]
        request_id = item["request_id"]
        media_type = item["accepted_media_types"][0]
        headers = (
            {}
            if advisory_content_type_absent
            and request_id == "npm-direct-advisories"
            else {"Content-Type": media_type}
        )
        return _unread_response(
            request,
            headers=headers,
            body=bodies[request_id],
        )

    real_client = loader.httpx.Client

    def client_factory(*args: object, **kwargs: object) -> httpx.Client:
        if kwargs.get("transport") is None:
            kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(loader.httpx, "Client", client_factory)
    authorization = _valid_authorization()
    validated = probe.validate_entra_calling_client_msal_frontend_host_ecosystem_compatibility_authorization(
        authorization
    )
    evidence = loader._load_live_ecosystem_registry_evidence(validated)
    assert loader.is_attested_live_ecosystem_registry_evidence(evidence)
    return authorization, evidence, bodies


def _replace_response_body(
    evidence: loader.LiveEcosystemRegistryEvidence,
    request_id: str,
    body: bytes,
) -> loader.LiveEcosystemRegistryEvidence:
    responses = tuple(
        dataclasses.replace(
            response,
            body=body,
            body_sha256=hashlib.sha256(body).hexdigest(),
        )
        if response.request_id == request_id
        else response
        for response in evidence.requests
    )
    return dataclasses.replace(
        evidence,
        requests=responses,
        aggregate_response_bytes=sum(len(response.body) for response in responses),
    )


def test_valid_live_exact_tuple_returns_explicit_bounded_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization, evidence, _ = _live_evidence(monkeypatch)
    receipt = probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
        authorization, evidence
    )
    assert receipt.readiness_status == probe.STATUS
    assert receipt.manifest_direct_package_count == 19
    assert receipt.mandatory_transitive_anchor_count == 3
    assert receipt.frontend_ecosystem_metadata_count == 22
    assert receipt.registry_package_metadata_count == 23
    assert receipt.official_http_request_count == 27
    assert receipt.signature_entry_count == 37
    assert receipt.signature_verified_package_count == 23
    assert receipt.provenance_present_count == 15
    assert receipt.provenance_absence_disposition_count == 8
    assert receipt.selected_metadata_advisory_count == 0
    assert receipt.peer_relationship_count == 41
    assert receipt.optional_peer_absence_disposition_count == 23
    assert receipt.current_registry_signature_verified_for_each_package
    assert receipt.receipt_is_not_independent_network_provenance
    assert receipt.accepted_console_invocation_and_exact_payload_hashes_required
    assert not receipt.complete_transitive_dependency_graph_resolved
    assert not receipt.transitive_dependency_advisory_audit_completed
    assert not receipt.package_tarball_downloaded
    assert not receipt.package_tarball_bytes_integrity_verified
    assert not receipt.provenance_attestation_statement_downloaded_or_verified
    assert not receipt.node_distribution_artifact_selected
    assert not receipt.node_shasums_signature_verified
    assert not receipt.package_manifest_created_or_modified
    assert not receipt.lockfile_created_or_modified
    assert not receipt.package_manager_executed
    assert not receipt.frontend_root_created


def test_live_advisory_response_with_absent_content_type_is_accepted_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization, evidence, _ = _live_evidence(
        monkeypatch, advisory_content_type_absent=True
    )
    advisory = next(
        response
        for response in evidence.requests
        if response.request_id == "npm-direct-advisories"
    )
    assert advisory.media_type == "absent"
    receipt = probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
        authorization, evidence
    )
    assert receipt.selected_metadata_advisory_disposition_complete


def test_receipt_render_is_canonical_and_round_trips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization, evidence, _ = _live_evidence(monkeypatch)
    receipt = probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
        authorization, evidence
    )
    rendered = probe.render_entra_calling_client_msal_frontend_host_ecosystem_compatibility_receipt(
        receipt
    )
    assert rendered == _canonical(json.loads(rendered))
    assert b"registry.npmjs.org" not in rendered
    assert b"nodejs.org" not in rendered
    assert json.loads(rendered)["official_response_body_set_sha256"] == (
        receipt.official_response_body_set_sha256
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("node_lts_codename", "changed"),
        ("signature_entry_count", 36),
        ("signature_verified_package_count", 22),
        ("provenance_present_count", 14),
        ("provenance_absence_disposition_count", 7),
        ("peer_relationship_count", 40),
        ("optional_peer_absence_disposition_count", 22),
        ("schema_version", True),
        ("selected_metadata_advisory_count", False),
        ("aggregate_response_bytes", 0),
        ("exact_step235_chain_bound", False),
        ("package_tarball_downloaded", True),
        ("official_response_body_set_sha256", "0" * 63),
    ],
)
def test_receipt_constructor_rejects_control_count_and_digest_tampering(
    monkeypatch: pytest.MonkeyPatch, field: str, replacement: object
) -> None:
    authorization, evidence, _ = _live_evidence(monkeypatch)
    receipt = probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
        authorization, evidence
    )
    with pytest.raises(ValueError):
        tampered = dataclasses.replace(receipt, **{field: replacement})
        probe.render_entra_calling_client_msal_frontend_host_ecosystem_compatibility_receipt(
            tampered
        )


@pytest.mark.parametrize(
    "field",
    [
        "approved_step235_package_manifest_sha256",
        "approved_step235_accepted_state_manifest_sha256",
        "approved_step235_architecture_selection_readiness_sha256",
        "approved_step235_architecture_selection_test_sha256",
        "approved_step235_canonical_receipt_sha256",
        "approved_step235_readiness_document_sha256",
        "approved_step235_architecture_plan_sha256",
        "approved_step235_security_plan_sha256",
        "approved_step235_experience_and_test_plan_sha256",
        "approved_step235_deferred_gate_plan_sha256",
    ],
)
def test_each_step235_identity_is_exact(field: str) -> None:
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityError):
        probe.validate_entra_calling_client_msal_frontend_host_ecosystem_compatibility_authorization(
            _valid_authorization(**{field: "0" * 64})
        )


def test_authorization_rejects_duplicate_unknown_wrong_type_and_oversize() -> None:
    duplicate = _valid_authorization()[:-1] + b',"schema_version":1}'
    unknown = json.loads(_valid_authorization())
    unknown["unexpected"] = False
    wrong = json.loads(_valid_authorization())
    wrong["schema_version"] = "1"
    for body in (
        duplicate,
        _canonical(unknown),
        _canonical(wrong),
        b"x" * (probe.MAX_AUTHORIZATION_BYTES + 1),
    ):
        with pytest.raises(
            probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityError
        ):
            probe.validate_entra_calling_client_msal_frontend_host_ecosystem_compatibility_authorization(
                body
            )


def test_json_nonfinite_overflow_is_rejected() -> None:
    with pytest.raises(ValueError):
        probe._bounded_json(b'{"value":1e999}')


def test_synthetic_evidence_cannot_be_relabelled_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization, _, _ = _live_evidence(monkeypatch)
    synthetic = loader.load_synthetic_ecosystem_registry_evidence(
        transport=httpx.MockTransport(
            lambda request: _unread_response(
                request,
                headers={"Content-Type": (
                    "text/plain"
                    if request.url.path.endswith("SHASUMS256.txt")
                    else "application/json"
                )},
                body=(b"x" if request.url.path.endswith("SHASUMS256.txt") else b"{}"),
            )
        )
    )
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityError):
        probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
            authorization, synthetic
        )
    forged_label = dataclasses.replace(
        synthetic, evidence_source="live_bounded_official_https"
    )
    assert not loader.is_attested_live_ecosystem_registry_evidence(forged_label)


@pytest.mark.parametrize("attribute", ["method", "url", "media_type"])
def test_response_id_method_url_media_type_correlation_is_exact(
    monkeypatch: pytest.MonkeyPatch, attribute: str
) -> None:
    authorization, evidence, _ = _live_evidence(monkeypatch)
    first = evidence.requests[0]
    replacement = {
        "method": "POST",
        "url": "https://registry.npmjs.org/react/19.2.8",
        "media_type": "text/plain",
    }[attribute]
    changed = dataclasses.replace(first, **{attribute: replacement})
    tampered = dataclasses.replace(
        evidence, requests=(changed,) + evidence.requests[1:]
    )
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityError):
        probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
            authorization, tampered
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("license", "GPL-3.0-only"),
        ("deprecated", "withdrawn"),
    ],
)
def test_license_and_deprecation_changes_fail_closed(
    monkeypatch: pytest.MonkeyPatch, field: str, replacement: str
) -> None:
    authorization, evidence, _ = _live_evidence(monkeypatch)
    request_id = "npm-package:react@19.2.8"
    body = json.loads(next(r.body for r in evidence.requests if r.request_id == request_id))
    body[field] = replacement
    tampered = _replace_response_body(evidence, request_id, _canonical(body))
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityError):
        probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
            authorization, tampered
        )


def test_exact_sri_and_tarball_package_correlation_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization, evidence, _ = _live_evidence(monkeypatch)
    request_id = "npm-package:react@19.2.8"
    original = json.loads(next(r.body for r in evidence.requests if r.request_id == request_id))
    mutations = []
    wrong_sri = json.loads(json.dumps(original))
    wrong_sri["dist"]["integrity"] = "sha512-" + base64.b64encode(b"x" * 64).decode()
    mutations.append(wrong_sri)
    wrong_tarball = json.loads(json.dumps(original))
    wrong_tarball["dist"]["tarball"] = (
        "https://registry.npmjs.org/other/-/other-19.2.8.tgz"
    )
    mutations.append(wrong_tarball)
    for mutation in mutations:
        tampered = _replace_response_body(evidence, request_id, _canonical(mutation))
        with pytest.raises(
            probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityError
        ):
            probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
                authorization, tampered
            )


@pytest.mark.parametrize("field", ["key", "keytype", "scheme", "expires"])
def test_reviewed_current_signing_key_fields_are_exact(
    monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    authorization, evidence, _ = _live_evidence(monkeypatch)
    request_id = "npm-signing-keys"
    value = json.loads(next(r.body for r in evidence.requests if r.request_id == request_id))
    value["keys"][0][field] = "changed"
    tampered = _replace_response_body(evidence, request_id, _canonical(value))
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityError):
        probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
            authorization, tampered
        )


def test_package_signature_and_provenance_status_are_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization, evidence, _ = _live_evidence(monkeypatch)
    request_id = "npm-package:react@19.2.8"
    value = json.loads(next(r.body for r in evidence.requests if r.request_id == request_id))
    invalid_signature = json.loads(json.dumps(value))
    invalid_signature["dist"]["signatures"][0]["sig"] = base64.b64encode(
        b"invalid"
    ).decode()
    absent_provenance = json.loads(json.dumps(value))
    del absent_provenance["dist"]["attestations"]
    for mutation in (invalid_signature, absent_provenance):
        tampered = _replace_response_body(evidence, request_id, _canonical(mutation))
        with pytest.raises(
            probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityError
        ):
            probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
                authorization, tampered
            )


def test_each_repeated_current_key_signature_must_be_distinct_and_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization, evidence, _ = _live_evidence(monkeypatch)
    request_id = "npm-package:vite@8.2.1"
    value = json.loads(next(r.body for r in evidence.requests if r.request_id == request_id))
    duplicate = json.loads(json.dumps(value))
    duplicate["dist"]["signatures"][1]["sig"] = duplicate["dist"]["signatures"][0][
        "sig"
    ]
    wrong_key = json.loads(json.dumps(value))
    wrong_key["dist"]["signatures"][1]["keyid"] = "SHA256:legacy"
    invalid_second = json.loads(json.dumps(value))
    invalid_second["dist"]["signatures"][1]["sig"] = base64.b64encode(
        b"invalid-second"
    ).decode("ascii")
    for mutation in (duplicate, wrong_key, invalid_second):
        tampered = _replace_response_body(evidence, request_id, _canonical(mutation))
        with pytest.raises(
            probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityError
        ):
            probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
                authorization, tampered
            )


def test_incompatible_engine_peer_and_anchor_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization, evidence, _ = _live_evidence(monkeypatch)
    mutations: list[tuple[str, dict[str, object]]] = []
    vite_id = "npm-package:vite@8.2.1"
    vite = json.loads(next(r.body for r in evidence.requests if r.request_id == vite_id))
    vite["engines"]["node"] = ">=25.0.0"
    mutations.append((vite_id, vite))
    dom_id = "npm-package:react-dom@19.2.8"
    dom = json.loads(next(r.body for r in evidence.requests if r.request_id == dom_id))
    dom["peerDependencies"]["react"] = "^20.0.0"
    mutations.append((dom_id, dom))
    msal_id = "npm-package:@azure/msal-browser@5.18.0"
    msal = json.loads(next(r.body for r in evidence.requests if r.request_id == msal_id))
    del msal["dependencies"]["@azure/msal-common"]
    mutations.append((msal_id, msal))
    msal_range_drift = json.loads(
        next(r.body for r in evidence.requests if r.request_id == msal_id)
    )
    msal_range_drift["dependencies"]["@azure/msal-common"] = "^16.12.0"
    mutations.append((msal_id, msal_range_drift))
    vitest_id = "npm-package:vitest@4.1.11"
    vitest = json.loads(
        next(r.body for r in evidence.requests if r.request_id == vitest_id)
    )
    del vitest["dependencies"]["vite"]
    mutations.append((vitest_id, vitest))
    for request_id, mutation in mutations:
        tampered = _replace_response_body(evidence, request_id, _canonical(mutation))
        with pytest.raises(
            probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityError
        ):
            probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
                authorization, tampered
            )


def test_nonempty_advisory_response_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization, evidence, _ = _live_evidence(monkeypatch)
    tampered = _replace_response_body(
        evidence,
        "npm-direct-advisories",
        _canonical({"react": [{"severity": "high"}]}),
    )
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityError):
        probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
            authorization, tampered
        )


@pytest.mark.parametrize("field", ["npm", "lts", "date", "security"])
def test_node_release_exact_fields_fail_closed(
    monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    authorization, evidence, _ = _live_evidence(monkeypatch)
    request_id = "node-release-index"
    value = json.loads(next(r.body for r in evidence.requests if r.request_id == request_id))
    selected = next(item for item in value if item["version"] == loader.NODE_VERSION_TAG)
    selected[field] = True if field == "security" else "changed"
    tampered = _replace_response_body(evidence, request_id, _canonical(value))
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityError):
        probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
            authorization, tampered
        )


def test_newer_node24_lts_and_shasums_change_force_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization, evidence, _ = _live_evidence(monkeypatch)
    index_id = "node-release-index"
    index = json.loads(next(r.body for r in evidence.requests if r.request_id == index_id))
    index.append(
        {
            "version": "v24.20.0",
            "date": "2026-09-01",
            "files": ["headers"],
            "lts": probe.NODE_LTS_CODENAME,
            "npm": "11.18.0",
            "security": False,
        }
    )
    newer = _replace_response_body(evidence, index_id, _canonical(index))
    changed_sum = _replace_response_body(
        evidence, "node-release-shasums", b"0" * 64 + b"  ../escape\n"
    )
    for tampered in (newer, changed_sum):
        with pytest.raises(
            probe.EntraCallingClientMSALFrontendHostEcosystemCompatibilityError
        ):
            probe.load_entra_calling_client_msal_frontend_host_ecosystem_compatibility(
                authorization, tampered
            )


@pytest.mark.parametrize(
    ("version", "constraint", "accepted"),
    [
        ("24.19.0", "^20.19.0 || >=22.12.0", True),
        ("24.19.0", ">=22.22.0", True),
        ("8.2.1", "^6.0.0 || ^7.0.0 || ^8.0.0-0", True),
        ("19.2.8", "^19.2.8", True),
        ("10.4.1", ">=10.0.0 <11.0.0", True),
        ("19.2.8", "^20.0.0", False),
        ("24.19.0", ">=25.0.0", False),
    ],
)
def test_closed_semver_evaluator(
    version: str, constraint: str, accepted: bool
) -> None:
    assert probe._satisfies_semver(version, constraint) is accepted


def test_probe_source_is_pure_and_has_no_network_or_mutation_imports() -> None:
    source = inspect.getsource(probe)
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not {
        "httpx",
        "requests",
        "urllib.request",
        "os",
        "pathlib",
        "subprocess",
    }.intersection(imports)
    forbidden_calls = {"open", "exec", "eval", "compile", "__import__"}
    assert not {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }.intersection(forbidden_calls)
