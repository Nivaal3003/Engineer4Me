"""Tests for the controlled MSAL Browser npm distribution artifact proof."""

from __future__ import annotations

import ast
import base64
import hashlib
import io
import json
import tarfile
from dataclasses import fields
from pathlib import Path

import pytest
from app.security.authentication_entra_calling_client_msal_browser_retry_reconciliation_readiness import (
    load_entra_calling_client_msal_retry_reconciliation_readiness,
)

import app.security.authentication_entra_calling_client_msal_browser_npm_artifact_probe as module
from app.security.authentication_entra_calling_client_msal_browser_npm_artifact_probe import (
    ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_DOCUMENT_TYPE,
    ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_PROFILE,
    ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_RECEIPT_TYPE,
    ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SCOPE,
    ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SOURCE,
    ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_STATUS,
    EntraCallingClientMSALBrowserNpmArtifactProbeError,
    probe_entra_calling_client_msal_browser_npm_artifact,
    render_entra_calling_client_msal_browser_npm_artifact_receipt,
)
from app.security.authentication_entra_calling_client_msal_browser_npm_http_loader import (
    MSAL_BROWSER_NPM_PACKAGE_NAME,
    MSAL_BROWSER_NPM_REVIEWED_LATEST_VERSION,
    MSAL_BROWSER_NPM_REVIEWED_VERSION,
    NPM_TARBALL_URL,
    EntraCallingClientMSALBrowserNpmHTTPResponse,
    build_entra_calling_client_msal_browser_npm_request_plan,
)
from tests import (
    test_security_authentication_entra_calling_client_msal_browser_retry_reconciliation_readiness as step218,
)


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def prerequisites(redirect_uris=(step218.step217.step216.step214.REDIRECT_URI,)):
    prior = step218.prerequisites(redirect_uris)
    retry_document = json.dumps(step218.values(prior), separators=(",", ":")).encode()
    receipt = load_entra_calling_client_msal_retry_reconciliation_readiness(
        document=retry_document,
        **prior,
    )
    return {
        **prior,
        "retry_reconciliation_document": retry_document,
        "approved_retry_reconciliation_document_sha256": (
            receipt.retry_reconciliation_document_sha256
        ),
    }


def document_values(prior):
    return {
        "document_type": ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_DOCUMENT_TYPE,
        "schema_version": 1,
        "source": ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SOURCE,
        "approved_retry_reconciliation_document_sha256": prior[
            "approved_retry_reconciliation_document_sha256"
        ],
        "artifact_profile": ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_PROFILE,
    }


def package_json(**changes):
    value = {
        "name": MSAL_BROWSER_NPM_PACKAGE_NAME,
        "version": MSAL_BROWSER_NPM_REVIEWED_VERSION,
        "license": "MIT",
        "exports": {
            ".": {
                "import": "./dist/index.mjs",
                "require": "./dist/index.cjs",
            },
            "./redirect-bridge": {
                "import": "./dist/redirect-bridge.mjs",
                "require": "./dist/redirect-bridge.cjs",
            },
            "./package.json": "./package.json",
        },
        "dependencies": {"@azure/msal-common": "16.11.3"},
        "scripts": {"build": "tsc"},
    }
    value.update(changes)
    return value


def tarball(*, package=None, extra=None, member_type=None):
    files = {
        "package/package.json": canonical(package or package_json()),
        "package/dist/index.mjs": b"export const packageName = 'msal-browser';\n",
        "package/dist/index.cjs": b"exports.packageName = 'msal-browser';\n",
        "package/dist/redirect-bridge.mjs": b"export function bridge() {}\n",
        "package/dist/redirect-bridge.cjs": b"exports.bridge = function () {};\n",
        "package/LICENSE": b"MIT License\n",
    }
    if extra:
        files.update(extra)
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT
    ) as archive:
        for name, body in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mode = 0o644
            info.mtime = 0
            if member_type is not None and name == next(iter(files)):
                info.type = member_type
                info.linkname = "package/LICENSE"
                info.size = 0
                archive.addfile(info)
            else:
                archive.addfile(info, io.BytesIO(body))
    return output.getvalue()


def evidence(
    *,
    tar_bytes=None,
    latest=MSAL_BROWSER_NPM_REVIEWED_LATEST_VERSION,
    metadata_changes=None,
    live=False,
):
    tar_bytes = tar_bytes or tarball()
    dist_tags = canonical({"latest": latest, "beta": "6.0.0-beta.1"})
    metadata = {
        "name": MSAL_BROWSER_NPM_PACKAGE_NAME,
        "version": MSAL_BROWSER_NPM_REVIEWED_VERSION,
        "license": "MIT",
        "dist": {
            "integrity": "sha512-"
            + base64.b64encode(hashlib.sha512(tar_bytes).digest()).decode(),
            "shasum": hashlib.sha1(tar_bytes, usedforsecurity=False).hexdigest(),
            "tarball": NPM_TARBALL_URL,
        },
    }
    if metadata_changes:
        metadata.update(metadata_changes)
    metadata_bytes = canonical(metadata)
    bodies = (dist_tags, metadata_bytes, tar_bytes)
    responses = []
    for request, body in zip(
        build_entra_calling_client_msal_browser_npm_request_plan(), bodies, strict=True
    ):
        responses.append(
            EntraCallingClientMSALBrowserNpmHTTPResponse(
                request=request,
                status_code=200,
                content_type=(
                    "application/octet-stream"
                    if request.resource == "tarball"
                    else "application/json"
                ),
                body=body,
                final_url=request.url,
                header_bytes=96,
                content_length=len(body),
                live_https_attested=live,
                tls_certificate_chain_checked=live,
                tls_hostname_checked=live,
                proxy_bypassed=live,
                redirects_rejected=live,
                retries_disabled=live,
                response_source_authenticity_checked=live,
            )
        )
    return tuple(responses)


def load(*, prior=None, values=None, evidence_value=None):
    prior = prior or prerequisites()
    values = document_values(prior) if values is None else values
    responses = evidence_value or evidence()

    def transport(plan):
        assert plan == build_entra_calling_client_msal_browser_npm_request_plan()
        return responses

    return probe_entra_calling_client_msal_browser_npm_artifact(
        document=json.dumps(values, separators=(",", ":")).encode(),
        transport=transport,
        **prior,
    )


def unsafe_replace(receipt, **changes):
    clone = object.__new__(type(receipt))
    for field in fields(receipt):
        object.__setattr__(
            clone, field.name, changes.get(field.name, getattr(receipt, field.name))
        )
    return clone


def production_exception_material(error):
    material = []
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        material.extend((repr(current), *(repr(item) for item in current.args)))
        pending.extend(
            linked
            for linked in (current.__context__, current.__cause__)
            if isinstance(linked, BaseException)
        )
        pending.extend(getattr(current, "exceptions", ()))
        traceback = current.__traceback__
        while traceback is not None:
            if traceback.tb_frame.f_globals.get("__name__") == module.__name__:
                material.extend(
                    repr(item) for item in traceback.tb_frame.f_locals.values()
                )
            traceback = traceback.tb_next
    return "\n".join(material)


def test_valid_synthetic_artifact_receipt_is_fail_closed():
    receipt = load()
    assert receipt.receipt_type == ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_RECEIPT_TYPE
    assert receipt.validation_scope == ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_SCOPE
    assert receipt.artifact_status == ENTRA_CALLING_CLIENT_MSAL_NPM_ARTIFACT_STATUS
    assert receipt.reviewed_candidate_version == "5.17.3"
    assert receipt.reviewed_latest_dist_tag_version == "5.18.0"
    assert receipt.synthetic_transport_used is True
    assert receipt.sealed_registry_request_count == 0
    assert all(
        getattr(receipt, name) is True for name in module._STRUCTURAL_TRUE_FIELDS
    )
    assert all(getattr(receipt, name) is False for name in module._LIVE_FIELDS)
    assert all(
        getattr(receipt, name) is False for name in module._DEFERRED_FALSE_FIELDS
    )
    assert receipt.candidate_is_latest is False
    assert receipt.package_selection_ready is False
    assert receipt.compiled_retry_path_inspected is False
    assert receipt.activation_ready is False


def test_response_hashes_and_archive_counts_are_independently_recomputed():
    responses = evidence()
    receipt = load(evidence_value=responses)
    assert (
        receipt.dist_tags_response_sha256
        == hashlib.sha256(responses[0].body).hexdigest()
    )
    assert (
        receipt.version_metadata_response_sha256
        == hashlib.sha256(responses[1].body).hexdigest()
    )
    assert receipt.tarball_sha256 == hashlib.sha256(responses[2].body).hexdigest()
    assert receipt.tarball_sha512 == hashlib.sha512(responses[2].body).hexdigest()
    assert receipt.evidence_response_count == 3
    assert receipt.regular_file_count == 6
    assert receipt.directory_count == 0
    assert receipt.lifecycle_install_script_count == 0
    assert receipt.export_target_count == 5
    assert receipt.runtime_dependency_count == 1


def test_live_receipt_partition_is_constructible_but_not_synthetic_public_input():
    receipt = load()
    changes = {name: True for name in module._LIVE_FIELDS}
    changes.update(synthetic_transport_used=False, sealed_registry_request_count=3)
    live_receipt = unsafe_replace(receipt, **changes)
    live_receipt.__post_init__()
    with pytest.raises(EntraCallingClientMSALBrowserNpmArtifactProbeError):
        load(evidence_value=evidence(live=True))


@pytest.mark.parametrize(
    "latest",
    [MSAL_BROWSER_NPM_REVIEWED_VERSION, "5.18.1", "latest", "05.18.0"],
)
def test_live_latest_tag_must_equal_reviewed_newer_version(latest):
    with pytest.raises(EntraCallingClientMSALBrowserNpmArtifactProbeError):
        load(evidence_value=evidence(latest=latest))


@pytest.mark.parametrize(
    "changes",
    [
        {"name": "other"},
        {"version": "5.17.2"},
        {"license": "ISC"},
        {"deprecated": "do not use"},
        {"dist": {}},
    ],
)
def test_version_metadata_identity_is_exact(changes):
    with pytest.raises(EntraCallingClientMSALBrowserNpmArtifactProbeError):
        load(evidence_value=evidence(metadata_changes=changes))


def test_sha512_and_legacy_sha1_must_both_match_tarball():
    values = list(evidence())
    tampered = bytearray(values[2].body)
    tampered[-1] ^= 1
    values[2] = unsafe_replace(
        values[2], body=bytes(tampered), content_length=len(tampered)
    )
    with pytest.raises(EntraCallingClientMSALBrowserNpmArtifactProbeError):
        load(evidence_value=tuple(values))


@pytest.mark.parametrize("mutation", ["short", "swapped"])
def test_partial_or_reordered_response_tuple_emits_no_receipt(mutation):
    values = evidence()
    if mutation == "short":
        changed = values[:2]
    else:
        changed = (values[1], values[0], values[2])
    with pytest.raises(EntraCallingClientMSALBrowserNpmArtifactProbeError):
        load(evidence_value=changed)


@pytest.mark.parametrize(
    "package_changes",
    [
        {"name": "other"},
        {"version": "5.17.2"},
        {"license": "ISC"},
        {"scripts": {"preinstall": "node evil.js"}},
        {"scripts": {"install": "node evil.js"}},
        {"scripts": {"postinstall": "node evil.js"}},
        {"exports": {".": "./dist/index.mjs"}},
        {
            "exports": {
                ".": "./missing.js",
                "./redirect-bridge": "./dist/redirect-bridge.mjs",
            }
        },
        {"dependencies": []},
        {"dependencies": {"x": 1}},
    ],
)
def test_package_json_identity_lifecycle_exports_and_dependencies_fail_closed(
    package_changes,
):
    with pytest.raises(EntraCallingClientMSALBrowserNpmArtifactProbeError):
        load(
            evidence_value=evidence(
                tar_bytes=tarball(package=package_json(**package_changes))
            )
        )


@pytest.mark.parametrize(
    "extra",
    [
        {"../escape": b"x"},
        {"/absolute": b"x"},
        {"package/../escape": b"x"},
        {"package\\evil": b"x"},
        {"Package/LICENSE": b"duplicate-case"},
        {"package/license.txt": b"second license"},
    ],
)
def test_tar_paths_and_license_closure_fail_closed(extra):
    with pytest.raises(EntraCallingClientMSALBrowserNpmArtifactProbeError):
        load(evidence_value=evidence(tar_bytes=tarball(extra=extra)))


@pytest.mark.parametrize(
    "member_type", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE]
)
def test_tar_links_and_special_files_are_rejected(member_type):
    with pytest.raises(EntraCallingClientMSALBrowserNpmArtifactProbeError):
        load(evidence_value=evidence(tar_bytes=tarball(member_type=member_type)))


def test_missing_license_is_rejected():
    broken = tarball(extra={"package/LICENSE": b""})
    with pytest.raises(EntraCallingClientMSALBrowserNpmArtifactProbeError):
        load(evidence_value=evidence(tar_bytes=broken))


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"source": "other"},
        {"artifact_profile": "other"},
        {"approved_retry_reconciliation_document_sha256": "0" * 64},
    ],
)
def test_artifact_document_is_exact_and_digest_bound(change):
    prior = prerequisites()
    values = document_values(prior)
    values.update(change)
    with pytest.raises(EntraCallingClientMSALBrowserNpmArtifactProbeError):
        load(prior=prior, values=values)


def test_artifact_document_rejects_extra_missing_duplicate_and_malformed_json():
    prior = prerequisites()
    values = document_values(prior)
    for body in (
        {**values, "extra": True},
        {key: item for key, item in values.items() if key != "source"},
    ):
        with pytest.raises(EntraCallingClientMSALBrowserNpmArtifactProbeError):
            load(prior=prior, values=body)
    duplicate = (
        b'{"document_type":"x","document_type":"y","schema_version":1,'
        b'"source":"x","approved_retry_reconciliation_document_sha256":"'
        + b"0" * 64
        + b'","artifact_profile":"x"}'
    )
    with pytest.raises(EntraCallingClientMSALBrowserNpmArtifactProbeError):
        probe_entra_calling_client_msal_browser_npm_artifact(
            document=duplicate,
            transport=lambda plan: evidence(),
            **prior,
        )


def test_step218_chain_reruns_before_document_and_transport(monkeypatch):
    calls = []

    def fail(**_kwargs):
        calls.append("step218")
        raise ValueError("secret-prerequisite")

    monkeypatch.setattr(
        module,
        "load_entra_calling_client_msal_retry_reconciliation_readiness",
        fail,
    )
    prior = prerequisites()
    with pytest.raises(EntraCallingClientMSALBrowserNpmArtifactProbeError):
        probe_entra_calling_client_msal_browser_npm_artifact(
            document=b"malformed",
            transport=lambda _plan: calls.append("transport"),
            **prior,
        )
    assert calls == ["step218"]


@pytest.mark.parametrize(
    "failure", [ValueError("secret"), KeyboardInterrupt("secret"), SystemExit("secret")]
)
def test_transport_failures_are_context_free_and_preserve_control_flow(failure):
    prior = prerequisites()

    def transport(_plan):
        raise failure

    expected = (
        type(failure)
        if isinstance(failure, (KeyboardInterrupt, SystemExit))
        else EntraCallingClientMSALBrowserNpmArtifactProbeError
    )
    with pytest.raises(expected) as caught:
        probe_entra_calling_client_msal_browser_npm_artifact(
            document=canonical(document_values(prior)),
            transport=transport,
            **prior,
        )
    assert "secret" not in production_exception_material(caught.value)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_receipt_omits_raw_identity_and_archive_contents():
    prior = prerequisites(
        (
            "https://app.engineer4me.invalid/auth/callback",
            "https://app.engineer4me.invalid/auth/complete",
            "https://app.engineer4me.invalid/auth/return",
        )
    )
    receipt = load(prior=prior)
    rendered = render_entra_calling_client_msal_browser_npm_artifact_receipt(receipt)
    for secret in (
        "/auth/callback",
        "/auth/complete",
        "/auth/return",
        "redirect-bridge.mjs",
        "@azure/msal-common",
    ):
        assert secret not in rendered


def test_every_receipt_boolean_is_exhaustively_integrity_enforced():
    receipt = load()
    boolean_fields = [
        field.name
        for field in fields(receipt)
        if type(getattr(receipt, field.name)) is bool
    ]
    expected = {
        "synthetic_transport_used",
        *module._STRUCTURAL_TRUE_FIELDS,
        *module._LIVE_FIELDS,
        *module._DEFERRED_FALSE_FIELDS,
    }
    assert set(boolean_fields) == expected
    for name in boolean_fields:
        tampered = unsafe_replace(receipt, **{name: not getattr(receipt, name)})
        with pytest.raises(ValueError):
            tampered.__post_init__()


@pytest.mark.parametrize("invalid", [True, 0.0, "1", None])
def test_every_receipt_count_rejects_wrong_exact_type(invalid):
    receipt = load()
    for name in module._COUNT_FIELDS:
        tampered = unsafe_replace(receipt, **{name: invalid})
        with pytest.raises(ValueError):
            tampered.__post_init__()


def test_every_receipt_digest_and_public_string_is_bound():
    receipt = load()
    for field in fields(receipt):
        if field.name.endswith("_sha256") or field.name in module._PUBLIC_STRING_FIELDS:
            with pytest.raises(ValueError):
                unsafe_replace(receipt, **{field.name: "invalid"}).__post_init__()


@pytest.mark.parametrize(
    ("approved", "observed"),
    [
        ("approved_inventory_document_sha256", "inventory_document_sha256"),
        (
            "approved_redirect_endpoint_control_document_sha256",
            "redirect_endpoint_control_document_sha256",
        ),
        (
            "approved_pkce_runtime_control_document_sha256",
            "pkce_runtime_control_document_sha256",
        ),
        (
            "approved_msal_browser_control_document_sha256",
            "msal_browser_control_document_sha256",
        ),
        (
            "approved_retry_reconciliation_document_sha256",
            "retry_reconciliation_document_sha256",
        ),
    ],
)
def test_paired_provenance_digests_must_match(approved, observed):
    receipt = load()
    replacement = "0" * 64
    if getattr(receipt, observed) == replacement:
        replacement = "1" * 64
    with pytest.raises(ValueError):
        unsafe_replace(receipt, **{observed: replacement}).__post_init__()


def test_renderer_is_canonical_and_revalidates():
    receipt = load()
    rendered = render_entra_calling_client_msal_browser_npm_artifact_receipt(receipt)
    assert rendered == json.dumps(
        {field.name: getattr(receipt, field.name) for field in fields(receipt)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    with pytest.raises(ValueError):
        render_entra_calling_client_msal_browser_npm_artifact_receipt(
            unsafe_replace(receipt, activation_ready=True)
        )


def test_source_ast_has_unique_complete_receipt_partitions_and_no_execution_io():
    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    receipt_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "EntraCallingClientMSALBrowserNpmArtifactProofReceipt"
    )
    declared = [
        node.target.id
        for node in receipt_class.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    ]
    assert len(declared) == len(set(declared))
    boolean_partition = {
        "synthetic_transport_used",
        *module._STRUCTURAL_TRUE_FIELDS,
        *module._LIVE_FIELDS,
        *module._DEFERRED_FALSE_FIELDS,
    }
    receipt = load()
    assert boolean_partition == {
        name for name in declared if type(getattr(receipt, name)) is bool
    }
    imports = {
        alias.name.split(".")[0]
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imports.isdisjoint({"subprocess", "socket", "ssl", "urllib", "pathlib"})
    assert "extractall(" not in source
    assert "extract(" not in source
    assert "subprocess" not in source
