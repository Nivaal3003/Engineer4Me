from __future__ import annotations

import ast
import hashlib
import io
import inspect
import runpy
import sys
from pathlib import Path

import httpx
import pytest

from app.security import (
    authentication_entra_calling_client_msal_browser_frontend_host_execution_platform_artifact_http_loader
    as loader,
)
from app.security import (
    authentication_entra_calling_client_msal_browser_frontend_host_execution_platform_artifact_authenticity_toolchain_probe
    as probe,
)


class _Stream(httpx.SyncByteStream):
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self.chunks = chunks
        self.closed = False
        self.yields = 0

    def __iter__(self):
        for chunk in self.chunks:
            self.yields += 1
            yield chunk

    def close(self) -> None:
        self.closed = True


class _SizedStream(httpx.SyncByteStream):
    def __init__(self, size: int) -> None:
        self.size = size
        self.closed = False

    def __iter__(self):
        remaining = self.size
        chunk = b"\x00" * (1024 * 1024)
        while remaining:
            count = min(remaining, len(chunk))
            yield chunk[:count]
            remaining -= count

    def close(self) -> None:
        self.closed = True


_BODIES = {
    "node-release-signing-key": b"key",
    "node-release-shasums": b"sums",
    "node-release-shasums-detached-signature": b"sig",
    "node-release-shasums-clearsigned": b"asc",
    "node-windows-x64-portable-archive": b"zip-bytes",
}


def _tiny_specs() -> tuple[loader._RequestSpec, ...]:
    values = []
    for index, (request_id, body) in enumerate(_BODIES.items()):
        media = (
            "application/zip"
            if request_id.endswith("archive")
            else "application/pgp-signature"
            if request_id.endswith("signature")
            else "text/plain"
        )
        values.append(
            loader._RequestSpec(
                request_id=request_id,
                url=f"https://nodejs.org/test/{index}",
                accepted_media_types=(media,),
                expected_bytes=len(body),
                expected_sha256=hashlib.sha256(body).hexdigest(),
                maximum_response_bytes=len(body),
                persist_to_file=request_id.endswith("archive"),
            )
        )
    return tuple(values)


def _response(
    request: httpx.Request,
    *,
    body: bytes,
    content_type: str,
    status: int = 200,
    headers: dict[str, str] | None = None,
    chunks: tuple[bytes, ...] | None = None,
) -> httpx.Response:
    response_headers = {
        "Content-Type": content_type,
        "Content-Length": str(len(body)),
        "Accept-Ranges": "bytes",
    }
    if headers:
        response_headers.update(headers)
    return httpx.Response(
        status,
        headers=response_headers,
        stream=_Stream(chunks or (body,)),
        request=request,
    )


def _transport(
    mutate=None, observed: list[httpx.Request] | None = None
) -> httpx.MockTransport:
    specs = {spec.url: spec for spec in _tiny_specs()}

    def handler(request: httpx.Request) -> httpx.Response:
        if observed is not None:
            observed.append(request)
        spec = specs[str(request.url)]
        body = _BODIES[spec.request_id]
        media = spec.accepted_media_types[0]
        if mutate is not None:
            return mutate(request, spec, body, media)
        return _response(request, body=body, content_type=media)

    return httpx.MockTransport(handler)


def _canonical_receipt() -> probe.EntraCallingClientMSALFrontendHostArtifactProofReceipt:
    return probe.EntraCallingClientMSALFrontendHostArtifactProofReceipt(
        receipt_type=probe.RECEIPT_TYPE,
        schema_version=probe.SCHEMA_VERSION,
        source=probe.SOURCE,
        scope=probe.SCOPE,
        status=probe.STATUS,
        approved_step238_accepted_state_manifest_sha256=probe.STEP238_ACCEPTED_STATE_MANIFEST_SHA256,
        approved_step238_package_manifest_sha256=probe.STEP238_PACKAGE_MANIFEST_SHA256,
        approved_step238_readiness_sha256=probe.STEP238_READINESS_SHA256,
        approved_step238_readiness_test_sha256=probe.STEP238_READINESS_TEST_SHA256,
        approved_step238_canonical_receipt_sha256=probe.STEP238_CANONICAL_RECEIPT_SHA256,
        approved_step238_readiness_document_sha256=probe.STEP238_READINESS_DOCUMENT_SHA256,
        approved_step238_readiness_status=probe.STEP238_READINESS_STATUS,
        request_count=5,
        aggregate_response_bytes=37_311_607,
        response_body_set_sha256=probe.EXPECTED_RESPONSE_BODY_SET_SHA256,
        signer_fingerprint=probe.EXPECTED_SIGNER_FINGERPRINT,
        signer_key_id=probe.EXPECTED_SIGNER_KEY_ID,
        detached_signature_digest_sha256=probe.EXPECTED_DETACHED_DIGEST_SHA256,
        clearsigned_signature_digest_sha256=probe.EXPECTED_CLEARSIGNED_DIGEST_SHA256,
        signed_shasums_sha256=probe.NODE_SHASUMS_SHA256,
        sorted_shasums_sha256=probe.EXPECTED_SORTED_SHASUMS_SHA256,
        archive_sha256=probe.NODE_ARCHIVE_SHA256,
        central_directory_sha256=probe.EXPECTED_CENTRAL_DIRECTORY_SHA256,
        archive_inventory_sha256=probe.EXPECTED_ARCHIVE_INVENTORY_SHA256,
        extracted_file_inventory_sha256=probe.EXPECTED_EXTRACTED_FILE_INVENTORY_SHA256,
        entry_count=probe.EXPECTED_ENTRY_COUNT,
        file_count=probe.EXPECTED_FILE_COUNT,
        directory_count=probe.EXPECTED_DIRECTORY_COUNT,
        uncompressed_bytes=probe.EXPECTED_UNCOMPRESSED_BYTES,
        compressed_payload_bytes=probe.EXPECTED_COMPRESSED_PAYLOAD_BYTES,
        node_executable_sha256=probe.NODE_EXECUTABLE_SHA256,
        npm_manifest_sha256=probe.NPM_MANIFEST_SHA256,
        npm_cli_sha256=probe.NPM_CLI_SHA256,
        npm_manifest_name="npm",
        npm_manifest_version=probe.NPM_VERSION,
        temporary_artifacts_cleaned=True,
        both_openpgp_signatures_verified=True,
        signed_checksum_binding_verified=True,
        complete_archive_structure_and_inventory_verified=True,
        safe_extraction_and_complete_file_inventory_verified=True,
        static_node_npm_toolchain_identity_verified=True,
        host_vendor_support_verified=False,
        node_or_npm_executed=False,
        lock_generation_authorized_or_performed=False,
        frontend_materialized=False,
        operational_write_performed=False,
    )


@pytest.fixture
def tiny_contract(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(loader, "_request_specs", _tiny_specs)


def test_official_request_contract_is_exact() -> None:
    contract = loader.official_request_contract_projection()
    assert len(contract) == loader.MAX_REQUEST_COUNT == 5
    assert [item["request_id"] for item in contract] == [
        "node-release-signing-key",
        "node-release-shasums",
        "node-release-shasums-detached-signature",
        "node-release-shasums-clearsigned",
        "node-windows-x64-portable-archive",
    ]
    assert len({item["url"] for item in contract}) == 5
    assert sum(bool(item["persist_to_file"]) for item in contract) == 1
    assert all(item["method"] == "GET" for item in contract)
    assert contract[-1]["expected_bytes"] == 37_304_352
    assert contract[-1]["expected_sha256"] == loader.NODE_ARCHIVE_SHA256


def test_private_live_path_requires_validator_attestation() -> None:
    assert "_load_live_official_artifact_evidence" not in loader.__all__
    forged = probe.EntraCallingClientMSALFrontendHostArtifactProofAuthorization(
        **probe._authorization_projection()
    )
    with pytest.raises(loader.OfficialArtifactHttpLoaderError):
        loader._load_live_official_artifact_evidence(forged)
    validated = probe.validate_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
        probe.render_entra_calling_client_msal_frontend_host_artifact_proof_authorization()
    )
    assert probe.is_validated_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
        validated
    )


def test_synthetic_flow_streams_archive_and_cleans_up(
    tiny_contract, tmp_path: Path
) -> None:
    evidence = loader.load_synthetic_official_artifact_evidence(
        transport=_transport(), temporary_parent=str(tmp_path)
    )
    root = Path(evidence.temporary_root)
    assert root.is_dir()
    assert Path(evidence.archive_path).read_bytes() == b"zip-bytes"
    assert evidence.request_count == 5
    assert evidence.aggregate_response_bytes == sum(map(len, _BODIES.values()))
    assert not loader.is_attested_live_official_artifact_evidence(evidence)
    assert evidence.deadline_monotonic - evidence.started_monotonic == 300.0
    loader.cleanup_official_artifact_evidence(evidence)
    assert evidence.cleanup_completed
    assert not root.exists()


def test_synthetic_request_headers_and_order_are_exact(
    tiny_contract, tmp_path: Path
) -> None:
    observed: list[httpx.Request] = []
    evidence = loader.load_synthetic_official_artifact_evidence(
        transport=_transport(observed=observed), temporary_parent=str(tmp_path)
    )
    try:
        assert [str(request.url) for request in observed] == [
            spec.url for spec in _tiny_specs()
        ]
        assert all(request.method == "GET" for request in observed)
        assert all(request.headers["accept-encoding"] == "identity" for request in observed)
        assert all("authorization" not in request.headers for request in observed)
        assert all("cookie" not in request.headers for request in observed)
        assert all("proxy-authorization" not in request.headers for request in observed)
    finally:
        loader.cleanup_official_artifact_evidence(evidence)


@pytest.mark.parametrize(
    ("status", "content_type", "extra_headers", "message"),
    [
        (301, "text/plain", {}, "status"),
        (200, "text/plain", {"Location": "https://example.invalid"}, "redirected"),
        (200, "application/json", {}, "media type"),
        (200, "text/plain;charset=iso-8859-1", {}, "charset"),
        (200, "text/plain", {"Content-Encoding": "gzip"}, "encoded"),
        (200, "text/plain", {"Transfer-Encoding": "chunked"}, "encoded"),
        (200, "text/plain", {"Set-Cookie": "x=y"}, "cookie"),
        (200, "text/plain", {"Accept-Ranges": "none"}, "byte-range"),
    ],
)
def test_response_shape_rejections(
    tiny_contract,
    tmp_path: Path,
    status: int,
    content_type: str,
    extra_headers: dict[str, str],
    message: str,
) -> None:
    def mutate(request, spec, body, media):
        return _response(
            request,
            body=body,
            content_type=content_type,
            status=status,
            headers=extra_headers,
        )

    with pytest.raises(loader.OfficialArtifactHttpLoaderError, match=message):
        loader.load_synthetic_official_artifact_evidence(
            transport=_transport(mutate), temporary_parent=str(tmp_path)
        )
    assert not any(tmp_path.iterdir())


@pytest.mark.parametrize("declared", ["", "-1", "+3", "03", "x", "999999"])
def test_content_length_must_be_exact_decimal(
    tiny_contract, tmp_path: Path, declared: str
) -> None:
    def mutate(request, spec, body, media):
        response = _response(request, body=body, content_type=media)
        response.headers["Content-Length"] = declared
        return response

    with pytest.raises(loader.OfficialArtifactHttpLoaderError, match="content length"):
        loader.load_synthetic_official_artifact_evidence(
            transport=_transport(mutate), temporary_parent=str(tmp_path)
        )


def test_accept_ranges_may_be_absent(tiny_contract, tmp_path: Path) -> None:
    def mutate(request, spec, body, media):
        return httpx.Response(
            200,
            headers={"Content-Type": media, "Content-Length": str(len(body))},
            stream=_Stream((body,)),
            request=request,
        )

    evidence = loader.load_synthetic_official_artifact_evidence(
        transport=_transport(mutate), temporary_parent=str(tmp_path)
    )
    loader.cleanup_official_artifact_evidence(evidence)


def test_preconsumed_response_is_rejected(tiny_contract, tmp_path: Path) -> None:
    def mutate(request, spec, body, media):
        return httpx.Response(
            200,
            headers={"Content-Type": media, "Content-Length": str(len(body))},
            content=body,
            request=request,
        )

    with pytest.raises(loader.OfficialArtifactHttpLoaderError, match="not unread"):
        loader.load_synthetic_official_artifact_evidence(
            transport=_transport(mutate), temporary_parent=str(tmp_path)
        )


def test_wrong_streamed_hash_is_rejected_and_cleaned(
    tiny_contract, tmp_path: Path
) -> None:
    def mutate(request, spec, body, media):
        wrong = b"X" + body[1:]
        return _response(request, body=wrong, content_type=media)

    with pytest.raises(loader.OfficialArtifactHttpLoaderError, match="identity"):
        loader.load_synthetic_official_artifact_evidence(
            transport=_transport(mutate), temporary_parent=str(tmp_path)
        )
    assert not any(tmp_path.iterdir())


def test_streamed_overflow_stops_before_third_chunk(
    tiny_contract, tmp_path: Path
) -> None:
    stream_holder: list[_Stream] = []

    def mutate(request, spec, body, media):
        stream = _Stream((body, b"x", b"not-read"))
        stream_holder.append(stream)
        return httpx.Response(
            200,
            headers={
                "Content-Type": media,
                "Content-Length": str(len(body)),
                "Accept-Ranges": "bytes",
            },
            stream=stream,
            request=request,
        )

    with pytest.raises(loader.OfficialArtifactHttpLoaderError, match="exceeds"):
        loader.load_synthetic_official_artifact_evidence(
            transport=_transport(mutate), temporary_parent=str(tmp_path)
        )
    assert not any(tmp_path.iterdir())
    assert stream_holder[0].yields == 2
    assert stream_holder[0].closed


def test_cleanup_is_single_use_and_exact(tiny_contract, tmp_path: Path) -> None:
    evidence = loader.load_synthetic_official_artifact_evidence(
        transport=_transport(), temporary_parent=str(tmp_path)
    )
    loader.cleanup_official_artifact_evidence(evidence)
    with pytest.raises(loader.OfficialArtifactHttpLoaderError, match="already"):
        loader.cleanup_official_artifact_evidence(evidence)


def test_cleanup_failure_retains_ownership(
    tiny_contract, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = loader.load_synthetic_official_artifact_evidence(
        transport=_transport(), temporary_parent=str(tmp_path)
    )
    root = evidence.temporary_root
    original = loader.shutil.rmtree
    monkeypatch.setattr(
        loader.shutil,
        "rmtree",
        lambda path: (_ for _ in ()).throw(OSError("blocked")),
    )
    with pytest.raises(loader.OfficialArtifactHttpLoaderError, match="cleanup"):
        loader.cleanup_official_artifact_evidence(evidence)
    assert root in loader._OWNED_TEMPORARY_ROOTS
    monkeypatch.setattr(loader.shutil, "rmtree", original)
    loader.cleanup_official_artifact_evidence(evidence)


def test_python_m_cli_uses_one_canonical_module_and_emits_one_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = loader._CANONICAL_MODULE_NAME
    authorization = (
        probe.render_entra_calling_client_msal_frontend_host_artifact_proof_authorization()
    )
    receipt = _canonical_receipt()
    expected_line = (
        probe.render_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_receipt(
            receipt
        )
        + b"\n"
    )
    contract = loader.official_request_contract_projection()
    expected_hashes = [str(item["expected_sha256"]) for item in contract]
    observed: list[httpx.Request] = []
    proof_observations: dict[str, object] = {}
    real_client = httpx.Client
    real_sha256 = hashlib.sha256
    hash_index = 0

    class _PinnedDigest:
        def __init__(self, expected: str) -> None:
            self.expected = expected

        def update(self, unused: bytes) -> None:
            return None

        def hexdigest(self) -> str:
            return self.expected

    def staged_sha256(data: bytes = b""):
        nonlocal hash_index
        if hash_index < len(expected_hashes):
            expected = expected_hashes[hash_index]
            hash_index += 1
            value = _PinnedDigest(expected)
            value.update(data)
            return value
        return real_sha256(data)

    by_url = {str(item["url"]): item for item in contract}

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        item = by_url[str(request.url)]
        media_type = str(item["accepted_media_types"][0])
        if media_type == "text/plain":
            media_type += ";charset=utf-8"
        return httpx.Response(
            200,
            headers={
                "Content-Type": media_type,
                "Content-Length": str(item["expected_bytes"]),
                "Accept-Ranges": "bytes",
            },
            stream=_SizedStream(int(item["expected_bytes"])),
            request=request,
        )

    def client_factory(**kwargs: object) -> httpx.Client:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(**kwargs)

    def proof_loader(
        document: bytes, evidence: object
    ) -> probe.EntraCallingClientMSALFrontendHostArtifactProofReceipt:
        active = sys.modules[module_name]
        proof_observations["canonical_alias_active"] = (
            active is sys.modules["__main__"]
        )
        proof_observations["exact_class"] = (
            type(evidence) is active.LiveOfficialArtifactEvidence
        )
        proof_observations["live_attested"] = (
            active.is_attested_live_official_artifact_evidence(evidence)
        )
        proof_observations["authorization_exact"] = (
            document == authorization
            and probe.is_validated_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
                probe.validate_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
                    document
                )
            )
        )
        proof_observations["temporary_root"] = evidence.temporary_root
        active.cleanup_official_artifact_evidence(evidence)
        return receipt

    stdin = io.TextIOWrapper(io.BytesIO(authorization), encoding="ascii")
    stdout_bytes = io.BytesIO()
    stdout = io.TextIOWrapper(stdout_bytes, encoding="ascii")
    original_module = sys.modules.pop(module_name)
    executed_module = None
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(httpx, "Client", client_factory)
            scoped.setattr(hashlib, "sha256", staged_sha256)
            scoped.setattr(
                probe,
                "load_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_proof",
                proof_loader,
            )
            scoped.setattr(sys, "stdin", stdin)
            scoped.setattr(sys, "stdout", stdout)
            with pytest.raises(SystemExit) as exited:
                runpy.run_module(module_name, run_name="__main__", alter_sys=True)
            stdout.flush()
            executed_module = sys.modules.get(module_name)
    finally:
        sys.modules[module_name] = original_module

    assert exited.value.code == 0
    assert executed_module is not None and executed_module is not original_module
    assert proof_observations["canonical_alias_active"] is True
    assert proof_observations["exact_class"] is True
    assert proof_observations["live_attested"] is True
    assert proof_observations["authorization_exact"] is True
    assert type(proof_observations["temporary_root"]) is str
    assert hash_index == 5
    assert len(observed) == 5
    assert [str(request.url) for request in observed] == [
        str(item["url"]) for item in contract
    ]
    assert all(request.headers["accept-encoding"] == "identity" for request in observed)
    assert stdout_bytes.getvalue() == expected_line
    assert stdout_bytes.getvalue().count(b"\n") == 1
    assert not Path(str(proof_observations["temporary_root"])).exists()


def test_transport_source_has_no_process_or_socket_escape() -> None:
    source = inspect.getsource(loader)
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert "subprocess" not in imported
    assert "socket" not in imported
    assert "requests" not in imported
    assert "urllib" not in imported
    assert "os.system" not in source
    assert "shell=True" not in source


def test_loader_boundary_constants_are_exact() -> None:
    assert loader.AUTOMATIC_RETRY_COUNT == 0
    assert loader.EXECUTION_DEADLINE_SECONDS == 300.0
    assert loader.MAX_REQUEST_COUNT == 5
    assert loader.MAX_ARCHIVE_RESPONSE_BYTES == 64 * 1024 * 1024
    assert loader.NODE_ARCHIVE_BYTES == 37_304_352
    assert loader.NODE_ARCHIVE_FILENAME == "node-v24.19.0-win-x64.zip"
    assert loader.NODE_ARCHIVE_SHA256 == probe.NODE_ARCHIVE_SHA256
