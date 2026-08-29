"""Capability-minimal Step 239 official Node.js artifact transport.

The loader owns the only network and download-directory capabilities in Step
239.  Its request inventory is closed: five ordered credential-free HTTPS GET
requests, with no redirects, proxy inheritance, response decoding, cookies,
or retries.  Four small responses remain in memory; the selected ZIP is
streamed once into a fresh out-of-repository temporary directory while it is
bounded and hashed.

Policy decisions, OpenPGP parsing, ZIP inspection, extraction, and static
toolchain identity checks belong to the sibling pure probe.  Synthetic
transports are test-only and can never create live-attested evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import httpx

_CANONICAL_MODULE_NAME = (
    "app.security."
    "authentication_entra_calling_client_msal_browser_frontend_host_"
    "execution_platform_artifact_http_loader"
)
if __name__ == "__main__":
    _canonical_name = getattr(__spec__, "name", None)
    _current_module = sys.modules.get(__name__)
    _existing_module = (
        sys.modules.get(_canonical_name)
        if type(_canonical_name) is str
        else None
    )
    if (
        _canonical_name != _CANONICAL_MODULE_NAME
        or _current_module is None
        or (
            _existing_module is not None
            and _existing_module is not _current_module
        )
    ):
        raise RuntimeError("Step 239 CLI module identity cannot be bound safely")
    sys.modules[_CANONICAL_MODULE_NAME] = _current_module

NODE_DISTRIBUTION_ORIGIN = "https://nodejs.org"
RAW_GITHUB_ORIGIN = "https://raw.githubusercontent.com"
NODE_VERSION_TAG = "v24.19.0"
NODE_ARCHIVE_FILENAME = "node-v24.19.0-win-x64.zip"

NODE_RELEASE_KEY_URL = (
    "https://raw.githubusercontent.com/nodejs/release-keys/"
    "7b6eb2d6ab524bb30487f31612cdbeb35ae37533/keys/"
    "5BE8A3F6C8A5C01D106C0AD820B1A390B168D356.asc"
)
NODE_SHASUMS_URL = (
    "https://nodejs.org/dist/v24.19.0/SHASUMS256.txt"
)
NODE_SHASUMS_SIG_URL = NODE_SHASUMS_URL + ".sig"
NODE_SHASUMS_ASC_URL = NODE_SHASUMS_URL + ".asc"
NODE_ARCHIVE_URL = (
    "https://nodejs.org/dist/v24.19.0/" + NODE_ARCHIVE_FILENAME
)

NODE_RELEASE_KEY_BYTES = 924
NODE_RELEASE_KEY_SHA256 = (
    "5115095e2f8010c75da052ecb1cfb3af630e084f0f8daa93a863557b01b0f90a"
)
NODE_SHASUMS_BYTES = 2_967
NODE_SHASUMS_SHA256 = (
    "be0629ee2bcd8e40bb856abdd3407f0762101b76bd60a36b8867f637733631c0"
)
NODE_SHASUMS_SIG_BYTES = 119
NODE_SHASUMS_SIG_SHA256 = (
    "801534e2d4c769c087e2e3eec89e879032872357e64e82336f86f03e72ece630"
)
NODE_SHASUMS_ASC_BYTES = 3_245
NODE_SHASUMS_ASC_SHA256 = (
    "88c7160b8d81c81bbbba7e3bd0bba88917b1e6a2e47e092044f43894a09ceb83"
)
NODE_ARCHIVE_BYTES = 37_304_352
NODE_ARCHIVE_SHA256 = (
    "57f71ab3652e797d84acddc79c81cc9ff1c6ddb2a1974cdb83f00fee9bff4c73"
)

MAX_AUTHORIZATION_BYTES = 16_384
MAX_REQUEST_COUNT = 5
MAX_KEY_RESPONSE_BYTES = 1024 * 1024
MAX_SIGNED_TEXT_RESPONSE_BYTES = 64 * 1024
MAX_ARCHIVE_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_AGGREGATE_RESPONSE_BYTES = (
    MAX_ARCHIVE_RESPONSE_BYTES
    + MAX_KEY_RESPONSE_BYTES
    + 3 * MAX_SIGNED_TEXT_RESPONSE_BYTES
)
MAX_RESPONSE_HEADER_COUNT = 64
MAX_RESPONSE_HEADER_BYTES = 16_384
EXECUTION_DEADLINE_SECONDS = 300.0
AUTOMATIC_RETRY_COUNT = 0
USER_AGENT = "Engineer4Me-Step239-OfficialNodeArtifactProof/1"
TEMPORARY_DIRECTORY_PREFIX = "Engineer4Me-Step239-Artifact-"


@dataclass(frozen=True, slots=True)
class _RequestSpec:
    request_id: str
    url: str
    accepted_media_types: tuple[str, ...]
    expected_bytes: int
    expected_sha256: str
    maximum_response_bytes: int
    persist_to_file: bool = False


@dataclass(frozen=True, slots=True)
class BoundedOfficialArtifactResponse:
    request_id: str
    method: Literal["GET"]
    url: str
    status_code: Literal[200]
    media_type: str
    content_length: int
    body_sha256: str
    body: bytes | None
    local_path: str | None


@dataclass(frozen=True, slots=True)
class LiveOfficialArtifactEvidence:
    evidence_source: Literal[
        "live_bounded_official_https", "synthetic_mock_transport"
    ]
    requests: tuple[BoundedOfficialArtifactResponse, ...]
    request_count: int
    aggregate_response_bytes: int
    redirects_followed: Literal[0]
    automatic_retries: Literal[0]
    environment_proxy_configuration_used: Literal[False]
    credentials_sent: Literal[False]
    response_decoding_used: Literal[False]
    started_monotonic: float
    deadline_monotonic: float
    temporary_root: str
    archive_path: str
    cleanup_completed: bool
    _loader_attestation: object = field(repr=False, compare=False)


class OfficialArtifactHttpLoaderError(RuntimeError):
    """Sanitized Step 239 bounded transport failure."""


_LIVE_EVIDENCE_ATTESTATION = object()
_SYNTHETIC_EVIDENCE_ATTESTATION = object()
_OWNED_TEMPORARY_ROOTS: set[str] = set()


def _request_specs() -> tuple[_RequestSpec, ...]:
    return (
        _RequestSpec(
            "node-release-signing-key",
            NODE_RELEASE_KEY_URL,
            ("text/plain",),
            NODE_RELEASE_KEY_BYTES,
            NODE_RELEASE_KEY_SHA256,
            MAX_KEY_RESPONSE_BYTES,
        ),
        _RequestSpec(
            "node-release-shasums",
            NODE_SHASUMS_URL,
            ("text/plain",),
            NODE_SHASUMS_BYTES,
            NODE_SHASUMS_SHA256,
            MAX_SIGNED_TEXT_RESPONSE_BYTES,
        ),
        _RequestSpec(
            "node-release-shasums-detached-signature",
            NODE_SHASUMS_SIG_URL,
            ("application/pgp-signature",),
            NODE_SHASUMS_SIG_BYTES,
            NODE_SHASUMS_SIG_SHA256,
            MAX_SIGNED_TEXT_RESPONSE_BYTES,
        ),
        _RequestSpec(
            "node-release-shasums-clearsigned",
            NODE_SHASUMS_ASC_URL,
            ("text/plain",),
            NODE_SHASUMS_ASC_BYTES,
            NODE_SHASUMS_ASC_SHA256,
            MAX_SIGNED_TEXT_RESPONSE_BYTES,
        ),
        _RequestSpec(
            "node-windows-x64-portable-archive",
            NODE_ARCHIVE_URL,
            ("application/zip",),
            NODE_ARCHIVE_BYTES,
            NODE_ARCHIVE_SHA256,
            MAX_ARCHIVE_RESPONSE_BYTES,
            True,
        ),
    )


def official_request_contract_projection() -> tuple[dict[str, object], ...]:
    """Return the exact non-secret request correlation contract."""

    return tuple(
        {
            "request_id": spec.request_id,
            "method": "GET",
            "url": spec.url,
            "accepted_media_types": spec.accepted_media_types,
            "expected_bytes": spec.expected_bytes,
            "expected_sha256": spec.expected_sha256,
            "maximum_response_bytes": spec.maximum_response_bytes,
            "persist_to_file": spec.persist_to_file,
        }
        for spec in _request_specs()
    )


def _validate_response_headers(
    response: httpx.Response, spec: _RequestSpec
) -> str:
    raw_headers = response.headers.raw
    if len(raw_headers) > MAX_RESPONSE_HEADER_COUNT:
        raise OfficialArtifactHttpLoaderError(
            "official artifact response header count exceeds its bound"
        )
    total = 0
    token = frozenset(
        b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        b"abcdefghijklmnopqrstuvwxyz"
    )
    for name, value in raw_headers:
        total += len(name) + len(value)
        if total > MAX_RESPONSE_HEADER_BYTES:
            raise OfficialArtifactHttpLoaderError(
                "official artifact response headers exceed their bound"
            )
        if not name or any(byte not in token for byte in name) or any(
            byte != 9 and not 32 <= byte <= 126 for byte in value
        ):
            raise OfficialArtifactHttpLoaderError(
                "official artifact response header is not canonical ASCII"
            )

    forbidden = (
        "content-encoding",
        "transfer-encoding",
        "location",
        "set-cookie",
    )
    if any(response.headers.get(name) is not None for name in forbidden):
        raise OfficialArtifactHttpLoaderError(
            "encoded redirected chunked or cookie response is forbidden"
        )
    accept_ranges = response.headers.get("accept-ranges")
    if accept_ranges is not None and accept_ranges.strip().lower() != "bytes":
        raise OfficialArtifactHttpLoaderError(
            "official artifact byte-range declaration is not exact"
        )

    raw_length = response.headers.get("content-length")
    if (
        raw_length is None
        or not raw_length.isascii()
        or not raw_length.isdecimal()
        or raw_length != str(spec.expected_bytes)
        or int(raw_length) != spec.expected_bytes
        or int(raw_length) > spec.maximum_response_bytes
    ):
        raise OfficialArtifactHttpLoaderError(
            "official artifact response content length is not exact"
        )

    raw_type = response.headers.get("content-type")
    if raw_type is None:
        raise OfficialArtifactHttpLoaderError(
            "official artifact response media type is missing"
        )
    parts = [part.strip().lower() for part in raw_type.split(";")]
    media_type = parts[0]
    if media_type not in spec.accepted_media_types:
        raise OfficialArtifactHttpLoaderError(
            "official artifact response media type is not accepted"
        )
    parameters = [part for part in parts[1:] if part]
    if media_type == "text/plain":
        if parameters not in ([], ["charset=utf-8"]):
            raise OfficialArtifactHttpLoaderError(
                "official artifact text charset is not accepted"
            )
    elif parameters:
        raise OfficialArtifactHttpLoaderError(
            "official artifact binary media parameters are forbidden"
        )
    return media_type + (
        ";charset=utf-8" if parameters == ["charset=utf-8"] else ""
    )


def _new_temporary_root(parent: str | None) -> Path:
    created: Path | None = None
    try:
        parent_path = None if parent is None else Path(parent).resolve(strict=True)
        if parent_path is not None and not parent_path.is_dir():
            raise ValueError("temporary parent is not a directory")
        value = tempfile.mkdtemp(
            prefix=TEMPORARY_DIRECTORY_PREFIX,
            dir=None if parent_path is None else str(parent_path),
        )
        created = Path(value)
        root = created.resolve(strict=True)
        cwd = Path.cwd().resolve(strict=True)
        if (
            not root.is_absolute()
            or root == cwd
            or cwd in root.parents
            or root in cwd.parents
            or root.is_symlink()
            or root.name.startswith(TEMPORARY_DIRECTORY_PREFIX) is False
        ):
            raise ValueError("temporary root is not isolated")
        root_string = str(root)
        if root_string in _OWNED_TEMPORARY_ROOTS:
            raise ValueError("temporary root identity is not unique")
        _OWNED_TEMPORARY_ROOTS.add(root_string)
        return root
    except (OSError, RuntimeError, ValueError) as error:
        if created is not None:
            try:
                if created.exists() and not created.is_symlink():
                    shutil.rmtree(created)
            except OSError:
                pass
        raise OfficialArtifactHttpLoaderError(
            "fresh artifact temporary directory could not be created"
        ) from error


def _read_response(
    client: httpx.Client,
    spec: _RequestSpec,
    *,
    deadline: float,
    temporary_root: Path,
) -> BoundedOfficialArtifactResponse:
    if time.monotonic() >= deadline:
        raise OfficialArtifactHttpLoaderError(
            "official artifact proof exceeded its deadline"
        )
    headers = {
        "Accept": ", ".join(spec.accepted_media_types),
        "Accept-Encoding": "identity",
        "User-Agent": USER_AGENT,
    }
    local_path: Path | None = None
    buffer = bytearray()
    digest = hashlib.sha256()
    total = 0
    try:
        with client.stream("GET", spec.url, headers=headers) as response:
            forbidden_request_headers = {
                "authorization",
                "cookie",
                "proxy-authorization",
            }
            if forbidden_request_headers.intersection(response.request.headers):
                raise OfficialArtifactHttpLoaderError(
                    "official artifact request credentials are forbidden"
                )
            if response.history:
                raise OfficialArtifactHttpLoaderError(
                    "official artifact redirect is forbidden"
                )
            if response.request.method != "GET":
                raise OfficialArtifactHttpLoaderError(
                    "official artifact response method is not exact"
                )
            if response.request.url != httpx.URL(spec.url):
                raise OfficialArtifactHttpLoaderError(
                    "official artifact response URL is not exact"
                )
            if response.status_code != 200:
                raise OfficialArtifactHttpLoaderError(
                    "official artifact response status is not accepted"
                )
            media_type = _validate_response_headers(response, spec)
            if response.is_stream_consumed or response.is_closed:
                raise OfficialArtifactHttpLoaderError(
                    "official artifact response stream is not unread"
                )

            output = None
            if spec.persist_to_file:
                local_path = temporary_root / NODE_ARCHIVE_FILENAME
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_BINARY"):
                    flags |= os.O_BINARY
                descriptor = os.open(local_path, flags, 0o600)
                output = os.fdopen(descriptor, "wb")
            try:
                for chunk in response.iter_raw():
                    if time.monotonic() >= deadline:
                        raise OfficialArtifactHttpLoaderError(
                            "official artifact proof exceeded its deadline"
                        )
                    total += len(chunk)
                    if total > spec.maximum_response_bytes:
                        raise OfficialArtifactHttpLoaderError(
                            "official artifact response exceeds its bound"
                        )
                    digest.update(chunk)
                    if output is None:
                        buffer.extend(chunk)
                    else:
                        output.write(chunk)
                if output is not None:
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                if output is not None:
                    output.close()
    except OfficialArtifactHttpLoaderError:
        raise
    except (httpx.HTTPError, httpx.StreamError, OSError, ValueError) as error:
        raise OfficialArtifactHttpLoaderError(
            "official artifact request failed"
        ) from error
    finally:
        try:
            client.cookies.clear()
        except Exception as error:
            raise OfficialArtifactHttpLoaderError(
                "official artifact cookie state could not be cleared"
            ) from error

    body_hash = digest.hexdigest()
    if total != spec.expected_bytes or body_hash != spec.expected_sha256:
        raise OfficialArtifactHttpLoaderError(
            "official artifact response identity is not exact"
        )
    if local_path is not None:
        try:
            stat = local_path.lstat()
            if (
                not local_path.is_file()
                or local_path.is_symlink()
                or stat.st_size != spec.expected_bytes
            ):
                raise ValueError("persisted archive is not an exact regular file")
        except (OSError, ValueError) as error:
            raise OfficialArtifactHttpLoaderError(
                "persisted official archive identity is invalid"
            ) from error
    return BoundedOfficialArtifactResponse(
        request_id=spec.request_id,
        method="GET",
        url=spec.url,
        status_code=200,
        media_type=media_type,
        content_length=total,
        body_sha256=body_hash,
        body=None if local_path is not None else bytes(buffer),
        local_path=None if local_path is None else str(local_path),
    )


def _load_official_artifact_evidence(
    *,
    transport: httpx.BaseTransport | None,
    evidence_source: Literal[
        "live_bounded_official_https", "synthetic_mock_transport"
    ],
    attestation: object,
    temporary_parent: str | None = None,
) -> LiveOfficialArtifactEvidence:
    specs = _request_specs()
    if (
        len(specs) != MAX_REQUEST_COUNT
        or len({spec.request_id for spec in specs}) != MAX_REQUEST_COUNT
        or len({spec.url for spec in specs}) != MAX_REQUEST_COUNT
        or sum(spec.persist_to_file for spec in specs) != 1
    ):
        raise OfficialArtifactHttpLoaderError(
            "official artifact request inventory is not exact"
        )
    temporary_root = _new_temporary_root(temporary_parent)
    started = time.monotonic()
    deadline = started + EXECUTION_DEADLINE_SECONDS
    responses: list[BoundedOfficialArtifactResponse] = []
    aggregate = 0
    try:
        timeout = httpx.Timeout(connect=10.0, read=30.0, write=5.0, pool=5.0)
        limits = httpx.Limits(max_connections=1, max_keepalive_connections=1)
        with httpx.Client(
            verify=True,
            trust_env=False,
            follow_redirects=False,
            timeout=timeout,
            limits=limits,
            transport=transport,
            http2=False,
        ) as client:
            for spec in specs:
                response = _read_response(
                    client,
                    spec,
                    deadline=deadline,
                    temporary_root=temporary_root,
                )
                aggregate += response.content_length
                if aggregate > MAX_AGGREGATE_RESPONSE_BYTES:
                    raise OfficialArtifactHttpLoaderError(
                        "official artifact aggregate response exceeds its bound"
                    )
                responses.append(response)
    except Exception:
        _remove_owned_temporary_root(temporary_root)
        raise

    archive = responses[-1]
    if archive.local_path is None or len(responses) != MAX_REQUEST_COUNT:
        _remove_owned_temporary_root(temporary_root)
        raise OfficialArtifactHttpLoaderError(
            "official artifact response inventory is not exact"
        )
    return LiveOfficialArtifactEvidence(
        evidence_source=evidence_source,
        requests=tuple(responses),
        request_count=len(responses),
        aggregate_response_bytes=aggregate,
        redirects_followed=0,
        automatic_retries=0,
        environment_proxy_configuration_used=False,
        credentials_sent=False,
        response_decoding_used=False,
        started_monotonic=started,
        deadline_monotonic=deadline,
        temporary_root=str(temporary_root),
        archive_path=archive.local_path,
        cleanup_completed=False,
        _loader_attestation=attestation,
    )


def _load_live_official_artifact_evidence(
    validated_authorization: object,
) -> LiveOfficialArtifactEvidence:
    """Private live path reachable only after exact authorization validation."""

    from app.security.authentication_entra_calling_client_msal_browser_frontend_host_execution_platform_artifact_authenticity_toolchain_probe import (
        EntraCallingClientMSALFrontendHostArtifactProofAuthorization,
        is_validated_entra_calling_client_msal_frontend_host_artifact_proof_authorization,
    )

    if (
        type(validated_authorization)
        is not EntraCallingClientMSALFrontendHostArtifactProofAuthorization
        or not is_validated_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
            validated_authorization
        )
    ):
        raise OfficialArtifactHttpLoaderError(
            "validated Step 239 artifact authorization is required"
        )
    return _load_official_artifact_evidence(
        transport=None,
        evidence_source="live_bounded_official_https",
        attestation=_LIVE_EVIDENCE_ATTESTATION,
    )


def load_synthetic_official_artifact_evidence(
    *, transport: httpx.BaseTransport, temporary_parent: str | None = None
) -> LiveOfficialArtifactEvidence:
    """Load test evidence which is structurally unable to satisfy live proof."""

    if transport is None:
        raise TypeError("an explicit synthetic transport is required")
    return _load_official_artifact_evidence(
        transport=transport,
        evidence_source="synthetic_mock_transport",
        attestation=_SYNTHETIC_EVIDENCE_ATTESTATION,
        temporary_parent=temporary_parent,
    )


def is_attested_live_official_artifact_evidence(evidence: object) -> bool:
    return (
        type(evidence) is LiveOfficialArtifactEvidence
        and evidence.evidence_source == "live_bounded_official_https"
        and evidence._loader_attestation is _LIVE_EVIDENCE_ATTESTATION
    )


def _remove_owned_temporary_root(root: Path) -> None:
    root_string = str(root)
    if root_string not in _OWNED_TEMPORARY_ROOTS:
        raise OfficialArtifactHttpLoaderError(
            "artifact temporary directory ownership is invalid"
        )
    try:
        if (
            not root.is_absolute()
            or root.name.startswith(TEMPORARY_DIRECTORY_PREFIX) is False
            or root.is_symlink()
        ):
            raise ValueError("temporary root identity changed")
        shutil.rmtree(root)
        if root.exists():
            raise OSError("temporary root remains")
    except (OSError, RuntimeError, ValueError) as error:
        raise OfficialArtifactHttpLoaderError(
            "artifact temporary directory cleanup failed"
        ) from error
    _OWNED_TEMPORARY_ROOTS.discard(root_string)


def cleanup_official_artifact_evidence(
    evidence: LiveOfficialArtifactEvidence,
) -> None:
    """Delete only the exact temporary root owned by this loader instance."""

    if type(evidence) is not LiveOfficialArtifactEvidence:
        raise TypeError("exact official artifact evidence is required")
    if evidence.cleanup_completed:
        raise OfficialArtifactHttpLoaderError(
            "artifact evidence cleanup was already completed"
        )
    _remove_owned_temporary_root(Path(evidence.temporary_root))
    object.__setattr__(evidence, "cleanup_completed", True)


def _read_authorization() -> bytes:
    value = sys.stdin.buffer.read(MAX_AUTHORIZATION_BYTES + 1)
    if not value or len(value) > MAX_AUTHORIZATION_BYTES:
        raise OfficialArtifactHttpLoaderError(
            "Step 239 authorization size is invalid"
        )
    return value


def main() -> int:
    """Run the sole live Step 239 path and emit one canonical receipt line."""

    evidence: LiveOfficialArtifactEvidence | None = None
    try:
        authorization = _read_authorization()
        from app.security.authentication_entra_calling_client_msal_browser_frontend_host_execution_platform_artifact_authenticity_toolchain_probe import (
            load_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_proof,
            render_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_receipt,
            validate_entra_calling_client_msal_frontend_host_artifact_proof_authorization,
        )

        validated = validate_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
            authorization
        )
        evidence = _load_live_official_artifact_evidence(validated)
        receipt = load_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_proof(
            authorization, evidence
        )
        if not evidence.cleanup_completed:
            raise OfficialArtifactHttpLoaderError(
                "Step 239 proof returned before cleanup was confirmed"
            )
        rendered = render_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_receipt(
            receipt
        )
        sys.stdout.buffer.write(rendered + b"\n")
        return 0
    except Exception:
        sys.stderr.write("Step 239 official artifact proof failed.\n")
        return 1
    finally:
        if evidence is not None and not evidence.cleanup_completed:
            try:
                cleanup_official_artifact_evidence(evidence)
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AUTOMATIC_RETRY_COUNT",
    "BoundedOfficialArtifactResponse",
    "EXECUTION_DEADLINE_SECONDS",
    "LiveOfficialArtifactEvidence",
    "MAX_REQUEST_COUNT",
    "NODE_ARCHIVE_BYTES",
    "NODE_ARCHIVE_FILENAME",
    "NODE_ARCHIVE_SHA256",
    "NODE_ARCHIVE_URL",
    "NODE_RELEASE_KEY_URL",
    "NODE_SHASUMS_ASC_URL",
    "NODE_SHASUMS_SIG_URL",
    "NODE_SHASUMS_URL",
    "OfficialArtifactHttpLoaderError",
    "cleanup_official_artifact_evidence",
    "is_attested_live_official_artifact_evidence",
    "load_synthetic_official_artifact_evidence",
    "main",
    "official_request_contract_projection",
]
