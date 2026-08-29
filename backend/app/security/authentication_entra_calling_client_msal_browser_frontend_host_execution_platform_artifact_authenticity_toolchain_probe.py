"""Deterministic Step 239 Node.js artifact authenticity/static proof.

This module owns policy, not transport.  It verifies the pinned OpenPGP v4
Ed25519 key and both release signatures without invoking GnuPG, binds the
signed checksum entries, validates every classic-ZIP structure and member,
extracts only into the loader-owned temporary root, proves the complete
filesystem and critical Node/npm byte identities, and requires cleanup before
returning a canonical receipt.

It never executes Node.js or npm.  Host support, Windows execution, package
lock generation, dependency installation, and frontend materialization remain
blocked successor gates.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import json
import math
import os
import re
import shutil
import stat
import struct
import time
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TITLE = (
    "Engineer4Me Phase 8 Step 239 controlled read-only official signed "
    "Windows-x64 portable Node.js artifact authenticity, safe-extraction, "
    "and static toolchain-identity proof v1"
)
DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_"
    "execution_platform_artifact_authenticity_toolchain_proof"
)
AUTHORIZATION_TYPE = DOCUMENT_TYPE + "_authorization"
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = (
    "engineer4me_controlled_official_signed_windows_x64_portable_node_"
    "artifact_authenticity_toolchain_probe"
)
SCOPE = (
    "exact_step238_chain_plus_controlled_official_signed_windows_x64_"
    "portable_node_artifact_authenticity_safe_extraction_and_static_"
    "toolchain_identity_proof"
)
STATUS = (
    "official_signed_windows_x64_portable_node_artifact_authenticity_safe_"
    "extraction_and_static_toolchain_identity_proven_host_support_execution_"
    "lock_generation_and_frontend_materialization_blocked"
)

STEP238_ACCEPTED_STATE_MANIFEST_SHA256 = (
    "9aedd62857fdbd27c90aba3a06a26064604727baee9e8dbdbb3fde6c8942377c"
)
STEP238_ACCEPTED_STATE_MANIFEST_BYTES = 32_882
STEP238_ACCEPTED_STATE_PATH_COUNT = 236
STEP238_PACKAGE_MANIFEST_SHA256 = (
    "ba038cc11601ad810fb694f9a61bddf004652dd9fc9c12de32edb5e64587b820"
)
STEP238_READINESS_SHA256 = (
    "c7aba41f6ed12f5cef2b3a05ca1c42ed78e25061bb4334653ce830af08bf70f9"
)
STEP238_READINESS_TEST_SHA256 = (
    "58e0c7a566d62a0e618e8be4e42534e70c6fb2659dbcc17399a80ba6f6728493"
)
STEP238_CANONICAL_RECEIPT_SHA256 = (
    "ea3320ac9cc9168f3d2b7837ccbcfead8245a5372b6d6dda1a1a2f7b8f352f25"
)
STEP238_READINESS_DOCUMENT_SHA256 = (
    "16e0940a97f34eafe7db635ea81da828fe8f55fa793d81538b2767adadefd281"
)
STEP238_READINESS_STATUS = (
    "offline_windows_x64_portable_toolchain_selected_download_signature_"
    "verification_extraction_execution_and_lock_generation_blocked"
)

NODE_VERSION = "24.19.0"
NODE_VERSION_STDOUT_FUTURE = "v24.19.0"
NPM_VERSION = "11.17.0"
NODE_ARCHIVE_FILENAME = "node-v24.19.0-win-x64.zip"
NODE_ARCHIVE_ROOT = "node-v24.19.0-win-x64"
NODE_ARCHIVE_BYTES = 37_304_352
NODE_ARCHIVE_SHA256 = (
    "57f71ab3652e797d84acddc79c81cc9ff1c6ddb2a1974cdb83f00fee9bff4c73"
)
NODE_EXECUTABLE_RELATIVE_PATH = NODE_ARCHIVE_ROOT + "/node.exe"
NODE_EXECUTABLE_BYTES = 92_825_416
NODE_EXECUTABLE_SHA256 = (
    "3602f2bb1a10f2cbab4c36886218a33c1ab3db87290e73b033c46c77147d0237"
)
NPM_MANIFEST_RELATIVE_PATH = (
    NODE_ARCHIVE_ROOT + "/node_modules/npm/package.json"
)
NPM_MANIFEST_BYTES = 6_856
NPM_MANIFEST_SHA256 = (
    "40c49aec1ef9a0cd1edb50b900d678705319faf9e3117f5336960ba7b3619e47"
)
NPM_CLI_RELATIVE_PATH = NODE_ARCHIVE_ROOT + "/node_modules/npm/bin/npm-cli.js"
NPM_CLI_BYTES = 56
NPM_CLI_SHA256 = (
    "3ce7cba6f5128dd5f54c98b6a5036b0f850496878cc2e21044b675fe3c594e3e"
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
EXPECTED_SIGNER_FINGERPRINT = "5BE8A3F6C8A5C01D106C0AD820B1A390B168D356"
EXPECTED_SIGNER_KEY_ID = "20B1A390B168D356"
EXPECTED_ED25519_OID = bytes.fromhex("2b06010401da470f01")
EXPECTED_DETACHED_CREATED = 1_785_764_696  # 2026-08-03T13:44:56Z
EXPECTED_CLEARSIGNED_CREATED = 1_785_764_674  # 2026-08-03T13:44:34Z
EXPECTED_DETACHED_DIGEST_PREFIX = bytes.fromhex("9143")
EXPECTED_CLEARSIGNED_DIGEST_PREFIX = bytes.fromhex("c198")
EXPECTED_SORTED_SHASUMS_SHA256 = (
    "d76b7864392c11a8c8ae09415649917279632cbe6cb21fb9feb5d925341a5c2c"
)

EXPECTED_ENTRY_COUNT = 2_454
EXPECTED_FILE_COUNT = 1_989
EXPECTED_DIRECTORY_COUNT = 465
EXPECTED_UNCOMPRESSED_BYTES = 106_112_876
EXPECTED_COMPRESSED_PAYLOAD_BYTES = 36_653_292
EXPECTED_DEFLATE_COUNT = 1_925
EXPECTED_STORED_COUNT = 529
EXPECTED_CENTRAL_DIRECTORY_OFFSET = 36_915_007
EXPECTED_CENTRAL_DIRECTORY_BYTES = 389_323
EXPECTED_CENTRAL_DIRECTORY_SHA256 = (
    "30f02fbe0c6cd2b266c79b7c265f8cd7954649e72c35deb267f81b60c10afafd"
)
EXPECTED_EOCD_OFFSET = 37_304_330
EXPECTED_ARCHIVE_INVENTORY_SHA256 = (
    "c1b19024bce26a156855dd461039ecbbceded5fce6fca62c46b98d9c33d232eb"
)
EXPECTED_EXTRACTED_FILE_INVENTORY_SHA256 = (
    "d73362347747f8df5238032f7c947551da3dbef15296a0ebf91802cdc9b99dea"
)
EXPECTED_RESPONSE_BODY_SET_SHA256 = (
    "6c309cbc87115615774c283cb803db06b0fe436b7f180f164541247101ecae59"
)
EXPECTED_DETACHED_DIGEST_SHA256 = (
    "9143b96cd187fc99c3c4fa499ad035dac3f7394636c1461241d6a01a5d4c4491"
)
EXPECTED_CLEARSIGNED_DIGEST_SHA256 = (
    "c198c2c4151cf711990c51d6a6a2c36e4ce052bc27b1517c91d41db1d878f254"
)

MAX_ARCHIVE_ENTRY_COUNT = 20_000
MAX_ARCHIVE_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_ENTRY_BYTES = 128 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_PATH_BYTES = 1_024
MAX_COMPONENT_BYTES = 255
MAX_PATH_DEPTH = 32
EXTRA_FIELD_BYTES = 36
READ_CHUNK_BYTES = 1024 * 1024
CANONICAL_RECEIPT_SHA256 = (
    "b7834dc025f6149a2d25de2d0b38b5553db4f3969d427dd25458cdf9e3e0ec46"
)

_SHASUM_LINE = re.compile(rb"^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)\n$")
_RESERVED_DOS_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}


class EntraCallingClientMSALFrontendHostArtifactProofError(ValueError):
    """Sanitized Step 239 proof failure."""


_AUTHORIZATION_ATTESTATION = object()


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostArtifactProofAuthorization:
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_browser_frontend_host_execution_platform_artifact_authenticity_toolchain_proof_authorization"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_step239_closed_package_installer"
    ]
    approved_step238_accepted_state_manifest_sha256: str
    approved_step238_package_manifest_sha256: str
    approved_step238_readiness_sha256: str
    approved_step238_readiness_test_sha256: str
    approved_step238_canonical_receipt_sha256: str
    approved_step238_readiness_document_sha256: str
    approved_step238_readiness_status: str
    _validator_attestation: object = dataclasses.field(
        default=None, repr=False, compare=False
    )


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALFrontendHostArtifactProofReceipt:
    receipt_type: str
    schema_version: int
    source: str
    scope: str
    status: str
    approved_step238_accepted_state_manifest_sha256: str
    approved_step238_package_manifest_sha256: str
    approved_step238_readiness_sha256: str
    approved_step238_readiness_test_sha256: str
    approved_step238_canonical_receipt_sha256: str
    approved_step238_readiness_document_sha256: str
    approved_step238_readiness_status: str
    request_count: int
    aggregate_response_bytes: int
    response_body_set_sha256: str
    signer_fingerprint: str
    signer_key_id: str
    detached_signature_digest_sha256: str
    clearsigned_signature_digest_sha256: str
    signed_shasums_sha256: str
    sorted_shasums_sha256: str
    archive_sha256: str
    central_directory_sha256: str
    archive_inventory_sha256: str
    extracted_file_inventory_sha256: str
    entry_count: int
    file_count: int
    directory_count: int
    uncompressed_bytes: int
    compressed_payload_bytes: int
    node_executable_sha256: str
    npm_manifest_sha256: str
    npm_cli_sha256: str
    npm_manifest_name: str
    npm_manifest_version: str
    temporary_artifacts_cleaned: bool
    both_openpgp_signatures_verified: bool
    signed_checksum_binding_verified: bool
    complete_archive_structure_and_inventory_verified: bool
    safe_extraction_and_complete_file_inventory_verified: bool
    static_node_npm_toolchain_identity_verified: bool
    host_vendor_support_verified: bool
    node_or_npm_executed: bool
    lock_generation_authorized_or_performed: bool
    frontend_materialized: bool
    operational_write_performed: bool

    def __post_init__(self) -> None:
        if (
            self.receipt_type != RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version != SCHEMA_VERSION
            or self.source != SOURCE
            or self.scope != SCOPE
            or self.status != STATUS
            or self.approved_step238_accepted_state_manifest_sha256
            != STEP238_ACCEPTED_STATE_MANIFEST_SHA256
            or self.approved_step238_package_manifest_sha256
            != STEP238_PACKAGE_MANIFEST_SHA256
            or self.approved_step238_readiness_sha256 != STEP238_READINESS_SHA256
            or self.approved_step238_readiness_test_sha256
            != STEP238_READINESS_TEST_SHA256
            or self.approved_step238_canonical_receipt_sha256
            != STEP238_CANONICAL_RECEIPT_SHA256
            or self.approved_step238_readiness_document_sha256
            != STEP238_READINESS_DOCUMENT_SHA256
            or self.approved_step238_readiness_status != STEP238_READINESS_STATUS
            or type(self.request_count) is not int
            or self.request_count != 5
            or type(self.aggregate_response_bytes) is not int
            or self.aggregate_response_bytes != 37_311_607
            or type(self.entry_count) is not int
            or self.entry_count != EXPECTED_ENTRY_COUNT
            or type(self.file_count) is not int
            or self.file_count != EXPECTED_FILE_COUNT
            or type(self.directory_count) is not int
            or self.directory_count != EXPECTED_DIRECTORY_COUNT
            or type(self.uncompressed_bytes) is not int
            or self.uncompressed_bytes != EXPECTED_UNCOMPRESSED_BYTES
            or type(self.compressed_payload_bytes) is not int
            or self.compressed_payload_bytes != EXPECTED_COMPRESSED_PAYLOAD_BYTES
            or self.response_body_set_sha256 != EXPECTED_RESPONSE_BODY_SET_SHA256
            or self.signer_fingerprint != EXPECTED_SIGNER_FINGERPRINT
            or self.signer_key_id != EXPECTED_SIGNER_KEY_ID
            or self.detached_signature_digest_sha256
            != EXPECTED_DETACHED_DIGEST_SHA256
            or self.clearsigned_signature_digest_sha256
            != EXPECTED_CLEARSIGNED_DIGEST_SHA256
            or self.signed_shasums_sha256 != NODE_SHASUMS_SHA256
            or self.sorted_shasums_sha256 != EXPECTED_SORTED_SHASUMS_SHA256
            or self.archive_sha256 != NODE_ARCHIVE_SHA256
            or self.central_directory_sha256
            != EXPECTED_CENTRAL_DIRECTORY_SHA256
            or self.archive_inventory_sha256
            != EXPECTED_ARCHIVE_INVENTORY_SHA256
            or self.extracted_file_inventory_sha256
            != EXPECTED_EXTRACTED_FILE_INVENTORY_SHA256
            or self.node_executable_sha256 != NODE_EXECUTABLE_SHA256
            or self.npm_manifest_sha256 != NPM_MANIFEST_SHA256
            or self.npm_cli_sha256 != NPM_CLI_SHA256
            or self.npm_manifest_name != "npm"
            or self.npm_manifest_version != NPM_VERSION
            or any(
                type(value) is not bool
                for value in (
                    self.temporary_artifacts_cleaned,
                    self.both_openpgp_signatures_verified,
                    self.signed_checksum_binding_verified,
                    self.complete_archive_structure_and_inventory_verified,
                    self.safe_extraction_and_complete_file_inventory_verified,
                    self.static_node_npm_toolchain_identity_verified,
                    self.host_vendor_support_verified,
                    self.node_or_npm_executed,
                    self.lock_generation_authorized_or_performed,
                    self.frontend_materialized,
                    self.operational_write_performed,
                )
            )
            or not self.temporary_artifacts_cleaned
            or not self.both_openpgp_signatures_verified
            or not self.signed_checksum_binding_verified
            or not self.complete_archive_structure_and_inventory_verified
            or not self.safe_extraction_and_complete_file_inventory_verified
            or not self.static_node_npm_toolchain_identity_verified
            or self.host_vendor_support_verified
            or self.node_or_npm_executed
            or self.lock_generation_authorized_or_performed
            or self.frontend_materialized
            or self.operational_write_performed
        ):
            raise ValueError("Step 239 receipt constants or types are invalid")


@dataclass(frozen=True, slots=True)
class _OpenPgpPublicKey:
    fingerprint: str
    key_id: str
    public_key: bytes


@dataclass(frozen=True, slots=True)
class _OpenPgpSignature:
    signature_type: int
    created: int
    digest: bytes
    issuer_fingerprint: str
    issuer_key_id: str


@dataclass(frozen=True, slots=True)
class _ArchiveProof:
    archive_inventory_sha256: str
    extracted_file_inventory_sha256: str
    entry_count: int
    file_count: int
    directory_count: int
    uncompressed_bytes: int
    compressed_payload_bytes: int
    node_executable_sha256: str
    npm_manifest_sha256: str
    npm_cli_sha256: str
    npm_manifest_name: str
    npm_manifest_version: str


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
        b"Engineer4Me-Step239-v1\x00"
        + domain.encode("ascii")
        + b"\x00"
        + _canonical(value)
    ).hexdigest()


def _authorization_projection() -> dict[str, object]:
    return {
        "document_type": AUTHORIZATION_TYPE,
        "schema_version": SCHEMA_VERSION,
        "source": "engineer4me_step239_closed_package_installer",
        "approved_step238_accepted_state_manifest_sha256": (
            STEP238_ACCEPTED_STATE_MANIFEST_SHA256
        ),
        "approved_step238_package_manifest_sha256": (
            STEP238_PACKAGE_MANIFEST_SHA256
        ),
        "approved_step238_readiness_sha256": STEP238_READINESS_SHA256,
        "approved_step238_readiness_test_sha256": (
            STEP238_READINESS_TEST_SHA256
        ),
        "approved_step238_canonical_receipt_sha256": (
            STEP238_CANONICAL_RECEIPT_SHA256
        ),
        "approved_step238_readiness_document_sha256": (
            STEP238_READINESS_DOCUMENT_SHA256
        ),
        "approved_step238_readiness_status": STEP238_READINESS_STATUS,
    }


def render_entra_calling_client_msal_frontend_host_artifact_proof_authorization() -> bytes:
    return _canonical(_authorization_projection())


def validate_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
    document: bytes,
) -> EntraCallingClientMSALFrontendHostArtifactProofAuthorization:
    if type(document) is not bytes or not document or len(document) > 16_384:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "Step 239 authorization is invalid"
        )
    expected_document = _canonical(_authorization_projection())
    if document != expected_document:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "Step 239 authorization is not exact canonical input"
        )
    try:
        value = json.loads(
            document.decode("ascii"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "Step 239 authorization is invalid"
        ) from error
    if (
        type(value) is not dict
        or type(value.get("schema_version")) is not int
        or value != _authorization_projection()
        or document != _canonical(value)
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "Step 239 authorization is not exact canonical input"
        )
    return EntraCallingClientMSALFrontendHostArtifactProofAuthorization(
        **value, _validator_attestation=_AUTHORIZATION_ATTESTATION
    )


def is_validated_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
    authorization: object,
) -> bool:
    if (
        type(authorization)
        is not EntraCallingClientMSALFrontendHostArtifactProofAuthorization
        or authorization._validator_attestation is not _AUTHORIZATION_ATTESTATION
    ):
        return False
    value = {
        field.name: getattr(authorization, field.name)
        for field in dataclasses.fields(authorization)
        if field.name != "_validator_attestation"
    }
    return (
        type(value.get("schema_version")) is int
        and value == _authorization_projection()
        and _canonical(value) == _canonical(_authorization_projection())
    )


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def _dearmor(blob: bytes, label: str) -> bytes:
    try:
        text = blob.decode("ascii")
    except UnicodeDecodeError as error:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP armor is not ASCII"
        ) from error
    if "\r" in text:
        text = text.replace("\r\n", "\n")
        if "\r" in text:
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "OpenPGP armor line endings are invalid"
            )
    lines = text.split("\n")
    begin = f"-----BEGIN PGP {label}-----"
    end = f"-----END PGP {label}-----"
    if not lines or lines[0] != begin or end not in lines:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP armor boundary is invalid"
        )
    end_index = lines.index(end)
    if any(lines[end_index + 1 :]):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP armor has trailing data"
        )
    try:
        blank = lines.index("", 1, end_index)
    except ValueError as error:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP armor header termination is invalid"
        ) from error
    headers = lines[1:blank]
    if any(":" not in header for header in headers):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP armor header is invalid"
        )
    body_lines = lines[blank + 1 : end_index]
    if len(body_lines) < 2 or not body_lines[-1].startswith("="):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP armor checksum is missing"
        )
    checksum_line = body_lines.pop()
    if any(
        not line
        or len(line) > 76
        or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", line) is None
        for line in body_lines
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP armor base64 is invalid"
        )
    try:
        decoded = base64.b64decode("".join(body_lines), validate=True)
        checksum = base64.b64decode(checksum_line[1:], validate=True)
    except (binascii.Error, ValueError) as error:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP armor base64 is invalid"
        ) from error
    if len(checksum) != 3 or int.from_bytes(checksum, "big") != _crc24(decoded):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP armor checksum is invalid"
        )
    return decoded


def _packets(data: bytes) -> tuple[tuple[int, bytes], ...]:
    if not data:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP packet stream is empty"
        )
    packets: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        first = data[offset]
        offset += 1
        if not first & 0x80:
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "OpenPGP packet header is invalid"
            )
        if first & 0x40:
            tag = first & 0x3F
            if offset >= len(data):
                raise EntraCallingClientMSALFrontendHostArtifactProofError(
                    "OpenPGP packet length is truncated"
                )
            length_byte = data[offset]
            offset += 1
            if length_byte < 192:
                length = length_byte
            elif length_byte < 224:
                if offset >= len(data):
                    raise EntraCallingClientMSALFrontendHostArtifactProofError(
                        "OpenPGP packet length is truncated"
                    )
                length = ((length_byte - 192) << 8) + data[offset] + 192
                offset += 1
            elif length_byte == 255:
                if offset + 4 > len(data):
                    raise EntraCallingClientMSALFrontendHostArtifactProofError(
                        "OpenPGP packet length is truncated"
                    )
                length = int.from_bytes(data[offset : offset + 4], "big")
                offset += 4
            else:
                raise EntraCallingClientMSALFrontendHostArtifactProofError(
                    "OpenPGP partial packet lengths are forbidden"
                )
        else:
            tag = (first >> 2) & 0x0F
            length_type = first & 0x03
            if length_type == 3:
                raise EntraCallingClientMSALFrontendHostArtifactProofError(
                    "OpenPGP indeterminate packet lengths are forbidden"
                )
            size = (1, 2, 4)[length_type]
            if offset + size > len(data):
                raise EntraCallingClientMSALFrontendHostArtifactProofError(
                    "OpenPGP packet length is truncated"
                )
            length = int.from_bytes(data[offset : offset + size], "big")
            offset += size
        if length < 0 or offset + length > len(data):
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "OpenPGP packet body is truncated"
            )
        packets.append((tag, data[offset : offset + length]))
        offset += length
    return tuple(packets)


def _read_mpi(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP MPI is truncated"
        )
    bits = int.from_bytes(data[offset : offset + 2], "big")
    offset += 2
    length = (bits + 7) // 8
    if bits == 0 or offset + length > len(data):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP MPI is invalid"
        )
    value = data[offset : offset + length]
    if value[0] == 0 or value[0].bit_length() + (length - 1) * 8 != bits:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP MPI is not minimally encoded"
        )
    return bits, value, offset + length


def _load_signer_public_key(armored: bytes) -> _OpenPgpPublicKey:
    packets = _packets(_dearmor(armored, "PUBLIC KEY BLOCK"))
    primary = [body for tag, body in packets if tag == 6]
    if len(primary) != 1:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP primary key inventory is not exact"
        )
    body = primary[0]
    if len(body) < 8 or body[0] != 4 or body[5] != 22:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP primary key algorithm is not exact"
        )
    oid_length = body[6]
    oid_end = 7 + oid_length
    if body[7:oid_end] != EXPECTED_ED25519_OID:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP Ed25519 curve identifier is not exact"
        )
    bits, q, end = _read_mpi(body, oid_end)
    if bits != 263 or len(q) != 33 or q[0] != 0x40 or end != len(body):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP Ed25519 public point is not exact"
        )
    fingerprint = hashlib.sha1(
        b"\x99" + len(body).to_bytes(2, "big") + body
    ).hexdigest().upper()
    if fingerprint != EXPECTED_SIGNER_FINGERPRINT:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP signer fingerprint is not exact"
        )
    return _OpenPgpPublicKey(
        fingerprint=fingerprint,
        key_id=fingerprint[-16:],
        public_key=q[1:],
    )


def _read_subpacket_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP signature subpacket is truncated"
        )
    first = data[offset]
    offset += 1
    if first < 192:
        return first, offset
    if first < 255:
        if first >= 224 or offset >= len(data):
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "OpenPGP signature subpacket length is forbidden"
            )
        return ((first - 192) << 8) + data[offset] + 192, offset + 1
    if offset + 4 > len(data):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP signature subpacket is truncated"
        )
    return int.from_bytes(data[offset : offset + 4], "big"), offset + 4


def _subpackets(data: bytes) -> tuple[tuple[int, bool, bytes], ...]:
    values: list[tuple[int, bool, bytes]] = []
    offset = 0
    while offset < len(data):
        length, offset = _read_subpacket_length(data, offset)
        if length < 1 or offset + length > len(data):
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "OpenPGP signature subpacket is invalid"
            )
        type_octet = data[offset]
        values.append(
            (type_octet & 0x7F, bool(type_octet & 0x80), data[offset + 1 : offset + length])
        )
        offset += length
    return tuple(values)


def _verify_signature_packet(
    packet: bytes,
    signed_data: bytes,
    key: _OpenPgpPublicKey,
    *,
    expected_type: int,
    expected_created: int,
    expected_digest_prefix: bytes,
) -> _OpenPgpSignature:
    if len(packet) != 117 or packet[:4] != bytes((4, expected_type, 22, 8)):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP signature packet header is not exact"
        )
    hashed_length = int.from_bytes(packet[4:6], "big")
    hashed_end = 6 + hashed_length
    if hashed_end + 2 > len(packet):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP hashed subpacket area is truncated"
        )
    hashed = _subpackets(packet[6:hashed_end])
    unhashed_length = int.from_bytes(packet[hashed_end : hashed_end + 2], "big")
    unhashed_start = hashed_end + 2
    unhashed_end = unhashed_start + unhashed_length
    if unhashed_end + 2 > len(packet):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP unhashed subpacket area is truncated"
        )
    unhashed = _subpackets(packet[unhashed_start:unhashed_end])
    if [item[0] for item in hashed] != [33, 2] or any(item[1] for item in hashed):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP hashed subpacket inventory is not exact"
        )
    fingerprint_data = hashed[0][2]
    created_data = hashed[1][2]
    if (
        fingerprint_data != b"\x04" + bytes.fromhex(key.fingerprint)
        or len(created_data) != 4
        or int.from_bytes(created_data, "big") != expected_created
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP hashed signer identity is not exact"
        )
    if (
        len(unhashed) != 1
        or unhashed[0][0] != 16
        or unhashed[0][1]
        or unhashed[0][2] != bytes.fromhex(key.key_id)
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP unhashed issuer advisory is not exact"
        )
    prefix = packet[:hashed_end]
    digest = hashlib.sha256(
        signed_data
        + prefix
        + b"\x04\xff"
        + len(prefix).to_bytes(4, "big")
    ).digest()
    left = packet[unhashed_end : unhashed_end + 2]
    if left != expected_digest_prefix or left != digest[:2]:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP signed digest prefix is not exact"
        )
    offset = unhashed_end + 2
    r_bits, r, offset = _read_mpi(packet, offset)
    s_bits, s, offset = _read_mpi(packet, offset)
    expected_bits = (255, 256) if expected_type == 0 else (256, 256)
    if (
        (r_bits, s_bits) != expected_bits
        or len(r) != 32
        or len(s) != 32
        or offset != len(packet)
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP Ed25519 signature MPIs are not exact"
        )
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(r + s, digest)
    except (InvalidSignature, ValueError) as error:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "OpenPGP Ed25519 signature verification failed"
        ) from error
    return _OpenPgpSignature(
        signature_type=expected_type,
        created=expected_created,
        digest=digest,
        issuer_fingerprint=key.fingerprint,
        issuer_key_id=key.key_id,
    )


def _recover_clearsigned(armored: bytes) -> tuple[bytes, bytes]:
    try:
        text = armored.decode("ascii")
    except UnicodeDecodeError as error:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "clear-signed checksums are not ASCII"
        ) from error
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "clear-signed checksums have invalid line endings"
        )
    marker = "-----BEGIN PGP SIGNATURE-----"
    prefix = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
    if not text.startswith(prefix) or f"\n{marker}\n" not in text:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "clear-signed checksum framing is not exact"
        )
    clear_text, signature_tail = text[len(prefix) :].split(
        f"\n{marker}\n", 1
    )
    recovered_lines = []
    for line in clear_text.split("\n"):
        if line.startswith("- "):
            line = line[2:]
        elif line.startswith("-"):
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "clear-signed dash escaping is invalid"
            )
        recovered_lines.append(line)
    recovered = "\n".join(recovered_lines).encode("ascii")
    signature_armor = (marker + "\n" + signature_tail).encode("ascii")
    return recovered, _dearmor(signature_armor, "SIGNATURE")


def _verify_openpgp(
    key_armor: bytes,
    shasums: bytes,
    detached_packet_bytes: bytes,
    clearsigned: bytes,
) -> tuple[_OpenPgpSignature, _OpenPgpSignature]:
    key = _load_signer_public_key(key_armor)
    detached_packets = _packets(detached_packet_bytes)
    if len(detached_packets) != 1 or detached_packets[0][0] != 2:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "detached OpenPGP packet inventory is not exact"
        )
    detached = _verify_signature_packet(
        detached_packets[0][1],
        shasums,
        key,
        expected_type=0,
        expected_created=EXPECTED_DETACHED_CREATED,
        expected_digest_prefix=EXPECTED_DETACHED_DIGEST_PREFIX,
    )
    recovered, clear_packet_bytes = _recover_clearsigned(clearsigned)
    if recovered != shasums:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "clear-signed checksum text is not byte-equal"
        )
    clear_packets = _packets(clear_packet_bytes)
    if len(clear_packets) != 1 or clear_packets[0][0] != 2:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "clear-signed OpenPGP packet inventory is not exact"
        )
    clear = _verify_signature_packet(
        clear_packets[0][1],
        shasums.replace(b"\n", b"\r\n"),
        key,
        expected_type=1,
        expected_created=EXPECTED_CLEARSIGNED_CREATED,
        expected_digest_prefix=EXPECTED_CLEARSIGNED_DIGEST_PREFIX,
    )
    return detached, clear


def _parse_shasums(shasums: bytes) -> dict[str, str]:
    if (
        len(shasums) != NODE_SHASUMS_BYTES
        or hashlib.sha256(shasums).hexdigest() != NODE_SHASUMS_SHA256
        or not shasums.endswith(b"\n")
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "signed checksum body identity is invalid"
        )
    lines = shasums.splitlines(keepends=True)
    values: dict[str, str] = {}
    for line in lines:
        match = _SHASUM_LINE.fullmatch(line)
        if match is None:
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "signed checksum line is not canonical"
            )
        digest = match.group(1).decode("ascii")
        name = match.group(2).decode("ascii")
        if name in values:
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "signed checksum filename is duplicated"
            )
        values[name] = digest
    if (
        len(values) != 32
        or hashlib.sha256(b"".join(sorted(lines))).hexdigest()
        != EXPECTED_SORTED_SHASUMS_SHA256
        or values.get(NODE_ARCHIVE_FILENAME) != NODE_ARCHIVE_SHA256
        or values.get("win-x64/node.exe") != NODE_EXECUTABLE_SHA256
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "signed checksum selection binding is invalid"
        )
    return values


def _is_reparse(path: Path) -> bool:
    value = path.lstat()
    attributes = getattr(value, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "Step 239 artifact proof exceeded its overall deadline"
        )


def _validate_member_name(name: str, *, is_directory: bool) -> tuple[str, ...]:
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError as error:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "ZIP member name is not ASCII"
        ) from error
    if (
        not name
        or len(encoded) > MAX_PATH_BYTES
        or name.startswith(("/", "\\"))
        or "\\" in name
        or ":" in name
        or "\x00" in name
        or "//" in name
        or unicodedata.normalize("NFC", name) != name
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in name)
        or is_directory != name.endswith("/")
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "ZIP member name is not canonical"
        )
    canonical = name[:-1] if is_directory else name
    components = canonical.split("/")
    if (
        not components
        or len(components) > MAX_PATH_DEPTH
        or components[0] != NODE_ARCHIVE_ROOT
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "ZIP member root or depth is invalid"
        )
    for component in components:
        stem = component.split(".", 1)[0].casefold()
        if (
            not component
            or component in (".", "..")
            or component[-1] in (" ", ".")
            or len(component.encode("ascii")) > MAX_COMPONENT_BYTES
            or stem in _RESERVED_DOS_NAMES
        ):
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "ZIP member component is unsafe"
            )
    return tuple(components)


def _classic_eocd(
    archive_path: Path, deadline: float
) -> tuple[int, int, int, bytes]:
    _check_deadline(deadline)
    try:
        size = archive_path.stat().st_size
        with archive_path.open("rb") as stream:
            tail_size = min(size, 65_557)
            stream.seek(size - tail_size)
            tail = stream.read(tail_size)
        marker = b"PK\x05\x06"
        position = tail.rfind(marker)
        if position < 0:
            raise ValueError("EOCD is missing")
        eocd_offset = size - tail_size + position
        if eocd_offset + 22 != size:
            raise ValueError("EOCD is not exactly at EOF")
        (
            signature,
            disk,
            central_disk,
            disk_entries,
            total_entries,
            central_bytes,
            central_offset,
            comment_length,
        ) = struct.unpack_from("<IHHHHIIH", tail, position)
        if (
            signature != 0x06054B50
            or disk != 0
            or central_disk != 0
            or disk_entries != EXPECTED_ENTRY_COUNT
            or total_entries != EXPECTED_ENTRY_COUNT
            or central_bytes != EXPECTED_CENTRAL_DIRECTORY_BYTES
            or central_offset != EXPECTED_CENTRAL_DIRECTORY_OFFSET
            or comment_length != 0
            or eocd_offset != EXPECTED_EOCD_OFFSET
            or b"PK\x06\x06" in tail
            or b"PK\x06\x07" in tail
        ):
            raise ValueError("classic EOCD identity is not exact")
        with archive_path.open("rb") as stream:
            stream.seek(central_offset)
            central = stream.read(central_bytes)
        if (
            len(central) != central_bytes
            or hashlib.sha256(central).hexdigest()
            != EXPECTED_CENTRAL_DIRECTORY_SHA256
        ):
            raise ValueError("central directory identity is not exact")
        return eocd_offset, central_offset, central_bytes, central
    except (OSError, ValueError, struct.error) as error:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "classic ZIP end record is invalid"
        ) from error


def _central_entries(
    central: bytes, deadline: float
) -> tuple[dict[str, object], ...]:
    offset = 0
    entries: list[dict[str, object]] = []
    while offset < len(central):
        _check_deadline(deadline)
        if offset + 46 > len(central):
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "ZIP central header is truncated"
            )
        fields = struct.unpack_from("<IHHHHHHIIIHHHHHII", central, offset)
        (
            signature,
            made_by,
            needed,
            flags,
            method,
            mod_time,
            mod_date,
            crc32,
            compressed,
            uncompressed,
            name_length,
            extra_length,
            comment_length,
            disk,
            internal_attributes,
            external_attributes,
            local_offset,
        ) = fields
        end = offset + 46 + name_length + extra_length + comment_length
        if end > len(central):
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "ZIP central variable fields are truncated"
            )
        name_bytes = central[offset + 46 : offset + 46 + name_length]
        extra = central[
            offset + 46 + name_length : offset + 46 + name_length + extra_length
        ]
        comment = central[offset + 46 + name_length + extra_length : end]
        try:
            name = name_bytes.decode("ascii")
        except UnicodeDecodeError as error:
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "ZIP central member name is not ASCII"
            ) from error
        if (
            signature != 0x02014B50
            or made_by != 63
            or needed not in (10, 20)
            or flags != 0
            or method not in (0, 8)
            or compressed == 0xFFFFFFFF
            or uncompressed == 0xFFFFFFFF
            or local_offset == 0xFFFFFFFF
            or extra_length != EXTRA_FIELD_BYTES
            or comment
            or disk != 0
            or internal_attributes != 0
            or len(extra) != 36
            or extra[:12]
            != b"\x0a\x00\x20\x00\x00\x00\x00\x00\x01\x00\x18\x00"
        ):
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "ZIP central header contract is invalid"
            )
        entries.append(
            {
                "name": name,
                "name_bytes": name_bytes,
                "extra": extra,
                "needed": needed,
                "flags": flags,
                "method": method,
                "mod_time": mod_time,
                "mod_date": mod_date,
                "crc32": crc32,
                "compressed": compressed,
                "uncompressed": uncompressed,
                "external_attributes": external_attributes,
                "local_offset": local_offset,
            }
        )
        offset = end
    if len(entries) != EXPECTED_ENTRY_COUNT or offset != len(central):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "ZIP central entry inventory is not exact"
        )
    return tuple(entries)


def _validate_local_headers(
    archive_path: Path,
    central_entries: tuple[dict[str, object], ...],
    central_offset: int,
    deadline: float,
) -> None:
    ranges: list[tuple[int, int]] = []
    try:
        with archive_path.open("rb") as stream:
            for entry in central_entries:
                _check_deadline(deadline)
                local_offset = int(entry["local_offset"])
                stream.seek(local_offset)
                header = stream.read(30)
                if len(header) != 30:
                    raise ValueError("local header is truncated")
                (
                    signature,
                    needed,
                    flags,
                    method,
                    mod_time,
                    mod_date,
                    crc32,
                    compressed,
                    uncompressed,
                    name_length,
                    extra_length,
                ) = struct.unpack("<IHHHHHIIIHH", header)
                name = stream.read(name_length)
                local_extra = stream.read(extra_length)
                if (
                    signature != 0x04034B50
                    or needed != entry["needed"]
                    or flags != entry["flags"]
                    or method != entry["method"]
                    or mod_time != entry["mod_time"]
                    or mod_date != entry["mod_date"]
                    or crc32 != entry["crc32"]
                    or compressed != entry["compressed"]
                    or uncompressed != entry["uncompressed"]
                    or name != entry["name_bytes"]
                    or local_extra
                ):
                    raise ValueError("central/local header mismatch")
                data_start = local_offset + 30 + name_length + extra_length
                data_end = data_start + compressed
                if data_end > central_offset:
                    raise ValueError("entry data crosses central directory")
                ranges.append((local_offset, data_end))
        ordered = sorted(ranges)
        if (
            not ordered
            or ordered[0][0] != 0
            or any(left[1] != right[0] for left, right in zip(ordered, ordered[1:]))
            or ordered[-1][1] != central_offset
        ):
            raise ValueError("entry data ranges overlap")
    except (OSError, ValueError, struct.error) as error:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "ZIP local-header or data-range validation failed"
        ) from error


def _inspect_archive(
    archive_path: Path, deadline: float
) -> tuple[tuple[zipfile.ZipInfo, ...], str]:
    _, central_offset, central_bytes, central = _classic_eocd(
        archive_path, deadline
    )
    raw_entries = _central_entries(central, deadline)
    _validate_local_headers(
        archive_path, raw_entries, central_offset, deadline
    )
    try:
        with zipfile.ZipFile(archive_path, "r", allowZip64=False) as archive:
            infos = tuple(archive.infolist())
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "ZIP parser rejected the selected archive"
        ) from error
    if len(infos) != EXPECTED_ENTRY_COUNT:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "ZIP CRC or entry inventory is invalid"
        )

    paths: dict[str, bool] = {}
    folded: set[str] = set()
    entry_projection: list[dict[str, object]] = []
    total_uncompressed = 0
    total_compressed = 0
    methods: dict[int, int] = {0: 0, 8: 0}
    for index, (info, raw) in enumerate(zip(infos, raw_entries, strict=True)):
        _check_deadline(deadline)
        is_directory = info.is_dir()
        components = _validate_member_name(info.filename, is_directory=is_directory)
        canonical = "/".join(components)
        folded_name = canonical.casefold()
        if canonical in paths or folded_name in folded:
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "ZIP member path collision is forbidden"
            )
        paths[canonical] = is_directory
        folded.add(folded_name)
        expected_external = 16 if is_directory else 32
        if (
            info.filename != raw["name"]
            or info.header_offset != raw["local_offset"]
            or info.flag_bits != 0
            or info.compress_type not in (0, 8)
            or info.create_system != 0
            or info.create_version != 63
            or info.extract_version != raw["needed"]
            or info.external_attr != expected_external
            or info.internal_attr != 0
            or info.comment
            or len(info.extra) != EXTRA_FIELD_BYTES
            or info.file_size != raw["uncompressed"]
            or info.compress_size != raw["compressed"]
            or info.CRC != raw["crc32"]
            or info.file_size > MAX_ARCHIVE_ENTRY_BYTES
            or (
                info.compress_size == 0
                and info.file_size != 0
            )
            or (
                info.compress_size > 0
                and info.file_size > info.compress_size * MAX_COMPRESSION_RATIO
            )
        ):
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "ZIP member metadata is outside the exact safe contract"
            )
        if len(components) > 1:
            for depth in range(1, len(components)):
                ancestor = "/".join(components[:depth])
                if ancestor in paths and not paths[ancestor]:
                    raise EntraCallingClientMSALFrontendHostArtifactProofError(
                        "ZIP file/directory prefix collision is forbidden"
                    )
        total_uncompressed += info.file_size
        total_compressed += info.compress_size
        methods[info.compress_type] += 1
        entry_projection.append(
            {
                "compressed_bytes": info.compress_size,
                "crc32": f"{info.CRC:08x}",
                "external_attributes": info.external_attr,
                "extra_sha256": hashlib.sha256(info.extra).hexdigest(),
                "kind": "directory" if is_directory else "file",
                "local_header_offset": info.header_offset,
                "method": info.compress_type,
                "path": info.filename,
                "uncompressed_bytes": info.file_size,
            }
        )
    for path, is_directory in paths.items():
        components = path.split("/")
        for depth in range(1, len(components)):
            ancestor = "/".join(components[:depth])
            if paths.get(ancestor) is not True:
                raise EntraCallingClientMSALFrontendHostArtifactProofError(
                    "ZIP ancestor directory inventory is incomplete"
                )
    file_count = sum(not value for value in paths.values())
    directory_count = sum(paths.values())
    if (
        len(paths) != EXPECTED_ENTRY_COUNT
        or file_count != EXPECTED_FILE_COUNT
        or directory_count != EXPECTED_DIRECTORY_COUNT
        or total_uncompressed != EXPECTED_UNCOMPRESSED_BYTES
        or total_compressed != EXPECTED_COMPRESSED_PAYLOAD_BYTES
        or total_uncompressed > MAX_ARCHIVE_EXPANDED_BYTES
        or methods != {0: EXPECTED_STORED_COUNT, 8: EXPECTED_DEFLATE_COUNT}
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "ZIP aggregate inventory is not exact"
        )
    projection = {
        "archive_sha256": NODE_ARCHIVE_SHA256,
        "central_directory_bytes": central_bytes,
        "central_directory_offset": central_offset,
        "central_directory_sha256": EXPECTED_CENTRAL_DIRECTORY_SHA256,
        "compressed_payload_bytes": total_compressed,
        "directory_count": directory_count,
        "entries": entry_projection,
        "entry_count": len(paths),
        "file_count": file_count,
        "schema_version": 1,
        "uncompressed_bytes": total_uncompressed,
    }
    digest = _framed("archive-inventory", projection)
    if digest != EXPECTED_ARCHIVE_INVENTORY_SHA256:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "ZIP canonical inventory identity is not exact"
        )
    return infos, digest


def _extract_and_prove(
    archive_path: Path,
    temporary_root: Path,
    infos: tuple[zipfile.ZipInfo, ...],
    archive_inventory_sha256: str,
    deadline: float,
) -> _ArchiveProof:
    _check_deadline(deadline)
    pending = temporary_root / "extracted.pending"
    published = temporary_root / "extracted"
    if pending.exists() or published.exists():
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "fresh extraction destination is not empty"
        )
    pending.mkdir(mode=0o700)
    file_projection: list[dict[str, object]] = []
    expected_directories: set[str] = set()
    expected_files: set[str] = set()
    critical_bytes: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(archive_path, "r", allowZip64=False) as archive:
            for info in infos:
                _check_deadline(deadline)
                is_directory = info.is_dir()
                components = _validate_member_name(
                    info.filename, is_directory=is_directory
                )
                destination = pending.joinpath(*components)
                resolved_parent = destination.parent.resolve(strict=True)
                if pending.resolve(strict=True) not in (
                    resolved_parent,
                    *resolved_parent.parents,
                ):
                    raise EntraCallingClientMSALFrontendHostArtifactProofError(
                        "ZIP extraction destination escaped its root"
                    )
                if _is_reparse(destination.parent):
                    raise EntraCallingClientMSALFrontendHostArtifactProofError(
                        "ZIP extraction ancestor is a reparse point"
                    )
                if is_directory:
                    destination.mkdir(mode=0o700)
                    expected_directories.add(info.filename)
                    continue
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_BINARY"):
                    flags |= os.O_BINARY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(destination, flags, 0o600)
                digest = hashlib.sha256()
                total = 0
                capture = info.filename in {
                    NPM_MANIFEST_RELATIVE_PATH,
                    NPM_CLI_RELATIVE_PATH,
                }
                captured = bytearray()
                try:
                    with os.fdopen(descriptor, "wb") as output, archive.open(
                        info, "r"
                    ) as source:
                        while True:
                            _check_deadline(deadline)
                            chunk = source.read(READ_CHUNK_BYTES)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > info.file_size or total > MAX_ARCHIVE_ENTRY_BYTES:
                                raise EntraCallingClientMSALFrontendHostArtifactProofError(
                                    "ZIP extraction byte bound was exceeded"
                                )
                            output.write(chunk)
                            digest.update(chunk)
                            if capture:
                                captured.extend(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                except Exception:
                    if not getattr(locals().get("output", None), "closed", True):
                        os.close(descriptor)
                    raise
                if total != info.file_size:
                    raise EntraCallingClientMSALFrontendHostArtifactProofError(
                        "ZIP extracted member length is not exact"
                    )
                value = digest.hexdigest()
                file_projection.append(
                    {"bytes": total, "path": info.filename, "sha256": value}
                )
                expected_files.add(info.filename)
                if capture:
                    critical_bytes[info.filename] = bytes(captured)
        pending.rename(published)
    except Exception:
        raise

    actual_directories: set[str] = set()
    actual_files: set[str] = set()
    expected_file_projection = {
        str(item["path"]): item for item in file_projection
    }
    for root_string, directory_names, file_names in os.walk(
        published, topdown=True, followlinks=False
    ):
        _check_deadline(deadline)
        root = Path(root_string)
        if _is_reparse(root):
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "extracted directory is a reparse point"
            )
        for directory_name in directory_names:
            path = root / directory_name
            if _is_reparse(path) or not path.is_dir():
                raise EntraCallingClientMSALFrontendHostArtifactProofError(
                    "extracted directory identity is invalid"
                )
            actual_directories.add(path.relative_to(published).as_posix() + "/")
        for file_name in file_names:
            _check_deadline(deadline)
            path = root / file_name
            if _is_reparse(path) or not path.is_file():
                raise EntraCallingClientMSALFrontendHostArtifactProofError(
                    "extracted file identity is invalid"
                )
            relative = path.relative_to(published).as_posix()
            actual_files.add(relative)
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as stream:
                while True:
                    _check_deadline(deadline)
                    chunk = stream.read(READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    size += len(chunk)
                    digest.update(chunk)
            if expected_file_projection.get(relative) != {
                "bytes": size,
                "path": relative,
                "sha256": digest.hexdigest(),
            }:
                raise EntraCallingClientMSALFrontendHostArtifactProofError(
                    "post-extraction file bytes are not exact"
                )
    if actual_directories != expected_directories or actual_files != expected_files:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "extracted filesystem inventory is not exact"
        )
    file_inventory_sha256 = _framed(
        "extracted-file-inventory", file_projection
    )
    if file_inventory_sha256 != EXPECTED_EXTRACTED_FILE_INVENTORY_SHA256:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "extracted file inventory identity is not exact"
        )

    file_values = {item["path"]: item for item in file_projection}
    node = file_values.get(NODE_EXECUTABLE_RELATIVE_PATH)
    manifest = file_values.get(NPM_MANIFEST_RELATIVE_PATH)
    cli = file_values.get(NPM_CLI_RELATIVE_PATH)
    if (
        node
        != {
            "bytes": NODE_EXECUTABLE_BYTES,
            "path": NODE_EXECUTABLE_RELATIVE_PATH,
            "sha256": NODE_EXECUTABLE_SHA256,
        }
        or manifest
        != {
            "bytes": NPM_MANIFEST_BYTES,
            "path": NPM_MANIFEST_RELATIVE_PATH,
            "sha256": NPM_MANIFEST_SHA256,
        }
        or cli
        != {
            "bytes": NPM_CLI_BYTES,
            "path": NPM_CLI_RELATIVE_PATH,
            "sha256": NPM_CLI_SHA256,
        }
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "critical extracted toolchain file identity is invalid"
        )
    try:
        npm_manifest = json.loads(
            critical_bytes[NPM_MANIFEST_RELATIVE_PATH].decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (KeyError, UnicodeDecodeError, ValueError, TypeError) as error:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "bundled npm manifest is invalid"
        ) from error
    if (
        type(npm_manifest) is not dict
        or npm_manifest.get("name") != "npm"
        or npm_manifest.get("version") != NPM_VERSION
        or npm_manifest.get("bin")
        != {"npm": "bin/npm-cli.js", "npx": "bin/npx-cli.js"}
        or npm_manifest.get("engines")
        != {"node": "^20.17.0 || >=22.9.0"}
        or critical_bytes.get(NPM_CLI_RELATIVE_PATH)
        != b"#!/usr/bin/env node\r\nrequire('../lib/cli.js')(process)\r\n"
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "bundled npm static identity is not exact"
        )
    return _ArchiveProof(
        archive_inventory_sha256=archive_inventory_sha256,
        extracted_file_inventory_sha256=file_inventory_sha256,
        entry_count=EXPECTED_ENTRY_COUNT,
        file_count=EXPECTED_FILE_COUNT,
        directory_count=EXPECTED_DIRECTORY_COUNT,
        uncompressed_bytes=EXPECTED_UNCOMPRESSED_BYTES,
        compressed_payload_bytes=EXPECTED_COMPRESSED_PAYLOAD_BYTES,
        node_executable_sha256=NODE_EXECUTABLE_SHA256,
        npm_manifest_sha256=NPM_MANIFEST_SHA256,
        npm_cli_sha256=NPM_CLI_SHA256,
        npm_manifest_name="npm",
        npm_manifest_version=NPM_VERSION,
    )


def _prove_archive(
    archive_path: Path, temporary_root: Path, deadline: float
) -> _ArchiveProof:
    _check_deadline(deadline)
    try:
        archive_resolved = archive_path.resolve(strict=True)
        root_resolved = temporary_root.resolve(strict=True)
        if (
            archive_resolved.parent != root_resolved
            or archive_resolved.name != NODE_ARCHIVE_FILENAME
            or _is_reparse(archive_resolved)
            or not archive_resolved.is_file()
            or archive_resolved.stat().st_size != NODE_ARCHIVE_BYTES
        ):
            raise ValueError("archive containment is invalid")
        digest = hashlib.sha256()
        with archive_resolved.open("rb") as stream:
            for chunk in iter(lambda: stream.read(READ_CHUNK_BYTES), b""):
                _check_deadline(deadline)
                digest.update(chunk)
        if digest.hexdigest() != NODE_ARCHIVE_SHA256:
            raise ValueError("archive hash is invalid")
    except (OSError, RuntimeError, ValueError) as error:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "downloaded archive byte identity is invalid"
        ) from error
    infos, inventory_sha256 = _inspect_archive(archive_resolved, deadline)
    return _extract_and_prove(
        archive_resolved, root_resolved, infos, inventory_sha256, deadline
    )


def _expected_response_identities() -> tuple[tuple[str, int, str], ...]:
    return (
        ("node-release-signing-key", NODE_RELEASE_KEY_BYTES, NODE_RELEASE_KEY_SHA256),
        ("node-release-shasums", NODE_SHASUMS_BYTES, NODE_SHASUMS_SHA256),
        (
            "node-release-shasums-detached-signature",
            NODE_SHASUMS_SIG_BYTES,
            NODE_SHASUMS_SIG_SHA256,
        ),
        (
            "node-release-shasums-clearsigned",
            NODE_SHASUMS_ASC_BYTES,
            NODE_SHASUMS_ASC_SHA256,
        ),
        (
            "node-windows-x64-portable-archive",
            NODE_ARCHIVE_BYTES,
            NODE_ARCHIVE_SHA256,
        ),
    )


def _expected_response_media_types() -> tuple[str, ...]:
    return (
        "text/plain;charset=utf-8",
        "text/plain;charset=utf-8",
        "application/pgp-signature",
        "text/plain;charset=utf-8",
        "application/zip",
    )


def _load_proof_core(
    authorization_document: bytes,
    evidence: object,
    *,
    require_live_attestation: bool,
) -> EntraCallingClientMSALFrontendHostArtifactProofReceipt:
    authorization = validate_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
        authorization_document
    )
    from app.security import (
        authentication_entra_calling_client_msal_browser_frontend_host_execution_platform_artifact_http_loader
        as loader,
    )

    if type(evidence) is not loader.LiveOfficialArtifactEvidence:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "exact official artifact evidence is required"
        )
    if require_live_attestation and not loader.is_attested_live_official_artifact_evidence(
        evidence
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "live-attested official artifact evidence is required"
        )
    expected = _expected_response_identities()
    expected_urls = tuple(
        str(item["url"]) for item in loader.official_request_contract_projection()
    )
    expected_media_types = _expected_response_media_types()
    requests = evidence.requests
    if (
        evidence.request_count != 5
        or len(requests) != 5
        or evidence.aggregate_response_bytes != 37_311_607
        or evidence.redirects_followed != 0
        or evidence.automatic_retries != 0
        or evidence.environment_proxy_configuration_used
        or evidence.credentials_sent
        or evidence.response_decoding_used
        or evidence.cleanup_completed
        or type(evidence.started_monotonic) is not float
        or type(evidence.deadline_monotonic) is not float
        or not math.isfinite(evidence.started_monotonic)
        or not math.isfinite(evidence.deadline_monotonic)
        or evidence.deadline_monotonic - evidence.started_monotonic != 300.0
        or time.monotonic() >= evidence.deadline_monotonic
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "official artifact transport evidence is not exact"
        )
    response_projection: list[dict[str, object]] = []
    response_bodies: dict[str, bytes] = {}
    for response, (request_id, size, digest), expected_url, expected_media_type in zip(
        requests,
        expected,
        expected_urls,
        expected_media_types,
        strict=True,
    ):
        is_archive = request_id == "node-windows-x64-portable-archive"
        if (
            response.request_id != request_id
            or response.method != "GET"
            or response.status_code != 200
            or response.url != expected_url
            or response.media_type != expected_media_type
            or response.content_length != size
            or response.body_sha256 != digest
            or (is_archive and (response.body is not None or response.local_path != evidence.archive_path))
            or (
                not is_archive
                and (
                    type(response.body) is not bytes
                    or len(response.body) != size
                    or hashlib.sha256(response.body).hexdigest() != digest
                    or response.local_path is not None
                )
            )
        ):
            raise EntraCallingClientMSALFrontendHostArtifactProofError(
                "official artifact response correlation is not exact"
            )
        if not is_archive:
            response_bodies[request_id] = response.body
        response_projection.append(
            {
                "body_sha256": digest,
                "bytes": size,
                "media_type": response.media_type,
                "request_id": request_id,
                "url": response.url,
            }
        )

    proof: _ArchiveProof | None = None
    detached: _OpenPgpSignature | None = None
    clear: _OpenPgpSignature | None = None
    cleanup_error: Exception | None = None
    try:
        _check_deadline(evidence.deadline_monotonic)
        shasums = response_bodies["node-release-shasums"]
        detached, clear = _verify_openpgp(
            response_bodies["node-release-signing-key"],
            shasums,
            response_bodies["node-release-shasums-detached-signature"],
            response_bodies["node-release-shasums-clearsigned"],
        )
        _parse_shasums(shasums)
        proof = _prove_archive(
            Path(evidence.archive_path),
            Path(evidence.temporary_root),
            evidence.deadline_monotonic,
        )
        _check_deadline(evidence.deadline_monotonic)
    finally:
        try:
            if not evidence.cleanup_completed:
                loader.cleanup_official_artifact_evidence(evidence)
        except Exception as error:
            cleanup_error = error
    if cleanup_error is not None or not evidence.cleanup_completed:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "Step 239 temporary artifact cleanup was not confirmed"
        ) from cleanup_error
    _check_deadline(evidence.deadline_monotonic)
    if proof is None or detached is None or clear is None:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "Step 239 artifact proof did not complete"
        )
    receipt = EntraCallingClientMSALFrontendHostArtifactProofReceipt(
        receipt_type=RECEIPT_TYPE,
        schema_version=SCHEMA_VERSION,
        source=SOURCE,
        scope=SCOPE,
        status=STATUS,
        approved_step238_accepted_state_manifest_sha256=(
            authorization.approved_step238_accepted_state_manifest_sha256
        ),
        approved_step238_package_manifest_sha256=(
            authorization.approved_step238_package_manifest_sha256
        ),
        approved_step238_readiness_sha256=(
            authorization.approved_step238_readiness_sha256
        ),
        approved_step238_readiness_test_sha256=(
            authorization.approved_step238_readiness_test_sha256
        ),
        approved_step238_canonical_receipt_sha256=(
            authorization.approved_step238_canonical_receipt_sha256
        ),
        approved_step238_readiness_document_sha256=(
            authorization.approved_step238_readiness_document_sha256
        ),
        approved_step238_readiness_status=(
            authorization.approved_step238_readiness_status
        ),
        request_count=5,
        aggregate_response_bytes=evidence.aggregate_response_bytes,
        response_body_set_sha256=_framed("response-body-set", response_projection),
        signer_fingerprint=EXPECTED_SIGNER_FINGERPRINT,
        signer_key_id=EXPECTED_SIGNER_KEY_ID,
        detached_signature_digest_sha256=detached.digest.hex(),
        clearsigned_signature_digest_sha256=clear.digest.hex(),
        signed_shasums_sha256=NODE_SHASUMS_SHA256,
        sorted_shasums_sha256=EXPECTED_SORTED_SHASUMS_SHA256,
        archive_sha256=NODE_ARCHIVE_SHA256,
        central_directory_sha256=EXPECTED_CENTRAL_DIRECTORY_SHA256,
        archive_inventory_sha256=proof.archive_inventory_sha256,
        extracted_file_inventory_sha256=proof.extracted_file_inventory_sha256,
        entry_count=proof.entry_count,
        file_count=proof.file_count,
        directory_count=proof.directory_count,
        uncompressed_bytes=proof.uncompressed_bytes,
        compressed_payload_bytes=proof.compressed_payload_bytes,
        node_executable_sha256=proof.node_executable_sha256,
        npm_manifest_sha256=proof.npm_manifest_sha256,
        npm_cli_sha256=proof.npm_cli_sha256,
        npm_manifest_name=proof.npm_manifest_name,
        npm_manifest_version=proof.npm_manifest_version,
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
    rendered = render_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_receipt(
        receipt
    )
    if hashlib.sha256(rendered).hexdigest() != CANONICAL_RECEIPT_SHA256:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "Step 239 canonical receipt identity is invalid"
        )
    return receipt


def _load_proof(
    authorization_document: bytes,
    evidence: object,
    *,
    require_live_attestation: bool,
) -> EntraCallingClientMSALFrontendHostArtifactProofReceipt:
    """Run the proof and clean every loader-owned failure path.

    The core deliberately owns the success-path cleanup ordering because the
    receipt may only be constructed after deletion is confirmed.  This outer
    boundary covers authorization, live-attestation, correlation, and other
    pre-proof failures that occur before the core's extraction ``finally``.
    """

    from app.security import (
        authentication_entra_calling_client_msal_browser_frontend_host_execution_platform_artifact_http_loader
        as loader,
    )

    try:
        return _load_proof_core(
            authorization_document,
            evidence,
            require_live_attestation=require_live_attestation,
        )
    except Exception:
        if (
            type(evidence) is loader.LiveOfficialArtifactEvidence
            and not evidence.cleanup_completed
        ):
            try:
                loader.cleanup_official_artifact_evidence(evidence)
            except Exception as cleanup_error:
                raise EntraCallingClientMSALFrontendHostArtifactProofError(
                    "Step 239 temporary artifact cleanup was not confirmed"
                ) from cleanup_error
        raise


def load_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_proof(
    authorization_document: bytes,
    evidence: object,
) -> EntraCallingClientMSALFrontendHostArtifactProofReceipt:
    return _load_proof(
        authorization_document, evidence, require_live_attestation=True
    )


def render_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_receipt(
    receipt: EntraCallingClientMSALFrontendHostArtifactProofReceipt,
) -> bytes:
    if type(receipt) is not EntraCallingClientMSALFrontendHostArtifactProofReceipt:
        raise TypeError("exact Step 239 artifact proof receipt is required")
    value = dataclasses.asdict(receipt)
    if (
        receipt.receipt_type != RECEIPT_TYPE
        or receipt.schema_version != SCHEMA_VERSION
        or receipt.source != SOURCE
        or receipt.scope != SCOPE
        or receipt.status != STATUS
        or not receipt.temporary_artifacts_cleaned
        or not receipt.both_openpgp_signatures_verified
        or not receipt.signed_checksum_binding_verified
        or not receipt.complete_archive_structure_and_inventory_verified
        or not receipt.safe_extraction_and_complete_file_inventory_verified
        or not receipt.static_node_npm_toolchain_identity_verified
        or receipt.host_vendor_support_verified
        or receipt.node_or_npm_executed
        or receipt.lock_generation_authorized_or_performed
        or receipt.frontend_materialized
        or receipt.operational_write_performed
    ):
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "Step 239 artifact proof receipt is not fail-closed"
        )
    rendered = _canonical(value)
    if hashlib.sha256(rendered).hexdigest() != CANONICAL_RECEIPT_SHA256:
        raise EntraCallingClientMSALFrontendHostArtifactProofError(
            "Step 239 canonical receipt identity is invalid"
        )
    return rendered


__all__ = [
    "AUTHORIZATION_TYPE",
    "CANONICAL_RECEIPT_SHA256",
    "DOCUMENT_TYPE",
    "EntraCallingClientMSALFrontendHostArtifactProofAuthorization",
    "EntraCallingClientMSALFrontendHostArtifactProofError",
    "EntraCallingClientMSALFrontendHostArtifactProofReceipt",
    "EXPECTED_ARCHIVE_INVENTORY_SHA256",
    "EXPECTED_EXTRACTED_FILE_INVENTORY_SHA256",
    "EXPECTED_SIGNER_FINGERPRINT",
    "NODE_ARCHIVE_SHA256",
    "NODE_EXECUTABLE_SHA256",
    "NPM_CLI_SHA256",
    "NPM_MANIFEST_SHA256",
    "RECEIPT_TYPE",
    "SCHEMA_VERSION",
    "SCOPE",
    "SOURCE",
    "STATUS",
    "STEP238_ACCEPTED_STATE_MANIFEST_SHA256",
    "STEP238_PACKAGE_MANIFEST_SHA256",
    "TITLE",
    "is_validated_entra_calling_client_msal_frontend_host_artifact_proof_authorization",
    "load_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_proof",
    "render_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_receipt",
    "render_entra_calling_client_msal_frontend_host_artifact_proof_authorization",
    "validate_entra_calling_client_msal_frontend_host_artifact_proof_authorization",
]
