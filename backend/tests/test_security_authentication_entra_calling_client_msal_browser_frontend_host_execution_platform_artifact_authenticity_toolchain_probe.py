from __future__ import annotations

import ast
import base64
import binascii
import dataclasses
import hashlib
import inspect
import json
import struct
import time
import zipfile
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.security import (
    authentication_entra_calling_client_msal_browser_frontend_host_execution_platform_artifact_authenticity_toolchain_probe
    as probe,
)
from app.security import (
    authentication_entra_calling_client_msal_browser_frontend_host_execution_platform_artifact_http_loader
    as loader,
)


def _mpi(value: bytes) -> bytes:
    bits = int.from_bytes(value, "big").bit_length()
    return bits.to_bytes(2, "big") + value


def _old_packet(tag: int, body: bytes) -> bytes:
    assert len(body) < 256
    return bytes((0x80 | (tag << 2), len(body))) + body


def _armor(label: str, packet: bytes) -> bytes:
    body = base64.b64encode(packet).decode("ascii")
    lines = [body[index : index + 64] for index in range(0, len(body), 64)]
    crc = base64.b64encode(probe._crc24(packet).to_bytes(3, "big")).decode(
        "ascii"
    )
    return (
        f"-----BEGIN PGP {label}-----\n\n"
        + "\n".join(lines)
        + f"\n={crc}\n-----END PGP {label}-----\n"
    ).encode("ascii")


def _signature_body(
    private: Ed25519PrivateKey,
    fingerprint: bytes,
    signed_data: bytes,
    signature_type: int,
    created: int,
) -> tuple[bytes, bytes, tuple[int, int]]:
    hashed = (
        b"\x16\x21\x04"
        + fingerprint
        + b"\x05\x02"
        + created.to_bytes(4, "big")
    )
    prefix = bytes((4, signature_type, 22, 8)) + len(hashed).to_bytes(
        2, "big"
    ) + hashed
    digest = hashlib.sha256(
        signed_data + prefix + b"\x04\xff" + len(prefix).to_bytes(4, "big")
    ).digest()
    raw = private.sign(digest)
    r, s = raw[:32], raw[32:]
    unhashed = b"\x09\x10" + fingerprint[-8:]
    body = (
        prefix
        + len(unhashed).to_bytes(2, "big")
        + unhashed
        + digest[:2]
        + _mpi(r)
        + _mpi(s)
    )
    return body, digest, (
        int.from_bytes(r, "big").bit_length(),
        int.from_bytes(s, "big").bit_length(),
    )


def _synthetic_openpgp_fixture(monkeypatch: pytest.MonkeyPatch):
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    key_body = (
        b"\x04"
        + (1_700_000_000).to_bytes(4, "big")
        + b"\x16"
        + bytes((len(probe.EXPECTED_ED25519_OID),))
        + probe.EXPECTED_ED25519_OID
        + _mpi(b"\x40" + public)
    )
    fingerprint = hashlib.sha1(
        b"\x99" + len(key_body).to_bytes(2, "big") + key_body
    ).digest()
    monkeypatch.setattr(probe, "EXPECTED_SIGNER_FINGERPRINT", fingerprint.hex().upper())
    monkeypatch.setattr(probe, "EXPECTED_SIGNER_KEY_ID", fingerprint[-8:].hex().upper())

    for counter in range(10_000):
        message = (
            f"{'0' * 64}  node-v24.19.0-win-x64.zip\n"
            f"{'1' * 64}  win-x64/node.exe\n"
            f"{counter:064x}  fixture-{counter}.txt\n"
        ).encode("ascii")
        detached_body, detached_digest, detached_bits = _signature_body(
            private,
            fingerprint,
            message,
            0,
            probe.EXPECTED_DETACHED_CREATED,
        )
        clear_body, clear_digest, clear_bits = _signature_body(
            private,
            fingerprint,
            message.replace(b"\n", b"\r\n"),
            1,
            probe.EXPECTED_CLEARSIGNED_CREATED,
        )
        if detached_bits == (255, 256) and clear_bits == (256, 256):
            break
    else:
        raise AssertionError("deterministic Ed25519 fixture bit pattern not found")

    monkeypatch.setattr(
        probe, "EXPECTED_DETACHED_DIGEST_PREFIX", detached_digest[:2]
    )
    monkeypatch.setattr(
        probe, "EXPECTED_CLEARSIGNED_DIGEST_PREFIX", clear_digest[:2]
    )
    detached_packet = _old_packet(2, detached_body)
    clear_packet = _old_packet(2, clear_body)
    clear_armor = _armor("SIGNATURE", clear_packet)
    clearsigned = (
        b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
        + message
        + b"\n"
        + clear_armor
    )
    return (
        _armor("PUBLIC KEY BLOCK", _old_packet(6, key_body)),
        message,
        detached_packet,
        clearsigned,
        fingerprint.hex().upper(),
    )


def _receipt_kwargs() -> dict[str, Any]:
    return {
        "receipt_type": probe.RECEIPT_TYPE,
        "schema_version": probe.SCHEMA_VERSION,
        "source": probe.SOURCE,
        "scope": probe.SCOPE,
        "status": probe.STATUS,
        "approved_step238_accepted_state_manifest_sha256": probe.STEP238_ACCEPTED_STATE_MANIFEST_SHA256,
        "approved_step238_package_manifest_sha256": probe.STEP238_PACKAGE_MANIFEST_SHA256,
        "approved_step238_readiness_sha256": probe.STEP238_READINESS_SHA256,
        "approved_step238_readiness_test_sha256": probe.STEP238_READINESS_TEST_SHA256,
        "approved_step238_canonical_receipt_sha256": probe.STEP238_CANONICAL_RECEIPT_SHA256,
        "approved_step238_readiness_document_sha256": probe.STEP238_READINESS_DOCUMENT_SHA256,
        "approved_step238_readiness_status": probe.STEP238_READINESS_STATUS,
        "request_count": 5,
        "aggregate_response_bytes": 37_311_607,
        "response_body_set_sha256": probe.EXPECTED_RESPONSE_BODY_SET_SHA256,
        "signer_fingerprint": probe.EXPECTED_SIGNER_FINGERPRINT,
        "signer_key_id": probe.EXPECTED_SIGNER_KEY_ID,
        "detached_signature_digest_sha256": probe.EXPECTED_DETACHED_DIGEST_SHA256,
        "clearsigned_signature_digest_sha256": probe.EXPECTED_CLEARSIGNED_DIGEST_SHA256,
        "signed_shasums_sha256": probe.NODE_SHASUMS_SHA256,
        "sorted_shasums_sha256": probe.EXPECTED_SORTED_SHASUMS_SHA256,
        "archive_sha256": probe.NODE_ARCHIVE_SHA256,
        "central_directory_sha256": probe.EXPECTED_CENTRAL_DIRECTORY_SHA256,
        "archive_inventory_sha256": probe.EXPECTED_ARCHIVE_INVENTORY_SHA256,
        "extracted_file_inventory_sha256": probe.EXPECTED_EXTRACTED_FILE_INVENTORY_SHA256,
        "entry_count": probe.EXPECTED_ENTRY_COUNT,
        "file_count": probe.EXPECTED_FILE_COUNT,
        "directory_count": probe.EXPECTED_DIRECTORY_COUNT,
        "uncompressed_bytes": probe.EXPECTED_UNCOMPRESSED_BYTES,
        "compressed_payload_bytes": probe.EXPECTED_COMPRESSED_PAYLOAD_BYTES,
        "node_executable_sha256": probe.NODE_EXECUTABLE_SHA256,
        "npm_manifest_sha256": probe.NPM_MANIFEST_SHA256,
        "npm_cli_sha256": probe.NPM_CLI_SHA256,
        "npm_manifest_name": "npm",
        "npm_manifest_version": probe.NPM_VERSION,
        "temporary_artifacts_cleaned": True,
        "both_openpgp_signatures_verified": True,
        "signed_checksum_binding_verified": True,
        "complete_archive_structure_and_inventory_verified": True,
        "safe_extraction_and_complete_file_inventory_verified": True,
        "static_node_npm_toolchain_identity_verified": True,
        "host_vendor_support_verified": False,
        "node_or_npm_executed": False,
        "lock_generation_authorized_or_performed": False,
        "frontend_materialized": False,
        "operational_write_performed": False,
    }


_NTFS_EXTRA = (
    b"\x0a\x00\x20\x00\x00\x00\x00\x00\x01\x00\x18\x00"
    + b"\x00" * 24
)


def _central_record(**overrides: object) -> bytes:
    values: dict[str, object] = {
        "signature": 0x02014B50,
        "made_by": 63,
        "needed": 10,
        "flags": 0,
        "method": 0,
        "mod_time": 0,
        "mod_date": 0,
        "crc32": 0,
        "compressed": 1,
        "uncompressed": 1,
        "name": (probe.NODE_ARCHIVE_ROOT + "/file").encode("ascii"),
        "extra": _NTFS_EXTRA,
        "comment": b"",
        "disk": 0,
        "internal_attributes": 0,
        "external_attributes": 32,
        "local_offset": 0,
    }
    values.update(overrides)
    name = bytes(values.pop("name"))
    extra = bytes(values.pop("extra"))
    comment = bytes(values.pop("comment"))
    header = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        int(values["signature"]),
        int(values["made_by"]),
        int(values["needed"]),
        int(values["flags"]),
        int(values["method"]),
        int(values["mod_time"]),
        int(values["mod_date"]),
        int(values["crc32"]),
        int(values["compressed"]),
        int(values["uncompressed"]),
        len(name),
        len(extra),
        len(comment),
        int(values["disk"]),
        int(values["internal_attributes"]),
        int(values["external_attributes"]),
        int(values["local_offset"]),
    )
    return header + name + extra + comment


def _local_record(
    name: str, data: bytes, *, local_offset: int = 0
) -> tuple[bytes, dict[str, object]]:
    encoded = name.encode("ascii")
    crc = binascii.crc32(data) & 0xFFFFFFFF
    header = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        10,
        0,
        0,
        0,
        0,
        crc,
        len(data),
        len(data),
        len(encoded),
        0,
    )
    entry: dict[str, object] = {
        "name": name,
        "name_bytes": encoded,
        "extra": _NTFS_EXTRA,
        "needed": 10,
        "flags": 0,
        "method": 0,
        "mod_time": 0,
        "mod_date": 0,
        "crc32": crc,
        "compressed": len(data),
        "uncompressed": len(data),
        "external_attributes": 32,
        "local_offset": local_offset,
    }
    return header + encoded + data, entry


class _InventoryArchive:
    def __init__(self, infos: tuple[zipfile.ZipInfo, ...]) -> None:
        self.infos = infos

    def __enter__(self) -> "_InventoryArchive":
        return self

    def __exit__(self, *unused: object) -> None:
        return None

    def infolist(self) -> list[zipfile.ZipInfo]:
        return list(self.infos)


def _inventory_info(
    name: str,
    *,
    file_size: int = 1,
    compress_size: int = 1,
    offset: int = 0,
) -> tuple[zipfile.ZipInfo, dict[str, object]]:
    info = zipfile.ZipInfo(name)
    info.create_system = 0
    info.create_version = 63
    info.extract_version = 10
    info.flag_bits = 0
    info.compress_type = 0
    info.external_attr = 16 if name.endswith("/") else 32
    info.internal_attr = 0
    info.comment = b""
    info.extra = _NTFS_EXTRA
    info.file_size = file_size
    info.compress_size = compress_size
    info.CRC = 0
    info.header_offset = offset
    raw: dict[str, object] = {
        "name": name,
        "name_bytes": name.encode("ascii"),
        "extra": _NTFS_EXTRA,
        "needed": 10,
        "flags": 0,
        "method": 0,
        "mod_time": 0,
        "mod_date": 33,
        "crc32": 0,
        "compressed": compress_size,
        "uncompressed": file_size,
        "external_attributes": info.external_attr,
        "local_offset": offset,
    }
    return info, raw


def _write_extraction_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, tuple[zipfile.ZipInfo, ...], str]:
    archive_path = tmp_path / "fixture.zip"
    manifest = json.dumps(
        {
            "name": "npm",
            "version": probe.NPM_VERSION,
            "bin": {"npm": "bin/npm-cli.js", "npx": "bin/npx-cli.js"},
            "engines": {"node": "^20.17.0 || >=22.9.0"},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    cli = b"#!/usr/bin/env node\r\nrequire('../lib/cli.js')(process)\r\n"
    files = (
        (probe.NODE_EXECUTABLE_RELATIVE_PATH, b"synthetic-node"),
        (probe.NPM_MANIFEST_RELATIVE_PATH, manifest),
        (probe.NPM_CLI_RELATIVE_PATH, cli),
    )
    directories = (
        probe.NODE_ARCHIVE_ROOT + "/",
        probe.NODE_ARCHIVE_ROOT + "/node_modules/",
        probe.NODE_ARCHIVE_ROOT + "/node_modules/npm/",
        probe.NODE_ARCHIVE_ROOT + "/node_modules/npm/bin/",
    )
    with zipfile.ZipFile(archive_path, "w", allowZip64=False) as archive:
        for directory in directories:
            archive.writestr(directory, b"")
        for name, body in files:
            archive.writestr(name, body)
    with zipfile.ZipFile(archive_path, "r", allowZip64=False) as archive:
        infos = tuple(archive.infolist())
    projection = [
        {"bytes": len(body), "path": name, "sha256": hashlib.sha256(body).hexdigest()}
        for name, body in files
    ]
    monkeypatch.setattr(probe, "NODE_EXECUTABLE_BYTES", len(files[0][1]))
    monkeypatch.setattr(
        probe, "NODE_EXECUTABLE_SHA256", hashlib.sha256(files[0][1]).hexdigest()
    )
    monkeypatch.setattr(probe, "NPM_MANIFEST_BYTES", len(manifest))
    monkeypatch.setattr(
        probe, "NPM_MANIFEST_SHA256", hashlib.sha256(manifest).hexdigest()
    )
    monkeypatch.setattr(probe, "NPM_CLI_BYTES", len(cli))
    monkeypatch.setattr(probe, "NPM_CLI_SHA256", hashlib.sha256(cli).hexdigest())
    inventory = probe._framed("extracted-file-inventory", projection)
    monkeypatch.setattr(probe, "EXPECTED_EXTRACTED_FILE_INVENTORY_SHA256", inventory)
    return archive_path, infos, inventory


def _owned_evidence(tmp_path: Path) -> loader.LiveOfficialArtifactEvidence:
    root = loader._new_temporary_root(str(tmp_path))
    archive = root / loader.NODE_ARCHIVE_FILENAME
    archive.write_bytes(b"")
    started = time.monotonic()
    return loader.LiveOfficialArtifactEvidence(
        evidence_source="synthetic_mock_transport",
        requests=(),
        request_count=0,
        aggregate_response_bytes=0,
        redirects_followed=0,
        automatic_retries=0,
        environment_proxy_configuration_used=False,
        credentials_sent=False,
        response_decoding_used=False,
        started_monotonic=started,
        deadline_monotonic=started + 300.0,
        temporary_root=str(root),
        archive_path=str(archive),
        cleanup_completed=False,
        _loader_attestation=object(),
    )


def _write_eocd_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    disk: int = 0,
    central_disk: int = 0,
    marker_prefix: bytes = b"payload",
    suffix: bytes = b"",
    comment_length: int = 0,
) -> Path:
    central = b"synthetic-central-directory"
    central_offset = len(marker_prefix)
    eocd_offset = central_offset + len(central)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        disk,
        central_disk,
        0,
        0,
        len(central),
        central_offset,
        comment_length,
    )
    path = tmp_path / "eocd.zip"
    path.write_bytes(marker_prefix + central + eocd + suffix)
    monkeypatch.setattr(probe, "EXPECTED_ENTRY_COUNT", 0)
    monkeypatch.setattr(probe, "EXPECTED_CENTRAL_DIRECTORY_BYTES", len(central))
    monkeypatch.setattr(probe, "EXPECTED_CENTRAL_DIRECTORY_OFFSET", central_offset)
    monkeypatch.setattr(probe, "EXPECTED_EOCD_OFFSET", eocd_offset)
    monkeypatch.setattr(
        probe,
        "EXPECTED_CENTRAL_DIRECTORY_SHA256",
        hashlib.sha256(central).hexdigest(),
    )
    return path


def test_frozen_title_scope_source_and_status_are_exact() -> None:
    assert probe.TITLE == (
        "Engineer4Me Phase 8 Step 239 controlled read-only official signed "
        "Windows-x64 portable Node.js artifact authenticity, safe-extraction, "
        "and static toolchain-identity proof v1"
    )
    assert probe.SCOPE.startswith("exact_step238_chain_plus_controlled_official")
    assert probe.SOURCE.endswith("artifact_authenticity_toolchain_probe")
    assert "host_support_execution_lock_generation_and_frontend_materialization_blocked" in probe.STATUS


def test_authorization_round_trip_is_exact_and_attested() -> None:
    document = probe.render_entra_calling_client_msal_frontend_host_artifact_proof_authorization()
    authorization = probe.validate_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
        document
    )
    assert document == json.dumps(
        probe._authorization_projection(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    assert probe.is_validated_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
        authorization
    )


@pytest.mark.parametrize("replacement", [True, 1.0, "1", None, 2])
def test_authorization_schema_type_confusion_is_rejected(replacement: object) -> None:
    value = probe._authorization_projection()
    value["schema_version"] = replacement
    document = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostArtifactProofError):
        probe.validate_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
            document
        )


@pytest.mark.parametrize(
    "mutation",
    [
        b"",
        b"{}",
        b"[]",
        b"null",
        b"{\"schema_version\":1,\"schema_version\":1}",
        probe.render_entra_calling_client_msal_frontend_host_artifact_proof_authorization() + b"\n",
        probe.render_entra_calling_client_msal_frontend_host_artifact_proof_authorization().replace(
            b"step238", b"step237", 1
        ),
    ],
)
def test_authorization_noncanonical_or_tampered_bytes_fail(mutation: bytes) -> None:
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostArtifactProofError):
        probe.validate_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
            mutation
        )


def test_direct_authorization_construction_is_not_attested() -> None:
    forged = probe.EntraCallingClientMSALFrontendHostArtifactProofAuthorization(
        **probe._authorization_projection()
    )
    assert not probe.is_validated_entra_calling_client_msal_frontend_host_artifact_proof_authorization(
        forged
    )


def test_synthetic_openpgp_v4_ed25519_detached_and_clear_signatures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key, message, detached, clearsigned, fingerprint = _synthetic_openpgp_fixture(
        monkeypatch
    )
    detached_result, clear_result = probe._verify_openpgp(
        key, message, detached, clearsigned
    )
    assert detached_result.signature_type == 0
    assert clear_result.signature_type == 1
    assert detached_result.issuer_fingerprint == fingerprint
    assert clear_result.issuer_fingerprint == fingerprint


@pytest.mark.parametrize(
    ("target", "index"),
    [
        ("key", 20),
        ("key", -20),
        ("detached", 5),
        ("detached", -5),
        ("clearsigned", 10),
        ("clearsigned", -10),
        ("message", 0),
        ("message", -1),
    ],
)
def test_openpgp_tampering_fails_closed(
    monkeypatch: pytest.MonkeyPatch, target: str, index: int
) -> None:
    key, message, detached, clearsigned, _ = _synthetic_openpgp_fixture(monkeypatch)
    values = {
        "key": bytearray(key),
        "message": bytearray(message),
        "detached": bytearray(detached),
        "clearsigned": bytearray(clearsigned),
    }
    value = values[target]
    value[index] ^= 1
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostArtifactProofError):
        probe._verify_openpgp(
            bytes(values["key"]),
            bytes(values["message"]),
            bytes(values["detached"]),
            bytes(values["clearsigned"]),
        )


@pytest.mark.parametrize(
    "packet",
    [
        b"",
        b"\x00",
        b"\x80",
        b"\x83x",
        b"\xc2\xe0",
        b"\xc2\xff\x00\x00\x00",
        b"\xc2\x05abc",
    ],
)
def test_packet_parser_rejects_truncation_partial_or_indeterminate(packet: bytes) -> None:
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostArtifactProofError):
        probe._packets(packet)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "/absolute",
        "C:/drive",
        "../escape",
        "node-v24.19.0-win-x64/../escape",
        "node-v24.19.0-win-x64\\file",
        "node-v24.19.0-win-x64//file",
        "node-v24.19.0-win-x64/con",
        "node-v24.19.0-win-x64/AUX.txt",
        "node-v24.19.0-win-x64/trailing.",
        "node-v24.19.0-win-x64/trailing ",
        "wrong-root/file",
        "node-v24.19.0-win-x64/file /",
        "node-v24.19.0-win-x64/\x01control",
        "node-v24.19.0-win-x64/café",
    ],
)
def test_unsafe_zip_member_names_are_rejected(name: str) -> None:
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostArtifactProofError):
        probe._validate_member_name(name, is_directory=name.endswith("/"))


@pytest.mark.parametrize(
    ("name", "directory", "components"),
    [
        ("node-v24.19.0-win-x64/", True, ("node-v24.19.0-win-x64",)),
        (
            "node-v24.19.0-win-x64/node.exe",
            False,
            ("node-v24.19.0-win-x64", "node.exe"),
        ),
        (
            "node-v24.19.0-win-x64/node_modules/@scope/pkg/file.js",
            False,
            (
                "node-v24.19.0-win-x64",
                "node_modules",
                "@scope",
                "pkg",
                "file.js",
            ),
        ),
    ],
)
def test_safe_zip_member_names_are_canonical(
    name: str, directory: bool, components: tuple[str, ...]
) -> None:
    assert probe._validate_member_name(name, is_directory=directory) == components


def test_shasums_parser_requires_unique_32_line_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_hash = "a" * 64
    executable_hash = "b" * 64
    lines = [
        f"{archive_hash}  {probe.NODE_ARCHIVE_FILENAME}\n".encode(),
        f"{executable_hash}  win-x64/node.exe\n".encode(),
    ] + [
        f"{index:064x}  fixture-{index}.txt\n".encode()
        for index in range(30)
    ]
    body = b"".join(lines)
    monkeypatch.setattr(probe, "NODE_SHASUMS_BYTES", len(body))
    monkeypatch.setattr(probe, "NODE_SHASUMS_SHA256", hashlib.sha256(body).hexdigest())
    monkeypatch.setattr(probe, "EXPECTED_SORTED_SHASUMS_SHA256", hashlib.sha256(b"".join(sorted(lines))).hexdigest())
    monkeypatch.setattr(probe, "NODE_ARCHIVE_SHA256", archive_hash)
    monkeypatch.setattr(probe, "NODE_EXECUTABLE_SHA256", executable_hash)
    values = probe._parse_shasums(body)
    assert len(values) == 32
    assert values[probe.NODE_ARCHIVE_FILENAME] == archive_hash


@pytest.mark.parametrize("suffix", [b"", b"x", b"\r\n", b"\n\n"])
def test_shasums_noncanonical_bytes_fail(suffix: bytes) -> None:
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostArtifactProofError):
        probe._parse_shasums(suffix)


def test_canonical_receipt_is_frozen() -> None:
    receipt = probe.EntraCallingClientMSALFrontendHostArtifactProofReceipt(
        **_receipt_kwargs()
    )
    rendered = probe.render_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_receipt(
        receipt
    )
    assert len(rendered) == 3_402
    assert hashlib.sha256(rendered).hexdigest() == probe.CANONICAL_RECEIPT_SHA256


@pytest.mark.parametrize(
    "field_name",
    [field.name for field in dataclasses.fields(probe.EntraCallingClientMSALFrontendHostArtifactProofReceipt)],
)
def test_every_receipt_field_is_tamper_evident(field_name: str) -> None:
    values = _receipt_kwargs()
    original = values[field_name]
    if type(original) is bool:
        values[field_name] = not original
    elif type(original) is int:
        values[field_name] = original + 1
    else:
        values[field_name] = str(original) + "x"
    with pytest.raises(ValueError):
        probe.EntraCallingClientMSALFrontendHostArtifactProofReceipt(**values)


def test_renderer_rejects_post_construction_tampering() -> None:
    receipt = probe.EntraCallingClientMSALFrontendHostArtifactProofReceipt(
        **_receipt_kwargs()
    )
    object.__setattr__(receipt, "response_body_set_sha256", "0" * 64)
    with pytest.raises(probe.EntraCallingClientMSALFrontendHostArtifactProofError):
        probe.render_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_receipt(
            receipt
        )


def test_overall_deadline_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe.time, "monotonic", lambda: 10.0)
    with pytest.raises(
        probe.EntraCallingClientMSALFrontendHostArtifactProofError,
        match="deadline",
    ):
        probe._check_deadline(10.0)
    probe._check_deadline(10.1)


def test_classic_eocd_and_central_identity_positive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_eocd_fixture(tmp_path, monkeypatch)
    eocd_offset, central_offset, central_bytes, central = probe._classic_eocd(
        path, time.monotonic() + 10.0
    )
    assert eocd_offset == probe.EXPECTED_EOCD_OFFSET
    assert central_offset == probe.EXPECTED_CENTRAL_DIRECTORY_OFFSET
    assert central_bytes == len(central)
    assert hashlib.sha256(central).hexdigest() == probe.EXPECTED_CENTRAL_DIRECTORY_SHA256


@pytest.mark.parametrize(
    "changes",
    [
        {"disk": 1},
        {"central_disk": 1},
        {"suffix": b"undeclared"},
        {"marker_prefix": b"PK\x06\x06zip64-record"},
        {"marker_prefix": b"PK\x06\x07zip64-locator"},
    ],
)
def test_classic_eocd_rejects_multidisk_trailing_and_zip64(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, object],
) -> None:
    path = _write_eocd_fixture(tmp_path, monkeypatch, **changes)
    with pytest.raises(
        probe.EntraCallingClientMSALFrontendHostArtifactProofError,
        match="end record",
    ):
        probe._classic_eocd(path, time.monotonic() + 10.0)


def test_raw_central_ntfs_entry_is_parsed_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    central = _central_record()
    monkeypatch.setattr(probe, "EXPECTED_ENTRY_COUNT", 1)
    entries = probe._central_entries(central, time.monotonic() + 10.0)
    assert len(entries) == 1
    assert entries[0]["extra"] == _NTFS_EXTRA
    assert entries[0]["external_attributes"] == 32


@pytest.mark.parametrize(
    "changes",
    [
        {"flags": 1},
        {"method": 99},
        {"compressed": 0xFFFFFFFF},
        {"uncompressed": 0xFFFFFFFF},
        {"local_offset": 0xFFFFFFFF},
        {"disk": 1},
        {"extra": b"\x00" * 36},
        {"extra": _NTFS_EXTRA + b"\x00"},
        {"comment": b"hidden"},
    ],
)
def test_raw_central_rejects_encryption_zip64_and_metadata_drift(
    monkeypatch: pytest.MonkeyPatch, changes: dict[str, object]
) -> None:
    monkeypatch.setattr(probe, "EXPECTED_ENTRY_COUNT", 1)
    with pytest.raises(
        probe.EntraCallingClientMSALFrontendHostArtifactProofError,
        match="central header contract",
    ):
        probe._central_entries(
            _central_record(**changes), time.monotonic() + 10.0
        )


def test_local_header_exact_contiguous_coverage_positive(tmp_path: Path) -> None:
    record, entry = _local_record(
        probe.NODE_ARCHIVE_ROOT + "/file", b"payload"
    )
    path = tmp_path / "local.zip"
    path.write_bytes(record)
    probe._validate_local_headers(
        path, (entry,), len(record), time.monotonic() + 10.0
    )


@pytest.mark.parametrize("failure", ["first-offset", "gap", "overlap", "crossing", "mismatch"])
def test_local_header_rejects_gap_overlap_crossing_and_mismatch(
    tmp_path: Path, failure: str
) -> None:
    name1 = probe.NODE_ARCHIVE_ROOT + "/one"
    name2 = probe.NODE_ARCHIVE_ROOT + "/two"
    first, entry1 = _local_record(name1, b"one")
    second_offset = len(first)
    second, entry2 = _local_record(name2, b"two", local_offset=second_offset)
    content = first + second
    entries: tuple[dict[str, object], ...] = (entry1, entry2)
    central_offset = len(content)
    if failure == "first-offset":
        content = b"x" + first
        shifted, entry1 = _local_record(name1, b"one", local_offset=1)
        assert content == b"x" + shifted
        entries = (entry1,)
        central_offset = len(content)
    elif failure == "gap":
        second_offset += 1
        second, entry2 = _local_record(name2, b"two", local_offset=second_offset)
        content = first + b"x" + second
        entries = (entry1, entry2)
        central_offset = len(content)
    elif failure == "overlap":
        entries = (entry1, dict(entry1))
        central_offset = len(first)
        content = first
    elif failure == "crossing":
        entries = (entry1,)
        central_offset = len(first) - 1
        content = first
    else:
        entry1 = dict(entry1)
        entry1["crc32"] = int(entry1["crc32"]) ^ 1
        entries = (entry1,)
        central_offset = len(first)
        content = first
    path = tmp_path / "bad-local.zip"
    path.write_bytes(content)
    with pytest.raises(
        probe.EntraCallingClientMSALFrontendHostArtifactProofError,
        match="local-header or data-range",
    ):
        probe._validate_local_headers(
            path, entries, central_offset, time.monotonic() + 10.0
        )


def _patch_raw_inventory(
    monkeypatch: pytest.MonkeyPatch,
    infos: tuple[zipfile.ZipInfo, ...],
    raws: tuple[dict[str, object], ...],
) -> None:
    monkeypatch.setattr(
        probe,
        "_classic_eocd",
        lambda unused_path, unused_deadline: (0, 1, 0, b""),
    )
    monkeypatch.setattr(
        probe, "_central_entries", lambda unused, unused_deadline: raws
    )
    monkeypatch.setattr(
        probe,
        "_validate_local_headers",
        lambda *unused_args, **unused_kwargs: None,
    )
    monkeypatch.setattr(probe, "EXPECTED_ENTRY_COUNT", len(infos))
    monkeypatch.setattr(
        probe.zipfile,
        "ZipFile",
        lambda *unused_args, **unused_kwargs: _InventoryArchive(infos),
    )


def test_archive_inventory_rejects_casefold_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _inventory_info(probe.NODE_ARCHIVE_ROOT + "/A")
    second = _inventory_info(probe.NODE_ARCHIVE_ROOT + "/a", offset=1)
    _patch_raw_inventory(
        monkeypatch, (first[0], second[0]), (first[1], second[1])
    )
    with pytest.raises(
        probe.EntraCallingClientMSALFrontendHostArtifactProofError,
        match="collision",
    ):
        probe._inspect_archive(tmp_path / "unused.zip", time.monotonic() + 10.0)


def test_archive_inventory_rejects_compression_bomb_ratio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = _inventory_info(
        probe.NODE_ARCHIVE_ROOT + "/bomb",
        file_size=probe.MAX_COMPRESSION_RATIO + 1,
        compress_size=1,
    )
    _patch_raw_inventory(monkeypatch, (value[0],), (value[1],))
    with pytest.raises(
        probe.EntraCallingClientMSALFrontendHostArtifactProofError,
        match="safe contract",
    ):
        probe._inspect_archive(tmp_path / "unused.zip", time.monotonic() + 10.0)


def test_safe_extraction_and_post_write_full_rehash_positive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path, infos, inventory = _write_extraction_fixture(
        tmp_path, monkeypatch
    )
    result = probe._extract_and_prove(
        archive_path,
        tmp_path,
        infos,
        "archive-inventory-fixture",
        time.monotonic() + 10.0,
    )
    assert result.extracted_file_inventory_sha256 == inventory
    assert (tmp_path / "extracted" / probe.NODE_EXECUTABLE_RELATIVE_PATH).is_file()


def test_post_write_tamper_is_detected_by_filesystem_rehash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive_path, infos, _ = _write_extraction_fixture(tmp_path, monkeypatch)
    original_rename = Path.rename

    def tampering_rename(source: Path, target: Path) -> Path:
        result = original_rename(source, target)
        Path(target, probe.NODE_EXECUTABLE_RELATIVE_PATH).write_bytes(b"changed")
        return result

    monkeypatch.setattr(Path, "rename", tampering_rename)
    with pytest.raises(
        probe.EntraCallingClientMSALFrontendHostArtifactProofError,
        match="post-extraction file bytes",
    ):
        probe._extract_and_prove(
            archive_path,
            tmp_path,
            infos,
            "archive-inventory-fixture",
            time.monotonic() + 10.0,
        )


def test_public_proof_rejects_synthetic_attestation_and_cleans_root(
    tmp_path: Path,
) -> None:
    evidence = _owned_evidence(tmp_path)
    root = Path(evidence.temporary_root)
    with pytest.raises(
        probe.EntraCallingClientMSALFrontendHostArtifactProofError,
        match="live-attested",
    ):
        probe.load_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_proof(
            probe.render_entra_calling_client_msal_frontend_host_artifact_proof_authorization(),
            evidence,
        )
    assert evidence.cleanup_completed
    assert not root.exists()


def test_preproof_correlation_failure_cleans_loader_owned_root(
    tmp_path: Path,
) -> None:
    evidence = _owned_evidence(tmp_path)
    root = Path(evidence.temporary_root)
    with pytest.raises(
        probe.EntraCallingClientMSALFrontendHostArtifactProofError,
        match="transport evidence",
    ):
        probe._load_proof(
            probe.render_entra_calling_client_msal_frontend_host_artifact_proof_authorization(),
            evidence,
            require_live_attestation=False,
        )
    assert evidence.cleanup_completed
    assert not root.exists()


def test_cleanup_failure_prevents_receipt_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = _owned_evidence(tmp_path)
    root = Path(evidence.temporary_root)
    bodies = (b"k", b"s", b"g", b"a", b"z")
    request_ids = tuple(item["request_id"] for item in loader.official_request_contract_projection())
    urls = tuple(str(item["url"]) for item in loader.official_request_contract_projection())
    media_types = ("text/plain", "text/plain", "application/pgp-signature", "text/plain", "application/zip")
    identities = tuple(
        (request_id, len(body), hashlib.sha256(body).hexdigest())
        for request_id, body in zip(request_ids, bodies, strict=True)
    )
    requests = tuple(
        loader.BoundedOfficialArtifactResponse(
            request_id=request_id,
            method="GET",
            url=url,
            status_code=200,
            media_type=media_type,
            content_length=len(body),
            body_sha256=digest,
            body=None if index == 4 else body,
            local_path=evidence.archive_path if index == 4 else None,
        )
        for index, ((request_id, unused_size, digest), url, media_type, body) in enumerate(
            zip(identities, urls, media_types, bodies, strict=True)
        )
    )
    evidence = dataclasses.replace(
        evidence,
        requests=requests,
        request_count=5,
        aggregate_response_bytes=37_311_607,
    )
    detached = probe._OpenPgpSignature(
        0,
        probe.EXPECTED_DETACHED_CREATED,
        bytes.fromhex(probe.EXPECTED_DETACHED_DIGEST_SHA256),
        probe.EXPECTED_SIGNER_FINGERPRINT,
        probe.EXPECTED_SIGNER_KEY_ID,
    )
    clearsigned = probe._OpenPgpSignature(
        1,
        probe.EXPECTED_CLEARSIGNED_CREATED,
        bytes.fromhex(probe.EXPECTED_CLEARSIGNED_DIGEST_SHA256),
        probe.EXPECTED_SIGNER_FINGERPRINT,
        probe.EXPECTED_SIGNER_KEY_ID,
    )
    archive_proof = probe._ArchiveProof(
        probe.EXPECTED_ARCHIVE_INVENTORY_SHA256,
        probe.EXPECTED_EXTRACTED_FILE_INVENTORY_SHA256,
        probe.EXPECTED_ENTRY_COUNT,
        probe.EXPECTED_FILE_COUNT,
        probe.EXPECTED_DIRECTORY_COUNT,
        probe.EXPECTED_UNCOMPRESSED_BYTES,
        probe.EXPECTED_COMPRESSED_PAYLOAD_BYTES,
        probe.NODE_EXECUTABLE_SHA256,
        probe.NPM_MANIFEST_SHA256,
        probe.NPM_CLI_SHA256,
        "npm",
        probe.NPM_VERSION,
    )
    rendered = False

    def renderer_was_not_allowed(unused_receipt: object) -> bytes:
        nonlocal rendered
        rendered = True
        return b"forbidden"

    def cleanup_failure(unused_evidence: object) -> None:
        raise loader.OfficialArtifactHttpLoaderError("synthetic cleanup failure")

    with monkeypatch.context() as scoped:
        scoped.setattr(probe, "_expected_response_identities", lambda: identities)
        scoped.setattr(probe, "_expected_response_media_types", lambda: media_types)
        scoped.setattr(probe, "_verify_openpgp", lambda *unused: (detached, clearsigned))
        scoped.setattr(probe, "_parse_shasums", lambda unused: {})
        scoped.setattr(probe, "_prove_archive", lambda *unused: archive_proof)
        scoped.setattr(
            probe,
            "render_entra_calling_client_msal_frontend_host_artifact_authenticity_toolchain_receipt",
            renderer_was_not_allowed,
        )
        scoped.setattr(loader, "cleanup_official_artifact_evidence", cleanup_failure)
        with pytest.raises(
            probe.EntraCallingClientMSALFrontendHostArtifactProofError,
            match="cleanup was not confirmed",
        ):
            probe._load_proof(
                probe.render_entra_calling_client_msal_frontend_host_artifact_proof_authorization(),
                evidence,
                require_live_attestation=False,
            )
    assert not rendered
    assert root.exists()
    loader.cleanup_official_artifact_evidence(evidence)
    assert evidence.cleanup_completed
    assert not root.exists()


def test_frozen_live_archive_and_static_identity_facts() -> None:
    assert probe.EXPECTED_ENTRY_COUNT == 2_454
    assert probe.EXPECTED_FILE_COUNT == 1_989
    assert probe.EXPECTED_DIRECTORY_COUNT == 465
    assert probe.EXPECTED_UNCOMPRESSED_BYTES == 106_112_876
    assert probe.EXPECTED_COMPRESSED_PAYLOAD_BYTES == 36_653_292
    assert probe.EXPECTED_CENTRAL_DIRECTORY_OFFSET == 36_915_007
    assert probe.EXPECTED_CENTRAL_DIRECTORY_BYTES == 389_323
    assert probe.NODE_EXECUTABLE_BYTES == 92_825_416
    assert probe.NPM_MANIFEST_BYTES == 6_856
    assert probe.NPM_CLI_BYTES == 56
    assert len(probe.NPM_CLI_SHA256) == 64


def test_probe_source_has_no_gpg_subprocess_or_execution_path() -> None:
    source = inspect.getsource(probe)
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
    assert "os.system" not in source
    assert "Popen(" not in source
    assert "run(" not in source
    assert "npm.cmd" not in source


def test_successor_order_remains_explicitly_blocked() -> None:
    assert probe.NODE_VERSION_STDOUT_FUTURE == "v24.19.0"
    assert "host_support_execution_lock_generation" in probe.STATUS
    receipt = probe.EntraCallingClientMSALFrontendHostArtifactProofReceipt(
        **_receipt_kwargs()
    )
    assert not receipt.host_vendor_support_verified
    assert not receipt.node_or_npm_executed
    assert not receipt.lock_generation_authorized_or_performed
    assert not receipt.frontend_materialized
