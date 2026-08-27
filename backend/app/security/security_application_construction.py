"""Controlled local construction of a readiness-bound secured application."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import stat
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from fastapi import FastAPI

from app.main import (
    OperationalReadinessConfirmedApplicationReceipt,
    create_readiness_confirmed_secured_application,
)
from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.authentication_readiness_preview import (
    read_authentication_readiness_preview,
)
from app.security.jwks_http_loader import OpenURL
from app.security.security_application_activation_readiness import (
    MAX_OPERATIONAL_APPLICATION_ACTIVATION_READINESS_RECEIPT_BYTES,
)


OPERATIONAL_APPLICATION_CONSTRUCTION_SCOPE = (
    "digest_confirmed_readiness_bound_secured_application_construction"
)


class OperationalApplicationConstructionFileError(ValueError):
    """Sanitized rejection of unsafe local construction evidence."""


class OperationalApplicationConstructionError(RuntimeError):
    """Sanitized rejection before a separate secured app is constructed."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _approved_digest(value: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise OperationalApplicationConstructionError(
            "approved activation readiness digest is invalid"
        )
    return value


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
    )


def _unchanged_file(left: os.stat_result, right: os.stat_result) -> bool:
    unchanged = (
        _same_file(left, right)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )
    if os.name == "nt":
        return unchanged
    return unchanged and left.st_ctime_ns == right.st_ctime_ns


def _read_activation_readiness_document(
    path: str | os.PathLike[str],
) -> bytes:
    """Read one stable, bounded, regular non-symlink readiness file."""

    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("operational activation readiness path is invalid")
    try:
        initial = os.lstat(path)
    except (OSError, ValueError):
        raise OperationalApplicationConstructionFileError(
            "operational activation readiness file could not be opened safely"
        ) from None
    if not stat.S_ISREG(initial.st_mode):
        raise OperationalApplicationConstructionFileError(
            "operational activation readiness must be a regular non-symlink file"
        )
    if initial.st_size == 0:
        raise OperationalApplicationConstructionFileError(
            "operational activation readiness file is empty"
        )
    if (
        initial.st_size
        > MAX_OPERATIONAL_APPLICATION_ACTIVATION_READINESS_RECEIPT_BYTES
    ):
        raise OperationalApplicationConstructionFileError(
            "operational activation readiness file exceeds the byte limit"
        )

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file(initial, opened):
            raise OperationalApplicationConstructionFileError(
                "operational activation readiness file changed before opening"
            )
        chunks: list[bytes] = []
        remaining = (
            MAX_OPERATIONAL_APPLICATION_ACTIVATION_READINESS_RECEIPT_BYTES + 1
        )
        while remaining > 0:
            chunk = os.read(descriptor, min(8_192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        document = b"".join(chunks)
        final = os.fstat(descriptor)
    except OperationalApplicationConstructionFileError:
        raise
    except (OSError, ValueError):
        raise OperationalApplicationConstructionFileError(
            "operational activation readiness file could not be read safely"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise OperationalApplicationConstructionFileError(
                    "operational activation readiness file could not be closed safely"
                ) from None

    if (
        len(document)
        > MAX_OPERATIONAL_APPLICATION_ACTIVATION_READINESS_RECEIPT_BYTES
    ):
        raise OperationalApplicationConstructionFileError(
            "operational activation readiness file exceeds the byte limit"
        )
    if not document:
        raise OperationalApplicationConstructionFileError(
            "operational activation readiness file is empty"
        )
    if not _unchanged_file(initial, final):
        raise OperationalApplicationConstructionFileError(
            "operational activation readiness file changed while it was read"
        )
    return document


def _operational_session_factory():
    from app.db.database import SessionLocal

    return SessionLocal


def _fresh_access_session():
    return _operational_session_factory()()


def _fresh_audit_session():
    return _operational_session_factory()()


def construct_local_readiness_confirmed_secured_application(
    *,
    authentication_document_path: str | os.PathLike[str],
    activation_readiness_path: str | os.PathLike[str],
    approved_activation_readiness_sha256: str,
    access_session_factory: Callable[[], object] | None = None,
    audit_session_factory: Callable[[], object] | None = None,
    open_url: OpenURL | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> FastAPI:
    """Construct, but never serve or install, one readiness-bound app."""

    approved = _approved_digest(approved_activation_readiness_sha256)
    if access_session_factory is not None and not callable(
        access_session_factory
    ):
        raise TypeError("operational access session factory must be callable")
    if audit_session_factory is not None and not callable(
        audit_session_factory
    ):
        raise TypeError("operational audit session factory must be callable")
    if open_url is not None and not callable(open_url):
        raise TypeError("operational JWKS transport must be callable")
    if not callable(clock):
        raise TypeError("operational application construction clock is required")

    readiness_document = _read_activation_readiness_document(
        activation_readiness_path
    )
    actual = hashlib.sha256(readiness_document).hexdigest()
    if not hmac.compare_digest(actual, approved):
        raise OperationalApplicationConstructionError(
            "operational activation readiness does not match approval"
        )

    authentication_readiness = read_authentication_readiness_preview(
        authentication_document_path
    )
    return create_readiness_confirmed_secured_application(
        authentication_readiness=authentication_readiness,
        activation_readiness_document=readiness_document,
        approved_activation_readiness_sha256=approved,
        access_session_factory=(
            access_session_factory
            if access_session_factory is not None
            else _fresh_access_session
        ),
        audit_session_factory=(
            audit_session_factory
            if audit_session_factory is not None
            else _fresh_audit_session
        ),
        open_url=open_url,
        clock=clock,
    )


def _canonical_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def render_operational_application_construction_receipt(
    receipt: OperationalReadinessConfirmedApplicationReceipt,
) -> str:
    """Render exact privacy-minimised evidence for a non-cutover build."""

    if type(receipt) is not OperationalReadinessConfirmedApplicationReceipt:
        raise TypeError("operational application construction receipt is required")
    try:
        canonical = OperationalReadinessConfirmedApplicationReceipt(
            activation_readiness_sha256=receipt.activation_readiness_sha256,
            postflight_receipt_sha256=receipt.postflight_receipt_sha256,
            configuration_sha256=receipt.configuration_sha256,
            jwks_document_sha256=receipt.jwks_document_sha256,
            bootstrap_document_sha256=receipt.bootstrap_document_sha256,
            issuer_sha256=receipt.issuer_sha256,
            user_id=receipt.user_id,
            organisation_id=receipt.organisation_id,
            entitlement_snapshot_id=receipt.entitlement_snapshot_id,
            readiness_checked_at=receipt.readiness_checked_at,
            construction_checked_at=receipt.construction_checked_at,
            route_bindings=receipt.route_bindings,
            protected_bindings=receipt.protected_bindings,
            public_bindings=receipt.public_bindings,
            readiness_bound=receipt.readiness_bound,
            application_constructed=receipt.application_constructed,
            deployment_cutover_performed=receipt.deployment_cutover_performed,
        )
    except (TypeError, ValueError):
        raise ValueError(
            "operational application construction receipt is invalid"
        ) from None
    if canonical != receipt:
        raise ValueError("operational application construction receipt is invalid")
    return json.dumps(
        {
            "scope": OPERATIONAL_APPLICATION_CONSTRUCTION_SCOPE,
            "activation_readiness_sha256": canonical.activation_readiness_sha256,
            "postflight_receipt_sha256": canonical.postflight_receipt_sha256,
            "configuration_sha256": canonical.configuration_sha256,
            "jwks_document_sha256": canonical.jwks_document_sha256,
            "bootstrap_document_sha256": canonical.bootstrap_document_sha256,
            "issuer_sha256": canonical.issuer_sha256,
            "user_id": str(canonical.user_id),
            "organisation_id": str(canonical.organisation_id),
            "entitlement_snapshot_id": str(canonical.entitlement_snapshot_id),
            "readiness_checked_at": _canonical_timestamp(
                canonical.readiness_checked_at
            ),
            "construction_checked_at": _canonical_timestamp(
                canonical.construction_checked_at
            ),
            "route_bindings": canonical.route_bindings,
            "protected_bindings": canonical.protected_bindings,
            "public_bindings": canonical.public_bindings,
            "readiness_bound": canonical.readiness_bound,
            "application_constructed": canonical.application_constructed,
            "deployment_cutover_performed": (
                canonical.deployment_cutover_performed
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def main(arguments: Sequence[str] | None = None) -> int:
    """Construct one separate app and print only its canonical receipt."""

    parser = argparse.ArgumentParser(
        description=(
            "Construct a separate readiness-bound Engineer4Me secured application."
        )
    )
    parser.add_argument("authentication_document")
    parser.add_argument("activation_readiness_receipt")
    parser.add_argument(
        "--approve-activation-readiness-sha256",
        required=True,
        dest="approved_activation_readiness_sha256",
    )
    options = parser.parse_args(arguments)
    try:
        application = construct_local_readiness_confirmed_secured_application(
            authentication_document_path=options.authentication_document,
            activation_readiness_path=options.activation_readiness_receipt,
            approved_activation_readiness_sha256=(
                options.approved_activation_readiness_sha256
            ),
        )
        rendered = render_operational_application_construction_receipt(
            application.state.security_activation
        )
    except Exception:
        parser.exit(2, "operational secured application construction failed\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OPERATIONAL_APPLICATION_CONSTRUCTION_SCOPE",
    "OperationalApplicationConstructionError",
    "OperationalApplicationConstructionFileError",
    "construct_local_readiness_confirmed_secured_application",
    "main",
    "render_operational_application_construction_receipt",
]
