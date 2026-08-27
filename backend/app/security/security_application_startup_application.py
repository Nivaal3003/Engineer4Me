"""Controlled local application for fresh secured-app startup assembly."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import stat
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from fastapi import FastAPI

from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.authentication_readiness_document import (
    MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES,
)
from app.security.bootstrap_document import MAX_BOOTSTRAP_DOCUMENT_BYTES
from app.security.jwks_http_loader import OpenURL
from app.security.security_application_startup import (
    OperationalSecuredApplicationStartupError,
    create_fresh_readiness_verified_secured_application,
    render_operational_secured_application_startup_receipt,
)
from app.security.security_bootstrap_operational_postflight import (
    MAX_OPERATIONAL_BOOTSTRAP_POSTFLIGHT_RECEIPT_BYTES,
)
from app.services.security_bootstrap_executor import BootstrapSessionFactory


class OperationalSecuredApplicationStartupFileError(ValueError):
    """Sanitized rejection of an unsafe local startup input file."""


class OperationalSecuredApplicationStartupApplicationError(RuntimeError):
    """Sanitized rejection of a local non-cutover startup assembly."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _approved_digest(value: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise OperationalSecuredApplicationStartupApplicationError(
            "approved postflight receipt digest is invalid"
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


def _read_local_document(
    path: str | os.PathLike[str],
    *,
    maximum_bytes: int,
    label: str,
) -> bytes:
    """Read one stable regular non-symlink file through an exact bound."""

    if not isinstance(path, (str, os.PathLike)):
        raise TypeError(f"operational startup {label} path is invalid")
    try:
        initial = os.lstat(path)
    except (OSError, ValueError):
        raise OperationalSecuredApplicationStartupFileError(
            f"operational startup {label} could not be opened safely"
        ) from None
    if not stat.S_ISREG(initial.st_mode):
        raise OperationalSecuredApplicationStartupFileError(
            f"operational startup {label} must be a regular non-symlink file"
        )
    if initial.st_size == 0:
        raise OperationalSecuredApplicationStartupFileError(
            f"operational startup {label} is empty"
        )
    if initial.st_size > maximum_bytes:
        raise OperationalSecuredApplicationStartupFileError(
            f"operational startup {label} exceeds the byte limit"
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
            raise OperationalSecuredApplicationStartupFileError(
                f"operational startup {label} changed before it was opened"
            )
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(8_192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        document = b"".join(chunks)
        final = os.fstat(descriptor)
    except OperationalSecuredApplicationStartupFileError:
        raise
    except (OSError, ValueError):
        raise OperationalSecuredApplicationStartupFileError(
            f"operational startup {label} could not be read safely"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise OperationalSecuredApplicationStartupFileError(
                    f"operational startup {label} could not be closed safely"
                ) from None

    if len(document) > maximum_bytes:
        raise OperationalSecuredApplicationStartupFileError(
            f"operational startup {label} exceeds the byte limit"
        )
    if not document:
        raise OperationalSecuredApplicationStartupFileError(
            f"operational startup {label} is empty"
        )
    if not _unchanged_file(initial, final):
        raise OperationalSecuredApplicationStartupFileError(
            f"operational startup {label} changed while it was read"
        )
    return document


def _operational_session_factory() -> BootstrapSessionFactory:
    from app.db.database import SessionLocal

    return SessionLocal


def _fresh_readiness_session():
    return _operational_session_factory()()


def _fresh_access_session():
    return _operational_session_factory()()


def _fresh_audit_session():
    return _operational_session_factory()()


def construct_local_fresh_readiness_verified_secured_application(
    *,
    authentication_document_path: str | os.PathLike[str],
    postflight_receipt_path: str | os.PathLike[str],
    bootstrap_document_path: str | os.PathLike[str],
    approved_postflight_receipt_sha256: str,
    readiness_session_factory: Callable[[], object] | None = None,
    access_session_factory: Callable[[], object] | None = None,
    audit_session_factory: Callable[[], object] | None = None,
    open_url: OpenURL | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> FastAPI:
    """Read approved local evidence and construct, but never serve, one app."""

    approved = _approved_digest(approved_postflight_receipt_sha256)
    factories = (
        ("readiness", readiness_session_factory),
        ("access", access_session_factory),
        ("audit", audit_session_factory),
    )
    for label, factory in factories:
        if factory is not None and not callable(factory):
            raise TypeError(f"operational {label} session factory must be callable")
    if open_url is not None and not callable(open_url):
        raise TypeError("operational JWKS transport must be callable")
    if not callable(clock):
        raise TypeError("operational startup assembly clock must be callable")

    postflight_document = _read_local_document(
        postflight_receipt_path,
        maximum_bytes=MAX_OPERATIONAL_BOOTSTRAP_POSTFLIGHT_RECEIPT_BYTES,
        label="postflight receipt",
    )
    actual = hashlib.sha256(postflight_document).hexdigest()
    if not hmac.compare_digest(actual, approved):
        raise OperationalSecuredApplicationStartupApplicationError(
            "operational postflight receipt does not match approval"
        )

    authentication_document = _read_local_document(
        authentication_document_path,
        maximum_bytes=MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES,
        label="authentication document",
    )
    bootstrap_document = _read_local_document(
        bootstrap_document_path,
        maximum_bytes=MAX_BOOTSTRAP_DOCUMENT_BYTES,
        label="bootstrap document",
    )

    try:
        return create_fresh_readiness_verified_secured_application(
            authentication_document=authentication_document,
            postflight_receipt_document=postflight_document,
            bootstrap_document=bootstrap_document,
            approved_postflight_receipt_sha256=approved,
            readiness_session_factory=(
                readiness_session_factory
                if readiness_session_factory is not None
                else _fresh_readiness_session
            ),
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
    except OperationalSecuredApplicationStartupError:
        raise OperationalSecuredApplicationStartupApplicationError(
            "operational secured application startup assembly failed"
        ) from None


def main(arguments: Sequence[str] | None = None) -> int:
    """Construct one separate startup app and print only canonical evidence."""

    parser = argparse.ArgumentParser(
        description=(
            "Construct a fresh readiness-verified Engineer4Me secured application."
        )
    )
    parser.add_argument("authentication_document")
    parser.add_argument("postflight_receipt")
    parser.add_argument("bootstrap_document")
    parser.add_argument("--approve-postflight-receipt-sha256", required=True)
    options = parser.parse_args(arguments)
    try:
        application = (
            construct_local_fresh_readiness_verified_secured_application(
                authentication_document_path=options.authentication_document,
                postflight_receipt_path=options.postflight_receipt,
                bootstrap_document_path=options.bootstrap_document,
                approved_postflight_receipt_sha256=(
                    options.approve_postflight_receipt_sha256
                ),
                clock=_utc_now,
            )
        )
        rendered = render_operational_secured_application_startup_receipt(
            application.state.security_startup
        )
    except Exception:
        parser.exit(2, "operational secured application startup assembly failed\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OperationalSecuredApplicationStartupApplicationError",
    "OperationalSecuredApplicationStartupFileError",
    "construct_local_fresh_readiness_verified_secured_application",
    "main",
]
