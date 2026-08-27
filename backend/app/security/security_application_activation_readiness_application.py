"""Controlled local entry point for secured-application activation readiness."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import stat
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.authentication_readiness_document import (
    MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES,
)
from app.security.bootstrap_document import MAX_BOOTSTRAP_DOCUMENT_BYTES
from app.security.security_application_activation_readiness import (
    OperationalApplicationActivationReadinessError,
    OperationalApplicationActivationReadinessReceipt,
    render_operational_application_activation_readiness,
    verify_operational_application_activation_readiness,
)
from app.security.security_bootstrap_operational_postflight import (
    MAX_OPERATIONAL_BOOTSTRAP_POSTFLIGHT_RECEIPT_BYTES,
)
from app.services.security_bootstrap_executor import BootstrapSessionFactory


class OperationalApplicationActivationReadinessFileError(ValueError):
    """Sanitized rejection of an unsafe local readiness input file."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _approved_digest(value: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise OperationalApplicationActivationReadinessError(
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
        raise TypeError(f"operational activation {label} path is invalid")
    try:
        initial = os.lstat(path)
    except (OSError, ValueError):
        raise OperationalApplicationActivationReadinessFileError(
            f"operational activation {label} could not be opened safely"
        ) from None
    if not stat.S_ISREG(initial.st_mode):
        raise OperationalApplicationActivationReadinessFileError(
            f"operational activation {label} must be a regular non-symlink file"
        )
    if initial.st_size == 0:
        raise OperationalApplicationActivationReadinessFileError(
            f"operational activation {label} is empty"
        )
    if initial.st_size > maximum_bytes:
        raise OperationalApplicationActivationReadinessFileError(
            f"operational activation {label} exceeds the byte limit"
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
            raise OperationalApplicationActivationReadinessFileError(
                f"operational activation {label} changed before it was opened"
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
    except OperationalApplicationActivationReadinessFileError:
        raise
    except (OSError, ValueError):
        raise OperationalApplicationActivationReadinessFileError(
            f"operational activation {label} could not be read safely"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise OperationalApplicationActivationReadinessFileError(
                    f"operational activation {label} could not be closed safely"
                ) from None

    if len(document) > maximum_bytes:
        raise OperationalApplicationActivationReadinessFileError(
            f"operational activation {label} exceeds the byte limit"
        )
    if not document:
        raise OperationalApplicationActivationReadinessFileError(
            f"operational activation {label} is empty"
        )
    if not _unchanged_file(initial, final):
        raise OperationalApplicationActivationReadinessFileError(
            f"operational activation {label} changed while it was read"
        )
    return document


def _operational_session_factory() -> BootstrapSessionFactory:
    from app.db.database import SessionLocal

    return SessionLocal


def verify_local_operational_application_activation_readiness(
    *,
    authentication_document_path: str | os.PathLike[str],
    postflight_receipt_path: str | os.PathLike[str],
    bootstrap_document_path: str | os.PathLike[str],
    approved_postflight_receipt_sha256: str,
    session_factory: BootstrapSessionFactory | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> OperationalApplicationActivationReadinessReceipt:
    """Verify exact local evidence against one fresh read-only public snapshot."""

    approved = _approved_digest(approved_postflight_receipt_sha256)
    if session_factory is not None and not callable(session_factory):
        raise TypeError("operational activation session factory must be callable")
    if not callable(clock):
        raise TypeError("operational activation readiness clock must be callable")

    postflight_document = _read_local_document(
        postflight_receipt_path,
        maximum_bytes=MAX_OPERATIONAL_BOOTSTRAP_POSTFLIGHT_RECEIPT_BYTES,
        label="postflight receipt",
    )
    actual = hashlib.sha256(postflight_document).hexdigest()
    if not hmac.compare_digest(actual, approved):
        raise OperationalApplicationActivationReadinessError(
            "operational bootstrap postflight receipt does not match approval"
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

    if session_factory is not None:
        factory = session_factory
    else:

        def factory():
            return _operational_session_factory()()

    return verify_operational_application_activation_readiness(
        authentication_document=authentication_document,
        postflight_receipt_document=postflight_document,
        bootstrap_document=bootstrap_document,
        approved_postflight_receipt_sha256=approved,
        session_factory=factory,
        clock=clock,
    )


def main(arguments: Sequence[str] | None = None) -> int:
    """Run one explicit readiness check or exit without disclosing inputs."""

    parser = argparse.ArgumentParser(
        description=(
            "Verify Engineer4Me secured-application activation readiness."
        )
    )
    parser.add_argument("authentication_document")
    parser.add_argument("postflight_receipt")
    parser.add_argument("bootstrap_document")
    parser.add_argument("--approve-postflight-receipt-sha256", required=True)
    options = parser.parse_args(arguments)
    try:
        receipt = verify_local_operational_application_activation_readiness(
            authentication_document_path=options.authentication_document,
            postflight_receipt_path=options.postflight_receipt,
            bootstrap_document_path=options.bootstrap_document,
            approved_postflight_receipt_sha256=(
                options.approve_postflight_receipt_sha256
            ),
            clock=_utc_now,
        )
        rendered = render_operational_application_activation_readiness(receipt)
    except Exception:
        parser.exit(2, "operational application activation readiness failed\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OperationalApplicationActivationReadinessFileError",
    "main",
    "verify_local_operational_application_activation_readiness",
]
