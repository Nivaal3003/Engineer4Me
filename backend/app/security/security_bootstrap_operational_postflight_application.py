"""Controlled local entry point for operational bootstrap postflight."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import stat
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.security_bootstrap_operational_postflight import (
    MAX_OPERATIONAL_BOOTSTRAP_EXECUTION_RECEIPT_BYTES,
    OperationalSecurityBootstrapPostflightDocumentError,
    OperationalSecurityBootstrapPostflightReceipt,
    render_operational_security_bootstrap_postflight_receipt,
    verify_operational_security_bootstrap_postflight,
)
from app.security.security_bootstrap_operational_preview import (
    read_operational_security_bootstrap_document,
)
from app.services.security_bootstrap_executor import BootstrapSessionFactory


class OperationalSecurityBootstrapPostflightFileError(ValueError):
    """Sanitized rejection of an unsafe local execution receipt file."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


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


def read_operational_security_bootstrap_execution_receipt(
    path: str | os.PathLike[str],
) -> bytes:
    """Read one stable regular non-symlink receipt through an exact bound."""

    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("operational bootstrap execution receipt path is invalid")
    try:
        initial = os.lstat(path)
    except (OSError, ValueError):
        raise OperationalSecurityBootstrapPostflightFileError(
            "operational bootstrap execution receipt could not be opened safely"
        ) from None
    if not stat.S_ISREG(initial.st_mode):
        raise OperationalSecurityBootstrapPostflightFileError(
            "operational bootstrap execution receipt must be a regular "
            "non-symlink file"
        )
    if initial.st_size == 0:
        raise OperationalSecurityBootstrapPostflightFileError(
            "operational bootstrap execution receipt is empty"
        )
    if initial.st_size > MAX_OPERATIONAL_BOOTSTRAP_EXECUTION_RECEIPT_BYTES:
        raise OperationalSecurityBootstrapPostflightFileError(
            "operational bootstrap execution receipt exceeds the byte limit"
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
            raise OperationalSecurityBootstrapPostflightFileError(
                "operational bootstrap execution receipt changed before it "
                "was opened"
            )
        chunks: list[bytes] = []
        remaining = MAX_OPERATIONAL_BOOTSTRAP_EXECUTION_RECEIPT_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(8_192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        document = b"".join(chunks)
        final = os.fstat(descriptor)
    except OperationalSecurityBootstrapPostflightFileError:
        raise
    except (OSError, ValueError):
        raise OperationalSecurityBootstrapPostflightFileError(
            "operational bootstrap execution receipt could not be read safely"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise OperationalSecurityBootstrapPostflightFileError(
                    "operational bootstrap execution receipt could not be "
                    "closed safely"
                ) from None
    if len(document) > MAX_OPERATIONAL_BOOTSTRAP_EXECUTION_RECEIPT_BYTES:
        raise OperationalSecurityBootstrapPostflightFileError(
            "operational bootstrap execution receipt exceeds the byte limit"
        )
    if not document:
        raise OperationalSecurityBootstrapPostflightFileError(
            "operational bootstrap execution receipt is empty"
        )
    if not _unchanged_file(initial, final):
        raise OperationalSecurityBootstrapPostflightFileError(
            "operational bootstrap execution receipt changed while it was read"
        )
    return document


def _approved_digest(value: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "approved execution receipt digest is invalid"
        )
    return value


def _operational_session_factory() -> BootstrapSessionFactory:
    from app.db.database import SessionLocal

    return SessionLocal


def verify_local_operational_security_bootstrap_postflight(
    *,
    execution_receipt_path: str | os.PathLike[str],
    bootstrap_document_path: str | os.PathLike[str],
    approved_execution_receipt_sha256: str,
    session_factory: BootstrapSessionFactory | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> OperationalSecurityBootstrapPostflightReceipt:
    """Verify one exact local receipt against one read-only public snapshot."""

    approved = _approved_digest(approved_execution_receipt_sha256)
    if session_factory is not None and not callable(session_factory):
        raise TypeError(
            "operational bootstrap postflight session factory must be callable"
        )
    if not callable(clock):
        raise TypeError("operational bootstrap postflight clock must be callable")
    receipt_document = read_operational_security_bootstrap_execution_receipt(
        execution_receipt_path
    )
    actual = hashlib.sha256(receipt_document).hexdigest()
    if not hmac.compare_digest(actual, approved):
        raise OperationalSecurityBootstrapPostflightDocumentError(
            "operational bootstrap execution receipt does not match approval"
        )
    bootstrap_document = read_operational_security_bootstrap_document(
        bootstrap_document_path
    )
    if session_factory is not None:
        factory = session_factory
    else:
        def factory():
            return _operational_session_factory()()

    return verify_operational_security_bootstrap_postflight(
        execution_receipt_document=receipt_document,
        bootstrap_document=bootstrap_document,
        approved_execution_receipt_sha256=approved,
        session_factory=factory,
        clock=clock,
    )


def main(arguments: Sequence[str] | None = None) -> int:
    """Run one explicit postflight or exit without disclosing local inputs."""

    parser = argparse.ArgumentParser(
        description="Verify one committed Engineer4Me security bootstrap."
    )
    parser.add_argument("execution_receipt")
    parser.add_argument("bootstrap_document")
    parser.add_argument("--approve-execution-receipt-sha256", required=True)
    options = parser.parse_args(arguments)
    try:
        receipt = verify_local_operational_security_bootstrap_postflight(
            execution_receipt_path=options.execution_receipt,
            bootstrap_document_path=options.bootstrap_document,
            approved_execution_receipt_sha256=(
                options.approve_execution_receipt_sha256
            ),
            clock=_utc_now,
        )
        rendered = render_operational_security_bootstrap_postflight_receipt(
            receipt
        )
    except Exception:
        parser.exit(2, "operational security bootstrap postflight failed\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OperationalSecurityBootstrapPostflightFileError",
    "main",
    "read_operational_security_bootstrap_execution_receipt",
    "verify_local_operational_security_bootstrap_postflight",
]
