"""One controlled boundary from reviewed bootstrap commit to postflight."""

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from app.security.jwks_http_loader import OpenURL
from app.security.security_bootstrap_operational_execution import (
    OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION,
    OperationalSecurityBootstrapExecutionReceipt,
    execute_local_operational_security_bootstrap,
    render_operational_security_bootstrap_execution_receipt,
)
from app.security.security_bootstrap_operational_postflight import (
    OperationalSecurityBootstrapPostflightReceipt,
    render_operational_security_bootstrap_postflight_receipt,
    verify_operational_security_bootstrap_postflight,
)
from app.security.security_bootstrap_operational_preview import (
    read_operational_security_bootstrap_document,
)
from app.services.security_bootstrap_executor import BootstrapSessionFactory


class OperationalSecurityBootstrapCommitOutcomeUnknownError(RuntimeError):
    """Execution ended before a trusted commit receipt could be returned."""


class OperationalSecurityBootstrapPostCommitVerificationError(RuntimeError):
    """The commit receipt exists, but its read-only postflight did not finish."""

    def __init__(self, execution_receipt_document: bytes) -> None:
        if (
            type(execution_receipt_document) is not bytes
            or not execution_receipt_document
        ):
            raise ValueError("post-commit recovery receipt is invalid")
        super().__init__(
            "operational security bootstrap committed but postflight failed"
        )
        self.execution_receipt_document = execution_receipt_document


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _operational_session_factory() -> BootstrapSessionFactory:
    from app.db.database import SessionLocal

    return SessionLocal


def _execution_document(
    receipt: OperationalSecurityBootstrapExecutionReceipt,
) -> bytes:
    return (
        render_operational_security_bootstrap_execution_receipt(receipt) + "\n"
    ).encode("utf-8")


def complete_local_operational_security_bootstrap(
    *,
    authentication_document_path: str,
    token_path: str,
    bootstrap_document_path: str,
    preview_document_path: str,
    approved_configuration_sha256: str,
    approved_jwks_document_sha256: str,
    approved_bootstrap_document_sha256: str,
    approved_preview_document_sha256: str,
    execution_confirmation: str,
    write_session_factory: BootstrapSessionFactory | None = None,
    read_session_factory: BootstrapSessionFactory | None = None,
    open_url: OpenURL | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> OperationalSecurityBootstrapPostflightReceipt:
    """Commit once, then verify that exact commit through a fresh read session."""

    for factory, label in (
        (write_session_factory, "write"),
        (read_session_factory, "read"),
    ):
        if factory is not None and not callable(factory):
            raise TypeError(
                f"operational bootstrap {label} session factory must be callable"
            )
    if not callable(clock):
        raise TypeError("operational bootstrap completion clock must be callable")

    if write_session_factory is not None:
        write_factory = write_session_factory
    else:
        def write_factory():
            return _operational_session_factory()()

    if read_session_factory is not None:
        read_factory = read_session_factory
    else:
        def read_factory():
            return _operational_session_factory()()

    try:
        execution = execute_local_operational_security_bootstrap(
            authentication_document_path=authentication_document_path,
            token_path=token_path,
            bootstrap_document_path=bootstrap_document_path,
            preview_document_path=preview_document_path,
            approved_configuration_sha256=approved_configuration_sha256,
            approved_jwks_document_sha256=approved_jwks_document_sha256,
            approved_bootstrap_document_sha256=(
                approved_bootstrap_document_sha256
            ),
            approved_preview_document_sha256=approved_preview_document_sha256,
            execution_confirmation=execution_confirmation,
            session_factory=write_factory,
            open_url=open_url,
            clock=clock,
        )
    except Exception:
        raise OperationalSecurityBootstrapCommitOutcomeUnknownError(
            "operational security bootstrap ended before commit confirmation"
        ) from None

    execution_document = _execution_document(execution)
    try:
        receipt_digest = hashlib.sha256(execution_document).hexdigest()
        bootstrap_document = read_operational_security_bootstrap_document(
            bootstrap_document_path
        )
        return verify_operational_security_bootstrap_postflight(
            execution_receipt_document=execution_document,
            bootstrap_document=bootstrap_document,
            approved_execution_receipt_sha256=receipt_digest,
            session_factory=read_factory,
            clock=clock,
        )
    except Exception:
        raise OperationalSecurityBootstrapPostCommitVerificationError(
            execution_document
        ) from None


def main(arguments: Sequence[str] | None = None) -> int:
    """Complete one bootstrap or exit with explicit retry-safe state guidance."""

    parser = argparse.ArgumentParser(
        description="Commit and verify one reviewed Engineer4Me bootstrap."
    )
    parser.add_argument("authentication_document")
    parser.add_argument("token")
    parser.add_argument("bootstrap_document")
    parser.add_argument("preview_document")
    parser.add_argument("--approve-configuration-sha256", required=True)
    parser.add_argument("--approve-jwks-sha256", required=True)
    parser.add_argument("--approve-bootstrap-sha256", required=True)
    parser.add_argument("--approve-preview-sha256", required=True)
    parser.add_argument(
        "--confirm-provider-ownership-and-bootstrap",
        required=True,
    )
    options = parser.parse_args(arguments)
    try:
        receipt = complete_local_operational_security_bootstrap(
            authentication_document_path=options.authentication_document,
            token_path=options.token,
            bootstrap_document_path=options.bootstrap_document,
            preview_document_path=options.preview_document,
            approved_configuration_sha256=options.approve_configuration_sha256,
            approved_jwks_document_sha256=options.approve_jwks_sha256,
            approved_bootstrap_document_sha256=options.approve_bootstrap_sha256,
            approved_preview_document_sha256=options.approve_preview_sha256,
            execution_confirmation=(
                options.confirm_provider_ownership_and_bootstrap
            ),
            clock=_utc_now,
        )
        rendered = render_operational_security_bootstrap_postflight_receipt(
            receipt
        )
    except OperationalSecurityBootstrapPostCommitVerificationError as exc:
        print(exc.execution_receipt_document.decode("utf-8"), end="")
        parser.exit(
            3,
            "operational security bootstrap commit was confirmed but postflight "
            "failed; do not retry bootstrap; run read-only postflight recovery\n",
        )
    except Exception:
        parser.exit(
            2,
            "operational security bootstrap completion failed before a commit "
            "receipt was returned; do not retry automatically; inspect the "
            "operational security state\n",
        )
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OPERATIONAL_BOOTSTRAP_EXECUTION_CONFIRMATION",
    "OperationalSecurityBootstrapCommitOutcomeUnknownError",
    "OperationalSecurityBootstrapPostCommitVerificationError",
    "complete_local_operational_security_bootstrap",
    "main",
]
