"""Explicit local-file reader and privacy-safe bootstrap preview renderer."""

from __future__ import annotations

import argparse
import json
import os
import stat
from collections.abc import Sequence

from app.security.bootstrap_document import MAX_BOOTSTRAP_DOCUMENT_BYTES, SecurityBootstrapPreview, load_security_bootstrap_document


class SecurityBootstrapPreviewFileError(ValueError):
    """Sanitized rejection of an unsafe or unavailable preview input file."""


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
    )


def read_security_bootstrap_preview(
    path: str | os.PathLike[str],
) -> SecurityBootstrapPreview:
    """Read one explicit regular file without following its final symlink."""

    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("security bootstrap preview path must be path-like")
    try:
        initial = os.lstat(path)
    except (OSError, ValueError):
        raise SecurityBootstrapPreviewFileError(
            "security bootstrap preview file could not be opened safely"
        ) from None
    if stat.S_ISLNK(initial.st_mode):
        raise SecurityBootstrapPreviewFileError(
            "security bootstrap preview file could not be opened safely"
        )
    if not stat.S_ISREG(initial.st_mode):
        raise SecurityBootstrapPreviewFileError(
            "security bootstrap preview input must be a regular file"
        )
    if initial.st_size == 0:
        raise SecurityBootstrapPreviewFileError(
            "security bootstrap preview file is empty"
        )
    if initial.st_size > MAX_BOOTSTRAP_DOCUMENT_BYTES:
        raise SecurityBootstrapPreviewFileError(
            "security bootstrap preview file exceeds the byte limit"
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
            raise SecurityBootstrapPreviewFileError(
                "security bootstrap preview file changed before it was opened"
            )
        chunks: list[bytes] = []
        remaining = MAX_BOOTSTRAP_DOCUMENT_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(8_192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        document = b"".join(chunks)
    except SecurityBootstrapPreviewFileError:
        raise
    except (OSError, ValueError):
        raise SecurityBootstrapPreviewFileError(
            "security bootstrap preview file could not be read safely"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise SecurityBootstrapPreviewFileError(
                    "security bootstrap preview file could not be closed safely"
                ) from None

    if len(document) > MAX_BOOTSTRAP_DOCUMENT_BYTES:
        raise SecurityBootstrapPreviewFileError(
            "security bootstrap preview file exceeds the byte limit"
        )
    if not document:
        raise SecurityBootstrapPreviewFileError(
            "security bootstrap preview file is empty"
        )
    return load_security_bootstrap_document(document).preview


def render_security_bootstrap_preview(preview: SecurityBootstrapPreview) -> str:
    """Render only approved non-secret review fields in canonical JSON."""

    if not isinstance(preview, SecurityBootstrapPreview):
        raise TypeError("security bootstrap preview is required")
    output = {
        "bootstrap_id": str(preview.bootstrap_id),
        "document_sha256": preview.document_sha256,
        "entitlement_plan": preview.entitlement_plan,
        "entitlement_snapshot_id": str(preview.entitlement_snapshot_id),
        "features": [item.value for item in preview.features],
        "initial_role": preview.initial_role.value,
        "membership_id": str(preview.membership_id),
        "organisation_id": str(preview.organisation_id),
        "quota_kinds": [item.value for item in preview.quota_kinds],
        "request_id": str(preview.request_id),
        "subscription_status": preview.subscription_status.value,
        "user_id": str(preview.user_id),
    }
    return json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render a read-only, privacy-safe Engineer4Me security bootstrap preview.")
    parser.add_argument("document", help="explicit local path to the reviewed bootstrap JSON document")
    options = parser.parse_args(arguments)
    print(render_security_bootstrap_preview(read_security_bootstrap_preview(options.document)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
