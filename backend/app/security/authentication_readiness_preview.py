"""Explicit local-file boundary for offline authentication-readiness preview."""

from __future__ import annotations

import argparse
import os
import stat
from collections.abc import Sequence

from app.security.authentication_readiness_document import (
    MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES,
    AuthenticationReadinessDocumentError,
    AuthenticationReadinessPreview,
    load_authentication_readiness_document,
    render_authentication_readiness_preview,
)


class AuthenticationReadinessPreviewFileError(ValueError):
    """Sanitized rejection of an unsafe or unavailable local input file."""


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


def _validated_initial_metadata(
    path: str | os.PathLike[str],
) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except (OSError, ValueError):
        raise AuthenticationReadinessPreviewFileError(
            "authentication readiness preview file could not be opened safely"
        ) from None
    if not stat.S_ISREG(metadata.st_mode):
        raise AuthenticationReadinessPreviewFileError(
            "authentication readiness preview input must be a regular non-symlink file"
        )
    if metadata.st_size == 0:
        raise AuthenticationReadinessPreviewFileError(
            "authentication readiness preview file is empty"
        )
    if metadata.st_size > MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES:
        raise AuthenticationReadinessPreviewFileError(
            "authentication readiness preview file exceeds the byte limit"
        )
    return metadata


def _open_regular_file(
    path: str | os.PathLike[str],
    expected: os.stat_result,
) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
    except (OSError, ValueError):
        if "descriptor" in locals():
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise AuthenticationReadinessPreviewFileError(
            "authentication readiness preview file could not be opened safely"
        ) from None
    if not stat.S_ISREG(opened.st_mode) or not _same_file(expected, opened):
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise AuthenticationReadinessPreviewFileError(
            "authentication readiness preview file changed before it was opened"
        )
    return descriptor


def _read_bounded_document(
    descriptor: int,
    expected: os.stat_result,
) -> bytes:
    try:
        chunks: list[bytes] = []
        remaining = MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(8_192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        document = b"".join(chunks)
        final = os.fstat(descriptor)
    except OSError:
        raise AuthenticationReadinessPreviewFileError(
            "authentication readiness preview file could not be read safely"
        ) from None
    if len(document) > MAX_AUTHENTICATION_READINESS_DOCUMENT_BYTES:
        raise AuthenticationReadinessPreviewFileError(
            "authentication readiness preview file exceeds the byte limit"
        )
    if not document:
        raise AuthenticationReadinessPreviewFileError(
            "authentication readiness preview file is empty"
        )
    if not _unchanged_file(expected, final):
        raise AuthenticationReadinessPreviewFileError(
            "authentication readiness preview file changed while it was read"
        )
    return document


def read_authentication_readiness_preview(
    path: str | os.PathLike[str],
) -> AuthenticationReadinessPreview:
    """Read and validate one explicit local regular file without global inputs."""

    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("authentication readiness preview path must be path-like")
    initial = _validated_initial_metadata(path)
    descriptor = _open_regular_file(path, initial)
    try:
        document = _read_bounded_document(descriptor, initial)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            raise AuthenticationReadinessPreviewFileError(
                "authentication readiness preview file could not be closed safely"
            ) from None
    return load_authentication_readiness_document(document).preview


def main(arguments: Sequence[str] | None = None) -> int:
    """Render one canonical local-only preview or exit with a sanitized error."""

    parser = argparse.ArgumentParser(
        description=("Render an offline Engineer4Me authentication-readiness preview.")
    )
    parser.add_argument(
        "document",
        help="explicit local path to the reviewed public-metadata JSON document",
    )
    options = parser.parse_args(arguments)
    try:
        preview = read_authentication_readiness_preview(options.document)
        rendered = render_authentication_readiness_preview(preview)
    except (
        AuthenticationReadinessDocumentError,
        AuthenticationReadinessPreviewFileError,
    ):
        parser.exit(2, "authentication readiness preview failed\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AuthenticationReadinessPreviewFileError",
    "main",
    "read_authentication_readiness_preview",
]
