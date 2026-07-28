"""Tests for the guarded filesystem document-content loader."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.ingestion.filesystem_document_content_loader import (
    DocumentContentNotFoundError,
    DocumentContentPathError,
    DocumentContentReadError,
    DocumentContentTooLargeError,
    FilesystemDocumentContentLoader,
    FilesystemDocumentContentLoaderConfig,
    FilesystemDocumentContentLoaderError,
)
from app.ingestion.ingestion_job_models import (
    IngestionDocumentResult,
    IngestionJob,
    IngestionJobType,
    IngestionSourceType,
)


DEFAULT_CONTENT = b"Rosemount pressure transmitter manual.\n"


def build_job(
    source_path: str | None = "uploads/manual.txt",
) -> tuple[IngestionJob, IngestionDocumentResult]:
    """Build one valid pending job and return its document."""

    document = IngestionDocumentResult(
        source_name="manual.txt",
        source_path=source_path,
        media_type="text/plain",
    )
    job = IngestionJob(
        job_type=IngestionJobType.SINGLE_DOCUMENT,
        source_type=IngestionSourceType.API_UPLOAD,
        submitted_by="filesystem-loader-test",
        documents=[document],
        total_document_count=1,
        metadata={"test_suite": "filesystem_content_loader"},
    )

    return job, job.documents[0]


def build_loader(
    root_directory: Path,
    *,
    maximum_content_bytes: int = 1024,
) -> FilesystemDocumentContentLoader:
    """Build a loader rooted beneath the pytest temporary directory."""

    return FilesystemDocumentContentLoader(
        FilesystemDocumentContentLoaderConfig(
            root_directory=root_directory,
            maximum_content_bytes=maximum_content_bytes,
        )
    )


class FakeSourcePath:
    """Provide deterministic stat and read behaviour to exercise race guards."""

    def __init__(
        self,
        *,
        declared_size: int = 0,
        content: bytes = b"",
        stat_error: OSError | None = None,
        open_error: OSError | None = None,
    ) -> None:
        self.declared_size = declared_size
        self.content = content
        self.stat_error = stat_error
        self.open_error = open_error

    def stat(self) -> SimpleNamespace:
        """Return a minimal stat result or raise the configured error."""

        if self.stat_error is not None:
            raise self.stat_error

        return SimpleNamespace(st_size=self.declared_size)

    def open(self, mode: str) -> BytesIO:
        """Return in-memory bytes or raise the configured error."""

        assert mode == "rb"

        if self.open_error is not None:
            raise self.open_error

        return BytesIO(self.content)


def use_fake_source(
    monkeypatch: pytest.MonkeyPatch,
    loader: FilesystemDocumentContentLoader,
    source: FakeSourcePath,
) -> None:
    """Replace path resolution with one deterministic fake source."""

    monkeypatch.setattr(
        loader,
        "resolve_source_path",
        lambda _job, _document: source,
    )


def test_config_canonicalises_root_and_is_frozen(
    tmp_path: Path,
) -> None:
    """The configuration stores one canonical immutable root."""

    root = tmp_path / "storage"
    root.mkdir()
    config = FilesystemDocumentContentLoaderConfig(
        root_directory=root / ".." / "storage",
    )

    assert config.root_directory == root.resolve()
    assert config.maximum_content_bytes == 100 * 1024 * 1024

    with pytest.raises(FrozenInstanceError):
        config.root_directory = tmp_path  # type: ignore[misc]


@pytest.mark.parametrize(
    "maximum_content_bytes",
    [0, -1, True, False, 1.5, "100", None],
)
def test_config_rejects_invalid_maximum_content_bytes(
    tmp_path: Path,
    maximum_content_bytes: Any,
) -> None:
    """The in-memory limit must be a positive non-boolean integer."""

    with pytest.raises(
        ValueError,
        match="maximum_content_bytes must be a positive integer",
    ):
        FilesystemDocumentContentLoaderConfig(
            root_directory=tmp_path,
            maximum_content_bytes=maximum_content_bytes,
        )


def test_config_rejects_blank_root() -> None:
    """A whitespace-only root cannot become a process-relative path."""

    with pytest.raises(
        ValueError,
        match="root_directory cannot be blank",
    ):
        FilesystemDocumentContentLoaderConfig(
            root_directory=Path("   "),
        )


def test_config_rejects_missing_root(tmp_path: Path) -> None:
    """The storage root must exist when runtime wiring is constructed."""

    with pytest.raises(ValueError, match="does not exist"):
        FilesystemDocumentContentLoaderConfig(
            root_directory=tmp_path / "missing",
        )


def test_config_rejects_file_root(tmp_path: Path) -> None:
    """A regular file cannot be used as the storage root."""

    file_root = tmp_path / "not-a-directory"
    file_root.write_bytes(b"content")

    with pytest.raises(ValueError, match="not a directory"):
        FilesystemDocumentContentLoaderConfig(
            root_directory=file_root,
        )


def test_loader_requires_valid_config() -> None:
    """Runtime construction rejects an unvalidated configuration object."""

    with pytest.raises(
        TypeError,
        match="FilesystemDocumentContentLoaderConfig",
    ):
        FilesystemDocumentContentLoader(object())  # type: ignore[arg-type]


def test_loader_reads_nested_relative_file(tmp_path: Path) -> None:
    """A normal relative storage key resolves and returns exact bytes."""

    source = tmp_path / "uploads" / "manual.txt"
    source.parent.mkdir()
    source.write_bytes(DEFAULT_CONTENT)
    loader = build_loader(tmp_path)
    job, document = build_job()

    assert loader.config.root_directory == tmp_path.resolve()
    assert loader.root_directory == tmp_path.resolve()
    assert loader.resolve_source_path(job, document) == source.resolve()
    assert loader.load(job, document) == DEFAULT_CONTENT


@pytest.mark.parametrize(
    "source_reference",
    [
        r"uploads\manual.txt",
        "  uploads/manual.txt  ",
    ],
)
def test_loader_normalises_supported_relative_references(
    tmp_path: Path,
    source_reference: str,
) -> None:
    """Windows separators and harmless outer whitespace are normalised."""

    source = tmp_path / "uploads" / "manual.txt"
    source.parent.mkdir()
    source.write_bytes(DEFAULT_CONTENT)
    loader = build_loader(tmp_path)
    job, document = build_job(source_reference)

    assert loader.load(job, document) == DEFAULT_CONTENT


@pytest.mark.parametrize("source_reference", [None, "", "   "])
def test_loader_rejects_missing_source_path(
    tmp_path: Path,
    source_reference: str | None,
) -> None:
    """Every runtime document must identify a persisted source."""

    loader = build_loader(tmp_path)
    job, document = build_job(source_reference)

    with pytest.raises(
        DocumentContentPathError,
        match="source_path is required",
    ):
        loader.load(job, document)


@pytest.mark.parametrize(
    "source_reference",
    [
        "/var/lib/engineer4me/manual.txt",
        r"C:\uploads\manual.txt",
        r"C:uploads\manual.txt",
        r"\\server\share\manual.txt",
    ],
)
def test_loader_rejects_absolute_and_drive_paths(
    tmp_path: Path,
    source_reference: str,
) -> None:
    """POSIX, Windows, drive-relative, and UNC paths are all refused."""

    loader = build_loader(tmp_path)
    job, document = build_job(source_reference)

    with pytest.raises(
        DocumentContentPathError,
        match="source_path must be relative",
    ):
        loader.load(job, document)


@pytest.mark.parametrize(
    "source_reference",
    [
        "../manual.txt",
        "uploads/../manual.txt",
        "./uploads/manual.txt",
        "uploads//manual.txt",
        "uploads/",
        r"uploads\..\manual.txt",
    ],
)
def test_loader_rejects_unsafe_path_segments(
    tmp_path: Path,
    source_reference: str,
) -> None:
    """Traversal, dot, and empty path components cannot reach the filesystem."""

    loader = build_loader(tmp_path)
    job, document = build_job(source_reference)

    with pytest.raises(
        DocumentContentPathError,
        match="unsafe path segment",
    ):
        loader.load(job, document)


def test_loader_rejects_control_characters(tmp_path: Path) -> None:
    """Control characters are rejected before a path object is resolved."""

    loader = build_loader(tmp_path)
    job, document = build_job("uploads/\x00manual.txt")

    with pytest.raises(
        DocumentContentPathError,
        match="control characters",
    ):
        loader.load(job, document)


def test_loader_reports_missing_file_without_exposing_path(
    tmp_path: Path,
) -> None:
    """Missing-source diagnostics use stable IDs instead of storage paths."""

    loader = build_loader(tmp_path)
    job, document = build_job("private/customer-a/manual.txt")

    with pytest.raises(DocumentContentNotFoundError) as captured:
        loader.load(job, document)

    message = str(captured.value)

    assert str(job.job_id) in message
    assert str(document.document_id) in message
    assert "private/customer-a/manual.txt" not in message


def test_loader_rejects_directory_source(tmp_path: Path) -> None:
    """An existing directory is not accepted as document content."""

    source_directory = tmp_path / "uploads" / "manual.txt"
    source_directory.mkdir(parents=True)
    loader = build_loader(tmp_path)
    job, document = build_job()

    with pytest.raises(
        DocumentContentNotFoundError,
        match="not a regular file",
    ):
        loader.load(job, document)


def test_loader_rejects_symlink_escape(tmp_path: Path) -> None:
    """A symlink cannot redirect a relative key outside the configured root."""

    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"secret")

    try:
        (root / "escape").symlink_to(
            outside,
            target_is_directory=True,
        )
    except (NotImplementedError, OSError):
        pytest.skip("Symbolic links are unavailable on this platform.")

    loader = build_loader(root)
    job, document = build_job("escape/secret.txt")

    with pytest.raises(
        DocumentContentPathError,
        match="escapes the configured content root",
    ):
        loader.load(job, document)


def test_loader_allows_symlink_confined_to_root(tmp_path: Path) -> None:
    """A symlink whose canonical target remains under the root is safe."""

    source_directory = tmp_path / "uploads"
    source_directory.mkdir()
    (source_directory / "manual.txt").write_bytes(DEFAULT_CONTENT)

    try:
        (tmp_path / "alias").symlink_to(
            source_directory,
            target_is_directory=True,
        )
    except (NotImplementedError, OSError):
        pytest.skip("Symbolic links are unavailable on this platform.")

    loader = build_loader(tmp_path)
    job, document = build_job("alias/manual.txt")

    assert loader.load(job, document) == DEFAULT_CONTENT


def test_loader_accepts_content_at_exact_limit(tmp_path: Path) -> None:
    """Content whose size equals the configured limit remains valid."""

    source = tmp_path / "manual.bin"
    source.write_bytes(b"1234")
    loader = build_loader(
        tmp_path,
        maximum_content_bytes=4,
    )
    job, document = build_job("manual.bin")

    assert loader.load(job, document) == b"1234"


def test_loader_rejects_declared_content_above_limit(
    tmp_path: Path,
) -> None:
    """Oversized content is rejected from metadata before allocation."""

    source = tmp_path / "manual.bin"
    source.write_bytes(b"12345")
    loader = build_loader(
        tmp_path,
        maximum_content_bytes=4,
    )
    job, document = build_job("manual.bin")

    with pytest.raises(
        DocumentContentTooLargeError,
        match="contains 5 bytes; the limit is 4 bytes",
    ):
        loader.load(job, document)


def test_loader_normalises_stat_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Filesystem inspection failures become adapter-specific read errors."""

    loader = build_loader(tmp_path)
    job, document = build_job()
    source = FakeSourcePath(
        stat_error=OSError("stat failed"),
    )
    use_fake_source(monkeypatch, loader, source)

    with pytest.raises(
        DocumentContentReadError,
        match="Unable to inspect source",
    ) as captured:
        loader.load(job, document)

    assert isinstance(
        captured.value,
        FilesystemDocumentContentLoaderError,
    )
    assert isinstance(captured.value.__cause__, OSError)


def test_loader_normalises_open_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Filesystem open/read failures become adapter-specific read errors."""

    loader = build_loader(tmp_path)
    job, document = build_job()
    source = FakeSourcePath(
        declared_size=4,
        open_error=OSError("open failed"),
    )
    use_fake_source(monkeypatch, loader, source)

    with pytest.raises(
        DocumentContentReadError,
        match="Unable to read source",
    ) as captured:
        loader.load(job, document)

    assert isinstance(captured.value.__cause__, OSError)


def test_loader_detects_source_size_change_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A file that shrinks after stat cannot be processed inconsistently."""

    loader = build_loader(tmp_path)
    job, document = build_job()
    source = FakeSourcePath(
        declared_size=4,
        content=b"123",
    )
    use_fake_source(monkeypatch, loader, source)

    with pytest.raises(
        DocumentContentReadError,
        match="changed while it was being read",
    ):
        loader.load(job, document)


def test_loader_detects_growth_beyond_limit_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A file that grows after stat cannot bypass the configured limit."""

    loader = build_loader(
        tmp_path,
        maximum_content_bytes=4,
    )
    job, document = build_job()
    source = FakeSourcePath(
        declared_size=4,
        content=b"12345",
    )
    use_fake_source(monkeypatch, loader, source)

    with pytest.raises(
        DocumentContentTooLargeError,
        match="exceeded the 4-byte limit",
    ):
        loader.load(job, document)
