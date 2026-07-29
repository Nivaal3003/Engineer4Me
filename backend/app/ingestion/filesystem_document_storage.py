"""Guarded filesystem storage for uploaded ingestion documents.

The public ingestion API must never treat a caller-provided path as a storage
location. This module supplies a transport-neutral storage boundary that:

- accepts bytes or a bounded binary stream;
- normalises untrusted display filenames without using them as paths;
- permits only document suffixes supported by the parser chain;
- generates opaque server-owned relative storage keys;
- creates files with exclusive semantics so existing content is never
  overwritten;
- calculates authoritative size and SHA-256 metadata while writing;
- supports checksum-guarded rollback of files whose job submission fails; and
- confines every operation beneath one canonical storage root.

The returned ``StoredDocument`` metadata maps directly onto
``IngestionDocumentResult`` without coupling this storage adapter to FastAPI.
"""

from __future__ import annotations

import os
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Final
from uuid import UUID, uuid4


_DEFAULT_MAXIMUM_CONTENT_BYTES: Final[int] = 25 * 1024 * 1024
_DEFAULT_READ_CHUNK_BYTES: Final[int] = 64 * 1024
_DEFAULT_MAXIMUM_FILENAME_CHARACTERS: Final[int] = 512
_DEFAULT_MAXIMUM_MEDIA_TYPE_CHARACTERS: Final[int] = 255
_PRIVATE_DIRECTORY_MODE: Final[int] = 0o700
_PRIVATE_FILE_MODE: Final[int] = 0o600

_DEFAULT_ALLOWED_SUFFIXES: Final[frozenset[str]] = frozenset(
    {
        ".txt",
        ".md",
        ".markdown",
        ".mdown",
        ".mkd",
        ".csv",
        ".tsv",
        ".tab",
        ".json",
        ".html",
        ".htm",
        ".xml",
        ".pdf",
        ".docx",
        ".xlsx",
        ".xls",
        ".jpg",
        ".jpeg",
        ".png",
        ".tif",
        ".tiff",
        ".bmp",
        ".webp",
    }
)

_SAFE_SUFFIX_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^\.[a-z0-9]+$"
)
_STORAGE_REFERENCE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?P<first_shard>[0-9a-f]{2})/"
    r"(?P<second_shard>[0-9a-f]{2})/"
    r"(?P<identifier>[0-9a-f]{32})"
    r"(?P<suffix>\.[a-z0-9]+)$"
)


def _has_canonical_storage_shards(match: re.Match[str]) -> bool:
    """Return whether a storage reference uses its identifier's shards."""

    identifier = match.group("identifier")

    return (
        match.group("first_shard") == identifier[:2]
        and match.group("second_shard") == identifier[2:4]
    )


class FilesystemDocumentStorageError(Exception):
    """Base exception for guarded document-storage failures."""


class DocumentStorageFilenameError(FilesystemDocumentStorageError):
    """Raised when an upload filename is empty, unsafe, or unsupported."""


class DocumentStorageContentError(FilesystemDocumentStorageError):
    """Raised when upload content does not provide valid binary data."""


class DocumentStorageEmptyError(DocumentStorageContentError):
    """Raised when an uploaded document contains no bytes."""


class DocumentStorageTooLargeError(DocumentStorageContentError):
    """Raised when uploaded content exceeds the configured byte limit."""


class DocumentStorageReadError(DocumentStorageContentError):
    """Raised when a source stream cannot be read consistently."""


class DocumentStorageConflictError(FilesystemDocumentStorageError):
    """Raised when a generated storage destination already exists."""


class DocumentStoragePathError(FilesystemDocumentStorageError):
    """Raised when a stored reference is malformed or escapes its root."""


class DocumentStorageWriteError(FilesystemDocumentStorageError):
    """Raised when uploaded bytes cannot be persisted consistently."""


class DocumentStorageDeleteError(FilesystemDocumentStorageError):
    """Raised when guarded rollback cannot safely remove stored content."""


@dataclass(frozen=True, slots=True)
class FilesystemDocumentStorageConfig:
    """Immutable controls for server-owned filesystem upload storage."""

    root_directory: Path
    maximum_content_bytes: int = _DEFAULT_MAXIMUM_CONTENT_BYTES
    read_chunk_bytes: int = _DEFAULT_READ_CHUNK_BYTES
    maximum_filename_characters: int = (
        _DEFAULT_MAXIMUM_FILENAME_CHARACTERS
    )
    maximum_media_type_characters: int = (
        _DEFAULT_MAXIMUM_MEDIA_TYPE_CHARACTERS
    )
    allowed_suffixes: frozenset[str] = field(
        default_factory=lambda: _DEFAULT_ALLOWED_SUFFIXES,
    )
    synchronise_writes: bool = True

    def __post_init__(self) -> None:
        """Validate limits and canonicalise the dedicated storage root."""

        if not isinstance(self.root_directory, (str, os.PathLike)):
            raise TypeError(
                "root_directory must be a filesystem path."
            )

        raw_root = str(self.root_directory).strip()

        if not raw_root:
            raise ValueError("root_directory cannot be blank.")

        try:
            resolved_root = Path(raw_root).expanduser().resolve(
                strict=True
            )
        except FileNotFoundError as error:
            raise ValueError(
                f"Filesystem storage root does not exist: {raw_root}"
            ) from error
        except OSError as error:
            raise ValueError(
                f"Filesystem storage root cannot be resolved: {raw_root}"
            ) from error

        if not resolved_root.is_dir():
            raise ValueError(
                f"Filesystem storage root is not a directory: {raw_root}"
            )

        for field_name in (
            "maximum_content_bytes",
            "read_chunk_bytes",
            "maximum_filename_characters",
            "maximum_media_type_characters",
        ):
            value = getattr(self, field_name)

            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
            ):
                raise ValueError(
                    f"{field_name} must be a positive integer."
                )

        if not isinstance(self.synchronise_writes, bool):
            raise TypeError("synchronise_writes must be a boolean.")

        raw_suffixes = self.allowed_suffixes

        if (
            isinstance(raw_suffixes, (str, bytes))
            or not isinstance(raw_suffixes, (set, frozenset))
            or not raw_suffixes
        ):
            raise ValueError(
                "allowed_suffixes must be a non-empty set of suffixes."
            )

        normalised_suffixes: set[str] = set()

        for suffix in raw_suffixes:
            if not isinstance(suffix, str):
                raise TypeError(
                    "allowed_suffixes must contain only strings."
                )

            normalised = suffix.strip().lower()

            if not _SAFE_SUFFIX_PATTERN.fullmatch(normalised):
                raise ValueError(
                    f"Unsupported configured document suffix: {suffix!r}."
                )

            normalised_suffixes.add(normalised)

        object.__setattr__(self, "root_directory", resolved_root)
        object.__setattr__(
            self,
            "allowed_suffixes",
            frozenset(normalised_suffixes),
        )


@dataclass(frozen=True, slots=True)
class StoredDocument:
    """Authoritative metadata for one successfully persisted upload."""

    storage_id: UUID
    source_name: str
    source_path: str
    media_type: str | None
    file_size_bytes: int
    checksum_sha256: str
    stored_at: datetime

    def __post_init__(self) -> None:
        """Reject malformed metadata even when instantiated directly."""

        if not isinstance(self.storage_id, UUID):
            raise TypeError("storage_id must be a UUID.")

        if not isinstance(self.source_name, str):
            raise TypeError("source_name must be a string.")

        if not self.source_name.strip():
            raise ValueError("source_name cannot be blank.")

        if not isinstance(self.source_path, str):
            raise TypeError("source_path must be a string.")

        match = _STORAGE_REFERENCE_PATTERN.fullmatch(self.source_path)

        if match is None or not _has_canonical_storage_shards(match):
            raise ValueError(
                "source_path must be an opaque server-owned reference."
            )

        if match.group("identifier") != self.storage_id.hex:
            raise ValueError(
                "source_path must contain the declared storage_id."
            )

        if Path(self.source_name).suffix.lower() != match.group("suffix"):
            raise ValueError(
                "source_name and source_path suffixes must match."
            )

        if (
            self.media_type is not None
            and not isinstance(self.media_type, str)
        ):
            raise TypeError("media_type must be a string when provided.")

        if (
            isinstance(self.file_size_bytes, bool)
            or not isinstance(self.file_size_bytes, int)
            or self.file_size_bytes < 1
        ):
            raise ValueError(
                "file_size_bytes must be a positive integer."
            )

        if not isinstance(self.checksum_sha256, str):
            raise TypeError("checksum_sha256 must be a string.")

        checksum = self.checksum_sha256.strip().lower()

        if len(checksum) != 64:
            raise ValueError(
                "checksum_sha256 must contain 64 hexadecimal characters."
            )

        try:
            int(checksum, 16)
        except ValueError as error:
            raise ValueError(
                "checksum_sha256 must contain only hexadecimal characters."
            ) from error

        if not isinstance(self.stored_at, datetime):
            raise TypeError("stored_at must be a datetime.")

        if (
            self.stored_at.tzinfo is None
            or self.stored_at.utcoffset() is None
        ):
            raise ValueError("stored_at must be timezone-aware.")

        object.__setattr__(self, "checksum_sha256", checksum)


class FilesystemDocumentStorage:
    """Persist untrusted upload streams beneath one guarded root."""

    def __init__(
        self,
        config: FilesystemDocumentStorageConfig,
    ) -> None:
        """Initialise storage with validated immutable controls."""

        if not isinstance(config, FilesystemDocumentStorageConfig):
            raise TypeError(
                "config must be a FilesystemDocumentStorageConfig."
            )

        self._config = config

    @property
    def config(self) -> FilesystemDocumentStorageConfig:
        """Return the immutable storage configuration."""

        return self._config

    @property
    def root_directory(self) -> Path:
        """Return the canonical dedicated storage root."""

        return self._config.root_directory

    def store_bytes(
        self,
        *,
        filename: str,
        content: bytes,
        media_type: str | None = None,
        storage_id: UUID | None = None,
    ) -> StoredDocument:
        """Persist one in-memory byte payload using bounded stream logic."""

        if not isinstance(content, bytes):
            raise TypeError("content must be supplied as bytes.")

        return self.store_stream(
            filename=filename,
            stream=BytesIO(content),
            media_type=media_type,
            storage_id=storage_id,
        )

    def store_stream(
        self,
        *,
        filename: str,
        stream: BinaryIO,
        media_type: str | None = None,
        storage_id: UUID | None = None,
    ) -> StoredDocument:
        """Persist one bounded binary stream without trusting its filename."""

        source_name, suffix = self._normalise_filename(filename)
        normalised_media_type = self._normalise_media_type(media_type)

        read_method = getattr(stream, "read", None)

        if not callable(read_method):
            raise TypeError("stream must provide a callable read method.")

        identifier = storage_id or uuid4()

        if not isinstance(identifier, UUID):
            raise TypeError("storage_id must be a UUID when provided.")

        relative_reference = self._build_storage_reference(
            identifier,
            suffix,
        )
        target_path = self._prepare_target_path(relative_reference)

        descriptor: int | None = None
        created = False
        total_bytes = 0
        checksum = sha256()

        try:
            descriptor = os.open(
                target_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                _PRIVATE_FILE_MODE,
            )
            created = True

            with os.fdopen(descriptor, "wb") as destination:
                descriptor = None

                while True:
                    chunk = self._read_chunk(stream)

                    if not chunk:
                        break

                    total_bytes += len(chunk)

                    if total_bytes > self._config.maximum_content_bytes:
                        raise DocumentStorageTooLargeError(
                            "Uploaded document exceeds the configured "
                            f"{self._config.maximum_content_bytes}-byte "
                            "storage limit."
                        )

                    checksum.update(chunk)
                    written = destination.write(chunk)

                    if written != len(chunk):
                        raise DocumentStorageWriteError(
                            "Uploaded document could not be written "
                            "consistently."
                        )

                if total_bytes == 0:
                    raise DocumentStorageEmptyError(
                        "Uploaded document contains no bytes."
                    )

                destination.flush()

                if self._config.synchronise_writes:
                    os.fsync(destination.fileno())

        except FileExistsError as error:
            raise DocumentStorageConflictError(
                "The generated document storage destination already exists."
            ) from error
        except FilesystemDocumentStorageError:
            if created:
                self._remove_partial_file(target_path)
            raise
        except OSError as error:
            if created:
                self._remove_partial_file(target_path)
            raise DocumentStorageWriteError(
                "Uploaded document could not be stored safely."
            ) from error
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

        try:
            stored_size = target_path.stat().st_size
        except OSError as error:
            self._remove_partial_file(target_path)
            raise DocumentStorageWriteError(
                "Stored document metadata could not be verified."
            ) from error

        if stored_size != total_bytes:
            self._remove_partial_file(target_path)
            raise DocumentStorageWriteError(
                "Stored document size does not match the accepted upload."
            )

        return StoredDocument(
            storage_id=identifier,
            source_name=source_name,
            source_path=relative_reference,
            media_type=normalised_media_type,
            file_size_bytes=total_bytes,
            checksum_sha256=checksum.hexdigest(),
            stored_at=datetime.now(UTC),
        )

    def delete(
        self,
        source_path: str,
        *,
        expected_checksum_sha256: str | None = None,
    ) -> bool:
        """Remove one stored upload for transactional rollback.

        A caller may provide the checksum returned by ``store_stream``. When
        supplied, deletion is refused if the file no longer has that checksum.
        Missing files return ``False`` so repeated rollback remains idempotent.
        """

        target_path = self._resolve_stored_path(
            source_path,
            missing_is_allowed=True,
        )

        if target_path is None:
            return False

        if expected_checksum_sha256 is not None:
            expected_checksum = self._normalise_checksum(
                expected_checksum_sha256
            )
            actual_checksum = self._calculate_file_checksum(target_path)

            if actual_checksum != expected_checksum:
                raise DocumentStorageDeleteError(
                    "Stored document checksum changed; rollback was refused."
                )

        try:
            target_path.unlink()
        except FileNotFoundError:
            return False
        except OSError as error:
            raise DocumentStorageDeleteError(
                "Stored document could not be removed safely."
            ) from error

        return True

    def _read_chunk(self, stream: BinaryIO) -> bytes:
        """Read and validate one bounded chunk from an untrusted stream."""

        try:
            chunk = stream.read(self._config.read_chunk_bytes)
        except Exception as error:
            raise DocumentStorageReadError(
                "Uploaded document stream could not be read."
            ) from error

        if chunk is None:
            raise DocumentStorageReadError(
                "Uploaded document stream returned no binary result."
            )

        if isinstance(chunk, (bytearray, memoryview)):
            chunk = bytes(chunk)

        if not isinstance(chunk, bytes):
            raise DocumentStorageReadError(
                "Uploaded document stream returned non-binary content."
            )

        if len(chunk) > self._config.read_chunk_bytes:
            raise DocumentStorageReadError(
                "Uploaded document stream returned more bytes than "
                "requested."
            )

        return chunk

    def _normalise_filename(
        self,
        filename: str,
    ) -> tuple[str, str]:
        """Return a bounded display filename and parser-supported suffix."""

        if not isinstance(filename, str):
            raise TypeError("filename must be a string.")

        cleaned = unicodedata.normalize("NFC", filename.strip())

        if not cleaned:
            raise DocumentStorageFilenameError(
                "Upload filename cannot be blank."
            )

        if any(
            ord(character) < 32 or ord(character) == 127
            for character in cleaned
        ):
            raise DocumentStorageFilenameError(
                "Upload filename contains control characters."
            )

        normalised = cleaned.replace("\\", "/")
        source_name = PurePosixPath(normalised).name.strip()

        if source_name in {"", ".", ".."}:
            raise DocumentStorageFilenameError(
                "Upload filename must contain a valid final name."
            )

        if (
            len(source_name)
            > self._config.maximum_filename_characters
        ):
            raise DocumentStorageFilenameError(
                "Upload filename exceeds the configured "
                f"{self._config.maximum_filename_characters}-character "
                "limit."
            )

        suffix = Path(source_name).suffix.lower()

        if suffix not in self._config.allowed_suffixes:
            raise DocumentStorageFilenameError(
                f"Upload filename uses an unsupported suffix: "
                f"{suffix or '<none>'}."
            )

        return source_name, suffix

    def _normalise_media_type(
        self,
        media_type: str | None,
    ) -> str | None:
        """Normalise optional untrusted media-type metadata."""

        if media_type is None:
            return None

        if not isinstance(media_type, str):
            raise TypeError("media_type must be a string when provided.")

        cleaned = media_type.strip().lower()

        if not cleaned:
            return None

        if any(
            ord(character) < 32 or ord(character) == 127
            for character in cleaned
        ):
            raise DocumentStorageContentError(
                "media_type contains control characters."
            )

        if (
            len(cleaned)
            > self._config.maximum_media_type_characters
        ):
            raise DocumentStorageContentError(
                "media_type exceeds the configured "
                f"{self._config.maximum_media_type_characters}-character "
                "limit."
            )

        return cleaned

    @staticmethod
    def _build_storage_reference(
        storage_id: UUID,
        suffix: str,
    ) -> str:
        """Build one opaque relative reference from a server-owned UUID."""

        identifier = storage_id.hex

        return (
            f"{identifier[:2]}/"
            f"{identifier[2:4]}/"
            f"{identifier}{suffix}"
        )

    def _prepare_target_path(
        self,
        source_path: str,
    ) -> Path:
        """Create private shard directories and return a confined target."""

        match = _STORAGE_REFERENCE_PATTERN.fullmatch(source_path)

        if match is None:
            raise DocumentStoragePathError(
                "Generated document storage reference is invalid."
            )

        if not _has_canonical_storage_shards(match):
            raise DocumentStoragePathError(
                "Generated document storage shards are inconsistent."
            )

        if match.group("suffix") not in self._config.allowed_suffixes:
            raise DocumentStoragePathError(
                "Generated document storage suffix is not permitted."
            )

        parts = PurePosixPath(source_path).parts
        resolved_parent = self.root_directory

        try:
            for shard in parts[:-1]:
                intended_directory = resolved_parent / shard
                intended_directory.mkdir(
                    mode=_PRIVATE_DIRECTORY_MODE,
                    exist_ok=True,
                )

                if intended_directory.is_symlink():
                    raise DocumentStoragePathError(
                        "Document storage shard cannot be a symbolic link."
                    )

                resolved_directory = intended_directory.resolve(
                    strict=True
                )

                try:
                    resolved_directory.relative_to(self.root_directory)
                except ValueError as error:
                    raise DocumentStoragePathError(
                        "Document storage directory escapes its "
                        "configured root."
                    ) from error

                if resolved_directory != intended_directory:
                    raise DocumentStoragePathError(
                        "Document storage shard cannot be a symbolic link."
                    )

                resolved_parent = resolved_directory
        except DocumentStoragePathError:
            raise
        except OSError as error:
            raise DocumentStorageWriteError(
                "Document storage directory could not be prepared."
            ) from error

        return resolved_parent / parts[-1]

    def _resolve_stored_path(
        self,
        source_path: str,
        *,
        missing_is_allowed: bool,
    ) -> Path | None:
        """Resolve one opaque stored reference beneath the configured root."""

        if not isinstance(source_path, str):
            raise TypeError("source_path must be a string.")

        match = _STORAGE_REFERENCE_PATTERN.fullmatch(source_path)

        if match is None:
            raise DocumentStoragePathError(
                "source_path is not a valid server-owned storage reference."
            )

        if not _has_canonical_storage_shards(match):
            raise DocumentStoragePathError(
                "source_path uses inconsistent document storage shards."
            )

        if match.group("suffix") not in self._config.allowed_suffixes:
            raise DocumentStoragePathError(
                "source_path uses a document suffix that is not permitted."
            )

        parts = PurePosixPath(source_path).parts
        unresolved_path = self.root_directory.joinpath(*parts)

        if unresolved_path.is_symlink():
            raise DocumentStoragePathError(
                "Stored document reference cannot target a symbolic link."
            )

        try:
            resolved_parent = unresolved_path.parent.resolve(strict=True)
        except FileNotFoundError:
            if missing_is_allowed:
                return None
            raise
        except OSError as error:
            raise DocumentStoragePathError(
                "Stored document directory could not be resolved safely."
            ) from error

        try:
            resolved_parent.relative_to(self.root_directory)
        except ValueError as error:
            raise DocumentStoragePathError(
                "Stored document directory escapes its configured root."
            ) from error

        if resolved_parent != unresolved_path.parent:
            raise DocumentStoragePathError(
                "Stored document shard cannot be a symbolic link."
            )

        try:
            resolved_path = unresolved_path.resolve(strict=True)
        except FileNotFoundError:
            if missing_is_allowed:
                return None
            raise
        except OSError as error:
            raise DocumentStoragePathError(
                "Stored document path could not be resolved safely."
            ) from error

        try:
            resolved_path.relative_to(self.root_directory)
        except ValueError as error:
            raise DocumentStoragePathError(
                "Stored document path escapes its configured root."
            ) from error

        if not resolved_path.is_file():
            raise DocumentStoragePathError(
                "Stored document reference is not a regular file."
            )

        return resolved_path

    def _calculate_file_checksum(self, path: Path) -> str:
        """Calculate a bounded checksum before guarded rollback."""

        try:
            declared_size = path.stat().st_size
        except OSError as error:
            raise DocumentStorageDeleteError(
                "Stored document metadata could not be inspected."
            ) from error

        if declared_size > self._config.maximum_content_bytes:
            raise DocumentStorageDeleteError(
                "Stored document exceeds the configured rollback limit."
            )

        checksum = sha256()
        total_bytes = 0

        try:
            with path.open("rb") as stored_file:
                while True:
                    chunk = stored_file.read(
                        self._config.read_chunk_bytes
                    )

                    if not chunk:
                        break

                    total_bytes += len(chunk)

                    if (
                        total_bytes
                        > self._config.maximum_content_bytes
                    ):
                        raise DocumentStorageDeleteError(
                            "Stored document grew beyond the configured "
                            "rollback limit."
                        )

                    checksum.update(chunk)
        except DocumentStorageDeleteError:
            raise
        except OSError as error:
            raise DocumentStorageDeleteError(
                "Stored document could not be verified for rollback."
            ) from error

        if total_bytes != declared_size:
            raise DocumentStorageDeleteError(
                "Stored document changed during rollback verification."
            )

        return checksum.hexdigest()

    @staticmethod
    def _normalise_checksum(value: str) -> str:
        """Validate one caller-supplied rollback checksum."""

        if not isinstance(value, str):
            raise TypeError(
                "expected_checksum_sha256 must be a string."
            )

        cleaned = value.strip().lower()

        if len(cleaned) != 64:
            raise ValueError(
                "expected_checksum_sha256 must contain "
                "64 hexadecimal characters."
            )

        try:
            int(cleaned, 16)
        except ValueError as error:
            raise ValueError(
                "expected_checksum_sha256 must contain only "
                "hexadecimal characters."
            ) from error

        return cleaned

    @staticmethod
    def _remove_partial_file(path: Path) -> None:
        """Best-effort cleanup that never hides the original failure."""

        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


__all__ = [
    "DocumentStorageConflictError",
    "DocumentStorageContentError",
    "DocumentStorageDeleteError",
    "DocumentStorageEmptyError",
    "DocumentStorageFilenameError",
    "DocumentStoragePathError",
    "DocumentStorageReadError",
    "DocumentStorageTooLargeError",
    "DocumentStorageWriteError",
    "FilesystemDocumentStorage",
    "FilesystemDocumentStorageConfig",
    "FilesystemDocumentStorageError",
    "StoredDocument",
]
