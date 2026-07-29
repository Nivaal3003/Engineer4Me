"""Tests for guarded server-owned filesystem document storage."""

from __future__ import annotations

import os
import stat
import unicodedata
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any
from unittest import TestCase
from unittest.mock import patch
from uuid import UUID

import app.ingestion.filesystem_document_storage as storage_module
from app.ingestion.filesystem_document_storage import (
    DocumentStorageConflictError,
    DocumentStorageContentError,
    DocumentStorageDeleteError,
    DocumentStorageEmptyError,
    DocumentStorageFilenameError,
    DocumentStoragePathError,
    DocumentStorageReadError,
    DocumentStorageTooLargeError,
    DocumentStorageWriteError,
    FilesystemDocumentStorage,
    FilesystemDocumentStorageConfig,
    FilesystemDocumentStorageError,
    StoredDocument,
)


FIXED_STORAGE_ID = UUID("12345678-1234-5678-1234-567812345678")
FIXED_SOURCE_PATH = (
    "12/34/12345678123456781234567812345678.txt"
)
DEFAULT_CONTENT = b"Rosemount pressure transmitter manual."
DEFAULT_CHECKSUM = sha256(DEFAULT_CONTENT).hexdigest()


def stored_files(root_directory: Path) -> list[Path]:
    """Return every regular stored file below one test root."""

    return sorted(
        path
        for path in root_directory.rglob("*")
        if path.is_file() and not path.is_symlink()
    )


class SequenceStream:
    """Return deterministic stream results and record requested sizes."""

    def __init__(self, results: list[object]) -> None:
        self.results = list(results)
        self.requested_sizes: list[int] = []

    def read(self, size: int) -> object:
        """Return the next configured result."""

        self.requested_sizes.append(size)

        if not self.results:
            return b""

        result = self.results.pop(0)

        if isinstance(result, Exception):
            raise result

        return result


class FakeChecksumPath:
    """Provide deterministic stat/open behaviour for checksum guards."""

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
        """Return configured metadata or raise its error."""

        if self.stat_error is not None:
            raise self.stat_error

        return SimpleNamespace(st_size=self.declared_size)

    def open(self, mode: str) -> BytesIO:
        """Return configured bytes or raise its error."""

        if mode != "rb":
            raise AssertionError(f"Unexpected mode: {mode}")

        if self.open_error is not None:
            raise self.open_error

        return BytesIO(self.content)


class FilesystemDocumentStorageConfigTests(TestCase):
    """Validate immutable filesystem storage controls."""

    def setUp(self) -> None:
        """Create one existing root per test."""

        self._temporary_directory = TemporaryDirectory()
        self.root_directory = Path(self._temporary_directory.name)

    def tearDown(self) -> None:
        """Remove the isolated root."""

        self._temporary_directory.cleanup()

    def test_config_canonicalises_root_and_is_frozen(self) -> None:
        """Configuration stores one canonical immutable root."""

        nested = self.root_directory / "nested"
        nested.mkdir()
        config = FilesystemDocumentStorageConfig(
            root_directory=nested / ".." / "nested",
        )

        self.assertEqual(config.root_directory, nested.resolve())

        with self.assertRaises(FrozenInstanceError):
            config.root_directory = self.root_directory  # type: ignore[misc]

    def test_config_defaults_are_bounded(self) -> None:
        """Defaults align with the complete parser and private writes."""

        config = FilesystemDocumentStorageConfig(
            root_directory=self.root_directory,
        )

        self.assertEqual(
            config.maximum_content_bytes,
            25 * 1024 * 1024,
        )
        self.assertEqual(config.read_chunk_bytes, 64 * 1024)
        self.assertEqual(config.maximum_filename_characters, 512)
        self.assertEqual(config.maximum_media_type_characters, 255)
        self.assertTrue(config.synchronise_writes)
        self.assertIsInstance(config.allowed_suffixes, frozenset)
        self.assertTrue(
            {
                ".txt",
                ".pdf",
                ".docx",
                ".xlsx",
                ".xls",
                ".png",
            }.issubset(config.allowed_suffixes)
        )

    def test_config_rejects_non_path_roots(self) -> None:
        """Only strings and filesystem path objects can identify a root."""

        for value in (None, 1, True, object()):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    TypeError,
                    "root_directory must be a filesystem path",
                ):
                    FilesystemDocumentStorageConfig(
                        root_directory=value,  # type: ignore[arg-type]
                    )

    def test_config_rejects_blank_root(self) -> None:
        """Whitespace cannot become a process-relative storage root."""

        with self.assertRaisesRegex(
            ValueError,
            "root_directory cannot be blank",
        ):
            FilesystemDocumentStorageConfig(
                root_directory="   ",  # type: ignore[arg-type]
            )

    def test_config_rejects_missing_root(self) -> None:
        """The storage root must already exist."""

        with self.assertRaisesRegex(ValueError, "does not exist"):
            FilesystemDocumentStorageConfig(
                root_directory=self.root_directory / "missing",
            )

    def test_config_rejects_regular_file_root(self) -> None:
        """A regular file cannot become the storage root."""

        file_path = self.root_directory / "file-root"
        file_path.write_bytes(b"content")

        with self.assertRaisesRegex(ValueError, "not a directory"):
            FilesystemDocumentStorageConfig(
                root_directory=file_path,
            )

    def test_config_rejects_invalid_positive_integer_controls(
        self,
    ) -> None:
        """Every byte and character limit is a positive integer."""

        field_names = (
            "maximum_content_bytes",
            "read_chunk_bytes",
            "maximum_filename_characters",
            "maximum_media_type_characters",
        )
        invalid_values: tuple[Any, ...] = (
            0,
            -1,
            True,
            False,
            1.5,
            "10",
            None,
        )

        for field_name in field_names:
            for value in invalid_values:
                with self.subTest(field_name=field_name, value=value):
                    with self.assertRaisesRegex(
                        ValueError,
                        f"{field_name} must be a positive integer",
                    ):
                        FilesystemDocumentStorageConfig(
                            root_directory=self.root_directory,
                            **{field_name: value},
                        )

    def test_config_rejects_non_boolean_synchronise_writes(
        self,
    ) -> None:
        """Write synchronisation has explicit boolean semantics."""

        for value in (0, 1, None, "true", object()):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    TypeError,
                    "synchronise_writes must be a boolean",
                ):
                    FilesystemDocumentStorageConfig(
                        root_directory=self.root_directory,
                        synchronise_writes=value,  # type: ignore[arg-type]
                    )

    def test_config_rejects_invalid_suffix_collections(self) -> None:
        """Suffix configuration is a non-empty set, never free text."""

        invalid_values: tuple[Any, ...] = (
            set(),
            frozenset(),
            ".txt",
            b".txt",
            [".txt"],
            (".txt",),
            None,
        )

        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ValueError,
                    "allowed_suffixes must be a non-empty set",
                ):
                    FilesystemDocumentStorageConfig(
                        root_directory=self.root_directory,
                        allowed_suffixes=value,
                    )

    def test_config_rejects_non_string_suffix_members(self) -> None:
        """Every allowed suffix must be text."""

        with self.assertRaisesRegex(
            TypeError,
            "allowed_suffixes must contain only strings",
        ):
            FilesystemDocumentStorageConfig(
                root_directory=self.root_directory,
                allowed_suffixes={".txt", 1},  # type: ignore[arg-type]
            )

    def test_config_rejects_unsafe_suffix_patterns(self) -> None:
        """Configured suffixes cannot contain paths or compound syntax."""

        invalid_suffixes = (
            "",
            "txt",
            ".",
            "..",
            ".tar.gz",
            ".pdf/",
            "../txt",
            ".pdf?",
            ".do cx",
        )

        for suffix in invalid_suffixes:
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(
                    ValueError,
                    "Unsupported configured document suffix",
                ):
                    FilesystemDocumentStorageConfig(
                        root_directory=self.root_directory,
                        allowed_suffixes={suffix},
                    )

    def test_config_normalises_allowed_suffixes(self) -> None:
        """Configured suffixes are lowercased, trimmed, and frozen."""

        config = FilesystemDocumentStorageConfig(
            root_directory=self.root_directory,
            allowed_suffixes={" .TXT ", ".Pdf", ".PDF"},
        )

        self.assertEqual(
            config.allowed_suffixes,
            frozenset({".txt", ".pdf"}),
        )


class StoredDocumentTests(TestCase):
    """Validate authoritative immutable stored-document metadata."""

    def build_document(self, **overrides: Any) -> StoredDocument:
        """Build metadata while permitting one field override."""

        values: dict[str, Any] = {
            "storage_id": FIXED_STORAGE_ID,
            "source_name": "manual.txt",
            "source_path": FIXED_SOURCE_PATH,
            "media_type": "text/plain",
            "file_size_bytes": len(DEFAULT_CONTENT),
            "checksum_sha256": DEFAULT_CHECKSUM,
            "stored_at": datetime.now(UTC),
        }
        values.update(overrides)
        return StoredDocument(**values)

    def test_metadata_is_valid_frozen_and_normalises_checksum(
        self,
    ) -> None:
        """Valid metadata is immutable with a canonical checksum."""

        document = self.build_document(
            checksum_sha256=f"  {DEFAULT_CHECKSUM.upper()}  ",
        )

        self.assertEqual(document.checksum_sha256, DEFAULT_CHECKSUM)

        with self.assertRaises(FrozenInstanceError):
            document.source_name = "changed.txt"  # type: ignore[misc]

    def test_metadata_rejects_invalid_storage_id(self) -> None:
        """The server-owned identifier is always a UUID."""

        with self.assertRaisesRegex(TypeError, "storage_id must be a UUID"):
            self.build_document(storage_id="not-a-uuid")

    def test_metadata_rejects_invalid_source_names(self) -> None:
        """Display source names must be non-blank strings."""

        invalid_cases = (
            (None, TypeError),
            (1, TypeError),
            ("", ValueError),
            ("   ", ValueError),
        )

        for value, expected_error in invalid_cases:
            with self.subTest(value=value):
                with self.assertRaises(expected_error):
                    self.build_document(source_name=value)

    def test_metadata_rejects_non_string_source_path(self) -> None:
        """Opaque references cannot be non-string values."""

        for value in (None, 1, FIXED_STORAGE_ID):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    TypeError,
                    "source_path must be a string",
                ):
                    self.build_document(source_path=value)

    def test_metadata_rejects_malformed_source_paths(self) -> None:
        """Opaque references reject traversal and noncanonical syntax."""

        invalid_paths = (
            "",
            "../manual.txt",
            "/12/34/12345678123456781234567812345678.txt",
            r"12\34\12345678123456781234567812345678.txt",
            "12/34/not-a-uuid.txt",
            "12/34/12345678123456781234567812345678.TXT",
            "12/34/12345678123456781234567812345678.tar.gz",
        )

        for source_path in invalid_paths:
            with self.subTest(source_path=source_path):
                with self.assertRaisesRegex(
                    ValueError,
                    "opaque server-owned reference",
                ):
                    self.build_document(source_path=source_path)

    def test_metadata_rejects_inconsistent_storage_shards(self) -> None:
        """Reference directories derive from the identifier prefix."""

        with self.assertRaisesRegex(
            ValueError,
            "opaque server-owned reference",
        ):
            self.build_document(
                source_path=(
                    "00/00/12345678123456781234567812345678.txt"
                ),
            )

    def test_metadata_rejects_identifier_mismatch(self) -> None:
        """Metadata cannot pair one UUID with another storage key."""

        with self.assertRaisesRegex(
            ValueError,
            "declared storage_id",
        ):
            self.build_document(
                storage_id=UUID(
                    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
                ),
            )

    def test_metadata_rejects_suffix_mismatch(self) -> None:
        """Display and stored suffixes describe the same parser format."""

        with self.assertRaisesRegex(
            ValueError,
            "suffixes must match",
        ):
            self.build_document(source_name="manual.pdf")

    def test_metadata_rejects_invalid_media_type(self) -> None:
        """Optional media type metadata must be text."""

        for value in (1, b"text/plain", object()):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    TypeError,
                    "media_type must be a string",
                ):
                    self.build_document(media_type=value)

    def test_metadata_accepts_absent_media_type(self) -> None:
        """Media type remains optional."""

        self.assertIsNone(self.build_document(media_type=None).media_type)

    def test_metadata_rejects_invalid_file_sizes(self) -> None:
        """Authoritative stored sizes are positive integers."""

        for value in (0, -1, True, False, 1.5, "1", None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ValueError,
                    "file_size_bytes must be a positive integer",
                ):
                    self.build_document(file_size_bytes=value)

    def test_metadata_rejects_non_string_checksum(self) -> None:
        """Checksums cannot be arbitrary values."""

        for value in (None, 1, b"a" * 64):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    TypeError,
                    "checksum_sha256 must be a string",
                ):
                    self.build_document(checksum_sha256=value)

    def test_metadata_rejects_malformed_checksums(self) -> None:
        """Checksums contain exactly 64 hexadecimal characters."""

        for value in ("", "a" * 63, "a" * 65, "g" * 64):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.build_document(checksum_sha256=value)

    def test_metadata_rejects_non_datetime_timestamp(self) -> None:
        """Storage timestamps are datetime objects."""

        with self.assertRaisesRegex(
            TypeError,
            "stored_at must be a datetime",
        ):
            self.build_document(stored_at="2026-07-29")

    def test_metadata_rejects_naive_timestamp(self) -> None:
        """Storage timestamps always include a timezone."""

        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            self.build_document(stored_at=datetime.now())


class FilesystemDocumentStorageWriteTests(TestCase):
    """Validate bounded exclusive upload persistence."""

    def setUp(self) -> None:
        """Create one isolated storage root."""

        self._temporary_directory = TemporaryDirectory()
        self.root_directory = Path(self._temporary_directory.name)

    def tearDown(self) -> None:
        """Remove test storage."""

        self._temporary_directory.cleanup()

    def build_storage(
        self,
        **overrides: Any,
    ) -> FilesystemDocumentStorage:
        """Build storage with optional control overrides."""

        values: dict[str, Any] = {
            "root_directory": self.root_directory,
            "maximum_content_bytes": 1024,
            "read_chunk_bytes": 8,
        }
        values.update(overrides)
        return FilesystemDocumentStorage(
            FilesystemDocumentStorageConfig(**values)
        )

    def test_storage_requires_valid_config(self) -> None:
        """Storage construction requires validated immutable controls."""

        with self.assertRaisesRegex(
            TypeError,
            "FilesystemDocumentStorageConfig",
        ):
            FilesystemDocumentStorage(object())  # type: ignore[arg-type]

    def test_storage_exposes_config_and_canonical_root(self) -> None:
        """Runtime composition can inspect immutable storage controls."""

        storage = self.build_storage()

        self.assertIs(storage.config, storage._config)
        self.assertEqual(
            storage.root_directory,
            self.root_directory.resolve(),
        )

    def test_store_bytes_persists_authoritative_metadata(self) -> None:
        """One byte payload receives deterministic server-owned metadata."""

        storage = self.build_storage()
        document = storage.store_bytes(
            filename="manual.txt",
            content=DEFAULT_CONTENT,
            media_type=" Text/Plain ",
            storage_id=FIXED_STORAGE_ID,
        )
        stored_path = self.root_directory.joinpath(
            *document.source_path.split("/")
        )

        self.assertEqual(document.storage_id, FIXED_STORAGE_ID)
        self.assertEqual(document.source_name, "manual.txt")
        self.assertEqual(document.source_path, FIXED_SOURCE_PATH)
        self.assertEqual(document.media_type, "text/plain")
        self.assertEqual(document.file_size_bytes, len(DEFAULT_CONTENT))
        self.assertEqual(document.checksum_sha256, DEFAULT_CHECKSUM)
        self.assertEqual(document.stored_at.tzinfo, UTC)
        self.assertEqual(stored_path.read_bytes(), DEFAULT_CONTENT)

    def test_store_generates_distinct_opaque_identifiers(self) -> None:
        """Default storage keys are server-owned and collision-resistant."""

        storage = self.build_storage()
        first = storage.store_bytes(
            filename="first.txt",
            content=b"first",
        )
        second = storage.store_bytes(
            filename="second.txt",
            content=b"second",
        )

        self.assertNotEqual(first.storage_id, second.storage_id)
        self.assertNotEqual(first.source_path, second.source_path)

        for document in (first, second):
            identifier = document.storage_id.hex
            self.assertEqual(
                document.source_path,
                (
                    f"{identifier[:2]}/{identifier[2:4]}/"
                    f"{identifier}.txt"
                ),
            )

    def test_store_sanitises_untrusted_filename_paths(self) -> None:
        """Display names never control storage directories."""

        storage = self.build_storage()
        document = storage.store_bytes(
            filename=r"../../untrusted\folder\Valve.PDF",
            content=b"%PDF-test",
            storage_id=FIXED_STORAGE_ID,
        )

        self.assertEqual(document.source_name, "Valve.PDF")
        self.assertEqual(
            document.source_path,
            "12/34/12345678123456781234567812345678.pdf",
        )
        self.assertNotIn("untrusted", document.source_path)
        self.assertNotIn("folder", document.source_path)

    def test_store_normalises_unicode_filename(self) -> None:
        """Display filenames use canonical NFC Unicode."""

        decomposed = "Cafe\u0301.txt"
        storage = self.build_storage()
        document = storage.store_bytes(
            filename=decomposed,
            content=b"content",
        )

        self.assertEqual(
            document.source_name,
            unicodedata.normalize("NFC", decomposed),
        )

    def test_store_blank_media_type_becomes_none(self) -> None:
        """Whitespace-only optional media types are omitted."""

        document = self.build_storage().store_bytes(
            filename="manual.txt",
            content=b"content",
            media_type="   ",
        )

        self.assertIsNone(document.media_type)

    def test_store_rejects_invalid_filename_type(self) -> None:
        """Filename metadata must be text."""

        with self.assertRaisesRegex(TypeError, "filename must be a string"):
            self.build_storage().store_bytes(
                filename=1,  # type: ignore[arg-type]
                content=b"content",
            )

    def test_store_rejects_blank_and_invalid_final_names(self) -> None:
        """Blank and directory-only names cannot identify a document."""

        for filename in ("", "   ", ".", "..", "../", "folder/"):
            with self.subTest(filename=filename):
                with self.assertRaises(DocumentStorageFilenameError):
                    self.build_storage().store_bytes(
                        filename=filename,
                        content=b"content",
                    )

    def test_store_rejects_filename_control_characters(self) -> None:
        """Control characters never enter stored display metadata."""

        for filename in (
            "manual\x00.txt",
            "manual\n.txt",
            "manual\t.txt",
            "manual\x7f.txt",
        ):
            with self.subTest(filename=filename):
                with self.assertRaisesRegex(
                    DocumentStorageFilenameError,
                    "control characters",
                ):
                    self.build_storage().store_bytes(
                        filename=filename,
                        content=b"content",
                    )

    def test_store_rejects_missing_or_unsupported_suffix(self) -> None:
        """Only formats supported by the parser chain are accepted."""

        for filename in (
            "manual",
            "manual.exe",
            "manual.tar.gz",
            ".txt",
        ):
            with self.subTest(filename=filename):
                with self.assertRaisesRegex(
                    DocumentStorageFilenameError,
                    "unsupported suffix",
                ):
                    self.build_storage().store_bytes(
                        filename=filename,
                        content=b"content",
                    )

    def test_store_rejects_overlong_filename(self) -> None:
        """Filename length is bounded before persistence."""

        storage = self.build_storage(
            maximum_filename_characters=12,
        )

        with self.assertRaisesRegex(
            DocumentStorageFilenameError,
            "12-character limit",
        ):
            storage.store_bytes(
                filename="long-manual.txt",
                content=b"content",
            )

    def test_store_rejects_invalid_media_type(self) -> None:
        """Media type must be safe bounded text when provided."""

        for value in (1, b"text/plain", object()):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    TypeError,
                    "media_type must be a string",
                ):
                    self.build_storage().store_bytes(
                        filename="manual.txt",
                        content=b"content",
                        media_type=value,
                    )

    def test_store_rejects_media_type_control_characters(self) -> None:
        """Media type metadata cannot contain controls."""

        for value in ("text/\nplain", "text/\x00plain", "text/\x7f"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    DocumentStorageContentError,
                    "control characters",
                ):
                    self.build_storage().store_bytes(
                        filename="manual.txt",
                        content=b"content",
                        media_type=value,
                    )

    def test_store_rejects_overlong_media_type(self) -> None:
        """Media type metadata has a configured character bound."""

        storage = self.build_storage(
            maximum_media_type_characters=10,
        )

        with self.assertRaisesRegex(
            DocumentStorageContentError,
            "10-character limit",
        ):
            storage.store_bytes(
                filename="manual.txt",
                content=b"content",
                media_type="application/pdf",
            )

    def test_store_bytes_rejects_non_bytes_content(self) -> None:
        """The in-memory convenience method has explicit bytes semantics."""

        for value in (bytearray(b"x"), memoryview(b"x"), "x", None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    TypeError,
                    "content must be supplied as bytes",
                ):
                    self.build_storage().store_bytes(
                        filename="manual.txt",
                        content=value,  # type: ignore[arg-type]
                    )

    def test_store_rejects_empty_content_and_cleans_file(self) -> None:
        """Empty uploads fail without leaving a partial file."""

        with self.assertRaises(DocumentStorageEmptyError):
            self.build_storage().store_bytes(
                filename="manual.txt",
                content=b"",
                storage_id=FIXED_STORAGE_ID,
            )

        self.assertEqual(stored_files(self.root_directory), [])

    def test_store_rejects_oversized_content_and_cleans_file(self) -> None:
        """Payloads above the byte limit fail transactionally."""

        storage = self.build_storage(maximum_content_bytes=4)

        with self.assertRaisesRegex(
            DocumentStorageTooLargeError,
            "4-byte storage limit",
        ):
            storage.store_bytes(
                filename="manual.txt",
                content=b"12345",
                storage_id=FIXED_STORAGE_ID,
            )

        self.assertEqual(stored_files(self.root_directory), [])

    def test_store_accepts_exact_maximum_content_size(self) -> None:
        """The configured limit is inclusive."""

        storage = self.build_storage(maximum_content_bytes=4)
        document = storage.store_bytes(
            filename="manual.txt",
            content=b"1234",
        )

        self.assertEqual(document.file_size_bytes, 4)

    def test_store_stream_reads_requested_chunks(self) -> None:
        """Stream reads are bounded by the configured chunk size."""

        stream = SequenceStream(
            [bytearray(b"abcd"), memoryview(b"ef"), b""],
        )
        storage = self.build_storage(read_chunk_bytes=4)
        document = storage.store_stream(
            filename="manual.txt",
            stream=stream,  # type: ignore[arg-type]
            storage_id=FIXED_STORAGE_ID,
        )
        path = self.root_directory.joinpath(
            *document.source_path.split("/")
        )

        self.assertEqual(path.read_bytes(), b"abcdef")
        self.assertEqual(stream.requested_sizes, [4, 4, 4])

    def test_store_stream_requires_callable_read(self) -> None:
        """Binary stream inputs provide a callable read method."""

        for stream in (object(), SimpleNamespace(read=None)):
            with self.subTest(stream=stream):
                with self.assertRaisesRegex(
                    TypeError,
                    "callable read method",
                ):
                    self.build_storage().store_stream(
                        filename="manual.txt",
                        stream=stream,  # type: ignore[arg-type]
                    )

    def test_store_stream_rejects_none_result(self) -> None:
        """A stream cannot return an indeterminate result."""

        stream = SequenceStream([None])

        with self.assertRaisesRegex(
            DocumentStorageReadError,
            "no binary result",
        ):
            self.build_storage().store_stream(
                filename="manual.txt",
                stream=stream,  # type: ignore[arg-type]
            )

        self.assertEqual(stored_files(self.root_directory), [])

    def test_store_stream_rejects_non_binary_result(self) -> None:
        """A stream cannot inject text or arbitrary objects."""

        for result in ("text", 1, object()):
            with self.subTest(result=result):
                stream = SequenceStream([result])

                with self.assertRaisesRegex(
                    DocumentStorageReadError,
                    "non-binary content",
                ):
                    self.build_storage().store_stream(
                        filename="manual.txt",
                        stream=stream,  # type: ignore[arg-type]
                    )

                self.assertEqual(stored_files(self.root_directory), [])

    def test_store_stream_rejects_oversized_returned_chunk(self) -> None:
        """A nonconforming stream cannot exceed the requested read size."""

        stream = SequenceStream([b"12345"])

        with self.assertRaisesRegex(
            DocumentStorageReadError,
            "more bytes than requested",
        ):
            self.build_storage(
                read_chunk_bytes=4,
            ).store_stream(
                filename="manual.txt",
                stream=stream,  # type: ignore[arg-type]
            )

        self.assertEqual(stored_files(self.root_directory), [])

    def test_store_stream_maps_read_error_and_cleans_file(self) -> None:
        """Stream failures never leave accepted-looking partial content."""

        stream = SequenceStream([b"first", OSError("read failed")])

        with self.assertRaisesRegex(
            DocumentStorageReadError,
            "could not be read",
        ):
            self.build_storage().store_stream(
                filename="manual.txt",
                stream=stream,  # type: ignore[arg-type]
                storage_id=FIXED_STORAGE_ID,
            )

        self.assertEqual(stored_files(self.root_directory), [])

    def test_store_rejects_invalid_explicit_storage_id(self) -> None:
        """Explicit deterministic identifiers remain UUID-only."""

        with self.assertRaisesRegex(
            TypeError,
            "storage_id must be a UUID",
        ):
            self.build_storage().store_bytes(
                filename="manual.txt",
                content=b"content",
                storage_id="1234",  # type: ignore[arg-type]
            )

    def test_store_conflict_never_overwrites_existing_content(self) -> None:
        """Exclusive creation preserves a prior document on collision."""

        storage = self.build_storage()
        first = storage.store_bytes(
            filename="manual.txt",
            content=b"original",
            storage_id=FIXED_STORAGE_ID,
        )

        with self.assertRaises(DocumentStorageConflictError):
            storage.store_bytes(
                filename="manual.txt",
                content=b"replacement",
                storage_id=FIXED_STORAGE_ID,
            )

        path = self.root_directory.joinpath(
            *first.source_path.split("/")
        )
        self.assertEqual(path.read_bytes(), b"original")

    def test_store_maps_open_error_to_write_error(self) -> None:
        """Filesystem creation errors use the storage exception boundary."""

        with patch.object(
            storage_module.os,
            "open",
            side_effect=PermissionError("denied"),
        ):
            with self.assertRaisesRegex(
                DocumentStorageWriteError,
                "could not be stored safely",
            ):
                self.build_storage().store_bytes(
                    filename="manual.txt",
                    content=b"content",
                )

        self.assertEqual(stored_files(self.root_directory), [])

    def test_store_synchronises_enabled_writes(self) -> None:
        """Enabled durable writes flush the completed file descriptor."""

        with patch.object(storage_module.os, "fsync") as fsync:
            self.build_storage(
                synchronise_writes=True,
            ).store_bytes(
                filename="manual.txt",
                content=b"content",
            )

        fsync.assert_called_once()

    def test_store_can_disable_write_synchronisation(self) -> None:
        """Controlled environments can disable the fsync call."""

        with patch.object(storage_module.os, "fsync") as fsync:
            self.build_storage(
                synchronise_writes=False,
            ).store_bytes(
                filename="manual.txt",
                content=b"content",
            )

        fsync.assert_not_called()

    def test_store_uses_private_file_and_directory_modes(self) -> None:
        """Created storage paths are private on POSIX filesystems."""

        document = self.build_storage().store_bytes(
            filename="manual.txt",
            content=b"content",
            storage_id=FIXED_STORAGE_ID,
        )
        file_path = self.root_directory.joinpath(
            *document.source_path.split("/")
        )

        self.assertEqual(
            stat.S_IMODE(file_path.stat().st_mode),
            0o600,
        )
        self.assertEqual(
            stat.S_IMODE(file_path.parent.stat().st_mode),
            0o700,
        )
        self.assertEqual(
            stat.S_IMODE(file_path.parent.parent.stat().st_mode),
            0o700,
        )

    def test_store_rejects_first_shard_symlink_without_side_effect(
        self,
    ) -> None:
        """A symlinked first shard cannot create paths outside the root."""

        outside = self.root_directory.parent / (
            f"{self.root_directory.name}-outside-first"
        )
        outside.mkdir()
        (self.root_directory / "12").symlink_to(
            outside,
            target_is_directory=True,
        )

        try:
            with self.assertRaises(DocumentStoragePathError):
                self.build_storage().store_bytes(
                    filename="manual.txt",
                    content=b"content",
                    storage_id=FIXED_STORAGE_ID,
                )

            self.assertFalse((outside / "34").exists())
        finally:
            if outside.exists():
                outside.rmdir()

    def test_store_rejects_second_shard_symlink(self) -> None:
        """A symlinked second shard cannot redirect a write."""

        outside = self.root_directory.parent / (
            f"{self.root_directory.name}-outside-second"
        )
        outside.mkdir()
        first_shard = self.root_directory / "12"
        first_shard.mkdir()
        (first_shard / "34").symlink_to(
            outside,
            target_is_directory=True,
        )

        try:
            with self.assertRaises(DocumentStoragePathError):
                self.build_storage().store_bytes(
                    filename="manual.txt",
                    content=b"content",
                    storage_id=FIXED_STORAGE_ID,
                )

            self.assertEqual(list(outside.iterdir()), [])
        finally:
            if outside.exists():
                outside.rmdir()

    def test_store_uses_existing_safe_shard_directories(self) -> None:
        """Normal existing shard directories remain reusable."""

        (self.root_directory / "12" / "34").mkdir(parents=True)
        document = self.build_storage().store_bytes(
            filename="manual.txt",
            content=b"content",
            storage_id=FIXED_STORAGE_ID,
        )

        self.assertEqual(document.source_path, FIXED_SOURCE_PATH)


class FilesystemDocumentStorageDeleteTests(TestCase):
    """Validate checksum-guarded confined rollback deletion."""

    def setUp(self) -> None:
        """Create one isolated storage adapter."""

        self._temporary_directory = TemporaryDirectory()
        self.root_directory = Path(self._temporary_directory.name)
        self.storage = FilesystemDocumentStorage(
            FilesystemDocumentStorageConfig(
                root_directory=self.root_directory,
                maximum_content_bytes=1024,
                read_chunk_bytes=8,
            )
        )

    def tearDown(self) -> None:
        """Remove test storage."""

        self._temporary_directory.cleanup()

    def store_fixed(
        self,
        content: bytes = DEFAULT_CONTENT,
    ) -> StoredDocument:
        """Persist one deterministic document."""

        return self.storage.store_bytes(
            filename="manual.txt",
            content=content,
            storage_id=FIXED_STORAGE_ID,
        )

    def path_for(self, document: StoredDocument) -> Path:
        """Resolve a stored document below the test root."""

        return self.root_directory.joinpath(
            *document.source_path.split("/")
        )

    def test_delete_with_matching_checksum_removes_file(self) -> None:
        """Transactional rollback removes the unchanged stored document."""

        document = self.store_fixed()
        path = self.path_for(document)

        self.assertTrue(
            self.storage.delete(
                document.source_path,
                expected_checksum_sha256=document.checksum_sha256,
            )
        )
        self.assertFalse(path.exists())

    def test_delete_is_idempotent_for_missing_file(self) -> None:
        """Repeated rollback reports that no file remains."""

        document = self.store_fixed()
        self.assertTrue(self.storage.delete(document.source_path))
        self.assertFalse(self.storage.delete(document.source_path))

    def test_delete_without_checksum_removes_file(self) -> None:
        """An explicit administrative deletion can omit checksum matching."""

        document = self.store_fixed()

        self.assertTrue(self.storage.delete(document.source_path))
        self.assertEqual(stored_files(self.root_directory), [])

    def test_delete_accepts_normalised_checksum_text(self) -> None:
        """Rollback checksum input is trimmed and case-insensitive."""

        document = self.store_fixed()

        self.assertTrue(
            self.storage.delete(
                document.source_path,
                expected_checksum_sha256=(
                    f"  {document.checksum_sha256.upper()}  "
                ),
            )
        )

    def test_delete_refuses_checksum_mismatch(self) -> None:
        """Changed content remains preserved for investigation."""

        document = self.store_fixed()
        path = self.path_for(document)

        with self.assertRaisesRegex(
            DocumentStorageDeleteError,
            "checksum changed",
        ):
            self.storage.delete(
                document.source_path,
                expected_checksum_sha256=sha256(b"different").hexdigest(),
            )

        self.assertEqual(path.read_bytes(), DEFAULT_CONTENT)

    def test_delete_rejects_non_string_checksum(self) -> None:
        """Rollback checksums have explicit string semantics."""

        for value in (1, b"a" * 64, object()):
            with self.subTest(value=value):
                document = self.store_fixed()

                with self.assertRaisesRegex(
                    TypeError,
                    "expected_checksum_sha256 must be a string",
                ):
                    self.storage.delete(
                        document.source_path,
                        expected_checksum_sha256=value,
                    )

                self.assertTrue(self.path_for(document).exists())
                self.storage.delete(document.source_path)

    def test_delete_rejects_malformed_checksum(self) -> None:
        """Rollback checksums are exactly 64 hexadecimal characters."""

        for value in ("", "a" * 63, "a" * 65, "g" * 64):
            with self.subTest(value=value):
                document = self.store_fixed()

                with self.assertRaises(ValueError):
                    self.storage.delete(
                        document.source_path,
                        expected_checksum_sha256=value,
                    )

                self.assertTrue(self.path_for(document).exists())
                self.storage.delete(document.source_path)

    def test_delete_rejects_non_string_source_path(self) -> None:
        """Stored references cannot be arbitrary values."""

        for value in (None, 1, FIXED_STORAGE_ID):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    TypeError,
                    "source_path must be a string",
                ):
                    self.storage.delete(value)  # type: ignore[arg-type]

    def test_delete_rejects_malformed_source_paths(self) -> None:
        """Traversal, absolute paths, and alternate separators are refused."""

        invalid_paths = (
            "",
            "../manual.txt",
            "/12/34/12345678123456781234567812345678.txt",
            r"12\34\12345678123456781234567812345678.txt",
            "12/34/12345678123456781234567812345678.TXT",
            "12/34/12345678123456781234567812345678.tar.gz",
            "12/34/not-a-uuid.txt",
        )

        for source_path in invalid_paths:
            with self.subTest(source_path=source_path):
                with self.assertRaises(DocumentStoragePathError):
                    self.storage.delete(source_path)

    def test_delete_rejects_disallowed_suffix(self) -> None:
        """A valid-looking opaque key must use the configured allowlist."""

        storage = FilesystemDocumentStorage(
            FilesystemDocumentStorageConfig(
                root_directory=self.root_directory,
                allowed_suffixes={".txt"},
            )
        )

        with self.assertRaisesRegex(
            DocumentStoragePathError,
            "suffix.*not permitted",
        ):
            storage.delete(
                "12/34/12345678123456781234567812345678.pdf"
            )

    def test_delete_rejects_inconsistent_shards(self) -> None:
        """Opaque references must use identifier-derived shard paths."""

        with self.assertRaisesRegex(
            DocumentStoragePathError,
            "inconsistent.*shards",
        ):
            self.storage.delete(
                "00/00/12345678123456781234567812345678.txt"
            )

    def test_delete_missing_canonical_path_returns_false(self) -> None:
        """A canonical reference with no shard tree is idempotently absent."""

        self.assertFalse(self.storage.delete(FIXED_SOURCE_PATH))

    def test_delete_missing_file_in_existing_shards_returns_false(
        self,
    ) -> None:
        """A missing leaf beneath safe shards is idempotently absent."""

        (self.root_directory / "12" / "34").mkdir(parents=True)

        self.assertFalse(self.storage.delete(FIXED_SOURCE_PATH))

    def test_delete_rejects_symbolic_link_leaf(self) -> None:
        """Rollback never follows a leaf symlink."""

        outside = self.root_directory.parent / (
            f"{self.root_directory.name}-outside-leaf.txt"
        )
        outside.write_bytes(b"outside")
        target = self.root_directory / "12" / "34"
        target.mkdir(parents=True)
        link = target / (
            "12345678123456781234567812345678.txt"
        )
        link.symlink_to(outside)

        try:
            with self.assertRaisesRegex(
                DocumentStoragePathError,
                "symbolic link",
            ):
                self.storage.delete(FIXED_SOURCE_PATH)

            self.assertEqual(outside.read_bytes(), b"outside")
        finally:
            outside.unlink(missing_ok=True)

    def test_delete_rejects_symbolic_link_shard(self) -> None:
        """Rollback cannot traverse a shard symlink outside the root."""

        outside = self.root_directory.parent / (
            f"{self.root_directory.name}-outside-delete"
        )
        outside_target = outside / "34"
        outside_target.mkdir(parents=True)
        outside_file = outside_target / (
            "12345678123456781234567812345678.txt"
        )
        outside_file.write_bytes(b"outside")
        (self.root_directory / "12").symlink_to(
            outside,
            target_is_directory=True,
        )

        try:
            with self.assertRaises(DocumentStoragePathError):
                self.storage.delete(FIXED_SOURCE_PATH)

            self.assertEqual(outside_file.read_bytes(), b"outside")
        finally:
            outside_file.unlink(missing_ok=True)
            outside_target.rmdir()
            outside.rmdir()

    def test_delete_rejects_directory_leaf(self) -> None:
        """An opaque file reference cannot resolve to a directory."""

        directory = self.root_directory.joinpath(
            *FIXED_SOURCE_PATH.split("/")
        )
        directory.mkdir(parents=True)

        with self.assertRaisesRegex(
            DocumentStoragePathError,
            "not a regular file",
        ):
            self.storage.delete(FIXED_SOURCE_PATH)

    def test_delete_refuses_checksum_of_oversized_file(self) -> None:
        """Rollback does not hash content beyond its configured bound."""

        storage = FilesystemDocumentStorage(
            FilesystemDocumentStorageConfig(
                root_directory=self.root_directory,
                maximum_content_bytes=4,
            )
        )
        path = self.root_directory.joinpath(
            *FIXED_SOURCE_PATH.split("/")
        )
        path.parent.mkdir(parents=True)
        path.write_bytes(b"12345")

        with self.assertRaisesRegex(
            DocumentStorageDeleteError,
            "rollback limit",
        ):
            storage.delete(
                FIXED_SOURCE_PATH,
                expected_checksum_sha256=sha256(b"12345").hexdigest(),
            )

        self.assertEqual(path.read_bytes(), b"12345")

    def test_delete_handles_unlink_missing_race(self) -> None:
        """A concurrent prior removal remains idempotent."""

        document = self.store_fixed()

        with patch.object(
            Path,
            "unlink",
            side_effect=FileNotFoundError(),
        ):
            self.assertFalse(self.storage.delete(document.source_path))

    def test_delete_maps_unlink_error(self) -> None:
        """Unexpected unlink failures use the delete exception boundary."""

        document = self.store_fixed()

        with patch.object(
            Path,
            "unlink",
            side_effect=PermissionError("denied"),
        ):
            with self.assertRaisesRegex(
                DocumentStorageDeleteError,
                "could not be removed safely",
            ):
                self.storage.delete(document.source_path)

    def test_checksum_helper_calculates_exact_digest(self) -> None:
        """Guarded checksum reads return the authoritative digest."""

        source = FakeChecksumPath(
            declared_size=len(DEFAULT_CONTENT),
            content=DEFAULT_CONTENT,
        )

        self.assertEqual(
            self.storage._calculate_file_checksum(  # type: ignore[arg-type]
                source
            ),
            DEFAULT_CHECKSUM,
        )

    def test_checksum_helper_maps_stat_error(self) -> None:
        """Metadata inspection failures use the delete boundary."""

        source = FakeChecksumPath(
            stat_error=PermissionError("denied"),
        )

        with self.assertRaisesRegex(
            DocumentStorageDeleteError,
            "metadata could not be inspected",
        ):
            self.storage._calculate_file_checksum(  # type: ignore[arg-type]
                source
            )

    def test_checksum_helper_maps_open_error(self) -> None:
        """Stored-file read failures use the delete boundary."""

        source = FakeChecksumPath(
            declared_size=1,
            open_error=PermissionError("denied"),
        )

        with self.assertRaisesRegex(
            DocumentStorageDeleteError,
            "could not be verified",
        ):
            self.storage._calculate_file_checksum(  # type: ignore[arg-type]
                source
            )

    def test_checksum_helper_detects_size_change(self) -> None:
        """A file that shrinks during verification is preserved."""

        source = FakeChecksumPath(
            declared_size=10,
            content=b"short",
        )

        with self.assertRaisesRegex(
            DocumentStorageDeleteError,
            "changed during rollback verification",
        ):
            self.storage._calculate_file_checksum(  # type: ignore[arg-type]
                source
            )

    def test_checksum_helper_detects_growth_beyond_limit(self) -> None:
        """A file that grows while hashing cannot bypass the limit."""

        storage = FilesystemDocumentStorage(
            FilesystemDocumentStorageConfig(
                root_directory=self.root_directory,
                maximum_content_bytes=4,
                read_chunk_bytes=4,
            )
        )
        source = FakeChecksumPath(
            declared_size=4,
            content=b"12345",
        )

        with self.assertRaisesRegex(
            DocumentStorageDeleteError,
            "grew beyond",
        ):
            storage._calculate_file_checksum(  # type: ignore[arg-type]
                source
            )


class FilesystemDocumentStorageContractTests(TestCase):
    """Validate public exceptions and exports."""

    def test_exception_hierarchy_is_stable(self) -> None:
        """Callers can catch the shared storage boundary."""

        exception_types = (
            DocumentStorageConflictError,
            DocumentStorageContentError,
            DocumentStorageDeleteError,
            DocumentStorageEmptyError,
            DocumentStorageFilenameError,
            DocumentStoragePathError,
            DocumentStorageReadError,
            DocumentStorageTooLargeError,
            DocumentStorageWriteError,
        )

        for exception_type in exception_types:
            with self.subTest(exception_type=exception_type):
                self.assertTrue(
                    issubclass(
                        exception_type,
                        FilesystemDocumentStorageError,
                    )
                )

        self.assertTrue(
            issubclass(
                DocumentStorageEmptyError,
                DocumentStorageContentError,
            )
        )
        self.assertTrue(
            issubclass(
                DocumentStorageTooLargeError,
                DocumentStorageContentError,
            )
        )
        self.assertTrue(
            issubclass(
                DocumentStorageReadError,
                DocumentStorageContentError,
            )
        )

    def test_public_exports_are_complete(self) -> None:
        """The module exposes its supported transport-neutral contract."""

        self.assertEqual(
            set(storage_module.__all__),
            {
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
            },
        )
