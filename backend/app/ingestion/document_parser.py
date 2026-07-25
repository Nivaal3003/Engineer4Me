"""Document parsing services for the Engineer4Me ingestion pipeline.

This module converts supported source documents into the normalised
``ParsedDocument`` structure used by later ingestion stages.

The initial implementation intentionally uses Python's standard library only.
It supports:

- Plain-text documents
- Markdown-style text documents
- CSV and TSV tables
- JSON documents
- HTML documents
- XML documents

Binary office documents, PDFs and images are detected but rejected with a
structured unsupported-format error until dedicated parsers are introduced.
"""

from __future__ import annotations

import csv
import html
import io
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable, Sequence

from app.ingestion.document_models import (
    ContentBlockType,
    DocumentFormat,
    DocumentUpload,
    ExtractionMethod,
    ParsedContentBlock,
    ParsedDocument,
    ParsedPage,
    ParsedTable,
)


PARSER_NAME = "engineer4me-standard-document-parser"
PARSER_VERSION = "1.0.0"

_DEFAULT_MAX_DOCUMENT_SIZE_BYTES = 25 * 1024 * 1024
_DEFAULT_ENCODINGS = (
    "utf-8",
    "utf-8-sig",
    "utf-16",
    "utf-16-le",
    "utf-16-be",
    "cp1252",
    "latin-1",
)

_SUPPORTED_DOCUMENT_FORMATS = {
    DocumentFormat.TXT,
    DocumentFormat.CSV,
    DocumentFormat.JSON,
    DocumentFormat.HTML,
    DocumentFormat.XML,
}

_MARKDOWN_SUFFIXES = {".md", ".markdown", ".mdown", ".mkd"}
_TSV_SUFFIXES = {".tsv", ".tab"}

_HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_UNDERLINE_HEADING_PATTERN = re.compile(r"^[=-]{3,}\s*$")
_UNORDERED_LIST_PATTERN = re.compile(r"^\s*[-*+]\s+(.+?)\s*$")
_ORDERED_LIST_PATTERN = re.compile(r"^\s*\d+[.)]\s+(.+?)\s*$")
_SAFETY_PREFIX_PATTERN = re.compile(
    r"^\s*(danger|warning|caution|note)\s*[:\-]\s*(.+?)\s*$",
    re.IGNORECASE,
)
_HTML_HEADING_TAGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
_HTML_BLOCK_TAGS = {
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "caption",
    "dd",
    "div",
    "dl",
    "dt",
    "figcaption",
    "figure",
    "footer",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "td",
    "th",
    "tr",
    "ul",
}


class DocumentParserError(ValueError):
    """Base exception for document-parser failures."""


class EmptyDocumentError(DocumentParserError):
    """Raised when a document contains no bytes or useful content."""


class DocumentTooLargeError(DocumentParserError):
    """Raised when a document exceeds the configured parser size limit."""


class DocumentEncodingError(DocumentParserError):
    """Raised when document bytes cannot be decoded safely."""


class UnsupportedDocumentFormatError(DocumentParserError):
    """Raised when no parser is available for the supplied document format."""


class MalformedDocumentError(DocumentParserError):
    """Raised when structured document content is invalid."""


@dataclass(frozen=True, slots=True)
class DocumentParserConfig:
    """Runtime configuration for ``DocumentParser``."""

    max_document_size_bytes: int = _DEFAULT_MAX_DOCUMENT_SIZE_BYTES
    allowed_encodings: tuple[str, ...] = _DEFAULT_ENCODINGS
    reject_empty_documents: bool = True
    strip_null_bytes: bool = True
    maximum_csv_rows: int = 100_000
    maximum_csv_columns: int = 1_000

    def __post_init__(self) -> None:
        if self.max_document_size_bytes <= 0:
            raise ValueError("max_document_size_bytes must be greater than zero.")

        if not self.allowed_encodings:
            raise ValueError("At least one text encoding must be configured.")

        if self.maximum_csv_rows <= 0:
            raise ValueError("maximum_csv_rows must be greater than zero.")

        if self.maximum_csv_columns <= 0:
            raise ValueError("maximum_csv_columns must be greater than zero.")


@dataclass(frozen=True, slots=True)
class DecodedDocument:
    """Decoded text and the encoding selected by the parser."""

    text: str
    encoding: str


class _NormalisingHTMLParser(HTMLParser):
    """Small HTML parser that extracts readable text without dependencies."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._ignored_depth = 0
        self.title: str | None = None
        self._inside_title = False
        self._title_parts: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        del attrs
        normalised_tag = tag.lower()

        if normalised_tag in {"script", "style", "noscript"}:
            self._ignored_depth += 1
            return

        if self._ignored_depth:
            return

        if normalised_tag == "title":
            self._inside_title = True
            self._title_parts = []

        if normalised_tag in _HTML_BLOCK_TAGS:
            self._append_break()

        if normalised_tag in _HTML_HEADING_TAGS:
            self._append_break()

    def handle_endtag(self, tag: str) -> None:
        normalised_tag = tag.lower()

        if normalised_tag in {"script", "style", "noscript"}:
            self._ignored_depth = max(0, self._ignored_depth - 1)
            return

        if self._ignored_depth:
            return

        if normalised_tag == "title":
            self._inside_title = False
            title = _normalise_inline_text(" ".join(self._title_parts))
            self.title = title or None

        if (
            normalised_tag in _HTML_BLOCK_TAGS
            or normalised_tag in _HTML_HEADING_TAGS
        ):
            self._append_break()

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return

        cleaned = _normalise_inline_text(data)
        if not cleaned:
            return

        if self._inside_title:
            self._title_parts.append(cleaned)

        self._parts.append(cleaned)

    def handle_entityref(self, name: str) -> None:
        if not self._ignored_depth:
            self._parts.append(html.unescape(f"&{name};"))

    def handle_charref(self, name: str) -> None:
        if not self._ignored_depth:
            self._parts.append(html.unescape(f"&#{name};"))

    def text(self) -> str:
        combined = " ".join(self._parts)
        combined = re.sub(r"[ \t]+\n", "\n", combined)
        combined = re.sub(r"\n[ \t]+", "\n", combined)
        combined = re.sub(r"[ \t]{2,}", " ", combined)
        combined = re.sub(r"\n{3,}", "\n\n", combined)
        return combined.strip()

    def _append_break(self) -> None:
        if self._parts and self._parts[-1] != "\n":
            self._parts.append("\n")


class DocumentParser:
    """Parse supported uploaded documents into normalised ingestion models."""

    def __init__(
        self,
        config: DocumentParserConfig | None = None,
    ) -> None:
        self.config = config or DocumentParserConfig()

    @property
    def parser_name(self) -> str:
        return PARSER_NAME

    @property
    def parser_version(self) -> str:
        return PARSER_VERSION

    def supports(self, upload: DocumentUpload) -> bool:
        """Return whether this parser can process the supplied upload."""

        effective_format = self.resolve_document_format(upload)

        return (
            effective_format in _SUPPORTED_DOCUMENT_FORMATS
            or self._is_markdown(upload.filename)
            or self._is_tsv(upload.filename)
        )

    def resolve_document_format(
        self,
        upload: DocumentUpload,
    ) -> DocumentFormat:
        """Resolve the effective format from metadata and filename."""

        suffix = Path(upload.filename).suffix.lower()

        if suffix in _MARKDOWN_SUFFIXES:
            return DocumentFormat.TXT

        if suffix in _TSV_SUFFIXES:
            return DocumentFormat.CSV

        if upload.document_format != DocumentFormat.UNKNOWN:
            return upload.document_format

        suffix_mapping = {
            ".txt": DocumentFormat.TXT,
            ".csv": DocumentFormat.CSV,
            ".json": DocumentFormat.JSON,
            ".html": DocumentFormat.HTML,
            ".htm": DocumentFormat.HTML,
            ".xml": DocumentFormat.XML,
        }

        return suffix_mapping.get(suffix, DocumentFormat.UNKNOWN)

    def parse(
        self,
        upload: DocumentUpload,
        content: bytes,
    ) -> ParsedDocument:
        """Parse uploaded document bytes.

        Args:
            upload: Upload metadata associated with the content.
            content: Raw file bytes.

        Returns:
            A normalised ``ParsedDocument``.

        Raises:
            EmptyDocumentError: If the source document is empty.
            DocumentTooLargeError: If the file exceeds the configured limit.
            UnsupportedDocumentFormatError: If no parser is available.
            DocumentEncodingError: If text decoding fails.
            MalformedDocumentError: If structured content is invalid.
        """

        self._validate_input(upload, content)

        effective_format = self.resolve_document_format(upload)

        if not self.supports(upload):
            raise UnsupportedDocumentFormatError(
                "No standard parser is available for "
                f"document format '{effective_format.value}' "
                f"and filename '{upload.filename}'."
            )

        decoded = self.decode_text(content)
        text = decoded.text

        if self.config.strip_null_bytes:
            text = text.replace("\x00", "")

        if self.config.reject_empty_documents and not text.strip():
            raise EmptyDocumentError(
                f"Document '{upload.filename}' contains no readable text."
            )

        if self._is_markdown(upload.filename):
            return self._parse_text_document(
                upload=upload,
                text=text,
                encoding=decoded.encoding,
                markdown=True,
            )

        if effective_format == DocumentFormat.TXT:
            return self._parse_text_document(
                upload=upload,
                text=text,
                encoding=decoded.encoding,
                markdown=False,
            )

        if effective_format == DocumentFormat.CSV:
            return self._parse_delimited_document(
                upload=upload,
                text=text,
                encoding=decoded.encoding,
            )

        if effective_format == DocumentFormat.JSON:
            return self._parse_json_document(
                upload=upload,
                text=text,
                encoding=decoded.encoding,
            )

        if effective_format == DocumentFormat.HTML:
            return self._parse_html_document(
                upload=upload,
                text=text,
                encoding=decoded.encoding,
            )

        if effective_format == DocumentFormat.XML:
            return self._parse_xml_document(
                upload=upload,
                text=text,
                encoding=decoded.encoding,
            )

        raise UnsupportedDocumentFormatError(
            f"Unsupported document format: {effective_format.value}."
        )

    def decode_text(self, content: bytes) -> DecodedDocument:
        """Decode source bytes using the configured encoding sequence."""

        for encoding in self.config.allowed_encodings:
            try:
                return DecodedDocument(
                    text=content.decode(encoding),
                    encoding=encoding,
                )
            except (UnicodeDecodeError, LookupError):
                continue

        raise DocumentEncodingError(
            "Document content could not be decoded using any configured "
            f"encoding: {', '.join(self.config.allowed_encodings)}."
        )

    def _validate_input(
        self,
        upload: DocumentUpload,
        content: bytes,
    ) -> None:
        if not isinstance(content, bytes):
            raise TypeError("Document content must be supplied as bytes.")

        if not content and self.config.reject_empty_documents:
            raise EmptyDocumentError(
                f"Document '{upload.filename}' contains no data."
            )

        actual_size = len(content)

        if actual_size > self.config.max_document_size_bytes:
            raise DocumentTooLargeError(
                f"Document '{upload.filename}' is {actual_size} bytes, "
                "which exceeds the configured limit of "
                f"{self.config.max_document_size_bytes} bytes."
            )

        if upload.size_bytes != actual_size:
            # Size mismatches are retained as parser warnings rather than
            # rejected because upload metadata may be generated before archive
            # extraction or transport normalisation.
            return

    def _parse_text_document(
        self,
        upload: DocumentUpload,
        text: str,
        encoding: str,
        *,
        markdown: bool,
    ) -> ParsedDocument:
        normalised_text = _normalise_document_text(text)
        blocks = _extract_text_blocks(
            normalised_text,
            markdown=markdown,
        )

        title = _derive_title_from_blocks(
            blocks,
            fallback_filename=upload.filename,
        )

        warnings = self._size_mismatch_warnings(upload, text, encoding)

        page = ParsedPage(
            page_number=1,
            text=normalised_text,
            blocks=blocks,
            extraction_method=ExtractionMethod.NATIVE_TEXT,
            extraction_confidence=1.0,
            warnings=[],
        )

        return ParsedDocument(
            document_id=upload.document_id,
            title=title,
            pages=[page],
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            extraction_method=ExtractionMethod.NATIVE_TEXT,
            extraction_confidence=1.0,
            warnings=warnings,
            errors=[],
            parser_metadata={
                "source_format": upload.document_format.value,
                "effective_format": DocumentFormat.TXT.value,
                "encoding": encoding,
                "markdown": markdown,
                "block_count": len(blocks),
            },
        )

    def _parse_delimited_document(
        self,
        upload: DocumentUpload,
        text: str,
        encoding: str,
    ) -> ParsedDocument:
        delimiter = self._detect_delimiter(upload.filename, text)

        try:
            reader = csv.reader(
                io.StringIO(text),
                delimiter=delimiter,
            )
            raw_rows = [
                [_normalise_inline_text(cell) for cell in row]
                for row in reader
            ]
        except csv.Error as exc:
            raise MalformedDocumentError(
                f"Delimited document '{upload.filename}' is invalid: {exc}"
            ) from exc

        rows = [row for row in raw_rows if any(cell for cell in row)]

        if not rows:
            raise EmptyDocumentError(
                f"Delimited document '{upload.filename}' contains no rows."
            )

        if len(rows) > self.config.maximum_csv_rows:
            raise MalformedDocumentError(
                f"Delimited document contains {len(rows)} rows, exceeding "
                f"the configured maximum of {self.config.maximum_csv_rows}."
            )

        largest_column_count = max(len(row) for row in rows)

        if largest_column_count > self.config.maximum_csv_columns:
            raise MalformedDocumentError(
                "Delimited document contains "
                f"{largest_column_count} columns, exceeding the configured "
                f"maximum of {self.config.maximum_csv_columns}."
            )

        padded_rows = [
            row + [""] * (largest_column_count - len(row))
            for row in rows
        ]

        headers = padded_rows[0]
        data_rows = padded_rows[1:]

        table = ParsedTable(
            headers=headers,
            rows=data_rows,
        )

        table_text = _table_to_text(headers, data_rows)

        block = ParsedContentBlock(
            block_type=ContentBlockType.TABLE,
            text=table_text,
            page_number=1,
            section_path=[],
            sequence_number=1,
            table=table,
            extraction_method=ExtractionMethod.TABLE_EXTRACTION,
            extraction_confidence=1.0,
            attributes={
                "delimiter": delimiter,
                "header_row_assumed": True,
            },
        )

        page = ParsedPage(
            page_number=1,
            text=table_text,
            blocks=[block],
            extraction_method=ExtractionMethod.TABLE_EXTRACTION,
            extraction_confidence=1.0,
            warnings=[],
        )

        warnings = self._size_mismatch_warnings(upload, text, encoding)

        if any(len(row) != largest_column_count for row in rows):
            warnings.append(
                "Rows contained different column counts and were padded "
                "with empty cells."
            )

        return ParsedDocument(
            document_id=upload.document_id,
            title=Path(upload.filename).stem,
            pages=[page],
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            extraction_method=ExtractionMethod.TABLE_EXTRACTION,
            extraction_confidence=1.0,
            warnings=warnings,
            errors=[],
            parser_metadata={
                "source_format": upload.document_format.value,
                "effective_format": DocumentFormat.CSV.value,
                "encoding": encoding,
                "delimiter": delimiter,
                "row_count": len(data_rows),
                "column_count": largest_column_count,
            },
        )

    def _parse_json_document(
        self,
        upload: DocumentUpload,
        text: str,
        encoding: str,
    ) -> ParsedDocument:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise MalformedDocumentError(
                f"JSON document '{upload.filename}' is invalid at "
                f"line {exc.lineno}, column {exc.colno}: {exc.msg}"
            ) from exc

        formatted_text = json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )

        blocks = _json_to_blocks(data)

        if not blocks:
            blocks = [
                ParsedContentBlock(
                    block_type=ContentBlockType.CODE,
                    text=formatted_text,
                    page_number=1,
                    section_path=[],
                    sequence_number=1,
                    extraction_method=ExtractionMethod.NATIVE_TEXT,
                    extraction_confidence=1.0,
                    attributes={"language": "json"},
                )
            ]

        page = ParsedPage(
            page_number=1,
            text=formatted_text,
            blocks=blocks,
            extraction_method=ExtractionMethod.NATIVE_TEXT,
            extraction_confidence=1.0,
            warnings=[],
        )

        title = _extract_json_title(data) or Path(upload.filename).stem

        return ParsedDocument(
            document_id=upload.document_id,
            title=title,
            pages=[page],
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            extraction_method=ExtractionMethod.NATIVE_TEXT,
            extraction_confidence=1.0,
            warnings=self._size_mismatch_warnings(upload, text, encoding),
            errors=[],
            parser_metadata={
                "source_format": upload.document_format.value,
                "effective_format": DocumentFormat.JSON.value,
                "encoding": encoding,
                "root_type": type(data).__name__,
                "block_count": len(blocks),
            },
        )

    def _parse_html_document(
        self,
        upload: DocumentUpload,
        text: str,
        encoding: str,
    ) -> ParsedDocument:
        parser = _NormalisingHTMLParser()

        try:
            parser.feed(text)
            parser.close()
        except Exception as exc:
            raise MalformedDocumentError(
                f"HTML document '{upload.filename}' could not be parsed: {exc}"
            ) from exc

        extracted_text = _normalise_document_text(parser.text())

        if self.config.reject_empty_documents and not extracted_text:
            raise EmptyDocumentError(
                f"HTML document '{upload.filename}' contains no readable text."
            )

        blocks = _extract_text_blocks(
            extracted_text,
            markdown=False,
        )

        page = ParsedPage(
            page_number=1,
            text=extracted_text,
            blocks=blocks,
            extraction_method=ExtractionMethod.NATIVE_TEXT,
            extraction_confidence=0.98,
            warnings=[],
        )

        return ParsedDocument(
            document_id=upload.document_id,
            title=parser.title or Path(upload.filename).stem,
            pages=[page],
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            extraction_method=ExtractionMethod.NATIVE_TEXT,
            extraction_confidence=0.98,
            warnings=self._size_mismatch_warnings(upload, text, encoding),
            errors=[],
            parser_metadata={
                "source_format": upload.document_format.value,
                "effective_format": DocumentFormat.HTML.value,
                "encoding": encoding,
                "html_title_found": parser.title is not None,
                "block_count": len(blocks),
            },
        )

    def _parse_xml_document(
        self,
        upload: DocumentUpload,
        text: str,
        encoding: str,
    ) -> ParsedDocument:
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise MalformedDocumentError(
                f"XML document '{upload.filename}' is invalid: {exc}"
            ) from exc

        blocks: list[ParsedContentBlock] = []
        sequence_number = 1

        for element, section_path in _walk_xml_elements(root):
            element_text = _normalise_inline_text(element.text or "")

            if not element_text:
                continue

            blocks.append(
                ParsedContentBlock(
                    block_type=ContentBlockType.PARAGRAPH,
                    text=element_text,
                    page_number=1,
                    section_path=section_path,
                    sequence_number=sequence_number,
                    extraction_method=ExtractionMethod.NATIVE_TEXT,
                    extraction_confidence=1.0,
                    attributes={
                        "xml_tag": _strip_xml_namespace(element.tag),
                        "xml_attributes": dict(element.attrib),
                    },
                )
            )
            sequence_number += 1

        extracted_text = "\n\n".join(block.text for block in blocks)

        if self.config.reject_empty_documents and not extracted_text:
            raise EmptyDocumentError(
                f"XML document '{upload.filename}' contains no readable text."
            )

        page = ParsedPage(
            page_number=1,
            text=extracted_text,
            blocks=blocks,
            extraction_method=ExtractionMethod.NATIVE_TEXT,
            extraction_confidence=1.0,
            warnings=[],
        )

        return ParsedDocument(
            document_id=upload.document_id,
            title=_strip_xml_namespace(root.tag),
            pages=[page],
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            extraction_method=ExtractionMethod.NATIVE_TEXT,
            extraction_confidence=1.0,
            warnings=self._size_mismatch_warnings(upload, text, encoding),
            errors=[],
            parser_metadata={
                "source_format": upload.document_format.value,
                "effective_format": DocumentFormat.XML.value,
                "encoding": encoding,
                "root_tag": _strip_xml_namespace(root.tag),
                "block_count": len(blocks),
            },
        )

    def _detect_delimiter(
        self,
        filename: str,
        text: str,
    ) -> str:
        if self._is_tsv(filename):
            return "\t"

        sample = text[:8192]

        try:
            dialect = csv.Sniffer().sniff(
                sample,
                delimiters=",;\t|",
            )
            return dialect.delimiter
        except csv.Error:
            return ","

    def _size_mismatch_warnings(
        self,
        upload: DocumentUpload,
        text: str,
        encoding: str,
    ) -> list[str]:
        try:
            decoded_size = len(text.encode(encoding))
        except (LookupError, UnicodeEncodeError):
            return []

        if decoded_size == upload.size_bytes:
            return []

        return [
            "Upload size metadata does not match the decoded source size: "
            f"metadata={upload.size_bytes}, decoded={decoded_size}."
        ]

    @staticmethod
    def _is_markdown(filename: str) -> bool:
        return Path(filename).suffix.lower() in _MARKDOWN_SUFFIXES

    @staticmethod
    def _is_tsv(filename: str) -> bool:
        return Path(filename).suffix.lower() in _TSV_SUFFIXES


def parse_document(
    upload: DocumentUpload,
    content: bytes,
    *,
    config: DocumentParserConfig | None = None,
) -> ParsedDocument:
    """Convenience function for parsing a single document."""

    return DocumentParser(config=config).parse(upload, content)


def _normalise_document_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(line.rstrip() for line in text.splitlines())
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _normalise_inline_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _extract_text_blocks(
    text: str,
    *,
    markdown: bool,
) -> list[ParsedContentBlock]:
    lines = text.splitlines()
    blocks: list[ParsedContentBlock] = []
    section_path: list[str] = []
    sequence_number = 1
    paragraph_lines: list[str] = []
    list_lines: list[str] = []
    code_lines: list[str] = []
    inside_code_block = False
    code_language: str | None = None

    def append_block(
        block_type: ContentBlockType,
        block_text: str,
        *,
        attributes: dict[str, Any] | None = None,
        block_section_path: Sequence[str] | None = None,
    ) -> None:
        nonlocal sequence_number

        cleaned_text = block_text.strip()
        if not cleaned_text:
            return

        blocks.append(
            ParsedContentBlock(
                block_type=block_type,
                text=cleaned_text,
                page_number=1,
                section_path=list(
                    section_path
                    if block_section_path is None
                    else block_section_path
                ),
                sequence_number=sequence_number,
                extraction_method=ExtractionMethod.NATIVE_TEXT,
                extraction_confidence=1.0,
                attributes=attributes or {},
            )
        )
        sequence_number += 1

    def flush_paragraph() -> None:
        if not paragraph_lines:
            return

        paragraph = " ".join(
            line.strip() for line in paragraph_lines if line.strip()
        )
        paragraph_lines.clear()

        safety_match = _SAFETY_PREFIX_PATTERN.match(paragraph)

        if safety_match:
            safety_label = safety_match.group(1).lower()
            safety_text = safety_match.group(2)

            safety_type_mapping = {
                "danger": ContentBlockType.DANGER,
                "warning": ContentBlockType.WARNING,
                "caution": ContentBlockType.CAUTION,
                "note": ContentBlockType.NOTE,
            }

            append_block(
                safety_type_mapping[safety_label],
                safety_text,
                attributes={"safety_label": safety_label},
            )
            return

        append_block(ContentBlockType.PARAGRAPH, paragraph)

    def flush_list() -> None:
        if not list_lines:
            return

        append_block(
            ContentBlockType.LIST,
            "\n".join(list_lines),
            attributes={"item_count": len(list_lines)},
        )
        list_lines.clear()

    def flush_code() -> None:
        if not code_lines:
            return

        attributes: dict[str, Any] = {}
        if code_language:
            attributes["language"] = code_language

        append_block(
            ContentBlockType.CODE,
            "\n".join(code_lines),
            attributes=attributes,
        )
        code_lines.clear()

    index = 0

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        if markdown and stripped.startswith("```"):
            flush_paragraph()
            flush_list()

            if inside_code_block:
                flush_code()
                inside_code_block = False
                code_language = None
            else:
                inside_code_block = True
                code_language = stripped[3:].strip() or None

            index += 1
            continue

        if inside_code_block:
            code_lines.append(line)
            index += 1
            continue

        if not stripped:
            flush_paragraph()
            flush_list()
            index += 1
            continue

        heading_match = _HEADING_PATTERN.match(stripped) if markdown else None

        if heading_match:
            flush_paragraph()
            flush_list()

            heading_level = len(heading_match.group(1))
            heading_text = heading_match.group(2).strip()
            section_path = section_path[: heading_level - 1]
            section_path.append(heading_text)

            append_block(
                (
                    ContentBlockType.TITLE
                    if heading_level == 1 and not blocks
                    else ContentBlockType.HEADING
                ),
                heading_text,
                attributes={"heading_level": heading_level},
            )
            index += 1
            continue

        if (
            markdown
            and index + 1 < len(lines)
            and _UNDERLINE_HEADING_PATTERN.match(lines[index + 1].strip())
        ):
            flush_paragraph()
            flush_list()

            underline = lines[index + 1].strip()
            heading_level = 1 if underline.startswith("=") else 2
            heading_text = stripped

            section_path = section_path[: heading_level - 1]
            section_path.append(heading_text)

            append_block(
                (
                    ContentBlockType.TITLE
                    if heading_level == 1 and not blocks
                    else ContentBlockType.HEADING
                ),
                heading_text,
                attributes={"heading_level": heading_level},
            )
            index += 2
            continue

        unordered_match = _UNORDERED_LIST_PATTERN.match(line)
        ordered_match = _ORDERED_LIST_PATTERN.match(line)

        if unordered_match or ordered_match:
            flush_paragraph()
            item_text = (
                unordered_match.group(1)
                if unordered_match
                else ordered_match.group(1)
            )
            list_lines.append(item_text)
            index += 1
            continue

        flush_list()
        paragraph_lines.append(stripped)
        index += 1

    flush_paragraph()
    flush_list()

    if inside_code_block:
        flush_code()

    if not blocks and text.strip():
        append_block(ContentBlockType.PARAGRAPH, text.strip())

    return blocks


def _derive_title_from_blocks(
    blocks: Sequence[ParsedContentBlock],
    *,
    fallback_filename: str,
) -> str:
    for block in blocks:
        if block.block_type in {
            ContentBlockType.TITLE,
            ContentBlockType.HEADING,
        }:
            return block.text[:500]

    for block in blocks:
        if block.text:
            first_line = block.text.splitlines()[0].strip()
            if first_line:
                return first_line[:500]

    return Path(fallback_filename).stem


def _table_to_text(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
) -> str:
    lines = [" | ".join(headers)]
    lines.extend(" | ".join(row) for row in rows)
    return "\n".join(lines).strip()


def _json_to_blocks(data: Any) -> list[ParsedContentBlock]:
    blocks: list[ParsedContentBlock] = []
    sequence_number = 1

    def add_block(
        block_type: ContentBlockType,
        text: str,
        section_path: Sequence[str],
        attributes: dict[str, Any],
    ) -> None:
        nonlocal sequence_number

        blocks.append(
            ParsedContentBlock(
                block_type=block_type,
                text=text,
                page_number=1,
                section_path=list(section_path),
                sequence_number=sequence_number,
                extraction_method=ExtractionMethod.NATIVE_TEXT,
                extraction_confidence=1.0,
                attributes=attributes,
            )
        )
        sequence_number += 1

    def walk(value: Any, path: list[str]) -> None:
        if isinstance(value, dict):
            for key, child_value in value.items():
                key_text = str(key)
                child_path = [*path, key_text]

                if isinstance(child_value, (dict, list)):
                    add_block(
                        ContentBlockType.HEADING,
                        key_text,
                        path,
                        {
                            "json_path": child_path,
                            "json_type": type(child_value).__name__,
                        },
                    )
                    walk(child_value, child_path)
                else:
                    add_block(
                        ContentBlockType.PARAGRAPH,
                        f"{key_text}: {_json_scalar_to_text(child_value)}",
                        path,
                        {
                            "json_path": child_path,
                            "json_type": type(child_value).__name__,
                        },
                    )
            return

        if isinstance(value, list):
            scalar_items = [
                child_value
                for child_value in value
                if not isinstance(child_value, (dict, list))
            ]

            if len(scalar_items) == len(value):
                add_block(
                    ContentBlockType.LIST,
                    "\n".join(
                        _json_scalar_to_text(item)
                        for item in scalar_items
                    ),
                    path,
                    {
                        "json_path": path,
                        "json_type": "list",
                        "item_count": len(value),
                    },
                )
                return

            for index, child_value in enumerate(value):
                child_path = [*path, str(index)]
                walk(child_value, child_path)
            return

        add_block(
            ContentBlockType.PARAGRAPH,
            _json_scalar_to_text(value),
            path,
            {
                "json_path": path,
                "json_type": type(value).__name__,
            },
        )

    walk(data, [])
    return blocks


def _json_scalar_to_text(value: Any) -> str:
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    return str(value)


def _extract_json_title(data: Any) -> str | None:
    if not isinstance(data, dict):
        return None

    for key in ("title", "name", "document_title", "product_name"):
        value = data.get(key)

        if isinstance(value, str) and value.strip():
            return value.strip()[:500]

    return None


def _walk_xml_elements(
    root: ET.Element,
) -> Iterable[tuple[ET.Element, list[str]]]:
    def walk(
        element: ET.Element,
        path: list[str],
    ) -> Iterable[tuple[ET.Element, list[str]]]:
        tag = _strip_xml_namespace(element.tag)
        current_path = [*path, tag]

        yield element, current_path

        for child in list(element):
            yield from walk(child, current_path)

    yield from walk(root, [])


def _strip_xml_namespace(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", maxsplit=1)[1]

    return tag
