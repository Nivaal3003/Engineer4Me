"""Tests for the Engineer4Me standard document parser."""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.ingestion.document_models import (
    ContentBlockType,
    DocumentFormat,
    DocumentUpload,
    ExtractionMethod,
)
from app.ingestion.document_parser import (
    PARSER_NAME,
    PARSER_VERSION,
    DecodedDocument,
    DocumentEncodingError,
    DocumentParser,
    DocumentParserConfig,
    DocumentTooLargeError,
    EmptyDocumentError,
    MalformedDocumentError,
    UnsupportedDocumentFormatError,
    parse_document,
)


def make_upload(
    *,
    filename: str = "document.txt",
    document_format: DocumentFormat = DocumentFormat.TXT,
    content: bytes = b"Engineer4Me",
    size_bytes: int | None = None,
) -> DocumentUpload:
    """Create isolated upload metadata for parser tests."""

    return DocumentUpload.model_construct(
        document_id=uuid4(),
        filename=filename,
        document_format=document_format,
        media_type=None,
        size_bytes=len(content) if size_bytes is None else size_bytes,
        storage_key=f"tests/{filename}",
        checksum_sha256="0" * 64,
        source=None,
        original_filename=filename,
        password_protected=False,
        archive_member_count=None,
        metadata={},
    )


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_default_parser_configuration():
    config = DocumentParserConfig()

    assert config.max_document_size_bytes == 25 * 1024 * 1024
    assert "utf-8" in config.allowed_encodings
    assert "cp1252" in config.allowed_encodings
    assert config.reject_empty_documents is True
    assert config.strip_null_bytes is True
    assert config.maximum_csv_rows == 100_000
    assert config.maximum_csv_columns == 1_000


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("max_document_size_bytes", 0),
        ("max_document_size_bytes", -1),
        ("maximum_csv_rows", 0),
        ("maximum_csv_rows", -1),
        ("maximum_csv_columns", 0),
        ("maximum_csv_columns", -1),
    ],
)
def test_parser_configuration_rejects_non_positive_limits(
    field_name,
    field_value,
):
    kwargs = {field_name: field_value}

    with pytest.raises(ValueError):
        DocumentParserConfig(**kwargs)


def test_parser_configuration_requires_an_encoding():
    with pytest.raises(
        ValueError,
        match="At least one text encoding",
    ):
        DocumentParserConfig(allowed_encodings=())


def test_parser_exposes_name_and_version():
    parser = DocumentParser()

    assert parser.parser_name == PARSER_NAME
    assert parser.parser_version == PARSER_VERSION
    assert PARSER_NAME == "engineer4me-standard-document-parser"
    assert PARSER_VERSION == "1.0.0"


def test_parser_uses_provided_configuration():
    config = DocumentParserConfig(max_document_size_bytes=123)
    parser = DocumentParser(config=config)

    assert parser.config is config
    assert parser.config.max_document_size_bytes == 123


# ---------------------------------------------------------------------------
# Format support and resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "document_format",
    [
        DocumentFormat.TXT,
        DocumentFormat.CSV,
        DocumentFormat.JSON,
        DocumentFormat.HTML,
        DocumentFormat.XML,
    ],
)
def test_parser_supports_standard_text_formats(document_format):
    upload = make_upload(document_format=document_format)

    assert DocumentParser().supports(upload) is True


@pytest.mark.parametrize(
    ("filename", "document_format"),
    [
        ("manual.md", DocumentFormat.UNKNOWN),
        ("manual.markdown", DocumentFormat.UNKNOWN),
        ("manual.mdown", DocumentFormat.UNKNOWN),
        ("manual.mkd", DocumentFormat.UNKNOWN),
        ("values.tsv", DocumentFormat.UNKNOWN),
        ("values.tab", DocumentFormat.UNKNOWN),
    ],
)
def test_parser_supports_markdown_and_tsv_suffixes(
    filename,
    document_format,
):
    upload = make_upload(
        filename=filename,
        document_format=document_format,
    )

    assert DocumentParser().supports(upload) is True


@pytest.mark.parametrize(
    "document_format",
    [
        DocumentFormat.PDF,
        DocumentFormat.DOC,
        DocumentFormat.DOCX,
        DocumentFormat.XLS,
        DocumentFormat.XLSX,
        DocumentFormat.JPG,
        DocumentFormat.PNG,
        DocumentFormat.ZIP,
    ],
)
def test_parser_does_not_support_binary_formats(document_format):
    upload = make_upload(document_format=document_format)

    assert DocumentParser().supports(upload) is False


@pytest.mark.parametrize(
    ("filename", "expected_format"),
    [
        ("document.txt", DocumentFormat.TXT),
        ("table.csv", DocumentFormat.CSV),
        ("data.json", DocumentFormat.JSON),
        ("page.html", DocumentFormat.HTML),
        ("page.htm", DocumentFormat.HTML),
        ("data.xml", DocumentFormat.XML),
        ("manual.md", DocumentFormat.TXT),
        ("table.tsv", DocumentFormat.CSV),
        ("unknown.bin", DocumentFormat.UNKNOWN),
    ],
)
def test_parser_resolves_unknown_format_from_filename(
    filename,
    expected_format,
):
    upload = make_upload(
        filename=filename,
        document_format=DocumentFormat.UNKNOWN,
    )

    result = DocumentParser().resolve_document_format(upload)

    assert result == expected_format


def test_explicit_format_is_preferred_for_normal_suffix():
    upload = make_upload(
        filename="document.data",
        document_format=DocumentFormat.JSON,
    )

    assert (
        DocumentParser().resolve_document_format(upload)
        == DocumentFormat.JSON
    )


def test_markdown_suffix_overrides_unknown_format():
    upload = make_upload(
        filename="manual.md",
        document_format=DocumentFormat.UNKNOWN,
    )

    assert (
        DocumentParser().resolve_document_format(upload)
        == DocumentFormat.TXT
    )


def test_tsv_suffix_resolves_as_csv():
    upload = make_upload(
        filename="measurements.tsv",
        document_format=DocumentFormat.UNKNOWN,
    )

    assert (
        DocumentParser().resolve_document_format(upload)
        == DocumentFormat.CSV
    )


# ---------------------------------------------------------------------------
# Decoding and validation
# ---------------------------------------------------------------------------


def test_decode_utf8_text():
    decoded = DocumentParser().decode_text(
        "Temperature ?C".encode("utf-8")
    )

    assert isinstance(decoded, DecodedDocument)
    assert decoded.text == "Temperature ?C"
    assert decoded.encoding == "utf-8"


def test_decode_utf16_text():
    decoded = DocumentParser().decode_text(
        "Pressure measurement".encode("utf-16")
    )

    assert decoded.text == "Pressure measurement"
    assert decoded.encoding in {
        "utf-16",
        "utf-16-le",
        "utf-16-be",
    }


def test_decode_cp1252_text():
    config = DocumentParserConfig(
        allowed_encodings=("utf-8", "cp1252"),
    )

    content = b"Valve \x96 closed"
    decoded = DocumentParser(config).decode_text(content)

    assert decoded.text == "Valve \u2013 closed"
    assert decoded.encoding == "cp1252"


def test_decode_raises_when_configured_encodings_fail():
    config = DocumentParserConfig(
        allowed_encodings=("utf-8",),
    )

    with pytest.raises(DocumentEncodingError):
        DocumentParser(config).decode_text(b"\xff\xfe\xfa")


def test_parse_requires_bytes():
    upload = make_upload()

    with pytest.raises(
        TypeError,
        match="must be supplied as bytes",
    ):
        DocumentParser().parse(upload, "not bytes")


def test_parse_rejects_empty_bytes():
    upload = make_upload(content=b"")

    with pytest.raises(
        EmptyDocumentError,
        match="contains no data",
    ):
        DocumentParser().parse(upload, b"")


def test_parse_rejects_whitespace_only_document():
    content = b"   \n\t  "
    upload = make_upload(content=content)

    with pytest.raises(
        EmptyDocumentError,
        match="contains no readable text",
    ):
        DocumentParser().parse(upload, content)


def test_parse_can_allow_empty_document():
    config = DocumentParserConfig(
        reject_empty_documents=False,
    )
    upload = make_upload(
        filename="empty.txt",
        content=b"",
    )

    result = DocumentParser(config).parse(upload, b"")

    assert result.title == "empty"
    assert result.full_text == ""
    assert result.page_count == 1
    assert result.pages[0].blocks == []


def test_parse_rejects_document_above_size_limit():
    content = b"123456"
    config = DocumentParserConfig(
        max_document_size_bytes=5,
    )
    upload = make_upload(content=content)

    with pytest.raises(
        DocumentTooLargeError,
        match="exceeds the configured limit",
    ):
        DocumentParser(config).parse(upload, content)


def test_parse_rejects_unsupported_format_before_decoding():
    content = b"%PDF-binary-content"
    upload = make_upload(
        filename="manual.pdf",
        document_format=DocumentFormat.PDF,
        content=content,
    )

    with pytest.raises(
        UnsupportedDocumentFormatError,
        match="No standard parser is available",
    ):
        DocumentParser().parse(upload, content)


def test_null_bytes_are_removed_by_default():
    content = b"Pressure\x00 transmitter"
    upload = make_upload(content=content)

    result = DocumentParser().parse(upload, content)

    assert "\x00" not in result.full_text
    assert result.full_text == "Pressure transmitter"


def test_null_bytes_can_be_preserved():
    content = b"Pressure\x00 transmitter"
    config = DocumentParserConfig(
        strip_null_bytes=False,
    )
    upload = make_upload(content=content)

    result = DocumentParser(config).parse(upload, content)

    assert "\x00" in result.full_text


def test_upload_size_mismatch_creates_warning():
    content = b"Engineer4Me"
    upload = make_upload(
        content=content,
        size_bytes=999,
    )

    result = DocumentParser().parse(upload, content)

    assert len(result.warnings) == 1
    assert "Upload size metadata does not match" in result.warnings[0]
    assert "metadata=999" in result.warnings[0]


def test_matching_upload_size_does_not_create_warning():
    content = b"Engineer4Me"
    upload = make_upload(content=content)

    result = DocumentParser().parse(upload, content)

    assert result.warnings == []


# ---------------------------------------------------------------------------
# Plain-text parsing
# ---------------------------------------------------------------------------


def test_parse_plain_text_document():
    content = (
        b"Pressure Transmitter\n\n"
        b"The device measures process pressure."
    )
    upload = make_upload(
        filename="pressure.txt",
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert result.document_id == upload.document_id
    assert result.title == "Pressure Transmitter"
    assert result.page_count == 1
    assert result.full_text == (
        "Pressure Transmitter\n\n"
        "The device measures process pressure."
    )
    assert result.character_count == len(result.full_text)
    assert result.word_count == 7
    assert result.parser_name == PARSER_NAME
    assert result.parser_version == PARSER_VERSION
    assert result.extraction_method == ExtractionMethod.NATIVE_TEXT
    assert result.extraction_confidence == 1.0
    assert result.errors == []


def test_plain_text_creates_paragraph_blocks():
    content = b"First paragraph.\n\nSecond paragraph."
    upload = make_upload(content=content)

    result = DocumentParser().parse(upload, content)
    blocks = result.pages[0].blocks

    assert len(blocks) == 2
    assert blocks[0].block_type == ContentBlockType.PARAGRAPH
    assert blocks[0].text == "First paragraph."
    assert blocks[1].text == "Second paragraph."
    assert [block.sequence_number for block in blocks] == [1, 2]


def test_plain_text_normalises_newlines():
    content = b"Line one.\r\n\r\n\r\n\r\nLine two.\r"
    upload = make_upload(content=content)

    result = DocumentParser().parse(upload, content)

    assert result.full_text == "Line one.\n\nLine two."


@pytest.mark.parametrize(
    ("prefix", "expected_type"),
    [
        ("DANGER", ContentBlockType.DANGER),
        ("WARNING", ContentBlockType.WARNING),
        ("CAUTION", ContentBlockType.CAUTION),
        ("NOTE", ContentBlockType.NOTE),
        ("danger", ContentBlockType.DANGER),
        ("warning", ContentBlockType.WARNING),
    ],
)
def test_plain_text_detects_safety_blocks(
    prefix,
    expected_type,
):
    text = f"{prefix}: Isolate electrical power before maintenance."
    content = text.encode("utf-8")
    upload = make_upload(content=content)

    result = DocumentParser().parse(upload, content)
    block = result.pages[0].blocks[0]

    assert block.block_type == expected_type
    assert block.text == "Isolate electrical power before maintenance."
    assert block.attributes["safety_label"] == prefix.lower()


def test_plain_text_detects_dash_safety_separator():
    content = b"WARNING - Depressurise the process connection."
    upload = make_upload(content=content)

    result = DocumentParser().parse(upload, content)

    assert (
        result.pages[0].blocks[0].block_type
        == ContentBlockType.WARNING
    )


def test_plain_text_detects_unordered_list():
    content = (
        b"- Isolate the process\n"
        b"- Verify zero energy\n"
        b"- Remove the transmitter"
    )
    upload = make_upload(content=content)

    result = DocumentParser().parse(upload, content)
    block = result.pages[0].blocks[0]

    assert block.block_type == ContentBlockType.LIST
    assert block.text == (
        "Isolate the process\n"
        "Verify zero energy\n"
        "Remove the transmitter"
    )
    assert block.attributes["item_count"] == 3


def test_plain_text_detects_ordered_list():
    content = (
        b"1. Close the isolation valve\n"
        b"2. Vent trapped pressure\n"
        b"3. Confirm zero pressure"
    )
    upload = make_upload(content=content)

    result = DocumentParser().parse(upload, content)
    block = result.pages[0].blocks[0]

    assert block.block_type == ContentBlockType.LIST
    assert block.attributes["item_count"] == 3


def test_plain_text_parser_metadata():
    content = b"Instrument information"
    upload = make_upload(content=content)

    result = DocumentParser().parse(upload, content)

    assert result.parser_metadata == {
        "source_format": "txt",
        "effective_format": "txt",
        "encoding": "utf-8",
        "markdown": False,
        "block_count": 1,
    }


# ---------------------------------------------------------------------------
# Markdown parsing
# ---------------------------------------------------------------------------


def test_parse_markdown_title_and_heading():
    content = (
        b"# Flowmeter Manual\n\n"
        b"## Installation\n\n"
        b"Mount the meter in the correct orientation."
    )
    upload = make_upload(
        filename="flowmeter.md",
        document_format=DocumentFormat.UNKNOWN,
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    blocks = result.pages[0].blocks

    assert result.title == "Flowmeter Manual"
    assert blocks[0].block_type == ContentBlockType.TITLE
    assert blocks[0].attributes["heading_level"] == 1
    assert blocks[1].block_type == ContentBlockType.HEADING
    assert blocks[1].attributes["heading_level"] == 2
    assert blocks[2].block_type == ContentBlockType.PARAGRAPH
    assert result.parser_metadata["markdown"] is True


def test_markdown_heading_section_paths():
    content = (
        b"# Manual\n\n"
        b"## Installation\n\n"
        b"### Wiring\n\n"
        b"Connect the signal cable."
    )
    upload = make_upload(
        filename="manual.md",
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    blocks = result.pages[0].blocks

    assert blocks[0].section_path == ["Manual"]
    assert blocks[1].section_path == ["Manual", "Installation"]
    assert blocks[2].section_path == [
        "Manual",
        "Installation",
        "Wiring",
    ]
    assert blocks[3].section_path == [
        "Manual",
        "Installation",
        "Wiring",
    ]


@pytest.mark.parametrize(
    ("underline", "expected_level"),
    [
        ("=======", 1),
        ("-------", 2),
    ],
)
def test_markdown_underlined_heading(
    underline,
    expected_level,
):
    text = f"Instrument Manual\n{underline}\n\nInformation."
    content = text.encode("utf-8")
    upload = make_upload(
        filename="manual.markdown",
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    heading = result.pages[0].blocks[0]

    assert heading.attributes["heading_level"] == expected_level


def test_markdown_extracts_fenced_code_block():
    content = (
        b"# Configuration\n\n"
        b"```json\n"
        b'{"range": "0-10 bar"}\n'
        b"```\n"
    )
    upload = make_upload(
        filename="configuration.md",
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    code_block = result.pages[0].blocks[1]

    assert code_block.block_type == ContentBlockType.CODE
    assert code_block.text == '{"range": "0-10 bar"}'
    assert code_block.attributes["language"] == "json"


def test_markdown_preserves_unclosed_code_block():
    content = (
        b"# Configuration\n\n"
        b"```python\n"
        b"range_value = 10\n"
    )
    upload = make_upload(
        filename="configuration.md",
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert result.pages[0].blocks[-1].block_type == ContentBlockType.CODE
    assert result.pages[0].blocks[-1].text == "range_value = 10"


# ---------------------------------------------------------------------------
# CSV and TSV parsing
# ---------------------------------------------------------------------------


def test_parse_csv_document():
    content = (
        b"tag,manufacturer,model\n"
        b"PT-101,Emerson,3051\n"
        b"FT-201,Endress+Hauser,Promag\n"
    )
    upload = make_upload(
        filename="instruments.csv",
        document_format=DocumentFormat.CSV,
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    block = result.pages[0].blocks[0]
    table = block.table

    assert result.title == "instruments"
    assert result.extraction_method == ExtractionMethod.TABLE_EXTRACTION
    assert block.block_type == ContentBlockType.TABLE
    assert block.extraction_method == ExtractionMethod.TABLE_EXTRACTION
    assert table is not None
    assert table.headers == ["tag", "manufacturer", "model"]
    assert table.rows == [
        ["PT-101", "Emerson", "3051"],
        ["FT-201", "Endress+Hauser", "Promag"],
    ]
    assert table.column_count == 3
    assert table.row_count == 2


def test_csv_parser_metadata():
    content = b"tag,value\nPT-101,10 bar\n"
    upload = make_upload(
        filename="values.csv",
        document_format=DocumentFormat.CSV,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert result.parser_metadata["delimiter"] == ","
    assert result.parser_metadata["row_count"] == 1
    assert result.parser_metadata["column_count"] == 2
    assert result.parser_metadata["encoding"] == "utf-8"


@pytest.mark.parametrize(
    ("delimiter", "filename"),
    [
        (";", "values.csv"),
        ("|", "values.csv"),
        ("\t", "values.tsv"),
    ],
)
def test_parse_alternative_delimiters(delimiter, filename):
    text = (
        f"tag{delimiter}value\n"
        f"PT-101{delimiter}10 bar\n"
    )
    content = text.encode("utf-8")
    upload = make_upload(
        filename=filename,
        document_format=DocumentFormat.UNKNOWN,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert result.parser_metadata["delimiter"] == delimiter
    assert result.pages[0].blocks[0].table.rows == [
        ["PT-101", "10 bar"]
    ]


def test_csv_ignores_fully_empty_rows():
    content = (
        b"tag,value\n"
        b"\n"
        b"PT-101,10 bar\n"
        b",\n"
    )
    upload = make_upload(
        filename="values.csv",
        document_format=DocumentFormat.CSV,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert result.pages[0].blocks[0].table.rows == [
        ["PT-101", "10 bar"]
    ]


def test_csv_pads_rows_with_missing_columns():
    content = (
        b"tag,manufacturer,model\n"
        b"PT-101,Emerson\n"
    )
    upload = make_upload(
        filename="values.csv",
        document_format=DocumentFormat.CSV,
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    table = result.pages[0].blocks[0].table

    assert table.rows == [["PT-101", "Emerson", ""]]
    assert any(
        "different column counts" in warning
        for warning in result.warnings
    )


def test_csv_with_header_only_is_valid():
    content = b"tag,manufacturer,model\n"
    upload = make_upload(
        filename="empty_table.csv",
        document_format=DocumentFormat.CSV,
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    table = result.pages[0].blocks[0].table

    assert table.headers == ["tag", "manufacturer", "model"]
    assert table.rows == []
    assert table.row_count == 0


def test_csv_rejects_no_meaningful_rows():
    content = b",,\n,,\n"
    upload = make_upload(
        filename="empty.csv",
        document_format=DocumentFormat.CSV,
        content=content,
    )

    with pytest.raises(
        EmptyDocumentError,
        match="contains no rows",
    ):
        DocumentParser().parse(upload, content)


def test_csv_rejects_excessive_rows():
    content = b"tag\nPT-101\nPT-102\n"
    config = DocumentParserConfig(maximum_csv_rows=2)
    upload = make_upload(
        filename="values.csv",
        document_format=DocumentFormat.CSV,
        content=content,
    )

    with pytest.raises(
        MalformedDocumentError,
        match="exceeding the configured maximum",
    ):
        DocumentParser(config).parse(upload, content)


def test_csv_rejects_excessive_columns():
    content = b"a,b,c\n1,2,3\n"
    config = DocumentParserConfig(maximum_csv_columns=2)
    upload = make_upload(
        filename="values.csv",
        document_format=DocumentFormat.CSV,
        content=content,
    )

    with pytest.raises(
        MalformedDocumentError,
        match="columns",
    ):
        DocumentParser(config).parse(upload, content)


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------


def test_parse_json_object():
    content = (
        b'{'
        b'"title": "Pressure Transmitter", '
        b'"manufacturer": "Emerson", '
        b'"model": "3051"'
        b'}'
    )
    upload = make_upload(
        filename="instrument.json",
        document_format=DocumentFormat.JSON,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert result.title == "Pressure Transmitter"
    assert result.parser_metadata["root_type"] == "dict"
    assert result.parser_metadata["block_count"] == 3
    assert '"manufacturer": "Emerson"' in result.full_text
    assert result.pages[0].blocks[0].text == (
        "title: Pressure Transmitter"
    )


def test_json_extracts_alternative_title_fields():
    content = b'{"product_name": "Magnetic Flowmeter"}'
    upload = make_upload(
        filename="instrument.json",
        document_format=DocumentFormat.JSON,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert result.title == "Magnetic Flowmeter"


def test_json_falls_back_to_filename_for_title():
    content = b'{"manufacturer": "Emerson"}'
    upload = make_upload(
        filename="instrument.json",
        document_format=DocumentFormat.JSON,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert result.title == "instrument"


def test_json_creates_heading_for_nested_object():
    content = (
        b'{'
        b'"specifications": {'
        b'"range": "0-10 bar", '
        b'"output": "4-20 mA"'
        b'}'
        b'}'
    )
    upload = make_upload(
        filename="instrument.json",
        document_format=DocumentFormat.JSON,
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    blocks = result.pages[0].blocks

    assert blocks[0].block_type == ContentBlockType.HEADING
    assert blocks[0].text == "specifications"
    assert blocks[1].section_path == ["specifications"]
    assert blocks[1].attributes["json_path"] == [
        "specifications",
        "range",
    ]


def test_json_creates_list_block_for_scalar_array():
    content = b'{"protocols": ["HART", "Modbus", "Profibus"]}'
    upload = make_upload(
        filename="instrument.json",
        document_format=DocumentFormat.JSON,
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    list_block = result.pages[0].blocks[1]

    assert list_block.block_type == ContentBlockType.LIST
    assert list_block.text == "HART\nModbus\nProfibus"
    assert list_block.attributes["item_count"] == 3


def test_json_formats_boolean_and_null_values():
    content = b'{"enabled": true, "replacement": null}'
    upload = make_upload(
        filename="instrument.json",
        document_format=DocumentFormat.JSON,
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    texts = [block.text for block in result.pages[0].blocks]

    assert "enabled: true" in texts
    assert "replacement: null" in texts


def test_json_empty_object_creates_code_block():
    content = b"{}"
    upload = make_upload(
        filename="empty.json",
        document_format=DocumentFormat.JSON,
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    block = result.pages[0].blocks[0]

    assert block.block_type == ContentBlockType.CODE
    assert block.text == "{}"
    assert block.attributes["language"] == "json"


def test_json_scalar_root_creates_paragraph():
    content = b"42"
    upload = make_upload(
        filename="value.json",
        document_format=DocumentFormat.JSON,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert (
        result.pages[0].blocks[0].block_type
        == ContentBlockType.PARAGRAPH
    )
    assert result.pages[0].blocks[0].text == "42"


def test_invalid_json_raises_malformed_document_error():
    content = b'{"manufacturer": "Emerson",}'
    upload = make_upload(
        filename="invalid.json",
        document_format=DocumentFormat.JSON,
        content=content,
    )

    with pytest.raises(
        MalformedDocumentError,
        match="JSON document",
    ):
        DocumentParser().parse(upload, content)


# ---------------------------------------------------------------------------
# HTML parsing
# ---------------------------------------------------------------------------


def test_parse_html_document():
    content = (
        b"<html>"
        b"<head><title>Valve Manual</title></head>"
        b"<body>"
        b"<h1>Control Valve</h1>"
        b"<p>Installation information.</p>"
        b"</body>"
        b"</html>"
    )
    upload = make_upload(
        filename="valve.html",
        document_format=DocumentFormat.HTML,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert result.title == "Valve Manual"
    assert "Control Valve" in result.full_text
    assert "Installation information." in result.full_text
    assert result.extraction_confidence == 0.98
    assert result.parser_metadata["html_title_found"] is True


def test_html_ignores_script_style_and_noscript_content():
    content = (
        b"<html><body>"
        b"<style>.hidden { display: none; }</style>"
        b"<script>alert('unsafe');</script>"
        b"<noscript>Enable scripts</noscript>"
        b"<p>Visible instrument information.</p>"
        b"</body></html>"
    )
    upload = make_upload(
        filename="page.html",
        document_format=DocumentFormat.HTML,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert "Visible instrument information." in result.full_text
    assert "display: none" not in result.full_text
    assert "alert" not in result.full_text
    assert "Enable scripts" not in result.full_text


def test_html_decodes_character_references():
    content = (
        b"<html><body>"
        b"<p>Pressure &gt; 10 bar &amp; temperature &lt; 100 C</p>"
        b"</body></html>"
    )
    upload = make_upload(
        filename="page.html",
        document_format=DocumentFormat.HTML,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert "Pressure > 10 bar & temperature < 100 C" in result.full_text


def test_html_without_title_uses_filename():
    content = b"<html><body><p>Document body.</p></body></html>"
    upload = make_upload(
        filename="installation.html",
        document_format=DocumentFormat.HTML,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert result.title == "installation"
    assert result.parser_metadata["html_title_found"] is False


def test_html_without_readable_text_is_rejected():
    content = b"<html><body><script>nothing()</script></body></html>"
    upload = make_upload(
        filename="empty.html",
        document_format=DocumentFormat.HTML,
        content=content,
    )

    with pytest.raises(
        EmptyDocumentError,
        match="contains no readable text",
    ):
        DocumentParser().parse(upload, content)


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------


def test_parse_xml_document():
    content = (
        b"<instrument>"
        b"<manufacturer>Emerson</manufacturer>"
        b"<model>3051</model>"
        b"</instrument>"
    )
    upload = make_upload(
        filename="instrument.xml",
        document_format=DocumentFormat.XML,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert result.title == "instrument"
    assert result.full_text == "Emerson\n\n3051"
    assert result.parser_metadata["root_tag"] == "instrument"
    assert result.parser_metadata["block_count"] == 2


def test_xml_records_section_paths_and_attributes():
    content = (
        b'<instrument manufacturer="Emerson">'
        b'<specification unit="bar">'
        b"<range>10</range>"
        b"</specification>"
        b"</instrument>"
    )
    upload = make_upload(
        filename="instrument.xml",
        document_format=DocumentFormat.XML,
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    block = result.pages[0].blocks[0]

    assert block.text == "10"
    assert block.section_path == [
        "instrument",
        "specification",
        "range",
    ]
    assert block.attributes["xml_tag"] == "range"
    assert block.attributes["xml_attributes"] == {}


def test_xml_preserves_element_attributes():
    content = (
        b"<instrument>"
        b'<range unit="bar">10</range>'
        b"</instrument>"
    )
    upload = make_upload(
        filename="instrument.xml",
        document_format=DocumentFormat.XML,
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    block = result.pages[0].blocks[0]

    assert block.attributes["xml_attributes"] == {"unit": "bar"}


def test_xml_removes_namespace_from_tags():
    content = (
        b'<ns:instrument xmlns:ns="urn:engineer4me">'
        b"<ns:model>3051</ns:model>"
        b"</ns:instrument>"
    )
    upload = make_upload(
        filename="instrument.xml",
        document_format=DocumentFormat.XML,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert result.title == "instrument"
    assert result.parser_metadata["root_tag"] == "instrument"
    assert result.pages[0].blocks[0].attributes["xml_tag"] == "model"


def test_invalid_xml_raises_malformed_document_error():
    content = b"<instrument><model>3051</instrument>"
    upload = make_upload(
        filename="invalid.xml",
        document_format=DocumentFormat.XML,
        content=content,
    )

    with pytest.raises(
        MalformedDocumentError,
        match="XML document",
    ):
        DocumentParser().parse(upload, content)


def test_xml_without_readable_text_is_rejected():
    content = b"<instrument><model /></instrument>"
    upload = make_upload(
        filename="empty.xml",
        document_format=DocumentFormat.XML,
        content=content,
    )

    with pytest.raises(
        EmptyDocumentError,
        match="contains no readable text",
    ):
        DocumentParser().parse(upload, content)


# ---------------------------------------------------------------------------
# Convenience API and common output
# ---------------------------------------------------------------------------


def test_parse_document_convenience_function():
    content = b"Engineer4Me document"
    upload = make_upload(content=content)

    result = parse_document(upload, content)

    assert result.document_id == upload.document_id
    assert result.title == "Engineer4Me document"
    assert result.parser_name == PARSER_NAME


def test_parse_document_accepts_custom_configuration():
    content = b"123456"
    upload = make_upload(content=content)
    config = DocumentParserConfig(
        max_document_size_bytes=5,
    )

    with pytest.raises(DocumentTooLargeError):
        parse_document(
            upload,
            content,
            config=config,
        )


@pytest.mark.parametrize(
    ("filename", "document_format", "content"),
    [
        (
            "document.txt",
            DocumentFormat.TXT,
            b"Text document",
        ),
        (
            "manual.md",
            DocumentFormat.UNKNOWN,
            b"# Manual",
        ),
        (
            "table.csv",
            DocumentFormat.CSV,
            b"tag,value\nPT-101,10\n",
        ),
        (
            "data.json",
            DocumentFormat.JSON,
            b'{"name": "Instrument"}',
        ),
        (
            "page.html",
            DocumentFormat.HTML,
            b"<p>Instrument</p>",
        ),
        (
            "data.xml",
            DocumentFormat.XML,
            b"<root><value>Instrument</value></root>",
        ),
    ],
)
def test_supported_parsers_create_one_page(
    filename,
    document_format,
    content,
):
    upload = make_upload(
        filename=filename,
        document_format=document_format,
        content=content,
    )

    result = DocumentParser().parse(upload, content)

    assert result.page_count == 1
    assert len(result.pages) == 1
    assert result.pages[0].page_number == 1
    assert all(
        block.page_number == 1
        for block in result.pages[0].blocks
    )


def test_content_block_sequence_numbers_are_contiguous():
    content = (
        b"# Manual\n\n"
        b"First paragraph.\n\n"
        b"- Item one\n"
        b"- Item two\n\n"
        b"WARNING: Isolate the equipment."
    )
    upload = make_upload(
        filename="manual.md",
        content=content,
    )

    result = DocumentParser().parse(upload, content)
    sequence_numbers = [
        block.sequence_number
        for block in result.pages[0].blocks
    ]

    assert sequence_numbers == list(
        range(1, len(sequence_numbers) + 1)
    )


def test_page_and_document_extraction_details_match():
    content = b"Instrument information"
    upload = make_upload(content=content)

    result = DocumentParser().parse(upload, content)
    page = result.pages[0]

    assert page.extraction_method == result.extraction_method
    assert page.extraction_confidence == result.extraction_confidence
    assert page.warnings == []
